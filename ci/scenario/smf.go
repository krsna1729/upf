// SPDX-License-Identifier: BSD-3-Clause

package scenario

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/n4"
	"github.com/krsna1729/upf/internal/session"
)

// N4 is what the scenarios send their session messages to and read the
// answers from: the SMF side of TS 29.244 7.5.
type N4 interface {
	Establish(*message.SessionEstablishmentRequest) message.Message
	Modify(*message.SessionModificationRequest) message.Message
	Delete(*message.SessionDeletionRequest) message.Message
}

// SMF is a stand-in SMF on the UP function's N4 interface: one PFCP
// association over UDP (TS 29.244 7.4.4) and the session messages, each sent as
// bytes and answered by the UP function's PFCP node before the next. It answers
// the node's heartbeats (7.4.2), so the association outlives a lane's windows.
// A message that gets no answer within a retransmission budget answers nil,
// which every caller reads as "no session-level response".
type SMF struct {
	conn     *net.UDPConn
	recovery *ie.IE

	mu    sync.Mutex
	seq   uint32
	waits map[uint32]chan message.Message
}

// smfNodeID is the stand-in's Node ID, the one the scenarios' messages carry.
const smfNodeID = "smf"

// Serve starts the UP function's PFCP node for the compiler on a loopback
// port -- the internal/n4 node upfd runs, with the compiler as its session
// handler -- and associates a stand-in SMF with it. The lanes drive every
// scenario through it, so each session message crosses N4 as a PFCP datagram.
// It also runs upfd's report loop (-urr-interval) once per tick: the tick is what
// drains the GTP-U responder's End Marker log and relays each End Marker
// through the tunnel its F-TEID forwards into. The scenarios ask for no usage
// report, so one that is decided anyway is logged.
func Serve(c *session.Compiler, log *slog.Logger) (*SMF, func(), error) {
	srv, err := n4.New(n4.Config{NodeID: "127.0.0.1", Listen: "127.0.0.1:0", Sessions: c, Logger: log})
	if err != nil {
		return nil, nil, err
	}
	if err := srv.Listen(); err != nil {
		return nil, nil, err
	}
	go func() { _ = srv.Serve() }()
	smf, err := Associate(srv.Addr().String())
	if err != nil {
		_ = srv.Close()
		return nil, nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		ticker := time.NewTicker(tick)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				for _, r := range c.EvaluateAll(ctx, now) {
					log.Warn("scenario: an unexpected usage report", "seid", r.SEID, "urr", r.URRID)
				}
			}
		}
	}()
	return smf, func() { cancel(); smf.Close(); _ = srv.Close() }, nil
}

// tick is the lanes' -urr-interval: short, so a relayed End Marker leaves
// within a phase.
const tick = 100 * time.Millisecond

// Associate dials the UP function's N4 address and sets up the association.
func Associate(addr string) (*SMF, error) {
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, err
	}
	s := &SMF{conn: conn, recovery: ie.NewRecoveryTimeStamp(time.Now()), waits: map[uint32]chan message.Message{}}
	go s.read()
	resp, err := s.exchange(message.NewAssociationSetupRequest(0, ie.NewNodeID("", "", smfNodeID), s.recovery))
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("association setup: %w", err)
	}
	setup, ok := resp.(*message.AssociationSetupResponse)
	if !ok || Cause(setup.Cause) != ie.CauseRequestAccepted {
		s.Close()
		return nil, fmt.Errorf("the association setup was not accepted: %v", resp)
	}
	return s, nil
}

// Close stops the stand-in. It sends no Association Release: a release ends
// every session of the association (7.4.4.3), and the lanes' sessions are
// gone with the process anyway.
func (s *SMF) Close() { _ = s.conn.Close() }

// read answers the node's heartbeats and hands every other message to the
// exchange waiting for its sequence number.
func (s *SMF) read() {
	buf := make([]byte, 65535)
	for {
		n, err := s.conn.Read(buf)
		if err != nil {
			return
		}
		msg, err := message.Parse(buf[:n])
		if err != nil {
			continue
		}
		if hb, ok := msg.(*message.HeartbeatRequest); ok {
			_ = s.send(message.NewHeartbeatResponse(hb.Sequence(), s.recovery))
			continue
		}
		s.mu.Lock()
		w := s.waits[msg.Sequence()]
		delete(s.waits, msg.Sequence())
		s.mu.Unlock()
		if w != nil {
			w <- msg
		}
	}
}

func (s *SMF) send(m message.Message) error {
	b := make([]byte, m.MarshalLen())
	if err := m.MarshalTo(b); err != nil {
		return err
	}
	_, err := s.conn.Write(b)
	return err
}

// exchange sends one request and waits for its answer, retransmitting it as
// a PFCP node does on silence (7.2.2.4.2).
func (s *SMF) exchange(m message.Message) (message.Message, error) {
	s.mu.Lock()
	s.seq++
	seq := s.seq
	w := make(chan message.Message, 1)
	s.waits[seq] = w
	s.mu.Unlock()
	m.SetSequenceNumber(seq)
	for range 3 {
		if err := s.send(m); err != nil {
			return nil, err
		}
		select {
		case resp := <-w:
			return resp, nil
		case <-time.After(3 * time.Second):
		}
	}
	s.mu.Lock()
	delete(s.waits, seq)
	s.mu.Unlock()
	return nil, errors.New("no answer from the UP function's N4 node")
}

func (s *SMF) answer(m message.Message) message.Message {
	resp, err := s.exchange(m)
	if err != nil {
		return nil
	}
	return resp
}

// Establish, Modify and Delete send the request over N4 and answer the UP
// function's response (nil when none came).
func (s *SMF) Establish(req *message.SessionEstablishmentRequest) message.Message {
	return s.answer(req)
}
func (s *SMF) Modify(req *message.SessionModificationRequest) message.Message { return s.answer(req) }
func (s *SMF) Delete(req *message.SessionDeletionRequest) message.Message     { return s.answer(req) }
