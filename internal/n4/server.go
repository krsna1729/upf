// Package n4 terminates PFCP (3GPP TS 29.244) on the N4 interface.
//
// It owns the UDP socket, the association with one CP function, and the
// liveness of that association. The wire format itself is the pinned
// github.com/wmnsk/go-pfcp library's; this package adds what that library
// deliberately leaves to its users: the node-level state machine and the
// dispatch to a session layer.
//
// One UP function serves one CP function at a time. Node-level messages
// (Association Setup, Association Release, Heartbeat) are handled here;
// session-level messages go to the SessionHandler.
package n4

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// Version is the PFCP version this node implements.
const Version = 1

// maxDatagram is the largest possible PFCP message: the 4-octet header plus
// the maximum of its 16-bit length field.
const maxDatagram = 4 + 65535

// maxSequence is the largest PFCP sequence number: it is 3 octets long.
const maxSequence = 0xffffff

// Liveness parameters, as in common PFCP practice: ask after 10 s of silence,
// wait 5 s for an answer, retry three times, then consider the peer gone.
const (
	DefaultHeartbeatEvery   = 10 * time.Second
	DefaultHeartbeatTimeout = 5 * time.Second
	DefaultHeartbeatRetries = 3
)

// SessionHandler handles the session-level messages of the associated CP
// function. Each method returns the response to send back; the server echoes
// the request's sequence number into it. A nil return means no response is
// sent, and the exchange is logged.
//
// The request, and the bytes behind it, belong to the socket's read loop: the
// handler must copy anything it keeps. It also must not block for long,
// because that loop serves one message at a time, heartbeats included.
type SessionHandler interface {
	Establish(req *message.SessionEstablishmentRequest) message.Message
	Modify(req *message.SessionModificationRequest) message.Message
	Delete(req *message.SessionDeletionRequest) message.Message

	// AssociationEnded reports that no session of the associated CP function
	// is valid any more: the association was released or timed out, or the CP
	// function restarted (its recovery time stamp moved).
	AssociationEnded(reason string)
}

// Config configures a Server.
type Config struct {
	// NodeID is the identity this UP function advertises (TS 29.244 8.2.2):
	// an IPv4 address, an IPv6 address, or an FQDN.
	NodeID string

	// Listen is the UDP address to bind, in host:port form.
	Listen string

	// UPFunctionFeatures are the four feature octets (TS 29.244 8.2.25) the
	// Association Setup Response advertises. The zero value advertises no
	// optional feature, which is what a UP function that implements only the
	// mandatory behaviour must say; each milestone that implements a feature
	// turns its bit on here.
	UPFunctionFeatures [4]uint8

	// Sessions receives the session-level messages. It may be nil, in which
	// case session requests are answered with Cause "Request rejected".
	Sessions SessionHandler

	// HeartbeatEvery is the silence after which the UP function asks the CP
	// function to prove it is there; HeartbeatTimeout is how long it waits for
	// an answer, and it gives up after HeartbeatRetries unanswered requests.
	// Zero values mean the defaults above.
	HeartbeatEvery   time.Duration
	HeartbeatTimeout time.Duration
	HeartbeatRetries int

	// Logger receives the operational log; nil means slog.Default().
	Logger *slog.Logger
}

// peer is the associated CP function.
type peer struct {
	addr        net.Addr
	nodeID      string
	recovery    time.Time
	hasRecovery bool
}

// pending is a heartbeat request this node sent and has no answer to yet.
type pending struct {
	seq    uint32
	sentAt time.Time
	tries  int
}

// Server is a PFCP node on the N4 interface.
type Server struct {
	cfg      Config
	log      *slog.Logger
	conn     net.PacketConn
	nodeID   *ie.IE
	features *ie.IE
	recovery *ie.IE

	mu       sync.Mutex
	peer     *peer
	lastSeen time.Time
	pending  *pending
	seq      uint32

	wake chan struct{}
	done chan struct{}
	once sync.Once
}

// New returns a Server that will listen on cfg.Listen.
func New(cfg Config) (*Server, error) {
	if cfg.NodeID == "" {
		return nil, errors.New("n4: NodeID is required")
	}
	if cfg.Listen == "" {
		return nil, errors.New("n4: Listen is required")
	}
	if cfg.HeartbeatEvery <= 0 {
		cfg.HeartbeatEvery = DefaultHeartbeatEvery
	}
	if cfg.HeartbeatTimeout <= 0 {
		cfg.HeartbeatTimeout = DefaultHeartbeatTimeout
	}
	if cfg.HeartbeatRetries <= 0 {
		cfg.HeartbeatRetries = DefaultHeartbeatRetries
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	// The recovery time stamp (TS 29.244 8.2.53) is the start wall clock, in
	// NTP seconds. It must be larger after a restart than before it, which
	// this is unless the clock goes backwards.
	return &Server{
		cfg:      cfg,
		log:      cfg.Logger,
		nodeID:   nodeID(cfg.NodeID),
		features: ie.NewUPFunctionFeatures(cfg.UPFunctionFeatures[0], cfg.UPFunctionFeatures[1], cfg.UPFunctionFeatures[2], cfg.UPFunctionFeatures[3]),
		recovery: ie.NewRecoveryTimeStamp(time.Now()),
		wake:     make(chan struct{}, 1),
		done:     make(chan struct{}),
	}, nil
}

// nodeID encodes id one way: an IPv4 address, an IPv6 address, or an FQDN.
func nodeID(id string) *ie.IE {
	if ip := net.ParseIP(id); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return ie.NewNodeID(v4.String(), "", "")
		}
		return ie.NewNodeID("", ip.String(), "")
	}
	return ie.NewNodeID("", "", id)
}

// Listen binds the N4 socket.
func (s *Server) Listen() error {
	if s.conn != nil {
		return errors.New("n4: already listening")
	}
	conn, err := net.ListenPacket("udp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("n4: listen %s: %w", s.cfg.Listen, err)
	}
	s.conn = conn
	return nil
}

// Addr returns the bound address, or nil before Listen.
func (s *Server) Addr() net.Addr {
	if s.conn == nil {
		return nil
	}
	return s.conn.LocalAddr()
}

// Peer reports the associated CP function: its Node ID as it reported it, its
// address, and whether an association exists.
func (s *Server) Peer() (nodeID string, addr net.Addr, associated bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.peer == nil {
		return "", nil, false
	}
	return s.peer.nodeID, s.peer.addr, true
}

// Serve handles messages until Close. Listen must have been called.
func (s *Server) Serve() error {
	if s.conn == nil {
		return errors.New("n4: Serve before Listen")
	}
	go s.liveness()

	buf := make([]byte, maxDatagram)
	for {
		n, from, err := s.conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-s.done:
				return nil
			default:
			}
			return err
		}
		if n == 0 {
			continue
		}
		s.handle(buf[:n], from)
	}
}

// Close stops Serve and releases the socket.
func (s *Server) Close() error {
	var err error
	s.once.Do(func() {
		close(s.done)
		if s.conn != nil {
			err = s.conn.Close()
		}
	})
	return err
}

// handle processes one datagram.
func (s *Server) handle(b []byte, from net.Addr) {
	if len(b) < 4 {
		s.log.Debug("n4: datagram too short", "from", from, "len", len(b))
		return
	}
	if v := int(b[0] >> 5); v != Version {
		// TS 29.244 7.2.1: another version gets a Version Not Supported
		// Response, and the message is not parsed any further.
		s.log.Info("n4: unsupported PFCP version", "from", from, "version", v)
		s.reply(from, message.NewVersionNotSupportedResponse(sequenceNumber(b)))
		return
	}
	msg, err := message.Parse(b)
	if err != nil {
		s.log.Warn("n4: malformed PFCP message", "from", from, "len", len(b), "err", err)
		return
	}
	s.noteActivity(from)

	switch msg.MessageType() {
	case message.MsgTypeHeartbeatRequest:
		s.onHeartbeat(msg.(*message.HeartbeatRequest), from)
	case message.MsgTypeHeartbeatResponse:
		s.onHeartbeatResponse(msg, from)
	case message.MsgTypeAssociationSetupRequest:
		s.onAssociationSetup(msg.(*message.AssociationSetupRequest), from)
	case message.MsgTypeAssociationReleaseRequest:
		s.onAssociationRelease(msg.(*message.AssociationReleaseRequest), from)
	case message.MsgTypeSessionEstablishmentRequest,
		message.MsgTypeSessionModificationRequest,
		message.MsgTypeSessionDeletionRequest:
		s.onSession(msg, from)
	default:
		// TS 29.244 7.2: a message type this node does not implement is
		// ignored. Association Update, Node Report, PFD Management and
		// Session Set Deletion arrive here until they are implemented.
		s.log.Info("n4: message ignored (not implemented)",
			"from", from, "type", msg.MessageTypeName(), "seq", msg.Sequence())
	}
}

// sequenceNumber reads the 3-octet sequence number of a message that has not
// been parsed: it follows the 4-octet header, and the 8-octet SEID when the S
// flag is set (TS 29.244 figure 7.2.2-1).
func sequenceNumber(b []byte) uint32 {
	off := 4
	if b[0]&0x01 != 0 {
		off += 8
	}
	if len(b) < off+3 {
		return 0
	}
	return uint32(b[off])<<16 | uint32(b[off+1])<<8 | uint32(b[off+2])
}

func (s *Server) onHeartbeat(req *message.HeartbeatRequest, from net.Addr) {
	if req.RecoveryTimeStamp != nil {
		if ts, err := req.RecoveryTimeStamp.RecoveryTimeStamp(); err == nil {
			s.checkRestart(from, ts)
		}
	}
	s.reply(from, message.NewHeartbeatResponse(req.Sequence(), s.recovery))
}

func (s *Server) onHeartbeatResponse(msg message.Message, from net.Addr) {
	s.mu.Lock()
	matched := s.pending != nil && s.pending.seq == msg.Sequence()
	if matched {
		s.pending = nil
	}
	s.mu.Unlock()
	if !matched {
		s.log.Debug("n4: unmatched heartbeat response", "from", from, "seq", msg.Sequence())
	}
}

func (s *Server) onAssociationSetup(req *message.AssociationSetupRequest, from net.Addr) {
	id, recovery, hasRecovery := "", time.Time{}, false
	if req.NodeID != nil {
		if got, err := req.NodeID.NodeID(); err == nil {
			id = got
		}
	}
	if req.RecoveryTimeStamp != nil {
		if ts, err := req.RecoveryTimeStamp.RecoveryTimeStamp(); err == nil {
			recovery, hasRecovery = ts, true
		}
	}

	s.mu.Lock()
	if s.peer != nil && !sameAddr(s.peer.addr, from) {
		associated := s.peer.nodeID
		s.mu.Unlock()
		s.log.Warn("n4: association setup from a second CP function: rejected",
			"from", from, "node_id", id, "associated_node_id", associated)
		s.reply(from, message.NewAssociationSetupResponse(req.Sequence(),
			s.nodeID, ie.NewCause(ie.CauseRequestRejected)))
		return
	}
	restarted := s.peer != nil && s.peer.hasRecovery && hasRecovery && recovery.After(s.peer.recovery)
	s.peer = &peer{addr: from, nodeID: id, recovery: recovery, hasRecovery: hasRecovery}
	s.lastSeen = time.Now()
	s.pending = nil
	s.mu.Unlock()
	s.signal()

	if restarted {
		s.log.Warn("n4: CP function restarted: recovery time stamp moved", "node_id", id, "from", from)
		s.ended("CP function restarted (recovery time stamp moved)")
	}
	// The mandatory IEs of the response (TS 29.244 7.4.4.2): Node ID, Cause,
	// Recovery Time Stamp, and the UP function's features.
	s.reply(from, message.NewAssociationSetupResponse(req.Sequence(),
		s.nodeID, ie.NewCause(ie.CauseRequestAccepted), s.recovery, s.features))
	s.log.Info("n4: association established", "node_id", id, "from", from, "recovery_time_stamp", hasRecovery)
}

func (s *Server) onAssociationRelease(req *message.AssociationReleaseRequest, from net.Addr) {
	s.mu.Lock()
	if s.peer == nil || !sameAddr(s.peer.addr, from) {
		s.mu.Unlock()
		s.log.Warn("n4: association release from an unassociated peer: rejected", "from", from)
		s.reply(from, message.NewAssociationReleaseResponse(req.Sequence(),
			s.nodeID, ie.NewCause(ie.CauseRequestRejected)))
		return
	}
	id := s.peer.nodeID
	s.peer, s.pending = nil, nil
	s.mu.Unlock()
	s.signal()

	s.reply(from, message.NewAssociationReleaseResponse(req.Sequence(),
		s.nodeID, ie.NewCause(ie.CauseRequestAccepted)))
	s.log.Info("n4: association released by the CP function", "node_id", id, "from", from)
	s.ended("association released by the CP function")
}

func (s *Server) onSession(msg message.Message, from net.Addr) {
	s.mu.Lock()
	associated := s.peer != nil && sameAddr(s.peer.addr, from)
	s.mu.Unlock()

	switch {
	case !associated:
		s.rejectSession(msg, from, ie.CauseNoEstablishedPFCPAssociation, "no established association")
	case s.cfg.Sessions == nil:
		s.rejectSession(msg, from, ie.CauseRequestRejected, "no session layer")
	default:
		resp := s.dispatchSession(msg)
		if resp == nil {
			s.log.Warn("n4: session message produced no response",
				"from", from, "type", msg.MessageTypeName(), "seq", msg.Sequence())
			return
		}
		resp.SetSequenceNumber(msg.Sequence())
		s.reply(from, resp)
	}
}

func (s *Server) dispatchSession(msg message.Message) message.Message {
	h := s.cfg.Sessions
	switch req := msg.(type) {
	case *message.SessionEstablishmentRequest:
		return h.Establish(req)
	case *message.SessionModificationRequest:
		return h.Modify(req)
	case *message.SessionDeletionRequest:
		return h.Delete(req)
	}
	return nil
}

// rejectSession answers a session-level request with a Cause, echoing the
// request's sequence number and, where the request carried one, its SEID.
func (s *Server) rejectSession(req message.Message, from net.Addr, cause uint8, why string) {
	c := ie.NewCause(cause)
	var resp message.Message
	switch r := req.(type) {
	case *message.SessionEstablishmentRequest:
		// Establishment has no UP F-SEID yet: the UP function would
		// allocate one.
		resp = message.NewSessionEstablishmentResponse(0, 0, 0, r.Sequence(), 0, c)
	case *message.SessionModificationRequest:
		resp = message.NewSessionModificationResponse(0, 0, r.SEID(), r.Sequence(), 0, c)
	case *message.SessionDeletionRequest:
		resp = message.NewSessionDeletionResponse(0, 0, r.SEID(), r.Sequence(), 0, c)
	default:
		s.log.Warn("n4: no response type for a session message", "type", req.MessageTypeName())
		return
	}
	s.log.Warn("n4: session request rejected",
		"from", from, "type", req.MessageTypeName(), "seq", req.Sequence(), "cause", causeName(cause), "why", why)
	s.reply(from, resp)
}

// checkRestart reports a CP function that restarted without re-associating: a
// heartbeat carrying a recovery time stamp later than the one from the
// association means its sessions are void (TS 29.244 7.4.1), and its next
// Association Setup Request rebuilds the association.
func (s *Server) checkRestart(from net.Addr, ts time.Time) {
	s.mu.Lock()
	if s.peer == nil || !sameAddr(s.peer.addr, from) || !s.peer.hasRecovery || !ts.After(s.peer.recovery) {
		s.mu.Unlock()
		return
	}
	id := s.peer.nodeID
	s.peer, s.pending = nil, nil
	s.mu.Unlock()
	s.signal()

	s.log.Warn("n4: CP function restarted: recovery time stamp moved", "node_id", id, "from", from)
	s.ended("CP function restarted (recovery time stamp moved)")
}

// noteActivity records a message from the associated peer: the association is
// alive, so an outstanding heartbeat needs no answer.
func (s *Server) noteActivity(from net.Addr) {
	s.mu.Lock()
	if s.peer != nil && sameAddr(s.peer.addr, from) {
		s.lastSeen = time.Now()
		s.pending = nil
	}
	s.mu.Unlock()
	s.signal()
}

func (s *Server) ended(reason string) {
	if s.cfg.Sessions != nil {
		s.cfg.Sessions.AssociationEnded(reason)
	}
}

// signal wakes the liveness loop to recompute its next step.
func (s *Server) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Server) reply(to net.Addr, m message.Message) {
	b := make([]byte, m.MarshalLen())
	if err := m.MarshalTo(b); err != nil {
		s.log.Error("n4: marshal", "type", m.MessageTypeName(), "err", err)
		return
	}
	if _, err := s.conn.WriteTo(b, to); err != nil {
		s.log.Error("n4: send", "type", m.MessageTypeName(), "to", to, "err", err)
	}
}

// sameAddr reports whether a and b are the same UDP endpoint. The IP parts are
// compared as addresses, so an IPv4 address and its IPv4-mapped IPv6 form
// match.
func sameAddr(a, b net.Addr) bool {
	ua, okA := a.(*net.UDPAddr)
	ub, okB := b.(*net.UDPAddr)
	if !okA || !okB {
		return a.String() == b.String()
	}
	return ua.Port == ub.Port && ua.IP.Equal(ub.IP)
}

func causeName(cause uint8) string {
	switch cause {
	case ie.CauseRequestAccepted:
		return "Request accepted"
	case ie.CauseRequestRejected:
		return "Request rejected"
	case ie.CauseNoEstablishedPFCPAssociation:
		return "No established PFCP association"
	}
	return fmt.Sprintf("cause %d", cause)
}

// action is what the liveness loop does next.
type action int

const (
	actionNone action = iota
	actionHeartbeat
	actionDead
)

// liveness asks an idle peer to prove it is there, and gives up on it after
// HeartbeatRetries unanswered requests (TS 29.244 7.4.1).
func (s *Server) liveness() {
	for {
		act, wait := s.plan(time.Now())
		if act != actionNone {
			s.fire(act)
			continue
		}
		var timer *time.Timer
		var tick <-chan time.Time
		if wait >= 0 {
			if wait <= 0 {
				wait = time.Millisecond
			}
			timer = time.NewTimer(wait)
			tick = timer.C
		}
		select {
		case <-s.done:
			if timer != nil {
				timer.Stop()
			}
			return
		case <-s.wake:
			if timer != nil {
				timer.Stop()
			}
		case <-tick:
		}
	}
}

// plan returns the next liveness step and how long to wait for it. A negative
// wait means there is nothing to wait for.
func (s *Server) plan(now time.Time) (action, time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.peer == nil {
		return actionNone, -1
	}
	if p := s.pending; p != nil {
		elapsed := now.Sub(p.sentAt)
		if elapsed < s.cfg.HeartbeatTimeout {
			return actionNone, s.cfg.HeartbeatTimeout - elapsed
		}
		if p.tries >= s.cfg.HeartbeatRetries {
			return actionDead, 0
		}
		return actionHeartbeat, 0
	}
	if silent := now.Sub(s.lastSeen); silent < s.cfg.HeartbeatEvery {
		return actionNone, s.cfg.HeartbeatEvery - silent
	}
	return actionHeartbeat, 0
}

func (s *Server) fire(act action) {
	switch act {
	case actionHeartbeat:
		s.mu.Lock()
		if s.peer == nil {
			s.mu.Unlock()
			return
		}
		to := s.peer.addr
		tries := 1
		if s.pending != nil {
			tries = s.pending.tries + 1
		}
		seq := s.nextSequence()
		s.pending = &pending{seq: seq, sentAt: time.Now(), tries: tries}
		s.mu.Unlock()

		s.log.Debug("n4: heartbeat request", "to", to, "seq", seq, "try", tries)
		s.reply(to, message.NewHeartbeatRequest(seq, s.recovery, nil))

	case actionDead:
		s.mu.Lock()
		if s.peer == nil {
			s.mu.Unlock()
			return
		}
		to := s.peer.addr
		tries := 0
		if s.pending != nil {
			tries = s.pending.tries
		}
		s.peer, s.pending = nil, nil
		s.mu.Unlock()
		s.signal()

		s.log.Warn("n4: PFCP peer gone: no answer to heartbeats", "peer", to, "requests", tries)
		s.ended("heartbeat timeout: no answer to " + fmt.Sprint(tries) + " heartbeat requests")
	}
}

// nextSequence returns the next sequence number for a request this node
// sends. Must be called with the lock held.
func (s *Server) nextSequence() uint32 {
	s.seq++
	if s.seq > maxSequence {
		s.seq = 1
	}
	return s.seq
}
