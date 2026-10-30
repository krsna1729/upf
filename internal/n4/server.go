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
	"bytes"
	"context"
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

// The UP Function Features bits of TS 29.244 8.2.25, octet 5, that this tree
// implements. A milestone turns its bit on in cmd/upfd as it lands: an optional
// feature is advertised only where the code behind it exists, and the answer
// otherwise declares the mandatory behaviour alone.
const (
	// FTUP is F-TEID allocation in the UP function: a PDI whose F-TEID IE
	// carries the CH flag is given an F-TEID, reported in the Created PDR --
	// one per PDI, and one for all the PDIs of a PFCP session that carry the
	// same CHOOSE ID (8.2.3; internal/session).
	FTUP = 0x10
	// EMPU is End Marker packet construction in the UP function (TS 29.244
	// 5.3.2 and 8.2.25: octet 6, bit 1 of the UP Function Features), set only
	// where the graph carries one out (upfd -end-marker).
	EMPU = 0x01
	// MNOP is measurement of the number of packets (TS 29.244 8.2.25: octet 7,
	// bit 5), advertised where the session layer runs: every usage report
	// carries the packet counts, and a URR's Measurement Information MNOP flag
	// asks for what the counters already hold.
	MNOP = 0x10
)

// Liveness parameters, as in common PFCP practice: ask after 10 s of silence,
// wait 5 s for an answer, retry three times, then consider the peer gone.
const (
	DefaultHeartbeatEvery   = 10 * time.Second
	DefaultHeartbeatTimeout = 5 * time.Second
	DefaultHeartbeatRetries = 3

	// DefaultReportTimeout and DefaultReportRetries bound the Session Report
	// Request exchange. A local SMF answers in microseconds; two seconds is the
	// same order as the heartbeat's timeout, and three attempts is what a
	// lost-datagram retry needs without holding the reporting loop for long.
	DefaultReportTimeout = 2 * time.Second
	DefaultReportRetries = 3
)

// SessionHandler handles the session-level messages of the associated CP
// function. Each method returns the response to send back; the server echoes
// the request's sequence number into it. A nil return means no response is
// sent, and the exchange is logged.
//
// The request, and the bytes behind it, belong to the socket's read loop: the
// handler must copy anything it keeps. With Config.SessionWorkers above one,
// the methods are called concurrently for different sessions -- the messages
// of one session are handled one at a time, in the order they arrived -- and
// AssociationEnded only once every message read before the end was answered.
// Otherwise the read loop serves one message at a time, heartbeats included,
// and a handler must not block it for long.
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

	// SessionWorkers is how many session messages are handled at once. A
	// session's messages go to one worker, by the SEID that names the session
	// (the CP F-SEID of an establishment), so each session's are handled in
	// order. Zero or one handles them in the read loop itself. More than one
	// is what lets the dataplane's transactions overlap: a session message is
	// mostly the wait for its transaction, and the read loop's heartbeats and
	// association messages no longer wait behind it.
	SessionWorkers int

	// HeartbeatEvery is the silence after which the UP function asks the CP
	// function to prove it is there; HeartbeatTimeout is how long it waits for
	// an answer, and it gives up after HeartbeatRetries unanswered requests.
	// Zero values mean the defaults above.
	HeartbeatEvery   time.Duration
	HeartbeatTimeout time.Duration
	HeartbeatRetries int

	// ReportTimeout is how long a Session Report Request waits for the CP
	// function's answer before it is sent again, and ReportRetries is how many
	// unanswered requests are given up on. Zero values mean the defaults above.
	// The usage a report carries is what the SMF bills, so an unanswered one is
	// retried rather than dropped.
	ReportTimeout time.Duration
	ReportRetries int

	// RecoveryTimeStamp is the Recovery Time Stamp (TS 29.244 8.2.53) this UP
	// function advertises, in wall-clock seconds. Zero means now, which is what
	// a start that holds no previous sessions must say: the stamp moving is how
	// an SMF learns its sessions are gone (7.4.1), so it re-establishes them.
	// A start that *restored* the sessions from a checkpoint passes the stamp
	// they were created under instead -- nothing was lost, so telling the SMF
	// that something was would make it re-establish sessions this node is
	// holding, and every one of those establishments would be refused for a rule
	// the restored session still owns (session.compile).
	RecoveryTimeStamp time.Time

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

// ReportAnswer is what the CP function answered a Session Report Request with
// (TS 29.244 7.5.8.3): the Cause that says whether it took the report, and the
// Update BAR it may carry. 5.2.4.1 gives one meaning to the Update BAR here --
// when the CP function answers a Downlink Data Report it may extend the flow's
// buffering -- and its numbers are the ones the session must hold afterwards.
type ReportAnswer struct {
	Cause uint8
	// UpdateBAR is the Update BAR IE (7.5.2.6, 8.2.29-8.2.30) the response
	// carried, or nil when it carried none: a response without one changes
	// nothing.
	UpdateBAR *ie.IE
}

// reportWait is a Session Report Request this node sent and has no answer to
// yet. The UP function initiates that exchange (TS 29.244 7.5.8), so unlike
// every other message here it is this node's own transaction, and the answer is
// handed to the Report call that is waiting for it rather than to a handler.
type reportWait struct {
	seq uint32
	got chan ReportAnswer // the CP function's answer, buffered once
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

	// reportMu serializes the report exchange: one Session Report Request is in
	// flight at a time, and report is the one being waited for. The usage a
	// report carries is a decision the session layer makes serially, so a
	// second concurrent report is not a case to optimize for.
	reportMu sync.Mutex
	report   *reportWait

	wake chan struct{}
	done chan struct{}
	once sync.Once

	// work is one bounded queue per session worker, nil without workers.
	// queued counts the messages read and not yet answered, under queuedMu;
	// drained is signalled when it reaches zero.
	work     []chan sessionWork
	queuedMu sync.Mutex
	queued   int
	drained  *sync.Cond
}

// sessionWork is one session message a worker answers.
type sessionWork struct {
	msg  message.Message
	from net.Addr
}

// sessionQueue is each worker's backlog: past it the read loop waits, which is
// the socket's own buffer taking the burst, as it does without workers.
const sessionQueue = 64

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
	if cfg.ReportTimeout <= 0 {
		cfg.ReportTimeout = DefaultReportTimeout
	}
	if cfg.ReportRetries <= 0 {
		cfg.ReportRetries = DefaultReportRetries
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	// The recovery time stamp (TS 29.244 8.2.53) is the start wall clock, in
	// NTP seconds. It must be larger after a restart than before it, which this
	// is unless the clock goes backwards -- unless the caller restored its
	// sessions from a checkpoint, in which case it passes the stamp those
	// sessions were created under: the sessions did not go, so the SMF must not
	// be told that they did (Config.RecoveryTimeStamp).
	stamp := cfg.RecoveryTimeStamp
	if stamp.IsZero() {
		stamp = time.Now()
	}
	s := &Server{
		cfg:      cfg,
		log:      cfg.Logger,
		nodeID:   nodeID(cfg.NodeID),
		features: ie.NewUPFunctionFeatures(cfg.UPFunctionFeatures[0], cfg.UPFunctionFeatures[1], cfg.UPFunctionFeatures[2], cfg.UPFunctionFeatures[3]),
		recovery: ie.NewRecoveryTimeStamp(stamp),
		wake:     make(chan struct{}, 1),
		done:     make(chan struct{}),
	}
	s.drained = sync.NewCond(&s.queuedMu)
	if cfg.SessionWorkers > 1 {
		s.work = make([]chan sessionWork, cfg.SessionWorkers)
		for i := range s.work {
			s.work[i] = make(chan sessionWork, sessionQueue)
		}
	}
	return s, nil
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
	for _, q := range s.work {
		go s.sessionWorker(q)
	}

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
		b := buf[:n]
		if s.work != nil {
			// A worker answers the message after this loop has read the next
			// datagram into buf, and the parsed IEs point into the bytes.
			b = bytes.Clone(b)
		}
		s.handle(b, from)
	}
}

// sessionWorker answers the session messages queued to it, in order.
func (s *Server) sessionWorker(q <-chan sessionWork) {
	for {
		select {
		case w := <-q:
			s.answerSession(w.msg, w.from)
			s.queuedMu.Lock()
			if s.queued--; s.queued == 0 {
				s.drained.Broadcast()
			}
			s.queuedMu.Unlock()
		case <-s.done:
			return
		}
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
	case message.MsgTypeSessionReportResponse:
		s.onReportResponse(msg.(*message.SessionReportResponse))
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

// Report sends a Session Report Request for one session and waits for the CP
// function's answer (TS 29.244 7.5.8.2-7.5.8.3): the UP function initiates this
// exchange, and the answer's Cause is what says the SMF took the report. An
// unanswered request is sent again ReportRetries times -- the usage it carries
// is what the SMF bills, so silence is not an outcome to forget quietly.
//
// seid is the F-SEID the CP function knows this session by (the CP F-SEID it
// put in the F-SEID IE): a report is addressed *to* the SMF, and the header's
// SEID is the identity the receiving node looks the session up with, so our own
// F-SEID would be a session the SMF cannot find.
//
// The Cause and the error are different things: a report the SMF *refused* is an
// answer (it arrived, and the caller decides what to do with the cause), while
// an error means no answer came at all. Only one report is in flight at a time.
//
// The answer carries the Update BAR the response did, if any (5.2.4.1): the
// session layer applies it to the session the report came from, so this call
// returns it rather than reading it and dropping it.
func (s *Server) Report(ctx context.Context, seid uint64, ies ...*ie.IE) (ReportAnswer, error) {
	if s.conn == nil {
		return ReportAnswer{}, errors.New("n4: the socket is not bound")
	}
	s.reportMu.Lock()
	defer s.reportMu.Unlock()

	s.mu.Lock()
	if s.peer == nil || s.peer.addr == nil {
		s.mu.Unlock()
		// 7.5.8.2: a report exists on an association. Sending one to nobody
		// would be a report the SMF never hears.
		return ReportAnswer{}, errors.New("n4: no CP function is associated")
	}
	to := s.peer.addr
	seq := s.nextSequence()
	wait := &reportWait{seq: seq, got: make(chan ReportAnswer, 1)}
	s.report = wait
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.report == wait {
			s.report = nil
		}
		s.mu.Unlock()
	}()

	req := message.NewSessionReportRequest(0, 0, seid, seq, 0, ies...)
	for try := 1; ; try++ {
		s.reply(to, req)
		select {
		case answer := <-wait.got:
			return answer, nil
		case <-ctx.Done():
			return ReportAnswer{}, fmt.Errorf("n4: session report for SEID %d: %w", seid, ctx.Err())
		case <-time.After(s.cfg.ReportTimeout):
			if try >= s.cfg.ReportRetries {
				return ReportAnswer{}, fmt.Errorf("n4: no answer to the session report for SEID %d after %d requests",
					seid, try)
			}
			s.log.Warn("n4: the session report is unanswered; sending it again",
				"seid", seid, "try", try, "to", to)
		}
	}
}

// onReportResponse hands the CP function's answer to the Report call waiting
// for it: the sequence number is the transaction, and a response to a report
// that already timed out is logged and dropped rather than delivered to the
// next one. The Update BAR the response may carry (5.2.4.1) goes with the
// answer: it is an instruction that belongs to the session the report named,
// and dropping it here would leave the numbers a Session Modification set.
func (s *Server) onReportResponse(resp *message.SessionReportResponse) {
	cause := uint8(ie.CauseRequestRejected)
	if resp.Cause != nil {
		if v, err := resp.Cause.Cause(); err == nil {
			cause = v
		}
	}
	s.mu.Lock()
	wait := s.report
	s.mu.Unlock()
	if wait == nil || wait.seq != resp.Sequence() {
		s.log.Info("n4: a session report response arrived with no report waiting for it",
			"seq", resp.Sequence(), "cause", causeName(cause))
		return
	}
	select {
	case wait.got <- ReportAnswer{Cause: cause, UpdateBAR: resp.UpdateBAR}:
	default:
		// The request was answered twice (this node's own retransmission
		// answered after the first answer arrived): the first one is the
		// report's outcome.
	}
}

// onHeartbeat handles a Heartbeat Request: the CP function's recovery time
// stamp, and its own liveness.
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
	s.log.Info("n4: association established", "node_id", id, "from", from, "has_recovery_time_stamp", hasRecovery)
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
	case s.work != nil:
		s.queuedMu.Lock()
		s.queued++
		s.queuedMu.Unlock()
		s.work[sessionKey(msg)%uint64(len(s.work))] <- sessionWork{msg: msg, from: from}
	default:
		s.answerSession(msg, from)
	}
}

// answerSession hands a session message to the session layer and sends its
// answer.
func (s *Server) answerSession(msg message.Message, from net.Addr) {
	resp := s.dispatchSession(msg)
	if resp == nil {
		s.log.Warn("n4: session message produced no response",
			"from", from, "type", msg.MessageTypeName(), "seq", msg.Sequence())
		return
	}
	resp.SetSequenceNumber(msg.Sequence())
	s.reply(from, resp)
}

// sessionKey is the identity a session's messages share: the CP F-SEID an
// establishment names, which is the SEID its retransmission names too, and the
// UP SEID in the header of every later message. A session's establishment and
// its later messages may go to different workers: the SMF learns the UP SEID
// from the establishment's answer, so nothing of the session follows it until
// it has been answered.
func sessionKey(msg message.Message) uint64 {
	if r, ok := msg.(*message.SessionEstablishmentRequest); ok {
		return cpSEIDOf(r)
	}
	return msg.SEID()
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

// cpSEIDOf is the CP F-SEID an establishment request names, or 0 when it names
// none: the header of an answer carries the identity of the peer's session
// (TS 29.244 7.2.2.4.2), which is the F-SEID the request sent.
func cpSEIDOf(r *message.SessionEstablishmentRequest) uint64 {
	if r.CPFSEID == nil {
		return 0
	}
	fields, err := r.CPFSEID.FSEID()
	if err != nil {
		return 0
	}
	return fields.SEID
}

// rejectSession answers a session-level request with a Cause, echoing the
// request's sequence number and, where the request carried one, its SEID.
func (s *Server) rejectSession(req message.Message, from net.Addr, cause uint8, why string) {
	c := ie.NewCause(cause)
	var resp message.Message
	switch r := req.(type) {
	case *message.SessionEstablishmentRequest:
		// The answer is addressed by the CP F-SEID the request named -- the
		// SMF's own identity for the session -- and by 0 when it named none.
		// The Node ID is mandatory in every Establishment Response, a
		// rejection included (TS 29.244 Table 7.5.3.1-1).
		resp = message.NewSessionEstablishmentResponse(0, 0, cpSEIDOf(r), r.Sequence(), 0, s.nodeID, c)
	case *message.SessionModificationRequest:
		// With no session layer there is no CP F-SEID to read; the SEID the
		// request carried is the only name left to answer under.
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
	if s.cfg.Sessions == nil {
		return
	}
	// Every session message read before the end is answered first, as the
	// read loop alone would have: the ones it reads after are refused, the
	// peer being gone.
	s.queuedMu.Lock()
	for s.queued > 0 {
		s.drained.Wait()
	}
	s.queuedMu.Unlock()
	s.cfg.Sessions.AssociationEnded(reason)
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
