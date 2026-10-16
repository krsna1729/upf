package n4_test

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/n4"
)

const (
	smfID   = "192.0.2.10" // the CP function's Node ID, as it reports it
	upfID   = "192.0.2.1"  // ours
	waitFor = time.Second  // every exchange is local; a second is generous
)

// recorder is a SessionHandler that records what it was given. Its responses
// carry a bogus sequence number, so a test can prove the server echoes the
// request's.
type recorder struct {
	mu        sync.Mutex
	establish int
	modify    int
	delete    int
	ended     chan string
}

func newRecorder() *recorder { return &recorder{ended: make(chan string, 4)} }

func (r *recorder) counts() (int, int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.establish, r.modify, r.delete
}

func (r *recorder) Establish(*message.SessionEstablishmentRequest) message.Message {
	r.mu.Lock()
	r.establish++
	r.mu.Unlock()
	return message.NewSessionEstablishmentResponse(0, 0, 0x1122, 4242, 0, ie.NewCause(ie.CauseRequestAccepted))
}

func (r *recorder) Modify(*message.SessionModificationRequest) message.Message {
	r.mu.Lock()
	r.modify++
	r.mu.Unlock()
	return message.NewSessionModificationResponse(0, 0, 0x1122, 4242, 0, ie.NewCause(ie.CauseRequestAccepted))
}

func (r *recorder) Delete(*message.SessionDeletionRequest) message.Message {
	r.mu.Lock()
	r.delete++
	r.mu.Unlock()
	return message.NewSessionDeletionResponse(0, 0, 0x1122, 4242, 0, ie.NewCause(ie.CauseRequestAccepted))
}

func (r *recorder) AssociationEnded(reason string) { r.ended <- reason }

func startServer(t *testing.T, cfg n4.Config) (*n4.Server, *net.UDPAddr) {
	t.Helper()
	cfg.Listen = "127.0.0.1:0"
	if cfg.NodeID == "" {
		cfg.NodeID = upfID
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	srv, err := n4.New(cfg)
	if err != nil {
		t.Fatalf("n4.New: %v", err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	go func() {
		if err := srv.Serve(); err != nil {
			t.Logf("Serve: %v", err)
		}
	}()
	return srv, srv.Addr().(*net.UDPAddr)
}

func connect(t *testing.T, addr *net.UDPAddr) *net.UDPConn {
	t.Helper()
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func sendMsg(t *testing.T, conn *net.UDPConn, m message.Message) {
	t.Helper()
	b := make([]byte, m.MarshalLen())
	if err := m.MarshalTo(b); err != nil {
		t.Fatalf("marshal %s: %v", m.MessageTypeName(), err)
	}
	if _, err := conn.Write(b); err != nil {
		t.Fatalf("write %s: %v", m.MessageTypeName(), err)
	}
}

func recvMsg(t *testing.T, conn *net.UDPConn, within time.Duration) message.Message {
	t.Helper()
	m := recvMaybe(t, conn, within)
	if m == nil {
		t.Fatalf("no response within %v", within)
	}
	return m
}

// recvMaybe returns the next message, or nil if none arrives in time.
func recvMaybe(t *testing.T, conn *net.UDPConn, within time.Duration) message.Message {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(within)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 65539)
	n, err := conn.Read(buf)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return nil
		}
		t.Fatalf("read: %v", err)
	}
	m, err := message.Parse(buf[:n])
	if err != nil {
		t.Fatalf("parse %d bytes: %v", n, err)
	}
	return m
}

// drain discards the messages already on the socket, so a later read sees the
// answer to a later request.
func drain(t *testing.T, conn *net.UDPConn) {
	t.Helper()
	for recvMaybe(t, conn, 50*time.Millisecond) != nil {
	}
}

func associate(t *testing.T, conn *net.UDPConn, seq uint32, opts ...*ie.IE) *message.AssociationSetupResponse {
	t.Helper()
	ies := []*ie.IE{ie.NewNodeID(smfID, "", "")}
	if len(opts) == 0 {
		ies = append(ies, ie.NewRecoveryTimeStamp(time.Now()))
	} else {
		ies = append(ies, opts...)
	}
	sendMsg(t, conn, message.NewAssociationSetupRequest(seq, ies...))
	resp, ok := recvMsg(t, conn, waitFor).(*message.AssociationSetupResponse)
	if !ok {
		t.Fatalf("no Association Setup Response")
	}
	if cause, err := resp.Cause.Cause(); err != nil || cause != ie.CauseRequestAccepted {
		t.Fatalf("association not accepted: cause=%d err=%v", cause, err)
	}
	return resp
}

func waitEnded(t *testing.T, r *recorder, contains string) string {
	t.Helper()
	select {
	case reason := <-r.ended:
		if !strings.Contains(reason, contains) {
			t.Fatalf("association ended with %q, want %q in it", reason, contains)
		}
		return reason
	case <-time.After(2 * time.Second):
		t.Fatalf("association did not end (%q expected)", contains)
		return ""
	}
}

func TestAssociationAndHeartbeat(t *testing.T) {
	srv, addr := startServer(t, n4.Config{})
	conn := connect(t, addr)

	cpRecovery := time.Now().Add(-time.Minute).Truncate(time.Second)
	setup := associate(t, conn, 7, ie.NewRecoveryTimeStamp(cpRecovery))

	if got := setup.Sequence(); got != 7 {
		t.Fatalf("sequence = %d, want 7", got)
	}
	if id, err := setup.NodeID.NodeID(); err != nil || id != upfID {
		t.Fatalf("Node ID = %q err=%v, want %q", id, err, upfID)
	}
	if setup.RecoveryTimeStamp == nil || setup.UPFunctionFeatures == nil {
		t.Fatalf("response lacks Recovery Time Stamp or UP Function Features")
	}
	features, err := setup.UPFunctionFeatures.UPFunctionFeatures()
	if err != nil || len(features) != 4 {
		t.Fatalf("UP Function Features = %v err=%v", features, err)
	}
	if features[0] != 0 || features[1] != 0 || features[2] != 0 || features[3] != 0 {
		t.Fatalf("UP Function Features advertise %v, and this node implements none of them", features)
	}
	ourRecovery, err := setup.RecoveryTimeStamp.RecoveryTimeStamp()
	if err != nil {
		t.Fatalf("recovery time stamp: %v", err)
	}
	if d := time.Since(ourRecovery); d < 0 || d > time.Minute {
		t.Fatalf("recovery time stamp %v is not this process's start", ourRecovery)
	}

	// The heartbeat response carries the same recovery time stamp: one value
	// per process, as TS 29.244 7.4.1 requires.
	sendMsg(t, conn, message.NewHeartbeatRequest(8, ie.NewRecoveryTimeStamp(cpRecovery), nil))
	hb, ok := recvMsg(t, conn, waitFor).(*message.HeartbeatResponse)
	if !ok {
		t.Fatalf("no Heartbeat Response")
	}
	if hb.Sequence() != 8 {
		t.Fatalf("sequence = %d, want 8", hb.Sequence())
	}
	ts, err := hb.RecoveryTimeStamp.RecoveryTimeStamp()
	if err != nil {
		t.Fatalf("heartbeat recovery time stamp: %v", err)
	}
	if !ts.Equal(ourRecovery) {
		t.Fatalf("recovery time stamp changed: %v then %v", ourRecovery, ts)
	}

	if id, peerAddr, ok := srv.Peer(); !ok || id != smfID || !peerAddr.(*net.UDPAddr).IP.Equal(conn.RemoteAddr().(*net.UDPAddr).IP) {
		t.Fatalf("Peer() = %q %v %v", id, peerAddr, ok)
	}
}

func TestAssociationReleaseEndsSessions(t *testing.T) {
	h := newRecorder()
	srv, addr := startServer(t, n4.Config{Sessions: h})
	conn := connect(t, addr)
	associate(t, conn, 1)

	sendMsg(t, conn, message.NewAssociationReleaseRequest(2, ie.NewNodeID(smfID, "", "")))
	rel, ok := recvMsg(t, conn, waitFor).(*message.AssociationReleaseResponse)
	if !ok {
		t.Fatalf("no Association Release Response")
	}
	if rel.Sequence() != 2 {
		t.Fatalf("sequence = %d, want 2", rel.Sequence())
	}
	if cause, err := rel.Cause.Cause(); err != nil || cause != ie.CauseRequestAccepted {
		t.Fatalf("release not accepted: cause=%d err=%v", cause, err)
	}
	waitEnded(t, h, "released")
	if _, _, ok := srv.Peer(); ok {
		t.Fatalf("association still recorded after release")
	}

	// Without an association, a session request has nothing to belong to.
	sendMsg(t, conn, message.NewSessionEstablishmentRequest(0, 0, 0, 3, 0))
	est, ok := recvMsg(t, conn, waitFor).(*message.SessionEstablishmentResponse)
	if !ok {
		t.Fatalf("no Session Establishment Response")
	}
	if cause, err := est.Cause.Cause(); err != nil || cause != ie.CauseNoEstablishedPFCPAssociation {
		t.Fatalf("cause = %d err=%v, want %d", cause, err, ie.CauseNoEstablishedPFCPAssociation)
	}
	if est.Sequence() != 3 {
		t.Fatalf("sequence = %d, want 3", est.Sequence())
	}
}

func TestSecondCPFunctionIsRejected(t *testing.T) {
	h := newRecorder()
	_, addr := startServer(t, n4.Config{Sessions: h})
	first := connect(t, addr)
	second := connect(t, addr)

	associate(t, first, 1)

	sendMsg(t, second, message.NewAssociationSetupRequest(2,
		ie.NewNodeID("192.0.2.11", "", ""), ie.NewRecoveryTimeStamp(time.Now())))
	resp, ok := recvMsg(t, second, waitFor).(*message.AssociationSetupResponse)
	if !ok {
		t.Fatalf("no Association Setup Response")
	}
	if cause, err := resp.Cause.Cause(); err != nil || cause != ie.CauseRequestRejected {
		t.Fatalf("cause = %d err=%v, want %d", cause, err, ie.CauseRequestRejected)
	}

	// The first association stands: its session requests are dispatched to the
	// session layer, not refused for lack of an association.
	sendMsg(t, first, message.NewSessionEstablishmentRequest(0, 0, 0, 3, 0))
	est, ok := recvMsg(t, first, waitFor).(*message.SessionEstablishmentResponse)
	if !ok {
		t.Fatalf("no Session Establishment Response")
	}
	if cause, _ := est.Cause.Cause(); cause == ie.CauseNoEstablishedPFCPAssociation {
		t.Fatalf("the first CP function lost its association")
	}
	if est.Sequence() != 3 {
		t.Fatalf("sequence = %d, want the request's 3", est.Sequence())
	}
	if n, _, _ := h.counts(); n != 1 {
		t.Fatalf("session layer saw %d establishments, want 1", n)
	}
}

func TestSessionRequestsWithoutSessionLayer(t *testing.T) {
	_, addr := startServer(t, n4.Config{})
	conn := connect(t, addr)
	associate(t, conn, 1)

	sendMsg(t, conn, message.NewSessionEstablishmentRequest(0, 0, 0, 2, 0))
	est, ok := recvMsg(t, conn, waitFor).(*message.SessionEstablishmentResponse)
	if !ok {
		t.Fatalf("no Session Establishment Response")
	}
	if cause, err := est.Cause.Cause(); err != nil || cause != ie.CauseRequestRejected {
		t.Fatalf("cause = %d err=%v, want %d", cause, err, ie.CauseRequestRejected)
	}
}

func TestHeartbeatInitiatorKeepsAssociationAlive(t *testing.T) {
	h := newRecorder()
	srv, addr := startServer(t, n4.Config{
		Sessions:         h,
		HeartbeatEvery:   40 * time.Millisecond,
		HeartbeatTimeout: 30 * time.Millisecond,
		HeartbeatRetries: 2,
	})
	conn := connect(t, addr)
	associate(t, conn, 1)

	// Answer every request for three intervals: the association must stand.
	requests := 0
	deadline := time.Now().Add(250 * time.Millisecond)
	for time.Now().Before(deadline) {
		m := recvMaybe(t, conn, 20*time.Millisecond)
		if m == nil {
			continue
		}
		req, ok := m.(*message.HeartbeatRequest)
		if !ok {
			t.Fatalf("got %s, want a Heartbeat Request", m.MessageTypeName())
		}
		if req.RecoveryTimeStamp == nil {
			t.Fatalf("heartbeat request without a recovery time stamp")
		}
		requests++
		sendMsg(t, conn, message.NewHeartbeatResponse(req.Sequence(), ie.NewRecoveryTimeStamp(time.Now())))
	}
	if requests == 0 {
		t.Fatalf("no heartbeat request while the association was idle")
	}
	select {
	case reason := <-h.ended:
		t.Fatalf("association ended while heartbeats were answered: %s", reason)
	default:
	}
	if _, _, ok := srv.Peer(); !ok {
		t.Fatalf("association lost while heartbeats were answered")
	}
}

func TestHeartbeatTimeoutEndsAssociation(t *testing.T) {
	h := newRecorder()
	srv, addr := startServer(t, n4.Config{
		Sessions:         h,
		HeartbeatEvery:   30 * time.Millisecond,
		HeartbeatTimeout: 20 * time.Millisecond,
		HeartbeatRetries: 2,
	})
	conn := connect(t, addr)
	associate(t, conn, 1)

	// The peer stays silent: the association must be given up on.
	waitEnded(t, h, "heartbeat")
	if _, _, ok := srv.Peer(); ok {
		t.Fatalf("association still recorded after the heartbeat timeout")
	}
	drain(t, conn) // the unanswered Heartbeat Requests
	sendMsg(t, conn, message.NewSessionEstablishmentRequest(0, 0, 0, 9, 0))
	est, ok := recvMsg(t, conn, waitFor).(*message.SessionEstablishmentResponse)
	if !ok {
		t.Fatalf("no Session Establishment Response")
	}
	if cause, _ := est.Cause.Cause(); cause != ie.CauseNoEstablishedPFCPAssociation {
		t.Fatalf("cause = %d, want %d", cause, ie.CauseNoEstablishedPFCPAssociation)
	}
}

func TestCPRestartVoidsAssociation(t *testing.T) {
	h := newRecorder()
	srv, addr := startServer(t, n4.Config{Sessions: h})
	conn := connect(t, addr)
	associate(t, conn, 1)

	// The same CP function, but a new process: its recovery time stamp moved
	// ahead of the one it associated with (TS 29.244 7.4.1).
	sendMsg(t, conn, message.NewHeartbeatRequest(2, ie.NewRecoveryTimeStamp(time.Now().Add(time.Hour)), nil))
	if m := recvMsg(t, conn, waitFor); m.MessageType() != message.MsgTypeHeartbeatResponse {
		t.Fatalf("got %s, want a Heartbeat Response", m.MessageTypeName())
	}
	waitEnded(t, h, "restarted")
	if _, _, ok := srv.Peer(); ok {
		t.Fatalf("association still recorded after a CP function restart")
	}
}

func TestVersionNotSupported(t *testing.T) {
	_, addr := startServer(t, n4.Config{})
	conn := connect(t, addr)

	m := message.NewAssociationSetupRequest(5, ie.NewNodeID(smfID, "", ""))
	b := make([]byte, m.MarshalLen())
	if err := m.MarshalTo(b); err != nil {
		t.Fatalf("marshal: %v", err)
	}
	b[0] = 2<<5 | (b[0] & 0x1f) // claim version 2
	if _, err := conn.Write(b); err != nil {
		t.Fatalf("write: %v", err)
	}

	resp := recvMsg(t, conn, waitFor)
	if resp.MessageType() != message.MsgTypeVersionNotSupportedResponse {
		t.Fatalf("got %s, want a Version Not Supported Response", resp.MessageTypeName())
	}
	if resp.Sequence() != 5 {
		t.Fatalf("sequence = %d, want the request's 5", resp.Sequence())
	}
}

func TestMalformedDatagramIgnored(t *testing.T) {
	_, addr := startServer(t, n4.Config{})
	conn := connect(t, addr)

	if _, err := conn.Write([]byte{0x20, 0x01, 0x00}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if m := recvMaybe(t, conn, 100*time.Millisecond); m != nil {
		t.Fatalf("answered a malformed datagram with %s", m.MessageTypeName())
	}

	// The socket is still serving.
	sendMsg(t, conn, message.NewHeartbeatRequest(1, ie.NewRecoveryTimeStamp(time.Now()), nil))
	if m := recvMsg(t, conn, waitFor); m.MessageType() != message.MsgTypeHeartbeatResponse {
		t.Fatalf("got %s, want a Heartbeat Response", m.MessageTypeName())
	}
}

func TestUnimplementedMessageTypesAreIgnored(t *testing.T) {
	_, addr := startServer(t, n4.Config{})
	conn := connect(t, addr)
	associate(t, conn, 1)

	// Node Report is not implemented: answer nothing, stay serving.
	sendMsg(t, conn, message.NewNodeReportRequest(2, ie.NewNodeID(smfID, "", ""), ie.NewNodeReportType(0)))
	if m := recvMaybe(t, conn, 100*time.Millisecond); m != nil {
		t.Fatalf("answered a Node Report Request with %s", m.MessageTypeName())
	}
	sendMsg(t, conn, message.NewHeartbeatRequest(3, ie.NewRecoveryTimeStamp(time.Now()), nil))
	if m := recvMsg(t, conn, waitFor); m.MessageType() != message.MsgTypeHeartbeatResponse {
		t.Fatalf("got %s, want a Heartbeat Response", m.MessageTypeName())
	}
}
