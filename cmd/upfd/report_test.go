// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/bess"
	"github.com/krsna1729/upf/internal/n4"
	"github.com/krsna1729/upf/internal/session"
)

// fakeDataplane is the two halves a session needs from bessd without a daemon:
// the transaction sink (the enforcement's drop and every other change is
// counted, not applied) and the counter reading the reporting loop makes.
type fakeDataplane struct {
	mu     sync.Mutex
	octets uint64
	txns   int
}

func (f *fakeDataplane) Apply(_ context.Context, changes ...bess.Change) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.txns += len(changes)
	return nil
}

// RuleCounts answers every rule asked for with the same totals, whatever
// ActionId the compiler allocated for it: the test's traffic is the traffic of
// the one rule it measures.
func (f *fakeDataplane) RuleCounts(_ context.Context, _ string, actionIDs ...uint32) ([]bess.RuleCount, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]bess.RuleCount, 0, len(actionIDs))
	for _, id := range actionIDs {
		out = append(out, bess.RuleCount{ActionID: id, Packets: f.octets / 37, Octets: f.octets})
	}
	return out, nil
}

// spent is the traffic the counters have counted since the test started.
func (f *fakeDataplane) spent(octets uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.octets = octets
}

// logCapture is a slog destination a test can read while the loop writes.
type logCapture struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (l *logCapture) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logCapture) contains(s string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Contains(l.buf.String(), s)
}

// reportConfig is the graph's shape for the loop's test: the module names a
// deployment passes (upfd's own defaults), with the counters this test's URR
// needs.
func reportConfig() session.Config {
	return session.Config{
		TEIDTable: "teid",
		Up: session.Direction{
			PDRTable: "pdr_ul", Actions: "at_ul", Meters: "mt_ul", Counters: "cnt_ul",
			PDRFields: []session.Field{session.SrcIP, session.DstIP, session.Proto,
				session.SrcPort, session.DstPort},
			NextHop: 1,
		},
		Down: session.Direction{
			PDRTable: "pdr_dl", Actions: "at_dl", Meters: "mt_dl", Counters: "cnt_dl",
			PDRFields: []session.Field{session.SrcIP, session.DstIP, session.Proto,
				session.SrcPort, session.DstPort},
			NextHop: 2, Tunnels: "enc",
		},
		N3Addr:  netip.MustParseAddr("192.0.2.1"),
		N3MAC:   [6]byte{2, 0, 0, 0, 0, 1},
		PeerMAC: [6]byte{2, 0, 0, 0, 0, 2},
	}
}

// reportLoopEstablishment is the session a charging SMF sends for this test: the
// two PDRs of a GTP-U session, and a URR on the uplink one whose only trigger
// is its volume quota -- so the only report the session can owe is the quota's.
// (internal/n4's live arm builds the same session; the helpers are not shared
// because one lives in a test binary of its own.)
func reportLoopEstablishment(seq uint32, cpSEID uint64) *message.SessionEstablishmentRequest {
	const forw = 0x02 // Apply Action: FORW (TS 29.244 8.2.26)
	return message.NewSessionEstablishmentRequest(0, 0, cpSEID, seq, 0,
		ie.NewNodeID("", "", "smf.local"),
		ie.NewFSEID(cpSEID, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, 0x11223344, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.2", "", 0, 0)),
			ie.NewFARID(1), ie.NewURRID(7)),
		ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x02, "10.45.0.2", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to assigned 53", "", "", "", 0)),
			ie.NewFARID(2)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(forw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
		ie.NewCreateFAR(ie.NewFARID(2), ie.NewApplyAction(forw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess),
				ie.NewOuterHeaderCreation(0x0100, 0x55667788, "10.20.30.2", "", 0, 0, 0))),
		ie.NewCreateURR(ie.NewURRID(7),
			ie.NewMeasurementMethod(0, 1, 0),    // VOLUM
			ie.NewReportingTriggers(0x00, 0x01), // VOLQU: the quota is the report
			ie.NewVolumeQuota(0x01, 370, 0, 0)),
	)
}

func marshal(t *testing.T, m message.Message) []byte {
	t.Helper()
	b := make([]byte, m.MarshalLen())
	if err := m.MarshalTo(b); err != nil {
		t.Fatalf("marshalling %s: %v", m.MessageTypeName(), err)
	}
	return b
}

// exchange sends a request and returns the answer, which must be the type
// given: the SMF's side of a request-and-answer the node answers.
func exchange(t *testing.T, conn *net.UDPConn, target net.Addr, req message.Message, wantType uint8) message.Message {
	t.Helper()
	if _, err := conn.WriteTo(marshal(t, req), target); err != nil {
		t.Fatalf("sending %s: %v", req.MessageTypeName(), err)
	}
	m := readWithin(t, conn, 2*time.Second)
	if m == nil {
		t.Fatalf("no answer to %s", req.MessageTypeName())
	}
	if m.MessageType() != wantType {
		t.Fatalf("the answer to %s is a %s", req.MessageTypeName(), m.MessageTypeName())
	}
	return m
}

// readWithin is the next datagram, or nil if none arrives in time.
func readWithin(t *testing.T, conn *net.UDPConn, within time.Duration) message.Message {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(within)); err != nil {
		t.Fatalf("setting the read deadline: %v", err)
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
		t.Fatalf("parsing %d bytes: %v", n, err)
	}
	return m
}

// waitFor polls until the condition holds, and fails with the diagnostic when
// it never does.
func waitFor(t *testing.T, within time.Duration, cond func() bool, what string, diag func() string) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s within %v; diagnostics: %s", what, within, diag())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (l *logCapture) log() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// TestReportLoopSendsAReportTheSMFAcknowledges is upfd's reporting loop end to
// end without a daemon: a real n4.Server on a socket, a real session compiled
// against the fake dataplane, and an SMF that receives the Session Report
// Request and answers it. It is the wiring the live arm (ci/session-report.sh)
// needs and nothing else covers: reportLoop ticks, Evaluate decides from the
// counters, Report sends, the SMF's response comes back, and the loop logs the
// acknowledgement.
func TestReportLoopSendsAReportTheSMFAcknowledges(t *testing.T) {
	smf, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listening for the SMF: %v", err)
	}
	defer smf.Close()

	dp := &fakeDataplane{}
	compiler := session.New(reportConfig(), dp, slog.New(slog.NewTextHandler(io.Discard, nil)))
	logs := &logCapture{}
	log := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo}))

	srv, err := n4.New(n4.Config{NodeID: "192.0.2.1", Listen: "127.0.0.1:0", Sessions: compiler, Logger: log})
	if err != nil {
		t.Fatalf("n4.New: %v", err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srv.Close()
	go func() { _ = srv.Serve() }()
	target := srv.Addr()

	// The SMF associates, then establishes the measured session -- the report
	// exists on an association, and the session is what carries a URR.
	exchange(t, smf, target, message.NewAssociationSetupRequest(1,
		ie.NewNodeID("", "", "smf.local"), ie.NewRecoveryTimeStamp(time.Now())),
		message.MsgTypeAssociationSetupResponse)
	established := exchange(t, smf, target, reportLoopEstablishment(2, 0x9001),
		message.MsgTypeSessionEstablishmentResponse)
	if cause, err := established.(*message.SessionEstablishmentResponse).Cause.Cause(); err != nil ||
		cause != ie.CauseRequestAccepted {
		t.Fatalf("the session was not accepted: cause=%d err=%v", cause, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go reportLoop(ctx, compiler, srv, 20*time.Millisecond, log)

	// The first tick is the window's baseline and reports nothing: a datagram
	// arriving now would be a report for traffic that has not happened.
	if m := readWithin(t, smf, 150*time.Millisecond); m != nil {
		t.Fatalf("the loop sent a %s before any traffic was counted", m.MessageTypeName())
	}

	// The traffic: four times the quota, so the next tick's window holds far
	// more than the session asked to be told about.
	dp.spent(4 * 370)
	m := readWithin(t, smf, 5*time.Second)
	if m == nil {
		t.Fatalf("no report within 5s; the loop's log: %s", logs.log())
	}
	report, ok := m.(*message.SessionReportRequest)
	if !ok {
		t.Fatalf("the loop sent a %s, want a Session Report Request", m.MessageTypeName())
	}
	// The SMF's answer: this is the acknowledgement, and the loop's log is
	// where it shows.
	answer := message.NewSessionReportResponse(0, 0, report.SEID(), report.Sequence(), 0,
		ie.NewCause(ie.CauseRequestAccepted))
	if _, err := smf.WriteTo(marshal(t, answer), target); err != nil {
		t.Fatalf("answering the report: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool { return logs.contains("usage report acknowledged") },
		"the loop logged the acknowledgement", logs.log)

	if len(report.UsageReport) != 1 {
		t.Fatalf("the report carries %d usage reports, want one", len(report.UsageReport))
	}
	children, err := report.UsageReport[0].UsageReport()
	if err != nil {
		t.Fatalf("the usage report's IEs: %v", err)
	}
	if id, err := children[0].URRID(); err != nil || id != 7 {
		t.Errorf("the report names URR %d (%v), want 7", id, err)
	}
	// And the enforcement reached the dataplane: the session's PDRs compile to
	// a drop, which is a transaction the fake counted.
	if dp.txns == 0 {
		t.Error("the enforcement wrote nothing to the dataplane")
	}
}
