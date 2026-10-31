// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
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
	last   []bess.Change
	// rules is the counting modules' own state, by module: the ActionId of
	// every rule whose counter entry the compiler wrote and has not erased.
	// The module holds one entry per measured rule, and a reading that names no
	// rule -- the tick's bulk read -- answers with every one of them
	// (urr_count.cc's get_counts).
	rules map[string][]uint32
}

func (f *fakeDataplane) Apply(_ context.Context, changes ...bess.Change) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.txns++
	f.last = changes
	if f.rules == nil {
		f.rules = map[string][]uint32{}
	}
	for _, ch := range changes {
		if !strings.HasSuffix(ch.Resource, "/counters") {
			continue
		}
		id, ok := ch.Key["action_id"].(uint32)
		if !ok {
			continue
		}
		// By module, the name a reading is addressed to, not the resource.
		module := strings.TrimSuffix(ch.Resource, "/counters")
		if ch.Value == nil {
			f.rules[module] = slices.DeleteFunc(f.rules[module],
				func(held uint32) bool { return held == id })
			continue
		}
		if !slices.Contains(f.rules[module], id) {
			f.rules[module] = append(f.rules[module], id)
		}
	}
	return nil
}

// snapshot is the transaction count and the last transaction, taken under the
// fake's own lock: the loop applies on its own goroutine.
func (f *fakeDataplane) snapshot() (int, []bess.Change) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.txns, f.last
}

// RuleCounts answers every rule asked for with the same totals, whatever
// ActionId the compiler allocated for it: the test's traffic is the traffic of
// the one rule it measures. Naming no rule is the module's own reading of every
// rule it holds, which is the read the reporting tick makes (report.go's
// EvaluateAll).
func (f *fakeDataplane) RuleCounts(_ context.Context, module string, actionIDs ...uint32) ([]bess.RuleCount, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(actionIDs) == 0 {
		actionIDs = f.rules[module]
	}
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
		GTPUDecap: "decap",
		FTEIDEndpoints: []session.FTEIDEndpoint{{
			ID: 1, ReferencePoint: "n3", TransportRouteDomain: 1,
			SourceInterface: ie.SrcInterfaceAccess,
			IPv4:            netip.MustParseAddr("192.0.2.1"),
		}},
		Up: session.Direction{
			PDRTable: "pdr_ul", Meters: "mt_ul", Counters: "cnt_ul",
			PDRFields: []session.Field{session.SrcIP, session.DstIP, session.Proto,
				session.SrcPort, session.DstPort, session.FTEIDContext, session.QFI},
			NextHop: 1,
		},
		Down: session.Direction{
			PDRTable: "pdr_dl", Meters: "mt_dl", Counters: "cnt_dl",
			PDRFields: []session.Field{session.SrcIP, session.DstIP, session.Proto,
				session.SrcPort, session.DstPort, session.RouteDomain, session.FTEIDContext,
				session.QFI},
			NextHop: 2, Tunnels: "enc",
		},
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
				ie.NewUEIPAddress(0x06, "10.45.0.2", "", 0, 0),
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

// periodicEstablishment is reportLoopEstablishment's session with a URR that
// reports on its period instead of a quota: a report is then due on every
// period, which is what the queue's tests need. The URR ID stays the one the PDR
// names, and the period is a whole second because the IE carries seconds
// (go-pfcp's MeasurementPeriod truncates to uint32 seconds).
func periodicEstablishment(seq uint32, cpSEID uint64, period time.Duration) *message.SessionEstablishmentRequest {
	est := reportLoopEstablishment(seq, cpSEID)
	// The typed field, not IEs: go-pfcp's constructor sorts each IE into its own
	// field, and the compiler reads those (message/session-establishment-request.go).
	est.CreateURR = []*ie.IE{ie.NewCreateURR(ie.NewURRID(7),
		ie.NewMeasurementMethod(0, 1, 0),    // VOLUM
		ie.NewReportingTriggers(0x01, 0x00), // PERIO
		ie.NewMeasurementPeriod(period))}
	return est
}

// sentReport is one report the loop asked to send, as the SMF would read it.
type sentReport struct {
	urrID uint32
	seqn  uint32
}

// queueSender is a reportSender that answers as the test tells it and records
// what it was asked to send, and when: the loop's queue and its backoff are
// judged from the reports it sees, identified by their URR and UR-SEQN.
type queueSender struct {
	mu         sync.Mutex
	sent       []sentReport
	at         []time.Time
	unanswered int   // this many calls are left without an answer
	refusal    uint8 // a Cause to answer with instead of accepted
}

func (s *queueSender) Report(_ context.Context, _ uint64, ies ...*ie.IE) (n4.ReportAnswer, error) {
	urr, seqn, err := reportIdentity(ies)
	if err != nil {
		return n4.ReportAnswer{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, sentReport{urrID: urr, seqn: seqn})
	s.at = append(s.at, time.Now())
	if s.unanswered > 0 {
		s.unanswered--
		return n4.ReportAnswer{}, errors.New("no answer from the SMF")
	}
	if s.refusal != 0 {
		return n4.ReportAnswer{Cause: s.refusal}, nil
	}
	return n4.ReportAnswer{Cause: ie.CauseRequestAccepted}, nil
}

func (s *queueSender) snapshot() []sentReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]sentReport(nil), s.sent...)
}

// times is when each send happened, and how many there were.
func (s *queueSender) times() []time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Time(nil), s.at...)
}

// reportIdentity is the URR and the UR-SEQN a report's IEs carry.
func reportIdentity(ies []*ie.IE) (uint32, uint32, error) {
	for _, i := range ies {
		if i.Type != ie.UsageReportWithinSessionReportRequest {
			continue
		}
		children, err := i.UsageReport()
		if err != nil {
			return 0, 0, err
		}
		var urrID, seqn uint32
		for _, c := range children {
			switch c.Type {
			case ie.URRID:
				urrID, err = c.URRID()
			case ie.URSEQN:
				seqn, err = c.URSEQN()
			}
			if err != nil {
				return 0, 0, err
			}
		}
		return urrID, seqn, nil
	}
	return 0, 0, errors.New("no usage report among the IEs")
}

// withUE gives an establishment another UE address and F-TEID: its two PDRs
// carry them, and building the whole session again to change two values would
// duplicate the shape reportLoopEstablishment owns. The typed fields hold the
// PDRs (go-pfcp's constructor sorts them there).
func withUE(est *message.SessionEstablishmentRequest, ue string, teid uint32) *message.SessionEstablishmentRequest {
	for i, p := range est.CreatePDR {
		if len(p.ChildIEs) == 0 || p.ChildIEs[0].Type != ie.PDRID {
			continue
		}
		id, err := p.ChildIEs[0].PDRID()
		if err != nil {
			continue
		}
		switch id {
		case 1:
			est.CreatePDR[i] = ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100),
				ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
					ie.NewFTEID(0x01, teid, net.ParseIP("192.0.2.1"), nil, 0),
					ie.NewUEIPAddress(0x02, ue, "", 0, 0)),
				ie.NewFARID(1), ie.NewURRID(7))
		case 2:
			est.CreatePDR[i] = ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(100),
				ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
					ie.NewUEIPAddress(0x06, ue, "", 0, 0),
					ie.NewSDFFilter("permit out udp from any to assigned 53", "", "", "", 0)),
				ie.NewFARID(2))
		}
	}
	return est
}

// loopSession is the compiler the queue's tests drive: every establishment
// given, over the fake dataplane, with the loop's own graph shape.
func loopSession(t *testing.T, ests ...*message.SessionEstablishmentRequest) *session.Compiler {
	t.Helper()
	compiler := session.New(reportConfig(), &fakeDataplane{},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, est := range ests {
		resp := compiler.Establish(est).(*message.SessionEstablishmentResponse)
		if cause, err := resp.Cause.Cause(); err != nil || cause != ie.CauseRequestAccepted {
			t.Fatalf("the establishment answered cause %d (%v), want accepted", cause, err)
		}
	}
	return compiler
}

// TestAnUnansweredReportIsSentAgainBeforeTheNextOne is the queue's reason to
// exist: a report the SMF did not answer is not lost, it is sent again before
// that session's newer one, and the UR-SEQNs the SMF reads stay in order.
func TestAnUnansweredReportIsSentAgainBeforeTheNextOne(t *testing.T) {
	sender := &queueSender{unanswered: 1}
	compiler := loopSession(t, periodicEstablishment(1, 0x9001, time.Second))
	logs := &logCapture{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go reportLoop(ctx, compiler, sender, 20*time.Millisecond, &reportStats{},
		slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo})))

	waitFor(t, 5*time.Second, func() bool { return len(sender.snapshot()) >= 2 },
		"the loop sent its first two reports", logs.log)
	sent := sender.snapshot()
	if sent[0].seqn != sent[1].seqn {
		t.Errorf("the first two sends were UR-SEQN %d then %d, want the same unanswered report twice",
			sent[0].seqn, sent[1].seqn)
	}
	// Once the SMF answers, the queue drains and the next window's report
	// follows: the UR-SEQNs only ever move forward.
	waitFor(t, 5*time.Second, func() bool {
		s := sender.snapshot()
		return len(s) >= 3 && s[2].seqn > s[0].seqn
	}, "a newer window's report followed the answered one", logs.log)
	waitFor(t, 2*time.Second, func() bool { return logs.contains("held and backed off") },
		"the loop logged the report as held", logs.log)
	if logs.contains("usage report dropped") {
		t.Errorf("a report was dropped with the queue far from full: %s", logs.log())
	}
}

// TestARefusedReportIsNotRetried: a refusal is the SMF's answer -- it reached
// the SMF and was rejected -- so the report goes, unlike one left unanswered.
func TestARefusedReportIsNotRetried(t *testing.T) {
	sender := &queueSender{refusal: ie.CauseSessionContextNotFound}
	compiler := loopSession(t, periodicEstablishment(1, 0x9001, time.Second))
	logs := &logCapture{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go reportLoop(ctx, compiler, sender, 20*time.Millisecond, &reportStats{},
		slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo})))

	waitFor(t, 5*time.Second, func() bool { return logs.contains("usage report refused") },
		"the loop logged the refusal", logs.log)
	// A refusal is the SMF's answer, so the next window's report follows it:
	// every report is sent exactly once, however many the session owes.
	waitFor(t, 10*time.Second, func() bool {
		seen := map[uint32]bool{}
		for _, s := range sender.snapshot() {
			seen[s.seqn] = true
		}
		return len(seen) >= 2
	}, "the loop sent the session's next window after the refusal", logs.log)
	seen := map[uint32]int{}
	for _, s := range sender.snapshot() {
		seen[s.seqn]++
	}
	for seqn, n := range seen {
		if n != 1 {
			t.Errorf("UR-SEQN %d was sent %d times, want once: a refusal is an answer", seqn, n)
		}
	}
}

// TestAReportForASessionTheSMFDeletedIsNotSent is finding 20's other half: a
// report that waited in the queue while the SMF deleted the session is usage
// the deletion's termination report already carried, so it is cancelled rather
// than sent -- an SMF mid-release may take it and count that usage twice (seen
// on free5GC: it accepted one 2 ms after the deletion).
func TestAReportForASessionTheSMFDeletedIsNotSent(t *testing.T) {
	sender := &queueSender{unanswered: 1}
	compiler := loopSession(t, periodicEstablishment(1, 0x9001, time.Second))
	logs := &logCapture{}
	stats := &reportStats{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go reportLoop(ctx, compiler, sender, 20*time.Millisecond, stats,
		slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo})))

	waitFor(t, 5*time.Second, func() bool { return len(sender.snapshot()) >= 1 },
		"the loop sent its first report", logs.log)
	before := len(sender.snapshot())

	// The SMF deletes the session: the report it never answered is now usage
	// the termination report has carried.
	resp := compiler.Delete(message.NewSessionDeletionRequest(0, 0, 1, 2, 0))
	if cause, _ := resp.(*message.SessionDeletionResponse).Cause.Cause(); cause != ie.CauseRequestAccepted {
		t.Fatalf("the deletion answered cause %d, want accepted", cause)
	}
	waitFor(t, 5*time.Second, func() bool { return logs.contains("usage reports cancelled") },
		"the loop cancelled the queued report", logs.log)

	// Five ticks with nothing more for that session: the queue is empty.
	time.Sleep(100 * time.Millisecond)
	if got := len(sender.snapshot()); got != before {
		t.Errorf("the loop sent %d reports after the deletion, want the %d it had already sent", got, before)
	}
	if got := stats.cancelled.Load(); got == 0 {
		t.Error("the cancelled report was not counted")
	}
}

// TestAHeldReportIsRetriedWithBackoff: a CP function that has stopped answering
// must not be sent to at the tick's rate -- every attempt costs the n4 layer's
// retry budget, and the tick also carries the evaluation that enforces every
// session's quota. So the repeats double apart, and the log follows the
// doublings rather than the ticks.
func TestAHeldReportIsRetriedWithBackoff(t *testing.T) {
	sender := &queueSender{unanswered: 1 << 30}
	compiler := loopSession(t, periodicEstablishment(1, 0x9001, time.Second))
	logs := &logCapture{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go reportLoop(ctx, compiler, sender, 5*time.Millisecond, &reportStats{},
		slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo})))

	// The first report is due a period in (1s), so this window holds ~1s of
	// retries: without a backoff that is ~200 sends at a 5ms tick to a peer that
	// has gone silent.
	time.Sleep(2 * time.Second)
	at := sender.times()
	if len(at) < 3 {
		t.Fatalf("the loop made %d attempts in 2s, want the report retried", len(at))
	}
	if len(at) > 16 {
		t.Errorf("a silent SMF was sent to %d times in 2s of 5ms ticks, want the backoff to keep it to the doublings", len(at))
	}
	var gaps []time.Duration
	for i := 1; i < len(at); i++ {
		gaps = append(gaps, at[i].Sub(at[i-1]))
	}
	if last := gaps[len(gaps)-1]; last <= gaps[0] {
		t.Errorf("the retry gaps are %v: they double, so the last must exceed the first", gaps)
	}
	if n := strings.Count(logs.log(), "held and backed off"); n > 8 {
		t.Errorf("%d log lines for one held report, want the first failure and the doublings", n)
	}
}

// TestATickStopsDrainingAfterATransportFailure: the first failed send of a tick
// ends that tick's drain, so the evaluation behind it (every session's windows
// and quotas) runs on time however many sessions are stuck behind a silent peer.
func TestATickStopsDrainingAfterATransportFailure(t *testing.T) {
	sender := &queueSender{unanswered: 1 << 30}
	compiler := loopSession(t,
		periodicEstablishment(1, 0x9001, time.Second),
		// A second session is its own UE address and F-TEID: two sessions for
		// one UE are refused (their PDRs would be ambiguous) and two sessions on
		// one complete F-TEID admission key belongs to one session.
		withUE(periodicEstablishment(2, 0x9002, time.Second), "10.45.0.9", 0x0a0a0a0a))
	logs := &logCapture{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go reportLoop(ctx, compiler, sender, 20*time.Millisecond, &reportStats{},
		slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo})))

	// The reports are due a period in (1s), so this holds about a second of a
	// silent peer with two sessions stuck behind it.
	time.Sleep(2 * time.Second)
	at := sender.times()
	if len(at) < 2 {
		t.Fatalf("two sessions had a report held and the loop made %d attempts in 2s, want more", len(at))
	}
	for i := 1; i < len(at); i++ {
		if gap := at[i].Sub(at[i-1]); gap < 10*time.Millisecond {
			t.Errorf("two sends %v apart: a tick must make one attempt once the peer has gone silent", gap)
		}
	}
}

// TestTheReportQueueIsBoundedPerSession: a CP function that never answers must
// not grow this node's memory without bound, and what does not fit is handed
// back -- the newest, whose decision the session layer can still take back --
// so the loop keeps its usage rather than losing it quietly.
func TestTheReportQueueIsBoundedPerSession(t *testing.T) {
	q := newReportQueue()
	var refused []uint32
	for seqn := uint32(0); seqn < reportQueueDepth+2; seqn++ {
		if d := q.add(session.Report{SEID: 1, URRID: 7, Seqn: seqn}); d != nil {
			refused = append(refused, d.Seqn)
		}
	}
	if len(refused) != 2 || refused[0] != reportQueueDepth || refused[1] != reportQueueDepth+1 {
		t.Errorf("the queue turned away UR-SEQNs %v, want the two newest (%d, %d)",
			refused, reportQueueDepth, reportQueueDepth+1)
	}
	if held := len(q.held[1]); held != reportQueueDepth {
		t.Errorf("the session holds %d reports, want the depth %d", held, reportQueueDepth)
	}
	// The eldest held report is what the SMF is owed first.
	if head, ok := q.head(1); !ok || head.report.Seqn != 0 {
		t.Errorf("the oldest held report is UR-SEQN %d (held %v), want 0", head.report.Seqn, ok)
	}
	q.done(1)
	if head, _ := q.head(1); head.report.Seqn != 1 {
		t.Errorf("after the acknowledgement the oldest is UR-SEQN %d, want 1", head.report.Seqn)
	}
	// An unanswered send is recorded without moving the report, and the next
	// attempt is what the backoff schedules.
	q.sent(1, time.Now(), time.Second)
	if head, _ := q.head(1); head.attempts != 1 {
		t.Errorf("the oldest report has %d attempts after one unanswered send, want 1", head.attempts)
	}
	// The sessions with reports waiting are visited in SEID order, so a session
	// that keeps failing delays only itself.
	q.add(session.Report{SEID: 2, URRID: 7})
	if got := q.seids(); len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Errorf("the queue's sessions are %v, want [1 2]", got)
	}
}

// windowSender is a reportSender that accepts every report and counts what the
// loop sends: the calls, by UR-SEQN, and the most in flight at once. A call
// after the first waits briefly for company, so a loop that pipelines is seen
// doing it and one that sends one at a time is seen not to (the wait is given
// up for good after the first that finds none).
type windowSender struct {
	mu            sync.Mutex
	calls         int
	bySeqn        map[uint32]int
	inFlight, max int
	alone         bool
	company       *sync.Cond
}

func (s *windowSender) Report(_ context.Context, _ uint64, ies ...*ie.IE) (n4.ReportAnswer, error) {
	_, seqn, err := reportIdentity(ies)
	if err != nil {
		return n4.ReportAnswer{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.bySeqn[seqn]++
	s.inFlight++
	s.max = max(s.max, s.inFlight)
	s.company.Broadcast()
	if s.calls > 1 && !s.alone && s.inFlight < 2 {
		timer := time.AfterFunc(time.Second, func() {
			s.mu.Lock()
			s.alone = true
			s.company.Broadcast()
			s.mu.Unlock()
		})
		for s.inFlight < 2 && !s.alone {
			s.company.Wait()
		}
		timer.Stop()
	}
	s.inFlight--
	return n4.ReportAnswer{Cause: ie.CauseRequestAccepted}, nil
}

// TestATickSendsEveryDueReportPipelined is UG-B2: a tick that owes a report to
// every one of 1000 sessions queues all of them -- the queue's bound is per
// session, not 256 sessions -- and sends each once, more than one in flight.
func TestATickSendsEveryDueReportPipelined(t *testing.T) {
	const sessions = 1000
	ests := make([]*message.SessionEstablishmentRequest, 0, sessions)
	for i := range sessions {
		ests = append(ests, withUE(periodicEstablishment(uint32(i+1), 0x9001+uint64(i), time.Second),
			fmt.Sprintf("10.46.%d.%d", i/250, i%250+1), 0x0b000000+uint32(i)))
	}
	compiler := loopSession(t, ests...)
	sender := &windowSender{bySeqn: map[uint32]int{}}
	sender.company = sync.NewCond(&sender.mu)
	stats := &reportStats{}
	logs := &logCapture{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go reportLoop(ctx, compiler, sender, 20*time.Millisecond, stats,
		slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn})))

	// Every session's first window ends on the same tick: each is answered,
	// or dropped by a queue with no room for it.
	waitFor(t, 30*time.Second, func() bool { return stats.sent.Load()+stats.dropped.Load() >= sessions },
		"the tick's reports were sent or dropped", logs.log)
	cancel()
	sender.mu.Lock()
	defer sender.mu.Unlock()
	if got := stats.dropped.Load(); got != 0 {
		t.Errorf("%d of %d due reports were dropped, want none", got, sessions)
	}
	if got := sender.bySeqn[0]; got != sessions {
		t.Errorf("%d first-window reports were sent, want one per session (%d)", got, sessions)
	}
	if sender.max < 2 {
		t.Errorf("at most %d report was in flight, want the drain to pipeline them", sender.max)
	}
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
		message.MsgTypeSessionEstablishmentResponse).(*message.SessionEstablishmentResponse)
	if cause, err := established.Cause.Cause(); err != nil || cause != ie.CauseRequestAccepted {
		t.Fatalf("the session was not accepted: cause=%d err=%v", cause, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go reportLoop(ctx, compiler, srv, 20*time.Millisecond, &reportStats{}, log)

	// The first tick is the window's baseline and reports nothing: a datagram
	// arriving now would be a report for traffic that has not happened.
	if m := readWithin(t, smf, 150*time.Millisecond); m != nil {
		t.Fatalf("the loop sent a %s before any traffic was counted", m.MessageTypeName())
	}

	// The traffic: four times the quota, so the next tick's window holds far
	// more than the session asked to be told about.
	before, _ := dp.snapshot()
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
	// The header names the session the way the SMF knows it: its own F-SEID
	// (0x9001 here), not ours -- a report under the UP F-SEID would be a
	// session the SMF cannot find.
	if report.SEID() != 0x9001 {
		t.Errorf("the report names SEID %#x, want the CP F-SEID 0x9001", report.SEID())
	}
	// And the establishment answer's own header carries the same CP F-SEID: the
	// receiving node's identity for the session is what a response is addressed
	// under (TS 29.244 7.2.2.4.2), which is why the loop has a CP SEID to use.
	if established.SEID() != 0x9001 {
		t.Errorf("the establishment answer names SEID %#x, want the CP F-SEID 0x9001", established.SEID())
	}
	// And the enforcement the report carries reached the dataplane: the uplink
	// PDR's rule comes out as a drop, which is a transaction the fake counted
	// (growth, because the establishment wrote one of its own).
	after, last := dp.snapshot()
	if after <= before {
		t.Errorf("the spent quota wrote no transaction (%d before, %d after)", before, after)
	}
	if !dropRule(last, uplinkRules) {
		t.Errorf("the last transaction does not write the uplink's rule as a drop: %v", last)
	}
}

// uplinkRules is the graph's uplink rule table, as the compiler names it.
const uplinkRules = "pdr_ul/rules"

// dropRule reports whether a transaction writes a rule of that resource with
// the drop gate: DROP_GATE is 8192 (core/gate.h; internal/session's own
// constant), and a rule that drops carries no ActionId with it.
func dropRule(changes []bess.Change, resource string) bool {
	for _, ch := range changes {
		if ch.Resource != resource || ch.Value == nil {
			continue
		}
		if gate, ok := ch.Value["gate"].(uint64); ok && gate == 8192 {
			return true
		}
	}
	return false
}
