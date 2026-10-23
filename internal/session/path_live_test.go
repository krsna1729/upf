// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/bess"
	"github.com/krsna1729/upf/internal/routing"
)

// The two TEIDs the lab graph's frames name. An SMF assigns the F-TEID of the
// uplink PDR (the TEID the UPF listens on) and the gNB's TEID for the downlink
// outer header; a session established with the helper above leaves both to the
// UPF, which allocates them -- deterministic only if the test is the first
// session of the daemon. Pinning them here is what lets a *graph* name them in
// a frame template, so this test can use the two frames ci/session-path.sh
// deploys.
const (
	pathUpTEID   = 0x11223344 // the TEID the graph's G-PDU carries
	pathDownTEID = 0x55667788 // the TEID the graph's encap must write
	// pathUpTEID2 is the second uplink stream's tunnel: the same UE packet, a
	// different instance's session (deploy/session-path.yaml's src_up2).
	pathUpTEID2 = 0x11223345
)

// pathEstablishment is establishment() with those two TEIDs pinned and the UE
// address the graph's frames carry (10.45.0.2, whose packet is
// 10.45.0.2:5000 -> 8.8.8.8:53).
func pathEstablishment(cpSEID uint64, ueIP string) *message.SessionEstablishmentRequest {
	return pathEstablishmentWithSDF(cpSEID, ueIP, "permit out udp from any to assigned 53")
}

// pathEstablishmentWithSDF is pathEstablishment with the downlink PDR's filter
// spelled out: the frames are fixed, so a test about a filter's shape (a prefix,
// for instance) must choose one the frames still match.
func pathEstablishmentWithSDF(cpSEID uint64, ueIP string, sdf string) *message.SessionEstablishmentRequest {
	return pathEstablishmentWith(cpSEID, ueIP, sdf, ie.NewCreateFAR(
		ie.NewFARID(2),
		ie.NewApplyAction(applyForw),
		ie.NewForwardingParameters(
			ie.NewDestinationInterface(ie.DstInterfaceAccess),
			ie.NewOuterHeaderCreation(0x0100, pathDownTEID, "10.20.30.2", "", 0, 0, 0),
		),
	))
}

// pathEstablishmentWith is the same session with the downlink FAR (and anything
// else a case needs) supplied by the caller: the uplink half, the UE address and
// the filter stay fixed, so a test varies exactly what it is about.
func pathEstablishmentWith(cpSEID uint64, ueIP, sdf string,
	downFAR *ie.IE, extra ...*ie.IE) *message.SessionEstablishmentRequest {
	ies := []*ie.IE{
		ie.NewNodeID("", "", "smf"),
		ie.NewFSEID(cpSEID, nil, nil),
		ie.NewCreatePDR(
			ie.NewPDRID(1),
			ie.NewPrecedence(100),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, pathUpTEID, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, ueIP, "", 0, 0),
			),
			ie.NewFARID(1),
			ie.NewQERID(1),
		),
		ie.NewCreatePDR(
			ie.NewPDRID(2),
			ie.NewPrecedence(100),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x06, ueIP, "", 0, 0),
				ie.NewSDFFilter(sdf, "", "", "", 0),
			),
			ie.NewFARID(2),
		),
		ie.NewCreateFAR(
			ie.NewFARID(1),
			ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore)),
		),
		downFAR,
		ie.NewCreateQER(
			ie.NewQERID(1),
			ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
			ie.NewMBR(1000, 2000),
		),
	}
	return message.NewSessionEstablishmentRequest(0, 0, cpSEID, 1, 0, append(ies, extra...)...)
}

// TestLiveSessionCarriesPackets is the packet-path proof: a session programmed
// over the control plane makes deploy/session-path.yaml carry packets in both
// directions. The graph's two Sources run from the moment it is applied, so the
// counters where each chain leaves the UPF are the evidence -- zero before the
// session exists (F-TEID admission misses go to gate 2, outside the PDR chains),
// non-zero after:
//
//   - the uplink's counter is the router's output: ingress admitted and
//     decapsulated the tunnel, the PDR rule matched the UE's packet, its
//     action selected the next hop, the meter passed it and the router found
//     the N6 route.
//   - the downlink's is the encap's output: the PDR rule matched the data
//     network's answer, its action selected the tunnel record, the meter passed
//     it and the encap wrote the outer headers from that record.
//
// The counter is the *output* gate's: a connection's Track hook is installed on
// the upstream module's ogate, so a Sink -- a module with no output gate at all
// -- appears in no metric (control_v2.ListMetrics).
//
// ci/session-path.sh starts the daemon with the plugin, applies that graph and
// runs this test with UPF_BESS_TARGET set, then checks the frames themselves in
// the daemon's log (the Dumps in the graph).
func TestLiveSessionCarriesPackets(t *testing.T) {
	carriesPackets(t, pathEstablishment(0x2222, "10.45.0.2"), true)
}

// TestLiveSessionCarriesPacketsWithAnSDFPrefix is the same proof with the
// downlink PDR's filter naming a prefix (10.45.0.0/16) instead of the UE's
// address: the frames are the same, the rule is a masked one, and the packets
// must still cross -- which is what says the classifier honours the mask rather
// than the prefix's network address alone.
func TestLiveSessionCarriesPacketsWithAnSDFPrefix(t *testing.T) {
	carriesPackets(t, pathEstablishmentWithSDF(0x3333, "10.45.0.2",
		"permit out udp from any to 10.45.0.0/16 53"), false)
}

// TestLiveSessionCarriesPacketsWithAPortRange: the downlink filter names a
// port range around the frames' destination port (53) instead of the port, so
// the rule is a WildcardMatch range on that field (BESS D-186) and the packets
// must still cross.
func TestLiveSessionCarriesPacketsWithAPortRange(t *testing.T) {
	carriesPackets(t, pathEstablishmentWithSDF(0x3334, "10.45.0.2",
		"permit out udp from any to 10.45.0.0/16 50-60"), false)
}

// TestLiveSessionCarriesNothingOutsideAPortRange is the range's other edge: a
// range that stops one port short of the frames' 53 (54-60) must select none of
// them. Without it, a range compiled to a masked-out field would pass the arm
// above while matching every port.
func TestLiveSessionCarriesNothingOutsideAPortRange(t *testing.T) {
	target := os.Getenv("UPF_BESS_TARGET")
	if target == "" {
		t.Skip("set UPF_BESS_TARGET (ci/session-path.sh does) to run against a live bessd")
	}
	ctx := context.Background()
	client, err := bess.Dial(ctx, target)
	if err != nil {
		t.Fatalf("dialing %s: %v", target, err)
	}
	defer client.Close()
	if err := client.Refresh(ctx); err != nil {
		t.Fatalf("reading the daemon's schema: %v", err)
	}
	c := New(liveConfig(), client, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))

	resp := c.Establish(pathEstablishmentWithSDF(0x3335, "10.45.0.2",
		"permit out udp from any to 10.45.0.0/16 54-60")).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the daemon refused the establishment with cause %d", got)
	}
	defer func() {
		del := message.NewSessionDeletionRequest(0, 0, upFSEID(t, resp), 9, 0)
		if got := cause(t, c.Delete(del)); got != ie.CauseRequestAccepted {
			t.Errorf("the deletion answered cause %d", got)
		}
	}()
	// The uplink is not constrained by the downlink filter: its packets
	// crossing is what says the session reached the packet path at all.
	waitForPackets(t, ctx, client, "rt", 10*time.Second)
	before := gatePackets(t, ctx, client, "enc")
	time.Sleep(time.Second)
	if n := gatePackets(t, ctx, client, "enc") - before; n != 0 {
		t.Errorf("a range of 54-60 let %v downlink packets to port 53 through", n)
	}
}

// carriesPackets establishes one session and waits for both chains to carry
// packets. controlArm belongs to the daemon's first session: it is the reading
// that makes the later counts evidence (the sources run from the moment the
// graph is applied, so a zero is absent state, not absent traffic), and it can
// only be taken before any session has existed.
func carriesPackets(t *testing.T, req *message.SessionEstablishmentRequest, controlArm bool) {
	t.Helper()
	target := os.Getenv("UPF_BESS_TARGET")
	if target == "" {
		t.Skip("set UPF_BESS_TARGET (ci/session-path.sh does) to run against a live bessd")
	}

	ctx := context.Background()
	client, err := bess.Dial(ctx, target)
	if err != nil {
		t.Fatalf("dialing %s: %v", target, err)
	}
	defer client.Close()
	if err := client.Refresh(ctx); err != nil {
		t.Fatalf("reading the daemon's schema: %v", err)
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	c := New(liveConfig(), client, log)

	if controlArm {
		for _, module := range []string{"rt", "enc"} {
			if n := gatePackets(t, ctx, client, module); n != 0 {
				t.Fatalf("%s already emitted %v packets before any session existed", module, n)
			}
		}
	}

	resp := c.Establish(req).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the daemon refused the establishment with cause %d", got)
	}
	t.Logf("established SEID %d, uplink TEID %#x, downlink TEID %#x", upFSEID(t, resp), pathUpTEID, pathDownTEID)
	defer func() {
		del := message.NewSessionDeletionRequest(0, 0, upFSEID(t, resp), 9, 0)
		if got := cause(t, c.Delete(del)); got != ie.CauseRequestAccepted {
			t.Errorf("the deletion answered cause %d", got)
		}
	}()

	up := waitForPackets(t, ctx, client, "rt", 10*time.Second)
	down := waitForPackets(t, ctx, client, "enc", 10*time.Second)
	t.Logf("uplink packets leaving toward N6: %v, downlink packets leaving toward N3: %v", up, down)
	if up == 0 || down == 0 {
		t.Errorf("a direction carried nothing: up %v, down %v", up, down)
	}
}

// TestLiveSessionSharedRecords is the shape a real SMF sends when it programs
// several uplink filters onto one tunnel: two uplink PDRs sharing one F-TEID and
// one QER, then a Modify that removes one of them. Both halves are where the
// the engine's transaction rules bite -- two PDRs share one F-TEID admission
// entry, and removing one must not erase a key the same transaction retains.
// The recorder used by unit tests accepts anything, so this live daemon check
// verifies the transaction engine rejects duplicate operations on one
// (resource, key) (`core/dataplane/transaction_engine.cc`).
func TestLiveSessionSharedRecords(t *testing.T) {
	target := os.Getenv("UPF_BESS_TARGET")
	if target == "" {
		t.Skip("set UPF_BESS_TARGET (ci/session-path.sh does) to run against a live bessd")
	}
	ctx := context.Background()
	client, err := bess.Dial(ctx, target)
	if err != nil {
		t.Fatalf("dialing %s: %v", target, err)
	}
	defer client.Close()
	if err := client.Refresh(ctx); err != nil {
		t.Fatalf("reading the daemon's schema: %v", err)
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	c := New(liveConfig(), client, log)

	// A TEID the graph's own frames do not use: this test carries no packets,
	// it only asks the daemon to take the change lists.
	req := sharedFTEIDEstablishment(0x7770, "10.45.0.3", 0x12340000)
	resp := c.Establish(req).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the daemon refused the establishment with cause %d", got)
	}
	defer func() {
		del := message.NewSessionDeletionRequest(0, 0, upFSEID(t, resp), 9, 0)
		if got := cause(t, c.Delete(del)); got != ie.CauseRequestAccepted {
			t.Errorf("the deletion answered cause %d", got)
		}
	}()
	t.Logf("established SEID %d with two uplink PDRs on one F-TEID", upFSEID(t, resp))

	// The shared admission entry must survive removing PDR 1 while PDR 2 still
	// names the same F-TEID. Removing PDR 2 then leaves no user of the key, so
	// the entry is erased.
	mod := message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 2, 0,
		ie.NewRemovePDR(ie.NewPDRID(1)),
	)
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the daemon refused the removal of the F-TEID's PDR with cause %d", got)
	}
	t.Logf("removed PDR 1; PDR 2 retained the shared admission entry")

	mod = message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 3, 0,
		ie.NewRemovePDR(ie.NewPDRID(2)),
	)
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the daemon refused removal of the last F-TEID PDR with cause %d", got)
	}
	t.Logf("removed PDR 2; the session released the admission entry")
}

// gatePackets is the packets a module's output gate has counted, from the
// daemon's own metrics (control_v2.ListMetrics): "bess_gate_packets_total" with
// the module's name, direction "out" and gate 0 -- the single chain each table
// in this graph has.
func gatePackets(t *testing.T, ctx context.Context, client *bess.Client, module string) float64 {
	t.Helper()
	return gatePacketsAt(t, ctx, client, module, "0")
}

// gatePacketsAt is gatePackets for a chosen output gate: a graph whose chains
// fan out (the router's two exits) is read by which gate carried what.
func gatePacketsAt(t *testing.T, ctx context.Context, client *bess.Client, module, gate string) float64 {
	t.Helper()
	samples, err := client.SDK().Metrics(ctx)
	if err != nil {
		t.Fatalf("reading metrics: %v", err)
	}
	var have []string
	for _, s := range samples {
		labels := s.GetLabels()
		if s.GetName() != "bess_gate_packets_total" {
			continue
		}
		have = append(have, labels["module"]+"/"+labels["direction"]+"/g"+labels["gate"]+"="+
			strconv.FormatFloat(s.GetValue(), 'f', 0, 64))
		if labels["module"] == module && labels["direction"] == "out" && labels["gate"] == gate {
			return s.GetValue()
		}
	}
	t.Fatalf("the daemon reports no output counter for module %q gate %s; it reports %v", module, gate, have)
	return 0
}

// waitForPackets waits until the module's output gate has counted a packet, or
// fails with what that means: the source is running whether or not a session
// exists, so a chain that never counts is a rule, an action, a meter, a route
// or a tunnel record that did not reach the packet path.
func waitForPackets(t *testing.T, ctx context.Context, client *bess.Client, module string, within time.Duration) float64 {
	t.Helper()
	// The counters are cumulative: a test that is not the daemon's first (the
	// prefix arm) judges its session by growth, so the baseline is taken here.
	before := gatePackets(t, ctx, client, module)
	deadline := time.Now().Add(within)
	for {
		if n := gatePackets(t, ctx, client, module); n > before {
			return n - before
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s emitted no packet within %s: the graph's source runs continuously, "+
				"so the session's state did not reach the packet path; output counters: %v",
				module, within, chainCounters(t, ctx, client))
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// pathUrrEstablishment is pathEstablishment with the URR given measuring the
// uplink PDR, and a QER that polices nothing: the meter would drop all but a
// trickle of the source's packets, and the counting module sits behind it, so a
// rate here would make the numbers a function of the meter rather than of the
// packets the source produced.
func pathUrrEstablishment(cpSEID uint64, ueIP string, urr *ie.IE) *message.SessionEstablishmentRequest {
	return message.NewSessionEstablishmentRequest(0, 0, cpSEID, 1, 0,
		ie.NewNodeID("", "", "smf"),
		ie.NewFSEID(cpSEID, nil, nil),
		ie.NewCreatePDR(
			ie.NewPDRID(1),
			ie.NewPrecedence(100),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, pathUpTEID, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, ueIP, "", 0, 0),
			),
			ie.NewFARID(1),
			ie.NewURRID(7),
		),
		ie.NewCreatePDR(
			ie.NewPDRID(2),
			ie.NewPrecedence(100),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x06, ueIP, "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to assigned 53", "", "", "", 0),
			),
			ie.NewFARID(2),
		),
		ie.NewCreateFAR(
			ie.NewFARID(1),
			ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore)),
		),
		ie.NewCreateFAR(
			ie.NewFARID(2),
			ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceAccess),
				ie.NewOuterHeaderCreation(0x0100, pathDownTEID, "10.20.30.2", "", 0, 0, 0),
			),
		),
		// A gate and nothing else: no MBR, so no meter stands between the rule
		// and the counting module.
		ie.NewCreateQER(
			ie.NewQERID(1),
			ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
		),
		urr,
	)
}

// TestLiveQuotaEvaluationStopsTheTraffic is the reporting path on a real
// daemon, end to end: the compiler's URR is measured by the graph's counting
// module, Evaluate reads that module's own command, the quota the test
// provisioned is spent, and the packet path stops carrying the session's
// traffic -- which is what the counter says, and what the meter's own gate
// counter says (it keeps rising before the evaluation and stands still after
// it, while the graph's source runs on).
func TestLiveQuotaEvaluationStopsTheTraffic(t *testing.T) {
	target := os.Getenv("UPF_BESS_TARGET")
	if target == "" {
		t.Skip("set UPF_BESS_TARGET (ci/session-path.sh does) to run against a live bessd")
	}

	ctx := context.Background()
	client, err := bess.Dial(ctx, target)
	if err != nil {
		t.Fatalf("dialing %s: %v", target, err)
	}
	defer client.Close()
	if err := client.Refresh(ctx); err != nil {
		t.Fatalf("reading the daemon's schema: %v", err)
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	c := New(liveConfig(), client, log)

	// A quota the source spends in a moment: ten of its packets, each 37 octets
	// of IP. The count below waits for the module to hold that much, so the
	// quota is spent before it is evaluated rather than at some other moment.
	const quota = 370
	resp := c.Establish(pathUrrEstablishment(0x5555, "10.45.0.2", ie.NewCreateURR(
		ie.NewURRID(7),
		ie.NewMeasurementMethod(0, 1, 0),    // VOLUM
		ie.NewReportingTriggers(0x00, 0x01), // VOLQU
		ie.NewVolumeQuota(0x01, quota, 0, 0),
	))).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the daemon refused the establishment with cause %d", got)
	}
	defer func() {
		del := message.NewSessionDeletionRequest(0, 0, upFSEID(t, resp), 9, 0)
		if got := cause(t, c.Delete(del)); got != ie.CauseRequestAccepted {
			t.Errorf("the deletion answered cause %d", got)
		}
	}()

	// The first reading is the window's base -- and reports nothing -- so the
	// quota is spent by the traffic after it.
	var counted uint64
	baseline := time.Now()
	if reports := evaluateAt(t, c, upFSEID(t, resp), baseline); len(reports) != 0 {
		t.Fatalf("the baseline reading returned %+v, want none", reports)
	}
	// Wait for the counter to grow past the quota: the reading the baseline
	// took is this one, so a growth of the quota (plus a margin, since the
	// baseline's own reading happens between the two samples) is what the next
	// evaluation reports.
	start := octetsOf(t, ctx, client, "cnt_ul")
	deadline := time.Now().Add(10 * time.Second)
	for octetsOf(t, ctx, client, "cnt_ul") < start+4*quota {
		if time.Now().After(deadline) {
			t.Fatalf("the counter did not grow past the quota within 10s: %d octets", octetsOf(t, ctx, client, "cnt_ul"))
		}
		time.Sleep(20 * time.Millisecond)
	}
	counted = octetsOf(t, ctx, client, "cnt_ul")

	reports, err := c.Evaluate(ctx, upFSEID(t, resp), time.Now())
	if err != nil {
		t.Fatalf("evaluating the session's usage: %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("evaluation returned %d reports, want one for the spent quota (%v octets counted)", len(reports), counted)
	}
	report := reports[0]
	if report.Trigger != TriggerVolumeQuota || !report.Enforcing {
		t.Errorf("the report is %v (enforcing %v), want an enforcing volume-quota report",
			report.Trigger, report.Enforcing)
	}
	if report.Up.Octets < quota {
		t.Errorf("the report says %d uplink octets, less than the %d it reports spent",
			report.Up.Octets, quota)
	}

	// The enforcement reached the packet path: over the same interval the
	// source keeps producing and the meter sees nothing.
	produced := gatePackets(t, ctx, client, "src_up")
	forwarded := gatePackets(t, ctx, client, "mt_ul")
	time.Sleep(500 * time.Millisecond)
	producedAfter := gatePackets(t, ctx, client, "src_up")
	forwardedAfter := gatePackets(t, ctx, client, "mt_ul")
	if producedAfter == produced {
		t.Fatalf("the graph's source stopped producing (%v packets): this test says nothing about the drop", produced)
	}
	if forwardedAfter != forwarded {
		t.Errorf("after the quota ran out %v more packets reached the meter; "+
			"the PDRs that name the URR must drop (source produced %v in the same interval)",
			forwardedAfter-forwarded, producedAfter-produced)
	}
	t.Logf("the report: %d packets, %d octets, trigger %v; the source produced %v packets "+
		"after the enforcement and the meter saw none",
		report.Up.Packets, report.Up.Octets, report.Trigger, producedAfter-produced)
}

// evaluateAt is Evaluate at a chosen instant: the live arm of the reporting
// decision, so a failure prints what the model decided rather than only that the
// packet path stood still.
func evaluateAt(t *testing.T, c *Compiler, seid uint64, now time.Time) []Report {
	t.Helper()
	reports, err := c.Evaluate(context.Background(), seid, now)
	if err != nil {
		t.Fatalf("evaluating the session's usage: %v", err)
	}
	return reports
}

// octetsOf is one counting module's octets for the single rule it measures: the
// live test's own reading, independent of the compiler's.
func octetsOf(t *testing.T, ctx context.Context, client *bess.Client, module string) uint64 {
	t.Helper()
	var total uint64
	for _, count := range countersOf(t, ctx, client, module) {
		total += count[1]
	}
	return total
}

// countersOf is one counting module's reading of every rule it measures, asked
// through the module's own command -- the call the reporting task makes. The
// argument and the answer are built from the daemon's schema, so a field the
// module does not declare fails here rather than reporting zero.
func countersOf(t *testing.T, ctx context.Context, client *bess.Client, module string) map[uint32][2]uint64 {
	t.Helper()
	arg, err := client.Message("upf.pb.UrrCountCommandGetCountsArg", nil)
	if err != nil {
		t.Fatalf("building the %s command argument: %v", module, err)
	}
	result, err := client.SDK().InvokeAction(ctx, module, "get_counts", arg)
	if err != nil {
		t.Fatalf("%s get_counts: %v", module, err)
	}
	response, err := client.Message("upf.pb.UrrCountCommandGetCountsResponse", nil)
	if err != nil {
		t.Fatalf("building the %s answer: %v", module, err)
	}
	if err := result.UnmarshalTo(response); err != nil {
		t.Fatalf("%s get_counts answered %s: %v", module, result.GetTypeUrl(), err)
	}
	out := map[uint32][2]uint64{}
	fields := response.ProtoReflect().Descriptor().Fields()
	counts := response.ProtoReflect().Get(fields.ByName("counts")).List()
	for i := range counts.Len() {
		count := counts.Get(i).Message()
		f := count.Descriptor().Fields()
		out[uint32(count.Get(f.ByName("action_id")).Uint())] = [2]uint64{
			count.Get(f.ByName("packets")).Uint(),
			count.Get(f.ByName("octets")).Uint(),
		}
	}
	return out
}

// TestLiveSessionCountsTheRulesATURReasures is the counting half of usage
// reporting, on a real daemon: deploy/session-path.yaml's Sources run from the
// moment the graph is applied, the session's uplink PDR is measured by a URR,
// and the module's own command reports what crossed the chain.
//
// The numbers are exact, not approximate: every frame the source produces is
// the same 51-byte frame, and what is counted is the IP packet's octets (the
// inner IPv4 header's Total Length, 37), not the frame's -- so the assertion
// "octets == 37 x packets" is also the one that says the 14-byte Ethernet
// header the framing adds is not data volume. The downlink chain measures
// nothing (no URR names its PDRs), and reports nothing: the entry is what makes
// a rule counted.
func TestLiveSessionCountsTheRulesATURReasures(t *testing.T) {
	target := os.Getenv("UPF_BESS_TARGET")
	if target == "" {
		t.Skip("set UPF_BESS_TARGET (ci/session-path.sh does) to run against a live bessd")
	}

	ctx := context.Background()
	client, err := bess.Dial(ctx, target)
	if err != nil {
		t.Fatalf("dialing %s: %v", target, err)
	}
	defer client.Close()
	if err := client.Refresh(ctx); err != nil {
		t.Fatalf("reading the daemon's schema: %v", err)
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	c := New(liveConfig(), client, log)

	// The run's own clock: the module's packet stamps are absolute times, and
	// they must be this run's -- a stamp before it would be an earlier run's
	// traffic, or an invented instant.
	runStart := time.Now()

	// The control arm: nothing is measured before this session exists, so a
	// later non-zero reading is the session's doing.
	if before := countersOf(t, ctx, client, "cnt_ul"); len(before) != 0 {
		t.Fatalf("cnt_ul already measures %d rules before any session exists: %v", len(before), before)
	}

	resp := c.Establish(pathUrrEstablishment(0x4444, "10.45.0.2", ie.NewCreateURR(
		ie.NewURRID(7),
		ie.NewMeasurementMethod(0, 1, 0),    // VOLUM
		ie.NewReportingTriggers(0x02, 0x00), // VOLTH
		// A threshold no run reaches: this arm is about the counting, and a
		// report would change what the chain carries.
		ie.NewVolumeThreshold(0x01, 1<<40, 0, 0),
	))).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the daemon refused the establishment with cause %d", got)
	}
	defer func() {
		del := message.NewSessionDeletionRequest(0, 0, upFSEID(t, resp), 9, 0)
		if got := cause(t, c.Delete(del)); got != ie.CauseRequestAccepted {
			t.Errorf("the deletion answered cause %d", got)
		}
	}()

	// The source's packets and this reading are not ordered: wait for the
	// counter to move. A run that never does is the module not counting, which
	// is what this test exists to notice.
	//
	// The pair is read until it agrees with itself: the module adds a packet's
	// count and its octets in two steps (urr_count.cc), so a reading taken
	// between them carries a packet whose octets are not in yet -- a torn pair
	// that the next reading resolves, not a counter that lost a packet. The
	// product below is what this test asserts, and it is only meaningful for a
	// reading that is not torn.
	const innerOctets = 37
	var packets, octets uint64
	deadline := time.Now().Add(10 * time.Second)
	for {
		counts := countersOf(t, ctx, client, "cnt_ul")
		if len(counts) > 1 {
			t.Fatalf("cnt_ul measures %d rules, and the session has one URR on one PDR: %v",
				len(counts), counts)
		}
		for _, count := range counts {
			packets, octets = count[0], count[1]
		}
		if packets != 0 && octets == innerOctets*packets {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the uplink chain carried no packet the URR measures within 10s "+
				"(or its octets never matched its packets: %d octets for %d packets); "+
				"output counters: %v", octets, packets, chainCounters(t, ctx, client))
		}
		time.Sleep(100 * time.Millisecond)
	}

	// The inner IPv4 packet's Total Length: the graph's uplink frame holds
	// 10.45.0.2:5000 -> 8.8.8.8:53 with a 9-byte payload, 20 + 8 + 9. The
	// product is asserted, not a per-packet average: an integer division would
	// hide a mixed run and an off-by-a-header remainder, and this test exists
	// to say the 14-byte Ethernet header is not data volume.
	if octets != innerOctets*packets {
		t.Errorf("the counter reports %d octets for %d packets, want %d -- the inner IP packet "+
			"of each 51-byte frame: the frame's Ethernet header is not data volume",
			octets, packets, innerOctets*packets)
	}
	// The stamps the module keeps for the rule, through the SDK's own reading
	// of them: the module stamps the packet's arrival on its monotonic clock,
	// the reading carries the wall clock at the same instant, and this side
	// places them on the clock an SMF reads (8.2.44, 8.2.45). A zero last stamp
	// for a rule that counted is a report an SMF cannot use.
	measured := countersOf(t, ctx, client, "cnt_ul")
	ids := make([]uint32, 0, len(measured))
	for id := range measured {
		ids = append(ids, id)
	}
	rules, err := client.RuleCounts(ctx, "cnt_ul", ids...)
	if err != nil {
		t.Fatalf("reading cnt_ul with its stamps: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("the reading carries %d rules, want the one the session measures", len(rules))
	}
	rule := rules[0]
	if rule.Last.IsZero() {
		t.Errorf("the reading carries no time for the rule it counted: %+v", rule)
	}
	if rule.Last.Before(runStart) || rule.Last.After(time.Now()) {
		t.Errorf("the rule's last packet is at %v, and this run began at %v: the stamp is not this run's",
			rule.Last, runStart)
	}
	if !rule.First.IsZero() && rule.First.After(rule.Last) {
		t.Errorf("the window's first packet is %v, after its last %v", rule.First, rule.Last)
	}
	t.Logf("cnt_ul times: window first %v, last %v", rule.First, rule.Last)

	if down := countersOf(t, ctx, client, "cnt_dl"); len(down) != 0 {
		t.Errorf("the downlink chain, which no URR measures, counts %d rules: %v", len(down), down)
	}
	t.Logf("cnt_ul: %d packets, %d octets, %d octets per packet", packets, octets, octets/packets)
}

// chainCounters is every output-gate packet counter the daemon reports, so a
// failure says where a packet stopped rather than only that it did.
func chainCounters(t *testing.T, ctx context.Context, client *bess.Client) []string {
	t.Helper()
	samples, err := client.SDK().Metrics(ctx)
	if err != nil {
		t.Fatalf("reading metrics: %v", err)
	}
	var out []string
	for _, s := range samples {
		if s.GetName() != "bess_gate_packets_total" {
			continue
		}
		labels := s.GetLabels()
		if labels["direction"] != "out" {
			continue
		}
		out = append(out, labels["module"]+"/g"+labels["gate"]+"="+
			strconv.FormatFloat(s.GetValue(), 'f', 0, 64))
	}
	sort.Strings(out)
	return out
}

// instancedUplinkEstablishment is one uplink PDR for one network instance: the
// F-TEID the graph's stream carries, the UE's address, and the instance's name
// (TS 29.244 8.2.4) -- what an SMF serving more than one instance sends. The
// FAR forwards toward the data network, so the forward takes the instance's own
// next hop.
func instancedUplinkEstablishment(cpSEID uint64, ueIP string, upTEID uint32, instance string) *message.SessionEstablishmentRequest {
	return message.NewSessionEstablishmentRequest(0, 0, cpSEID, 1, 0,
		ie.NewNodeID("", "", "smf"),
		ie.NewFSEID(cpSEID, nil, nil),
		ie.NewCreatePDR(
			ie.NewPDRID(1),
			ie.NewPrecedence(100),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewNetworkInstance(instance),
				ie.NewFTEID(0x01, upTEID, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, ueIP, "", 0, 0),
			),
			ie.NewFARID(1),
		),
		ie.NewCreateFAR(
			ie.NewFARID(1),
			ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore)),
		),
	)
}

// TestLiveTwoInstancesRouteIndependently is docs/design.md's milestone 4 on a
// real daemon: two sessions for the *same* subscriber address, one per network
// instance, each carrying its own tunnel on N3. The graph
// (deploy/session-instances.yaml, which ci/session-instances.sh deploys) has two
// uplink streams, one per session (TEIDs 0x11223344 and 0x11223345, bursts 32
// and 4), so the router's two output gates say which stream left by which exit:
// the internet session's packets by gate 0, the ims session's by gate 2, which
// is that instance's next hop. The window the exits are measured over is fixed
// once both are moving: a snapshot taken the instant the second stream starts
// says nothing, and the ratio over a window is the streams' own 8 (measured
// 8.00, three runs of 2 s).
//
// The instance is what a deployment classifies each packet's flow by, and on
// the uplink the packet's own tag is the tunnel it arrived on: one UE address
// cannot tell two instances' sessions apart, and before the tunnel was part of
// the rule's key the second session's rule was keyed identically to the first's
// -- one rule, one action, whichever session wrote last.
func TestLiveTwoInstancesRouteIndependently(t *testing.T) {
	target := os.Getenv("UPF_BESS_TARGET")
	if target == "" {
		t.Skip("set UPF_BESS_TARGET (ci/session-path.sh does) to run against a live bessd")
	}
	ctx := context.Background()
	client, err := bess.Dial(ctx, target)
	if err != nil {
		t.Fatalf("dialing %s: %v", target, err)
	}
	defer client.Close()
	if err := client.Refresh(ctx); err != nil {
		t.Fatalf("reading the daemon's schema: %v", err)
	}

	instances, err := routing.New([]routing.Interface{
		{Instance: "internet", Domain: 0, NextHop: 1, Pool: []netip.Prefix{netip.MustParsePrefix("10.45.0.0/16")}},
		{Instance: "ims", Domain: 1, NextHop: 3, Pool: []netip.Prefix{netip.MustParsePrefix("10.45.0.0/16")}},
	}, 2)
	if err != nil {
		t.Fatalf("the graph's two instances: %v", err)
	}
	cfg := liveConfig()
	cfg.Instances = instances
	// deploy/session-instances.yaml's uplink table classifies by the tunnel the
	// packet arrived on (`fteid_context`, the decap's own metadata attribute): that
	// is what tells two instances' sessions with one UE address apart, and the
	// field list here mirrors the manifest's the way every other list does.
	cfg.Up.PDRFields = []Field{SrcIP, DstIP, Proto, SrcPort, DstPort, FTEIDContext, QFI}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	c := New(cfg, client, log)

	// One session per stream, both for 10.45.0.2: the same subscriber address,
	// two instances, two tunnels.
	for _, s := range []struct {
		cpSEID   uint64
		teid     uint32
		instance string
	}{
		{0x3311, pathUpTEID, "internet"},
		{0x3312, pathUpTEID2, "ims"},
	} {
		resp := c.Establish(instancedUplinkEstablishment(s.cpSEID, "10.45.0.2", s.teid, s.instance)).(*message.SessionEstablishmentResponse)
		if got := cause(t, resp); got != ie.CauseRequestAccepted {
			t.Fatalf("the %s session for 10.45.0.2 answered cause %d, want accepted", s.instance, got)
		}
		// The session layer looks a session up by the SEID *it* allocated, which
		// is what the answer's F-SEID carries.
		seid := upFSEID(t, resp)
		t.Logf("established the %s session for 10.45.0.2: SEID %d, uplink TEID %#x", s.instance, seid, s.teid)
		defer func() {
			del := message.NewSessionDeletionRequest(0, 0, seid, 9, 0)
			if got := cause(t, c.Delete(del)); got != ie.CauseRequestAccepted {
				t.Errorf("deleting the %s session answered cause %d", s.instance, got)
			}
		}()
	}

	// Each stream leaves by its own instance's exit, and the two exits' counts
	// say which is which: the streams' bursts differ by 8, so the internet
	// session's gate must outgrow the ims one's. A single rule would send both
	// streams to one gate.
	beforeN6 := gatePacketsAt(t, ctx, client, "rt", "0")
	beforeN9 := gatePacketsAt(t, ctx, client, "rt", "2")
	deadline := time.Now().Add(10 * time.Second)
	var n6, n9 float64
	for {
		n6 = gatePacketsAt(t, ctx, client, "rt", "0") - beforeN6
		n9 = gatePacketsAt(t, ctx, client, "rt", "2") - beforeN9
		if n6 > 0 && n9 > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the two instances' exits carried %v and %v packets in 10s, want both moving: %v",
				n6, n9, chainCounters(t, ctx, client))
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Both exits are moving, so the two streams' own rates can be compared over
	// a fixed window instead of at the instant the second one starts: the
	// streams' bursts differ by 8, and a single rule would send both to one
	// gate, whichever session wrote last.
	window := 2 * time.Second
	startN6, startN9 := n6, n9
	time.Sleep(window)
	winN6 := gatePacketsAt(t, ctx, client, "rt", "0") - beforeN6 - startN6
	winN9 := gatePacketsAt(t, ctx, client, "rt", "2") - beforeN9 - startN9
	if winN6 == 0 || winN9 == 0 {
		t.Fatalf("in %v the exits carried %v and %v packets, want both moving: %v",
			window, winN6, winN9, chainCounters(t, ctx, client))
	}
	t.Logf("in %v: gate 0 carried %v packets, gate 2 %v, ratio %.2f (the streams' bursts differ by 8)",
		window, winN6, winN9, winN6/winN9)
	// The ratio is not itself the proof of separation -- the two rules' keys
	// are -- but it says both streams are flowing and neither is leaking onto
	// the other's exit, which is what a single shared rule would do. Measured
	// 8.00 on three runs of this window.
	if ratio := winN6 / winN9; ratio < 6 || ratio > 10 {
		t.Errorf("the exits carried %v and %v packets in %v (ratio %.2f), want the streams' own 8: one exit per stream",
			winN6, winN9, window, ratio)
	}
}
