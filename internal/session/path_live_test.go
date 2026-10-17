// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"context"
	"log/slog"
	"net"
	"os"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/bess"
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
			ie.NewQERID(1),
		),
		ie.NewCreatePDR(
			ie.NewPDRID(2),
			ie.NewPrecedence(100),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x02, ueIP, "", 0, 0),
				ie.NewSDFFilter(sdf, "", "", "", 0),
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
		ie.NewCreateQER(
			ie.NewQERID(1),
			ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
			ie.NewMBR(1000, 2000),
		),
	)
}

// TestLiveSessionCarriesPackets is the packet-path proof: a session programmed
// over the control plane makes deploy/session-path.yaml carry packets in both
// directions. The graph's two Sources run from the moment it is applied, so the
// counters where each chain leaves the UPF are the evidence -- zero before the
// session exists (nothing selects those packets: the TEID table drops the G-PDU
// and the downlink table has no rule), non-zero after:
//
//   - the uplink's counter is the router's output: the TEID rule matched, the
//     decap stripped the tunnel, the PDR rule matched the UE's packet, its
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
	t.Logf("established SEID %d, uplink TEID %#x, downlink TEID %#x", resp.Header.SEID, pathUpTEID, pathDownTEID)
	defer func() {
		del := message.NewSessionDeletionRequest(0, 0, resp.Header.SEID, 9, 0)
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
// engine's transaction rules bite -- one TEID rule named twice by the
// establishment, an erase of a key the same transaction writes by the removal --
// and the recorder the unit tests use takes anything, so this is the only place
// the daemon's verdict is heard (core/dataplane/transaction_engine.cc rejects a
// second operation on one (resource, key) in a transaction).
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
		del := message.NewSessionDeletionRequest(0, 0, resp.Header.SEID, 9, 0)
		if got := cause(t, c.Delete(del)); got != ie.CauseRequestAccepted {
			t.Errorf("the deletion answered cause %d", got)
		}
	}()
	t.Logf("established SEID %d with two uplink PDRs on one F-TEID", resp.Header.SEID)

	// PDR 1 is the one the shared TEID rule was written from (the first PDR, in
	// precedence order), and PDR 2 survives to rewrite it: that is the case
	// where a removal's erase list and a write can name one key in one
	// transaction. Then PDR 2 goes too, which is the case where the session has
	// no user of the TEID left and the rule is erased.
	mod := message.NewSessionModificationRequest(0, 0, resp.Header.SEID, 2, 0,
		ie.NewRemovePDR(ie.NewPDRID(1)),
	)
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the daemon refused the removal of the TEID's PDR with cause %d", got)
	}
	t.Logf("removed PDR 1; PDR 2 rewrote the shared TEID rule in the same transaction")

	mod = message.NewSessionModificationRequest(0, 0, resp.Header.SEID, 3, 0,
		ie.NewRemovePDR(ie.NewPDRID(2)),
	)
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the daemon refused the second removal with cause %d", got)
	}
	t.Logf("removed PDR 2; the session holds no user of the TEID rule now")
}

// gatePackets is the packets a module's output gate has counted, from the
// daemon's own metrics (control_v2.ListMetrics): "bess_gate_packets_total" with
// the module's name, direction "out" and gate 0 -- the single chain each table
// in this graph has.
func gatePackets(t *testing.T, ctx context.Context, client *bess.Client, module string) float64 {
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
		if labels["module"] == module && labels["direction"] == "out" && labels["gate"] == "0" {
			return s.GetValue()
		}
	}
	t.Fatalf("the daemon reports no output counter for module %q; it reports %v", module, have)
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

// pathUrrEstablishment is pathEstablishment with a URR measuring the uplink
// PDR, and a QER that polices nothing: the meter would drop all but a trickle
// of the source's packets, and the counting module sits behind it, so a rate
// here would make the numbers a function of the meter rather than of the
// packets the source produced. The URR's threshold is far above what a run
// carries, so nothing in it fires yet (reporting is not implemented).
func pathUrrEstablishment(cpSEID uint64, ueIP string) *message.SessionEstablishmentRequest {
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
				ie.NewUEIPAddress(0x02, ueIP, "", 0, 0),
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
		ie.NewCreateURR(
			ie.NewURRID(7),
			ie.NewMeasurementMethod(0, 1, 0),    // VOLUM
			ie.NewReportingTriggers(0x02, 0x00), // VOLTH
			ie.NewVolumeThreshold(0x01, 1<<40, 0, 0),
		),
	)
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

	// The control arm: nothing is measured before this session exists, so a
	// later non-zero reading is the session's doing.
	if before := countersOf(t, ctx, client, "cnt_ul"); len(before) != 0 {
		t.Fatalf("cnt_ul already measures %d rules before any session exists: %v", len(before), before)
	}

	resp := c.Establish(pathUrrEstablishment(0x4444, "10.45.0.2")).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the daemon refused the establishment with cause %d", got)
	}
	defer func() {
		del := message.NewSessionDeletionRequest(0, 0, resp.Header.SEID, 9, 0)
		if got := cause(t, c.Delete(del)); got != ie.CauseRequestAccepted {
			t.Errorf("the deletion answered cause %d", got)
		}
	}()

	// The source's packets and this reading are not ordered: wait for the
	// counter to move. A run that never does is the module not counting, which
	// is what this test exists to notice.
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
		if packets != 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the uplink chain carried no packet the URR measures within 10s; "+
				"output counters: %v", chainCounters(t, ctx, client))
		}
		time.Sleep(100 * time.Millisecond)
	}

	// The inner IPv4 packet's Total Length: the graph's uplink frame holds
	// 10.45.0.2:5000 -> 8.8.8.8:53 with a 9-byte payload, 20 + 8 + 9.
	const innerOctets = 37
	if got := octets / packets; got != innerOctets {
		t.Errorf("the counter reports %d octets per packet, want the inner IP packet's %d "+
			"(%d packets, %d octets): the frame's Ethernet header is not data volume",
			got, innerOctets, packets, octets)
	}
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
