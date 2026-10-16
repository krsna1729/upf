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
				ie.NewFTEID(0x02, pathUpTEID, net.ParseIP("192.0.2.1"), nil, 0),
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
