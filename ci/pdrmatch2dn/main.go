// SPDX-License-Identifier: BSD-3-Clause

// Command pdrmatch2dn is the Go half of ci/pdrmatch-2dn.sh: the two-network-
// instance proof, driven one window at a time so every packet that leaves can
// be traced to the stream that produced it.
//
// The graph (deploy/pdrmatch-2dn.yaml) puts two data networks' interfaces on
// one Vif, a selector keyed on (route domain, UE address) in front of the keyed
// per-session matcher, and two uplink streams on two tunnels. The claim is the
// case TS 23.501 5.6.12 NOTE 1 gives as the reason a Network Instance exists:
// two subscribers with the *same* address, one per data network, and each
// direction leaves toward its own network.
//
// One process, three arms, because a controller is long-lived and its id spaces
// are the deployment's: two processes would hand out SEID 1, action 1 and meter
// 1 twice, and the second session would take the first one's records.
//
//	control   every stream stopped, no session: nothing may leave
//	window A  session A (internet): only A's two streams are injected
//	window B  session B (campus, the same UE address): only B's
//	window C  both sessions live, the internet instance's streams again: A's
//	          records must still take them, not B's
//
// The windows are what make the evidence a correlation rather than a sighting:
// while A runs, the campus stream is stopped and the campus session does not
// exist, so B's TEID cannot appear in A's window; while B runs, A's stream is
// stopped, so A's TEID cannot appear in B's. A deployment that swapped the two
// sessions' rules would pass a "both TEIDs appeared" check and fail these.
//
// The windows are separated by a handshake with the caller (-handshake DIR),
// because the frames' bytes -- which TEID, which exit, which L2 -- are checked
// by the shell from the daemon's Dumps, and a window's dump lines must be read
// before the next window starts:
//
//	control.done  the control arm is over: the caller may read the log so far
//	a.done        window A is over and its streams are stopped
//	a.go          the caller has read it: window B may start
//	b.done        window B is over
//	b.go          the caller has read it: window C may start
//	c.done        window C is over
//
// With no -handshake the arms run straight through, which is useful by hand.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/bess"
	"github.com/krsna1729/upf/internal/routing"
	"github.com/krsna1729/upf/internal/session"
)

// The graph's names (deploy/pdrmatch-2dn.yaml) and the gates its connections
// give them.
const (
	upModule      = "pdr_match_ul"
	upRules       = upModule + "/rules"
	downModule    = "pdr_match_dl"
	downRules     = downModule + "/rules"
	selector      = "sel_dl"
	selectorRules = selector + "/rules"
	router        = "rt"
	// The router's two data-network exits. Every other module here has one
	// output gate, so gate 0 is also the selector's, the matcher's and the
	// access-side next hop's.
	internetGate = "0" // the internet instance's exit (N6)
	campusGate   = "2" // the campus instance's exit (the second data network)
)

// The deployment's two instances, as `upfd -instances` spells them and as the
// graph's Vif writes them: name, route domain, next hop -- and the pool both
// serve, which is the same one.
const (
	internet = "internet"
	campus   = "campus"
	pool     = "10.45.0.0/16"
)

// The sessions: one subscriber address, two data networks.
const (
	ueIP    = "10.45.0.2"
	n3Addr  = "192.0.2.1"
	gnbAddr = "10.20.30.2"
	seidA   = 0x2222
	seidB   = 0x3333
	upTEIDa = 0x11223344
	upTEIDb = 0x11223345
	dlTEIDa = 0x55667788
	dlTEIDb = 0x55667789

	// The N9 peer arm: a third session on internet whose FAR is a tunnel, and
	// the peer's session on campus (domain 2) that owns the tunnel's TEID and
	// whose own instance's next hop carries the decapped packet.
	seidC    = 0x4444
	seidD    = 0x5555
	upTEIDc  = 0x11223346
	peerTEID = 0x55667790
	uePeer   = "10.45.0.3"

	// The PCF's Flow Description is the downlink form on both PDRs (TS 29.244
	// 5.2.1A.2A): the UE answered by 8.8.8.8:5000 -> UE:53 is "to assigned 53",
	// and the uplink PDR reads the same string swapped.
	uplinkRule   = "permit out udp from any 53 to assigned"
	downlinkRule = "permit out udp from any to assigned 53"
)

// applyForw is the Apply Action of a FAR that forwards: the only one these
// PDRs name.
const applyForw uint8 = 0x02

const waitWithin = 15 * time.Second

// The graph's Sources, and the sizes their `settings` carry: burst 0 stops a
// stream, so a window injects exactly one data network's traffic.
var streams = []struct {
	name string
	size int
}{
	{"src_up", 87},   // the internet session's tunnel
	{"src_up2", 87},  // the campus session's tunnel
	{"src_dn1", 51},  // the internet data network's frame
	{"src_dn2", 51},  // the campus data network's frame
	{"src_peer", 87}, // the N9 peer's uplinked packet
}

func main() {
	target := flag.String("target", "127.0.0.1:10514", "bessd's control_v2 gRPC address")
	handshake := flag.String("handshake", "", "directory to signal each arm's end in (empty: run straight through)")
	flag.Parse()

	if err := run(*target, *handshake); err != nil {
		fmt.Fprintf(os.Stderr, "pdrmatch2dn: %v\n", err)
		os.Exit(1)
	}
}

func run(target, handshake string) error {
	ctx := context.Background()
	client, err := bess.Dial(ctx, target)
	if err != nil {
		return fmt.Errorf("dialing %s: %w", target, err)
	}
	defer client.Close()
	if err := client.Refresh(ctx); err != nil {
		return fmt.Errorf("reading the daemon's schema: %w", err)
	}

	// Every arm starts from stopped streams: a window's packets are the ones
	// this arm starts, never a previous arm's leftovers.
	if err := stopAll(ctx, client); err != nil {
		return err
	}
	if err := control(ctx, client); err != nil {
		return err
	}
	if err := signal(handshake, "control.done"); err != nil {
		return err
	}
	if err := await(handshake, "control.go"); err != nil {
		return err
	}

	// One compiler for both windows: it owns the deployment's id spaces, and a
	// second compiler would hand out SEID 1, action 1 and meter 1 again.
	c := session.New(config(), client, slog.New(slog.NewTextHandler(os.Stderr,
		&slog.HandlerOptions{Level: slog.LevelInfo})))

	if err := window(ctx, client, c, internet, seidA, upTEIDa, dlTEIDa, "src_dn1", "src_up", internetGate); err != nil {
		return err
	}
	if err := signal(handshake, "a.done"); err != nil {
		return err
	}
	if err := await(handshake, "a.go"); err != nil {
		return err
	}

	if err := window(ctx, client, c, campus, seidB, upTEIDb, dlTEIDb, "src_dn2", "src_up2", campusGate); err != nil {
		return err
	}
	if err := signal(handshake, "b.done"); err != nil {
		return err
	}
	if err := await(handshake, "b.go"); err != nil {
		return err
	}

	if err := both(ctx, client); err != nil {
		return err
	}
	if err := signal(handshake, "c.done"); err != nil {
		return err
	}
	if err := await(handshake, "c.go"); err != nil {
		return err
	}

	if err := peer(ctx, client, c); err != nil {
		return err
	}
	if err := signal(handshake, "peer.done"); err != nil {
		return err
	}
	fmt.Println("pdrmatch2dn: all four arms done: one subscriber address, two data networks, both directions, and an N9 peer")
	return nil
}

// peer is the fourth arm: the internet instance's session sends its uplink
// into an N9 tunnel (FAR: Core plus an outer header, hop 4); the G-PDU is
// dumped and fed back into the TEID table, where the peer's session owns its
// TEID. That session is in the campus instance, and its own instance's next
// hop sends the decapped packet to the campus exit. A graph that did not decap
// the tunnel, or that resolved the peer's egress through the wrong instance,
// would not deliver it.
func peer(ctx context.Context, client *bess.Client, c *session.Compiler) error {
	exits := []exit{{module: router, gate: internetGate}, {module: router, gate: campusGate}}
	before, err := snapshot(ctx, client, exits)
	if err != nil {
		return err
	}
	for _, msg := range []*message.SessionEstablishmentRequest{peerLocal(), peerRemote()} {
		resp, ok := c.Establish(msg).(*message.SessionEstablishmentResponse)
		if !ok {
			return errors.New("the peer establishment answered no session-level response")
		}
		if got := cause(resp.Cause); got != ie.CauseRequestAccepted {
			return fmt.Errorf("the N9 peer's establishment was refused with cause %d", got)
		}
		seid, err := resp.UPFSEID.FSEID()
		if err != nil {
			return fmt.Errorf("the peer establishment answer's F-SEID: %w", err)
		}
		fmt.Printf("pdrmatch2dn: peer: established SEID %d\n", seid.SEID)
	}
	if err := setBurst(ctx, client, "src_peer", 87, 32); err != nil {
		return err
	}
	if _, err := waitFor(ctx, client, router, campusGate, value(before, exits, router, campusGate)); err != nil {
		return fmt.Errorf("the decapped packet never left by the campus exit: %w", err)
	}
	if err := stopAll(ctx, client); err != nil {
		return err
	}
	time.Sleep(time.Second)
	after, err := snapshot(ctx, client, exits)
	if err != nil {
		return err
	}
	if grew := value(after, exits, router, internetGate) - value(before, exits, router, internetGate); grew != 0 {
		return fmt.Errorf("the N9 packet also left by the internet exit (%v packets); the tunnel is the only uplink egress", grew)
	}
	fmt.Println("pdrmatch2dn: peer: the tunneled packet was decapped, matched the campus session, and left by the campus exit")
	return nil
}

// peerLocal is the internet session that forwards into the N9 tunnel.
func peerLocal() *message.SessionEstablishmentRequest {
	return message.NewSessionEstablishmentRequest(0, 0, seidC, 1, 0,
		ie.NewNodeID("", "", "smf"),
		ie.NewFSEID(seidC, nil, nil),
		ie.NewCreatePDR(
			ie.NewPDRID(1),
			ie.NewPrecedence(100),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, upTEIDc, net.ParseIP(n3Addr), nil, 0),
				ie.NewNetworkInstance(internet),
				ie.NewUEIPAddress(0x02, uePeer, "", 0, 0),
				ie.NewSDFFilter(uplinkRule, "", "", "", 0),
			),
			ie.NewFARID(1),
		),
		ie.NewCreateFAR(
			ie.NewFARID(1),
			ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceCore),
				ie.NewNetworkInstance(internet),
				ie.NewOuterHeaderCreation(0x0100, peerTEID, gnbAddr, "", 0, 0, 0),
			),
		),
	)
}

// peerRemote is the peer's session: it owns the TEID the local FAR's outer
// header creation names, so the tunneled packet's decap lands on this session
// in the campus instance. Its PDR is an uplink one, and the FAR sends it to
// the campus instance's own data network (its next hop, not internet's).
func peerRemote() *message.SessionEstablishmentRequest {
	return message.NewSessionEstablishmentRequest(0, 0, seidD, 1, 0,
		ie.NewNodeID("", "", "smf"),
		ie.NewFSEID(seidD, nil, nil),
		ie.NewCreatePDR(
			ie.NewPDRID(1),
			ie.NewPrecedence(100),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, peerTEID, net.ParseIP(n3Addr), nil, 0),
				ie.NewNetworkInstance(campus),
				ie.NewUEIPAddress(0x02, uePeer, "", 0, 0),
				ie.NewSDFFilter(uplinkRule, "", "", "", 0),
			),
			ie.NewFARID(1),
		),
		ie.NewCreateFAR(
			ie.NewFARID(1),
			ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceCore),
				ie.NewNetworkInstance(campus),
			),
		),
	)
}

// both is the third arm: both sessions live, and the internet instance's two
// streams must still reach the internet session's own records -- its TEID on
// the downlink, its exit on the uplink. This is the arm a graph fails if the
// two sessions' keys do not differ: the campus session's rule would take the
// frame, and the internet TEID would never appear again.
func both(ctx context.Context, client *bess.Client) error {
	exits := []exit{
		{module: selector, gate: internetGate}, {module: downModule, gate: internetGate}, {module: router, gate: internetGate},
		{module: router, gate: campusGate}, {module: upModule, gate: internetGate},
	}
	before, err := snapshot(ctx, client, exits)
	if err != nil {
		return err
	}
	if err := setBurst(ctx, client, "src_dn1", 51, 32); err != nil {
		return err
	}
	if err := setBurst(ctx, client, "src_up", 87, 32); err != nil {
		return err
	}
	if _, err := waitFor(ctx, client, downModule, internetGate, value(before, exits, downModule, internetGate)); err != nil {
		return fmt.Errorf("with both sessions live, %s never matched the internet instance's frame: %w", downModule, err)
	}
	if _, err := waitFor(ctx, client, router, internetGate, value(before, exits, router, internetGate)); err != nil {
		return fmt.Errorf("with both sessions live, the internet instance's uplink never left by gate %s: %w", internetGate, err)
	}
	if err := stopAll(ctx, client); err != nil {
		return err
	}
	time.Sleep(time.Second)
	after, err := snapshot(ctx, client, exits)
	if err != nil {
		return err
	}
	if grew := value(after, exits, router, campusGate) - value(before, exits, router, campusGate); grew != 0 {
		return fmt.Errorf("with both sessions live, the campus exit carried %v packets, and this arm injects only the internet instance's streams", grew)
	}
	fmt.Println("pdrmatch2dn: both sessions live: the internet instance's streams still reached the internet session")
	return nil
}

// signal and await are the handshake with the caller (a no-op without a
// directory): the shell reads the daemon's log between the windows, and the
// windows must not overlap it.
func signal(dir, name string) error {
	if dir == "" {
		return nil
	}
	if err := os.WriteFile(filepath.Join(dir, name), nil, 0o644); err != nil {
		return fmt.Errorf("signalling %s: %w", name, err)
	}
	return nil
}

func await(dir, name string) error {
	if dir == "" {
		return nil
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the caller never wrote %s", name)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// control is the control arm: with no session and every stream stopped, no
// packet may leave any exit, and the three maps must be empty. The graph's
// Sources carry burst 0, so a non-zero counter here is state, not traffic.
func control(ctx context.Context, client *bess.Client) error {
	// The deployment's next hops: the graph names the two instances' L2 (the
	// fork's Router writes a resolved next hop's addresses, D-153), and the
	// lane's byte checks read the frames that leave by them -- so a resource
	// that did not take must fail here rather than as a missing MAC later.
	hops, err := client.Contents(ctx, "rt/next_hops")
	if err != nil {
		return fmt.Errorf("reading rt/next_hops: %w", err)
	}
	entries := hops["rt/next_hops"]
	if len(entries) != 4 {
		return fmt.Errorf("rt/next_hops holds %d next hops, and the deployment names 4: %v", len(entries), entries)
	}
	for _, e := range entries {
		id := fmt.Sprint(e.Key["id"])
		dst := fmt.Sprint(e.Value["dstMac"])
		src := fmt.Sprint(e.Value["srcMac"])
		if id == "1" || id == "3" {
			// The two data networks' exits: the lane reads these bytes in the
			// frames that leave them.
			if len(dst) == 0 || dst == "<nil>" || len(src) == 0 || src == "<nil>" {
				return fmt.Errorf("next hop %s names no L2 pair: %v", id, e.Value)
			}
		}
	}
	fmt.Printf("pdrmatch2dn: rt/next_hops: %v\n", entries)

	for _, res := range []string{upRules, downRules, selectorRules} {
		got, err := client.Contents(ctx, res)
		if err != nil {
			return fmt.Errorf("reading %s: %w", res, err)
		}
		if n := len(got[res]); n != 0 {
			return fmt.Errorf("%s holds %d keys before any session", res, n)
		}
	}
	exits := []exit{
		{module: selector, gate: internetGate}, {module: downModule, gate: internetGate}, {module: router, gate: internetGate},
		{module: router, gate: campusGate}, {module: upModule, gate: internetGate},
	}
	before, err := snapshot(ctx, client, exits)
	if err != nil {
		return err
	}
	time.Sleep(2 * time.Second)
	after, err := snapshot(ctx, client, exits)
	if err != nil {
		return err
	}
	for i, e := range exits {
		if after[i] != before[i] {
			return fmt.Errorf("with every stream stopped and no session, %s gate %s counted %v packets (was %v)",
				e.module, e.gate, after[i], before[i])
		}
	}
	fmt.Printf("pdrmatch2dn: control: no session, every stream stopped, every exit at zero (%v)\n", after)
	return nil
}

// window establishes one instance's session, injects only that instance's two
// streams, and requires the expected exits to move while the other instance's
// exit does not.
func window(ctx context.Context, client *bess.Client, c *session.Compiler, instance string, seid uint64, upTEID, dlTEID uint32, downSrc, upSrc, own string) error {
	exits := []exit{
		{module: selector, gate: internetGate}, {module: downModule, gate: internetGate}, {module: router, gate: internetGate},
		{module: router, gate: campusGate}, {module: upModule, gate: internetGate},
	}
	before, err := snapshot(ctx, client, exits)
	if err != nil {
		return err
	}

	resp, ok := c.Establish(establishment(instance, seid, upTEID, dlTEID)).(*message.SessionEstablishmentResponse)
	if !ok {
		return errors.New("the establishment answered no session-level response")
	}
	if got := cause(resp.Cause); got != ie.CauseRequestAccepted {
		return fmt.Errorf("the %s establishment was refused with cause %d", instance, got)
	}
	fseid, err := resp.UPFSEID.FSEID()
	if err != nil {
		return fmt.Errorf("the establishment answer's F-SEID: %w", err)
	}
	fmt.Printf("pdrmatch2dn: %s: established SEID %d (the PDI named %q): uplink F-TEID %#x, downlink TEID %#x\n",
		instance, fseid.SEID, instance, upTEID, dlTEID)

	// The selector's rules, as the daemon holds them: one per session, and the
	// session this window established must be one of them, named by its SEID.
	if err := selectorHolds(ctx, client, fseid.SEID); err != nil {
		return err
	}

	// Inject this instance's two streams only.
	if err := setBurst(ctx, client, downSrc, 51, 32); err != nil {
		return err
	}
	if err := setBurst(ctx, client, upSrc, 87, 32); err != nil {
		return err
	}
	// The downlink: the frame was selected, matched and encapsulated.
	if _, err := waitFor(ctx, client, downModule, internetGate, value(before, exits, downModule, internetGate)); err != nil {
		return fmt.Errorf("%s never matched the %s frame: %w", downModule, instance, err)
	}
	// The uplink: the session's rule matched and the action's next hop sent the
	// packet out -- N6 for internet, the campus exit for campus.
	if _, err := waitFor(ctx, client, router, own, value(before, exits, router, own)); err != nil {
		return fmt.Errorf("the %s session's uplink packet never left by gate %s: %w", instance, own, err)
	}
	if err := stopAll(ctx, client); err != nil {
		return err
	}
	time.Sleep(time.Second)

	after, err := snapshot(ctx, client, exits)
	if err != nil {
		return err
	}
	for i, e := range exits {
		grew := after[i] - before[i]
		switch {
		case e.module == router && e.gate == own:
			if grew == 0 {
				return fmt.Errorf("the %s window: %s gate %s did not move", instance, e.module, e.gate)
			}
		case e.module == router && (e.gate == internetGate || e.gate == campusGate):
			// The other instance's exit: this window injects no traffic for it,
			// and its session does not exist yet (internet) or is idle (campus).
			if grew != 0 {
				return fmt.Errorf("the %s window: %s gate %s carried %v packets, and this window injects no traffic for that instance",
					instance, e.module, e.gate, grew)
			}
		}
	}
	fmt.Printf("pdrmatch2dn: %s: ok: its own exit (gate %s) moved, the other instance's exit did not\n", instance, own)
	return nil
}

// exit names one module's output gate.
type exit struct{ module, gate string }

// value finds an exit's count in a snapshot of the same list.
func value(counts []float64, exits []exit, module, gate string) float64 {
	for i, e := range exits {
		if e.module == module && e.gate == gate {
			return counts[i]
		}
	}
	return 0
}

// selectorHolds requires the selector's rules to include one naming `seid`, and
// prints them all: the keys are the (route domain, UE address) pair the graph
// declared, and the values are the session ids the matcher is keyed by.
func selectorHolds(ctx context.Context, client *bess.Client, seid uint64) error {
	got, err := client.Contents(ctx, selectorRules)
	if err != nil {
		return fmt.Errorf("reading %s: %w", selectorRules, err)
	}
	entries := got[selectorRules]
	found := false
	for _, e := range entries {
		action, ok := e.Value["actionId"].(json.Number)
		if !ok {
			return fmt.Errorf("%s: a rule carries no action id: %v", selectorRules, e.Value)
		}
		if fmt.Sprint(action) == fmt.Sprint(seid) {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("%s holds no rule naming session %d: %v", selectorRules, seid, entries)
	}
	line, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	fmt.Printf("pdrmatch2dn: %s holds %s\n", selectorRules, line)
	return nil
}

// snapshot is several modules' output gates at one moment, in the list's order.
func snapshot(ctx context.Context, client *bess.Client, exits []exit) ([]float64, error) {
	out := make([]float64, len(exits))
	for i, e := range exits {
		n, err := gatePackets(ctx, client, e.module, e.gate)
		if err != nil {
			return nil, err
		}
		out[i] = n
	}
	return out, nil
}

// stopAll stops every Source: burst 0 is a stream that injects nothing.
func stopAll(ctx context.Context, client *bess.Client) error {
	for _, s := range streams {
		if err := setBurst(ctx, client, s.name, s.size, 0); err != nil {
			return err
		}
	}
	return nil
}

// setBurst sets a Source's `settings` singleton (burst 0 stops the stream).
func setBurst(ctx context.Context, client *bess.Client, src string, size, burst int) error {
	err := client.Apply(ctx, bess.Change{
		Resource: src + "/settings",
		Value:    map[string]any{"pkt_size": size, "burst": burst},
	})
	if err != nil {
		return fmt.Errorf("setting %s/settings to burst %d: %w", src, burst, err)
	}
	return nil
}

// gatePackets is one module's output gate, from the daemon's own metrics
// (bess_gate_packets_total): "the packets this module emitted on this gate".
func gatePackets(ctx context.Context, client *bess.Client, module, gate string) (float64, error) {
	samples, err := client.SDK().Metrics(ctx)
	if err != nil {
		return 0, fmt.Errorf("reading metrics: %w", err)
	}
	for _, s := range samples {
		if s.GetName() != "bess_gate_packets_total" {
			continue
		}
		labels := s.GetLabels()
		if labels["module"] == module && labels["direction"] == "out" && labels["gate"] == gate {
			return s.GetValue(), nil
		}
	}
	return 0, fmt.Errorf("the daemon reports no output counter for %s gate %s", module, gate)
}

// waitFor waits until `module`'s gate has emitted a packet beyond `baseline`.
func waitFor(ctx context.Context, client *bess.Client, module, gate string, baseline float64) (float64, error) {
	deadline := time.Now().Add(waitWithin)
	for {
		now, err := gatePackets(ctx, client, module, gate)
		if err != nil {
			return 0, err
		}
		if now > baseline {
			return now - baseline, nil
		}
		if time.Now().After(deadline) {
			return 0, fmt.Errorf("no packet within %s", waitWithin)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// cause is a response's Cause IE as a PFCP cause value.
func cause(i *ie.IE) uint8 {
	if i == nil {
		return 0
	}
	c, err := i.Cause()
	if err != nil {
		return 0
	}
	return c
}

// config is the deployed graph's shape (deploy/pdrmatch-2dn.yaml), in the
// compiler's own terms: the two instances the graph's Vif writes (domains 1
// and 2, serving one pool), the selector's key -- the route domain and then the
// UE address, the two fields the graph declares -- and the per-direction names.
func config() session.Config {
	instances, err := routing.New([]routing.Interface{
		{Instance: internet, Domain: 1, NextHop: 1, Pool: []netip.Prefix{netip.MustParsePrefix(pool)},
			// The N9 exit: the tunnel out of this instance (hop 4), distinct
			// from plain N6 (hop 1).
			Hops: map[routing.Egress]uint32{
				{DestIfc: ie.DstInterfaceCore}:               1,
				{DestIfc: ie.DstInterfaceCore, Tunnel: true}: 4,
			}},
		{Instance: campus, Domain: 2, NextHop: 3, Pool: []netip.Prefix{netip.MustParsePrefix(pool)}},
	}, 3)
	if err != nil {
		panic(err) // the deployment above is this program's own constant
	}
	return session.Config{
		TEIDTable: "teid",
		TEIDGate:  0,
		Up: session.Direction{
			// No PDRTable: this direction's rules are the map's.
			PdrMatch: upModule,
			Actions:  "at_ul",
			Meters:   "mt_ul",
			Counters: "cnt_ul",
			NextHop:  1,
			// The N9 tunnel's records: the encap hop 4 sends them through.
			Tunnels: "enc_peer",
		},
		Down: session.Direction{
			PdrMatch:        downModule,
			Selector:        selector,
			SelectorActions: "sel_at",
			SelectorFields:  []session.Field{session.RouteDomain, session.DstIP},
			Actions:         "at_dl",
			Meters:          "mt_dl",
			Counters:        "cnt_dl",
			NextHop:         2,
			Tunnels:         "enc",
		},
		Instances: instances,
		N3Addr:    netip.MustParseAddr(n3Addr),
		N3MAC:     [6]byte{2, 0, 0, 0, 0x0a, 0x01},
		PeerMAC:   [6]byte{2, 0, 0, 0, 0x0a, 0x02},
	}
}

// establishment is one session: an uplink PDR on the pinned F-TEID whose SDF
// filter is a rule the graph's frame matches, and a downlink PDR for the UE
// address. The PDI names the instance (TS 29.244 8.2.4) -- the name the
// deployment resolves to a route domain -- and the uplink FAR's Forwarding
// Parameters name it too, which is the instance a forward out leaves by.
func establishment(instance string, seid uint64, upTEID, dlTEID uint32) *message.SessionEstablishmentRequest {
	return message.NewSessionEstablishmentRequest(0, 0, seid, 1, 0,
		ie.NewNodeID("", "", "smf"),
		ie.NewFSEID(seid, nil, nil),
		ie.NewCreatePDR(
			ie.NewPDRID(1),
			ie.NewPrecedence(100),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, upTEID, net.ParseIP(n3Addr), nil, 0),
				ie.NewNetworkInstance(instance),
				ie.NewUEIPAddress(0x02, ueIP, "", 0, 0),
				ie.NewSDFFilter(uplinkRule, "", "", "", 0),
			),
			ie.NewFARID(1),
		),
		ie.NewCreatePDR(
			ie.NewPDRID(2),
			ie.NewPrecedence(100),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewNetworkInstance(instance),
				ie.NewUEIPAddress(0x02, ueIP, "", 0, 0),
				ie.NewSDFFilter(downlinkRule, "", "", "", 0),
			),
			ie.NewFARID(2),
		),
		ie.NewCreateFAR(
			ie.NewFARID(1),
			ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceCore),
				ie.NewNetworkInstance(instance),
			),
		),
		ie.NewCreateFAR(
			ie.NewFARID(2),
			ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceAccess),
				ie.NewOuterHeaderCreation(0x0100, dlTEID, gnbAddr, "", 0, 0, 0),
			),
		),
	)
}
