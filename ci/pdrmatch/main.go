// SPDX-License-Identifier: BSD-3-Clause

// Command pdrmatch is the Go half of ci/pdrmatch-path.sh: the session-
// establishment half of the keyed per-session matcher's live proof. The script
// deploys deploy/pdrmatch-path.yaml and checks the packets' bytes in the
// daemon's Dumps; this program programs the session and reads the daemon's own
// counters, which is the half no shell can do (the rules are compiled by
// internal/session).
//
// What it does, in order, and why each step is evidence rather than decoration:
//
//  1. reads the daemon's schema, so every message is built from the daemon's
//     own descriptor set and not from a hand-typed shape;
//  2. takes the control arm: the uplink chain's output counters before any
//     session exists. The graph's Source runs from the moment the graph is
//     applied, so a zero here is absent state, not absent traffic;
//  3. establishes one session through the compiler's PdrMatch opt-in. The
//     uplink's PDRs become one key of `pdr_match_ul/rules` -- that session's
//     rule list as the value -- keyed by 0x11223344, the F-TEID the decap
//     writes and the graph's G-PDU carries;
//  4. reads that key back and prints it: the rules as the *module* holds them,
//     with the ActionId it will put on a packet that matches;
//  5. waits for `pdr_match_ul`'s own output gate to count a packet -- a packet
//     the module does not match is dropped, never emitted, so that gate is what
//     says the match happened in the module -- and then for the same packets to
//     reach the router's N6 gate, which is what says the rule's own result
//     named a next hop and the meter passed the packet;
//  6. deletes the session, so the daemon's state ends where it started.
//
// It exits non-zero on the first thing that is not what the claim says.
package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/bess"
	"github.com/krsna1729/upf/internal/session"
)

// The session the arm establishes, and the graph it is established into
// (deploy/pdrmatch-path.yaml). The two TEIDs are the graph's own frames': the
// F-TEID of the uplink PDR (which is also the key of `pdr_match_ul/rules`) and
// the gNB's TEID for the downlink outer header.
const (
	cpSEID   uint64 = 0x2222
	ueIP            = "10.45.0.2"
	upTEID   uint32 = 0x11223344
	downTEID uint32 = 0x55667788
	// The PCF's Flow Description is the downlink form on both PDRs (TS 29.244
	// 5.2.1A.2A): the UE answered by 8.8.8.8:5000 -> UE:53 is "to assigned 53",
	// and the uplink PDR reads the same string swapped. The uplink frame is
	// UE:5000 -> 8.8.8.8:53, so its filter is the form whose swap names port 53 at
	// the far end.
	uplinkRule   = "permit out udp from any 53 to assigned"
	downlinkRule = "permit out udp from any to assigned 53"
	// The modules the claim is read from, by the names the graph declares: the
	// uplink's matcher, and the downlink's selector and matcher, whose session
	// the selector names by the UE address.
	module      = "pdr_match_ul"
	rulesRes    = module + "/rules"
	downModule  = "pdr_match_dl"
	downRes     = downModule + "/rules"
	selector    = "sel_dl"
	selectorRes = selector + "/rules"
	router      = "rt"
	n6Gate      = "0"
	n3Gate      = "1"
	waitWithin  = 15 * time.Second
)

// applyForw is the Apply Action of a FAR that forwards: the only one these two
// PDRs name.
const applyForw uint8 = 0x02

func main() {
	target := flag.String("target", "127.0.0.1:10514", "bessd's control_v2 gRPC address")
	flag.Parse()

	if err := run(*target); err != nil {
		fmt.Fprintf(os.Stderr, "pdrmatch: %v\n", err)
		os.Exit(1)
	}
}

func run(target string) error {
	ctx := context.Background()
	client, err := bess.Dial(ctx, target)
	if err != nil {
		return fmt.Errorf("dialing %s: %w", target, err)
	}
	defer client.Close()
	if err := client.Refresh(ctx); err != nil {
		return fmt.Errorf("reading the daemon's schema: %w", err)
	}
	fmt.Printf("pdrmatch: %s, schema %s\n", target, client.Version())

	// The control arm, before the daemon holds any session.
	before := map[string]float64{}
	for _, m := range []string{module, router, selector, downModule} {
		n, err := gatePackets(ctx, client, m, n6Gate)
		if err != nil {
			return err
		}
		before[m] = n
	}
	fmt.Printf("pdrmatch: before any session: %s out=%v, %s gate %s=%v\n",
		module, before[module], router, n6Gate, before[router])
	for _, m := range []string{module, router} {
		if before[m] != 0 {
			return fmt.Errorf("%s had already emitted %v packets: the graph's source runs from the moment it is applied, so this is a session's state and not the control arm",
				m, before[m])
		}
	}
	// The downlink's two modules are counted on their own gate, and the graph's
	// downlink source runs from the moment it is applied: a zero here is absent
	// state, not absent traffic.
	for _, m := range []string{selector, downModule} {
		n, err := gatePackets(ctx, client, m, n6Gate)
		if err != nil {
			return err
		}
		if n != 0 {
			return fmt.Errorf("%s had already emitted %v downlink packets before any session", m, n)
		}
	}
	for _, res := range []string{rulesRes, selectorRes, downRes} {
		if err := empty(ctx, client, res); err != nil {
			return err
		}
	}

	// The session, through the compiler: the uplink's PDRs are the PdrMatch
	// map's key 0x11223344, the downlink's stay on the WildcardMatch path
	// (that direction's selector is not built yet).
	c := session.New(config(), client, slog.New(slog.NewTextHandler(os.Stderr,
		&slog.HandlerOptions{Level: slog.LevelInfo})))
	resp, ok := c.Establish(establishment()).(*message.SessionEstablishmentResponse)
	if !ok {
		return errors.New("the establishment answered no session-level response")
	}
	if got := cause(resp.Cause); got != ie.CauseRequestAccepted {
		return fmt.Errorf("the daemon refused the establishment with cause %d", got)
	}
	if resp.UPFSEID == nil {
		return errors.New("the establishment answer carries no F-SEID")
	}
	fseid, err := resp.UPFSEID.FSEID()
	if err != nil {
		return fmt.Errorf("the establishment answer's F-SEID: %w", err)
	}
	fmt.Printf("pdrmatch: established SEID %d: uplink F-TEID %#x (the map's key), downlink TEID %#x\n",
		fseid.SEID, upTEID, downTEID)
	defer func() {
		del, ok := c.Delete(message.NewSessionDeletionRequest(0, 0, fseid.SEID, 3, 0)).(*message.SessionDeletionResponse)
		if !ok || cause(del.Cause) != ie.CauseRequestAccepted {
			fmt.Fprintln(os.Stderr, "pdrmatch: the deletion was not accepted")
			return
		}
		fmt.Println("pdrmatch: deleted the session")
	}()

	// The module's own map, as the daemon holds it: what the compiler wrote,
	// decoded through the module's codec. The ActionId in it is the value the
	// packet path will put on a matching packet, and reading it here is what
	// ties the counters below to a *named* id.
	action, err := readback(ctx, client, fseid, upTEID)
	if err != nil {
		return err
	}
	if err := resolve(ctx, client, action); err != nil {
		return err
	}

	// The module matched: its output gate counts only what it emitted, and a
	// packet it does not match is dropped (it is not this module's packet).
	matched, err := waitFor(ctx, client, module, n6Gate, before[module])
	if err != nil {
		return fmt.Errorf("the module never emitted a packet: %w", err)
	}
	fmt.Printf("pdrmatch: ok: the module matched the session's packet: %s gate %s carried %v more packets\n",
		module, n6Gate, matched)

	// And the result reached the packet path: the router left by the next hop
	// the rule itself named.
	id := fmt.Sprintf("ok: the module wrote ActionId %v on the packet", action)
	if _, err := waitFor(ctx, client, router, n6Gate, before[router]); err != nil {
		return fmt.Errorf("the packet never reached %s gate %s (the rule result did not resolve): %w",
			router, n6Gate, err)
	}
	uplink, err := gatePackets(ctx, client, router, n6Gate)
	if err != nil {
		return err
	}
	fmt.Printf("pdrmatch: %s: %s gate %s carried %v: the rule's result left by its next hop\n",
		id, router, n6Gate, uplink)
	if err := qfiFlows(ctx, client); err != nil {
		return err
	}
	return downlink(ctx, client, fseid)
}

// downlink is the selector's half of the live proof: the session is named for a
// packet that carries no tunnel by the UE address it is addressed to, and the
// matcher behind the selector matches the session's own rules.
//
// The graph's downlink source has been running since the graph was applied, and
// its frame is addressed to the UE, so the whole chain is exercised as soon as
// the session is: before it, both modules emitted nothing (the control arm).
func downlink(ctx context.Context, client *bess.Client, fseid *ie.FSEIDFields) error {
	// The selector's rule, as the daemon holds it: the UE address as the key,
	// and the session id it writes into the packet's metadata.
	got, err := client.Contents(ctx, selectorRes)
	if err != nil {
		return fmt.Errorf("reading %s: %w", selectorRes, err)
	}
	entries := got[selectorRes]
	if len(entries) != 1 {
		return fmt.Errorf("%s holds %d keys, want the session's one address", selectorRes, len(entries))
	}
	line, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	fmt.Printf("pdrmatch: %s holds %s\n", selectorRes, line)
	result, ok := entries[0].Value["result"].(string)
	if !ok {
		return fmt.Errorf("%s: the rule carries no result: %v", selectorRes, entries[0].Value)
	}
	raw, err := base64.StdEncoding.DecodeString(result)
	if err != nil || len(raw) < 4 {
		return fmt.Errorf("%s: the rule's result %q is not a session id: %w", selectorRes, result, err)
	}
	action := binary.BigEndian.Uint32(raw)
	if action != uint32(fseid.SEID) {
		return fmt.Errorf("%s names session %d, want the session's id %d", selectorRes, action, fseid.SEID)
	}

	// The matcher's own map, keyed by that same id: the selector writes the key
	// the module reads, which is what ties the two together.
	held, err := client.Contents(ctx, downRes)
	if err != nil {
		return fmt.Errorf("reading %s: %w", downRes, err)
	}
	down := held[downRes]
	if len(down) != 1 {
		return fmt.Errorf("%s holds %d keys, want the session's one", downRes, len(down))
	}
	if key := down[0].Key["session"]; fmt.Sprint(key) != fmt.Sprint(fseid.SEID) {
		return fmt.Errorf("%s is keyed by %v, want the session id %d", downRes, key, fseid.SEID)
	}
	if rules, ok := down[0].Value["rules"].([]any); !ok || len(rules) != 1 {
		return fmt.Errorf("%s: the session's value is %v, want its one downlink PDR's rules", downRes, down[0].Value)
	}
	fmt.Printf("pdrmatch: %s (SEID %d) holds the session's own rules\n", downRes, fseid.SEID)

	// The selector matched: its output gate counts only what it named a session
	// for, and a packet it does not match is dropped (its default gate).
	named, err := waitFor(ctx, client, selector, n6Gate, 0)
	if err != nil {
		return fmt.Errorf("the selector never named a session: %w", err)
	}
	fmt.Printf("pdrmatch: ok: the selector named the session for %v downlink packets\n", named)
	// And the matcher matched them: it emitted on its own gate, which is what
	// says the rules the map holds were applied to the packet.
	if _, err := waitFor(ctx, client, downModule, n6Gate, 0); err != nil {
		return fmt.Errorf("the downlink matcher never matched the session's packet: %w", err)
	}
	// And the result reached the packet path: the rule named the next hop, the
	// meter passed the packet, and the encap left by the N3 next hop.
	carried, err := waitFor(ctx, client, router, n3Gate, 0)
	if err != nil {
		return fmt.Errorf("the downlink packet never reached %s gate %s (the rule's result did not resolve): %w",
			router, n3Gate, err)
	}
	matched, err := gatePackets(ctx, client, downModule, n6Gate)
	if err != nil {
		return err
	}
	fmt.Printf("pdrmatch: ok: %s gate %s carried %v packets, and %s gate %s carried %v: the downlink left by the action's next hop\n",
		downModule, n6Gate, matched, router, n3Gate, carried)
	return nil
}

// config is the deployed graph's shape (deploy/pdrmatch-path.yaml), in the
// compiler's own terms: the names internal/session's Config spells, with the
// uplink's PDRs in the keyed per-session matcher and the downlink's unchanged.
func config() session.Config {
	return session.Config{
		TEIDTable: "teid",
		Up: session.Direction{
			// No PDRTable: this direction's rules are the map's, and the
			// WildcardMatch form of them is not built (compile).
			PdrMatch: module,
			Meters:   "mt_ul",
			Counters: "cnt_ul",
			NextHop:  1,
		},
		Down: session.Direction{
			// The downlink's rules are the map's too, and its session is named
			// by the selector in front of the matcher: the UE address the
			// packet is addressed to (this graph is a one-instance deployment,
			// so the route domain is not a field of the key).
			PdrMatch:       downModule,
			Selector:       selector,
			SelectorFields: []session.Field{session.DstIP},
			Meters:         "mt_dl",
			Counters:       "cnt_dl",
			NextHop:        2,
			Tunnels:        "enc",
		},
		N3Addr:  netip.MustParseAddr("192.0.2.1"),
		N3MAC:   [6]byte{2, 0, 0, 0, 0, 1},
		PeerMAC: [6]byte{2, 0, 0, 0, 0, 2},
	}
}

// establishment is the session: one uplink PDR on the pinned F-TEID whose SDF
// filter is a rule the graph's frame matches (the UE's address from the PDI,
// protocol 17 and destination port 53 from the filter), one downlink PDR, and
// a QER on the uplink behind whose meter the packets still flow.
func establishment() *message.SessionEstablishmentRequest {
	return message.NewSessionEstablishmentRequest(0, 0, cpSEID, 1, 0,
		ie.NewNodeID("", "", "smf"),
		ie.NewFSEID(cpSEID, nil, nil),
		ie.NewCreatePDR(
			ie.NewPDRID(1),
			ie.NewPrecedence(100),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, upTEID, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, ueIP, "", 0, 0),
				ie.NewSDFFilter(uplinkRule, "", "", "", 0),
			),
			ie.NewFARID(1),
			ie.NewQERID(1),
		),
		// The same tunnel's two QoS flows, at a higher precedence than the
		// rule that names none: QFI 9 is dropped (its FAR does nothing) and
		// QFI 5 is forwarded. A module that ignored the QFI would match the
		// first of them for every packet of the tunnel.
		ie.NewCreatePDR(
			ie.NewPDRID(3),
			ie.NewPrecedence(10),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, upTEID, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, ueIP, "", 0, 0),
				ie.NewSDFFilter(uplinkRule, "", "", "", 0),
				ie.NewQFI(9),
			),
			ie.NewFARID(3),
		),
		ie.NewCreatePDR(
			ie.NewPDRID(4),
			ie.NewPrecedence(20),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, upTEID, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, ueIP, "", 0, 0),
				ie.NewSDFFilter(uplinkRule, "", "", "", 0),
				ie.NewQFI(5),
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
				ie.NewSDFFilter(downlinkRule, "", "", "", 0),
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
				ie.NewOuterHeaderCreation(0x0100, downTEID, "10.20.30.2", "", 0, 0, 0),
			),
		),
		ie.NewCreateFAR(ie.NewFARID(3), ie.NewApplyAction(0)),
		ie.NewCreateQER(
			ie.NewQERID(1),
			ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
			ie.NewMBR(1000, 2000),
		),
	)
}

// readback prints the map's one key -- the session, and the rules the module
// holds for it -- and returns the ActionId of its first rule.
func readback(ctx context.Context, client *bess.Client, fseid *ie.FSEIDFields, teid uint32) (json.Number, error) {
	got, err := client.Contents(ctx, rulesRes)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", rulesRes, err)
	}
	entries := got[rulesRes]
	if len(entries) != 1 {
		return "", fmt.Errorf("%s holds %d keys, want the session's one", rulesRes, len(entries))
	}
	if key := entries[0].Key["session"]; key != nil {
		if fmt.Sprint(key) != fmt.Sprint(teid) {
			return "", fmt.Errorf("%s is keyed by %v, want the session's F-TEID %#x", rulesRes, key, teid)
		}
	}
	rules, ok := entries[0].Value["rules"].([]any)
	if !ok || len(rules) == 0 {
		return "", fmt.Errorf("%s: the value carries no rules: %v", rulesRes, entries[0].Value)
	}
	// The rule that names no QFI: the session's general one, and the one with
	// an ActionId to read (QFI 9's drops, and names none). protojson spells
	// the fields in lower camel case ("actionId", "qfi"), which is what the
	// daemon's readback decodes to -- the same names the compiler wrote in
	// snake case in the transaction.
	var action json.Number
	named := 0
	for _, r := range rules {
		rule, ok := r.(map[string]any)
		if !ok {
			return "", fmt.Errorf("%s: a rule is %T, not a rule", rulesRes, r)
		}
		if rule["qfi"] != nil {
			named++
			continue
		}
		if action, ok = rule["actionId"].(json.Number); !ok {
			return "", fmt.Errorf("%s: the rule carries no action id: %v", rulesRes, rule)
		}
	}
	if named != 2 || len(rules) != 3 {
		return "", fmt.Errorf("%s holds %d rules, %d naming a QFI, want 3 and 2", rulesRes, len(rules), named)
	}
	line, err := json.Marshal(entries)
	if err != nil {
		return "", err
	}
	fmt.Printf("pdrmatch: %s (SEID %d) holds %s\n", rulesRes, fseid.SEID, line)
	return action, nil
}

// resolve prints the result the rule itself carries: the point where the
// ActionId stops being a field the module wrote and becomes the meter levels
// and next hop it wrote with it.
func resolve(ctx context.Context, client *bess.Client, action json.Number) error {
	got, err := client.Contents(ctx, rulesRes)
	if err != nil {
		return fmt.Errorf("reading %s: %w", rulesRes, err)
	}
	for _, e := range got[rulesRes] {
		if fmt.Sprint(e.Key["session"]) != fmt.Sprint(upTEID) {
			continue
		}
		list, _ := e.Value["rules"].([]any)
		for _, raw := range list {
			rule, _ := raw.(map[string]any)
			if fmt.Sprint(rule["actionId"]) != fmt.Sprint(action) {
				continue
			}
			line, err := json.Marshal(rule)
			if err != nil {
				return err
			}
			fmt.Printf("pdrmatch: %s rule for action %v carries its result: %s\n", rulesRes, action, line)
			return nil
		}
	}
	return fmt.Errorf("%s holds no rule with action %v: the rule names an id nothing resolves", rulesRes, action)
}

// empty fails when the resource holds anything: the control arm for the map
// itself, and the reason a later key is the session's.
func empty(ctx context.Context, client *bess.Client, name string) error {
	got, err := client.Contents(ctx, name)
	if err != nil {
		return fmt.Errorf("reading %s: %w", name, err)
	}
	if n := len(got[name]); n != 0 {
		return fmt.Errorf("%s holds %d keys before any session", name, n)
	}
	fmt.Printf("pdrmatch: %s is empty\n", name)
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

// qfiFlows is the QFI proof, read from the module's own gate counters: the
// session's list is [QFI 9: drop, QFI 5: forward, no QFI: forward], and the
// graph has a stream for each of the last two flows besides the plain one. One
// stream runs at a time (a Source's `settings` is how the others are stopped),
// so what a counter gained is that stream's.
//
//   - QFI 9 must reach the module (the decap's gate counts it) and must not
//     leave it: its rule is a drop. A module that ignored the QFI would drop
//     every stream, the next one included.
//   - QFI 5 must leave the module and the router: the first rule of its list
//     that matches is the forward, not the QFI 9 drop that precedes it in the
//     session's order.
func qfiFlows(ctx context.Context, client *bess.Client) error {
	stop := func(src string, size int) error { return setBurst(ctx, client, src, size, 0) }
	if err := stop("src_up", 87); err != nil {
		return err
	}
	time.Sleep(time.Second) // what the plain stream already sent drains

	gate := func(m string) (float64, error) { return gatePackets(ctx, client, m, n6Gate) }
	run := func(src string) (decap, matched, routed float64, err error) {
		var d0, m0, r0 float64
		for _, g := range []struct {
			m string
			v *float64
		}{{"decap0", &d0}, {module, &m0}, {router, &r0}} {
			if *g.v, err = gate(g.m); err != nil {
				return
			}
		}
		if err = setBurst(ctx, client, src, 95, 32); err != nil {
			return
		}
		time.Sleep(2500 * time.Millisecond) // two Dump samples of this stream
		if err = stop(src, 95); err != nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
		var d1, m1, r1 float64
		for _, g := range []struct {
			m string
			v *float64
		}{{"decap0", &d1}, {module, &m1}, {router, &r1}} {
			if *g.v, err = gate(g.m); err != nil {
				return
			}
		}
		return d1 - d0, m1 - m0, r1 - r0, nil
	}

	d, m, r, err := run("src_q9")
	if err != nil {
		return err
	}
	fmt.Printf("pdrmatch: QFI 9 stream: the decap emitted %v, the module %v, the router %v\n", d, m, r)
	if d == 0 {
		return errors.New("the QFI 9 stream never reached the module: the check below would pass for want of traffic")
	}
	if m != 0 || r != 0 {
		return fmt.Errorf("QFI 9's packets left the module (%v) or the router (%v): its rule drops", m, r)
	}
	fmt.Println("pdrmatch: ok: QFI 9's packets reached the module and were dropped by its QFI 9 rule")

	d, m, r, err = run("src_q5")
	if err != nil {
		return err
	}
	fmt.Printf("pdrmatch: QFI 5 stream: the decap emitted %v, the module %v, the router %v\n", d, m, r)
	if d == 0 || m == 0 || r == 0 {
		return fmt.Errorf("QFI 5's packets did not cross: decap %v, module %v, router %v", d, m, r)
	}
	fmt.Println("pdrmatch: ok: QFI 5's packets were forwarded, not dropped by the QFI 9 rule ahead of them")
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
