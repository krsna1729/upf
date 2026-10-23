// SPDX-License-Identifier: BSD-3-Clause

// Command ifacepath is the Go half of ci/iface-path.sh: the interface grammar's
// lane. Every PFCP Source Interface value (TS 29.244 8.2.2) and Destination
// Interface value (8.2.24) this UPF serves is driven end to end, one session
// per case, and each case is checked where its packet left by -- and, where the
// value is refused, on the cause the SMF reads.
//
// The graph is deploy/iface-path.yaml: the deployed path with every egress the
// grammar can name declared (its rt/next_hops are this program's hops: 1 the
// data network's, 2 the access side's, 3 a tunnel out of an instance, 4 the
// service LAN's, 5 the re-injection's), and the streams that inject each case's
// frame. The compiler below is the deployment's own, in the compiler's terms:
// the same egress table `upfd -instances` builds. The scenario sessions (S1,
// S4, S5, S8, S9) are ci/scenario's, the ones ci/vethlayout drives over veths.
//
//	control   every stream stopped, no session: nothing may leave
//	egress    S1 (Core, no outer header), S2 (Core, one: a tunnel out of the
//	          instance), S3 (the service LAN, with the Forwarding Policy it
//	          requires): each leaves by its own hop
//	ulcl      S8 (Mode 2): one TEID, two uplink PDRs, the data network's hop
//	          and an N9 tunnel
//	ulcl_n9_down  the remote PSA's downlink arrives on S8's N9 F-TEID and
//	          leaves toward the gNB
//	down      S6 (a PDR whose PDI names the service LAN's interface and whose
//	          FAR names Core): the data
//	          network's frame leaves by the instance's plain hop
//	mode1_down  the data network's answer to S1's UE leaves toward its gNB
//	forward   Create a temporary FAR for S1; its uplink frame leaves through
//	          the target-RAN tunnel, then a bounded local timer starts
//	forward_cleanup  After that timer, restore FAR 1 and remove the temporary
//	          FAR; the same stream returns to N6 (N4/data-plane fixture only)
//	vn        S4 (an uplink PDR whose FAR names 5G VN Internal) re-injects its
//	          packet into the subscriber-side table, where S5 (a PDR whose PDI
//	          names 5G VN Internal) takes it and tunnels it to that UE's gNB
//	concurrent  S9 (Mode 3: N9 arrival, N6 egress) joins the others, and every
//	          scenario's stream runs at once while all sessions are live; the
//	          window stays open until the shell has read each session's bytes
//	concurrent_stop  the streams are stopped and the Dumps' last lines read
//	refuse    the values this UP does not serve (the CP function's path, the
//	          Spare values, LI Function, and the egresses this deployment does
//	          not declare) and the two mandatory-IE conditions: each cause
//	arp       an ARP request for a session's UE address is answered
//	gone      the session is deleted: the entry goes and the address is not
//	          answered any more
//
// The arms are separated by a handshake with the caller (ci/iface-path.sh),
// because the frames' bytes are read from the daemon's Dumps by the shell, and
// a window's dump lines must be read before the next window starts. With no
// -handshake the arms run straight through.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/ci/scenario"
	"github.com/krsna1729/upf/internal/bess"
	"github.com/krsna1729/upf/internal/routing"
	"github.com/krsna1729/upf/internal/session"
)

// The graph's names (deploy/iface-path.yaml).
const (
	upModule   = "pdr_ul"
	downModule = "pdr_dl"
	router     = "rt"
	arpModule  = "arp_n6"
	arpEntries = arpModule + "/entries"
)

// The exits, as the graph's egress_gates and the driver's hops: the Router's
// gate is interface - 1 (D-049), and each value of these constants is one
// connection of deploy/iface-path.yaml.
const (
	n6Gate     = "0" // hop 1: the data network (N6)
	accessGate = "1" // hop 2: the access side, through the encap
	n9Gate     = "2" // hop 3: a tunnel out of an instance, through the encap
	lanGate    = "3" // hop 4: the service LAN
	vnGate     = "4" // hop 5: the re-injection, into the subscriber-side table
	arpGate    = "0" // arp_n6's one output
)

// The deployment, as `upfd -instances` spells it and as the graph's resources
// declare it: two instances (domains 1 and 2, one pool), one of which declares
// the tunnel, the service LAN and the re-injection, and the interface's ARP
// identity.
const (
	internet = "internet"
	vn       = "vn"
	// One pool, wide enough for the collision pair the arp arm establishes.
	pool = "10.44.0.0/14"

	n3Addr = "192.0.2.1"
	n9Addr = "192.0.2.9"
	n6Addr = "192.0.2.2"
)

// The next hops, by id: the same numbers in rt/next_hops and in the compiler's
// egress table.
const (
	hopN6     uint32 = 1
	hopAccess uint32 = 2
	hopN9     uint32 = 3
	hopLAN    uint32 = 4
	hopVN     uint32 = 5
)

// The Forwarding Policy the service LAN's forward carries: Table 7.5.2.3-2
// makes it mandatory there, and this UP holds the identifier.
const forwardingPolicy = "steering-1"

// The grammar's own cases, beside ci/scenario's: each with its own subscriber
// address, F-TEID and tunnel, so no two cases share a rule or an entry.
const (
	seidS2 = 0x4102
	seidS3 = 0x4103
	seidS6 = 0x4106
	seidS7 = 0x4107

	upTEID2 = 0x11223345
	upTEID3 = 0x11223346
	upTEID6 = 0x11223349
	upTEID7 = 0x1122334a

	dlTEID2 = 0x55667782
	dlTEID3 = 0x55667783
	dlTEID7 = 0x55667787

	// The UE addresses, one per session. "assigned" in a filter is the PDR's
	// own address, so each session's rules are its own.
	ueS2 = "10.45.0.3"
	ueS3 = "10.45.0.4"
	ueS6 = "10.45.0.7"

	// One session's two addresses, and why they are a pair: the responder's
	// table has 131072 slots for the graph's 65536 entries and
	// Hash(ip) = (ip * 2654435761) & 131071, so two addresses a multiple of
	// 131072 apart start their probe in one slot. One transaction publishing
	// both into the slot each claimed at Reserve loses one of them; only a pair
	// like this shows it.
	siblingA = "10.44.0.2"
	siblingB = "10.46.0.2"

	gnbAddr = "10.20.30.9"
)

// The lane's GTP-U addresses, and its one peer: every tunnel here goes to the
// same far end, because the exits are Dumps and the TEID is what tells them
// apart.
var (
	local = scenario.Local{N3: n3Addr, N9: n9Addr}
	peers = scenario.Peers{GNB: gnbAddr, GNB2: gnbAddr, UPF: gnbAddr, UPF2: gnbAddr}
)

const waitWithin = 30 * time.Second

// The graph's Sources and the sizes their `settings` carry: burst 0 stops a
// stream, so each arm injects exactly the streams its case is about.
var streams = []struct {
	name string
	size int
}{
	{"src_up", 87},
	{"src_up2", 87},
	{"src_up3", 87},
	{"src_vn", 87},
	{"src_ulcl_n6", 87},
	{"src_ulcl_n9", 87},
	{"src_ulcl_dn9", 87},
	{"src_n9", 87},
	{"src_dn", 51},
	{"src_dn1", 51},
	{"src_arp", 42},
	{"src_arp2", 42},
}

// concurrentStreams are every scenario's streams, started together: Mode 1's
// uplink (src_up) and downlink (src_dn1), Mode 2's two branches and the remote
// PSA's downlink, Mode 3's N9 arrival, Mode 5's re-injection, and S6's
// subscriber-side forward.
var concurrentStreams = []string{
	"src_up", "src_dn1",
	"src_ulcl_n6", "src_ulcl_n9", "src_ulcl_dn9",
	"src_n9",
	"src_vn",
	"src_dn",
}

func main() {
	target := flag.String("target", "127.0.0.1:10514", "bessd's control_v2 gRPC address")
	handshake := flag.String("handshake", "", "directory to signal each arm's end in (empty: run straight through)")
	flag.Parse()

	if err := run(*target, *handshake); err != nil {
		fmt.Fprintf(os.Stderr, "ifacepath: %v\n", err)
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
	if err := stopAll(ctx, client); err != nil {
		return err
	}
	if err := control(ctx, client); err != nil {
		return err
	}
	if err := pass(handshake, "control"); err != nil {
		return err
	}

	// One compiler for every arm: it owns the deployment's id spaces, and a
	// second one would hand out SEID 1, action 1 and meter 1 again.
	c := session.New(config(), client, slog.New(slog.NewTextHandler(os.Stdout,
		&slog.HandlerOptions{Level: slog.LevelInfo})))

	seid1, err := egress(ctx, client, c)
	if err != nil {
		return err
	}
	if err := pass(handshake, "egress"); err != nil {
		return err
	}
	if err := ulcl(ctx, client, c); err != nil {
		return err
	}
	if err := pass(handshake, "ulcl"); err != nil {
		return err
	}
	if err := ulclN9Down(ctx, client); err != nil {
		return err
	}
	if err := pass(handshake, "ulcl_n9_down"); err != nil {
		return err
	}
	if err := down(ctx, client, c); err != nil {
		return err
	}
	if err := pass(handshake, "down"); err != nil {
		return err
	}
	if err := mode1Down(ctx, client); err != nil {
		return err
	}
	if err := pass(handshake, "mode1_down"); err != nil {
		return err
	}
	var forwardExpiry time.Time
	if err := forwardArm(ctx, client, c, seid1, &forwardExpiry); err != nil {
		return err
	}
	if err := pass(handshake, "forward"); err != nil {
		return err
	}
	if err := forwardCleanupArm(ctx, client, c, seid1, forwardExpiry); err != nil {
		return err
	}
	if err := pass(handshake, "forward_cleanup"); err != nil {
		return err
	}
	if err := fiveGVN(ctx, client, c); err != nil {
		return err
	}
	if err := pass(handshake, "vn"); err != nil {
		return err
	}
	// The streams stay live through the concurrent window: the shell reads
	// the Dumps until every session's bytes have shown, then lets them stop.
	if err := concurrent(ctx, client, c); err != nil {
		return err
	}
	if err := pass(handshake, "concurrent"); err != nil {
		return err
	}
	if err := stopAll(ctx, client); err != nil {
		return err
	}
	if err := pass(handshake, "concurrent_stop"); err != nil {
		return err
	}
	if err := refusals(c); err != nil {
		return err
	}
	if err := pass(handshake, "refuse"); err != nil {
		return err
	}
	if err := arp(ctx, client, c, scenario.UE1); err != nil {
		return err
	}
	if err := pass(handshake, "arp"); err != nil {
		return err
	}
	if err := gone(ctx, client, c, seid1, scenario.UE1); err != nil {
		return err
	}
	if err := pass(handshake, "gone"); err != nil {
		return err
	}
	fmt.Println("ifacepath: every Source and Destination Interface value served (or refused) with its own egress")
	return nil
}

// pass is one arm boundary in the handshake with the caller: it signals that
// this arm's frames exist and waits for the caller to read them (a no-op
// without a directory).
func pass(dir, name string) error {
	return scenario.Pass(dir, name, 60*time.Second)
}

// control is the control arm: with no session and every stream stopped, no
// packet may leave any exit, and the daemon's own resources must be the
// deployment's (five next hops and one ARP entry, the interface's).
func control(ctx context.Context, client *bess.Client) error {
	// The deployment's next hops: a hop the resource did not take would show as
	// a frame leaving by the wrong exit, so it is checked here.
	hops, err := client.Contents(ctx, router+"/next_hops")
	if err != nil {
		return fmt.Errorf("reading rt/next_hops: %w", err)
	}
	entries := hops[router+"/next_hops"]
	if len(entries) != 5 {
		return fmt.Errorf("rt/next_hops holds %d next hops, and the deployment names 5: %v", len(entries), entries)
	}
	for _, e := range entries {
		id := fmt.Sprint(e.Key["id"])
		dst := fmt.Sprint(e.Value["dstMac"])
		// Hops 1 and 4 are the ones the lane byte-checks the L2 pair of; the
		// others name a gate alone (the encap builds the tunnel's own header,
		// and a re-injected packet keeps the addresses it arrives with).
		if (id == fmt.Sprint(hopN6) || id == fmt.Sprint(hopLAN)) && (dst == "<nil>" || dst == "") {
			return fmt.Errorf("next hop %s names no L2 pair: %v", id, e.Value)
		}
	}
	fmt.Printf("ifacepath: rt/next_hops: %v\n", entries)

	// The interface's own ARP entry: the deployment's, not a session's.
	if err := printARPEntries(ctx, client, "the deployment's"); err != nil {
		return err
	}

	before, err := snapshot(ctx, client)
	if err != nil {
		return err
	}
	time.Sleep(2 * time.Second)
	after, err := snapshot(ctx, client)
	if err != nil {
		return err
	}
	for i, e := range exits {
		if after[i] != before[i] {
			return fmt.Errorf("with every stream stopped and no session, %s gate %s counted %v packets (was %v)",
				e.module, e.gate, after[i], before[i])
		}
	}
	fmt.Printf("ifacepath: control: no session, every stream stopped, every exit at zero (%v)\n", after)
	return nil
}

// egress establishes the three sessions whose forward is toward the data
// network and starts their streams:
//
//   - S1: Destination Interface Core with no outer header (the instance's plain
//     hop, 1: N6);
//   - S2: Destination Interface Core with one (a tunnel out of the instance,
//     hop 3: N9);
//   - S3: Destination Interface SGi-LAN/N6-LAN with the Forwarding Policy it
//     requires (hop 4: the service LAN).
//
// Each uplink PDR's PDI names the instance its forward leaves by, and each
// forward is the egress the deployment declares for its value.
func egress(ctx context.Context, client *bess.Client, c *session.Compiler) (uint64, error) {
	cases := []scenario.Session{
		scenario.S1(peers),
		{
			Name:     "S2: Destination Interface Core with an outer header (a tunnel out of the instance)",
			Instance: internet, SEID: seidS2,
			Up: scenario.PDR{SrcIfc: ie.SrcInterfaceAccess, UE: ueS2, SDF: scenario.Port53Query, TEID: upTEID2,
				FAR: scenario.Forward(ie.DstInterfaceCore, scenario.Tunnel(dlTEID2, gnbAddr))},
			Down: scenario.PDR{SrcIfc: ie.SrcInterfaceCore, UE: ueS2, SDF: scenario.Port53,
				FAR: scenario.Forward(ie.DstInterfaceAccess, scenario.Tunnel(dlTEID2, gnbAddr))},
		},
		{
			Name:     "S3: Destination Interface SGi-LAN/N6-LAN with its Forwarding Policy",
			Instance: internet, SEID: seidS3,
			Up: scenario.PDR{SrcIfc: ie.SrcInterfaceAccess, UE: ueS3, SDF: scenario.Port53Query, TEID: upTEID3,
				FAR: scenario.Forward(ie.DstInterfaceSGiLANN6LAN, ie.NewForwardingPolicy(forwardingPolicy))},
			Down: scenario.PDR{SrcIfc: ie.SrcInterfaceCore, UE: ueS3, SDF: scenario.Port53,
				FAR: scenario.Forward(ie.DstInterfaceAccess, scenario.Tunnel(dlTEID3, gnbAddr))},
		},
	}
	before, err := snapshot(ctx, client)
	if err != nil {
		return 0, err
	}
	var seid1 uint64
	for _, cs := range cases {
		seid, err := establish(c, cs)
		if err != nil {
			return 0, err
		}
		if cs.SEID == scenario.SEID1 {
			seid1 = seid
		}
	}
	// The three uplink streams: S1's, S2's and S3's own G-PDUs, one stream each
	// (the frames are distinct, so a shared stream would not say whose exit
	// moved).
	if err := inject(ctx, client, "src_up", "src_up2", "src_up3"); err != nil {
		return 0, err
	}
	// Each session's own exit must move: S1's by the data network's hop (gate
	// 0), S2's by a tunnel out of the instance (gate 2), S3's by the service
	// LAN's (gate 3).
	for _, e := range []exit{{module: router, gate: n6Gate}, {module: router, gate: n9Gate}, {module: router, gate: lanGate}} {
		if _, err := waitFor(ctx, client, e.module, e.gate, value(before, e)); err != nil {
			return 0, fmt.Errorf("the %s exit (gate %s) never carried a packet: %w", e.module, e.gate, err)
		}
	}
	if err := stopAll(ctx, client); err != nil {
		return 0, err
	}
	if err := arpPresent(ctx, client, scenario.UE1, "S1's UE address"); err != nil {
		return 0, err
	}
	fmt.Println("ifacepath: egress: the data network's hop, a tunnel out of the instance and the service LAN each carried their frame")
	if seid1 == 0 {
		return 0, errors.New("the first case's answer named no session")
	}
	return seid1, nil
}

// ulcl establishes S8 (Mode 2): one session with two uplink PDRs and one
// tunnel. The destination selects the PDR, and the PDR's FAR selects the exit.
// The general filter matches port 53 at any destination; the specific one
// matches 10.46.0.2:53 and is given the higher precedence, so the two frames
// -- both on the session's one TEID -- leave by the data network's hop and by
// a tunnel out of the instance (N9) respectively.
func ulcl(ctx context.Context, client *bess.Client, c *session.Compiler) error {
	before, err := snapshot(ctx, client)
	if err != nil {
		return err
	}
	if _, err := establish(c, scenario.S8(peers)); err != nil {
		return err
	}
	if err := inject(ctx, client, "src_ulcl_n6", "src_ulcl_n9"); err != nil {
		return err
	}
	for _, e := range []exit{{module: router, gate: n6Gate}, {module: router, gate: n9Gate}} {
		if _, err := waitFor(ctx, client, e.module, e.gate, value(before, e)); err != nil {
			return fmt.Errorf("the ULCL session's %s exit (gate %s) never carried a packet: %w", e.module, e.gate, err)
		}
	}
	if err := stopAll(ctx, client); err != nil {
		return err
	}
	fmt.Println("ifacepath: ulcl: one session's two destinations left by the data network's hop and by a tunnel out of the instance")
	return nil
}

// ulclN9Down is Mode 2's other direction: the remote PSA's downlink arrives
// tunneled on S8's N9 F-TEID (endpoint 2), which admits it to the
// subscriber-side table, and S8's PDR for it tunnels it to the gNB -- the
// access side's exit, and never the data network's.
func ulclN9Down(ctx context.Context, client *bess.Client) error {
	return single(ctx, client, "src_ulcl_dn9", accessGate, n6Gate,
		"ulcl_n9_down: the remote PSA's N9 downlink left toward the gNB")
}

// down establishes S6 -- a PDR whose PDI names the service LAN's interface
// (Source Interface 2: the side toward the subscriber, whichever ingress the
// deployment gives the service fabric) and whose FAR names Destination
// Interface Core with no outer header -- and starts the data network's frame:
// it must leave by the instance's plain hop (gate 0), which is the N6 exit the
// uplink's own case uses from the other direction.
func down(ctx context.Context, client *bess.Client, c *session.Compiler) error {
	cs := scenario.Session{
		Name:     "S6: a PDR whose PDI names Source Interface 2 (SGi-LAN/N6-LAN), forwarding to Core",
		Instance: internet, SEID: seidS6,
		Up: scenario.PDR{SrcIfc: ie.SrcInterfaceAccess, UE: ueS6, SDF: scenario.Port53Query, TEID: upTEID6,
			FAR: scenario.Forward(ie.DstInterfaceCore)},
		Down: scenario.PDR{SrcIfc: ie.SrcInterfaceSGiLANN6LAN, UE: ueS6, SDF: scenario.Port53,
			FAR: scenario.Forward(ie.DstInterfaceCore)},
	}
	before, err := snapshot(ctx, client)
	if err != nil {
		return err
	}
	if _, err := establish(c, cs); err != nil {
		return err
	}
	if err := inject(ctx, client, "src_dn"); err != nil {
		return err
	}
	if _, err := waitFor(ctx, client, router, n6Gate, value(before, exit{module: router, gate: n6Gate})); err != nil {
		return fmt.Errorf("the data network's frame never left by the data network's exit: %w", err)
	}
	if err := stopAll(ctx, client); err != nil {
		return err
	}
	fmt.Println("ifacepath: down: a subscriber-side PDR's plain forward left by the data network's exit")
	return nil
}

// mode1Down is Mode 1's downlink: the data network's answer to S1's UE
// arrives on N6 and leaves through the encap toward S1's gNB.
func mode1Down(ctx context.Context, client *bess.Client) error {
	return single(ctx, client, "src_dn1", accessGate, n6Gate,
		"mode1_down: the data network's answer to S1's UE left toward its gNB")
}

// single starts one stream and requires its exit to move and another exit not
// to: the arms whose session is already established.
func single(ctx context.Context, client *bess.Client, src, want, not, done string) error {
	before, err := snapshot(ctx, client)
	if err != nil {
		return err
	}
	if err := inject(ctx, client, src); err != nil {
		return err
	}
	if _, err := waitFor(ctx, client, router, want, value(before, exit{module: router, gate: want})); err != nil {
		return fmt.Errorf("%s never left by gate %s: %w", src, want, err)
	}
	if err := stopAll(ctx, client); err != nil {
		return err
	}
	time.Sleep(time.Second)
	after, err := snapshot(ctx, client)
	if err != nil {
		return err
	}
	if grew := value(after, exit{module: router, gate: not}) - value(before, exit{module: router, gate: not}); grew != 0 {
		return fmt.Errorf("%s also carried %v packets by gate %s", src, grew, not)
	}
	fmt.Printf("ifacepath: %s\n", done)
	return nil
}

// forwardArm models the temporary N3 forwarding leg of Mode 6. It creates a
// separate FAR, rebinds only S1's uplink PDR, and starts the SMF timer when the
// accepted N4 modification installs that leg.
func forwardArm(ctx context.Context, client *bess.Client, c *session.Compiler, seid uint64, expiry *time.Time) error {
	before, err := snapshot(ctx, client)
	if err != nil {
		return err
	}
	if err := scenario.Modify(c, scenario.StartForward(seid, peers.GNB2), "creating the temporary forwarding FAR"); err != nil {
		return err
	}
	*expiry = time.Now().Add(scenario.ForwardingTimer)
	if err := inject(ctx, client, "src_up"); err != nil {
		return err
	}
	if _, err := waitFor(ctx, client, router, accessGate, value(before, exit{module: router, gate: accessGate})); err != nil {
		return fmt.Errorf("the temporary uplink forward toward the access side never reached it: %w", err)
	}
	if err := stopAll(ctx, client); err != nil {
		return err
	}
	time.Sleep(time.Second)
	after, err := snapshot(ctx, client)
	if err != nil {
		return err
	}
	if grew := value(after, exit{module: router, gate: n6Gate}) - value(before, exit{module: router, gate: n6Gate}); grew != 0 {
		return fmt.Errorf("the temporary access forward carried %v packets by the data network's exit", grew)
	}
	fmt.Printf("ifacepath: forward: temporary FAR %d tunneled the uplink to the target RAN; timer %s started\n",
		scenario.ForwardFARID, scenario.ForwardingTimer)
	return nil
}

// forwardCleanupArm waits for the timer started by forwardArm, then models the
// SMF's N4 cleanup: restore S1's steady FAR, remove the temporary FAR, and prove
// the live session forwards the same uplink stream through N6 again.
func forwardCleanupArm(ctx context.Context, client *bess.Client, c *session.Compiler, seid uint64, expiry time.Time) error {
	if expiry.IsZero() {
		return errors.New("the temporary forwarding timer was not started")
	}
	if remaining := time.Until(expiry); remaining > 0 {
		timer := time.NewTimer(remaining)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
	before, err := snapshot(ctx, client)
	if err != nil {
		return err
	}
	if err := scenario.Modify(c, scenario.EndForward(seid),
		fmt.Sprintf("restoring the steady FAR and removing temporary FAR %d", scenario.ForwardFARID)); err != nil {
		return err
	}
	if err := inject(ctx, client, "src_up"); err != nil {
		return err
	}
	if _, err := waitFor(ctx, client, router, n6Gate, value(before, exit{module: router, gate: n6Gate})); err != nil {
		return fmt.Errorf("the uplink stream did not resume through N6 after timer cleanup: %w", err)
	}
	if err := stopAll(ctx, client); err != nil {
		return err
	}
	after, err := snapshot(ctx, client)
	if err != nil {
		return err
	}
	if grew := value(after, exit{module: router, gate: accessGate}) - value(before, exit{module: router, gate: accessGate}); grew != 0 {
		return fmt.Errorf("the removed temporary FAR still sent %v packets toward the access side", grew)
	}
	fmt.Printf("ifacepath: forward_cleanup: timer expired; S1 returned to FAR 1 and temporary FAR %d was removed\n",
		scenario.ForwardFARID)
	return nil
}

// fiveGVN is the 5G VN case, both steps: S4 (an uplink PDR whose FAR names
// Destination Interface 5) re-injects its UE-to-UE packet into the
// subscriber-side table, where S5 (a PDR whose PDI names Source Interface 5G VN
// Internal) takes it and tunnels it to the target UE's gNB. The re-injection's
// hop is gate 4 and S5's forward is the access side's (gate 1).
func fiveGVN(ctx context.Context, client *bess.Client, c *session.Compiler) error {
	before, err := snapshot(ctx, client)
	if err != nil {
		return err
	}
	for _, cs := range []scenario.Session{scenario.S4(peers), scenario.S5(peers)} {
		if _, err := establish(c, cs); err != nil {
			return err
		}
	}
	if err := inject(ctx, client, "src_vn"); err != nil {
		return err
	}
	// The re-injection itself, then the target session's forward.
	if _, err := waitFor(ctx, client, router, vnGate, value(before, exit{module: router, gate: vnGate})); err != nil {
		return fmt.Errorf("the forward toward 5G VN Internal never reached the re-injection gate: %w", err)
	}
	if _, err := waitFor(ctx, client, router, accessGate, value(before, exit{module: router, gate: accessGate})); err != nil {
		return fmt.Errorf("the re-injected packet never reached the target session's own exit: %w", err)
	}
	if err := stopAll(ctx, client); err != nil {
		return err
	}
	fmt.Println("ifacepath: vn: the re-injected packet was matched on the 5G VN Internal side and left toward its own UE")
	return nil
}

// concurrent adds S9 (Mode 3: the uplink arrives on S9's N9 F-TEID, the same
// TEID S1 holds on N3, and leaves by N6) to the sessions the earlier arms left
// established -- S1 (Mode 1, back on its steady FAR after Mode 6's leg), S8
// (Mode 2), S4 and S5 (Mode 5) and S6 -- and starts every scenario's stream at
// once. Each exit a scenario names must move while all of them are live, and
// the exits none of them names (the service LAN's, the responder's) must not.
// The streams are left running: the shell reads each session's own bytes out
// of the Dump its exit feeds, and the caller stops them after the window.
func concurrent(ctx context.Context, client *bess.Client, c *session.Compiler) error {
	if _, err := establish(c, scenario.S9(peers)); err != nil {
		return err
	}
	before, err := snapshot(ctx, client)
	if err != nil {
		return err
	}
	if err := inject(ctx, client, concurrentStreams...); err != nil {
		return err
	}
	moved := []exit{
		{module: router, gate: n6Gate}, {module: router, gate: accessGate},
		{module: router, gate: n9Gate}, {module: router, gate: vnGate},
	}
	for _, e := range moved {
		if _, err := waitFor(ctx, client, e.module, e.gate, value(before, e)); err != nil {
			return fmt.Errorf("with every scenario live, the %s exit (gate %s) never carried a packet: %w", e.module, e.gate, err)
		}
	}
	time.Sleep(time.Second)
	after, err := snapshot(ctx, client)
	if err != nil {
		return err
	}
	for _, e := range []exit{{module: router, gate: lanGate}, {module: arpModule, gate: arpGate}} {
		if grew := value(after, e) - value(before, e); grew != 0 {
			return fmt.Errorf("with every scenario live, %s gate %s carried %v packets, and no scenario names it", e.module, e.gate, grew)
		}
	}
	delta := func(e exit) float64 { return value(after, e) - value(before, e) }
	fmt.Printf("ifacepath: concurrent: every scenario's exit moved with all sessions live "+
		"(N6 +%v, access +%v, N9 +%v, 5G VN +%v; service LAN +0, ARP +0)\n",
		delta(moved[0]), delta(moved[1]), delta(moved[2]), delta(moved[3]))
	return nil
}

// refusals drives every value and condition this UP does not serve, one
// establishment each: the SMF must read the cause that names the fault (73 for
// a rule it cannot carry, 66 for the IE that is missing) rather than an
// accepted session that serves nothing.
func refusals(c *session.Compiler) error {
	base := scenario.Session{Instance: internet, SEID: 0x4200,
		Up: scenario.PDR{SrcIfc: ie.SrcInterfaceAccess, UE: "10.45.1.1", SDF: scenario.Port53Query, TEID: 0x22223344,
			FAR: scenario.Forward(ie.DstInterfaceCore)},
		Down: scenario.PDR{SrcIfc: ie.SrcInterfaceCore, UE: "10.45.1.1", SDF: scenario.Port53,
			FAR: scenario.Forward(ie.DstInterfaceAccess, scenario.Tunnel(scenario.DLTEID1, gnbAddr))},
	}
	for _, tc := range []struct {
		name string
		// mutate is the case as this refusal sends it. want is the cause the
		// SMF must read.
		mutate func(*scenario.Session)
		want   uint8
	}{
		{"Source Interface 3 (CP-function)", func(cs *scenario.Session) {
			cs.Up.SrcIfc = ie.SrcInterfaceCPFunction
		}, ie.CauseRuleCreationModificationFailure},
		{"Source Interface 5 (a Spare value)", func(cs *scenario.Session) {
			cs.Up.SrcIfc = 5
		}, ie.CauseRuleCreationModificationFailure},
		{"Destination Interface 3 (CP-function)", func(cs *scenario.Session) {
			cs.Up.FAR = scenario.Forward(ie.DstInterfaceCPFunction)
		}, ie.CauseRuleCreationModificationFailure},
		{"Destination Interface 4 (LI Function)", func(cs *scenario.Session) {
			cs.Up.FAR = scenario.Forward(ie.DstInterfaceLIFunction)
		}, ie.CauseRuleCreationModificationFailure},
		{"Destination Interface 5 on an instance with no 5G VN egress", func(cs *scenario.Session) {
			cs.Up.FAR = scenario.Forward(ie.DstInterface5GVNInternal)
		}, ie.CauseRuleCreationModificationFailure},
		{"a forwarding FAR with no Forwarding Parameters", func(cs *scenario.Session) {
			cs.Up.FAR = []*ie.IE{ie.NewApplyAction(scenario.ApplyForw)}
		}, ie.CauseMandatoryIEMissing},
		{"Forwarding Parameters with no Destination Interface", func(cs *scenario.Session) {
			cs.Up.FAR = []*ie.IE{ie.NewApplyAction(scenario.ApplyForw), ie.NewForwardingParameters()}
		}, ie.CauseMandatoryIEMissing},
		{"SGi-LAN/N6-LAN with no Forwarding Policy", func(cs *scenario.Session) {
			cs.Up.FAR = scenario.Forward(ie.DstInterfaceSGiLANN6LAN)
		}, ie.CauseMandatoryIEMissing},
	} {
		cs := base
		cs.SEID++
		cs.Up.TEID += 0x10
		cs.Name = tc.name
		tc.mutate(&cs)
		resp, ok := c.Establish(cs.Message(local)).(*message.SessionEstablishmentResponse)
		if !ok {
			return fmt.Errorf("%s: the establishment answered no session-level response", tc.name)
		}
		got := scenario.Cause(resp.Cause)
		if got != tc.want {
			return fmt.Errorf("%s answered cause %d, want %d (the controller's own line names the value)", tc.name, got, tc.want)
		}
		fmt.Printf("ifacepath: refused: %s: cause %d\n", tc.name, got)
	}
	return nil
}

// arp is the subscriber's ARP identity: the session's address is in the
// responder's entries, and an ARP request for it is answered.
func arp(ctx context.Context, client *bess.Client, c *session.Compiler, ue string) error {
	if err := arpPresent(ctx, client, ue, "the session's UE address"); err != nil {
		return err
	}
	before, err := snapshot(ctx, client)
	if err != nil {
		return err
	}
	if err := inject(ctx, client, "src_arp"); err != nil {
		return err
	}
	if _, err := waitFor(ctx, client, arpModule, arpGate, value(before, exit{module: arpModule, gate: arpGate})); err != nil {
		return fmt.Errorf("the ARP request for %s was never answered: %w", ue, err)
	}
	if err := stopAll(ctx, client); err != nil {
		return err
	}
	fmt.Printf("ifacepath: arp: the reply for %s left the responder\n", ue)

	// One transaction's two entries. The pair's addresses collide in the
	// responder's table (the graph sizes it 65536, the constructor doubles it,
	// and the hash is `ip * 2654435761 & mask`), so both ride one transaction's
	// publish phase: publishing each into the slot it claimed at Reserve would
	// put them in one slot and lose one. Both must therefore be held, the
	// second must be answered over ARP too, and both must go with the session
	// (the erases are one transaction as well).
	cs := scenario.Session{
		Name:     "S7: two addresses of one session, one transaction",
		Instance: internet, SEID: seidS7,
		Up: scenario.PDR{SrcIfc: ie.SrcInterfaceAccess, UE: siblingA, SDF: scenario.Port53Query, TEID: upTEID7,
			FAR: scenario.Forward(ie.DstInterfaceCore)},
		Down: scenario.PDR{SrcIfc: ie.SrcInterfaceCore, UE: siblingA, SDF: scenario.Port53,
			FAR: scenario.Forward(ie.DstInterfaceAccess, scenario.Tunnel(dlTEID7, gnbAddr))},
		Down2: &scenario.PDR{SrcIfc: ie.SrcInterfaceCore, UE: siblingB, SDF: scenario.Port53,
			FAR: scenario.Forward(ie.DstInterfaceAccess, scenario.Tunnel(dlTEID7, gnbAddr))},
	}
	seid, err := establish(c, cs)
	if err != nil {
		return err
	}
	for _, addr := range []string{siblingA, siblingB} {
		if err := arpPresent(ctx, client, addr, "one address of the session's pair"); err != nil {
			return err
		}
	}
	fmt.Printf("ifacepath: arp: one transaction published both entries: %s and %s\n", siblingA, siblingB)
	// The Dump prints one packet per interval (a second, here) and the S1 reply
	// above took the current interval's one packet, so the pair's reply must
	// arrive after the next tick to be readable at all: the wait is the dump's
	// own policy, not the responder's.
	time.Sleep(1200 * time.Millisecond)
	before, err = snapshot(ctx, client)
	if err != nil {
		return err
	}
	if err := inject(ctx, client, "src_arp2"); err != nil {
		return err
	}
	if _, err := waitFor(ctx, client, arpModule, arpGate, value(before, exit{module: arpModule, gate: arpGate})); err != nil {
		return fmt.Errorf("the request for %s was never answered: %w", siblingA, err)
	}
	if err := stopAll(ctx, client); err != nil {
		return err
	}
	resp, ok := c.Delete(message.NewSessionDeletionRequest(0, 0, seid, 1, 0)).(*message.SessionDeletionResponse)
	if !ok {
		return errors.New("the pair's deletion answered no session-level response")
	}
	if got := scenario.Cause(resp.Cause); got != ie.CauseRequestAccepted {
		return fmt.Errorf("the pair's deletion answered cause %d", got)
	}
	for _, addr := range []string{siblingA, siblingB} {
		if err := arpAbsent(ctx, client, addr, "the pair's deletion leaves"); err != nil {
			return err
		}
	}
	fmt.Printf("ifacepath: arp: one transaction erased both entries: %s and %s\n", siblingA, siblingB)
	return nil
}

// gone deletes the session and proves the entry went with it: the address is no
// longer held, and an ARP request for it is not answered (the responder drops a
// request it holds no entry for, so nothing may appear on its gate).
func gone(ctx context.Context, client *bess.Client, c *session.Compiler, seid uint64, ue string) error {
	resp, ok := c.Delete(message.NewSessionDeletionRequest(0, 0, seid, 1, 0)).(*message.SessionDeletionResponse)
	if !ok {
		return errors.New("the deletion answered no session-level response")
	}
	if got := scenario.Cause(resp.Cause); got != ie.CauseRequestAccepted {
		return fmt.Errorf("the deletion answered cause %d", got)
	}
	if err := arpAbsent(ctx, client, ue, "after the deletion"); err != nil {
		return err
	}
	before, err := snapshot(ctx, client)
	if err != nil {
		return err
	}
	if err := inject(ctx, client, "src_arp"); err != nil {
		return err
	}
	time.Sleep(2 * time.Second)
	after, err := snapshot(ctx, client)
	if err != nil {
		return err
	}
	if grew := value(after, exit{module: arpModule, gate: arpGate}) - value(before, exit{module: arpModule, gate: arpGate}); grew != 0 {
		return fmt.Errorf("the deleted session's address was answered %v times, and the entry went with the session", grew)
	}
	if err := stopAll(ctx, client); err != nil {
		return err
	}
	fmt.Printf("ifacepath: gone: the deleted session's address %s is no longer answered\n", ue)
	return nil
}

// establish sends one case through ci/scenario and names it in the driver's
// log: the shell reads what each arm established from these lines.
func establish(c *session.Compiler, cs scenario.Session) (uint64, error) {
	seid, err := scenario.Establish(c, cs, local)
	if err != nil {
		return 0, err
	}
	fmt.Printf("ifacepath: established: %s (SEID %d, instance %q)\n", cs.Name, seid, cs.Instance)
	return seid, nil
}

// exit names one module's output gate.
type exit struct{ module, gate string }

// exits is every counter an arm compares: the router's five egresses and the
// responder's one.
var exits = []exit{
	{module: router, gate: n6Gate},
	{module: router, gate: accessGate},
	{module: router, gate: n9Gate},
	{module: router, gate: lanGate},
	{module: router, gate: vnGate},
	{module: arpModule, gate: arpGate},
}

// value finds an exit's count in a snapshot (the list's own order).
func value(counts []float64, e exit) float64 {
	for i, x := range exits {
		if x == e {
			return counts[i]
		}
	}
	return 0
}

// snapshot is every exit's count at one moment.
func snapshot(ctx context.Context, client *bess.Client) ([]float64, error) {
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

// arpEntriesOf is the responder's entries, keyed by address.
func arpEntriesOf(ctx context.Context, client *bess.Client) (map[string]string, error) {
	got, err := client.Contents(ctx, arpEntries)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", arpEntries, err)
	}
	out := map[string]string{}
	for _, e := range got[arpEntries] {
		out[fmt.Sprint(e.Key["ip"])] = fmt.Sprint(e.Value["macAddr"])
	}
	return out, nil
}

// printARPEntries prints the responder's entries, in address order.
func printARPEntries(ctx context.Context, client *bess.Client, what string) error {
	entries, err := arpEntriesOf(ctx, client)
	if err != nil {
		return err
	}
	line, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	fmt.Printf("ifacepath: %s ARP entries: %s\n", what, line)
	return nil
}

// arpPresent requires the responder to hold an entry for `ue`, with the
// interface's own MAC as its value.
func arpPresent(ctx context.Context, client *bess.Client, ue, what string) error {
	entries, err := arpEntriesOf(ctx, client)
	if err != nil {
		return err
	}
	mac, ok := entries[ue]
	if !ok {
		return fmt.Errorf("%s %s is not in %s: %v", what, ue, arpEntries, entries)
	}
	if mac != "02:00:00:00:06:01" {
		return fmt.Errorf("the entry for %s carries %q, want the interface's own 02:00:00:00:06:01", ue, mac)
	}
	fmt.Printf("ifacepath: the responder holds %s -> %s\n", ue, mac)
	return nil
}

// arpAbsent requires the responder to hold no entry for `ue`, and prints what
// it does hold: the other sessions' entries must have survived.
func arpAbsent(ctx context.Context, client *bess.Client, ue, what string) error {
	entries, err := arpEntriesOf(ctx, client)
	if err != nil {
		return err
	}
	if mac, ok := entries[ue]; ok {
		return fmt.Errorf("%s: the address %s is still held (%s): %v", what, ue, mac, entries)
	}
	line, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	// The label is the caller's, so the line that belongs to one check is not
	// the line another check greps (the shell reads its evidence out of this
	// log by prefix).
	fmt.Printf("ifacepath: %s %s holds %s\n", what, arpEntries, line)
	return nil
}

// inject starts the named streams: burst 32 is the graph's own setting, and
// every other stream stays at zero.
func inject(ctx context.Context, client *bess.Client, srcs ...string) error {
	for _, s := range streams {
		burst := 0
		if slices.Contains(srcs, s.name) {
			burst = 32
		}
		if err := setBurst(ctx, client, s.name, s.size, burst); err != nil {
			return err
		}
	}
	return nil
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

// config is the deployment's shape (deploy/iface-path.yaml), in the compiler's
// own terms: the two instances and their egress tables (the same hops the
// graph's rt/next_hops declares), the interface's ARP identity, and the module
// names the graph gives.
func config() session.Config {
	instances, err := routing.New([]routing.Interface{
		{
			Instance: internet, Domain: 1, NextHop: hopN6,
			Pool: []netip.Prefix{netip.MustParsePrefix(pool)},
			// Every egress this increment's grammar can name, as the -instances
			// flag spells them: a plain forward, a tunnel (N9, or indirect
			// forwarding), the service LAN, and the ARP identity the subscriber
			// addresses are answered with.
			Hops: map[routing.Egress]uint32{
				{DestIfc: ie.DstInterfaceCore}:               hopN6,
				{DestIfc: ie.DstInterfaceCore, Tunnel: true}: hopN9,
				{DestIfc: ie.DstInterfaceSGiLANN6LAN}:        hopLAN,
			},
			ARP: arpModule, ARPMAC: [6]byte{0x02, 0, 0, 0, 6, 1},
		},
		{
			Instance: vn, Domain: 2,
			Pool: []netip.Prefix{netip.MustParsePrefix(pool)},
			// Only the re-injection: a forward out of this instance that names
			// anything else is a rule the deployment does not serve.
			Hops: map[routing.Egress]uint32{
				{DestIfc: ie.DstInterface5GVNInternal}: hopVN,
			},
			ARP: arpModule, ARPMAC: [6]byte{0x02, 0, 0, 0, 6, 1},
		},
	}, 3)
	if err != nil {
		panic(err) // the deployment above is this program's own constant
	}
	return session.Config{
		GTPUDecap: "decap0",
		Up: session.Direction{
			PDRTable:  upModule,
			PDRFields: []session.Field{session.SrcIP, session.DstIP, session.Proto, session.SrcPort, session.DstPort, session.FTEIDContext, session.QFI},
			Meters:    "mt_ul",
			Counters:  "cnt_ul",
			NextHop:   hopN6,
			// The uplink chain's forward can add a tunnel of its own (the
			// indirect-forwarding case), so the encap's records are written for
			// this direction too.
			Tunnels: "enc",
		},
		Down: session.Direction{
			PDRTable:  downModule,
			PDRFields: []session.Field{session.SrcIP, session.DstIP, session.Proto, session.SrcPort, session.DstPort, session.RouteDomain, session.FTEIDContext, session.QFI},
			Meters:    "mt_dl",
			Counters:  "cnt_dl",
			NextHop:   hopAccess,
			Tunnels:   "enc",
		},
		Instances: instances,
		// The access side's own hop, whichever direction the PDR is on (the
		// lane's graph names it -access-next-hop 2).
		AccessNextHop: hopAccess,
		FTEIDEndpoints: []session.FTEIDEndpoint{{
			ID: 1, ReferencePoint: "n3", TransportRouteDomain: 1,
			SourceInterface: ie.SrcInterfaceAccess, IPv4: netip.MustParseAddr(n3Addr),
		}, {
			// The local end of a tunnel out of the instance (S2, S8's N9
			// branch): a Core-side FAR with Outer Header Creation needs an n9
			// endpoint of the forwarding instance to source it from.
			ID: 2, ReferencePoint: "n9", TransportRouteDomain: 1,
			SourceInterface: ie.SrcInterfaceCore, Instance: internet,
			IPv4: netip.MustParseAddr(n9Addr),
		}},
	}
}
