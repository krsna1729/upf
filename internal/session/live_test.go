// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"context"
	"log/slog"
	"net/netip"
	"os"
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/bess"
)

// liveConfig is the graph deploy/session-live.yaml deploys: the module names,
// exactly as a deployment spells them.
func liveConfig() Config {
	cfg := testConfig()
	cfg.TEIDTable = "teid"
	cfg.TEIDGate = 0
	cfg.Up = Direction{
		PDRTable:  "pdr_ul",
		PDRFields: []Field{SrcIP, DstIP, Proto, SrcPort, DstPort, QFI},
		Actions:   "at_ul",
		Meters:    "mt_ul",
		Counters:  "cnt_ul",
		NextHop:   1,
	}
	cfg.Down = Direction{
		PDRTable:  "pdr_dl",
		PDRFields: []Field{SrcIP, DstIP, Proto, SrcPort, DstPort},
		Actions:   "at_dl",
		Meters:    "mt_dl",
		Counters:  "cnt_dl",
		NextHop:   2,
		Tunnels:   "enc",
	}
	// UPF_PROFILE=custom is the keyed per-session matcher on both directions
	// (deploy/pdrmatch-path.yaml): the same lab, the same module names, the
	// uplink's rules in `pdr_match_ul` instead of the wildcard table, and the
	// downlink's in `pdr_match_dl`, whose session `sel_dl` names by the UE
	// address the packet is addressed to.
	if os.Getenv("UPF_PROFILE") == CustomProfile {
		cfg.Up.PDRTable, cfg.Up.PDRFields = "", nil
		cfg.Up.PdrMatch = "pdr_match_ul"
		cfg.Down.PDRTable, cfg.Down.PDRFields = "", nil
		cfg.Down.PdrMatch = "pdr_match_dl"
		cfg.Down.Selector = "sel_dl"
		cfg.Down.SelectorActions = "sel_at"
		cfg.Down.SelectorFields = []Field{DstIP}
	}
	// UPF_FIREWALL=1 is the generic profile's other strategy on both
	// directions (deploy/firewall-path.yaml): the stock firewall module holds
	// each direction's PDRs as one ordered policy, behind the same ActionTables.
	if os.Getenv("UPF_FIREWALL") == "1" {
		cfg.Up.PDRTable, cfg.Up.PDRFields, cfg.Up.Firewall = "", nil, "fw_ul"
		cfg.Down.PDRTable, cfg.Down.PDRFields, cfg.Down.Firewall = "", nil, "fw_dl"
	}
	cfg.N3Addr = netip.MustParseAddr("192.0.2.1")
	cfg.N3MAC = [6]byte{2, 0, 0, 0, 0, 1}
	cfg.PeerMAC = [6]byte{2, 0, 0, 0, 0, 2}
	// MaxActions, MaxMeters and MaxTEIDs keep their defaults: the lab graphs
	// declare those capacities (65536) on their Meter, ActionTable and
	// GtpuEncap modules, and the compiler's id spaces must equal them -- a
	// session whose meter id is beyond the capacity is refused as invalid.
	return cfg
}

// TestLiveSessionProgramsTheDaemon runs the whole control path against a real
// bessd with the plugin loaded: the compiler's transaction is built from the
// daemon's own schema (every message named as the descriptor says, protobuf
// JSON under it), the daemon validates the references between the resources it
// writes, and it commits all of it or none of it. Nothing here is recorded:
// a message the daemon does not accept fails the test with what it said.
//
// ci/session-live.sh starts the daemon, applies deploy/session-live.yaml and
// runs this test with UPF_BESS_TARGET set.
func TestLiveSessionProgramsTheDaemon(t *testing.T) {
	target := os.Getenv("UPF_BESS_TARGET")
	if target == "" {
		t.Skip("set UPF_BESS_TARGET (ci/session-live.sh does) to run against a live bessd")
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

	// Establish: eleven records across six resources, in one transaction.
	resp := c.Establish(establishment(0x1111, "10.45.0.2")).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the daemon refused the establishment with cause %d", got)
	}
	var teid uint32
	if len(resp.CreatedPDR) == 0 {
		t.Fatal("the answer carries no Created PDR")
	}
	children, err := resp.CreatedPDR[0].CreatedPDR()
	if err != nil {
		t.Fatal(err)
	}
	for _, ch := range children {
		if ch.Type == ie.FTEID {
			f, err := ch.FTEID()
			if err != nil {
				t.Fatal(err)
			}
			teid = f.TEID
		}
	}
	if teid == 0 {
		t.Fatal("the Created PDR carries no F-TEID")
	}
	t.Logf("established SEID %d, TEID %#x", upFSEID(t, resp), teid)

	// A retransmission must not write again: the daemon would refuse a second
	// key or, worse, a second session's records would sit in the tables.
	again := c.Establish(establishment(0x1111, "10.45.0.2")).(*message.SessionEstablishmentResponse)
	if got := cause(t, again); got != ie.CauseRequestAccepted {
		t.Fatalf("the retransmission answered cause %d", got)
	}
	if upFSEID(t, again) != upFSEID(t, resp) {
		t.Errorf("the retransmission got SEID %d, the first answered %d",
			upFSEID(t, again), upFSEID(t, resp))
	}

	// Modify: the downlink tunnel moves to another gNB endpoint, and the whole
	// session is rewritten (same keys, new contents) in one transaction.
	mod := message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 2, 0,
		ie.NewUpdateFAR(ie.NewFARID(2), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceAccess),
				ie.NewOuterHeaderCreation(0x0100, 0x55667788, "10.20.30.9", "", 0, 0, 0),
			)),
	)
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the daemon refused the modification with cause %d", got)
	}

	// Delete: every record the session wrote is erased. The daemon refuses an
	// erase of a key that is not there, so a clean answer means the compiler
	// named exactly what it had written.
	if got := cause(t, c.Delete(message.NewSessionDeletionRequest(0, 0, upFSEID(t, resp), 3, 0))); got != ie.CauseRequestAccepted {
		t.Fatalf("the daemon refused the deletion with cause %d", got)
	}

	// And once more: a retransmitted deletion is answered, not applied (the
	// session is gone from the compiler, and the daemon from the ledger).
	if got := cause(t, c.Delete(message.NewSessionDeletionRequest(0, 0, upFSEID(t, resp), 4, 0))); got != ie.CauseSessionContextNotFound {
		t.Errorf("a retransmitted deletion answered cause %d, want session-not-found", got)
	}
}

// TestLiveStartupSweepErasesStaleSessions is the restart wall (docs/design.md):
// a controller that comes up against a daemon still holding an earlier run's
// session takes it out before it serves PFCP, in one transaction. The stale
// entries are written the way a previous run wrote them -- through the
// compiler's own transaction -- so the sweep's readback and its erase keys are
// exercised against the daemon's schema, and the daemon is the one that says
// whether the erase was valid.
func TestLiveStartupSweepErasesStaleSessions(t *testing.T) {
	target := os.Getenv("UPF_BESS_TARGET")
	if target == "" {
		t.Skip("set UPF_BESS_TARGET (ci/session-live.sh does) to run against a live bessd")
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
	c := client

	// What an earlier controller left behind: a session programmed into the
	// daemon before the process died.
	stale := New(liveConfig(), c, quietLogger())
	resp := stale.Establish(establishment(0x6201, "10.45.0.2")).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the stale establishment answered cause %d", got)
	}

	// The tables the sweep must cover, from the compiler's own list: one it
	// stops reading is a stale session it cannot take out.
	before, err := c.Contents(ctx, stale.resources()...)
	if err != nil {
		t.Fatalf("reading the tables the stale session wrote: %v", err)
	}
	entries := 0
	for _, e := range before {
		entries += len(e)
	}
	if entries == 0 {
		t.Fatal("the stale session left nothing behind: the sweep would have nothing to take out")
	}

	// The restart: a fresh process sweeps before its PFCP socket opens.
	fresh := New(liveConfig(), c, quietLogger())
	if err := fresh.Sweep(ctx); err != nil {
		t.Fatalf("the startup sweep: %v", err)
	}
	after, err := c.Contents(ctx, fresh.resources()...)
	if err != nil {
		t.Fatalf("reading the tables after the sweep: %v", err)
	}
	for _, name := range fresh.resources() {
		if n := len(after[name]); n != 0 {
			t.Errorf("%s holds %d entries after the sweep, want none", name, n)
		}
	}

	// The sweep takes out sessions, not the deployment: the graph's own next
	// hops are not a session's resource and survive.
	hops, err := c.Contents(ctx, "rt/next_hops")
	if err != nil {
		t.Fatalf("reading the graph's next hops: %v", err)
	}
	if len(hops["rt/next_hops"]) == 0 {
		t.Error("the sweep erased the graph's own next hops")
	}
}

// TestLiveSessionSharesOneFTEIDPerCHOOSEID programs a session whose two uplink
// PDIs carry one CHOOSE ID (TS 29.244 8.2.3) into a real daemon. The unit test
// beside it checks what the compiler builds; this one checks that the daemon
// takes it -- two PDIs on one TEID rule is one (resource, key) written once,
// which is what the engine's transaction rules allow -- and that the answer the
// SMF would read names one TEID for both.
func TestLiveSessionSharesOneFTEIDPerCHOOSEID(t *testing.T) {
	target := os.Getenv("UPF_BESS_TARGET")
	if target == "" {
		t.Skip("set UPF_BESS_TARGET (ci/session-live.sh does) to run against a live bessd")
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

	c := New(liveConfig(), client, quietLogger())
	resp := c.Establish(chidEstablishment(0x2222, "10.45.0.4", 3, 3)).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the daemon refused the establishment with cause %d", got)
	}
	defer func() {
		del := message.NewSessionDeletionRequest(0, 0, upFSEID(t, resp), 9, 0)
		if got := cause(t, c.Delete(del)); got != ie.CauseRequestAccepted {
			t.Errorf("the daemon refused the deletion with cause %d", got)
		}
	}()
	one, two := createdTEID(t, resp.CreatedPDR, 1), createdTEID(t, resp.CreatedPDR, 2)
	if one == 0 || two == 0 {
		t.Fatalf("the answer carries no F-TEID for one of the two PDIs (%#x, %#x)", one, two)
	}
	if one != two {
		t.Errorf("two PDIs with CHOOSE ID 3 got TEIDs %#x and %#x: they asked for one tunnel", one, two)
	}
	t.Logf("established SEID %d: two PDIs, one F-TEID %#x", upFSEID(t, resp), one)
}
