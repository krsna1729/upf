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
		PDRFields: []Field{SrcIP, DstIP, Proto, SrcPort, DstPort},
		Actions:   "at_ul",
		Meters:    "mt_ul",
		NextHop:   1,
	}
	cfg.Down = Direction{
		PDRTable:  "pdr_dl",
		PDRFields: []Field{SrcIP, DstIP, Proto, SrcPort, DstPort},
		Actions:   "at_dl",
		Meters:    "mt_dl",
		NextHop:   2,
		Tunnels:   "enc",
	}
	cfg.N3Addr = netip.MustParseAddr("192.0.2.1")
	cfg.N3MAC = [6]byte{2, 0, 0, 0, 0, 1}
	cfg.PeerMAC = [6]byte{2, 0, 0, 0, 0, 2}
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
	t.Logf("established SEID %d, TEID %#x", resp.Header.SEID, teid)

	// A retransmission must not write again: the daemon would refuse a second
	// key or, worse, a second session's records would sit in the tables.
	again := c.Establish(establishment(0x1111, "10.45.0.2")).(*message.SessionEstablishmentResponse)
	if got := cause(t, again); got != ie.CauseRequestAccepted {
		t.Fatalf("the retransmission answered cause %d", got)
	}
	if again.Header.SEID != resp.Header.SEID {
		t.Errorf("the retransmission got SEID %d, the first answered %d",
			again.Header.SEID, resp.Header.SEID)
	}

	// Modify: the downlink tunnel moves to another gNB endpoint, and the whole
	// session is rewritten (same keys, new contents) in one transaction.
	mod := message.NewSessionModificationRequest(0, 0, resp.Header.SEID, 2, 0,
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
	if got := cause(t, c.Delete(message.NewSessionDeletionRequest(0, 0, resp.Header.SEID, 3, 0))); got != ie.CauseRequestAccepted {
		t.Fatalf("the daemon refused the deletion with cause %d", got)
	}

	// And once more: a retransmitted deletion is answered, not applied (the
	// session is gone from the compiler, and the daemon from the ledger).
	if got := cause(t, c.Delete(message.NewSessionDeletionRequest(0, 0, resp.Header.SEID, 4, 0))); got != ie.CauseSessionContextNotFound {
		t.Errorf("a retransmitted deletion answered cause %d, want session-not-found", got)
	}
}
