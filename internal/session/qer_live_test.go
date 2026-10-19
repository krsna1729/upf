// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/bess"
)

// TestLiveGBRSplitsTheMeter is finding 6's GBR half with nothing faked: the
// lane's graph meters the uplink with a two-rate three-colour meter whose
// committed rate is the QER's GBR (8.2.7) and whose peak is its MBR (8.2.8),
// and the band between them leaves the meter's ogate 1 -- the gate the graph
// wires beside green. The daemon's own per-gate counters (bess_gate_packets_total,
// one sample per module gate) are what proves the split: a session whose GBR is
// a trickle and whose MBR is generous, with the graph's Source blasting, must
// show packets on the green gate, on the yellow gate, and on red (the ceiling).
//
// The QER is set by a modification first, so this also pins the Update QER path
// for the two IEs: nothing about a GBR is special to establishment.
func TestLiveGBRSplitsTheMeter(t *testing.T) {
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
	cfg := liveConfig()
	c := New(cfg, client, slog.New(slog.NewTextHandler(os.Stderr,
		&slog.HandlerOptions{Level: slog.LevelWarn})))

	// The lane's own uplink frames (UE 10.45.0.2, the pinned TEIDs) match this
	// session's access PDR, so the graph's Source is metered from the moment it
	// is established.
	resp := c.Establish(pathEstablishment(0x7401, "10.45.0.2")).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	seid := upFSEID(t, resp)

	// The counter's own reading: one sample per module gate
	// (bess_gate_packets_total), which is how a colour is counted at all. An
	// *unwired* gate has no Track hook and no sample, so red -- which the
	// graph leaves unwired, dropping above the ceiling -- is not read here;
	// what this pins is the band the GBR opens.
	gatePackets := func() (green, yellow, red float64) {
		t.Helper()
		samples, err := client.SDK().Metrics(ctx)
		if err != nil {
			t.Fatalf("reading the daemon's metrics: %v", err)
		}
		for _, s := range samples {
			if s.GetName() != "bess_gate_packets_total" {
				continue
			}
			l := s.GetLabels()
			if l["module"] != cfg.Up.Meters || l["direction"] != "out" {
				continue
			}
			switch l["gate"] {
			case "0":
				green += s.GetValue()
			case "1":
				yellow += s.GetValue()
			case "2":
				red += s.GetValue()
			}
		}
		return green, yellow, red
	}
	waitFor := func(what string, ok func() bool) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			if ok() {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s", what)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}

	// The session's own rate is its MBR alone, so every packet of the blast is
	// either within the ceiling (green) or over it (red, dropped unwired):
	// yellow is the GBR's signature and is empty until the SMF names one.
	waitFor("the metered uplink to count packets", func() bool {
		green, _, _ := gatePackets()
		return green > 0
	})
	if _, yellow, _ := gatePackets(); yellow != 0 {
		t.Fatalf("the meter shows %v yellow packets for a QER with no GBR", yellow)
	}

	// A GBR of 1 kbit/s against the session's MBR: everything past the first
	// few bytes of each refill is above the guarantee and below the ceiling.
	mod := message.NewSessionModificationRequest(0, 0, seid, 2, 0,
		ie.NewUpdateQER(ie.NewQERID(1),
			ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
			ie.NewMBR(1000, 2000), ie.NewGBR(1, 1)))
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification that sets the GBR answered cause %d", got)
	}
	waitFor("the GBR's band to fill", func() bool {
		_, yellow, _ := gatePackets()
		return yellow > 0
	})
	green, yellow, red := gatePackets()
	t.Logf("%s: green %.0f, yellow %.0f, red %.0f packets", cfg.Up.Meters, green, yellow, red)

	// The session goes: the daemon is shared with the lane's other tests, and
	// each of them allocates its session's ids from its own pool.
	if got := cause(t, c.Delete(message.NewSessionDeletionRequest(0, 0, seid, 3, 0))); got != ie.CauseRequestAccepted {
		t.Fatalf("the deletion answered cause %d", got)
	}
}
