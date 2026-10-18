// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/bess"
)

// liveBuffering is the buffering branch of deploy/session-path.yaml, as upfd's
// flags spell it (-buffer-store, -buffer-counter, -buffer-gate).
func liveBuffering(cfg *Config) {
	cfg.Buffering = &Buffering{Store: "buf", Counter: "cnt_buf", Gate: 1}
}

// bufferEstablishment is pathEstablishment with the downlink FAR asking for the
// packets to be held: Apply Action BUFF alone (TS 29.244 8.2.26), the BAR the
// SMF provisions and associates to it (5.2.4.1), and no forwarding parameters --
// the FAR an SMF sends for an idle UE whose downlink data is waiting.
func bufferEstablishment(cpSEID uint64, ueIP string) *message.SessionEstablishmentRequest {
	return pathEstablishmentWith(cpSEID, ueIP, "permit out udp from any to assigned 53",
		ie.NewCreateFAR(
			ie.NewFARID(2),
			ie.NewApplyAction(applyBuff),
			ie.NewBARID(1),
		),
		ie.NewCreateBAR(
			ie.NewBARID(1),
			ie.NewDLBufferingDuration(30*time.Second),
			ie.NewDLBufferingSuggestedPacketCount(16),
		),
	)
}

// TestLiveSessionBuffersAndReleasesTheHeldPackets is the buffering proof against
// a real daemon: an SMF that asks for the packets to be held gets exactly that
// -- the packets reach the store and do not cross -- it is told which PDR's
// first packet is being held, and the instruction that moves the path releases
// what was held into the action path, where the new instruction applies.
//
// The evidence is the graph's own counters: the branch's counting module is
// what the Downlink Data Report is decided from, and the encap's output gate is
// where a downlink packet leaves the UPF once it is forwarded. The graph's
// downlink source runs from the moment it is applied, so a flat encap output
// while the branch's counter moves is "held, not forwarded".
//
// ci/session-path.sh starts the daemon, applies that graph and runs this test
// with UPF_BESS_TARGET set.
func TestLiveSessionBuffersAndReleasesTheHeldPackets(t *testing.T) {
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
	cfg := liveConfig()
	liveBuffering(&cfg)
	c := New(cfg, client, log)

	// The control arm: nothing is buffered before this session exists, so a
	// later non-zero reading is the session's doing, and the store holds no
	// flow's own numbers either.
	if before := countersOf(t, ctx, client, "cnt_buf"); len(before) != 0 {
		t.Fatalf("cnt_buf already measures %d rules before any session exists: %v", len(before), before)
	}
	if before := storeFlowEntries(t, ctx, client, cfg.Buffering.Store); len(before) != 0 {
		t.Fatalf("the store holds %d per-flow entries before any session exists: %v", len(before), before)
	}
	forwardedBefore := gatePackets(t, ctx, client, "enc")

	resp := c.Establish(bufferEstablishment(0x6161, "10.45.0.2")).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the daemon refused the establishment with cause %d", got)
	}
	seid := upFSEID(t, resp)
	defer func() {
		del := message.NewSessionDeletionRequest(0, 0, seid, 9, 0)
		if got := cause(t, c.Delete(del)); got != ie.CauseRequestAccepted {
			t.Errorf("the deletion answered cause %d", got)
		}
	}()

	// 0. The store's own entry carries the SMF's numbers, live: 8.2.29's
	// duration as the flow's timeout_ns and 8.2.30's Suggested Packet Count as
	// its max_packets_per_flow (deviation 1 of docs/compliance.md's BUFF row).
	// This is what makes the BAR cap and expire the flow rather than the graph's
	// PacketStoreArg. The expiry itself is the store's own task (EvictExpired
	// frees the packets at this timeout) and is not observable through this
	// controller's control surface -- no module description or held-packet
	// counter is served -- so this arm proves the numbers reached the store, not
	// their effect.
	entries := storeFlowEntries(t, ctx, client, cfg.Buffering.Store)
	if len(entries) != 1 {
		t.Fatalf("the store holds %d per-flow entries for one buffering session, want 1: %v", len(entries), entries)
	}
	if got := flowValueU64(t, entries[0].Value, "timeoutNs"); got != uint64(30*time.Second) {
		t.Errorf("the store's entry carries timeoutNs %v, want the BAR's 30s", got)
	}
	if got := flowValueU64(t, entries[0].Value, "maxPacketsPerFlow"); got != 16 {
		t.Errorf("the store's entry carries maxPacketsPerFlow %v, want the BAR's 16", got)
	}

	// 1. Held: the packets reach the branch's counter -- which is the store's
	// input -- and the encap's output does not move.
	var held uint64
	deadline := time.Now().Add(10 * time.Second)
	for {
		counts := countersOf(t, ctx, client, "cnt_buf")
		for _, count := range counts {
			held = count[0]
		}
		if held != 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no packet reached the buffering branch within 10s; output counters: %v",
				chainCounters(t, ctx, client))
		}
		time.Sleep(100 * time.Millisecond)
	}
	if forwarded := gatePackets(t, ctx, client, "enc"); forwarded != forwardedBefore {
		t.Fatalf("the encap carried %v packets (was %v) while the FAR only asked to hold them",
			forwarded-forwardedBefore, forwardedBefore)
	}

	// 2. The SMF is owed a Downlink Data Report naming the PDR whose first
	// packet is held (5.2.4.1), and exactly one: the reading is windowed, and a
	// second tick owes nothing for the same episode.
	owed := c.EvaluateDownlinks(ctx)
	if len(owed) != 1 {
		t.Fatalf("%d sessions owe a Downlink Data Report, want 1: %+v", len(owed), owed)
	}
	if len(owed[0].PDRs) != 1 || owed[0].PDRs[0] != 2 {
		t.Fatalf("the report names PDRs %v, want the downlink PDR 2", owed[0].PDRs)
	}
	if owed[0].SEID != seid {
		t.Fatalf("the report is for session %d, want %d", owed[0].SEID, seid)
	}
	c.ConfirmDownlinks(ctx, owed[0].SEID, owed[0].PDRs)
	if again := c.EvaluateDownlinks(ctx); len(again) != 0 {
		t.Fatalf("a second reading owes %d reports for one episode: %+v", len(again), again)
	}

	// 3. The SMF moves the path: an Update FAR that forwards, with the gNB's
	// tunnel. The compiler writes the action record and the tunnel in that
	// transaction and releases what the flow held, so the held packets leave
	// under the instruction this very request wrote.
	mod := message.NewSessionModificationRequest(0, 0, seid, 7, 0,
		ie.NewUpdateFAR(
			ie.NewFARID(2),
			ie.NewApplyAction(applyForw),
			ie.NewUpdateForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceAccess),
				ie.NewOuterHeaderCreation(0x0100, pathDownTEID, "10.20.30.2", "", 0, 0, 0),
			),
		))
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the daemon refused the modification with cause %d", got)
	}

	var forwarded float64
	deadline = time.Now().Add(10 * time.Second)
	for {
		forwarded = gatePackets(t, ctx, client, "enc")
		if forwarded > forwardedBefore {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the held packets did not reach the encap within 10s after the instruction "+
				"(encap output %v, was %v); output counters: %v",
				forwarded, forwardedBefore, chainCounters(t, ctx, client))
		}
		time.Sleep(100 * time.Millisecond)
	}

	// The episode is over: the branch's counter entry is gone with the rule
	// that buffered (compile erases it), so nothing is counted for a flow that
	// no longer holds anything. The store's per-flow entry goes with it -- the
	// numbers were the instruction for an episode that is over, and a later
	// session that reuses the ActionId must not inherit them.
	if counts := countersOf(t, ctx, client, "cnt_buf"); len(counts) != 0 {
		t.Fatalf("the branch still measures %d rules after the flow stopped buffering: %v",
			len(counts), counts)
	}
	if entries := storeFlowEntries(t, ctx, client, cfg.Buffering.Store); len(entries) != 0 {
		t.Fatalf("the store still holds %d per-flow entries after the flow stopped buffering: %v",
			len(entries), entries)
	}
	t.Logf("held: %d packets counted on the branch; forwarded after the instruction: %v -> %v",
		held, forwardedBefore, forwarded)
}

// storeFlowEntries reads the store's per-flow "flows" entries as the daemon
// holds them: the SMF's own numbers for each flow (8.2.29, 8.2.30), keyed by
// the ActionId the rule carries.
func storeFlowEntries(t *testing.T, ctx context.Context, client *bess.Client, store string) []bess.Entry {
	t.Helper()
	got, err := client.Contents(ctx, store+"/flows")
	if err != nil {
		t.Fatalf("reading %s/flows: %v", store, err)
	}
	return got[store+"/flows"]
}

// flowValueU64 reads a 64-bit field of a "flows" entry's value as the daemon
// reported it. The SDK decodes the entry's protobuf JSON with UseNumber, so a
// uint32 arrives as a number and a uint64 as a string (protojson's 64-bit form);
// both are read here. `field` is the proto field's JSON name (protojson's
// lowerCamelCase: "timeoutNs", "maxPacketsPerFlow").
func flowValueU64(t *testing.T, value map[string]any, field string) uint64 {
	t.Helper()
	switch v := value[field].(type) {
	case json.Number:
		n, err := strconv.ParseUint(v.String(), 10, 64)
		if err != nil {
			t.Fatalf("the entry's %s is %v, not a number: %v", field, value[field], err)
		}
		return n
	case string:
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			t.Fatalf("the entry's %s is %q, not a number: %v", field, v, err)
		}
		return n
	default:
		t.Fatalf("the entry carries no %s: %v", field, value)
		return 0
	}
}
