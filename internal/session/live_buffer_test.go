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

// bufferEstablishment is bufferEstablishmentFor with the BAR's DL Buffering
// Duration at the 30 s the release case holds under: long enough that nothing
// in that test's run can expire, so what the instruction releases is what the
// store held.
func bufferEstablishment(cpSEID uint64, ueIP string) *message.SessionEstablishmentRequest {
	return bufferEstablishmentFor(cpSEID, ueIP, 30*time.Second)
}

// bufferEstablishmentFor is pathEstablishment with the downlink FAR asking for
// the packets to be held -- Apply Action BUFF alone (TS 29.244 8.2.26), the BAR
// the SMF provisions and associates to it (5.2.4.1), and no forwarding
// parameters, the FAR an SMF sends for an idle UE whose downlink data is
// waiting -- and the BAR's DL Buffering Duration (8.2.29) chosen by the case:
// it is the number the compiler writes into the store's per-flow entry as
// `timeout_ns`, so the expiry proof needs one short enough to wait out and the
// release proof one long enough never to.
func bufferEstablishmentFor(cpSEID uint64, ueIP string, duration time.Duration) *message.SessionEstablishmentRequest {
	return pathEstablishmentWith(cpSEID, ueIP, "permit out udp from any to assigned 53",
		ie.NewCreateFAR(
			ie.NewFARID(2),
			ie.NewApplyAction(applyBuff),
			ie.NewBARID(1),
		),
		ie.NewCreateBAR(
			ie.NewBARID(1),
			ie.NewDLBufferingDuration(duration),
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
	// PacketStoreArg. The 30 s here is deliberately longer than this test's run,
	// so nothing expires under it; what the timeout_ns *does* is the sibling
	// test's proof (TestLiveSessionHoldsNothingAfterTheBufferingDurationPasses),
	// which waits out a short one and finds nothing left to release.
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

// downlinkSource is the graph's own downlink generator (deploy/buffer-path.yaml,
// deploy/session-path.yaml): the frames it keeps sending are what fills the
// store, and its live `settings` singleton is how this arm stops the stream for
// the expiry case and starts it again.
const downlinkSource = "src_dn"

// TestLiveSessionHoldsNothingAfterTheBufferingDurationPasses is the DL Buffering
// Duration's expiry, live, and it is stated as a bound rather than raced.
//
// The BAR's 8.2.29 number is the store's per-flow `timeout_ns` -- the sibling
// test above reads it back -- and the store frees a flow's packets once they are
// older than it. The freeing is not on a timer of the SMF's or ours: BESS's
// owner task sweeps 256 flows a run from where the last run stopped (the
// amendment to D-129 that landed with 0bfd2783, `EvictExpiredBounded`), and a
// run costs the same whatever the store holds. This session has one flow, so a
// rotation is one run and the bound after the deadline is the next run of the
// store's task -- not a fixed period: a blocked task is scheduled again within
// its own backoff (2^20 cycles at most, ~0.3 ms on this host), so the one-second
// margin this test waits over the duration is thousands of rotations. An older
// daemon frees only under pressure (`EvictExpired`, called when the store is at
// its global `max_packets`), which this store never approaches, so this case
// needs a daemon carrying the sweep as well as the `key_attrs` change.
//
// The expiry itself is silent: the sweep calls PacketFree, emits nothing on a
// gate and no metric, and this controller is not served the module's GetDesc, so
// there is no count to read and the observable is the *absence* of the later
// effect. That effect is the SMF's instruction (TS 29.244 5.2.4.1's Update FAR
// that forwards the buffered downlink), which the sibling test proves releases
// the flow and moves the encap 0 -> 11136. Here the flow was freed before the
// instruction arrived, so the release has nothing to send and the encap does not
// move at all.
//
// The differential is the per-flow entry itself, and it is why the wait is
// short: with `timeout_ns` absent the store's module-wide `timeout_ms` (5000 in
// deploy/buffer-path.yaml) is what holds the flow, so the same packets would
// still be there when the instruction arrives and the release *would* move the
// encap. Running this test against a compiler that writes no `timeout_ns` is
// therefore the failing case, and 2 s of duration with 1 s of margin keeps the
// wait under the module-wide 5 s so that only the entry can have freed them.
//
// The graph's downlink source is stopped once the store is filled, and started
// again before the test returns. That is this test's control of the generator,
// not an SMF instruction: with the source running, the instruction's own
// forwarding floods the encap with the graph's frames -- the sibling test's
// 11136 -- and one flow's handful of released packets could not be seen at all.
// Stopped, the release is the only thing that can move the encap.
//
// ci/buffer-path.sh starts the daemon, applies that graph and runs this test
// with UPF_BESS_TARGET set.
func TestLiveSessionHoldsNothingAfterTheBufferingDurationPasses(t *testing.T) {
	target := os.Getenv("UPF_BESS_TARGET")
	if target == "" {
		t.Skip("set UPF_BESS_TARGET (ci/buffer-path.sh does) to run against a live bessd")
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

	// The control arm, as in the release case: nothing is buffered and no flow
	// has numbers before this session exists, so what follows is the session's
	// doing.
	if before := countersOf(t, ctx, client, "cnt_buf"); len(before) != 0 {
		t.Fatalf("cnt_buf already measures %d rules before any session exists: %v", len(before), before)
	}
	if before := storeFlowEntries(t, ctx, client, cfg.Buffering.Store); len(before) != 0 {
		t.Fatalf("the store holds %d per-flow entries before any session exists: %v", len(before), before)
	}

	// The generator is the graph's own; this test stops it after the fill and
	// starts it again before it returns, so a later case sees the graph the
	// deployment applied.
	defer setSourceBurst(t, ctx, client, downlinkSource, 32)

	// The BAR's duration: short enough to wait out, with a margin over it that
	// the store's own timeout_ms cannot cover for (5 s module-wide).
	const duration = 2 * time.Second

	resp := c.Establish(bufferEstablishmentFor(0x6162, "10.45.0.2", duration)).(*message.SessionEstablishmentResponse)
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

	// 0. The store's entry carries the short duration. This is the number the
	// sweep reads for this flow; without it the module's own timeout_ms is what
	// the flow is held under (BESS's LimitsFor), which is the differential.
	entries := storeFlowEntries(t, ctx, client, cfg.Buffering.Store)
	if len(entries) != 1 {
		t.Fatalf("the store holds %d per-flow entries for one buffering session, want 1: %v", len(entries), entries)
	}
	if got := flowValueU64(t, entries[0].Value, "timeoutNs"); got != uint64(duration) {
		t.Errorf("the store's entry carries timeoutNs %v, want the BAR's %v", got, duration)
	}

	// 1. Fill: the count in front of the store is what the source puts there,
	// and the entry's cap (8.2.30's 16) has turned over several times by the
	// time the count reaches 64 -- so the flow is in the store with a full
	// queue, holding packets the source sent, when the generator stops.
	var counted uint64
	deadline := time.Now().Add(10 * time.Second)
	for {
		for _, count := range countersOf(t, ctx, client, "cnt_buf") {
			counted = count[0]
		}
		if counted >= 64 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the branch counted only %d packets in 10s: the graph's source is not filling the store; "+
				"output counters: %v", counted, chainCounters(t, ctx, client))
		}
		time.Sleep(50 * time.Millisecond)
	}

	// 2. Stop the generator, then let what the pipeline still holds settle.
	// The store stamps a packet when it drains it, so the last one stored is
	// the one the wait has to outlive; the branch's count standing still is how
	// that is seen.
	setSourceBurst(t, ctx, client, downlinkSource, 0)
	quiet := counted
	deadline = time.Now().Add(10 * time.Second)
	for {
		time.Sleep(200 * time.Millisecond)
		for _, count := range countersOf(t, ctx, client, "cnt_buf") {
			counted = count[0]
		}
		if counted == quiet {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the branch kept counting after the generator stopped: %d packets, was %d", counted, quiet)
		}
		quiet = counted
	}

	// Still held: the branch counted the arrivals and the encap has nothing.
	// What the store holds now is held, not forwarded.
	forwardedBefore := gatePackets(t, ctx, client, "enc")

	// 3. Wait out the duration plus the margin: past the deadline, inside the
	// module-wide timeout that would hold the flow without the entry.
	time.Sleep(duration + time.Second)

	// 4. The SMF's instruction: an Update FAR that forwards, with the gNB's
	// tunnel -- the same one the release case sends. The compiler ends the
	// buffering episode with it and tells the store to release this flow, and
	// the store has nothing left under it.
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

	// 5. Nothing moves. A release is accepted, not completed (the store applies
	// the request on a later run), so this waits a second where the bound is
	// the store's next run -- a second that no release is coming to fill.
	time.Sleep(time.Second)
	forwarded := gatePackets(t, ctx, client, "enc")
	if forwarded != forwardedBefore {
		t.Fatalf("the encap carried %v packets after the instruction (was %v): the store still held this flow, "+
			"so its per-flow timeoutNs did not free it and the module-wide timeout_ms had not expired it either -- "+
			"the state this test separates from a flow the sweep did free",
			forwarded-forwardedBefore, forwardedBefore)
	}

	// The instruction did land: the branch's counter entry and the store's
	// per-flow entry are gone with the episode (compile erases both), so the
	// flat encap is not a session that never moved.
	if counts := countersOf(t, ctx, client, "cnt_buf"); len(counts) != 0 {
		t.Fatalf("the branch still measures %d rules after the flow stopped buffering: %v", len(counts), counts)
	}
	if entries := storeFlowEntries(t, ctx, client, cfg.Buffering.Store); len(entries) != 0 {
		t.Fatalf("the store still holds %d per-flow entries after the flow stopped buffering: %v", len(entries), entries)
	}
	t.Logf("held: %d packets counted on the branch under the BAR's timeout_ns %v, freed by the store's own sweep; "+
		"forwarded after the wait: %v -> %v", counted, duration, forwardedBefore, forwarded)
}

// setSourceBurst writes the burst of one of the graph's generators, live: the
// Source's `settings` singleton (source.cc, D-129) is read once a run by the
// module's task, and 0 makes it allocate nothing -- the stream stops without the
// graph being changed. 32 is the graph's own burst (deploy/buffer-path.yaml).
func setSourceBurst(t *testing.T, ctx context.Context, client *bess.Client, module string, burst int) {
	t.Helper()
	if err := client.Apply(ctx, bess.Change{
		Resource: module + "/settings",
		Value:    map[string]any{"pkt_size": 51, "burst": burst},
	}); err != nil {
		t.Fatalf("setting %s/settings to burst %d: %v", module, burst, err)
	}
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
