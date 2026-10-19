// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"context"
	"errors"
	"math"
	"strconv"
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/bess"
)

// bufferingConfig is the test graph with the buffering branch deploy/upf.yaml
// declares: the store, the counting module in front of it, and the gate a BUFF
// rule delivers on (upfd's -buffer-store, -buffer-counter, -buffer-gate).
func bufferingConfig() Config {
	cfg := testConfig()
	cfg.Buffering = &Buffering{Store: "buf", Counter: "cnt_buf", Gate: 1}
	return cfg
}

// buffEstablishment is establishment() with the downlink FAR asking for the
// packets to be held -- Apply Action BUFF and nothing else (8.2.26) -- and the
// BAR it is associated with (7.5.2.6, 8.2.55).
func buffEstablishment(cpSEID uint64, ueIP string) *message.SessionEstablishmentRequest {
	return buffEstablishmentWithBAR(cpSEID, ueIP, barDurationAndCount())
}

func barDurationAndCount() *ie.IE {
	return ie.NewCreateBAR(
		ie.NewBARID(1),
		ie.NewDLBufferingDuration(30*time.Second),
		ie.NewDLBufferingSuggestedPacketCount(16),
	)
}

func buffEstablishmentWithBAR(cpSEID uint64, ueIP string, bar *ie.IE) *message.SessionEstablishmentRequest {
	req := establishment(cpSEID, ueIP)
	req.CreateFAR[1] = ie.NewCreateFAR(
		ie.NewFARID(2),
		ie.NewApplyAction(applyBuff),
		ie.NewBARID(1),
	)
	req.CreateBAR = bar
	return req
}

// TestABuffFARIsGatedToTheStoreAndCounted is what the compiler writes for a FAR
// whose Apply Action is BUFF: the rule leaves the PDR table by the buffering
// gate instead of the drop gate, it still carries an ActionId (the flow's key in
// the store and in the counter in front of it), no action record is written --
// nothing forwards -- and the branch's counter is what makes the flow's first
// packet visible to the reporting side (5.2.4.1).
func TestABuffFARIsGatedToTheStoreAndCounted(t *testing.T) {
	rec := &recorder{}
	c := New(bufferingConfig(), rec, quietLogger())

	resp := c.Establish(buffEstablishment(0x7101, "10.45.0.7")).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	changes := rec.last()
	r := ruleCarrying(t, changes, fieldDstIP, []byte{10, 45, 0, 7})
	if got := r.gate(); got != 1 {
		t.Errorf("a BUFF FAR's rule gates %d, want the buffering gate 1", got)
	}
	flow := r.actionID()
	if flow == 0 {
		t.Fatal("a BUFF FAR's rule carries no ActionId: the store has no flow to key on")
	}
	find(t, changes, "cnt_buf/counters", "action_id", flow)
	// The action record *is* written, and it has to be: the engine validates a
	// rule's action_id as a reference whatever gate the rule takes (D-021), so a
	// buffering rule naming an id nothing upserts is refused and the session is
	// lost -- what the live arm found. The release path reads the same record
	// when the store's gate 0 re-enters the action path, and the modification
	// that stops buffering updates this key in place.
	action := find(t, changes, actionsRes(c.cfg.Down), "id", flow)
	if got := action.Value["next_hop_id"]; got == nil {
		t.Error("a BUFF FAR's action record carries no next hop: the release path would have nowhere to send the packets")
	}
	for _, ch := range changes {
		if ch.Resource == c.cfg.Down.Tunnels {
			t.Errorf("a BUFF FAR wrote a tunnel record in %s: nothing is encapsulated until the SMF says forward", ch.Resource)
		}
	}
}

// TestDeletingABufferingSessionErasesItsBufferCounter pins the other half of
// the entry's life: it is written so that "a later erase has something to
// erase", and a deletion is that later erase. It is what the live arm needs to
// hold -- the n4 package's DDN test establishes a buffering session, gets its
// report and deletes it, and if the counter entry outlives the deletion the
// next test in the same daemon reads a table that is not empty, which is
// exactly how ci/buffer-path.sh failed.
func TestDeletingABufferingSessionErasesItsBufferCounter(t *testing.T) {
	cfg := bufferingConfig()
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())

	resp := c.Establish(buffEstablishment(0x7101, "10.45.0.7")).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	flow := ruleCarrying(t, rec.last(), fieldDstIP, []byte{10, 45, 0, 7}).actionID()
	if flow == 0 {
		t.Fatal("a BUFF FAR's rule carries no ActionId")
	}
	find(t, rec.last(), bufferCountersRes(cfg.Buffering), "action_id", flow)

	if got := cause(t, c.Delete(message.NewSessionDeletionRequest(0, 0, upFSEID(t, resp), 9, 0))); got != ie.CauseRequestAccepted {
		t.Fatalf("the deletion answered cause %d", got)
	}
	for _, ch := range rec.last() {
		if ch.Resource != bufferCountersRes(cfg.Buffering) || ch.Value != nil {
			continue
		}
		if id, ok := ch.Key["action_id"].(uint32); ok && id == flow {
			return
		}
	}
	t.Errorf("the deletion wrote no erase for %s's entry for action %d: the entry outlives the session and the next test in the daemon sees a table that is not empty",
		bufferCountersRes(cfg.Buffering), flow)
}

// TestABARTheSessionDoesNotHoldIsRefused pins the reference rule: a FAR that
// names a BAR the session does not have asks for buffering under numbers nobody
// sent, which 5.2.4.1 makes the CP function's instruction. The establishment is
// refused (cause 73) rather than compiled against a guess -- the same answer a
// PDR naming an unprovisioned URR gets.
func TestABARTheSessionDoesNotHoldIsRefused(t *testing.T) {
	rec := &recorder{}
	c := New(bufferingConfig(), rec, quietLogger())

	req := buffEstablishment(0x7102, "10.45.0.7")
	req.CreateBAR = nil
	resp := c.Establish(req).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRuleCreationModificationFailure {
		t.Fatalf("a FAR naming a BAR the session does not hold answered cause %d, want 73", got)
	}
}

// TestTheBARsParametersAreReadWhereverTheySit reads the two parameters this UPF
// can honour (8.2.29's timer and 8.2.30's count), including the two codes of the
// duration that are not durations: all-zero is the deactivated timer (no
// instruction) and the infinite unit is hold-without-expiry. The last is the one
// value that reaches the store as a timeout of zero.
func TestTheBARsParametersAreReadWhereverTheySit(t *testing.T) {
	rec := &recorder{}
	c := New(bufferingConfig(), rec, quietLogger())

	resp := c.Establish(buffEstablishment(0x7103, "10.45.0.7")).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	seid := upFSEID(t, resp)
	entry := c.sessions[seid].BARs[1]
	if entry == nil {
		t.Fatal("the session holds no BAR 1 after establishing one")
	}
	if !entry.hasDuration || entry.duration != 30*time.Second || entry.infinite {
		t.Errorf("the BAR's duration is %+v, want 30s", entry)
	}
	if !entry.hasCount || entry.count != 16 {
		t.Errorf("the BAR's suggested count is %+v, want 16", entry)
	}
	if ns, ok := entry.timeoutNS(); !ok || ns != uint64(30*time.Second) {
		t.Errorf("the flow's timeout is (%d, %v), want (30s, true)", ns, ok)
	}

	// An Update BAR in a modification carries what changes: the deactivated
	// timer clears the override, and the count goes with it.
	mod := message.NewSessionModificationRequest(0, 0, seid, 7, 0,
		ie.NewUpdateBAR(
			ie.UpdateBARWithinSessionModificationRequest,
			ie.NewBARID(1),
			ie.NewDLBufferingDuration(0),
			ie.NewDLBufferingSuggestedPacketCount(0),
		))
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification answered cause %d", got)
	}
	entry = c.sessions[seid].BARs[1]
	if entry.hasDuration || entry.hasCount {
		t.Errorf("an all-zero Update BAR left %+v, want no instruction at all", entry)
	}
	if _, ok := entry.timeoutNS(); ok {
		t.Error("a deactivated timer still yields a timeout: the module's own default is the instruction")
	}

	// The infinite unit is the other non-duration: hold until the SMF says what
	// to do, which the store reads as a timeout of zero.
	mod = message.NewSessionModificationRequest(0, 0, seid, 8, 0,
		ie.NewUpdateBAR(
			ie.UpdateBARWithinSessionModificationRequest,
			ie.NewBARID(1),
			ie.NewDLBufferingDuration(time.Duration(math.MaxInt64)),
		))
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification answered cause %d", got)
	}
	entry = c.sessions[seid].BARs[1]
	if !entry.infinite {
		t.Fatalf("the infinite timer was read as %+v", entry)
	}
	if ns, ok := entry.timeoutNS(); !ok || ns != 0 {
		t.Errorf("the infinite timer's timeout is (%d, %v), want (0, true)", ns, ok)
	}
}

// TestABufferingFlowsOwnNumbersAreWrittenToTheStore closes deviation (1) of
// docs/compliance.md's BUFF row: the store's per-flow "flows" entry is the
// SMF's own instruction for that flow -- 8.2.29's DL Buffering Duration as the
// store's timeout_ns and 8.2.30's Suggested Packet Count as its
// max_packets_per_flow -- keyed by the same ActionId the rule carries (BESS
// D-129), so the numbers cap and expire this flow rather than the graph's
// arguments. It follows the BAR the PDR's FAR names through an update, and the
// deactivated and infinite codes reach the entry as the store reads them
// (absent, and a present zero for hold-without-expiry).
func TestABufferingFlowsOwnNumbersAreWrittenToTheStore(t *testing.T) {
	cfg := bufferingConfig()
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())

	resp := c.Establish(buffEstablishment(0x7104, "10.45.0.7")).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	flow := ruleCarrying(t, rec.last(), fieldDstIP, []byte{10, 45, 0, 7}).actionID()
	if flow == 0 {
		t.Fatal("a BUFF FAR's rule carries no ActionId")
	}
	entry := find(t, rec.last(), flowsRes(cfg.Buffering), "id", flow)
	if got := entry.Value["timeout_ns"]; got != uint64(30*time.Second) {
		t.Errorf("the flow's entry carries timeout_ns %v, want the BAR's 30s", got)
	}
	if got := entry.Value["max_packets_per_flow"]; got != uint32(16) {
		t.Errorf("the flow's entry carries max_packets_per_flow %v, want the BAR's 16", got)
	}

	// An Update BAR rewrites the entry: the numbers the SMF sent last are the
	// ones in force.
	mod := message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 7, 0,
		ie.NewUpdateBAR(
			ie.UpdateBARWithinSessionModificationRequest,
			ie.NewBARID(1),
			ie.NewDLBufferingDuration(10*time.Second),
			ie.NewDLBufferingSuggestedPacketCount(64),
		))
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification answered cause %d", got)
	}
	entry = find(t, rec.last(), flowsRes(cfg.Buffering), "id", flow)
	if got := entry.Value["timeout_ns"]; got != uint64(10*time.Second) {
		t.Errorf("after the update the flow's entry carries timeout_ns %v, want 10s", got)
	}
	if got := entry.Value["max_packets_per_flow"]; got != uint32(64) {
		t.Errorf("after the update the flow's entry carries max_packets_per_flow %v, want 64", got)
	}

	// The deactivated timer and a zero count are no instruction: the entry
	// carries neither field, so the module's own numbers stay in force for this
	// flow.
	mod = message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 8, 0,
		ie.NewUpdateBAR(
			ie.UpdateBARWithinSessionModificationRequest,
			ie.NewBARID(1),
			ie.NewDLBufferingDuration(0),
			ie.NewDLBufferingSuggestedPacketCount(0),
		))
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification answered cause %d", got)
	}
	entry = find(t, rec.last(), flowsRes(cfg.Buffering), "id", flow)
	if _, ok := entry.Value["timeout_ns"]; ok {
		t.Errorf("a deactivated timer still wrote a timeout: %+v", entry.Value)
	}
	if _, ok := entry.Value["max_packets_per_flow"]; ok {
		t.Errorf("a zero count still wrote a cap: %+v", entry.Value)
	}

	// The infinite unit is hold-without-expiry, which the store reads as a
	// present timeout of zero -- not as "absent", which would be the graph's.
	mod = message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 9, 0,
		ie.NewUpdateBAR(
			ie.UpdateBARWithinSessionModificationRequest,
			ie.NewBARID(1),
			ie.NewDLBufferingDuration(time.Duration(math.MaxInt64)),
		))
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification answered cause %d", got)
	}
	entry = find(t, rec.last(), flowsRes(cfg.Buffering), "id", flow)
	got, ok := entry.Value["timeout_ns"]
	if !ok || got != uint64(0) {
		t.Errorf("the infinite timer wrote timeout_ns %v (present %v), want a present 0", got, ok)
	}

	// A deletion takes the entry out with the rest of the session's records.
	if got := cause(t, c.Delete(message.NewSessionDeletionRequest(0, 0, upFSEID(t, resp), 9, 0))); got != ie.CauseRequestAccepted {
		t.Fatalf("the deletion answered cause %d", got)
	}
	erased := false
	for _, ch := range rec.last() {
		if ch.Resource != flowsRes(cfg.Buffering) || ch.Value != nil {
			continue
		}
		if id, ok := ch.Key["id"].(uint32); ok && id == flow {
			erased = true
		}
	}
	if !erased {
		t.Errorf("the deletion wrote no erase for %s's entry for action %d: the entry outlives the session",
			flowsRes(cfg.Buffering), flow)
	}
}

// TestAnUpdateBARInASessionReportResponseIsAppliedToTheSession closes deviation
// (3) of docs/compliance.md's BUFF row: 5.2.4.1 lets the CP function extend a
// flow's buffering when it answers a Downlink Data Report, and the Update BAR it
// carries there is applied to the same model a Session Modification's Update BAR
// writes -- the DL Buffering Duration (8.2.29, with the stopped-timer and
// infinite codes) and the DL Buffering Suggested Packet Count (8.2.30).
func TestAnUpdateBARInASessionReportResponseIsAppliedToTheSession(t *testing.T) {
	rec := &recorder{}
	c := New(bufferingConfig(), rec, quietLogger())

	resp := c.Establish(buffEstablishment(0x7109, "10.45.0.7")).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	seid := upFSEID(t, resp)
	// The numbers a Session Modification set, which the response replaces.
	if entry := c.sessions[seid].BARs[1]; entry == nil || entry.duration != 30*time.Second || entry.count != 16 {
		t.Fatalf("the establishment's BAR is %+v, want 30s/16", entry)
	}

	c.ApplyUpdateBAR(context.Background(), seid, ie.NewUpdateBARWithinSessionReportResponse(
		ie.NewBARID(1),
		ie.NewDLBufferingDuration(10*time.Second),
		ie.NewDLBufferingSuggestedPacketCount(64),
	))
	entry := c.sessions[seid].BARs[1]
	if !entry.hasDuration || entry.duration != 10*time.Second || entry.infinite {
		t.Errorf("the response's duration left %+v, want 10s", entry)
	}
	if !entry.hasCount || entry.count != 64 {
		t.Errorf("the response's suggested count left %+v, want 64", entry)
	}
	if ns, ok := entry.timeoutNS(); !ok || ns != uint64(10*time.Second) {
		t.Errorf("the flow's timeout is (%d, %v), want (10s, true)", ns, ok)
	}

	// The infinite unit is hold-without-expiry, exactly as in a modification.
	c.ApplyUpdateBAR(context.Background(), seid, ie.NewUpdateBARWithinSessionReportResponse(
		ie.NewBARID(1),
		ie.NewDLBufferingDuration(time.Duration(math.MaxInt64)),
	))
	entry = c.sessions[seid].BARs[1]
	if !entry.infinite {
		t.Fatalf("the infinite timer in a response was read as %+v", entry)
	}
	if ns, ok := entry.timeoutNS(); !ok || ns != 0 {
		t.Errorf("the infinite timer's timeout is (%d, %v), want (0, true)", ns, ok)
	}

	// And the deactivated code clears the override, as 8.2.29 says.
	c.ApplyUpdateBAR(context.Background(), seid, ie.NewUpdateBARWithinSessionReportResponse(
		ie.NewBARID(1),
		ie.NewDLBufferingDuration(0),
		ie.NewDLBufferingSuggestedPacketCount(0),
	))
	entry = c.sessions[seid].BARs[1]
	if entry.hasDuration || entry.hasCount {
		t.Errorf("an all-zero Update BAR in a response left %+v, want no instruction at all", entry)
	}
}

// TestAnUpdateBARInAReportResponseRewritesTheStoreEntry is the store half of
// 5.2.4.1's extension: the numbers a Session Report Response carries reach the
// per-flow "flows" entry of the flow that is holding packets now, so the
// extended duration and cap are what expire and cap it -- not only the model,
// which the next request to compile the session would have written anyway.
func TestAnUpdateBARInAReportResponseRewritesTheStoreEntry(t *testing.T) {
	cfg := bufferingConfig()
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())

	resp := c.Establish(buffEstablishment(0x710b, "10.45.0.7")).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	seid := upFSEID(t, resp)
	flow := ruleCarrying(t, rec.last(), fieldDstIP, []byte{10, 45, 0, 7}).actionID()
	if flow == 0 {
		t.Fatal("a BUFF FAR's rule carries no ActionId")
	}

	c.ApplyUpdateBAR(context.Background(), seid, ie.NewUpdateBARWithinSessionReportResponse(
		ie.NewBARID(1),
		ie.NewDLBufferingDuration(10*time.Second),
		ie.NewDLBufferingSuggestedPacketCount(64),
	))
	entry := find(t, rec.last(), flowsRes(cfg.Buffering), "id", flow)
	if got := entry.Value["timeout_ns"]; got != uint64(10*time.Second) {
		t.Errorf("the response left the store entry's timeout_ns %v, want 10s", got)
	}
	if got := entry.Value["max_packets_per_flow"]; got != uint32(64) {
		t.Errorf("the response left the store entry's max_packets_per_flow %v, want 64", got)
	}
}

// TestAnUpdateBARForABARTheSessionDoesNotHoldIsIgnored is the stray-response
// case: the SMF names a BAR the session does not have. It must not create one or
// overwrite something else -- it is a no-op, the way a report response with no
// report waiting for it is ignored (internal/n4.onReportResponse).
func TestAnUpdateBARForABARTheSessionDoesNotHoldIsIgnored(t *testing.T) {
	rec := &recorder{}
	c := New(bufferingConfig(), rec, quietLogger())

	resp := c.Establish(buffEstablishment(0x710a, "10.45.0.7")).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	seid := upFSEID(t, resp)
	txns := len(rec.txns)

	c.ApplyUpdateBAR(context.Background(), seid, ie.NewUpdateBARWithinSessionReportResponse(
		ie.NewBARID(2),
		ie.NewDLBufferingDuration(10*time.Second),
		ie.NewDLBufferingSuggestedPacketCount(64),
	))

	if len(c.sessions[seid].BARs) != 1 {
		t.Errorf("the session holds %d BARs after an Update BAR for BAR 2, want the one it had",
			len(c.sessions[seid].BARs))
	}
	if entry := c.sessions[seid].BARs[1]; entry.duration != 30*time.Second || entry.count != 16 {
		t.Errorf("the BAR the session holds is now %+v, want the establishment's 30s/16", entry)
	}
	if len(rec.txns) != txns {
		t.Errorf("an Update BAR the session cannot place wrote %d transactions, want none", len(rec.txns)-txns)
	}
}

// TestASessionReportResponseWithNoUpdateBARChangesNothing: 5.2.4.1 makes the
// Update BAR optional in the answer, so a response that carries none is the
// common case and must leave the session's BARs exactly as a modification set
// them.
func TestASessionReportResponseWithNoUpdateBARChangesNothing(t *testing.T) {
	rec := &recorder{}
	c := New(bufferingConfig(), rec, quietLogger())

	resp := c.Establish(buffEstablishment(0x710c, "10.45.0.7")).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	seid := upFSEID(t, resp)
	txns := len(rec.txns)

	c.ApplyUpdateBAR(context.Background(), seid, nil)

	if entry := c.sessions[seid].BARs[1]; entry == nil ||
		entry.duration != 30*time.Second || entry.count != 16 {
		t.Errorf("the BAR is %+v after a response with no Update BAR, want the establishment's 30s/16", entry)
	}
	if len(rec.txns) != txns {
		t.Errorf("a response with no Update BAR wrote %d transactions, want none", len(rec.txns)-txns)
	}
}

// TestAnUpdateBARAfterTheEpisodeEndedIsIgnored: an Update BAR in a Session
// Report Response answers a Downlink Data Report for a flow that was buffering.
// If the SMF's own later instruction already moved that PDR off buffering, the
// numbers arrive for an episode that is over, and applying them would leave them
// for a later episode they were never sent for (5.2.4.1's "stop applying
// buffering when new instruction is received" is that move, and a response does
// not undo it).
func TestAnUpdateBARAfterTheEpisodeEndedIsIgnored(t *testing.T) {
	rec := &recorder{}
	c := New(bufferingConfig(), rec, quietLogger())

	resp := c.Establish(buffEstablishment(0x710b, "10.45.0.7")).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	seid := upFSEID(t, resp)

	// The SMF's own instruction moves the FAR to forward: the episode is over.
	mod := message.NewSessionModificationRequest(0, 0, seid, 7, 0,
		ie.NewUpdateFAR(
			ie.NewFARID(2),
			ie.NewApplyAction(applyForw),
			ie.NewUpdateForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceAccess),
				ie.NewOuterHeaderCreation(0x0100, 0x55667788, "10.20.30.2", "", 0, 0, 0),
			),
		))
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification answered cause %d", got)
	}
	txns := len(rec.txns)

	c.ApplyUpdateBAR(context.Background(), seid, ie.NewUpdateBARWithinSessionReportResponse(
		ie.NewBARID(1),
		ie.NewDLBufferingDuration(10*time.Second),
		ie.NewDLBufferingSuggestedPacketCount(64),
	))
	if entry := c.sessions[seid].BARs[1]; entry == nil || entry.duration != 30*time.Second || entry.count != 16 {
		t.Errorf("the BAR is %+v after an Update BAR for an ended episode, want the establishment's 30s/16", entry)
	}
	if len(rec.txns) != txns {
		t.Errorf("an Update BAR for an ended episode wrote %d transactions, want none", len(rec.txns)-txns)
	}
}

// TestAModificationThatStopsBufferingReleasesTheFlow is the instruction half of
// 5.2.4.1: "the UP function shall stop applying buffering when new instruction
// is received from the CP function. The buffered packets shall be either dropped
// or forwarded". The modification that gives the PDR a forward path is that
// instruction, so the flow's held packets are released -- after the transaction
// that moved the FAR has landed -- and they leave by the action path the same
// request wrote.
func TestAModificationThatStopsBufferingReleasesTheFlow(t *testing.T) {
	rec := &recorder{}
	c := New(bufferingConfig(), rec, quietLogger())

	resp := c.Establish(buffEstablishment(0x7104, "10.45.0.7")).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	seid := upFSEID(t, resp)
	flow := ruleCarrying(t, rec.last(), fieldDstIP, []byte{10, 45, 0, 7}).actionID()

	mod := message.NewSessionModificationRequest(0, 0, seid, 7, 0,
		ie.NewUpdateFAR(
			ie.NewFARID(2),
			ie.NewApplyAction(applyForw),
			ie.NewUpdateForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceAccess),
				ie.NewOuterHeaderCreation(0x0100, 0x55667788, "10.20.30.2", "", 0, 0, 0),
			),
		))
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification answered cause %d", got)
	}
	if len(rec.released) != 1 {
		t.Fatalf("the store was told to release %v, want one release of buf/<the flow>", rec.released)
	} else if got := rec.released[0][len("buf/"):]; got != strconv.FormatUint(uint64(flow), 10) {
		t.Errorf("the release names flow %s, want the rule's ActionId %d", got, flow)
	}
	if stats := c.Stats(); stats.BuffersReleased != 1 {
		t.Errorf("the release is counted %d times, want 1", stats.BuffersReleased)
	}

	// The rule forwards now, with an action record: the packets that were held
	// leave into the action path, and the next ones do not stop at the store.
	changes := rec.last()
	if got := ruleCarrying(t, changes, fieldDstIP, []byte{10, 45, 0, 7}).gate(); got != 0 {
		t.Errorf("the rule still gates %d after the FAR forwards, want 0", got)
	}
	find(t, changes, actionsRes(c.cfg.Down), "id", flow)
}

// TestADeletionDropsWhatTheFlowHeld is the other half of 5.2.4.1's "dropped or
// forwarded": a session that is going away has no path to forward its held
// packets over, so the store is told to drop them.
func TestADeletionDropsWhatTheFlowHeld(t *testing.T) {
	rec := &recorder{}
	c := New(bufferingConfig(), rec, quietLogger())

	resp := c.Establish(buffEstablishment(0x7105, "10.45.0.7")).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	seid := upFSEID(t, resp)
	flow := ruleCarrying(t, rec.last(), fieldDstIP, []byte{10, 45, 0, 7}).actionID()

	del := message.NewSessionDeletionRequest(0, 0, seid, 9, 0)
	if got := cause(t, c.Delete(del)); got != ie.CauseRequestAccepted {
		t.Fatalf("the deletion answered cause %d", got)
	}
	if len(rec.dropped) != 1 {
		t.Fatalf("the store was told to drop %v, want one drop of buf/%d", rec.dropped, flow)
	}
	if got := rec.dropped[0]; got != "buf/"+strconv.FormatUint(uint64(flow), 10) {
		t.Errorf("the drop names %s, want buf/%d", got, flow)
	}
}

// TestAReleaseTheStoreRefusesIsCountedNotFatal pins the failure policy: the
// SMF's instruction is in force whether or not the store takes the command, so a
// refused release is a count and a log line, never a refusal of the
// modification -- answering a failure would make the SMF re-apply a change that
// already landed.
func TestAReleaseTheStoreRefusesIsCountedNotFatal(t *testing.T) {
	rec := &recorder{storeFail: errors.New("no such module")}
	c := New(bufferingConfig(), rec, quietLogger())

	resp := c.Establish(buffEstablishment(0x7106, "10.45.0.7")).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	mod := message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 7, 0,
		ie.NewUpdateFAR(
			ie.NewFARID(2),
			ie.NewApplyAction(applyForw),
			ie.NewUpdateForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceAccess),
				ie.NewOuterHeaderCreation(0x0100, 0x55667788, "10.20.30.2", "", 0, 0, 0),
			),
		))
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("a store that refused the release failed the modification with cause %d", got)
	}
	if stats := c.Stats(); stats.BufferFailures != 1 {
		t.Errorf("the refused release is counted %d times, want 1", stats.BufferFailures)
	}
}

// TestTheDownlinkReportIsOwedOncePerBufferingEpisode is the DDN decision: the
// SMF is told about the first buffered packet of each PDR (5.2.4.1), once, and
// the reading is the branch's counters -- windowed, so the stamp means "a packet
// arrived since the previous reading". The episode ends when the instruction
// arrives, so a later BUFF owes its own report.
func TestTheDownlinkReportIsOwedOncePerBufferingEpisode(t *testing.T) {
	rec := &recorder{}
	c := New(bufferingConfig(), rec, quietLogger())

	resp := c.Establish(buffEstablishment(0x7107, "10.45.0.7")).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	seid := upFSEID(t, resp)
	flow := ruleCarrying(t, rec.last(), fieldDstIP, []byte{10, 45, 0, 7}).actionID()

	// Nothing has arrived: the reading has no window stamp, and no report is
	// owed. The counter's cells outlive a rule, so "Packets > 0" would not be
	// evidence of anything -- the stamp is what says a packet crossed since the
	// previous reading.
	rec.counts = nil
	if got := c.EvaluateDownlinks(context.Background()); len(got) != 0 {
		t.Fatalf("a reading with no packet stamp owes %d reports: %+v", len(got), got)
	}

	// A packet arrived and the FAR asked for no notification: the flow holds it
	// and the CP function hears nothing. NOCP is the SMF's own field for this
	// (8.2.26), so a Downlink Data Report sent without it is a message the SMF
	// did not ask for -- and it is the arm this establishment exists in, its FAR
	// carrying BUFF alone.
	arrived := time.Now()
	rec.counts = map[string][]bess.RuleCount{
		"cnt_buf": {{ActionID: flow, Packets: 3, Octets: 153, First: arrived, Last: arrived}},
	}
	if got := c.EvaluateDownlinks(context.Background()); len(got) != 0 {
		t.Fatalf("a BUFF FAR that named no NOCP owed %d reports: %+v", len(got), got)
	}

	// Then the SMF asks to be told. The episode is the same one -- the packets
	// are still held -- so the report is owed now, and it carries the packet
	// that arrived while nobody was listening: what the reading is windowed by
	// is the counter's own stamp, and that window is still open.
	ask := message.NewSessionModificationRequest(0, 0, seid, 6, 0,
		ie.NewUpdateFAR(
			ie.NewFARID(2),
			ie.NewApplyAction(applyBuff|applyNOCP),
			ie.NewBARID(1),
		))
	if got := cause(t, c.Modify(ask)); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification that set NOCP answered cause %d", got)
	}

	owed := c.EvaluateDownlinks(context.Background())
	if len(owed) != 1 || len(owed[0].PDRs) != 1 || owed[0].PDRs[0] != 2 || owed[0].SEID != seid {
		t.Fatalf("the report is %+v, want one naming PDR 2 of session %d", owed, seid)
	}
	ies := owed[0].IEs()
	if len(ies) != 2 || ies[0].Type != ie.ReportType || ies[1].Type != ie.DownlinkDataReport {
		t.Fatalf("the report's IEs are %v, want the Report Type and a Downlink Data Report", ies)
	}
	// The type is what an SMF reads first: a report whose type does not say
	// DLDR is one it cannot place (8.2.21).
	if !ies[0].HasDLDR() {
		t.Errorf("the report's type is %#v, want the DLDR bit", ies[0].Payload)
	}
	if ies[0].HasUSAR() {
		t.Errorf("the report claims a usage report: %#v", ies[0].Payload)
	}
	// A second reading before the SMF has taken the first owes the same one
	// again: what the flag stands for is the SMF knowing.
	if again := c.EvaluateDownlinks(context.Background()); len(again) != 1 {
		t.Fatalf("an unconfirmed report was not offered again: %+v", again)
	}
	c.ConfirmDownlinks(context.Background(), seid, owed[0].PDRs)
	if again := c.EvaluateDownlinks(context.Background()); len(again) != 0 {
		t.Fatalf("a confirmed report was offered again: %+v", again)
	}

	// The instruction moves the path: the episode is over. A later BUFF is a
	// new episode and owes its own report for its own first packet.
	mod := message.NewSessionModificationRequest(0, 0, seid, 7, 0,
		ie.NewUpdateFAR(
			ie.NewFARID(2),
			ie.NewApplyAction(applyForw),
			ie.NewUpdateForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceAccess),
				ie.NewOuterHeaderCreation(0x0100, 0x55667788, "10.20.30.2", "", 0, 0, 0),
			),
		))
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification answered cause %d", got)
	}
	if c.sessions[seid].PDRs[2].buffer {
		t.Fatal("the PDR still buffers after a FORW FAR")
	}
	mod = message.NewSessionModificationRequest(0, 0, seid, 8, 0,
		ie.NewUpdateFAR(
			ie.NewFARID(2),
			ie.NewApplyAction(applyBuff|applyNOCP),
			ie.NewBARID(1),
		))
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the second modification answered cause %d", got)
	}
	if got := c.EvaluateDownlinks(context.Background()); len(got) != 1 {
		t.Fatalf("a new buffering episode owes no report: %+v", got)
	}
}
