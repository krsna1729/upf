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

	// A packet arrived: one report, naming the PDR whose flow is holding it.
	arrived := time.Now()
	rec.counts = map[string][]bess.RuleCount{
		"cnt_buf": {{ActionID: flow, Packets: 3, Octets: 153, First: arrived, Last: arrived}},
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
			ie.NewApplyAction(applyBuff),
			ie.NewBARID(1),
		))
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the second modification answered cause %d", got)
	}
	if got := c.EvaluateDownlinks(context.Background()); len(got) != 1 {
		t.Fatalf("a new buffering episode owes no report: %+v", got)
	}
}
