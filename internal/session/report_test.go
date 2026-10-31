// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/bess"
)

// TestATickReadsEachCounterModuleOnce is the shape upfd's loop depends on
// (docs/design.md, the control plane's O(total sessions) item 3): one
// EvaluateAll over every measured session makes **one counter read per counter
// module**, not one per session, and decides exactly the reports the per-session
// read path decides. The cost is the read path, and this is the read path.
//
// It is the failing-first test of that change: implemented as Evaluate per
// session -- one RuleCounts call per session, the shape the tick had -- the
// first assertion fails with one call per session, and the per-session compiler
// beside it is the same scenario over the old reading, so the reports the two
// produce are compared rather than described.
func TestATickReadsEachCounterModuleOnce(t *testing.T) {
	const (
		sessions = 8
		urrID    = 7
	)
	ctx := context.Background()
	// One clock for both ticks and for both compilers: a report's window is
	// the length between two readings, and the two paths have to read the same
	// numbers from the same instants.
	baseline, traffic := time.Unix(1_700_000_000, 0), time.Unix(1_700_000_000, 0).Add(time.Second)

	// Two compilers over the same scenario. bulk is ticked by EvaluateAll (the
	// reading under test); each is ticked by Evaluate per session, which is one
	// counter read per session -- the reading the tick used to make, and the
	// reports it must still decide.
	bulkRec, eachRec := &recorder{}, &recorder{}
	bulk, each := New(testConfig(), bulkRec, quietLogger()), New(testConfig(), eachRec, quietLogger())

	seids := make([]uint64, 0, sessions)
	for i := range sessions {
		cp := uint64(0x5010 + i)
		// Each session has its own complete F-TEID admission key and UE address.
		// The key includes endpoint, family, local address and TEID; different
		// sessions cannot claim the same full key.
		fteid, ue := uint32(0x2000+i), fmt.Sprintf("10.45.%d.%d", i/250, i%250+1)
		resp := bulk.Establish(urrSession(cp, fteid, ue, urrID, quotaURR(urrID, 100))).(*message.SessionEstablishmentResponse)
		if got := cause(t, resp); got != ie.CauseRequestAccepted {
			t.Fatalf("session %d: the measured session answered cause %d", i, got)
		}
		// A second, identical establishment for the per-session compiler: the
		// same sessions, the same ids (the local SEID is allocated in order),
		// and its own copy of the request.
		if got := cause(t, each.Establish(urrSession(cp, fteid, ue, urrID, quotaURR(urrID, 100)))); got != ie.CauseRequestAccepted {
			t.Fatalf("session %d: the measured session answered cause %d on the per-session compiler", i, got)
		}
		seids = append(seids, upFSEID(t, resp))
	}
	// EvaluateAll reports low SEID first; the per-session path below is walked
	// in the same order, so the two report lists are comparable element by
	// element.
	slices.Sort(seids)

	// The baseline tick: every URR's first reading is its baseline, so nothing
	// is owed -- read once per counter module, for every session the tick then
	// judges in memory.
	if reports := bulk.EvaluateAll(ctx, baseline); len(reports) != 0 {
		t.Fatalf("the baseline tick returned %d reports, want none", len(reports))
	}
	baselineReads := len(bulkRec.calls)
	assertTheTicksReads(t, bulkRec.calls[:baselineReads], sessions)
	for _, seid := range seids {
		if reports, err := each.Evaluate(ctx, seid, baseline); err != nil || len(reports) != 0 {
			t.Fatalf("the baseline evaluation of session %d returned %d reports (%v), want none",
				seid, len(reports), err)
		}
	}

	// The traffic that spends every session's quota, as each counting module
	// holds it: one entry per rule its URRs measure. The fake answers the
	// module's bulk read from exactly this state.
	bulkRec.counts = map[string][]bess.RuleCount{testConfig().Up.Counters: measuredRules(t, bulk, seids)}
	eachRec.counts = map[string][]bess.RuleCount{testConfig().Up.Counters: measuredRules(t, each, seids)}

	bulkReports := bulk.EvaluateAll(ctx, traffic)
	assertTheTicksReads(t, bulkRec.calls[baselineReads:], sessions)

	var eachReports []Report
	for _, seid := range seids {
		reports, err := each.Evaluate(ctx, seid, traffic)
		if err != nil {
			t.Fatalf("evaluating session %d: %v", seid, err)
		}
		eachReports = append(eachReports, reports...)
	}
	if n := 2 * sessions; len(eachRec.calls) != n {
		t.Errorf("the per-session path made %d counter reads over %d sessions and two ticks, want %d: "+
			"one per session per tick is the read path the tick no longer walks", len(eachRec.calls), sessions, n)
	}

	if len(bulkReports) != sessions {
		t.Fatalf("the tick returned %d reports, want one per session (%d): %+v",
			len(bulkReports), sessions, bulkReports)
	}
	for _, r := range bulkReports {
		if r.Trigger != TriggerVolumeQuota || !r.Enforcing {
			t.Errorf("the tick's report for SEID %d is %v (enforcing %v), want the spent volume quota",
				r.SEID, r.Trigger, r.Enforcing)
		}
	}
	if !reflect.DeepEqual(bulkReports, eachReports) {
		t.Errorf("the tick's reports are not the per-session path's:\n tick: %+v\n each: %+v",
			bulkReports, eachReports)
	}
}

// urrSession is urrEstablishment with the session's own complete F-TEID key
// and UE address. The report-tick scenario covers many sessions; each key is
// exact, and the helper also builds the URR, PDR and FAR.
func urrSession(cpSEID uint64, fteid uint32, ueIP string, urrID uint32, urr *ie.IE) *message.SessionEstablishmentRequest {
	return message.NewSessionEstablishmentRequest(0, 0, cpSEID, 1, 0,
		ie.NewFSEID(cpSEID, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				testFTEID(fteid),
				ie.NewUEIPAddress(0x02, ueIP, "", 0, 0)),
			ie.NewFARID(1), ie.NewURRID(urrID)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
		urr,
	)
}

// assertTheTicksReads is the bound a tick is judged by: one call per counter
// module per countChunk rules, naming the rules the sessions measure, and never
// one call per session. The graph under test measures one uplink PDR per
// session, so cnt_ul is the one module in play and one chunk holds them all; a
// call per session would be visible here as more entries.
func assertTheTicksReads(t *testing.T, calls []readCall, sessions int) {
	t.Helper()
	want := []readCall{{module: testConfig().Up.Counters, rules: sessions}}
	if !reflect.DeepEqual(calls, want) {
		t.Errorf("a tick over %d sessions made %v, want %v: one read per counter module, naming its rules",
			sessions, calls, want)
	}
}

// measuredRules is every rule the sessions' URRs measure, as the counting
// module holds it: one entry per measured PDR, carrying the traffic that spends
// the URR's quota. The caller's compiler hands over the rules it would have
// named, so each fake is seeded with its own ids.
func measuredRules(t *testing.T, c *Compiler, seids []uint64) []bess.RuleCount {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []bess.RuleCount
	for _, seid := range seids {
		s := c.sessions[seid]
		if s == nil {
			t.Fatalf("session %d is not in the compiler: the two compilers did not allocate the same ids", seid)
		}
		for _, p := range pdrsInOrder(s) {
			if len(p.urrIDs) == 0 || p.actionID == 0 || p.drop {
				continue
			}
			// The quota is 100 octets and the reading is 120: every session's
			// quota is spent by this one tick.
			out = append(out, bess.RuleCount{ActionID: p.actionID, Packets: 3, Octets: 120})
		}
	}
	return out
}

// The daemon's message bound, as boundedReader applies it: a reply over 64 MiB
// is refused, and a counted rule is 34 B of it on the wire (UG-B1).
const (
	messageBound = 64 << 20
	ruleOnWire   = 34
)

// boundedReader is a counting module behind the daemon's message bound: a
// reading whose reply would pass messageBound is refused, and a reading that
// names no rule answers every rule the module holds. It counts the calls, the
// refusals, the most rules one call named, and how often each ActionId was
// named. Its reply slice is reused, so what a tick allocates is the tick's.
type boundedReader struct {
	*recorder
	held          []uint32
	named         []uint8
	refused, most int
	reply         []bess.RuleCount
}

func (r *boundedReader) RuleCounts(_ context.Context, module string, actionIDs ...uint32) ([]bess.RuleCount, error) {
	r.calls = append(r.calls, readCall{module: module, rules: len(actionIDs)})
	r.most = max(r.most, len(actionIDs))
	if len(actionIDs) == 0 {
		actionIDs = r.held
	}
	if size := len(actionIDs) * ruleOnWire; size > messageBound {
		r.refused++
		return nil, fmt.Errorf("a reply of %d B is over the %d B message bound", size, messageBound)
	}
	r.reply = r.reply[:0]
	for _, id := range actionIDs {
		r.named[id]++
		r.reply = append(r.reply, bess.RuleCount{ActionID: id, Packets: 1, Octets: 100})
	}
	return r.reply, nil
}

// boundedTick is a compiler holding sessions × perSession rules its URRs
// measure, all counted by cnt_ul, behind a boundedReader. One session is
// established through PFCP and cloned with its own PDRs, URRs and ActionIds
// 1..sessions×perSession: millions of rules established one message at a time
// would cost minutes and gigabytes the tick's read is not about.
func boundedTick(t *testing.T, sessions, perSession int) (*Compiler, *boundedReader) {
	t.Helper()
	reader := &boundedReader{recorder: &recorder{}}
	c := New(testConfig(), reader, quietLogger())
	resp := c.Establish(urrSession(0x5010, 0x2000, "10.45.0.1", 7, quotaURR(7, 100))).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the measured session answered cause %d", got)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	seid := upFSEID(t, resp)
	model := c.sessions[seid]
	delete(c.sessions, seid)
	measured := pdrsInOrder(model)[0]
	rules := sessions * perSession
	reader.held = make([]uint32, 0, rules)
	reader.named = make([]uint8, rules+1)
	for i := range sessions {
		s := *model
		s.LocalSEID = seid + 1 + uint64(i)
		s.cachedPDRs = nil
		s.PDRs = make(map[uint16]*pdr, perSession)
		pdrs := make([]pdr, perSession)
		for j := range pdrs {
			pdrs[j] = *measured
			pdrs[j].id = uint16(j + 1)
			pdrs[j].actionID = uint32(len(reader.held) + 1)
			reader.held = append(reader.held, pdrs[j].actionID)
			s.PDRs[pdrs[j].id] = &pdrs[j]
		}
		s.URRs = make(map[uint32]*urr, len(model.URRs))
		for id, u := range model.URRs {
			own := *u
			s.URRs[id] = &own
		}
		c.sessions[s.LocalSEID] = &s
	}
	return c, reader
}

// raceEnabled is set by race_test.go in a -race build.
var raceEnabled bool

// TestATickReadsEveryRuleUnderTheMessageBound is UG-B1: at 2.1M counted rules
// one reply holding them all is 71 MB, over the daemon's 64 MiB bound, and a
// tick that read each module in one call was refused every time -- no session
// read, no URR ever reported. Read in chunks of named ActionIds, every rule is
// named exactly once, no call passes the chunk cap or the bound, and every
// session's URR takes its first reading.
func TestATickReadsEveryRuleUnderTheMessageBound(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("2.1M rules: ~1.4 GB of heap")
	}
	const sessions, perSession = 32_813, 64 // 2,100,032 rules
	c, reader := boundedTick(t, sessions, perSession)
	c.EvaluateAll(context.Background(), time.Unix(1_700_000_000, 0))

	if reader.refused != 0 || reader.most > countChunk {
		t.Errorf("%d of %d readings refused, the largest naming %d rules: want none refused, each ≤ %d",
			reader.refused, len(reader.calls), reader.most, countChunk)
	}
	unread := 0
	for _, n := range reader.named[1:] {
		if n != 1 {
			unread++
		}
	}
	if unread != 0 {
		t.Errorf("%d of %d rules were not named exactly once", unread, len(reader.named)-1)
	}
	baselined := 0
	for _, s := range c.sessions {
		if s.URRs[7].baselined {
			baselined++
		}
	}
	if baselined != sessions {
		t.Errorf("%d of %d sessions took their first reading", baselined, sessions)
	}
}

// TestATickAllocatesAtMostOnePerRule bounds what a tick's read costs the heap:
// the answers land in a slice indexed by ActionId the report loop keeps, so a
// tick over 100K rules allocates at most one object per rule, sessions
// included.
func TestATickAllocatesAtMostOnePerRule(t *testing.T) {
	const sessions, perSession = 1_563, 64 // 100,032 rules
	c, reader := boundedTick(t, sessions, perSession)
	now := time.Unix(1_700_000_000, 0)
	allocs := testing.AllocsPerRun(4, func() {
		now = now.Add(time.Second)
		c.EvaluateAll(context.Background(), now)
	})
	if perRule := allocs / float64(len(reader.held)); perRule > 1 {
		t.Errorf("a tick over %d rules made %.0f allocations, %.2f per rule: want ≤ 1",
			len(reader.held), allocs, perRule)
	}
}

// TestAReportTakenBackIsDecidedAgain is UG-B2's other half: a report the loop
// could not queue is taken back, so the next tick reports the same usage under
// the same UR-SEQN instead of the window being lost to a moved base.
func TestAReportTakenBackIsDecidedAgain(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(urrEstablishment(0x5010, 7, fullURR(7))).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the measured session answered cause %d", got)
	}
	seid := upFSEID(t, resp)
	ctx, at := context.Background(), time.Unix(1_700_000_000, 0)
	if reports := c.EvaluateAll(ctx, at); len(reports) != 0 {
		t.Fatalf("the baseline tick returned %d reports, want none", len(reports))
	}
	// 2 MiB crosses the URR's 1 MiB volume threshold.
	var counts []bess.RuleCount
	for _, p := range pdrsInOrder(sessionOf(t, c, seid)) {
		if len(p.urrIDs) > 0 && p.actionID != 0 {
			counts = append(counts, bess.RuleCount{ActionID: p.actionID, Packets: 2, Octets: 2 << 20})
		}
	}
	rec.counts = map[string][]bess.RuleCount{testConfig().Up.Counters: counts}
	first := c.EvaluateAll(ctx, at.Add(time.Second))
	if len(first) != 1 || first[0].Up.Octets != 2<<20 {
		t.Fatalf("the threshold tick returned %+v, want one report of 2 MiB", first)
	}
	if !c.Unreport(first[0]) {
		t.Fatal("the tick's own report could not be taken back")
	}
	again := c.EvaluateAll(ctx, at.Add(2*time.Second))
	if len(again) != 1 || again[0].Up.Octets != first[0].Up.Octets || again[0].Seqn != first[0].Seqn {
		t.Errorf("after taking the report back the next tick returned %+v, want the same %d octets under UR-SEQN %d",
			again, first[0].Up.Octets, first[0].Seqn)
	}
	// A report something later has moved past cannot be taken back.
	if c.Unreport(first[0]) {
		t.Error("a report the next tick superseded was taken back")
	}
}
