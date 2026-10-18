// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"context"
	"fmt"
	"net"
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
		// Each session its own F-TEID and UE address: the table in front of the
		// decap holds one rule per TEID, so two sessions of one compiler cannot
		// share one.
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

// urrSession is urrEstablishment with the session's own F-TEID and UE address:
// the tick's scenario is many sessions at once, and two sessions of one
// compiler cannot share a TEID -- the table in front of the decap holds one
// rule per TEID. The URR, its PDR and its FAR are exactly what that helper
// builds.
func urrSession(cpSEID uint64, fteid uint32, ueIP string, urrID uint32, urr *ie.IE) *message.SessionEstablishmentRequest {
	return message.NewSessionEstablishmentRequest(0, 0, cpSEID, 1, 0,
		ie.NewFSEID(cpSEID, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, fteid, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, ueIP, "", 0, 0)),
			ie.NewFARID(1), ie.NewURRID(urrID)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
		urr,
	)
}

// assertTheTicksReads is the bound a tick is judged by: one call per counter
// module, each naming no rules -- the module's own reading of every rule it
// holds, one round trip -- and never one call per session. The graph under test
// measures uplink PDRs, so cnt_ul is the one module in play; a call that named
// two resources at once is impossible through the reader (one module per call)
// and a call naming several would be visible here as a second entry.
func assertTheTicksReads(t *testing.T, calls []readCall, sessions int) {
	t.Helper()
	want := []readCall{{module: testConfig().Up.Counters}}
	if !reflect.DeepEqual(calls, want) {
		t.Errorf("a tick over %d sessions made %v, want %v: one read per counter module, naming no rules",
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
