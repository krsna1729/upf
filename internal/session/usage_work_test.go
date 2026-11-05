// SPDX-License-Identifier: BSD-3-Clause
package session

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/bess"
)

func usageScenario(t *testing.T, request *message.SessionEstablishmentRequest) (*Compiler, *recorder, uint64, uint32) {
	t.Helper()
	r := &recorder{}
	c := New(testConfig(), r, quietLogger())
	response := c.Establish(request).(*message.SessionEstablishmentResponse)
	if got := cause(t, response); got != ie.CauseRequestAccepted {
		t.Fatalf("establishment cause %d", got)
	}
	id := ruleCarrying(t, r.last(), fieldSrcIP, []byte{10, 45, 0, 2}).actionID()
	return c, r, upFSEID(t, response), id
}

func TestIdleVolumeClockDoesNotReadInactiveRules(t *testing.T) {
	c, r, _, id := usageScenario(t, urrEstablishment(0x7201, 7, quotaURR(7, 100)))
	ctx, at := context.Background(), time.Unix(1700000000, 0)
	c.EvaluateAll(ctx, at)
	r.calls = nil
	if reports := c.EvaluateAll(ctx, at.Add(time.Hour)); len(reports) != 0 {
		t.Fatalf("idle quota reported %+v", reports)
	}
	if len(r.calls) != 0 {
		t.Errorf("idle volume-only session requested counter readings: %v", r.calls)
	}
	r.counts = map[string][]bess.RuleCount{testConfig().Up.Counters: {{ActionID: id, Packets: 2, Octets: 120}}}
	reports := c.EvaluateAll(ctx, at.Add(time.Hour+time.Second))
	if len(reports) != 1 || reports[0].Up.Octets != 120 || !reports[0].Enforcing {
		t.Fatalf("new activity did not spend the quota: %+v", reports)
	}
}

func TestPeriodicClockReportsWithoutDirtyTraffic(t *testing.T) {
	urr := ie.NewCreateURR(ie.NewURRID(7), ie.NewMeasurementMethod(0, 1, 0),
		ie.NewReportingTriggers(0x01, 0), ie.NewMeasurementPeriod(3*time.Second))
	c, _, _, _ := usageScenario(t, urrEstablishment(0x7202, 7, urr))
	ctx, at := context.Background(), time.Unix(1700000000, 0)
	c.EvaluateAll(ctx, at)
	for _, second := range []int{1, 2, 3, 4, 6} {
		reports := c.EvaluateAll(ctx, at.Add(time.Duration(second)*time.Second))
		if second == 3 || second == 6 {
			if len(reports) != 1 || reports[0].Trigger != TriggerPeriod || reports[0].Up != (Usage{}) || reports[0].Duration != 3*time.Second {
				t.Fatalf("second %d: periodic window %+v", second, reports)
			}
		} else if len(reports) != 0 {
			t.Fatalf("second %d: premature periodic report %+v", second, reports)
		}
	}
}

func TestStampedTimeQuotaDoesNotAdvanceDuringIdleClock(t *testing.T) {
	c, r, _, id := usageScenario(t, urrEstablishment(0x7203, 7, timeQuotaURR(7, 3*time.Second)))
	ctx, at := context.Background(), time.Unix(1700000000, 0)
	c.EvaluateAll(ctx, at)
	r.counts = map[string][]bess.RuleCount{testConfig().Up.Counters: {{ActionID: id, Packets: 2, Octets: 200,
		First: at.Add(time.Second), Last: at.Add(2 * time.Second)}}}
	if reports := c.EvaluateAll(ctx, at.Add(2*time.Second)); len(reports) != 0 {
		t.Fatalf("one second of activity spent a three-second quota: %+v", reports)
	}
	if reports := c.EvaluateAll(ctx, at.Add(50*time.Second)); len(reports) != 0 {
		t.Fatalf("idle clock spent a stamped quota: %+v", reports)
	}
	r.counts[testConfig().Up.Counters][0] = bess.RuleCount{ActionID: id, Packets: 4, Octets: 400,
		First: at.Add(50 * time.Second), Last: at.Add(51 * time.Second)}
	reports := c.EvaluateAll(ctx, at.Add(51*time.Second))
	if len(reports) != 1 || reports[0].Trigger != TriggerTimeQuota || !reports[0].Enforcing ||
		!reports[0].First.Equal(at.Add(time.Second)) || !reports[0].Last.Equal(at.Add(51*time.Second)) {
		t.Fatalf("resumed activity lost its time window: %+v", reports)
	}
}

func TestUnstampedTimeQuotaKeepsClockFallback(t *testing.T) {
	c, _, _, _ := usageScenario(t, urrEstablishment(0x7204, 7, timeQuotaURR(7, 3*time.Second)))
	ctx, at := context.Background(), time.Unix(1700000000, 0)
	c.EvaluateAll(ctx, at)
	if reports := c.EvaluateAll(ctx, at.Add(2*time.Second)); len(reports) != 0 {
		t.Fatalf("early time quota: %+v", reports)
	}
	reports := c.EvaluateAll(ctx, at.Add(3*time.Second))
	if len(reports) != 1 || reports[0].Trigger != TriggerTimeQuota || !reports[0].Enforcing {
		t.Fatalf("unstamped backend lost its existing time fallback: %+v", reports)
	}
}

func TestDirtyCounterReadFailureRetainsQuotaWork(t *testing.T) {
	c, r, _, id := usageScenario(t, urrEstablishment(0x7205, 7, quotaURR(7, 100)))
	ctx, at := context.Background(), time.Unix(1700000000, 0)
	c.EvaluateAll(ctx, at)
	r.counts = map[string][]bess.RuleCount{testConfig().Up.Counters: {{ActionID: id, Packets: 2, Octets: 120}}}
	r.readFail = errors.New("counter reading unavailable")
	if reports := c.EvaluateAll(ctx, at.Add(time.Second)); len(reports) != 0 {
		t.Fatalf("failed reading reported invented usage: %+v", reports)
	}
	r.readFail = nil
	reports := c.EvaluateAll(ctx, at.Add(2*time.Second))
	if len(reports) != 1 || reports[0].Up.Octets != 120 || !reports[0].Enforcing {
		t.Fatalf("acknowledged activity was lost after a counter failure: %+v", reports)
	}
}

func TestRefusedQuotaEnforcementRetriesWithoutNewPackets(t *testing.T) {
	c, r, _, id := usageScenario(t, urrEstablishment(0x7206, 7, quotaURR(7, 100)))
	ctx, at := context.Background(), time.Unix(1700000000, 0)
	c.EvaluateAll(ctx, at)
	r.counts = map[string][]bess.RuleCount{testConfig().Up.Counters: {{ActionID: id, Packets: 2, Octets: 120}}}
	r.fail = errors.New("transaction temporarily refused")
	reports := c.EvaluateAll(ctx, at.Add(time.Second))
	if len(reports) != 1 || !reports[0].Enforcing {
		t.Fatalf("refused enforcement lost its quota report: %+v", reports)
	}
	r.fail = nil
	c.EvaluateAll(ctx, at.Add(2*time.Second))
	if gate := ruleCarrying(t, r.last(), fieldSrcIP, []byte{10, 45, 0, 2}).gate(); gate != dropGate {
		t.Fatalf("quota retry left traffic forwarding on gate %d", gate)
	}
}

func TestPeriodicSelectionDoesNotSwallowSimultaneousQuota(t *testing.T) {
	urr := ie.NewCreateURR(ie.NewURRID(7), ie.NewMeasurementMethod(0, 1, 0),
		ie.NewReportingTriggers(0x01, 0x01), ie.NewMeasurementPeriod(time.Second),
		ie.NewVolumeQuota(0x01, 100, 0, 0))
	c, r, _, id := usageScenario(t, urrEstablishment(0x7207, 7, urr))
	ctx, at := context.Background(), time.Unix(1700000000, 0)
	c.EvaluateAll(ctx, at)
	r.counts = map[string][]bess.RuleCount{testConfig().Up.Counters: {{ActionID: id, Packets: 2, Octets: 120}}}
	reports := c.EvaluateAll(ctx, at.Add(time.Second))
	if len(reports) != 1 || reports[0].Trigger != TriggerPeriod || reports[0].Up.Octets != 120 || !reports[0].Enforcing {
		t.Fatalf("period/quota collision changed precedence or enforcement: %+v", reports)
	}
}

func TestDirtyLinkedQuotaReportsWholeGroup(t *testing.T) {
	c, r, _, id := usageScenario(t, liusaEstablishment(0x7208, 9))
	ctx, at := context.Background(), time.Unix(1700000000, 0)
	c.EvaluateAll(ctx, at)
	if reports := c.EvaluateAll(ctx, at.Add(2*time.Second)); len(reports) != 0 {
		t.Fatalf("LIUSA's own period generated a report: %+v", reports)
	}
	r.counts = map[string][]bess.RuleCount{testConfig().Up.Counters: {{ActionID: id, Packets: 2, Octets: 1500}}}
	reports := c.EvaluateAll(ctx, at.Add(3*time.Second))
	if len(reports) != 1 || reports[0].URRID != 9 || reports[0].Up.Octets != 1500 ||
		len(reports[0].Linked) != 1 || reports[0].Linked[0].URRID != 7 || reports[0].Linked[0].Up.Octets != 1500 {
		t.Fatalf("traffic-selected linked report lost a member: %+v", reports)
	}
}

func TestDeletingOneDeadlineDoesNotLoseOtherSessionsPeriods(t *testing.T) {
	c := New(testConfig(), &recorder{}, quietLogger())
	periods := make(map[uint64]int)
	var remove uint64
	for i, period := range []int{8, 2, 7, 3, 6, 4, 5, 1} {
		urr := ie.NewCreateURR(ie.NewURRID(7), ie.NewMeasurementMethod(0, 1, 0),
			ie.NewReportingTriggers(0x01, 0), ie.NewMeasurementPeriod(time.Duration(period)*time.Second))
		response := c.Establish(urrSession(uint64(0x7400+i), uint32(0x7000+i),
			fmt.Sprintf("10.45.0.%d", 2+i), 7, urr)).(*message.SessionEstablishmentResponse)
		if got := cause(t, response); got != ie.CauseRequestAccepted {
			t.Fatalf("session %d cause %d", i, got)
		}
		seid := upFSEID(t, response)
		periods[seid] = period
		if period == 3 {
			remove = seid
		}
	}
	ctx, at := context.Background(), time.Unix(1700000000, 0)
	c.EvaluateAll(ctx, at)
	for second := 1; second <= 24; second++ {
		if second == 9 {
			if got := cause(t, c.Delete(message.NewSessionDeletionRequest(0, 0, remove, 2, 0))); got != ie.CauseRequestAccepted {
				t.Fatalf("deletion cause %d", got)
			}
			delete(periods, remove)
		}
		reports := c.EvaluateAll(ctx, at.Add(time.Duration(second)*time.Second))
		due := make(map[uint64]int)
		for seid, period := range periods {
			if second%period == 0 {
				due[seid] = period
			}
		}
		for _, report := range reports {
			period, expected := due[report.SEID]
			if !expected || report.Trigger != TriggerPeriod || report.Duration != time.Duration(period)*time.Second {
				t.Fatalf("second %d: unexpected/mistimed report %+v", second, report)
			}
			delete(due, report.SEID)
		}
		if len(due) != 0 {
			t.Fatalf("second %d lost periodic reports for %v", second, due)
		}
	}
}
