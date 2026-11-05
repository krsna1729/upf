// SPDX-License-Identifier: BSD-3-Clause
package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/bess"
)

type interruptedChanges struct {
	*recorder
	ids                         []uint32
	active, failed, fullyQueued bool
}

func (r *interruptedChanges) AppendRuleChanges(_ context.Context, dst []uint32, module string,
	acknowledge, sequence, after uint64) (bess.RuleChangePage, error) {
	if !r.active || module != testConfig().Up.Counters {
		return bess.RuleChangePage{Sequence: acknowledge + 1, ActionIDs: dst}, nil
	}
	if acknowledge == 2 && r.fullyQueued {
		return bess.RuleChangePage{Sequence: 3, ActionIDs: dst}, nil
	}
	if acknowledge != 1 {
		return bess.RuleChangePage{}, errors.New("unfinished snapshot acknowledged")
	}
	if after == 0 {
		return bess.RuleChangePage{Sequence: 2, NextAfter: 1, ActionIDs: append(dst, r.ids[0])}, nil
	}
	if !r.failed {
		r.failed = true
		return bess.RuleChangePage{}, errors.New("second page reply lost")
	}
	r.fullyQueued = true
	return bess.RuleChangePage{Sequence: 2, ActionIDs: append(dst, r.ids[1])}, nil
}

func TestInterruptedDirtySnapshotCannotLoseTheUnreceivedSessionsQuota(t *testing.T) {
	r := &interruptedChanges{recorder: &recorder{}}
	c := New(testConfig(), r, quietLogger())
	for i, ue := range []string{"10.45.0.2", "10.45.0.3"} {
		response := c.Establish(urrSession(uint64(0x7300+i), uint32(0x6000+i), ue, 7, quotaURR(7, 100))).(*message.SessionEstablishmentResponse)
		if got := cause(t, response); got != ie.CauseRequestAccepted {
			t.Fatalf("session %d cause %d", i, got)
		}
		r.ids = append(r.ids, ruleCarrying(t, r.last(), fieldSrcIP, []byte{10, 45, 0, byte(2 + i)}).actionID())
	}
	ctx, at := context.Background(), time.Unix(1700000000, 0)
	c.EvaluateAll(ctx, at)
	r.active = true
	for _, id := range r.ids {
		if r.counts == nil {
			r.counts = make(map[string][]bess.RuleCount)
		}
		r.counts[testConfig().Up.Counters] = append(r.counts[testConfig().Up.Counters], bess.RuleCount{ActionID: id, Packets: 2, Octets: 120})
	}
	first := c.EvaluateAll(ctx, at.Add(time.Second))
	if len(first) != 1 || first[0].Up.Octets != 120 || !first[0].Enforcing {
		t.Fatalf("received page's quota was lost: %+v", first)
	}
	second := c.EvaluateAll(ctx, at.Add(2*time.Second))
	if len(second) != 1 || second[0].SEID == first[0].SEID || second[0].Up.Octets != 120 || !second[0].Enforcing {
		t.Fatalf("retry lost the other quota or charged the first one twice: %+v", second)
	}
	if reports := c.EvaluateAll(ctx, at.Add(3*time.Second)); len(reports) != 0 {
		t.Fatalf("completed snapshot charged usage twice: %+v", reports)
	}
}
