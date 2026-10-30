// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/bess"
	"github.com/krsna1729/upf/internal/n4sim"
)

// refuseLarge is the recorder with a daemon that refuses any transaction
// longer than over changes.
type refuseLarge struct {
	*recorder
	over    int
	refused int
}

func (r *refuseLarge) Apply(ctx context.Context, changes ...bess.Change) error {
	if len(changes) > r.over {
		r.refused++
		return errors.New("refused: too large")
	}
	return r.recorder.Apply(ctx, changes...)
}

// establishN establishes n sessions on c and returns their UP SEIDs.
func establishN(t *testing.T, c *Compiler, n int) []uint64 {
	t.Helper()
	ups := make([]uint64, 0, n)
	for i := 1; i <= n; i++ {
		resp := c.Establish(establishment(uint64(i), fmt.Sprintf("10.1.%d.%d", i>>8, i&0xff)))
		est, ok := resp.(*message.SessionEstablishmentResponse)
		if !ok {
			t.Fatalf("session %d: %#v", i, resp)
		}
		if cause, err := n4sim.Cause(est); err != nil || cause != 1 {
			t.Fatalf("session %d: cause %d (%v)", i, cause, err)
		}
		ups = append(ups, upFSEID(t, est))
	}
	return ups
}

// erases counts the erase changes of txns.
func erases(txns [][]bess.Change) int {
	n := 0
	for _, tx := range txns {
		for _, ch := range tx {
			if ch.Value == nil {
				n++
			}
		}
	}
	return n
}

// An association's end takes its sessions out in a few transactions rather than
// one each -- it runs in the N4 read loop, and a million round trips held that
// loop past the SMF's heartbeats -- and erases exactly what deleting each
// session would have. A batch the daemon refuses is taken again one session at
// a time, so every session still goes.
func TestAssociationEndedBatchesTheRemovals(t *testing.T) {
	const n = 300

	// What n separate deletions erase.
	one := &recorder{}
	c := New(testConfig(), one, quietLogger())
	for i, up := range establishN(t, c, n) {
		c.Delete(message.NewSessionDeletionRequest(0, 0, up, uint32(n+i+2), 0))
	}
	want := erases(one.txns[n:])
	if want == 0 || len(one.txns) != 2*n {
		t.Fatalf("the per-session deletions: %d erases in %d transactions", want, len(one.txns)-n)
	}

	for _, over := range []int{1 << 30, 50} {
		t.Run(fmt.Sprintf("daemon takes up to %d", over), func(t *testing.T) {
			ap := &refuseLarge{recorder: &recorder{}, over: over}
			c := New(testConfig(), ap, quietLogger())
			establishN(t, c, n)
			c.AssociationEnded("test")

			ended := ap.txns[n:]
			if got := c.Stats().Sessions; got != 0 {
				t.Fatalf("%d sessions left after the association ended", got)
			}
			if got := erases(ended); got != want {
				t.Errorf("the end erased %d records; deleting each session erases %d", got, want)
			}
			for i, tx := range ended {
				if len(tx) > sweepBatch {
					t.Errorf("transaction %d has %d changes, above the %d bound", i, len(tx), sweepBatch)
				}
			}
			if ap.refused == 0 && len(ended) >= n/10 {
				t.Errorf("%d transactions for %d sessions: the end is not batched", len(ended), n)
			}
			if ap.refused > 0 && len(ended) != n {
				t.Errorf("after %d refused batches, %d transactions; want one per session", ap.refused, len(ended))
			}
		})
	}
}
