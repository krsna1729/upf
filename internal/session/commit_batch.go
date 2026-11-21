package session

import (
	"context"
	"errors"
	"sync"
	"time"

	sdk "github.com/krsna1729/bess/sdk/go/bess"
	"github.com/krsna1729/upf/internal/bess"
)

const (
	// Leave room for independent RPCs at light load. Queue only behind work
	// already in flight; never wait on a timer to fill a batch.
	sessionCommitLanes = 4
	sessionCommitWidth = 8
	sessionCommitQueue = 32
)

type sessionCommit struct {
	ctx     context.Context
	id      uint32
	changes []bess.Change
	ready   chan struct{}
	err     error
	slot    int // -1 for a follower; a selected leader owns its batch
	batch   [sessionCommitWidth]*sessionCommit
	n       int
}

type sessionCommits struct {
	mu     sync.Mutex
	active [sessionCommitLanes][sessionCommitWidth]uint32
	queue  [sessionCommitQueue]*sessionCommit
	n      int
}

func (c *Compiler) commitSession(ctx context.Context, changes []bess.Change) error {
	// Other resources can carry dependencies between sessions. Keep a
	// multi-resource write whole, but order it with writes of its own entry.
	if _, ok := c.target.(sessionTarget); ok {
		name := c.cfg.Appliance + "/sessions"
		for _, change := range changes {
			if change.Resource == name {
				if k, ok := bess.Get[SessionKey](change.Key); ok && k.SessionID != 0 {
					return c.commits.apply(ctx, c.ap, k.SessionID, changes)
				}
			}
		}
	}
	return c.ap.Apply(ctx, changes...)
}

func (b *sessionCommits) apply(ctx context.Context, ap Applier, id uint32, changes []bess.Change) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	if b.n == 0 && !b.has(id) {
		for i := range b.active {
			if b.active[i][0] == 0 {
				b.active[i][0] = id
				b.mu.Unlock()
				err := ap.Apply(ctx, changes...)
				b.finish(i)
				return err
			}
		}
	}
	if b.n == len(b.queue) {
		b.mu.Unlock()
		return &bess.BusyError{}
	}
	r := &sessionCommit{ctx: ctx, id: id, changes: changes, ready: make(chan struct{}), slot: -1}
	b.queue[b.n] = r
	b.n++
	b.mu.Unlock()

	select {
	case <-r.ready:
	case <-ctx.Done():
		b.mu.Lock()
		for i, pending := range b.queue[:b.n] {
			if pending == r {
				b.remove(i, 1)
				b.schedule()
				b.mu.Unlock()
				return ctx.Err()
			}
		}
		b.mu.Unlock()
		// Already dispatched: don't report an outcome until the group's
		// receipt is resolved. A cancelled caller cannot undo a send.
		<-r.ready
	}
	if r.slot >= 0 {
		b.send(ap, r)
		b.finish(r.slot)
	}
	return r.err
}

// scale: at most four groups of eight entries; the queue never scans sessions.
func (b *sessionCommits) has(id uint32) bool {
	for _, group := range &b.active {
		for _, active := range group {
			if active == 0 {
				break
			}
			if active == id {
				return true
			}
		}
	}
	return false
}

func (b *sessionCommits) remove(start, n int) {
	copy(b.queue[start:], b.queue[start+n:b.n])
	clear(b.queue[b.n-n : b.n])
	b.n -= n
}

// schedule hands the oldest ready prefix to its first caller. Stop on a
// repeated key instead of skipping it: later writes must not overtake it.
// scale: 32 queued requests and at most four groups of eight active keys.
func (b *sessionCommits) schedule() {
	for slot := range b.active {
		if b.n == 0 || b.has(b.queue[0].id) {
			return
		}
		if b.active[slot][0] != 0 {
			continue
		}
		r := b.queue[0]
		r.slot = slot
		width := sessionCommitWidth
		if len(r.changes) != 1 {
			width = 1
		}
		for _, next := range b.queue[:min(b.n, width)] {
			if r.n > 0 && len(next.changes) != 1 || b.has(next.id) {
				break
			}
			b.active[slot][r.n] = next.id
			r.batch[r.n] = next
			r.n++
		}
		b.remove(0, r.n)
		close(r.ready)
	}
}

func (b *sessionCommits) finish(slot int) {
	b.mu.Lock()
	clear(b.active[slot][:])
	b.schedule()
	b.mu.Unlock()
}

func (b *sessionCommits) send(ap Applier, r *sessionCommit) {
	if r.n == 1 {
		r.err = ap.Apply(r.ctx, r.changes...)
		return
	}
	var members [sessionCommitWidth]*sessionCommit
	var changes [sessionCommitWidth]bess.Change
	n := 0
	var deadline time.Time
	for _, m := range r.batch[:r.n] {
		if err := m.ctx.Err(); err != nil {
			m.err = err
			continue
		}
		if d, ok := m.ctx.Deadline(); ok && (deadline.IsZero() || d.Before(deadline)) {
			deadline = d
		}
		members[n], changes[n] = m, m.changes[0]
		n++
	}
	switch n {
	case 0:
	case 1:
		members[0].err = ap.Apply(members[0].ctx, changes[0])
	default:
		// Cancelling one member after dispatch must not cancel its peers.
		// Bound the shared call by the earliest original deadline, and let
		// the SDK resolve its one receipt before members can release IDs.
		ctx := context.WithoutCancel(members[0].ctx)
		cancel := func() {}
		if !deadline.IsZero() {
			ctx, cancel = context.WithDeadline(ctx, deadline)
		}
		err := ap.Apply(ctx, changes[:n]...)
		cancel()
		if definiteRefusal(err) {
			// BESS guarantees none applied. Keep indexed failures; send the
			// collateral members separately. Unindexed memory or BUSY errors
			// need singles to recover each member's own result.
			var rejected *bess.RejectedError
			if errors.As(err, &rejected) {
				for _, f := range rejected.Failures {
					if f.Index >= 0 && f.Index < n {
						members[f.Index].err = &bess.RejectedError{
							Record: rejected.Record, Failures: []sdk.OpFailure{{Error: f.Error}},
						}
					}
				}
			}
			for i, m := range members[:n] {
				if m.err == nil {
					m.err = ap.Apply(m.ctx, changes[i])
				}
			}
		} else {
			// An unknown outcome belongs to the entire group. Never resend
			// its members using new request IDs.
			for _, m := range members[:n] {
				m.err = err
			}
		}
	}
	for _, m := range r.batch[1:r.n] {
		close(m.ready)
	}
}
