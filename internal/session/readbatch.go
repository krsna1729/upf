// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"context"
	"sync"

	"github.com/krsna1729/upf/internal/bess"
)

// readBatch coalesces the single-session counter readings that session
// workers make at the same time: a deletion's last window, a query's or a
// removed URR's report. Each reading was its own get_counts round trip, and
// at churn rates those round trips were a fifth of a deletion's CPU.
//
// A reading for a module with no reading in flight is sent at once, so an
// idle UPF answers as before. A reading that arrives while one is in flight
// joins the module's next round, which its first member sends as soon as the
// one in flight returns; the round's members share that reply. Every rule a
// round names is a different session's (an action id belongs to one session),
// and the module restarts each named rule's window once, as the separate
// readings did.
// Once queued, a reading belongs to the round. A caller may stop waiting,
// but its cancellation does not cancel the read for the other members.
//
// scale: a round holds at most one reading per session worker
// (n4.MaxSessionWorkers) and at most countChunk rules; a reading that would
// pass countChunk is sent on its own.
type readBatch struct {
	mu      sync.Mutex
	modules map[string]*moduleReads
}

// moduleReads is one counting module's reading in flight, if any, and the
// round waiting for it.
type moduleReads struct {
	name string
	busy bool
	next *readRound
}

// readRound is one get_counts on behalf of every reading that joined it.
type readRound struct {
	ids    []uint32
	start  chan struct{} // closed when the round may be sent
	done   chan struct{} // closed when counts and err are set
	counts []bess.RuleCount
	err    error
}

// read is the reading of ids in module, through reader. The result may hold
// other sessions' rules as well; the caller looks up its own.
func (b *readBatch) read(ctx context.Context, reader CounterReader, module string, ids []uint32) ([]bess.RuleCount, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.mu.Lock()
	if b.modules == nil {
		b.modules = map[string]*moduleReads{}
	}
	m := b.modules[module]
	if m == nil {
		m = &moduleReads{name: module}
		b.modules[module] = m
	}
	if !m.busy {
		m.busy = true
		b.mu.Unlock()
		r := &readRound{ids: ids}
		b.send(ctx, reader, m, r)
		return r.counts, r.err
	}
	r, first := m.next, false
	if r == nil {
		r, first = &readRound{start: make(chan struct{}), done: make(chan struct{})}, true
		m.next = r
	} else if len(r.ids)+len(ids) > countChunk {
		b.mu.Unlock()
		return reader.AppendRuleCounts(ctx, nil, module, ids...)
	}
	r.ids = append(r.ids, ids...)
	b.mu.Unlock()
	if first {
		if ctx.Done() == nil {
			b.runRound(ctx, reader, m, r)
		} else {
			go b.runRound(context.WithoutCancel(ctx), reader, m, r)
		}
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-r.done:
		return r.counts, r.err
	}
}

func (b *readBatch) runRound(ctx context.Context, reader CounterReader, m *moduleReads, r *readRound) {
	<-r.start
	b.send(ctx, reader, m, r)
}

// send reads r, then hands the module to the round that gathered meanwhile,
// or marks it idle.
func (b *readBatch) send(ctx context.Context, reader CounterReader, m *moduleReads, r *readRound) {
	r.counts, r.err = reader.AppendRuleCounts(ctx, nil, m.name, r.ids...)
	b.mu.Lock()
	next := m.next
	m.next = nil
	if next == nil {
		m.busy = false
	}
	b.mu.Unlock()
	if r.done != nil {
		close(r.done)
	}
	if next != nil {
		close(next.start)
	}
}
