// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"context"
	"errors"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/krsna1729/upf/internal/bess"
	"github.com/krsna1729/upf/internal/scaletest"
)

// gatedCounts answers every rule it is asked for with its id as the packet
// count, and holds its first call until the test opens the gate.
type gatedCounts struct {
	ops     scaletest.Ops
	mu      sync.Mutex
	calls   [][]uint32
	entered chan struct{}
	gate    chan struct{}
}

func (g *gatedCounts) AppendRuleCounts(ctx context.Context, dst []bess.RuleCount, _ string, ids ...uint32) ([]bess.RuleCount, error) {
	g.mu.Lock()
	g.calls = append(g.calls, slices.Clone(ids))
	first := len(g.calls) == 1
	g.mu.Unlock()
	g.ops.Add("get_counts")
	if first {
		close(g.entered)
		<-g.gate
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, id := range ids {
		dst = append(dst, bess.RuleCount{ActionID: id, Packets: uint64(id)})
	}
	return dst, nil
}

func (*gatedCounts) AppendRuleChanges(_ context.Context, dst []uint32, _ string, _, _, _ uint64) (bess.RuleChangePage, error) {
	return bess.RuleChangePage{ActionIDs: dst}, nil
}

// TestConcurrentSessionReadingsShareOneRoundTrip: readings that arrive while
// one is in flight go out together as one get_counts when it returns, and
// each still finds its own rules in the reply. A reading with nothing in
// flight goes out at once.
func TestConcurrentSessionReadingsShareOneRoundTrip(t *testing.T) {
	const module, waiting = "upf/counters_ul", 6
	reader := &gatedCounts{entered: make(chan struct{}), gate: make(chan struct{})}
	var b readBatch
	got := make([][]bess.RuleCount, waiting+1)
	errs := make([]error, waiting+1)
	var wg sync.WaitGroup
	read := func(i int) {
		defer wg.Done()
		got[i], errs[i] = b.read(context.Background(), reader, module, []uint32{uint32(100 + i)})
	}
	wg.Add(1)
	go read(0)
	<-reader.entered
	wg.Add(waiting)
	for i := 1; i <= waiting; i++ {
		go read(i)
	}
	// Every later reading has joined the next round before the first returns.
	for {
		b.mu.Lock()
		joined := 0
		if next := b.modules[module].next; next != nil {
			joined = len(next.ids)
		}
		b.mu.Unlock()
		if joined == waiting {
			break
		}
	}
	close(reader.gate)
	wg.Wait()

	scaletest.RPCsAtMost(t, &reader.ops, "get_counts", 2)
	for i := range got {
		if errs[i] != nil {
			t.Fatalf("reading %d: %v", i, errs[i])
		}
		id := uint32(100 + i)
		if !slices.ContainsFunc(got[i], func(r bess.RuleCount) bool { return r.ActionID == id && r.Packets == uint64(id) }) {
			t.Errorf("reading %d of rule %d got %v", i, id, got[i])
		}
	}
	// The module is idle again: the next reading goes out at once, alone.
	if _, err := b.read(context.Background(), reader, module, []uint32{7}); err != nil {
		t.Fatal(err)
	}
	if last := reader.calls[len(reader.calls)-1]; !slices.Equal(last, []uint32{7}) {
		t.Errorf("an idle module's reading named %v, want only its own rule", last)
	}
}

func TestCanceledRoundLeaderDoesNotCancelOtherReadings(t *testing.T) {
	const module = "upf/counters_ul"
	reader := &gatedCounts{entered: make(chan struct{}), gate: make(chan struct{})}
	var b readBatch
	go b.read(t.Context(), reader, module, []uint32{1})
	<-reader.entered
	open := sync.OnceFunc(func() { close(reader.gate) })
	defer open()

	canceled, cancel := context.WithCancel(t.Context())
	defer cancel()
	leader := make(chan error, 1)
	go func() {
		_, err := b.read(canceled, reader, module, []uint32{2})
		leader <- err
	}()
	waitFor := func(n int) {
		t.Helper()
		end := time.Now().Add(time.Second)
		for time.Now().Before(end) {
			b.mu.Lock()
			next := b.modules[module].next
			joined := next != nil && len(next.ids) == n
			b.mu.Unlock()
			if joined {
				return
			}
			runtime.Gosched()
		}
		t.Fatalf("%d readings did not join the round", n)
	}
	waitFor(1)
	survives := make(chan []bess.RuleCount, 1)
	go func() {
		rules, _ := b.read(t.Context(), reader, module, []uint32{3})
		survives <- rules
	}()
	waitFor(2)
	cancel()
	select {
	case err := <-leader:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("leader returned %v, want canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("leader waited for the previous read after cancellation")
	}
	open()
	select {
	case rules := <-survives:
		if !slices.ContainsFunc(rules, func(r bess.RuleCount) bool { return r.ActionID == 3 && r.Packets == 3 }) {
			t.Fatalf("live member lost its reading: %v", rules)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled leader stranded its round")
	}
}
