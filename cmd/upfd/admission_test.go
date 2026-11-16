// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"io"
	"log/slog"
	"math"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/krsna1729/upf/internal/session"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// TestHeapAdmissionHoldsTheLiveHeapToItsShare: a session is admitted while the
// live heap is at most the share of the limit, and refused one byte past it;
// with no limit, or a share of 0, every session is.
func TestHeapAdmissionHoldsTheLiveHeapToItsShare(t *testing.T) {
	for _, tc := range []struct {
		live, limit uint64
		fraction    float64
		want        bool
	}{
		{700, 1000, 0.7, true},
		{701, 1000, 0.7, false},
		{1 << 40, 0, 0.7, true}, // no limit
		{1 << 40, 1000, 0, true},
	} {
		if got := heapAdmits(tc.live, tc.limit, tc.fraction); got != tc.want {
			t.Errorf("heapAdmits(%d, %d, %v) = %v, want %v", tc.live, tc.limit, tc.fraction, got, tc.want)
		}
	}
}

// TestTheHeapGaugeReadsTheRuntimesLimit: the gauge's limit is the one the
// runtime holds the heap under, and 0 when it holds it under none -- not
// MaxInt64, which would make every heap fit any share of it.
func TestTheHeapGaugeReadsTheRuntimesLimit(t *testing.T) {
	prev := debug.SetMemoryLimit(1 << 30)
	defer debug.SetMemoryLimit(prev)
	g := newHeapGauge()
	if _, limit := g.read(); limit != 1<<30 {
		t.Errorf("with a 1 GiB limit the gauge reads %d", limit)
	}
	debug.SetMemoryLimit(math.MaxInt64)
	if _, limit := g.read(); limit != 0 {
		t.Errorf("with no limit the gauge reads %d, want 0", limit)
	}
}

// The clock only advances when a test permits the next deletion/sample check;
// deadlines below detect deadlocks, not the passage of a collection interval.
type heapRecoveryClock struct {
	waiting chan struct{}
	tick    chan struct{}
}

func newHeapRecoveryClock(h *heapAdmissionRecovery) *heapRecoveryClock {
	c := &heapRecoveryClock{waiting: make(chan struct{}), tick: make(chan struct{})}
	h.pause = func(ctx context.Context) bool {
		select {
		case c.waiting <- struct{}{}:
		case <-ctx.Done():
			return false
		}
		select {
		case <-c.tick:
			return true
		case <-ctx.Done():
			return false
		}
	}
	return c
}

func awaitHeapRecovery(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("heap recovery worker did not reach the expected step")
	}
}

func (c *heapRecoveryClock) advance(t *testing.T) {
	t.Helper()
	select {
	case c.tick <- struct{}{}:
	case <-time.After(5 * time.Second):
		t.Fatal("heap recovery worker did not wait for its interval")
	}
	awaitHeapRecovery(t, c.waiting)
}

func runHeapRecovery(t *testing.T, h *heapAdmissionRecovery, deleted func() uint64) (context.CancelFunc, <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.run(ctx, deleted)
	}()
	t.Cleanup(func() {
		cancel()
		awaitHeapRecovery(t, done)
	})
	return cancel, done
}

func TestHeapAdmissionRecoversAfterIdleDeletion(t *testing.T) {
	var live atomic.Uint64
	live.Store(100)
	h := newHeapAdmission(0.7, func() (uint64, uint64) { return live.Load(), 1000 })
	clock := newHeapRecoveryClock(h)
	cfg := reportConfig()
	cfg.Admit = h.admit
	c := session.New(cfg, &fakeDataplane{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	var collections atomic.Uint64
	h.collect = func() {
		// This must return on the collecting goroutine: collection while
		// holding Compiler.mu would deadlock here, not merely fail a text check.
		if c.Stats().Deleted != 1 {
			return
		}
		collections.Add(1)
		live.Store(100)
	}
	runHeapRecovery(t, h, func() uint64 { return c.Stats().Deleted })
	first := c.Establish(reportLoopEstablishment(1, 1)).(*message.SessionEstablishmentResponse)
	if cause, err := first.Cause.Cause(); err != nil || cause != ie.CauseRequestAccepted {
		t.Fatalf("initial establishment: cause=%d err=%v", cause, err)
	}
	fseid, err := first.UPFSEID.FSEID()
	if err != nil {
		t.Fatal(err)
	}
	live.Store(800) // The last collection's sample stays closed after deletion.
	refused := reportLoopEstablishment(2, 2)
	for range 32 {
		resp := c.Establish(refused).(*message.SessionEstablishmentResponse)
		if cause, err := resp.Cause.Cause(); err != nil || cause != ie.CauseNoResourcesAvailable {
			t.Fatalf("closed establishment: cause=%d err=%v", cause, err)
		}
	}
	awaitHeapRecovery(t, clock.waiting)
	clock.advance(t)
	if n := collections.Load(); n != 0 {
		t.Fatalf("collected %d times without successful deletions", n)
	}
	resp := c.Delete(message.NewSessionDeletionRequest(0, 0, fseid.SEID, 3, 0)).(*message.SessionDeletionResponse)
	if cause, err := resp.Cause.Cause(); err != nil || cause != ie.CauseRequestAccepted {
		t.Fatalf("deletion while closed: cause=%d err=%v", cause, err)
	}
	// No further admission call wakes the worker: the idle deletion is enough.
	clock.advance(t)
	if n := collections.Load(); n != 1 {
		t.Fatalf("collected %d times after deletion, want 1", n)
	}
	retried := c.Establish(refused).(*message.SessionEstablishmentResponse)
	if cause, err := retried.Cause.Cause(); err != nil || cause != ie.CauseRequestAccepted {
		t.Fatalf("establishment after collection: cause=%d err=%v", cause, err)
	}
}

func TestHeapAdmissionCollectionsRequireNewDeletionsAndCooldown(t *testing.T) {
	h := newHeapAdmission(0.7, func() (uint64, uint64) { return 800, 1000 })
	clock := newHeapRecoveryClock(h)
	var deleted, collections atomic.Uint64
	deleted.Store(1)
	h.collect = func() { collections.Add(1) } // Collection does not always reopen admission.
	runHeapRecovery(t, h, deleted.Load)
	if h.admit() {
		t.Fatal("closed sample admitted a session")
	}
	awaitHeapRecovery(t, clock.waiting)
	for range 3 {
		for range 32 {
			h.admit() // Bounded signals must not block behind the worker's wait.
		}
		clock.advance(t)
		if n := collections.Load(); n != 1 {
			t.Fatalf("collected %d times without new deletions, want 1", n)
		}
	}
	deleted.Store(2)
	h.admit()
	if n := collections.Load(); n != 1 {
		t.Fatalf("collected before the interval elapsed: %d", n)
	}
	clock.advance(t)
	if n := collections.Load(); n != 2 {
		t.Fatalf("collected %d times after new deletion progress, want 2", n)
	}
}

func TestHeapAdmissionRecoveryRechecksSample(t *testing.T) {
	var live, collections atomic.Uint64
	live.Store(800)
	h := newHeapAdmission(0.7, func() (uint64, uint64) { return live.Load(), 1000 })
	h.collect = func() { collections.Add(1) }
	observed := make(chan struct{})
	calls := 0
	cancel, done := runHeapRecovery(t, h, func() uint64 {
		calls++
		if calls == 1 {
			h.admit() // Queue one last refusal before the normal GC completes.
			live.Store(100)
		} else {
			close(observed) // The worker already rechecked the first sample.
		}
		return 1
	})
	h.admit()
	awaitHeapRecovery(t, observed)
	cancel()
	awaitHeapRecovery(t, done)
	if n := collections.Load(); n != 0 {
		t.Fatalf("forced %d collections despite a reopened sample", n)
	}
}

func TestHeapAdmissionRecoveryCancellation(t *testing.T) {
	for _, waiting := range []bool{false, true} {
		name := "idle"
		if waiting {
			name = "timer"
		}
		t.Run(name, func(t *testing.T) {
			h := newHeapAdmission(0.7, func() (uint64, uint64) { return 800, 1000 })
			entered := make(chan struct{})
			pause := h.pause
			var once sync.Once
			h.pause = func(ctx context.Context) bool {
				once.Do(func() { close(entered) })
				return pause(ctx)
			}
			h.collect = func() { t.Error("collected without deletion progress") }
			cancel, done := runHeapRecovery(t, h, func() uint64 { return 0 })
			if waiting {
				h.admit()
				awaitHeapRecovery(t, entered)
			}
			cancel()
			awaitHeapRecovery(t, done)
		})
	}
}

func TestHeapAdmissionRecoveryJoinsInFlightCollection(t *testing.T) {
	h := newHeapAdmission(0.7, func() (uint64, uint64) { return 800, 1000 })
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	releaseCollection := func() { once.Do(func() { close(release) }) }
	h.collect = func() {
		close(entered)
		<-release
	}
	var deleted atomic.Uint64
	deleted.Store(1)
	cancel, done := runHeapRecovery(t, h, deleted.Load)
	// Release before the worker's cleanup join even if an assertion fails.
	t.Cleanup(releaseCollection)
	h.admit()
	awaitHeapRecovery(t, entered)
	deleted.Store(2)
	for range 32 {
		h.admit() // New reclaimable work cannot start a concurrent collection.
	}
	cancel()
	select {
	case <-done:
		t.Fatal("worker reported stopped while collection was still in flight")
	default:
	}
	releaseCollection()
	awaitHeapRecovery(t, done)
}
