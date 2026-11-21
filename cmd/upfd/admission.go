// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"log/slog"
	"math"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"sync"
	"sync/atomic"
	"time"
)

// defaultHeapAdmission is the share of the runtime's memory limit the live heap
// may fill before upfd stops admitting new sessions. The limit (memlimit.go)
// is a soft Go runtime target, not a heap/RSS/cgroup ceiling. Near a live-heap
// floor it can cause frequent GC. Historical 100K-session bulk measurements
// (establish, modify, delete; live heap 385 MB in modify) under three limits
// (evidence/go-garbage, -tight{640,520,440}-trim):
//
//	live/limit  0.64  0.78  0.93
//	modify GC   12.5% 40.7% 78.2% of upfd's CPU
//
// 0.7 is the current policy, not a universal workload optimum. This sampled
// check cannot replace hard capacity reservations or account for non-Go memory.
const defaultHeapAdmission = 0.7

// heapReopenGap is the hysteresis band: closed at the share, admission reopens
// only once the estimate is this share of the limit below it. Without it a
// node at the boundary opens and closes on every collection. Thresholded
// load shedding with a release band is the usual overload-manager shape.
const heapReopenGap = 0.05

// admittedSessionBytes is the live heap one session adds, counted above the
// 1,255 B internal/session's TestASessionHoldsAtMostItsBytes holds (measured
// 1,195 B, docs/design.md). The live reading only changes when a collection
// ends; sessions admitted since are counted at this size, so a fast fill
// cannot overshoot the share between collections (live alone ended at 0.738
// against 0.7 for 250K establishments under a 380 MiB scope; this, 0.697).
const admittedSessionBytes = 1600

// heapReading is one sample: the heap the last collection kept live, the
// runtime's memory limit (0 when there is none) and the count of completed
// collections, which tells whether live has been refreshed since.
type heapReading struct {
	live, limit, cycles uint64
}

// heapGauge reads the heap the last collection kept live and the runtime's
// memory limit. The live heap changes only when a collection ends, so one read
// per establishment costs a lock and a copy, not a walk of the heap.
type heapGauge struct {
	mu     sync.Mutex
	sample [2]metrics.Sample
}

func newHeapGauge() *heapGauge {
	g := &heapGauge{}
	g.sample[0].Name = "/gc/heap/live:bytes"
	g.sample[1].Name = "/gc/cycles/total:gc-cycles"
	return g
}

// read reports the live heap, the memory limit (0 when the runtime has none:
// no GOMEMLIMIT and no cgroup limit) and the collections completed so far.
func (g *heapGauge) read() heapReading {
	var r heapReading
	g.mu.Lock()
	metrics.Read(g.sample[:])
	r.live = g.sample[0].Value.Uint64()
	r.cycles = g.sample[1].Value.Uint64()
	g.mu.Unlock()
	if l := debug.SetMemoryLimit(-1); l != math.MaxInt64 {
		r.limit = uint64(l)
	}
	return r
}

// heapAdmits compares an estimated live heap to a share of the soft runtime
// target. A fraction of 0 or no runtime target disables this check.
func heapAdmits(live, limit uint64, fraction float64) bool {
	return fraction <= 0 || limit == 0 || float64(live) <= fraction*float64(limit)
}

// heapAdmissionRecovery decides admission under Compiler.mu (the session layer
// calls admit with it held). Its single worker observes successful deletions
// through Stats outside that lock, then refreshes a stale closed sample at
// most once per second, only after new deletion progress. No collection ever
// runs on the request path, and repeated refusals or elapsed time alone never
// force one: the runtime's own periodic collection bounds a stale-high
// reading on an idle node.
type heapAdmissionRecovery struct {
	fraction   float64
	perSession uint64
	read       func() heapReading
	refused    chan struct{}
	collect    func()
	pause      func(context.Context) bool
	log        *slog.Logger

	mu         sync.Mutex
	closed     bool
	cycles     uint64 // the collection count the sinceCycle count is relative to
	sinceCycle uint64 // sessions admitted since that collection

	closedGauge atomic.Bool
	refusals    atomic.Uint64
}

func newHeapAdmission(fraction float64, perSession uint64, read func() heapReading, log *slog.Logger) *heapAdmissionRecovery {
	return &heapAdmissionRecovery{
		fraction:   fraction,
		perSession: perSession,
		read:       read,
		log:        log,
		refused:    make(chan struct{}, 1),
		collect:    runtime.GC,
		pause: func(ctx context.Context) bool {
			timer := time.NewTimer(time.Second)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return false
			case <-timer.C:
				return true
			}
		},
	}
}

// decide applies the estimate and the hysteresis to one reading; admitting
// says whether a session is being admitted now (the worker only rechecks).
func (h *heapAdmissionRecovery) decide(r heapReading, admitting bool) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if r.cycles != h.cycles {
		h.cycles, h.sinceCycle = r.cycles, 0
	}
	estimate := r.live + h.sinceCycle*h.perSession
	if admitting {
		estimate += h.perSession
	}
	share := h.fraction
	if h.closed {
		share = max(0, h.fraction-heapReopenGap)
	}
	ok := heapAdmits(estimate, r.limit, share)
	if ok && admitting {
		h.sinceCycle++
	}
	if ok == h.closed && h.fraction > 0 && r.limit > 0 {
		h.closed = !ok
		h.closedGauge.Store(h.closed)
		if h.log != nil {
			state := "reopened"
			if h.closed {
				state = "closed"
			}
			h.log.Info("heap admission "+state, "live", r.live, "estimate", estimate,
				"limit", r.limit, "share", share)
		}
	}
	return ok
}

func (h *heapAdmissionRecovery) admit() bool {
	if h.decide(h.read(), true) {
		return true
	}
	h.refusals.Add(1)
	select {
	case h.refused <- struct{}{}:
	default:
	}
	return false
}

// run keeps watching after a refusal so a later deletion can reopen an idle
// node without another PFCP request. Cancellation stops the wait, not an
// in-flight runtime.GC: the caller must join this worker on shutdown.
func (h *heapAdmissionRecovery) run(ctx context.Context, deletions func() uint64) {
	var collected uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-h.refused:
		}
		for {
			if ctx.Err() != nil {
				return
			}
			deleted := deletions()
			if h.decide(h.read(), false) {
				break
			}
			if deleted > collected {
				if ctx.Err() != nil {
					return
				}
				collected = deleted
				h.collect()
			}
			// This also rate-limits collections across reopen/refusal cycles.
			if !h.pause(ctx) {
				return
			}
		}
	}
}
