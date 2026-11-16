// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"math"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"sync"
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

// heapGauge reads the heap the last collection kept live and the runtime's
// memory limit. The live heap changes only when a collection ends, so one read
// per establishment costs a lock and a copy, not a walk of the heap.
type heapGauge struct {
	mu     sync.Mutex
	sample [1]metrics.Sample
}

func newHeapGauge() *heapGauge {
	g := &heapGauge{}
	g.sample[0].Name = "/gc/heap/live:bytes"
	return g
}

// read reports the live heap and the memory limit, the limit 0 when the
// runtime has none (no GOMEMLIMIT and no cgroup limit).
func (g *heapGauge) read() (live, limit uint64) {
	g.mu.Lock()
	metrics.Read(g.sample[:])
	live = g.sample[0].Value.Uint64()
	g.mu.Unlock()
	if l := debug.SetMemoryLimit(-1); l != math.MaxInt64 {
		limit = uint64(l)
	}
	return live, limit
}

// heapAdmits compares the last collection's live heap to a share of the soft
// runtime target. A fraction of 0 or no runtime target disables this check.
func heapAdmits(live, limit uint64, fraction float64) bool {
	return fraction <= 0 || limit == 0 || float64(live) <= fraction*float64(limit)
}

// heapAdmissionRecovery only signals under Compiler.mu. Its single worker
// observes successful deletions through Stats outside that lock, then refreshes
// a stale closed sample at most once per second, only after new deletion progress.
type heapAdmissionRecovery struct {
	fraction float64
	read     func() (uint64, uint64)
	refused  chan struct{}
	collect  func()
	pause    func(context.Context) bool
}

func newHeapAdmission(fraction float64, read func() (uint64, uint64)) *heapAdmissionRecovery {
	return &heapAdmissionRecovery{
		fraction: fraction,
		read:     read,
		refused:  make(chan struct{}, 1),
		collect:  runtime.GC,
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

func (h *heapAdmissionRecovery) admit() bool {
	live, limit := h.read()
	if heapAdmits(live, limit, h.fraction) {
		return true
	}
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
			live, limit := h.read()
			if heapAdmits(live, limit, h.fraction) {
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
