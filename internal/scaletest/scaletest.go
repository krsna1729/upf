// SPDX-License-Identifier: BSD-3-Clause

// Package scaletest is how a test proves a scale claim with a count rather
// than a time (docs/engineering-guide.md §2 rule 11, §8): the calls a fake
// served, the allocations at two sizes, the heap each item holds, and the
// daemon's message bound as a fake enforces it.
package scaletest

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"sync"
	"testing"
)

// Ops is a fake's named counters: the RPCs, Applies or peeks it served. The
// zero value is ready, and it is safe for concurrent use. Counting a name
// already seen does not allocate, so a fake that counts can sit inside
// testing.AllocsPerRun.
type Ops struct {
	mu sync.Mutex
	n  map[string]int
}

// Add counts one name and returns its new count.
func (o *Ops) Add(name string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.n == nil {
		o.n = map[string]int{}
	}
	o.n[name]++
	return o.n[name]
}

// Count is how many times name was counted.
func (o *Ops) Count(name string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.n[name]
}

// Reset forgets every count: a test measures the step after its setup.
func (o *Ops) Reset() {
	o.mu.Lock()
	defer o.mu.Unlock()
	clear(o.n)
}

// RPCsAtMost fails t if the fake counted name more than want times.
func RPCsAtMost(t testing.TB, ops *Ops, name string, want int) {
	t.Helper()
	if got := ops.Count(name); got > want {
		t.Errorf("%d %s, want at most %d", got, name, want)
	}
}

// allocRuns is testing.AllocsPerRun's run count for AllocsFollowChange.
const allocRuns = 10

// AllocsFollowChange fails t if the step build(n) returns allocates more at
// sizes[1] than at sizes[0] plus slack: the step's allocations follow what it
// changes, not what is installed. build does the setup for n items (outside
// the measurement) and returns the step. The convention is sizes 64 and 8000.
func AllocsFollowChange(t testing.TB, build func(n int) func(), sizes [2]int, slack float64) {
	t.Helper()
	small := testing.AllocsPerRun(allocRuns, build(sizes[0]))
	large := testing.AllocsPerRun(allocRuns, build(sizes[1]))
	t.Logf("%.1f allocations at n=%d, %.1f at n=%d", small, sizes[0], large, sizes[1])
	if large > small+slack {
		t.Errorf("the step made %.1f allocations at n=%d and %.1f at n=%d: want at most %.1f more",
			small, sizes[0], large, sizes[1], slack)
	}
}

// HeapPerItem is the heap build(n) leaves in use, per item: HeapInuse after a
// GC, less HeapInuse after a GC before build, divided by n. GOGC is fixed at
// 100 while it runs, so the reading does not move with the environment's GOGC.
// build must keep what it builds reachable past its return (assign it to a
// variable the caller uses afterwards, or runtime.KeepAlive it there).
func HeapPerItem(t testing.TB, n int, build func(n int)) float64 {
	t.Helper()
	if n <= 0 {
		t.Fatalf("HeapPerItem needs n > 0, got %d", n)
		return 0
	}
	defer debug.SetGCPercent(debug.SetGCPercent(100))
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	build(n)
	runtime.GC()
	runtime.ReadMemStats(&after)
	perItem := float64(int64(after.HeapInuse)-int64(before.HeapInuse)) / float64(n)
	t.Logf("%.1f B of heap per item over %d items", perItem, n)
	return perItem
}

// MessageBound is bessd's gRPC message limit: a reply larger is refused.
const MessageBound = 64 << 20

// MessageBytesAtMost is the daemon's message bound in a fake reader: before
// answering, the reader asks Reply whether a reply of that many bytes may
// leave, and answers with the error if not. Each refusal is counted in Ops as
// "refused", so RPCsAtMost(t, &bound.Ops, "refused", 0) says no reading was.
type MessageBytesAtMost struct {
	Ops
}

// Reply refuses a reply over MessageBound bytes.
func (m *MessageBytesAtMost) Reply(bytes int) error {
	if bytes > MessageBound {
		m.Add("refused")
		return fmt.Errorf("a reply of %d B is over the %d B message bound", bytes, MessageBound)
	}
	return nil
}
