// SPDX-License-Identifier: BSD-3-Clause

package scaletest

import (
	"errors"
	"runtime"
	"testing"
)

// fakeTB records what a helper reported instead of failing the real test, so
// each helper's failure path is itself under test. Fatalf ends the helper the
// way testing.T's does, by unwinding to run.
type fakeTB struct {
	testing.TB
	errors, fatals int
}

var errFatal = errors.New("fatal")

func (f *fakeTB) Helper()                     {}
func (f *fakeTB) Logf(string, ...any)         {}
func (f *fakeTB) Errorf(string, ...any)       { f.errors++ }
func (f *fakeTB) Fatalf(string, ...any)       { f.fatals++; panic(errFatal) }
func (f *fakeTB) failures() (int, int)        { return f.errors, f.fatals }
func newFake(t *testing.T) *fakeTB            { return &fakeTB{TB: t} }
func (f *fakeTB) run(helper func(testing.TB)) { defer recoverFatal(); helper(f) }

func recoverFatal() {
	if r := recover(); r != nil && r != errFatal {
		panic(r)
	}
}

func TestRPCsAtMostFailsOverTheBound(t *testing.T) {
	var ops Ops
	for range 3 {
		ops.Add("Apply")
	}
	ok, over := newFake(t), newFake(t)
	ok.run(func(tb testing.TB) { RPCsAtMost(tb, &ops, "Apply", 3) })
	over.run(func(tb testing.TB) { RPCsAtMost(tb, &ops, "Apply", 2) })
	if e, _ := ok.failures(); e != 0 {
		t.Errorf("3 Applies against a bound of 3 failed %d times", e)
	}
	if e, _ := over.failures(); e != 1 {
		t.Errorf("3 Applies against a bound of 2 failed %d times, want 1", e)
	}
	ops.Reset()
	if n := ops.Count("Apply"); n != 0 {
		t.Errorf("after Reset Apply counts %d", n)
	}
}

func TestOpsCountsWithoutAllocatingOnceANameIsSeen(t *testing.T) {
	var ops Ops
	ops.Add("cnt_buf")
	if n := testing.AllocsPerRun(100, func() { ops.Add("cnt_buf") }); n != 0 {
		t.Errorf("counting a seen name allocates %v times", n)
	}
}

// sink keeps the per-item allocations reachable, so the compiler cannot elide them.
var sink [][]byte

func TestAllocsFollowChangeFailsAPerItemStep(t *testing.T) {
	perItem := func(n int) func() {
		return func() {
			sink = make([][]byte, n)
			for i := range sink {
				sink[i] = make([]byte, 8)
			}
		}
	}
	constant := func(n int) func() { return func() { sink = make([][]byte, 1) } }
	grows, flat := newFake(t), newFake(t)
	grows.run(func(tb testing.TB) { AllocsFollowChange(tb, perItem, [2]int{64, 8000}, 8) })
	flat.run(func(tb testing.TB) { AllocsFollowChange(tb, constant, [2]int{64, 8000}, 0) })
	if e, _ := grows.failures(); e != 1 {
		t.Errorf("a step allocating per item failed %d times, want 1", e)
	}
	if e, _ := flat.failures(); e != 0 {
		t.Errorf("a constant step failed %d times", e)
	}
	sink = nil
}

func TestHeapPerItemMeasuresWhatBuildKeeps(t *testing.T) {
	const n = 1 << 20
	var kept []uint64
	perItem := HeapPerItem(t, n, func(n int) { kept = make([]uint64, n) })
	runtime.KeepAlive(kept)
	if perItem < 7 || perItem > 9 {
		t.Errorf("a []uint64 of %d measured %.2f B per item, want about 8", n, perItem)
	}
	f := newFake(t)
	f.run(func(tb testing.TB) { HeapPerItem(tb, 0, func(int) {}) })
	if _, fatal := f.failures(); fatal != 1 {
		t.Errorf("n = 0 stopped the helper %d times, want 1", fatal)
	}
}

func TestMessageBytesAtMostRefusesOverTheBound(t *testing.T) {
	var bound MessageBytesAtMost
	if err := bound.Reply(MessageBound); err != nil {
		t.Errorf("a reply of exactly the bound was refused: %v", err)
	}
	if err := bound.Reply(MessageBound + 1); err == nil {
		t.Error("a reply one byte over the bound was answered")
	}
	f := newFake(t)
	f.run(func(tb testing.TB) { RPCsAtMost(tb, &bound.Ops, "refused", 0) })
	if e, _ := f.failures(); e != 1 {
		t.Errorf("one refusal against a bound of none failed %d times, want 1", e)
	}
}
