// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"math"
	"runtime/debug"
	"testing"
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
