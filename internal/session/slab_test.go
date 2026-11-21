// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"errors"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
)

// Every test checks that each record read holds the compiler's lock.
func init() { slabLockCheck = true }

// hasPointers reports whether a value of t holds a Go pointer anywhere.
func hasPointers(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Pointer, reflect.UnsafePointer, reflect.Map, reflect.Slice, reflect.String,
		reflect.Chan, reflect.Func, reflect.Interface:
		return true
	case reflect.Array:
		return t.Len() != 0 && hasPointers(t.Elem())
	case reflect.Struct:
		for i := range t.NumField() {
			if hasPointers(t.Field(i).Type) {
				return true
			}
		}
	}
	return false
}

// TestTheSlabsHoldNoPointers: a slab segment is one array the collector
// marks without reading only while its element holds no pointer, so a field
// that adds one to a record would put every record of a million sessions
// back in the scan.
func TestTheSlabsHoldNoPointers(t *testing.T) {
	for _, v := range []any{pdr{}, far{}, qer{}, urr{}, recRef{}, [slabSeg]pdr{}, [slabSeg]urr{}} {
		if typ := reflect.TypeOf(v); hasPointers(typ) {
			t.Errorf("%v holds a pointer", typ)
		}
	}
	const n = 4 * slabSeg
	var sl slab[pdr]
	f := measureFootprint(n, func() {
		for i := range n {
			if _, _, err := sl.alloc(pdr{id: uint16(i)}); err != nil {
				t.Fatal(err)
			}
		}
	})
	t.Logf("live %.1f B, scanned %.2f B, %.4f objects per record", f.live, f.scan, f.objects)
	if f.scan > 1 || f.objects > 0.01 {
		t.Errorf("a slab record costs the collector %.2f B scanned and %.4f objects, want none", f.scan, f.objects)
	}
	runtime.KeepAlive(&sl)
}

func mustPanic(t *testing.T, want string, f func()) {
	t.Helper()
	defer func() {
		t.Helper()
		r := recover()
		if s, _ := r.(string); !strings.Contains(s, want) {
			t.Errorf("panicked with %v, want %q", r, want)
		}
	}()
	f()
}

// TestASlabReusesFreedSlotsUnderANewGeneration: a freed slot is the next one
// handed out, under a generation the old handle does not carry, so a read or
// a free through the old handle panics rather than reaching the new record.
func TestASlabReusesFreedSlotsUnderANewGeneration(t *testing.T) {
	var sl slab[far]
	a, p, err := sl.alloc(far{id: 1})
	if err != nil || a == 0 || p.id != 1 || sl.at(a) != p {
		t.Fatalf("alloc = %#x, %v, %v", a, p, err)
	}
	b, _, _ := sl.alloc(far{id: 2})
	sl.release(a)
	if sl.live != 1 {
		t.Errorf("%d live after a free, want 1", sl.live)
	}
	mustPanic(t, "used after it was freed", func() { sl.at(a) })
	c, q, _ := sl.alloc(far{id: 3})
	if c&recIndexMask != a&recIndexMask || c == a {
		t.Errorf("the freed slot %#x came back as %#x: want its index under a new generation", a, c)
	}
	if q.id != 3 || sl.at(b).id != 2 {
		t.Errorf("records %d and %d, want 3 and 2", q.id, sl.at(b).id)
	}
	mustPanic(t, "used after it was freed", func() { sl.at(a) })
	mustPanic(t, "used after it was freed", func() { sl.release(a) })
	mustPanic(t, "used after it was freed", func() { sl.at(0) })
	// A freed record reads as zero through nothing: release zeroes it.
	sl.release(c)
	if got := sl.recs[0][c&recIndexMask]; got != (far{}) {
		t.Errorf("a freed slot still holds %+v", got)
	}
}

// TestASlabGrowsBySegmentsThatNeverMove: past a segment's records a new one
// is added, and a record's address does not change when it is.
func TestASlabGrowsBySegmentsThatNeverMove(t *testing.T) {
	var sl slab[qer]
	first, p, _ := sl.alloc(qer{id: 1})
	for i := range 2 * slabSeg {
		if _, _, err := sl.alloc(qer{id: uint32(i + 2)}); err != nil {
			t.Fatal(err)
		}
	}
	if len(sl.recs) != 3 || len(sl.gens) != 3 {
		t.Errorf("%d record and %d generation segments for %d records, want 3", len(sl.recs), len(sl.gens), 2*slabSeg+1)
	}
	if sl.at(first) != p || p.id != 1 {
		t.Error("a record moved when the slab grew")
	}
	sl.next = recIndexMask + 1
	sl.free = nil
	if _, _, err := sl.alloc(qer{}); !errors.Is(err, errNoResources) {
		t.Errorf("an exhausted slab answered %v, want errNoResources", err)
	}
}

// TestARecordReadOutsideTheLockPanics is the check slabLockCheck turns on for
// every test: a record read by a goroutine that does not hold the compiler's
// lock.
func TestARecordReadOutsideTheLockPanics(t *testing.T) {
	var mu sync.Mutex
	sl := slab[urr]{mu: &mu}
	mu.Lock()
	h, _, _ := sl.alloc(urr{id: 7})
	if sl.at(h).id != 7 {
		t.Fatal("the record is not what was put")
	}
	mu.Unlock()
	if !slabLockCheck {
		t.Skip("slabLockCheck is off")
	}
	mustPanic(t, "without the compiler's lock", func() { sl.at(h) })
}

// TestARecordIndexIsCopyOnWrite: a session's index adds and removes by
// building a new slice, so a walk sees the records as they were when it
// began; past recIndexSmall of one kind every kind moves to maps.
func TestARecordIndexIsCopyOnWrite(t *testing.T) {
	var rs records
	var ix recIndex
	pdrs := recs[uint16, pdr]{&ix, &rs.pdrs, pdrRecs}
	fars := recs[uint32, far]{&ix, &rs.fars, farRecs}
	for _, id := range []uint32{5, 1, 3} {
		if _, err := fars.add(id, far{id: id}); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []uint16{2, 1} {
		pdrs.add(id, pdr{id: id})
	}
	if got := fars.ids(); !slices.Equal(got, []uint32{1, 3, 5}) || pdrs.len() != 2 || ix.n != [recKinds]uint8{2, 3, 0, 0} {
		t.Fatalf("FAR ids %v, %d PDRs, runs %v", got, pdrs.len(), ix.n)
	}
	// A walk in progress still visits a record taken out of the index while
	// the taker owns it; freeing it is what ends that, so a free waits for
	// the walk.
	var seen []uint32
	var taken uint32
	for id, f := range fars.all() {
		if id == 1 {
			taken = fars.take(3)
			fars.add(4, far{id: 4})
		}
		if f.id != id {
			t.Errorf("the walk read FAR %d under id %d", f.id, id)
		}
		seen = append(seen, id)
	}
	rs.fars.release(taken)
	if !slices.Equal(seen, []uint32{1, 3, 5}) {
		t.Errorf("the walk saw %v, want the ids as it began: 1 3 5", seen)
	}
	if got := fars.ids(); !slices.Equal(got, []uint32{1, 4, 5}) || fars.at(3) != nil || fars.at(4).id != 4 {
		t.Errorf("after the walk FAR ids %v", got)
	}
	if pdrs.at(2).id != 2 || pdrs.at(9) != nil {
		t.Error("the PDR run moved under the FARs' changes")
	}

	for id := range uint16(recIndexSmall + 1) {
		if !pdrs.has(id) {
			pdrs.add(id, pdr{id: id})
		}
	}
	if ix.big == nil || ix.small != nil {
		t.Fatal("past recIndexSmall PDRs the index is still a slice")
	}
	if pdrs.len() != recIndexSmall+1 || fars.len() != 3 || fars.at(5).id != 5 {
		t.Errorf("after growing: %d PDRs, %d FARs", pdrs.len(), fars.len())
	}
	var ordered []uint16
	for id := range pdrs.ordered() {
		ordered = append(ordered, id)
	}
	if !slices.IsSorted(ordered) || len(ordered) != recIndexSmall+1 {
		t.Errorf("ordered walk %v", ordered)
	}

	snap, err := ix.copyInto(&rs)
	if err != nil {
		t.Fatal(err)
	}
	if rs.pdrs.live != 2*(recIndexSmall+1) || rs.fars.live != 6 {
		t.Errorf("a copy holds %v records, want twice the index's", rs.live())
	}
	view := recs[uint16, pdr]{&snap, &rs.pdrs, pdrRecs}
	if view.at(3) == pdrs.at(3) || view.at(3).id != 3 {
		t.Error("the copy shares a record with the index")
	}
	snap.releaseInto(&rs)
	ix.releaseInto(&rs)
	if rs.live() != [recKinds]int{} || ix.big != nil {
		t.Errorf("released indexes left %v records", rs.live())
	}
}
