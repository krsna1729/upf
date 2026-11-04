// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"cmp"
	"slices"
	"testing"
)

// idMapOf builds an idMap from a map literal: a test's session spelled out.
func idMapOf[K cmp.Ordered, V any](m map[K]V) idMap[K, V] {
	var out idMap[K, V]
	for k, v := range m {
		out.set(k, v)
	}
	return out
}

// TestAnIDMapFindsEveryEntryEitherSideOfItsMove: up to idMapSmall entries
// are a sorted slice and the next moves them to a map; every entry is found,
// replaced and removed the same way in both forms, and ids are in order.
func TestAnIDMapFindsEveryEntryEitherSideOfItsMove(t *testing.T) {
	for _, n := range []int{idMapSmall, idMapSmall + 1} {
		var m idMap[uint16, int]
		for i := n; i >= 1; i-- { // reverse: every insert lands at the front
			m.set(uint16(i), i)
		}
		if got, want := m.big != nil, n > idMapSmall; got != want {
			t.Errorf("%d entries: map form %v, want %v", n, got, want)
		}
		want := make([]uint16, n)
		for i := range want {
			want[i] = uint16(i + 1)
		}
		if ids := m.ids(); !slices.Equal(ids, want) {
			t.Errorf("%d entries: ids %v, want %v", n, ids, want)
		}
		m.set(3, 300)
		for i := 1; i <= n; i++ {
			v, ok := m.get(uint16(i))
			if wantV := map[bool]int{true: 300, false: i}[i == 3]; !ok || v != wantV {
				t.Errorf("%d entries: get(%d) = %d, %v; want %d", n, i, v, ok, wantV)
			}
		}
		m.del(1)
		m.del(uint16(n + 5)) // absent: no change
		if m.has(1) || m.len() != n-1 {
			t.Errorf("%d entries: after removing 1, has(1) %v and %d entries, want false and %d", n, m.has(1), m.len(), n-1)
		}
	}
}

// TestAWalkSeesTheEntriesItBeganWith: a removal or an addition made while
// walking (a merge that drops or adds a rule inside a loop over the session's
// rules) does not skip an entry still to come or visit one twice.
func TestAWalkSeesTheEntriesItBeganWith(t *testing.T) {
	m := idMapOf(map[uint32]string{1: "a", 2: "b", 3: "c", 4: "d"})
	var seen []uint32
	for id := range m.all() {
		seen = append(seen, id)
		if id == 1 {
			m.del(1)
			m.del(2)
			m.set(0, "z")
		}
	}
	if !slices.Equal(seen, []uint32{1, 2, 3, 4}) {
		t.Errorf("the walk visited %v, want the four ids it began with", seen)
	}
	if ids := m.ids(); !slices.Equal(ids, []uint32{0, 3, 4}) {
		t.Errorf("after the walk the ids are %v, want [0 3 4]", ids)
	}
}
