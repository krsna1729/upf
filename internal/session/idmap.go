// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"cmp"
	"iter"
	"maps"
	"slices"
)

// idMapSmall is how many entries an idMap holds in its sorted slice before it
// moves them to a map: a session names a handful of rules of each kind, and a
// slice of them is 16 B of id and pointer each on amd64, where a Go map's
// first group is 144 B and its header 48. Past it the map's constant-time insert is what
// keeps a session of thousands of PDRs from costing O(n) per insert.
const idMapSmall = 16

type idEntry[K cmp.Ordered, V any] struct {
	id K
	v  V
}

// idMap is a session's rules of one kind, by rule id. The zero value is
// empty and ready to use.
//
// It is copy-on-write in its slice form: a set of a new id and a del build a
// new backing array, so an iteration in progress (all) walks the entries as
// they were when it began -- a removal or an addition made while walking does
// not move what is still to be visited.
type idMap[K cmp.Ordered, V any] struct {
	small []idEntry[K, V] // sorted by id; nil once big holds the entries
	big   map[K]V
}

func (m *idMap[K, V]) find(id K) (int, bool) {
	return slices.BinarySearchFunc(m.small, id, func(e idEntry[K, V], id K) int { return cmp.Compare(e.id, id) })
}

// get returns the entry for id, and whether there is one.
func (m *idMap[K, V]) get(id K) (V, bool) {
	if m.big != nil {
		v, ok := m.big[id]
		return v, ok
	}
	if i, ok := m.find(id); ok {
		return m.small[i].v, true
	}
	var zero V
	return zero, false
}

// at returns the entry for id, or the zero value.
func (m *idMap[K, V]) at(id K) V {
	v, _ := m.get(id)
	return v
}

// has says whether there is an entry for id.
func (m *idMap[K, V]) has(id K) bool {
	_, ok := m.get(id)
	return ok
}

// set puts v under id.
func (m *idMap[K, V]) set(id K, v V) {
	if m.big != nil {
		m.big[id] = v
		return
	}
	i, ok := m.find(id)
	if ok {
		m.small[i].v = v
		return
	}
	if len(m.small) == idMapSmall {
		m.big = make(map[K]V, idMapSmall*2)
		for _, e := range m.small {
			m.big[e.id] = e.v
		}
		m.big[id] = v
		m.small = nil
		return
	}
	next := make([]idEntry[K, V], len(m.small)+1)
	copy(next, m.small[:i])
	next[i] = idEntry[K, V]{id, v}
	copy(next[i+1:], m.small[i:])
	m.small = next
}

// del removes id's entry, if there is one.
func (m *idMap[K, V]) del(id K) {
	if m.big != nil {
		delete(m.big, id)
		return
	}
	i, ok := m.find(id)
	if !ok {
		return
	}
	if len(m.small) == 1 {
		m.small = nil
		return
	}
	next := make([]idEntry[K, V], len(m.small)-1)
	copy(next, m.small[:i])
	copy(next[i:], m.small[i+1:])
	m.small = next
}

func (m *idMap[K, V]) len() int {
	if m.big != nil {
		return len(m.big)
	}
	return len(m.small)
}

// all yields every entry: in id order in the slice form, in the map's order
// past idMapSmall. It is one call to walk so that it inlines: a range over it
// then keeps its loop body on the stack, and walking a session's rules
// allocates nothing.
func (m *idMap[K, V]) all() iter.Seq2[K, V] {
	return func(yield func(K, V) bool) { m.walk(yield) }
}

func (m *idMap[K, V]) walk(yield func(K, V) bool) {
	if m.big != nil {
		for k, v := range m.big {
			if !yield(k, v) {
				return
			}
		}
		return
	}
	for _, e := range m.small { // the slice as the walk began: set and del copy
		if !yield(e.id, e.v) {
			return
		}
	}
}

// ids returns the ids in order: what every transaction this compiler writes
// is built from (idsOf).
func (m *idMap[K, V]) ids() []K {
	if m.big != nil {
		return slices.Sorted(maps.Keys(m.big))
	}
	out := make([]K, len(m.small))
	for i, e := range m.small {
		out[i] = e.id
	}
	return out
}

// cloneIDMap copies m and each entry it points at: a snapshot the model can be
// put back to after a merge has changed entries in place.
func cloneIDMap[K cmp.Ordered, V any](m idMap[K, *V]) idMap[K, *V] {
	out := idMap[K, *V]{}
	if m.big != nil {
		out.big = make(map[K]*V, len(m.big))
		// A rollback publishes these values as the live model. One survivor
		// must not retain an arbitrarily large block after later removals.
		for k, v := range m.big {
			cp := *v
			out.big[k] = &cp
		}
		return out
	}
	if len(m.small) > 0 {
		out.small = make([]idEntry[K, *V], len(m.small))
		entries := make([]V, len(m.small))
		for i, e := range m.small {
			entries[i] = *e.v
			out.small[i] = idEntry[K, *V]{e.id, &entries[i]}
		}
	}
	return out
}
