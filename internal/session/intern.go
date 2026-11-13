// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"hash/maphash"
	"net/netip"
	"sync/atomic"
)

// internSlots is the size of each interner's table.
const internSlots = 256

var internSeed = maphash.MakeSeed()

// interner shares values of a kind every session would otherwise carry its
// own copy of: an SMF provisions the same few flow descriptions, network
// instances and N3 addresses to every subscriber. It is a fixed table indexed
// by the key's hash, not a set: a value whose slot holds an equal one is
// handed that one, any other takes the slot. So a value that recurs is
// shared, a value no other session has costs nothing beyond itself -- no
// table entry outlives it -- and the table holds at most internSlots values
// alive. A value is never written once interned, so every holder shares it.
type interner[K comparable, V any] struct {
	keyOf func(*V) K
	slots [internSlots]atomic.Pointer[V]
}

// get returns the value for key: the slot's if it is equal, else the one build
// makes, which then takes the slot. Nothing may write the value after this.
func (t *interner[K, V]) get(key K, build func() *V) *V {
	slot := &t.slots[maphash.Comparable(internSeed, key)%internSlots]
	if v := slot.Load(); v != nil && t.keyOf(v) == key {
		return v
	}
	v := build()
	slot.Store(v)
	return v
}

// sdfFilters holds parsed SDF filters: "permit out ip from any to assigned"
// names the UE address symbolically (the key builder fills it in), so most
// sessions name one of a handful. oriented and resolveSDFIDs copy rather than
// write.
var sdfFilters = interner[sdfFilter, sdfFilter]{keyOf: func(f *sdfFilter) sdfFilter { return *f }}

// internSDF returns a shared copy equal to f, or f itself.
// f must be complete: nothing may write it after this.
func internSDF(f *sdfFilter) *sdfFilter {
	return sdfFilters.get(*f, func() *sdfFilter { return f })
}

// pdrExtKey is a pdrExt as a key: the QFIs as a string.
type pdrExtKey struct {
	v4, v6              netip.Addr
	instance, reference string
	qfis                string
}

var pdrExts = interner[pdrExtKey, pdrExt]{keyOf: func(e *pdrExt) pdrExtKey {
	return pdrExtKey{v4: e.fteidIPv4, v6: e.fteidIPv6, instance: e.instance, reference: e.reference, qfis: string(e.qfis)}
}}

var farExts = interner[farExt, farExt]{keyOf: func(e *farExt) farExt { return *e }}

var localEnds = interner[localEnd, localEnd]{keyOf: func(e *localEnd) localEnd { return *e }}
