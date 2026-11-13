// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"net/netip"
	"runtime"
	"sync"
	"weak"
)

// interner holds one copy of each value of a kind every session would
// otherwise carry its own of: an SMF provisions the same few flow descriptions,
// network instances and N3 addresses to every subscriber. A value is never
// written once interned, so every holder shares it. The table holds weak
// pointers: a value nobody holds any more is collected, and its entry goes
// with it.
type interner[K comparable, V any] struct {
	mu sync.Mutex
	m  map[K]weak.Pointer[V]
}

// get returns the shared value for key, built by build when there is none.
// Nothing may write the value after this.
func (t *interner[K, V]) get(key K, build func() *V) *V {
	t.mu.Lock()
	defer t.mu.Unlock()
	if shared := t.m[key].Value(); shared != nil {
		return shared
	}
	v := build()
	if t.m == nil {
		t.m = map[K]weak.Pointer[V]{}
	}
	t.m[key] = weak.Make(v)
	runtime.AddCleanup(v, t.forget, key)
	return v
}

// forget drops the entry of a collected value, unless a new one has taken its
// place since.
func (t *interner[K, V]) forget(key K) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.m[key].Value() == nil {
		delete(t.m, key)
	}
}

// sdfFilters holds the parsed SDF filters: "permit out ip from any to
// assigned" names the UE address symbolically (the key builder fills it in),
// so a million sessions name a handful of filters. oriented and resolveSDFIDs
// copy rather than write.
var sdfFilters interner[sdfFilter, sdfFilter]

// internSDF returns the shared copy of f, which becomes it when there is none.
// f must be complete: nothing may write it after this.
func internSDF(f *sdfFilter) *sdfFilter {
	return sdfFilters.get(*f, func() *sdfFilter { return f })
}

// pdrExtKey is a pdrExt as a map key: the QFIs as a string.
type pdrExtKey struct {
	v4, v6              netip.Addr
	instance, reference string
	qfis                string
}

var pdrExts interner[pdrExtKey, pdrExt]

var farExts interner[farExt, farExt]
