// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"runtime"
	"sync"
	"weak"
)

// sdfFilters holds one copy of each parsed SDF filter. An SMF provisions the
// same few flow descriptions to every subscriber ("permit out ip from any to
// assigned": the UE address is filled in when the key is built), so a million
// sessions name a handful of filters, and a copy per PDR is 112 B each. A
// filter is never written after it is parsed (orientation and resolveSDFIDs
// copy), so PDRs share it. The table holds weak pointers: a filter no PDR
// names any more is collected, and its entry goes with it.
var sdfFilters = struct {
	sync.Mutex
	m map[sdfFilter]weak.Pointer[sdfFilter]
}{m: map[sdfFilter]weak.Pointer[sdfFilter]{}}

// internSDF returns the shared copy of f, which becomes it when there is none.
// f must be complete: nothing may write it after this.
func internSDF(f *sdfFilter) *sdfFilter {
	sdfFilters.Lock()
	defer sdfFilters.Unlock()
	if shared := sdfFilters.m[*f].Value(); shared != nil {
		return shared
	}
	sdfFilters.m[*f] = weak.Make(f)
	runtime.AddCleanup(f, forgetSDF, *f)
	return f
}

// forgetSDF drops the entry of a collected filter, unless a new copy has
// taken its place since.
func forgetSDF(key sdfFilter) {
	sdfFilters.Lock()
	defer sdfFilters.Unlock()
	if sdfFilters.m[key].Value() == nil {
		delete(sdfFilters.m, key)
	}
}
