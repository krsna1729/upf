// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"fmt"
	"iter"
	"maps"
	"slices"
	"sync"
)

// A session's records (pdr, far, qer, urr) are not Go objects of their own:
// each lives in a slot of one of the compiler's slabs (records), named by a
// uint32 handle, and a session lists its handles in one noscan slice
// (recIndex). The records hold no pointer (store.go), so a slab's segments
// are noscan arrays the collector marks without reading, and a session costs
// it the Session object and that slice rather than an object per record.
//
// Layout. A slab is segments of slabSeg records, each segment one array that
// never moves once made, with a parallel array of one-byte generations. A
// handle is the slot's index (low recIndexBits bits; index 0 is never used, so
// handle 0 names nothing) and the slot's generation when it was handed out
// (the top byte). Freed slots are reused last-in first-out. An empty segment
// gives back its records, except segment zero, which stays warm for churn.
// Its generation bytes stay so reuse cannot revive an old handle.
//
// Ownership. Every handle has exactly one owner, which frees it:
//   - the session's model: its index, its pending removals and replaced forms
//     (sessionChanges.removed, .stale) and its removed QERs. merge frees a
//     FAR or URR it removes, and a removed PDR a create of the same id makes
//     live again (forgetRemoval); settle frees the removals and replaced
//     forms once the dataplane took the transaction; releaseSession frees
//     everything the model names and empties the index.
//   - a modification's snapshot (modelSnapshot), which copies every record
//     the model names into slots of its own. rollback frees the failed
//     model's records and hands the snapshot's to the model; a modification
//     that stands (settle, or an unknown outcome) frees the snapshot's.
//
// Readers. Every read of a record holds Compiler.mu, as every free does, and
// a record pointer (*pdr, ...) is a borrow that ends with the lock hold that
// made it: nothing keeps one across an unlock, so no reader can hold a slot
// while it is freed and reused. The generation is the check on that rule, not
// the mechanism: a read through a handle whose slot was freed since panics,
// and tests also check every read holds the lock (slabLockCheck). A
// generation wraps after 256 reuses of one slot, past which a stale handle
// would go undetected; the rule above, not the byte, is what makes the reuse
// safe.

const (
	slabShift = 10
	slabSeg   = 1 << slabShift

	recIndexBits = 24
	recIndexMask = 1<<recIndexBits - 1
)

// slabLockCheck makes every record read check that the compiler's lock is
// held: a TryLock that succeeds means nobody held it. Tests set it.
var slabLockCheck bool

// errRecordsExhausted is a slab with no handle left: 2^24-1 records of one
// kind in one compiler. It is a refusal for want of a resource (cause 75),
// not a crash.
var errRecordsExhausted = fmt.Errorf("%w: session records", errNoResources)

type slabMetadata struct {
	generation [slabSeg]uint8
	used       uint16
}

// slab is the storage of one record kind. Every method runs under the
// compiler's lock (mu).
type slab[T any] struct {
	mu     *sync.Mutex
	recs   []*[slabSeg]T
	gens   []*slabMetadata
	next   uint32   // the first never-used index; 0 is reserved
	free   []uint32 // freed indexes, reused last first
	live   int
	mapped int
}

func (sl *slab[T]) checkLocked() {
	if sl.mu != nil && sl.mu.TryLock() {
		sl.mu.Unlock()
		panic("session: a session record read without the compiler's lock")
	}
}

// alloc puts v in a free slot and returns its handle and the record.
func (sl *slab[T]) alloc(v T) (uint32, *T, error) {
	var i uint32
	if n := len(sl.free); n != 0 {
		i = sl.free[n-1]
		sl.free = sl.free[:n-1]
	} else {
		if sl.next == 0 {
			sl.next = 1
		}
		if sl.next > recIndexMask {
			return 0, nil, errRecordsExhausted
		}
		i = sl.next
		sl.next++
		if int(i>>slabShift) == len(sl.recs) {
			sl.recs = append(sl.recs, nil)
			sl.gens = append(sl.gens, new(slabMetadata))
		}
	}
	seg := i >> slabShift
	if sl.recs[seg] == nil {
		sl.recs[seg] = new([slabSeg]T)
		sl.mapped++
	}
	meta := sl.gens[seg]
	meta.used++
	sl.live++
	p := &sl.recs[seg][i&(slabSeg-1)]
	*p = v
	return uint32(meta.generation[i&(slabSeg-1)])<<recIndexBits | i, p, nil
}

// slot is h's index, after checking h names a live record: its slot is in
// use and holds the generation h was handed out with.
func (sl *slab[T]) slot(h uint32) uint32 {
	i := h & recIndexMask
	if i == 0 || i >= sl.next || sl.gens[i>>slabShift].generation[i&(slabSeg-1)] != uint8(h>>recIndexBits) {
		panic(fmt.Sprintf("session: record handle %#x used after it was freed", h))
	}
	return i
}

// at is the record h names. The pointer is valid until the caller's lock
// hold ends.
func (sl *slab[T]) at(h uint32) *T {
	if slabLockCheck {
		sl.checkLocked()
	}
	i := sl.slot(h)
	return &sl.recs[i>>slabShift][i&(slabSeg-1)]
}

// release frees h's slot: its record is zeroed and its generation moves on,
// so a handle still naming it fails at.
func (sl *slab[T]) release(h uint32) {
	i := sl.slot(h)
	var zero T
	sl.recs[i>>slabShift][i&(slabSeg-1)] = zero
	seg := i >> slabShift
	meta := sl.gens[seg]
	meta.generation[i&(slabSeg-1)]++
	sl.free = append(sl.free, i)
	sl.live--
	meta.used--
	if seg != 0 && meta.used == 0 {
		sl.recs[seg] = nil
		sl.mapped--
	}
}

func (sl *slab[T]) releaseAll(hs []uint32) {
	for _, h := range hs {
		sl.release(h)
	}
}

// copyAll copies the records hs names into new slots, in a new list; nil for
// none. On an error it has freed what it copied.
func (sl *slab[T]) copyAll(hs []uint32) ([]uint32, error) {
	if len(hs) == 0 {
		return nil, nil
	}
	out := make([]uint32, len(hs))
	for i, h := range hs {
		n, _, err := sl.alloc(*sl.at(h))
		if err != nil {
			sl.releaseAll(out[:i])
			return nil, err
		}
		out[i] = n
	}
	return out, nil
}

// resolve appends the records hs names to out.
func (sl *slab[T]) resolve(out []*T, hs []uint32) []*T {
	for _, h := range hs {
		out = append(out, sl.at(h))
	}
	return out
}

// records is the compiler's slabs, one per record kind.
type records struct {
	pdrs slab[pdr]
	fars slab[far]
	qers slab[qer]
	urrs slab[urr]
}

func (rs *records) attach(mu *sync.Mutex) {
	rs.pdrs.mu, rs.fars.mu, rs.qers.mu, rs.urrs.mu = mu, mu, mu, mu
}

// live is how many records of each kind are allocated, and segments how many
// segments the slabs hold: what a deletion gives back and a re-establishment
// reuses.
func (rs *records) live() [recKinds]int {
	return [recKinds]int{rs.pdrs.live, rs.fars.live, rs.qers.live, rs.urrs.live}
}

func (rs *records) segments() int {
	return rs.pdrs.mapped + rs.fars.mapped + rs.qers.mapped + rs.urrs.mapped
}

// recKind is which slab a handle of a recIndex names.
type recKind uint8

const (
	pdrRecs recKind = iota
	farRecs
	qerRecs
	urrRecs
	recKinds
)

// recIndexSmall is how many records of one kind a recIndex holds in its
// sorted slice before every kind moves to maps: a session names a handful of
// rules of each kind, and 8 B of id and handle each is what they cost there,
// where a Go map's first group is 144 B and its header 48. Past it the maps'
// constant-time insert is what keeps a session of thousands of PDRs from
// costing O(n) per insert.
const recIndexSmall = 16

type recRef struct{ id, h uint32 }

// recIndex is a session's records by kind and rule id: one noscan slice of
// every kind's (id, handle) pairs, the PDRs', FARs', QERs' and URRs' in turn,
// each run sorted by id (n counts each run), or, once a kind passes
// recIndexSmall, a map per kind. The zero value is empty.
//
// It is copy-on-write in its slice form: adding or removing an id builds a
// new slice, so a walk in progress visits the entries as they were when it
// began. Replacing the handle of an id already there writes in place.
type recIndex struct {
	big   *[recKinds]map[uint32]uint32
	small []recRef
	n     [recKinds]uint8
}

func (x *recIndex) span(k recKind) (lo, hi int) {
	for i := range k {
		lo += int(x.n[i])
	}
	return lo, lo + int(x.n[k])
}

func (x *recIndex) find(k recKind, id uint32) (int, bool) {
	lo, hi := x.span(k)
	i, ok := slices.BinarySearchFunc(x.small[lo:hi], id, func(r recRef, id uint32) int {
		switch {
		case r.id < id:
			return -1
		case r.id > id:
			return 1
		}
		return 0
	})
	return lo + i, ok
}

func (x *recIndex) get(k recKind, id uint32) (uint32, bool) {
	if x.big != nil {
		h, ok := x.big[k][id]
		return h, ok
	}
	if i, ok := x.find(k, id); ok {
		return x.small[i].h, true
	}
	return 0, false
}

func (x *recIndex) count(k recKind) int {
	if x.big != nil {
		return len(x.big[k])
	}
	return int(x.n[k])
}

func (x *recIndex) set(k recKind, id, h uint32) {
	if x.big != nil {
		x.bigSet(k, id, h)
		return
	}
	i, ok := x.find(k, id)
	if ok {
		x.small[i].h = h
		return
	}
	if x.n[k] == recIndexSmall {
		x.grow()
		x.bigSet(k, id, h)
		return
	}
	next := make([]recRef, len(x.small)+1)
	copy(next, x.small[:i])
	next[i] = recRef{id, h}
	copy(next[i+1:], x.small[i:])
	x.small = next
	x.n[k]++
}

// bigSet sets id in kind k's map, made on its first entry: a kind the
// session names none of costs no map.
func (x *recIndex) bigSet(k recKind, id, h uint32) {
	if x.big[k] == nil {
		x.big[k] = map[uint32]uint32{}
	}
	x.big[k][id] = h
}

// grow moves every kind to its map.
func (x *recIndex) grow() {
	big := &[recKinds]map[uint32]uint32{}
	lo := 0
	for k := range recKinds {
		if x.n[k] != 0 {
			big[k] = make(map[uint32]uint32, max(int(x.n[k]), recIndexSmall*2))
		}
		for _, r := range x.small[lo : lo+int(x.n[k])] {
			big[k][r.id] = r.h
		}
		lo += int(x.n[k])
	}
	x.big, x.small, x.n = big, nil, [recKinds]uint8{}
}

// del takes id out and returns its handle, 0 for none.
func (x *recIndex) del(k recKind, id uint32) uint32 {
	if x.big != nil {
		h := x.big[k][id]
		delete(x.big[k], id)
		return h
	}
	i, ok := x.find(k, id)
	if !ok {
		return 0
	}
	h := x.small[i].h
	if len(x.small) == 1 {
		x.small = nil
	} else {
		next := make([]recRef, len(x.small)-1)
		copy(next, x.small[:i])
		copy(next[i:], x.small[i+1:])
		x.small = next
	}
	x.n[k]--
	return h
}

// handles appends every handle of kind k to out, in id order in the slice
// form.
func (x *recIndex) handles(k recKind, out []uint32) []uint32 {
	if x.big != nil {
		for _, h := range x.big[k] {
			out = append(out, h)
		}
		return out
	}
	lo, hi := x.span(k)
	for _, r := range x.small[lo:hi] {
		out = append(out, r.h)
	}
	return out
}

// copyInto is x with every record copied into a new slot of rs: what a
// snapshot holds. On an error it has freed what it copied.
func (x *recIndex) copyInto(rs *records) (recIndex, error) {
	var out recIndex
	var err error
	copyOne := func(k recKind, h uint32) uint32 {
		if err != nil {
			return 0
		}
		var n uint32
		switch k {
		case pdrRecs:
			n, _, err = rs.pdrs.alloc(*rs.pdrs.at(h))
		case farRecs:
			n, _, err = rs.fars.alloc(*rs.fars.at(h))
		case qerRecs:
			n, _, err = rs.qers.alloc(*rs.qers.at(h))
		case urrRecs:
			n, _, err = rs.urrs.alloc(*rs.urrs.at(h))
		}
		return n
	}
	if x.big != nil {
		out.big = &[recKinds]map[uint32]uint32{}
		for k := range recKinds {
			if len(x.big[k]) != 0 {
				out.big[k] = make(map[uint32]uint32, len(x.big[k]))
			}
			for id, h := range x.big[k] {
				if n := copyOne(k, h); err == nil {
					out.big[k][id] = n
				}
			}
		}
	} else if len(x.small) != 0 {
		out.small, out.n = make([]recRef, len(x.small)), x.n
		lo := 0
		for k := range recKinds {
			for i := lo; i < lo+int(x.n[k]); i++ {
				if n := copyOne(k, x.small[i].h); err == nil {
					out.small[i] = recRef{x.small[i].id, n}
				}
			}
			lo += int(x.n[k])
		}
	}
	if err != nil {
		out.releaseInto(rs)
		return recIndex{}, err
	}
	return out, nil
}

// releaseInto frees every record x names and empties x.
func (x *recIndex) releaseInto(rs *records) {
	free := func(k recKind, h uint32) {
		if h == 0 {
			return // a copy that failed part way
		}
		switch k {
		case pdrRecs:
			rs.pdrs.release(h)
		case farRecs:
			rs.fars.release(h)
		case qerRecs:
			rs.qers.release(h)
		case urrRecs:
			rs.urrs.release(h)
		}
	}
	if x.big != nil {
		for k := range recKinds {
			for _, h := range x.big[k] {
				free(k, h)
			}
		}
	} else {
		lo := 0
		for k := range recKinds {
			for _, r := range x.small[lo : lo+int(x.n[k])] {
				free(k, r.h)
			}
			lo += int(x.n[k])
		}
	}
	*x = recIndex{}
}

// recs is one kind of a session's records, read through its slab: the view
// Session.PDRs and its kin return.
type recs[K ~uint16 | ~uint32, T any] struct {
	ix   *recIndex
	sl   *slab[T]
	kind recKind
}

// at is id's record, nil for none.
func (v recs[K, T]) at(id K) *T {
	if h, ok := v.ix.get(v.kind, uint32(id)); ok {
		return v.sl.at(h)
	}
	return nil
}

// handle is id's handle, 0 for none.
func (v recs[K, T]) handle(id K) uint32 {
	h, _ := v.ix.get(v.kind, uint32(id))
	return h
}

func (v recs[K, T]) has(id K) bool {
	_, ok := v.ix.get(v.kind, uint32(id))
	return ok
}

func (v recs[K, T]) len() int { return v.ix.count(v.kind) }

// add makes rec id's record, in a new slot; id has none.
func (v recs[K, T]) add(id K, rec T) (*T, error) {
	h, p, err := v.sl.alloc(rec)
	if err != nil {
		return nil, err
	}
	v.ix.set(v.kind, uint32(id), h)
	return p, nil
}

// put makes the record h names id's; the one id named, if any, is the
// caller's to free or keep.
func (v recs[K, T]) put(id K, h uint32) { v.ix.set(v.kind, uint32(id), h) }

// take removes id and returns its handle (0 for none), which the caller now
// owns.
func (v recs[K, T]) take(id K) uint32 { return v.ix.del(v.kind, uint32(id)) }

// drop removes id and frees its record.
func (v recs[K, T]) drop(id K) {
	if h := v.ix.del(v.kind, uint32(id)); h != 0 {
		v.sl.release(h)
	}
}

// all yields every record: in id order in the slice form, in the maps'
// order past recIndexSmall. It is one call to walk so that it inlines: a
// range over it then keeps its loop body on the stack, and walking a
// session's rules allocates nothing.
func (v recs[K, T]) all() iter.Seq2[K, *T] {
	return func(yield func(K, *T) bool) { v.walk(yield) }
}

func (v recs[K, T]) walk(yield func(K, *T) bool) {
	if b := v.ix.big; b != nil {
		for id, h := range b[v.kind] {
			if !yield(K(id), v.sl.at(h)) {
				return
			}
		}
		return
	}
	lo, hi := v.ix.span(v.kind)
	for _, r := range v.ix.small[lo:hi] { // the slice as the walk began
		if !yield(K(r.id), v.sl.at(r.h)) {
			return
		}
	}
}

// ids returns the ids in order: what every transaction this compiler writes
// is built from.
func (v recs[K, T]) ids() []K {
	if b := v.ix.big; b != nil {
		out := make([]K, 0, len(b[v.kind]))
		for id := range b[v.kind] {
			out = append(out, K(id))
		}
		slices.Sort(out)
		return out
	}
	lo, hi := v.ix.span(v.kind)
	out := make([]K, hi-lo)
	for i, r := range v.ix.small[lo:hi] {
		out[i] = K(r.id)
	}
	return out
}

// ordered yields every record in id order. The slice form is already sorted
// and walks as all does, allocating nothing; past recIndexSmall the ids are
// sorted first, and a record removed during the walk is skipped.
func (v recs[K, T]) ordered() iter.Seq2[K, *T] {
	return func(yield func(K, *T) bool) { v.walkOrdered(yield) }
}

func (v recs[K, T]) walkOrdered(yield func(K, *T) bool) {
	b := v.ix.big
	if b == nil {
		v.walk(yield)
		return
	}
	for _, id := range slices.Sorted(maps.Keys(b[v.kind])) {
		if h, ok := b[v.kind][id]; ok && !yield(K(id), v.sl.at(h)) {
			return
		}
	}
}

// list returns the records in id order, in a new slice the caller may
// extend.
func (v recs[K, T]) list() []*T {
	return v.appendTo(make([]*T, 0, v.len()))
}

// appendTo appends the records in id order to out: a caller with a stack
// buffer for the usual handful allocates nothing.
func (v recs[K, T]) appendTo(out []*T) []*T {
	for _, p := range v.ordered() {
		out = append(out, p)
	}
	return out
}
