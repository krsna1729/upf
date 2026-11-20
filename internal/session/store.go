// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"fmt"
	"hash/maphash"
	"net/netip"
	"slices"
	"sync/atomic"
	"unsafe"
)

// The session records (pdr, far, qer, urr) hold no Go pointers: what they
// share with other sessions, or what varies in length, is a uint32 handle into
// one of the compiler's tables below. The collector then skips the records
// (they live in noscan spans), and a million sessions do not cost a million
// copies of a provisioning every subscriber shares.
//
// Ownership is per session, not per record copy. A session holds one reference
// to every handle any of its records names -- the model, the pending erasures,
// the removed QERs -- listed, sorted, in a blob of its own (s.refs, refsOf),
// so the list costs the session no Go object. Records are copied freely (a modification's
// snapshot, a replaced PDR's stale form): a copy names only handles the session
// already holds. A handle the session stops naming is given back only at a
// quiescent point (trim), when no snapshot of the session is outstanding
// (s.copies), so a rollback never restores a record naming a freed handle.
// The session's end gives back everything it holds (drop).
//
// Writes (acquire, own, trim, drop) run under Compiler.mu. Reads (get) take no
// lock: storage is segmented, a segment never moves, and the segment directory
// is published atomically; an entry is written once, before its handle is
// published, and is rewritten only after its last reference went.

// ipAddr is a netip.Addr without the zone pointer: the 16 address bytes and
// the family (4, 6, or 0 for none). A PFCP address carries no zone.
type ipAddr struct {
	b   [16]byte
	fam uint8
}

func ipOf(a netip.Addr) ipAddr {
	switch {
	case a.Is4():
		v := a.As4()
		var out ipAddr
		copy(out.b[:], v[:])
		out.fam = 4
		return out
	case a.Is6():
		return ipAddr{b: a.As16(), fam: 6}
	}
	return ipAddr{}
}

func (a ipAddr) addr() netip.Addr {
	switch a.fam {
	case 4:
		return netip.AddrFrom4([4]byte(a.b[:4]))
	case 6:
		return netip.AddrFrom16(a.b)
	}
	return netip.Addr{}
}

func (a ipAddr) IsValid() bool { return a.fam != 0 }

// ipPrefix is a netip.Prefix as an ipAddr and a length.
type ipPrefix struct {
	a    ipAddr
	bits int16
}

func prefixOf(p netip.Prefix) ipPrefix {
	if !p.IsValid() {
		return ipPrefix{}
	}
	return ipPrefix{a: ipOf(p.Addr()), bits: int16(p.Bits())}
}

func (p ipPrefix) prefix() netip.Prefix {
	if !p.a.IsValid() {
		return netip.Prefix{}
	}
	return netip.PrefixFrom(p.a.addr(), int(p.bits))
}

// The handle kinds a session can hold, in the top bits of each s.refs entry.
const (
	kindExt    = 1 + iota // pdrExt
	kindFarExt            // farExt
	kindPolicy            // qerPolicy
	kindLimits            // urrLimits
	kindEnd               // localEnd
	kindSDF               // sdfFilter
	kindBlob              // a byte string: an id list, a rule identity

	kindShift  = 28
	handleMask = 1<<kindShift - 1
)

const segShift, segSize = 10, 1 << 10

type tableEntry[V comparable] struct {
	v    V
	hash uint32
	refs uint32
}

// table is a refcounted set of values of one kind, each named by a handle.
// Handle 0 is the zero value and holds no reference. The index is open
// addressing over the entries' hashes; a value is compared whole on a hash
// match, so equal values share one entry and unequal ones never alias.
type table[V comparable] struct {
	dir   atomic.Pointer[[]*[segSize]tableEntry[V]]
	next  uint32 // the first never-used entry; 0 is reserved for the zero value
	free  []uint32
	index []uint32
	live  int
	seed  maphash.Seed
	zero  V
}

func (t *table[V]) entry(h uint32) *tableEntry[V] {
	return &(*t.dir.Load())[h>>segShift][h&(segSize-1)]
}

// get is the value h names. It is valid while a reference to h is held.
func (t *table[V]) get(h uint32) *V {
	if h == 0 {
		return &t.zero
	}
	e := t.entry(h)
	if e.refs == 0 {
		panic(fmt.Sprintf("session: handle %d read after its last reference went", h))
	}
	return &e.v
}

// acquire returns the handle of a value equal to v, made if there is none,
// with one reference the caller now holds.
func (t *table[V]) acquire(v V) uint32 {
	if v == t.zero {
		return 0
	}
	if t.dir.Load() == nil {
		t.seed = maphash.MakeSeed()
	}
	hash := uint32(maphash.Comparable(t.seed, v))
	if len(t.index) != 0 {
		mask := uint32(len(t.index) - 1)
		for i := hash & mask; t.index[i] != 0; i = (i + 1) & mask {
			if e := t.entry(t.index[i]); e.hash == hash && e.v == v {
				e.refs++
				return t.index[i]
			}
		}
	}
	h := t.alloc()
	*t.entry(h) = tableEntry[V]{v: v, hash: hash, refs: 1}
	t.live++
	t.index = indexInsert(t.index, h, hash, t.live, func(h uint32) uint32 { return t.entry(h).hash })
	return h
}

func (t *table[V]) alloc() uint32 {
	if n := len(t.free); n != 0 {
		h := t.free[n-1]
		t.free = t.free[:n-1]
		return h
	}
	if t.next == 0 {
		t.next = 1
	}
	h := t.next
	if h > handleMask {
		panic("session: a store table is out of handles")
	}
	t.next++
	dir := t.dir.Load()
	if dir == nil || int(h>>segShift) >= len(*dir) {
		var grown []*[segSize]tableEntry[V]
		if dir != nil {
			grown = append(grown, *dir...)
		}
		grown = append(grown, new([segSize]tableEntry[V]))
		t.dir.Store(&grown)
	}
	return h
}

func (t *table[V]) retain(h uint32) {
	if h != 0 {
		t.entry(h).refs++
	}
}

// release gives back one reference; the last one frees the entry.
func (t *table[V]) release(h uint32) {
	if h == 0 {
		return
	}
	e := t.entry(h)
	if e.refs == 0 {
		panic(fmt.Sprintf("session: handle %d released after its last reference went", h))
	}
	if e.refs--; e.refs != 0 {
		return
	}
	indexDelete(t.index, h, e.hash, func(h uint32) uint32 { return t.entry(h).hash })
	e.v = t.zero
	t.live--
	t.free = append(t.free, h)
}

// indexInsert puts h into an open-addressing index, growing it past 3/4.
func indexInsert(index []uint32, h, hash uint32, live int, hashOf func(uint32) uint32) []uint32 {
	if live*4 > len(index)*3 {
		grown := make([]uint32, max(16, 2*len(index)))
		mask := uint32(len(grown) - 1)
		for _, old := range index {
			if old == 0 {
				continue
			}
			i := hashOf(old) & mask
			for grown[i] != 0 {
				i = (i + 1) & mask
			}
			grown[i] = old
		}
		index = grown
	}
	mask := uint32(len(index) - 1)
	i := hash & mask
	for index[i] != 0 {
		i = (i + 1) & mask
	}
	index[i] = h
	return index
}

// indexDelete takes h out of an index by backward shift: no tombstones, so a
// probe never walks a slot that once held something.
func indexDelete(index []uint32, h, hash uint32, hashOf func(uint32) uint32) {
	mask := uint32(len(index) - 1)
	i := hash & mask
	for index[i] != h {
		i = (i + 1) & mask
	}
	for j := (i + 1) & mask; index[j] != 0; j = (j + 1) & mask {
		home := hashOf(index[j]) & mask
		// Move j's entry back to i unless its home lies cyclically in (i, j].
		if (j > i && (home <= i || home > j)) || (j < i && home <= i && home > j) {
			index[i] = index[j]
			i = j
		}
	}
	index[i] = 0
}

// blobSeg is the size of a byte segment; a longer blob gets a segment of its
// own.
const blobSeg = 64 << 10

type blobEntry struct {
	seg, off, n, hash, refs uint32
}

// blobs is a refcounted set of byte strings in segmented noscan storage, each
// named by a handle; equal strings share one. Freed space is reused by size
// (rounded to 8 bytes); a blob longer than a segment has its own, given back
// with it.
type blobs struct {
	entries  table[blobEntry] // only its storage and free list: the index is below
	segs     atomic.Pointer[[][]byte]
	tail     uint32 // the fill offset of the last shared segment
	shared   int32  // the last shared segment, -1 for none
	holes    map[uint32][]uint64
	freeSegs []uint32
	index    []uint32
	live     int
	seed     maphash.Seed
}

func (b *blobs) bytes(h uint32) []byte {
	if h == 0 {
		return nil
	}
	e := b.entries.get(h)
	seg := (*b.segs.Load())[e.seg]
	return seg[e.off : e.off+e.n : e.off+e.n]
}

// words is the blob h read in place as uint32s in native byte order. A blob
// starts on an 8-byte boundary of its segment (blobClass), so the view is
// aligned.
func (b *blobs) words(h uint32) []uint32 {
	v := b.bytes(h)
	if len(v) == 0 {
		return nil
	}
	return unsafe.Slice((*uint32)(unsafe.Pointer(&v[0])), len(v)/4)
}

func (b *blobs) acquire(v []byte) uint32 {
	if len(v) == 0 {
		return 0
	}
	if b.segs.Load() == nil {
		b.seed = maphash.MakeSeed()
		b.shared = -1
		b.holes = map[uint32][]uint64{}
		b.segs.Store(&[][]byte{})
	}
	hash := uint32(maphash.Bytes(b.seed, v))
	if len(b.index) != 0 {
		mask := uint32(len(b.index) - 1)
		for i := hash & mask; b.index[i] != 0; i = (i + 1) & mask {
			if e := b.entries.entry(b.index[i]); e.v.hash == hash && string(b.bytes(b.index[i])) == string(v) {
				e.refs++
				return b.index[i]
			}
		}
	}
	seg, off := b.place(uint32(len(v)))
	copy((*b.segs.Load())[seg][off:], v)
	h := b.entries.alloc()
	*b.entries.entry(h) = tableEntry[blobEntry]{v: blobEntry{seg: seg, off: off, n: uint32(len(v)), hash: hash}, refs: 1}
	b.live++
	b.index = indexInsert(b.index, h, hash, b.live, func(h uint32) uint32 { return b.entries.entry(h).v.hash })
	return h
}

func blobClass(n uint32) uint32 { return (n + 7) &^ 7 }

// place finds room for n bytes: a freed hole of the same class, the tail of
// the shared segment, a new shared segment, or a segment of its own.
func (b *blobs) place(n uint32) (seg, off uint32) {
	class := blobClass(n)
	if class > blobSeg/4 {
		return b.newSeg(class), 0
	}
	if holes := b.holes[class]; len(holes) != 0 {
		at := holes[len(holes)-1]
		b.holes[class] = holes[:len(holes)-1]
		return uint32(at >> 32), uint32(at)
	}
	if b.shared < 0 || b.tail+class > blobSeg {
		b.shared, b.tail = int32(b.newSeg(blobSeg)), 0
	}
	off = b.tail
	b.tail += class
	return uint32(b.shared), off
}

func (b *blobs) newSeg(size uint32) uint32 {
	segs := *b.segs.Load()
	if n := len(b.freeSegs); n != 0 {
		i := b.freeSegs[n-1]
		b.freeSegs = b.freeSegs[:n-1]
		grown := slices.Clone(segs)
		grown[i] = make([]byte, size)
		b.segs.Store(&grown)
		return i
	}
	grown := append(slices.Clone(segs), make([]byte, size))
	b.segs.Store(&grown)
	return uint32(len(grown) - 1)
}

func (b *blobs) release(h uint32) {
	if h == 0 {
		return
	}
	e := b.entries.entry(h)
	if e.refs == 0 {
		panic(fmt.Sprintf("session: blob %d released after its last reference went", h))
	}
	if e.refs--; e.refs != 0 {
		return
	}
	indexDelete(b.index, h, e.v.hash, func(h uint32) uint32 { return b.entries.entry(h).v.hash })
	b.live--
	if class := blobClass(e.v.n); class > blobSeg/4 {
		segs := slices.Clone(*b.segs.Load())
		segs[e.v.seg] = nil
		b.segs.Store(&segs)
		b.freeSegs = append(b.freeSegs, e.v.seg)
	} else {
		b.holes[class] = append(b.holes[class], uint64(e.v.seg)<<32|uint64(e.v.off))
	}
	e.v = blobEntry{}
	b.entries.free = append(b.entries.free, h)
}

// idList is a short list of ids held in place: up to two in ids, more as a
// blob of every id in native byte order (more), read in place by store.ids.
type idList struct {
	n    uint16
	ids  [2]uint32
	more uint32
}

func (l *idList) len() int { return int(l.n) }

// store is the compiler's tables. Every method that writes runs under
// Compiler.mu.
type store struct {
	exts     table[pdrExt]
	farExts  table[farExt]
	policies table[qerPolicy]
	limits   table[urrLimits]
	ends     table[localEnd]
	sdfs     table[sdfFilter]
	blobs    blobs

	scratch []uint32 // trim's handle list, reused
	refBuf  []uint32 // own's new handle list, reused
}

func (st *store) release(typed uint32) {
	h := typed & handleMask
	switch typed >> kindShift {
	case kindExt:
		st.exts.release(h)
	case kindFarExt:
		st.farExts.release(h)
	case kindPolicy:
		st.policies.release(h)
	case kindLimits:
		st.limits.release(h)
	case kindEnd:
		st.ends.release(h)
	case kindSDF:
		st.sdfs.release(h)
	case kindBlob:
		st.blobs.release(h)
	default:
		panic(fmt.Sprintf("session: handle kind %d", typed>>kindShift))
	}
}

// own records that s holds the reference to h of the given kind the caller
// acquired; a session holds one reference per handle, so a second is given
// back. It returns h.
func (st *store) own(s *Session, kind, h uint32) uint32 {
	if h == 0 {
		return 0
	}
	typed := kind<<kindShift | h
	held := st.refsOf(s)
	i, found := slices.BinarySearch(held, typed)
	if found {
		st.release(typed)
		return h
	}
	list := append(append(append(st.refBuf[:0], held[:i]...), typed), held[i:]...)
	st.setRefs(s, list)
	st.refBuf = list[:0]
	return h
}

// refsOf is the handles s holds, read in place.
func (st *store) refsOf(s *Session) []uint32 {
	return st.blobs.words(s.refs)
}

// setRefs makes list the handles s holds. The new blob is taken before the
// old one goes back, so list may be read from it.
func (st *store) setRefs(s *Session, list []uint32) {
	var h uint32
	if len(list) != 0 {
		h = st.blobs.acquire(unsafe.Slice((*byte)(unsafe.Pointer(&list[0])), 4*len(list)))
	}
	st.blobs.release(s.refs)
	s.refs = h
}

func (st *store) ownExt(s *Session, v pdrExt) uint32 {
	return st.own(s, kindExt, st.exts.acquire(v))
}

func (st *store) ownFarExt(s *Session, v farExt) uint32 {
	return st.own(s, kindFarExt, st.farExts.acquire(v))
}

func (st *store) ownPolicy(s *Session, v qerPolicy) uint32 {
	return st.own(s, kindPolicy, st.policies.acquire(v))
}

func (st *store) ownLimits(s *Session, v urrLimits) uint32 {
	return st.own(s, kindLimits, st.limits.acquire(v))
}

func (st *store) ownEnd(s *Session, v localEnd) uint32 {
	return st.own(s, kindEnd, st.ends.acquire(v))
}

func (st *store) ownBlob(s *Session, v []byte) uint32 {
	return st.own(s, kindBlob, st.blobs.acquire(v))
}

// ownIDs makes an idList of ids, held by s.
func (st *store) ownIDs(s *Session, ids []uint32) idList {
	l := idList{n: uint16(len(ids))}
	if len(ids) <= len(l.ids) {
		copy(l.ids[:], ids)
		return l
	}
	l.more = st.ownBlob(s, unsafe.Slice((*byte)(unsafe.Pointer(&ids[0])), 4*len(ids)))
	return l
}

// ownSDFs makes the idList of a PDR's SDF filters, each held by s.
func (st *store) ownSDFs(s *Session, filters []sdfFilter) idList {
	var buf [8]uint32
	hs := buf[:0]
	for _, f := range filters {
		hs = append(hs, st.own(s, kindSDF, st.sdfs.acquire(f)))
	}
	return st.ownIDs(s, hs)
}

// ids is l's ids, read in place: l itself or the blob it names, neither of
// which changes while the list is held. The caller must not write it. A
// slice rather than an iterator: a range-over-func body that does not
// inline is a closure, and what it captures escapes to the heap.
func (st *store) ids(l *idList) []uint32 {
	if l.n <= uint16(len(l.ids)) {
		return l.ids[:l.n:l.n]
	}
	return st.blobs.words(l.more)
}

// sdfAt is the i-th SDF filter of l.
func (st *store) sdfAt(l *idList, i int) *sdfFilter {
	return st.sdfs.get(st.ids(l)[i])
}

// each appends to out every handle s's records name, typed by kind.
func (st *store) handles(s *Session, out []uint32) []uint32 {
	addList := func(l *idList, kind uint32) {
		if l.n > uint16(len(l.ids)) {
			out = append(out, kindBlob<<kindShift|l.more)
		}
		if kind != 0 {
			for _, h := range st.ids(l) {
				if h != 0 {
					out = append(out, kind<<kindShift|h)
				}
			}
		}
	}
	addPDR := func(p *pdr) {
		if p.ext != 0 {
			out = append(out, kindExt<<kindShift|p.ext)
		}
		if p.tunnelEnd != 0 {
			out = append(out, kindEnd<<kindShift|p.tunnelEnd)
		}
		addList(&p.sdfs, kindSDF)
		addList(&p.qerIDs, 0)
		addList(&p.urrIDs, 0)
	}
	for _, p := range s.PDRs.all() {
		addPDR(p)
	}
	for _, p := range s.pending.removedPDRs() {
		addPDR(p)
	}
	for _, p := range s.pending.stalePDRs() {
		addPDR(p)
	}
	for _, f := range s.FARs.all() {
		if f.ext != 0 {
			out = append(out, kindFarExt<<kindShift|f.ext)
		}
	}
	addQER := func(q *qer) {
		if q.policy != 0 {
			out = append(out, kindPolicy<<kindShift|q.policy)
		}
	}
	for _, q := range s.QERs.all() {
		addQER(q)
	}
	for _, q := range s.rare().removedQERs {
		addQER(q)
	}
	for _, u := range s.URRs.all() {
		if u.limits != 0 {
			out = append(out, kindLimits<<kindShift|u.limits)
			if l := st.limits.get(u.limits); l.linked.n > uint16(len(l.linked.ids)) {
				out = append(out, kindBlob<<kindShift|l.linked.more)
			}
		}
	}
	return out
}

// trim gives back the handles s holds and no record of s names any more. It
// does nothing while a snapshot of s is outstanding (s.copies): the snapshot's
// records may name them, and a rollback would restore those.
func (st *store) trim(s *Session) {
	if s.copies != 0 {
		return
	}
	live := st.handles(s, st.scratch[:0])
	slices.Sort(live)
	live = slices.Compact(live)
	st.scratch = live[:0]
	j := 0
	held := st.refsOf(s)
	for _, typed := range held {
		for j < len(live) && live[j] < typed {
			panic(fmt.Sprintf("session: session %d names handle %#x it does not hold", s.LocalSEID, live[j]))
		}
		if j < len(live) && live[j] == typed {
			j++
			continue
		}
		st.release(typed)
	}
	if j != len(live) {
		panic(fmt.Sprintf("session: session %d names handle %#x it does not hold", s.LocalSEID, live[j]))
	}
	if len(live) != len(held) {
		st.setRefs(s, live)
	}
}

// drop gives back every handle s holds: the session is gone.
func (st *store) drop(s *Session) {
	for _, typed := range st.refsOf(s) {
		st.release(typed)
	}
	st.setRefs(s, nil)
}
