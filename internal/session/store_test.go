// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"bytes"
	"fmt"
	"hash/maphash"
	"net/netip"
	"slices"
	"testing"
)

// withPDI gives p a PDI extension and SDF filters held by a session of its
// own in st: what a test that builds a PDR by hand needs to read them back.
func withPDI(st *store, p *pdr, ext pdrExt, sdfs ...sdfFilter) *pdr {
	s := &Session{}
	p.ext = st.ownExt(s, ext)
	p.sdfs = st.ownSDFs(s, sdfs)
	return p
}

func TestATableSharesEqualValuesAndFreesTheLast(t *testing.T) {
	var tb table[localEnd]
	a := localEnd{address: ipOf(netip.MustParseAddr("192.0.2.1")), domain: 7}
	b := localEnd{address: ipOf(netip.MustParseAddr("192.0.2.2")), domain: 7}
	if h := tb.acquire(localEnd{}); h != 0 {
		t.Fatalf("the zero value took handle %d, want 0", h)
	}
	ha, hb, ha2 := tb.acquire(a), tb.acquire(b), tb.acquire(a)
	if ha == 0 || ha == hb || ha != ha2 {
		t.Fatalf("handles %d, %d, %d: want equal values to share one, unequal ones apart", ha, hb, ha2)
	}
	if *tb.get(ha) != a || *tb.get(hb) != b {
		t.Fatal("a handle reads another value")
	}
	tb.release(ha)
	if *tb.get(ha) != a {
		t.Fatal("a value went with one of its two references")
	}
	tb.release(ha)
	if tb.live != 1 {
		t.Fatalf("%d values live, want 1", tb.live)
	}
	if hc := tb.acquire(a); *tb.get(hc) != a || *tb.get(hb) != b {
		t.Fatal("a freed entry's reuse moved another value")
	}
}

// TestATableIndexSurvivesChurn: backward-shift deletion keeps every live value
// findable whatever order values come and go in.
func TestATableIndexSurvivesChurn(t *testing.T) {
	var tb table[qerPolicy]
	held := map[uint64]uint32{}
	for round := range 20 {
		for i := range uint64(500) {
			v := qerPolicy{mbUL: i + 1, mbDL: uint64(round)}
			held[i] = tb.acquire(v)
		}
		for i := range uint64(500) {
			if (i+uint64(round))%3 == 0 {
				continue
			}
			tb.release(held[i])
			delete(held, i)
		}
		for i, h := range held {
			if got := tb.acquire(*tb.get(h)); got != h {
				t.Fatalf("round %d: value %d found at %d, held at %d", round, i, got, h)
			}
			tb.release(h)
		}
		for i, h := range held {
			tb.release(h)
			delete(held, i)
		}
		if tb.live != 0 {
			t.Fatalf("round %d: %d values outlived their references", round, tb.live)
		}
	}
}

func TestBlobsShareBytesAndReuseFreedSpace(t *testing.T) {
	var b blobs
	x, y := []byte("rule-identity-one"), []byte("rule-identity-two")
	hx, hy, hx2 := b.acquire(x), b.acquire(y), b.acquire(x)
	if hx != hx2 || hx == hy || !bytes.Equal(b.bytes(hx), x) || !bytes.Equal(b.bytes(hy), y) {
		t.Fatal("equal blobs are not shared, or a handle reads other bytes")
	}
	b.release(hx)
	b.release(hx)
	segs := len(*b.segs.Load())
	tail := b.tail
	hz := b.acquire([]byte("rule-identity-new"))
	if len(*b.segs.Load()) != segs || b.tail != tail {
		t.Fatal("a freed blob's space was not reused by one of its size")
	}
	if !bytes.Equal(b.bytes(hy), y) || !bytes.Equal(b.bytes(hz), []byte("rule-identity-new")) {
		t.Fatal("reusing freed space overwrote a live blob")
	}
	big := bytes.Repeat([]byte{7}, blobSeg)
	hb := b.acquire(big)
	if !bytes.Equal(b.bytes(hb), big) {
		t.Fatal("a blob longer than a segment reads back wrong")
	}
	b.release(hb)
	if len(b.freeSegs) != 1 || (*b.segs.Load())[b.freeSegs[0]] != nil {
		t.Fatal("a released long blob kept its segment")
	}
}

func TestAnEmptiedStoreGivesBackMultiSegmentBacking(t *testing.T) {
	var st store
	var a, b Session
	for i := uint64(1); i <= segSize+1; i++ {
		st.ownPolicy(&a, qerPolicy{mbUL: i})
	}
	st.ownBlob(&b, bytes.Repeat([]byte{7}, blobSeg))
	st.drop(&a)
	if st.policies.dir.Load() != nil {
		t.Fatal("the empty policy table kept its segments")
	}
	st.drop(&b)
	if st.blobs.segs.Load() != nil {
		t.Fatal("the empty blob store kept its segments")
	}
	want := []byte("refill")
	h := st.ownBlob(&a, want)
	if got := st.blobs.bytes(h); !bytes.Equal(got, want) {
		t.Fatalf("refill: got %q, want %q", got, want)
	}
	st.drop(&a)
}

// TestASessionHoldsEachHandleOnceAndTrimGivesBackTheRest: own keeps one
// reference per handle per session, trim gives back what no record names,
// a snapshot holds trim off, and drop gives back everything.
func TestASessionHoldsEachHandleOnceAndTrimGivesBackTheRest(t *testing.T) {
	var st store
	s := &Session{rs: &records{}}
	q, _ := s.QERs().add(1, qer{id: 1})
	q.policy = st.ownPolicy(s, qerPolicy{mbUL: 10})
	if h := st.ownPolicy(s, qerPolicy{mbUL: 10}); h != q.policy || st.policies.entry(h).refs != 1 {
		t.Fatalf("a second own of one value took another reference (%d)", st.policies.entry(h).refs)
	}
	old := q.policy
	s.copies++
	q.policy = st.ownPolicy(s, qerPolicy{mbUL: 20})
	st.trim(s)
	if st.policies.entry(old).refs != 1 {
		t.Fatal("trim gave back a handle while a snapshot was outstanding")
	}
	s.copies--
	st.trim(s)
	if st.policies.entry(old).refs != 0 || st.policies.live != 1 || len(st.refsOf(s)) != 1 {
		t.Fatalf("trim left %d values and %d refs, want the one the QER names", st.policies.live, len(st.refsOf(s)))
	}
	st.drop(s)
	if st.policies.live != 0 || s.refs != 0 || st.blobs.live != 0 {
		t.Fatal("drop left a value behind")
	}
}

func TestAStoreBatchInternsOneOwnershipList(t *testing.T) {
	for _, n := range []int{16, 64} {
		var st store
		s := &Session{}
		st.ownPolicy(s, qerPolicy{mbUL: 1})
		before := st.blobs.tail
		st.beginRefs(s)
		for i := n; i > 0; i-- {
			policy := qerPolicy{mbUL: uint64(i)}
			st.ownPolicy(s, policy)
			st.ownPolicy(s, policy)
		}
		st.finishRefs()
		if got := st.blobs.tail - before; got != blobClass(4*uint32(n)) {
			t.Errorf("%d handles took %d bytes in ownership lists, want one list", n, got)
		}
		st.drop(s)
		if st.policies.live != 0 || st.blobs.live != 0 {
			t.Fatalf("%d handles: drop left %d policies and %d blobs", n, st.policies.live, st.blobs.live)
		}
	}
}

// TestAClaimIsFoundByItsWholeKeyAndTheIndexShrinks: a claim is found by its
// bytes, interned or not, with its owner; a slot whose fingerprint matches but
// whose key differs is not the claim; claims given up are not found, and an
// emptied index gives its slots and the keys back.
func TestAClaimIsFoundByItsWholeKeyAndTheIndexShrinks(t *testing.T) {
	var st store
	const n = 3000
	keys := make([]uint32, n)
	for i := range keys {
		keys[i] = st.blobs.acquire(fmt.Appendf(nil, "\x01rule-%d", i))
		st.claim(keys[i], uint64(i+1))
		st.blobs.release(keys[i])
	}
	for i, h := range keys {
		at := st.claimNamed(fmt.Sprintf("\x01rule-%d", i))
		if at < 0 || at != st.claimOf(h) || st.claims[at].owner != uint64(i+1) {
			t.Fatalf("claim %d is not found with its owner (slot %d)", i, at)
		}
	}
	// A forged slot with an unclaimed key's fingerprint and key 1's blob: the
	// bytes decide, so the unclaimed key is not found in it.
	absent := "\x01rule-absent"
	forged := claimSlot{hash: uint32(maphash.String(st.blobs.seed, absent)), key: keys[1], owner: 99}
	st.claimed++
	st.claims = openInsert(st.claims, st.claimed, forged)
	if at := st.claimNamed(absent); at >= 0 {
		t.Fatalf("a fingerprint match with other bytes was taken for the claim (owner %d)", st.claims[at].owner)
	}
	for i := range st.claims {
		if st.claims[i] == forged {
			st.claimed--
			st.claims = openDelete(st.claims, st.claimed, uint32(i))
			break
		}
	}
	for i := 0; i < n; i += 2 {
		st.unclaim(st.claimOf(keys[i]))
	}
	for i := range n {
		at := st.claimNamed(fmt.Sprintf("\x01rule-%d", i))
		if (at >= 0) != (i%2 == 1) {
			t.Fatalf("claim %d found=%v after every even claim went", i, at >= 0)
		}
	}
	for i := 1; i < n; i += 2 {
		st.unclaim(st.claimOf(keys[i]))
	}
	if st.claimed != 0 || len(st.claims) > 16 || st.blobs.live != 0 {
		t.Fatalf("an emptied index holds %d claims in %d slots and %d keys", st.claimed, len(st.claims), st.blobs.live)
	}
}

// TestASessionListsItsClaimsUntilItGivesThemUp: the claims a session lists
// survive trim (they are no record's), forgetClaims takes off only the ones
// given up, and dropClaims ends the rest and empties the list.
func TestASessionListsItsClaimsUntilItGivesThemUp(t *testing.T) {
	var st store
	s := &Session{LocalSEID: 7, rs: &records{}}
	q, _ := s.QERs().add(1, qer{id: 1})
	q.policy = st.ownPolicy(s, qerPolicy{mbUL: 10})
	var hs []uint32
	for _, k := range []string{"\x01a", "\x01b", "\x02c"} {
		h := st.blobs.acquire([]byte(k))
		st.claim(h, s.LocalSEID)
		st.blobs.release(h)
		hs = append(hs, h)
	}
	st.addClaims(s, hs)
	st.trim(s)
	if got := st.claimsOf(s); len(got) != 3 || st.claimed != 3 {
		t.Fatalf("trim left %d of 3 listed claims, %d claimed", len(got), st.claimed)
	}
	st.unclaim(st.claimOf(hs[1]))
	st.forgetClaims(s, hs[1:2])
	if got := st.claimsOf(s); len(got) != 2 || got[0]&handleMask != hs[0] || got[1]&handleMask != hs[2] {
		t.Fatalf("forgetClaims left %x, want the claims on %d and %d", got, hs[0], hs[2])
	}
	st.dropClaims(s)
	if st.claimed != 0 || len(st.claimsOf(s)) != 0 || len(st.refsOf(s)) != 1 {
		t.Fatalf("dropClaims left %d claims and %d listed, %d refs", st.claimed, len(st.claimsOf(s)), len(st.refsOf(s)))
	}
	st.drop(s)
	if st.blobs.live != 0 || st.policies.live != 0 {
		t.Fatal("the session's end left a blob or a value behind")
	}
}

// TestTheFTEIDIndexComparesWholeKeysAndShrinks: keys that differ only in
// endpoint, family or address are distinct claims with their own owner,
// context and direction; removed keys are gone, and an emptied index shrinks.
func TestTheFTEIDIndexComparesWholeKeysAndShrinks(t *testing.T) {
	var x fteidIndex
	v4, v6 := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")
	key := func(i int) fteidKey {
		return fteidKeyOf(uint32(1+i%3), []uint8{0, 4, 6}[i%3], uint32(1+i/3), v4, v6)
	}
	const n = 3000
	for i := range n {
		x.put(key(i), fteidOwner{seid: uint64(i + 1), ctx: uint32(i), down: i%2 == 1})
	}
	for i := range n {
		o, ok := x.get(key(i))
		if !ok || o != (fteidOwner{seid: uint64(i + 1), ctx: uint32(i), down: i%2 == 1}) {
			t.Fatalf("key %d reads %+v, %v", i, o, ok)
		}
	}
	for i := 0; i < n; i += 2 {
		x.remove(key(i))
	}
	for i := range n {
		if _, ok := x.get(key(i)); ok != (i%2 == 1) {
			t.Fatalf("key %d claimed=%v after every even key went", i, ok)
		}
	}
	for i := 1; i < n; i += 2 {
		x.remove(key(i))
	}
	if x.live != 0 || len(x.slots) > 16 {
		t.Fatalf("an emptied index holds %d keys in %d slots", x.live, len(x.slots))
	}
}

// TestASessionSetPagesItsMembersInOrder: a set counts its members once, pages
// them in slot order across word boundaries, resumes where a page stopped,
// and a union adds only what is missing.
func TestASessionSetPagesItsMembersInOrder(t *testing.T) {
	var a, b sessionSet
	want := []uint32{1, 63, 64, 65, 127, 128, 1000}
	for _, slot := range want {
		a.add(slot)
		a.add(slot)
	}
	if a.len() != len(want) || !a.has(64) || a.has(2) || a.has(5000) {
		t.Fatalf("a set of %d holds %d", len(want), a.len())
	}
	var got []uint32
	for from := uint32(0); ; {
		got, from = a.page(got, from, 3)
		if from == 0 {
			break
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("pages gave %v, want %v", got, want)
	}
	b.add(64)
	b.add(7)
	b.union(&a)
	a.remove(64)
	a.remove(64)
	if b.len() != len(want)+1 || a.len() != len(want)-1 || a.has(64) {
		t.Fatalf("union holds %d, want %d; removal left %d", b.len(), len(want)+1, a.len())
	}
	b.clear()
	if b.len() != 0 || b.has(7) {
		t.Fatal("a cleared set kept a member")
	}
}
