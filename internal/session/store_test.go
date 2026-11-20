// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"bytes"
	"net/netip"
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

// TestASessionHoldsEachHandleOnceAndTrimGivesBackTheRest: own keeps one
// reference per handle per session, trim gives back what no record names,
// a snapshot holds trim off, and drop gives back everything.
func TestASessionHoldsEachHandleOnceAndTrimGivesBackTheRest(t *testing.T) {
	var st store
	s := &Session{}
	q := &qer{id: 1}
	s.QERs.set(1, q)
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
