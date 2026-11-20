// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"testing"

	"github.com/krsna1729/upf/internal/scaletest"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// countedEstablishment is the session n4bench establishes at scale
// (docs/design.md, "upfd's own memory"): establishment's two PDRs, two FARs
// and QER, and a volume-quota URR on the uplink PDR.
func countedEstablishment(cpSEID uint64, ueIP string) *message.SessionEstablishmentRequest {
	req := establishment(cpSEID, ueIP)
	children, err := req.CreatePDR[0].CreatePDR()
	if err != nil {
		panic(err)
	}
	req.CreatePDR[0] = ie.NewCreatePDR(append(children, ie.NewURRID(7))...)
	req.CreateURR = []*ie.IE{ie.NewCreateURR(ie.NewURRID(7), ie.NewMeasurementMethod(0, 1, 0),
		ie.NewReportingTriggers(0, 1), ie.NewVolumeQuota(1, 1<<50, 0, 0))}
	return req
}

// TestASessionHoldsAtMostItsBytes: the heap a session leaves in use is what
// bounds the sessions a pod holds (cmd/upfd's admission refuses past a share
// of the limit), so it is pinned here, per session, over enough sessions that
// the compiler's own maps are amortised.
func TestASessionHoldsAtMostItsBytes(t *testing.T) {
	const n = 20000
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	var c *Compiler
	per := scaletest.HeapPerItem(t, n, func(n int) {
		c = New(testConfig(), &discardApplier{}, quietLogger())
		for i := range n {
			ue := fmt.Sprintf("10.%d.%d.%d", 1+i>>16, i>>8&0xff, i&0xff)
			if got := cause(t, c.Establish(countedEstablishment(uint64(0x10000+i), ue))); got != ie.CauseRequestAccepted {
				t.Fatalf("establishment %d answered cause %d", i, got)
			}
		}
	})
	runtime.ReadMemStats(&after)
	live := float64(int64(after.HeapAlloc)-int64(before.HeapAlloc)) / n
	t.Logf("%.1f B of live objects per session", live)
	// 2,550 B before the session-memory series (perf/upfd-session-memory):
	// rare fields behind pointers, interned shared provisioning, walked
	// caches. 1,511 B after it; 1,403 B with pointer-free records
	// (store.go); 1,395 B with rule identities as store blobs.
	if live > 1465 {
		t.Errorf("a session retains %.0f B of live objects, want at most 1465", live)
	}
	// Before the layout changes: 4,543-4,665 B. After rule maps, PDR
	// derived fields, pending state and URR padding: 3,050-3,224 B. After
	// the session-memory series: 2,022-2,109 B. Pointer-free records:
	// 1,739 B. Rule identities as store blobs: 1,660 B.
	if per > 1745 {
		t.Errorf("a session holds %.0f B of heap, want at most 1745", per)
	}
	runtime.KeepAlive(c)
}

// footprint is what build leaves live, per item, after a GC: heap bytes in
// live objects, heap bytes the collector must scan for pointers
// (/gc/scan/heap:bytes) and heap objects (/gc/heap/objects:objects).
type footprint struct{ live, scan, objects float64 }

func measureFootprint(n int, build func()) footprint {
	samples := []metrics.Sample{{Name: "/gc/scan/heap:bytes"}, {Name: "/gc/heap/objects:objects"}}
	read := func() (uint64, uint64, uint64) {
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		metrics.Read(samples)
		return m.HeapAlloc, samples[0].Value.Uint64(), samples[1].Value.Uint64()
	}
	defer debug.SetGCPercent(debug.SetGCPercent(100))
	a0, s0, o0 := read()
	build()
	a1, s1, o1 := read()
	per := func(a, b uint64) float64 { return float64(int64(b)-int64(a)) / float64(n) }
	return footprint{live: per(a0, a1), scan: per(s0, s1), objects: per(o0, o1)}
}

// establishCounted establishes n counted sessions on c and returns their SEIDs.
func establishCounted(t *testing.T, c *Compiler, n int) []uint64 {
	seids := make([]uint64, 0, n)
	for i := range n {
		ue := fmt.Sprintf("10.%d.%d.%d", 1+i>>16, i>>8&0xff, i&0xff)
		resp, ok := c.Establish(countedEstablishment(uint64(0x10000+i), ue)).(*message.SessionEstablishmentResponse)
		if !ok || cause(t, resp) != ie.CauseRequestAccepted {
			t.Fatalf("establishment %d was not accepted", i)
		}
		seids = append(seids, upFSEID(t, resp))
	}
	return seids
}

// TestASessionIsFewObjectsTheCollectorBarelyScans: the collector's work is
// the bytes it scans and the objects it marks, so a million sessions cost what
// their pointer-holding objects cost. 894.5 B scanned and 17.03 objects per
// session before the records held handles instead of pointers (store.go);
// 566.7 B and 14.03 after; 431.3 B and 11.03 once rule identities and their
// owners left Go strings and maps for store blobs and a noscan index.
func TestASessionIsFewObjectsTheCollectorBarelyScans(t *testing.T) {
	const n = 20000
	var c *Compiler
	f := measureFootprint(n, func() {
		c = New(testConfig(), &discardApplier{}, quietLogger())
		establishCounted(t, c, n)
	})
	t.Logf("live %.1f B, scanned %.1f B, %.2f objects per session", f.live, f.scan, f.objects)
	if f.scan > 453 {
		t.Errorf("the collector scans %.0f B per session, want at most 453", f.scan)
	}
	if f.objects > 11.6 {
		t.Errorf("a session is %.2f heap objects, want at most 11.6", f.objects)
	}
	runtime.KeepAlive(c)
}

// TestDeletedSessionsGiveTheStoreBack: deleting every session returns every
// table entry and blob it held, and establishing them again costs what it
// cost the first time -- the tables reuse what was freed rather than grow.
func TestDeletedSessionsGiveTheStoreBack(t *testing.T) {
	const n = 5000
	c := New(testConfig(), &discardApplier{}, quietLogger())
	live := func() [7]int {
		c.mu.Lock()
		defer c.mu.Unlock()
		st := &c.st
		return [7]int{st.exts.live, st.farExts.live, st.policies.live, st.limits.live, st.ends.live, st.sdfs.live, st.blobs.live}
	}
	segments := func() int {
		c.mu.Lock()
		defer c.mu.Unlock()
		if p := c.st.blobs.segs.Load(); p != nil {
			return len(*p)
		}
		return 0
	}
	var first [7]int
	var firstSegs int
	for round := range 3 {
		seids := establishCounted(t, c, n)
		if round == 0 {
			first, firstSegs = live(), segments()
		} else if got := live(); got != first || segments() != firstSegs {
			t.Errorf("round %d holds %v entries in %d segments, the first held %v in %d", round, got, segments(), first, firstSegs)
		}
		for i, seid := range seids {
			if got := cause(t, c.Delete(message.NewSessionDeletionRequest(0, 0, seid, uint32(i+2), 0))); got != ie.CauseRequestAccepted {
				t.Fatalf("deleting session %d answered cause %d", i, got)
			}
		}
		if got := live(); got != [7]int{} || c.st.claimed != 0 {
			t.Fatalf("round %d: deleted sessions left %v entries (ext, farExt, policy, limits, end, sdf, blob) and %d claims", round, got, c.st.claimed)
		}
	}
}
