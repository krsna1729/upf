// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"fmt"
	"runtime"
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
	// caches. 1,511 B after it.
	if live > 1600 {
		t.Errorf("a session retains %.0f B of live objects, want at most 1600", live)
	}
	// Before the layout changes: 4,543-4,665 B. After rule maps, PDR
	// derived fields, pending state and URR padding: 3,050-3,224 B. After
	// the session-memory series: 2,022-2,109 B.
	if per > 2300 {
		t.Errorf("a session holds %.0f B of heap, want at most 2300", per)
	}
	runtime.KeepAlive(c)
}
