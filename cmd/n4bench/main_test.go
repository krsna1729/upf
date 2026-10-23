// SPDX-License-Identifier: BSD-3-Clause

package main

import "testing"

// What a real SMF does with a pinned F-TEID: it makes the value unique itself,
// one per session. A bench that pins one value for a whole phase measures the
// UPF refusing all but the first, and reports it as if the path were at fault.
func TestSessionParamsPinOneValuePerSession(t *testing.T) {
	const base = 0x0a2d0000 // 10.45.0.0
	params := sessionParams(4, 0x900000, base, []string{"10.20.30.2"}, "192.0.2.1")
	if len(params) != 4 {
		t.Fatalf("asked for 4 sessions, got %d", len(params))
	}
	seen := map[uint32]bool{}
	for i, p := range params {
		if want := uint32(0x900000 + i); p.FTEID != want {
			t.Errorf("session %d pins %#x, want %#x", i, p.FTEID, want)
		}
		if seen[p.FTEID] {
			t.Errorf("session %d reuses the pinned %#x", i, p.FTEID)
		}
		seen[p.FTEID] = true
		if want := uint32(base + i); p.UEIP != offsetAddr(want, 0) {
			t.Errorf("session %d's UE address is %s, want %s", i, p.UEIP, offsetAddr(want, 0))
		}
		if p.CPSEID != uint64(0x1000+i) || p.TEID != uint32(0x100000+i) {
			t.Errorf("session %d: seids are %#x/%#x, want the per-index pair",
				i, p.CPSEID, p.TEID)
		}
		if p.GnBIP != "10.20.30.2" || p.N3IP != "192.0.2.1" {
			t.Errorf("session %d: addresses are %s/%s", i, p.GnBIP, p.N3IP)
		}
	}

	// Zero pins nothing: every session asks the UPF to choose.
	for i, p := range sessionParams(4, 0, base, []string{"10.20.30.2"}, "192.0.2.1") {
		if p.FTEID != 0 {
			t.Errorf("with -fteid 0, session %d pins %#x", i, p.FTEID)
		}
	}

	// A -gnb list alternates: session i takes the (i mod n)-th address.
	gnbs := []string{"10.20.30.2", "2001:db8:20::2"}
	for i, p := range sessionParams(4, 0, base, gnbs, "192.0.2.1") {
		if p.GnBIP != gnbs[i%2] {
			t.Errorf("session %d's gNB is %s, want %s", i, p.GnBIP, gnbs[i%2])
		}
	}
}
