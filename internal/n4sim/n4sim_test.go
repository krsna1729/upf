// SPDX-License-Identifier: BSD-3-Clause

package n4sim

import (
	"net"
	"testing"
)

// The outer header's family follows the gNB address: an IPv6 gNB is an
// IPv6 tunnel (description 0x0200), not an IPv4 one with no address.
func TestOuterHeaderCreationFollowsTheGNBFamily(t *testing.T) {
	for _, tc := range []struct {
		gnb       string
		v4, v6    bool
		wantField string
	}{
		{"10.20.30.2", true, false, "10.20.30.2"},
		{"2001:db8:20::2", false, true, "2001:db8:20::2"},
	} {
		f, err := outerHeaderCreation(0x100000, tc.gnb).OuterHeaderCreation()
		if err != nil {
			t.Fatalf("%s: %v", tc.gnb, err)
		}
		if f.HasIPv4() != tc.v4 || f.HasIPv6() != tc.v6 || f.TEID != 0x100000 {
			t.Errorf("%s: v4 %v v6 %v teid %#x", tc.gnb, f.HasIPv4(), f.HasIPv6(), f.TEID)
		}
		got := f.IPv4Address
		if tc.v6 {
			got = f.IPv6Address
		}
		if !got.Equal(net.ParseIP(tc.wantField)) {
			t.Errorf("%s: address %v", tc.gnb, got)
		}
	}
}

// A handover asks for an End Marker: SNDEM on the message.
func TestHandoverCarriesSNDEM(t *testing.T) {
	m := Handover(3, 0x99, 2, 0x110000, "10.20.30.2")
	if m.PFCPSMReqFlags == nil || !m.PFCPSMReqFlags.HasSNDEM() {
		t.Fatalf("no SNDEM in the handover: %+v", m)
	}
}
