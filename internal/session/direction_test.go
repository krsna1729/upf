// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
)

func TestPDRDirectionFollowsUEAddressSide(t *testing.T) {
	for _, tc := range []struct {
		name      string
		source    uint8
		hasUEIP   bool
		ueIPDst   bool
		sdfs      []*sdfFilter
		wantDown  bool
		wantError bool
	}{
		{name: "Access remains uplink with destination address", source: ie.SrcInterfaceAccess, hasUEIP: true, ueIPDst: true},
		{name: "Core source address is uplink", source: ie.SrcInterfaceCore, hasUEIP: true},
		{name: "Core destination address is downlink", source: ie.SrcInterfaceCore, hasUEIP: true, ueIPDst: true, wantDown: true},
		{name: "5G-VN source address is uplink", source: ie.SrcInterface5GVNInternal, hasUEIP: true},
		{name: "5G-VN destination address is downlink", source: ie.SrcInterface5GVNInternal, hasUEIP: true, ueIPDst: true, wantDown: true},
		{name: "assigned source implies uplink", source: ie.SrcInterfaceCore, sdfs: []*sdfFilter{{srcAssigned: true}}},
		{name: "assigned destination implies downlink", source: ie.SrcInterfaceCore, sdfs: []*sdfFilter{{dstAssigned: true}}, wantDown: true},
		{name: "conflicting assigned sides are refused", source: ie.SrcInterfaceCore, sdfs: []*sdfFilter{{srcAssigned: true}, {dstAssigned: true}}, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := pdrDownlink(tc.source, tc.hasUEIP, tc.ueIPDst, tc.sdfs)
			if (err != nil) != tc.wantError {
				t.Fatalf("pdrDownlink() error = %v, wantError %v", err, tc.wantError)
			}
			if err == nil && got != tc.wantDown {
				t.Errorf("pdrDownlink() = %v, want %v", got, tc.wantDown)
			}
		})
	}
}

func TestCoreUplinkPDRMatchesUEAsSourceAndSelectsUplinkChain(t *testing.T) {
	p := &pdr{
		srcIfc:  ie.SrcInterfaceCore,
		down:    false,
		hasUEIP: true,
		ueIP:    netip.MustParseAddr("10.45.0.2"),
	}
	for _, tc := range []struct {
		field Field
		want  []byte
		match bool
	}{
		{field: SrcIP, want: []byte{10, 45, 0, 2}, match: true},
		{field: DstIP, match: false},
	} {
		got, matches, err := p.matchValue(tc.field)
		if err != nil {
			t.Fatalf("matchValue(%s): %v", tc.field, err)
		}
		if matches != tc.match {
			t.Errorf("matchValue(%s) constrained = %v, want %v", tc.field, matches, tc.match)
		}
		if tc.match && string(got.value) != string(tc.want) {
			t.Errorf("matchValue(%s) value = %v, want %v", tc.field, got.value, tc.want)
		}
	}
	c := &Compiler{cfg: Config{Up: Direction{PDRTable: "pdr_ul"}, Down: Direction{PDRTable: "pdr_dl"}}}
	if got := c.direction(p).PDRTable; got != "pdr_ul" {
		t.Errorf("Core-source uplink selected table %q, want pdr_ul", got)
	}
}

func TestPDRResultCarriesResolvedRouteDomain(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    *pdr
		size int
	}{
		{name: "uplink", p: &pdr{domain: 7}, size: 20},
		{name: "downlink", p: &pdr{down: true, domain: 9}, size: 24},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := pdrResult(tc.p)
			if len(got) != tc.size {
				t.Fatalf("result size = %d, want %d", len(got), tc.size)
			}
			if domain := binary.BigEndian.Uint32(got[resultRouteDomain:]); domain != tc.p.domain {
				t.Errorf("result route_domain = %d, want %d", domain, tc.p.domain)
			}
		})
	}
}
