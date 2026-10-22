// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"bytes"
	"net"
	"net/netip"
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/routing"
)

// TestULCLOneSessionBranchesByDestination is the ULCL shape in the compiler's
// terms: one session and one tunnel, two uplink PDRs that differ only in the
// destination they select, and two FARs -- the local data network and a tunnel
// out of the instance (N9). The rules must land in one table with one action
// each, and the actions must name the two egresses; a compiler that let the
// second PDR inherit the first's action would send both destinations out of
// one exit.
func TestULCLOneSessionBranchesByDestination(t *testing.T) {
	domains, err := routing.New([]routing.Interface{{
		Instance: "internet", Domain: 0, NextHop: 1,
		Pool: []netip.Prefix{netip.MustParsePrefix("10.45.0.0/16")},
		Hops: map[routing.Egress]uint32{
			{DestIfc: ie.DstInterfaceCore}:               1,
			{DestIfc: ie.DstInterfaceCore, Tunnel: true}: 3,
		},
	}}, 4)
	if err != nil {
		t.Fatalf("the deployment was refused: %v", err)
	}
	cfg := testConfig()
	cfg.Instances = domains
	cfg.FTEIDEndpoints = append(cfg.FTEIDEndpoints, FTEIDEndpoint{
		ID: 2, ReferencePoint: "n9", TransportRouteDomain: 2,
		SourceInterface: ie.SrcInterfaceCore, Instance: "internet",
		IPv4: netip.MustParseAddr("192.0.2.9"),
	})
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())

	req := message.NewSessionEstablishmentRequest(0, 0, 0x5570, 1, 0,
		ie.NewFSEID(0x5570, nil, nil),
		ie.NewCreatePDR(
			ie.NewPDRID(1), ie.NewPrecedence(20),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewNetworkInstance("internet"),
				ie.NewFTEID(0x01, 0x11223348, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.8", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any 53 to assigned", "", "", "", 0),
			),
			ie.NewFARID(1),
		),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
		ie.NewCreatePDR(
			ie.NewPDRID(2), ie.NewPrecedence(10),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewNetworkInstance("internet"),
				ie.NewUEIPAddress(0x02, "10.45.0.8", "", 0, 0),
				ie.NewSDFFilter("permit out udp from 10.46.0.2 53 to assigned", "", "", "", 0),
			),
			ie.NewFARID(2),
		),
		ie.NewCreateFAR(ie.NewFARID(2), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceCore),
				ie.NewOuterHeaderCreation(0x0100, 0x55667788, "192.0.2.9", "", 0, 0, 0),
			)),
		ie.NewCreatePDR(
			ie.NewPDRID(3), ie.NewPrecedence(100),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewNetworkInstance("internet"),
				ie.NewUEIPAddress(0x06, "10.45.0.8", "", 0, 0),
				ie.NewSDFFilter("permit out ip from any to assigned", "", "", "", 0),
			),
			ie.NewFARID(3),
		),
		ie.NewCreateFAR(ie.NewFARID(3), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceAccess),
				ie.NewOuterHeaderCreation(0x0100, 0x55667788, "192.0.2.9", "", 0, 0, 0),
			)),
	)
	if got := cause(t, c.Establish(req)); got != ie.CauseRequestAccepted {
		t.Fatalf("a ULCL session answered cause %d, want accepted", got)
	}

	var ulRules []rule
	for _, r := range rules(rec.last()) {
		if r.change.Resource == "pdr_ul/rules" {
			ulRules = append(ulRules, r)
		}
	}
	if len(ulRules) != 2 {
		t.Fatalf("the uplink table got %d rules for two PDRs, want two", len(ulRules))
	}
	hops := map[uint32]uint32{}
	for _, r := range ulRules {
		hops[r.actionID()] = nextHop(t, rec.last(), r.actionID())
	}
	want := map[uint32]bool{1: true, 3: true}
	for _, hop := range hops {
		if !want[hop] {
			t.Errorf("an uplink PDR names hop %d, want one action per exit (1 and 3): %v", hop, hops)
		}
		delete(want, hop)
	}
	if len(want) != 0 {
		t.Errorf("the two PDRs do not name both exits: %v", hops)
	}
	// The second PDR's destination is the address its SDF names; the first's
	// leaves the destination unconstrained and matches by port alone.
	var general, specific int64
	foundDst := false
	for _, r := range ulRules {
		if bytes.Equal(r.value(1), []byte{10, 46, 0, 2}) {
			foundDst = true
			specific = r.priority()
			if got := r.mask(1); !bytes.Equal(got, []byte{0xff, 0xff, 0xff, 0xff}) {
				t.Errorf("the N9 rule's destination mask is %v, want a /32", got)
			}
		} else if bytes.Equal(r.mask(1), []byte{0, 0, 0, 0}) {
			general = r.priority()
		}
	}
	if !foundDst {
		t.Error("no uplink rule selects the N9 destination 10.46.0.2")
	}
	if specific <= general {
		t.Errorf("the specific rule's priority is %d and the general rule's %d; the specific destination must win where both match",
			specific, general)
	}
}
