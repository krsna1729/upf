// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"net"
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// A bidirectional SDF filter (TS 29.244 5.2.1A.3) is provisioned by ID: one
// PDR carries the flow description and the SDF Filter ID, the PDR of the other
// direction carries the ID alone. Open5GS builds every bidirectional flow so:
// the downlink PDR has both, the uplink PDR only the ID.
func bidirectional(cp uint64, downlinkFilter, uplinkFilter *ie.IE) *message.SessionEstablishmentRequest {
	return message.NewSessionEstablishmentRequest(0, 0, cp, 1, 0,
		ie.NewNodeID("", "", "smf"),
		ie.NewFSEID(cp, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, 0x7c, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0),
				uplinkFilter),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw)),
		ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0),
				downlinkFilter),
			ie.NewFARID(2)),
		ie.NewCreateFAR(ie.NewFARID(2), ie.NewApplyAction(applyForw)),
	)
}

func TestAnUplinkPDRThatNamesABidirectionalFilterByIDGetsItsFlowDescription(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	got := cause(t, c.Establish(bidirectional(0x7c01,
		ie.NewSDFFilter(udp53, "", "", "", 7), // the downlink PDR: description and ID
		ie.NewSDFFilter("", "", "", "", 7))))  // the uplink PDR: the ID alone
	if got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d, want it accepted (Open5GS's shape)", got)
	}
	written, _ := ulRules(rec.last())
	if len(written) != 1 {
		t.Fatalf("%d uplink rules, want 1", len(written))
	}
	// The uplink PDR reads the same description swapped (5.2.1A.2A): the
	// description's source port 53 is the far end's port in the uplink packet.
	if port := written[0].value(4); len(port) != 2 || port[0] != 0 || port[1] != 53 {
		t.Errorf("the uplink rule's destination port is %v, want 53", port)
	}
	if proto := written[0].value(2); len(proto) != 1 || proto[0] != 17 {
		t.Errorf("the uplink rule's protocol is %v, want udp", proto)
	}
}

func TestAnIDNoPDRDefinesIsRefused(t *testing.T) {
	c := New(testConfig(), &recorder{}, quietLogger())
	got := cause(t, c.Establish(bidirectional(0x7c02,
		ie.NewSDFFilter(udp53, "", "", "", 7),
		ie.NewSDFFilter("", "", "", "", 8))))
	if got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("cause %d, want a rule failure: SDF Filter ID 8 is defined nowhere", got)
	}
}

func TestAMatchTheUPDoesNotImplementIsRefusedNotDropped(t *testing.T) {
	// Dropping any of these makes the rule match what the IE was there to
	// exclude. An SDF filter's ToS, SPI and flow label are the same.
	for name, extra := range map[string]*ie.IE{
		"ToS":                  ie.NewSDFFilter(udp53, "ab", "", "", 0),
		"SPI":                  ie.NewSDFFilter(udp53, "", "abcd", "", 0),
		"flow label":           ie.NewSDFFilter(udp53, "", "", "abc", 0),
		"application id":       ie.New(ie.ApplicationID, []byte("app")),
		"traffic endpoint id":  ie.New(ie.TrafficEndpointID, []byte{1}),
		"ethernet filter":      ie.New(ie.EthernetPacketFilter, nil),
		"ethernet pdu session": ie.New(ie.EthernetPDUSessionInformation, []byte{1}),
		"framed route":         ie.New(ie.FramedRoute, []byte("10.0.0.0/8")),
		"framed routing":       ie.New(ie.FramedRouting, []byte{0, 0, 0, 1}),
		"framed ipv6 route":    ie.New(ie.FramedIPv6Route, []byte("2001:db8::/32")),
		"multicast":            ie.New(ie.IPMulticastAddressingInfo, nil),
	} {
		t.Run(name, func(t *testing.T) {
			c := New(testConfig(), &recorder{}, quietLogger())
			req := uplinkPDI(0x7c10, []string{udp53}, nil)
			req.CreatePDR[0] = ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100),
				ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
					ie.NewFTEID(0x01, 0x7c, net.ParseIP("192.0.2.1"), nil, 0),
					ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0),
					extra),
				ie.NewFARID(1))
			if got := cause(t, c.Establish(req)); got != ie.CauseRuleCreationModificationFailure {
				t.Errorf("cause %d, want a rule failure", got)
			}
		})
	}
}
