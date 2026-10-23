// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"bytes"
	"net"
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// An SMF copies the PCF's Flow Description -- always the downlink form, "from
// the remote side to the UE" -- into the PDI of both the uplink and the
// downlink PDR, and the UP function swaps source and destination, address and
// port, for a PDR whose Source Interface is ACCESS (TS 29.244 5.2.1A.2A).
// Open5GS's UPF does the same (lib/pfcp/handler.c, ogs_ipfw_rule_swap).
const dlForm = "permit out udp from 8.8.8.8/32 53 to assigned"

func uplinkWithDLForm(sdf string) *message.SessionEstablishmentRequest {
	return message.NewSessionEstablishmentRequest(0, 0, 0x7a01, 1, 0,
		ie.NewFSEID(0x7a01, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, 0x7a, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0),
				ie.NewSDFFilter(sdf, "", "", "", 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
	)
}

func TestAnUplinkPDRKeysTheWildcardRuleOnTheSwappedFilter(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	if got := cause(t, c.Establish(uplinkWithDLForm(dlForm))); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	var up *rule
	for _, r := range rules(rec.last()) {
		if r.change.Resource == "pdr_ul/rules" {
			r := r
			up = &r
		}
	}
	if up == nil {
		t.Fatal("no uplink rule written")
	}
	// The uplink table's fields: source address, destination address,
	// protocol, source port, destination port (testConfig).
	if got := up.value(0); !bytes.Equal(got, []byte{10, 45, 0, 6}) {
		t.Errorf("the source address is %v, want the UE's", got)
	}
	if got, m := up.value(1), up.mask(1); !bytes.Equal(got, []byte{8, 8, 8, 8}) || !bytes.Equal(m, []byte{255, 255, 255, 255}) {
		t.Errorf("the destination address is %v/%v, want 8.8.8.8/32", got, m)
	}
	if got := up.value(4); !bytes.Equal(got, []byte{0, 53}) {
		t.Errorf("the destination port is %v, want 53", got)
	}
	if m := up.mask(3); !bytes.Equal(m, []byte{0, 0}) {
		t.Errorf("the source port is constrained (mask %v), but the filter names none on the UE's side", m)
	}
}
