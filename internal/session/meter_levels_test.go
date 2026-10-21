// SPDX-License-Identifier: BSD-3-Clause
package session

import (
	"net"
	"strings"
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// twoLevelEstablishment is two uplink PDRs, each naming its own flow QER and
// one QER they share: the QER both PDRs name is the session's shared one
// (sharedRateQER), so each PDR's own meter is its flow's and the second id is
// the session's.
func twoLevelEstablishment(cpSEID uint64, ueIP string, fteid uint32) *message.SessionEstablishmentRequest {
	return message.NewSessionEstablishmentRequest(0, 0, cpSEID, 1, 0,
		ie.NewFSEID(cpSEID, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, fteid, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, ueIP, "", 0, 0),
				ie.NewSDFFilter("permit out udp from any 1000 to any", "", "", "", 0)),
			ie.NewFARID(1), ie.NewQERID(1), ie.NewQERID(9)),
		ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(20),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, fteid, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, ueIP, "", 0, 0),
				ie.NewSDFFilter("permit out udp from any 2000 to any", "", "", "", 0)),
			ie.NewFARID(1), ie.NewQERID(2), ie.NewQERID(9)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
		ie.NewCreateQER(ie.NewQERID(1),
			ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen), ie.NewMBR(1000, 2000)),
		ie.NewCreateQER(ie.NewQERID(2),
			ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen), ie.NewMBR(3000, 4000)),
		ie.NewCreateQER(ie.NewQERID(9),
			ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen), ie.NewMBR(9000, 9000)),
	)
}

// TestTheTwoLevelActionNamesTheFlowsMeterThenTheSessions: every rule's result
// names the PDR's own rate-bearing QER first and the session's shared one
// after it, so the Meter stops a red packet at the flow's bucket before the
// session's is charged. The second slot is one id across both PDRs (the shared
// QER) and the first differs (each PDR's flow), which is the order the design
// asks for seen from the rules alone.
func TestTheTwoLevelActionNamesTheFlowsMeterThenTheSessions(t *testing.T) {
	cfg := testConfig()
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())
	resp := c.Establish(twoLevelEstablishment(0x7777, "10.45.0.9", 0x44444444)).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}

	var flows, shared []uint32
	for _, r := range rules(rec.last()) {
		if !strings.HasPrefix(r.change.Resource, rulesRes(cfg.Up)) {
			continue
		}
		ids := r.meterIDs()
		if ids[0] == 0 {
			t.Errorf("the rule carries no flow meter: %v", ids)
		}
		if r.nextHop() == 0 {
			t.Errorf("the rule's next hop went missing: %v", r.change.Value)
		}
		flows = append(flows, ids[0])
		shared = append(shared, ids[1])
	}
	if len(flows) != 2 {
		t.Fatalf("the session wrote %d rules, want one per PDR", len(flows))
	}
	if flows[0] == 0 || flows[1] == 0 || flows[0] == flows[1] {
		t.Errorf("the flows' meters are %v, want two different non-zero ids", flows)
	}
	if shared[0] == 0 || shared[0] != shared[1] {
		t.Errorf("the sessions' meters are %v, want one shared non-zero id", shared)
	}
	if flows[0] == shared[0] || flows[1] == shared[1] {
		t.Errorf("a PDR's flow meter (%v) is its session's (%v)", flows, shared)
	}
}
