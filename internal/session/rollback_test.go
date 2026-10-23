// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"net"
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// A modification the merge refuses must leave the session as the SMF last saw
// it. Left half-applied -- the refused PDR in the model, naming a URR the
// session lacks -- it failed every later message of the session the same way:
// the SMF's retry, and the follow-up it sends after any refusal.

func namesUnknownURR(seq uint32, seid uint64, extra ...*ie.IE) *message.SessionModificationRequest {
	ies := append([]*ie.IE{
		ie.NewUpdatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, 0x1000, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.2", "", 0, 0)),
			ie.NewFARID(1), ie.NewURRID(55)),
	}, extra...)
	return message.NewSessionModificationRequest(0, 0, seid, seq, 0, ies...)
}

func TestARefusedModificationLeavesTheSessionAsItWas(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(urrEstablishment(0x3071, 7, quotaURR(7, 1<<30))).(*message.SessionEstablishmentResponse)
	seid := upFSEID(t, resp)

	if got := cause(t, c.Modify(namesUnknownURR(2, seid))); got != ie.CauseRuleCreationModificationFailure {
		t.Fatalf("a PDR naming URR 55 answered cause %d, want a rule failure", got)
	}
	if ids := sessionOf(t, c, seid).PDRs[1].urrIDs; len(ids) != 1 || ids[0] != 7 {
		t.Errorf("the refused update left PDR 1 naming URRs %v, want its own 7", ids)
	}
	benign := message.NewSessionModificationRequest(0, 0, seid, 3, 0,
		ie.NewUpdateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewUpdateForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))))
	if got := cause(t, c.Modify(benign)); got != ie.CauseRequestAccepted {
		t.Errorf("the next modification answered cause %d, want it accepted: the refusal left nothing behind", got)
	}
	if got := cause(t, c.Delete(message.NewSessionDeletionRequest(0, 0, seid, 4, 0))); got != ie.CauseRequestAccepted {
		t.Errorf("the deletion answered cause %d", got)
	}
}

func TestARefusedModificationGivesBackTheMetersAndTEIDsItTook(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(urrEstablishment(0x3072, 7, quotaURR(7, 1<<30))).(*message.SessionEstablishmentResponse)
	seid := upFSEID(t, resp)

	c.mu.Lock()
	metersBefore := len(c.meters.released)
	c.mu.Unlock()
	// A new QER with a rate (the merge allocates its meters) and a second
	// uplink PDR pinned to an F-TEID of its own, in a request the merge refuses
	// for the first PDR's URR.
	req := namesUnknownURR(2, seid,
		ie.NewCreateQER(ie.NewQERID(9), ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen), ie.NewMBR(1000, 2000)),
		ie.NewCreatePDR(ie.NewPDRID(5), ie.NewPrecedence(20),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, 0x4242, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.2", "", 0, 0),
				ie.NewSDFFilter(udp53, "", "", "", 0)),
			ie.NewFARID(1), ie.NewQERID(9)))
	if got := cause(t, c.Modify(req)); got != ie.CauseRuleCreationModificationFailure {
		t.Fatalf("cause %d, want a rule failure", got)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.fteidTEIDKeys[0x4242]) != 0 {
		t.Error("the refused request's exact F-TEID key was not released")
	}
	if got := len(c.meters.released) - metersBefore; got != 2 {
		t.Errorf("%d meters were given back, want the refused QER's uplink and downlink pair", got)
	}
	if s := c.sessions[seid]; s.QERs[9] != nil || s.PDRs[5] != nil {
		t.Error("the refused request's QER or PDR is in the model")
	}
}
