// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// pfcpsimEstablishment is the shape OMEC's pfcpsim (the PFCP simulator CNTC's
// conformance suite drives) establishes with: a forwarding uplink FAR and a
// downlink FAR that DROPs and carries a zero-valued Outer Header Creation (GTP-U/
// UDP/IPv4, TEID 0, address 0.0.0.0) -- a placeholder for the gNB tunnel the
// SMF will fill in with a modification.
func pfcpsimEstablishment(cpSEID uint64, ueIP string, ohc *ie.IE) *message.SessionEstablishmentRequest {
	est := establishmentWithFTEID(cpSEID, ueIP, 0x11223344)
	est.CreateFAR = []*ie.IE{
		ie.NewCreateFAR(
			ie.NewFARID(1),
			ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
		ie.NewCreateFAR(
			ie.NewFARID(2),
			ie.NewApplyAction(0x01), // DROP
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess), ohc)),
	}
	return est
}

func TestAPlaceholderTunnelOnADroppingFARIsAcceptedAndWritesNoTunnel(t *testing.T) {
	// A zero TEID and the unspecified address name no tunnel: the SMF has not
	// told the UP function where the gNB is yet, and the FAR drops until it
	// does. Refusing it refused the whole establishment of every session of
	// an SMF that works this way.
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	placeholder := ie.NewOuterHeaderCreation(0x0100, 0, "0.0.0.0", "", 0, 0, 0)

	resp := c.Establish(pfcpsimEstablishment(0x9a01, "10.45.0.3", placeholder)).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d, want it accepted", got)
	}
	for _, ch := range rec.last() {
		if ch.Resource == tunnelsRes(c.cfg.Down) {
			t.Errorf("a tunnel record was written for a placeholder: %v", ch)
		}
	}

	// The modification that names the real tunnel writes it.
	mod := message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 2, 0,
		ie.NewUpdateFAR(
			ie.NewFARID(2),
			ie.NewApplyAction(applyForw),
			ie.NewUpdateForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceAccess),
				ie.NewOuterHeaderCreation(0x0100, 0x55667788, "10.20.30.2", "", 0, 0, 0))))
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification that names the tunnel answered cause %d", got)
	}
	var wrote bool
	for _, ch := range rec.last() {
		if ch.Resource == tunnelsRes(c.cfg.Down) {
			wrote = true
		}
	}
	if !wrote {
		t.Error("the modification that named the gNB's tunnel wrote no tunnel record")
	}
}

func TestATunnelWithAZeroTEIDButARealPeerIsStillRefused(t *testing.T) {
	// TEID 0 is not a tunnel a G-PDU can use (TS 29.281 reserves it), and a
	// real peer address beside it is no placeholder: that is a malformed FAR,
	// refused rather than turned into a record that sends nothing anywhere.
	c := New(testConfig(), &recorder{}, quietLogger())
	bad := ie.NewOuterHeaderCreation(0x0100, 0, "10.20.30.2", "", 0, 0, 0)

	resp := c.Establish(pfcpsimEstablishment(0x9a02, "10.45.0.4", bad)).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got == ie.CauseRequestAccepted {
		t.Fatal("a zero TEID beside a real peer address was accepted")
	}
}
