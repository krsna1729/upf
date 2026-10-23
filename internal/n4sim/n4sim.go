// SPDX-License-Identifier: BSD-3-Clause

// Package n4sim builds the PFCP messages a client of the UPF's N4 node sends:
// the associate, establish, modify and delete requests an SMF would send, with
// the element set internal/session's compiler accepts (the same shape the
// session tests and ci/session-live.sh use, parameterised so every session has
// its own keys).
//
// It is the client-side counterpart of the compiler: a load client
// (cmd/n4bench) drives this, and the smoke tests can too.
package n4sim

import (
	"fmt"
	"net"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// now is the clock every timestamp in this package reads: one place, so a test
// can see where time enters.
func now() time.Time { return time.Now() }

// Apply action bits as the compiler reads them (internal/session/compile.go).
const (
	applyDrop = 0x01
	applyForw = 0x02
)

// Session is one session's request parameters. Every field that becomes a key
// in the dataplane must differ between sessions: the CP SEID, the TEID the
// downlink uses, the UE address, and the two ports of the SDF filter.
type Session struct {
	CPSEID uint64 // this session's CP F-SEID
	TEID   uint32 // the TEID the gNB expects on the downlink
	FTEID  uint32 // the uplink F-TEID the SMF pins; 0: the UPF chooses one
	UEIP   string // the UE's address, an uplink PDR's key and a downlink PDR's
	GnBIP  string // the gNB's N3 address (IPv4 or IPv6): the outer header's destination
	N3IP   string // the UPF's N3 address: the F-TEID the UPF answers with
	SDF    string // the uplink filter; empty: the default permit for port 53
}

// sdf is the filter to send for a session.
func (s Session) sdf() string {
	if s.SDF == "" {
		return "permit out udp from any to assigned 53"
	}
	return s.SDF
}

// fteidIE is the F-TEID IE an SMF sends. With a value pinned, that is a V4
// F-TEID (flag 0x01 -- go-pfcp's HasIPv4 is the first bit; 0x02 is V6) carrying
// the TEID and the UPF's N3 address. With nothing pinned it is the CH request:
// the CH bit (0x04) with the family the UP function is to assign (V4, 0x01), so
// 0x05 -- which is what TS 29.244 8.2.3 has an SMF send, and carries no TEID at
// all. A TEID of zero *with* the V4 flag alone is a pinned zero, a shape no SMF
// sends and only a lenient UPF reads as "choose".
func fteidIE(s Session) *ie.IE {
	if s.FTEID == 0 {
		return ie.NewFTEID(0x05, 0, nil, nil, 0)
	}
	return ie.NewFTEID(0x01, s.FTEID, net.ParseIP(s.N3IP), nil, 0)
}

// Associate is an Association Setup Request from an SMF named nodeID.
func Associate(seq uint32, nodeID string) *message.AssociationSetupRequest {
	return message.NewAssociationSetupRequest(seq,
		ie.NewNodeID("", "", nodeID),
		ie.NewRecoveryTimeStamp(now()),
	)
}

// Establish is a Session Establishment Request: an uplink PDR (access side,
// F-TEID, UE address) forwarding to the core, and a downlink PDR (core side,
// UE address, SDF) whose FAR creates the GTP-U outer header toward the gNB,
// with one QER for the session. That is what an SMF's first message carries.
func Establish(seq uint32, s Session) *message.SessionEstablishmentRequest {
	return message.NewSessionEstablishmentRequest(0, 0, s.CPSEID, seq, 0,
		ie.NewNodeID("", "", "smf"),
		ie.NewFSEID(s.CPSEID, nil, nil),
		ie.NewCreatePDR(
			ie.NewPDRID(1),
			ie.NewPrecedence(100),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceAccess),
				fteidIE(s),
				ie.NewUEIPAddress(0x02, s.UEIP, "", 0, 0),
			),
			ie.NewFARID(1),
			ie.NewQERID(1),
		),
		ie.NewCreatePDR(
			ie.NewPDRID(2),
			ie.NewPrecedence(100),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x06, s.UEIP, "", 0, 0),
				ie.NewSDFFilter(s.sdf(), "", "", "", 0),
			),
			ie.NewFARID(2),
		),
		ie.NewCreateFAR(
			ie.NewFARID(1),
			ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore)),
		),
		ie.NewCreateFAR(
			ie.NewFARID(2),
			ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceAccess),
				outerHeaderCreation(s.TEID, s.GnBIP),
			),
		),
		ie.NewCreateQER(
			ie.NewQERID(1),
			ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
			ie.NewMBR(1000, 2000),
		),
	)
}

// outerHeaderCreation is the OHC toward a gNB: GTP-U/UDP/IPv4 (description
// 0x0100) for an IPv4 address, GTP-U/UDP/IPv6 (0x0200) for an IPv6 one (TS
// 29.244 8.2.56).
func outerHeaderCreation(teid uint32, gnbIP string) *ie.IE {
	if ip := net.ParseIP(gnbIP); ip != nil && ip.To4() == nil {
		return ie.NewOuterHeaderCreation(0x0200, teid, "", gnbIP, 0, 0, 0)
	}
	return ie.NewOuterHeaderCreation(0x0100, teid, gnbIP, "", 0, 0, 0)
}

// Modify rewrites the downlink FAR's outer header: the same session (same
// keys), a new gNB endpoint, which is what a handover looks like on N4. It is
// also the cheapest transaction an SMF sends, so it is the one a rate limit is
// most often expressed in.
func Modify(seq uint32, seid uint64, farID uint32, teid uint32, gnbIP string) *message.SessionModificationRequest {
	return message.NewSessionModificationRequest(0, 0, seid, seq, 0,
		ie.NewUpdateFAR(ie.NewFARID(farID), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceAccess),
				outerHeaderCreation(teid, gnbIP),
			)),
	)
}

// Handover is Modify as a path switch: the FAR's new tunnel in Update
// Forwarding Parameters and the message's PFCPSMReq-Flags with SNDEM (0x02,
// TS 29.244 8.2.31), which asks the UPF to send an End Marker on the tunnel it
// leaves (5.3.2).
func Handover(seq uint32, seid uint64, farID uint32, teid uint32, gnbIP string) *message.SessionModificationRequest {
	return message.NewSessionModificationRequest(0, 0, seid, seq, 0,
		ie.NewPFCPSMReqFlags(0x02),
		ie.NewUpdateFAR(ie.NewFARID(farID), ie.NewApplyAction(applyForw),
			ie.NewUpdateForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceAccess),
				outerHeaderCreation(teid, gnbIP),
			)),
	)
}

// Delete removes the session by its UPF-side SEID (the one the establishment
// response carried).
func Delete(seq uint32, seid uint64) *message.SessionDeletionRequest {
	return message.NewSessionDeletionRequest(0, 0, seid, seq, 0)
}

// HeartbeatResponse answers a Heartbeat Request the UPF initiated, so a long
// run does not lose the association to a timeout.
func HeartbeatResponse(seq uint32) *message.HeartbeatResponse {
	return message.NewHeartbeatResponse(seq, ie.NewRecoveryTimeStamp(now()))
}

// Cause is the Cause value of any session-level or association-level response.
func Cause(m message.Message) (uint8, error) {
	var i *ie.IE
	switch v := m.(type) {
	case *message.AssociationSetupResponse:
		i = v.Cause
	case *message.SessionEstablishmentResponse:
		i = v.Cause
	case *message.SessionModificationResponse:
		i = v.Cause
	case *message.SessionDeletionResponse:
		i = v.Cause
	default:
		return 0, fmt.Errorf("%s carries no cause", m.MessageTypeName())
	}
	if i == nil {
		return 0, fmt.Errorf("%s carries no cause", m.MessageTypeName())
	}
	return i.Cause()
}
