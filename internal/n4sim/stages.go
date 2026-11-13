// SPDX-License-Identifier: BSD-3-Clause

package n4sim

import (
	"fmt"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// StageEstablish builds a graph-layout fixture with 1, 2, 3, 4 or 8 distinct
// resources written on establishment. These are real PFCP rule combinations,
// not the generic ExactMatch replacement fixture used for the SDK floor:
// 1: one dropping downlink classifier; 2: uplink classifier and F-TEID;
// 3: add an uplink meter; 4: add an uplink usage counter;
// 8: both classifiers, meters and counters, F-TEID and downlink tunnel.
// The graph must configure separate UL/DL tables, meters and counters, and one
// local IPv4 endpoint. The compiler benchmark checks the actual emitted stages.
func StageEstablish(seq uint32, s Session, stages int) (*message.SessionEstablishmentRequest, error) {
	switch stages {
	case 1, 2, 3, 4, 8:
	default:
		return nil, fmt.Errorf("stage count %d: want 1, 2, 3, 4 or 8", stages)
	}
	parts := []*ie.IE{ie.NewNodeID("", "", "smf"), ie.NewFSEID(s.CPSEID, nil, nil)}
	if stages == 1 {
		parts = append(parts,
			ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(100),
				ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
					ie.NewUEIPAddress(0x06, s.UEIP, "", 0, 0)), ie.NewFARID(2)),
			ie.NewCreateFAR(ie.NewFARID(2), ie.NewApplyAction(applyDrop)))
		return message.NewSessionEstablishmentRequest(0, 0, s.CPSEID, seq, 0, parts...), nil
	}
	ul := []*ie.IE{ie.NewPDRID(1), ie.NewPrecedence(100),
		ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess), fteidIE(s),
			ie.NewUEIPAddress(0x02, s.UEIP, "", 0, 0)), ie.NewFARID(1)}
	if stages >= 3 {
		ul = append(ul, ie.NewQERID(1))
		dlRate := uint64(0)
		if stages == 8 {
			dlRate = 2000
		}
		parts = append(parts, ie.NewCreateQER(ie.NewQERID(1),
			ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen), ie.NewMBR(1000, dlRate)))
	}
	if stages >= 4 {
		ul = append(ul, ie.NewURRID(7))
		parts = append(parts, ie.NewCreateURR(ie.NewURRID(7), ie.NewMeasurementMethod(0, 1, 0),
			ie.NewReportingTriggers(0, 1), ie.NewVolumeQuota(1, 1<<50, 0, 0)))
	}
	parts = append(parts, ie.NewCreatePDR(ul...), ie.NewCreateFAR(ie.NewFARID(1),
		ie.NewApplyAction(applyForw), ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))))
	if stages == 8 {
		parts = append(parts,
			ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(100),
				ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
					ie.NewUEIPAddress(0x06, s.UEIP, "", 0, 0)),
				ie.NewFARID(2), ie.NewQERID(1), ie.NewURRID(7)),
			ie.NewCreateFAR(ie.NewFARID(2), ie.NewApplyAction(applyForw),
				ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess),
					outerHeaderCreation(s.TEID, s.GnBIP))))
	}
	return message.NewSessionEstablishmentRequest(0, 0, s.CPSEID, seq, 0, parts...), nil
}
