// SPDX-License-Identifier: BSD-3-Clause

package n4_test

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// ddnPDRID is the downlink PDR the buffered session's report must name.
const ddnPDRID = 2

// bufferedReportEstablishment is the session an SMF asks for when an idle UE has
// downlink data waiting: the uplink PDR forwards, and the downlink PDR's FAR
// asks for the packets to be *held* -- Apply Action BUFF and nothing else
// (TS 29.244 8.2.26) -- with the BAR the CP function provisions and associates
// to it (5.2.4.1, 7.5.2.6). No forwarding parameters on that FAR: there is no
// tunnel for the UE while it is idle, which is exactly why the packets wait.
func bufferedReportEstablishment(seq uint32, cpSEID uint64) *message.SessionEstablishmentRequest {
	const (
		buff = 0x04 // Apply Action: BUFF (TS 29.244 8.2.26, octet 5 bit 3)
		forw = 0x02 // Apply Action: FORW
	)
	return message.NewSessionEstablishmentRequest(0, 0, cpSEID, seq, 0,
		ie.NewNodeID("", "", smfID),
		ie.NewFSEID(cpSEID, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, reportUpTEID, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.2", "", 0, 0)),
			ie.NewFARID(1)),
		ie.NewCreatePDR(ie.NewPDRID(ddnPDRID), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x02, "10.45.0.2", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to assigned 53", "", "", "", 0)),
			ie.NewFARID(2)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(forw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
		ie.NewCreateFAR(ie.NewFARID(2), ie.NewApplyAction(buff), ie.NewBARID(1)),
		ie.NewCreateBAR(ie.NewBARID(1),
			ie.NewDLBufferingDuration(30*time.Second),
			ie.NewDLBufferingSuggestedPacketCount(16)),
	)
}

// TestLiveDownlinkReportReachesTheSMF is the Downlink Data Report path end to
// end, with this test as the SMF: ci/session-report.sh starts bessd with
// deploy/buffer-path.yaml and upfd with the buffering flags, and the test
// establishes a session whose downlink FAR asks for the packets to be held. The
// graph's own source keeps sending downlink packets, so a real daemon holds a
// real flow's first packet; upfd's tick reads the branch's counters (the
// trigger is a poll, docs/design.md) and owes the SMF a Session Report Request
// with a Downlink Data Report naming the PDR. What is checked is what an SMF
// sees: the Report Type, the PDR the report names, and that the report is
// addressed to the SMF's own F-SEID. The acknowledgement this test sends back is
// what makes the report delivered -- and what stops the next tick from offering
// it again (5.2.4.1's "the first buffered DL packet").
func TestLiveDownlinkReportReachesTheSMF(t *testing.T) {
	target := os.Getenv("UPF_N4_TARGET")
	if target == "" {
		t.Skip("set UPF_N4_TARGET (ci/session-report.sh does) to run against a live upfd")
	}
	raddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		t.Fatalf("resolving %s: %v", target, err)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		t.Fatalf("dialing %s: %v", target, err)
	}
	defer conn.Close()

	associate(t, conn, 5)
	sendMsg(t, conn, bufferedReportEstablishment(6, 0x9003))
	resp, ok := recvMsg(t, conn, 5*time.Second).(*message.SessionEstablishmentResponse)
	if !ok {
		t.Fatal("the establishment was not answered")
	}
	if cause, err := resp.Cause.Cause(); err != nil || cause != ie.CauseRequestAccepted {
		t.Fatalf("the session was not accepted: cause=%d err=%v", cause, err)
	}

	m := recvMsg(t, conn, 20*time.Second)
	report, ok := m.(*message.SessionReportRequest)
	if !ok {
		t.Fatalf("the UP function sent a %s, want a Session Report Request", m.MessageTypeName())
	}
	// The acknowledgement first, so a failure below is about the report and not
	// about a report left unanswered.
	sendMsg(t, conn, message.NewSessionReportResponse(0, 0, report.SEID(), report.Sequence(), 0,
		ie.NewCause(ie.CauseRequestAccepted)))

	if report.SEID() != 0x9003 {
		t.Errorf("the report names SEID %#x, want the CP F-SEID 0x9003", report.SEID())
	}
	if !report.ReportType.HasDLDR() {
		t.Errorf("the report's type is not a downlink data report: %+v", report.ReportType)
	}
	if report.ReportType.HasUSAR() {
		t.Errorf("the report claims a usage report too: %+v", report.ReportType)
	}
	if report.DownlinkDataReport == nil {
		t.Fatal("the report carries no Downlink Data Report IE")
	}
	children, err := report.DownlinkDataReport.DownlinkDataReport()
	if err != nil {
		t.Fatalf("the Downlink Data Report's IEs: %v", err)
	}
	var pdrs []uint16
	for _, child := range children {
		if child.Type == ie.PDRID {
			if id, err := child.PDRID(); err == nil {
				pdrs = append(pdrs, id)
			}
		}
	}
	if len(pdrs) != 1 || pdrs[0] != ddnPDRID {
		t.Fatalf("the report names PDRs %v, want the buffering PDR %d", pdrs, ddnPDRID)
	}
	t.Logf("the report: DLDR, PDR %d, SEID %#x", pdrs[0], report.SEID())
}
