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

// The graph's frames, as deploy/session-path.yaml declares them and
// ci/session-path.sh's test uses: the G-PDU names this F-TEID, its inner
// packets are the UE's 10.45.0.2:5000 -> 8.8.8.8:53, and the downlink FAR's
// outer header names the other one. A session pinned to them makes the graph's
// Sources produce counted traffic without any other setup.
const (
	reportUpTEID   = 0x11223344
	reportDownTEID = 0x55667788
)

// reportURRID is the URR this test's session carries, and reportQuota the
// volume that stops its traffic: a few packets of the source's 37-octet IP
// packets, so a second of traffic is far past it.
const (
	reportURRID = 7
	reportQuota = 370
)

// usageReportEstablishment is the session an SMF asks for when it wants usage
// measured: the two PDRs of a GTP-U session, and a URR on the uplink one with a
// volume quota and nothing else -- VOLQU alone, so the only report it can owe is
// the quota's.
func usageReportEstablishment(seq uint32, cpSEID uint64) *message.SessionEstablishmentRequest {
	const forw = 0x02 // Apply Action: FORW (TS 29.244 8.2.26)
	return message.NewSessionEstablishmentRequest(0, 0, cpSEID, seq, 0,
		ie.NewNodeID("", "", smfID),
		ie.NewFSEID(cpSEID, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, reportUpTEID, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.2", "", 0, 0)),
			ie.NewFARID(1), ie.NewURRID(reportURRID)),
		ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x02, "10.45.0.2", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to assigned 53", "", "", "", 0)),
			ie.NewFARID(2)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(forw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
		ie.NewCreateFAR(ie.NewFARID(2), ie.NewApplyAction(forw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess),
				ie.NewOuterHeaderCreation(0x0100, reportDownTEID, "10.20.30.2", "", 0, 0, 0))),
		ie.NewCreateURR(ie.NewURRID(reportURRID),
			ie.NewMeasurementMethod(0, 1, 0),    // VOLUM
			ie.NewReportingTriggers(0x00, 0x01), // VOLQU: the quota is the report
			ie.NewVolumeQuota(0x01, reportQuota, 0, 0)),
	)
}

// TestLiveUsageReportReachesTheSMF is the whole reporting path against a live
// upfd, with this test as the SMF: ci/session-report.sh starts bessd with the
// session-path graph and upfd with -urr-interval, the test associates and
// establishes a session a URR measures, and then waits for the Session Report
// Request the UP function owes it -- answering it, which is the acknowledgement
// upfd's log records. What is checked is what an SMF sees: the Report Type, the
// URR, the UR-SEQN, the trigger, and the volume the graph's packets produced.
func TestLiveUsageReportReachesTheSMF(t *testing.T) {
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

	associate(t, conn, 1)
	sendMsg(t, conn, usageReportEstablishment(2, 0x9001))
	resp, ok := recvMsg(t, conn, 5*time.Second).(*message.SessionEstablishmentResponse)
	if !ok {
		t.Fatal("the establishment was not answered")
	}
	if cause, err := resp.Cause.Cause(); err != nil || cause != ie.CauseRequestAccepted {
		t.Fatalf("the session was not accepted: cause=%d err=%v", cause, err)
	}

	// The report: upfd's reporting tick reads the counters once for the
	// baseline and then reports what the window holds, so the report arrives a
	// tick or two after the session exists.
	m := recvMsg(t, conn, 20*time.Second)
	report, ok := m.(*message.SessionReportRequest)
	if !ok {
		t.Fatalf("the UP function sent a %s, want a Session Report Request", m.MessageTypeName())
	}
	// The acknowledgement: the SMF's own answer, which is what makes the report
	// delivered (upfd logs "usage report acknowledged" when this arrives).
	sendMsg(t, conn, message.NewSessionReportResponse(0, 0, report.SEID(), report.Sequence(), 0,
		ie.NewCause(ie.CauseRequestAccepted)))

	// The report is addressed to the SMF, so the header names the session the
	// way *the SMF* knows it: the CP F-SEID this test allocated (0x9001, the
	// value in its own F-SEID IE). A report under our own F-SEID would be a
	// session the SMF cannot find (TS 29.244 7.2.2.4.2).
	if report.SEID() != 0x9001 {
		t.Errorf("the report names SEID %#x, want the CP F-SEID 0x9001", report.SEID())
	}
	if !report.ReportType.HasUSAR() {
		t.Errorf("the report's type is not a usage report: %+v", report.ReportType)
	}
	if len(report.UsageReport) != 1 {
		t.Fatalf("the report carries %d usage reports, want one", len(report.UsageReport))
	}
	children, err := report.UsageReport[0].UsageReport()
	if err != nil {
		t.Fatalf("the usage report's IEs: %v", err)
	}
	byType := map[ie.IEType]*ie.IE{}
	for _, child := range children {
		byType[child.Type] = child
	}
	if id, err := byType[ie.URRID].URRID(); err != nil || id != reportURRID {
		t.Errorf("the report names URR %d (%v), want %d", id, err, reportURRID)
	}
	if seqn, err := byType[ie.URSEQN].URSEQN(); err != nil || seqn != 0 {
		t.Errorf("the report carries UR-SEQN %d (%v), want 0 for a URR's first report", seqn, err)
	}
	// The trigger is VOLQU: the reason this report exists is the quota.
	flags, err := byType[ie.UsageReportTrigger].UsageReportTrigger()
	if err != nil || len(flags) < 2 || flags[0] != 0 || flags[1] != 0x01 {
		t.Errorf("the report's trigger is %#v (%v), want only VOLQU (octet 6 bit 1; Figure 8.2.41-1)", flags, err)
	}
	vol, err := byType[ie.VolumeMeasurement].VolumeMeasurement()
	if err != nil {
		t.Fatalf("the report's volume measurement: %v", err)
	}
	if vol.TotalVolume < reportQuota {
		t.Errorf("the report says %d octets, less than the %d quota it reports spent",
			vol.TotalVolume, reportQuota)
	}
	// The octets are the graph's frames: each 51-byte frame holds a 37-octet IP
	// packet (the same identity ci/session-path.sh's counting test checks).
	if vol.TotalNumberOfPackets == 0 || vol.TotalVolume%vol.TotalNumberOfPackets != 0 {
		t.Errorf("the report's %d octets over %d packets is not a whole number of octets per packet",
			vol.TotalVolume, vol.TotalNumberOfPackets)
	}
	t.Logf("the report: URR %d, UR-SEQN 0, VOLQU, %d packets, %d octets (UL %d, DL %d)",
		reportURRID, vol.TotalNumberOfPackets, vol.TotalVolume, vol.UplinkVolume, vol.DownlinkVolume)

	// The session's end: the deletion's answer carries the URR's last window
	// (TS 29.244 5.2.2.3.1), TERMR, under the next UR-SEQN. The quota stopped
	// the traffic, so the window after the quota's report is empty -- what is
	// checked is that the SMF is told, and which report it is.
	up, err := resp.UPFSEID.FSEID()
	if err != nil {
		t.Fatalf("the response's UP F-SEID: %v", err)
	}
	sendMsg(t, conn, message.NewSessionDeletionRequest(0, 0, up.SEID, 3, 0))
	del, ok := recvMsg(t, conn, 5*time.Second).(*message.SessionDeletionResponse)
	if !ok {
		t.Fatal("the deletion was not answered")
	}
	if cause, err := del.Cause.Cause(); err != nil || cause != ie.CauseRequestAccepted {
		t.Fatalf("the deletion was not accepted: cause=%d err=%v", cause, err)
	}
	if len(del.UsageReport) != 1 {
		t.Fatalf("the deletion response carries %d usage reports, want one for URR %d", len(del.UsageReport), reportURRID)
	}
	if !del.UsageReport[0].HasTERMR() {
		t.Error("the deletion's usage report is not a termination report")
	}
	last, err := del.UsageReport[0].UsageReport()
	if err != nil {
		t.Fatalf("the termination report's IEs: %v", err)
	}
	var termSeqn uint32 = 99
	for _, child := range last {
		switch child.Type {
		case ie.URRID:
			if id, _ := child.URRID(); id != reportURRID {
				t.Errorf("the termination report names URR %d, want %d", id, reportURRID)
			}
		case ie.URSEQN:
			termSeqn, _ = child.URSEQN()
		}
	}
	if termSeqn != 1 {
		t.Errorf("the termination report carries UR-SEQN %d, want 1 (the quota's report was 0)", termSeqn)
	}
}
