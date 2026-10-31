// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// tunnelSession is a session whose FAR sends into an N3 tunnel: a downlink PDR
// (Source Interface Core) forwarding toward Access with an Outer Header
// Creation. The creation's TEID and address are the remote F-TEID this UPF
// sends with -- the tunnel the peer names when it cannot reach it.
func tunnelSession(cpSEID uint64, teid uint32, peer string) *message.SessionEstablishmentRequest {
	return message.NewSessionEstablishmentRequest(0, 0, cpSEID, 1, 0,
		ie.NewFSEID(cpSEID, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x06, "10.45.0.6", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to 10.10.0.0/16 1000", "", "", "", 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess),
				ie.NewOuterHeaderCreation(0x0100, teid, peer, "", 0, 0, 0))),
	)
}

// TestAPeerErrorIndicationBecomesAnERIRReport is finding 15 (TS 29.244 5.10):
// the peer's GTP-U Error Indication names a tunnel this UPF sends into, the
// responder's log holds the event, and the tick turns it into a Session Report
// Request whose Report Type is the Error Indication Report and whose Error
// Indication Report IE carries that remote F-TEID -- once, not once per tick:
// the drain delivers each indication once.
//
// The session has no URR, so this is also the shape a deployment that measures
// nothing runs: the error table is read on its own, with no counter module in
// the graph at all.
func TestAPeerErrorIndicationBecomesAnERIRReport(t *testing.T) {
	const (
		outTEID = 0x11223344
		peer    = "10.20.30.2"
	)
	ctx := context.Background()
	rec := &recorder{}
	cfg := testConfig()
	cfg.GTPUErrors = "echo0"
	c := New(cfg, rec, quietLogger())

	resp := c.Establish(tunnelSession(0x8880, outTEID, peer)).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the tunnel session answered cause %d", got)
	}

	// The responder's log as drain_errors answers it: the peer reported this
	// session's own tunnel, and one TEID that names no session of this UPF.
	rec.errors = map[string][]uint32{"echo0": {outTEID, 0xdeadbeef}}
	t0 := time.Unix(1_700_000_000, 0)

	reports := c.EvaluateAll(ctx, t0)
	if len(reports) != 1 {
		t.Fatalf("the tick returned %d reports, want one Error Indication Report", len(reports))
	}
	report := reports[0]
	if len(report.Errors) != 1 || report.Errors[0].TEID != outTEID || report.Errors[0].Addr != netip.MustParseAddr(peer) {
		t.Fatalf("the report carries %v, want the remote F-TEID %#x at %s", report.Errors, outTEID, peer)
	}
	ies := report.IEs()
	if len(ies) != 2 || ies[0].Type != ie.ReportType {
		t.Fatalf("the report's IEs are %v, want a Report Type and one Error Indication Report", ieTypes(ies))
	}
	if !ies[0].HasERIR() {
		t.Error("the Report Type does not have the ERIR bit")
	}
	if ies[0].HasUSAR() {
		t.Error("an Error Indication Report carries the USAR bit as well")
	}
	if ies[1].Type != ie.ErrorIndicationReport {
		t.Fatalf("the second IE is %#x, want the Error Indication Report", ies[1].Type)
	}
	inner, err := ies[1].ErrorIndicationReport()
	if err != nil || len(inner) != 1 || inner[0].Type != ie.FTEID {
		t.Fatalf("the Error Indication Report holds %v (%v), want one F-TEID", ieTypes(inner), err)
	}
	fteid, err := inner[0].FTEID()
	if err != nil {
		t.Fatalf("the F-TEID IE does not parse: %v", err)
	}
	if fteid.TEID != outTEID {
		t.Errorf("the F-TEID names TEID %#x, want the remote one (%#x)", fteid.TEID, outTEID)
	}
	if !fteid.IPv4Address.Equal(net.ParseIP(peer)) {
		t.Errorf("the F-TEID names %v, want the peer the FAR sends to (%s)", fteid.IPv4Address, peer)
	}

	// Nothing new was drained: the next tick owes nothing, which is what keeps
	// a tunnel loss from being reported once per tick forever.
	if again := c.EvaluateAll(ctx, t0.Add(time.Second)); len(again) != 0 {
		t.Errorf("the next tick returned %d reports with nothing drained, want none", len(again))
	}
	// A new indication is drained, and reported.
	rec.errors = map[string][]uint32{"echo0": {outTEID}}
	if next := c.EvaluateAll(ctx, t0.Add(2*time.Second)); len(next) != 1 {
		t.Errorf("the tick after a new indication returned %d reports, want one", len(next))
	}
}

// TestAnErrorIndicationForAnotherTunnelCostsASessionNothing is UG-R2's EI half:
// a tick with indications walks every session, so a session none of whose
// tunnels the peer named must cost no allocation.
func TestAnErrorIndicationForAnotherTunnelCostsASessionNothing(t *testing.T) {
	cfg := testConfig()
	cfg.GTPUErrors = "echo0"
	c := New(cfg, &recorder{}, quietLogger())
	resp := c.Establish(tunnelSession(0x8880, 0x11223344, "10.20.30.2")).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the tunnel session answered cause %d", got)
	}
	seid := upFSEID(t, resp)
	s := sessionOf(t, c, seid)
	indications := map[uint32]bool{0xdeadbeef: true}
	if allocs := testing.AllocsPerRun(100, func() {
		if owed := c.errorReports(seid, s, indications); owed != nil {
			t.Fatalf("a session was reported about another tunnel: %+v", owed)
		}
	}); allocs != 0 {
		t.Errorf("a session the indications do not name made %.0f allocations, want 0", allocs)
	}
}

// TestAReportCanCarryUsageAndAnErrorIndication is the one-tick case where an
// SMF is owed both: the Report Type says so in one message (8.2.21), and the
// usage the URR's window measured is still there -- an error about one tunnel
// is no reason to drop the report beside it.
func TestAReportCanCarryUsageAndAnErrorIndication(t *testing.T) {
	report := Report{
		URRID:   7,
		Seqn:    1,
		Trigger: TriggerPeriod,
		Up:      Usage{Packets: 2, Octets: 128},
		Errors:  []ErrorIndication{{TEID: 0x11223344, Addr: netip.MustParseAddr("10.20.30.2")}},
	}
	ies := report.IEs()
	if len(ies) != 3 {
		t.Fatalf("the report's IEs are %v, want a Report Type, an Error Indication Report and a Usage Report", ieTypes(ies))
	}
	if !ies[0].HasERIR() || !ies[0].HasUSAR() {
		t.Errorf("the Report Type is %#x, want both the ERIR and the USAR bits", mustUint8(t, ies[0]))
	}
	if ies[1].Type != ie.ErrorIndicationReport || ies[2].Type != ie.UsageReportWithinSessionReportRequest {
		t.Errorf("the report's IEs after the type are %v, want the Error Indication Report first", ieTypes(ies[1:]))
	}
}

// ieTypes spells IEs for a failure message: a garbled IE list is read by what
// the IEs are, not by their payloads.
func ieTypes(ies []*ie.IE) []string {
	out := make([]string, 0, len(ies))
	for _, i := range ies {
		out = append(out, fmt.Sprintf("%#x", i.Type))
	}
	return out
}

func mustUint8(t *testing.T, i *ie.IE) uint8 {
	t.Helper()
	v, err := i.ReportType()
	if err != nil {
		t.Fatalf("the Report Type IE does not read: %v", err)
	}
	return v
}
