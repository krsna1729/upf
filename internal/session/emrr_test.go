// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/bess"
)

// reemrSession is an uplink PDR on endpoint 1's pinned F-TEID whose URR asks
// for REEMR alone (TS 29.244 8.2.19 octet 7).
func reemrSession(cpSEID uint64, teid uint32) *message.SessionEstablishmentRequest {
	return message.NewSessionEstablishmentRequest(0, 0, cpSEID, 1, 0,
		ie.NewFSEID(cpSEID, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, teid, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.9", "", 0, 0)),
			ie.NewFARID(1),
			ie.NewURRID(7)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
		ie.NewCreateURR(ie.NewURRID(7),
			ie.NewMeasurementMethod(0, 1, 0),          // VOLUM
			ie.NewReportingTriggers(0x00, 0x00, 0x01), // REEMR
		),
	)
}

func TestAREEMRURRNeedsAnEndMarkerLog(t *testing.T) {
	c := New(testConfig(), &recorder{}, quietLogger())
	resp := c.Establish(reemrSession(0x9100, 0x11223344)).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got == ie.CauseRequestAccepted {
		t.Fatal("a REEMR URR was accepted by a deployment that tracks no End Markers")
	}
}

// An End Marker on the PDR's own local F-TEID is reported once, as a Usage
// Report with EMRRE; the same TEID on another endpoint is another tunnel and
// reports nothing.
func TestAnEndMarkerOnThePDRsFTEIDBecomesAnEMRREUsageReport(t *testing.T) {
	const teid = 0x11223344
	ctx := context.Background()
	rec := &recorder{}
	cfg := testConfig()
	cfg.GTPUEndMarkers = "echo0"
	c := New(cfg, rec, quietLogger())
	resp := c.Establish(reemrSession(0x9101, teid)).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the REEMR session answered cause %d", got)
	}
	seid := upFSEID(t, resp)
	t0 := time.Unix(1_700_000_000, 0)

	rec.endMarkers = map[string][]bess.EndMarker{"echo0": {
		{EndpointID: 2, TEID: teid},     // the same TEID on another endpoint
		{EndpointID: 1, TEID: teid + 1}, // another TEID on this endpoint
	}}
	if reports := c.EvaluateAll(ctx, t0); len(reports) != 0 {
		t.Fatalf("End Markers on other tunnels were reported: %+v", reports)
	}

	rec.endMarkers = map[string][]bess.EndMarker{"echo0": {{EndpointID: 1, TEID: teid}}}
	reports := c.EvaluateAll(ctx, t0.Add(time.Second))
	if len(reports) != 1 || reports[0].SEID != seid || reports[0].URRID != 7 || !reports[0].EndMarker ||
		reports[0].Trigger != TriggerEndMarker {
		t.Fatalf("the tick returned %+v, want one EMRRE report for URR 7", reports)
	}
	ies := reports[0].IEs()
	if len(ies) != 2 || !ies[0].HasUSAR() || ies[1].Type != ie.UsageReportWithinSessionReportRequest {
		t.Fatalf("the report's IEs are %v, want a Report Type with USAR and one Usage Report", ieTypes(ies))
	}
	inner, err := ies[1].UsageReport()
	if err != nil {
		t.Fatalf("the Usage Report does not parse: %v", err)
	}
	var trigger *ie.IE
	for _, i := range inner {
		if i.Type == ie.UsageReportTrigger {
			trigger = i
		}
	}
	if trigger == nil || !trigger.HasEMRRE() || trigger.HasPERIO() || trigger.HasVOLTH() {
		t.Fatalf("the Usage Report Trigger is %v, want EMRRE alone", trigger)
	}

	if reports := c.EvaluateAll(ctx, t0.Add(2*time.Second)); len(reports) != 0 {
		t.Fatalf("a drained End Marker was reported again: %+v", reports)
	}
}
