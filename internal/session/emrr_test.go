// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"bytes"
	"context"
	"net"
	"net/netip"
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

// TestReceivedEndMarkersAreRelayedThroughTheirTunnels: an End Marker that
// arrives on a local F-TEID whose PDR forwards into a GTP-U tunnel leaves on
// that tunnel -- the tunnel's own TEID toward its peer, from its local
// address, through its transport's port -- once per arrival (TS 29.244
// Table 8.2.64-1 NOTE 2; TS 23.502 4.9.1.3.3 step 10b). The source I-UPF of
// an indirect-forwarding handover relays the PSA's marker toward the source
// RAN and the source RAN's marker toward the target UPF; an N9-to-N9 transit
// relays it over N9. A PDR that ends the tunnel or drops relays nothing.
func TestReceivedEndMarkersAreRelayedThroughTheirTunnels(t *testing.T) {
	cfg := modesConfig(t)
	base := endMarkerBase()
	cfg.EndMarker = base
	cfg.GTPUEndMarkers = "echo0"
	n3Frames := endMarkerListener(t, base+".1")
	n9Frames := endMarkerListener(t, base+".2")
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())
	t.Cleanup(func() {
		for _, conn := range c.endMarkerConns {
			conn.Close()
		}
	})
	establish := func(req *message.SessionEstablishmentRequest) *message.SessionEstablishmentResponse {
		t.Helper()
		resp, ok := c.Establish(req).(*message.SessionEstablishmentResponse)
		if !ok || cause(t, resp) != ie.CauseRequestAccepted {
			t.Fatalf("session %#x was refused: %v", req.SEID(), resp)
		}
		return resp
	}
	accessPDR := func(id uint16, extra ...*ie.IE) *ie.IE {
		return ie.NewCreatePDR(ie.NewPDRID(id), ie.NewPrecedence(100),
			ie.NewPDI(append([]*ie.IE{ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewNetworkInstance("internet"), chooseFTEID()}, extra...)...),
			ie.NewOuterHeaderRemoval(0, 0), ie.NewFARID(uint32(id)))
	}
	corePDR := func(id uint16, extra ...*ie.IE) *ie.IE {
		return ie.NewCreatePDR(ie.NewPDRID(id), ie.NewPrecedence(100),
			ie.NewPDI(append([]*ie.IE{ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewNetworkInstance("internet"), chooseFTEID()}, extra...)...),
			ie.NewOuterHeaderRemoval(0, 0), ie.NewFARID(uint32(id)))
	}
	tunnel := func(teid uint32, peer string) *ie.IE {
		return ie.NewOuterHeaderCreation(0x0100, teid, peer, "", 0, 0, 0)
	}

	// The source I-UPF (Mode 6): the PSA's downlink on its N9 F-TEID to the
	// source RAN, then step 11d's forwarding tunnel toward the target UPF.
	src := establish(message.NewSessionEstablishmentRequest(0, 0, 0x9401, 1, 0,
		ie.NewFSEID(0x9401, nil, nil),
		accessPDR(1, ie.NewUEIPAddress(0x02, "10.45.7.2", "", 0, 0)),
		forwardTo(1, ie.DstInterfaceCore, tunnel(0x77000001, "198.51.100.5")),
		corePDR(2, ie.NewUEIPAddress(0x06, "10.45.7.2", "", 0, 0)),
		forwardTo(2, ie.DstInterfaceAccess, tunnel(0x77000002, "10.20.30.2"))))
	srcDown, _ := createdFTEIDOf(t, src.CreatedPDR, 2)
	srcSEID := upFSEID(t, src)
	fwd, ok := c.Modify(message.NewSessionModificationRequest(0, 0, srcSEID, 2, 0,
		accessPDR(3, ie.NewTGPPInterfaceType(ie.TGPPInterfaceTypeN3ForDataForwarding)),
		forwardTo(3, ie.DstInterfaceAccess, tunnel(0x77000003, "198.51.100.77")))).(*message.SessionModificationResponse)
	if !ok || cause(t, fwd) != ie.CauseRequestAccepted {
		t.Fatalf("step 11d was refused: %v", fwd)
	}
	srcFwd, _ := createdFTEIDOf(t, fwd.CreatedPDR, 3)

	// Mode 4: an I-UPF between an I-UPF and the PSA, N9 both ways, no UE.
	transit := establish(message.NewSessionEstablishmentRequest(0, 0, 0x9402, 1, 0,
		ie.NewFSEID(0x9402, nil, nil),
		accessPDR(1, ie.NewTGPPInterfaceType(ie.TGPPInterfaceTypeN9)),
		forwardTo(1, ie.DstInterfaceCore, tunnel(0x77000011, "198.51.100.3")),
		corePDR(2),
		forwardTo(2, ie.DstInterfaceAccess, tunnel(0x77000012, "198.51.100.1"),
			ie.NewTGPPInterfaceType(ie.TGPPInterfaceTypeN9))))
	transitDown, _ := createdFTEIDOf(t, transit.CreatedPDR, 2)

	// What ends here: a PSA's uplink to N6, and a target UPF's downlink
	// still dropped before step 8a.
	psa := establish(message.NewSessionEstablishmentRequest(0, 0, 0x9403, 1, 0,
		ie.NewFSEID(0x9403, nil, nil),
		accessPDR(1, ie.NewUEIPAddress(0x02, "10.45.7.3", "", 0, 0)),
		forwardTo(1, ie.DstInterfaceCore)))
	psaUp, _ := createdFTEIDOf(t, psa.CreatedPDR, 1)
	held := establish(message.NewSessionEstablishmentRequest(0, 0, 0x9404, 1, 0,
		ie.NewFSEID(0x9404, nil, nil),
		corePDR(2, ie.NewUEIPAddress(0x06, "10.45.7.4", "", 0, 0)),
		ie.NewCreateFAR(ie.NewFARID(2), ie.NewApplyAction(applyDrop))))
	heldDown, _ := createdFTEIDOf(t, held.CreatedPDR, 2)

	rec.endMarkers = map[string][]bess.EndMarker{"echo0": {
		{EndpointID: 2, TEID: srcDown},
		{EndpointID: 1, TEID: srcFwd},
		{EndpointID: 2, TEID: transitDown},
		{EndpointID: 1, TEID: psaUp},
		{EndpointID: 2, TEID: heldDown},
		{EndpointID: 1, TEID: srcDown}, // the same TEID on the other endpoint is no tunnel of it
	}}
	c.EvaluateAll(context.Background(), time.Unix(1_700_000_000, 0))

	expect := func(frames <-chan []byte, teid uint32, peer, local string) {
		t.Helper()
		want, err := endMarkerFrame(teid, netip.MustParseAddr(peer), netip.MustParseAddr(local))
		if err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-frames:
			if !bytes.Equal(got, want) {
				t.Errorf("the relayed End Marker is\n% x\nwant TEID %#x toward %s from %s\n% x", got, teid, peer, local, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("no End Marker was relayed with TEID %#x toward %s", teid, peer)
		}
	}
	expect(n3Frames, 0x77000002, "10.20.30.2", modesN3)    // step 10b: toward the source RAN
	expect(n3Frames, 0x77000003, "198.51.100.77", modesN3) // the forwarding tunnel to the target UPF
	expect(n9Frames, 0x77000012, "198.51.100.1", modesN9)  // N9 transit toward the upstream I-UPF
	select {
	case got := <-n3Frames:
		t.Errorf("an End Marker was relayed where none is owed: % x", got)
	case got := <-n9Frames:
		t.Errorf("an End Marker was relayed where none is owed: % x", got)
	case <-time.After(200 * time.Millisecond):
	}
	if stats := c.Stats(); stats.Markers != 3 || stats.MarkerFailures != 0 {
		t.Errorf("markers sent %d, failed %d, want 3 and 0", stats.Markers, stats.MarkerFailures)
	}

	// The drain delivered each arrival once: the next tick relays nothing.
	c.EvaluateAll(context.Background(), time.Unix(1_700_000_001, 0))
	select {
	case got := <-n3Frames:
		t.Errorf("a drained End Marker was relayed again: % x", got)
	case <-time.After(200 * time.Millisecond):
	}
}
