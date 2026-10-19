// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"net"
	"testing"

	"github.com/wmnsk/go-pfcp/ie"

	"github.com/krsna1729/upf/internal/bess"
)

// meterOf finds the meter entry a rule's action names, in the direction's own
// meter table. The action is what puts the id on the packet, so reading the
// resource without it would pin an entry and not the enforcement.
func meterOf(t *testing.T, changes []bess.Change, r rule, dir Direction) map[string]any {
	t.Helper()
	meterID, _ := find(t, changes, actionsRes(dir), "id", r.actionID()).Value["meter_id"].(uint32)
	if meterID == 0 {
		t.Fatalf("rule %v names no meter", r.change.Key)
	}
	trtcm, _ := find(t, changes, metersRes(dir), "id", meterID).Value["tr_tcm"].(map[string]any)
	if trtcm == nil {
		t.Fatalf("meter %d has no two-rate profile", meterID)
	}
	return trtcm
}

// uplinkRule is the session's one uplink rule, the PDR the fixtures below send.
func uplinkRule(t *testing.T, changes []bess.Change, qfi byte) rule {
	t.Helper()
	mask := byte(0xff)
	if qfi == 0 {
		// A PDR that names no QFI leaves the field unmasked, so its rule is the
		// one whose QFI mask is zero.
		mask = 0x00
	}
	r, ok := ruleWithQFI(changes, qfiField(t), []byte{qfi}, []byte{mask})
	if !ok {
		t.Fatalf("no uplink rule keyed on QFI %d", qfi)
	}
	return r
}

// TestAQERsGBRIsTheMetersCommittedRate is finding 6's GBR half: a QER carries
// both a guaranteed rate (8.2.7) and a ceiling (8.2.8), and a meter that
// polices only the ceiling throws the guarantee away. The committed rate is the
// GBR and the peak is the MBR, so the band between them is yellow -- and the
// graph decides what that band means (deploy/upf.yaml forwards it).
func TestAQERsGBRIsTheMetersCommittedRate(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	req := establishment(0x9201, "10.45.0.9")
	req.CreatePDR = []*ie.IE{flowPDR(1, 100, "10.45.0.9", 0x11223344, 0, 1)}
	req.CreateQER = []*ie.IE{ie.NewCreateQER(
		ie.NewQERID(1), ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
		ie.NewMBR(1000, 2000), ie.NewGBR(500, 1000))}
	if got := cause(t, c.Establish(req)); got != ie.CauseRequestAccepted {
		t.Fatalf("a QER with a GBR and an MBR answered cause %d", got)
	}
	trtcm := meterOf(t, rec.last(), uplinkRule(t, rec.last(), 0), testConfig().Up)
	// kbit/s -> bytes/s, the unit the MBR and GBR IEs share (uint40).
	if got, want := trtcm["committed_rate"], uint64(500*1000/8); got != want {
		t.Errorf("the committed rate is %v, want the GBR (%d bytes/s)", got, want)
	}
	if got, want := trtcm["peak_rate"], uint64(1000*1000/8); got != want {
		t.Errorf("the peak rate is %v, want the MBR (%d bytes/s)", got, want)
	}
}

// TestAQERsAveragingWindowIsTheMetersBurst: 8.2.115 says the rates are
// calculated over a duration the SMF names in milliseconds. The meter's burst
// is that window -- what may arrive at once before the rate is judged -- and
// without the IE the tenth of a second this tree always used stands.
func TestAQERsAveragingWindowIsTheMetersBurst(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra *ie.IE
		burst uint64
	}{
		{"no window: this UP's tenth of a second", nil, 1000 * 1000 / 8 / 10},
		{"the SMF's 200 ms window", ie.NewAveragingWindow(200), 1000 * 1000 / 8 / 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{}
			c := New(testConfig(), rec, quietLogger())
			req := establishment(0x9202, "10.45.0.9")
			req.CreatePDR = []*ie.IE{flowPDR(1, 100, "10.45.0.9", 0x11223344, 0, 1)}
			qer := ie.NewCreateQER(ie.NewQERID(1), ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
				ie.NewMBR(1000, 2000))
			if tc.extra != nil {
				qer = ie.NewCreateQER(ie.NewQERID(1), ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
					ie.NewMBR(1000, 2000), tc.extra)
			}
			req.CreateQER = []*ie.IE{qer}
			if got := cause(t, c.Establish(req)); got != ie.CauseRequestAccepted {
				t.Fatalf("the establishment answered cause %d", got)
			}
			trtcm := meterOf(t, rec.last(), uplinkRule(t, rec.last(), 0), testConfig().Up)
			if got := trtcm["peak_burst"]; got != tc.burst {
				t.Errorf("the peak burst is %v, want the rate over the window (%d bytes)", got, tc.burst)
			}
		})
	}
}

// TestAGBRAboveTheMBRIsRefused: a guarantee above the ceiling is not a policy
// any two-rate meter holds -- the module refuses such a profile outright -- so
// the session is refused with a cause rather than written and then failing the
// transaction it was written in.
func TestAGBRAboveTheMBRIsRefused(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	req := establishment(0x9203, "10.45.0.9")
	req.CreatePDR = []*ie.IE{flowPDR(1, 100, "10.45.0.9", 0x11223344, 0, 1)}
	req.CreateQER = []*ie.IE{ie.NewCreateQER(
		ie.NewQERID(1), ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
		ie.NewMBR(1000, 2000), ie.NewGBR(2000, 1000))}
	if got := cause(t, c.Establish(req)); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a QER whose GBR is above its MBR answered cause %d, want 73", got)
	}
	if len(rec.txns) != 0 {
		t.Error("the refused session wrote to the dataplane")
	}
}

// TestAPDRWithSeveralRateBearingQERsEnforcesTheSharedOne is finding 6's
// combination half, within what one meter per rule can hold: a PDR naming two
// QERs with rates is policed by the session's shared one -- the QER the most
// PDRs name, which is how 5.2.1 describes the session's own rate -- and not by
// whichever the SMF listed last, a choice no deployment can predict.
func TestAPDRWithSeveralRateBearingQERsEnforcesTheSharedOne(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	req := establishment(0x9204, "10.45.0.9")
	// Two flows of the session's aggregate QER and one flow of its own QER:
	// QER 1 is the one the session shares. The flow QER is listed last, which
	// is what the compiler used to enforce.
	req.CreatePDR = []*ie.IE{
		flowPDR(1, 200, "10.45.0.9", 0x11223344, 0, 1),
		flowPDR(2, 150, "10.45.0.9", 0x11223344, 5, 1),
		// One flow naming both QERs: the SMF's order puts the flow QER last.
		ie.NewCreatePDR(ie.NewPDRID(3), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, 0x11223344, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.9", "", 0, 0),
				ie.NewQFI(9)),
			ie.NewFARID(1), ie.NewQERID(1), ie.NewQERID(2)),
	}
	req.CreateQER = []*ie.IE{
		ie.NewCreateQER(ie.NewQERID(1), ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
			ie.NewMBR(1000, 2000)),
		ie.NewCreateQER(ie.NewQERID(2), ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
			ie.NewMBR(3000, 4000)),
	}
	if got := cause(t, c.Establish(req)); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	up := testConfig().Up
	meterID := func(r rule) uint32 {
		v, _ := find(t, rec.last(), actionsRes(up), "id", r.actionID()).Value["meter_id"].(uint32)
		return v
	}
	peak := func(id uint32) uint64 {
		trtcm, _ := find(t, rec.last(), metersRes(up), "id", id).Value["tr_tcm"].(map[string]any)
		v, _ := trtcm["peak_rate"].(uint64)
		return v
	}
	// Both flows that share QER 1 carry the same meter, and it is QER 1's rate.
	first, second := meterID(uplinkRule(t, rec.last(), 0)), meterID(uplinkRule(t, rec.last(), 5))
	if first == 0 || first != second {
		t.Fatalf("the session's shared flows name meters %d and %d, want the same one", first, second)
	}
	if got, want := peak(first), uint64(1000*1000/8); got != want {
		t.Errorf("the shared meter's peak is %d, want QER 1's MBR (%d)", got, want)
	}
	// The flow that named both is policed by the session's meter, not by the
	// flow QER listed after it.
	if third := meterID(uplinkRule(t, rec.last(), 9)); third != first {
		t.Errorf("the flow naming both QERs names meter %d, want the shared one (%d)", third, first)
	}
}

// TestAQERThatCapsOneDirectionWritesOneMeter: an MBR whose field is zero caps
// nothing in that direction, and no meter profile holds a zero rate (the module
// refuses one). The entry is not written, and -- the point -- the establishment
// is accepted rather than failing on the dataplane's refusal.
func TestAQERThatCapsOneDirectionWritesOneMeter(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	req := establishment(0x9205, "10.45.0.9")
	req.CreatePDR = []*ie.IE{flowPDR(1, 100, "10.45.0.9", 0x11223344, 0, 1)}
	req.CreateQER = []*ie.IE{ie.NewCreateQER(
		ie.NewQERID(1), ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
		ie.NewMBR(0, 2000))}
	if got := cause(t, c.Establish(req)); got != ie.CauseRequestAccepted {
		t.Fatalf("a QER capping only the downlink answered cause %d", got)
	}
	for _, ch := range rec.last() {
		if ch.Resource == metersRes(testConfig().Up) {
			t.Errorf("the uplink meter table was written (%v) for a QER that caps nothing uplink", ch.Value)
		}
	}
	written := false
	for _, ch := range rec.last() {
		if ch.Resource == metersRes(testConfig().Down) {
			written = true
		}
	}
	if !written {
		t.Error("the downlink meter was not written for a QER that caps it")
	}
}
