// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"strconv"
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// TestDROBUIsReadWhereverTheCPFunctionPutsIt mirrors SNDEM's reading (TS 29.244
// 8.2.31): DROBU is the first bit of the same octet, and the flag may sit on the
// message or inside a FAR's forwarding parameters, so both places must find it
// -- and SNDEM's bit must not be mistaken for it.
func TestDROBUIsReadWhereverTheCPFunctionPutsIt(t *testing.T) {
	cases := []struct {
		name string
		ies  []*ie.IE
		want bool
	}{
		{"the flag on the message", []*ie.IE{ie.NewPFCPSMReqFlags(0x01)}, true},
		{"the flag inside an Update FAR's forwarding parameters", []*ie.IE{
			ie.NewUpdateFAR(ie.NewFARID(2),
				ie.NewUpdateForwardingParameters(ie.NewPFCPSMReqFlags(0x01)))}, true},
		{"the flag inside a Create FAR's forwarding parameters", []*ie.IE{
			ie.NewCreateFAR(ie.NewFARID(2),
				ie.NewForwardingParameters(ie.NewPFCPSMReqFlags(0x01)))}, true},
		{"SNDEM alone is not DROBU", []*ie.IE{ie.NewPFCPSMReqFlags(0x02)}, false},
		{"no flag at all", []*ie.IE{ie.NewUpdateFAR(ie.NewFARID(2))}, false},
	}
	for _, tc := range cases {
		if got := drobu(tc.ies); got != tc.want {
			t.Errorf("%s: drobu is %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestADROBUModificationDropsWhatTheFlowHeld is TS 29.244 8.2.31's DROBU
// (7.5.4.1 NOTE 1): the flag asks the UP function to discard every packet the
// PFCP session currently buffers, before the FARs' Apply Action takes effect.
// The modification here would otherwise have released the flow into the new
// forwarding path -- it moves the FAR to FORW -- so DROBU must turn that
// release into a drop rather than let the held packets leave.
func TestADROBUModificationDropsWhatTheFlowHeld(t *testing.T) {
	rec := &recorder{}
	c := New(bufferingConfig(), rec, quietLogger())

	resp := c.Establish(buffEstablishment(0x7107, "10.45.0.7")).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	seid := upFSEID(t, resp)
	flow := ruleCarrying(t, rec.last(), fieldDstIP, []byte{10, 45, 0, 7}).actionID()

	mod := message.NewSessionModificationRequest(0, 0, seid, 7, 0,
		ie.NewPFCPSMReqFlags(0x01),
		ie.NewUpdateFAR(
			ie.NewFARID(2),
			ie.NewApplyAction(applyForw),
			ie.NewUpdateForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceAccess),
				ie.NewOuterHeaderCreation(0x0100, 0x55667788, "10.20.30.2", "", 0, 0, 0),
			),
		))
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification answered cause %d", got)
	}
	if len(rec.released) != 0 {
		t.Errorf("the store was told to release %v, want none: DROBU discards what a flow holds, it does not forward it", rec.released)
	}
	if len(rec.dropped) != 1 {
		t.Fatalf("the store was told to drop %v, want one drop of buf/%d", rec.dropped, flow)
	}
	if got := rec.dropped[0]; got != "buf/"+strconv.FormatUint(uint64(flow), 10) {
		t.Errorf("the drop names %s, want buf/%d", got, flow)
	}
	if stats := c.Stats(); stats.BuffersDropped != 1 {
		t.Errorf("the drop is counted %d times, want 1", stats.BuffersDropped)
	}
}

// TestADROBUWithNothingBufferedIsAccepted pins 8.2.31's "if any": a session
// that holds no packets answers DROBU with the ordinary accepted, not a
// refusal -- there is simply nothing to drop, and no instruction is refused.
func TestADROBUWithNothingBufferedIsAccepted(t *testing.T) {
	rec := &recorder{}
	c := New(bufferingConfig(), rec, quietLogger())

	resp := c.Establish(establishment(0x7108, "10.45.0.8")).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	mod := message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 7, 0,
		ie.NewPFCPSMReqFlags(0x01))
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("a DROBU with nothing buffered answered cause %d, want the ordinary accepted", got)
	}
	if len(rec.dropped) != 0 || len(rec.released) != 0 {
		t.Errorf("the store saw drop %v release %v, want neither", rec.dropped, rec.released)
	}
}
