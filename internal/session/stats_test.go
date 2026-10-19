// SPDX-License-Identifier: BSD-3-Clause
package session

import (
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// TestStatsCountWhatTheSMFAsked: the counters are the SMF's own view of this
// node -- what it asked for and what it was told -- so a request that is
// answered twice (a retransmission) is one establishment, and a deletion that
// finds nothing to delete is neither a deletion nor a refusal.
func TestStatsCountWhatTheSMFAsked(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	if got := c.Stats(); got != (StatsSnapshot{}) {
		t.Errorf("a fresh compiler reports %+v, want every counter at zero", got)
	}

	est := establishmentWithFTEID(1, "10.45.0.2", 0x11223344)
	resp := c.Establish(est).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	if got := c.Stats(); got.Sessions != 1 || got.Established != 1 {
		t.Errorf("after one establishment the counters are %+v, want one session and one establishment", got)
	}

	// The same request again: the answer repeats what the SMF already had, so
	// the session is still one and no second establishment is counted.
	if got := cause(t, c.Establish(est)); got != ie.CauseRequestAccepted {
		t.Errorf("the retransmitted establishment answered cause %d", got)
	}
	if got := c.Stats(); got.Sessions != 1 || got.Established != 1 || got.Refused != 0 {
		t.Errorf("after a retransmission the counters are %+v, want them unchanged", got)
	}

	if got := cause(t, c.Modify(message.NewSessionModificationRequest(0, 0, 1, 2, 0,
		ie.NewFSEID(1, nil, nil),
		ie.NewUpdateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewUpdateForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore)))))); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification answered cause %d", got)
	}
	if got := c.Stats(); got.Modified != 1 {
		t.Errorf("after one modification the counters are %+v, want one", got)
	}

	// A refusal: a port range is a rule the classifier cannot carry.
	if got := cause(t, c.Establish(message.NewSessionEstablishmentRequest(0, 0, 2, 3, 0,
		ie.NewFSEID(2, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to assigned 1000-2000", "", "", "", 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess)))))); got != ie.CauseRuleCreationModificationFailure {
		t.Fatalf("the refused establishment answered cause %d", got)
	}
	if got := c.Stats(); got.Refused != 1 || got.Sessions != 1 {
		t.Errorf("after one refusal the counters are %+v, want one refusal and one session", got)
	}

	del := message.NewSessionDeletionRequest(0, 0, upFSEID(t, resp), 4, 0)
	if got := cause(t, c.Delete(del)); got != ie.CauseRequestAccepted {
		t.Fatalf("the deletion answered cause %d", got)
	}
	// The same deletion again: the session is already gone, which is what the
	// request asked for, so it is neither a deletion nor a refusal.
	if got := cause(t, c.Delete(del)); got != ie.CauseSessionContextNotFound {
		t.Fatalf("the retransmitted deletion answered cause %d", got)
	}
	want := StatsSnapshot{Established: 1, Modified: 1, Deleted: 1, Refused: 1}
	if got := c.Stats(); got != want {
		t.Errorf("the counters are %+v, want %+v", got, want)
	}
}
