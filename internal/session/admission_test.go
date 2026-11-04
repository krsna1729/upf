// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"path/filepath"
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// TestANodeWithNoRoomRefusesOnlyNewSessions: Config.Admit is asked about new
// sessions only. With no room an establishment is answered cause 75 before
// anything reaches the dataplane, while what the SMF already has keeps
// working: a retransmission is answered as before, a modification and a
// deletion are applied, and a restart's replay puts every session back -- a
// refused replay would be a session the SMF holds and the UPF does not.
func TestANodeWithNoRoomRefusesOnlyNewSessions(t *testing.T) {
	room := true
	cfg := testConfig()
	cfg.Admit = func() bool { return room }
	j, _ := checkpointJournal(t, filepath.Join(t.TempDir(), "checkpoint"))
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())
	c.Checkpoint(j)

	first := c.Establish(establishment(0xa001, "10.45.0.2")).(*message.SessionEstablishmentResponse)
	if got := cause(t, first); got != ie.CauseRequestAccepted {
		t.Fatalf("the first establishment answered cause %d", got)
	}
	seid := upFSEID(t, first)

	room = false
	written := len(rec.txns)
	if got := cause(t, c.Establish(establishment(0xa002, "10.45.0.3")).(*message.SessionEstablishmentResponse)); got != ie.CauseNoResourcesAvailable {
		t.Fatalf("a new session with no room answered cause %d, want %d", got, ie.CauseNoResourcesAvailable)
	}
	if len(rec.txns) != written {
		t.Errorf("the refused session wrote %d transactions to the dataplane", len(rec.txns)-written)
	}
	if s := c.Stats(); s.Sessions != 1 || s.Refused != 1 || s.Unadmitted != 1 {
		t.Errorf("after one refusal: %d sessions, %d refused, %d unadmitted; want 1, 1, 1", s.Sessions, s.Refused, s.Unadmitted)
	}

	again := c.Establish(establishment(0xa001, "10.45.0.2")).(*message.SessionEstablishmentResponse)
	if got := cause(t, again); got != ie.CauseRequestAccepted {
		t.Fatalf("a retransmitted establishment with no room answered cause %d", got)
	}
	if got := upFSEID(t, again); got != seid {
		t.Errorf("the retransmission answered SEID %#x, want the session's %#x", got, seid)
	}
	if got := cause(t, c.Modify(message.NewSessionModificationRequest(0, 0, seid, 2, 0,
		ie.NewUpdateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewUpdateForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore)))))); got != ie.CauseRequestAccepted {
		t.Fatalf("a modification with no room answered cause %d", got)
	}

	restarted := New(cfg, &recorder{}, quietLogger())
	restarted.Checkpoint(j)
	if err := restarted.Restore(j); err != nil {
		t.Fatalf("replaying the checkpoint with no room: %v", err)
	}
	if s := restarted.Stats(); s.Sessions != 1 || s.Unadmitted != 0 {
		t.Errorf("the replay with no room holds %d sessions (%d unadmitted), want 1 (0)", s.Sessions, s.Unadmitted)
	}

	if got := cause(t, c.Delete(message.NewSessionDeletionRequest(0, 0, seid, 3, 0))); got != ie.CauseRequestAccepted {
		t.Fatalf("a deletion with no room answered cause %d", got)
	}
	room = true
	if got := cause(t, c.Establish(establishment(0xa002, "10.45.0.3")).(*message.SessionEstablishmentResponse)); got != ie.CauseRequestAccepted {
		t.Fatalf("the refused session, sent again with room, answered cause %d", got)
	}
}
