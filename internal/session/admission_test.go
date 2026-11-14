// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/krsna1729/upf/internal/bess"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
	"google.golang.org/grpc/codes"
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

func TestSessionCapacityReservesBeforeApplyAndDeletionReturnsRoom(t *testing.T) {
	cfg := testConfig()
	cfg.MaxSessions = 1
	gate := &gatedApply{inner: &recorder{}, entered: make(chan struct{}), release: make(chan struct{})}
	unblock := sync.OnceFunc(func() { close(gate.release) })
	defer unblock()
	c := New(cfg, gate, quietLogger())
	first := make(chan *message.SessionEstablishmentResponse, 1)
	go func() {
		first <- c.Establish(establishment(0xa101, "10.45.0.2")).(*message.SessionEstablishmentResponse)
	}()
	select {
	case <-gate.entered:
	case response := <-first:
		t.Fatalf("first establishment did not reach Apply: %v", response)
	}
	if s := c.Stats(); s.Sessions != 0 || s.ReservedSessions != 1 {
		t.Fatalf("in-flight establishment: %+v", s)
	}
	if got := cause(t, c.Establish(establishment(0xa102, "10.45.0.3"))); got != ie.CauseNoResourcesAvailable {
		t.Fatalf("overlapping establishment at capacity: cause %d", got)
	}
	unblock()
	accepted := <-first
	if got := cause(t, accepted); got != ie.CauseRequestAccepted {
		t.Fatalf("first establishment: cause %d", got)
	}
	if s := c.Stats(); s.Sessions != 1 || s.ReservedSessions != 0 {
		t.Fatalf("committed establishment: %+v", s)
	}
	again := c.Establish(establishment(0xa101, "10.45.0.2")).(*message.SessionEstablishmentResponse)
	if cause(t, again) != ie.CauseRequestAccepted || upFSEID(t, again) != upFSEID(t, accepted) {
		t.Fatal("retransmission at capacity did not preserve the accepted session")
	}
	if got := cause(t, c.Delete(message.NewSessionDeletionRequest(0, 0, upFSEID(t, accepted), 3, 0))); got != ie.CauseRequestAccepted {
		t.Fatalf("deletion at capacity: cause %d", got)
	}
	if got := cause(t, c.Establish(establishment(0xa102, "10.45.0.3"))); got != ie.CauseRequestAccepted {
		t.Fatalf("capacity was not returned after deletion: cause %d", got)
	}
}

func TestSessionCapacityReleasesKnownRefusalsButKeepsUnknownOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		unknown bool
	}{
		{"capacity", &bess.InvalidRequestError{Code: codes.ResourceExhausted}, false},
		{"busy", &bess.BusyError{Attempts: 1}, false},
		{"rejected", &bess.RejectedError{}, false},
		{"unanswered", errors.New("reply lost"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.MaxSessions = 1
			if !tc.unknown {
				cfg.MaxTEIDs = 2
			} // a leaked id prevents recovery
			rec := &recorder{fail: tc.err}
			c := New(cfg, rec, quietLogger())
			now := time.Unix(1700000000, 0)
			c.teids.now = func() time.Time { return now }
			if got := cause(t, c.Establish(establishment(0xa201, "10.45.0.2"))); got == ie.CauseRequestAccepted {
				t.Fatal("failed Apply was answered accepted")
			}
			rec.fail = nil
			now = now.Add(time.Minute) // allow the legitimate F-TEID reuse grace
			if tc.unknown {
				if s := c.Stats(); s.Sessions != 0 || s.ReservedSessions != 1 {
					t.Fatalf("unknown outcome lost its reservation: %+v", s)
				}
				if got := cause(t, c.Establish(establishment(0xa202, "10.45.0.3"))); got != ie.CauseNoResourcesAvailable {
					t.Fatalf("unknown outcome let capacity be reused: cause %d", got)
				}
				if len(rec.txns) != 0 {
					t.Fatal("capacity refusal reached the dataplane")
				}
			} else {
				if got := cause(t, c.Establish(establishment(0xa201, "10.45.0.2"))); got != ie.CauseRequestAccepted {
					t.Fatalf("known refusal leaked capacity or ids: cause %d", got)
				}
			}
		})
	}
}
