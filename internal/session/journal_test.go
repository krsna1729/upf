// SPDX-License-Identifier: BSD-3-Clause
package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// checkpointJournal opens a fresh journal for a test and returns it with the
// stamp its run advertises.
func checkpointJournal(t *testing.T, path string) (*Journal, time.Time) {
	t.Helper()
	j, err := OpenJournal(path)
	if err != nil {
		t.Fatalf("opening the checkpoint: %v", err)
	}
	t.Cleanup(func() { j.Close() })
	stamp := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	if err := j.Start(stamp, false); err != nil {
		t.Fatalf("starting the checkpoint: %v", err)
	}
	return j, stamp
}

// TestTheCheckpointReplaysSessions: the journal is the difference between a
// restart that loses every session and one the SMF never notices. A second
// compiler -- the restarted process -- replays it into an empty model before
// its socket opens, and holds what the first one held: the same sessions, the
// same local SEIDs the SMF addresses them by, the same rule keys, and the
// Recovery Time Stamp the SMF was told.
func TestTheCheckpointReplaysSessions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checkpoint")
	j, stamp := checkpointJournal(t, path)

	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	c.Checkpoint(j)

	// Two subscriber sessions, and the first one's downlink PDR moved to
	// another UE address: the replay has to reproduce the model *after* the
	// change, not the one the establishment described.
	resp := c.Establish(establishment(0x9901, "10.45.0.2")).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	seid := upFSEID(t, resp)
	second := c.Establish(establishment(0x9902, "10.45.0.3")).(*message.SessionEstablishmentResponse)
	if got := cause(t, second); got != ie.CauseRequestAccepted {
		t.Fatalf("the second establishment answered cause %d", got)
	}
	if got := cause(t, c.Modify(message.NewSessionModificationRequest(0, 0, seid, 2, 0,
		ie.NewUpdatePDR(ie.NewPDRID(2), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x02, "10.45.0.7", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to assigned 53", "", "", "", 0)),
			ie.NewFARID(2))))); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification answered cause %d", got)
	}
	if got := cause(t, c.Delete(message.NewSessionDeletionRequest(0, 0, upFSEID(t, second), 3, 0))); got != ie.CauseRequestAccepted {
		t.Fatalf("the deletion answered cause %d", got)
	}
	if held := c.Stats().Sessions; held != 1 {
		t.Fatalf("the first run holds %d sessions, want 1", held)
	}
	size, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	// The restart: a new compiler, the same journal, no messages applied by
	// anyone but the replay.
	restarted := &recorder{}
	c2 := New(testConfig(), restarted, quietLogger())
	c2.Checkpoint(j)
	if got := c2.Stats().Sessions; got != 0 {
		t.Fatalf("the restarted compiler starts with %d sessions, want none", got)
	}
	if err := c2.Restore(j); err != nil {
		t.Fatalf("replaying the checkpoint: %v", err)
	}
	if held := c2.Stats().Sessions; held != 1 {
		t.Fatalf("the replay restored %d sessions, want the one the first run held", held)
	}
	// Replaying is not applying: the records are already in the file, so the
	// replay leaves it exactly as it was. (The modifications below are applies,
	// and they do grow it.)
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if after.Size() != size.Size() {
		t.Errorf("the replay grew the journal from %d to %d bytes", size.Size(), after.Size())
	}
	// The SEID is the old one: the SMF addresses the session by it, and a
	// replayed session that answered under a new one would be a session the SMF
	// cannot reach.
	if got := cause(t, c2.Modify(message.NewSessionModificationRequest(0, 0, seid, 4, 0,
		ie.NewUpdateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewUpdateForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore)))))); got != ie.CauseRequestAccepted {
		t.Errorf("a modification addressed to the session's old SEID answered cause %d, want accepted", got)
	}
	// The deleted session is not back, and its retransmitted deletion is
	// answered the way the SMF expects rather than replayed into a session.
	if got := cause(t, c2.Delete(message.NewSessionDeletionRequest(0, 0, upFSEID(t, second), 5, 0))); got != ie.CauseSessionContextNotFound {
		t.Errorf("the deleted session's retransmitted deletion answered cause %d, want session-not-found", got)
	}
	// The replayed model is the one *after* the modification: the old
	// address's rule key is free, so another session may hold it.
	if got := cause(t, c2.Establish(establishment(0x9903, "10.45.0.7"))); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a session for the address the restored session moved to answered cause %d, want a rule failure", got)
	}
	// Replaying is not applying: the journal is exactly what it was, since a
	// record is written when an SMF's message is applied and a replay answers
	// nobody.
	if got, ok := j.Recovery(); !ok || !got.Equal(stamp) {
		t.Errorf("the journal's Recovery Time Stamp is %v (ok=%v), want the %v it started with", got, ok, stamp)
	}
}

// TestTheCheckpointIgnoresATornRecord: a record is written before the SMF is
// answered, so the last line of a journal can be cut short by a crash -- and
// that message is one nobody was answered for, which the SMF retransmits. The
// records before it are the checkpoint; the torn one is not a reason to drop it.
func TestTheCheckpointIgnoresATornRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checkpoint")
	j, _ := checkpointJournal(t, path)
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	c.Checkpoint(j)
	if got := cause(t, c.Establish(establishment(0x9911, "10.45.0.2"))); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	// A half-written record: the beginning of a line, no newline.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"kind":"establish","seid":5,"msg":"AA`); err != nil {
		t.Fatal(err)
	}
	f.Close()

	c2 := New(testConfig(), &recorder{}, quietLogger())
	if err := c2.Restore(j); err != nil {
		t.Fatalf("a torn last record failed the replay: %v", err)
	}
	if held := c2.Stats().Sessions; held != 1 {
		t.Errorf("the replay restored %d sessions, want the 1 the complete records describe", held)
	}
}

// TestTheCheckpointRefusesCorruption: a line that does not parse is not a torn
// tail -- the records after it cannot be trusted either -- so the replay
// refuses the whole file rather than installing half of a run's sessions. The
// caller's answer is a new Recovery Time Stamp and the SMF's own
// re-establishment.
func TestTheCheckpointRefusesCorruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checkpoint")
	j, _ := checkpointJournal(t, path)
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	c.Checkpoint(j)
	if got := cause(t, c.Establish(establishment(0x9921, "10.45.0.2"))); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("not a record\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	c2 := New(testConfig(), &recorder{}, quietLogger())
	if err := c2.Restore(j); err == nil {
		t.Error("a journal with a corrupt line replayed without an error")
	}
}

// TestTheCheckpointStampSurvivesARestart: the stamp is what tells the SMF
// whether this node lost its sessions (TS 29.244 7.4.1). A run that restored
// them advertises the recorded stamp -- Start leaves the file alone -- and a run
// that restored nothing advertises a new one, because a stamp that moved
// *backwards* is worse than one that moved forwards: the SMF would read it as a
// restart it has already seen.
func TestTheCheckpointStampSurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checkpoint")
	j, stamp := checkpointJournal(t, path)
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	c.Checkpoint(j)
	if got := cause(t, c.Establish(establishment(0x9931, "10.45.0.2"))); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}

	restart, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer restart.Close()
	if got, ok := restart.Recovery(); !ok || !got.Equal(stamp) {
		t.Fatalf("the reopened journal's stamp is %v (ok=%v), want %v", got, ok, stamp)
	}
	later := stamp.Add(90 * time.Second)
	if err := restart.Start(later, true); err != nil {
		t.Fatal(err)
	}
	if got, _ := restart.Recovery(); !got.Equal(stamp) {
		t.Errorf("a restoring run rewrote the stamp to %v, want the recorded %v", got, stamp)
	}
	// And a run that restored nothing replaces it, records and all: it
	// advertises a stamp no earlier run used, so the file it leaves behind must
	// begin with that one.
	fresh := stamp.Add(time.Hour)
	if err := restart.Start(fresh, false); err != nil {
		t.Fatal(err)
	}
	if got, ok := restart.Recovery(); !ok || !got.Equal(fresh) {
		t.Errorf("a fresh run's journal reads stamp %v (ok=%v), want %v", got, ok, fresh)
	}
	c2 := New(testConfig(), &recorder{}, quietLogger())
	if err := c2.Restore(restart); err != nil {
		t.Fatalf("replaying after the reset: %v", err)
	}
	if held := c2.Stats().Sessions; held != 0 {
		t.Errorf("a run that restored nothing replayed %d sessions", held)
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), "10.45.0.2") {
		t.Error("the reset journal still describes the sessions it said it had lost")
	}
}

// TestTheAssociationEndingClearsTheCheckpoint: the CP function restarted, so
// its sessions are void (TS 29.244 7.4.1) and the journal must not hand them
// back to a later restart of ours -- the SMF would then re-establish them and
// every establishment would be refused for rules the replayed sessions hold.
func TestTheAssociationEndingClearsTheCheckpoint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checkpoint")
	j, _ := checkpointJournal(t, path)
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	c.Checkpoint(j)
	if got := cause(t, c.Establish(establishment(0x9941, "10.45.0.2"))); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	c.AssociationEnded("CP function restarted (recovery time stamp moved)")
	if held := c.Stats().Sessions; held != 0 {
		t.Fatalf("the association's end left %d sessions, want none", held)
	}
	c2 := New(testConfig(), &recorder{}, quietLogger())
	if err := c2.Restore(j); err != nil {
		t.Fatalf("replaying after the association ended: %v", err)
	}
	if held := c2.Stats().Sessions; held != 0 {
		t.Errorf("a restart after the association ended replayed %d sessions, want none", held)
	}
	// The stamp is kept: this node did not restart, so its Recovery Time Stamp
	// is not a fact that changed.
	if _, ok := j.Recovery(); !ok {
		t.Error("clearing the sessions threw the Recovery Time Stamp away")
	}
}
