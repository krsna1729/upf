// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"errors"
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// UG-R10 as #117 left it: -max-pdrs bounded only the PDRs, while the merge
// takes a slab slot, store blobs and a copied snapshot entry for every FAR,
// QER, URR, BAR and MAR the peer adds. -max-records caps each kind the same
// way, at the same point: before the merge and before the snapshot.

// An establishment over the record cap is refused before the merge allocates
// the model, and no session is left behind.
func TestAnEstablishmentBeyondTheRecordCapIsRefused(t *testing.T) {
	cfg := testConfig()
	cfg.MaxRecords = 1
	c := New(cfg, &recorder{}, quietLogger())
	resp := c.Establish(establishment(0x7b01, "10.45.0.11")).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseNoResourcesAvailable {
		t.Fatalf("a two-FAR establishment under a one-FAR cap answered cause %d, want %d",
			got, ie.CauseNoResourcesAvailable)
	}
	if n := len(c.sessions); n != 0 {
		t.Errorf("the refused establishment left %d sessions", n)
	}
}

// A modification that would grow a session's FARs past the cap is refused
// before the snapshot stages the model: the slab holds what it held, the
// session owns no copy of its model, and the dataplane was asked for nothing.
// #117's PDR-cap test would pass with a refusal anywhere; this one pins the
// point of the refusal, which is the only place that keeps a peer-chosen
// record count from costing a deep copy per modify.
func TestAGrowingFARBeyondTheRecordCapIsRefusedBeforeTheSnapshot(t *testing.T) {
	cfg := testConfig()
	cfg.MaxRecords = 2
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())
	resp := c.Establish(establishmentWithFTEID(0x7b02, "10.45.0.12", 0x01020304)).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	c.mu.Lock()
	liveBefore, segsBefore, copiesBefore := c.recs.live(), c.recs.segments(), 0
	for _, s := range c.sessions {
		copiesBefore = int(s.copies)
	}
	c.mu.Unlock()
	appliesBefore := len(rec.txns)

	mod := message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 2, 0,
		ie.NewCreateFAR(ie.NewFARID(3), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
	)
	if got := cause(t, c.Modify(mod)); got != ie.CauseNoResourcesAvailable {
		t.Fatalf("the third FAR answered cause %d, want %d", got, ie.CauseNoResourcesAvailable)
	}

	c.mu.Lock()
	liveAfter, segsAfter := c.recs.live(), c.recs.segments()
	copiesAfter, fars := 0, 0
	for _, s := range c.sessions {
		copiesAfter, fars = int(s.copies), s.FARs().len()
	}
	c.mu.Unlock()
	if liveAfter != liveBefore {
		t.Errorf("the refused modification holds %v slab records, want the %v it held before",
			liveAfter, liveBefore)
	}
	if segsAfter != segsBefore {
		t.Errorf("the refused modification grew the slab from %d segments to %d", segsBefore, segsAfter)
	}
	if copiesAfter != copiesBefore {
		t.Errorf("the refused modification left the session with %d model copies, want %d",
			copiesAfter, copiesBefore)
	}
	if fars != 2 {
		t.Errorf("the refused modification left %d FARs, want the session's 2", fars)
	}
	if got := len(rec.txns); got != appliesBefore {
		t.Errorf("the refused modification applied %d transactions, want none", got-appliesBefore)
	}
}

// A URR-only modification cannot grow past the other-record cap.
func TestGrowingURRsPastTheRecordCapIsRefused(t *testing.T) {
	cfg := testConfig()
	cfg.MaxRecords = 2
	c := New(cfg, &recorder{}, quietLogger())
	resp := c.Establish(establishmentWithFTEID(0x7b03, "10.45.0.13", 0x01020304)).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	seid := upFSEID(t, resp)
	// One more URR than the cap allows.
	mod := message.NewSessionModificationRequest(0, 0, seid, 2, 0,
		quotaURR(7, 100), quotaURR(8, 100), quotaURR(9, 100),
	)
	if got := cause(t, c.Modify(mod)); got != ie.CauseNoResourcesAvailable {
		t.Fatalf("the third URR answered cause %d, want %d", got, ie.CauseNoResourcesAvailable)
	}
	c.mu.Lock()
	var urrs int
	for _, s := range c.sessions {
		urrs = s.URRs().len()
	}
	c.mu.Unlock()
	if urrs != 0 {
		t.Errorf("the refused modification left %d URRs, want none", urrs)
	}
	// Restating what the session holds is not growth.
	restate := message.NewSessionModificationRequest(0, 0, seid, 3, 0,
		ie.NewUpdateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
		ie.NewUpdateFAR(ie.NewFARID(2), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceAccess),
				ie.NewOuterHeaderCreation(0x0100, 0x11223344, "10.20.30.2", "", 0, 0, 0))),
	)
	if got := cause(t, c.Modify(restate)); got != ie.CauseRequestAccepted {
		t.Fatalf("restating the capped FARs answered cause %d, want %d",
			got, ie.CauseRequestAccepted)
	}
}

// A removed QER stays the session's -- record, meter id, and a snapshot copy
// -- until the transaction that erases its records lands, so it counts
// against the QER cap until then: a session whose modifications keep failing
// cannot accumulate a removed history that every later modify deep-copies.
func TestTheRecordCapBoundsTheRemovedQERHistory(t *testing.T) {
	cfg := testConfig()
	cfg.MaxRecords = 3
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())
	resp := c.Establish(establishmentWithFTEID(0x7b04, "10.45.0.14", 0x01020304)).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	seid := upFSEID(t, resp)
	rec.fail = errors.New("the dataplane did not answer")
	refused := 0
	for i, qid := range []uint32{2, 3, 4, 5} {
		mod := message.NewSessionModificationRequest(0, 0, seid, uint32(i+2), 0,
			ie.NewRemoveQER(ie.NewQERID(uint32(i+1))),
			ie.NewCreateQER(ie.NewQERID(qid), ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
				ie.NewMBR(1000, 2000)),
		)
		got := cause(t, c.Modify(mod))
		if got == ie.CauseNoResourcesAvailable {
			refused++
			continue
		}
		if got != ie.CauseRequestRejected {
			t.Fatalf("modification %d answered %d, want the unknown outcome", i+2, got)
		}
		if refused != 0 {
			t.Fatalf("modification %d was accepted after one was refused by the cap", i+2)
		}
	}
	if refused == 0 {
		t.Fatal("no modification of the removed-QER history was refused by the record cap")
	}
	c.mu.Lock()
	var liveQERs, removed, copies int
	for _, s := range c.sessions {
		liveQERs, removed, copies = s.QERs().len(), len(s.rare().removedQERs), int(s.copies)
	}
	c.mu.Unlock()
	if liveQERs+removed > int(cfg.MaxRecords) {
		t.Errorf("the session owns %d live and %d removed QERs, over the cap of %d",
			liveQERs, removed, cfg.MaxRecords)
	}
	if copies != 0 {
		t.Errorf("the session still holds %d model copies", copies)
	}
}

// The MARs a message removes wait in the pending list for the same reason
// the removed QERs do, so they count against the cap until settle frees them.
func TestTheRecordCapBoundsTheRemovedMARHistory(t *testing.T) {
	cfg := marConfig()
	cfg.MaxRecords = 4
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())
	resp := c.Establish(marEstablishment(0x7b05, "10.45.0.15")).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	seid := upFSEID(t, resp)
	rec.fail = errors.New("the dataplane did not answer")
	// Every modification leaves one live MAR and one pending removed one
	// behind, because its transaction never landed.
	refused := 0
	for i, id := range []uint16{8, 9, 10, 11} {
		mod := message.NewSessionModificationRequest(0, 0, seid, uint32(i+2), 0,
			ie.NewRemoveMAR(ie.NewMARID(uint16(i+7))),
			ie.NewCreateMAR(
				ie.NewMARID(id),
				ie.NewSteeringFunctionality(ie.SteeringFunctionalityATSSSLL),
				ie.NewSteeringMode(ie.SteeringModeActiveStandby),
				ie.NewTGPPAccessForwardingActionInformation(
					ie.NewFARID(2), ie.NewPriority(ie.PriorityActive)),
				ie.NewNonTGPPAccessForwardingActionInformation(
					ie.NewFARID(3), ie.NewPriority(ie.PriorityStandby)),
			),
			ie.NewUpdatePDR(ie.NewPDRID(2), ie.NewMARID(id)),
		)
		got := cause(t, c.Modify(mod))
		if got == ie.CauseNoResourcesAvailable {
			refused++
			continue
		}
		if got != ie.CauseRequestRejected {
			t.Fatalf("modification %d answered %d, want the unknown outcome", i+2, got)
		}
		if refused != 0 {
			t.Fatalf("modification %d was accepted after one was refused by the cap", i+2)
		}
	}
	if refused == 0 {
		t.Fatal("no modification of the removed-MAR history was refused by the record cap")
	}
	c.mu.Lock()
	var liveMARs, pendingMARs int
	for _, s := range c.sessions {
		liveMARs, pendingMARs = len(s.rare().MARs), len(s.pending.removedPolicies())
	}
	c.mu.Unlock()
	if liveMARs+pendingMARs > int(cfg.MaxRecords) {
		t.Errorf("the session owns %d live and %d removed MARs, over the cap of %d",
			liveMARs, pendingMARs, cfg.MaxRecords)
	}
}

// A session that already holds more records than the cap (one restored from a
// checkpoint written before the cap was lowered) may still change, so long as
// the change does not grow a kind: it can be modified down.
func TestASessionOverTheRecordCapMayShrink(t *testing.T) {
	cfg := testConfig()
	c := New(cfg, &recorder{}, quietLogger())
	resp := c.Establish(establishmentWithFTEID(0x7b06, "10.45.0.16", 0x01020304)).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	cfg.MaxRecords = 1
	c.cfg.MaxRecords = 1
	seid := upFSEID(t, resp)
	mod := message.NewSessionModificationRequest(0, 0, seid, 2, 0,
		ie.NewRemoveFAR(ie.NewFARID(2)),
		ie.NewUpdatePDR(ie.NewPDRID(2), ie.NewFARID(1)),
	)
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("shrinking a session over the record cap answered cause %d, want %d",
			got, ie.CauseRequestAccepted)
	}
	c.mu.Lock()
	var fars int
	for _, s := range c.sessions {
		fars = s.FARs().len()
	}
	c.mu.Unlock()
	if fars != 1 {
		t.Errorf("the session holds %d FARs after the removal, want 1", fars)
	}
	// And it may not grow again.
	grow := message.NewSessionModificationRequest(0, 0, seid, 3, 0,
		ie.NewCreateFAR(ie.NewFARID(4), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
		ie.NewUpdatePDR(ie.NewPDRID(2), ie.NewFARID(4)),
	)
	if got := cause(t, c.Modify(grow)); got != ie.CauseNoResourcesAvailable {
		t.Fatalf("growing a session over the record cap answered cause %d, want %d",
			got, ie.CauseNoResourcesAvailable)
	}
}
