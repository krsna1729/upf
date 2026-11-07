// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"context"
	"net"
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/bess"
)

// A modification the merge refuses must leave the session as the SMF last saw
// it. Left half-applied -- the refused PDR in the model, naming a URR the
// session lacks -- it failed every later message of the session the same way:
// the SMF's retry, and the follow-up it sends after any refusal.

func namesUnknownURR(seq uint32, seid uint64, extra ...*ie.IE) *message.SessionModificationRequest {
	ies := append([]*ie.IE{
		ie.NewUpdatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, 0x1000, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.2", "", 0, 0)),
			ie.NewFARID(1), ie.NewURRID(55)),
	}, extra...)
	return message.NewSessionModificationRequest(0, 0, seid, seq, 0, ies...)
}

func TestARefusedModificationLeavesTheSessionAsItWas(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(urrEstablishment(0x3071, 7, quotaURR(7, 1<<30))).(*message.SessionEstablishmentResponse)
	seid := upFSEID(t, resp)

	if got := cause(t, c.Modify(namesUnknownURR(2, seid))); got != ie.CauseRuleCreationModificationFailure {
		t.Fatalf("a PDR naming URR 55 answered cause %d, want a rule failure", got)
	}
	if ids := sessionOf(t, c, seid).PDRs.at(1).urrIDs; len(ids) != 1 || ids[0] != 7 {
		t.Errorf("the refused update left PDR 1 naming URRs %v, want its own 7", ids)
	}
	benign := message.NewSessionModificationRequest(0, 0, seid, 3, 0,
		ie.NewUpdateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewUpdateForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))))
	if got := cause(t, c.Modify(benign)); got != ie.CauseRequestAccepted {
		t.Errorf("the next modification answered cause %d, want it accepted: the refusal left nothing behind", got)
	}
	if got := cause(t, c.Delete(message.NewSessionDeletionRequest(0, 0, seid, 4, 0))); got != ie.CauseRequestAccepted {
		t.Errorf("the deletion answered cause %d", got)
	}
}

func TestARefusedModificationGivesBackTheMetersAndTEIDsItTook(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(urrEstablishment(0x3072, 7, quotaURR(7, 1<<30))).(*message.SessionEstablishmentResponse)
	seid := upFSEID(t, resp)

	c.mu.Lock()
	metersBefore := len(c.meters.freed)
	c.mu.Unlock()
	// A new QER with a rate (the merge allocates its meters) and a second
	// uplink PDR pinned to an F-TEID of its own, in a request the merge refuses
	// for the first PDR's URR.
	req := namesUnknownURR(2, seid,
		ie.NewCreateQER(ie.NewQERID(9), ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen), ie.NewMBR(1000, 2000)),
		ie.NewCreatePDR(ie.NewPDRID(5), ie.NewPrecedence(20),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, 0x4242, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.2", "", 0, 0),
				ie.NewSDFFilter(udp53, "", "", "", 0)),
			ie.NewFARID(1), ie.NewQERID(9)))
	if got := cause(t, c.Modify(req)); got != ie.CauseRuleCreationModificationFailure {
		t.Fatalf("cause %d, want a rule failure", got)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fteidTEIDKeys[0x4242] != 0 {
		t.Error("the refused request's exact F-TEID key was not released")
	}
	if got := len(c.meters.freed) - metersBefore; got != 2 {
		t.Errorf("%d meters were given back, want the refused QER's uplink and downlink pair", got)
	}
	if s := c.sessions[seid]; s.QERs.at(9) != nil || s.PDRs.at(5) != nil {
		t.Error("the refused request's QER or PDR is in the model")
	}
}

// An unanswered delta may or may not have committed. Even a definite refusal
// of its successor cannot make the uncertain baseline safe for another delta.
func TestUnansweredModificationRestatesResourcesUntilAWriteCompletes(t *testing.T) {
	for _, module := range []string{"", "upf"} {
		t.Run("appliance="+module, func(t *testing.T) {
			cfg := testConfig()
			cfg.Appliance = module
			rec := &recorder{}
			c := New(cfg, rec, quietLogger())
			resp := c.Establish(establishment(0xa101, "10.45.0.9")).(*message.SessionEstablishmentResponse)
			if got := cause(t, resp); got != ie.CauseRequestAccepted {
				t.Fatalf("establishment cause %d", got)
			}
			mod := message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 2, 0,
				ie.NewUpdateFAR(ie.NewFARID(2),
					ie.NewUpdateForwardingParameters(
						ie.NewOuterHeaderCreation(0x0100, 0x55667788, "10.20.30.9", "", 0, 0, 0))))
			rec.fail = context.DeadlineExceeded
			if got := cause(t, c.Modify(mod)); got == ie.CauseRequestAccepted {
				t.Fatal("an unanswered modification was accepted")
			}
			rec.fail = &bess.RejectedError{}
			if got := cause(t, c.Modify(mod)); got == ie.CauseRequestAccepted {
				t.Fatal("a rejected reconciliation was accepted")
			}
			rec.fail = nil
			if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
				t.Fatalf("reconciliation cause %d", got)
			}
			for _, table := range []Table{PDRUplink, PDRDownlink} {
				if got := len(changesFor(rec.last(), c.res(table))); got != 1 {
					t.Errorf("reconciliation wrote %d %s records, want one", got, table)
				}
			}
			completed := len(rec.txns)
			if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
				t.Fatalf("subsequent modification cause %d", got)
			}
			if len(rec.txns) != completed {
				t.Error("an identical request after a completed reconciliation sent another transaction")
			}
		})
	}
}

// Exercise the schedule where usage enforcement commits after the control
// request took its rollback snapshot, but before it merges a new quota. The
// forwarding result equals the snapshot, not the now-dropping dataplane.
func TestQuotaGrantAfterInterleavedEnforcementReopensTheClassifier(t *testing.T) {
	c, rec, seid, set := measured(t, 0xa104, 0, 0)
	s := sessionOf(t, c, seid)
	c.mu.Lock()
	before := s.snapshot()
	c.mu.Unlock()
	set(10000+(1<<30), 200)
	if reports := evaluate(t, c, seid); len(reports) != 1 {
		t.Fatalf("quota enforcement produced %d reports, want one", len(reports))
	}
	dropped := ruleCarrying(t, rec.last(), fieldSrcIP, []byte{10, 45, 0, 2})
	if dropped.gate() != dropGate {
		t.Fatal("the interleaved quota enforcement did not stop traffic")
	}
	_, _, _, _, urrs, _, err := parseCreate([]*ie.IE{
		ie.NewUpdateURR(ie.NewURRID(7), ie.NewVolumeQuota(0x01, 2<<30, 0, 0)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.merge(s, nil, nil, nil, nil, urrs, nil, removals{}); err != nil {
		t.Fatal(err)
	}
	changes, _, err := c.compileModel(s, &before, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.apply(context.Background(), s, changes); err != nil {
		t.Fatal(err)
	}
	c.settle(s)
	forwarding := ruleCarrying(t, rec.last(), fieldSrcIP, []byte{10, 45, 0, 2})
	if forwarding.change.Value == nil || forwarding.gate() == dropGate {
		t.Fatal("the granted quota left the dataplane classifier dropping")
	}
}

// An older resource-neutral delta completing after an overlapping unanswered
// full write cannot certify that the dataplane now matches the model.
func TestAnOlderDeltaCannotClearOverlappingUnknownCompletion(t *testing.T) {
	c, rec, seid, _ := measured(t, 0xa105, 0, 0)
	s := sessionOf(t, c, seid)
	c.mu.Lock()
	before := s.snapshot()
	c.mu.Unlock()
	older, _, err := c.compileModel(s, &before, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(older.resources) != 0 {
		t.Fatal("the unchanged model did not produce a resource-neutral delta")
	}
	newer, _, err := c.compile(s)
	if err != nil {
		t.Fatal(err)
	}
	rec.fail = context.DeadlineExceeded
	if err := c.apply(context.Background(), s, newer); err == nil {
		t.Fatal("the newer write unexpectedly completed")
	}
	rec.fail = nil
	if err := c.apply(context.Background(), s, older); err != nil {
		t.Fatal(err)
	}
	// Only a new isolated write can reconcile the unknown result. A quota
	// update that leaves forwarding unchanged otherwise needs no classifier.
	if got := cause(t, c.Modify(query(seid, 2,
		ie.NewUpdateURR(ie.NewURRID(7), ie.NewVolumeQuota(0x01, 2<<30, 0, 0))))); got != ie.CauseRequestAccepted {
		t.Fatalf("reconciliation cause %d", got)
	}
	if got := len(changesFor(rec.last(), c.res(PDRUplink))); got != 1 {
		t.Fatalf("reconciliation wrote %d classifiers, want the complete model", got)
	}
}
