// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"context"
	"strings"
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/bess"
)

func sessionMajorConfig(layout SessionLayout) Config {
	cfg := testConfig()
	cfg.Appliance = "upf"
	cfg.Sessions = &layout
	return cfg
}

// sessionEntry is the transaction's one "upf/sessions" change, and fails when
// the transaction also writes a table the entry replaces.
func sessionEntry(t *testing.T, changes []bess.Change) bess.Change {
	t.Helper()
	var entry []bess.Change
	for _, ch := range changes {
		switch ch.Resource {
		case "upf/sessions":
			entry = append(entry, ch)
		case "upf/fteids", "upf/pdr_ul", "upf/pdr_dl", "upf/meters",
			"upf/counters_ul", "upf/counters_dl", "upf/tunnels":
			t.Errorf("the transaction writes %s, which the session entry replaces", ch.Resource)
		}
	}
	if len(entry) != 1 {
		t.Fatalf("the transaction holds %d upf/sessions changes, want one", len(entry))
	}
	return entry[0]
}

// entryAction is the action the entry's first rule of a direction names.
func entryAction(t *testing.T, value bess.Payload, downlink bool) SessionAction {
	t.Helper()
	entry := payload[SessionEntry](value)
	actions, pdrs := entry.Actions, entry.PDRs
	for _, p := range pdrs {
		if p.Downlink != downlink {
			continue
		}
		pos := p.Action
		if pos == 0 || int(pos) > len(actions) {
			t.Fatalf("a rule names action %d of %d", pos, len(actions))
		}
		return actions[pos-1]
	}
	t.Fatalf("the entry has no downlink=%v rule", downlink)
	return SessionAction{}
}

// TestSessionMajorWritesOneEntryPerSession: under -target session-major an
// establishment, a modification and a deletion each reach the dataplane as
// one "<module>/sessions" change for the session -- the rules, F-TEID,
// meters, counters and tunnel inside it -- with the session's id and its
// actions' ids kept across the rewrite, which is what keeps its URR cells and
// buckets in the dataplane.
func TestSessionMajorWritesOneEntryPerSession(t *testing.T) {
	rec := &recorder{}
	c := New(sessionMajorConfig(SessionLayout{MaxSessions: 8, Actions: 4, QERs: 4}), rec, quietLogger())
	resp := c.Establish(establishment(0x9301, "10.45.0.3")).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("establishment cause %d", got)
	}
	est := sessionEntry(t, rec.last())
	id := payload[SessionKey](est.Key).SessionID
	if id == 0 || id > 8 || est.Value == nil {
		t.Fatalf("entry key %v value %v: want an upsert of a session id in 1..8", est.Key, est.Value)
	}
	// QER 1 has a rate, so it is a meter per policed direction, as in the
	// masked layout: two of the entry's QER slots.
	entry := payload[SessionEntry](est.Value)
	for field, got := range map[string]int{"fteids": len(entry.FTEIDs), "qers": len(entry.QERs), "actions": len(entry.Actions), "pdrs": len(entry.PDRs)} {
		want := 2
		if field == "fteids" {
			want = 1
		}
		if got != want {
			t.Errorf("the entry has %d %s, want %d", got, field, want)
		}
	}
	ul, dl := entryAction(t, est.Value, false), entryAction(t, est.Value, true)
	qers := payload[SessionEntry](est.Value).QERs
	if pos, ok := present(ul.PDRQER); !ok || pos == 0 || int(pos) > len(qers) || qers[pos-1].TrTCM == (MeterProfile{}) {
		t.Errorf("the uplink action is not policed by the session's QER: %v", ul)
	}
	if optional(ul.NextHopID) != uint32(1) || optional(dl.NextHopID) != uint32(2) {
		t.Errorf("next hops ul %v dl %v, want the directions' 1 and 2", optional(ul.NextHopID), optional(dl.NextHopID))
	}
	tunnel := dl.Tunnel
	if tunnel == nil {
		t.Fatal("the downlink action carries no tunnel")
	}

	mod := message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 2, 0,
		ie.NewUpdateFAR(ie.NewFARID(2), ie.NewApplyAction(applyForw),
			ie.NewUpdateForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess),
				ie.NewOuterHeaderCreation(0x0100, 0x55667788, "10.20.30.9", "", 0, 0, 0))))
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("modification cause %d", got)
	}
	upd := sessionEntry(t, rec.last())
	if payload[SessionKey](upd.Key).SessionID != id || upd.Value == nil {
		t.Fatalf("the modification wrote key %v value-nil=%v, want an upsert of session %d", upd.Key, upd.Value == nil, id)
	}
	ul2, dl2 := entryAction(t, upd.Value, false), entryAction(t, upd.Value, true)
	if ul2.ActionID != ul.ActionID || dl2.ActionID != dl.ActionID {
		t.Errorf("the rewrite renamed the actions: ul %v->%v dl %v->%v",
			ul.ActionID, ul2.ActionID, dl.ActionID, dl2.ActionID)
	}
	if tunnel2 := dl2.Tunnel; tunnel2 == nil || tunnel2.TEID == tunnel.TEID {
		t.Errorf("the downlink tunnel %v did not follow the FAR (was %v)", tunnel2, tunnel)
	}

	if got := cause(t, c.Delete(message.NewSessionDeletionRequest(0, 0, upFSEID(t, resp), 3, 0))); got != ie.CauseRequestAccepted {
		t.Fatalf("deletion cause %d", got)
	}
	del := sessionEntry(t, rec.last())
	if payload[SessionKey](del.Key).SessionID != id || del.Value != nil {
		t.Fatalf("the deletion wrote key %v value %v, want the erase of session %d", del.Key, del.Value, id)
	}
}

// onePDREstablishment is a session of one uplink PDR: one action.
func onePDREstablishment(cpSEID uint64, ueIP string) *message.SessionEstablishmentRequest {
	return message.NewSessionEstablishmentRequest(0, 0, cpSEID, 1, 0,
		ie.NewNodeID("", "", "smf"),
		ie.NewFSEID(cpSEID, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess), testFTEID(0),
				ie.NewUEIPAddress(0x02, ueIP, "", 0, 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))))
}

// TestSessionMajorRefusesWhatTheStrideCannotHold: a session needing more
// actions than the module's stride holds is refused before anything is sent,
// and that refusal gives its session id back (the only id here), so the next
// session that fits is accepted; a session beyond the module's capacity is
// refused for resources.
func TestSessionMajorRefusesWhatTheStrideCannotHold(t *testing.T) {
	rec := &recorder{}
	c := New(sessionMajorConfig(SessionLayout{MaxSessions: 1, Actions: 1, QERs: 4}), rec, quietLogger())
	if got := cause(t, c.Establish(establishment(0x9302, "10.45.0.4"))); got == ie.CauseRequestAccepted {
		t.Fatal("a two-action session was accepted by a one-action stride")
	}
	if len(rec.txns) != 0 {
		t.Fatalf("the refused session sent %d transactions", len(rec.txns))
	}
	if got := cause(t, c.Establish(onePDREstablishment(0x9303, "10.45.0.5"))); got != ie.CauseRequestAccepted {
		t.Fatalf("a fitting session after the refusal answered cause %d: the refused one kept the session id", got)
	}
	if got := cause(t, c.Establish(onePDREstablishment(0x9304, "10.45.0.6"))); got != ie.CauseNoResourcesAvailable {
		t.Fatalf("a session beyond -max-sessions answered cause %d, want no resources (%d)", got, ie.CauseNoResourcesAvailable)
	}
	for _, txn := range rec.txns {
		for _, ch := range txn {
			if strings.HasPrefix(ch.Resource, "upf/") && ch.Resource != "upf/sessions" &&
				!strings.HasSuffix(ch.Resource, "/buffer_counters") && !strings.HasSuffix(ch.Resource, "/flows") &&
				!strings.HasSuffix(ch.Resource, "/policies") && !strings.HasSuffix(ch.Resource, "/entries") {
				t.Errorf("a session-major transaction wrote %s", ch.Resource)
			}
		}
	}
}

// TestSessionMajorAssociationEndErasesOneEntryPerSession: an association's
// end takes its sessions out in batched transactions (AssociationEnded), and
// under -target session-major each session leaves as its one
// "<module>/sessions" erase, as a deletion does -- not as erases of the
// tables the entry replaces, which the session-major module does not have.
func TestSessionMajorAssociationEndErasesOneEntryPerSession(t *testing.T) {
	const n = 5
	rec := &recorder{}
	c := New(sessionMajorConfig(SessionLayout{MaxSessions: 8, Actions: 4, QERs: 4}), rec, quietLogger())
	establishN(t, c, n)
	before := len(rec.txns)
	c.AssociationEnded("test")

	if got := c.Stats().Sessions; got != 0 {
		t.Fatalf("%d sessions left after the association ended", got)
	}
	ids := map[uint32]bool{}
	for _, tx := range rec.txns[before:] {
		for _, ch := range tx {
			if ch.Resource != "upf/sessions" || ch.Value != nil {
				t.Errorf("the end wrote %s (erase %v); want only upf/sessions erases", ch.Resource, ch.Value == nil)
				continue
			}
			id := payload[SessionKey](ch.Key).SessionID
			ids[id] = true
		}
	}
	if len(ids) != n {
		t.Errorf("the end erased %d session entries, want %d", len(ids), n)
	}
}

// A quota lives in the controller. Updating it without changing the resolved
// forwarding state must not require a native write or replace the live entry
// with a partial one when the next FAR update does change forwarding.
func TestSessionMajorQuotaOnlyUpdatePreservesForwarding(t *testing.T) {
	rec := &recorder{}
	c := New(sessionMajorConfig(SessionLayout{MaxSessions: 8, Actions: 4, QERs: 4}), rec, quietLogger())
	req := establishment(0x9310, "10.45.0.3")
	children, err := req.CreatePDR[0].CreatePDR()
	if err != nil {
		t.Fatal(err)
	}
	req.CreatePDR[0] = ie.NewCreatePDR(append(children, ie.NewURRID(7))...)
	req.CreateURR = append(req.CreateURR, quotaURR(7, 1<<30))
	resp := c.Establish(req).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("establishment cause %d", got)
	}
	seid := upFSEID(t, resp)
	before := len(rec.txns)
	if got := cause(t, c.Modify(message.NewSessionModificationRequest(0, 0, seid, 2, 0,
		ie.NewUpdateURR(ie.NewURRID(7), ie.NewVolumeQuota(0x01, 2<<30, 0, 0))))); got != ie.CauseRequestAccepted {
		t.Fatalf("quota update cause %d", got)
	}
	if len(rec.txns) != before {
		t.Fatalf("a controller-only quota update wrote the dataplane")
	}
	if got := sessionOf(t, c, seid).URRs.at(7).volQuota.total; got != 2<<30 {
		t.Fatalf("quota is %d, want %d", got, uint64(2<<30))
	}
	if got := cause(t, c.Modify(message.NewSessionModificationRequest(0, 0, seid, 3, 0,
		ie.NewUpdateFAR(ie.NewFARID(2), ie.NewUpdateForwardingParameters(
			ie.NewOuterHeaderCreation(0x0100, 0x55667788, "10.20.30.9", "", 0, 0, 0)))))); got != ie.CauseRequestAccepted {
		t.Fatalf("FAR update cause %d", got)
	}
	entry := sessionEntry(t, rec.last())
	pdrs := payload[SessionEntry](entry.Value).PDRs
	if len(pdrs) != 2 {
		t.Fatalf("FAR update replaced the session with %d PDRs, want both directions", len(pdrs))
	}
	ul, dl := entryAction(t, entry.Value, false), entryAction(t, entry.Value, true)
	tunnel := dl.Tunnel
	if tunnel.TEID != uint32(0x55667788) || ul.Count != true {
		t.Fatalf("full forwarding/counting state was not preserved: ul=%v dl=%v", ul, dl)
	}
}

// The decision to preserve the entry belongs to the compiled plan. Rechecking
// mutable session state during apply can turn an older no-op into a blank or
// stale replacement after another modification has changed forwarding.
func TestSessionMajorEarlierNoopDoesNotOverwriteLaterForwarding(t *testing.T) {
	rec := &recorder{}
	c := New(sessionMajorConfig(SessionLayout{MaxSessions: 8, Actions: 4, QERs: 4}), rec, quietLogger())
	resp := c.Establish(establishment(0x9311, "10.45.0.4")).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("establishment cause %d", got)
	}
	seid := upFSEID(t, resp)
	s := sessionOf(t, c, seid)
	c.mu.Lock()
	before := s.snapshot()
	c.mu.Unlock()
	older, _, err := c.compileModel(s, &before, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := cause(t, c.Modify(message.NewSessionModificationRequest(0, 0, seid, 2, 0,
		ie.NewUpdateFAR(ie.NewFARID(2), ie.NewUpdateForwardingParameters(
			ie.NewOuterHeaderCreation(0x0100, 0x66778899, "10.20.30.9", "", 0, 0, 0)))))); got != ie.CauseRequestAccepted {
		t.Fatalf("later FAR update cause %d", got)
	}
	if err := c.apply(context.Background(), s, older); err != nil {
		t.Fatal(err)
	}
	entry := sessionEntry(t, rec.last())
	dl := entryAction(t, entry.Value, true)
	tunnel := dl.Tunnel
	if tunnel.TEID != uint32(0x66778899) {
		t.Fatalf("the earlier no-op overwrote the later tunnel: %v", dl)
	}
	entryAction(t, entry.Value, false)
}
