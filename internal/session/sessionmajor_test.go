// SPDX-License-Identifier: BSD-3-Clause

package session

import (
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
func entryAction(t *testing.T, value map[string]any, downlink bool) map[string]any {
	t.Helper()
	actions, _ := value["actions"].([]map[string]any)
	pdrs, _ := value["pdrs"].([]map[string]any)
	for _, p := range pdrs {
		if p["downlink"] != downlink {
			continue
		}
		pos, _ := p["action"].(uint32)
		if pos == 0 || int(pos) > len(actions) {
			t.Fatalf("a rule names action %d of %d", pos, len(actions))
		}
		return actions[pos-1]
	}
	t.Fatalf("the entry has no downlink=%v rule", downlink)
	return nil
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
	id, _ := est.Key["session_id"].(uint32)
	if id == 0 || id > 8 || est.Value == nil {
		t.Fatalf("entry key %v value %v: want an upsert of a session id in 1..8", est.Key, est.Value)
	}
	// QER 1 has a rate, so it is a meter per policed direction, as in the
	// masked layout: two of the entry's QER slots.
	for field, want := range map[string]int{"fteids": 1, "qers": 2, "actions": 2, "pdrs": 2} {
		if got, _ := est.Value[field].([]map[string]any); len(got) != want {
			t.Errorf("the entry has %d %s, want %d", len(got), field, want)
		}
	}
	ul, dl := entryAction(t, est.Value, false), entryAction(t, est.Value, true)
	qers, _ := est.Value["qers"].([]map[string]any)
	if pos, _ := ul["pdr_qer"].(uint32); pos == 0 || int(pos) > len(qers) || qers[pos-1]["tr_tcm"] == nil {
		t.Errorf("the uplink action is not policed by the session's QER: %v", ul)
	}
	if ul["next_hop_id"] != uint32(1) || dl["next_hop_id"] != uint32(2) {
		t.Errorf("next hops ul %v dl %v, want the directions' 1 and 2", ul["next_hop_id"], dl["next_hop_id"])
	}
	tunnel, _ := dl["tunnel"].(map[string]any)
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
	if upd.Key["session_id"] != id || upd.Value == nil {
		t.Fatalf("the modification wrote key %v value-nil=%v, want an upsert of session %d", upd.Key, upd.Value == nil, id)
	}
	ul2, dl2 := entryAction(t, upd.Value, false), entryAction(t, upd.Value, true)
	if ul2["action_id"] != ul["action_id"] || dl2["action_id"] != dl["action_id"] {
		t.Errorf("the rewrite renamed the actions: ul %v->%v dl %v->%v",
			ul["action_id"], ul2["action_id"], dl["action_id"], dl2["action_id"])
	}
	if tunnel2, _ := dl2["tunnel"].(map[string]any); tunnel2 == nil || tunnel2["teid"] == tunnel["teid"] {
		t.Errorf("the downlink tunnel %v did not follow the FAR (was %v)", tunnel2, tunnel)
	}

	if got := cause(t, c.Delete(message.NewSessionDeletionRequest(0, 0, upFSEID(t, resp), 3, 0))); got != ie.CauseRequestAccepted {
		t.Fatalf("deletion cause %d", got)
	}
	del := sessionEntry(t, rec.last())
	if del.Key["session_id"] != id || del.Value != nil {
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
			id, _ := ch.Key["session_id"].(uint32)
			ids[id] = true
		}
	}
	if len(ids) != n {
		t.Errorf("the end erased %d session entries, want %d", len(ids), n)
	}
}
