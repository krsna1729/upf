// SPDX-License-Identifier: BSD-3-Clause

// The per-session matcher (docs/design.md, "the keyed write"): a direction
// whose PDRs are written as one key of a *map* resource -- that session's rule
// list as the value -- instead of one key per rule of a table every session
// shares. What the shape is for is the size of a session change: one upsert of
// O(this session's rules), a modification that touches no other session's key,
// and a deletion that erases exactly its own.
//
// The resource, the key and the value are the frozen contract in
// datapath/upf_datapath.proto (Upf.PdrMatchModule owns it): "<module>/rules",
// PdrMatchKey{session} -> PdrMatchEntry{rules}, the rules in the SMF's
// Precedence order, first match wins. These tests read the transaction through
// the compiler's own encoder, so a changed shape shows as a failed assertion
// rather than as a silent mismatch with the module.

package session

import (
	"context"
	"net"
	"slices"
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/bess"
)

// pdrMatchConfig is testConfig with the uplink's PDRs in the named
// per-session matcher; the downlink stays on the WildcardMatch path, because
// the opt-in is per direction.
func pdrMatchConfig(module string) Config {
	cfg := testConfig()
	cfg.Up.PdrMatch = module
	return cfg
}

// pdrMatchEstablishment is the session these tests establish: an uplink PDR
// pinned to `teid` (which is the map's key -- the F-TEID the decap writes as
// the module's key attribute), and a downlink one that is not this path's.
func pdrMatchEstablishment(cpSEID uint64, ueIP string, teid, precedence uint32, sdf string) *message.SessionEstablishmentRequest {
	uplink := []*ie.IE{
		ie.NewSourceInterface(ie.SrcInterfaceAccess),
		ie.NewFTEID(0x01, teid, net.ParseIP("192.0.2.1"), nil, 0),
		ie.NewUEIPAddress(0x02, ueIP, "", 0, 0),
	}
	if sdf != "" {
		uplink = append(uplink, ie.NewSDFFilter(sdf, "", "", "", 0))
	}
	return message.NewSessionEstablishmentRequest(0, 0, cpSEID, 1, 0,
		ie.NewNodeID("", "", "smf"),
		ie.NewFSEID(cpSEID, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(precedence),
			ie.NewPDI(uplink...), ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
		ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x02, ueIP, "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to assigned 53", "", "", "", 0)),
			ie.NewFARID(2)),
		ie.NewCreateFAR(ie.NewFARID(2), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess))),
	)
}

// changesFor is every change of a transaction naming one resource.
func changesFor(changes []bess.Change, resource string) []bess.Change {
	var out []bess.Change
	for _, ch := range changes {
		if ch.Resource == resource {
			out = append(out, ch)
		}
	}
	return out
}

// pdrMatchKey is one key of the map, as the transaction spells it: the F-TEID,
// and nothing else.
func pdrMatchKey(t *testing.T, ch bess.Change) uint32 {
	t.Helper()
	teid, ok := ch.Key["session"].(uint32)
	if !ok {
		t.Fatalf("the change for %s carries the key %v, want {\"session\": <F-TEID>}", ch.Resource, ch.Key)
	}
	return teid
}

// pdrMatchRules is the rule list a map change writes, or fails: the value is
// the session's own rules, in the SMF's Precedence order.
func pdrMatchRules(t *testing.T, ch bess.Change) []map[string]any {
	t.Helper()
	rules, ok := ch.Value["rules"].([]map[string]any)
	if !ok {
		t.Fatalf("the change for %s carries the value %v, want {\"rules\": [...]}", ch.Resource, ch.Value)
	}
	return rules
}

// oneMapChange is the single change a transaction must carry for a direction's
// map: one key per session, and this session's key is the only one the
// transaction names.
func oneMapChange(t *testing.T, changes []bess.Change, resource string, teid uint32) bess.Change {
	t.Helper()
	mine := changesFor(changes, resource)
	if len(mine) != 1 {
		t.Fatalf("the transaction carries %d changes for %s, want exactly the session's one key", len(mine), resource)
	}
	if got := pdrMatchKey(t, mine[0]); got != teid {
		t.Fatalf("the change for %s is keyed by F-TEID %#x, want the session's %#x", resource, got, teid)
	}
	return mine[0]
}

func TestTheUplinkOptInWritesOneKeyPerSession(t *testing.T) {
	// The point of the map resource: a session's PDRs are one key's value, so
	// establishing one session is one upsert that names no other session's key
	// -- where the shared WildcardMatch table is one upsert per rule of a table
	// holding every session's.
	rec := &recorder{}
	c := New(pdrMatchConfig("pdr_match_ul"), rec, quietLogger())
	const teidA, teidB = 0x11, 0x22

	if got := cause(t, c.Establish(pdrMatchEstablishment(0x6a01, "10.45.0.6", teidA, 100, "permit out udp from any 5060 to assigned"))); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	entry := oneMapChange(t, rec.last(), "pdr_match_ul/rules", teidA)
	list := pdrMatchRules(t, entry)
	if len(list) != 1 {
		t.Fatalf("the session's entry holds %d rules, want its one uplink PDR's", len(list))
	}
	// The rule is the 5-tuple BESS's firewall rule is, plus the ActionId the
	// packet leaves with; the uplink's own selection is the UE address.
	if got := list[0]["src_ip"]; got != "10.45.0.6/32" {
		t.Errorf("the rule's src_ip is %v, want the UE's host route", got)
	}
	if got := list[0]["proto"]; got != uint32(17) {
		t.Errorf("the rule's proto is %v, want udp (17)", got)
	}
	if got := list[0]["dst_port_low"]; got != uint32(5060) {
		t.Errorf("the rule's dst_port_low is %v, want 5060", got)
	}
	if got := list[0]["drop"]; got != false {
		t.Errorf("a forwarding PDR's rule carries drop=%v, want false", got)
	}
	action, ok := list[0]["action_id"].(uint32)
	if !ok || action == 0 {
		t.Fatalf("the rule's action_id is %v, and a matching packet leaves with one", list[0]["action_id"])
	}
	// The same rule carries the result the matcher writes directly: two meter
	// levels and the Router next hop, not a reference to an action table.
	ids, ok := list[0]["meter_ids"].([]uint32)
	if !ok || len(ids) != 2 {
		t.Errorf("the rule's meter levels are %v, want two slots (this PDR names no QER)", list[0]["meter_ids"])
	}
	if got := list[0]["next_hop_id"]; got != uint32(1) {
		t.Errorf("the rule's next hop is %v, want the uplink's (1)", got)
	}
	// A change naming no key would be a write of the whole map, which is not
	// this resource: the map is upserted one session at a time.
	if entry.Value == nil {
		t.Error("the establishment erased the session's key instead of writing it")
	}

	// Nothing went to the shared uplink table: the direction's match is the map
	// key now. The downlink's PDR is another direction and keeps its
	// WildcardMatch rule.
	if n := len(changesFor(rec.last(), "pdr_ul/rules")); n != 0 {
		t.Errorf("the opt-in path also wrote %d WildcardMatch rules for the uplink", n)
	}
	if n := len(changesFor(rec.last(), "pdr_dl/rules")); n != 1 {
		t.Errorf("the downlink wrote %d WildcardMatch rules, want its one", n)
	}

	// A second session's establishment names its own key and no other's.
	if got := cause(t, c.Establish(pdrMatchEstablishment(0x6a02, "10.45.0.7", teidB, 100, "permit out tcp from any 443 to assigned"))); got != ie.CauseRequestAccepted {
		t.Fatalf("the second establishment answered cause %d", got)
	}
	second := oneMapChange(t, rec.last(), "pdr_match_ul/rules", teidB)
	if got := pdrMatchRules(t, second)[0]["dst_port_low"]; got != uint32(443) {
		t.Errorf("the second session's rule carries dst_port_low=%v, want its own filter's 443", got)
	}
	if _, ok := find0(rec.last(), "pdr_match_ul/rules", "session", teidA); ok {
		t.Error("the second session's transaction named the first session's key")
	}
}

func TestTheSessionsRulesAreInPrecedenceOrder(t *testing.T) {
	// The list's order is the SMF's own: TS 29.244 8.2.11 has the lower
	// Precedence value win, and the module applies the first rule that matches
	// (datapath/upf_datapath.proto, PdrMatchEntry). The WildcardMatch path
	// inverts the Precedence into the classifier's priority because its rules
	// are separate keys; this one is a list, so it is sorted ascending and not
	// inverted. Created out of order, so PDR id order is not precedence order.
	rec := &recorder{}
	c := New(pdrMatchConfig("pdr_match_ul"), rec, quietLogger())
	const teid = 0x31
	req := message.NewSessionEstablishmentRequest(0, 0, 0x6b01, 1, 0,
		ie.NewNodeID("", "", "smf"),
		ie.NewFSEID(0x6b01, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(200),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, teid, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any 5060 to assigned", "", "", "", 0)),
			ie.NewFARID(1)),
		ie.NewCreatePDR(ie.NewPDRID(3), ie.NewPrecedence(300),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, teid, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any 53 to assigned", "", "", "", 0)),
			ie.NewFARID(2)),
		ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, teid, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0),
				ie.NewSDFFilter("permit out tcp from any 80 to assigned", "", "", "", 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
		// A FAR that neither forwards nor buffers: its PDR drops, and a
		// dropping rule names no action (the module refuses drop with one).
		ie.NewCreateFAR(ie.NewFARID(2), ie.NewApplyAction(0)),
	)
	if got := cause(t, c.Establish(req)); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	// One F-TEID, so one key: the session's three PDRs are one entry's list --
	// three keys of the shared table would be three rules there.
	list := pdrMatchRules(t, oneMapChange(t, rec.last(), "pdr_match_ul/rules", teid))
	if len(list) != 3 {
		t.Fatalf("the entry holds %d rules, want the session's three", len(list))
	}
	wantPorts := []uint32{80, 5060, 53} // Precedence 100, 200, 300
	wantProto := []uint32{6, 17, 17}    // tcp, udp, udp
	for i, want := range wantPorts {
		if got := list[i]["dst_port_low"]; got != want {
			t.Errorf("rule %d's dst_port_low is %v, want %d (the Precedence order)", i, got, want)
		}
		if got := list[i]["proto"]; got != wantProto[i] {
			t.Errorf("rule %d's proto is %v, want %d", i, got, wantProto[i])
		}
	}
	if got := list[0]["drop"]; got != false {
		t.Errorf("the lowest Precedence rule carries drop=%v, want false", got)
	}
	if got := list[2]["drop"]; got != true {
		t.Errorf("a rule whose FAR asks for nothing carries drop=%v, want true", got)
	}
	if _, ok := list[2]["action_id"]; ok {
		t.Errorf("a dropping rule names the action %v, and the module refuses drop with one", list[2]["action_id"])
	}
}

func TestAModificationRewritesOnlyItsOwnKey(t *testing.T) {
	// A modification rewrites the session's own key: one upsert of its rules,
	// and no other session's key in the transaction -- which is the whole
	// difference from the shared table, where a session's rule key can be
	// claimed by whoever wrote it first.
	rec := &recorder{}
	c := New(pdrMatchConfig("pdr_match_ul"), rec, quietLogger())
	const teidA, teidB = 0x41, 0x42
	respA := c.Establish(pdrMatchEstablishment(0x6c01, "10.45.0.6", teidA, 100, "permit out udp from any 5060 to assigned")).(*message.SessionEstablishmentResponse)
	if got := cause(t, respA); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	if got := cause(t, c.Establish(pdrMatchEstablishment(0x6c02, "10.45.0.7", teidB, 100, "permit out udp from any 5060 to assigned"))); got != ie.CauseRequestAccepted {
		t.Fatalf("the second establishment answered cause %d", got)
	}

	// The Update PDR names no F-TEID: the session keeps the pinned one, and so
	// keeps its key (merge keeps the dataplane identity of an updated PDR).
	mod := message.NewSessionModificationRequest(0, 0, upFSEID(t, respA), 2, 0,
		ie.NewUpdatePDR(ie.NewPDRID(1), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0),
				ie.NewSDFFilter("permit out tcp from any 443 to assigned", "", "", "", 0)),
			ie.NewFARID(1)),
	)
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification answered cause %d", got)
	}
	entry := oneMapChange(t, rec.last(), "pdr_match_ul/rules", teidA)
	if entry.Value == nil {
		t.Fatal("the modification erased the session's key instead of rewriting it")
	}
	list := pdrMatchRules(t, entry)
	if len(list) != 1 {
		t.Fatalf("the rewritten entry holds %d rules, want the modified PDR's one", len(list))
	}
	if got := list[0]["dst_port_low"]; got != uint32(443) {
		t.Errorf("the rewritten rule's dst_port_low is %v, want the modified 443", got)
	}
	if got := list[0]["proto"]; got != uint32(6) {
		t.Errorf("the rewritten rule's proto is %v, want the modified tcp (6)", got)
	}
	if _, ok := find0(rec.last(), "pdr_match_ul/rules", "session", teidB); ok {
		t.Error("the modification named the other session's key")
	}
}

func TestDeletingASessionErasesExactlyItsOwnKey(t *testing.T) {
	// The shared table has no key a session owns -- one rule key can serve two
	// sessions' identical filters, which is why the WoodcardMatch path refuses
	// the second claimant. The map's key is the session's, so a deletion erases
	// it and only it: the other session's rules stay programmed.
	rec := &recorder{}
	c := New(pdrMatchConfig("pdr_match_ul"), rec, quietLogger())
	const teidA, teidB = 0x51, 0x52
	respA := c.Establish(pdrMatchEstablishment(0x6d01, "10.45.0.6", teidA, 100, "permit out udp from any 5060 to assigned")).(*message.SessionEstablishmentResponse)
	if got := cause(t, respA); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	respB := c.Establish(pdrMatchEstablishment(0x6d02, "10.45.0.7", teidB, 100, "permit out udp from any 5060 to assigned")).(*message.SessionEstablishmentResponse)
	if got := cause(t, respB); got != ie.CauseRequestAccepted {
		t.Fatalf("the second establishment answered cause %d", got)
	}

	del := c.Delete(message.NewSessionDeletionRequest(0, 0, upFSEID(t, respA), 3, 0))
	if got := cause(t, del); got != ie.CauseRequestAccepted {
		t.Fatalf("the deletion answered cause %d", got)
	}
	entry := oneMapChange(t, rec.last(), "pdr_match_ul/rules", teidA)
	if entry.Value != nil {
		t.Errorf("the deletion wrote the session's key (%v) instead of erasing it", entry.Value)
	}
	if _, ok := find0(rec.last(), "pdr_match_ul/rules", "session", teidB); ok {
		t.Error("the deletion named the other session's key, which is still in the dataplane")
	}
	// The whole deletion is still one transaction for the session's own
	// records: nothing else about the map moves.
	if n := len(changesFor(rec.last(), "pdr_match_ul/rules")); n != 1 {
		t.Errorf("the deletion carries %d changes for the map, want the session's one key", n)
	}
}

func TestThePdrMatchPathIsOptIn(t *testing.T) {
	// Without the flag the direction is the WildcardMatch path, byte for byte:
	// no map change at all, and the effect of the rule is asserted here so that
	// "no change for the map" is not confused with "no rule anywhere".
	rec := &recorder{}
	c := New(pdrMatchConfig(""), rec, quietLogger())
	if got := cause(t, c.Establish(pdrMatchEstablishment(0x6e01, "10.45.0.6", 0x61, 100, "permit out udp from any 5060 to assigned"))); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	if n := len(changesFor(rec.last(), "pdr_match_ul/rules")); n != 0 {
		t.Errorf("a graph with no per-session matcher wrote %d map changes", n)
	}
	if n := len(changesFor(rec.last(), "pdr_ul/rules")); n != 1 {
		t.Errorf("the uplink wrote %d WildcardMatch rules, want its one", n)
	}
}

func TestAPdrMatchPDINamingAQFIIsCarriedOnItsRule(t *testing.T) {
	// Two PDRs of one tunnel that differ only by QFI are two rules of the
	// session's one list, each naming its flow; a PDR that names none names no
	// key at all (a rule that says qfi=0 would match only a packet with no
	// container). The order stays the SMF's Precedence order.
	rec := &recorder{}
	c := New(pdrMatchConfig("pdr_match_ul"), rec, quietLogger())
	const teid = 0x71
	pdr := func(id uint16, prec uint32, qfi int) *ie.IE {
		pdi := []*ie.IE{
			ie.NewSourceInterface(ie.SrcInterfaceAccess),
			ie.NewFTEID(0x01, teid, net.ParseIP("192.0.2.1"), nil, 0),
			ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0),
		}
		if qfi >= 0 {
			pdi = append(pdi, ie.NewQFI(uint8(qfi)))
		}
		return ie.NewCreatePDR(ie.NewPDRID(id), ie.NewPrecedence(prec), ie.NewPDI(pdi...), ie.NewFARID(1))
	}
	req := message.NewSessionEstablishmentRequest(0, 0, 0x6f01, 1, 0,
		ie.NewFSEID(0x6f01, nil, nil),
		pdr(1, 300, -1), pdr(2, 100, 9), pdr(3, 200, 5),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
	)
	if got := cause(t, c.Establish(req)); got != ie.CauseRequestAccepted {
		t.Fatalf("a PDI naming a QFI answered cause %d", got)
	}
	list := pdrMatchRules(t, oneMapChange(t, rec.last(), "pdr_match_ul/rules", teid))
	if len(list) != 3 {
		t.Fatalf("the entry holds %d rules, want three", len(list))
	}
	for i, want := range []any{uint32(9), uint32(5), nil} { // Precedence 100, 200, 300
		got, ok := list[i]["qfi"]
		if want == nil {
			if ok {
				t.Errorf("rule %d names QFI %v, want none", i, got)
			}
		} else if got != want {
			t.Errorf("rule %d names QFI %v, want %v", i, got, want)
		}
	}
}

func TestTheSweepResetsAnEarlierRunsOptInMap(t *testing.T) {
	// The restart wall reaches the opt-in map: an earlier run's key is a
	// session this process does not know, and the module matches packets on
	// it. The sweep empties the whole map in the daemon (ResetResources), not
	// key by key.
	cfg := pdrMatchConfig("pdr_match_ul")
	f := &sweepFake{contents: map[string][]bess.Entry{}}
	c := New(cfg, f, quietLogger())
	for _, name := range c.resources() {
		f.contents[name] = []bess.Entry{{Key: map[string]any{"id": uint64(1)}}}
	}
	f.contents["pdr_match_ul/rules"] = []bess.Entry{
		{Key: map[string]any{"session": uint32(0x81)}},
		{Key: map[string]any{"session": uint32(0x82)}},
	}
	if err := c.Sweep(context.Background()); err != nil {
		t.Fatalf("the sweep: %v", err)
	}
	found := false
	for _, names := range f.resets {
		if slices.Contains(names, "pdr_match_ul/rules") {
			found = true
		}
	}
	if !found {
		t.Error("the sweep did not reset the opt-in map")
	}
	if len(f.changes) != 0 {
		t.Errorf("the sweep erased %d keys one by one from tables it reset", len(f.changes))
	}
}
