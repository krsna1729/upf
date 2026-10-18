// SPDX-License-Identifier: BSD-3-Clause

// The downlink selector (selector.go): the module that names a session for a
// packet that carries no tunnel, and the keyed matcher it feeds. A downlink
// packet has no F-TEID to name its session with, so the session is the one
// whose UE address the packet is addressed to -- within the route domain the
// deployment classified it in -- and the selector is that look-up.
//
// These tests read the transaction through the compiler's own encoder, so a
// changed shape shows as a failed assertion rather than as a silent mismatch
// with the graph.

package session

import (
	"bytes"
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/bess"
)

// selectorConfig is testConfig with the downlink's PDRs in the keyed matcher,
// behind the selector that names their session: what -profile custom
// configures, and what deploy/custom-pdrmatch.yaml wires.
func selectorConfig(fields ...Field) Config {
	cfg := testConfig()
	cfg.Down.PdrMatch = "pdr_match_dl"
	cfg.Down.Selector = "sel_dl"
	cfg.Down.SelectorActions = "sel_at"
	cfg.Down.SelectorFields = fields
	return cfg
}

// selectorKeyOfChange is one selector rule's key, as the transaction spells it:
// one FieldData per field of the graph's key, in its order.
func selectorKeyOfChange(t *testing.T, ch bess.Change) [][]byte {
	t.Helper()
	fields, ok := ch.Key["fields"].([]map[string]any)
	if !ok {
		t.Fatalf("the change for %s carries the key %v, want {\"fields\": [...]}", ch.Resource, ch.Key)
	}
	out := make([][]byte, 0, len(fields))
	for _, f := range fields {
		value, ok := f["value_bin"].([]byte)
		if !ok {
			t.Fatalf("the selector key carries %v, want a value_bin per field", f)
		}
		out = append(out, value)
	}
	return out
}

// The address the selector names a session by, and the session id it writes:
// one rule per (route domain, UE address) the session's downlink PDRs name.
func TestTheSelectorNamesTheSessionByItsUEAddress(t *testing.T) {
	rec := &recorder{}
	c := New(selectorConfig(DstIP), rec, quietLogger())
	est := pdrMatchEstablishment(0x7101, "10.45.0.6", 0x31, 100, "permit out udp from any 5060 to assigned")
	resp := c.Establish(est).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	seid := upFSEID(t, resp)

	// The selector's rule: the UE address the packet is addressed to, and the
	// session id the module writes into the packet's `action_id` attribute --
	// which is the key the matcher behind it reads.
	mine := changesFor(rec.last(), "sel_dl/rules")
	if len(mine) != 1 {
		t.Fatalf("the transaction carries %d selector rules, want the session's one address", len(mine))
	}
	key := selectorKeyOfChange(t, mine[0])
	if len(key) != 1 || !bytes.Equal(key[0], []byte{10, 45, 0, 6}) {
		t.Errorf("the selector's key is %v, want the UE address alone (the graph declares one field)", key)
	}
	if got := mine[0].Value["action_id"]; got != uint32(seid) {
		t.Errorf("the selector's action_id is %v, want the session id %d", got, seid)
	}
	if got := mine[0].Value["gate"]; got != uint64(0) {
		t.Errorf("the selector's gate is %v, want 0: the graph's connection to the matcher", got)
	}
	// The rule's action id is a reference into the selector's own action
	// table: a rule naming an action nothing upserts is refused by the engine.
	record, ok := find0(rec.last(), "sel_at/actions", "id", uint32(seid))
	if !ok {
		t.Fatalf("the rule names action %d, and the transaction writes no such record", seid)
	}
	if record.Value["meter_id"] != 0 || record.Value["next_hop_id"] != 0 {
		t.Errorf("the selector's action record is %v, want no meter and no next hop: the selector's gate is the matcher", record.Value)
	}

	// The matcher's map is keyed by the session, not by a tunnel: this
	// direction's PDRs have no F-TEID at all.
	entry := oneMapChange(t, rec.last(), "pdr_match_dl/rules", uint32(seid))
	if rules := pdrMatchRules(t, entry); len(rules) != 1 {
		t.Errorf("the session's downlink entry holds %d rules, want its one downlink PDR's", len(rules))
	}
	// The shared downlink table is not written at all: the direction's match is
	// the map key now.
	if n := len(changesFor(rec.last(), "pdr_dl/rules")); n != 0 {
		t.Errorf("the transaction carries %d changes for the shared downlink table, want none", n)
	}
}

// The route domain is the other half of the key where the graph classifies by
// it: the interface the packet arrived on, which keeps two network instances'
// overlapping prefixes apart.
func TestTheSelectorKeyCarriesTheRouteDomainWhereTheGraphHasOne(t *testing.T) {
	rec := &recorder{}
	cfg := instancedConfig(t)
	cfg.Down.PdrMatch = "pdr_match_dl"
	cfg.Down.Selector = "sel_dl"
	cfg.Down.SelectorActions = "sel_at"
	cfg.Down.SelectorFields = []Field{RouteDomain, DstIP}
	c := New(cfg, rec, quietLogger())
	// The same address in both instances: two sessions, two rules, two domains.
	for i, instance := range []string{"internet", "ims"} {
		est := instancedEstablishment(uint64(0x7200+i), "10.45.0.7", uint32(0x40+i), instance)
		if got := cause(t, c.Establish(est)); got != ie.CauseRequestAccepted {
			t.Fatalf("the establishment on %s answered cause %d", instance, got)
		}
		key := selectorKeyOfChange(t, changesFor(rec.last(), "sel_dl/rules")[0])
		if len(key) != 2 {
			t.Fatalf("the selector's key on %s is %v, want the domain and the address", instance, key)
		}
		if want := []byte{0, 0, 0, byte(i)}; !bytes.Equal(key[0], want) {
			t.Errorf("the selector's key on %s carries domain %v, want %v", instance, key[0], want)
		}
		if !bytes.Equal(key[1], []byte{10, 45, 0, 7}) {
			t.Errorf("the selector's key on %s carries address %v, want the UE's", instance, key[1])
		}
	}
}

// Two sessions whose downlink PDRs name one address would each select the
// other's packets -- and the second's deletion would erase the first's rule --
// so the second is refused, exactly as two sessions naming one WildcardMatch
// rule are. The address is the first session's while it lives, and free again
// once it is gone.
func TestASecondSessionCannotTakeTheSelectorsAddress(t *testing.T) {
	rec := &recorder{}
	c := New(selectorConfig(DstIP), rec, quietLogger())
	first := c.Establish(pdrMatchEstablishment(0x7301, "10.45.0.8", 0x51, 100, "")).(*message.SessionEstablishmentResponse)
	if got := cause(t, first); got != ie.CauseRequestAccepted {
		t.Fatalf("the first establishment answered cause %d", got)
	}
	before := len(rec.txns)
	second := c.Establish(pdrMatchEstablishment(0x7302, "10.45.0.8", 0x52, 100, "")).(*message.SessionEstablishmentResponse)
	if got := cause(t, second); got != ie.CauseRuleCreationModificationFailure {
		t.Fatalf("a second session on the same UE address answered cause %d, want the rule failure", got)
	}
	// The refusal wrote nothing: a session that takes no claim it did not hold
	// leaves the first session's rule alone.
	if got := len(rec.txns); got != before {
		t.Errorf("the refused establishment applied %d transactions, want the %d the first one did", got-before, 0)
	}

	deleteAndParse(t, c, upFSEID(t, first))
	third := c.Establish(pdrMatchEstablishment(0x7303, "10.45.0.8", 0x53, 100, "")).(*message.SessionEstablishmentResponse)
	if got := cause(t, third); got != ie.CauseRequestAccepted {
		t.Fatalf("the address was not free after the first session's deletion: cause %d", got)
	}
}

// A session that ends takes its selector rule with it, and the rule goes before
// the action record it references: the engine refuses to remove an action a
// live rule names (D-021).
func TestTheDeletionErasesTheSelectorRuleBeforeItsAction(t *testing.T) {
	rec := &recorder{}
	c := New(selectorConfig(DstIP), rec, quietLogger())
	resp := c.Establish(pdrMatchEstablishment(0x7401, "10.45.0.9", 0x61, 100, "")).(*message.SessionEstablishmentResponse)
	seid := upFSEID(t, resp)
	deleteAndParse(t, c, seid)

	// The rule goes before the action record it references: the engine refuses
	// to remove an action a live rule names (D-021). The map key is this
	// session's own and no record references it, so its place is free.
	at := func(resource string) int {
		for i, ch := range rec.last() {
			if ch.Resource == resource {
				return i
			}
		}
		return -1
	}
	rule, action, mapped := at("sel_dl/rules"), at("sel_at/actions"), at("pdr_match_dl/rules")
	if rule < 0 || action < 0 || mapped < 0 {
		t.Fatalf("the deletion names rule=%d action=%d map=%d, want all three erased", rule, action, mapped)
	}
	if rule > action {
		t.Errorf("the deletion removes the action record (at %d) before the rule that names it (at %d)", action, rule)
	}
}
