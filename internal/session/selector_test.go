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
	"encoding/binary"
	"log/slog"
	"strings"
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
	// The uplink is the custom profile's too (the map keyed by the F-TEID): two
	// sessions that share a UE address are told apart by the tunnel there, which
	// is what makes the *downlink* the place their address can collide.
	cfg.Up.PDRTable, cfg.Up.PDRFields = "", nil
	cfg.Up.PdrMatch = "pdr_match_ul"
	cfg.Down.PDRTable, cfg.Down.PDRFields = "", nil
	cfg.Down.PdrMatch = "pdr_match_dl"
	cfg.Down.Selector = "sel_dl"
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

// selectorActionID is the session id a selector rule's result carries: the
// ExactMatch writes it into `action_id`, which the matcher behind it reads.
func selectorActionID(t *testing.T, ch bess.Change) uint32 {
	t.Helper()
	b, _ := ch.Value["result"].([]byte)
	if len(b) < 4 {
		t.Fatalf("the selector rule carries no result record: %v", ch.Value)
	}
	return binary.BigEndian.Uint32(b)
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
	if got := selectorActionID(t, mine[0]); got != uint32(seid) {
		t.Errorf("the selector's result is %d, want the session id %d", got, seid)
	}
	if got := mine[0].Value["gate"]; got != uint64(0) {
		t.Errorf("the selector's gate is %v, want 0: the graph's connection to the matcher", got)
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

// The other half of that fact: where the graph does *not* classify by the route
// domain, the domain cannot keep two sessions apart either. Their rules are one
// key to the engine -- the address alone -- so the second session is refused,
// and the refusal is the same one a same-domain collision gets. A claim built
// from the session's own (route domain, address) would differ while the rule it
// guards is the same rule, and the second session's rule would silently take
// the first's packets (found live by ci/pdrmatch-2dn.sh's probe: with
// `route_domain` dropped from the key, the campus session took the internet
// frame).
func TestASelectorThatIgnoresTheRouteDomainHoldsOneSessionPerAddress(t *testing.T) {
	var logged bytes.Buffer
	rec := &recorder{}
	cfg := instancedConfig(t)
	cfg.Down.PdrMatch = "pdr_match_dl"
	cfg.Down.Selector = "sel_dl"
	cfg.Down.SelectorFields = []Field{DstIP} // the graph reads no route domain
	c := New(cfg, rec, slog.New(slog.NewTextHandler(&logged, nil)))

	first := c.Establish(instancedEstablishment(0x7801, "10.45.0.9", 0x61, "internet")).(*message.SessionEstablishmentResponse)
	if got := cause(t, first); got != ie.CauseRequestAccepted {
		t.Fatalf("the first establishment answered cause %d", got)
	}
	// The key the engine holds, and therefore the key the claim is: the address
	// alone, whatever the session's own fields are.
	key := selectorKeyOfChange(t, changesFor(rec.last(), "sel_dl/rules")[0])
	if len(key) != 1 || !bytes.Equal(key[0], []byte{10, 45, 0, 9}) {
		t.Fatalf("the selector's key is %v, want the address alone (the graph declares one field)", key)
	}
	before := len(rec.txns)
	second := c.Establish(instancedEstablishment(0x7802, "10.45.0.9", 0x62, "ims")).(*message.SessionEstablishmentResponse)
	if got := cause(t, second); got != ie.CauseRuleCreationModificationFailure {
		t.Fatalf("the second instance's session on the same address answered cause %d, want the rule failure: the two sessions' keys are one key", got)
	}
	if msg := logged.String(); !strings.Contains(msg, "the downlink address") || !strings.Contains(msg, "10.45.0.9") ||
		!strings.Contains(msg, "is session 1's") {
		t.Errorf("the refusal does not name the downlink key it could not take:\n%s", msg)
	}
	// The refused establishment wrote nothing, so the first session's rule is
	// still the first session's: the second did not take it on the way in.
	if got := len(rec.txns); got != before {
		t.Errorf("the refused establishment applied %d transactions, want none", got-before)
	}
}

// A selector field that is not the session's is refused before anything is
// written: the key names the session, and the protocol or a port is a field of
// one PDR -- a selector keyed on it would name the PDR rather than the session
// the matcher needs. The refusal comes from the claim, which is the engine's key
// (selectorClaim), so it happens before any rule of the message is applied.
func TestASelectorFieldThatIsNotTheSessionsIsRefused(t *testing.T) {
	rec := &recorder{}
	c := New(selectorConfig(Proto), rec, quietLogger())
	resp := c.Establish(pdrMatchEstablishment(0x7901, "10.45.0.10", 0x81, 100, "")).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRuleCreationModificationFailure {
		t.Fatalf("a selector keyed on the protocol answered cause %d, want the rule failure", got)
	}
	if n := len(rec.txns); n != 0 {
		t.Errorf("the refused establishment applied %d transactions, want none", n)
	}
}

// Two sessions whose downlink PDRs name one address would each select the
// other's packets -- and the second's deletion would erase the first's rule --
// so the second is refused, exactly as two sessions naming one WildcardMatch
// rule are. The address is the first session's while it lives, and free again
// once it is gone.
func TestASecondSessionCannotTakeTheSelectorsAddress(t *testing.T) {
	var logged bytes.Buffer
	rec := &recorder{}
	c := New(selectorConfig(DstIP), rec, slog.New(slog.NewTextHandler(&logged, nil)))
	first := c.Establish(pdrMatchEstablishment(0x7301, "10.45.0.8", 0x51, 100, "")).(*message.SessionEstablishmentResponse)
	if got := cause(t, first); got != ie.CauseRequestAccepted {
		t.Fatalf("the first establishment answered cause %d", got)
	}
	before := len(rec.txns)
	second := c.Establish(pdrMatchEstablishment(0x7302, "10.45.0.8", 0x52, 100, "")).(*message.SessionEstablishmentResponse)
	if got := cause(t, second); got != ie.CauseRuleCreationModificationFailure {
		t.Fatalf("a second session on the same UE address answered cause %d, want the rule failure", got)
	}
	// The refusal is the selector's own: the uplink of the two sessions is told
	// apart by its tunnel, so what collides is the downlink address.
	if !strings.Contains(logged.String(), "the downlink address 0/10.45.0.8 is session 1's") {
		t.Errorf("the refusal does not name the downlink address it could not take:\n%s", logged.String())
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

// A session whose downlink PDI moves to another UE address moves its selector
// rule with it: the old key is erased (with the action record it referenced),
// the new one is written, and the map key -- the session -- stays the session's.
// The address it left is free for another session afterwards.
func TestAModificationThatMovesTheUEAddressMovesTheSelectorsRule(t *testing.T) {
	rec := &recorder{}
	c := New(selectorConfig(DstIP), rec, quietLogger())
	resp := c.Establish(pdrMatchEstablishment(0x7501, "10.45.0.6", 0x71, 100, "")).(*message.SessionEstablishmentResponse)
	seid := upFSEID(t, resp)
	move := func() *message.SessionModificationRequest {
		return message.NewSessionModificationRequest(0, 0, seid, 2, 0,
			ie.NewUpdatePDR(ie.NewPDRID(2), ie.NewPrecedence(100),
				ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
					ie.NewUEIPAddress(0x02, "10.45.0.7", "", 0, 0),
					ie.NewSDFFilter("permit out udp from any to assigned 53", "", "", "", 0)),
				ie.NewFARID(2)),
		)
	}
	if got := cause(t, c.Modify(move())); got != ie.CauseRequestAccepted {
		t.Fatalf("the address move answered cause %d", got)
	}
	changes := rec.last()
	// The erase and the write are two operations on different keys, and the
	// engine refuses two operations on one key -- so the old key must be gone
	// from the write and the new one from the erase.
	var erased, written [][]byte
	for _, ch := range changesFor(changes, "sel_dl/rules") {
		key := selectorKeyOfChange(t, ch)
		if ch.Value == nil {
			erased = append(erased, key[0])
			continue
		}
		written = append(written, key[0])
		if got := selectorActionID(t, ch); got != uint32(seid) {
			t.Errorf("the new rule's result is %d, want the session id %d", got, seid)
		}
	}
	if len(erased) != 1 || !bytes.Equal(erased[0], []byte{10, 45, 0, 6}) {
		t.Errorf("the transaction erased %v, want the address the session left", erased)
	}
	if len(written) != 1 || !bytes.Equal(written[0], []byte{10, 45, 0, 7}) {
		t.Errorf("the transaction wrote %v, want the address the session moved to", written)
	}
	// The map key is the session's either way: the move rewrites it, and one
	// key is all the session has.
	oneMapChange(t, changes, "pdr_match_dl/rules", uint32(seid))

	// The address it left is free: the claim went with the key.
	if got := cause(t, c.Establish(pdrMatchEstablishment(0x7502, "10.45.0.6", 0x72, 100, ""))); got != ie.CauseRequestAccepted {
		t.Errorf("the address the session left answered cause %d, want it free", got)
	}
}

// The capability the selector buys, and the reason the downlink had to move off
// the shared table for it: a downlink PDR whose SDF filter names a port
// *range*. The shared WildcardMatch keys on a masked value per field, and a mask
// holds one port, not a range (compile.go's matchValue), so this message is
// refused with cause 73 on the generic profile
// (TestPortRangeIsRefusedNotMatchedTooWidely) -- and was refused on the custom
// profile too while its downlink was that table. The keyed matcher's rules are
// the firewall rule shape, which carries the two bounds.
func TestTheSelectorCarriesADownlinkPortRange(t *testing.T) {
	rec := &recorder{}
	c := New(selectorConfig(DstIP), rec, quietLogger())
	est := pdrMatchEstablishment(0x7701, "10.45.0.6", 0x91, 100, "permit out udp from any 5060 to assigned")
	est.CreatePDR = []*ie.IE{
		est.CreatePDR[0],
		ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to assigned 5000-5100", "", "", "", 0)),
			ie.NewFARID(2)),
	}
	resp := c.Establish(est).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("a downlink port range answered cause %d, want it accepted by the keyed matcher", got)
	}
	entry := oneMapChange(t, rec.last(), "pdr_match_dl/rules", uint32(upFSEID(t, resp)))
	rules := pdrMatchRules(t, entry)
	if len(rules) != 1 {
		t.Fatalf("the session's downlink entry holds %d rules, want one", len(rules))
	}
	if got := rules[0]["dst_port_low"]; got != uint32(5000) {
		t.Errorf("the rule's lower bound is %v, want 5000", got)
	}
	if got := rules[0]["dst_port_high"]; got != uint32(5100) {
		t.Errorf("the rule's upper bound is %v, want 5100: the range is the rule's, not a single port", got)
	}
}

// selectorOps splits one resource's changes into the erases (a change with no
// value) and the writes.
func selectorOps(t *testing.T, changes []bess.Change, resource string) (erased, written []bess.Change) {
	t.Helper()
	for _, ch := range changesFor(changes, resource) {
		if ch.Value == nil {
			erased = append(erased, ch)
			continue
		}
		written = append(written, ch)
	}
	return erased, written
}
