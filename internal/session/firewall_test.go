// SPDX-License-Identifier: BSD-3-Clause

// The firewall path (docs/design.md): a direction whose PDRs are matched by
// BESS's `firewall` table instead of the WildcardMatch one. Its rules carry
// what a mask cannot -- a port *range*, and prefixes of both address families
// in one policy -- so the two refusals of the WildcardMatch path are lifted
// here and only here.

package session

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/bess"
)

// firewallConfig is testConfig with the named firewall modules holding the
// direction's PDRs; "" leaves that direction on the WildcardMatch path.
func firewallConfig(up, down string) Config {
	cfg := testConfig()
	cfg.Up.Firewall = up
	cfg.Down.Firewall = down
	return cfg
}

// firewallPolicy is the policy a transaction carries for a firewall module: the
// whole ordered rule list, which is what the resource holds.
func firewallPolicy(t *testing.T, changes []bess.Change, resource string) []map[string]any {
	t.Helper()
	for _, ch := range changes {
		if ch.Resource != resource {
			continue
		}
		if ch.Key != nil {
			t.Fatalf("%s is a singleton, but the change carries the key %v", resource, ch.Key)
		}
		rules, ok := ch.Value["rules"].([]map[string]any)
		if !ok {
			t.Fatalf("%s's value is not a rule list: %v", resource, ch.Value)
		}
		return rules
	}
	t.Fatalf("no change for %s among %d changes", resource, len(changes))
	return nil
}

// firewallEstablishment is the downlink-only session the firewall tests use: one
// PDR with the given Precedence and SDF filter, and a FAR that forwards.
func firewallEstablishment(cpSEID uint64, ueIP string, precedence uint32, sdf string) *message.SessionEstablishmentRequest {
	return message.NewSessionEstablishmentRequest(0, 0, cpSEID, 1, 0,
		ie.NewFSEID(cpSEID, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(precedence),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x06, ueIP, "", 0, 0),
				ie.NewSDFFilter(sdf, "", "", "", 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess))),
	)
}

func TestAPortRangeCompilesToAFirewallRuleWithItsRange(t *testing.T) {
	// The WildcardMatch path refuses this filter
	// (TestPortRangeIsRefusedNotMatchedTooWidely): a range is 2n-2 prefixes per
	// field there, charged to the table's tuple budget. The firewall table
	// checks a rule's ports after its masked key hits, so a range costs it no
	// group, no mask and no entry -- and on the firewall path the filter
	// compiles to a rule that carries it.
	rec := &recorder{}
	c := New(firewallConfig("", "fw_dl"), rec, quietLogger())
	req := firewallEstablishment(0x5f01, "10.45.0.6", 10, "permit out udp from any to assigned 1000-2000")
	if got := cause(t, c.Establish(req)); got != ie.CauseRequestAccepted {
		t.Fatalf("a port range on the firewall path answered cause %d, want accepted", got)
	}
	policy := firewallPolicy(t, rec.last(), "fw_dl/rules")
	if len(policy) != 1 {
		t.Fatalf("the policy holds %d rules, want 1", len(policy))
	}
	r := policy[0]
	// The rule's field names are BESS's FirewallArg.Rule, so what the module
	// reads is what the test reads.
	if got := r["dst_ip"]; got != "10.45.0.6/32" {
		t.Errorf("the rule's dst_ip is %v, want the UE's host route", got)
	}
	if got := r["proto"]; got != uint32(17) {
		t.Errorf("the rule's proto is %v, want udp (17)", got)
	}
	if got := r["dst_port_low"]; got != uint32(1000) {
		t.Errorf("the rule's dst_port_low is %v, want 1000", got)
	}
	if got := r["dst_port_high"]; got != uint32(2000) {
		t.Errorf("the rule's dst_port_high is %v, want 2000", got)
	}
	if got := r["drop"]; got != false {
		t.Errorf("a forwarding PDR's rule carries drop=%v, want false", got)
	}
	if _, ok := r["src_ip"]; ok {
		t.Errorf("the SDF's source is \"any\", but the rule constrains it: %v", r["src_ip"])
	}
	// The PDR's match is the firewall rule: nothing may also be written to the
	// WildcardMatch table for it (rules is this test side's reader of that
	// table).
	if n := len(rules(rec.last())); n != 0 {
		t.Errorf("the firewall path also wrote %d WildcardMatch rules", n)
	}
}

func TestAnIPv6SDFPrefixCompilesOnTheFirewallPathOnly(t *testing.T) {
	// An IPv6 SDF prefix has no four bytes to be masked into, so the
	// WildcardMatch key refuses it rather than widening it to "any address"
	// (TestANonIPv4PDIIsRefusedNotWidened). The firewall's table holds both
	// families in one policy -- the family is part of a group's identity -- so
	// the same request compiles on the firewall path and the rule carries the
	// prefix as a CIDR string with its length.
	req := func() *message.SessionEstablishmentRequest {
		return firewallEstablishment(0x5f02, "10.45.0.6", 10, "permit out udp from any to 2001:db8::/32 53")
	}

	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	if got := cause(t, c.Establish(req())); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("the WildcardMatch path answered cause %d, want a rule failure", got)
	}
	if len(rec.txns) != 0 {
		t.Error("a refused session on the WildcardMatch path wrote to the dataplane")
	}

	rec = &recorder{}
	c = New(firewallConfig("", "fw_dl"), rec, quietLogger())
	if got := cause(t, c.Establish(req())); got != ie.CauseRequestAccepted {
		t.Fatalf("the firewall path answered cause %d, want accepted", got)
	}
	policy := firewallPolicy(t, rec.last(), "fw_dl/rules")
	if len(policy) != 1 {
		t.Fatalf("the policy holds %d rules, want 1", len(policy))
	}
	r := policy[0]
	if got := r["dst_ip"]; got != "2001:db8::/32" {
		t.Errorf("the rule's dst_ip is %v, want the IPv6 prefix", got)
	}
	if got := r["dst_port_low"]; got != uint32(53) {
		t.Errorf("the rule's dst_port_low is %v, want 53", got)
	}
	if got := r["dst_port_high"]; got != uint32(53) {
		t.Errorf("the rule's dst_port_high is %v, want 53", got)
	}
}

func TestAMixedFamilyFirewallRuleIsRefused(t *testing.T) {
	// A firewall rule's family comes from its prefixes, and one rule names one:
	// the module refuses "'x' and 'y' are different families" itself, and a
	// refused rule refuses the whole policy -- which is every live session's
	// rules. So the compiler refuses the session here, where the SMF learns it
	// (cause 73), and the policy of the sessions already programmed is left
	// alone.
	rec := &recorder{}
	c := New(firewallConfig("", "fw_dl"), rec, quietLogger())
	// The SDF's source is IPv6 and the destination is the UE's address, whose
	// family the PDI fixes at IPv4: the two sides of one rule cannot agree.
	req := firewallEstablishment(0x5f03, "10.45.0.6", 10, "permit out tcp from 2001:db8::/32 to assigned")
	if got := cause(t, c.Establish(req)); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a mixed-family rule answered cause %d, want a rule failure", got)
	}
	if len(rec.txns) != 0 {
		t.Error("a refused session wrote a firewall policy")
	}
}

func TestAFirewallDeploymentThatBuffersIsRefused(t *testing.T) {
	// A buffering PDR's packets are held by the store its rule delivers them
	// to, and a firewall rule has no gate: its verdict is drop or pass on the
	// output the packet arrived on. Compiling it would answer the SMF that its
	// downlink is held while nothing holds it.
	cfg := firewallConfig("", "fw_dl")
	cfg.Buffering = &Buffering{Store: "buf", Counter: "cnt_buf", Gate: 1}
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())
	req := firewallEstablishment(0x5f04, "10.45.0.7", 10, "permit out udp from any to assigned 53")
	req.CreateFAR[0] = ie.NewCreateFAR(
		ie.NewFARID(1),
		ie.NewApplyAction(applyBuff),
		ie.NewBARID(1),
	)
	req.CreateBAR = barDurationAndCount()
	if got := cause(t, c.Establish(req)); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a BUFF PDR on the firewall path answered cause %d, want a rule failure", got)
	}
	if len(rec.txns) != 0 {
		t.Error("a refused session wrote a firewall policy")
	}
}

func TestAFirewallRuleCarriesThePDRAVerdict(t *testing.T) {
	// A FAR whose Apply Action is DROP compiles to the drop gate on the
	// WildcardMatch path; the firewall's own words are drop and pass, so the
	// rule carries the verdict itself.
	rec := &recorder{}
	c := New(firewallConfig("", "fw_dl"), rec, quietLogger())
	req := firewallEstablishment(0x5f05, "10.45.0.8", 10, "permit out udp from any to assigned 53")
	req.CreateFAR[0] = ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyDrop))
	if got := cause(t, c.Establish(req)); got != ie.CauseRequestAccepted {
		t.Fatalf("a DROP FAR answered cause %d", got)
	}
	policy := firewallPolicy(t, rec.last(), "fw_dl/rules")
	if len(policy) != 1 {
		t.Fatalf("the policy holds %d rules, want 1", len(policy))
	}
	if got := policy[0]["drop"]; got != true {
		t.Errorf("a DROP FAR's rule carries drop=%v, want true", got)
	}
}

func TestAForwardingFirewallRuleCarriesItsResult(t *testing.T) {
	// The stock module writes a rule's action_id into the packet's metadata
	// (BESS D-141) and its result record into the meter and next-hop
	// attributes. Each PDR has its own id, so the policy -- one resource for
	// every session -- carries many ids, one per rule. A rule that drops names
	// neither.
	rec := &recorder{}
	c := New(firewallConfig("", "fw_dl"), rec, quietLogger())
	req := firewallEstablishment(0x5f06, "10.45.0.9", 10, "permit out udp from any to assigned 53")
	if got := cause(t, c.Establish(req)); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	policy := firewallPolicy(t, rec.last(), "fw_dl/rules")
	id, ok := policy[0]["action_id"].(uint32)
	if !ok || id == 0 {
		t.Fatalf("a forwarding rule carries action_id %v, want a non-zero id", policy[0]["action_id"])
	}
	result, ok := policy[0]["result"].([]byte)
	if !ok || len(result) != 16 {
		t.Fatalf("the forwarding rule carries result %v, want two meter levels, a next hop and a route domain", policy[0]["result"])
	}
	if hop := binary.BigEndian.Uint32(result[8:12]); hop != 2 {
		t.Errorf("the rule's result takes next hop %d, want the access side's (2)", hop)
	}
	if domain := binary.BigEndian.Uint32(result[12:]); domain != 0 {
		t.Errorf("the rule's result writes route domain %d, want the default instance's (0)", domain)
	}

	rec = &recorder{}
	c = New(firewallConfig("", "fw_dl"), rec, quietLogger())
	req = firewallEstablishment(0x5f07, "10.45.0.10", 10, "permit out udp from any to assigned 53")
	req.CreateFAR[0] = ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyDrop))
	if got := cause(t, c.Establish(req)); got != ie.CauseRequestAccepted {
		t.Fatalf("a DROP FAR answered cause %d", got)
	}
	drop := firewallPolicy(t, rec.last(), "fw_dl/rules")[0]
	if got, ok := drop["action_id"]; ok {
		t.Errorf("a dropping rule names the action %v", got)
	}
	if got, ok := drop["result"]; ok {
		t.Errorf("a dropping rule carries the result %v", got)
	}
}

func TestTheFirewallPathIsOptIn(t *testing.T) {
	// No firewall module configured: nothing changes. The two shapes the
	// firewall path lifts are refused as they always were, the WildcardMatch
	// rules are written as they always were, and no change names a firewall
	// policy -- which is what the arms in ci/ run against (the installed graph
	// carries no `firewall` module, and a graph that names one does not load).
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	if got := cause(t, c.Establish(
		firewallEstablishment(0x5f06, "10.45.0.6", 10, "permit out udp from any to assigned 1000-2000"),
	)); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a port range answered cause %d with no firewall module, want a rule failure", got)
	}
	if got := cause(t, c.Establish(
		firewallEstablishment(0x5f07, "10.45.0.6", 10, "permit out udp from any to 2001:db8::/32 53"),
	)); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("an IPv6 SDF prefix answered cause %d with no firewall module, want a rule failure", got)
	}
	if len(rec.txns) != 0 {
		t.Fatal("refused sessions wrote to the dataplane")
	}

	if got := cause(t, c.Establish(establishment(0x5f08, "10.45.0.6"))); got != ie.CauseRequestAccepted {
		t.Fatalf("an ordinary session answered cause %d", got)
	}
	if len(rules(rec.last())) == 0 {
		t.Error("the session wrote no WildcardMatch rule")
	}
	for _, ch := range rec.last() {
		if _, ok := ch.Value["rules"]; ok && ch.Key == nil {
			t.Errorf("a graph with no firewall module wrote the policy %s", ch.Resource)
		}
	}
}

func TestTheFirewallPolicyIsTheUnionOfTheLiveSessions(t *testing.T) {
	// A firewall's rules resource is a singleton: it holds the whole policy,
	// and the module builds the table whole and swaps it. So a session's
	// transaction carries the policy of every live session -- a write of one
	// session's rules alone would erase the rules the sessions already
	// programmed have, and a packet no rule matches is *dropped* by the module,
	// not passed. The order is the spec's own: TS 29.244 8.2.11 has the lower
	// Precedence value win, and a firewall list applies its first matching rule,
	// so the list is sorted by Precedence ascending.
	rec := &recorder{}
	c := New(firewallConfig("", "fw_dl"), rec, quietLogger())
	first := firewallEstablishment(0x5f10, "10.45.0.10", 10, "permit out udp from any to assigned 1000-2000")
	if got := cause(t, c.Establish(first)); got != ie.CauseRequestAccepted {
		t.Fatalf("the first session answered cause %d", got)
	}
	second := firewallEstablishment(0x5f11, "10.45.0.11", 5, "permit out tcp from any to assigned 80")
	if got := cause(t, c.Establish(second)); got != ie.CauseRequestAccepted {
		t.Fatalf("the second session answered cause %d", got)
	}
	policy := firewallPolicy(t, rec.last(), "fw_dl/rules")
	if len(policy) != 2 {
		t.Fatalf("the policy holds %d rules, want both sessions'", len(policy))
	}
	// The second session's Precedence is the lower one, so its rule is first.
	if got := policy[0]["dst_ip"]; got != "10.45.0.11/32" {
		t.Errorf("the first rule's dst_ip is %v, want the lower Precedence session's", got)
	}
	if got := policy[1]["dst_ip"]; got != "10.45.0.10/32" {
		t.Errorf("the second rule's dst_ip is %v, want the other session's", got)
	}
}

func TestDeletingASessionRewritesTheFirewallPolicy(t *testing.T) {
	// The deletion withdraws one rule of a list rather than a key: the policy
	// it writes holds the sessions that are left, and the last deletion writes
	// an empty one -- a policy left behind would pass packets no session owns.
	rec := &recorder{}
	c := New(firewallConfig("", "fw_dl"), rec, quietLogger())
	first := c.Establish(firewallEstablishment(
		0x5f20, "10.45.0.20", 10, "permit out udp from any to assigned 1000-2000",
	)).(*message.SessionEstablishmentResponse)
	if got := cause(t, first); got != ie.CauseRequestAccepted {
		t.Fatalf("the first session answered cause %d", got)
	}
	second := c.Establish(firewallEstablishment(
		0x5f21, "10.45.0.21", 10, "permit out tcp from any to assigned 80",
	)).(*message.SessionEstablishmentResponse)
	if got := cause(t, second); got != ie.CauseRequestAccepted {
		t.Fatalf("the second session answered cause %d", got)
	}

	del := c.Delete(message.NewSessionDeletionRequest(0, 0, upFSEID(t, first), 2, 0))
	if got := cause(t, del); got != ie.CauseRequestAccepted {
		t.Fatalf("the deletion answered cause %d", got)
	}
	policy := firewallPolicy(t, rec.last(), "fw_dl/rules")
	if len(policy) != 1 {
		t.Fatalf("the policy holds %d rules after the deletion, want the one left", len(policy))
	}
	if got := policy[0]["dst_ip"]; got != "10.45.0.21/32" {
		t.Errorf("the rule left in the policy is %v, want the live session's", got)
	}

	del = c.Delete(message.NewSessionDeletionRequest(0, 0, upFSEID(t, second), 3, 0))
	if got := cause(t, del); got != ie.CauseRequestAccepted {
		t.Fatalf("the last deletion answered cause %d", got)
	}
	if left := firewallPolicy(t, rec.last(), "fw_dl/rules"); len(left) != 0 {
		t.Errorf("the last deletion left %d rules in the policy, want none", len(left))
	}
}

func TestAModificationWritesItsRulesOnce(t *testing.T) {
	// A modification's session is already in the model when its policy is
	// built, so the session is named once, not twice: a policy that listed its
	// rules twice would hand the module a table with a duplicate rule in it --
	// the first of the pair always winning, the second never reachable.
	rec := &recorder{}
	c := New(firewallConfig("", "fw_dl"), rec, quietLogger())
	resp := c.Establish(firewallEstablishment(
		0x5f30, "10.45.0.30", 10, "permit out udp from any to assigned 1000-2000",
	)).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	// A modification carrying a new Precedence for the same PDR: the whole
	// session is rewritten (docs/design.md, "Modification semantics").
	mod := message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 2, 0,
		ie.NewUpdatePDR(ie.NewPDRID(1), ie.NewPrecedence(3),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x06, "10.45.0.30", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to assigned 1000-2000", "", "", "", 0)),
			ie.NewFARID(1)),
	)
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification answered cause %d", got)
	}
	policy := firewallPolicy(t, rec.last(), "fw_dl/rules")
	if len(policy) != 1 {
		t.Fatalf("the policy holds %d rules after the modification, want one", len(policy))
	}
	if got := policy[0]["dst_ip"]; got != "10.45.0.30/32" {
		t.Errorf("the rule's dst_ip is %v, want the session's UE", got)
	}
}

func TestTheSweepReplacesAStaleFirewallPolicy(t *testing.T) {
	// The restart wall reaches the firewall path too: an earlier run's policy
	// matches packets this process has no session for, and a firewall rule's
	// verdict is drop or *pass*, so a controller that came up beside one would
	// pass traffic no session it knows owns. The policy is a singleton, so
	// there is no key to erase: the sweep writes an empty one, which no rule
	// matches -- and writes nothing at all where the policy is already empty.
	cfg := firewallConfig("", "fw_dl")
	f := &sweepFake{contents: map[string][]bess.Entry{}}
	c := New(cfg, f, quietLogger())
	for _, name := range c.resources() {
		if name == firewallRes(cfg.Down) {
			continue
		}
		f.contents[name] = []bess.Entry{{Key: map[string]any{"id": uint64(1)}}}
	}
	// What reads back is the policy as the daemon holds it: one entry, no key,
	// and the rules of a run that ended.
	f.contents[firewallRes(cfg.Down)] = []bess.Entry{{Value: map[string]any{
		"rules": []any{map[string]any{"src_ip": "10.48.0.0/16", "drop": false}},
	}}}
	if err := c.Sweep(context.Background()); err != nil {
		t.Fatalf("the sweep: %v", err)
	}
	if len(f.changes) != 1 {
		t.Fatalf("the sweep wrote %d transactions, want one", len(f.changes))
	}
	found := false
	for _, ch := range f.changes[0] {
		if ch.Resource != firewallRes(cfg.Down) {
			continue
		}
		found = true
		if ch.Key != nil {
			t.Errorf("the sweep erased the policy with a key: %v", ch.Key)
		}
		if rules, _ := ch.Value["rules"].([]map[string]any); len(rules) != 0 {
			t.Errorf("the sweep wrote the policy with %d rules, want an empty one", len(rules))
		}
	}
	if !found {
		t.Error("the sweep left an earlier run's firewall policy in place")
	}

	// A policy that is already empty is what this run would write: nothing to
	// change, so no transaction (an empty one is refused by the daemon).
	f = &sweepFake{contents: map[string][]bess.Entry{
		firewallRes(cfg.Down): {{Value: map[string]any{"rules": []any{}}}},
	}}
	c = New(cfg, f, quietLogger())
	if err := c.Sweep(context.Background()); err != nil {
		t.Fatalf("the sweep over an empty policy: %v", err)
	}
	if len(f.changes) != 0 {
		t.Errorf("the sweep wrote %d transactions over an empty policy, want none", len(f.changes))
	}
}

// TestAFirewallRulesUESideFollowsThePDIsSD: the firewall path places the UE IP
// address by the same rule as the WildcardMatch key -- 8.2.62 bit 3 says which
// side it is -- and its unconstrained side is an omitted field, so a PDI that
// names a destination constrains dst_ip alone.
func TestAFirewallRulesUESideFollowsThePDIsSD(t *testing.T) {
	rec := &recorder{}
	c := New(firewallConfig("", "fw_dl"), rec, quietLogger())
	req := message.NewSessionEstablishmentRequest(0, 0, 0x5f11, 1, 0,
		ie.NewFSEID(0x5f11, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				// V4 | S/D: the address is the packet's destination.
				ie.NewUEIPAddress(0x06, "192.0.2.9", "", 0, 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess))),
	)
	if got := cause(t, c.Establish(req)); got != ie.CauseRequestAccepted {
		t.Fatalf("a destination-flagged PDI on the firewall path answered cause %d, want accepted", got)
	}
	policy := firewallPolicy(t, rec.last(), "fw_dl/rules")
	if len(policy) != 1 {
		t.Fatalf("the policy holds %d rules, want 1", len(policy))
	}
	if got, ok := policy[0]["src_ip"]; ok {
		t.Errorf("the rule constrains src_ip to %v, want it omitted: the PDI named a destination", got)
	}
	if got := policy[0]["dst_ip"]; got != "192.0.2.9/32" {
		t.Errorf("the rule's dst_ip is %v, want the PDI's destination address", got)
	}
}

// TestAFirewallRuleRefusesTheSDContradiction: a downlink PDI whose filter names
// the UE as the flow's source ("from assigned") while its UE IP address IE says
// that address is the destination are two readings of one IE pair, and the
// firewall path refuses them as the key path does.
func TestAFirewallRuleRefusesTheSDContradiction(t *testing.T) {
	rec := &recorder{}
	c := New(firewallConfig("", "fw_dl"), rec, quietLogger())
	req := message.NewSessionEstablishmentRequest(0, 0, 0x5f12, 1, 0,
		ie.NewFSEID(0x5f12, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				// V4 | S/D: the UE's address is the destination.
				ie.NewUEIPAddress(0x06, "10.45.0.6", "", 0, 0),
				ie.NewSDFFilter("permit out ip from assigned to any", "", "", "", 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess))),
	)
	if got := cause(t, c.Establish(req)); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("the contradiction answered cause %d, want a rule failure", got)
	}
	if len(rec.txns) != 0 {
		t.Error("a refused session wrote to the dataplane")
	}
}
func TestFirewallRejectsPDRsWhoseTunnelIdentityItCannotMatch(t *testing.T) {
	rec := &recorder{}
	cfg := firewallConfig("fw_ul", "")
	c := New(cfg, rec, quietLogger())
	resp := c.Establish(establishmentWithFTEID(0x5f20, "10.45.0.6", 0x11223344))
	if got := cause(t, resp); got == ie.CauseRequestAccepted {
		t.Fatal("firewall accepted an FTEID PDR although it cannot key endpoint metadata")
	}
	if len(rec.txns) != 0 {
		t.Fatal("unsupported firewall/FTEID PDR reached Apply")
	}
}
