// SPDX-License-Identifier: BSD-3-Clause
package session

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/bess"
	"github.com/krsna1729/upf/internal/routing"
)

// twoInstances is the deployment these tests drive: two network instances that
// serve the same subscriber prefix -- docs/design.md's milestone 4 -- each with
// its own route domain, its own egress and its own name.
func twoInstances(t *testing.T) *routing.Domains {
	t.Helper()
	d, err := routing.New([]routing.Interface{
		{Instance: "internet", Domain: 0, NextHop: 1, Pool: []netip.Prefix{netip.MustParsePrefix("10.45.0.0/16")}},
		{Instance: "ims", Domain: 1, NextHop: 3, Pool: []netip.Prefix{netip.MustParsePrefix("10.45.0.0/16")}},
	}, 4)
	if err != nil {
		t.Fatalf("the two-instance deployment was refused: %v", err)
	}
	return d
}

// instancedConfig is testConfig for a graph whose tables classify by route
// domain (the downlink) and by the tunnel the packet arrived on (the uplink):
// the shape deploy/session-path.yaml takes when it serves two instances.
func instancedConfig(t *testing.T) Config {
	t.Helper()
	cfg := testConfig()
	cfg.Instances = twoInstances(t)
	cfg.Up.PDRFields = []Field{SrcIP, DstIP, Proto, SrcPort, DstPort, UpfTEID, QFI}
	cfg.Down.PDRFields = []Field{SrcIP, DstIP, Proto, SrcPort, DstPort, RouteDomain}
	return cfg
}

// threeInstanceConfig is instancedConfig with a third instance: a test that
// moves a forward between instances has to see a hop that is neither the one it
// starts at nor the one a cleared field falls back to.
func threeInstanceConfig(t *testing.T) Config {
	t.Helper()
	cfg := testConfig()
	d, err := routing.New([]routing.Interface{
		{Instance: "internet", Domain: 0, NextHop: 1, Pool: []netip.Prefix{netip.MustParsePrefix("10.45.0.0/16")}},
		{Instance: "ims", Domain: 1, NextHop: 3, Pool: []netip.Prefix{netip.MustParsePrefix("10.45.0.0/16")}},
		{Instance: "voip", Domain: 2, NextHop: 4, Pool: []netip.Prefix{netip.MustParsePrefix("10.45.0.0/16")}},
	}, 4)
	if err != nil {
		t.Fatalf("the three-instance deployment was refused: %v", err)
	}
	cfg.Instances = d
	cfg.Up.PDRFields = []Field{SrcIP, DstIP, Proto, SrcPort, DstPort, UpfTEID, QFI}
	cfg.Down.PDRFields = []Field{SrcIP, DstIP, Proto, SrcPort, DstPort, RouteDomain}
	return cfg
}

// instancedEstablishment is establishmentWithFTEID with every PDI naming a
// network instance (8.2.4), which is what an SMF serving more than one sends.
func instancedEstablishment(cpSEID uint64, ueIP string, fteid uint32, instance string) *message.SessionEstablishmentRequest {
	est := establishmentWithFTEID(cpSEID, ueIP, fteid)
	est.CreatePDR = []*ie.IE{
		ie.NewCreatePDR(
			ie.NewPDRID(1),
			ie.NewPrecedence(100),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewNetworkInstance(instance),
				ie.NewFTEID(0x01, fteid, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, ueIP, "", 0, 0),
			),
			ie.NewFARID(1),
			ie.NewQERID(1),
		),
		ie.NewCreatePDR(
			ie.NewPDRID(2),
			ie.NewPrecedence(100),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewNetworkInstance(instance),
				ie.NewUEIPAddress(0x02, ueIP, "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to assigned 53", "", "", "", 0),
			),
			ie.NewFARID(2),
		),
	}
	return est
}

// ruleIn returns the rule a transaction wrote into one direction's table.
func ruleIn(t *testing.T, changes []bess.Change, table string) rule {
	t.Helper()
	for _, r := range rules(changes) {
		if strings.HasPrefix(r.change.Resource, table+"/") {
			return r
		}
	}
	t.Fatalf("no rule in %s among %d changes", table, len(changes))
	return rule{}
}

// nextHop is the Router next hop the rule carrying actionID writes into its
// result. The rule is found by its result, not by a separate action resource:
// the classifier writes the next hop itself.
func nextHop(t *testing.T, changes []bess.Change, actionID uint32) uint32 {
	t.Helper()
	for _, r := range rules(changes) {
		if r.actionID() == actionID && len(r.result()) >= 16 {
			return r.nextHop()
		}
	}
	t.Fatalf("no rule carries action %d, so no result names a next hop", actionID)
	return 0
}

// actionFields is the action data a rule's result carries, in the shape tests
// used when it lived in an ActionTable record.
func actionFields(t *testing.T, changes []bess.Change, dir Direction, actionID uint32) map[string]any {
	t.Helper()
	for _, r := range rules(changes) {
		if !strings.HasPrefix(r.change.Resource, rulesRes(dir)) {
			continue
		}
		if r.actionID() != actionID {
			continue
		}
		ids := r.meterIDs()
		return map[string]any{
			"meter_id":    ids[0],
			"meter_ids":   []uint32{ids[0], ids[1]},
			"next_hop_id": r.nextHop(),
		}
	}
	t.Fatalf("no rule in %s carries action %d", rulesRes(dir), actionID)
	return nil
}

// TestTwoInstancesRouteIndependently is docs/design.md's milestone 4: two
// subscribers behind the same private prefix, on two network instances. Both
// sessions are served, and the rule that selects each one is its own -- the
// domain on the downlink, the tunnel on the uplink -- so one instance's traffic
// cannot take the other's exit.
func TestTwoInstancesRouteIndependently(t *testing.T) {
	cfg := instancedConfig(t)
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())

	// The same subscriber address, two tunnels, two instances.
	resp := c.Establish(instancedEstablishment(1, "10.45.0.2", 0x11223344, "internet"))
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the first instance's session answered cause %d", got)
	}
	internet := rec.last()
	if len(rec.txns) != 1 {
		t.Fatalf("the establishment wrote %d transactions, want one", len(rec.txns))
	}
	resp = c.Establish(instancedEstablishment(2, "10.45.0.2", 0x11223345, "ims"))
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the second instance's session for the same address answered cause %d, want accepted: %s",
			got, "the domain is what tells the two apart")
	}
	ims := rec.last()
	if len(rec.txns) != 2 {
		t.Fatalf("the second establishment wrote %d transactions in all, want two", len(rec.txns))
	}

	// The uplink: the tunnel is the session's own identity, and it is in the
	// key -- without it the two rules would be one key, and the second session
	// would silently take the first one's rule.
	ulInternet := ruleIn(t, internet, "pdr_ul")
	ulIMS := ruleIn(t, ims, "pdr_ul")
	if got := binary.BigEndian.Uint32(ulInternet.value(5)); got != 0x11223344 {
		t.Errorf("the uplink key's tunnel field is %#x, want the internet session's 0x11223344", got)
	}
	if got := binary.BigEndian.Uint32(ulIMS.value(5)); got != 0x11223345 {
		t.Errorf("the uplink key's tunnel field is %#x, want the ims session's 0x11223345", got)
	}
	if !bytes.Equal(ulInternet.mask(5), []byte{0xff, 0xff, 0xff, 0xff}) {
		t.Errorf("the uplink key's tunnel mask is %x, want every byte constrained", ulInternet.mask(5))
	}

	// The downlink: the domain is what separates the same filter in two
	// instances, and it is what the deployment's interface writes into the
	// packet that arrives on it.
	dlInternet := ruleIn(t, internet, "pdr_dl")
	dlIMS := ruleIn(t, ims, "pdr_dl")
	if got := binary.BigEndian.Uint32(dlInternet.value(5)); got != 0 {
		t.Errorf("the downlink key's domain field is %d, want the internet instance's 0", got)
	}
	if got := binary.BigEndian.Uint32(dlIMS.value(5)); got != 1 {
		t.Errorf("the downlink key's domain field is %d, want the ims instance's 1", got)
	}

	// And the forwards leave by each instance's own egress.
	if got := nextHop(t, internet, ulInternet.actionID()); got != 1 {
		t.Errorf("the internet session's uplink forward takes next hop %d, want its instance's 1", got)
	}
	if got := nextHop(t, ims, ulIMS.actionID()); got != 3 {
		t.Errorf("the ims session's uplink forward takes next hop %d, want its instance's 3", got)
	}
	// The downlink keeps the access side's hop: a forward toward the UE leaves
	// through the encap whatever instance the PDI named.
	if got := nextHop(t, internet, dlInternet.actionID()); got != 2 {
		t.Errorf("the internet session's downlink forward takes next hop %d, want the access side's 2", got)
	}
	if got := nextHop(t, ims, dlIMS.actionID()); got != 2 {
		t.Errorf("the ims session's downlink forward takes next hop %d, want the access side's 2", got)
	}
}

// TestAPDINamingAnUnknownInstanceIsRefused: a name the deployment does not
// configure is a rule this UPF cannot place. Before the instance was read at
// all, such a rule was served by the default interface -- indistinguishable
// from one naming ours (docs/claims.md's row over 8.2.89/8.2.4).
func TestAPDINamingAnUnknownInstanceIsRefused(t *testing.T) {
	rec := &recorder{}
	c := New(instancedConfig(t), rec, quietLogger())
	resp := c.Establish(instancedEstablishment(1, "10.45.0.2", 0x11223344, "voip"))
	if got := cause(t, resp); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a PDI naming an unconfigured instance answered cause %d, want a rule failure", got)
	}
	if len(rec.txns) != 0 {
		t.Error("a refused session wrote to the dataplane")
	}
}

// TestAPDIWithoutAnInstanceTakesTheDefault: the IE is optional (8.2.4), and a
// rule that names none is a rule this deployment's first interface serves.
func TestAPDIWithoutAnInstanceTakesTheDefault(t *testing.T) {
	rec := &recorder{}
	c := New(instancedConfig(t), rec, quietLogger())
	resp := c.Establish(instancedEstablishment(1, "10.45.0.2", 0x11223344, ""))
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("a PDI naming no instance answered cause %d, want accepted", got)
	}
	changes := rec.last()
	ul := ruleIn(t, changes, "pdr_ul")
	dl := ruleIn(t, changes, "pdr_dl")
	if got := binary.BigEndian.Uint32(dl.value(5)); got != 0 {
		t.Errorf("the default interface's domain is %d, want the first configured one's (0)", got)
	}
	if got := nextHop(t, changes, ul.actionID()); got != 1 {
		t.Errorf("the default interface's uplink forward takes next hop %d, want its own (1)", got)
	}
}

// TestAnAddressOutsideTheInstancesPoolIsRefused: the deployment says what each
// interface serves, and an address elsewhere is a session this UPF places
// nowhere -- a success there would leave the SMF believing in a path no packet
// takes.
func TestAnAddressOutsideTheInstancesPoolIsRefused(t *testing.T) {
	rec := &recorder{}
	c := New(instancedConfig(t), rec, quietLogger())
	resp := c.Establish(instancedEstablishment(1, "10.46.0.2", 0x11223344, "internet"))
	if got := cause(t, resp); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("an address outside the instance's pool answered cause %d, want a rule failure", got)
	}
	if len(rec.txns) != 0 {
		t.Error("a refused session wrote to the dataplane")
	}
}

// TestTheTunnelFieldNeedsATunnel: a table that classifies by the tunnel cannot
// key a PDR whose PDI names no F-TEID -- TEID 0 would be claimed by every such
// session at once.
func TestTheTunnelFieldNeedsATunnel(t *testing.T) {
	cfg := instancedConfig(t)
	cfg.Down.PDRFields = []Field{SrcIP, DstIP, Proto, SrcPort, DstPort, UpfTEID}
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())
	// A downlink PDR has no F-TEID: the field has nothing to key.
	resp := c.Establish(instancedEstablishment(1, "10.45.0.2", 0x11223344, "internet"))
	if got := cause(t, resp); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a PDR with no tunnel in a tunnel-keyed table answered cause %d, want a rule failure", got)
	}
	if len(rec.txns) != 0 {
		t.Error("a refused session wrote to the dataplane")
	}
}

// withForwardInstance gives an establishment's uplink FAR a Network Instance
// inside its forwarding parameters (8.2.4): the shape an SMF uses when the
// traffic leaves by an instance other than the one the PDI selected.
func withForwardInstance(est *message.SessionEstablishmentRequest, instance string) *message.SessionEstablishmentRequest {
	// The first Create FAR is the uplink's (its destination is the core side,
	// as establishmentWithFTEID builds it); the downlink's is left alone.
	est.CreateFAR[0] = ie.NewCreateFAR(
		ie.NewFARID(1),
		ie.NewApplyAction(applyForw),
		ie.NewForwardingParameters(
			ie.NewDestinationInterface(ie.DstInterfaceCore),
			ie.NewNetworkInstance(instance),
		),
	)
	return est
}

// TestTheForwardsNetworkInstanceChoosesTheEgress: a FAR's Network Instance
// (8.2.4 inside the forwarding parameters) is where its traffic leaves by, and
// an SMF may name one the PDI did not -- the uplink rule of an N9 deployment
// selects a flow in one instance and sends it toward the peer UPF's.
func TestTheForwardsNetworkInstanceChoosesTheEgress(t *testing.T) {
	rec := &recorder{}
	c := New(instancedConfig(t), rec, quietLogger())

	// The PDI's instance is internet (domain 0), the forward's is ims (next hop
	// 3): the rule is classified where the flow came from and leaves where the
	// FAR says.
	resp := c.Establish(withForwardInstance(
		instancedEstablishment(1, "10.45.0.2", 0x11223344, "internet"), "ims"))
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("a FAR naming a configured instance answered cause %d, want accepted", got)
	}
	changes := rec.last()
	ul := ruleIn(t, changes, "pdr_ul")
	if got := binary.BigEndian.Uint32(ul.value(5)); got != 0x11223344 {
		t.Errorf("the rule's tunnel field is %#x, want the session's own TEID", got)
	}
	if got := nextHop(t, changes, ul.actionID()); got != 3 {
		t.Errorf("the forward takes next hop %d, want the FAR's instance's 3", got)
	}

	// And a name the deployment does not serve is refused, like the PDI's.
	rec2 := &recorder{}
	c2 := New(instancedConfig(t), rec2, quietLogger())
	resp = c2.Establish(withForwardInstance(
		instancedEstablishment(2, "10.45.0.3", 0x11223346, "internet"), "voip"))
	if got := cause(t, resp); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a FAR naming an unconfigured instance answered cause %d, want a rule failure", got)
	}
	if len(rec2.txns) != 0 {
		t.Error("a refused session wrote to the dataplane")
	}
}

// TestTheInstanceIsReadInBothTheFormsAnSMFSends: the IEs' Network Instance is
// an OctetString (8.2.4), and the name arrives either as its own bytes or in
// the DNS-label form an SMF that encodes its DNN APN-style writes (open5gs
// sends "internet" as 0x08 followed by the letters). Both must resolve to the
// deployment's interface, and a plain name must not be cut short at a first
// byte that happens to be small enough to look like a label length.
func TestTheInstanceIsReadInBothTheFormsAnSMFSends(t *testing.T) {
	for _, c := range []struct {
		name     string
		iface    string // the deployment's instance name
		encoded  *ie.IE // the IE an SMF sends for it
		accepted bool
	}{
		{"the bytes", "internet", ie.NewNetworkInstance("internet"), true},
		{"DNS labels", "internet", ie.NewNetworkInstanceFQDN("internet"), true},
		{"a dotted name's bytes", "my.dnn", ie.NewNetworkInstance("my.dnn"), true},
		{"a dotted name in labels", "my.dnn", ie.NewNetworkInstanceFQDN("my.dnn"), true},
		{"a name that is not served", "ims", ie.NewNetworkInstance("internet"), false},
		{"a digit-led plain name", "5gc", ie.NewNetworkInstance("5gc"), true},
		{"labels with a root octet", "internet", ie.New(ie.NetworkInstance, []byte("\x08internet\x00")), true},
		{"the bytes with a root octet", "internet", ie.New(ie.NetworkInstance, []byte("internet\x00")), true},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg := instancedConfig(t)
			domains, err := routing.New([]routing.Interface{
				{Instance: c.iface, Domain: 0, NextHop: 1,
					Pool: []netip.Prefix{netip.MustParsePrefix("10.45.0.0/16")}},
			}, 2)
			if err != nil {
				t.Fatalf("the one-interface deployment was refused: %v", err)
			}
			cfg.Instances = domains

			est := instancedEstablishment(1, "10.45.0.2", 0x11223344, "")
			est.CreatePDR = []*ie.IE{
				ie.NewCreatePDR(
					ie.NewPDRID(1),
					ie.NewPrecedence(100),
					ie.NewPDI(
						ie.NewSourceInterface(ie.SrcInterfaceAccess),
						c.encoded,
						ie.NewFTEID(0x01, 0x11223344, net.ParseIP("192.0.2.1"), nil, 0),
						ie.NewUEIPAddress(0x02, "10.45.0.2", "", 0, 0),
					),
					ie.NewFARID(1),
				),
			}
			rec := &recorder{}
			compiler := New(cfg, rec, quietLogger())
			resp := compiler.Establish(est)
			got := cause(t, resp)
			if c.accepted && got != ie.CauseRequestAccepted {
				t.Errorf("the instance %q written as %s answered cause %d, want accepted",
					c.iface, c.name, got)
			}
			if !c.accepted && got == ie.CauseRequestAccepted {
				t.Errorf("the instance %q written as %s was accepted, and no interface serves it",
					c.iface, c.name)
			}
		})
	}
}

// TestAnUpdateFARKeepsWhatItDoesNotCarry: an Update FAR carries what changes
// (7.5.4.3), and the fields it leaves out keep the values the session has --
// their zero values are not neutral. No Apply Action means no forward,
// destination interface 0 is the access side (which stops the instance being
// resolved at all, so an uplink forward would go back out of N3), and an empty
// instance falls back to the PDI's, which is another exit. Each update below
// moves the forward to a hop that neither of the bugs above would produce.
func TestAnUpdateFARKeepsWhatItDoesNotCarry(t *testing.T) {
	rec := &recorder{}
	c := New(threeInstanceConfig(t), rec, quietLogger())
	if got := cause(t, c.Establish(withForwardInstance(
		instancedEstablishment(1, "10.45.0.2", 0x11223344, "internet"), "ims"))); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	hop := func(t *testing.T, req *message.SessionModificationRequest) uint32 {
		t.Helper()
		if got := cause(t, c.Modify(req)); got != ie.CauseRequestAccepted {
			t.Fatalf("the update answered cause %d", got)
		}
		changes := rec.last()
		ul := ruleIn(t, changes, "pdr_ul")
		return nextHop(t, changes, ul.actionID())
	}

	// The Apply Action, with the forwarding parameters a forwarding FAR must
	// carry and no instance among them: the forward does not move, so it still
	// leaves by the FAR's instance (ims, 3) -- not by the PDI's (internet, 1),
	// which is where an update that dropped the instance would send it.
	if got := hop(t, message.NewSessionModificationRequest(0, 0, 1, 2, 0,
		ie.NewFSEID(1, nil, nil),
		ie.NewUpdateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewUpdateForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))))); got != 3 {
		t.Errorf("after an Apply-Action-only update the forward takes next hop %d, want the instance's 3 still", got)
	}

	// The instance, in the update form: that form is a different IE from the
	// create form, and naming one moves the forward -- it leaves by voip (4),
	// not by the PDI's internet (1), which is where the record's instance would
	// take it.
	if got := hop(t, message.NewSessionModificationRequest(0, 0, 1, 3, 0,
		ie.NewFSEID(1, nil, nil),
		ie.NewUpdateFAR(ie.NewFARID(1),
			ie.NewApplyAction(applyForw),
			ie.NewUpdateForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceCore),
				ie.NewNetworkInstance("voip"))))); got != 4 {
		t.Errorf("naming an instance in the update form took next hop %d, want voip's 4", got)
	}

	// The destination interface, and its value is 0: the access side is a value
	// an SMF names, not an absent field, so the forward moves -- the instance is
	// not resolved then, and an uplink PDR's forward toward the access side
	// leaves through the encap, which the downlink direction's own hop (2) is,
	// whichever direction the PDR is on.
	if got := hop(t, message.NewSessionModificationRequest(0, 0, 1, 4, 0,
		ie.NewFSEID(1, nil, nil),
		ie.NewUpdateFAR(ie.NewFARID(1),
			ie.NewApplyAction(applyForw),
			ie.NewUpdateForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess))))); got != 2 {
		t.Errorf("an update to the access side took next hop %d, want the access side's 2", got)
	}

	// And back to the core side: the instance those two updates did not carry
	// is voip still. An update that cleared it would leave the forward on the
	// PDI's instance (1) instead.
	if got := hop(t, message.NewSessionModificationRequest(0, 0, 1, 5, 0,
		ie.NewFSEID(1, nil, nil),
		ie.NewUpdateFAR(ie.NewFARID(1),
			ie.NewApplyAction(applyForw),
			ie.NewUpdateForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))))); got != 4 {
		t.Errorf("an update back to the core side took next hop %d, want voip's 4 still", got)
	}
}

// TestAOneInstanceDeploymentIsUnchanged: with no -instances the compiler reads
// no Network Instance, every rule is domain 0, and each direction keeps the
// next hop the deployment's flags gave it -- the tables that existed before the
// domains did keep working.
func TestAOneInstanceDeploymentIsUnchanged(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(establishmentWithFTEID(1, "10.45.0.2", 0x11223344))
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the one-instance deployment answered cause %d, want accepted", got)
	}
	changes := rec.last()
	ul := ruleIn(t, changes, "pdr_ul")
	dl := ruleIn(t, changes, "pdr_dl")
	// The uplink table carries the QFI field and the downlink's does not: the
	// rules take exactly the fields each graph declares.
	if len(ul.values) != 6 || len(dl.values) != 5 {
		t.Errorf("the rules carry %d and %d fields, want the tables' own six and five",
			len(ul.values), len(dl.values))
	}
	if got := nextHop(t, changes, ul.actionID()); got != 1 {
		t.Errorf("the uplink forward takes next hop %d, want -n6-next-hop's 1", got)
	}
	if got := nextHop(t, changes, dl.actionID()); got != 2 {
		t.Errorf("the downlink forward takes next hop %d, want -n3-next-hop's 2", got)
	}
}

// TestAnUpdateThatRenamesTheInstanceMovesTheRule: the domain is part of the
// rule's key, so a modification that puts a PDR in another instance erases the
// rule it left behind rather than leaving packets selected by both.
func TestAnUpdateThatRenamesTheInstanceMovesTheRule(t *testing.T) {
	rec := &recorder{}
	c := New(instancedConfig(t), rec, quietLogger())
	if got := cause(t, c.Establish(instancedEstablishment(1, "10.45.0.2", 0x11223344, "internet"))); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	moved := instancedEstablishment(1, "10.45.0.2", 0x11223344, "ims")
	req := message.NewSessionModificationRequest(0, 0, 1, 2, 0,
		ie.NewFSEID(1, nil, nil),
		moved.CreatePDR[1], // the downlink PDR, in the other instance now
	)
	resp := c.Modify(req)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the update answered cause %d", got)
	}
	changes := rec.last()
	var erased, written bool
	for _, ch := range changes {
		if !strings.HasPrefix(ch.Resource, "pdr_dl/") {
			continue
		}
		if ch.Value == nil {
			erased = true
		} else {
			written = true
		}
	}
	if !erased || !written {
		t.Errorf("the move wrote %d changes in pdr_dl (erased=%v written=%v), want the old key erased and the new one written",
			len(changes), erased, written)
	}
}

// TestAPDIsDestinationAddressGoesInTheDestinationField: 8.2.62's bit 3 (S/D)
// names the side the UE IP address IE's address appears on. Set, the address is
// a destination -- an Access PDR matching the CP function's address for DHCP or
// RADIUS (5.2.1's own example) -- and compiling it as the source (the side the
// Source Interface implies) writes a rule that matches nothing the SMF
// described. The address is also outside the interface's pool, which is asked
// about the session's UE address alone: this one is another node's.
func TestAPDIsDestinationAddressGoesInTheDestinationField(t *testing.T) {
	rec := &recorder{}
	c := New(instancedConfig(t), rec, quietLogger())
	req := message.NewSessionEstablishmentRequest(0, 0, 0x5561, 1, 0,
		ie.NewFSEID(0x5561, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewNetworkInstance("internet"),
				ie.NewFTEID(0x01, 0x11223344, net.ParseIP("192.0.2.1"), nil, 0),
				// V4 | S/D: the address is the packet's destination.
				ie.NewUEIPAddress(0x06, "192.0.2.9", "", 0, 0)),
			ie.NewFARID(1)),
		ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewNetworkInstance("internet"),
				ie.NewUEIPAddress(0x02, "10.45.0.2", "", 0, 0),
				ie.NewSDFFilter("permit out ip from any to assigned", "", "", "", 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
	)
	if got := cause(t, c.Establish(req)); got != ie.CauseRequestAccepted {
		t.Fatalf("a PDI whose address is a destination answered cause %d, want accepted", got)
	}
	ul := ruleIn(t, rec.last(), "pdr_ul")
	if got := ul.value(1); !bytes.Equal(got, []byte{192, 0, 2, 9}) {
		t.Errorf("the uplink key's destination is %v, want the PDI's destination address", got)
	}
	if got := ul.mask(1); !bytes.Equal(got, []byte{0xff, 0xff, 0xff, 0xff}) {
		t.Errorf("the uplink key's destination mask is %v, want a /32", got)
	}
	if got := ul.mask(0); !bytes.Equal(got, []byte{0, 0, 0, 0}) {
		t.Errorf("the uplink key's source mask is %v, want unconstrained: the PDI named no source", got)
	}
}

// TestADestinationAddressIsNotTheSessionsUEAddress: the bit that makes an
// Access PDR's address a destination also says it is not the subscriber's, so
// a PDI that names no address does not inherit it -- and a session with no UE
// address anywhere is refused rather than keyed on another node's address. The
// address here is inside the interface's pool, so it is the split (not the
// pool) that decides: read as the UE's, the session would stand with the
// downlink keyed on it.
func TestADestinationAddressIsNotTheSessionsUEAddress(t *testing.T) {
	rec := &recorder{}
	c := New(instancedConfig(t), rec, quietLogger())
	req := message.NewSessionEstablishmentRequest(0, 0, 0x5563, 1, 0,
		ie.NewFSEID(0x5563, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewNetworkInstance("internet"),
				ie.NewFTEID(0x01, 0x11223344, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x06, "10.45.0.9", "", 0, 0)),
			ie.NewFARID(1)),
		// The downlink names no address of its own: it would inherit the
		// session's, and there is none.
		ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewNetworkInstance("internet"),
				ie.NewSDFFilter("permit out ip from 203.0.113.7 to any", "", "", "", 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess))),
	)
	if got := cause(t, c.Establish(req)); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a session whose only address is a destination's answered cause %d, want a rule failure", got)
	}
	if len(rec.txns) != 0 {
		t.Error("a refused session wrote to the dataplane")
	}
}
