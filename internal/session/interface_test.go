// SPDX-License-Identifier: BSD-3-Clause

// The Source Interface values of a PDR's PDI (TS 29.244 8.2.2, Table
// 8.2.2-1), and the side each names. The value says which side the packet came
// from: Access is the access side, the others are the sides toward the
// subscriber -- Core, the service LAN's interface and the 5G VN's internal
// interface, the last of them being where a re-injected packet comes back in.
// A value this UP does not serve (the CP function's own path, and the Spare
// values) is refused with the cause the SMF can act on rather than carried
// into a chain, which is what used to happen to all of them.

package session

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/routing"
)

// subscriberSideEstablishment is a session whose subscriber-side PDR (the one
// with the SDF filter, the downlink's shape) names `srcIfc` rather than Core:
// the service LAN's interface or the 5G VN's internal interface, which are the
// values this UP serves and used to put in the wrong chain.
func subscriberSideEstablishment(cpSEID uint64, ueIP string, fteid uint32, srcIfc uint8) *message.SessionEstablishmentRequest {
	return message.NewSessionEstablishmentRequest(0, 0, cpSEID, 1, 0,
		ie.NewNodeID("", "", "smf"),
		ie.NewFSEID(cpSEID, nil, nil),
		ie.NewCreatePDR(
			ie.NewPDRID(1),
			ie.NewPrecedence(100),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceAccess),
				testFTEID(fteid),
				ie.NewUEIPAddress(0x02, ueIP, "", 0, 0),
			),
			ie.NewFARID(1),
		),
		ie.NewCreateFAR(
			ie.NewFARID(1),
			ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore)),
		),
		ie.NewCreatePDR(
			ie.NewPDRID(2),
			ie.NewPrecedence(100),
			ie.NewPDI(
				ie.NewSourceInterface(srcIfc),
				ie.NewUEIPAddress(0x06, ueIP, "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to assigned 53", "", "", "", 0),
			),
			ie.NewFARID(2),
		),
		ie.NewCreateFAR(
			ie.NewFARID(2),
			ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceAccess),
				ie.NewOuterHeaderCreation(0x0100, 0x11223344, "10.20.30.2", "", 0, 0, 0),
			),
		),
	)
}

// TestASubscriberSideSourceInterfaceValueIsMatchedTowardTheSubscriber: the
// service LAN's interface and the 5G VN's internal interface are the
// subscriber's side, so a PDI naming one of them compiles into the downlink
// chain -- with the access side's egress -- rather than into the uplink chain,
// which is where the value used to end up.
func TestASubscriberSideSourceInterfaceValueIsMatchedTowardTheSubscriber(t *testing.T) {
	for _, c := range []struct {
		name   string
		srcIfc uint8
	}{
		{"SGi-LAN/N6-LAN (2)", ie.SrcInterfaceSGiLANN6LAN},
		{"5G VN Internal (4)", ie.SrcInterface5GVNInternal},
	} {
		t.Run(c.name, func(t *testing.T) {
			rec := &recorder{}
			cfg := testConfig()
			c2 := New(cfg, rec, quietLogger())
			resp := c2.Establish(subscriberSideEstablishment(0x7301, "10.45.0.8", 0x51, c.srcIfc))
			if got := cause(t, resp); got != ie.CauseRequestAccepted {
				t.Fatalf("the establishment answered cause %d", got)
			}
			changes := rec.last()
			r := ruleIn(t, changes, cfg.Down.PDRTable)
			if got := r.value(fieldDstIP); len(got) != 4 || got[3] != 8 {
				t.Errorf("the downlink rule matches %v, want the PDI's own subscriber-side PDR", got)
			}
			// The direction's own egress is the fallback: the FAR names
			// Destination Interface Access, so it leaves through the encap.
			if got := nextHop(t, changes, r.actionID()); got != cfg.Down.NextHop {
				t.Errorf("the forward takes next hop %d, want the access side's %d", got, cfg.Down.NextHop)
			}
			// The other PDR -- the uplink one -- is the uplink's alone.
			if n := len(changesFor(changes, cfg.Up.PDRTable+"/rules")); n != 1 {
				t.Errorf("the uplink table holds %d rules, want the one uplink PDR's", n)
			}
			if n := len(changesFor(changes, cfg.Down.PDRTable+"/rules")); n != 1 {
				t.Errorf("the downlink table holds %d rules, want the one subscriber-side PDR's", n)
			}
		})
	}
}

// TestEverySourceInterfaceValueIsServedOrRefused is the whole table: the four
// values this UP serves compile, and the rest -- the CP function's own path and
// the Spare values -- are refused with the cause that says the rule cannot be
// carried, so the SMF is not told a session is standing that matches nothing.
func TestEverySourceInterfaceValueIsServedOrRefused(t *testing.T) {
	served := map[uint8]bool{
		ie.SrcInterfaceAccess: true, ie.SrcInterfaceCore: true,
		ie.SrcInterfaceSGiLANN6LAN: true, ie.SrcInterface5GVNInternal: true,
	}
	for v := uint8(0); v <= 15; v++ {
		if served[v] {
			continue
		}
		_, err := parsePDR(ie.NewCreatePDR(
			ie.NewPDRID(1),
			ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(v), ie.NewUEIPAddress(0x02, "10.45.0.2", "", 0, 0)),
			ie.NewFARID(1),
		))
		if err == nil {
			t.Errorf("the Source Interface value %d was accepted", v)
			continue
		}
		if !errors.Is(err, errNotExpressible) {
			t.Errorf("the refusal of value %d is %v, want the rule-failure cause", v, err)
		}
		want := "Source Interface value " + strconv.Itoa(int(v)) + " is not one this UP serves"
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal of value %d says %q, want it to name the IE and the value", v, err)
		}
	}
	// And the CP function's value through the wire: the same cause the SMF
	// reads, not an accepted session that serves nothing.
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(subscriberSideEstablishment(0x7303, "10.45.0.10", 0x53, ie.SrcInterfaceCPFunction))
	if got := cause(t, resp); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a PDI whose Source Interface is the CP function answered cause %d, want 73", got)
	}
	if len(rec.txns) != 0 {
		t.Errorf("the refused establishment wrote %d transactions, want none", len(rec.txns))
	}
}

// TestAnUnreadableSourceInterfaceIsRefused: an IE that cannot be read at all is
// not a value this UP can serve, and treating it as Access -- which is what an
// ignored read error used to do -- would put a rule the SMF never asked for
// into the uplink chain.
func TestAnUnreadableSourceInterfaceIsRefused(t *testing.T) {
	_, err := parsePDR(ie.NewCreatePDR(
		ie.NewPDRID(1),
		ie.NewPrecedence(100),
		ie.NewPDI(ie.New(ie.SourceInterface, nil), ie.NewUEIPAddress(0x02, "10.45.0.2", "", 0, 0)),
		ie.NewFARID(1),
	))
	if err == nil {
		t.Fatal("a Source Interface IE with no value was accepted")
	}
	if !strings.Contains(err.Error(), "Source Interface") {
		t.Errorf("the refusal says %q, want it to name the IE", err)
	}
}

// The Destination Interface values of a FAR (TS 29.244 8.2.24, Table 8.2.24-1),
// and the egress each names. Which value reaches which exit is the deployment's
// data (the -instances flag's *-next-hop keys, internal/routing), not a switch
// in the compiler: an egress the deployment declares nothing for is refused with
// the rule-failure cause, and the two IE conditions that go with the value (the
// Forwarding Parameters IE of a forwarding FAR, and the Forwarding Policy of a
// forward toward SGi-LAN/N6-LAN, Tables 7.5.2.3-1 and 7.5.2.3-2) are checked
// with the cause that says the message is incomplete.

// egressConfig is the deployment these tests drive: one instance whose egress
// table names a plain forward (N6), a tunnel (N9, or indirect forwarding) and
// the service LAN, a second whose only egress is the 5G VN re-injection, and the
// access side's own hop.
func egressConfig(t *testing.T) Config {
	t.Helper()
	d, err := routing.New([]routing.Interface{
		{
			Instance: "internet", Domain: 0, NextHop: 1,
			Hops: map[routing.Egress]uint32{
				{DestIfc: ie.DstInterfaceCore}:               1,
				{DestIfc: ie.DstInterfaceCore, Tunnel: true}: 3,
				{DestIfc: ie.DstInterfaceSGiLANN6LAN}:        4,
			},
		},
		{
			Instance: "vn", Domain: 1,
			Hops: map[routing.Egress]uint32{{DestIfc: ie.DstInterface5GVNInternal}: 5},
		},
	}, 4)
	if err != nil {
		t.Fatalf("the deployment was refused: %v", err)
	}
	cfg := testConfig()
	cfg.Instances = d
	cfg.FTEIDEndpoints = append(cfg.FTEIDEndpoints, FTEIDEndpoint{
		ID: 2, ReferencePoint: "n9", TransportRouteDomain: 2,
		SourceInterface: ie.SrcInterfaceCore, Instance: "internet",
		IPv4: netip.MustParseAddr("192.0.2.9"),
	})
	cfg.AccessNextHop = 2
	cfg.Up.PDRFields = []Field{SrcIP, DstIP, Proto, SrcPort, DstPort, FTEIDContext, QFI}
	cfg.Down.PDRFields = []Field{SrcIP, DstIP, Proto, SrcPort, DstPort, RouteDomain}
	return cfg
}

// farTo is the children of a FAR that forwards, after its FAR ID: the Apply
// Action and the forwarding parameters that name `dst` (and whatever else the
// caller adds inside them -- an outer header, a forwarding policy).
func farTo(dst uint8, extra ...*ie.IE) []*ie.IE {
	return []*ie.IE{
		ie.NewApplyAction(applyForw),
		ie.NewForwardingParameters(append([]*ie.IE{ie.NewDestinationInterface(dst)}, extra...)...),
	}
}

// egressEstablishment is a session of two PDRs on `instance`: an uplink one
// (the F-TEID `fteid`) and one from the subscriber side, each forwarding with
// the FAR the caller names.
func egressEstablishment(cpSEID uint64, ueIP string, fteid uint32, instance string,
	uplinkFAR, downFAR []*ie.IE) *message.SessionEstablishmentRequest {
	return message.NewSessionEstablishmentRequest(0, 0, cpSEID, 1, 0,
		ie.NewNodeID("", "", "smf"),
		ie.NewFSEID(cpSEID, nil, nil),
		ie.NewCreatePDR(
			ie.NewPDRID(1),
			ie.NewPrecedence(100),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewNetworkInstance(instance),
				testFTEID(fteid),
				ie.NewUEIPAddress(0x02, ueIP, "", 0, 0),
			),
			ie.NewFARID(1),
		),
		ie.NewCreateFAR(append([]*ie.IE{ie.NewFARID(1)}, uplinkFAR...)...),
		ie.NewCreatePDR(
			ie.NewPDRID(2),
			ie.NewPrecedence(100),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewNetworkInstance(instance),
				ie.NewUEIPAddress(0x06, ueIP, "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to assigned 53", "", "", "", 0),
			),
			ie.NewFARID(2),
		),
		ie.NewCreateFAR(append([]*ie.IE{ie.NewFARID(2)}, downFAR...)...),
	)
}

// tunnelTo is the tunnel an indirect-forwarding FAR adds: an Outer Header
// Creation naming the far end (its F-TEID and address).
func tunnelTo(teid uint32, addr string) *ie.IE {
	return ie.NewOuterHeaderCreation(0x0100, teid, addr, "", 0, 0, 0)
}

// TestAForwardTowardTheAccessSideEncapsulatesWhicheverDirection: Destination
// Interface Access is the side toward the UE, and which direction the PDR is on
// does not change it -- an *uplink* PDR whose FAR names Access is indirect data
// forwarding (8.2.2 NOTE 2: the value infers no direction), and its packets go
// back out through the encap rather than toward N6, which is where the
// direction's own hop would have sent them.
func TestAForwardTowardTheAccessSideEncapsulatesWhicheverDirection(t *testing.T) {
	cfg := egressConfig(t)
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())
	resp := c.Establish(egressEstablishment(0x7401, "10.45.0.2", 0x61, "internet",
		farTo(ie.DstInterfaceAccess, tunnelTo(0x22334455, "10.20.30.9")),
		farTo(ie.DstInterfaceAccess, tunnelTo(0x11223344, "10.20.30.2"))))
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	changes := rec.last()
	ul := ruleIn(t, changes, cfg.Up.PDRTable)
	if got := nextHop(t, changes, ul.actionID()); got != cfg.AccessNextHop {
		t.Errorf("the uplink forward toward the access side takes next hop %d, want the access side's %d",
			got, cfg.AccessNextHop)
	}
	dl := ruleIn(t, changes, cfg.Down.PDRTable)
	if got := nextHop(t, changes, dl.actionID()); got != cfg.AccessNextHop {
		t.Errorf("the downlink forward toward the access side takes next hop %d, want the access side's %d",
			got, cfg.AccessNextHop)
	}

	// A deployment that names no -access-next-hop takes the downlink
	// direction's own hop, which is the encap's gate in every deployed graph.
	cfg.AccessNextHop = 0
	rec = &recorder{}
	c = New(cfg, rec, quietLogger())
	resp = c.Establish(egressEstablishment(0x7402, "10.45.0.3", 0x62, "internet",
		farTo(ie.DstInterfaceAccess, tunnelTo(0x22334456, "10.20.30.9")),
		farTo(ie.DstInterfaceAccess, tunnelTo(0x11223345, "10.20.30.2"))))
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment with no -access-next-hop answered cause %d", got)
	}
	ul = ruleIn(t, rec.last(), cfg.Up.PDRTable)
	if got := nextHop(t, rec.last(), ul.actionID()); got != cfg.Down.NextHop {
		t.Errorf("with no access hop declared the forward takes %d, want the downlink direction's %d",
			got, cfg.Down.NextHop)
	}
}

func TestTemporaryAccessForwardFARRetainsSessionAfterCleanup(t *testing.T) {
	cfg := egressConfig(t)
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())
	const seid = 0x7420
	resp := c.Establish(egressEstablishment(seid, "10.45.0.20", 0x70, "internet",
		farTo(ie.DstInterfaceCore),
		farTo(ie.DstInterfaceAccess, tunnelTo(0x22334460, "10.20.30.2"))))
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the steady session answered cause %d", got)
	}
	resource := cfg.Up.Tunnels + "/tunnels"
	base := rec.last()
	uplink := ruleIn(t, base, cfg.Up.PDRTable)
	downlink := ruleIn(t, base, cfg.Down.PDRTable)
	if _, ok := find0(base, resource, "action_id", uplink.actionID()); ok {
		t.Fatal("the steady uplink FAR unexpectedly has an outer-header tunnel")
	}
	if got := find(t, base, resource, "action_id", downlink.actionID()).Value["teid"]; got != uint32(0x22334460) {
		t.Fatalf("the steady downlink tunnel has TEID %v, want 0x22334460", got)
	}

	upSEID := upFSEID(t, resp.(*message.SessionEstablishmentResponse))
	mod := message.NewSessionModificationRequest(0, 0, upSEID, 2, 0,
		ie.NewFSEID(seid, nil, nil),
		ie.NewCreateFAR(
			ie.NewFARID(9),
			ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceAccess),
				ie.NewOuterHeaderCreation(0x0100, 0x55aa55aa, "10.20.30.9", "", 0, 0, 0),
			),
		),
		ie.NewUpdatePDR(ie.NewPDRID(1), ie.NewFARID(9)),
	)
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("installing the temporary forwarding FAR answered cause %d", got)
	}
	temporary := rec.last()
	temporaryUplink := ruleIn(t, temporary, cfg.Up.PDRTable)
	if temporaryUplink.actionID() != uplink.actionID() {
		t.Fatal("rebinding the PDR changed its action ID")
	}
	if got := nextHop(t, temporary, uplink.actionID()); got != cfg.AccessNextHop {
		t.Fatalf("the temporary forward takes next hop %d, want access hop %d", got, cfg.AccessNextHop)
	}
	if got := find(t, temporary, resource, "action_id", uplink.actionID()).Value["teid"]; got != uint32(0x55aa55aa) {
		t.Fatalf("the temporary uplink tunnel has TEID %v, want 0x55aa55aa", got)
	}

	cleanup := message.NewSessionModificationRequest(0, 0, upSEID, 3, 0,
		ie.NewFSEID(seid, nil, nil),
		ie.NewUpdatePDR(ie.NewPDRID(1), ie.NewFARID(1)),
		ie.NewRemoveFAR(ie.NewFARID(9)),
	)
	if got := cause(t, c.Modify(cleanup)); got != ie.CauseRequestAccepted {
		t.Fatalf("restoring the steady FAR and removing the temporary FAR answered cause %d", got)
	}
	restored := rec.last()
	restoredUplink := ruleIn(t, restored, cfg.Up.PDRTable)
	if restoredUplink.actionID() != uplink.actionID() {
		t.Fatal("cleanup changed the active uplink PDR's action ID")
	}
	if got := nextHop(t, restored, uplink.actionID()); got != cfg.Up.NextHop {
		t.Fatalf("the restored forward takes next hop %d, want steady hop %d", got, cfg.Up.NextHop)
	}
	if erased, ok := find0(restored, resource, "action_id", uplink.actionID()); !ok || erased.Value != nil {
		t.Fatal("cleanup did not erase the temporary uplink tunnel record")
	}
	if changed, ok := find0(restored, resource, "action_id", downlink.actionID()); ok && changed.Value == nil {
		t.Fatal("cleanup erased the unrelated downlink tunnel record")
	}
}

// TestATunnelOutOfAnInstanceTakesTheTunnelEgress: Destination Interface Core
// with an Outer Header Creation is a tunnel out of the instance -- N9, or the
// tunnel of an indirect forward -- and it leaves by the egress the deployment
// declared for it, not by the instance's plain hop.
func TestATunnelOutOfAnInstanceTakesTheTunnelEgress(t *testing.T) {
	cfg := egressConfig(t)
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())
	// The FAR's own Network Instance names where the tunnel leaves by, and it
	// need not be the instance the PDI selected.
	resp := c.Establish(egressEstablishment(0x7410, "10.45.0.4", 0x63, "internet",
		farTo(ie.DstInterfaceCore, tunnelTo(0x22334457, "10.20.30.9")),
		farTo(ie.DstInterfaceCore, ie.NewNetworkInstance("internet"), tunnelTo(0x11223347, "10.20.30.9"))))
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	dl := ruleIn(t, rec.last(), cfg.Down.PDRTable)
	if got := nextHop(t, rec.last(), dl.actionID()); got != 3 {
		t.Errorf("the tunneled forward takes next hop %d, want the instance's tunnel egress 3", got)
	}

	// An instance that declares no tunnel egress: refused, not sent out of the
	// plain hop, which would leak an encapsulated packet as plain IP.
	rec = &recorder{}
	c = New(cfg, rec, quietLogger())
	resp = c.Establish(egressEstablishment(0x7411, "10.45.0.5", 0x64, "internet",
		farTo(ie.DstInterfaceCore, tunnelTo(0x22334458, "10.20.30.9")),
		farTo(ie.DstInterfaceCore, ie.NewNetworkInstance("vn"), tunnelTo(0x11223348, "10.20.30.9"))))
	if got := cause(t, resp); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a tunnel out of an instance with no tunnel egress answered cause %d, want 73", got)
	}
	if len(rec.txns) != 0 {
		t.Errorf("the refused establishment wrote %d transactions, want none", len(rec.txns))
	}
}

// TestDestinationRoutingNamesNoNextHop: in destination mode the Router decides
// the egress from the packet's destination and graph routes. The compiler does
// not resolve the FAR to a next-hop ID.
// The PDR result's `next_hop_id` is 0, but the tunnel record is still written.
// The FIB chooses the encap gate, and `GtpuEncap` reads the tunnel by the PDR
// result's ActionId.
func TestDestinationRoutingNamesNoNextHop(t *testing.T) {
	cfg := egressConfig(t)
	cfg.RouteMode = RouteByDestination
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())
	resp := c.Establish(egressEstablishment(0x7460, "10.45.0.2", 0x6e, "internet",
		farTo(ie.DstInterfaceCore, tunnelTo(0x22334455, "10.20.30.9")),
		farTo(ie.DstInterfaceSGiLANN6LAN, ie.NewForwardingPolicy("steering-1"))))
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	changes := rec.last()
	ul := ruleIn(t, changes, cfg.Up.PDRTable)
	if got := nextHop(t, changes, ul.actionID()); got != 0 {
		t.Errorf("the uplink action names next hop %d, want 0: the Router's FIB decides", got)
	}
	dl := ruleIn(t, changes, cfg.Down.PDRTable)
	if got := nextHop(t, changes, dl.actionID()); got != 0 {
		t.Errorf("the downlink action names next hop %d, want 0: the Router's FIB decides", got)
	}

	// The Router looks the packet up in the domain it was classified in, so a
	// FAR that forwards into another instance cannot be expressed by routes
	// this compiler writes; it is refused rather than routed in the wrong FIB.
	rec = &recorder{}
	c = New(cfg, rec, quietLogger())
	resp = c.Establish(egressEstablishment(0x7461, "10.45.0.3", 0x6f, "internet",
		farTo(ie.DstInterfaceCore),
		farTo(ie.DstInterfaceCore, ie.NewNetworkInstance("vn"))))
	if got := cause(t, resp); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a forward into another instance answered cause %d, want 73", got)
	}
	if len(rec.txns) != 0 {
		t.Errorf("the refused establishment wrote %d transactions, want none", len(rec.txns))
	}
}

// TestDestinationRoutingChecksAnAccessFARsInstance: an Access forward names
// hop 0 like every other expressible forward in destination mode, but it does
// not skip the mode's one limit. The Router looks the packet up in the domain
// it was classified in, and an Access FAR that forwards into another instance
// -- or names one the deployment does not serve -- cannot be expressed by the
// routes this compiler writes. Returning 0 for it before the check would accept
// a rule whose packet the Router routes in the wrong table (or would send it
// out of an exit the FAR never named).
func TestDestinationRoutingChecksAnAccessFARsInstance(t *testing.T) {
	cfg := egressConfig(t)
	cfg.RouteMode = RouteByDestination
	for _, tc := range []struct {
		name     string
		instance string
	}{
		{"another configured instance", "vn"},
		{"an instance the deployment does not serve", "elsewhere"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{}
			c := New(cfg, rec, quietLogger())
			resp := c.Establish(egressEstablishment(0x7470, "10.45.0.4", 0x70, "internet",
				farTo(ie.DstInterfaceCore),
				farTo(ie.DstInterfaceAccess, ie.NewNetworkInstance(tc.instance))))
			if got := cause(t, resp); got != ie.CauseRuleCreationModificationFailure {
				t.Errorf("an Access forward naming %s answered cause %d, want 73", tc.name, got)
			}
			if len(rec.txns) != 0 {
				t.Errorf("the refused establishment wrote %d transactions, want none", len(rec.txns))
			}
		})
	}

	// The same forward with no instance named falls back to the PDI's, stays in
	// the packet's domain, and names hop 0.
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())
	resp := c.Establish(egressEstablishment(0x7471, "10.45.0.5", 0x71, "internet",
		farTo(ie.DstInterfaceCore),
		farTo(ie.DstInterfaceAccess, tunnelTo(0x22334459, "10.20.30.9"))))
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("an Access forward in the packet's own instance answered cause %d", got)
	}
	dl := ruleIn(t, rec.last(), cfg.Down.PDRTable)
	if got := nextHop(t, rec.last(), dl.actionID()); got != 0 {
		t.Errorf("the access forward names next hop %d, want 0: the Router's FIB decides", got)
	}
}

// TestAServiceLanForwardTakesTheServiceLanEgress: Destination Interface
// SGi-LAN/N6-LAN is the service fabric's exit, declared per instance.
func TestAServiceLanForwardTakesTheServiceLanEgress(t *testing.T) {
	cfg := egressConfig(t)
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())
	resp := c.Establish(egressEstablishment(0x7420, "10.45.0.6", 0x65, "internet",
		farTo(ie.DstInterfaceCore),
		farTo(ie.DstInterfaceSGiLANN6LAN, ie.NewForwardingPolicy("steering-1"))))
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	dl := ruleIn(t, rec.last(), cfg.Down.PDRTable)
	if got := nextHop(t, rec.last(), dl.actionID()); got != 4 {
		t.Errorf("the service-LAN forward takes next hop %d, want the service LAN's egress 4", got)
	}
}

// TestAServiceLanForwardNeedsItsForwardingPolicy: Table 7.5.2.3-2 makes the
// Forwarding Policy IE mandatory when the Destination Interface is
// SGi-LAN/N6-LAN, and the answer says so (cause 66) instead of forwarding into
// a fabric that would apply no policy.
func TestAServiceLanForwardNeedsItsForwardingPolicy(t *testing.T) {
	rec := &recorder{}
	c := New(egressConfig(t), rec, quietLogger())
	resp := c.Establish(egressEstablishment(0x7421, "10.45.0.7", 0x66, "internet",
		farTo(ie.DstInterfaceCore),
		farTo(ie.DstInterfaceSGiLANN6LAN)))
	if got := cause(t, resp); got != ie.CauseMandatoryIEMissing {
		t.Errorf("a service-LAN forward with no Forwarding Policy answered cause %d, want 66", got)
	}
	if len(rec.txns) != 0 {
		t.Errorf("the refused establishment wrote %d transactions, want none", len(rec.txns))
	}
}

// TestAFiveGVNInternalForwardTakesTheReInjectionGate: Destination Interface 5
// sends the packet back into this UP's own subscriber-side chain, which is the
// gate the deployment declares for it.
func TestAFiveGVNInternalForwardTakesTheReInjectionGate(t *testing.T) {
	cfg := egressConfig(t)
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())
	// The VN instance declares no data-network exit: both of this session's
	// forwards are re-injections, which is what a 5G VN group session does.
	resp := c.Establish(egressEstablishment(0x7430, "10.45.0.8", 0x67, "vn",
		farTo(ie.DstInterface5GVNInternal),
		farTo(ie.DstInterface5GVNInternal)))
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the 5G VN establishment answered cause %d", got)
	}
	dl := ruleIn(t, rec.last(), cfg.Down.PDRTable)
	if got := nextHop(t, rec.last(), dl.actionID()); got != 5 {
		t.Errorf("the re-injected forward takes next hop %d, want the re-injection gate 5", got)
	}

	// A re-injection adds no outer header: the packet re-enters the chain as it
	// is, so a FAR that names both is a request this UP cannot carry.
	rec = &recorder{}
	c = New(cfg, rec, quietLogger())
	resp = c.Establish(egressEstablishment(0x7431, "10.45.0.9", 0x68, "vn",
		farTo(ie.DstInterface5GVNInternal),
		farTo(ie.DstInterface5GVNInternal, tunnelTo(0x11223349, "10.20.30.9"))))
	if got := cause(t, resp); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a re-injection with an outer header answered cause %d, want 73", got)
	}
}

// TestAnUplinkForwardWithAnOuterHeaderWritesTheTunnelRecord: an uplink forward
// that adds an outer header of its own (an N9 uplink, or indirect data
// forwarding) leaves through the encap, and the encap forwards only a packet
// whose ActionId it holds a record for -- a frame it has no session for is
// dropped (datapath/gtpu_encap.cc). So the record is the *direction's*, and the
// uplink needs one written as much as the downlink does.
func TestAnUplinkForwardWithAnOuterHeaderWritesTheTunnelRecord(t *testing.T) {
	cfg := egressConfig(t)
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())
	resp := c.Establish(egressEstablishment(0x7450, "10.45.0.2", 0x6b, "internet",
		farTo(ie.DstInterfaceCore, tunnelTo(0x22334455, "10.20.30.9")),
		farTo(ie.DstInterfaceAccess, tunnelTo(0x11223344, "10.20.30.2"))))
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	changes := rec.last()
	ul := ruleIn(t, changes, cfg.Up.PDRTable)
	// The rule delivers on the instance's tunnel egress ...
	if got := nextHop(t, changes, ul.actionID()); got != 3 {
		t.Errorf("the uplink forward takes next hop %d, want the instance's tunnel egress 3", got)
	}
	// ... and the record the encap resolves by that action carries the FAR's
	// own outer header.
	record := find(t, changes, tunnelsRes(cfg.Up), "action_id", ul.actionID())
	if got := record.Value["teid"]; got != uint32(0x22334455) {
		t.Errorf("the uplink tunnel record's TEID is %v, want the FAR's 0x22334455", got)
	}
}

// TestAnUplinkOuterHeaderWithNoTunnelModuleIsRefused: a deployment that names
// no uplink tunnel module cannot carry that record, and compiling the rule
// anyway would send its packets to an encap with no session for them. Cause 73
// names the flag instead of blackholing the SMF's traffic.
func TestAnUplinkOuterHeaderWithNoTunnelModuleIsRefused(t *testing.T) {
	cfg := egressConfig(t)
	cfg.Up.Tunnels = ""
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())
	resp := c.Establish(egressEstablishment(0x7451, "10.45.0.2", 0x6c, "internet",
		farTo(ie.DstInterfaceCore, tunnelTo(0x22334455, "10.20.30.9")),
		farTo(ie.DstInterfaceAccess, tunnelTo(0x11223344, "10.20.30.2"))))
	if got := cause(t, resp); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("an uplink tunnel forward with no tunnel module answered cause %d, want 73", got)
	}
	if len(rec.txns) != 0 {
		t.Error("a refused session wrote to the dataplane")
	}
}

// TestAPlainForwardOutOfAnInstanceWithNoNextHopIsRefused: an instance may
// declare no plain egress -- its forwards all tunnel, or it only re-injects --
// and then a forward that needs one has nowhere to go. Hop 0 is no Router next
// hop: the action would name it and the Router would drop the packet, with the
// SMF told the rule is in force.
func TestAPlainForwardOutOfAnInstanceWithNoNextHopIsRefused(t *testing.T) {
	cfg := egressConfig(t)
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())
	resp := c.Establish(egressEstablishment(0x7452, "10.45.0.2", 0x6d, "vn",
		farTo(ie.DstInterfaceCore),
		farTo(ie.DstInterface5GVNInternal)))
	if got := cause(t, resp); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a plain forward out of an instance with no next hop answered cause %d, want 73", got)
	}
	if len(rec.txns) != 0 {
		t.Error("a refused session wrote to the dataplane")
	}
}

// TestACPFunctionsForwardIsRefused: Destination Interface 3 is the CP
// function's own path (Table 8.2.24-1), which is no user-plane exit of this UP.
func TestACPFunctionsForwardIsRefused(t *testing.T) {
	rec := &recorder{}
	c := New(egressConfig(t), rec, quietLogger())
	resp := c.Establish(egressEstablishment(0x7440, "10.45.0.10", 0x69, "internet",
		farTo(ie.DstInterfaceCore),
		farTo(ie.DstInterfaceCPFunction)))
	if got := cause(t, resp); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a CP-function forward answered cause %d, want 73", got)
	}
	if len(rec.txns) != 0 {
		t.Errorf("the refused establishment wrote %d transactions, want none", len(rec.txns))
	}
}

// TestALawfulInterceptionForwardIsRefused: Destination Interface 4 is the LI
// function's, and an X3 copy is a duplication action rather than the forward
// this FAR asks for.
func TestALawfulInterceptionForwardIsRefused(t *testing.T) {
	rec := &recorder{}
	c := New(egressConfig(t), rec, quietLogger())
	resp := c.Establish(egressEstablishment(0x7441, "10.45.0.11", 0x6a, "internet",
		farTo(ie.DstInterfaceCore),
		farTo(ie.DstInterfaceLIFunction)))
	if got := cause(t, resp); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("an LI-function forward answered cause %d, want 73", got)
	}
	if len(rec.txns) != 0 {
		t.Errorf("the refused establishment wrote %d transactions, want none", len(rec.txns))
	}
}

// TestAnUndefinedDestinationInterfaceValueIsRefused: 6..15 are Spare in Table
// 8.2.24-1, and a forward toward a value no interface names is refused rather
// than handed the instance's own hop.
func TestAnUndefinedDestinationInterfaceValueIsRefused(t *testing.T) {
	for _, v := range []uint8{6, 15} {
		rec := &recorder{}
		c := New(egressConfig(t), rec, quietLogger())
		resp := c.Establish(egressEstablishment(0x7450+uint64(v), "10.45.0.12", 0x6b, "internet",
			farTo(ie.DstInterfaceCore),
			farTo(v)))
		if got := cause(t, resp); got != ie.CauseRuleCreationModificationFailure {
			t.Errorf("Destination Interface value %d answered cause %d, want 73", v, got)
		}
		if len(rec.txns) != 0 {
			t.Errorf("the refused establishment for value %d wrote %d transactions, want none", v, len(rec.txns))
		}
	}
}

// TestAForwardingFarNeedsForwardingParameters: Table 7.5.2.3-1 makes the
// Forwarding Parameters IE mandatory when the Apply Action requests forwarding,
// and the answer (cause 66) names what is missing.
func TestAForwardingFarNeedsForwardingParameters(t *testing.T) {
	rec := &recorder{}
	c := New(egressConfig(t), rec, quietLogger())
	resp := c.Establish(egressEstablishment(0x7460, "10.45.0.13", 0x6c, "internet",
		[]*ie.IE{ie.NewApplyAction(applyForw)},
		farTo(ie.DstInterfaceAccess, tunnelTo(0x1122334a, "10.20.30.2"))))
	if got := cause(t, resp); got != ie.CauseMandatoryIEMissing {
		t.Errorf("a forwarding FAR with no forwarding parameters answered cause %d, want 66", got)
	}
	if len(rec.txns) != 0 {
		t.Errorf("the refused establishment wrote %d transactions, want none", len(rec.txns))
	}
}

// TestForwardingParametersNeedADestinationInterface: Table 7.5.2.3-2 makes the
// Destination Interface mandatory inside the forwarding parameters, and an IE
// that names nothing is not a forward this UP can place.
func TestForwardingParametersNeedADestinationInterface(t *testing.T) {
	rec := &recorder{}
	c := New(egressConfig(t), rec, quietLogger())
	resp := c.Establish(egressEstablishment(0x7461, "10.45.0.14", 0x6d, "internet",
		farTo(ie.DstInterfaceCore),
		[]*ie.IE{ie.NewApplyAction(applyForw), ie.NewForwardingParameters()}))
	if got := cause(t, resp); got != ie.CauseMandatoryIEMissing {
		t.Errorf("forwarding parameters with no Destination Interface answered cause %d, want 66", got)
	}
	if len(rec.txns) != 0 {
		t.Errorf("the refused establishment wrote %d transactions, want none", len(rec.txns))
	}
}

// TestAnEgressTheDeploymentDoesNotDeclareIsRefused: the deployment's table is
// what says which egress exists, and the one-instance deployment (no
// -instances) has only the direction's own hop: the values this increment adds
// are refused there, each with the cause that says the rule failed rather than
// being silently sent out of the data network's exit.
func TestAnEgressTheDeploymentDoesNotDeclareIsRefused(t *testing.T) {
	for _, c := range []struct {
		name string
		far  []*ie.IE
		want uint8
	}{
		{"a service-LAN forward", farTo(ie.DstInterfaceSGiLANN6LAN, ie.NewForwardingPolicy("steering-1")),
			ie.CauseRuleCreationModificationFailure},
		{"a 5G VN forward", farTo(ie.DstInterface5GVNInternal), ie.CauseRuleCreationModificationFailure},
		{"a tunnel out of the instance", farTo(ie.DstInterfaceCore, tunnelTo(0x1122334b, "10.20.30.9")),
			ie.CauseRuleCreationModificationFailure},
	} {
		t.Run(c.name, func(t *testing.T) {
			rec := &recorder{}
			// The one-instance deployment: no -instances at all.
			c2 := New(testConfig(), rec, quietLogger())
			resp := c2.Establish(egressEstablishment(0x7470, "10.45.0.15", 0x6e, "internet",
				farTo(ie.DstInterfaceCore), c.far))
			if got := cause(t, resp); got != c.want {
				t.Errorf("%s on a deployment with no such egress answered cause %d, want %d", c.name, got, c.want)
			}
			if len(rec.txns) != 0 {
				t.Errorf("the refused establishment wrote %d transactions, want none", len(rec.txns))
			}
		})
	}
	// And the tunneled service-LAN egress the flag grammar cannot declare: a
	// deployment that needs one adds the key (not this increment), so the
	// forward is refused rather than sent out of the plain service-LAN hop.
	rec := &recorder{}
	c2 := New(egressConfig(t), rec, quietLogger())
	resp := c2.Establish(egressEstablishment(0x7471, "10.45.0.16", 0x6f, "internet",
		farTo(ie.DstInterfaceCore),
		farTo(ie.DstInterfaceSGiLANN6LAN, ie.NewForwardingPolicy("steering-1"), tunnelTo(0x1122334c, "10.20.30.9"))))
	if got := cause(t, resp); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a tunneled service-LAN forward answered cause %d, want 73", got)
	}
}
