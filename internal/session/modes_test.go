// SPDX-License-Identifier: BSD-3-Clause

// The N4 shapes of the three project scenarios that need more than one
// ordinary PDU-session shape (docs/compliance.md): Mode 4, an UL CL or
// Branching Point behind an I-UPF, which receives on N9 and sends on N9 (TS
// 23.502 4.3.5.4 step 6, 4.3.5.7 NOTE 2/NOTE 4); N19 forwarding between PSAs
// in a group-level N4 session (TS 23.501 5.8.2.13.1, TS 23.502 4.13.8.2.2);
// and Mode 6, the indirect data forwarding tunnels of an N2 handover (TS
// 23.502 4.9.1.3.2 steps 11b-11e, 4.9.1.3.3 steps 8a, 13a and 15a).

package session

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/bess"
	"github.com/krsna1729/upf/internal/routing"
)

// The modes' deployment: N3 on 192.0.2.1 (transport domain 1) and one N9
// endpoint on 192.0.2.9 (transport domain 2) that also terminates N19, scoped
// to the data network's instance as `upfd -instances` requires; a 5G VN
// instance whose only egress is the re-injection.
const (
	modesN3      = "192.0.2.1"
	modesN9      = "192.0.2.9"
	modesHopN6   = 1
	modesHopAcc  = 2
	modesHopTun  = 3
	modesHopVN   = 5
	modesUpCtx   = 5 // the uplink table's fteid_context field
	modesDownCtx = 6 // the downlink table's
)

func modesConfig(t *testing.T) Config {
	t.Helper()
	domains, err := routing.New([]routing.Interface{{
		Instance: "internet", Domain: 1, NextHop: modesHopN6,
		Pool: []netip.Prefix{netip.MustParsePrefix("10.45.0.0/16")},
		Hops: map[routing.Egress]uint32{
			{DestIfc: ie.DstInterfaceCore}:               modesHopN6,
			{DestIfc: ie.DstInterfaceCore, Tunnel: true}: modesHopTun,
		},
	}, {
		Instance: "vn", Domain: 2,
		Pool: []netip.Prefix{netip.MustParsePrefix("10.45.0.0/16")},
		Hops: map[routing.Egress]uint32{
			{DestIfc: ie.DstInterface5GVNInternal}: modesHopVN,
		},
	}}, 6)
	if err != nil {
		t.Fatalf("the deployment was refused: %v", err)
	}
	cfg := testConfig()
	cfg.Instances = domains
	cfg.AccessNextHop = modesHopAcc
	cfg.FTEIDEndpoints = append(cfg.FTEIDEndpoints, FTEIDEndpoint{
		ID: 2, ReferencePoint: "n9", TransportRouteDomain: 2,
		SourceInterface: ie.SrcInterfaceCore, Instance: "internet", IPv4: netip.MustParseAddr(modesN9),
	})
	return cfg
}

// forwardTo is a forwarding FAR's Apply Action and Forwarding Parameters.
func forwardTo(id uint32, dst uint8, extra ...*ie.IE) *ie.IE {
	return ie.NewCreateFAR(ie.NewFARID(id), ie.NewApplyAction(applyForw),
		ie.NewForwardingParameters(append([]*ie.IE{ie.NewDestinationInterface(dst)}, extra...)...))
}

// chooseFTEID is the F-TEID IE that asks the UP function to allocate (CH, V4).
func chooseFTEID() *ie.IE { return ie.NewFTEID(0x05, 0, nil, nil, 0) }

// createdFTEID is the F-TEID a response's Created PDR names for pdrID.
func createdFTEIDOf(t *testing.T, created []*ie.IE, pdrID uint16) (uint32, string) {
	t.Helper()
	for _, i := range created {
		children, err := i.CreatedPDR()
		if err != nil {
			t.Fatal(err)
		}
		var id uint16
		var teid uint32
		var addr string
		for _, ch := range children {
			switch ch.Type {
			case ie.PDRID:
				id, _ = ch.PDRID()
			case ie.FTEID:
				f, err := ch.FTEID()
				if err != nil {
					t.Fatal(err)
				}
				teid, addr = f.TEID, f.IPv4Address.String()
			}
		}
		if id == pdrID {
			return teid, addr
		}
	}
	t.Fatalf("no Created PDR for PDR %d", pdrID)
	return 0, ""
}

// ruleWithContext is the rule whose fteid_context field (index i) is ctx.
func ruleWithContext(t *testing.T, changes []bess.Change, i int, ctx uint32) rule {
	t.Helper()
	want := []byte{byte(ctx >> 24), byte(ctx >> 16), byte(ctx >> 8), byte(ctx)}
	return ruleCarrying(t, changes, i, want)
}

// openAddresses fails unless the rule leaves both address fields open.
func openAddresses(t *testing.T, r rule, what string) {
	t.Helper()
	for _, f := range []int{fieldSrcIP, fieldDstIP} {
		if m := r.mask(f); !bytes.Equal(m, []byte{0, 0, 0, 0}) {
			t.Errorf("%s: address field %d is constrained (mask %v); the F-TEID alone identifies the tunnel", what, f, m)
		}
	}
}

// tunnelLocal is the tunnel record's local address and transport domain.
func tunnelLocal(t *testing.T, changes []bess.Change, cfg Config, actionID uint32) (netip.Addr, any, map[string]any) {
	t.Helper()
	ch := find(t, changes, cfg.Down.Tunnels+"/tunnels", "action_id", actionID)
	a, _ := netip.AddrFromSlice(ch.Value["local_address"].([]byte))
	return a, ch.Value["transport_route_domain"], ch.Value
}

// TestCascadedN9TransitUsesTheN9EndpointBothWays is Mode 4: an UL CL inserted
// behind an existing I-UPF (TS 23.502 4.3.5.4 step 6). The uplink arrives from
// that I-UPF over N9 -- Source Interface Access, the direction, with Source
// Interface Type N9 -- and leaves over N9 toward the PSA; the PSA's downlink
// arrives over N9 and leaves over N9 toward the I-UPF -- Destination Interface
// Access with Destination Interface Type N9. Both F-TEIDs are allocated on the
// N9 endpoint and both tunnels are sourced from it; the same session without
// the types puts the uplink F-TEID and the downlink tunnel on N3, which is the
// RAN's.
func TestCascadedN9TransitUsesTheN9EndpointBothWays(t *testing.T) {
	transit := func(seid uint64, ue string, typed bool) *message.SessionEstablishmentRequest {
		upPDI := []*ie.IE{ie.NewSourceInterface(ie.SrcInterfaceAccess), ie.NewNetworkInstance("internet"),
			chooseFTEID(), ie.NewUEIPAddress(0x02, ue, "", 0, 0)}
		downFwd := []*ie.IE{ie.NewOuterHeaderCreation(0x0100, 0x44000002, "198.51.100.1", "", 0, 0, 0)}
		if typed {
			upPDI = append(upPDI, ie.NewTGPPInterfaceType(ie.TGPPInterfaceTypeN9))
			downFwd = append(downFwd, ie.NewTGPPInterfaceType(ie.TGPPInterfaceTypeN9))
		}
		return message.NewSessionEstablishmentRequest(0, 0, seid, 1, 0,
			ie.NewFSEID(seid, nil, nil),
			ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100), ie.NewPDI(upPDI...),
				ie.NewOuterHeaderRemoval(0, 0), ie.NewFARID(1)),
			forwardTo(1, ie.DstInterfaceCore,
				ie.NewOuterHeaderCreation(0x0100, 0x44000001, "198.51.100.3", "", 0, 0, 0)),
			ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(100),
				ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore), ie.NewNetworkInstance("internet"),
					chooseFTEID(), ie.NewUEIPAddress(0x06, ue, "", 0, 0)),
				ie.NewOuterHeaderRemoval(0, 0), ie.NewFARID(2)),
			forwardTo(2, ie.DstInterfaceAccess, downFwd...),
		)
	}
	cfg := modesConfig(t)
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())

	resp, ok := c.Establish(transit(0x9301, "10.45.4.2", true)).(*message.SessionEstablishmentResponse)
	if !ok || cause(t, resp) != ie.CauseRequestAccepted {
		t.Fatalf("the transit session was refused: %v", resp)
	}
	changes := rec.last()
	for _, id := range []uint16{1, 2} {
		teid, addr := createdFTEIDOf(t, resp.CreatedPDR, id)
		if addr != modesN9 {
			t.Errorf("PDR %d's F-TEID is on %s, want the N9 endpoint %s", id, addr, modesN9)
		}
		adm, ok := teidRule(changes, cfg.GTPUDecap+"/fteids", teid)
		if !ok || adm.Key["endpoint_id"] != uint32(2) {
			t.Errorf("PDR %d's admission is not on endpoint 2: %v", id, adm.Key)
		}
		if want := uint32(id - 1); adm.Value["direction"] != want {
			t.Errorf("PDR %d's admission direction is %v, want %d", id, adm.Value["direction"], want)
		}
	}
	ul := ruleCarrying(t, changes, fieldSrcIP, []byte{10, 45, 4, 2})
	dl := ruleCarrying(t, changes, fieldDstIP, []byte{10, 45, 4, 2})
	if got := ul.nextHop(); got != modesHopTun {
		t.Errorf("the uplink leaves by hop %d, want the N9 tunnel's %d", got, modesHopTun)
	}
	if got := dl.nextHop(); got != modesHopAcc {
		t.Errorf("the downlink leaves by hop %d, want the access side's %d (the encap)", got, modesHopAcc)
	}
	for what, action := range map[string]uint32{"uplink to the PSA": ul.actionID(), "downlink to the I-UPF": dl.actionID()} {
		local, domain, _ := tunnelLocal(t, changes, cfg, action)
		if local.String() != modesN9 || domain != uint32(2) {
			t.Errorf("the %s tunnel is sourced from %s in transport domain %v, want %s in 2", what, local, domain, modesN9)
		}
	}

	// The same rules without the types: the uplink's F-TEID and the
	// downlink's tunnel take the Source/Destination Interface's own endpoint.
	resp, ok = c.Establish(transit(0x9302, "10.45.4.3", false)).(*message.SessionEstablishmentResponse)
	if !ok || cause(t, resp) != ie.CauseRequestAccepted {
		t.Fatalf("the untyped session was refused: %v", resp)
	}
	if _, addr := createdFTEIDOf(t, resp.CreatedPDR, 1); addr != modesN3 {
		t.Errorf("without a Source Interface Type the Access F-TEID is on %s, want N3's %s", addr, modesN3)
	}
	dl = ruleCarrying(t, rec.last(), fieldDstIP, []byte{10, 45, 4, 3})
	if local, _, _ := tunnelLocal(t, rec.last(), cfg, dl.actionID()); local.String() != modesN3 {
		t.Errorf("without a Destination Interface Type the Access tunnel is sourced from %s, want N3's %s", local, modesN3)
	}

	// A Core-side arrival is from another UPF: an N3 type there names no
	// endpoint, and the session is refused rather than admitted on N3.
	bad := message.NewSessionEstablishmentRequest(0, 0, 0x9303, 1, 0,
		ie.NewFSEID(0x9303, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore), ie.NewNetworkInstance("internet"),
				chooseFTEID(), ie.NewUEIPAddress(0x06, "10.45.4.4", "", 0, 0),
				ie.NewTGPPInterfaceType(ie.TGPPInterfaceTypeN33GPPAccess)),
			ie.NewFARID(1)),
		forwardTo(1, ie.DstInterfaceAccess, ie.NewOuterHeaderCreation(0x0100, 0x44000003, "198.51.100.1", "", 0, 0, 0)),
	)
	if got := cause(t, c.Establish(bad)); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a Core PDR typed N3 answered cause %d, want a rule failure", got)
	}
}

// TestPSABehindAnIUPFTakesItsN9UplinkAsAccess is Mode 3, a PSA whose uplink
// arrives over N9 from an I-UPF and leaves by N6, with the interface values
// the direction notes give (TS 29.244 Table 8.2.2-1 NOTE 1: Access is the
// uplink's source; Table 8.2.24-1 NOTE 1: Access is the downlink's
// destination) and the 3GPP Interface Type naming N9 (8.2.118): the uplink
// F-TEID is admitted on the N9 endpoint into the uplink chain and leaves by
// the data network's hop, and the downlink toward the I-UPF leaves through
// the encap sourced from the N9 endpoint.
func TestPSABehindAnIUPFTakesItsN9UplinkAsAccess(t *testing.T) {
	cfg := modesConfig(t)
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())
	const ue = "10.45.3.2"
	resp, ok := c.Establish(message.NewSessionEstablishmentRequest(0, 0, 0x9331, 1, 0,
		ie.NewFSEID(0x9331, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess), ie.NewNetworkInstance("internet"),
				chooseFTEID(), ie.NewUEIPAddress(0x02, ue, "", 0, 0),
				ie.NewTGPPInterfaceType(ie.TGPPInterfaceTypeN9)),
			ie.NewOuterHeaderRemoval(0, 0), ie.NewFARID(1)),
		forwardTo(1, ie.DstInterfaceCore),
		ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore), ie.NewNetworkInstance("internet"),
				ie.NewUEIPAddress(0x06, ue, "", 0, 0)),
			ie.NewFARID(2)),
		forwardTo(2, ie.DstInterfaceAccess,
			ie.NewOuterHeaderCreation(0x0100, 0x44000009, "198.51.100.1", "", 0, 0, 0),
			ie.NewTGPPInterfaceType(ie.TGPPInterfaceTypeN9)),
	)).(*message.SessionEstablishmentResponse)
	if !ok || cause(t, resp) != ie.CauseRequestAccepted {
		t.Fatalf("the PSA session was refused: %v", resp)
	}
	changes := rec.last()
	teid, addr := createdFTEIDOf(t, resp.CreatedPDR, 1)
	if addr != modesN9 {
		t.Errorf("the N9 uplink's F-TEID is on %s, want the N9 endpoint %s", addr, modesN9)
	}
	adm, ok := teidRule(changes, cfg.GTPUDecap+"/fteids", teid)
	if !ok || adm.Key["endpoint_id"] != uint32(2) || adm.Value["direction"] != uint32(0) {
		t.Errorf("the N9 uplink's admission is %v -> %v, want endpoint 2 toward the uplink chain", adm.Key, adm.Value)
	}
	ul := ruleCarrying(t, changes, fieldSrcIP, []byte{10, 45, 3, 2})
	if !strings.HasPrefix(ul.change.Resource, cfg.Up.PDRTable) {
		t.Errorf("the N9 uplink's rule is in %s, want the uplink table", ul.change.Resource)
	}
	if got := ul.nextHop(); got != modesHopN6 {
		t.Errorf("the N9 uplink leaves by hop %d, want the data network's %d", got, modesHopN6)
	}
	dl := ruleCarrying(t, changes, fieldDstIP, []byte{10, 45, 3, 2})
	if got := dl.nextHop(); got != modesHopAcc {
		t.Errorf("the downlink toward the I-UPF leaves by hop %d, want the access side's %d", got, modesHopAcc)
	}
	if local, domain, _ := tunnelLocal(t, changes, cfg, dl.actionID()); local.String() != modesN9 || domain != uint32(2) {
		t.Errorf("the downlink toward the I-UPF is sourced from %s in transport domain %v, want %s in 2", local, domain, modesN9)
	}
}

// vnMember is a 5G VN member session on this PSA (TS 23.501 5.8.2.13.1): its
// uplink forwards to 5G VN Internal, and its 5G VN Internal PDR tunnels the
// traffic toward the member's gNB.
func vnMember(seid uint64, ue string, dlTEID uint32) *message.SessionEstablishmentRequest {
	return message.NewSessionEstablishmentRequest(0, 0, seid, 1, 0,
		ie.NewFSEID(seid, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess), ie.NewNetworkInstance("vn"),
				chooseFTEID(), ie.NewUEIPAddress(0x02, ue, "", 0, 0)),
			ie.NewOuterHeaderRemoval(0, 0), ie.NewFARID(1)),
		forwardTo(1, ie.DstInterface5GVNInternal),
		ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterface5GVNInternal), ie.NewNetworkInstance("vn"),
				ie.NewUEIPAddress(0x06, ue, "", 0, 0)),
			ie.NewFARID(2)),
		forwardTo(2, ie.DstInterfaceAccess, ie.NewOuterHeaderCreation(0x0100, dlTEID, "10.20.30.2", "", 0, 0, 0)),
	)
}

// TestN19GroupLevelSessionBesideItsMembers: the group-level N4 session an SMF
// creates at each PSA when N19 forwarding is applied (TS 23.502 4.13.8.2.2),
// with the rules TS 23.501 5.8.2.13.1 gives it -- per N19 tunnel, a Core PDR on
// the N19 F-TEID forwarding to 5G VN Internal, and a 5G VN Internal PDR for the
// UEs anchored at the peer PSA forwarding over N19 (Destination Interface
// Core). It has no UE of its own: it is accepted beside the member sessions
// under one association, its N19 PDR is keyed by the F-TEID alone (any member's
// traffic arrives on it), and its deletion takes only its own state.
func TestN19GroupLevelSessionBesideItsMembers(t *testing.T) {
	cfg := modesConfig(t)
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())
	for i, m := range []*message.SessionEstablishmentRequest{
		vnMember(0x9311, "10.45.0.5", 0x55667784), vnMember(0x9312, "10.45.0.6", 0x55667789),
	} {
		if got := cause(t, c.Establish(m)); got != ie.CauseRequestAccepted {
			t.Fatalf("member %d was refused with cause %d", i, got)
		}
	}
	group := message.NewSessionEstablishmentRequest(0, 0, 0x9319, 1, 0,
		ie.NewFSEID(0x9319, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore), ie.NewNetworkInstance("internet"),
				chooseFTEID(), ie.NewTGPPInterfaceType(ie.TGPPInterfaceTypeN19)),
			ie.NewOuterHeaderRemoval(0, 0), ie.NewFARID(1)),
		forwardTo(1, ie.DstInterface5GVNInternal, ie.NewNetworkInstance("vn")),
		ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterface5GVNInternal), ie.NewNetworkInstance("vn"),
				ie.NewUEIPAddress(0x06, "10.45.9.2", "", 0, 0)),
			ie.NewFARID(2)),
		forwardTo(2, ie.DstInterfaceCore,
			ie.NewOuterHeaderCreation(0x0100, 0x77000002, "198.51.100.19", "", 0, 0, 0),
			ie.NewNetworkInstance("internet"), ie.NewTGPPInterfaceType(ie.TGPPInterfaceTypeN19)),
	)
	resp, ok := c.Establish(group).(*message.SessionEstablishmentResponse)
	if !ok || cause(t, resp) != ie.CauseRequestAccepted {
		t.Fatalf("the group-level session was refused: %v", resp)
	}
	changes := rec.last()
	teid, addr := createdFTEIDOf(t, resp.CreatedPDR, 1)
	if addr != modesN9 {
		t.Errorf("the N19 F-TEID is on %s, want the N9/N19 endpoint %s", addr, modesN9)
	}
	adm, ok := teidRule(changes, cfg.GTPUDecap+"/fteids", teid)
	if !ok || adm.Value["direction"] != uint32(1) {
		t.Fatalf("the N19 admission is not toward the subscriber side: %v", adm)
	}
	n19 := ruleWithContext(t, changes, modesDownCtx, adm.Value["context_id"].(uint32))
	if !strings.HasPrefix(n19.change.Resource, cfg.Down.PDRTable) {
		t.Errorf("the N19 PDR's rule is in %s, want the subscriber-side table", n19.change.Resource)
	}
	openAddresses(t, n19, "the N19 PDR")
	if got := n19.nextHop(); got != modesHopVN {
		t.Errorf("the N19 arrival leaves by hop %d, want the 5G VN re-injection's %d", got, modesHopVN)
	}
	// The re-injected packet is classified again in the 5G VN group's route
	// domain (the FAR's instance), where the members' 5G VN Internal PDRs are.
	if res := n19.result(); len(res) < resultRouteDomain+4 ||
		binary.BigEndian.Uint32(res[resultRouteDomain:]) != 2 {
		t.Errorf("the N19 arrival is re-injected into route domain %v, want the 5G VN's 2", res)
	}
	out := ruleCarrying(t, changes, fieldDstIP, []byte{10, 45, 9, 2})
	if got := out.nextHop(); got != modesHopTun {
		t.Errorf("traffic to the peer PSA's UE leaves by hop %d, want the tunnel's %d", got, modesHopTun)
	}
	local, _, rec19 := tunnelLocal(t, changes, cfg, out.actionID())
	peer, _ := netip.AddrFromSlice(rec19["peer_address"].([]byte))
	if local.String() != modesN9 || peer.String() != "198.51.100.19" || rec19["teid"] != uint32(0x77000002) {
		t.Errorf("the N19 tunnel is %s -> %s TEID %v, want %s -> 198.51.100.19 TEID 0x77000002",
			local, peer, rec19["teid"], modesN9)
	}

	// Releasing the group session (TS 23.502 4.13.8.2.2, the last member on
	// this UPF gone) erases its own admission and rules and nothing of the
	// members'.
	before := len(rec.txns)
	gF, err := resp.UPFSEID.FSEID()
	if err != nil {
		t.Fatal(err)
	}
	del, ok := c.Delete(message.NewSessionDeletionRequest(0, 0, gF.SEID, 2, 0)).(*message.SessionDeletionResponse)
	if !ok || cause(t, del) != ie.CauseRequestAccepted {
		t.Fatalf("the group-level session's release was refused: %v", del)
	}
	if len(rec.txns) == before {
		t.Fatal("the release wrote nothing")
	}
	// The response's SEID is the CP's; the UP's is in the answer's F-SEID.
	for _, ch := range rec.last() {
		if ch.Resource == cfg.GTPUDecap+"/fteids" && ch.Value == nil && ch.Key["teid"] != teid {
			t.Errorf("the group release erased another session's admission %v", ch.Key)
		}
	}
}

// TestIndirectForwardingTunnelsFollowTheHandoverProcedure drives this UPF in
// both UPF roles of an inter NG-RAN N2 handover with UPF re-allocation and
// indirect forwarding, as two PDU sessions -- one UE leaving this UPF's area
// (it is the S-UPF), one arriving (it is the T-UPF) -- with the N4 messages of
// TS 23.502 4.9.1.3. Each indirect forwarding tunnel is a PDR on an F-TEID the
// UP function allocates (Source Interface Access) and a FAR toward the next
// forwarding endpoint (Destination Interface Access, TS 29.244 8.2.2 NOTE 2);
// what arrives on it is the UE's downlink, so the rule is keyed by the F-TEID
// alone. The T-UPF's tunnel goes by a modification after the SMF's timer
// (step 15a), the S-UPF's with the session (step 13a).
func TestIndirectForwardingTunnelsFollowTheHandoverProcedure(t *testing.T) {
	cfg := modesConfig(t)
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())

	// Step 6c: the T-UPF's N4 session. The uplink leaves over N9 to the PSA;
	// the downlink's AN tunnel is not known before step 8a, so its FAR drops.
	est := message.NewSessionEstablishmentRequest(0, 0, 0x9321, 1, 0,
		ie.NewFSEID(0x9321, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess), ie.NewNetworkInstance("internet"),
				chooseFTEID(), ie.NewUEIPAddress(0x02, "10.45.6.2", "", 0, 0)),
			ie.NewOuterHeaderRemoval(0, 0), ie.NewFARID(1)),
		forwardTo(1, ie.DstInterfaceCore, ie.NewOuterHeaderCreation(0x0100, 0x66000001, "198.51.100.5", "", 0, 0, 0)),
		ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore), ie.NewNetworkInstance("internet"),
				chooseFTEID(), ie.NewUEIPAddress(0x06, "10.45.6.2", "", 0, 0)),
			ie.NewOuterHeaderRemoval(0, 0), ie.NewFARID(2)),
		ie.NewCreateFAR(ie.NewFARID(2), ie.NewApplyAction(0x01)),
	)
	resp, ok := c.Establish(est).(*message.SessionEstablishmentResponse)
	if !ok || cause(t, resp) != ie.CauseRequestAccepted {
		t.Fatalf("step 6c was refused: %v", resp)
	}
	fseid, err := resp.UPFSEID.FSEID()
	if err != nil {
		t.Fatal(err)
	}
	tSEID := fseid.SEID

	// Steps 11b/11c: the T-RAN's forwarding tunnel, and a DL forwarding
	// tunnel the T-UPF allocates.
	mod := message.NewSessionModificationRequest(0, 0, tSEID, 2, 0,
		ie.NewCreatePDR(ie.NewPDRID(3), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess), ie.NewNetworkInstance("internet"),
				chooseFTEID(), ie.NewTGPPInterfaceType(ie.TGPPInterfaceTypeN3ForDataForwarding)),
			ie.NewOuterHeaderRemoval(0, 0), ie.NewFARID(3)),
		forwardTo(3, ie.DstInterfaceAccess, ie.NewOuterHeaderCreation(0x0100, 0x66000003, "10.20.30.3", "", 0, 0, 0)),
	)
	mresp, ok := c.Modify(mod).(*message.SessionModificationResponse)
	if !ok || cause(t, mresp) != ie.CauseRequestAccepted {
		t.Fatalf("step 11b was refused: %v", mresp)
	}
	fwdTEID, fwdAddr := createdFTEIDOf(t, mresp.CreatedPDR, 3)
	if fwdTEID == 0 || fwdAddr != modesN3 {
		t.Fatalf("step 11c's T-UPF SM N3 forwarding info is %#x@%s, want an allocated TEID on N3 %s", fwdTEID, fwdAddr, modesN3)
	}
	changes := rec.last()
	adm, ok := teidRule(changes, cfg.GTPUDecap+"/fteids", fwdTEID)
	if !ok {
		t.Fatal("the forwarding tunnel is not admitted")
	}
	fwd := ruleWithContext(t, changes, modesUpCtx, adm.Value["context_id"].(uint32))
	openAddresses(t, fwd, "the forwarding tunnel's PDR")
	if got := fwd.nextHop(); got != modesHopAcc {
		t.Errorf("forwarded data leaves by hop %d, want the access side's %d", got, modesHopAcc)
	}
	local, _, frec := tunnelLocal(t, changes, cfg, fwd.actionID())
	if peer, _ := netip.AddrFromSlice(frec["peer_address"].([]byte)); local.String() != modesN3 ||
		peer.String() != "10.20.30.3" || frec["teid"] != uint32(0x66000003) {
		t.Errorf("the forward is %s -> %s TEID %v, want %s -> the T-RAN's 10.20.30.3 TEID 0x66000003",
			local, peer, frec["teid"], modesN3)
	}

	// Step 8a: the T-RAN's DL AN tunnel.
	upd := message.NewSessionModificationRequest(0, 0, tSEID, 3, 0,
		ie.NewUpdateFAR(ie.NewFARID(2), ie.NewApplyAction(applyForw),
			ie.NewUpdateForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess),
				ie.NewOuterHeaderCreation(0x0100, 0x66000002, "10.20.30.3", "", 0, 0, 0))),
	)
	if got := cause(t, c.Modify(upd)); got != ie.CauseRequestAccepted {
		t.Fatalf("step 8a answered cause %d", got)
	}

	// Step 15a: after the indirect data forwarding timer, the forwarding
	// resources go and the session stays.
	rel := message.NewSessionModificationRequest(0, 0, tSEID, 4, 0,
		ie.NewRemovePDR(ie.NewPDRID(3)), ie.NewRemoveFAR(ie.NewFARID(3)))
	if got := cause(t, c.Modify(rel)); got != ie.CauseRequestAccepted {
		t.Fatalf("step 15a answered cause %d", got)
	}
	erased := false
	for _, ch := range rec.last() {
		if ch.Resource == cfg.GTPUDecap+"/fteids" && ch.Value == nil {
			if ch.Key["teid"] != fwdTEID {
				t.Errorf("step 15a erased another admission: %v", ch.Key)
			}
			erased = true
		}
	}
	if !erased {
		t.Error("step 15a left the forwarding tunnel admitted")
	}

	// The S-UPF's session: steady N3 and N9, then steps 11d/11e allocate its
	// DL forwarding tunnel toward the T-UPF's, and step 13a releases the
	// whole session, the forwarding resource with it.
	sEst := message.NewSessionEstablishmentRequest(0, 0, 0x9322, 1, 0,
		ie.NewFSEID(0x9322, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess), ie.NewNetworkInstance("internet"),
				chooseFTEID(), ie.NewUEIPAddress(0x02, "10.45.6.3", "", 0, 0)),
			ie.NewOuterHeaderRemoval(0, 0), ie.NewFARID(1)),
		forwardTo(1, ie.DstInterfaceCore, ie.NewOuterHeaderCreation(0x0100, 0x66000011, "198.51.100.5", "", 0, 0, 0)),
		ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore), ie.NewNetworkInstance("internet"),
				chooseFTEID(), ie.NewUEIPAddress(0x06, "10.45.6.3", "", 0, 0)),
			ie.NewOuterHeaderRemoval(0, 0), ie.NewFARID(2)),
		forwardTo(2, ie.DstInterfaceAccess, ie.NewOuterHeaderCreation(0x0100, 0x66000012, "10.20.30.2", "", 0, 0, 0)),
	)
	sresp, ok := c.Establish(sEst).(*message.SessionEstablishmentResponse)
	if !ok || cause(t, sresp) != ie.CauseRequestAccepted {
		t.Fatalf("the S-UPF's session was refused: %v", sresp)
	}
	sF, err := sresp.UPFSEID.FSEID()
	if err != nil {
		t.Fatal(err)
	}
	sMod := message.NewSessionModificationRequest(0, 0, sF.SEID, 2, 0,
		ie.NewCreatePDR(ie.NewPDRID(3), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess), ie.NewNetworkInstance("internet"), chooseFTEID()),
			ie.NewOuterHeaderRemoval(0, 0), ie.NewFARID(3)),
		forwardTo(3, ie.DstInterfaceAccess, ie.NewOuterHeaderCreation(0x0100, 0x66000013, "198.51.100.77", "", 0, 0, 0)),
	)
	smresp, ok := c.Modify(sMod).(*message.SessionModificationResponse)
	if !ok || cause(t, smresp) != ie.CauseRequestAccepted {
		t.Fatalf("step 11d was refused: %v", smresp)
	}
	sFwd, _ := createdFTEIDOf(t, smresp.CreatedPDR, 3)
	if got := cause(t, c.Delete(message.NewSessionDeletionRequest(0, 0, sF.SEID, 3, 0))); got != ie.CauseRequestAccepted {
		t.Fatalf("step 13a answered cause %d", got)
	}
	gone := map[uint32]bool{}
	for _, ch := range rec.last() {
		if ch.Resource == cfg.GTPUDecap+"/fteids" && ch.Value == nil {
			gone[ch.Key["teid"].(uint32)] = true
		}
	}
	if !gone[sFwd] || len(gone) != 3 {
		t.Errorf("step 13a erased admissions %v, want the S-UPF's three including forwarding tunnel %#x", gone, sFwd)
	}
}
