// SPDX-License-Identifier: BSD-3-Clause

// The subscriber's ARP identity on the data network (arp.go): one entry per
// session per address on the interface that declares a responder, claimed like
// a rule key, written and erased with the session. The module answers only for
// the addresses it holds and drops everything that is not an ARP request, so a
// missing entry is indistinguishable from a downlink that never arrives.

package session

import (
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/routing"
)

// arpConfig is the deployment these tests drive: one instance that declares the
// responder module and the MAC its replies carry, and a graph that classifies
// the downlink by route domain.
func arpConfig(t *testing.T) Config {
	t.Helper()
	d, err := routing.New([]routing.Interface{{
		Instance: "internet", Domain: 0, NextHop: 1,
		Pool: []netip.Prefix{netip.MustParsePrefix("10.45.0.0/16")},
		ARP:  "arp_n6", ARPMAC: [6]byte{0x02, 0, 0, 0, 6, 1},
	}}, 4)
	if err != nil {
		t.Fatalf("the deployment was refused: %v", err)
	}
	cfg := testConfig()
	cfg.Instances = d
	cfg.Up.PDRFields = []Field{SrcIP, DstIP, Proto, SrcPort, DstPort, UpfTEID, QFI}
	cfg.Down.PDRFields = []Field{SrcIP, DstIP, Proto, SrcPort, DstPort, RouteDomain}
	return cfg
}

// arpEstablishment is a session of two PDRs on `instance`: an uplink one, and
// one from the subscriber side whose filter is `sdf` (two sessions for one
// address are told apart by it, so the address is what their ARP entries share).
func arpEstablishment(cpSEID uint64, ueIP string, fteid uint32, sdf string) *message.SessionEstablishmentRequest {
	return message.NewSessionEstablishmentRequest(0, 0, cpSEID, 1, 0,
		ie.NewNodeID("", "", "smf"),
		ie.NewFSEID(cpSEID, nil, nil),
		ie.NewCreatePDR(
			ie.NewPDRID(1),
			ie.NewPrecedence(100),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewNetworkInstance("internet"),
				ie.NewFTEID(0x01, fteid, net.ParseIP("192.0.2.1"), nil, 0),
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
				ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewNetworkInstance("internet"),
				ie.NewUEIPAddress(0x02, ueIP, "", 0, 0),
				ie.NewSDFFilter(sdf, "", "", "", 0),
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

// TestASessionsUEAddressIsAnsweredOnItsInterface: the entry is in the session's
// own transaction, keyed by the address, and its value is the interface's own
// MAC -- the reply comes from the UPF, not from the UE.
func TestASessionsUEAddressIsAnsweredOnItsInterface(t *testing.T) {
	rec := &recorder{}
	c := New(arpConfig(t), rec, quietLogger())
	resp := c.Establish(arpEstablishment(0x7501, "10.45.0.2", 0x71, "permit out udp from any to assigned 53"))
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	entry := find(t, rec.last(), "arp_n6/entries", "ip", "10.45.0.2")
	if got := entry.Value["mac_addr"]; got != "02:00:00:00:06:01" {
		t.Errorf("the entry's MAC is %v, want the interface's own 02:00:00:00:06:01", got)
	}
	// A deployment whose interface declares no responder writes nothing: there
	// is no module to hold the entry.
	rec = &recorder{}
	c = New(testConfig(), rec, quietLogger())
	resp = c.Establish(arpEstablishment(0x7502, "10.45.0.3", 0x72, "permit out udp from any to assigned 53"))
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment on a deployment with no responder answered cause %d", got)
	}
	for _, ch := range rec.last() {
		if strings.HasSuffix(ch.Resource, "/entries") {
			t.Errorf("an entry was written to %s, and the deployment names no responder", ch.Resource)
		}
	}
}

// TestTheARPEntryGoesWhenTheSessionDoes: a deletion answers for the address no
// more, and the entry goes in the deletion's own transaction -- with the
// address's old form, when a modification moved it.
func TestTheARPEntryGoesWhenTheSessionDoes(t *testing.T) {
	rec := &recorder{}
	c := New(arpConfig(t), rec, quietLogger())
	resp := c.Establish(arpEstablishment(0x7510, "10.45.0.4", 0x73, "permit out udp from any to assigned 53"))
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	seid := upFSEID(t, resp.(*message.SessionEstablishmentResponse))

	// A modification that moves the subscriber's address: the old entry is
	// erased, the new one written.
	moved := arpEstablishment(0x7510, "10.45.0.5", 0, "permit out udp from any to assigned 53")
	mod := message.NewSessionModificationRequest(0, 0, seid, 1, 0,
		ie.NewUpdatePDR(
			ie.NewPDRID(2),
			ie.NewPrecedence(100),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewNetworkInstance("internet"),
				ie.NewUEIPAddress(0x02, "10.45.0.5", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to assigned 53", "", "", "", 0),
			),
			ie.NewFARID(2),
		))
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification answered cause %d: %s", got, moved)
	}
	changes := rec.last()
	if _, ok := find0(changes, "arp_n6/entries", "ip", "10.45.0.4"); !ok {
		t.Error("the moved-away address's entry was not erased")
	}
	find(t, changes, "arp_n6/entries", "ip", "10.45.0.5")

	// And the deletion takes the entry that stands.
	del := message.NewSessionDeletionRequest(0, 0, seid, 1, 0)
	if got := cause(t, c.Delete(del)); got != ie.CauseRequestAccepted {
		t.Fatalf("the deletion answered cause %d", got)
	}
	if _, ok := find0(rec.last(), "arp_n6/entries", "ip", "10.45.0.5"); !ok {
		t.Error("the deletion left the session's ARP entry behind, and the address is answered for good")
	}
	// The claim is free again: a session that takes the address is accepted.
	c2 := New(arpConfig(t), rec, quietLogger())
	if got := cause(t, c2.Establish(arpEstablishment(0x7511, "10.45.0.5", 0x74, "permit out udp from any to assigned 53"))); got != ie.CauseRequestAccepted {
		t.Errorf("a session taking a deleted session's address answered cause %d", got)
	}
}

// TestTwoSessionsCannotClaimOneARPEntry: one address is one UE's, and the
// second session is refused rather than written -- the second entry would take
// the first session's downlink, and the SMF would have been told both stand.
func TestTwoSessionsCannotClaimOneARPEntry(t *testing.T) {
	rec := &recorder{}
	c := New(arpConfig(t), rec, quietLogger())
	resp := c.Establish(arpEstablishment(0x7520, "10.45.0.6", 0x75, "permit out udp from any to assigned 53"))
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the first establishment answered cause %d", got)
	}
	// The second session is told apart by its filter -- the rule keys differ --
	// and only the address is shared.
	resp = c.Establish(arpEstablishment(0x7521, "10.45.0.6", 0x76, "permit out udp from any to assigned 54"))
	if got := cause(t, resp); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a second session for one subscriber address answered cause %d, want 73", got)
	}
	if len(rec.txns) != 1 {
		t.Errorf("the refused establishment wrote a transaction (%d in all), and a refused message writes nothing", len(rec.txns))
	}
}
