// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"context"
	"net/netip"
	"slices"
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/bess"
	"github.com/krsna1729/upf/internal/routing"
)

// Independent graph spellings used by the pre-target session tests.
func rulesRes(d Direction) string           { return d.PDRTable + "/rules" }
func metersRes(d Direction) string          { return d.Meters + "/meters" }
func tunnelsRes(d Direction) string         { return d.Tunnels + "/tunnels" }
func countersRes(d Direction) string        { return d.Counters + "/counters" }
func bufferCountersRes(b *Buffering) string { return b.Counter + "/counters" }
func flowsRes(b *Buffering) string          { return b.Store + "/flows" }

// A direction-changing PDR keeps its action id. Counter cells outlive their
// entries, so sharing one counter table would attribute its old-direction
// totals to the new direction and report usage twice.
func TestADirectionChangeMovesTheCounterBetweenTables(t *testing.T) {
	for _, module := range []string{"", "upf"} {
		t.Run("appliance="+module, func(t *testing.T) {
			cfg := testConfig()
			cfg.Appliance = module
			rec := &recorder{}
			c := New(cfg, rec, quietLogger())
			resp := c.Establish(message.NewSessionEstablishmentRequest(0, 0, 0x9101, 1, 0,
				ie.NewFSEID(0x9101, nil, nil),
				ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
					ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
						ie.NewUEIPAddress(0x06, "10.45.0.2", "", 0, 0)),
					ie.NewFARID(1), ie.NewURRID(7)),
				ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
					ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess))),
				fullURR(7),
			)).(*message.SessionEstablishmentResponse)
			if got := cause(t, resp); got != ie.CauseRequestAccepted {
				t.Fatalf("establishment cause %d", got)
			}
			up, down := c.res(CountersUplink), c.res(CountersDownlink)
			ids := counterKeys(rec.last(), down)
			if len(ids) != 1 {
				t.Fatalf("%s holds %d entries, want one", down, len(ids))
			}
			flip := message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 2, 0,
				ie.NewUpdatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
					ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess), testFTEID(0),
						ie.NewUEIPAddress(0x02, "10.45.0.2", "", 0, 0)),
					ie.NewFARID(1), ie.NewURRID(7)),
				ie.NewUpdateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
					ie.NewUpdateForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))))
			if got := cause(t, c.Modify(flip)); got != ie.CauseRequestAccepted {
				t.Fatalf("direction change cause %d", got)
			}
			changes := rec.last()
			if erased, ok := find0(changes, down, "action_id", ids[0]); !ok || erased.Value != nil {
				t.Errorf("%s: old-direction entry %d was not erased", down, ids[0])
			}
			if moved := find(t, changes, up, "action_id", ids[0]); moved.Value == nil {
				t.Errorf("%s: new-direction entry %d was erased", up, ids[0])
			}
			if up == down {
				t.Fatal("direction change retains old-direction counter cells")
			}
		})
	}
}

func applianceARPConfig(t *testing.T) Config {
	t.Helper()
	domains, err := routing.New([]routing.Interface{
		{Instance: "internet", Domain: 0, NextHop: 1, ARP: "arp_a", ARPMAC: [6]byte{2, 0, 0, 0, 0, 1},
			Pool: []netip.Prefix{netip.MustParsePrefix("10.45.0.0/16")}},
		{Instance: "other", Domain: 1, NextHop: 1, ARP: "arp_b", ARPMAC: [6]byte{2, 0, 0, 0, 0, 2},
			Pool: []netip.Prefix{netip.MustParsePrefix("10.46.0.0/16")}},
	}, 4)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig()
	cfg.Appliance, cfg.Instances = "upf", domains
	return cfg
}

// Both interfaces' subscriber entries are owned by the restarted controller;
// their single physical table must be read once and filtered by both pools.
func TestApplianceSweepClearsEverySubscriberPool(t *testing.T) {
	cfg := applianceARPConfig(t)
	fake := &sweepFake{contents: map[string][]bess.Entry{
		"upf/entries": {
			{Key: map[string]any{"ip": "10.45.0.2"}},
			{Key: map[string]any{"ip": "10.46.0.2"}},
			{Key: map[string]any{"ip": "192.0.2.2"}},
		},
	}}
	if err := New(cfg, fake, quietLogger()).Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	var erased []string
	for _, txn := range fake.changes {
		for _, ch := range txn {
			if ch.Resource == "upf/entries" {
				erased = append(erased, ch.Key["ip"].(string))
			}
		}
	}
	slices.Sort(erased)
	if !slices.Equal(erased, []string{"10.45.0.2", "10.46.0.2"}) {
		t.Fatalf("swept addresses %v; want both subscriber pools, not the deployment address", erased)
	}
}

// The appliance's ARP table has an address-only key. One session cannot
// silently overwrite a different interface's MAC for that address.
func TestApplianceRefusesConflictingARPIdentities(t *testing.T) {
	cfg := applianceARPConfig(t)
	// Match the address on both interfaces for this test.
	interfaces := cfg.Instances.Interfaces()
	interfaces[1].Pool = interfaces[0].Pool
	var err error
	cfg.Instances, err = routing.New(interfaces, 4)
	if err != nil {
		t.Fatal(err)
	}
	pdrFor := func(id uint16, instance string) *ie.IE {
		return ie.NewCreatePDR(ie.NewPDRID(id), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore), ie.NewNetworkInstance(instance),
				ie.NewUEIPAddress(0x06, "10.45.0.2", "", 0, 0)), ie.NewFARID(1))
	}
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())
	resp := c.Establish(message.NewSessionEstablishmentRequest(0, 0, 0x9102, 1, 0,
		ie.NewFSEID(0x9102, nil, nil), pdrFor(1, "internet"), pdrFor(2, "other"),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess)))))
	if got := cause(t, resp); got != ie.CauseRuleCreationModificationFailure {
		t.Fatalf("conflicting ARP identities cause %d, want rule failure", got)
	}
	if len(rec.txns) != 0 {
		t.Fatal("refused ARP identity conflict wrote a transaction")
	}
}
