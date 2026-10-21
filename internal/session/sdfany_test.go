// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"net"
	"testing"

	"github.com/krsna1729/upf/internal/bess"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// A PDI may carry several SDF Filter IEs and several QFI IEs, and the PDR
// matches a packet that any of them matches (TS 29.244 7.5.2.2, NOTE 4). Each
// combination is a rule of its own, sharing the PDR's Precedence and action.

const (
	udp53  = "permit out udp from any 53 to assigned"
	tcp443 = "permit out tcp from any 443 to assigned"
)

func uplinkPDI(cp uint64, filters []string, qfis []uint8) *message.SessionEstablishmentRequest {
	pdi := []*ie.IE{
		ie.NewSourceInterface(ie.SrcInterfaceAccess),
		ie.NewFTEID(0x01, 0x7b, net.ParseIP("192.0.2.1"), nil, 0),
		ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0),
	}
	for _, f := range filters {
		pdi = append(pdi, ie.NewSDFFilter(f, "", "", "", 0))
	}
	for _, q := range qfis {
		pdi = append(pdi, ie.NewQFI(q))
	}
	return message.NewSessionEstablishmentRequest(0, 0, cp, 1, 0,
		ie.NewFSEID(cp, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100), ie.NewPDI(pdi...), ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
	)
}

// ulRules are the uplink rules a transaction writes (a value) or erases (none).
func ulRules(changes []bess.Change) (written, erased []rule) {
	for _, r := range rules(changes) {
		if r.change.Resource != "pdr_ul/rules" {
			continue
		}
		if r.change.Value == nil {
			erased = append(erased, r)
		} else {
			written = append(written, r)
		}
	}
	return
}

// seen is the set of (destination port, qfi) pairs the rules constrain.
func seen(rs []rule) map[[2]int]int {
	out := map[[2]int]int{}
	for _, r := range rs {
		port := int(r.value(4)[0])<<8 | int(r.value(4)[1])
		out[[2]int{port, int(r.value(5)[0])}]++
	}
	return out
}

func TestSeveralSDFFiltersAreSeveralRules(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	if got := cause(t, c.Establish(uplinkPDI(0x7b01, []string{udp53, tcp443}, nil))); got != ie.CauseRequestAccepted {
		t.Fatalf("cause %d", got)
	}
	written, _ := ulRules(rec.last())
	got := seen(written)
	if len(written) != 2 || got[[2]int{53, 0}] != 1 || got[[2]int{443, 0}] != 1 {
		t.Fatalf("the PDR's rules are %v, want one for port 53 and one for 443", got)
	}
	if written[0].actionID() != written[1].actionID() {
		t.Errorf("the two rules carry actions %d and %d, want the PDR's one", written[0].actionID(), written[1].actionID())
	}
}

func TestSeveralQFIsAreSeveralRules(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	if got := cause(t, c.Establish(uplinkPDI(0x7b02, nil, []uint8{5, 9}))); got != ie.CauseRequestAccepted {
		t.Fatalf("cause %d", got)
	}
	written, _ := ulRules(rec.last())
	got := seen(written)
	if len(written) != 2 || got[[2]int{0, 5}] != 1 || got[[2]int{0, 9}] != 1 {
		t.Fatalf("the PDR's rules are %v, want one for QFI 5 and one for QFI 9", got)
	}
}

func TestFiltersAndQFIsMultiplyAndModificationErasesWhatItDrops(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(uplinkPDI(0x7b03, []string{udp53, tcp443}, []uint8{5, 9})).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("cause %d", got)
	}
	written, _ := ulRules(rec.last())
	if len(written) != 4 {
		t.Fatalf("2 filters x 2 QFIs wrote %d rules, want 4: %v", len(written), seen(written))
	}
	// Keep one filter and one QFI: three rules go.
	mod := message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 2, 0,
		ie.NewUpdatePDR(ie.NewPDRID(1), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0),
				ie.NewSDFFilter(udp53, "", "", "", 0),
				ie.NewQFI(5)),
			ie.NewFARID(1)))
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("modification cause %d", got)
	}
	written, erased := ulRules(rec.last())
	if got := seen(erased); len(erased) != 3 || got[[2]int{53, 5}] != 0 {
		t.Errorf("the modification erased %v, want the three combinations it dropped and not (53, 5)", got)
	}
	if got := seen(written); len(written) != 1 || got[[2]int{53, 5}] != 1 {
		t.Errorf("the modification wrote %v, want the one it kept", got)
	}
	// The deletion takes the one that is left.
	if got := cause(t, c.Delete(message.NewSessionDeletionRequest(0, 0, upFSEID(t, resp), 3, 0))); got != ie.CauseRequestAccepted {
		t.Fatalf("deletion cause %d", got)
	}
	if _, erased := ulRules(rec.last()); len(erased) != 1 {
		t.Errorf("the deletion erased %d uplink rules, want 1", len(erased))
	}
}

func TestSeveralSDFFiltersAreSeveralRulesOfTheSessionsList(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cfg      Config
		resource string
	}{
		{"firewall", firewallConfig("fw_ul", ""), "fw_ul/rules"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{}
			c := New(tc.cfg, rec, quietLogger())
			if got := cause(t, c.Establish(uplinkPDI(0x7b04, []string{udp53, tcp443}, nil))); got != ie.CauseRequestAccepted {
				t.Fatalf("cause %d", got)
			}
			list := firewallPolicy(t, rec.last(), tc.resource)
			ports := map[uint32]bool{}
			for _, r := range list {
				p, _ := r["dst_port_low"].(uint32)
				ports[p] = true
			}
			if len(list) != 2 || !ports[53] || !ports[443] {
				t.Errorf("the list is %v, want a rule for port 53 and one for 443", list)
			}
		})
	}
}

func TestTheFirewallPathRefusesAPDIThatNamesAQFI(t *testing.T) {
	rec := &recorder{}
	c := New(firewallConfig("fw_ul", ""), rec, quietLogger())
	if got := cause(t, c.Establish(uplinkPDI(0x7b05, []string{udp53}, []uint8{5}))); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("cause %d, want a rule failure: the firewall has no QFI field, so the rule would match every flow", got)
	}
}
