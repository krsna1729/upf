// SPDX-License-Identifier: BSD-3-Clause

// The subscriber's ARP identity on the data network.
//
// The N6 side is an Ethernet segment: before a packet addressed to a UE can be
// sent, the sender asks ARP who holds that address. The address is the
// session's (the SMF provisioned it, and this UPF is what the address is
// reachable through), so the answer has to be this UPF's, and the deployment
// says which identity it answers with: the interface's ARP responder module and
// its own Ethernet address (internal/routing's Interface.ARP/ARPMAC).
//
// One entry per session per address, claimed like a rule key: two sessions
// cannot answer for one address, and the entry goes when the session (or the
// PDR that named the address) does. TS 23.501 6.2.3 makes the ARP/ND responder
// a UPF function "for the Ethernet PDUs"; for IP PDU sessions the same duty is
// the deployment's -- this UPF is the address's next hop, and a segment that
// never learns its MAC address drops the downlink before the N6 port.
//
// The responder module itself drops every non-ARP packet (the fork's
// arp_responder.cc), so it belongs on the ARP branch of the ingress graph and
// nowhere else (docs/datapath.md).
package session

import (
	"net"
	"net/netip"

	"github.com/krsna1729/upf/internal/bess"
)

// arpEntry is one address a session answers for, as the module's resource
// spells it: the responder module, the IPv4 address, and the Ethernet address
// the reply carries (the interface's own, not the UE's).
type arpEntry struct {
	module string
	addr   netip.Addr
	mac    [6]byte
}

// claim is the compiler's own name for this entry: the resource's key, spelled
// the way the module's key is (the address in dotted decimal). Two sessions
// whose subscriber-side PDRs name one address on one interface would each
// answer for the other's traffic, so the second is refused exactly as two
// sessions naming one rule key are.
func (e arpEntry) claim() string {
	return e.module + "/entries\x00" + e.addr.String()
}

// change is the write that puts the entry in the responder's table.
func (e arpEntry) change() bess.Change {
	return bess.Change{
		Resource: e.module + "/entries",
		Key:      map[string]any{"ip": e.addr.String()},
		Value:    map[string]any{"mac_addr": macString(e.mac)},
	}
}

// erasure is the change that takes the entry out.
func (e arpEntry) erasure() bess.Change {
	return bess.Change{Resource: e.module + "/entries", Key: map[string]any{"ip": e.addr.String()}}
}

// arpEntryOf is the entry one PDR's address is answered by: a subscriber-side
// PDR whose interface declares a responder, with an IPv4 address of its own (or
// the session's, which merge fills in). A PDI naming an instance the deployment
// does not configure is resolved nowhere, and its write is refused before an
// entry could exist -- so there is nothing to erase and nothing to claim.
func (c *Compiler) arpEntryOf(p *pdr) (arpEntry, bool) {
	if !p.down || !p.ueIP.IsValid() || !p.ueIP.Unmap().Is4() {
		return arpEntry{}, false
	}
	ifc, err := c.interfaceFor(p)
	if err != nil || ifc.ARP == "" {
		return arpEntry{}, false
	}
	return arpEntry{module: ifc.ARP, addr: p.ueIP.Unmap(), mac: ifc.ARPMAC}, true
}

// arpEntries is every entry a session's subscriber-side PDRs name, in the PDRs'
// order and without repeats: a session whose downlink PDRs sit on two instances
// answers on both, and one whose two PDRs name one address answers once.
func (c *Compiler) arpEntries(s *Session) []arpEntry {
	var out []arpEntry
	seen := map[string]bool{}
	for _, p := range pdrsInOrder(s) {
		e, ok := c.arpEntryOf(p)
		if !ok {
			continue
		}
		if seen[e.claim()] {
			continue
		}
		seen[e.claim()] = true
		out = append(out, e)
	}
	return out
}

// macString is an Ethernet address as the fork's ArpResponder reads it back:
// lower case, colon-separated (core/utils/ether.cc's ToString), which is also
// what net.HardwareAddr prints.
func macString(mac [6]byte) string {
	return net.HardwareAddr(mac[:]).String()
}
