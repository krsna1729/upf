// The downlink selector (TS 29.244 5.2.1): the packet path's way of naming the
// session a packet from the data network belongs to.
//
// An uplink packet names its session by the tunnel it arrived on -- the F-TEID
// the decap writes, which is the uplink matcher's key. A downlink packet
// carries no tunnel: the session is the one whose UE address the packet is
// addressed to, within the route domain the deployment classified the packet in
// (the network instance's, internal/routing). The selector is that look-up: one
// rule per (route domain, UE address), whose value is the session id, which the
// module writes into the packet's `action_id` attribute -- and that attribute
// is the key the downlink PdrMatch reads.
//
// It is the downlink's half of the keyed write. The matcher holds one key per
// session (that session's rules as the value); the selector is what turns a
// packet into that key, so the matcher itself needs no index of UE addresses.
package session

import (
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"

	"github.com/wmnsk/go-pfcp/ie"

	"github.com/krsna1729/upf/internal/bess"
)

// selectorKey is one key of the selector: the route domain a packet was
// classified in, and the UE address it is addressed to. The zero domain is the
// one-instance deployment's (every rule is domain 0 there).
type selectorKey struct {
	domain uint32
	addr   netip.Addr
}

// String is the key as the compiler spells it in its claim table.
func (k selectorKey) String() string {
	return fmt.Sprintf("%d/%s", k.domain, k.addr)
}

// selectorKeyOf is the selector key one PDR names, if it names one: a PDR from
// the core side whose PDI carries an IPv4 UE address. The address is the
// session's -- merge fills a PDI's address in from the session's when the PDI
// names none -- and the domain is the interface the PDI's network instance
// resolved to.
func selectorKeyOf(p *pdr) (selectorKey, bool) {
	if p.srcIfc != ie.SrcInterfaceCore || !p.ueIP.IsValid() || !p.ueIP.Unmap().Is4() {
		return selectorKey{}, false
	}
	return selectorKey{domain: p.domain, addr: p.ueIP.Unmap()}, true
}

// selectorKeys are the keys a session's downlink PDRs name, in the PDRs' order
// and without repeats: one selector rule per key, all of them the session's. A
// PDI that names no UE address leaves nothing to key on -- the session would be
// named by no packet -- so it is refused rather than written as a rule that
// matches an address every session shares.
func selectorKeys(s *Session) ([]selectorKey, error) {
	var keys []selectorKey
	seen := map[selectorKey]bool{}
	for _, p := range pdrsInOrder(s) {
		if p.srcIfc != ie.SrcInterfaceCore {
			continue
		}
		k, ok := selectorKeyOf(p)
		if !ok {
			return nil, fmt.Errorf(
				"%w: PDR %d names no IPv4 UE address, and the downlink selector names a session by it",
				errNotExpressible, p.id)
		}
		if seen[k] {
			continue
		}
		seen[k] = true
		keys = append(keys, k)
	}
	return keys, nil
}

// selectorRuleKey is the ExactMatch key of one selector key: one FieldData per
// field the graph declared, in its order (ExactMatchRuleKey, which is one list
// where WildcardMatch's key is a list of values beside a list of masks).
//
// Only a field of the session can be in it. The address is the UE's, and the
// route domain is the deployment's classification of the interface the packet
// arrived on; anything else -- the protocol, a port -- belongs to one PDR of the
// session, and a selector keyed on it would name the PDR rather than the
// session the matcher needs.
func selectorRuleKey(d Direction, k selectorKey) (map[string]any, error) {
	fields := make([]map[string]any, 0, len(d.SelectorFields))
	for _, f := range d.SelectorFields {
		value := make([]byte, f.width())
		switch f {
		case DstIP:
			copy(value, k.addr.AsSlice())
		case RouteDomain:
			binary.BigEndian.PutUint32(value, k.domain)
		default:
			return nil, fmt.Errorf(
				"%w: the downlink selector's key is the session's, and the %s is a field of one PDR",
				errNotExpressible, f)
		}
		fields = append(fields, map[string]any{"value_bin": value})
	}
	return map[string]any{"fields": fields}, nil
}

// selectorID is the id the selector writes for a session: the session's own
// local SEID, which is unique while the session lives and needs no other
// allocator (the module's attribute is 32 bits wide, and a UPF is not asked for
// four billion sessions at once). A session whose SEID does not fit is refused
// rather than named by a truncated id -- which would name another session.
func selectorID(s *Session) (uint32, error) {
	if s.LocalSEID == 0 || s.LocalSEID > math.MaxUint32 {
		return 0, fmt.Errorf(
			"%w: the session's SEID %d does not fit the selector's 32-bit session id",
			errNotExpressible, s.LocalSEID)
	}
	return uint32(s.LocalSEID), nil
}

// selectorChanges is the selector's writes for one session: the action record
// its rules reference, and one rule per key the session's downlink PDRs name.
//
// The record exists because BESS validates a rule's action id as a reference
// into the action resource the module declares (D-021): it carries neither meter
// nor next hop, because a packet the selector matches leaves on the module's own
// gate -- the matcher -- and the table is never in the packet path at all.
func (c *Compiler) selectorChanges(s *Session) ([]bess.Change, error) {
	d := c.cfg.Down
	if d.Selector == "" {
		return nil, nil
	}
	keys, err := selectorKeys(s)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, nil
	}
	id, err := selectorID(s)
	if err != nil {
		return nil, err
	}
	changes := make([]bess.Change, 0, len(keys)+1)
	if d.SelectorActions != "" {
		changes = append(changes, bess.Change{
			Resource: selectorActionsRes(d),
			Key:      map[string]any{"id": id},
			Value:    map[string]any{"meter_id": 0, "next_hop_id": 0},
		})
	}
	for _, k := range keys {
		key, err := selectorRuleKey(d, k)
		if err != nil {
			return nil, err
		}
		changes = append(changes, bess.Change{
			Resource: selectorRes(d),
			Key:      key,
			Value:    map[string]any{"gate": uint64(0), "action_id": id},
		})
	}
	return changes, nil
}

// selectorErases is what a deletion (or a replaced form) withdraws: every rule
// the session's keys name, and the action record they referenced -- the rule
// first, because the engine refuses to remove an action a live rule names.
func (c *Compiler) selectorErases(s *Session) ([]bess.Change, error) {
	d := c.cfg.Down
	if d.Selector == "" {
		return nil, nil
	}
	keys, err := selectorKeys(s)
	if err != nil {
		// The session is going: a key that cannot be built is one no rule of
		// it can hold, so the erases are what can be named.
		return nil, nil
	}
	if len(keys) == 0 {
		return nil, nil
	}
	changes := make([]bess.Change, 0, len(keys)+1)
	for _, k := range keys {
		key, err := selectorRuleKey(d, k)
		if err != nil {
			return nil, err
		}
		changes = append(changes, bess.Change{Resource: selectorRes(d), Key: key})
	}
	if d.SelectorActions != "" {
		id, err := selectorID(s)
		if err != nil {
			return nil, err
		}
		changes = append(changes, bess.Change{
			Resource: selectorActionsRes(d),
			Key:      map[string]any{"id": id},
		})
	}
	return changes, nil
}

// selectorClaim is the compiler's own name for one key of a direction's
// selector. Two sessions whose downlink PDRs name one (route domain, address)
// would each select the other's packets, and the second's rule would erase the
// first's on the way out, so the second is refused exactly as two sessions
// naming one WildcardMatch rule are.
func selectorClaim(d Direction, k selectorKey) string {
	return selectorRes(d) + "\x00" + k.String()
}
