// SPDX-License-Identifier: BSD-3-Clause

// The PFCP side of the session layer: reading a session message into the
// model below, resolving it into dataplane resources, and answering.
//
// The rule shapes are the ones deploy/upf.yaml declares: a WildcardMatch table
// whose rule value is {priority, gate, action_id} (BESS D-141), an ActionTable
// whose action names a meter and a next hop, a Meter per policed direction, the
// plugin's per-session tunnel record for the downlink, and its per-TEID session
// entry for the uplink.

package session

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/bess"
)

// The Apply Action flags a FAR can carry (TS 29.244 8.2.26, octet 5).
const (
	applyDrop = 0x01
	applyForw = 0x02
	applyBuff = 0x04
)

// The bytes a rule whose FAR drops leaves on.
const dropGate = 8192 // DROP_GATE (core/gate.h)

// errNotExpressible marks a well-formed rule the dataplane cannot carry: a port
// range needs the range kernel of the roadmap's classifier work, and an address
// or prefix that is not IPv4 has no four-byte form at all. The request is not
// malformed, so the SMF is told the rule failed, not that the message was
// wrong.
var errNotExpressible = errors.New("the rule cannot be expressed by a mask")

// errNoResources marks a session the UPF cannot carry for want of a resource:
// an F-TEID the allocator has none of, or one another session already holds.
// The SMF is told cause 75 ("no resources available"), which is what it retries
// or reconciles against; a rule failure (cause 73) would say the filter was
// wrong, and an accepted answer with no usable F-TEID would blackhole the
// uplink while claiming success. (Cause 74 is PFCP Entity In Congestion: the
// answer for a *busy* UPF, not for one whose id space is empty.)
var errNoResources = errors.New("no resources available")

// idsOf returns a table's keys in order. Every transaction this compiler
// writes is built from these: a map's iteration order must never decide what
// the dataplane is told, or which id an object gets.
func idsOf[K ~uint16 | ~uint32, V any](m map[K]V) []K {
	out := make([]K, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

// pdrsInOrder and qersInOrder are the session's objects in id order.
func pdrsInOrder(s *Session) []*pdr {
	out := make([]*pdr, 0, len(s.PDRs))
	for _, id := range idsOf(s.PDRs) {
		out = append(out, s.PDRs[id])
	}
	return out
}

func qersInOrder(s *Session) []*qer {
	out := make([]*qer, 0, len(s.QERs))
	for _, id := range idsOf(s.QERs) {
		out = append(out, s.QERs[id])
	}
	return out
}

// pdrReq is a Create PDR or an Update PDR, as the SMF sent it.
type pdrReq struct {
	id         uint16
	precedence uint32
	srcIfc     uint8
	ueIP       netip.Addr
	hasUEIP    bool
	sdf        *sdfFilter
	farID      uint32
	qerIDs     []uint32
	urrIDs     []uint32

	// An uplink PDR's PDI names an F-TEID: the TEID the SMF expects us to
	// use (0: ours to choose) and, for the address, usually 0.
	hasFTEID bool
	teid     uint32
}

type farReq struct {
	id       uint32
	apply    uint8
	destIfc  uint8
	teid     uint32
	peer     netip.Addr
	hasOuter bool
}

type qerReq struct {
	id      uint32
	gateUL  uint8
	gateDL  uint8
	mbUL    uint64
	mbDL    uint64
	hasRate bool
}

type urrReq struct{ id uint32 }

// Establish implements n4.SessionHandler.
func (c *Compiler) Establish(req *message.SessionEstablishmentRequest) message.Message {
	ies := establishmentIEs(req)
	cpSEID, err := cpFSEID(ies)
	if err != nil {
		c.log.Warn("session: the establishment request names no CP F-SEID", "error", err)
		return establishResponse(req, 0, ie.CauseMandatoryIEMissing, nil)
	}
	pdrs, fars, qers, err := parseCreate(ies)
	if err != nil {
		c.log.Warn("session: cannot read the establishment request", "error", err)
		return establishResponse(req, 0, parseCause(err), nil)
	}

	c.mu.Lock()
	// A retransmission of an establishment we already applied: answer as
	// before rather than allocating a second session for it.
	if s := c.findByCP(cpSEID); s != nil {
		created := s.createdPDRs(c.cfg)
		c.mu.Unlock()
		c.log.Info("session: establishment repeated", "cp_seid", cpSEID, "seid", s.LocalSEID)
		return establishResponse(req, s.LocalSEID, ie.CauseRequestAccepted, created)
	}
	local := c.nextSEID
	c.nextSEID++
	c.mu.Unlock()

	s := &Session{
		LocalSEID: local,
		CPSEID:    cpSEID,
		PDRs:      map[uint16]*pdr{},
		FARs:      map[uint32]*far{},
		QERs:      map[uint32]*qer{},
		URRs:      map[uint32]*urr{},
	}
	if err := c.merge(s, pdrs, fars, qers, nil, nil, nil); err != nil {
		c.log.Warn("session: cannot carry the establishment request",
			"cp_seid", cpSEID, "error", err)
		// merge allocates as it goes (the F-TEID among them) and refuses when a
		// later PDR names something the table cannot carry, or a value another
		// session holds: what it got through is this session's and is not going
		// anywhere.
		c.mu.Lock()
		c.releaseSession(s)
		c.mu.Unlock()
		return establishResponse(req, local, compileCause(err), nil)
	}

	changes, created, err := c.compile(s)
	if err != nil {
		c.log.Warn("session: cannot compile the establishment request",
			"cp_seid", cpSEID, "error", err)
		// The compile allocated ids before it hit the error: they are this
		// session's and it is not becoming a session, so nothing else can
		// release them.
		c.mu.Lock()
		c.releaseSession(s)
		c.mu.Unlock()
		return establishResponse(req, local, compileCause(err), nil)
	}
	if err := c.ap.Apply(context.Background(), changes...); err != nil {
		c.log.Warn("session: the dataplane refused the session",
			"cp_seid", cpSEID, "seid", local, "error", err)
		// A definite refusal means nothing of this session is in the dataplane,
		// so its ids are free again. An *unanswered* request is different: the
		// transaction may have committed, and handing those ids to the next
		// session would let it overwrite records this request's rules still
		// select -- so they stay allocated, and the leak is the safe failure.
		if definiteRefusal(err) {
			c.mu.Lock()
			c.releaseSession(s)
			c.mu.Unlock()
		}
		return establishResponse(req, local, causeOf(err), nil)
	}

	c.mu.Lock()
	c.sessions[local] = s
	for _, p := range pdrsInOrder(s) {
		if p.teid != 0 {
			c.byTEID[p.teid] = s
		}
	}
	c.mu.Unlock()

	c.log.Info("session: established", "cp_seid", cpSEID, "seid", local,
		"ue_ip", s.UEIP.String(), "pdrs", len(s.PDRs), "changes", len(changes))
	return establishResponse(req, local, ie.CauseRequestAccepted, created)
}

// Modify implements n4.SessionHandler: the request's lists are merged into the
// session and the whole session is rewritten in one transaction. Rewriting
// what did not change is idempotent (the daemon applies resource contents, not
// commands), and it keeps one code path for every modification shape; the
// per-record optimizations of docs/design.md ("Modification semantics") can
// narrow it later without changing what the dataplane holds.
func (c *Compiler) Modify(req *message.SessionModificationRequest) message.Message {
	seid := req.SEID()
	c.mu.Lock()
	s := c.sessions[seid]
	c.mu.Unlock()
	if s == nil {
		return modifyResponse(req, seid, ie.CauseSessionContextNotFound, nil)
	}

	ies := modificationIEs(req)
	pdrs, fars, qers, err := parseCreate(ies)
	if err != nil {
		c.log.Warn("session: cannot read the modification request", "seid", seid, "error", err)
		return modifyResponse(req, seid, parseCause(err), nil)
	}
	removePDRs, removeFARs := parseRemovals(ies)

	// merge takes the lock itself.
	if err := c.merge(s, pdrs, fars, qers, nil, removePDRs, removeFARs); err != nil {
		c.log.Warn("session: cannot carry the modification request", "seid", seid, "error", err)
		return modifyResponse(req, seid, compileCause(err), nil)
	}

	changes, created, err := c.compile(s)
	if err != nil {
		c.log.Warn("session: cannot compile the modification request", "seid", seid, "error", err)
		// What this compile allocated is not released: the session is live and
		// its records name those ids, so freeing them would let the pool hand
		// them to a session whose record the live one still selects. The ids of
		// objects a modification removed are leaked for the same reason; a
		// provenance-tracked release is the fix (docs/design.md).
		return modifyResponse(req, seid, compileCause(err), nil)
	}
	if err := c.ap.Apply(context.Background(), changes...); err != nil {
		c.log.Warn("session: the dataplane refused the modification", "seid", seid, "error", err)
		return modifyResponse(req, seid, causeOf(err), nil)
	}

	c.mu.Lock()
	for _, p := range pdrsInOrder(s) {
		if p.teid != 0 {
			c.byTEID[p.teid] = s
		}
	}
	c.mu.Unlock()

	c.log.Info("session: modified", "seid", seid, "pdrs", len(s.PDRs), "changes", len(changes))
	return modifyResponse(req, seid, ie.CauseRequestAccepted, created)
}

// Delete implements n4.SessionHandler.
func (c *Compiler) Delete(req *message.SessionDeletionRequest) message.Message {
	seid := req.SEID()
	c.mu.Lock()
	s := c.sessions[seid]
	c.mu.Unlock()
	if s == nil {
		// Already gone: the SMF gets the answer it wanted (a retransmitted
		// deletion must not be an error).
		return deleteResponse(req, seid, ie.CauseSessionContextNotFound)
	}
	if err := c.remove(context.Background(), s); err != nil {
		c.log.Warn("session: the dataplane refused the deletion", "seid", seid, "error", err)
		return deleteResponse(req, seid, causeOf(err))
	}
	c.log.Info("session: deleted", "seid", seid)
	return deleteResponse(req, seid, ie.CauseRequestAccepted)
}

// merge folds a request's objects into the session's model.
func (c *Compiler) merge(s *Session, pdrs []pdrReq, fars []farReq, qers []qerReq,
	urrs []urrReq, removePDRs []uint16, removeFARs []uint32) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, q := range qers {
		entry := s.QERs[q.id]
		if entry == nil {
			entry = &qer{id: q.id}
			s.QERs[q.id] = entry
		}
		// An Update QER carries what changed; every field it names replaces
		// the one before it.
		entry.gateUL, entry.gateDL = q.gateUL, q.gateDL
		if q.hasRate {
			entry.mbUL, entry.mbDL, entry.hasRate = q.mbUL, q.mbDL, true
			if entry.meterUL == 0 {
				if id, err := c.meters.alloc(); err != nil {
					c.log.Warn("session: no meter id left for a QER", "qer", q.id)
				} else {
					entry.meterUL = id
				}
			}
			if entry.meterDL == 0 {
				if id, err := c.meters.alloc(); err != nil {
					c.log.Warn("session: no meter id left for a QER", "qer", q.id)
				} else {
					entry.meterDL = id
				}
			}
		}
	}
	for _, f := range fars {
		entry := s.FARs[f.id]
		if entry == nil {
			entry = &far{id: f.id}
			s.FARs[f.id] = entry
		}
		entry.apply, entry.destIfc = f.apply, f.destIfc
		if f.hasOuter {
			entry.teid, entry.peer, entry.hasOuter = f.teid, f.peer, true
		}
	}
	for _, u := range urrs {
		if s.URRs[u.id] == nil {
			s.URRs[u.id] = &urr{id: u.id}
		}
	}
	for _, id := range removePDRs {
		delete(s.PDRs, id)
	}
	for _, id := range removeFARs {
		delete(s.FARs, id)
	}
	for _, p := range pdrs {
		old := s.PDRs[p.id]
		pdr := &pdr{
			id: p.id, precedence: p.precedence, srcIfc: p.srcIfc,
			ueIP: p.ueIP, sdf: p.sdf, farID: p.farID,
			qerIDs: p.qerIDs,
		}
		if old != nil {
			// An update keeps the dataplane identity: the rule that already
			// selects this PDR keeps its action id, so a worker switching
			// between old and new state never sees a dangling reference.
			pdr.actionID = old.actionID
			pdr.teid = old.teid
			pdr.meterID = old.meterID
		}
		if p.hasFTEID && p.srcIfc == ie.SrcInterfaceAccess {
			if p.teid != 0 {
				// An F-TEID the SMF pinned is ours to use and ours to keep out
				// of the allocator's way: another session handed the same
				// value would share the TEID rule, and its uplink packets
				// would land in whichever session wrote the rule last.
				if other := c.byTEID[p.teid]; other != nil && other != s {
					return fmt.Errorf(
						"%w: the pinned F-TEID %#x is session %d's",
						errNoResources, p.teid, other.LocalSEID)
				}
				pdr.teid = p.teid
				c.teids.reserve(p.teid)
			} else if pdr.teid == 0 {
				// The SMF left the F-TEID to us (TEID 0): allocate one and
				// report it in the Created PDR. Failing to is not something to
				// shrug at -- a session with TEID 0 has no rule to be selected
				// by, so the uplink would blackhole while the SMF was told the
				// establishment succeeded.
				id, err := c.teids.alloc()
				if err != nil {
					return fmt.Errorf("%w: %v", errNoResources, err)
				}
				pdr.teid = id
			}
		}
		if p.ueIP.IsValid() {
			s.UEIP = p.ueIP
		}
		s.PDRs[p.id] = pdr
	}
	// Resolve what each PDR's FAR and QERs mean for the dataplane: a forward or
	// a drop, the meter of the QER this direction is policed by, and (downlink)
	// the tunnel record the FAR's outer header creation names.
	for _, p := range pdrsInOrder(s) {
		far := s.FARs[p.farID]
		dir := c.direction(p.srcIfc)
		p.drop = far == nil || far.apply&applyForw == 0
		p.meterID = 0
		p.tunnels = nil
		for _, qid := range p.qerIDs {
			entry := s.QERs[qid]
			if entry == nil {
				continue
			}
			if p.srcIfc == ie.SrcInterfaceAccess {
				if entry.gateUL == ie.GateStatusClosed {
					p.drop = true
				}
				if entry.hasRate {
					p.meterID = entry.meterUL
				}
			} else {
				if entry.gateDL == ie.GateStatusClosed {
					p.drop = true
				}
				if entry.hasRate {
					p.meterID = entry.meterDL
				}
			}
		}
		if dir.Tunnels != "" && far != nil && far.hasOuter {
			p.tunnels = []string{tunnelsRes(dir)}
		}
		if !p.ueIP.IsValid() {
			// The PDI names no address of its own, so the session's is the one
			// an SMF means (it may send the address on one direction only). An
			// uplink rule with the address masked out instead would match every
			// session's decapsulated packets at that precedence.
			p.ueIP = s.UEIP
		}
	}
	return nil
}

// compile turns a session's model into the resource changes that program it,
// and the Created PDRs the answer carries. Every action and meter id the
// session needs is allocated here, once.
func (c *Compiler) compile(s *Session) ([]bess.Change, []*ie.IE, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	changes := make([]bess.Change, 0, 4*len(s.PDRs)+len(s.QERs))
	created := make([]*ie.IE, 0, len(s.PDRs))

	// Meters first: an action references the meter its QER resolved to. One
	// record per policed direction, each a two-rate three-colour meter with the
	// QER's own rate committed and peak (the same value twice: a QER's MBR
	// allows a rate, not an excess), and a tenth of a second of burst.
	for _, q := range qersInOrder(s) {
		if !q.hasRate {
			continue
		}
		if q.meterUL != 0 {
			changes = append(changes, meterChange(metersRes(c.cfg.Up), q.meterUL, q.mbUL))
		}
		if q.meterDL != 0 {
			changes = append(changes, meterChange(metersRes(c.cfg.Down), q.meterDL, q.mbDL))
		}
	}

	for _, p := range pdrsInOrder(s) {
		dir := c.direction(p.srcIfc)
		key, err := p.ruleKey(dir.PDRFields)
		if err != nil {
			return nil, nil, fmt.Errorf("PDR %d: %w", p.id, err)
		}
		if p.drop && p.actionID == 0 {
			// A drop needs no action record: the rule's gate is the whole
			// result, and the packet path pays for nothing else.
			changes = append(changes, bess.Change{
				Resource: rulesRes(dir),
				Key:      key,
				Value: map[string]any{
					"priority":  p.precedence,
					"gate":      uint64(dropGate),
					"action_id": uint32(0),
				},
			})
			continue
		}
		if p.actionID == 0 {
			id, err := c.actions.alloc()
			if err != nil {
				return nil, nil, fmt.Errorf("allocating an action for PDR %d: %w", p.id, err)
			}
			p.actionID = id
		}

		changes = append(changes, bess.Change{
			Resource: actionsRes(dir),
			Key:      map[string]any{"id": p.actionID},
			Value:    map[string]any{"meter_id": p.meterID, "next_hop_id": dir.NextHop},
		})

		// A downlink PDR's FAR names the tunnel this session's packets leave
		// by: the record is keyed by the same action id the rule carries.
		for _, resource := range p.tunnels {
			far := s.FARs[p.farID]
			changes = append(changes, bess.Change{
				Resource: resource,
				Key:      map[string]any{"action_id": p.actionID},
				Value: map[string]any{
					"teid":      far.teid,
					"gnb_ip":    far.peer.String(),
					"ether_src": c.cfg.N3MAC[:],
					"ether_dst": c.cfg.PeerMAC[:],
				},
			})
		}

		changes = append(changes, bess.Change{
			Resource: rulesRes(dir),
			Key:      key,
			Value: map[string]any{
				// The table's own output gate: one chain per direction.
				"priority":  p.precedence,
				"gate":      uint64(0),
				"action_id": p.actionID,
			},
		})

		// An uplink PDR's F-TEID is what makes the TEID ours: a rule of the
		// table in front of the decap, which delivers matching G-PDUs to it.
		// A TEID no rule names is dropped there (the table's default gate),
		// so the decap itself needs no session state.
		if p.teid != 0 {
			changes = append(changes, bess.Change{
				Resource: c.teidRes(),
				Key:      teidRuleKey(p.teid),
				Value: map[string]any{
					"priority": p.precedence,
					"gate":     uint64(c.cfg.TEIDGate),
				},
			})
			created = append(created, ie.NewCreatedPDR(
				ie.NewPDRID(p.id),
				createdFTEID(p.teid, c.cfg.N3Addr)))
		}
	}
	return changes, created, nil
}

// ruleKey is the WildcardMatch rule key for a PDR: for every field of the
// table, the mask the PDI constrains it with, and the value the packet must
// carry. A field the PDI does not name is masked out, which is what lets one
// table hold PDRs of different shapes.
//
// The value must be canonical (value & ^mask == 0), and the key is the
// concatenation of mask then value per field.
func (p *pdr) ruleKey(fields []Field) (map[string]any, error) {
	// The table's key message is WildcardMatchRuleKey: one FieldData per
	// field, values and masks in two parallel lists (protobuf JSON, which is
	// how the SDK builds it: a bytes field is base64).
	values := make([]map[string]any, 0, len(fields))
	masks := make([]map[string]any, 0, len(fields))
	for _, f := range fields {
		width := f.width()
		mask := make([]byte, width)
		value := make([]byte, width)
		m, ok, err := p.matchValue(f)
		if err != nil {
			return nil, fmt.Errorf("the PDI's %s: %w", f, err)
		}
		if ok {
			copy(mask, m.mask)
			copy(value, m.value)
		}
		values = append(values, map[string]any{"value_bin": value})
		masks = append(masks, map[string]any{"value_bin": mask})
	}
	return map[string]any{"values": values, "masks": masks}, nil
}

// match is one field's constraint: the bits a PDI fixes, and the mask that says
// which of them matter. The two differ where the PDI names a prefix -- an SDF
// filter's "to 10.10.0.0/16" is a rule about a /16, not about the address
// 10.10.0.0 -- and the mask is what makes it so.
type match struct {
	value []byte
	mask  []byte
}

// ones is a mask of n bytes, all bits set.
func ones(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = 0xff
	}
	return b
}

// host is a field constrained to one IPv4 address: the UE's, where a PDI names
// it. No address at all is *unconstrained*, not inexpressible -- the zero
// netip.Addr is how "the PDI says nothing about this field" arrives here (a PDR
// with no UE IP IE, an SMF that sent the address on the other direction's PDI
// only), and refusing those would turn a valid session into cause 73. An
// address the table's four bytes cannot carry is inexpressible, never
// "unconstrained": a PDI naming an IPv6 UE is a session whose rules must not be
// written at all, because a masked-out address matches every address --
// another session's packets included.
func host(a netip.Addr) (match, bool, error) {
	if !a.IsValid() {
		// merge fills a PDR's address in from the session's when its own PDI
		// names none, so this is a session with no UE address anywhere: there
		// is nothing to key the rule on, and leaving the field open would let
		// the rule match every session's decapsulated packets.
		return match{}, false, fmt.Errorf("%w: no UE address for the rule's key", errNotExpressible)
	}
	a = a.Unmap()
	if !a.Is4() {
		return match{}, false, fmt.Errorf("%w: address %s is not IPv4", errNotExpressible, a)
	}
	b := a.As4()
	return match{value: b[:], mask: ones(4)}, true, nil
}

// pref is a field constrained to an IPv4 prefix: the value is its network
// address (the canonical form the classifier requires, value & ^mask == 0) and
// the mask its length, bit by bit so a /12 is as expressible as a /16. A
// filter whose address carries host bits ("10.10.1.5/16") means the network:
// the Flow Description's form is address/mask, and the mask is what the table
// carries.
func pref(p netip.Prefix) (match, error) {
	a := p.Addr().Unmap()
	if !a.Is4() {
		return match{}, fmt.Errorf("%w: prefix %s is not IPv4", errNotExpressible, p)
	}
	bits := p.Bits()
	if bits < 0 || bits > 32 {
		return match{}, fmt.Errorf("%w: prefix %s has no IPv4 length", errNotExpressible, p)
	}
	b := a.As4()
	m := make([]byte, 4)
	for i := 0; i < bits; i++ {
		m[i/8] |= 0x80 >> (i % 8)
	}
	for i := range b {
		b[i] &= m[i]
	}
	return match{value: b[:], mask: m}, nil
}

// matchValue is the constraint a PDR puts on one field of its table, whether it
// constrains it at all, and whether the PDI names something the table cannot
// express. The three states are distinct on purpose: a field the PDI leaves
// open is masked out (an uplink PDR is chosen by its UE address, not its
// destination); a field the PDI names is constrained; and one it names in a
// form a 4-byte mask cannot carry is a session the SMF is told to fix, not one
// whose rule quietly matches everything.
func (p *pdr) matchValue(f Field) (match, bool, error) {
	switch f {
	case SrcIP:
		// The uplink's UE address is the source. A downlink PDR's SDF may name
		// either side; when it names no source, the source stays unconstrained
		// -- the peer on the data network is not the UE, so constraining this
		// field to the SDF's *destination* would demand the UE's address on
		// both sides and match no packet at all.
		if p.srcIfc == ie.SrcInterfaceAccess {
			if p.sdf != nil && p.sdf.srcOK {
				m, err := pref(p.sdf.src)
				return m, err == nil, err
			}
			return host(p.ueIP)
		}
		if p.sdf != nil && p.sdf.srcOK {
			m, err := pref(p.sdf.src)
			return m, err == nil, err
		}
		return match{}, false, nil
	case DstIP:
		if p.srcIfc == ie.SrcInterfaceAccess {
			return match{}, false, nil // the uplink is chosen by its UE address
		}
		if p.sdf != nil && p.sdf.dstOK {
			m, err := pref(p.sdf.dst)
			return m, err == nil, err
		}
		return host(p.ueIP)
	case Proto:
		if p.sdf != nil && p.sdf.protoOK {
			return match{value: []byte{p.sdf.proto}, mask: ones(1)}, true, nil
		}
		return match{}, false, nil
	case SrcPort:
		if p.sdf != nil && p.sdf.sportOK {
			b := make([]byte, 2)
			binary.BigEndian.PutUint16(b, p.sdf.sport)
			return match{value: b, mask: ones(2)}, true, nil
		}
		return match{}, false, nil
	case DstPort:
		if p.sdf != nil && p.sdf.dportOK {
			b := make([]byte, 2)
			binary.BigEndian.PutUint16(b, p.sdf.dport)
			return match{value: b, mask: ones(2)}, true, nil
		}
		return match{}, false, nil
	default:
		return match{}, false, nil
	}
}

// createdPDRs is what the response re-states on a retransmission.
func (s *Session) createdPDRs(cfg Config) []*ie.IE {
	out := make([]*ie.IE, 0, len(s.PDRs))
	for _, p := range pdrsInOrder(s) {
		if p.teid != 0 {
			out = append(out, ie.NewCreatedPDR(
				ie.NewPDRID(p.id),
				createdFTEID(p.teid, cfg.N3Addr)))
		}
	}
	return out
}

// -- reading the request ------------------------------------------------------

// requestIEs is a message's IEs in one list. go-pfcp's constructors and its own
// parser put the IEs the header names into typed fields, so a handler never
// sees them in req.IEs: the typed fields *are* the request. Absent fields are
// nil, and a nil IE is not an IE.
func requestIEs(lists ...[]*ie.IE) []*ie.IE {
	var out []*ie.IE
	for _, list := range lists {
		for _, i := range list {
			if i != nil {
				out = append(out, i)
			}
		}
	}
	return out
}

// establishmentIEs is what an establishment request carries.
func establishmentIEs(req *message.SessionEstablishmentRequest) []*ie.IE {
	return requestIEs(
		[]*ie.IE{req.NodeID, req.CPFSEID},
		req.CreatePDR, req.CreateFAR, req.CreateQER, req.CreateURR,
	)
}

// modificationIEs is what a modification request carries: what it creates,
// what it updates, and what it removes.
func modificationIEs(req *message.SessionModificationRequest) []*ie.IE {
	return requestIEs(
		[]*ie.IE{req.NodeID, req.CPFSEID},
		req.CreatePDR, req.CreateFAR, req.CreateQER, req.CreateURR,
		req.UpdatePDR, req.UpdateFAR, req.UpdateQER, req.UpdateURR,
		req.RemovePDR, req.RemoveFAR, req.RemoveQER, req.RemoveURR,
	)
}

func cpFSEID(ies []*ie.IE) (uint64, error) {
	for _, i := range ies {
		if i.Type != ie.FSEID {
			continue
		}
		fields, err := i.FSEID()
		if err != nil {
			return 0, err
		}
		return fields.SEID, nil
	}
	return 0, errors.New("no CP F-SEID")
}

// parseCreate reads the Create/Update lists a session message carries.
func parseCreate(ies []*ie.IE) ([]pdrReq, []farReq, []qerReq, error) {
	var pdrs []pdrReq
	var fars []farReq
	var qers []qerReq
	for _, i := range ies {
		switch i.Type {
		case ie.CreatePDR, ie.UpdatePDR:
			p, err := parsePDR(i)
			if err != nil {
				return nil, nil, nil, err
			}
			pdrs = append(pdrs, p)
		case ie.CreateFAR, ie.UpdateFAR:
			f, err := parseFAR(i)
			if err != nil {
				return nil, nil, nil, err
			}
			fars = append(fars, f)
		case ie.CreateQER, ie.UpdateQER:
			q, err := parseQER(i)
			if err != nil {
				return nil, nil, nil, err
			}
			qers = append(qers, q)
		}
	}
	return pdrs, fars, qers, nil
}

// parseRemovals reads the PDR and FAR ids a modification removes.
func parseRemovals(ies []*ie.IE) ([]uint16, []uint32) {
	var pdrs []uint16
	var fars []uint32
	for _, i := range ies {
		switch i.Type {
		case ie.RemovePDR:
			children, err := i.RemovePDR()
			if err != nil {
				continue
			}
			for _, c := range children {
				if c.Type != ie.PDRID {
					continue
				}
				if id, err := c.PDRID(); err == nil {
					pdrs = append(pdrs, id)
				}
			}
		case ie.RemoveFAR:
			children, err := i.RemoveFAR()
			if err != nil {
				continue
			}
			for _, c := range children {
				if c.Type != ie.FARID {
					continue
				}
				if id, err := c.FARID(); err == nil {
					fars = append(fars, id)
				}
			}
		}
	}
	return pdrs, fars
}

func parsePDR(i *ie.IE) (pdrReq, error) {
	children, err := i.CreatePDR()
	what := "Create PDR"
	if i.Type == ie.UpdatePDR {
		children, err = i.UpdatePDR()
		what = "Update PDR"
	}
	if err != nil {
		return pdrReq{}, fmt.Errorf("%s: %w", what, err)
	}
	p := pdrReq{}
	for _, c := range children {
		switch c.Type {
		case ie.PDRID:
			if id, err := c.PDRID(); err == nil {
				p.id = id
			}
		case ie.Precedence:
			if v, err := c.Precedence(); err == nil {
				p.precedence = v
			}
		case ie.FARID:
			if id, err := c.FARID(); err == nil {
				p.farID = id
			}
		case ie.QERID:
			if id, err := c.QERID(); err == nil {
				p.qerIDs = append(p.qerIDs, id)
			}
		case ie.PDI:
			pdiChildren, err := c.PDI()
			if err != nil {
				return pdrReq{}, fmt.Errorf("PDI: %w", err)
			}
			if err := parsePDI(&p, pdiChildren); err != nil {
				return pdrReq{}, err
			}
		}
	}
	if p.id == 0 {
		return pdrReq{}, errors.New("PDR without a PDR ID")
	}
	return p, nil
}

func parsePDI(p *pdrReq, children []*ie.IE) error {
	for _, c := range children {
		switch c.Type {
		case ie.SourceInterface:
			if v, err := c.SourceInterface(); err == nil {
				p.srcIfc = v
			}
		case ie.FTEID:
			fields, err := c.FTEID()
			if err != nil {
				return fmt.Errorf("F-TEID: %w", err)
			}
			p.hasFTEID = true
			p.teid = fields.TEID
		case ie.UEIPAddress:
			fields, err := c.UEIPAddress()
			if err != nil {
				return fmt.Errorf("UE IP address: %w", err)
			}
			switch {
			case fields.IPv4Address != nil:
				if a, ok := netip.AddrFromSlice(fields.IPv4Address); ok {
					p.ueIP, p.hasUEIP = a.Unmap(), true
				}
			case fields.IPv6Address != nil:
				// The tables' address fields are four bytes: an IPv6 UE address
				// has no form here, and reading the IE as "no address" would
				// compile a rule that matches every session's packets.
				return fmt.Errorf("%w: the UE IP address is IPv6", errNotExpressible)
			}
		case ie.SDFFilter:
			fields, err := c.SDFFilter()
			if err != nil {
				return fmt.Errorf("SDF filter: %w", err)
			}
			filter, err := parseFlowDescription(fields.FlowDescription, p.ueIP)
			if err != nil {
				return fmt.Errorf("SDF filter: %w", err)
			}
			p.sdf = filter
		}
	}
	return nil
}

func parseFAR(i *ie.IE) (farReq, error) {
	children, err := i.CreateFAR()
	what := "Create FAR"
	if i.Type == ie.UpdateFAR {
		children, err = i.UpdateFAR()
		what = "Update FAR"
	}
	if err != nil {
		return farReq{}, fmt.Errorf("%s: %w", what, err)
	}
	f := farReq{}
	for _, c := range children {
		switch c.Type {
		case ie.FARID:
			if id, err := c.FARID(); err == nil {
				f.id = id
			}
		case ie.ApplyAction:
			flags, err := c.ApplyAction()
			if err != nil {
				return farReq{}, fmt.Errorf("Apply Action: %w", err)
			}
			if len(flags) > 0 {
				f.apply = flags[0]
			}
		case ie.ForwardingParameters:
			fwd, err := c.ForwardingParameters()
			if err != nil {
				return farReq{}, fmt.Errorf("Forwarding Parameters: %w", err)
			}
			for _, fp := range fwd {
				switch fp.Type {
				case ie.DestinationInterface:
					if v, err := fp.DestinationInterface(); err == nil {
						f.destIfc = v
					}
				case ie.OuterHeaderCreation:
					fields, err := fp.OuterHeaderCreation()
					if err != nil {
						return farReq{}, fmt.Errorf("Outer Header Creation: %w", err)
					}
					if fields.TEID == 0 {
						return farReq{}, errors.New(
							"Outer Header Creation without a TEID")
					}
					peer, ok := netip.AddrFromSlice(fields.IPv4Address)
					if !ok {
						return farReq{}, errors.New(
							"Outer Header Creation without an IPv4 address")
					}
					f.hasOuter, f.teid, f.peer = true, fields.TEID, peer.Unmap()
				}
			}
		}
	}
	if f.id == 0 {
		return farReq{}, errors.New("FAR without a FAR ID")
	}
	return f, nil
}

func parseQER(i *ie.IE) (qerReq, error) {
	children, err := i.CreateQER()
	what := "Create QER"
	if i.Type == ie.UpdateQER {
		children, err = i.UpdateQER()
		what = "Update QER"
	}
	if err != nil {
		return qerReq{}, fmt.Errorf("%s: %w", what, err)
	}
	q := qerReq{gateUL: ie.GateStatusOpen, gateDL: ie.GateStatusOpen}
	for _, c := range children {
		switch c.Type {
		case ie.QERID:
			if id, err := c.QERID(); err == nil {
				q.id = id
			}
		case ie.GateStatus:
			if ul, err := c.GateStatusUL(); err == nil {
				q.gateUL = ul
			}
			if dl, err := c.GateStatusDL(); err == nil {
				q.gateDL = dl
			}
		case ie.MBR:
			payload, err := c.MBR()
			if err != nil || len(payload) < 10 {
				return qerReq{}, errors.New("MBR: malformed")
			}
			q.mbUL = uint40(payload[0:5])
			q.mbDL = uint40(payload[5:10])
			q.hasRate = true
		}
	}
	if q.id == 0 {
		return qerReq{}, errors.New("QER without a QER ID")
	}
	return q, nil
}

// meterChange is the resource for one policed direction: a two-rate three-colour
// meter at `rate` bytes per second, with a tenth of a second of burst.
func meterChange(resource string, id uint32, rate uint64) bess.Change {
	burst := rate / 10
	return bess.Change{
		Resource: resource,
		Key:      map[string]any{"id": id},
		Value: map[string]any{
			"tr_tcm": map[string]any{
				"committed_rate":  rate,
				"committed_burst": burst,
				"peak_rate":       rate,
				"peak_burst":      burst,
			},
		},
	}
}

// uint40 reads the 5-octet, octet-aligned integer the MBR IE carries. Its unit
// is kb/s (TS 29.244 8.2.8); the meter's rates are bytes per second.
func uint40(b []byte) uint64 {
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v * 1000 / 8
}

// ----------------------------------------------------------------------------

// sdfFilter is a parsed IPFilterRule: what the PDR's rule must match, and what
// it leaves to the PDI's own fields.
type sdfFilter struct {
	proto   uint8
	protoOK bool
	src     netip.Prefix
	srcOK   bool
	dst     netip.Prefix
	dstOK   bool
	sport   uint16
	sportOK bool
	dport   uint16
	dportOK bool
}

// parseFlowDescription reads the IPFilterRule form the SDF Filter IE carries
// (TS 29.244 8.2.5): "permit <dir> <proto> from <src> [<port>] to <dst>
// [<port>]". "assigned" is the PDI's UE address, "any" leaves the field
// unconstrained.
//
// A range that is not one value cannot be expressed by a mask, so it is
// refused here rather than silently matched too widely: the dataplane needs the
// range kernel of the roadmap's classifier work for that.
func parseFlowDescription(fd string, ue netip.Addr) (*sdfFilter, error) {
	fields := strings.Fields(fd)
	if len(fields) < 4 {
		return nil, fmt.Errorf("flow description %q is too short", fd)
	}
	if fields[0] != "permit" {
		return nil, fmt.Errorf("flow description %q: only 'permit' rules can be a PDR", fd)
	}
	// permit [in|out] <proto> from <src> [port] to <dst> [port]
	i := 1
	if fields[i] == "in" || fields[i] == "out" {
		i++
	}
	if len(fields) < i+4 {
		return nil, fmt.Errorf("flow description %q is too short", fd)
	}

	f := &sdfFilter{}
	switch strings.ToLower(fields[i]) {
	case "ip", "any":
		// nothing to constrain
	case "tcp":
		f.proto, f.protoOK = 6, true
	case "udp":
		f.proto, f.protoOK = 17, true
	case "icmp":
		f.proto, f.protoOK = 1, true
	default:
		n, err := strconv.ParseUint(fields[i], 10, 8)
		if err != nil {
			return nil, fmt.Errorf("flow description %q: unknown protocol %q", fd, fields[i])
		}
		f.proto, f.protoOK = uint8(n), true
	}
	i++
	if fields[i] != "from" {
		return nil, fmt.Errorf("flow description %q: expected 'from'", fd)
	}
	i++
	addr, next, err := parseFilterAddr(fields[i], ue)
	if err != nil {
		return nil, fmt.Errorf("flow description %q: %w", fd, err)
	}
	f.src, f.srcOK = addr, addr.IsValid()
	i += next
	if i < len(fields) && fields[i] != "to" {
		port, err := parseFilterPort(fields[i])
		if err != nil {
			return nil, fmt.Errorf("flow description %q: %w", fd, err)
		}
		f.sport, f.sportOK = port, true
		i++
	}
	if i >= len(fields) || fields[i] != "to" {
		return nil, fmt.Errorf("flow description %q: expected 'to'", fd)
	}
	i++
	if i >= len(fields) {
		return nil, fmt.Errorf("flow description %q: no destination", fd)
	}
	addr, next, err = parseFilterAddr(fields[i], ue)
	if err != nil {
		return nil, fmt.Errorf("flow description %q: %w", fd, err)
	}
	f.dst, f.dstOK = addr, addr.IsValid()
	i += next
	if i < len(fields) {
		port, err := parseFilterPort(fields[i])
		if err != nil {
			return nil, fmt.Errorf("flow description %q: %w", fd, err)
		}
		f.dport, f.dportOK = port, true
		i++
	}
	if i != len(fields) {
		return nil, fmt.Errorf("flow description %q: trailing %q", fd, strings.Join(fields[i:], " "))
	}
	return f, nil
}

// parseFilterAddr reads one address of a flow description: "any", "assigned",
// an address, or a prefix. It returns the prefix (invalid for "any", which is
// how the caller knows the field is unconstrained) and how many words of the
// description it read.
func parseFilterAddr(word string, ue netip.Addr) (netip.Prefix, int, error) {
	switch strings.ToLower(word) {
	case "any":
		return netip.Prefix{}, 1, nil
	case "assigned":
		if !ue.Is4() {
			return netip.Prefix{}, 0, errors.New(
				"'assigned' with no UE address in the PDI")
		}
		return netip.PrefixFrom(ue, 32), 1, nil
	}
	if strings.Contains(word, "/") {
		p, err := netip.ParsePrefix(word)
		if err != nil {
			return netip.Prefix{}, 0, fmt.Errorf("invalid address %q", word)
		}
		// A Flow Description is address/mask (TS 29.244 8.2.2, by way of TS
		// 29.212 5.4.2): host bits in the address are not a different filter,
		// they are bits the mask ignores. The rule the table gets carries the
		// network address and the mask (compile.go, pref).
		return p, 1, nil
	}
	a, err := netip.ParseAddr(word)
	if err != nil {
		return netip.Prefix{}, 0, fmt.Errorf("invalid address %q", word)
	}
	return netip.PrefixFrom(a.Unmap(), a.BitLen()), 1, nil
}

// parseFilterPort reads one port of a flow description: a number, or a range
// that collapses to one.
func parseFilterPort(word string) (uint16, error) {
	if lo, hi, ok := strings.Cut(word, "-"); ok {
		a, err := strconv.ParseUint(lo, 10, 16)
		if err != nil {
			return 0, fmt.Errorf("invalid port %q", word)
		}
		b, err := strconv.ParseUint(hi, 10, 16)
		if err != nil {
			return 0, fmt.Errorf("invalid port %q", word)
		}
		if a != b {
			return 0, fmt.Errorf("%w: port range %q", errNotExpressible, word)
		}
		return uint16(a), nil
	}
	v, err := strconv.ParseUint(word, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", word)
	}
	return uint16(v), nil
}

// -- answers ------------------------------------------------------------------

func establishResponse(req *message.SessionEstablishmentRequest, seid uint64,
	cause uint8, created []*ie.IE) message.Message {
	ies := []*ie.IE{ie.NewCause(cause)}
	if cause == ie.CauseRequestAccepted {
		ies = append(ies, ie.NewFSEID(seid, nil, nil))
		ies = append(ies, created...)
	}
	return message.NewSessionEstablishmentResponse(0, 0, seid, req.Sequence(), 0, ies...)
}

func modifyResponse(req *message.SessionModificationRequest, seid uint64,
	cause uint8, created []*ie.IE) message.Message {
	ies := []*ie.IE{ie.NewCause(cause)}
	if cause == ie.CauseRequestAccepted {
		ies = append(ies, created...)
	}
	return message.NewSessionModificationResponse(0, 0, seid, req.Sequence(), 0, ies...)
}

func deleteResponse(req *message.SessionDeletionRequest, seid uint64, cause uint8) message.Message {
	return message.NewSessionDeletionResponse(0, 0, seid, req.Sequence(), 0,
		ie.NewCause(cause))
}

// parseCause maps a request-reading failure to the cause the SMF sees: a
// well-formed rule the dataplane cannot carry is a rule failure (what a
// retransmission of it would hit again), while an unreadable message is a
// rejection.
func parseCause(err error) uint8 {
	if errors.Is(err, errNotExpressible) {
		return ie.CauseRuleCreationModificationFailure
	}
	return ie.CauseRequestRejected
}

// compileCause maps a compile failure to the cause the SMF sees. A rule the
// mask cannot express is a rule failure; a resource the UPF has none of is
// cause 75 ("no resources available"), which is what an SMF retries or
// reconciles against.
func compileCause(err error) uint8 {
	if errors.Is(err, errNoResources) {
		return ie.CauseNoResourcesAvailable
	}
	return ie.CauseRuleCreationModificationFailure
}

// causeOf maps a failed transaction to the cause the SMF sees. The SDK's
// errors say *what* failed, and a refusal must not look like a success: the
// dataplane is all-or-nothing, so nothing of the session is in place when one
// of these returns.
func causeOf(err error) uint8 {
	switch {
	case definiteRefusal(err):
		return ie.CauseRuleCreationModificationFailure
	default:
		// A conflict, a busy dataplane, a restarted daemon or an unanswered
		// request: the SMF retries, and the retry finds the state this attempt
		// did or did not leave (a repeated establishment is answered with what
		// is in place).
		return ie.CauseRequestRejected
	}
}

// definiteRefusal reports whether the SDK's error says the daemon refused the
// transaction outright. The alternative is an outcome that is unknown (no
// answer, a transport error): the transaction may have committed, so a caller
// must not treat the session's ids or records as its own to undo.
func definiteRefusal(err error) bool {
	var invalid *bess.InvalidRequestError
	var rejected *bess.RejectedError
	return errors.As(err, &invalid) || errors.As(err, &rejected)
}

// createdFTEID is the F-TEID of a Created PDR: our own TEID and the N3
// address, with the flags telling the SMF which address family the field
// carries (an F-TEID's IPv4 flag is bit 1; the zero flags of a field built by
// hand would drop the address).
func createdFTEID(teid uint32, addr netip.Addr) *ie.IE {
	ip := net.IP(nil)
	if addr.Is4() {
		b := addr.As4()
		ip = b[:]
	}
	fields := ie.NewFTEIDFields(0, teid, ip, nil, 0)
	if ip != nil {
		fields.SetIPv4Flag()
	}
	return ie.NewFTEID(fields.Flags, teid, ip, nil, 0)
}
