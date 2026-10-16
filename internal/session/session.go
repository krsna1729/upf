// SPDX-License-Identifier: BSD-3-Clause

// Package session compiles PFCP sessions into BESS state (docs/design.md):
// a session change becomes one control_v2 transaction, all or nothing, and the
// packet path never chases a control-plane relation.
//
// The compiler resolves a PDR's relations once, at programming time:
//
//	PDR     -> one rule in the graph's PDR table, whose {gate, action_id} the
//	           packet path returns in one lookup
//	FAR     -> a next hop (forwarding) or a drop; the downlink one also a
//	           tunnel record, keyed by the same ActionId
//	QER     -> a meter record per direction, referenced by the action
//	F-TEID  -> an entry in the decap's session table, so only TEIDs this UPF
//	           advertised are accepted
//
// State here is a cache of what the SMF asked for, not a source of truth: a
// restarted controller rebuilds it from the PFCP messages the SMF replays
// (docs/design.md, "Restart and failure semantics").
package session

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sync"

	"github.com/krsna1729/upf/internal/bess"
)

// Applier writes a session's changes to the dataplane, all or nothing.
// *bess.Client implements it; a test substitutes a recorder.
type Applier interface {
	Apply(ctx context.Context, changes ...bess.Change) error
}

// Field is one entry of the PDR table's key, in the order the deployed graph
// declared it. The compiler sets a mask per field: a rule matches what its PDI
// names and masks the rest out, so one table holds every PDR shape.
type Field uint8

const (
	SrcIP Field = iota
	DstIP
	Proto
	SrcPort
	DstPort
)

// width is the field's width in bytes, as the packet carries it.
func (f Field) width() int {
	switch f {
	case SrcIP, DstIP:
		return 4
	case Proto:
		return 1
	case SrcPort, DstPort:
		return 2
	default:
		return 0
	}
}

// Direction is one half of the deployed graph: where a PDR of this direction
// sends its matches, and what a forward means there.
//
// The two directions are two chains of modules, because a BESS module has one
// output gate per path: the uplink's Meter feeds the Router that leaves toward
// N6, the downlink's feeds the GtpuEncap that leaves toward N3. The PDR table
// is shared; the rule's own gate picks the chain (docs/design.md).
type Direction struct {
	// PDRTable is the WildcardMatch module holding this direction's PDR rules
	// ("pdr_ul", "pdr_dl"). One table per direction, because the rule names an
	// ActionId and a table declares one actions resource: the classifier's
	// reference check (D-141) is then exact for every rule.
	PDRTable string
	// PDRFields is that table's key, in the graph's order.
	PDRFields []Field
	// Actions is the ActionTable module the direction's action records live
	// in ("at_ul", "at_dl").
	Actions string
	// Meters is the Meter module its QER meters live in.
	Meters string
	// NextHop is the Router next hop a forward leaves by (uplink); 0 for a
	// direction that ends in a tunnel (downlink).
	NextHop uint32
	// Tunnels is the GtpuEncap module whose per-session records the direction
	// writes (downlink only; empty for the uplink).
	Tunnels string
}

// Config is the deployed graph's shape and the constants a session's resources
// point at.
type Config struct {
	// TEIDTable is the WildcardMatch module whose rules are the F-TEID match
	// ("teid"): one rule per session, holding the TEID at the offset the
	// module's own argument gives it (Eth 14 + IPv4 20 + UDP 8 + the GTP-U
	// header's flags, type and length 4). The decap behind it decapsulates
	// only what reaches it; the graph sets the offset, so this compiler needs
	// the table's name alone (deploy/smoke-gtpu.yaml, docs/design.md).
	TEIDTable string
	// TEIDGate is the gate a TEID rule delivers on: the decap's output gate.
	TEIDGate uint32

	// Up and Down are the two chains.
	Up, Down Direction

	// N3Addr is the UPF's N3 IPv4 address: the F-TEID we advertise, and the
	// outer source of a downlink packet.
	N3Addr netip.Addr
	// The Ethernet addresses of the N3 hop (the graph's port and its peer).
	N3MAC, PeerMAC [6]byte

	// MaxActions, MaxMeters and MaxTEIDs bound the id spaces: the dataplane's
	// tables are sized at construction.
	MaxActions uint32
	MaxMeters  uint32
	MaxTEIDs   uint32
}

// direction of a PDR: the uplink chain for a packet the UE sends, the downlink
// chain for one it receives.
func (c *Compiler) direction(srcIfc uint8) Direction {
	if srcIfc == 1 { // SrcInterfaceCore: from the network, toward the UE
		return c.cfg.Down
	}
	return c.cfg.Up
}

func (c Config) withDefaults() Config {
	if c.MaxActions == 0 {
		c.MaxActions = 1 << 16
	}
	if c.MaxMeters == 0 {
		c.MaxMeters = 1 << 16
	}
	if c.MaxTEIDs == 0 {
		c.MaxTEIDs = 1 << 16
	}
	for _, d := range []*Direction{&c.Up, &c.Down} {
		if len(d.PDRFields) == 0 {
			d.PDRFields = []Field{SrcIP, DstIP, Proto, SrcPort, DstPort}
		}
	}
	return c
}

// Compiler turns PFCP sessions into BESS state. It implements the N4 server's
// session handler (internal/n4.SessionHandler).
type Compiler struct {
	cfg Config
	ap  Applier
	log *slog.Logger

	mu       sync.Mutex
	sessions map[uint64]*Session // by local SEID
	byTEID   map[uint32]*Session // by the N3 TEID we advertised
	nextSEID uint64
	actions  *idPool
	meters   *idPool
	teids    *idPool
}

// New returns a compiler writing through ap.
func New(cfg Config, ap Applier, log *slog.Logger) *Compiler {
	if log == nil {
		log = slog.Default()
	}
	cfg = cfg.withDefaults()
	return &Compiler{
		cfg:      cfg,
		ap:       ap,
		log:      log,
		sessions: map[uint64]*Session{},
		byTEID:   map[uint32]*Session{},
		nextSEID: 1,
		actions:  newIDPool(cfg.MaxActions),
		meters:   newIDPool(cfg.MaxMeters),
		teids:    newIDPool(cfg.MaxTEIDs),
	}
}

// findByCP is the session the SMF's F-SEID names; the caller holds the lock.
func (c *Compiler) findByCP(cpSEID uint64) *Session {
	for _, s := range c.sessions {
		if s.CPSEID == cpSEID {
			return s
		}
	}
	return nil
}

// Session is what the SMF asked for, as compiled.
type Session struct {
	LocalSEID uint64
	CPSEID    uint64 // the CP function's F-SEID, for events and reports
	UEIP      netip.Addr

	PDRs map[uint16]*pdr
	FARs map[uint32]*far
	QERs map[uint32]*qer
	URRs map[uint32]*urr
}

// pdr is one compiled PDR: its rule in the PDR table and what it resolved to.
type pdr struct {
	id         uint16
	precedence uint32
	srcIfc     uint8
	ueIP       netip.Addr
	sdf        *sdfFilter
	farID      uint32
	qerIDs     []uint32

	teid     uint32   // uplink: the TEID we advertised (0 when not ours)
	actionID uint32   // the action record this PDR's rule names
	meterID  uint32   // the meter record a QER resolved to, in this chain's Meter
	tunnels  []string // per-session tunnel records to write (downlink)
	drop     bool     // the FAR drops, or the QER's gate is closed this way
}

// far is one compiled FAR.
type far struct {
	id       uint32
	apply    uint8
	destIfc  uint8
	teid     uint32
	peer     netip.Addr
	hasOuter bool
}

type qer struct {
	id      uint32
	gateUL  uint8
	gateDL  uint8
	mbUL    uint64 // bytes per second, as the dataplane's meter wants it
	mbDL    uint64
	hasRate bool

	// One meter record per policed direction, allocated with the session and
	// released with it. Each lives in that direction's chain.
	meterUL uint32
	meterDL uint32
}

type urr struct {
	id uint32
}

// AssociationEnded implements n4.SessionHandler: no session of the association
// is valid any more, so the dataplane's session state goes with it.
func (c *Compiler) AssociationEnded(reason string) {
	c.mu.Lock()
	sessions := make([]*Session, 0, len(c.sessions))
	for _, s := range c.sessions {
		sessions = append(sessions, s)
	}
	c.mu.Unlock()

	for _, s := range sessions {
		if err := c.remove(context.Background(), s); err != nil {
			c.log.Warn("session: dropping a session after the association ended",
				"seid", s.LocalSEID, "reason", reason, "error", err)
			continue
		}
		c.log.Info("session: removed after the association ended",
			"seid", s.LocalSEID, "reason", reason)
	}
}

// idPool hands out small ids and takes them back, so a long-lived UPF reuses
// the space the dataplane's fixed-size tables have.
type idPool struct {
	limit uint32
	next  uint32
	free  []uint32
}

func newIDPool(limit uint32) *idPool { return &idPool{limit: limit, next: 1} }

func (p *idPool) alloc() (uint32, error) {
	if n := len(p.free); n != 0 {
		id := p.free[n-1]
		p.free = p.free[:n-1]
		return id, nil
	}
	if p.next >= p.limit {
		return 0, errors.New("id space exhausted")
	}
	id := p.next
	p.next++
	return id, nil
}

func (p *idPool) release(id uint32) {
	if id == 0 {
		return
	}
	p.free = append(p.free, id)
}

// resource names, as the deployed graph spells them.
func rulesRes(d Direction) string   { return d.PDRTable + "/rules" }
func (c *Compiler) teidRes() string { return c.cfg.TEIDTable + "/rules" }
func actionsRes(d Direction) string { return d.Actions + "/actions" }
func metersRes(d Direction) string  { return d.Meters + "/meters" }
func tunnelsRes(d Direction) string { return d.Tunnels + "/tunnels" }

// teidRuleKey is the key of a session's TEID rule: the four bytes of the TEID,
// masked all ones. One field, so the table's field order is its argument's.
func teidRuleKey(teid uint32) map[string]any {
	value := []byte{byte(teid >> 24), byte(teid >> 16), byte(teid >> 8), byte(teid)}
	mask := []byte{0xff, 0xff, 0xff, 0xff}
	return map[string]any{
		"values": []map[string]any{{"value_bin": value}},
		"masks":  []map[string]any{{"value_bin": mask}},
	}
}

// remove takes a session's state out of the dataplane and frees its ids. The
// order is the reverse of installation: the rule that can select an action
// goes before the action and the tunnel it names, so a worker never reads a
// record whose resources are gone (the engine's own reference checks are the
// backstop, docs/design.md).
func (c *Compiler) remove(ctx context.Context, s *Session) error {
	changes := make([]bess.Change, 0, 4*len(s.PDRs)+2)
	for _, p := range pdrsInOrder(s) {
		changes = append(changes, bess.Change{
			Resource: rulesRes(c.direction(p.srcIfc)),
			Key:      p.ruleKey(c.direction(p.srcIfc).PDRFields)})
	}
	for _, p := range pdrsInOrder(s) {
		dir := c.direction(p.srcIfc)
		if p.actionID != 0 {
			changes = append(changes,
				bess.Change{Resource: actionsRes(dir), Key: map[string]any{"id": p.actionID}})
		}
		if p.meterID != 0 {
			changes = append(changes,
				bess.Change{Resource: metersRes(dir), Key: map[string]any{"id": p.meterID}})
		}
		for _, t := range p.tunnels {
			changes = append(changes, bess.Change{Resource: t, Key: map[string]any{"action_id": p.actionID}})
		}
		if p.teid != 0 {
			changes = append(changes, bess.Change{Resource: c.teidRes(),
				Key: teidRuleKey(p.teid)})
		}
	}
	if len(changes) != 0 {
		if err := c.ap.Apply(ctx, changes...); err != nil {
			return err
		}
	}

	c.mu.Lock()
	delete(c.sessions, s.LocalSEID)
	for _, p := range pdrsInOrder(s) {
		if p.teid != 0 {
			delete(c.byTEID, p.teid)
			c.teids.release(p.teid)
		}
		if p.actionID != 0 {
			c.actions.release(p.actionID)
		}
		c.meters.release(p.meterID)
	}
	c.mu.Unlock()
	return nil
}
