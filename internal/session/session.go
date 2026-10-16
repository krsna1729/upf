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
//	F-TEID  -> a rule in the graph's TEID table, so only TEIDs this UPF
//	           advertised are accepted
//
// State here is a cache of what the SMF asked for, not a source of truth --
// and only for as long as the process lives: a restarted controller has no
// PFCP state (SEIDs, session identity, URR configuration) to rebuild from
// yet, which is docs/design.md's restart wall.
package session

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/netip"
	"strconv"
	"sync"
	"time"

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

// String is the field's name as the graph's manifest spells the offset: a cause
// and a log line that name the field are what an SMF's operator works from.
func (f Field) String() string {
	switch f {
	case SrcIP:
		return "source address"
	case DstIP:
		return "destination address"
	case Proto:
		return "protocol"
	case SrcPort:
		return "source port"
	case DstPort:
		return "destination port"
	default:
		return "field " + strconv.Itoa(int(f))
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
	// NextHop is the Router next hop a forward leaves by, for either
	// direction: the uplink's is the N6 route, the downlink's the N3 one.
	// Every chain that holds an ActionTable must route on the id it writes --
	// the module fails closed (drops every packet) when the attribute has no
	// reader, and a Router drops an id it does not know -- so 0 here is only
	// correct for a graph whose chain has no ActionTable at all.
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

	// IDReuseDelay is how long a released id waits before the pool may hand it
	// out again. A transaction that removes a record leaves its slot retiring
	// for a grace period (core/dataplane/slot_table.h), and creating a record
	// at an id that is still retiring is refused -- so a session established
	// right after another one was deleted must not be given its ids back. The
	// engine's retirement is asynchronous, so this is a generous margin rather
	// than a synchronisation; the pool hands out fresh ids while it has them.
	IDReuseDelay time.Duration
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
	if c.IDReuseDelay == 0 {
		// A second is orders of magnitude more than the cascade of grace
		// periods a removal needs; it costs nothing while the pool has fresh
		// ids to hand out.
		c.IDReuseDelay = time.Second
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
		actions:  newIDPool(cfg.MaxActions, cfg.IDReuseDelay),
		meters:   newIDPool(cfg.MaxMeters, cfg.IDReuseDelay),
		teids:    newIDPool(cfg.MaxTEIDs, 0),
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
//
// The walk is spread, not in order: the pool starts at a random point and steps
// by a random stride, so it visits the whole space once. Two reasons, both
// about the dataplane's slots. A transaction that removes a record leaves its
// slot retiring for a grace period and refuses a publish into it
// (core/dataplane/slot_table.h: CanPublish), and the engine's cascade of those
// periods is asynchronous: a compiler that reissued the ids it had just
// released got "the meter is still retiring (removed less than a grace period
// ago)", and the session established right after a deletion was refused. And a
// *new* compiler -- after a controller restart, replaying what the SMF sends
// again -- knows nothing of what the daemon still holds retiring, so it must
// not walk its predecessor's order either. A released id is reused only after
// the walk has come round (and then only once it has aged), which is far longer
// than any grace period.
type idPool struct {
	limit  uint32
	start  uint32 // where the walk began, and so where it is done
	next   uint32
	stride uint32
	walked bool // the walk has visited every id once
	grace  time.Duration
	now    func() time.Time
	freed  []freedID
	// taken holds ids the pool must not hand out even though its own books say
	// nothing about them: an F-TEID an SMF pinned, which another session is
	// using right now. Pool-owned ids need no entry (the walk visits each once,
	// and a released one is aged before it is visited again).
	taken map[uint32]bool
	// released is the ids waiting in freed: a session releases an id once per
	// PDR that names it, and the pool must not queue it twice.
	released map[uint32]bool
}

type freedID struct {
	id uint32
	at time.Time
}

// newIDPool returns a pool of ids 1..limit-1 (the dataplane's slots are
// numbered from 1). The starting point and the stride are random; the stride is
// coprime with the space, so the walk visits every id.
func newIDPool(limit uint32, grace time.Duration) *idPool {
	p := &idPool{limit: limit, grace: grace, now: time.Now,
		taken: map[uint32]bool{}, released: map[uint32]bool{}}
	if limit < 2 {
		// No usable id at all (the slots are numbered from 1): the walk is
		// over before it starts, so alloc goes straight to the empty free list
		// and answers no-resources. A misconfigured -capacity must not panic in
		// the walk's arithmetic (limit 0 would underflow span).
		p.walked = true
		return p
	}
	span := limit - 1
	p.start = 1 + rand.Uint32N(span)
	p.next = p.start
	for {
		p.stride = 1 + rand.Uint32N(span)
		if gcd(p.stride, span) == 1 {
			return p
		}
	}
}

func gcd(a, b uint32) uint32 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// advance is one step of the walk: ids stay in 1..limit-1.
func (p *idPool) advance(id uint32) uint32 {
	span := p.limit - 1
	if span < 1 {
		span = 1 // a pool with no ids: the walk is one step long
	}
	return 1 + (id-1+p.stride)%span
}

func (p *idPool) alloc() (uint32, error) {
	// One walk of the space: an id released behind the walk waits for the
	// round trip, which is what keeps it out of circulation past the grace.
	// An id another session pinned is skipped wherever the walk meets it.
	for !p.walked {
		id := p.next
		p.next = p.advance(p.next)
		if p.next == p.start {
			p.walked = true
		}
		if !p.taken[id] {
			return id, nil
		}
	}
	// The walk is done: a released id, if one has aged.
	for n := len(p.freed); n != 0; n = len(p.freed) {
		oldest := p.freed[0]
		if p.now().Sub(oldest.at) < p.grace {
			break
		}
		p.freed = p.freed[1:]
		delete(p.released, oldest.id)
		if !p.taken[oldest.id] {
			return oldest.id, nil
		}
	}
	return 0, errors.New("id space exhausted")
}

// reserve keeps an id the pool did not hand out out of the walk: an F-TEID an
// SMF pinned. It is not released: the pool never owned it, and freeing a
// foreign value would hand it to a session that did not ask for it (0x11223344
// is a legal pin and an illegal allocation).
func (p *idPool) reserve(id uint32) {
	if id == 0 {
		return
	}
	p.taken[id] = true
}

// release takes back an id the pool handed out. A reserved one is ignored --
// delete on a session whose SMF pinned the F-TEID must not feed that value into
// the free list -- and so is one already waiting in the free list: a session
// says its ids once per PDR, so the same meter arrives several times when its
// QER is shared, and two entries would later be handed to two sessions. A zero
// grace means the id may be reused as soon as the walk is over (for a space
// whose resource has no retire period: the TEID table's rules are keyed, not
// slotted).
func (p *idPool) release(id uint32) {
	if id == 0 || p.taken[id] || p.released[id] {
		return
	}
	p.released[id] = true
	p.freed = append(p.freed, freedID{id: id, at: p.now()})
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
		dir := c.direction(p.srcIfc)
		key, err := p.ruleKey(dir.PDRFields)
		if err != nil {
			// The session's rules were written with these keys, so this is a
			// PDI that changed under a live session: fail the deletion rather
			// than leave the rule behind.
			return fmt.Errorf("PDR %d: %w", p.id, err)
		}
		changes = append(changes, bess.Change{Resource: rulesRes(dir), Key: key})
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
	c.releaseSession(s)
	c.mu.Unlock()
	return nil
}

// releaseSession frees the ids a session's records hold, each exactly once: one
// F-TEID, and one QER's meter, usually appear in several of a session's PDRs,
// and freeing an id twice would queue it in the free list twice and hand it to
// two sessions. The caller holds the lock. A reserved id (an F-TEID the SMF
// pinned) is not freed: the pool never handed it out.
func (c *Compiler) releaseSession(s *Session) {
	for _, p := range pdrsInOrder(s) {
		if p.teid != 0 {
			// Only if this session is what the mapping names. Between a
			// refused merge and this release (a separate lock), the holder can
			// delete -- freeing the name -- and another session can pin the
			// same value and take it: erasing that mapping would let a third
			// session take the TEID and overwrite the new holder's rule.
			if c.byTEID[p.teid] == s {
				delete(c.byTEID, p.teid)
			}
			c.teids.release(p.teid)
		}
		if p.actionID != 0 {
			c.actions.release(p.actionID)
		}
		if p.meterID != 0 {
			c.meters.release(p.meterID)
		}
	}
}
