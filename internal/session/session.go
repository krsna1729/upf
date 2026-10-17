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
// and only for as long as the process lives, unless the run was given a
// checkpoint (journal.go): the journal holds the applied session messages and
// the Recovery Time Stamp, so a restart that restores it advertises that stamp
// and keeps the sessions the SMF believes in (docs/design.md's restart wall).
package session

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/bess"
	"github.com/krsna1729/upf/internal/routing"
)

// Applier writes a session's changes to the dataplane, all or nothing.
// *bess.Client implements it; a test substitutes a recorder.
type Applier interface {
	Apply(ctx context.Context, changes ...bess.Change) error
}

// CounterReader is the half of a dataplane a URR's measurement needs: the
// counting module's own reading of the rules named, by ActionId (report.go).
// It is a capability of its own rather than another method of Applier because a
// dataplane without counters (a graph that charges nothing, or a stand-in in a
// test) is a plain fact about that graph, and only a session that has a URR
// ever asks.
type CounterReader interface {
	RuleCounts(ctx context.Context, module string, actionIDs ...uint32) ([]bess.RuleCount, error)
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
	// RouteDomain is not in the packet: it is the metadata attribute the
	// deployment's interface writes for the interface a packet arrived on
	// (BESS's `route_domain`). It is what keeps two network instances'
	// overlapping prefixes apart -- the same filter in two instances is two
	// rules, because their domains differ (internal/routing).
	RouteDomain
	// UpfTEID is the decap's own metadata attribute: the tunnel a decapsulated
	// packet arrived on. A graph declares it in the uplink table when two
	// sessions may serve one UE address -- two network instances -- because the
	// tunnel, not the address, is what tells those packets apart then.
	UpfTEID
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
	case RouteDomain, UpfTEID:
		// Both are four-byte metadata attributes, as the graph declares them.
		return 4
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
	case RouteDomain:
		return "route domain"
	case UpfTEID:
		return "tunnel endpoint"
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
	// Counters is the UrrCount module this direction's per-rule counters live
	// in ("cnt_ul", "cnt_dl"; empty for a graph with no usage reporting). A
	// session's PDRs that a URR measures get one entry there, keyed by the
	// ActionId the rule names, and the module counts what the chain forwards.
	Counters string
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

	// Instances is the deployment's network instances (internal/routing): the
	// names a PDI's Network Instance (TS 29.244 8.2.4) may use, the route
	// domain each is classified in, the addresses each serves, and the next
	// hop a forward out of it takes. Nil is the one-instance deployment: no
	// PDI's instance is resolved, every rule is domain 0, and each direction's
	// next hop is the deployment's own (the -n6-next-hop and -n3-next-hop
	// flags), which is what the rows in docs/compliance.md describe until a
	// deployment configures more than one.
	Instances *routing.Domains

	// N3Addr is the UPF's N3 IPv4 address: the F-TEID we advertise, and the
	// outer source of a downlink packet.
	N3Addr netip.Addr
	// The Ethernet addresses of the N3 hop (the graph's port and its peer).
	N3MAC, PeerMAC [6]byte

	// EndMarker is the graph's unix_port socket path: where an End Marker
	// packet is written when a modification's SNDEM flag moves a tunnel out
	// from under a session (TS 29.244 5.3.2). Empty means this UPF constructs
	// none, and the association response advertises no EMPU for it.
	EndMarker string

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
	// contents is the same dataplane as a reader, when it can be read back at
	// all: a restarted controller sweeps an earlier run's sessions out of it
	// (sweep.go), and a test's applier may not offer the reading.
	contents ContentReader
	// counters is the same dataplane as a counter reader, when it has that
	// capability: the Applier interface stays what every applier must answer,
	// and a graph without counting modules is a graph a URR cannot report from
	// (Evaluate says so rather than reporting zero forever).
	counters CounterReader
	log      *slog.Logger

	// endMarkerConn is this run's connection to the graph's end-marker port,
	// opened on the first marker and dropped when a write fails (the daemon
	// behind it restarted, or the graph has no such port). Guarded by mu.
	endMarkerConn *net.UnixConn

	// journal is the checkpoint this run writes (journal.go), when there is
	// one. It is set once, before the PFCP socket opens, and never changes: no
	// session message can be in flight while the caller is still setting it.
	// restoring is true while a journal is being replayed into this compiler,
	// which is what keeps a replay from journalling itself.
	journal   *Journal
	restoring bool

	mu       sync.Mutex
	sessions map[uint64]*Session // by local SEID
	byTEID   map[uint32]*Session // by the N3 TEID we advertised
	nextSEID uint64
	actions  *idPool
	meters   *idPool
	teids    *idPool

	// rules is the owner of every rule key a live session holds, by the key the
	// engine sees (resource, then the WildcardMatch key). The PDR tables are
	// shared by every session and one key is one rule: a second session writing
	// a key the first holds would take its packets and, when it went, erase the
	// rule it left behind (compile claims a key, settle and remove give it up).
	rules map[string]uint64

	// stats counts what this compiler's three entry points answered: what a
	// management endpoint reports (Stats).
	stats counters
}

// New returns a compiler writing through ap.
func New(cfg Config, ap Applier, log *slog.Logger) *Compiler {
	if log == nil {
		log = slog.Default()
	}
	cfg = cfg.withDefaults()
	c := &Compiler{
		cfg:      cfg,
		ap:       ap,
		log:      log,
		sessions: map[uint64]*Session{},
		byTEID:   map[uint32]*Session{},
		rules:    map[string]uint64{},
		nextSEID: 1,
		actions:  newIDPool(cfg.MaxActions, cfg.IDReuseDelay),
		meters:   newIDPool(cfg.MaxMeters, cfg.IDReuseDelay),
		teids:    newIDPool(cfg.MaxTEIDs, 0),
	}
	if reader, ok := ap.(CounterReader); ok {
		c.counters = reader
	}
	if reader, ok := ap.(ContentReader); ok {
		c.contents = reader
	}
	return c
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

	// chids is the F-TEID the session allocated per CHOOSE ID (TS 29.244
	// 8.2.3): PDIs whose F-TEID IE carries the same CHOOSE ID are one tunnel
	// endpoint, and the F-TEID is handed to each of them rather than allocated
	// once per PDI. An entry lives while some PDR of the session names the TEID
	// it holds (settle drops the rest), so the map never carries a value the
	// pool has taken back -- which would put two sessions on one TEID rule.
	chids map[uint8]uint32

	// removed holds the PDRs a modification took out of the model: their
	// records are still in the dataplane, and the next transaction that
	// compiles the session erases them (compile), so the SMF is never told a
	// PDR is gone while its rule still selects packets. settle clears the list
	// once that transaction is applied, which leaves the retry after a refusal
	// erasing the same records.
	removed []*pdr

	// stale holds the PDRs a modification replaced: an update keeps a PDR's
	// action and its tunnel, but a new filter or a new UE address is a new rule
	// key, and the old one would go on selecting that action. compile erases an
	// old key unless the same transaction writes it, which is what keeps one
	// key from being written and erased at once (the engine rejects that).
	stale []*pdr

	// ruleKeys are the rule keys this session holds in the compiler's table of
	// owners, kept here so a release touches only them: a deletion at the
	// million-session target would otherwise walk every live key under the
	// lock. compile adds a key when it is the first to claim it, settle removes
	// the ones a transaction gave up, and releaseSession frees what is left.
	ruleKeys []string
}

// holdsRuleKey reports whether the session already lists a rule key. The list
// is a session's own -- a handful of rules -- so the scan is the point: it
// costs nothing next to a map, and it keeps the entry from being added twice
// when a key is claimed, given up and claimed again. The caller holds the lock.
func (s *Session) holdsRuleKey(key string) bool {
	for _, k := range s.ruleKeys {
		if k == key {
			return true
		}
	}
	return false
}

// forgetRuleKey drops a key from the session's list. The caller holds the lock.
func (s *Session) forgetRuleKey(key string) {
	for i, k := range s.ruleKeys {
		if k == key {
			s.ruleKeys = append(s.ruleKeys[:i], s.ruleKeys[i+1:]...)
			return
		}
	}
}

// forgetRemoval marks a PDR id as live again: a request may remove a PDR and
// create it in the same message, and the removal is folded in first.
func (s *Session) forgetRemoval(id uint16) {
	for i, p := range s.removed {
		if p.id == id {
			s.removed = append(s.removed[:i], s.removed[i+1:]...)
			return
		}
	}
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
	urrIDs     []uint32

	// instance is the Network Instance IE the PDI carried (TS 29.244 8.2.4),
	// empty when the SMF named none: resolve turns it into the deployment's
	// interface, whose route domain goes into the rule's key and whose next hop
	// sends the forward out.
	instance string
	domain   uint32
	// nextHop is the Router next hop this PDR's forward leaves by: the
	// deployment's for the direction, or the network instance's when the FAR
	// forwards toward the data network (resolve).
	nextHop uint32

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
	// instance is the Forwarding Parameters' Network Instance (8.2.4), empty
	// when the SMF named none: the interface a forward out of this FAR leaves
	// by (resolve).
	instance string
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

// volumeLimit is one volume-valued IE of a URR: the Volume Threshold (8.2.13)
// or the Volume Quota (8.2.50). The three fields are separate limits -- the
// spec's TOVOL/ULVOL/DLVOL are three flags, not a sum -- and the flags matter
// because a limit the SMF did not provision must not fire.
type volumeLimit struct {
	hasTotal bool
	total    uint64 // octets
	hasUL    bool
	ul       uint64
	hasDL    bool
	dl       uint64
}

// empty reports whether the SMF provisioned no limit at all.
func (v volumeLimit) empty() bool { return !v.hasTotal && !v.hasUL && !v.hasDL }

// reached reports whether the measured volumes have reached the limit: any
// field the SMF provisioned is a limit of its own, per 5.2.2.2.1 ("the measured
// traffic reaches the quota"), and the total is what both directions together
// came to.
func (v volumeLimit) reached(ul, dl uint64) bool {
	return (v.hasTotal && ul+dl >= v.total) ||
		(v.hasUL && ul >= v.ul) ||
		(v.hasDL && dl >= v.dl)
}

// urr is one Usage Reporting Rule as the SMF provisioned it (TS 29.244 8.2.54
// and the IEs 7.5.2.4 allows): what it measures, when it reports, and the
// thresholds and quotas that make it report or stop the traffic.
//
// Everything here is control-side state, read by the reporting task
// (docs/design.md, the mapping table's URR row): the packet path counts per rule and knows nothing
// of thresholds. The reporting bookkeeping lives here too, under the compiler's
// lock -- the session model is the one place that knows a URR's lifetime, and a
// map of its own would have to chase session deletion, modification and the
// refusal rollback to stay in step with it.
type urr struct {
	id uint32

	// The Measurement Method (8.2.40): VOLUM, DURAT or both. EVENT is refused
	// when the URR is read (this UP detects no events), so at least one of
	// these is set.
	volume   bool
	duration bool

	// The Reporting Triggers (8.2.19) this UP implements: the ones a report is
	// generated from. A trigger the SMF sets and this UP does not implement is
	// refused when the URR is read -- a URR that reports less often than asked
	// is a session the SMF mis-bills.
	periodic    bool
	onVolumeTh  bool
	onTimeTh    bool
	onVolQuota  bool
	onTimeQuota bool

	// period is the Measurement Period (8.2.42) in seconds, with periodic set.
	period time.Duration

	// The thresholds (8.2.13, 8.2.14) and quotas (8.2.50, 8.2.51). A quota is
	// what stops the traffic (5.2.2.2.1): when it is reached the PDRs that name
	// this URR compile to a drop (enforcing).
	volThreshold  volumeLimit
	timeThreshold time.Duration
	hasTimeTh     bool
	volQuota      volumeLimit
	timeQuota     time.Duration
	hasTimeQuota  bool

	// enforcing is set by the reporting task when a quota is exhausted: the
	// PDRs that name this URR then drop. A modification that provisions a new
	// quota or threshold clears it, which is how the SMF re-opens the traffic.
	enforcing bool

	// The reporting task's bookkeeping. reported is where the last report of
	// this URR ended, so a report carries the usage of the interval it covers
	// and the next periodic one has a period to measure; seqn is the UR-SEQN
	// of the next report (5.2.2.3: the first report of a URR is 0).
	reported time.Time
	seqn     uint32

	// windowFirst and windowLast are the *current* reporting window's own first
	// and last counted packet. The dataplane stamps a tick's own first packet (a
	// reading clears it) and a window spans however many ticks its period is, so
	// which packets opened and closed the window are remembered here; a report
	// opens the next one. stamped says whether any reading carried a stamp at
	// all: a graph whose counters carry none falls back to the window's length.
	windowFirst time.Time
	windowLast  time.Time
	stamped     bool

	// lastUp and lastDown are the counters these PDRs had counted when the last
	// report was made, so that report's successor covers the usage after it
	// rather than the session's lifetime (report.go, "the window"), and
	// baselined says whether that base has been taken from a reading yet: the
	// first reading is the baseline, because the cells of a reused ActionId are
	// another rule's totals.
	lastUp, lastDown Usage
	baselined        bool
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
	if c.journal != nil {
		// The sessions the journal describes went with the association: a later
		// restart must not replay them for a CP function that considers them
		// void.
		if err := c.journal.Reset(); err != nil {
			c.log.Warn("session: could not clear the checkpoint", "reason", reason, "error", err)
		}
	}
}

// Checkpoint gives the session layer its journal (docs/design.md's restart
// wall). The caller sets it before the PFCP socket opens, so no session message
// is in flight while the pointer is written, and it never changes after.
func (c *Compiler) Checkpoint(j *Journal) { c.journal = j }

// checkpoint appends an applied message to the journal, when there is one. The
// callers answer the SMF after this returns: that ordering is what makes a
// restart a reapply rather than a guess -- every change the SMF was told about
// is in the file, and a record that was cut short belongs to a message nobody
// was answered for, which the SMF retransmits.
func (c *Compiler) checkpoint(kind string, seid uint64, msg message.Message) {
	if c.journal == nil || c.restoring {
		return
	}
	if err := c.journal.record(kind, seid, msg); err != nil {
		// The change is in the dataplane; the journal no longer describes it,
		// so the next restart advertises a new Recovery Time Stamp and the SMF
		// re-establishes. There is nothing else to undo here.
		c.log.Error("session: the checkpoint did not take the change", "kind", kind, "seid", seid, "error", err)
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
		if !p.taken[id] && !p.released[id] {
			// A released id is skipped even though nothing holds it: it is in
			// the free list, and handing it out here would hand it out twice.
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
// SMF pinned. The walk visits each id once and never returns, so this matters
// twice: a pinned value must not be handed out while the session holds it, and
// once released (releaseSession) the value comes back only because release
// queues it -- outside the pool's range nothing queues it, which is what keeps
// 0x11223344 (a legal pin, an illegal allocation) out of the free list.
func (p *idPool) reserve(id uint32) {
	if id == 0 {
		return
	}
	p.taken[id] = true
}

// release takes back an id the pool handed out, or ends the reservation of one
// an SMF pinned. Either way the id is queued for allocation when it lies in the
// pool's own range: the walk visits each id once and never comes round again, so
// a value it passed while it was taken or reserved would otherwise be gone for
// the life of the pool -- the SMF that pinned it could not pin it again, and no
// other session could be given it. A value outside the range (0x11223344 is a
// legal pin and an illegal allocation) only ends its reservation: the range is
// what the deployment's peer expects to see in a TEID. A zero grace means an id
// may be reused as soon as the walk is over (for a resource with no retire
// period: the TEID table's rules are keyed, not slotted).
func (p *idPool) release(id uint32) {
	if id == 0 {
		return
	}
	delete(p.taken, id)
	if id >= p.limit || p.released[id] {
		return
	}
	p.released[id] = true
	p.freed = append(p.freed, freedID{id: id, at: p.now()})
}

// resource names, as the deployed graph spells them.
func rulesRes(d Direction) string    { return d.PDRTable + "/rules" }
func (c *Compiler) teidRes() string  { return c.cfg.TEIDTable + "/rules" }
func actionsRes(d Direction) string  { return d.Actions + "/actions" }
func metersRes(d Direction) string   { return d.Meters + "/meters" }
func tunnelsRes(d Direction) string  { return d.Tunnels + "/tunnels" }
func countersRes(d Direction) string { return d.Counters + "/counters" }

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
	// One erase per (resource, key): a session's PDRs name the same records --
	// the meter of a QER in each direction, and one F-TEID when two uplink PDRs
	// carry it -- so erasing per PDR would name the same record several times
	// in one transaction.
	seen := map[string]bool{}
	add := func(ch bess.Change) {
		k := ch.Resource + "\x00" + fmt.Sprint(ch.Key)
		if seen[k] {
			return
		}
		seen[k] = true
		changes = append(changes, ch)
	}
	// The records of a PDR a modification removed are still in the dataplane
	// when the session goes: they are out of the model, so a deletion that
	// walked only the model would leave them programmed for good. A replaced
	// PDR's old form is here for the same reason: an update that was refused
	// left the model holding the new key while the old one is still programmed.
	// The dedupe above is what lets both lists name the same records as the
	// PDRs that stayed.
	all := pdrsInOrder(s)
	all = append(all, s.removed...)
	all = append(all, s.stale...)
	for _, p := range all {
		dir := c.direction(p.srcIfc)
		key, err := p.ruleKey(dir.PDRFields)
		if err != nil {
			// The session's rules were written with these keys, so this is a
			// PDI that changed under a live session: fail the deletion rather
			// than leave the rule behind.
			return fmt.Errorf("PDR %d: %w", p.id, err)
		}
		add(bess.Change{Resource: rulesRes(dir), Key: key})
	}
	for _, p := range all {
		dir := c.direction(p.srcIfc)
		if p.actionID != 0 {
			add(bess.Change{Resource: actionsRes(dir), Key: map[string]any{"id": p.actionID}})
		}
		for _, t := range p.tunnels {
			add(bess.Change{Resource: t, Key: map[string]any{"action_id": p.actionID}})
		}
		if p.teid != 0 {
			add(bess.Change{Resource: c.teidRes(), Key: teidRuleKey(p.teid)})
		}
		if dir.Counters != "" && len(p.urrIDs) > 0 && p.actionID != 0 {
			add(bess.Change{Resource: countersRes(dir), Key: map[string]any{"action_id": p.actionID}})
		}
	}
	// Meters belong to QERs, not to PDRs: compile writes one per policed
	// direction whether or not a PDR names it, so a deletion erases them from
	// the same list. Erasing them per PDR instead would miss the meter of a
	// direction no PDR of this session uses, and would name the QER's meter
	// once per PDR.
	for _, q := range qersInOrder(s) {
		if !q.hasRate {
			continue
		}
		if q.meterUL != 0 {
			add(bess.Change{Resource: metersRes(c.cfg.Up), Key: map[string]any{"id": q.meterUL}})
		}
		if q.meterDL != 0 {
			add(bess.Change{Resource: metersRes(c.cfg.Down), Key: map[string]any{"id": q.meterDL}})
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

// settle forgets the removals a transaction carried out, once the dataplane has
// taken it, and gives up the rule keys that transaction erased. Until then they
// stay listed and claimed, so a refused modification's retry erases the same
// records rather than leaving them behind. A TEID that no PDR of the session
// names any more also loses its mapping and its reservation here: nothing else
// would clear them before the session ends, and every later pin of that value
// would be refused as this session's.
func (c *Compiler) settle(s *Session) {
	c.mu.Lock()
	defer c.mu.Unlock()
	gones := append(append([]*pdr(nil), s.removed...), s.stale...)
	for _, p := range gones {
		if p.teid == 0 || c.byTEID[p.teid] != s || teidNamed(s, p.teid) {
			continue
		}
		delete(c.byTEID, p.teid)
		c.teids.release(p.teid)
	}
	// A CHID's F-TEID is the session's while a PDR names it: an entry left
	// holding a released TEID would hand that value to a later PDR with the same
	// CHOOSE ID, and two sessions would come to share one TEID rule.
	for chid, teid := range s.chids {
		if !teidNamed(s, teid) {
			delete(s.chids, chid)
		}
	}
	// The rule keys this transaction erased are given up now that it has landed.
	// Until then they stay the session's: a refused transaction leaves the rule
	// programmed (and the retry erases it again), so a claim dropped while the
	// transaction is in the air would let another session write over that rule
	// -- and be erased by this session's retry. A key a PDR of the session
	// still names is one the transaction *wrote* rather than erased (compile
	// skips the erase for those), and it stays claimed.
	live := map[string]bool{}
	for _, p := range s.PDRs {
		dir := c.direction(p.srcIfc)
		if key, err := p.ruleKey(dir.PDRFields); err == nil {
			live[rulesRes(dir)+"\x00"+fmt.Sprint(key)] = true
		}
	}
	for _, p := range gones {
		dir := c.direction(p.srcIfc)
		key, err := p.ruleKey(dir.PDRFields)
		if err != nil {
			continue
		}
		rkey := rulesRes(dir) + "\x00" + fmt.Sprint(key)
		if !live[rkey] && c.rules[rkey] == s.LocalSEID {
			delete(c.rules, rkey)
			s.forgetRuleKey(rkey)
		}
	}
	s.removed, s.stale = nil, nil
}

// releaseSession frees the ids a session's records hold, each exactly once: one
// F-TEID, and one QER's meter, usually appear in several of a session's PDRs,
// and freeing an id twice would queue it in the free list twice and hand it to
// two sessions. The caller holds the lock. A reserved id (an F-TEID the SMF
// pinned) is not queued for allocation -- the pool never handed it out -- so
// only its reservation ends.
func (c *Compiler) releaseSession(s *Session) {
	// The rule keys this session holds go with it: the deletion that called
	// this erased them, and a claim kept past that would refuse another session
	// the key for good. The keys are the session's own list, so a release costs
	// the session's own rules rather than a walk of every live key under the
	// lock -- which is what a million sessions make unaffordable.
	for _, key := range s.ruleKeys {
		if c.rules[key] == s.LocalSEID {
			delete(c.rules, key)
		}
	}
	s.ruleKeys = nil
	// Each id once per pool: a session says its ids once per PDR, and two
	// uplink PDRs sharing a pinned F-TEID would otherwise release it twice --
	// the second release finds the reservation gone and queues an SMF's value
	// for allocation.
	teids := map[uint32]bool{}
	actions := map[uint32]bool{}
	meters := map[uint32]bool{}
	all := pdrsInOrder(s)
	// A PDR a modification removed still holds ids, and a replaced PDR's old
	// form holds the TEID it used to have: the records are erased by the
	// deletion above, and the ids are freed here with the rest.
	all = append(all, s.removed...)
	all = append(all, s.stale...)
	for _, p := range all {
		if p.teid != 0 && !teids[p.teid] {
			teids[p.teid] = true
			// Only if this session is what the mapping names. The mapping goes
			// in during merge, under merge's lock, so nothing else can hold
			// this value while this session has it: the guard is what the
			// rollback property rests on (a refused session clears its own
			// mapping and nobody else's), and it is defensive, not reachable
			// today.
			if c.byTEID[p.teid] == s {
				delete(c.byTEID, p.teid)
			}
			c.teids.release(p.teid)
		}
		if p.actionID != 0 && !actions[p.actionID] {
			actions[p.actionID] = true
			c.actions.release(p.actionID)
		}
	}
	// The meters are the QERs': one per policed direction, allocated with the
	// QER and not with the PDRs that happen to name it.
	for _, q := range qersInOrder(s) {
		if q.meterUL != 0 && !meters[q.meterUL] {
			meters[q.meterUL] = true
			c.meters.release(q.meterUL)
		}
		if q.meterDL != 0 && !meters[q.meterDL] {
			meters[q.meterDL] = true
			c.meters.release(q.meterDL)
		}
	}
}
