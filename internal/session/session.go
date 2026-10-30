// SPDX-License-Identifier: BSD-3-Clause

// Package session compiles PFCP sessions into BESS state (docs/design.md):
// a session change becomes one control_v2 transaction, all or nothing, and the
// packet path never chases a control-plane relation.
//
// The compiler resolves a PDR's relations once, at programming time:
//
//	PDR     -> one graph rule; one lookup writes its ActionId, meter IDs, and
//	           next-hop/domain result fields into packet metadata
//	FAR     -> a next hop (forwarding) or a drop; a downlink forward also has
//	           a tunnel record keyed by the same ActionId
//	QER     -> a meter record per QER, named by meter IDs in the PDR result
//	F-TEID  -> one admission key per configured local address family:
//	           endpoint ID, address family/address and TEID
//
// State here is a cache of what the SMF asked for, not a source of truth --
// and only for as long as the process lives, unless the run was given a
// checkpoint (journal.go): the journal holds the applied session messages and
// the Recovery Time Stamp, so a restart that restores it advertises that stamp
// and keeps the sessions the SMF believes in (docs/design.md's restart wall).
package session

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
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
// ever asks. counters is where the target says the table is read
// (Target.Counts): a module, or "<module>/<table>".
type CounterReader interface {
	RuleCounts(ctx context.Context, counters string, actionIDs ...uint32) ([]bess.RuleCount, error)
}

// WindowReader is CounterReader without opening the next window: the same
// reading, leaving each rule's first-packet stamp where it is (report.go). The
// Downlink Data Report path needs it -- a report the SMF never took has to be
// offered again, and a reading that cleared the stamp would read the next tick
// as "nothing arrived" -- and a dataplane that cannot do it falls back to the
// ordinary reading, which loses at most the retry of one report.
type WindowReader interface {
	PeekRuleCounts(ctx context.Context, counters string, actionIDs ...uint32) ([]bess.RuleCount, error)
}

// ErrorReader is the GTP-U responder's error table as a dataplane capability:
// the Error Indications the peer sent this UPF, by the TEID each named (TS
// 29.244 5.10). It is a capability of its own for the same reason the counter
// reader is -- a graph whose responder does not track them never asks, and one
// whose responder is a different module from its counters still answers.
type ErrorReader interface {
	ErrorCounts(ctx context.Context, module string, teids ...uint32) ([]bess.ErrorCount, error)
}

// EndMarkerReader is the GTP-U responder's End Marker log as a dataplane
// capability: the End Markers that arrived since the previous drain, each
// returned once, by the endpoint and local TEID it came in on (TS 29.281
// 7.3.2). A drain consumes what it returns, so only the report loop calls it.
type EndMarkerReader interface {
	DrainEndMarkers(ctx context.Context, module string) ([]bess.EndMarker, uint64, error)
}

// StoreCommands is the dataplane as a command sender for the packet store: the
// release and drop of what one flow holds (TS 29.244 5.2.4.1). It is a
// capability of its own for the same reason CounterReader is -- a graph with no
// store never asks -- and the commands carry the flow id, never configuration:
// the numbers the SMF sent are resource values (8.2.29, 8.2.30).
type StoreCommands interface {
	ReleaseFlow(ctx context.Context, module string, id uint32) error
	DropFlow(ctx context.Context, module string, id uint32) error
	// ClearStore frees everything the store holds. The restart wall wants it:
	// the packets a previous run's flows held live in the daemon, and a
	// controller that comes up knows neither the flows nor the episode they
	// belonged to -- leaving them to age out would hand a later session the
	// previous one's packets.
	ClearStore(ctx context.Context, module string) error
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
	// FTEIDContext is the metadata attribute GtpuDecap writes from the exact
	// F-TEID admission entry a G-PDU matched (`fteid_context`): a compiler
	// allocated id standing for one session's (endpoint, TEID) in one
	// direction. The admission lookup already compared endpoint, family, local
	// address and TEID, so the PDR key needs only this 4-byte id; a TEID
	// repeated on another endpoint or by another session has a different one.
	FTEIDContext
	QFI
)

// width is the field's width in bytes, as the packet carries it.
func (f Field) width() int {
	switch f {
	case SrcIP, DstIP:
		return 4
	case Proto, QFI:
		return 1
	case SrcPort, DstPort:
		return 2
	case RouteDomain, FTEIDContext:
		return 4
	default:
		return 0
	}
}

// String is the field's name as the graph's manifest spells the offset.
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
	case FTEIDContext:
		return "F-TEID context"
	case QFI:
		return "QFI"
	default:
		return "field " + strconv.Itoa(int(f))
	}
}

// FlagName is the field as module flags spell it.
func (f Field) FlagName() string {
	switch f {
	case SrcIP:
		return "src"
	case DstIP:
		return "dst"
	case Proto:
		return "proto"
	case SrcPort:
		return "sport"
	case DstPort:
		return "dport"
	case RouteDomain:
		return "domain"
	case FTEIDContext:
		return "fteid"
	case QFI:
		return "qfi"
	default:
		return "field" + strconv.Itoa(int(f))
	}
}

// Direction is one half of the deployed graph: where a PDR of this direction
// sends its matches, and what a forward means there.

// Direction is one half of the deployed graph: where a PDR of this direction
// sends its matches, and what a forward means there.
//
// RouteMode is how the deployment's Router decides where a forward leaves.
type RouteMode uint8

const (
	// RouteByHop is the policy mode: a FAR's egress is resolved when the
	// session is installed to the next-hop id its action names, and the Router
	// resolves that id -- one gate per egress, whatever the destination.
	RouteByHop RouteMode = iota

	// RouteByDestination is the routed mode: the action names no next hop (0),
	// and the Router looks the packet's own IPv4 destination up in the route
	// domain it carries. The deployment's routes are the decisions, so one
	// egress can reach many destinations (a transit N6, an N9 peer by address,
	// ECMP, per-packet ULCL branching).
	RouteByDestination
)

// ParseRouteMode reads -route-mode: "hop" (the default) or "destination".
func ParseRouteMode(s string) (RouteMode, error) {
	switch s {
	case "hop":
		return RouteByHop, nil
	case "destination":
		return RouteByDestination, nil
	}
	return 0, fmt.Errorf("route mode %q is hop or destination", s)
}

// The two directions are two chains of modules, because a BESS module has one
// output gate per path: the uplink's Meter feeds the Router that leaves toward
// N6, the downlink's feeds the GtpuEncap that leaves toward N3. The PDR table
// is shared; the rule's own gate picks the chain (docs/design.md).
type Direction struct {
	// PDRTable is the `WildcardMatch` module holding this direction's rules
	// (`pdr_ul` or `pdr_dl`). Its `result_fields` define the PDR result; a hit
	// writes ActionId, meter IDs, next hop and route domain directly to metadata.
	// The output chain is direction-specific.
	PDRTable string
	// PDRFields is that table's key, in the graph's order.
	PDRFields []Field
	// Meters is the Meter module its QER meters live in. The module is
	// built with `levels: 2`: the classifier's result writes the PDR's own
	// rate-bearing QER first and the session's shared one second, so a packet
	// the flow's bucket drops is not charged to the session's.
	Meters string
	// NextHop is the Router next hop a forward leaves by, for either
	// direction: the uplink's is the N6 route, the downlink's the N3 one. The
	// classifier's result writes it into the packet's `next_hop_id` attribute,
	// and the Router downstream reads it; an id the Router does not know is a
	// drop.
	NextHop uint32
	// Tunnels is the GtpuEncap module whose per-session records the direction
	// writes: the downlink's GTP-U tunnel toward the gNB, and an uplink forward
	// that adds an outer header of its own (indirect data forwarding, or the
	// uplink of an N9 tunnel). One deployment usually has one encap module and
	// names it in both directions -- the action ids are the session's, so one
	// module holds both directions' records. A direction with no module refuses
	// such a forward rather than compiling a rule the encap would drop.
	Tunnels string
	// Counters is the UrrCount module this direction's per-rule counters live
	// in ("cnt_ul", "cnt_dl"; empty for a graph with no usage reporting). A
	// session's PDRs that a URR measures get one entry there, keyed by the
	// ActionId the rule names, and the module counts what the chain forwards.
	Counters string
}

// FTEIDEndpoint is a configured local GTP-U endpoint. Slice order is the
// deterministic CHOOSE preference order.
type FTEIDEndpoint struct {
	ID                   uint32
	ReferencePoint       string
	TransportRouteDomain uint32
	SourceInterface      uint8
	Instance             string
	IPv4                 netip.Addr
	IPv6                 netip.Addr
}

// FTEIDKey is the exact GTP-U admission identity.
type FTEIDKey struct {
	EndpointID    uint32
	AddressFamily uint32
	LocalAddress  []byte
	TEID          uint32
}

// Direction: where a PDR of this direction sends its matches, and what a
// forward means there.
// Config is the deployed graph's shape and the constants a session's resources
// point at.
type Config struct {
	// GTPUDecap is the GtpuDecap module owning the /fteids resource.
	GTPUDecap string

	// GTPUErrors is the GTP-U responder module whose error table the report
	// loop reads; it is reached from GtpuDecap's unknown/control gate.
	// Empty means the graph's responder does not track them and the SMF is
	// told of no tunnel loss; a session whose FAR sends with a TEID the peer
	// reported is reported as an Error Indication Report (TS 29.244 5.10).
	GTPUErrors string

	// GTPUEndMarkers is the GTP-U responder module whose End Marker log the
	// report loop drains (track_end_markers). A URR that asks for REEMR
	// (TS 29.244 8.2.19) is refused when it is empty: the End Marker it asks
	// to hear about would never be seen. With it set, an End Marker on a PDR's
	// local F-TEID is reported as a Usage Report with the EMRRE trigger
	// (8.2.41) for every REEMR URR the PDR names.
	GTPUEndMarkers string

	// RouteMode is how the graph's Router decides a forward's egress. It must
	// agree with the Router module's own `mode` argument: a graph in
	// ROUTE_MODE_DESTINATION ignores the next hop an action names, and a graph
	// in the default mode drops a packet whose action names 0.
	RouteMode RouteMode

	// Up and Down are the two chains.
	Up, Down Direction

	// Instances is the deployment's network instances (internal/routing): the
	// names a PDI's Network Instance (TS 29.244 8.2.4) may use, the route
	// domain each is classified in, the addresses each serves, and the next
	// hop a forward out of it takes. Nil is the one-instance deployment: no
	// PDI's instance is resolved, every rule is domain 0, and each direction's
	// next hop is the deployment's own (the -n6-next-hop and -n3-next-hop
	// flags), which is what the rows in docs/claims.md describe until a
	// deployment configures more than one.
	Instances *routing.Domains

	// Atsss is the AtsssSteer module a MAR-steered PDR's packets go through
	// (its "<module>/policies" and "<module>/health" resources). Empty means
	// this deployment does not steer, and a MAR PDR is refused rather than
	// compiled into a rule that would drop.
	Atsss string

	// AccessNextHop is the Router next hop a forward whose FAR names
	// Destination Interface Access (TS 29.244 8.2.24, value 0) leaves by,
	// whichever direction the PDR is on: the encap on a downlink forward, and
	// the indirect-forwarding tunnel an uplink forward leaves through (8.2.2
	// NOTE 2). 0 leaves every such forward to the downlink direction's own
	// Down.NextHop, which is what a deployment without uplink forwarding wants.
	AccessNextHop uint32

	// NodeID is this UP function's Node ID as the association advertised it
	// (IP address or FQDN), and N4Addr its N4 IPv4 address: the Session
	// Establishment Response names the one and the UP F-SEID carries the other.
	NodeID string
	N4Addr netip.Addr

	// FTEIDEndpoints are ordered; that order resolves CHOOSE requests and
	// selects the configured local endpoint for each routed GTP-U reference
	// point. TransportRouteDomain is independent of the inner route_domain.
	FTEIDEndpoints []FTEIDEndpoint

	// EndMarker is the base graph unix_port path. A marker uses the old
	// tunnel's transport route domain as a suffix: <path>.<domain>.
	EndMarker string

	// Buffering is the graph's buffering branch (TS 29.244 7.5.2.6, 5.2.4):
	// where the packets of a FAR whose Apply Action is BUFF and not FORW are
	// held. Nil means the deployment buffers nothing -- such a FAR's rule drops,
	// which is what docs/claims.md records for a graph without a store.
	Buffering *Buffering

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

	// Appliance is the one module that runs the whole user plane
	// (UpfAppliance, upfd's -target appliance): every table is that module's
	// (target.go), and the module fields above say only which of them this
	// deployment uses. Empty is the module graph, whose tables are
	// "<module>/<table>" of the modules those fields name.
	Appliance string
}

// downlink is whether this PDR's packets travel toward the UE. Source
// Interface identifies the logical ingress side; it does not select a
// direction for every procedure. merge derives this from the PDI's UE-address
// side when present, then from an "assigned" SDF side, with the ordinary
// Source Interface behavior as the fallback.
func (p *pdr) downlink() bool { return p.down }

// direction is the PDR's packet direction, not its Source Interface.
func (c *Compiler) direction(p *pdr) Direction {
	if p.downlink() {
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
	if len(c.Up.PDRFields) == 0 {
		c.Up.PDRFields = []Field{SrcIP, DstIP, Proto, SrcPort, DstPort,
			FTEIDContext, QFI}
	}
	if len(c.Down.PDRFields) == 0 {
		c.Down.PDRFields = []Field{SrcIP, DstIP, Proto, SrcPort, DstPort,
			RouteDomain, FTEIDContext, QFI}
	}
	return c
}

// Compiler turns PFCP sessions into BESS state. It implements the N4 server's
// session handler (internal/n4.SessionHandler).
type Compiler struct {
	cfg Config
	// target names every table and command module the compilation uses
	// (target.go): the graph's, or the appliance's.
	target Target
	ap     Applier
	// contents is the same dataplane as a reader, when it can be read back at
	// all: a restarted controller sweeps an earlier run's sessions out of it
	// (sweep.go), and a test's applier may not offer the reading.
	contents ContentReader
	// counters is the same dataplane as a counter reader, when it has that
	// capability: the Applier interface stays what every applier must answer,
	// and a graph without counting modules is a graph a URR cannot report from
	// (Evaluate says so rather than reporting zero forever).
	counters CounterReader

	// markersDropped is the End Marker log's lost count the report loop last
	// logged: the drain answers a running total, and only an increase is news.
	// Only EvaluateAll touches it, from the one report loop.
	markersDropped uint64
	// peek is the same counter reader without the window restart, when the
	// dataplane offers it (WindowReader): the DDN path's reading.
	peek WindowReader
	// store is the same dataplane as a command sender, when it can be one: the
	// release and drop of a buffering flow's held packets (5.2.4.1). A graph
	// with no store never asks, and a dataplane that cannot send commands
	// leaves it nil -- a buffering instruction is then applied without the
	// release that follows it, which upfd's log and metrics say.
	store StoreCommands
	log   *slog.Logger

	// Marker connections are shared by transport socket path, guarded by mu.
	endMarkerConns map[string]*net.UnixConn

	// journal is the checkpoint this run writes (journal.go), when there is
	// one. It is set once, before the PFCP socket opens, and never changes: no
	// session message can be in flight while the caller is still setting it.
	// restoring is true while a journal is being replayed into this compiler,
	// which is what keeps a replay from journalling itself.
	journal   *Journal
	restoring bool

	mu            sync.Mutex
	sessions      map[uint64]*Session
	nextSEID      uint64
	byFTEID       map[string]fteidOwner
	fteidTEIDKeys map[uint32]map[string]bool
	actions       *idPool
	policies      *idPool
	meters        *idPool
	teids         *idPool
	// fteidContexts is the admission context each (session, direction,
	// endpoint, TEID) holds while one of its exact F-TEID keys is claimed: the
	// id GtpuDecap writes as `fteid_context` and the PDR key matches. Like the
	// TEID it replaced in that key, a context is reusable once released: its
	// admission entries leave in the same transaction as its rules. A pinned
	// TEID outside MaxTEIDs still takes a context, so the pool is not bounded
	// by it: the decap's max_fteids is what bounds live contexts.
	fteidContexts map[fteidContextKey]*fteidContext
	contexts      *idPool
	// MAR policy and tunnel records are allocated from the same pools as
	// action records: a tunnel key shares the GtpuEncap table with an ordinary
	// PDR's action key, and a policy key must be unique across sessions. The
	// pools are separate only where their resources are; the action pool
	// supplies both action and tunnel keys.

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

type fteidOwner struct {
	session *Session
	down    bool
}

type fteidContextKey struct {
	session  *Session
	down     bool
	endpoint uint32
	teid     uint32
}

type fteidContext struct {
	id   uint32
	keys int // claimed exact admission keys that write this id
}

// New returns a compiler writing through ap.
func New(cfg Config, ap Applier, log *slog.Logger) *Compiler {
	if log == nil {
		log = slog.Default()
	}
	cfg = cfg.withDefaults()
	c := &Compiler{
		cfg:           cfg,
		target:        newTarget(cfg),
		ap:            ap,
		log:           log,
		sessions:      map[uint64]*Session{},
		rules:         map[string]uint64{},
		byFTEID:       map[string]fteidOwner{},
		fteidTEIDKeys: map[uint32]map[string]bool{},
		fteidContexts: map[fteidContextKey]*fteidContext{},
		nextSEID:      1,
		actions:       newIDPool(cfg.MaxActions, cfg.IDReuseDelay),
		policies:      newIDPool(cfg.MaxActions, cfg.IDReuseDelay),
		meters:        newIDPool(cfg.MaxMeters, cfg.IDReuseDelay),
		teids:         newIDPool(cfg.MaxTEIDs, 0),
		contexts:      newIDPool(1<<31, 0),
	}
	if reader, ok := ap.(CounterReader); ok {
		c.counters = reader
	}
	if reader, ok := ap.(ContentReader); ok {
		c.contents = reader
	}
	if cmds, ok := ap.(StoreCommands); ok {
		c.store = cmds
	}
	if peek, ok := ap.(WindowReader); ok {
		c.peek = peek
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

type chosenFTEID struct {
	TEID            uint32
	EndpointID      uint32
	Families        []uint8
	SourceInterface uint8
	Instance        string
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
	// BARs are what the SMF asks a buffering FAR to hold (TS 29.244 7.5.2.6):
	// the DL Buffering Duration and the DL Buffering Suggested Packet Count,
	// referenced by the FARs' BAR ID (8.2.55). They are a map rather than a
	// field of the FAR because an Update BAR arrives on its own -- including in
	// a Session Report Response, which is how the SMF answers a Downlink Data
	// Report -- and the flows that reference it must be reprogrammed without a
	// FAR in the message.
	BARs map[uint8]*bar

	// MARs are the session's Multi-Access Rules (TS 29.244 7.5.2.8), by MAR
	// ID. A PDR names one instead of a FAR; the two access actions it holds
	// are what AtsssSteer applies.
	MARs map[uint16]*mar

	// chids stores the allocated endpoint, complete address-family set and TEID
	// per CHOOSE ID (TS 29.244 8.2.3). All PDIs sharing an ID reuse precisely
	// that selection, which remains reserved for a retry until no PDR names it.
	chids map[uint8]chosenFTEID

	// erirSent is the count of each TEID this session's SMF has already been
	// told about: the responder's error counts only grow (bess.ErrorCounts),
	// so a report is due when a reading is above the high-water mark kept
	// here. The mark moves when the report is decided, not when the SMF
	// answers it -- the report queue holds it until the SMF does (5.10).
	erirSent map[uint32]uint64

	// Cached sorted slices for hot compile paths; invalidated on mutation.
	cachedPDRs []*pdr
	cachedQERs []*qer
	cachedMARs []*mar

	// removed holds the PDRs a modification took out of the model: their
	// records are still in the dataplane, and the next transaction that
	// compiles the session erases them (compile), so the SMF is never told a
	// PDR is gone while its rule still selects packets. settle clears the list
	// once that transaction is applied, which leaves the retry after a refusal
	// erasing the same records.
	removed []*pdr

	// removedMARs holds the MARs a modification took out of the model. Their
	// policy records are still in the dataplane until compile erases them, so
	// a refused modification can put the MAR back.
	removedMARs []*mar

	// retiredTunnels are MAR tunnel records an update replaced (an access
	// stopped tunnelling, or became "no standby"). compile erases them and
	// settle returns their ids after the transaction lands.
	retiredTunnels []uint32

	// stale holds the PDRs a modification replaced: an update keeps a PDR's
	// action and its tunnel, but a new filter or a new UE address is a new rule
	// key, and the old one would go on selecting that action. compile erases an
	// old key unless the same transaction writes it, which is what keeps one
	// key from being written and erased at once (the engine rejects that).
	stale []*pdr

	// removedQERs holds the QERs a modification took out of the model. Their
	// meters were allocated with the QER (one per policed direction) and are
	// released with the session's other ids (releaseSession) rather than at the
	// removal: a refused modification puts the QER back, and a meter already
	// returned to the pool would be one another session may police with while
	// this one still names it.
	removedQERs []*qer

	// ending holds the flows whose buffering episode this model has ended: the
	// PDRs a modification took out of buffering, by their ActionId. Their held
	// packets are released once the transaction that ended the episode has
	// landed (5.2.4.1), and settle clears the list then -- so a refused
	// transaction retries the release with the change itself. resolve is what
	// appends, because a request that carries only the FAR rebuilds no PDR and
	// this is the one place the transition is visible.
	ending []uint32

	// ruleKeys are the rule keys this session holds in the compiler's table of
	// owners, kept here so a release touches only them: a deletion at the
	// million-session target would otherwise walk every live key under the
	// lock. compile adds a key when it is the first to claim it, settle removes
	// the ones a transaction gave up, and releaseSession frees what is left.
	ruleKeys []string
}

// modelSnapshot is a session's model as it stood before a modification was
// merged: the maps by copy of each entry (merge updates a FAR, a QER, a URR or
// a BAR in place), and the lists the merge appends to. It is what a merge that
// fails validation goes back to, so that a refused modification leaves the
// session as the SMF last saw it rather than half-changed -- a half-changed
// model fails every later message the same way, the SMF's retry included.
type modelSnapshot struct {
	ueIP netip.Addr
	pdrs map[uint16]*pdr
	fars map[uint32]*far
	qers map[uint32]*qer
	urrs map[uint32]*urr
	bars map[uint8]*bar
	mars map[uint16]*mar

	removed, stale []*pdr
	removedMARs    []*mar
	retiredTunnels []uint32
	ending         []uint32
	removedQERs    []*qer
}

func cloneEntries[K comparable, V any](m map[K]*V) map[K]*V {
	out := make(map[K]*V, len(m))
	for k, v := range m {
		cp := *v
		out[k] = &cp
	}
	return out
}

// snapshot copies the model. The caller holds the lock.
func (s *Session) snapshot() modelSnapshot {
	return modelSnapshot{
		ueIP: s.UEIP,
		pdrs: cloneEntries(s.PDRs), fars: cloneEntries(s.FARs), qers: cloneEntries(s.QERs),
		urrs: cloneEntries(s.URRs), bars: cloneEntries(s.BARs),
		mars:    cloneEntries(s.MARs),
		removed: slices.Clone(s.removed), stale: slices.Clone(s.stale), ending: slices.Clone(s.ending),
		removedMARs:    slices.Clone(s.removedMARs),
		retiredTunnels: slices.Clone(s.retiredTunnels),
		removedQERs:    slices.Clone(s.removedQERs),
	}
}

// rollback puts the model back and gives back the ids the failed merge took:
// the F-TEIDs of PDRs that exist only in the failed state, and the meters of
// QERs that do. An F-TEID the session allocated per CHOOSE ID stays (the map
// is not restored): it is what a retry of the same request is handed again,
// and settle drops it once no PDR names it. The caller holds the lock.
func (c *Compiler) rollback(s *Session, snap modelSnapshot) {
	failedPDRs := pdrsInOrder(s)
	failedPDRs = append(failedPDRs, s.removed...)
	failedPDRs = append(failedPDRs, s.stale...)
	failedQERs := qersInOrder(s)
	failedMARs := append(marsInOrder(s), s.removedMARs...)
	failedRetired := slices.Clone(s.retiredTunnels)

	s.UEIP = snap.ueIP
	s.PDRs, s.FARs, s.QERs, s.URRs, s.BARs, s.MARs = snap.pdrs, snap.fars, snap.qers, snap.urrs, snap.bars, snap.mars
	s.invalidateOrderCache()
	s.removed, s.stale, s.ending = snap.removed, snap.stale, snap.ending
	s.removedMARs = snap.removedMARs
	s.retiredTunnels = snap.retiredTunnels
	s.removedQERs = snap.removedQERs

	// MAR policy and tunnel ids allocated by the failed merge are not in the
	// restored model (or its removal list); return them. An id the snapshot
	// still holds is the same reservation, not a new one.
	livePolicies := map[uint32]bool{}
	liveTunnels := map[uint32]bool{}
	for _, m := range append(marsInOrder(s), s.removedMARs...) {
		if m.policyID != 0 {
			livePolicies[m.policyID] = true
		}
		for _, id := range m.tunnelIDs {
			if id != 0 {
				liveTunnels[id] = true
			}
		}
	}
	for _, id := range s.retiredTunnels {
		if id != 0 {
			liveTunnels[id] = true
		}
	}
	policies := map[uint32]bool{}
	tunnels := map[uint32]bool{}
	for _, m := range failedMARs {
		if m.policyID != 0 && !livePolicies[m.policyID] && !policies[m.policyID] {
			policies[m.policyID] = true
			c.policies.release(m.policyID)
		}
		for _, id := range m.tunnelIDs {
			if id != 0 && !liveTunnels[id] && !tunnels[id] {
				tunnels[id] = true
				c.actions.release(id)
			}
		}
	}
	for _, id := range failedRetired {
		if id != 0 && !liveTunnels[id] && !tunnels[id] {
			tunnels[id] = true
			c.actions.release(id)
		}
	}
	for _, p := range failedPDRs {
		c.releaseFTEIDClaim(s, p, false)
	}
	meters := map[uint32]bool{}
	for _, q := range qersInOrder(s) {
		meters[q.meterUL], meters[q.meterDL] = true, true
	}
	for _, q := range failedQERs {
		for _, m := range []uint32{q.meterUL, q.meterDL} {
			if m != 0 && !meters[m] {
				meters[m] = true
				c.meters.release(m)
			}
		}
	}
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
	// down says the PDR's packets come from the side toward the subscriber:
	// the Source Interface value is not Access (downSide). It is set where the
	// value is parsed -- the value cannot change later, an Update PDR being the
	// PDR's whole new form -- and read wherever a PDR is put in a chain (the
	// direction), keyed for a look-up (the downlink selector) or proxied for
	// (the subscriber ARP answer).
	down bool
	ueIP netip.Addr
	// hasUEIP records that this PDI carried the UE IP Address IE; an address
	// inherited from another PDR must not be mistaken for an explicit S/D bit.
	hasUEIP bool
	// ueIPDst is 8.2.62's bit 3 as the PDI carried it: set, the address is the
	// packet's destination (ueAddr says what that means for the session).
	ueIPDst bool
	farID   uint32
	// hasMAR and marID are the MAR this PDR's packets are steered by (TS
	// 29.244 8.2.34). A MAR PDR has no FAR of its own: the MAR's two access
	// actions are its egress.
	hasMAR   bool
	marID    uint16
	policyID uint32 // the shared AtsssSteer policy this PDR's MAR compiled to
	qerIDs   []uint32
	urrIDs   []uint32

	// instance is the Network Instance IE the PDI carried (TS 29.244 8.2.4),
	// empty when the SMF named none: resolve turns it into the deployment's
	// interface, whose route domain goes into the rule's key and whose next hop
	// sends the forward out.
	instance string
	domain   uint32

	// sdfs and qfis are what the PDI named (TS 29.244 8.2.89 and the SDF
	// Filter IE): the SDF filters and QoS flows this rule selects, any of
	// which matches. A PDI that names no QFI leaves the uplink table's qfi
	// field open -- the session's general rule for the flow -- and the rule
	// then matches every QFI of it.
	sdfs []*sdfFilter
	qfis []uint8
	// sdf, hasQFI and qfi are one combination of the two lists, and are set
	// only on the copies variants() makes: the matchers read one filter and
	// one QFI per rule.
	sdf    *sdfFilter
	hasQFI bool
	qfi    uint8
	// encapQFI is the QFI of the QER this PDR's downlink record carries
	// (resolve). hasEncapQFI distinguishes an absent QFI from valid QFI 0
	// (TS 38.415 5.5.3.3).
	encapQFI    uint8
	hasEncapQFI bool

	// nextHop is the Router next hop this PDR's forward leaves by: the
	// deployment's for the direction, or the network instance's when the FAR
	// forwards toward the data network (resolve).
	nextHop uint32

	hasFTEID, hasChoose, hasCHID bool
	chid                         uint8
	fteidIPv4, fteidIPv6         netip.Addr
	wantIPv4, wantIPv6           bool
	teid                         uint32 // local ingress TEID, in either direction (0 for plain N6)
	endpointID                   uint32
	endpointFamily               uint8
	fteidContext                 uint32 // the admission context the decap writes for this PDR's F-TEID
	endpointIPv4, endpointIPv6   netip.Addr
	endpointFamilies             []uint8
	tunnelLocalAddress           netip.Addr
	transportRouteDomain         uint32
	actionID                     uint32 // the ActionId carried in this PDR rule's result
	meterID                      uint32 // the meter record a QER resolved to, in this chain's Meter
	// ownMeterID and sharedMeterID are that choice's halves: the PDR's own
	// last rate-bearing QER, and the session's shared QER (0 when the PDR
	// names none). The PDR result writes the own meter ID first and the shared
	// session meter ID second, as the direction's `Meter(levels: 2)` consumes them.
	ownMeterID    uint32
	sharedMeterID uint32
	tunnels       []string // per-session tunnel records to write (downlink)
	// writtenTunnels are the tunnel resources this PDR's action holds in the
	// dataplane: a rebind to a FAR without Outer Header Creation erases them.
	writtenTunnels []string
	drop           bool // the FAR drops, or the QER's gate is closed this way
	// buffer says the FAR asks for the packets to be held (Apply Action BUFF
	// without FORW) and the deployment has a store: the rule delivers on the
	// buffering branch instead, and the flow's key is the ActionId the rule
	// carries. A PDR that buffers is never a PDR that drops -- a closed QER
	// gate is an instruction to stop, not to hold (resolve).
	buffer bool
	// ddnSent says the SMF has been told about this buffering episode's first
	// packet: the report is owed once per episode ("the first buffered DL
	// packet", 5.2.4.1), and resolve clears the flag when the PDR stops
	// buffering -- the instruction that ends the episode.
	ddnSent bool
	// notify says the FAR's Apply Action carried NOCP (8.2.26): the CP
	// function asked to be told when the first downlink packet is buffered.
	// BUFF without NOCP is an instruction to hold the packets and report
	// nothing, and a Downlink Data Report sent anyway is a message the SMF did
	// not ask for (its own NOCP field says so).
	notify bool
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

	// hasFwd, hasDestIfc, hasPolicy and policy are what the FAR's forwarding
	// parameters named, as they stand after every message that touched this
	// FAR: the IE itself (mandatory for a FAR that forwards, Table
	// 7.5.2.3-1), the Destination Interface inside it (mandatory, Table
	// 7.5.2.3-2), and the Forwarding Policy (mandatory for a forward toward
	// SGi-LAN/N6-LAN, Table 7.5.2.3-2). An Update FAR that names none of them
	// leaves them as the session has them, which is why the checks read the
	// record and not the message.
	hasFwd     bool
	hasDestIfc bool
	policy     string
	hasPolicy  bool

	// hasBAR and barID are the FAR's BAR ID (8.2.55): the buffering instruction
	// this FAR's buffered packets live under. resolve refuses a reference to a
	// BAR the session does not hold, the way it refuses a PDR naming a URR the
	// session does not have -- compiling a buffer against a rule the SMF never
	// provisioned would hold packets under numbers nobody sent.
	hasBAR bool
	barID  uint8

	// hasMarking and marking are the FAR's Transport Level Marking
	// (TS 29.244 8.2.12, inside the Forwarding Parameters): the two octets the
	// SMF asks this FAR's outer headers to be marked with, the DSCP in the
	// high octet and the mask in the low one. It reaches the tunnel record a
	// downlink PDR's FAR writes, where the encap applies it over the inner
	// packet's own class (the TunnelEntry's "marking" field).
	hasMarking bool
	marking    uint16
}

// mar is one compiled Multi-Access Rule (TS 29.244 7.5.2.8): the steering
// mode and the two access actions an ATSSS PDR's packets choose between.
type mar struct {
	id uint16
	// mode is the MAR's Steering Mode (8.2.83); only active/standby (0) is
	// compiled, because that is the one AtsssSteer applies.
	mode uint8
	// accesses are the 3GPP and the non-3GPP access, in that order. The slice
	// is length 2 and is replaced whole by an Update MAR.
	accesses [2]marAccess
	// preferred is the active access's index, 0 or 1.
	preferred uint32
	// nextHops are the Router next hops the two accesses leave by, resolved
	// at compile time from their FARs.
	nextHops [2]uint32
	// policyID is the AtsssSteer policy key, unique across sessions (a PFCP
	// MAR ID is only session-local) and allocated once per MAR.
	policyID uint32
	// tunnelIDs are the GtpuEncap records the two accesses name, allocated
	// when an access adds an outer header and kept for the session's life.
	tunnelIDs             [2]uint32
	tunnelLocalAddresses  [2]netip.Addr
	transportRouteDomains [2]uint32
}

// marAccess is one access of a MAR: the FAR it forwards through (TS 29.244
// 8.2.34) and the priority that makes it active or standby. A nil/missing
// access is a MAR that has not been provisioned yet; resolve refuses it rather
// than steering into a zero.
type marAccess struct {
	farID uint32
	// hasFarID distinguishes FAR 0 (a legal FAR) from an access the message
	// did not name.
	hasFarID  bool
	priority  uint8
	hasPrior  bool
	weight    uint8
	hasWeight bool
}

// Buffering is the deployment's buffering branch: the store a BUFF FAR's
// packets are held in, the counting module in front of it, and the rule gate
// that delivers them there.
//
// The store is BESS's own packet store (core/modules/packet_store.h), keyed by
// the ActionId the classifier writes -- the same id the rule's action and
// tunnel records are keyed by, so one value resolves the whole session. Its
// "<module>/flows" resource carries what the SMF asked for that flow: the DL
// Buffering Duration (8.2.29) as a timeout and the DL Buffering Suggested
// Packet Count (8.2.30) as the flow's cap, both optional, both falling back to
// the module's own arguments when the SMF named neither. Release and drop stay
// commands (they act on the packets held, not on configuration).
type Buffering struct {
	// Store is the packet store module whose "flows" resource each buffering
	// rule writes an entry to. Empty means the graph has no store.
	Store string
	// Counter is the UrrCount module on the BUFF branch, in front of the store:
	// the count is what makes "the first buffered DL packet for this PDR"
	// visible to the reporting side, which polls it. The module the direction's
	// URR counters live in is a different instance: a buffered packet leaves
	// the chain at the rule's gate and would never reach that one.
	Counter string
	// Gate is the PDR table gate that delivers on that branch.
	Gate uint32
}

type bar struct {
	id uint8

	// hasDuration says the DL Buffering Duration IE (8.2.29) was there. The
	// IE's one octet is a timer: a unit (bits 8-6) and a value (bits 5-1).
	// All-zero is the deactivated code -- the timer is stopped, which is no
	// instruction -- and is what hasDuration false means; the "infinite" unit
	// is hold-without-expiry, and that is the one case that reaches the store
	// as a timeout of zero.
	hasDuration bool
	duration    time.Duration
	infinite    bool

	// hasCount says the DL Buffering Suggested Packet Count IE (8.2.30) was
	// there, in packets. Zero is no instruction (the module's own cap), since
	// "buffer no packets" is not something an SMF asks for.
	hasCount bool
	count    uint32
}

// empty reports whether the BAR carries no buffering instruction at all: the
// spec allows a BAR to be provisioned empty and filled in later (5.2.4.1's note
// about a Session Report Response), so this is a state the compiler writes a
// flow entry for without any override.
func (b *bar) empty() bool { return !b.hasDuration && !b.hasCount }

// timeoutNS is the flow's DL Buffering Duration as the store wants it, and
// whether it has one at all: no override (the module's own timeout), or zero
// for the infinite unit, which means the packets are held until the SMF says
// what to do with them.
func (b *bar) timeoutNS() (uint64, bool) {
	if b == nil || !b.hasDuration {
		return 0, false
	}
	if b.infinite {
		return 0, true
	}
	return uint64(b.duration), true
}

type qer struct {
	id      uint32
	gateUL  uint8
	gateDL  uint8
	mbUL    uint64 // bytes per second, as the dataplane's meter wants it
	mbDL    uint64
	hasRate bool

	// gbUL and gbDL are the QER's GBR (8.2.7), the guaranteed rate, in the same
	// unit as the MBR. A meter that polices the MBR alone -- which is what this
	// one did -- drops everything above the ceiling and says nothing about the
	// band between the two: with both named, the meter's committed rate is the
	// GBR and that band is yellow, so the deployment can treat it as the
	// guarantee 8.2.7 means rather than policing it flat. A GBR above the MBR
	// is refused (merge): no two-rate meter holds it.
	gbUL, gbDL uint64
	hasGBR     bool

	// window is the QER's Averaging Window (8.2.115): the duration the rates
	// are measured over, which the meter takes as its burst. Zero means the SMF
	// named none, and this UP's own tenth of a second applies.
	window    time.Duration
	hasWindow bool

	// hasQFI and qfi are the QER's QFI (TS 29.244 8.2.89): the QoS flow this
	// QER polices, which is also the one the downlink encap must write into the
	// PDU Session Container of the packets it tunnels (resolve takes it into
	// the tunnel record the PDR's FAR names). The IE is optional -- a QER
	// without one polices the session's flows and marks none of them.
	hasQFI bool
	qfi    uint8

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
	// onEndMarker is REEMR (8.2.19 octet 7): report when an End Marker arrives
	// on the local F-TEID of a PDR this URR measures (Usage Report Trigger
	// EMRRE, 8.2.41).
	onEndMarker bool

	// linkedReporting is LIUSA (8.2.19): the URR is reported through its link,
	// not on its own triggers -- the group's report is owed when a URR it is
	// linked to is due, and this URR is carried in it. Its own limits still
	// stop the traffic (quotaReached), and its window still moves with the
	// group's report. A LIUSA URR with nothing linked to it is refused when
	// the session is resolved (compile.go, `resolve`).
	linkedReporting bool

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

	// linked are the URR's Linked URR IDs (TS 29.244 8.2.55): the URRs this one
	// reports with. A session's URRs joined by these edges are one linked group
	// and share one UR-SEQN (report.go, "the group").
	linked []uint32

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

	// deliveredUp, deliveredDown and deliveredAt are the reading the SMF was
	// last *told* up to, and when that window opened. lastUp/lastDown move as
	// soon as a report is decided, because the queue holds that report and the
	// next tick must not report the same usage twice; this trio moves only when
	// the message carrying it is accepted (Compiler.ConfirmReport,
	// Compiler.advanceAfter). A session that ends while a report is still in
	// the queue is reported from this trio, so the usage that report held
	// reaches the SMF in the termination report instead of going with it
	// (docs/claims.md, finding 20).
	deliveredUp, deliveredDown Usage
	deliveredAt                time.Time
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
// period: F-TEID admission entries are exact-index keys, not slots).
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

// res is the resource table t is, as the compiler's target names it.
func (c *Compiler) res(t Table) string { return c.target.Resource(t) }

func (c *Compiler) teidRes() string { return c.res(FTEIDs) }
func fteidKey(endpointID, family uint32, address []byte, teid uint32) map[string]any {
	return map[string]any{
		"endpoint_id": endpointID, "address_family": family,
		"local_address": slices.Clone(address), "teid": teid,
	}
}

// The classifier's result record, as every deployed graph declares it:
// action_id (4), meter_id for the meter stack (8: the PDR's own QER, then the
// session's, big-endian), next_hop_id (4), route_domain (4), and -- on the
// downlink -- steering_policy_id (4, 0 without a MAR). BESS writes the record
// into metadata (`result_fields`); no action table is in the chain.
const (
	resultActionID    = 0
	resultMeterID     = 4
	resultNextHopID   = 12
	resultRouteDomain = 16
	resultSize        = 20
	resultSteeringID  = 20
)

// pdrResult is one PDR rule's result record. The meter stack has two levels in
// every deployment: the second is 0 when the PDR names no shared QER, which
// the Meter skips. The selected PDI Network Instance is written to
// route_domain after the classifier; on a downlink MAR PDR, AtsssSteer reads
// the final policy id and selects the access.
func pdrResult(p *pdr) []byte {
	b := make([]byte, p.resultSize())
	binary.BigEndian.PutUint32(b[resultActionID:], p.actionID)
	own, shared := meterSlots(p)
	binary.BigEndian.PutUint32(b[resultMeterID:], own)
	binary.BigEndian.PutUint32(b[resultMeterID+4:], shared)
	binary.BigEndian.PutUint32(b[resultNextHopID:], p.nextHop)
	binary.BigEndian.PutUint32(b[resultRouteDomain:], p.domain)
	if p.downlink() {
		steering := uint32(0)
		if p.hasMAR && !p.drop && !p.buffer {
			steering = p.policyID
		}
		binary.BigEndian.PutUint32(b[resultSteeringID:], steering)
	}
	return b
}

// resultSize is the base record width (action, meters, next hop and domain),
// plus the downlink's optional steering-policy id.
func (p *pdr) resultSize() int {
	if p.downlink() {
		return resultSize + 4
	}
	return resultSize
}

// meterSlots is the two-level meter stack a PDR carries: its own rate-bearing
// QER first, the session's shared one second. A PDR that names only the shared
// QER puts it in the first slot -- there is no flow bucket to police before
// it, and a meter id in level 1 is what every graph read before the stack.
func meterSlots(p *pdr) (uint32, uint32) {
	if p.ownMeterID == 0 {
		return p.sharedMeterID, 0
	}
	return p.ownMeterID, p.sharedMeterID
}

func fteidKeysOf(p *pdr) []map[string]any {
	families := p.endpointFamilies
	if len(families) == 0 {
		families = []uint8{p.endpointFamily}
	}
	keys := make([]map[string]any, 0, len(families))
	for _, family := range families {
		var address []byte
		if family == 6 {
			v := p.endpointIPv6.As16()
			address = v[:]
		} else {
			v := p.endpointIPv4.As4()
			address = v[:]
		}
		keys = append(keys, fteidKey(p.endpointID, uint32(family), address, p.teid))
	}
	return keys
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
		dir := c.direction(p)
		keys, err := p.ruleKeys(dir.PDRFields)
		if err != nil {
			// The session's rules were written with these keys, so this is a
			// PDI that changed under a live session: fail the deletion rather
			// than leave the rule behind.
			return fmt.Errorf("PDR %d: %w", p.id, err)
		}
		for _, key := range keys {
			add(bess.Change{Resource: c.res(pdrTable(p.downlink())), Key: key})
		}
	}
	// And the ARP entries the session's subscriber addresses hold: the address
	// is the session's, so a deletion that left the entry behind would keep
	// answering for a UE this UPF no longer carries. `all` holds a moved
	// address's old form too, and the dedupe above is what keeps one entry from
	// being named twice.
	for _, p := range all {
		if e, ok := c.arpEntryOf(p); ok {
			add(e.erasure())
		}
	}
	for _, p := range all {
		dir := c.direction(p)
		for _, t := range p.tunnels {
			add(bess.Change{Resource: t, Key: map[string]any{"action_id": p.actionID}})
		}
		if p.teid != 0 {
			for _, key := range fteidKeysOf(p) {
				add(bess.Change{Resource: c.teidRes(), Key: key})
			}
		}
		if dir.Counters != "" && len(p.urrIDs) > 0 && p.actionID != 0 {
			add(bess.Change{Resource: c.res(counterTable(p.downlink())), Key: map[string]any{"action_id": p.actionID}})
		}
		// A PDR that buffers is counted by a *second* module, in front of the
		// store, and compile writes its entry too (writeBufferCounter). The
		// deletion erased only the direction's counter, so the buffering
		// module's entry outlived the session: it is what says "arrivals are
		// news" for the DDN path, and nothing else would ever take it out. The
		// next session to use the daemon then read a table that was not empty
		// (ci/buffer-path.sh's second test, "cnt_buf already measures 1 rules
		// before any session exists").
		if p.buffer && p.actionID != 0 && c.cfg.Buffering != nil && c.cfg.Buffering.Counter != "" {
			add(bess.Change{Resource: c.res(BufferCounters), Key: map[string]any{"action_id": p.actionID}})
		}
		// The store's per-flow "flows" entry is the session's too: compile
		// writes the SMF's own numbers there (writeFlowEntry), and it is
		// configuration, not the packets -- the drop command below frees those.
		// A deletion that left the entry would hand a later session that reuses
		// the ActionId a timeout and a cap the SMF never sent it.
		if p.buffer && p.actionID != 0 && c.cfg.Buffering != nil && c.cfg.Buffering.Store != "" {
			add(bess.Change{Resource: c.res(Flows), Key: map[string]any{"id": p.actionID}})
		}
	}
	// A MAR's policy and the two tunnel records its accesses name are the
	// session's records too. A MAR a modification removed is on the list for
	// the same reason a removed PDR's records are: it is out of the model but
	// still in the dataplane until this transaction erases it.
	if c.cfg.Atsss != "" {
		for _, m := range append(marsInOrder(s), s.removedMARs...) {
			if m.policyID != 0 {
				add(bess.Change{Resource: c.res(Policies),
					Key: map[string]any{"policy_id": m.policyID}})
			}
			for _, id := range m.tunnelIDs {
				if id != 0 {
					add(bess.Change{Resource: c.res(TunnelsDownlink),
						Key: map[string]any{"action_id": id}})
				}
			}
		}
		for _, id := range s.retiredTunnels {
			add(bess.Change{Resource: c.res(TunnelsDownlink),
				Key: map[string]any{"action_id": id}})
		}
	}
	// Meters belong to QERs, not to PDRs: compile writes one per policed
	// direction whether or not a PDR names it, so a deletion erases them from
	// the same list. Erasing them per PDR instead would miss the meter of a
	// direction no PDR of this session uses, and would name the QER's meter
	// once per PDR. A QER a modification removed is on the list too: its record
	// is in the daemon, and a record nobody names goes on holding the rate it
	// was written with until another session reuses the id.
	for _, q := range append(qersInOrder(s), s.removedQERs...) {
		if !q.hasRate {
			continue
		}
		if q.meterUL != 0 {
			add(bess.Change{Resource: c.res(MetersUplink), Key: map[string]any{"id": q.meterUL}})
		}
		if q.meterDL != 0 {
			add(bess.Change{Resource: c.res(MetersDownlink), Key: map[string]any{"id": q.meterDL}})
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
		c.releaseFTEIDClaim(s, p, false)
	}
	// A CHID's F-TEID remains owned while a PDR names it. Keeping a released
	// CHID would hand a recycled TEID to a later PDR and let sessions claim the
	// same complete admission key.
	for chid, chosen := range s.chids {
		if !chosenNamed(s, chosen) {
			delete(s.chids, chid)
			if len(c.fteidTEIDKeys[chosen.TEID]) == 0 {
				c.teids.release(chosen.TEID)
			}
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
		dir := c.direction(p)
		if keys, err := p.ruleKeys(dir.PDRFields); err == nil {
			for _, key := range keys {
				live[c.res(pdrTable(p.downlink()))+"\x00"+fmt.Sprint(key)] = true
			}
		}
	}
	// The ARP claims of the session's own subscriber addresses, held with the
	// entries they write (arpEntry.claim).
	for _, p := range s.PDRs {
		if e, ok := c.arpEntryOf(p); ok {
			live[e.claim()] = true
		}
	}
	for _, p := range gones {
		dir := c.direction(p)
		keys, err := p.ruleKeys(dir.PDRFields)
		if err != nil {
			continue
		}
		for _, key := range keys {
			rkey := c.res(pdrTable(p.downlink())) + "\x00" + fmt.Sprint(key)
			if !live[rkey] && c.rules[rkey] == s.LocalSEID {
				delete(c.rules, rkey)
				s.forgetRuleKey(rkey)
			}
		}
	}
	// And an ARP claim the same way: the entry a PDR of the session still names
	// is live, and one that moved or went is not.
	for _, p := range gones {
		e, ok := c.arpEntryOf(p)
		if !ok {
			continue
		}
		if claim := e.claim(); !live[claim] && c.rules[claim] == s.LocalSEID {
			delete(c.rules, claim)
			s.forgetRuleKey(claim)
		}
	}
	// A MAR the transaction removed, and a tunnel record an update retired,
	// are gone from the dataplane now; return their ids after the commit.
	// Keeping them until session deletion would exhaust the pools on repeated
	// create/remove or tunneled-to-plain updates.
	policies := map[uint32]bool{}
	tunnels := map[uint32]bool{}
	for _, m := range s.removedMARs {
		if m.policyID != 0 && !policies[m.policyID] {
			policies[m.policyID] = true
			c.policies.release(m.policyID)
		}
		for _, id := range m.tunnelIDs {
			if id != 0 && !tunnels[id] {
				tunnels[id] = true
				c.actions.release(id)
			}
		}
	}
	for _, id := range s.retiredTunnels {
		if id != 0 && !tunnels[id] {
			tunnels[id] = true
			c.actions.release(id)
		}
	}
	s.retiredTunnels = nil
	s.removed, s.stale, s.ending, s.removedMARs = nil, nil, nil, nil
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
	actions := map[uint32]bool{}
	policies := map[uint32]bool{}
	meters := map[uint32]bool{}
	all := pdrsInOrder(s)
	// A PDR a modification removed still holds ids, and a replaced PDR's old
	// form holds the TEID it used to have: the records are erased by the
	// deletion above, and the ids are freed here with the rest.
	all = append(all, s.removed...)
	all = append(all, s.stale...)
	for _, p := range all {
		c.releaseFTEIDClaim(s, p, true)
		if p.actionID != 0 && !actions[p.actionID] {
			actions[p.actionID] = true
			c.actions.release(p.actionID)
		}
	}
	for _, chosen := range s.chids {
		if len(c.fteidTEIDKeys[chosen.TEID]) == 0 {
			c.teids.release(chosen.TEID)
		}
	}
	clear(s.chids)
	// The meters are the QERs': one per policed direction, allocated with the
	// QER and not with the PDRs that happen to name it. A QER a modification
	// removed is one of them: the removal took it out of the model, so this is
	// where its ids come back.
	for _, m := range append(marsInOrder(s), s.removedMARs...) {
		if m.policyID != 0 && !policies[m.policyID] {
			policies[m.policyID] = true
			c.policies.release(m.policyID)
		}
		for _, id := range m.tunnelIDs {
			if id != 0 && !actions[id] {
				actions[id] = true
				c.actions.release(id)
			}
		}
	}
	for _, id := range s.retiredTunnels {
		if id != 0 && !actions[id] {
			actions[id] = true
			c.actions.release(id)
		}
	}
	for _, q := range append(qersInOrder(s), s.removedQERs...) {
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

// invalidateOrderCache clears the sorted slices cached during compilation.
func (s *Session) invalidateOrderCache() {
	if s != nil {
		s.cachedPDRs = nil
		s.cachedQERs = nil
		s.cachedMARs = nil
	}
}
