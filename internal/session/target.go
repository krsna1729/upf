// SPDX-License-Identifier: BSD-3-Clause

package session

import "fmt"

// Table is one logical table: what a compiled session writes or a deployment
// owns, before any dataplane names it. The compiler decides the writes in
// these terms; a Target turns each into the resource it is.
type Table uint8

// Session tables written by the compiler. SweepResources preserves the
// historical whole-table reset list.
const (
	// FTEIDs is GTP-U admission: FteidKey -> FteidEntry.
	FTEIDs Table = iota
	// PDRUplink and PDRDownlink are the PDR classifiers: WildcardMatchRuleKey
	// -> WildcardMatchRuleValue (the result record of session.go's pdrResult).
	PDRUplink
	PDRDownlink
	// MetersUplink and MetersDownlink are the QER meters: MeterIdKey ->
	// MeterPolicyValue.
	MetersUplink
	MetersDownlink
	// CountersUplink and CountersDownlink are the URR counters: CounterKey ->
	// CounterEntry, read back by get_counts.
	CountersUplink
	CountersDownlink
	// BufferCounters counts the buffering branch's arrivals, keyed by the same
	// ActionId as the direction's counter (the Downlink Data Report's trigger).
	BufferCounters
	// TunnelsUplink and TunnelsDownlink are the GTP-U encap records:
	// TunnelKey -> TunnelEntry.
	TunnelsUplink
	TunnelsDownlink
	// Policies is ATSSS steering: AtsssSteeringPolicyKey ->
	// AtsssSteeringPolicy.
	Policies
	// Flows is the packet store's per-flow BAR numbers: PacketStoreFlowKey
	// -> PacketStoreFlowValue.
	Flows
	// The deployment's tables: a target names them, the compiler never writes
	// them and the sweep never empties them.
	//
	// Health is ATSSS access health (AtsssAccessHealthKey ->
	// AtsssAccessHealth). Each Router owns next_hops, neighbors, routes,
	// next_hop_state and groups; the transport Router uses flat
	// transport_* names. The PDR result's next_hop_id references NextHops,
	// with Neighbors as its key holder.
	Health
	NextHops
	Neighbors
	Routes
	NextHopState
	Groups
	TransportNextHops
	TransportNeighbors
	TransportRoutes
	TransportNextHopState
	TransportGroups

	tableCount
)

var tableNames = [tableCount]string{
	FTEIDs: "fteids", PDRUplink: "pdr_ul", PDRDownlink: "pdr_dl",
	MetersUplink: "meters_ul", MetersDownlink: "meters_dl",
	CountersUplink: "counters_ul", CountersDownlink: "counters_dl",
	BufferCounters: "buffer_counters",
	TunnelsUplink:  "tunnels_ul", TunnelsDownlink: "tunnels_dl",
	Policies: "policies", Flows: "flows", Health: "health",
	NextHops: "next_hops", Neighbors: "neighbors", Routes: "routes",
	NextHopState: "next_hop_state", Groups: "groups",
	TransportNextHops: "transport_next_hops", TransportNeighbors: "transport_neighbors",
	TransportRoutes: "transport_routes", TransportNextHopState: "transport_next_hop_state",
	TransportGroups: "transport_groups",
}

func (t Table) String() string {
	if t < tableCount {
		return tableNames[t]
	}
	return fmt.Sprintf("table(%d)", uint8(t))
}

// pdrTable, meterTable, counterTable and tunnelTable are a direction's table.
func pdrTable(down bool) Table     { return pick(down, PDRDownlink, PDRUplink) }
func meterTable(down bool) Table   { return pick(down, MetersDownlink, MetersUplink) }
func counterTable(down bool) Table { return pick(down, CountersDownlink, CountersUplink) }
func tunnelTable(down bool) Table  { return pick(down, TunnelsDownlink, TunnelsUplink) }

func pick(down bool, dl, ul Table) Table {
	if down {
		return dl
	}
	return ul
}

// Target is where a compiled session lands: the resource each logical table
// is, the module each command goes to, the End Marker socket of each
// transport domain and the gate a buffering rule takes. The compilation is
// the same for every target; only these names differ.
//
// Two logical tables share a resource only where their keys cannot collide
// and no entry's state outlives a move between them.
type Target interface {
	// Resource is the resource table t is, "" when this dataplane has none.
	Resource(t Table) string
	// Entries is the ARP table that answers for an interface whose -instances
	// line names responder (its arp=).
	Entries(responder string) string
	// Counts is where get_counts for counter table t goes: a module whose one
	// counter table the command reads ("cnt_ul"), or "<module>/<table>" for a
	// module that owns several, the table then named in the command's
	// argument (bess.Client.RuleCounts).
	Counts(t Table) string
	// Store is the module release, drop and clear go to; Errors the one
	// get_errors goes to; EndMarkers the one drain_end_markers goes to.
	Store() string
	Errors() string
	EndMarkers() string
	// EndMarkerSocket is the unix socket an End Marker leaves by for a
	// tunnel in transport route domain domain.
	EndMarkerSocket(domain uint32) string
	// BufferGate is the PDR rule gate that delivers on the buffering branch.
	BufferGate() uint32
	// SweepResources lists whole session tables to reset at startup, in
	// dependency order. ARP entries are swept selectively by subscriber pool.
	SweepResources() []string
}

// newTarget is the target cfg describes: the appliance when it names one,
// the graph of its module fields otherwise.
func newTarget(cfg Config) Target {
	if cfg.Appliance != "" {
		return applianceTarget{module: cfg.Appliance, cfg: cfg}
	}
	return graphTarget{cfg: cfg}
}

// endMarkerPath is <base>.<domain>: the unix port of the routed path for
// that transport domain, in both forms of the dataplane.
func endMarkerPath(base string, domain uint32) string {
	return fmt.Sprintf("%s.%d", base, domain)
}

// graphTarget is the module graph (deploy/upf.yaml): every table is
// "<module>/<table>" of the module its Config field names, a command goes to
// that module, and a module name left empty is a table the graph does not
// have.
type graphTarget struct {
	cfg Config
}

func graphResource(module, table string) string {
	if module == "" {
		return ""
	}
	return module + "/" + table
}

func (g graphTarget) Resource(t Table) string {
	c := g.cfg
	switch t {
	case FTEIDs:
		return graphResource(c.GTPUDecap, "fteids")
	case PDRUplink:
		return graphResource(c.Up.PDRTable, "rules")
	case PDRDownlink:
		return graphResource(c.Down.PDRTable, "rules")
	case MetersUplink:
		return graphResource(c.Up.Meters, "meters")
	case MetersDownlink:
		return graphResource(c.Down.Meters, "meters")
	case CountersUplink:
		return graphResource(c.Up.Counters, "counters")
	case CountersDownlink:
		return graphResource(c.Down.Counters, "counters")
	case BufferCounters:
		if c.Buffering == nil {
			return ""
		}
		return graphResource(c.Buffering.Counter, "counters")
	case TunnelsUplink:
		return graphResource(c.Up.Tunnels, "tunnels")
	case TunnelsDownlink:
		return graphResource(c.Down.Tunnels, "tunnels")
	case Policies:
		return graphResource(c.Atsss, "policies")
	case Flows:
		if c.Buffering == nil {
			return ""
		}
		return graphResource(c.Buffering.Store, "flows")
	case Health:
		return graphResource(c.Atsss, "health")
	}
	// The graph's Routers (rt, rt_transport) are named by its manifest alone:
	// no flag names them, because nothing upfd does touches them.
	return ""
}

func (g graphTarget) Entries(responder string) string { return graphResource(responder, "entries") }

func (g graphTarget) Counts(t Table) string {
	switch t {
	case CountersUplink:
		return g.cfg.Up.Counters
	case CountersDownlink:
		return g.cfg.Down.Counters
	case BufferCounters:
		if g.cfg.Buffering != nil {
			return g.cfg.Buffering.Counter
		}
	}
	return ""
}

func (g graphTarget) Store() string {
	if g.cfg.Buffering == nil {
		return ""
	}
	return g.cfg.Buffering.Store
}

func (g graphTarget) Errors() string     { return g.cfg.GTPUErrors }
func (g graphTarget) EndMarkers() string { return g.cfg.GTPUEndMarkers }

func (g graphTarget) EndMarkerSocket(domain uint32) string {
	return endMarkerPath(g.cfg.EndMarker, domain)
}

func (g graphTarget) BufferGate() uint32 {
	if g.cfg.Buffering == nil {
		return 0
	}
	return g.cfg.Buffering.Gate
}

// applianceTarget is one module that runs the whole user plane (UpfAppliance,
// between the port modules): every table is "<module>/<table>" under one
// name, and every command goes to that module.
//
// The two directions share only configuration with disjoint allocated ids:
//
//   - meters: a QER's uplink and downlink meters are two ids of one pool
//     (Compiler.meters), so no key is both, and a PDR that changes direction
//     moves to its QER's other meter rather than taking its bucket along;
//   - tunnels: keyed by ActionId, one pool (Compiler.actions) for both
//     directions and for the MAR accesses; a record is configuration only,
//     so rewriting one in place is what the graph's shared encap does too.
//
// The counters are not shared. A PDR keeps its ActionId when a modification
// changes its direction (compile.go, "An update keeps the dataplane
// identity"), and a counter's cells outlive its entry (urr_count.cc): one
// table would carry the uplink's totals into the downlink reading, and the
// URR would report them a second time as downlink usage. Two tables keep the
// graph's arithmetic, where the downlink's cells for that id start from what
// that table counted. The buffering branch's counter is a third table: it is
// keyed by the same ActionId as the direction's.
type applianceTarget struct {
	module string
	cfg    Config
}

// applianceTables are the appliance's own table names, where they differ
// from tableNames: the shared ones.
var applianceTables = map[Table]string{
	MetersUplink: "meters", MetersDownlink: "meters",
	TunnelsUplink: "tunnels", TunnelsDownlink: "tunnels",
}

// ApplianceBufferGate is the appliance's PDR rule gate for "hold in the
// store": 0 forwards, dropGate drops.
const ApplianceBufferGate = 1

func (a applianceTarget) Resource(t Table) string {
	if t >= tableCount {
		return ""
	}
	if name, ok := applianceTables[t]; ok {
		return a.module + "/" + name
	}
	return a.module + "/" + tableNames[t]
}

// Entries is one table whatever responder an interface names: the appliance
// answers ARP for every N6 interface from it, keyed by the address alone.
func (a applianceTarget) Entries(string) string { return a.module + "/entries" }

func (a applianceTarget) Counts(t Table) string {
	switch t {
	case CountersUplink, CountersDownlink, BufferCounters:
		return a.Resource(t)
	}
	return ""
}

func (a applianceTarget) Store() string      { return a.module }
func (a applianceTarget) Errors() string     { return a.module }
func (a applianceTarget) EndMarkers() string { return a.module }

func (a applianceTarget) EndMarkerSocket(domain uint32) string {
	return endMarkerPath(a.cfg.EndMarker, domain)
}

func (a applianceTarget) BufferGate() uint32 { return ApplianceBufferGate }

func (g graphTarget) SweepResources() []string     { return sweepResources(g, g.cfg) }
func (a applianceTarget) SweepResources() []string { return sweepResources(a, a.cfg) }

// Keep the graph's reset list and ordering. Policies are not in the historical
// whole-table sweep; health and routing tables belong to the deployment.
func sweepResources(target Target, cfg Config) []string {
	var names []string
	add := func(t Table, used bool) {
		name := target.Resource(t)
		if !used || name == "" {
			return
		}
		for _, have := range names {
			if have == name {
				return
			}
		}
		names = append(names, name)
	}
	add(FTEIDs, true)
	for _, d := range []struct {
		Direction
		down bool
	}{{cfg.Up, false}, {cfg.Down, true}} {
		add(pdrTable(d.down), d.PDRTable != "")
		add(meterTable(d.down), d.Meters != "")
		add(counterTable(d.down), d.Counters != "")
	}
	add(TunnelsUplink, cfg.Up.Tunnels != "")
	add(TunnelsDownlink, cfg.Down.Tunnels != "")
	buffering := cfg.Buffering != nil && cfg.Buffering.Store != "" && cfg.Buffering.Counter != ""
	add(BufferCounters, buffering)
	add(Flows, buffering)
	return names
}
