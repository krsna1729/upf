# The fork's Router, and this UPF's gaps

This UPF asks the Router one question per packet: *which gate does this forward
leave by*. The answer is decided when the session is installed -- the FAR's
egress is resolved to a hop id then (`internal/session/compile.go`, the action
record) -- so the deployment's Router is a hop table on the packet path, not a
routing table. Part 1 is what the fork's Router does today, read in this tree
and named by file and line. Part 2 is what routing inside a network instance
would need, and where each piece goes; nothing there is implemented, and
`docs/compliance.md` records the consequence (one next hop per instance, per
installation).

## Part 1 - what the Router does

| fact | where |
|---|---|
| One Router owns both halves: the per-domain FIBs (an LPM each) and the next hops every domain's routes share. A route is `(domain, IPv4 dst) --LPM--> NextHopId --slot table--> NextHop`; a domain id is an index into a dense array of `max_domains` slots published through a SlotTable, so a reader resolves a domain with one acquire load, no lock and no search, and an unknown or out-of-range domain is a miss | `core/route/router.h:104-135`, `core/route/route_domain.h` |
| The module's packet path resolves **only** the hop id the packet carries. `Router::ProcessBatch` reads `next_hop_id` from packet metadata, `LookupNextHops` maps a whole burst of ids to `NextHop` objects in one call, and the gate is `hop->egress` (`interface = gate + 1`, D-049). The module never consults a FIB | `core/modules/router.cc:300-345` |
| An unresolved hop fails closed: a hop whose neighbour state is not `kResolved`, or one that names neither MAC, drops the packet; `OnEvent(PreResume)` reports an unreadable `next_hop_id` attribute once instead of dropping silently | `core/modules/router.cc:300-345`, `:285-298` |
| A hop that names both `dst_mac` and `src_mac` has the frame's Ethernet addresses rewritten in place (`route::RewriteL2`, BESS D-153); a hop that names one or none forwards the header it arrived with. A shared payload is copied first, so a rewrite never writes into a buffer another module holds | `core/modules/router.cc:320-345`, `core/route/l3_packet.h` |
| The configuration is the module's own resource: `<module>/next_hops`, keyed by hop id, each value `{dst_mac, src_mac, egress_gate}`. Our graphs write ids 1-5: 1 the data network's hop (a MAC pair), 2 the access side's (through the encap), 3 a tunnel out of the instance (the encap again), 4 the service LAN's, 5 the 5G VN re-injection | `deploy/upf.yaml`, `deploy/iface-path.yaml` (`rt/next_hops`) |
| Hops are not scoped by domain: `LookupNextHops` takes ids and nothing else. Only routes are (`RouteKey` carries the domain). Two network instances that leave by the same hop share it | `core/route/router.h:478-490`, `:104-135` |
| The library has the routing half: `LookupRoute(domain, dst)`, `SetRoute`, `ReplaceRouteSetAtomic` (strict replacement of one domain's whole route set), ECMP groups (`groups_`, `LookupGroup`), and a neighbor table. None of it is on the module's packet path | `core/route/router.h:223-280`, `:430-500` |

## Part 2 - the gaps, each with its seam

**(a) A FIB lookup on the packet path.** A deployment whose instance has more
than one destination behind one interface -- a transit N6 with many prefixes, an
N9 peer chosen by address, an ECMP set -- cannot be provisioned today: the
compiler resolves one hop per instance at installation time
(`routing.Interface.Hops` -> `p.nextHop` -> the action record), so every packet
of that instance leaves by that gate. The library side is ready
(`LookupRoute`, the domain's LPM); what is missing is a policy for *when* the
module routes instead of forwarding the id it was given. The natural one: a
hop id of 0 means "not named" (the same convention `RewriteL2` uses for a zero
MAC), so the module routes a packet whose action record carries 0, in the domain
the packet's `route_domain` names, to the hop the FIB resolves -- and drops it
where the FIB has no route. That needs an argument saying which attribute holds
the destination (the graph's key already knows: `dst_ip` is in every deployed
PDR table) and a resource for the routes themselves (`route::LpmResource`
exists, `core/route/lpm_resource.h`). It is a module change, ours or the fork's;
no part of it is in the packet path's way until a deployment asks for it.

**(b) Connected and local routes.** Nothing derives them. An interface that
knows its own address and domain (`Vif`'s `interfaces`: `ip_addr`,
`route_domain`) is the natural input and `SetRoute`/`ReplaceRouteSetAtomic` the
output, so a deployment could write one interface line instead of every prefix
it serves; today the graph's resources are written by hand, and a prefix the
deployment's own interface holds must be listed like any other. This is the
cheapest of the three and the one a lab deployment feels first (a `Vif` whose
address is reachable only because someone wrote a route for it).

**(c) A neighbour resolver module.** `route::NeighborTable`
(`core/route/neighbor_table.h`) is complete and control-side: `Bind` ties a hop
to an `(interface, IPv4)` neighbour, `Update` records what resolution learned
and returns the hops to republish, `Publish` writes them into a Router, and a
learned neighbour and a controller's statement end in the same `NextHop`. The
header says plainly what is missing: "No ARP is sent or answered here ... a
resolver module is the application's", and nothing in `core/modules/` drives the
table (`grep -l NeighborTable core/modules/` is empty). Our deployment writes
both MACs of every hop, so `RewriteL2` always has a pair and no resolution is
needed; a data network whose next hop moves (a router that answers for a virtual
address, a peer whose MAC changes) needs the module: send the request
(`BuildArpRequest`), parse the reply (`ParseArp`), and publish what `Update`
returns. Until then, a MAC that changes is a control-plane edit, not packet-side
learning.

What follows from (a)-(c) for the deployment as it stands: the UPF's own
egresses are hop ids decided per FAR, the compiler refuses an egress the
instance does not declare (`internal/routing`), and the one place a routed
deployment is recorded as limited is the FAR's Destination Interface and Network
Instance being "where the traffic leaves by, not a next hop"
(`docs/compliance.md`, "routing inside a network instance").
