# The fork's Router, and this UPF's gaps

The Router is BESS's (`core/modules/router.cc`, library `core/route/router.h`).
It is the only place this repository forwards an IP packet: the classifier's
rule result writes a next-hop id (hop mode), or the packet's own destination is
looked up in its route domain (destination mode). This document records what
the Router does today, what the graph binds, and which routing work this UPF
does not do.

## What the module does

| Area | Behaviour |
|---|---|
| Packet path | `Router::ProcessBatch` reads `next_hop_id` metadata and forwards to the next hop's egress gate (hop mode, `ROUTE_MODE_NEXT_HOP_ID`, the default). In `ROUTE_MODE_DESTINATION` it reads the packet's IPv4 destination and the `route_domain` metadata the ingress `Vif` wrote, and looks the prefix up in that domain's LPM table. |
| Routes | Per-domain IPv4 LPM (`LpmRouteTable`). A route's value is a next-hop id or an ECMP group id, never both. A missing domain in an upsert creates it (`CreateDomainLocked`); domain 0 always exists. |
| Next hops | `NextHop` is an egress interface id, a neighbour state, and the destination/source MACs. `RewriteL2` writes the MACs; the module also decrements the IPv4 hop count and drops TTL 1. A hop with no egress (`kInvalidInterfaceId`) is a blackhole: the frame ends there. |
| ECMP | `NextHopGroup` holds 1..64 members; a flow picks one by a hash the module is configured with (`flow_hash`: whole flow by default, or address pair only). Membership is immutable; changing it publishes a new group. |
| Neighbour state | `kResolved`, `kIncomplete`, `kUnreachable`. The packet path forwards only a resolved hop. Hop mode drops an unresolved one; destination mode drops it or punts to `punt_unresolved_gate`. |
| Misses | In destination mode a FIB miss drops or goes to `punt_miss_gate`. Both are counted. A frame that is not IPv4, is malformed, or is a non-initial fragment is dropped and counted rather than guessed at. Hop mode forwards what the metadata names and drops the rest. |
| Resources | `next_hops` (`RouterNextHopIdKey`/`RouterNextHopValue`), `groups` (`RouterGroupIdKey`/`RouterGroupValue`), `routes` (`RouterRouteKey`/`RouterRouteValue`). Reads are canonical: defaults omitted, a resolved neighbour absent, a zero MAC absent. |
| Update modes | `SetRoute`/`RemoveRoute` are in-place and atomic per call, not per sequence. `ReplaceRouteSetAtomic` builds and validates a whole domain off to the side and publishes it with one store; a failure leaves the old set visible. A route may name only a published next hop; a next hop cannot be removed while a route names it. |
| Bounds | `max_routes`, `max_tbl8s`, `max_next_hops`, `max_domains`, `max_groups`; domains 0..`max_domains-1`, route values 24-bit. `upfd -max-domains` is checked against the same bound (`internal/routing.MaxDomains`). |
| Gates | An output gate per next-hop egress interface. The module's drop gate is where an unresolved hop, a miss without a punt gate, and a malformed header go. |

What the graph binds:

- `deploy/upf.yaml`: hop mode. `rt/next_hops` holds the deployment's five
  static hops (the data network's and the access side's with their L2 pairs, a
  tunnel out of an instance, the service LAN's, the 5G VN re-injection); gate 2
  is the uplink tunnel to the encap, gate 4 the 5G VN re-injection into
  `pdr_dl`, gate 1 the downlink encap. `max_domains` is 1.
- `deploy/route-path.yaml`: destination mode. The graph declares the routes and
  next hops; `upfd` runs with `-route-mode=destination`, so a forward's result
  names hop 0 and the Router decides from the packet's destination and domain.
  `ci/route-path.sh` proves both directions.

## Gaps in this UPF

These are controller/deployment gaps, not Router features the fork lacks. Each
row names the seam that would close it.

| Gap | What happens today | Where it would be closed |
|---|---|---|
| No route programming from the controller | `rt/routes` is static graph configuration (`deploy/route-path.yaml`). `upfd` writes sessions, meter states, tunnels and next hops, never a route or a group. A routed N6/N9 transport cannot follow the SMF's prefixes without an operator editing the graph. | A controller resource editor for `RouterRouteKey`/`RouterRouteValue` (and groups), ideally one `ReplaceRouteSetAtomic` per domain per transaction; `upfd`'s interface configs (`-instances` pools) are the natural input. |
| No connected or local routes | Nothing derives a prefix from an interface. The `Vif` knows `ip_addr` and `route_domain`; the Router knows neither, and a subscriber prefix is not in any route table. | Derive connected routes from each interface's pool/address and install local addresses as blackhole or local hops, through the same `ReplaceRouteSetAtomic` seam. |
| No neighbour resolver | Every next hop's MAC is static, written in the graph. There is no ARP/ND module that moves a hop between `kIncomplete` and `kResolved`; `punt_unresolved_gate` can only send the frame somewhere else. | A resolver module on the egress branch that watches ARP/ND replies (or a controller resolver fed by the N6 ARP traffic) and calls the `next_hops` resource with the learned MAC and state. |
| Destination mode cannot express a FAR's different instance | The Router routes in the domain the packet carries. A FAR that names another network instance would need the packet's domain rewritten between the classifier and the Router; no module does that, so the compiler refuses the FAR (`destinationHop`). | A domain-write stage between the table and the Router, or a policy-hop form for the cross-instance case. |
| No IPv6 FIB | The route tables are IPv4 (`Ipv4Prefix`, 32-bit address). IPv6 PDRs are expressible; a routed IPv6 transport is not. | A second LPM family in `LpmRouteTable`, or a separate v6 Router instance keyed by the same domain. |
| No ICMP for a dropped forward | TTL expiry and a blackhole are silent; the Router counts them (`ttl_expired_frames`, `blackholed_frames` in destination mode) and does not answer. | An ICMP module on the Router's drop path, if the deployment wants the peer to learn why. |

`docs/claims.json` carries the conformance rows; this page is the operational
inventory those rows refer to.
