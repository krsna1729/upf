# Router behavior in the UPF graph

BESS `Router` (`core/modules/router.cc`, `core/route/`) has two modes and dual-stack
destination routing. `deploy/upf.yaml` uses two Router instances because inner
session forwarding and outer GTP-U routing use different keys.

## The two Router instances

| module | mode | lookup | graph role |
|---|---|---|---|
| `rt` | `ROUTE_MODE_NEXT_HOP_ID` (default) | `next_hop_id` from the PDR result | Inner session forwarding. Hop 1 reaches N6, hops 2/3 reach `GtpuEncap`, and hop 5 is the optional service-LAN re-injection path. |
| `rt_transport` | `ROUTE_MODE_DESTINATION` | IPv4/IPv6 destination in `transport_route_domain` | Routes encapsulated packets, GTP-U responses and End Markers to N3/N9. The graph configures an IPv4 and IPv6 default route in each transport domain. |

The inner Router resolves the N6 next hop and writes its Ethernet addresses.
The post-encap Router selects the N3 or N9 transport interface by destination
and domain, then resolves that interface's neighbor. Both instances use the
same Router implementation, but each has its own resources, resolver and
metadata context.

`rt_transport` sets `domain_attr: transport_route_domain`; the default is
`route_domain`. `GtpuEncap` writes the tunnel's transport domain. N3/N9 input
tags and End Marker inputs set the domain before their frames reach
`rt_transport`. The N3/N9 logical endpoints can share a physical port.

## Routes and next hops

The Router's resources are `<router>/routes`, `<router>/next_hops`, and
`<router>/groups`. A route key includes a route domain and either an IPv4 or
IPv6 prefix. Its value names a next hop or a group. In destination mode, the
most-specific route in the packet's domain wins. In next-hop mode, the
`next_hop_id` metadata selects the forwarding adjacency directly.

`deploy/upf.yaml` owns the inner next-hop gates and the outer transport FIB.
`rt_transport/routes` contains `0.0.0.0/0` and `::/0` in domains 1 and 2;
their next-hop bindings select the configured N3/N9 interface and peer. The
session compiler writes PDR results and tunnel records, not FIB routes. Route
policy remains deployment configuration; `upfd` does not install routes from
PFCP Network Instance names.

The configured `neighbor_bindings` seed incomplete next hops and assign their
IDs to the resolver. Routes can name those IDs, but a static
`<router>/next_hops` record must not overwrite a resolver-owned ID. The other
inner next hops in `deploy/upf.yaml` are static gate mappings.

## ARP and Neighbor Discovery

Both Router instances have `resolver_interfaces` and `neighbor_bindings`.
`Vif.vif_id_attr` writes `neighbor_interface_id`; Router uses that interface ID
to associate incoming ARP or IPv6 Neighbor Discovery frames with the correct
resolver interface. This metadata is separate from `route_domain`,
`transport_route_domain`, endpoint IDs and queue IDs.

Router sends received neighbor frames from workers to a bounded control-side
ring. Its maintenance path validates ARP replies and IPv6 Neighbor
Advertisements, updates the neighbor state, and publishes a complete next-hop
record. A Router task emits ARP requests or Neighbor Solicitations. Retries,
aging and failure are bounded by the configured resolver timers and
`max_neighbors`.

Unresolved or unreachable neighbors fail closed in this graph; no punt gate is
configured. A valid reply or advertisement updates the next-hop adjacency
without changing the route that names it. `docs/neighbor-resolution.md` in the
BESS tree documents identity checks, timers and publication semantics.

## Packet handling and limits

- Destination mode routes IPv4 and IPv6. It decrements IPv4 TTL and repairs the
  checksum, or decrements the IPv6 hop limit. A missing route, invalid header,
  unresolved neighbor, expired TTL/hop limit or blackhole hop is dropped and
  counted. The Router does not generate ICMP errors.
- Next-hop mode uses `next_hop_id`, rewrites L2, and decrements IPv4 TTL. It
  forwards non-IPv4 frames without a hop-count change. The deployed inner PDR
  fields are IPv4; outer transport routing supports IPv4 and IPv6.
- Route resources are static graph configuration in this deployment. The UPF
  has no routing protocol, RIB or PFCP-driven route update path.
- `UpfArpResponder` answers IPv4 ARP for the N6 interface and active UE
  addresses. `Vif` answers Neighbor Solicitations for its own interface
  address; the graph does not provide proxy NDP for the UE pool.

See `docs/datapath.md` for module and metadata ownership, `deploy/upf.yaml` for
the production graph, and `deploy/route-path.yaml` with `ci/route-path.sh` for
the destination-mode route proof.
