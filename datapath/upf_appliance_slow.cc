// SPDX-License-Identifier: BSD-3-Clause
#include "upf_appliance.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <limits>
#include <optional>
#include "arp_proxy.h"
#include "dataplane/resource_registry.h"
#include "framework/module_tick.h"
#include "packet_pool.h"
#include "route/forward.h"
#include "route/neighbor_resolver.h"
#include "worker.h"

namespace {
namespace route = bess::route;
namespace dp = bess::dataplane;
namespace fw = bess::framework;
using upf::appliance::Interface;
using upf::appliance::Lane;
using Ethernet = bess::utils::Ethernet;
using Resolver = route::NeighborResolver;

// One worker produces receive frames; the control-side tick produces wire
// solicitations. Fixed slots are admitted with Slow, with no packet allocation
// or control-frame payload copy on the receive path.
template <typename T, size_t N> struct Spsc {
  std::array<T, N> slots{};
  alignas(64) std::atomic<size_t> producer{0};
  alignas(64) std::atomic<size_t> consumer{0};
  bool Push(const T &value) noexcept {
    const size_t p = producer.load(std::memory_order_relaxed);
    if (p - consumer.load(std::memory_order_acquire) == N) return false;
    slots[p % N] = value;
    producer.store(p + 1, std::memory_order_release);
    return true;
  }
  bool Pop(T &value) noexcept {
    const size_t c = consumer.load(std::memory_order_relaxed);
    if (c == producer.load(std::memory_order_acquire)) return false;
    value = slots[c % N];
    consumer.store(c + 1, std::memory_order_release);
    return true;
  }
};
struct RxFrame { bess::PacketHandle packet = nullptr; uint16_t interface = 0; };
struct ArpCopy {
  std::array<uint8_t, route::kArpFrameSize> frame{};
  uint16_t interface = 0;
};
struct NeighborSide {
  fw::Sized<Resolver> resolver;
  Spsc<RxFrame, 1024> rx;
  Spsc<ArpCopy, 256> arp;
  Spsc<Resolver::Solicitation, 256> tx;
  fw::MemoryLease pending_lease;
  route::NeighborTable::Updates pending;
};

std::expected<Resolver::InterfaceAddress, std::string> Cidr(const std::string &text) {
  const size_t slash = text.find('/');
  if (slash == std::string::npos || slash + 1 == text.size() ||
      text.size() - slash - 1 > 3) return std::unexpected("interface address needs CIDR prefix");
  unsigned prefix = 0;
  for (size_t i = slash + 1; i < text.size(); ++i) {
    if (text[i] < '0' || text[i] > '9') return std::unexpected("invalid CIDR prefix");
    prefix = prefix * 10 + static_cast<unsigned>(text[i] - '0');
  }
  Resolver::InterfaceAddress out;
  bess::utils::be32_t v4;
  const std::string address = text.substr(0, slash);
  if (bess::utils::ParseIpv4Address(address, &v4)) {
    if (prefix > 32) return std::unexpected("invalid IPv4 prefix length");
    out.address = route::NeighborAddress::Ipv4(v4.value());
  } else if (auto v6 = bess::utils::ParseIpv6Address(address)) {
    if (prefix > 128) return std::unexpected("invalid IPv6 prefix length");
    out.address = route::NeighborAddress::Ipv6(*v6);
  } else return std::unexpected("invalid interface address");
  out.prefix_length = static_cast<uint8_t>(prefix);
  return out;
}
std::expected<Resolver::Config, std::string> ResolverConfig(
    const upf::pb::UpfApplianceRouterArg &a, size_t hops, uint64_t tick_us) {
  Resolver::Config c;
  if (a.max_neighbors() > hops) return std::unexpected("max_neighbors exceeds max_next_hops");
  c.capacity = a.max_neighbors() ? a.max_neighbors() : std::min<size_t>(1024, hops);
  std::string error;
  auto ms = [&](bool present, uint64_t value, uint64_t fallback, bool zero) {
    value = present ? value : fallback;
    if ((!zero && value == 0) || value > std::numeric_limits<uint64_t>::max() / 1000)
      error = "invalid neighbor timing";
    return value;
  };
  const uint64_t first = ms(a.has_neighbor_first_probe_ms(), a.neighbor_first_probe_ms(), 1000, true);
  const uint64_t interval = ms(a.has_neighbor_probe_interval_ms(), a.neighbor_probe_interval_ms(), 1000, false);
  const uint64_t maximum = ms(a.has_neighbor_max_probe_interval_ms(), a.neighbor_max_probe_interval_ms(), 8000, false);
  const uint64_t lifetime = ms(a.has_neighbor_reachable_lifetime_ms(), a.neighbor_reachable_lifetime_ms(), 30000, true);
  const uint64_t retry = ms(a.has_neighbor_unreachable_retry_ms(), a.neighbor_unreachable_retry_ms(), 8000, true);
  if (maximum < interval) error = "neighbor backoff ceiling is below interval";
  if (a.has_neighbor_max_probes() && a.neighbor_max_probes() == 0) error = "neighbor_max_probes must be nonzero";
  if (!error.empty()) return std::unexpected(error);
  const auto ticks = [tick_us](uint64_t value) {
    const uint64_t us = value * 1000;
    return us / tick_us + (us % tick_us != 0);
  };
  c.timing = {.first_probe = ticks(first), .probe_interval = ticks(interval),
      .max_probe_interval = ticks(maximum),
      .max_probes = a.has_neighbor_max_probes() ? a.neighbor_max_probes() : 3,
      .reachable_lifetime = ticks(lifetime), .unreachable_retry = ticks(retry)};
  return c;
}

std::expected<dp::ResourceKey, std::string> HopKey(const bess::pb::RouterNextHopIdKey &key) {
  if (key.id() == 0) return std::unexpected("next hop id 0 is invalid");
  return dp::EncodeKey(route::NextHopId(key.id()));
}
std::expected<Ethernet::Address, std::string> Mac(const std::string &s) {
  if (s.empty()) return Ethernet::Address{};
  if (s.size() != Ethernet::Address::kSize) return std::unexpected("MAC must have 6 bytes");
  return Ethernet::Address(reinterpret_cast<const uint8_t *>(s.data()));
}
std::expected<std::any, std::string> Hop(const bess::pb::RouterNextHopValue &v) {
  if (!bess::IsValidGateValue(v.egress_gate())) return std::unexpected("invalid egress gate");
  auto src = Mac(v.src_mac()), dst = Mac(v.dst_mac());
  if (!src) return std::unexpected(src.error());
  if (!dst) return std::unexpected(dst.error());
  route::NextHop h;
  h.egress = dp::InterfaceId(static_cast<uint16_t>(v.egress_gate() + 1));
  h.src_mac = *src; h.dst_mac = *dst;
  switch (v.neighbor()) {
    case bess::pb::ROUTER_NEIGHBOR_STATE_UNSPECIFIED:
    case bess::pb::ROUTER_NEIGHBOR_STATE_RESOLVED: h.neighbor = route::NeighborState::kResolved; break;
    case bess::pb::ROUTER_NEIGHBOR_STATE_INCOMPLETE: h.neighbor = route::NeighborState::kIncomplete; break;
    case bess::pb::ROUTER_NEIGHBOR_STATE_UNREACHABLE: h.neighbor = route::NeighborState::kUnreachable; break;
    default: return std::unexpected("invalid neighbor state");
  }
  switch (v.kind()) {
    case bess::pb::ROUTER_NEXT_HOP_KIND_UNSPECIFIED:
    case bess::pb::ROUTER_NEXT_HOP_KIND_FORWARD: h.kind = route::NextHopKind::kForward; break;
    case bess::pb::ROUTER_NEXT_HOP_KIND_LOCAL:
      if ((v.egress_gate() != 0 && v.egress_gate() != DROP_GATE) || !src->IsZero() || !dst->IsZero())
        return std::unexpected("local hop names no egress or MAC");
      h.kind = route::NextHopKind::kLocal; h.egress = dp::kInvalidInterfaceId; break;
    default: return std::unexpected("invalid next hop kind");
  }
  // DROP_GATE is the graph's blackhole, not interface 8193.
  if (v.egress_gate() == DROP_GATE) h.egress = dp::kInvalidInterfaceId;
  return std::any(h);
}
bess::pb::RouterNextHopValue HopPb(const route::NextHop &h) {
  bess::pb::RouterNextHopValue v;
  if (h.kind == route::NextHopKind::kLocal) {
    v.set_kind(bess::pb::ROUTER_NEXT_HOP_KIND_LOCAL); return v;
  }
  v.set_egress_gate(h.egress == dp::kInvalidInterfaceId ? DROP_GATE : h.egress.value() - 1);
  if (h.neighbor == route::NeighborState::kIncomplete) v.set_neighbor(bess::pb::ROUTER_NEIGHBOR_STATE_INCOMPLETE);
  if (h.neighbor == route::NeighborState::kUnreachable) v.set_neighbor(bess::pb::ROUTER_NEIGHBOR_STATE_UNREACHABLE);
  if (!h.src_mac.IsZero()) v.set_src_mac(reinterpret_cast<const char *>(h.src_mac.bytes), 6);
  if (!h.dst_mac.IsZero()) v.set_dst_mac(reinterpret_cast<const char *>(h.dst_mac.bytes), 6);
  return v;
}
std::expected<std::any, std::string> Neighbor(const bess::pb::RouterNeighborBinding &v) {
  if (!v.interface_id() || v.interface_id() > 0xffff || v.ipv4().empty() == v.ipv6().empty())
    return std::unexpected("neighbor needs valid interface and exactly one address");
  dp::InterfaceId id(static_cast<uint16_t>(v.interface_id()));
  if (!v.ipv4().empty()) {
    bess::utils::be32_t ip;
    if (!bess::utils::ParseIpv4Address(v.ipv4(), &ip)) return std::unexpected("invalid neighbor IPv4");
    return std::any(route::NeighborKey(id, ip.value()));
  }
  const auto ip = bess::utils::ParseIpv6Address(v.ipv6());
  if (!ip) return std::unexpected("invalid neighbor IPv6");
  return std::any(route::NeighborKey(id, *ip));
}
bess::pb::RouterNeighborBinding NeighborPb(const route::NeighborKey &key) {
  bess::pb::RouterNeighborBinding v;
  v.set_interface_id(key.interface.value());
  if (key.address.is_ipv4()) v.set_ipv4(bess::utils::ToIpv4Address(bess::utils::be32_t(key.address.ipv4())));
  else v.set_ipv6(bess::utils::ToIpv6Address(key.address.ipv6()));
  return v;
}
std::expected<dp::ResourceKey, std::string> RouteKey(const bess::pb::RouterRouteKey &k) {
  if (k.domain() >= route::kMaxRouteDomains || k.ipv4().empty() == k.ipv6().empty())
    return std::unexpected("route needs valid domain and exactly one prefix");
  const route::RouteDomainId domain(k.domain());
  if (!k.ipv4().empty()) {
    bess::utils::be32_t ip;
    if (k.prefix_length() > 32 || !bess::utils::ParseIpv4Address(k.ipv4(), &ip)) return std::unexpected("invalid IPv4 prefix");
    auto p = route::Ipv4Prefix::Make(ip.value(), static_cast<uint8_t>(k.prefix_length()));
    if (!p) return std::unexpected(route::RouteErrorName(p.error()));
    return route::Router::RouteKey(domain, *p);
  }
  const auto ip = bess::utils::ParseIpv6Address(k.ipv6());
  if (!ip || k.prefix_length() > 128) return std::unexpected("invalid IPv6 prefix");
  auto p = route::Ipv6Prefix::Make(*ip, static_cast<uint8_t>(k.prefix_length()));
  if (!p) return std::unexpected(route::RouteErrorName(p.error()));
  return route::Router::RouteKey(domain, *p);
}
void BindRouter(fw::ResourceBindings &codecs, route::Router &r, bool destination,
                std::vector<fw::ResourceBinding> &bindings) {
  auto *router = &r;
  bindings.push_back(codecs.Bind(*r.next_hops_resource_object(),
      std::make_shared<fw::TypedCodec<bess::pb::RouterNextHopIdKey, bess::pb::RouterNextHopValue>>(
      HopKey, Hop, [router](const auto &visit) {
        router->ForEachNextHop([&](route::NextHopId id, const route::NextHop &h) {
          if (router->IsNeighborBound(id)) return;
          bess::pb::RouterNextHopIdKey k; k.set_id(id.value()); visit(k, HopPb(h));
        });
      })));
  bindings.push_back(codecs.Bind(*r.neighbors_resource_object(),
      std::make_shared<fw::TypedCodec<bess::pb::RouterNextHopIdKey, bess::pb::RouterNeighborBinding>>(
      HopKey, Neighbor, [router](const auto &visit) {
        router->ForEachNeighborBinding([&](route::NextHopId id, const route::NeighborKey &n) {
          bess::pb::RouterNextHopIdKey k; k.set_id(id.value()); visit(k, NeighborPb(n));
        });
      })));
  bindings.push_back(codecs.Bind(*r.next_hop_state_resource_object(),
      std::make_shared<fw::TypedCodec<bess::pb::RouterNextHopIdKey, bess::pb::RouterNextHopState>>(
      HopKey, [](const bess::pb::RouterNextHopState &v) -> std::expected<std::any, std::string> {
        return std::any(route::NextHopState{v.down()});
      }, [router](const auto &visit) {
        router->ForEachNextHopState([&](route::NextHopId id, const route::NextHopState &s) {
          bess::pb::RouterNextHopIdKey k; k.set_id(id.value());
          bess::pb::RouterNextHopState v; v.set_down(s.down); visit(k, v);
        });
      })));
  bindings.push_back(codecs.Bind(*r.groups_resource_object(),
      std::make_shared<fw::TypedCodec<bess::pb::RouterGroupIdKey, bess::pb::RouterGroupValue>>(
      [destination](const bess::pb::RouterGroupIdKey &k) -> std::expected<dp::ResourceKey, std::string> {
        if (!destination) return std::unexpected("next-hop-only router has no groups");
        if (!k.id()) return std::unexpected("group id 0 is invalid");
        return dp::EncodeKey(route::NextHopGroupId(k.id()));
      }, [](const bess::pb::RouterGroupValue &v) -> std::expected<std::any, std::string> {
        const size_t active = v.member_ids_size(), standby = v.standby_member_ids_size();
        if (!active || active + standby > route::NextHopGroup::kMaxMembers) return std::unexpected("invalid group size");
        route::NextHopGroup g; g.size = active; g.standby_size = standby;
        for (size_t i = 0; i < active; ++i) {
          if (!v.member_ids(i)) return std::unexpected("group member id 0 is invalid");
          g.members[i] = route::NextHopId(v.member_ids(i));
        }
        for (size_t i = 0; i < standby; ++i) {
          if (!v.standby_member_ids(i)) return std::unexpected("group standby id 0 is invalid");
          g.members[active + i] = route::NextHopId(v.standby_member_ids(i));
        }
        return std::any(g);
      }, [router](const auto &visit) {
        router->ForEachNextHopGroup([&](route::NextHopGroupId id, const route::NextHopGroup &g) {
          bess::pb::RouterGroupIdKey k; k.set_id(id.value()); bess::pb::RouterGroupValue v;
          for (auto id : g.actives()) v.add_member_ids(id.value());
          for (auto id : g.standbys()) v.add_standby_member_ids(id.value());
          visit(k, v);
        });
      })));
  bindings.push_back(codecs.Bind(*r.routes_resource_object(),
      std::make_shared<fw::TypedCodec<bess::pb::RouterRouteKey, bess::pb::RouterRouteValue>>(
      [destination](const bess::pb::RouterRouteKey &k) -> std::expected<dp::ResourceKey, std::string> {
        if (!destination) return std::unexpected("next-hop-only router has no routes");
        return RouteKey(k);
      }, [](const bess::pb::RouterRouteValue &v) -> std::expected<std::any, std::string> {
        if (v.next_hop_id() && !v.group_id()) return std::any(route::NextHopId(v.next_hop_id()));
        if (v.group_id() && !v.next_hop_id()) return std::any(route::NextHopGroupId(v.group_id()));
        return std::unexpected("route names exactly one next hop or group");
      }, [router](const auto &visit) {
        router->ForEachRoute([&](const route::RouteKey &id, route::NextHopId h, route::NextHopGroupId g) {
          bess::pb::RouterRouteKey k; k.set_domain(id.domain.value());
          k.set_ipv4(bess::utils::ToIpv4Address(bess::utils::be32_t(id.prefix.addr())));
          k.set_prefix_length(id.prefix.length()); bess::pb::RouterRouteValue v;
          if (g.value()) v.set_group_id(g.value()); else v.set_next_hop_id(h.value());
          visit(k, v);
        });
        router->ForEachIpv6Route([&](route::RouteDomainId d, route::Ipv6Prefix p,
                                    route::NextHopId h, route::NextHopGroupId g) {
          bess::pb::RouterRouteKey k; k.set_domain(d.value());
          k.set_ipv6(bess::utils::ToIpv6Address(p.addr())); k.set_prefix_length(p.length());
          bess::pb::RouterRouteValue v;
          if (g.value()) v.set_group_id(g.value()); else v.set_next_hop_id(h.value());
          visit(k, v);
        });
      })));
}
void QueueUpdates(NeighborSide &s, std::span<const std::pair<route::NextHopId, route::NextHop>> updates) {
  for (const auto &u : updates) {
    auto it = std::find_if(s.pending.begin(), s.pending.end(), [&](const auto &p) { return p.first == u.first; });
    if (it == s.pending.end()) s.pending.push_back(u); else it->second = u.second;
  }
}
}  // namespace

struct UpfAppliance::Slow {
  fw::MemoryLease lease;
  NeighborSide inner, transport;
  std::vector<fw::ResourceBinding> bindings;
  fw::TickEndpoint tick;
  ~Slow() {
    tick = fw::TickEndpoint{};
    bindings.clear();
    RxFrame frame;
    for (auto *s : {&inner, &transport}) while (s->rx.Pop(frame)) bess::PacketFree(frame.packet);
  }
  void BindingChanges(UpfAppliance &owner, NeighborSide &s, route::Router &r, uint64_t now) {
    auto changes = r.TakeNeighborBindingChanges();
    if (changes.empty()) return;
    std::stable_sort(changes.begin(), changes.end(), [](const auto &a, const auto &b) { return a.id < b.id; });
    size_t n = 0;
    for (const auto &c : changes) {
      if (n && changes[n - 1].id == c.id) changes[n - 1] = c;
      else changes[n++] = c;
    }
    changes.resize(n);
    std::erase_if(s.pending, [&](const auto &p) {
      return std::binary_search(changes.begin(), changes.end(), route::NeighborBindingChange{p.first, {}},
          [](const auto &a, const auto &b) { return a.id < b.id; });
    });
    const auto install = [&](const auto &c, bool count) {
      auto h = s.resolver->Bind(c.id, *c.neighbor, now);
      if (!h) { if (count) owner.Count(Reason::kNeighborPublish); return false; }
      const std::pair<route::NextHopId, route::NextHop> u{c.id, *h};
      QueueUpdates(s, std::span(&u, 1)); return true;
    };
    std::vector<bool> installed(changes.size(), false);
    {
      struct Deferred { Resolver &r; ~Deferred() { r.ForgetUnbound(); } } deferred{*s.resolver};
      s.resolver->DeferForgetting();
      // Preserve learned identities before releasing bindings: two keys swapped
      // at capacity must not be forgotten and re-created as incomplete.
      for (size_t i = 0; i < changes.size(); ++i)
        if (changes[i].neighbor && s.resolver->StatusOf(*changes[i].neighbor)) installed[i] = install(changes[i], false);
      for (size_t i = 0; i < changes.size(); ++i)
        if (!installed[i] && s.resolver->BindingOf(changes[i].id) != changes[i].neighbor) s.resolver->Unbind(changes[i].id);
    }
    for (size_t i = 0; i < changes.size(); ++i)
      if (!installed[i] && changes[i].neighbor) install(changes[i], true);
  }
  void Service(UpfAppliance &owner, NeighborSide &s, route::Router &r, fw::TickContext &ctx) {
    const uint64_t now = ctx.tick();
    BindingChanges(owner, s, r, now);
    RxFrame rx;
    for (unsigned i = 0; i < 64 && !ctx.Expired() && s.rx.Pop(rx); ++i) {
      bess::PacketRef pkt(rx.packet);
      const std::span<const uint8_t> bytes(pkt.head_data<const uint8_t *>(), pkt.head_len());
      const dp::InterfaceId id(rx.interface);
      const bool arp = reinterpret_cast<const Ethernet *>(bytes.data())->ether_type.value() == Ethernet::kArp;
      auto progress = arp ? s.resolver->OnArp(now, id, bytes) : s.resolver->OnNd(now, id, bytes);
      QueueUpdates(s, progress.updates);
      bess::PacketFree(rx.packet);
    }
    ArpCopy copy;
    for (unsigned i = 0; i < 64 && !ctx.Expired() && s.arp.Pop(copy); ++i)
      QueueUpdates(s, s.resolver->OnArp(now, dp::InterfaceId(copy.interface), copy.frame).updates);
    if (!ctx.Expired()) {
      auto progress = s.resolver->Poll(now, 64);
      QueueUpdates(s, progress.updates);
      for (const auto &q : progress.solicitations) if (!s.tx.Push(q)) owner.Count(Reason::kNeighborTxFull);
    }
    const size_t take = std::min<size_t>(64, s.pending.size());
    if (!take) return;
    std::vector<dp::Op> ops; ops.reserve(take);
    for (size_t i = 0; i < take; ++i) ops.push_back(r.SetNeighborManagedNextHopOp(s.pending[i].first, s.pending[i].second));
    const dp::Resource *owned[] = {r.neighbors_resource_object()};
    auto result = owner.init_context().resources().ApplyOwned(owned, ops);
    if (result.outcome == dp::ResourceRegistry::OwnedApplyResult::Outcome::kApplied)
      s.pending.erase(s.pending.begin(), s.pending.begin() + static_cast<ptrdiff_t>(take));
    else owner.Count(Reason::kNeighborPublish);
  }
};

CommandResponse UpfAppliance::InitSlow(const upf::pb::UpfApplianceArg &arg) {
  auto &memory = init_context().memory();
  auto lease = memory.Lease("slow", sizeof(Slow), sizeof(Slow));
  slow_ = std::make_shared<Slow>(); slow_->lease = std::move(lease);
  const auto tick_us = init_context().ticks().interval().count();
  if (tick_us <= 0) return CommandFailure(EINVAL, "appliance neighbor and buffer timers need maintenance loop");
  const uint64_t now = init_context().ticks().current_tick();
  for (bool transport : {false, true}) {
    const auto &a = transport ? arg.transport_router() : arg.router();
    auto &target = transport ? transport_router_ : router_;
    auto &side = transport ? slow_->transport : slow_->inner;
    const size_t hops = a.max_next_hops() ? a.max_next_hops() : 4096;
    const size_t domains = a.max_domains() ? a.max_domains() : (transport ? 3 : 1);
    if (!transport && (a.max_ipv4_routes() || a.max_ipv6_routes() || a.max_groups() || domains != 1))
      return CommandFailure(EINVAL, "inner router is next-hop-only");
    route::Router::Config config;
    if (transport) {
      route::LpmRouteTable::Config v4; v4.max_routes = a.max_ipv4_routes() ? a.max_ipv4_routes() : 64;
      route::Ipv6RouteTable::Config v6; v6.max_routes = a.max_ipv6_routes() ? a.max_ipv6_routes() : 64;
      config.ipv4 = v4; config.ipv6 = v6;
    }
    auto resolver_config = ResolverConfig(a, hops, static_cast<uint64_t>(tick_us));
    if (!resolver_config) return CommandFailure(EINVAL, "%s", resolver_config.error().c_str());
    const std::string prefix = name() + (transport ? "/transport_" : "/");
    const route::RouterResourceNames resources{prefix + "next_hops", prefix + "neighbors",
        prefix + "next_hop_state", prefix + "routes", prefix + "groups"};
    const std::string build = name() + (transport ? "_transport" : "_inner");
    auto router_lease = memory.LeaseFor<route::Router>(transport ? "transport_router" : "router",
        build, config, hops, init_context().rcu(), domains, a.max_groups(), resources);
    auto resolver_lease = memory.LeaseFor<Resolver>(transport ? "transport_resolver" : "resolver", *resolver_config, now);
    auto router = route::Router::Create(build, config, hops, init_context().rcu(), domains, a.max_groups(), resources);
    if (!router) return CommandFailure(route::RouteErrno(router.error()), "%s", route::RouteErrorName(router.error()));
    target = fw::MemoryScope::Adopt(std::move(router_lease), std::move(*router));
    auto resolver = Resolver::Create(*resolver_config, now);
    if (!resolver) return CommandFailure(EINVAL, "%s", resolver.error().c_str());
    side.resolver = fw::MemoryScope::Adopt(std::move(resolver_lease), std::move(*resolver));
    const size_t pending_bytes = resolver_config->capacity * sizeof(route::NeighborTable::Updates::value_type);
    side.pending_lease = memory.Lease(transport ? "transport_neighbor_updates" : "neighbor_updates",
        pending_bytes, pending_bytes);
    side.pending.reserve(resolver_config->capacity);
    for (const auto &entry : arg.interfaces()) {
      if (entry.n6() == transport) continue;
      Resolver::Interface iface{dp::InterfaceId(static_cast<uint16_t>(entry.id())), {}, {}};
      if (!iface.mac.FromString(entry.mac_addr()) || iface.mac.IsZero()) return CommandFailure(EINVAL, "invalid resolver interface MAC");
      for (const auto &text : entry.addresses()) {
        auto address = Cidr(text);
        if (!address) return CommandFailure(EINVAL, "%s", address.error().c_str());
        iface.addresses.push_back(*address);
      }
      if (iface.addresses.empty()) return CommandFailure(EINVAL, "resolver interface needs CIDR addresses");
      auto result = side.resolver->ConfigureInterface(iface, now);
      if (!result) return CommandFailure(EINVAL, "%s", result.error().c_str());
    }
    route::NeighborBindingPolicy policy;
    policy.capacity = resolver_config->capacity;
    policy.validate = [resolver = side.resolver.get()](const route::NeighborKey &key) { return resolver->CheckBind(key); };
    auto policy_result = target->SetNeighborBindingPolicy(std::move(policy));
    if (!policy_result) return CommandFailure(route::RouteErrno(policy_result.error()), "%s", route::RouteErrorName(policy_result.error()));
    auto enrolled = target->Enroll(init_context().resources());
    if (!enrolled) return CommandFailure(EINVAL, "%s", enrolled.error().c_str());
    BindRouter(init_context().codecs(), *target, transport, slow_->bindings);
  }
  if (RegisterTask(nullptr) == INVALID_TASK_ID) return CommandFailure(ENOMEM, "appliance task registration failed");
  slow_->tick = fw::TickEndpoint(init_context().ticks(), std::chrono::steady_clock::duration::zero(),
      [this](fw::TickContext &ctx) {
        slow_->Service(*this, slow_->inner, *router_, ctx);
        slow_->Service(*this, slow_->transport, *transport_router_, ctx);
      });
  return CommandSuccess();
}

void UpfAppliance::ReleaseSlow() {
  if (slow_) { slow_->tick = fw::TickEndpoint{}; slow_->bindings.clear(); }
  for (auto *router : {router_.get(), transport_router_.get()}) if (router) {
    auto result = router->Release();
    if (!result) LOG(ERROR) << "UpfAppliance router release: " << result.error();
  }
  router_.reset(); transport_router_.reset(); slow_.reset();
}

bool UpfAppliance::SlowIngress(Context *, bess::PacketRef pkt, uint16_t ingress,
                               uint16_t vlan, State &s) {
  const auto bytes = std::span(pkt.head_data<uint8_t *>(), pkt.head_len());
  if (bytes.size() < sizeof(Ethernet)) return false;
  const auto *eth = reinterpret_cast<const Ethernet *>(bytes.data());
  const bool arp = eth->ether_type.value() == Ethernet::kArp;
  const bool nd = eth->ether_type.value() == Ethernet::kIpv6 && bytes.size() > 54 &&
      bytes[20] == route::kIpv6NextHeaderIcmpv6 && (bytes[54] == 135 || bytes[54] == 136);
  if (!arp && !nd) return false;
  const Interface *base = nullptr;
  for (const auto &iface : interfaces_) {
    if (iface.ingress_gate != ingress || iface.vlan != vlan) continue;
    if (!base || eth->dst_addr == iface.mac) base = &iface;
    if (arp && !iface.n6 && route::AnswerArpRequest(bytes, iface.mac, iface.ipv4)) {
      s.interface = &iface; s.output_gate = iface.output_gate; s.lane = Lane::kOutput; return true;
    }
    if (nd && bytes[54] == 135 && (pkt.is_linear() || pkt.head_len() == route::kNdFrameSize)) {
      const size_t capacity = pkt.head_len() + (pkt.is_linear() ? pkt.tailroom() : 0);
      const size_t answered = route::AnswerNeighborSolicitation(bytes, iface.mac, iface.ipv6,
          {pkt.head_data<uint8_t *>(), capacity});
      if (answered) {
        if (pkt.is_linear()) {
          pkt.set_data_len(static_cast<uint16_t>(answered));
          pkt.set_total_len(static_cast<uint32_t>(answered));
        }
        s.interface = &iface; s.output_gate = iface.output_gate; s.lane = Lane::kOutput; return true;
      }
    }
  }
  if (!base) { Drop(s, Reason::kUnknownInput); return true; }
  s.interface = base;
  // N6 ARP enters the resolver/proxy before MAC admission. All other peer
  // control follows Vif's destination-MAC admission after own requests above.
  if (!(arp && base->n6)) {
    base = FindInterface(ingress, vlan, eth->dst_addr);
    if (!base) { Drop(s, Reason::kUnknownMac); return true; }
    s.interface = base;
  }
  if (!slow_) { Drop(s, Reason::kNeighborInputFull); return true; }
  auto &side = base->n6 ? slow_->inner : slow_->transport;
  const auto queue = [&] {
    if (!side.rx.Push(RxFrame{pkt.handle(), base->id})) { Drop(s, Reason::kNeighborInputFull); return; }
    Count(Reason::kNeighborConsumed);
    s.lane = Lane::kHeld;
  };
  if (arp) {
    if (bytes.size() < route::kArpFrameSize) { Drop(s, Reason::kArpShort); return true; }
    const auto *message = reinterpret_cast<const bess::utils::Arp *>(bytes.data() + sizeof(Ethernet));
    if (base->n6) {
      if (message->opcode.value() == bess::utils::Arp::kRequest) {
        ArpCopy original; original.interface = base->id;
        std::memcpy(original.frame.data(), bytes.data(), original.frame.size());
        if (!side.arp.Push(original)) Count(Reason::kNeighborInputFull);
        else Count(Reason::kNeighborConsumed);
        const auto verdict = upf::arp::AnswerProxyRequest(bytes, [this](uint32_t ip) { return entries_->Lookup(ip); });
        if (verdict == upf::arp::ProxyVerdict::kReply) {
          s.output_gate = base->output_gate; s.lane = Lane::kOutput;
        } else Drop(s, verdict == upf::arp::ProxyVerdict::kTooShort ? Reason::kArpShort : Reason::kArpUnknown);
      } else { Count(Reason::kArpNotRequest); queue(); }
    } else if (message->opcode.value() == bess::utils::Arp::kReply) {
      const bool own = std::any_of(interfaces_.begin(), interfaces_.end(), [&](const auto &iface) {
        return !iface.n6 && iface.ipv4 == message->sender_ip_addr;
      });
      if (own) { s.output_gate = base->output_gate; s.lane = Lane::kOutput; }
      else queue();
    } else Drop(s, Reason::kArpNotRequest);
  } else if (bytes[54] == 136) {
    const bool own = std::any_of(interfaces_.begin(), interfaces_.end(), [&](const auto &iface) {
      return iface.n6 == base->n6 && std::memcmp(bytes.data() + 22, iface.ipv6.bytes, 16) == 0;
    });
    if (own) { s.output_gate = base->output_gate; s.lane = Lane::kOutput; }
    else queue();
  }
  else Drop(s, Reason::kNdUnknown);
  return true;
}

void UpfAppliance::Transport(bess::PacketBatch *batch, State *states, size_t n) {
  bool done[bess::PacketBatch::kMaxBurst]{};
  for (size_t first = 0; first < n; ++first) {
    if (done[first] || states[first].lane != Lane::kTransport) continue;
    const uint32_t domain = states[first].transport_route_domain;
    std::span<const uint8_t> frames[bess::PacketBatch::kMaxBurst];
    size_t lengths[bess::PacketBatch::kMaxBurst], indices[bess::PacketBatch::kMaxBurst];
    route::FrameRoute routes[bess::PacketBatch::kMaxBurst];
    size_t count = 0;
    for (size_t i = first; i < n; ++i) if (!done[i] && states[i].lane == Lane::kTransport &&
        states[i].transport_route_domain == domain) {
      auto pkt = batch->packet(i);
      frames[count] = {pkt.head_data<const uint8_t *>(), pkt.head_len()};
      lengths[count] = pkt.total_len(); indices[count++] = i; done[i] = true;
    }
    route::ResolveFrames(*transport_router_, route::RouteDomainId(domain),
        std::span(frames, count), std::span(lengths, count), std::span(routes, count));
    for (size_t j = 0; j < count; ++j) {
      auto &s = states[indices[j]]; const auto &r = routes[j];
      using V = route::ForwardVerdict;
      Reason reason = Reason::kTransportMalformed;
      switch (r.verdict) {
        case V::kForward: {
          const Interface *egress = nullptr;
          for (const auto &iface : interfaces_) if (!iface.n6 && iface.id == r.egress.value()) { egress = &iface; break; }
          if (!egress) { Drop(s, Reason::kTransportEgress); continue; }
          auto pkt = batch->packet(indices[j]);
          route::WriteForwarded({pkt.head_data<uint8_t *>(), pkt.head_len()}, r.family, r.l3_offset, *r.hop);
          s.output_gate = egress->output_gate; s.lane = Lane::kOutput; continue;
        }
        case V::kNotIp: reason = Reason::kTransportNotIp; break;
        case V::kMalformed: reason = Reason::kTransportMalformed; break;
        case V::kNonInitialFragment: reason = Reason::kTransportFragment; break;
        case V::kFamilyDisabled: reason = Reason::kTransportFamily; break;
        case V::kLinkScope: reason = Reason::kTransportLinkScope; break;
        case V::kNoRoute: reason = Reason::kTransportNoRoute; break;
        case V::kUnresolved: reason = Reason::kTransportUnresolved; break;
        case V::kLocalDelivery: reason = Reason::kTransportLocal; break;
        case V::kTtlExpired: reason = Reason::kTransportTtl; break;
        case V::kNoEgress: reason = Reason::kTransportEgress; break;
      }
      Drop(s, reason);
    }
  }
}

struct task_result UpfAppliance::RunTask(Context *ctx, bess::PacketBatch *batch, void *) {
  batch->clear();
  uint32_t emitted = 0; uint64_t bits = 0;
  if (slow_) for (bool transport : {false, true}) {
    auto &side = transport ? slow_->transport : slow_->inner;
    Resolver::Solicitation item;
    for (size_t i = 0; i < bess::PacketBatch::kMaxBurst && side.tx.Pop(item); ++i) {
      const Interface *egress = nullptr;
      for (const auto &iface : interfaces_) if (iface.n6 != transport && iface.id == item.egress.value()) { egress = &iface; break; }
      if (!egress) { Count(Reason::kBadEgress); continue; }
      const auto handle = current_worker.packet_pool()->Alloc(item.length);
      if (handle == nullptr) { Count(Reason::kNeighborAlloc); continue; }
      bess::PacketRef pkt(handle);
      std::memcpy(pkt.head_data<uint8_t *>(), item.frame.data(), item.length);
      EmitPacket(ctx, pkt, egress->output_gate);
      ++emitted; bits += item.length * 8;
    }
  }
  BufferTask(ctx, batch);
  ProcessOGates(ctx);
  // Requests and released flows are worker-owned and can remain queued after
  // BufferTask consumes this burst, so this shared task must stay runnable.
  return {.block = false, .packets = emitted, .bits = bits};
}
