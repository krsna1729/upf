// SPDX-License-Identifier: BSD-3-Clause
#include "upf_appliance.h"

#include <algorithm>
#include <ctime>
#include <format>
#include <limits>
#include "framework/plugin.h"
#include "utils/ip.h"

using namespace upf::appliance;
namespace upb = upf::pb;

const ResourceTables UpfAppliance::resource_tables = {
    ResourceTable::Map<upb::FteidKey, upb::FteidEntry>("fteids"),
    ResourceTable::Map<bess::pb::WildcardMatchRuleKey, bess::pb::WildcardMatchRuleValue>("pdr_ul"),
    ResourceTable::Map<bess::pb::WildcardMatchRuleKey, bess::pb::WildcardMatchRuleValue>("pdr_dl"),
    ResourceTable::Map<bess::pb::MeterIdKey, bess::pb::MeterPolicyValue>("meters").Rebuilds(),
    ResourceTable::Map<upb::CounterKey, upb::CounterEntry>("counters_ul"),
    ResourceTable::Map<upb::CounterKey, upb::CounterEntry>("counters_dl"),
    ResourceTable::Map<upb::CounterKey, upb::CounterEntry>("buffer_counters"),
    ResourceTable::Map<upb::TunnelKey, upb::TunnelEntry>("tunnels"),
    ResourceTable::Map<upb::AtsssSteeringPolicyKey, upb::AtsssSteeringPolicy>("policies"),
    ResourceTable::Map<upb::AtsssAccessHealthKey, upb::AtsssAccessHealth>("health"),
    ResourceTable::Map<upb::UpfArpResponderEntryKey, upb::UpfArpResponderEntryValue>("entries"),
    ResourceTable::Map<bess::pb::PacketStoreFlowKey, bess::pb::PacketStoreFlowValue>("flows").Rebuilds(),
    ResourceTable::Map<bess::pb::RouterNextHopIdKey, bess::pb::RouterNextHopValue>("next_hops"),
    ResourceTable::Map<bess::pb::RouterNextHopIdKey, bess::pb::RouterNeighborBinding>("neighbors"),
    ResourceTable::Map<bess::pb::RouterNextHopIdKey, bess::pb::RouterNextHopState>("next_hop_state"),
    ResourceTable::Map<bess::pb::RouterGroupIdKey, bess::pb::RouterGroupValue>("groups"),
    ResourceTable::Map<bess::pb::RouterRouteKey, bess::pb::RouterRouteValue>("routes"),
    ResourceTable::Map<bess::pb::RouterNextHopIdKey, bess::pb::RouterNextHopValue>("transport_next_hops"),
    ResourceTable::Map<bess::pb::RouterNextHopIdKey, bess::pb::RouterNeighborBinding>("transport_neighbors"),
    ResourceTable::Map<bess::pb::RouterNextHopIdKey, bess::pb::RouterNextHopState>("transport_next_hop_state"),
    ResourceTable::Map<bess::pb::RouterGroupIdKey, bess::pb::RouterGroupValue>("transport_groups"),
    ResourceTable::Map<bess::pb::RouterRouteKey, bess::pb::RouterRouteValue>("transport_routes"),
};
// The session-major layout: "sessions" replaces fteids, pdr_ul/pdr_dl,
// counters_ul/counters_dl and tunnels; "meters" holds shared meters only.
const ResourceTables UpfSessionAppliance::resource_tables = {
    ResourceTable::Map<upb::UpfSessionKey, upb::UpfSession>("sessions"),
    ResourceTable::Map<bess::pb::MeterIdKey, bess::pb::MeterPolicyValue>("meters").Rebuilds(),
    ResourceTable::Map<upb::CounterKey, upb::CounterEntry>("buffer_counters"),
    ResourceTable::Map<upb::AtsssSteeringPolicyKey, upb::AtsssSteeringPolicy>("policies"),
    ResourceTable::Map<upb::AtsssAccessHealthKey, upb::AtsssAccessHealth>("health"),
    ResourceTable::Map<upb::UpfArpResponderEntryKey, upb::UpfArpResponderEntryValue>("entries"),
    ResourceTable::Map<bess::pb::PacketStoreFlowKey, bess::pb::PacketStoreFlowValue>("flows").Rebuilds(),
    ResourceTable::Map<bess::pb::RouterNextHopIdKey, bess::pb::RouterNextHopValue>("next_hops"),
    ResourceTable::Map<bess::pb::RouterNextHopIdKey, bess::pb::RouterNeighborBinding>("neighbors"),
    ResourceTable::Map<bess::pb::RouterNextHopIdKey, bess::pb::RouterNextHopState>("next_hop_state"),
    ResourceTable::Map<bess::pb::RouterGroupIdKey, bess::pb::RouterGroupValue>("groups"),
    ResourceTable::Map<bess::pb::RouterRouteKey, bess::pb::RouterRouteValue>("routes"),
    ResourceTable::Map<bess::pb::RouterNextHopIdKey, bess::pb::RouterNextHopValue>("transport_next_hops"),
    ResourceTable::Map<bess::pb::RouterNextHopIdKey, bess::pb::RouterNeighborBinding>("transport_neighbors"),
    ResourceTable::Map<bess::pb::RouterNextHopIdKey, bess::pb::RouterNextHopState>("transport_next_hop_state"),
    ResourceTable::Map<bess::pb::RouterGroupIdKey, bess::pb::RouterGroupValue>("transport_groups"),
    ResourceTable::Map<bess::pb::RouterRouteKey, bess::pb::RouterRouteValue>("transport_routes"),
};
const Commands UpfAppliance::cmds = {
    {"get_counts", "upf.pb.UrrCountCommandGetCountsArg", MODULE_CMD_FUNC(&UpfAppliance::CommandGetCounts), Command::THREAD_SAFE, "upf.pb.UrrCountCommandGetCountsResponse"},
    {"drain_errors", "upf.pb.GtpuResponderCommandDrainErrorsArg", MODULE_CMD_FUNC(&UpfAppliance::CommandDrainErrors), Command::THREAD_SAFE, "upf.pb.GtpuResponderCommandDrainErrorsResponse"},
    {"drain_end_markers", "upf.pb.GtpuResponderCommandDrainEndMarkersArg", MODULE_CMD_FUNC(&UpfAppliance::CommandDrainEndMarkers), Command::THREAD_SAFE, "upf.pb.GtpuResponderCommandDrainEndMarkersResponse"},
    {"release", "bess.pb.PacketStoreCommandReleaseArg", MODULE_CMD_FUNC(&UpfAppliance::CommandRelease), Command::THREAD_SAFE},
    {"drop", "bess.pb.PacketStoreCommandDropArg", MODULE_CMD_FUNC(&UpfAppliance::CommandDrop), Command::THREAD_SAFE},
    {"clear", "bess.pb.PacketStoreCommandClearArg", MODULE_CMD_FUNC(&UpfAppliance::CommandClear), Command::THREAD_SAFE},
    {"get_drops", "bess.pb.EmptyArg", MODULE_CMD_FUNC(&UpfAppliance::CommandGetDrops), Command::THREAD_SAFE, "upf.pb.UpfApplianceCommandGetDropsResponse"},
    {"self_test", "bess.pb.EmptyArg", MODULE_CMD_FUNC(&UpfAppliance::CommandSelfTest), Command::THREAD_UNSAFE},
};

UpfAppliance::UpfAppliance() : UpfAppliance(false) {}
UpfAppliance::UpfAppliance(bool session_layout) : session_layout_(session_layout) {
  max_allowed_workers_ = 1;
}
UpfAppliance::~UpfAppliance() = default;

CommandResponse UpfAppliance::Init(const upb::UpfApplianceArg &arg) {
  if (arg.decap().port() > 65535 || arg.encap().src_port() > 65535 ||
      arg.encap().dst_port() > 65535)
    return CommandFailure(EINVAL, "invalid UDP port");
  if (arg.meter().levels() != 0 && arg.meter().levels() != 2)
    return CommandFailure(EINVAL, "meter levels must be 2");
  if (!session_layout_ && arg.has_session())
    return CommandFailure(EINVAL, "'session' configures UpfSessionAppliance, not UpfAppliance");
  if (!arg.encap().tunnel_attr().empty() || !arg.atsss().policy_attr().empty() ||
      !arg.atsss().next_hop_attr().empty() || !arg.atsss().tunnel_attr().empty() ||
      !arg.atsss().accounting_attr().empty())
    return CommandFailure(EINVAL, "UpfAppliance does not use metadata attributes");
  const uint64_t stamp = arg.recovery_time_stamp() ? arg.recovery_time_stamp() :
      static_cast<uint64_t>(std::time(nullptr)) + upf::datapath::kGtpuEpoch1900;
  if (stamp > std::numeric_limits<uint32_t>::max())
    return CommandFailure(EINVAL, "recovery_time_stamp exceeds 32 bits");
  stamp_ = stamp;
  port_ = arg.decap().port() ? arg.decap().port() : 2152;
  src_port_ = arg.encap().src_port();
  dst_port_ = arg.encap().dst_port() ? arg.encap().dst_port() : 2152;
  capacity_ = arg.counters().capacity() ? arg.counters().capacity() : 65536;
  if (arg.interfaces_size() == 0)
    return CommandFailure(EINVAL, "at least one interface is required");
  // These are immutable tables too: admission precedes their backing storage.
  const size_t interface_bytes = arg.interfaces_size() * sizeof(Interface);
  interfaces_lease_ = init_context().memory().Lease("interfaces", interface_bytes, interface_bytes);
  interfaces_.reserve(arg.interfaces_size());
  for (const auto &in : arg.interfaces()) {
    if (in.ingress_gate() >= MAX_GATES || in.output_gate() >= MAX_GATES ||
        in.id() == 0 || in.id() > MAX_GATES || in.vlan() > 4095 ||
        (!in.n6() && in.endpoint_id() == 0))
      return CommandFailure(EINVAL, "invalid interface gate/id/VLAN/endpoint");
    Interface iface;
    iface.ingress_gate = in.ingress_gate();
    iface.output_gate = in.output_gate();
    iface.id = in.id();
    iface.vlan = in.vlan();
    iface.n6 = in.n6();
    iface.endpoint_id = in.endpoint_id();
    iface.route_domain = in.route_domain();
    iface.transport_route_domain = in.transport_route_domain();
    if (!iface.mac.FromString(in.mac_addr()) || iface.mac.IsZero())
      return CommandFailure(EINVAL, "invalid interface MAC");
    if (!in.ip_addr().empty() && !bess::utils::ParseIpv4Address(in.ip_addr(), &iface.ipv4))
      return CommandFailure(EINVAL, "invalid interface IPv4 address");
    if (!in.ipv6_addr().empty()) {
      auto ip = bess::utils::ParseIpv6Address(in.ipv6_addr());
      if (!ip) return CommandFailure(EINVAL, "invalid interface IPv6 address");
      iface.ipv6 = *ip;
    }
    for (const auto &old : interfaces_) {
      if ((old.n6 == iface.n6 && old.id == iface.id) ||
          (old.ingress_gate == iface.ingress_gate && old.vlan == iface.vlan && old.mac == iface.mac) ||
          (old.ingress_gate == iface.ingress_gate && old.n6 != iface.n6))
        return CommandFailure(EINVAL, "ambiguous interface id or ingress match");
    }
    interfaces_.push_back(iface);
  }
  for (const auto &marker : arg.marker_inputs()) {
    if (marker.ingress_gate() >= MAX_GATES || marker.interface_id() == 0 ||
        std::none_of(interfaces_.begin(), interfaces_.end(), [&](const auto &i) {
          return !i.n6 && i.id == marker.interface_id();
        }) || std::any_of(interfaces_.begin(), interfaces_.end(), [&](const auto &i) {
          return i.ingress_gate == marker.ingress_gate();
        }) || std::any_of(marker_inputs_.begin(), marker_inputs_.end(), [&](const auto &m) {
          return m.ingress_gate() == marker.ingress_gate();
        }))
      return CommandFailure(EINVAL, "invalid or duplicate marker ingress");
    marker_inputs_.push_back(marker);
  }
  for (const auto &c : arg.next_hop_classes()) {
    if (c.egress_gate() >= MAX_GATES || c.output_gate() >= MAX_GATES ||
        !upb::UpfApplianceNextHopClass_Action_IsValid(c.action()) ||
        std::any_of(next_hop_classes_.begin(), next_hop_classes_.end(), [&](const auto &old) {
          return old.egress_gate() == c.egress_gate();
        }))
      return CommandFailure(EINVAL, "invalid or duplicate next-hop class");
    next_hop_classes_.push_back(c);
  }
  if (next_hop_classes_.empty())
    return CommandFailure(EINVAL, "next_hop_classes must map inner Router gates");
  auto response = InitResources(arg);
  if (response.error().code()) return response;
  response = InitSlow(arg);
  if (response.error().code()) return response;
  response = InitBuffer(arg);
  if (response.error().code()) return response;
  meter_metric_ = init_context().metrics().Register([this](bess::stats::MetricWriter &writer) {
    constexpr const char *directions[] = {"ul", "dl"};
    constexpr const char *colors[] = {"green", "yellow", "red"};
    for (size_t direction = 0; direction < 2; ++direction) {
      for (size_t color = 0; color < 3; ++color) {
        writer.Counter("bess_upf_meter_packets_total",
            "Packets by final QER meter color",
            static_cast<double>(meter_colors_[direction][color].load(std::memory_order_relaxed)),
            {{"module", name()}, {"direction", directions[direction]}, {"color", colors[color]}});
      }
    }
  });
  return CommandSuccess();
}

void UpfAppliance::DeInit() {
  meter_metric_.Reset();
  ReleaseBuffer();
  ReleaseSlow();
  ReleaseResources();
}

const Interface *UpfAppliance::FindInterface(uint16_t ingress, uint16_t vlan,
    const bess::utils::Ethernet::Address &mac) const noexcept {
  for (const auto &i : interfaces_)
    if (i.ingress_gate == ingress && i.vlan == vlan && i.mac == mac) return &i;
  return nullptr;
}

CommandResponse UpfAppliance::CommandDrainErrors(const upb::GtpuResponderCommandDrainErrorsArg &) {
  upb::GtpuResponderCommandDrainErrorsResponse out;
  if (errors_) {
    for (const auto &event : errors_->Drain()) out.add_teids(event.teid);
    out.set_dropped(errors_->Dropped());
  }
  return CommandSuccess(out);
}
CommandResponse UpfAppliance::CommandDrainEndMarkers(const upb::GtpuResponderCommandDrainEndMarkersArg &) {
  upb::GtpuResponderCommandDrainEndMarkersResponse out;
  if (end_markers_) {
    for (const auto &event : end_markers_->Drain()) {
      auto *e = out.add_end_markers(); e->set_endpoint_id(event.endpoint_id); e->set_teid(event.teid);
    }
    out.set_dropped(end_markers_->Dropped());
  }
  return CommandSuccess(out);
}

CommandResponse UpfAppliance::CommandGetDrops(const bess::pb::EmptyArg &) {
  static constexpr const char *names[] = {
    "unknown_input", "short_ethernet", "unknown_mac", "bad_vlan", "not_writable",
    "malformed_gtpu", "nonlinear", "bad_inner", "decap_no_room", "pdr_short",
    "pdr_miss", "pdr_drop", "pdr_gate", "meter_unknown", "meter_red", "no_policy",
    "no_access", "no_next_hop", "unresolved", "local_hop", "router_malformed",
    "ttl_expired", "bad_egress", "repass_limit", "no_tunnel", "encap_failed",
    "transport_not_ip", "transport_malformed", "transport_fragment", "transport_family",
    "transport_link_scope", "transport_no_route", "transport_unresolved", "transport_local",
    "transport_ttl", "transport_egress", "control_peer_error", "control_end_marker",
    "control_nonlinear", "control_malformed", "control_port", "control_type",
    "control_zero_teid", "control_l3", "control_no_room", "arp_short", "arp_not_request",
    "arp_unknown", "nd_unknown", "neighbor_input_full", "neighbor_tx_full", "neighbor_alloc",
    "neighbor_publish", "buffer_evicted", "buffer_expired", "buffer_dropped",
    "buffer_request_full", "buffer_state_full", "neighbor_consumed",
    "end_marker_relay_unsent", "session_gone"};
  static_assert(std::size(names) == static_cast<size_t>(Reason::kCount));
  upb::UpfApplianceCommandGetDropsResponse out;
  for (size_t i = 0; i < std::size(names); ++i) {
    auto *e = out.add_drops(); e->set_reason(names[i]);
    e->set_count(reasons_[i].load(std::memory_order_relaxed));
  }
  return CommandSuccess(out);
}
CheckConstraintResult UpfAppliance::CheckModuleConstraints() const {
  auto result = Module::CheckModuleConstraints();
  // Every bank has the same planes; buffer_counters exists in both layouts.
  // One plane is written by whichever worker runs the module.
  if (buffer_counters_.cells && buffer_counters_.cells->workers() > 1) {
    for (size_t wid = buffer_counters_.cells->workers(); wid < active_workers().size(); ++wid)
      if (active_workers()[wid]) {
        LOG(ERROR) << name() << ": active worker id exceeds counter worker_planes";
        return CHECK_FATAL_ERROR;
      }
  }
  return result;
}
std::string UpfAppliance::GetDesc() const {
  uint64_t drops = 0;
  for (const auto &n : reasons_) drops += n.load(std::memory_order_relaxed);
  return std::format("{} interfaces, {}{} UL / {} DL PDRs, {} counted outcomes", interfaces_.size(),
      sessions_ ? std::format("{} sessions, ", sessions_->LiveCount()) : std::string(),
      pdr_ul_.table ? pdr_ul_.table->size() : 0, pdr_dl_.table ? pdr_dl_.table->size() : 0, drops);
}
ADD_MODULE(UpfAppliance, "upf_appliance", "owns the complete UPF user plane; no graph or fallback")
ADD_MODULE(UpfSessionAppliance, "upf_session_appliance",
           "UpfAppliance with the session-major layout: one entry per PFCP session, rewritten live")
