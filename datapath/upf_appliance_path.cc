// SPDX-License-Identifier: BSD-3-Clause
#include "upf_appliance.h"

#include <algorithm>
#include <array>
#include <cstring>
#include "upf_appliance_frame.h"
#include "gtpu_admission.h"
#include "packet_mutation.h"
#include "packet_reshape.h"
#include "route/forward.h"
#include "utils/time.h"

using namespace upf::appliance;
namespace gtpu = upf::datapath;
namespace route = bess::route;
namespace meter = bess::meter;
namespace classifier = bess::classifier;
namespace {
constexpr size_t kBurst = bess::PacketBatch::kMaxBurst;
bool Active(const FrameState &s) { return s.lane == Lane::kUl || s.lane == Lane::kDl; }
std::span<const uint8_t> Bytes(bess::PacketRef p) {
  return {p.head_data<const uint8_t *>(), p.head_len()};
}
}

void UpfAppliance::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  const size_t n = batch->cnt();
  State states[kBurst]{};
  gtpu::ParsedGtpu parsed[kBurst]{};
  gtpu::FteidId keys[kBurst]{};
  uint64_t values[kBurst];
  uint64_t candidates = 0;
  const uint16_t ingress = ctx->current_igate;
  const upf::pb::UpfApplianceMarkerInput *marker = nullptr;
  for (const auto &m : marker_inputs_) if (m.ingress_gate() == ingress) { marker = &m; break; }
  bool known_input = marker != nullptr;
  for (const auto &iface : interfaces_) known_input |= iface.ingress_gate == ingress;
  for (size_t i = 0; i < n; ++i) {
    auto &s = states[i];
    if (!known_input) { Drop(s, Reason::kUnknownInput); continue; }
    auto p = batch->packet(i);
    if (p.head_len() < 14) { Drop(s, Reason::kShortEthernet); continue; }
    // Port ingress normally owns the payload exclusively. Shared input needs
    // the same unavoidable copy the graph's Vif/Router make before mutation.
    auto handle = p.handle();
    if (!bess::packet::EnsureWritable(handle)) { Drop(s, Reason::kNotWritable); continue; }
    batch->handles()[i] = handle;
    p = bess::PacketRef(handle);
    if (marker != nullptr) {
      s.lane = Lane::kTransport;
      s.transport_route_domain = marker->transport_route_domain();
      continue;
    }
    uint16_t vlan = 0;
    auto *data = p.head_data<uint8_t *>();
    const auto type = gtpu::GetWire16(data + 12);
    if (type == 0x8100 || type == 0x88a8) {
      if (p.head_len() < 18) { Drop(s, Reason::kBadVlan); continue; }
      vlan = gtpu::GetWire16(data + 14) & 0xfff;
      // Vif removes one tag and preserves the following EtherType.
      std::memmove(data + 4, data, 12);
      p.adj(4);
    }
    if (SlowIngress(ctx, p, ingress, vlan, s)) continue;
    const auto *eth = p.head_data<const bess::utils::Ethernet *>();
    s.interface = FindInterface(ingress, vlan, eth->dst_addr);
    if (s.interface == nullptr) { Drop(s, Reason::kUnknownMac); continue; }
    s.endpoint_id = s.interface->endpoint_id;
    s.route_domain = s.interface->route_domain;
    s.transport_route_domain = s.interface->transport_route_domain;
    if (s.interface->n6) {
      s.lane = Lane::kDl; s.direction = 1;
      continue;
    }
    switch (gtpu::ParseGtpuAdmission(Bytes(p), p.total_len(), port_, s.endpoint_id, &parsed[i])) {
      case gtpu::GtpuParseKind::kMalformed:
        Drop(s, Reason::kMalformedGtpu); break;
      case gtpu::GtpuParseKind::kControl:
        ControlGtpu(ctx, p, s); break;
      case gtpu::GtpuParseKind::kGpdu:
        keys[i] = parsed[i].key;
        candidates |= uint64_t{1} << i;
        break;
    }
  }
  // Exactly one F-TEID bulk admission for this ingress burst, pending entries
  // included in the unknown-tunnel control path rather than admitted.
  const uint64_t hits = candidates ? fteids_->LookupBatch(
      reinterpret_cast<const std::byte *>(keys), sizeof(keys[0]), values, n) : 0;
  for (uint64_t m = candidates; m; m &= m - 1) {
    const size_t i = __builtin_ctzll(m);
    auto &s = states[i];
    auto p = batch->packet(i);
    uint32_t context = 0;
    const uint8_t direction = gtpu::FteidOutputGate((hits & (uint64_t{1} << i)) != 0, values[i], &context);
    if (direction == 2) { ControlGtpu(ctx, p, s); continue; }
    if (!p.is_linear()) { Drop(s, Reason::kNonlinear); continue; }
    const auto &g = parsed[i];
    const auto bytes = Bytes(p);
    if (g.info.tunnel.inner_offset >= bytes.size()) { Drop(s, Reason::kBadInner); continue; }
    const uint8_t version = bytes[g.info.tunnel.inner_offset] >> 4;
    if (version != 4 && version != 6) { Drop(s, Reason::kBadInner); continue; }
    const auto md = gtpu::BuildGtpuDecapMetadata(bytes, g, context);
    // Save the twelve Ethernet octets, which may overlap a later prepend.
    uint8_t macs[12];
    std::memcpy(macs, bytes.data(), sizeof(macs));
    p.adj(g.info.tunnel.inner_offset);
    auto *eth = static_cast<uint8_t *>(p.prepend(14));
    if (!eth) { Drop(s, Reason::kDecapNoRoom); continue; }
    gtpu::WriteDecapsulatedEthernetHeader(eth, macs, version);
    s.fteid_context = md.fteid_context; s.qfi = md.qfi;
    s.direction = direction; s.lane = direction ? Lane::kDl : Lane::kUl;
  }
  ClassifyPdr(batch, states, n, false);
  ClassifyPdr(batch, states, n, true);
  MeterCountRoute(ctx, batch, states, n);
  Transport(batch, states, n);
  Finish(ctx, batch, states, n);
}

void UpfAppliance::ControlGtpu(Context *ctx, bess::PacketRef p, State &s) {
  const gtpu::GtpuControlContext c{.port = port_, .recovery_time_stamp = stamp_,
      .errors = errors_.get(), .end_markers = end_markers_.get(), .worker = ctx->wid.value()};
  const auto v = gtpu::AnswerGtpuControl(p, c, [&] { return s.endpoint_id; });
  if (gtpu::IsGtpuReply(v)) { s.lane = Lane::kTransport; return; }
  // Verdict order is stable in the shared helper; every consumed/drop reason
  // is distinct, and drain_errors/drain_end_markers expose the detailed events.
  switch (v) {
    case gtpu::GtpuControlVerdict::kPeerErrorIndication: Drop(s, Reason::kControlPeerError); break;
    case gtpu::GtpuControlVerdict::kEndMarker: Drop(s, Reason::kControlEndMarker); break;
    case gtpu::GtpuControlVerdict::kNotLinear: Drop(s, Reason::kControlNonlinear); break;
    case gtpu::GtpuControlVerdict::kMalformed: Drop(s, Reason::kControlMalformed); break;
    case gtpu::GtpuControlVerdict::kNotOurPort: Drop(s, Reason::kControlPort); break;
    case gtpu::GtpuControlVerdict::kUnsupportedType: Drop(s, Reason::kControlType); break;
    case gtpu::GtpuControlVerdict::kZeroTeid: Drop(s, Reason::kControlZeroTeid); break;
    case gtpu::GtpuControlVerdict::kUnsupportedL3: Drop(s, Reason::kControlL3); break;
    case gtpu::GtpuControlVerdict::kNoRoom: Drop(s, Reason::kControlNoRoom); break;
    default: break;
  }
}

void UpfAppliance::ClassifyPdr(bess::PacketBatch *batch, State *states, size_t n, bool dl) {
  auto &pdr = dl ? pdr_dl_ : pdr_ul_;
  std::byte keys[kBurst][22];
  uint8_t positions[kBurst];
  classifier::ConcurrentMaskedTable::Match matches[kBurst];
  size_t count = 0;
  for (size_t i = 0; i < n; ++i) {
    auto &s = states[i];
    if (s.lane != (dl ? Lane::kDl : Lane::kUl)) continue;
    if (!BuildPdrKey(Bytes(batch->packet(i)), dl, s.route_domain, s.fteid_context, s.qfi, keys[count])) {
      Drop(s, Reason::kPdrShort); continue;
    }
    positions[count++] = i;
  }
  const uint64_t hits = count ? pdr.table->LookupBatch(
      classifier::ConstBytes(&keys[0][0], sizeof(keys)), sizeof(keys[0]), matches, count) : 0;
  // UpfSessionAppliance: the rule's result id is the session, its version and
  // the action position -- no record, no index; stage-major, so the batch's
  // config lines are fetched together, then bound.
  const ActionConfig *configs[kBurst];
  for (size_t k = 0; k < count; ++k) {
    auto &s = states[positions[k]];
    configs[k] = nullptr;
    if (!(hits & (uint64_t{1} << k))) { Drop(s, Reason::kPdrMiss); continue; }
    const auto &match = matches[k];
    if (match.gate == DROP_GATE) { Drop(s, Reason::kPdrDrop); continue; }
    if (match.gate != 0 && match.gate != 1) { Drop(s, Reason::kPdrGate); continue; }
    const uint32_t result = pdr.table->RuleAt(match.rule_id).result_id;
    if (match.gate == 1) s.lane = Lane::kBuffer;
    if (session_layout_) {
      s.session_id = SessionResource::SessionOf(result);
      s.version = SessionResource::VersionOf(result);
      s.action_index = s.tunnel_action_index = SessionResource::IndexOf(result);
      configs[k] = &sessions_->Config(s.session_id, s.version, s.action_index);
      __builtin_prefetch(configs[k]);
      continue;
    }
    const auto r = pdr.records->Lookup(result);
    const auto *b = reinterpret_cast<const uint8_t *>(r.data());
    s.action_id = gtpu::GetWire32(b);
    s.meters[0] = gtpu::GetWire32(b + 4); s.meters[1] = gtpu::GetWire32(b + 8);
    s.next_hop_id = gtpu::GetWire32(b + 12); s.route_domain = gtpu::GetWire32(b + 16);
    s.policy_id = dl ? gtpu::GetWire32(b + 20) : 0;
    s.direction = dl ? 1 : 0;
  }
  if (session_layout_)
    for (size_t k = 0; k < count; ++k)
      if (configs[k]) BindSession(states[positions[k]], *configs[k], dl);
}

void UpfAppliance::BindSession(State &s, const ActionConfig &c, bool dl) const noexcept {
  s.action_id = c.action_id;
  s.meters[0] = c.meter[0]; s.meters[1] = c.meter[1];
  s.next_hop_id = c.next_hop_id; s.route_domain = c.route_domain;
  s.policy_id = dl ? c.policy_id : 0;
  s.cell = c.cell;
  s.direction = dl ? 1 : 0;
}

// A held frame resumes against its session as it is now (as the graph's
// release re-reads the action): the current version's action with the same
// id, all of it, or nothing -- the session or the action is gone.
bool UpfAppliance::RebindSession(State &s) const noexcept {
  if (s.session_id == 0 || s.session_id > sessions_->limits().capacity) return false;
  const uint8_t version = sessions_->Active(s.session_id);
  if (version == SessionResource::kGone) return false;
  const int index = sessions_->Find(s.session_id, version, s.action_id);
  if (s.action_id == 0 || index < 0) return false;
  s.version = version;
  s.action_index = s.tunnel_action_index = static_cast<uint8_t>(index);
  BindSession(s, sessions_->Config(s.session_id, version, s.action_index), s.direction == 1);
  return true;
}

void UpfAppliance::CountSessions(Context *ctx, bess::PacketBatch *batch, State *states, size_t n) {
  // The matched action's cells in its session's stride: one writer (the
  // worker), atomic cells that get_counts reads beside it.
  for (size_t i = 0; i < n; ++i) {
    const auto &s = states[i];
    if (!Active(s) || !(s.cell & ActionConfig::kCount)) continue;
    sessions_->Cells(s.session_id, s.cell & ActionConfig::kCellSlot).urr[s.direction].Add(
        UsageOctets(Bytes(batch->packet(i)), batch->packet(i).total_len()), ctx->current_ns);
  }
}

void UpfAppliance::MeterSessions(bess::PacketBatch *batch, State *states, size_t n, uint64_t now,
    meter::MeterColor *colors, std::array<std::array<uint64_t, 3>, 2> &color_counts) {
  for (size_t level = 0; level != 2; ++level) {
    // The session's own buckets are checked in place; shared meters in one
    // MeterSet batch, read only when a frame names one.
    meter::MeterState *own[kBurst]; uint8_t own_at[kBurst]; size_t owned = 0;
    meter::MeterId ids[kBurst]; uint32_t costs[kBurst];
    meter::MeterColor compact[kBurst]; uint8_t shared_at[kBurst]; size_t shared = 0;
    for (size_t i = 0; i < n; ++i) {
      const auto &s = states[i];
      const uint32_t ref = s.meters[level];
      if (!Active(s) || ref == 0) continue;
      MeterSlot &slot = sessions_->Meter(s.session_id,
          static_cast<uint16_t>((ref & ~uint32_t{ActionConfig::kSharedMeter}) - 1));
      if (ref & ActionConfig::kSharedMeter) {
        shared_at[shared] = i; ids[shared] = meter::MeterId(slot.shared());
        costs[shared] = batch->packet(i).total_len(); compact[shared] = colors[i]; ++shared;
        continue;
      }
      own_at[owned] = i; own[owned] = &slot.meter();
      __builtin_prefetch(own[owned], 1);
      ++owned;
    }
    const auto result = [&](State &s, size_t i, meter::MeterColor color) {
      if (color == meter::MeterColor::kRed) {
        ++color_counts[s.direction][2];
        Drop(s, Reason::kMeterRed);
      } else {
        colors[i] = color;
      }
    };
    for (size_t j = 0; j < owned; ++j) {
      const size_t i = own_at[j];
      result(states[i], i, own[j]->CheckColorAware(now, batch->packet(i).total_len(), colors[i]));
    }
    if (shared == 0) continue;
    const uint64_t found = meter_set_.Read()->CheckBatchColorAware(
        std::span(ids, shared), std::span(costs, shared), std::span(compact, shared), now);
    for (size_t j = 0; j < shared; ++j) {
      auto &s = states[shared_at[j]];
      if (!(found & (uint64_t{1} << j))) Drop(s, Reason::kMeterUnknown);
      else result(s, shared_at[j], compact[j]);
    }
  }
}

void UpfAppliance::CountUsage(Context *ctx, bess::PacketBatch *batch, State *states,
    size_t n, Counters &bank, bool buffer) {
  const auto plane = bank.cells->ForWorker(ctx->wid);
  uint32_t counted[kBurst];
  size_t count = 0;
  for (size_t i = 0; i < n; ++i) {
    const auto &s = states[i];
    if (buffer ? s.lane != Lane::kBuffer : !Active(s)) continue;
    if (!buffer && ((&bank == &counters_ul_) != (s.direction == 0))) continue;
    const Id id(s.action_id);
    if (id.value() == 0 || id.value() > capacity_ || !bank.entries->Lookup(id)) continue;
    plane.Add(id.value() - 1, 0, 1);
    plane.Add(id.value() - 1, 1, UsageOctets(Bytes(batch->packet(i)), batch->packet(i).total_len()));
    bool seen = false;
    for (size_t j = 0; j < count; ++j) seen |= counted[j] == id.value();
    if (!seen) counted[count++] = id.value();
  }
  for (size_t j = 0; j < count; ++j) {
    auto &stamp = bank.stamps[counted[j] - 1];
    if (stamp.first.load(std::memory_order_relaxed) == 0)
      stamp.first.store(ctx->current_ns, std::memory_order_relaxed);
    stamp.last.store(ctx->current_ns, std::memory_order_relaxed);
  }
}

void UpfAppliance::MeterCountRoute(Context *ctx, bess::PacketBatch *batch, State *states, size_t n) {
  const auto *set = meter_set_.Read();
  const uint64_t now = meter::MeterNow();
  // At most one reinjection, hence at most two PDR/meter/router passes.
  for (unsigned pass = 0; pass != 2; ++pass) {
    CountUsage(ctx, batch, states, n, buffer_counters_, true);
    for (size_t i = 0; i < n; ++i) if (states[i].lane == Lane::kBuffer) {
      Hold(ctx, batch->packet(i), states[i]); states[i].lane = Lane::kHeld;
    }
    meter::MeterColor colors[kBurst];
    std::fill_n(colors, n, meter::MeterColor::kGreen);
    std::array<std::array<uint64_t, 3>, 2> color_counts{};
    if (session_layout_) MeterSessions(batch, states, n, now, colors, color_counts);
    else for (size_t level = 0; level != 2; ++level) {
      meter::MeterId ids[kBurst]; uint32_t costs[kBurst];
      meter::MeterColor compact[kBurst]; uint8_t positions[kBurst]; size_t count = 0;
      for (size_t i = 0; i < n; ++i) if (Active(states[i]) && states[i].meters[level]) {
        positions[count] = i; ids[count] = meter::MeterId(states[i].meters[level]);
        costs[count] = batch->packet(i).total_len(); compact[count] = colors[i]; ++count;
      }
      const uint64_t found = count ? set->CheckBatchColorAware(
          std::span(ids, count), std::span(costs, count), std::span(compact, count), now) : 0;
      for (size_t j = 0; j < count; ++j) {
        auto &s = states[positions[j]];
        if (!(found & (uint64_t{1} << j))) Drop(s, Reason::kMeterUnknown);
        else if (compact[j] == meter::MeterColor::kRed) {
          ++color_counts[s.direction][2];
          Drop(s, Reason::kMeterRed);
        }
        else colors[positions[j]] = compact[j];
      }
    }
    for (size_t i = 0; i < n; ++i) {
      if (Active(states[i])) {
        ++color_counts[states[i].direction][colors[i] == meter::MeterColor::kYellow ? 1 : 0];
      }
    }
    for (size_t direction = 0; direction < 2; ++direction) {
      for (size_t color = 0; color < 3; ++color) {
        if (color_counts[direction][color] != 0) {
          meter_colors_[direction][color].fetch_add(color_counts[direction][color], std::memory_order_relaxed);
        }
      }
    }
    if (session_layout_) {
      CountSessions(ctx, batch, states, n);
    } else {
      CountUsage(ctx, batch, states, n, counters_ul_, false);
      CountUsage(ctx, batch, states, n, counters_dl_, false);
    }
    route::NextHopId ids[kBurst]; const route::NextHop *hops[kBurst];
    uint8_t positions[kBurst]; size_t count = 0;
    for (size_t i = 0; i < n; ++i) {
      auto &s = states[i]; if (!Active(s)) continue;
      if (s.direction == 1) {
        const auto selected = upf::atsss::Steer(s.policy_id,
            [&](uint32_t id) { return policies_->Lookup(Id(id)); },
            [&](uint32_t id) { return health_->Lookup(Id(id)); });
        if (selected.verdict == upf::atsss::SteerVerdict::kNoPolicy) { Drop(s, Reason::kNoPolicy); continue; }
        if (selected.verdict == upf::atsss::SteerVerdict::kNoAccess) { Drop(s, Reason::kNoAccess); continue; }
        if (selected.access) {
          s.next_hop_id = selected.access->next_hop_id;
          // Session-major: a 1-based action position in the frame's version.
          if (session_layout_ && selected.access->tunnel_id != 0)
            s.tunnel_action_index = static_cast<uint8_t>(selected.access->tunnel_id - 1);
        }
      }
      positions[count] = i; ids[count++] = route::NextHopId(s.next_hop_id);
    }
    const uint64_t found = count ? router_->LookupNextHops(std::span(ids, count), std::span(hops, count)) : 0;
    bool reinject = false;
    for (size_t k = 0; k < count; ++k) {
      const size_t i = positions[k]; auto &s = states[i];
      if (!(found & (uint64_t{1} << k))) { Drop(s, Reason::kNoNextHop); continue; }
      const auto &hop = *hops[k];
      if (hop.kind == route::NextHopKind::kLocal) { Drop(s, Reason::kLocalHop); continue; }
      if (hop.neighbor != route::NeighborState::kResolved) { Drop(s, Reason::kUnresolved); continue; }
      auto p = batch->packet(i);
      bess::packet::ParsedFrame parsed;
      const auto status = bess::packet::ParseFrame(Bytes(p), parsed, p.total_len());
      if (status != bess::packet::ParseStatus::kOk && status != bess::packet::ParseStatus::kNotIp &&
          status != bess::packet::ParseStatus::kFragment) { Drop(s, Reason::kRouterMalformed); continue; }
      if (status == bess::packet::ParseStatus::kNotIp) {
        if (!route::RewriteL2(p, hop)) { Drop(s, Reason::kRouterMalformed); continue; }
      } else if (route::WriteForwarded(std::span(p.head_data<uint8_t *>(), p.head_len()),
          parsed.l3 == bess::packet::L3Kind::kIpv6 ? route::L3Family::kIpv6 : route::L3Family::kIpv4,
          parsed.l3_offset, hop) != route::TtlResult::kForward) { Drop(s, Reason::kTtlExpired); continue; }
      const uint32_t gate = hop.egress.value() == 0 ? DROP_GATE : hop.egress.value() - 1;
      const upf::pb::UpfApplianceNextHopClass *cls = nullptr;
      for (const auto &c : next_hop_classes_) if (c.egress_gate() == gate) { cls = &c; break; }
      if (!cls) { Drop(s, Reason::kBadEgress); continue; }
      switch (cls->action()) {
        case upf::pb::UpfApplianceNextHopClass::OUTPUT:
          s.output_gate = cls->output_gate(); s.lane = Lane::kOutput; break;
        case upf::pb::UpfApplianceNextHopClass::ENCAP: {
          Tunnel local;
          const Tunnel *t = nullptr;
          if (!session_layout_) {
            t = tunnels_->Lookup(Id(s.action_id));
          } else if (s.tunnel_action_index < sessions_->limits().max_actions) {
            const auto &c = sessions_->Config(s.session_id, s.version, s.tunnel_action_index);
            if (c.action_id != 0 && c.has_tunnel()) { local = c.tunnel(); t = &local; }
          }
          if (!t) { Drop(s, Reason::kNoTunnel); break; }
          if (!Encap(p, *t)) { Drop(s, Reason::kEncapFailed); break; }
          s.transport_route_domain = t->transport_route_domain; s.lane = Lane::kTransport; break;
        }
        case upf::pb::UpfApplianceNextHopClass::REINJECT_DL:
          if (s.repass != 0) Drop(s, Reason::kRepassLimit);
          else { ++s.repass; s.lane = Lane::kDl; s.direction = 1; reinject = true; }
          break;
        default: Drop(s, Reason::kBadEgress); break;
      }
    }
    if (!reinject) break;
    ClassifyPdr(batch, states, n, true);
  }
}

bool UpfAppliance::Encap(bess::PacketRef p, const Tunnel &t) const {
  if (!p.is_linear() || p.total_len() < 34) return false;
  const auto *frame = p.head_data<const uint8_t *>();
  const auto ether = gtpu::GetWire16(frame + 12);
  const auto *ip = frame + 14;
  const size_t available = p.total_len() - 14;
  size_t length = 0; uint8_t traffic_class = 0;
  if (ether == 0x0800) {
    if ((ip[0] >> 4) != 4) return false;
    const size_t header = size_t(ip[0] & 15) * 4;
    length = gtpu::GetWire16(ip + 2);
    if (header < 20 || header > available || length < header || length > available) return false;
    traffic_class = ip[1];
  } else if (ether == 0x86dd) {
    if (available < 40 || (ip[0] >> 4) != 6) return false;
    length = size_t{40} + gtpu::GetWire16(ip + 4);
    if (length > available) return false;
    traffic_class = uint8_t((ip[0] & 15) << 4 | ip[1] >> 4);
  } else return false;
  const size_t outer_bytes = gtpu::GtpOuterHeaderBytes(t.family, t.has_qfi);
  if (!outer_bytes) return false;
  if (p.total_len() > 14 + length) p.trim(p.total_len() - 14 - length);
  const uint16_t source = src_port_ ? src_port_ : bess::tunnel::FlowEntropyPort(Bytes(p));
  p.adj(14);
  auto *out = static_cast<uint8_t *>(p.prepend(outer_bytes));
  return out && gtpu::WriteGtpOuterHeaders(out, t.family, t.local, t.peer, t.teid,
      source, dst_port_, t.has_qfi, t.qfi, t.marking, traffic_class, length);
}

void UpfAppliance::Finish(Context *ctx, bess::PacketBatch *batch, State *states, size_t n) {
  gate_idx_t gates[kBurst];
  size_t keep = 0;
  for (size_t i = 0; i < n; ++i) {
    if (states[i].lane == Lane::kHeld) continue;
    batch->handles()[keep] = batch->handles()[i];
    gates[keep++] = states[i].lane == Lane::kOutput ? states[i].output_gate : DROP_GATE;
  }
  batch->set_cnt(keep);
  if (keep) EmitBatch(ctx, batch, gates);
}
void UpfAppliance::Resume(Context *ctx, bess::PacketBatch *batch, State *states, size_t n) {
  for (size_t i = 0; i < n; ++i) {
    auto &s = states[i];
    s.lane = s.direction ? Lane::kDl : Lane::kUl;
    if (session_layout_ && !RebindSession(s)) Drop(s, Reason::kSessionGone);
  }
  MeterCountRoute(ctx, batch, states, n);
  Transport(batch, states, n);
  Finish(ctx, batch, states, n);
}
