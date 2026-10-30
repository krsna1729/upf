// SPDX-License-Identifier: BSD-3-Clause

#include "gtpu_encap.h"

#include <algorithm>
#include <cstring>
#include <format>
#include <span>
#include <string>
#include <utility>

// Before every other BESS header: glog must win over protobuf's absl logging.
#include "utils/logging.h"

#include "commands.h"
#include "dataplane/resource.h"
#include "dataplane/resource_registry.h"
#include "framework/plugin.h"
#include "framework/resource_codec.h"
#include "utils/endian.h"
#include "tunnel/tunnel.h"
#include "gtpu_wire.h"

using bess::utils::be32_t;
namespace dataplane = bess::dataplane;

namespace {
constexpr size_t kDefaultMaxTunnels = 65536;

uint16_t Get16(const uint8_t *p) noexcept {
  return static_cast<uint16_t>((uint16_t{p[0]} << 8) | p[1]);
}
}  // namespace


const ResourceTables GtpuEncap::resource_tables = {
    ResourceTable::Map<upf::pb::TunnelKey, upf::pb::TunnelEntry>("tunnels"),
};

CommandResponse GtpuEncap::Init(const upf::pb::GtpuEncapArg &arg) {
  if (arg.tunnel_attr() == "action_id")
    return CommandFailure(EINVAL, "the tunnel attribute must not be 'action_id'");
  if (arg.src_port() > 65535 || arg.dst_port() > 65535)
    return CommandFailure(EINVAL, "invalid UDP port field");
  src_port_ = static_cast<uint16_t>(arg.src_port());
  dst_port_ = arg.dst_port() == 0 ? bess::tunnel::kGtpuPort
                                  : static_cast<uint16_t>(arg.dst_port());

  const size_t capacity = arg.max_tunnels() == 0
                              ? kDefaultMaxTunnels
                              : arg.max_tunnels();
  tunnels_ = init_context().memory().Create<dataplane::SlotTable<ActionId, Tunnel>>(
      "tunnels", capacity);
  resource_ = std::make_unique<dataplane::SlotResource<ActionId, Tunnel>>(
      name() + "/tunnels", *tunnels_);
  binding_ = init_context().codecs().Bind(
      *resource_,
      std::make_shared<bess::framework::TypedCodec<upf::pb::TunnelKey,
                                                    upf::pb::TunnelEntry>>(
          [](const upf::pb::TunnelKey &key)
              -> std::expected<dataplane::ResourceKey, std::string> {
            if (key.action_id() == 0)
              return std::unexpected("action id 0 names no tunnel");
            return dataplane::EncodeKey(ActionId(key.action_id()));
          },
          [](const upf::pb::TunnelEntry &value)
              -> std::expected<std::any, std::string> {
            if (value.teid() == 0)
              return std::unexpected("the 'teid' field is required");
            const size_t length = value.local_address().size();
            if ((length != 4 && length != 16) ||
                value.peer_address().size() != length)
              return std::unexpected("local_address and peer_address must both be 4 or 16 bytes");
            if (value.qfi() > 63)
              return std::unexpected("invalid 'qfi' field");
            if (!value.qfi_present() && value.qfi() != 0)
              return std::unexpected("qfi must be zero when qfi_present is false");
            if (value.marking() > 0xffff)
              return std::unexpected("invalid 'marking' field");
            Tunnel tunnel{};
            tunnel.teid = value.teid();
            tunnel.family = length == 4 ? 4 : 6;
            const size_t offset = length == 4 ? 12 : 0;
            std::memcpy(tunnel.local + offset, value.local_address().data(), length);
            std::memcpy(tunnel.peer + offset, value.peer_address().data(), length);
            if (std::all_of(tunnel.local, tunnel.local + 16,
                            [](uint8_t byte) { return byte == 0; }) ||
                std::all_of(tunnel.peer, tunnel.peer + 16,
                            [](uint8_t byte) { return byte == 0; }))
              return std::unexpected("tunnel addresses must not be unspecified");
            tunnel.transport_route_domain = value.transport_route_domain();
            tunnel.qfi = static_cast<uint8_t>(value.qfi());
            tunnel.has_qfi = value.qfi_present();
            tunnel.marking = static_cast<uint16_t>(value.marking());
            return std::any(tunnel);
          },
          [this](const auto &visit) {
            for (size_t i = 1; i <= tunnels_->capacity(); ++i) {
              const ActionId id(static_cast<ActionId::rep_type>(i));
              const Tunnel *tunnel = tunnels_->Current(id);
              if (tunnel == nullptr) continue;
              upf::pb::TunnelKey key;
              key.set_action_id(id.value());
              upf::pb::TunnelEntry value;
              value.set_teid(tunnel->teid);
              const size_t offset = tunnel->family == 4 ? 12 : 0;
              const size_t length = tunnel->family == 4 ? 4 : 16;
              value.set_local_address(
                  reinterpret_cast<const char *>(tunnel->local + offset), length);
              value.set_peer_address(
                  reinterpret_cast<const char *>(tunnel->peer + offset), length);
              value.set_qfi(tunnel->qfi);
              value.set_qfi_present(tunnel->has_qfi);
              value.set_marking(tunnel->marking);
              value.set_transport_route_domain(tunnel->transport_route_domain);
              visit(key, value);
            }
          }));
  if (auto registered = init_context().resources().Register(resource_.get());
      !registered) {
    binding_.Reset();
    resource_.reset();
    return CommandFailure(EEXIST, "%s", registered.error().c_str());
  }

  using AccessMode = bess::metadata::Attribute::AccessMode;
  action_attr_ = AddMetadataAttr("action_id", sizeof(be32_t), AccessMode::kRead);
  if (action_attr_ < 0) {
    const std::string resource_name = resource_->name();
    CHECK(init_context().resources().Unregister(resource_name));
    binding_.Reset();
    resource_.reset();
    return CommandFailure(-action_attr_, "add_metadata_attr() failed");
  }
  if (!arg.tunnel_attr().empty()) {
    has_tunnel_ = true;
    tunnel_attr_ = AddMetadataAttr(arg.tunnel_attr(), sizeof(be32_t),
                                   AccessMode::kRead);
    if (tunnel_attr_ < 0) {
      const std::string resource_name = resource_->name();
      CHECK(init_context().resources().Unregister(resource_name));
      binding_.Reset();
      resource_.reset();
      return CommandFailure(-tunnel_attr_, "add_metadata_attr() failed");
    }
  }
  domain_attr_ = AddMetadataAttr("transport_route_domain", sizeof(be32_t),
                                 AccessMode::kWrite);
  if (domain_attr_ < 0) {
    const std::string resource_name = resource_->name();
    CHECK(init_context().resources().Unregister(resource_name));
    binding_.Reset();
    resource_.reset();
    return CommandFailure(-domain_attr_, "add_metadata_attr() failed");
  }
  return CommandSuccess();
}

void GtpuEncap::DeInit() {
  if (resource_ == nullptr) return;
  binding_.Reset();
  const std::string resource_name = resource_->name();
  auto unregistered = init_context().resources().Unregister(resource_name);
  CHECK(unregistered) << unregistered.error();
  resource_.reset();
}

void GtpuEncap::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  const auto action_offset = attr_offset(action_attr_);
  const auto tunnel_offset = has_tunnel_ ? attr_offset(tunnel_attr_) : -1;
  const auto domain_offset = attr_offset(domain_attr_);
  gate_idx_t ogates[bess::PacketBatch::kMaxBurst];
  for (int i = 0; i < batch->cnt(); ++i) {
    bess::PacketRef pkt = batch->packet(i);
    ogates[i] = DROP_GATE;
    uint32_t id = get_attr_with_offset<be32_t>(action_offset, pkt).value();
    if (bess::metadata::IsValidOffset(tunnel_offset)) {
      const uint32_t selected = get_attr_with_offset<be32_t>(tunnel_offset, pkt).value();
      if (selected != 0) id = selected;
    }
    const Tunnel *tunnel = LookupTunnel(ActionId(id));
    if (tunnel == nullptr || !pkt.is_linear() ||
        pkt.total_len() < bess::tunnel::kEthernetBytes + 20)
      continue;

    const auto *frame = pkt.head_data<const uint8_t *>();
    const auto *eth = reinterpret_cast<const bess::utils::Ethernet *>(frame);
    const uint16_t ether_type = eth->ether_type.value();
    const size_t ip_offset = bess::tunnel::kEthernetBytes;
    const size_t available = pkt.total_len() - ip_offset;
    const uint8_t *inner_ip = frame + ip_offset;
    size_t inner_len = 0;
    uint8_t inner_class = 0;
    if (ether_type == bess::utils::Ethernet::Type::kIpv4) {
      if (available < 20 || (inner_ip[0] >> 4) != 4) continue;
      const size_t header_length = static_cast<size_t>(inner_ip[0] & 0x0f) * 4;
      inner_len = Get16(inner_ip + 2);
      if (header_length < 20 || header_length > available ||
          inner_len < header_length || inner_len > available) continue;
      inner_class = inner_ip[1];
    } else if (ether_type == bess::utils::Ethernet::Type::kIpv6) {
      if (available < 40 || (inner_ip[0] >> 4) != 6) continue;
      inner_len = size_t{40} + Get16(inner_ip + 4);
      if (inner_len < 40 || inner_len > available) continue;
      inner_class = static_cast<uint8_t>(((inner_ip[0] & 0x0f) << 4) |
                                         (inner_ip[1] >> 4));
    } else {
      continue;
    }
    const size_t outer_bytes =
        upf::datapath::GtpOuterHeaderBytes(tunnel->family, tunnel->has_qfi);
    if (outer_bytes == 0) continue;
    if (pkt.total_len() > ip_offset + inner_len)
      pkt.trim(static_cast<uint16_t>(pkt.total_len() - ip_offset - inner_len));
    const uint16_t source_port = src_port_ != 0 ? src_port_ :
        bess::tunnel::FlowEntropyPort(std::span<const uint8_t>(frame, pkt.head_len()));

    // The existing inner IP bytes become the GTP-U payload; only header space
    // is prepended and filled by the shared wire writer.
    pkt.adj(static_cast<uint16_t>(ip_offset));
    auto *outer = static_cast<uint8_t *>(pkt.prepend(outer_bytes));
    if (outer == nullptr) continue;
    if (!upf::datapath::WriteGtpOuterHeaders(
            outer, tunnel->family, tunnel->local, tunnel->peer, tunnel->teid,
            source_port, dst_port_, tunnel->has_qfi, tunnel->qfi,
            tunnel->marking, inner_class, inner_len))
      continue;
    set_attr_with_offset<be32_t>(domain_offset, pkt,
                                 be32_t(tunnel->transport_route_domain));
    ogates[i] = 0;
  }
  EmitBatch(ctx, batch, ogates);
}

std::string GtpuEncap::GetDesc() const {
  return std::format("{} tunnels", tunnels_ ? tunnels_->size() : 0);
}

ADD_MODULE(GtpuEncap, "gtpu_encap",
           "encapsulates packets with routed outer IPv4/IPv6 GTP-U headers")
