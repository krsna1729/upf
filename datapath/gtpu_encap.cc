// SPDX-License-Identifier: BSD-3-Clause

#include "gtpu_encap.h"

#include <cstring>
#include <format>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// Before every other BESS header: glog must win over protobuf's absl logging
// in this translation unit (docs/plugin-api.md, "Logging").
#include "utils/logging.h"

#include "commands.h"
#include "dataplane/resource.h"
#include "dataplane/resource_registry.h"
#include "framework/plugin.h"
#include "framework/resource_codec.h"
#include "tunnel/tunnel.h"
#include "utils/endian.h"
#include "utils/ip.h"

using bess::utils::be16_t;
using bess::utils::be32_t;

namespace dataplane = bess::dataplane;

enum {
  ATTR_R_ACTION_ID,
};

constexpr size_t kOuterBytes = bess::tunnel::kEthernetBytes + bess::tunnel::kIpv4Bytes +
                               bess::tunnel::kUdpBytes + bess::tunnel::kGtpuBaseBytes;

// The extension header type of a PDU Session Container (TS 29.281 table
// 5.2.2.7-1).
constexpr uint8_t kPduSessionContainer = 0x85;

// What a PDU Session Container adds after the GTP-U base header: the 4-octet
// optional tail -- sequence number, N-PDU number and the next-extension-header
// type, which the E flag makes present (TS 29.281 5.1) -- and the container
// itself, one 4-octet unit: its length, the two content octets that hold the
// PDU type and the QFI, and the next-type octet that ends the chain.
constexpr size_t kPduSessionBytes = 8;

// 0 means "the argument did not say": one tunnel record per session of a large
// access network (a few tens of bytes per slot).
constexpr size_t kDefaultMaxTunnels = 65536;

const ResourceTables GtpuEncap::resource_tables = {
    ResourceTable::Map<upf::pb::TunnelKey, upf::pb::TunnelEntry>("tunnels"),
};

namespace {

// A dotted IPv4 address, from the network-order value the wire carries.
std::string IpToString(uint32_t ip) {
  return std::format("{}.{}.{}.{}", ip >> 24 & 0xff, ip >> 16 & 0xff,
                     ip >> 8 & 0xff, ip & 0xff);
}

// A 6-byte Ethernet address from a wire field, or an error.
std::expected<bess::utils::Ethernet::Address, std::string> ParseEther(
    std::string_view bytes, std::string_view field) {
  if (bytes.size() != sizeof(bess::utils::Ethernet::Address)) {
    return std::unexpected(std::format("'{}' must be 6 bytes", field));
  }
  bess::utils::Ethernet::Address address;
  std::memcpy(address.bytes, bytes.data(), bytes.size());
  return address;
}

}  // namespace

CommandResponse GtpuEncap::Init(const upf::pb::GtpuEncapArg &arg) {
  if (arg.src_ip().empty()) {
    return CommandFailure(EINVAL, "the 'src_ip' field is required");
  }
  bess::utils::be32_t src;
  if (!bess::utils::ParseIpv4Address(arg.src_ip(), &src) || src.value() == 0) {
    return CommandFailure(EINVAL, "invalid 'src_ip' field");
  }
  src_ip_ = src.value();

  if (arg.src_port() != 0) {
    if (arg.src_port() > 65535) {
      return CommandFailure(EINVAL, "invalid 'src_port' field");
    }
    src_port_ = static_cast<uint16_t>(arg.src_port());
  }
  dst_port_ = bess::tunnel::kGtpuPort;
  if (arg.dst_port() != 0) {
    if (arg.dst_port() > 65535) {
      return CommandFailure(EINVAL, "invalid 'dst_port' field");
    }
    dst_port_ = static_cast<uint16_t>(arg.dst_port());
  }

  const size_t max_tunnels =
      arg.max_tunnels() == 0 ? kDefaultMaxTunnels : arg.max_tunnels();
  tunnels_ =
      std::make_unique<dataplane::SlotTable<ActionId, Tunnel>>(max_tunnels);
  resource_ = std::make_unique<dataplane::SlotResource<ActionId, Tunnel>>(
      name() + "/tunnels", *tunnels_);

  // Typed keys and values over the RPC (D-025), so the controller can write a
  // session's tunnel without generated code for this plugin's protobufs.
  binding_ = init_context().codecs().Bind(
      *resource_,
      std::make_shared<
          bess::framework::TypedCodec<upf::pb::TunnelKey, upf::pb::TunnelEntry>>(
          [](const upf::pb::TunnelKey &key)
              -> std::expected<dataplane::ResourceKey, std::string> {
            if (key.action_id() == 0) {
              return std::unexpected("action id 0 names no tunnel");
            }
            return dataplane::EncodeKey(ActionId(key.action_id()));
          },
          [](const upf::pb::TunnelEntry &value)
              -> std::expected<std::any, std::string> {
            Tunnel tunnel{};
            if (value.teid() == 0) {
              return std::unexpected("the 'teid' field is required");
            }
            tunnel.teid = value.teid();
            bess::utils::be32_t gnb_ip;
            if (!bess::utils::ParseIpv4Address(value.gnb_ip(), &gnb_ip) ||
                gnb_ip.value() == 0) {
              return std::unexpected("invalid 'gnb_ip' field");
            }
            tunnel.gnb_ip = gnb_ip.value();
            auto ether_src = ParseEther(value.ether_src(), "ether_src");
            if (!ether_src) {
              return std::unexpected(ether_src.error());
            }
            auto ether_dst = ParseEther(value.ether_dst(), "ether_dst");
            if (!ether_dst) {
              return std::unexpected(ether_dst.error());
            }
            tunnel.ether_src = *ether_src;
            tunnel.ether_dst = *ether_dst;
            if (value.qfi() > 63) {
              return std::unexpected("invalid 'qfi' field");
            }
            tunnel.qfi = static_cast<uint8_t>(value.qfi());
            // The Transport Level Marking (8.2.42) is the IE's two octets, so
            // anything wider than them is a record no message could have
            // produced. 0 -- absent, or the SMF asking for none -- means the
            // inner TOS is copied.
            if (value.marking() > 0xffff) {
              return std::unexpected("invalid 'marking' field");
            }
            tunnel.marking = static_cast<uint16_t>(value.marking());
            return std::any(tunnel);
          },
          // Every live tunnel, as its value names it.
          [this](const auto &visit) {
            for (size_t i = 1; i <= tunnels_->capacity(); i++) {
              const ActionId id(static_cast<ActionId::rep_type>(i));
              const Tunnel *tunnel = tunnels_->Current(id);
              if (tunnel == nullptr) {
                continue;
              }
              upf::pb::TunnelKey key;
              key.set_action_id(id.value());
              upf::pb::TunnelEntry value;
              value.set_teid(tunnel->teid);
              value.set_gnb_ip(IpToString(tunnel->gnb_ip));
              value.set_ether_src(std::string(
                  reinterpret_cast<const char *>(tunnel->ether_src.bytes),
                  sizeof(tunnel->ether_src.bytes)));
              value.set_ether_dst(std::string(
                  reinterpret_cast<const char *>(tunnel->ether_dst.bytes),
                  sizeof(tunnel->ether_dst.bytes)));
              value.set_qfi(tunnel->qfi);
              value.set_marking(tunnel->marking);
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
  action_attr_ = AddMetadataAttr("action_id", sizeof(bess::utils::be32_t),
                                 AccessMode::kRead);
  if (action_attr_ < 0) {
    const std::string name = resource_->name();
    CHECK(init_context().resources().Unregister(name));
    binding_.Reset();
    resource_.reset();
    return CommandFailure(-action_attr_, "add_metadata_attr() failed");
  }

  return CommandSuccess();
}

void GtpuEncap::DeInit() {
  if (resource_ == nullptr) {
    return;
  }
  binding_.Reset();
  // A tunnel record is referenced by nothing: the id that names it comes from
  // packet metadata, not from a ledger, so the compiler writes the record
  // before the rule that can select it (docs/design.md, install order).
  const std::string name = resource_->name();
  auto unregistered = init_context().resources().Unregister(name);
  CHECK(unregistered) << unregistered.error();
  resource_.reset();
}

void GtpuEncap::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  // One offset load per batch: the layout does not change under a batch.
  const auto action_offset = attr_offset(action_attr_);
  gate_idx_t ogates[bess::PacketBatch::kMaxBurst];
  const size_t cnt = batch->cnt();

  for (size_t i = 0; i < cnt; i++) {
    bess::PacketRef pkt = batch->packet(i);
    ogates[i] = DROP_GATE;

    const be32_t action_id = get_attr_with_offset<be32_t>(action_offset, pkt);
    const Tunnel *tunnel = LookupTunnel(ActionId(action_id.value()));
    if (tunnel == nullptr) [[unlikely]] {
      continue;  // no session: never send it out untunnelled
    }

    // The graph carries frames (the decap leaves one, a port delivers one),
    // but a G-PDU's payload is the inner IP packet (TS 29.281): the inner
    // Ethernet header stays behind, and the tunnel's own outer header is
    // IPv4, so a non-IPv4 frame is not something this tunnel record can carry.
    // The outer headers are written in one segment, as the inner frame is
    // read from one.
    const auto *inner = pkt.head_data<const bess::utils::Ethernet *>();
    if (pkt.total_len() <
            bess::tunnel::kEthernetBytes + bess::tunnel::kIpv4Bytes ||
        inner->ether_type != be16_t(bess::utils::Ethernet::Type::kIpv4) ||
        not pkt.is_linear()) [[unlikely]] {
      continue;
    }

    const uint16_t inner_len =
        static_cast<uint16_t>(pkt.total_len() - bess::tunnel::kEthernetBytes);
    const uint16_t src_port =
        src_port_ != 0
            ? src_port_
            : bess::tunnel::FlowEntropyPort(std::span<const uint8_t>(
                  pkt.head_data<const uint8_t *>(), pkt.head_len()));

    // Skip the inner frame's header: its bytes become headroom for the outer
    // headers the prepend re-exposes, so no payload byte is copied. The head
    // is the inner IPv4 header now, which is where the class byte is read: the
    // inner packet's TOS (its DSCP and ECN) travels on the outer header,
    // because the RAN's transport is DSCP-marked and a UPF that dropped it
    // would send every downlink packet as best effort.
    pkt.adj(static_cast<uint16_t>(bess::tunnel::kEthernetBytes));
    const uint8_t inner_tos =
        pkt.head_data<const bess::utils::Ipv4 *>()->type_of_service;

    // When the session's record names a Transport Level Marking (TS 29.244
    // 8.2.42), the SMF's DSCP wins over the inner packet's: the marking's high
    // octet is the ToS/Traffic Class the outer header carries and its low
    // octet is the mask naming which bits of the inner header's own class
    // survive -- the ECN bits with the spec's 0xFC, which applying the marking
    // must not change (the NOTE under 8.2.42). Without a marking the inner TOS
    // is copied, byte for byte as before.
    uint8_t outer_tos = inner_tos;
    if (tunnel->marking != 0) {
      const uint8_t mask = static_cast<uint8_t>(tunnel->marking & 0xff);
      const uint8_t marked = static_cast<uint8_t>(tunnel->marking >> 8);
      outer_tos = static_cast<uint8_t>((marked & mask) |
                                       (inner_tos & static_cast<uint8_t>(~mask)));
    }

    // The session's QoS flow (TS 29.244 8.2.89): 0 means this session's
    // G-PDUs carry no PDU Session Container, and every byte below is then
    // exactly what it was before the tunnel record had a QFI. The extra bytes
    // are sized before the prepend, because the lengths and the headroom are
    // one decision: the container is part of the G-PDU.
    const uint8_t qfi = tunnel->qfi;
    const size_t ext_bytes = qfi == 0 ? 0 : kPduSessionBytes;

    auto *outer = static_cast<uint8_t *>(pkt.prepend(kOuterBytes + ext_bytes));
    if (outer == nullptr) [[unlikely]] {
      continue;  // no headroom for the outer headers
    }

    bess::utils::Ethernet *eth = reinterpret_cast<bess::utils::Ethernet *>(outer);
    eth->src_addr = tunnel->ether_src;
    eth->dst_addr = tunnel->ether_dst;
    eth->ether_type = be16_t(bess::utils::Ethernet::Type::kIpv4);

    bess::tunnel::WriteIpv4(outer + bess::tunnel::kEthernetBytes, be32_t(src_ip_),
                            be32_t(tunnel->gnb_ip), bess::utils::Ipv4::Proto::kUdp,
                            static_cast<uint16_t>(bess::tunnel::kUdpBytes +
                                                  bess::tunnel::kGtpuBaseBytes +
                                                  ext_bytes + inner_len),
                            /*ttl=*/64, /*tos=*/outer_tos);
    bess::tunnel::WriteUdp(outer + bess::tunnel::kEthernetBytes + bess::tunnel::kIpv4Bytes,
                           src_port, dst_port_,
                           static_cast<uint16_t>(bess::tunnel::kGtpuBaseBytes + ext_bytes +
                                                 inner_len));
    // UDP checksum 0: legal for IPv4 (RFC 768), and the packet may still be
    // marked for TX offload downstream (core/packet_tx_checksum.h).
    uint8_t *gtpu = outer + bess::tunnel::kEthernetBytes + bess::tunnel::kIpv4Bytes +
                    bess::tunnel::kUdpBytes;
    // The GTP-U Length field counts everything after the 8 mandatory octets,
    // the extension headers included (TS 29.281 5.1).
    bess::tunnel::WriteGtpu(gtpu, tunnel->teid,
                            static_cast<uint16_t>(ext_bytes + inner_len));

    if (qfi != 0) {
      // The E flag makes the 4-octet optional tail present, and its last octet
      // names the first extension header (TS 29.281 5.1). The S flag stays
      // clear -- nothing in this packet is sequenced -- so the sequence number
      // and the N-PDU number are written as zero, the value a receiver that
      // does not interpret them reads.
      gtpu[0] |= 0x04;
      gtpu[bess::tunnel::kGtpuBaseBytes] = 0;      // sequence number
      gtpu[bess::tunnel::kGtpuBaseBytes + 1] = 0;
      gtpu[bess::tunnel::kGtpuBaseBytes + 2] = 0;  // N-PDU number
      gtpu[bess::tunnel::kGtpuBaseBytes + 3] = kPduSessionContainer;

      // The container: one 4-octet unit (length 1), the downlink PDU Session
      // Information content, and no further extension header. The content is
      // the minimum two octets -- the PDU type in the high nibble of the first
      // (0 = DL PDU SESSION INFORMATION, TS 38.415 5.5.3.1) with its QMP, SNP
      // and spare bits clear, and the QFI in the low six bits of the second
      // (PPP and RQI above it, 5.5.2.1), which is the field the NG-RAN reads
      // to place the packet on its QoS flow.
      uint8_t *container = gtpu + bess::tunnel::kGtpuBaseBytes + 4;
      container[0] = 1;
      container[1] = 0x00;
      container[2] = static_cast<uint8_t>(qfi & 0x3f);
      container[3] = 0;
    }

    ogates[i] = 0;
  }

  // One call for the batch: when every packet leaves by the same gate -- the
  // common case, and the only one here -- the batch leaves whole, and a
  // dropped packet costs the drop and nothing else (core/module.h:EmitBatch).
  EmitBatch(ctx, batch, ogates);
}

std::string GtpuEncap::GetDesc() const {
  return std::format("{} tunnels, src {}", tunnels_ == nullptr ? 0 : tunnels_->size(),
                     IpToString(src_ip_));
}

ADD_MODULE(GtpuEncap, "gtpu_encap",
           "encapsulates packets with outer Eth/IPv4/UDP/GTP-U headers (G-PDU)")
