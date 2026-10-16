// SPDX-License-Identifier: BSD-3-Clause

#include "gtpu_encap.h"

#include <span>

#include "framework/plugin.h"
#include "tunnel/tunnel.h"
#include "utils/endian.h"
#include "utils/ether.h"
#include "utils/ip.h"

using bess::utils::be16_t;
using bess::utils::be32_t;

enum {
  ATTR_R_ETHER_SRC,
  ATTR_R_ETHER_DST,
  ATTR_R_UPF_TEID,
  ATTR_R_UPF_GNB_IP,
};

constexpr size_t kOuterBytes = bess::tunnel::kEthernetBytes + bess::tunnel::kIpv4Bytes +
                               bess::tunnel::kUdpBytes + bess::tunnel::kGtpuBaseBytes;

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

  using AccessMode = bess::metadata::Attribute::AccessMode;
  AddMetadataAttr("ether_src", sizeof(bess::utils::Ethernet::Address), AccessMode::kRead);
  AddMetadataAttr("ether_dst", sizeof(bess::utils::Ethernet::Address), AccessMode::kRead);
  AddMetadataAttr("upf_teid", 4, AccessMode::kRead);
  AddMetadataAttr("upf_gnb_ip", 4, AccessMode::kRead);

  return CommandSuccess();
}

void GtpuEncap::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  const auto eth_src = attr_offset(ATTR_R_ETHER_SRC);
  const auto eth_dst = attr_offset(ATTR_R_ETHER_DST);
  const auto teid = attr_offset(ATTR_R_UPF_TEID);
  const auto gnb_ip = attr_offset(ATTR_R_UPF_GNB_IP);

  for (bess::PacketRef pkt : batch->packets()) {
    const be32_t session_teid = get_attr_with_offset<be32_t>(teid, pkt);
    const be32_t peer = get_attr_with_offset<be32_t>(gnb_ip, pkt);
    if (unlikely(session_teid.value() == 0 || peer.value() == 0)) {
      DropPacket(ctx, pkt);  // no session, or its peer is unresolved
      continue;
    }

    const uint16_t inner_len = static_cast<uint16_t>(pkt.total_len());
    const uint16_t src_port = src_port_ != 0
                                  ? src_port_
                                  : bess::tunnel::FlowEntropyPort(std::span<const uint8_t>(
                                        pkt.head_data<const uint8_t *>(), pkt.head_len()));

    auto *outer = static_cast<uint8_t *>(pkt.prepend(kOuterBytes));
    if (unlikely(outer == nullptr)) {
      DropPacket(ctx, pkt);
      continue;
    }

    bess::utils::Ethernet *eth = reinterpret_cast<bess::utils::Ethernet *>(outer);
    eth->src_addr = get_attr_with_offset<bess::utils::Ethernet::Address>(eth_src, pkt);
    eth->dst_addr = get_attr_with_offset<bess::utils::Ethernet::Address>(eth_dst, pkt);
    eth->ether_type = be16_t(bess::utils::Ethernet::Type::kIpv4);

    bess::tunnel::WriteIpv4(outer + bess::tunnel::kEthernetBytes, be32_t(src_ip_), peer,
                            bess::utils::Ipv4::Proto::kUdp,
                            static_cast<uint16_t>(bess::tunnel::kUdpBytes +
                                                  bess::tunnel::kGtpuBaseBytes + inner_len));
    bess::tunnel::WriteUdp(outer + bess::tunnel::kEthernetBytes + bess::tunnel::kIpv4Bytes, src_port,
                           dst_port_,
                           static_cast<uint16_t>(bess::tunnel::kGtpuBaseBytes + inner_len));
    // UDP checksum 0: legal for IPv4 (RFC 768), and the packet may still be
    // marked for TX offload downstream (core/packet_tx_checksum.h).
    bess::tunnel::WriteGtpu(outer + bess::tunnel::kEthernetBytes + bess::tunnel::kIpv4Bytes +
                                bess::tunnel::kUdpBytes,
                            session_teid.value(), inner_len);

    EmitPacket(ctx, pkt, 0);
  }
}

// The plugin descriptor (BESS_PLUGIN) is defined once per library, in
// gtpu_decap.cc: both modules are registered by this one .so.
ADD_MODULE(GtpuEncap, "gtpu_encap",
           "encapsulates packets with outer Eth/IPv4/UDP/GTP-U headers (G-PDU)")
