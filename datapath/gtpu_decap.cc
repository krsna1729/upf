// SPDX-License-Identifier: BSD-3-Clause

#include "gtpu_decap.h"

#include <cstdint>
#include <format>
#include <span>
#include <string>

// Before every other BESS header: glog must win over protobuf's absl logging
// in this translation unit (docs/plugin-api.md, "Logging").
#include "utils/logging.h"

#include "commands.h"
#include "framework/plugin.h"
#include "tunnel/tunnel.h"
#include "utils/endian.h"
#include "utils/ether.h"

// The class has no resource tables: a session's TEID is a rule of the
// classifier in front of this module (the compiler writes one per session).
const ResourceTables GtpuDecap::resource_tables = {};

CommandResponse GtpuDecap::Init(const upf::pb::GtpuDecapArg &arg) {
  if (arg.port() != 0) {
    if (arg.port() > 65535) {
      return CommandFailure(EINVAL, "invalid 'port' field");
    }
    port_ = static_cast<uint16_t>(arg.port());
  } else {
    port_ = bess::tunnel::kGtpuPort;
  }

  using AccessMode = bess::metadata::Attribute::AccessMode;
  teid_attr_ = AddMetadataAttr("upf_teid", sizeof(bess::utils::be32_t),
                               AccessMode::kWrite);
  if (teid_attr_ < 0) {
    return CommandFailure(-teid_attr_, "add_metadata_attr() failed");
  }

  return CommandSuccess();
}

void GtpuDecap::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  // One offset load per batch: the layout does not change under a batch.
  const auto teid_offset = attr_offset(teid_attr_);
  gate_idx_t ogates[bess::PacketBatch::kMaxBurst];
  const size_t cnt = batch->cnt();

  for (size_t i = 0; i < cnt; i++) {
    bess::PacketRef pkt = batch->packet(i);
    ogates[i] = DROP_GATE;

    // The parse and the reframing read one segment: a chained packet is not
    // something this module can reframe in place (it would need a copy, and
    // the packet path here makes none).
    if (not pkt.is_linear()) [[unlikely]] {
      continue;
    }

    bess::conntrack::ParsedFlowPacket outer;
    bess::tunnel::GtpuInfo info;
    const auto status = bess::tunnel::DecapGtpu(
        std::span<const uint8_t>(pkt.head_data<const uint8_t *>(),
                                 pkt.head_len()),
        outer, info, port_, pkt.total_len());
    if (status != bess::tunnel::DecapError::kOk) [[unlikely]] {
      continue;
    }

    // The attribute is written for the modules downstream that read it. A
    // write-only attribute no module reads is not allocated at all: the
    // pipeline gives it kMetadataOffsetNoWrite ("attr not read downstream",
    // core/metadata.cc:FillOffsetArrays), so writing it is a no-op -- correct,
    // and a graph that wants the TEID in a packet's metadata must have a
    // reader for it.
    set_attr_with_offset<bess::utils::be32_t>(
        teid_offset, pkt, bess::utils::be32_t(info.tunnel.id));

    // The graph carries Ethernet frames: BESS's core modules (the router's
    // lookup, the classifiers) read IPv4 behind an Ethernet header, so the
    // packet the graph sees is the inner packet behind a header. The head
    // moves to the inner packet and a header is written in front of it -- the
    // outer frame's own addresses, the inner packet's type -- using the
    // headroom the outer headers occupied: no byte of the payload is copied.
    const auto *outer_eth = pkt.head_data<const bess::utils::Ethernet *>();
    const bess::utils::Ethernet::Address src = outer_eth->src_addr;
    const bess::utils::Ethernet::Address dst = outer_eth->dst_addr;

    pkt.adj(static_cast<uint16_t>(info.tunnel.inner_offset));
    // 4 or 6 in the first nibble of the payload: what a G-PDU can carry. Read
    // before the new header is written in front of it.
    const uint8_t version = *pkt.head_data<const uint8_t *>() >> 4;
    if (version != 4 && version != 6) [[unlikely]] {
      continue;
    }

    auto *eth = static_cast<bess::utils::Ethernet *>(
        pkt.prepend(bess::tunnel::kEthernetBytes));
    if (eth == nullptr) [[unlikely]] {
      continue;  // no headroom for a frame header
    }
    eth->src_addr = src;
    eth->dst_addr = dst;
    eth->ether_type =
        bess::utils::be16_t(version == 4 ? bess::utils::Ethernet::Type::kIpv4
                                        : bess::utils::Ethernet::Type::kIpv6);
    ogates[i] = 0;
  }

  // One call for the batch: when every packet leaves by the same gate -- the
  // common case, and the only one here -- the batch leaves whole, and a
  // dropped packet costs the drop and nothing else (core/module.h:EmitBatch).
  EmitBatch(ctx, batch, ogates);
}

std::string GtpuDecap::GetDesc() const {
  return std::format("port {}", port_);
}

// One plugin descriptor for the whole library (gtpu_encap.cc carries the other
// module; BESS_PLUGIN must appear exactly once per .so).
BESS_PLUGIN("upf_datapath", "0.2.0");

ADD_MODULE(GtpuDecap, "gtpu_decap",
           "decapsulates GTP-U (outer Eth/IP/UDP/GTP-U) to a frame holding the "
           "inner IP packet; the F-TEID match is the classifier in front of it")
