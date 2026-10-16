// SPDX-License-Identifier: BSD-3-Clause

#include "gtpu_decap.h"

#include <span>

#include "framework/plugin.h"
#include "tunnel/tunnel.h"
#include "utils/endian.h"

enum {
  ATTR_W_UPF_TEID,
};

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
  AddMetadataAttr("upf_teid", 4, AccessMode::kWrite);

  return CommandSuccess();
}

void GtpuDecap::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  using bess::utils::be32_t;
  const auto teid = attr_offset(ATTR_W_UPF_TEID);

  for (bess::PacketRef pkt : batch->packets()) {
    bess::conntrack::ParsedFlowPacket outer;
    bess::tunnel::GtpuInfo info;
    const auto status = bess::tunnel::DecapGtpu(
        std::span<const uint8_t>(pkt.head_data<const uint8_t *>(), pkt.head_len()), outer, info,
        port_, pkt.total_len());
    if (unlikely(status != bess::tunnel::DecapError::kOk)) {
      DropPacket(ctx, pkt);
      continue;
    }
    set_attr_with_offset<be32_t>(teid, pkt, be32_t(info.tunnel.id));
    pkt.adj(static_cast<uint16_t>(info.tunnel.inner_offset));
    EmitPacket(ctx, pkt, 0);
  }
}

// One plugin descriptor for the whole library (gtpu_encap.cc carries the other
// module; BESS_PLUGIN must appear exactly once per .so).
BESS_PLUGIN("upf_datapath", "0.1.0");

ADD_MODULE(GtpuDecap, "gtpu_decap",
           "decapsulates GTP-U (outer Eth/IP/UDP/GTP-U) to the inner IP packet")
