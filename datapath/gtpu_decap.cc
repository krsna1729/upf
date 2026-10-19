// SPDX-License-Identifier: BSD-3-Clause

#include "gtpu_decap.h"

#include <algorithm>
#include <cstdint>
#include <format>
#include <span>
#include <string>

// Before every other BESS header: glog must win over protobuf's absl logging
// in this translation unit (docs/plugin-api.md, "Logging").
#include "utils/logging.h"

#include "commands.h"
#include "framework/plugin.h"
#include "pdu_session_qfi.h"
#include "tunnel/tunnel.h"
#include "utils/endian.h"
#include "utils/ether.h"

// The class has no resource tables: a session's TEID is a rule of the
// classifier in front of this module (the compiler writes one per session).
const ResourceTables GtpuDecap::resource_tables = {};

namespace {

// The extension header type of a PDU Session Container (TS 29.281 table
// 5.2.2.7-1): what the chain below is walked for.
constexpr uint8_t kPduSessionContainer = 0x85;

// The `qfi` attribute's contract (pdu_session_qfi.h): what this module writes
// when the chain carried no PDU Session Container at all.
using upf::kNoPduSessionQfi;

// The QFI a G-PDU's next-extension-header chain carries, or kNoPduSessionQfi
// when the chain holds no PDU Session Container (pdu_session_qfi.h: the
// attribute's contract, and why the "no container" value cannot be 0). The
// tunnel library walks and validates the
// chain but reports only the first header's type, so the walk is repeated here
// for the one byte the container carries: the QFI sits in the low six bits of
// its second content octet (TS 38.415 5.5.2.1: PPP and RQI above it in the
// downlink frame; 5.5.2.2: spare above it in the uplink one). `end` is where
// the library found the T-PDU, which is where the chain ends.
uint8_t PduSessionQfi(std::span<const uint8_t> frame, size_t gtpu, size_t end) noexcept {
  // The optional tail -- sequence number, N-PDU number and the octet that
  // names the first extension header -- is present only if a flag of octet 1
  // is set (TS 29.281 5.1); without the E flag there is no chain to walk.
  if ((frame[gtpu] & 0x04) == 0) {
    return kNoPduSessionQfi;
  }
  const size_t limit = std::min(end, frame.size());
  if (gtpu + bess::tunnel::kGtpuBaseBytes + 4 > limit) {
    return kNoPduSessionQfi;
  }
  uint8_t next = frame[gtpu + bess::tunnel::kGtpuBaseBytes + 3];
  size_t off = gtpu + bess::tunnel::kGtpuBaseBytes + 4;
  for (size_t n = 0; next != 0; n++) {
    // One extension header: a length octet in 4-octet units -- the count takes
    // in that octet and the next-type octet that ends the header -- then the
    // content, then the next header's type.
    if (n > 16 || off + 4 > limit) {
      return kNoPduSessionQfi;
    }
    const size_t len = size_t{frame[off]} * 4;
    if (len == 0 || off + len > limit) {
      return kNoPduSessionQfi;
    }
    if (next == kPduSessionContainer) {
      // The length is in 4-octet units, so a non-zero one covers at least the
      // two content octets this reads: the PDU type and then the QFI.
      return static_cast<uint8_t>(frame[off + 2] & 0x3f);
    }
    next = frame[off + len - 1];
    off += len;
  }
  // The chain ended without a PDU Session Container.
  return kNoPduSessionQfi;
}

}  // namespace

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

  // The QFI of the PDU Session Container, one byte: 0..63 (TS 38.415 5.5.3.3's
  // six-bit field) or kNoPduSessionQfi when the G-PDU carried no container
  // (pdu_session_qfi.h). Like the TEID above it is written,
  // not read: the modules that consume it -- the uplink PDR table's match
  // fields -- own the reader side of the attribute.
  qfi_attr_ = AddMetadataAttr("qfi", sizeof(uint8_t), AccessMode::kWrite);
  if (qfi_attr_ < 0) {
    return CommandFailure(-qfi_attr_, "add_metadata_attr() failed");
  }

  return CommandSuccess();
}

void GtpuDecap::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  // One offset load per batch: the layout does not change under a batch.
  const auto teid_offset = attr_offset(teid_attr_);
  const auto qfi_offset = attr_offset(qfi_attr_);
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

    const std::span<const uint8_t> frame(pkt.head_data<const uint8_t *>(), pkt.head_len());
    bess::conntrack::ParsedFlowPacket outer;
    bess::tunnel::GtpuInfo info;
    const auto status = bess::tunnel::DecapGtpu(frame, outer, info, port_, pkt.total_len());
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

    // The QFI of the PDU Session Container the chain carries, or
    // kNoPduSessionQfi when it carries none. The write happens either way: a
    // packet's metadata area is reused mbuf space that nothing clears between
    // packets, so a G-PDU without a container would otherwise hand the
    // previous packet's QFI to the table that matches on it -- the reason
    // WildcardMatch writes its action id on a miss too
    // (core/modules/wildcard_match.cc). The "no container" value sits above
    // the QFI range, because 0 is a flow a real gNB sends
    // (pdu_session_qfi.h).
    const uint8_t qfi = PduSessionQfi(
        frame, size_t{outer.l4_offset} + bess::tunnel::kUdpBytes,
        info.tunnel.inner_offset);
    set_attr_with_offset<uint8_t>(qfi_offset, pkt, qfi);

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
           "inner IP packet, writing the TEID to `upf_teid` and the QFI of a "
           "PDU Session Container to `qfi` (255 when none was carried); the "
           "F-TEID match is the classifier in front of it")
