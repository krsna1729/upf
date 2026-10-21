// SPDX-License-Identifier: BSD-3-Clause

#include "gtpu_responder.h"

#include <cstdint>
#include <cstring>
#include <ctime>
#include <string>
#include <utility>

// Before every other BESS header: glog must win over protobuf's absl logging
// in this translation unit (docs/plugin-api.md, "Logging").
#include "utils/logging.h"

#include "commands.h"
#include "conntrack/packet_parse.h"
#include "framework/plugin.h"
#include "tunnel/tunnel.h"
#include "utils/checksum.h"
#include "utils/endian.h"
#include "utils/ether.h"
#include "utils/ip.h"

using bess::utils::be16_t;
using bess::utils::be32_t;

// The GTP-U message types this module knows (TS 29.281 table 6.1-1).
constexpr uint8_t kEchoRequest = 1;
constexpr uint8_t kEchoResponse = 2;
constexpr uint8_t kErrorIndication = 26;
constexpr uint8_t kGtpdu = 255;

// An Echo Response's information elements (TS 29.281 7.2.2): the
// Recovery IE is mandatory there "due to backwards compatibility reasons" and
// its restart counter is set to zero (8.2); the Recovery Time Stamp is
// optional (8.7) and this module sends it, because a peer that reads it learns
// when this UPF's GTP-U entity started.
constexpr uint8_t kRecovery = 14;              // TV, one octet of value (8.2)
constexpr uint8_t kRecoveryTimeStamp = 231;    // TLV: two octets of length (8.7)

// Bytes after the mandatory 8-octet header: the S-flag field (sequence number,
// N-PDU number, next extension header type -- 5.1 sets S for an echo) and the
// two IEs above.
constexpr size_t kReplyTail = 4 + 2 + 11;

// An Error Indication's tail (7.3.1): no S-flag field (5.1 leaves S clear) and
// the TEID IE -- type 16, TV, a four-octet value -- naming the TEID the peer
// used for a tunnel this node does not have.
constexpr uint8_t kTeidIe = 16;
constexpr size_t kErrorTail = 1 + 4;

// Seconds from 1900-01-01 to 1970-01-01: the Recovery Time Stamp's value is
// "the time in seconds relative to 00:00:00 on 1 January 1900" (8.7), which is
// the first four octets of an RFC 5905 timestamp.
constexpr uint64_t kEpoch1900 = 2208988800ULL;

const ResourceTables GtpuResponder::resource_tables = {};

const Commands GtpuResponder::cmds = {
    {"get_errors", "upf.pb.GtpuResponderCommandGetErrorsArg",
     MODULE_CMD_FUNC(&GtpuResponder::CommandGetErrors), Command::THREAD_SAFE,
     "upf.pb.GtpuResponderCommandGetErrorsResponse"},
};

namespace {

// One 16-bit field at `p`, network order.
inline uint16_t Get16(const uint8_t *p) { return static_cast<uint16_t>(p[0] << 8 | p[1]); }
inline void Put16(uint8_t *p, uint16_t v) {
  p[0] = static_cast<uint8_t>(v >> 8);
  p[1] = static_cast<uint8_t>(v);
}
inline uint32_t Get32(const uint8_t *p) {
  return static_cast<uint32_t>(p[0]) << 24 | static_cast<uint32_t>(p[1]) << 16 |
         static_cast<uint32_t>(p[2]) << 8 | static_cast<uint32_t>(p[3]);
}
inline void Put32(uint8_t *p, uint32_t v) {
  p[0] = static_cast<uint8_t>(v >> 24);
  p[1] = static_cast<uint8_t>(v >> 16);
  p[2] = static_cast<uint8_t>(v >> 8);
  p[3] = static_cast<uint8_t>(v);
}

}  // namespace

CommandResponse GtpuResponder::Init(const upf::pb::GtpuResponderArg &arg) {
  if (arg.port() != 0) {
    if (arg.port() > 65535) {
      return CommandFailure(EINVAL, "invalid 'port' field");
    }
    port_ = static_cast<uint16_t>(arg.port());
  } else {
    port_ = bess::tunnel::kGtpuPort;
  }

  // The stamp names when this GTP-U entity started (8.7). The graph's start
  // is the entity's, so the clock at Init is the honest default; a deployment
  // that keeps a node's identity across a graph replay -- `upfd -checkpoint`
  // does that for the PFCP side -- passes the value it means.
  const uint64_t seconds =
      arg.recovery_time_stamp() != 0
          ? arg.recovery_time_stamp()
          : static_cast<uint64_t>(std::time(nullptr)) + kEpoch1900;
  if (seconds > 0xffffffffULL) {
    return CommandFailure(EINVAL, "invalid 'recovery_time_stamp' field");
  }
  stamp_ = static_cast<uint32_t>(seconds);
  if (arg.track_errors()) {
    errors_ = std::make_unique<ErrorSlot[]>(kErrorSlots);
  }
  if (!arg.reply_gate_attr().empty()) {
    reply_gate_attr_ = AddMetadataAttr(
        arg.reply_gate_attr(), sizeof(be32_t),
        bess::metadata::Attribute::AccessMode::kRead);
    if (reply_gate_attr_ < 0) {
      return CommandFailure(-reply_gate_attr_, "add_metadata_attr() failed");
    }
  }
  return CommandSuccess();
}

// RecordError adds one to the slot of a TEID the peer could not reach. A
// relaxed load-add-store: an Error Indication is a rare message, and a count
// lost to a concurrent reader would be one indication, not a count of packets
// -- the same price urr_count pays for a stamp. A slot is claimed with a
// compare-exchange from 0, so two workers that race on a new TEID agree on one
// slot and the loser adds to the same entry.
void GtpuResponder::RecordError(uint32_t teid) {
  for (size_t i = 0; i < kErrorSlots; i++) {
    ErrorSlot &slot = errors_[(teid + i) % kErrorSlots];
    uint32_t held = slot.teid.load(std::memory_order_acquire);
    if (held == 0) {
      uint32_t empty = 0;
      if (!slot.teid.compare_exchange_strong(empty, teid, std::memory_order_acq_rel)) {
        held = empty;
      } else {
        held = teid;
      }
    }
    if (held == teid) {
      slot.count.fetch_add(1, std::memory_order_relaxed);
      return;
    }
  }
  untracked_.fetch_add(1, std::memory_order_relaxed);
}

CommandResponse GtpuResponder::CommandGetErrors(
    const upf::pb::GtpuResponderCommandGetErrorsArg &arg) {
  upf::pb::GtpuResponderCommandGetErrorsResponse response;
  if (errors_ == nullptr) {
    return CommandSuccess(response);
  }
  auto report = [&](size_t i) {
    const uint32_t teid = errors_[i].teid.load(std::memory_order_acquire);
    if (teid == 0) {
      return;
    }
    auto *entry = response.add_errors();
    entry->set_teid(teid);
    entry->set_count(errors_[i].count.load(std::memory_order_relaxed));
  };
  if (arg.teids_size() == 0) {
    for (size_t i = 0; i < kErrorSlots; i++) {
      report(i);
    }
  } else {
    for (uint32_t teid : arg.teids()) {
      for (size_t i = 0; i < kErrorSlots; i++) {
        if (errors_[i].teid.load(std::memory_order_acquire) == teid) {
          report(i);
          break;
        }
      }
    }
  }
  response.set_untracked(untracked_.load(std::memory_order_relaxed));
  return CommandSuccess(response);
}

void GtpuResponder::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  gate_idx_t ogates[bess::PacketBatch::kMaxBurst];
  const size_t cnt = batch->cnt();
  const auto reply_offset =
      reply_gate_attr_ >= 0 ? attr_offset(reply_gate_attr_) : -1;

  for (size_t i = 0; i < cnt; i++) {
    bess::PacketRef pkt = batch->packet(i);
    ogates[i] = DROP_GATE;
    uint32_t reply_gate = 0;
    if (reply_gate_attr_ >= 0) {
      if (!bess::metadata::IsValidOffset(reply_offset)) continue;
      reply_gate = get_attr_with_offset<be32_t>(reply_offset, pkt).value();
      if (reply_gate >= MAX_GATES) continue;
    }

    // The reply is written in place over one segment, so a chained packet is
    // not something this module can answer.
    if (not pkt.is_linear()) [[unlikely]] {
      continue;
    }

    bess::conntrack::ParsedFlowPacket outer;
    bess::tunnel::GtpuInfo info{};
    const auto status = bess::tunnel::DecapGtpu(
        std::span<const uint8_t>(pkt.head_data<const uint8_t *>(), pkt.head_len()),
        outer, info, port_, pkt.total_len());
    if (status != bess::tunnel::DecapError::kOk &&
        status != bess::tunnel::DecapError::kNotTunnel) [[unlikely]] {
      continue;
    }
    if (outer.l4 != bess::conntrack::L4Kind::kUdp || outer.dst_port != port_) [[unlikely]] {
      continue;
    }

    // The core tunnel codec has checked lengths, optional fields and extension
    // chains. A valid unknown G-PDU may carry a PDU Session Container too.
    const size_t gtp = size_t{outer.l4_offset} + bess::tunnel::kUdpBytes;
    if (pkt.head_len() < gtp + bess::tunnel::kGtpuBaseBytes) [[unlikely]] {
      continue;
    }
    uint8_t *g = pkt.head_data<uint8_t *>() + gtp;
    if (g[1] != kGtpdu && (g[0] & 0x05) != 0) [[unlikely]] {
      continue;
    }
    // Two messages reach this module through the TEID table's default gate: an
    // Echo Request (7.1, TEID 0) and a G-PDU whose TEID no session names
    // (7.3.1). The second is answered with an Error Indication when its TEID is
    // not 0 -- TEID 0 is the echo path, and no G-PDU carries it.
    // Validate before inspecting Error Indication IEs, even without ingress.
    if (gtp + bess::tunnel::kGtpuBaseBytes + Get16(g + 2) >
            size_t{outer.l4_offset} + outer.l4_length ||
        Get16(pkt.head_data<const uint8_t *>() + outer.l4_offset + 4) !=
            outer.l4_length ||
        ((g[0] & 0x02) != 0 && Get16(g + 2) < 4)) {
      continue;
    }
    // The peer could not reach a TEID this UPF sent to; record, never reply.
    if (g[1] == kErrorIndication) {
      if (errors_ != nullptr) {
        // Offsets are from g, which is the GTP-U header: the tail follows the
        // mandatory 8 octets, plus the S-flag field when the peer set S.
        size_t at = bess::tunnel::kGtpuBaseBytes;
        if ((g[0] & 0x02) != 0) {
          at += 4;
        }
        const size_t end = bess::tunnel::kGtpuBaseBytes + Get16(g + 2);
        while (at + 5 <= end) {  // a TV IE is type(1) + value(4)
          if (g[at] == kTeidIe) {
            uint32_t teid = Get32(g + at + 1);
            if (teid != 0) {
              RecordError(teid);
            }
            break;
          }
          at += 5;
        }
      }
      continue;  // no reply: ogates[i] stays DROP_GATE
    }
    const bool echo = g[1] == kEchoRequest;
    if (!echo && g[1] != kGtpdu) [[unlikely]] {
      continue;  // a message type this module does not answer
    }
    if (gtp + bess::tunnel::kGtpuBaseBytes + Get16(g + 2) > pkt.total_len()) [[unlikely]] {
      continue;
    }
    uint32_t unknownTeid = 0;
    if (!echo) {
      unknownTeid = Get32(g + 4);
      if (unknownTeid == 0) [[unlikely]] {
        continue;  // TEID 0 is the echo path (7.1), not a failed tunnel
      }
    }
    const size_t tailLen = echo ? kReplyTail : kErrorTail;

    // The request's sequence number, which the reply answers with (5.1: a
    // receiver interprets it when S is set). An Echo Request this module
    // accepts without the S-flag field has none, and the reply sends zero.
    uint16_t sequence = 0;
    if (echo && (g[0] & 0x02) != 0) {
      if (gtp + bess::tunnel::kGtpuBaseBytes + 2 > pkt.total_len()) [[unlikely]] {
        continue;  // S set, no room for the field
      }
      sequence = Get16(g + 8);
    }

    // The outer IPv4 header, rewritten in place: the two addresses swapped,
    // the length cut to the reply's, the checksum recomputed. An IPv4 header
    // with options is not one `CalculateIpv4NoOptChecksum` covers, so it is
    // not one this module replies to.
    auto *ip = reinterpret_cast<bess::utils::Ipv4 *>(pkt.head_data<uint8_t *>() +
                                                     outer.l3_offset);
    if (ip->version != 4 || ip->header_length != 5) [[unlikely]] {
      continue;
    }
    std::swap(ip->src, ip->dst);
    ip->length = be16_t(static_cast<uint16_t>(bess::tunnel::kIpv4Bytes +
                                              bess::tunnel::kUdpBytes +
                                              bess::tunnel::kGtpuBaseBytes + tailLen));
    ip->checksum = bess::utils::CalculateIpv4NoOptChecksum(*ip);

    // The UDP header: the ports swapped -- so the reply leaves for the port
    // the request came from -- the length cut, checksum 0 (legal over IPv4,
    // and what the encap writes on the way out too).
    uint8_t *udp = pkt.head_data<uint8_t *>() + outer.l4_offset;
    const uint16_t src_port = Get16(udp);
    Put16(udp, Get16(udp + 2));
    Put16(udp + 2, src_port);
    Put16(udp + 4, static_cast<uint16_t>(bess::tunnel::kUdpBytes +
                                         bess::tunnel::kGtpuBaseBytes + tailLen));
    Put16(udp + 6, 0);

    // The GTP-U header. An Echo Response carries the S-flag field and TEID 0
    // (7.1); an Error Indication carries S clear and TEID 0 too -- the peer
    // knows no tunnel toward this node, so the TEID it used travels in the
    // IE below (7.3.1).
    g[0] = echo ? 0x32 : 0x30;  // version 1, PT 1; S 1 for the echo, E/PN 0
    g[1] = echo ? kEchoResponse : kErrorIndication;
    Put16(g + 2, static_cast<uint16_t>(tailLen));
    auto *teid = reinterpret_cast<be32_t *>(g + 4);
    *teid = be32_t(0);

    // The frame's own addresses: the reply leaves toward whoever asked.
    auto *eth = pkt.head_data<bess::utils::Ethernet *>();
    std::swap(eth->src_addr, eth->dst_addr);

    // Drop whatever the request carried -- a Recovery Time Stamp of its own,
    // a private extension -- and write this node's answer in its place. The
    // tail is appended, not copied over: the reply is longer than a request
    // that carried no IE at all.
    const size_t keep = gtp + bess::tunnel::kGtpuBaseBytes;
    if (pkt.total_len() > keep) {
      pkt.trim(static_cast<uint16_t>(pkt.total_len() - keep));
    }
    auto *tail = static_cast<uint8_t *>(pkt.append(static_cast<uint16_t>(tailLen)));
    if (tail == nullptr) [[unlikely]] {
      continue;  // no tailroom for the reply
    }
    if (!echo) {
      tail[0] = kTeidIe;
      Put32(tail + 1, unknownTeid);
      ogates[i] = static_cast<gate_idx_t>(reply_gate);
      continue;
    }
    Put16(tail, sequence);
    tail[2] = 0;  // N-PDU number
    tail[3] = 0;  // next extension header type
    tail[4] = kRecovery;
    tail[5] = 0;  // the restart counter is set to zero (8.2)
    tail[6] = kRecoveryTimeStamp;
    tail[7] = 0;
    tail[8] = 8;
    tail[9] = static_cast<uint8_t>(stamp_ >> 24);
    tail[10] = static_cast<uint8_t>(stamp_ >> 16);
    tail[11] = static_cast<uint8_t>(stamp_ >> 8);
    tail[12] = static_cast<uint8_t>(stamp_);
    std::memset(tail + 13, 0, 4);  // the 32-bit fraction

    ogates[i] = static_cast<gate_idx_t>(reply_gate);
  }

  EmitBatch(ctx, batch, ogates);
}

std::string GtpuResponder::GetDesc() const { return std::format("port {}", port_); }

ADD_MODULE(GtpuResponder, "gtpu_responder",
           "answers GTP-U Echo Requests (type 1) with the reply (type 2): the "
           "graph routes TEID-0 messages here, and everything else is dropped")
