// SPDX-License-Identifier: BSD-3-Clause

#ifndef UPF_DATAPATH_GTPU_CONTROL_H_
#define UPF_DATAPATH_GTPU_CONTROL_H_

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <utility>

#include "end_marker_log.h"
#include "gtpu_wire.h"
#include "packet.h"
#include "packet_parse.h"
#include "tunnel/tunnel.h"
#include "utils/checksum.h"
#include "utils/ether.h"
#include "utils/ip.h"

// The GTP-U control path (TS 29.281 7.2, 7.3): the per-packet half of what
// arrives on GtpuDecap gate 2 -- Echo Requests, peer Error Indications, End
// Markers and valid G-PDUs whose endpoint-scoped F-TEID is not admitted. One
// implementation for the GtpuResponder module and UpfAppliance: each owns its
// counters and log and calls AnswerGtpuControl per packet.
//
// An Echo Request and an unknown G-PDU are answered in place: the request with
// its Ethernet, IP and UDP addresses swapped, the type replaced, and the
// lengths recomputed. An Echo Response keeps the S-flag field (5.1: an echo
// sets it), sends TEID 0, and carries the two IEs 7.2.2 names: the mandatory
// Recovery IE with a zero restart counter, and this node's Recovery Time Stamp
// -- 17 bytes after the header. An Error Indication has S clear, TEID 0 (the
// peer knows no tunnel toward this node), and one TEID IE naming the TEID it
// used -- 5 bytes after the header. Both copy nothing but their tail, allocate
// nothing, and read no session state. A peer Error Indication is counted and
// an End Marker logged; neither is answered. Everything else is dropped, with
// the reason in the verdict.

namespace upf::datapath {

// The GTP-U message types this path knows (TS 29.281 table 6.1-1); a G-PDU is
// bess::tunnel::kGtpuGpdu.
inline constexpr uint8_t kGtpuEchoRequest = 1;
inline constexpr uint8_t kGtpuEchoResponse = 2;
inline constexpr uint8_t kGtpuErrorIndication = 26;
inline constexpr uint8_t kGtpuEndMarker = 254;

// An Echo Response's information elements (7.2.2): the Recovery IE is
// mandatory there "due to backwards compatibility reasons" and its restart
// counter is set to zero (8.2); the Recovery Time Stamp is optional (8.7) and
// is sent, because a peer that reads it learns when this UPF's GTP-U entity
// started.
inline constexpr uint8_t kGtpuRecoveryIe = 14;            // TV, one octet (8.2)
inline constexpr uint8_t kGtpuRecoveryTimeStampIe = 231;  // TLV, two-octet length (8.7)

// Bytes after the mandatory 8-octet header: the S-flag field (sequence number,
// N-PDU number, next extension header type -- 5.1 sets S for an echo) and the
// two IEs above.
inline constexpr size_t kGtpuEchoResponseTail = 4 + 2 + 11;

// An Error Indication's tail (7.3.1): no S-flag field (5.1 leaves S clear) and
// the TEID IE -- type 16, TV, a four-octet value -- naming the TEID the peer
// used for a tunnel this node does not have.
inline constexpr uint8_t kGtpuTeidIe = 16;
inline constexpr size_t kGtpuErrorIndicationTail = 1 + 4;

// Seconds from 1900-01-01 to 1970-01-01: the Recovery Time Stamp's value is
// "the time in seconds relative to 00:00:00 on 1 January 1900" (8.7), which is
// the first four octets of an RFC 5905 timestamp.
inline constexpr uint64_t kGtpuEpoch1900 = 2208988800ULL;

// The Error Indications a peer sent (7.3.1), one monotonic count per TEID it
// could not reach. Nothing is cleared: a reading is what the controller's
// report compares with the count it last reported.
//
// Record is a relaxed add: an Error Indication is a rare message, and a count
// lost to a concurrent reader would be one indication, not a count of packets
// -- the same price urr_count pays for a stamp. A slot is claimed with a
// compare-exchange from 0, so two workers that race on a new TEID agree on one
// slot and the loser adds to the same entry. Small on purpose: a flood of
// distinct TEIDs is a scan, not a tunnel loss, and a full table is counted
// (Untracked) rather than dropped silently.
//
// Memory (BESS D-198): the slots are glibc memory, made by the constructor and
// never grown; Bytes/GlibcBytes is what the constructor allocates.
class GtpuErrorCounts {
 public:
  // 64 slots are 1 KiB.
  static constexpr size_t kDefaultSlots = 64;

  explicit GtpuErrorCounts(size_t slots = kDefaultSlots)
      : slots_(std::make_unique<Slot[]>(slots)), size_(slots) {}

  static size_t Bytes(size_t slots) noexcept { return slots * sizeof(Slot); }
  static size_t GlibcBytes(size_t slots) noexcept { return Bytes(slots); }
  size_t bytes() const noexcept { return Bytes(size_); }

  // One more indication naming `teid`. TEID 0 is the echo path and names no
  // tunnel: the caller never records it (0 marks an empty slot).
  void Record(uint32_t teid) noexcept {
    for (size_t i = 0; i < size_; i++) {
      Slot &slot = slots_[(teid + i) % size_];
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

  // visit(teid, count) for every claimed slot, in slot order.
  template <typename Visit>
  void ForEach(Visit &&visit) const {
    for (size_t i = 0; i < size_; i++) {
      const uint32_t teid = slots_[i].teid.load(std::memory_order_acquire);
      if (teid != 0) {
        visit(teid, slots_[i].count.load(std::memory_order_relaxed));
      }
    }
  }

  // The count for `teid`, or nullopt when no slot holds it (TEID 0 never
  // does).
  std::optional<uint64_t> Count(uint32_t teid) const noexcept {
    for (size_t i = 0; i < size_; i++) {
      if (slots_[i].teid.load(std::memory_order_acquire) == teid) {
        if (teid == 0) {
          return std::nullopt;
        }
        return slots_[i].count.load(std::memory_order_relaxed);
      }
    }
    return std::nullopt;
  }

  // Indications lost to a full table.
  uint64_t Untracked() const noexcept { return untracked_.load(std::memory_order_relaxed); }

 private:
  // 0 is empty, and the count only grows.
  struct Slot {
    std::atomic<uint32_t> teid{0};
    std::atomic<uint64_t> count{0};
  };

  std::unique_ptr<Slot[]> slots_;
  size_t size_;
  std::atomic<uint64_t> untracked_{0};
};

// What AnswerGtpuControl did with a packet.
enum class GtpuControlVerdict : uint8_t {
  // Answered: the frame now holds the reply; send it back where it came from.
  kEchoResponse,     // to an Echo Request (7.2.2)
  kErrorIndication,  // to a G-PDU on a TEID this node does not have (7.3.1)
  // Consumed, never answered: drop the packet.
  kPeerErrorIndication,  // counted in GtpuControlContext::errors when set
  kEndMarker,            // logged in GtpuControlContext::end_markers when set
  // Dropped.
  kNotLinear,        // a chained packet: the reply is written over one segment
  kMalformed,        // the tunnel codec or a GTP-U length/flag check refuses it
  kNotOurPort,       // not UDP to GtpuControlContext::port
  kUnsupportedType,  // a message type this path does not answer
  kZeroTeid,         // a G-PDU on TEID 0, which is the echo path (7.1)
  kUnsupportedL3,    // IPv4 with options, or an outer header the reply cannot carry
  kNoRoom,           // no tailroom for the reply
};

inline constexpr bool IsGtpuReply(GtpuControlVerdict verdict) noexcept {
  return verdict == GtpuControlVerdict::kEchoResponse ||
         verdict == GtpuControlVerdict::kErrorIndication;
}

// What the control path needs from its owner, fixed for a burst.
struct GtpuControlContext {
  uint16_t port = bess::tunnel::kGtpuPort;  // the UDP port messages arrive on
  uint32_t recovery_time_stamp = 0;  // seconds from 1900 to this entity's start (8.7)
  GtpuErrorCounts *errors = nullptr;      // peer Error Indications; nullptr: not counted
  EndMarkerLog *end_markers = nullptr;    // End Markers; nullptr: not logged
  size_t worker = 0;                      // the end_markers ring this worker writes
};

struct GtpuControlResult {
  GtpuControlVerdict verdict;
  size_t reply_len = 0;  // the reply's frame length when IsGtpuReply(verdict)
};

// The frame form: `frame` is one contiguous Ethernet frame, and `tailroom`
// writable bytes follow it. A reply is written in place (into the tailroom
// when it is longer than the request) and its length returned; the caller
// sets the frame's length to it. `endpoint_of()` returns the logical endpoint
// the packet arrived on (0: unknown) and is called only for an End Marker
// that is logged.
template <typename EndpointOf>
GtpuControlResult AnswerGtpuControlFrame(std::span<uint8_t> frame, size_t tailroom,
                                         const GtpuControlContext &ctx,
                                         EndpointOf &&endpoint_of) noexcept {
  using Verdict = GtpuControlVerdict;
  namespace tunnel = bess::tunnel;
  uint8_t *const data = frame.data();
  const size_t len = frame.size();

  bess::packet::ParsedFrame outer;
  tunnel::GtpuInfo info{};
  const auto status =
      tunnel::DecapGtpu(std::span<const uint8_t>(data, len), outer, info, ctx.port, len);
  if (status != tunnel::DecapError::kOk && status != tunnel::DecapError::kNotTunnel)
      [[unlikely]] {
    return {Verdict::kMalformed};
  }
  if (outer.l4 != bess::packet::L4Kind::kUdp || outer.dst_port != ctx.port) [[unlikely]] {
    return {Verdict::kNotOurPort};
  }

  // The core tunnel codec has checked lengths, optional fields and extension
  // chains. A valid unknown G-PDU may carry a PDU Session Container too.
  const size_t gtp = size_t{outer.l4_offset} + tunnel::kUdpBytes;
  if (len < gtp + tunnel::kGtpuBaseBytes) [[unlikely]] {
    return {Verdict::kMalformed};
  }
  uint8_t *g = data + gtp;
  if (g[1] != tunnel::kGtpuGpdu && (g[0] & 0x05) != 0) [[unlikely]] {
    return {Verdict::kMalformed};
  }
  // The G-PDU is answered when its TEID is nonzero: TEID 0 is the echo path,
  // and no G-PDU carries it. Validate before inspecting Error Indication IEs.
  const size_t gtpu_length = GetWire16(g + 2);
  if (gtp + tunnel::kGtpuBaseBytes + gtpu_length > size_t{outer.l4_offset} + outer.l4_length ||
      GetWire16(data + outer.l4_offset + 4) != outer.l4_length ||
      ((g[0] & 0x02) != 0 && gtpu_length < 4)) {
    return {Verdict::kMalformed};
  }
  // The peer could not reach a TEID this UPF sent to; record, never reply.
  if (g[1] == kGtpuErrorIndication) {
    if (ctx.errors != nullptr) {
      // Offsets are from g, which is the GTP-U header: the tail follows the
      // mandatory 8 octets, plus the S-flag field when the peer set S.
      size_t at = tunnel::kGtpuBaseBytes;
      if ((g[0] & 0x02) != 0) {
        at += 4;
      }
      const size_t end = tunnel::kGtpuBaseBytes + gtpu_length;
      while (at + 5 <= end) {  // a TV IE is type(1) + value(4)
        if (g[at] == kGtpuTeidIe) {
          const uint32_t teid = GetWire32(g + at + 1);
          if (teid != 0) {
            ctx.errors->Record(teid);
          }
          break;
        }
        at += 5;
      }
    }
    return {Verdict::kPeerErrorIndication};
  }
  // The peer ends the stream on this UPF's own tunnel (7.3.2): the header's
  // TEID is the local one. Record it with the endpoint it came in on, never
  // reply.
  if (g[1] == kGtpuEndMarker) {
    if (ctx.end_markers != nullptr) {
      const uint32_t endpoint = endpoint_of();
      const uint32_t teid = GetWire32(g + 4);
      if (endpoint != 0 && teid != 0) {
        ctx.end_markers->Record(ctx.worker, {endpoint, teid});
      }
    }
    return {Verdict::kEndMarker};
  }
  const bool echo = g[1] == kGtpuEchoRequest;
  if (!echo && g[1] != tunnel::kGtpuGpdu) [[unlikely]] {
    return {Verdict::kUnsupportedType};
  }
  if (gtp + tunnel::kGtpuBaseBytes + gtpu_length > len) [[unlikely]] {
    return {Verdict::kMalformed};
  }
  uint32_t unknown_teid = 0;
  if (!echo) {
    unknown_teid = GetWire32(g + 4);
    if (unknown_teid == 0) [[unlikely]] {
      return {Verdict::kZeroTeid};
    }
  }
  const size_t tail_len = echo ? kGtpuEchoResponseTail : kGtpuErrorIndicationTail;

  // The request's sequence number, which the reply answers with (5.1: a
  // receiver interprets it when S is set). An Echo Request accepted without
  // the S-flag field has none, and the reply sends zero.
  uint16_t sequence = 0;
  if (echo && (g[0] & 0x02) != 0) {
    if (gtp + tunnel::kGtpuBaseBytes + 2 > len) [[unlikely]] {
      return {Verdict::kMalformed};  // S set, no room for the field
    }
    sequence = GetWire16(g + 8);
  }

  // Every check before the first write: a dropped packet is left as it came.
  // IPv4 options are unsupported by the no-options checksum helper.
  const size_t udp_length = tunnel::kUdpBytes + tunnel::kGtpuBaseBytes + tail_len;
  const bool ipv4 = outer.l3 == bess::packet::L3Kind::kIpv4;
  uint8_t *ip = data + outer.l3_offset;
  size_t ipv6_payload = 0;
  if (ipv4) {
    const auto *ip4 = reinterpret_cast<const bess::utils::Ipv4 *>(ip);
    if (ip4->version != 4 || ip4->header_length != 5) [[unlikely]] {
      return {Verdict::kUnsupportedL3};
    }
  } else if (outer.l3 == bess::packet::L3Kind::kIpv6) {
    if (outer.l4_offset < outer.l3_offset + 40 || (ip[0] >> 4) != 6) [[unlikely]] {
      return {Verdict::kUnsupportedL3};
    }
    ipv6_payload = size_t{outer.l4_offset} - (size_t{outer.l3_offset} + 40) + udp_length;
    if (ipv6_payload > 65535) [[unlikely]] {
      return {Verdict::kUnsupportedL3};
    }
  } else {
    return {Verdict::kUnsupportedL3};
  }
  // Whatever the request carried after its header -- a Recovery Time Stamp of
  // its own, a private extension -- is replaced by this node's answer, which
  // may be longer than the request.
  const size_t keep = gtp + tunnel::kGtpuBaseBytes;
  if (keep + tail_len > len + tailroom) [[unlikely]] {
    return {Verdict::kNoRoom};
  }

  // IPv4 or IPv6 endpoints and lengths.
  if (ipv4) {
    auto *ip4 = reinterpret_cast<bess::utils::Ipv4 *>(ip);
    std::swap(ip4->src, ip4->dst);
    ip4->length = bess::utils::be16_t(static_cast<uint16_t>(tunnel::kIpv4Bytes + udp_length));
    ip4->checksum = bess::utils::CalculateIpv4NoOptChecksum(*ip4);
  } else {
    for (size_t octet = 0; octet < 16; ++octet) {
      std::swap(ip[8 + octet], ip[24 + octet]);
    }
    PutWire16(ip + 4, static_cast<uint16_t>(ipv6_payload));
  }

  // Swap the UDP ports, cut its length, and zero its checksum. IPv4 permits
  // zero; IPv6's mandatory checksum is computed once the reply tail exists.
  uint8_t *udp = data + outer.l4_offset;
  const uint16_t src_port = GetWire16(udp);
  PutWire16(udp, GetWire16(udp + 2));
  PutWire16(udp + 2, src_port);
  PutWire16(udp + 4, static_cast<uint16_t>(udp_length));
  PutWire16(udp + 6, 0);

  // The GTP-U header. An Echo Response carries the S-flag field and TEID 0
  // (7.1); an Error Indication carries S clear and TEID 0 too -- the peer
  // knows no tunnel toward this node, so the TEID it used travels in the IE
  // below (7.3.1).
  g[0] = echo ? 0x32 : 0x30;  // version 1, PT 1; S 1 for the echo, E/PN 0
  g[1] = echo ? kGtpuEchoResponse : kGtpuErrorIndication;
  PutWire16(g + 2, static_cast<uint16_t>(tail_len));
  PutWire32(g + 4, 0);

  // The frame's own addresses: the reply leaves toward whoever asked.
  auto *eth = reinterpret_cast<bess::utils::Ethernet *>(data);
  std::swap(eth->src_addr, eth->dst_addr);

  uint8_t *tail = data + keep;
  if (!echo) {
    tail[0] = kGtpuTeidIe;
    PutWire32(tail + 1, unknown_teid);
  } else {
    PutWire16(tail, sequence);
    tail[2] = 0;  // N-PDU number
    tail[3] = 0;  // next extension header type
    tail[4] = kGtpuRecoveryIe;
    tail[5] = 0;  // the restart counter is set to zero (8.2)
    tail[6] = kGtpuRecoveryTimeStampIe;
    tail[7] = 0;
    tail[8] = 8;
    PutWire32(tail + 9, ctx.recovery_time_stamp);
    std::memset(tail + 13, 0, 4);  // the 32-bit fraction
  }
  if (!ipv4) {
    PutWire16(udp + 6, Ipv6UdpChecksum(ip + 8, ip + 24, udp, udp_length));
  }
  return {echo ? Verdict::kEchoResponse : Verdict::kErrorIndication, keep + tail_len};
}

// The packet form: AnswerGtpuControlFrame over a linear packet's one segment,
// with the packet's length set to a reply's. The room was checked before the
// first write, so the length change cannot fail.
template <typename EndpointOf>
GtpuControlVerdict AnswerGtpuControl(bess::PacketRef pkt, const GtpuControlContext &ctx,
                                     EndpointOf &&endpoint_of) noexcept {
  if (!pkt.is_linear()) [[unlikely]] {
    return GtpuControlVerdict::kNotLinear;
  }
  const size_t len = pkt.head_len();
  const GtpuControlResult result = AnswerGtpuControlFrame(
      std::span<uint8_t>(pkt.head_data<uint8_t *>(), len), pkt.tailroom(), ctx, endpoint_of);
  if (IsGtpuReply(result.verdict)) {
    if (result.reply_len < len) {
      pkt.trim(static_cast<uint16_t>(len - result.reply_len));
    } else if (result.reply_len > len) {
      pkt.append(static_cast<uint16_t>(result.reply_len - len));
    }
  }
  return result.verdict;
}

}  // namespace upf::datapath

#endif  // UPF_DATAPATH_GTPU_CONTROL_H_
