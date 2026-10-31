// SPDX-License-Identifier: BSD-3-Clause

#ifndef UPF_DATAPATH_GTPU_ADMISSION_H_
#define UPF_DATAPATH_GTPU_ADMISSION_H_

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

#include "packet_parse.h"
#include "fteid_resource.h"
#include "pdu_session_qfi.h"
#include "tunnel/tunnel.h"

namespace upf::datapath {

enum class GtpuParseKind : uint8_t { kMalformed, kControl, kGpdu };
// The End Marker's message type (TS 29.281 table 6.1-1).
inline constexpr uint8_t kGtpuEndMarker = 254;
struct ParsedGtpu {
  bess::packet::ParsedFrame outer{};
  bess::tunnel::GtpuInfo info{};
  FteidId key{};
  uint8_t family = 0;
};

// What GtpuDecap writes for an admitted G-PDU: the admission context its F-TEID
// entry carries (the whole tunnel identity the PDR tables key) and the QFI of
// its PDU Session Container.
struct GtpuDecapMetadata {
  uint32_t fteid_context = 0;
  uint8_t qfi = upf::kNoPduSessionQfi;
};

inline uint8_t PduSessionQfi(std::span<const uint8_t> frame, size_t gtpu,
                             size_t end) noexcept {
  if ((frame[gtpu] & 0x04) == 0) return upf::kNoPduSessionQfi;
  const size_t limit = std::min(end, frame.size());
  if (gtpu + bess::tunnel::kGtpuBaseBytes + 4 > limit)
    return upf::kNoPduSessionQfi;
  uint8_t next = frame[gtpu + bess::tunnel::kGtpuBaseBytes + 3];
  size_t offset = gtpu + bess::tunnel::kGtpuBaseBytes + 4;
  for (size_t n = 0; next != 0; ++n) {
    if (n > 16 || offset + 4 > limit) return upf::kNoPduSessionQfi;
    const size_t length = size_t{frame[offset]} * 4;
    if (length == 0 || offset + length > limit)
      return upf::kNoPduSessionQfi;
    if (next == 0x85) return frame[offset + 2] & 0x3f;
    next = frame[offset + length - 1];
    offset += length;
  }
  return upf::kNoPduSessionQfi;
}

// ParseGtpuAdmission splits a frame into a G-PDU, a control message or a
// malformed one, and builds the F-TEID key both of the first two are on.
inline GtpuParseKind ParseGtpuAdmission(std::span<const uint8_t> frame,
                                       size_t total_length, uint16_t port,
                                       uint32_t endpoint_id,
                                       ParsedGtpu *parsed) noexcept {
  if (endpoint_id == 0) return GtpuParseKind::kMalformed;
  const auto status = bess::tunnel::DecapGtpu(
      frame, parsed->outer, parsed->info, port, total_length);
  const bool control =
      status == bess::tunnel::DecapError::kNotTunnel &&
      parsed->outer.l4 == bess::packet::L4Kind::kUdp &&
      parsed->outer.dst_port == port &&
      parsed->info.message_type != bess::tunnel::kGtpuGpdu &&
      parsed->info.message_type != 0;
  if (!control && status != bess::tunnel::DecapError::kOk)
    return GtpuParseKind::kMalformed;
  parsed->family = parsed->outer.l3 == bess::packet::L3Kind::kIpv4 ? 4 : 6;
  auto &key = parsed->key;
  key[0] = static_cast<uint8_t>(endpoint_id >> 24);
  key[1] = static_cast<uint8_t>(endpoint_id >> 16);
  key[2] = static_cast<uint8_t>(endpoint_id >> 8);
  key[3] = static_cast<uint8_t>(endpoint_id);
  key[4] = parsed->family;
  std::copy(parsed->outer.dst.begin(), parsed->outer.dst.end(), key.begin() + 5);
  if (parsed->family == 4) {
    std::fill(key.begin() + 5, key.begin() + 17, 0);
    std::copy_n(parsed->outer.dst.begin(), 4, key.begin() + 17);
  }
  const uint32_t teid = parsed->info.tunnel.id;
  key[21] = static_cast<uint8_t>(teid >> 24);
  key[22] = static_cast<uint8_t>(teid >> 16);
  key[23] = static_cast<uint8_t>(teid >> 8);
  key[24] = static_cast<uint8_t>(teid);
  return control ? GtpuParseKind::kControl : GtpuParseKind::kGpdu;
}


// FteidOutputGate is the decap gate for one lookup: 0 known UL, 1 known DL, 2
// unknown or still pending. A known entry's context is stored in *context.
inline uint8_t FteidOutputGate(bool hit, uint64_t value,
                               uint32_t *context) noexcept {
  if (!hit || value == 0) return 2;
  const auto *record = reinterpret_cast<const FteidResource::DirectionRecord *>(
      static_cast<uintptr_t>(value));
  const uint8_t state = record->state.load(std::memory_order_acquire);
  if (state != 1 && state != 2) return 2;  // pending reservations are not admitted
  *context = record->context_id;
  return static_cast<uint8_t>(state - 1);  // known UL leaves gate 0, known DL gate 1
}

// FteidRelays is the End Marker relays of one lookup: the tunnels an End
// Marker on an admitted F-TEID leaves relayed through, or null when the F-TEID
// is unknown, still pending, or forwards into no tunnel.
inline const EndMarkerRelays *FteidRelays(bool hit, uint64_t value) noexcept {
  if (!hit || value == 0) return nullptr;
  const auto *record = reinterpret_cast<const FteidResource::DirectionRecord *>(
      static_cast<uintptr_t>(value));
  const uint8_t state = record->state.load(std::memory_order_acquire);
  if (state != 1 && state != 2) return nullptr;
  return record->relays.load(std::memory_order_acquire);
}

inline GtpuDecapMetadata BuildGtpuDecapMetadata(
    std::span<const uint8_t> frame, const ParsedGtpu &parsed,
    uint32_t fteid_context) noexcept {
  GtpuDecapMetadata metadata;
  metadata.fteid_context = fteid_context;
  metadata.qfi = PduSessionQfi(
      frame, size_t{parsed.outer.l4_offset} + bess::tunnel::kUdpBytes,
      parsed.info.tunnel.inner_offset);
  return metadata;
}

inline void WriteDecapsulatedEthernetHeader(
    uint8_t *destination, const uint8_t *outer_ethernet,
    uint8_t inner_version) noexcept {
  std::memcpy(destination, outer_ethernet, 12);
  const uint16_t ether_type = inner_version == 4 ? 0x0800 : 0x86dd;
  destination[12] = static_cast<uint8_t>(ether_type >> 8);
  destination[13] = static_cast<uint8_t>(ether_type);
}

}  // namespace upf::datapath

#endif  // UPF_DATAPATH_GTPU_ADMISSION_H_
