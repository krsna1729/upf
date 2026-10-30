// SPDX-License-Identifier: BSD-3-Clause
#ifndef UPF_DATAPATH_UPF_APPLIANCE_FRAME_H_
#define UPF_DATAPATH_UPF_APPLIANCE_FRAME_H_
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include "gtpu_wire.h"
namespace upf::appliance {
// Deliberately fixed IPv4 offsets, even for IPv6: this is the graph's PDR
// key, not a general five-tuple parser. Every byte is initialized on success.
inline bool BuildPdrKey(std::span<const uint8_t> frame, bool downlink,
                        uint32_t domain, uint32_t context, uint8_t qfi,
                        std::span<std::byte> key) noexcept {
  if (frame.size() < 38 || key.size() < (downlink ? 22u : 18u)) return false;
  auto *out = reinterpret_cast<uint8_t *>(key.data());
  std::memcpy(out, frame.data() + 26, 4);
  std::memcpy(out + 4, frame.data() + 30, 4);
  out[8] = frame[23];
  std::memcpy(out + 9, frame.data() + 34, 4);
  size_t at = 13;
  if (downlink) { upf::datapath::PutWire32(out + at, domain); at += 4; }
  upf::datapath::PutWire32(out + at, context);
  out[at + 4] = qfi;
  return true;
}
inline uint64_t UsageOctets(std::span<const uint8_t> frame, size_t total) noexcept {
  if (frame.size() >= 34 && frame[12] == 8 && frame[13] == 0) {
    const uint16_t length = upf::datapath::GetWire16(frame.data() + 16);
    if (length >= 20 && length <= total - 14) return length;
  }
  return total;
}
}  // namespace upf::appliance
#endif
