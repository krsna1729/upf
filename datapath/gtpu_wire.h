// SPDX-License-Identifier: BSD-3-Clause

#ifndef UPF_DATAPATH_GTPU_WIRE_H_
#define UPF_DATAPATH_GTPU_WIRE_H_

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

#include "tunnel/tunnel.h"
#include "utils/endian.h"
#include "utils/ether.h"

namespace upf::datapath {

inline void PutWire16(uint8_t *p, uint16_t value) noexcept {
  p[0] = static_cast<uint8_t>(value >> 8);
  p[1] = static_cast<uint8_t>(value);
}
inline uint16_t GetWire16(const uint8_t *p) noexcept {
  return static_cast<uint16_t>((uint16_t{p[0]} << 8) | p[1]);
}

inline void WriteOuterIpv6(uint8_t *ip, const uint8_t src[16],
                           const uint8_t dst[16], uint16_t payload_length,
                           uint8_t traffic_class, uint8_t hop_limit = 64) noexcept {
  ip[0] = static_cast<uint8_t>(0x60 | (traffic_class >> 4));
  ip[1] = static_cast<uint8_t>((traffic_class << 4) & 0xf0);
  PutWire16(ip + 4, payload_length);
  ip[6] = 17;
  ip[7] = hop_limit;
  std::memcpy(ip + 8, src, 16);
  std::memcpy(ip + 24, dst, 16);
}

inline uint16_t Ipv6UdpChecksum(const uint8_t *src, const uint8_t *dst,
                                const uint8_t *udp, size_t length) noexcept {
  uint32_t sum = 0;
  auto add = [&sum](const uint8_t *bytes, size_t size) {
    for (size_t i = 0; i + 1 < size; i += 2)
      sum += static_cast<uint32_t>((uint16_t{bytes[i]} << 8) | bytes[i + 1]);
    if (size & 1) sum += static_cast<uint32_t>(bytes[size - 1]) << 8;
  };
  add(src, 16);
  add(dst, 16);
  sum += static_cast<uint32_t>((length >> 16) & 0xffff);
  sum += static_cast<uint32_t>(length & 0xffff);
  sum += 17;
  add(udp, length);
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  const uint16_t result = static_cast<uint16_t>(~sum);
  return result == 0 ? 0xffff : result;
}

inline uint8_t ApplyTransportMarking(uint8_t inner, uint16_t marking) noexcept {
  if (marking == 0) return inner;
  const uint8_t mask = static_cast<uint8_t>(marking);
  const uint8_t marked = static_cast<uint8_t>(marking >> 8);
  return static_cast<uint8_t>((marked & mask) | (inner & ~mask));
}

inline void WritePduSessionContainer(uint8_t *gtpu, uint8_t qfi) noexcept {
  gtpu[0] |= 0x04;
  gtpu[8] = gtpu[9] = gtpu[10] = 0;
  gtpu[11] = 0x85;
  gtpu[12] = 1;
  gtpu[13] = 0;
  gtpu[14] = static_cast<uint8_t>(qfi & 0x3f);
  gtpu[15] = 0;
}

inline size_t GtpOuterHeaderBytes(uint8_t family, bool has_qfi) noexcept {
  if (family != 4 && family != 6) return 0;
  return 14 + (family == 4 ? 20 : 40) + 8 + 8 + (has_qfi ? 8 : 0);
}

// Writes outer headers before an already-positioned inner IP packet. Inner
// bytes are neither copied nor modified.
inline bool WriteGtpOuterHeaders(uint8_t *frame, uint8_t family,
                                const uint8_t local[16],
                                const uint8_t peer[16], uint32_t teid,
                                uint16_t source_port, uint16_t dest_port,
                                bool has_qfi, uint8_t qfi, uint16_t marking,
                                uint8_t inner_class,
                                size_t inner_length) noexcept {
  const size_t header_length = GtpOuterHeaderBytes(family, has_qfi);
  if (header_length == 0 || (has_qfi && qfi > 63) ||
      (!has_qfi && qfi != 0) || teid == 0)
    return false;
  const size_t extension_length = has_qfi ? 8 : 0;
  const size_t ip_length = 8 + 8 + extension_length + inner_length;
  if (ip_length > 65535 || (family == 4 && ip_length > 65515) ||
      extension_length + inner_length > 65535 ||
      8 + extension_length + inner_length > 65535)
    return false;

  std::memset(frame, 0, 14);
  auto *ethernet = reinterpret_cast<bess::utils::Ethernet *>(frame);
  ethernet->ether_type = bess::utils::be16_t(
      family == 4 ? bess::utils::Ethernet::Type::kIpv4
                  : bess::utils::Ethernet::Type::kIpv6);
  const uint8_t traffic_class = ApplyTransportMarking(inner_class, marking);
  const size_t ip_header_length = family == 4 ? 20 : 40;
  uint8_t *ip = frame + 14;
  if (family == 4) {
    bess::utils::be32_t src, dst;
    std::memcpy(&src, local + 12, 4);
    std::memcpy(&dst, peer + 12, 4);
    bess::tunnel::WriteIpv4(ip, src, dst, 17,
                            static_cast<uint16_t>(ip_length), 64,
                            traffic_class);
  } else {
    WriteOuterIpv6(ip, local, peer, static_cast<uint16_t>(ip_length),
                   traffic_class, 64);
  }
  uint8_t *udp = ip + ip_header_length;
  const size_t gtpu_payload = 8 + extension_length + inner_length;
  bess::tunnel::WriteUdp(udp, source_port, dest_port,
                         static_cast<uint16_t>(gtpu_payload));
  uint8_t *gtpu = udp + 8;
  bess::tunnel::WriteGtpu(
      gtpu, teid, static_cast<uint16_t>(extension_length + inner_length));
  if (has_qfi) WritePduSessionContainer(gtpu, qfi);
  if (family == 6)
    PutWire16(udp + 6, Ipv6UdpChecksum(local, peer, udp, 8 + gtpu_payload));
  return true;
}

}  // namespace upf::datapath

#endif  // UPF_DATAPATH_GTPU_WIRE_H_
