// SPDX-License-Identifier: BSD-3-Clause

#include <gtest/gtest.h>

#include <algorithm>
#include <any>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <span>
#include <thread>
#include <vector>

#include "utils/logging.h"
#include "dataplane/resource.h"
#include "end_marker_log.h"
#include "fteid_resource.h"
#include "flow/shared_exact_index.h"
#include "gtpu_admission.h"
#include "gtpu_wire.h"
#include "rcu/rcu_domain.h"
#include "tunnel/tunnel.h"
#include "utils/checksum.h"
#include "utils/endian.h"
#include "utils/dpdk_memory.h"
#include "utils/ether.h"

namespace {
using bess::flow::SharedExactIndex;
using bess::utils::be16_t;
using upf::datapath::FteidId;

struct TestIndex {
  explicit TestIndex(size_t capacity)
      : domain(64), index(SharedExactIndex::Create(
            sizeof(FteidId), capacity, domain, bess::utils::MemoryNode())) {}
  bess::rcu::RcuDomain domain;
  std::unique_ptr<SharedExactIndex> index;
};

std::vector<uint8_t> Gtpu4(uint8_t message_type = bess::tunnel::kGtpuGpdu,
                           bool bad_ip_length = false,
                           bool bad_gtpu_length = false,
                           uint32_t teid = 0x10203040) {
  constexpr size_t kPayload = 20;
  constexpr size_t kEthernet = 14;
  std::vector<uint8_t> frame(kEthernet + 20 + 8 + 8 + kPayload);
  auto *eth = reinterpret_cast<bess::utils::Ethernet *>(frame.data());
  eth->ether_type = be16_t(bess::utils::Ethernet::Type::kIpv4);
  for (size_t i = 0; i < 6; ++i) {
    frame[i] = static_cast<uint8_t>(i + 1);
    frame[6 + i] = static_cast<uint8_t>(i + 7);
  }
  uint8_t *ip = frame.data() + kEthernet;
  bess::tunnel::WriteIpv4(ip, bess::utils::be32_t(0x0a000001),
      bess::utils::be32_t(0x0a000002), 17,
      static_cast<uint16_t>(8 + 8 + kPayload));
  uint8_t *udp = ip + 20;
  bess::tunnel::WriteUdp(udp, 2152, 2152, static_cast<uint16_t>(8 + kPayload));
  uint8_t *gtpu = udp + 8;
  bess::tunnel::WriteGtpu(gtpu, teid, static_cast<uint16_t>(kPayload));
  gtpu[1] = message_type;
  if (bad_gtpu_length) gtpu[3] = 0xff;
  frame[kEthernet + 20 + 8 + 8] = 0x45;
  if (bad_ip_length) ip[3] = 10;
  return frame;
}

std::vector<uint8_t> Gtpu6(bool extension = false) {
  constexpr size_t kPayload = 40;
  const size_t ip_extension = extension ? 8 : 0;
  constexpr size_t kEthernet = 14;
  std::vector<uint8_t> frame(kEthernet + 40 + ip_extension + 8 + 8 +
                             (extension ? 8 : 0) + kPayload);
  auto *eth = reinterpret_cast<bess::utils::Ethernet *>(frame.data());
  eth->ether_type = be16_t(bess::utils::Ethernet::Type::kIpv6);
  uint8_t *ip = frame.data() + kEthernet;
  ip[0] = 0x60;
  ip[4] = static_cast<uint8_t>(
      (ip_extension + 8 + 8 + (extension ? 8 : 0) + kPayload) >> 8);
  ip[5] = static_cast<uint8_t>(
      ip_extension + 8 + 8 + (extension ? 8 : 0) + kPayload);
  ip[6] = extension ? 0 : 17;
  ip[7] = 55;
  ip[8] = 0x20;
  ip[24] = 0x20;
  uint8_t *udp = ip + 40;
  for (size_t i = 0; i < 6; ++i) {
    frame[i] = static_cast<uint8_t>(i + 1);
    frame[6 + i] = static_cast<uint8_t>(i + 7);
  }
  if (extension) {
    udp[0] = 17;
    udp[1] = 0;
    udp += 8;
  }
  bess::tunnel::WriteUdp(
      udp, 2152, 2152,
      static_cast<uint16_t>(8 + (extension ? 8 : 0) + kPayload));
  uint8_t *gtpu = udp + 8;
  bess::tunnel::WriteGtpu(
      gtpu, 0x10203040,
      static_cast<uint16_t>((extension ? 8 : 0) + kPayload));
  if (!extension) {
    gtpu[8] = 0x60;
  } else {
    gtpu[0] |= 0x04;
    gtpu[8] = gtpu[9] = gtpu[10] = 0;
    gtpu[11] = 0x85;
    gtpu[12] = 1;
    gtpu[13] = 0;
    gtpu[14] = 9;
    gtpu[15] = 0;
    gtpu[16] = 0x60;
  }
  return frame;
}

FteidId Key(uint32_t endpoint, uint8_t family, uint32_t teid,
            uint8_t address_suffix) {
  FteidId id{};
  id[0] = static_cast<uint8_t>(endpoint >> 24);
  id[1] = static_cast<uint8_t>(endpoint >> 16);
  id[2] = static_cast<uint8_t>(endpoint >> 8);
  id[3] = static_cast<uint8_t>(endpoint);
  id[4] = family;
  id[20] = address_suffix;
  id[21] = static_cast<uint8_t>(teid >> 24);
  id[22] = static_cast<uint8_t>(teid >> 16);
  id[23] = static_cast<uint8_t>(teid >> 8);
  id[24] = static_cast<uint8_t>(teid);
  return id;
}

void Publish(upf::datapath::FteidResource &resource, const FteidId &id,
             uint8_t direction, uint32_t context = 7,
             upf::datapath::EndMarkerRelays relays = {}) {
  auto reservation = resource.Reserve(bess::dataplane::Op::Upsert(
      resource.name(), bess::dataplane::EncodeKey(id),
      std::any(upf::datapath::FteidRecord{direction, context, std::move(relays)})));
  ASSERT_TRUE(reservation.has_value());
  bess::dataplane::Retirer retirer;
  reservation->staged->Publish(retirer);
}

uint64_t TableValue(const SharedExactIndex &table, const FteidId &key,
                    bool *hit) {
  uint64_t value = 0;
  *hit = table.LookupBatch(reinterpret_cast<const std::byte *>(key.data()),
                           key.size(), &value, 1) != 0;
  return value;
}

uint8_t TableDirection(const SharedExactIndex &table, const FteidId &key,
                       bool *hit) {
  const uint64_t value = TableValue(table, key, hit);
  if (!*hit) return 255;
  const auto *record = reinterpret_cast<const upf::datapath::FteidResource::
                                         DirectionRecord *>(
      static_cast<uintptr_t>(value));
  return static_cast<uint8_t>(record->state.load(std::memory_order_acquire) - 1);
}

TEST(GtpuAdmission, BuildsCompleteEndpointScopedKeysAndDirectionGates) {
  auto ipv4 = Gtpu4();
  upf::datapath::ParsedGtpu parsed4;
  EXPECT_EQ(upf::datapath::ParseGtpuAdmission(ipv4, ipv4.size(), 2152, 7,
                                               &parsed4),
            upf::datapath::GtpuParseKind::kGpdu);
  EXPECT_EQ(parsed4.family, 4);
  EXPECT_EQ(parsed4.key[0], 0);
  EXPECT_EQ(parsed4.key[3], 7);
  EXPECT_EQ(parsed4.key[4], 4);
  EXPECT_EQ(parsed4.key[17], 10);
  EXPECT_EQ(parsed4.key[20], 2);
  EXPECT_EQ(parsed4.key[24], 0x40);

  auto ipv6 = Gtpu6(true);
  upf::datapath::ParsedGtpu parsed6;
  EXPECT_EQ(upf::datapath::ParseGtpuAdmission(ipv6, ipv6.size(), 2152, 8,
                                               &parsed6),
            upf::datapath::GtpuParseKind::kGpdu);
  EXPECT_EQ(parsed6.family, 6);
  EXPECT_EQ(parsed6.key[3], 8);
  EXPECT_EQ(parsed6.key[4], 6);
  const auto metadata6 =
      upf::datapath::BuildGtpuDecapMetadata(ipv6, parsed6, 8);
  EXPECT_EQ(metadata6.fteid_context, 8);
  EXPECT_EQ(metadata6.qfi, 9);

  const auto first = Key(7, 4, 0x10203040, 2);
  EXPECT_NE(first, Key(8, 4, 0x10203040, 2));
  EXPECT_NE(first, Key(7, 4, 0x10203040, 3));
  EXPECT_NE(first, Key(7, 6, 0x10203040, 2));
  upf::datapath::FteidResource::DirectionRecord ul;
  upf::datapath::FteidResource::DirectionRecord dl;
  ul.context_id = 0x51;
  dl.context_id = 0x52;
  ul.state.store(1, std::memory_order_relaxed);
  dl.state.store(2, std::memory_order_relaxed);
  const auto metadata =
      upf::datapath::BuildGtpuDecapMetadata(ipv4, parsed4, 0x51);
  EXPECT_EQ(metadata.fteid_context, 0x51);
  EXPECT_EQ(metadata.qfi, upf::kNoPduSessionQfi);
  constexpr size_t inner_length = 20;
  std::vector<uint8_t> decapsulated(14 + inner_length);
  std::copy_n(ipv4.data() + parsed4.info.tunnel.inner_offset, inner_length,
              decapsulated.data() + 14);
  upf::datapath::WriteDecapsulatedEthernetHeader(decapsulated.data(),
                                                 ipv4.data(), 4);
  EXPECT_EQ(std::vector<uint8_t>(decapsulated.begin(), decapsulated.begin() + 12),
            std::vector<uint8_t>(ipv4.begin(), ipv4.begin() + 12));
  EXPECT_EQ(decapsulated[12], 0x08);
  EXPECT_EQ(decapsulated[13], 0x00);
  EXPECT_TRUE(std::equal(ipv4.begin() + parsed4.info.tunnel.inner_offset,
                         ipv4.begin() + parsed4.info.tunnel.inner_offset +
                             inner_length,
                         decapsulated.begin() + 14));
  const uint64_t ul_value = reinterpret_cast<uintptr_t>(&ul);
  const uint64_t dl_value = reinterpret_cast<uintptr_t>(&dl);
  uint32_t context = 0;
  EXPECT_EQ(upf::datapath::FteidOutputGate(true, ul_value, &context), 0);
  EXPECT_EQ(context, 0x51);
  EXPECT_EQ(upf::datapath::FteidOutputGate(true, dl_value, &context), 1);
  EXPECT_EQ(context, 0x52);
  dl.state.store(0, std::memory_order_relaxed);
  context = 0;
  EXPECT_EQ(upf::datapath::FteidOutputGate(true, dl_value, &context), 2);
  EXPECT_EQ(upf::datapath::FteidOutputGate(false, ul_value, &context), 2);
  EXPECT_EQ(context, 0) << "a pending or missing entry must not admit a context";
}

TEST(GtpuAdmission, SplitsControlFromMalformedPackets) {
  auto control = Gtpu4(1);
  upf::datapath::ParsedGtpu parsed;
  EXPECT_EQ(upf::datapath::ParseGtpuAdmission(control, control.size(), 2152, 7,
                                               &parsed),
            upf::datapath::GtpuParseKind::kControl);
  auto unknown = Gtpu4();
  EXPECT_EQ(upf::datapath::ParseGtpuAdmission(unknown, unknown.size(), 2152, 7,
                                               &parsed),
            upf::datapath::GtpuParseKind::kGpdu);
  uint32_t context = 0;
  EXPECT_EQ(upf::datapath::FteidOutputGate(false, 0, &context), 2);
  auto malformed4 = Gtpu4(bess::tunnel::kGtpuGpdu, true);
  EXPECT_EQ(upf::datapath::ParseGtpuAdmission(malformed4, malformed4.size(),
              2152, 7, &parsed), upf::datapath::GtpuParseKind::kMalformed);
  auto bad_ipv4_options = Gtpu4();
  bad_ipv4_options[14] = 0x4f;
  EXPECT_EQ(upf::datapath::ParseGtpuAdmission(
                bad_ipv4_options, bad_ipv4_options.size(), 2152, 7, &parsed),
            upf::datapath::GtpuParseKind::kMalformed);
  auto malformed_gtpu = Gtpu4(bess::tunnel::kGtpuGpdu, false, true);
  EXPECT_EQ(upf::datapath::ParseGtpuAdmission(malformed_gtpu,
              malformed_gtpu.size(), 2152, 7, &parsed),
            upf::datapath::GtpuParseKind::kMalformed);
  auto malformed6 = Gtpu6();
  malformed6[18] = malformed6[19] = 0xff;
  EXPECT_EQ(upf::datapath::ParseGtpuAdmission(malformed6, malformed6.size(),
              2152, 7, &parsed), upf::datapath::GtpuParseKind::kMalformed);
  auto bad_extension = Gtpu6(true);
  bad_extension[55] = 0xff;
  EXPECT_EQ(upf::datapath::ParseGtpuAdmission(bad_extension,
              bad_extension.size(), 2152, 7, &parsed),
            upf::datapath::GtpuParseKind::kMalformed);
  auto bad_gtpu_extension = Gtpu6(true);
  bad_gtpu_extension[82] = 0;
  EXPECT_EQ(upf::datapath::ParseGtpuAdmission(
                bad_gtpu_extension, bad_gtpu_extension.size(), 2152, 7,
                &parsed),
            upf::datapath::GtpuParseKind::kMalformed);
}

TEST(FteidResource, FullKeyDirectionPendingCapacityAndReuse) {
  TestIndex table(4);
  ASSERT_NE(table.index, nullptr);
  upf::datapath::FteidResource resource("decap/fteids", *table.index,
                                        table.domain, 4);
  EXPECT_EQ(upf::datapath::FteidResource::Bytes("decap/fteids", *table.index,
                                                table.domain, 4),
            resource.bytes());
  const auto first = Key(1, 4, 55, 1);
  const auto second = Key(2, 4, 55, 1);
  const auto third = Key(1, 4, 55, 2);
  const auto ipv6 = Key(1, 6, 55, 1);

  auto pending = resource.Reserve(bess::dataplane::Op::Upsert(
      resource.name(), bess::dataplane::EncodeKey(first),
      std::any(upf::datapath::FteidRecord{0, 7})));
  ASSERT_TRUE(pending.has_value());
  bool hit = false;
  const uint64_t pending_value = TableValue(*table.index, first, &hit);
  EXPECT_TRUE(hit);
  uint32_t context = 0;
  EXPECT_EQ(upf::datapath::FteidOutputGate(hit, pending_value, &context), 2);
  EXPECT_FALSE(resource.Reserve(bess::dataplane::Op::Upsert(
      resource.name(), bess::dataplane::EncodeKey(Key(4, 4, 55, 1)),
      std::any(upf::datapath::FteidRecord{0, 0}))).has_value())
      << "an entry without an admission context was accepted";
  EXPECT_FALSE(resource.Contains(bess::dataplane::EncodeKey(first)));
  EXPECT_FALSE(resource.Reserve(bess::dataplane::Op::Upsert(
      resource.name(), bess::dataplane::EncodeKey(first),
      std::any(upf::datapath::FteidRecord{1, 7}))).has_value());
  pending->staged->Abort();
  EXPECT_FALSE(TableValue(*table.index, first, &hit));
  EXPECT_FALSE(hit);

  Publish(resource, first, 0);
  Publish(resource, second, 1);
  Publish(resource, third, 0);
  Publish(resource, first, 0);  // same-direction duplicate is a no-op
  Publish(resource, ipv6, 1);
  EXPECT_FALSE(resource.Reserve(bess::dataplane::Op::Upsert(
      resource.name(), bess::dataplane::EncodeKey(first),
      std::any(upf::datapath::FteidRecord{1, 7}))).has_value());
  EXPECT_FALSE(resource.Reserve(bess::dataplane::Op::Upsert(
      resource.name(), bess::dataplane::EncodeKey(first),
      std::any(upf::datapath::FteidRecord{0, 8}))).has_value())
      << "a live key was silently given another admission context";
  EXPECT_EQ(resource.LiveCount(), 4u);
  EXPECT_EQ(TableDirection(*table.index, first, &hit), 0);
  EXPECT_TRUE(hit);
  EXPECT_EQ(TableDirection(*table.index, second, &hit), 1);
  EXPECT_TRUE(hit);
  EXPECT_FALSE(resource.Contains(bess::dataplane::EncodeKey(Key(3, 4, 55, 1))));
}

TEST(FteidResource, RejectsCapacityAndReusesAbortedReservations) {
  TestIndex table(1);
  ASSERT_NE(table.index, nullptr);
  upf::datapath::FteidResource resource("decap/fteids", *table.index,
                                        table.domain, 1);
  const auto first = Key(1, 4, 9, 1);
  const auto second = Key(2, 4, 9, 1);
  auto pending = resource.Reserve(bess::dataplane::Op::Upsert(
      resource.name(), bess::dataplane::EncodeKey(first),
      std::any(upf::datapath::FteidRecord{0, 7})));
  ASSERT_TRUE(pending.has_value());
  EXPECT_FALSE(resource.Reserve(bess::dataplane::Op::Upsert(
      resource.name(), bess::dataplane::EncodeKey(second),
      std::any(upf::datapath::FteidRecord{1, 7}))).has_value());
  pending->staged->Abort();
  Publish(resource, second, 1);
  EXPECT_EQ(resource.LiveCount(), 1u);
  auto erase = resource.Reserve(bess::dataplane::Op::Erase(
      resource.name(), bess::dataplane::EncodeKey(second)));
  ASSERT_TRUE(erase.has_value());
  erase->staged->Abort();
  EXPECT_TRUE(resource.Contains(bess::dataplane::EncodeKey(second)));
}

TEST(GtpuOuterWriter, BuildsIpv4LengthsChecksumDscpQfiAndPreservesInner) {
  std::array<uint8_t, 16> local{}, peer{};
  local[12] = 10; local[15] = 1;
  peer[12] = 10; peer[15] = 2;
  constexpr size_t inner_length = 20;
  const size_t headers = upf::datapath::GtpOuterHeaderBytes(4, true);
  std::vector<uint8_t> frame(headers + inner_length);
  auto *inner = frame.data() + headers;
  inner[0] = 0x45;
  inner[1] = 0x13;
  inner[2] = 0;
  inner[3] = inner_length;
  for (size_t i = 4; i < inner_length; ++i) inner[i] = static_cast<uint8_t>(i);
  const std::vector<uint8_t> original(inner, inner + inner_length);
  ASSERT_TRUE(upf::datapath::WriteGtpOuterHeaders(frame.data(), 4,
      local.data(), peer.data(), 0x01020304, 12345, 2152, true, 9, 0x2afc,
      0x13, inner_length));
  auto *eth = reinterpret_cast<const bess::utils::Ethernet *>(frame.data());
  EXPECT_EQ(eth->src_addr.ToString(), "00:00:00:00:00:00");
  EXPECT_EQ(eth->dst_addr.ToString(), "00:00:00:00:00:00");
  const auto *ip = reinterpret_cast<const bess::utils::Ipv4 *>(frame.data() + 14);
  EXPECT_TRUE(bess::utils::VerifyIpv4NoOptChecksum(*ip));
  EXPECT_EQ(ip->length.value(), 64);
  EXPECT_EQ(ip->type_of_service, 0x2b);
  EXPECT_EQ(ip->ttl, 64);
  EXPECT_EQ(frame[26], 10);
  EXPECT_EQ(frame[29], 1);
  EXPECT_EQ(frame[30], 10);
  EXPECT_EQ(frame[33], 2);
  const uint8_t *udp = frame.data() + 14 + 20;
  EXPECT_EQ((uint16_t{udp[0]} << 8) | udp[1], 12345);
  EXPECT_EQ((uint16_t{udp[2]} << 8) | udp[3], 2152);
  EXPECT_EQ((uint16_t{udp[4]} << 8) | udp[5], 44);
  EXPECT_EQ(udp[6], 0);
  EXPECT_EQ(udp[7], 0);
  const uint8_t *gtpu = udp + 8;
  EXPECT_EQ((uint16_t{gtpu[2]} << 8) | gtpu[3], 28);
  EXPECT_EQ(gtpu[14], 9);
  EXPECT_TRUE(std::equal(original.begin(), original.end(), frame.begin() + headers));
}

TEST(GtpuOuterWriter, BuildsIpv6LengthsChecksumHopQfiAndPreservesInner) {
  std::array<uint8_t, 16> local{}, peer{};
  local[0] = peer[0] = 0x20;
  peer[15] = 1;
  constexpr size_t inner_length = 40;
  const size_t headers = upf::datapath::GtpOuterHeaderBytes(6, true);
  std::vector<uint8_t> frame(headers + inner_length);
  auto *inner = frame.data() + headers;
  inner[0] = 0x60;
  inner[1] = 0x13;
  for (size_t i = 2; i < inner_length; ++i) inner[i] = static_cast<uint8_t>(i);
  const std::vector<uint8_t> original(inner, inner + inner_length);
  ASSERT_TRUE(upf::datapath::WriteGtpOuterHeaders(frame.data(), 6,
      local.data(), peer.data(), 0x01020304, 12345, 2152, true, 9, 0, 0x13,
      inner_length));
  const uint8_t *ip = frame.data() + 14;
  EXPECT_EQ(ip[7], 64);
  EXPECT_EQ(upf::datapath::GetWire16(ip + 4), 64);
  EXPECT_EQ(ip[0], 0x61);
  EXPECT_EQ(ip[1], 0x30);
  EXPECT_TRUE(std::equal(local.begin(), local.end(), ip + 8));
  EXPECT_TRUE(std::equal(peer.begin(), peer.end(), ip + 24));
  const uint8_t *udp = ip + 40;
  EXPECT_EQ(upf::datapath::GetWire16(udp + 4), 64);
  EXPECT_NE(upf::datapath::GetWire16(udp + 6), 0);
  EXPECT_EQ(upf::datapath::Ipv6UdpChecksum(local.data(), peer.data(), udp, 64),
            0xffff);
  const uint8_t *gtpu = udp + 8;
  EXPECT_NE(gtpu[0] & 0x04, 0);
  EXPECT_EQ(upf::datapath::GetWire16(gtpu + 2), 48);
  EXPECT_EQ(gtpu[14], 9);
  EXPECT_TRUE(std::equal(original.begin(), original.end(), frame.begin() + headers));
}

TEST(GtpuOuterWriter, EncodesQfiZeroAndOmitsAnAbsentQfi) {
  std::array<uint8_t, 16> local{}, peer{};
  local[12] = peer[12] = 10;
  peer[15] = 2;
  constexpr size_t inner_length = 20;
  const size_t headers = upf::datapath::GtpOuterHeaderBytes(4, true);
  std::vector<uint8_t> frame(headers + inner_length);
  uint8_t *inner = frame.data() + headers;
  inner[0] = 0x45;
  ASSERT_TRUE(upf::datapath::WriteGtpOuterHeaders(frame.data(), 4,
      local.data(), peer.data(), 99, 12345, 2152, true, 0, 0, 0, inner_length));
  const uint8_t *gtpu = frame.data() + 14 + 20 + 8;
  EXPECT_NE(gtpu[0] & 0x04, 0);
  EXPECT_EQ(upf::datapath::GetWire16(gtpu + 2), 28);
  EXPECT_EQ(gtpu[14], 0);

  const size_t plain_headers = upf::datapath::GtpOuterHeaderBytes(4, false);
  std::vector<uint8_t> plain(plain_headers + inner_length);
  plain[plain_headers] = 0x45;
  ASSERT_TRUE(upf::datapath::WriteGtpOuterHeaders(plain.data(), 4,
      local.data(), peer.data(), 99, 12345, 2152, false, 0, 0, 0,
      inner_length));
  const uint8_t *plain_gtpu = plain.data() + 14 + 20 + 8;
  EXPECT_EQ(plain_gtpu[0] & 0x04, 0);
  EXPECT_EQ(upf::datapath::GetWire16(plain_gtpu + 2), 20);
  EXPECT_EQ(plain.size(), plain_headers + inner_length);
}

// The relayed End Marker is the one upfd builds for a tunnel
// (internal/session/endmarker.go endMarkerFrame): zero MACs, TTL/hop limit 64,
// UDP 2152 to 2152, GTP-U 0x30 type 254 length 0, the IPv4 frame padded to 60
// bytes and the IPv6 one with its UDP checksum.
TEST(GtpuOuterWriter, WritesTheEndMarkerUpfdBuildsForATunnel) {
  std::array<uint8_t, 16> local4{}, peer4{};
  std::copy_n(std::array<uint8_t, 4>{192, 0, 2, 1}.begin(), 4, local4.begin() + 12);
  std::copy_n(std::array<uint8_t, 4>{10, 20, 30, 9}.begin(), 4, peer4.begin() + 12);
  std::vector<uint8_t> frame4(upf::datapath::EndMarkerFrameBytes(4), 0xaa);
  ASSERT_TRUE(upf::datapath::WriteEndMarker(frame4.data(), 4, local4.data(),
                                            peer4.data(), 0x5566778b));
  const std::vector<uint8_t> want4 = {
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x00,
      0x45, 0x00, 0x00, 0x24, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x50, 0xab,
      0xc0, 0x00, 0x02, 0x01, 0x0a, 0x14, 0x1e, 0x09,
      0x08, 0x68, 0x08, 0x68, 0x00, 0x10, 0x00, 0x00,
      0x30, 0xfe, 0x00, 0x00, 0x55, 0x66, 0x77, 0x8b,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  EXPECT_EQ(frame4, want4);

  std::array<uint8_t, 16> local6{0x20, 0x01, 0x0d, 0xb8, 0, 0x09}, peer6 = local6;
  local6[15] = 1;
  peer6[15] = 2;
  std::vector<uint8_t> frame6(upf::datapath::EndMarkerFrameBytes(6), 0xaa);
  ASSERT_TRUE(upf::datapath::WriteEndMarker(frame6.data(), 6, local6.data(),
                                            peer6.data(), 0x77000012));
  const std::vector<uint8_t> want6 = {
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x86, 0xdd,
      0x60, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x40,
      0x20, 0x01, 0x0d, 0xb8, 0x00, 0x09, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
      0x20, 0x01, 0x0d, 0xb8, 0x00, 0x09, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
      0x08, 0x68, 0x08, 0x68, 0x00, 0x10, 0xeb, 0x66,
      0x30, 0xfe, 0x00, 0x00, 0x77, 0x00, 0x00, 0x12};
  EXPECT_EQ(frame6, want6);
}

upf::datapath::EndMarkerRelay Relay4(uint32_t teid, uint32_t domain) {
  upf::datapath::EndMarkerRelay relay;
  relay.teid = teid;
  relay.family = 4;
  std::copy_n(std::array<uint8_t, 4>{192, 0, 2, 1}.begin(), 4, relay.local.begin() + 12);
  std::copy_n(std::array<uint8_t, 4>{10, 20, 30, 9}.begin(), 4, relay.peer.begin() + 12);
  relay.transport_route_domain = domain;
  return relay;
}

// A burst through GtpuDecap's steps: parse every frame, one batch lookup, then
// each End Marker's relays written as new frames beside the burst. The one End
// Marker on an F-TEID whose PDR forwards into a tunnel leaves exactly once, as
// that tunnel's -- its TEID, from its local address to its peer, in its
// transport domain; the G-PDU and the Echo Request on that F-TEID, and the End
// Markers on an F-TEID that ends at N6 (no relays), on one still pending and
// on one nobody admitted, leave none.
TEST(EndMarkerRelay, OneEndMarkerInABurstLeavesOnceThroughItsFteidsTunnel) {
  TestIndex table(8);
  ASSERT_NE(table.index, nullptr);
  upf::datapath::FteidResource resource("decap/fteids", *table.index,
                                        table.domain, 8);
  constexpr uint32_t kEndpoint = 2;
  constexpr uint32_t kForwarding = 0x11223351, kEnding = 0x11223344,
                     kPending = 0x11223352, kUnknown = 0x11223399;
  constexpr uint8_t kEndMarker = upf::datapath::kGtpuEndMarker;
  auto key_of = [](uint32_t teid) {
    const auto frame = Gtpu4(kEndMarker, false, false, teid);
    upf::datapath::ParsedGtpu parsed;
    upf::datapath::ParseGtpuAdmission(frame, frame.size(), 2152, kEndpoint, &parsed);
    return parsed.key;
  };
  Publish(resource, key_of(kForwarding), 1, 7, {Relay4(0x5566778b, 3)});
  Publish(resource, key_of(kEnding), 0, 8);
  auto pending = resource.Reserve(bess::dataplane::Op::Upsert(
      resource.name(), bess::dataplane::EncodeKey(key_of(kPending)),
      std::any(upf::datapath::FteidRecord{1, 9, {Relay4(0x77, 3)}})));
  ASSERT_TRUE(pending.has_value());

  const std::vector<std::vector<uint8_t>> burst = {
      Gtpu4(kEndMarker, false, false, kForwarding),
      Gtpu4(bess::tunnel::kGtpuGpdu, false, false, kForwarding),
      Gtpu4(1, false, false, kForwarding),  // an Echo Request
      Gtpu4(kEndMarker, false, false, kEnding),
      Gtpu4(kEndMarker, false, false, kPending),
      Gtpu4(kEndMarker, false, false, kUnknown),
  };
  FteidId keys[8]{};
  bool end_marker[8]{};
  uint64_t values[8]{};
  for (size_t i = 0; i < burst.size(); ++i) {
    upf::datapath::ParsedGtpu parsed;
    const auto kind = upf::datapath::ParseGtpuAdmission(
        burst[i], burst[i].size(), 2152, kEndpoint, &parsed);
    ASSERT_NE(kind, upf::datapath::GtpuParseKind::kMalformed);
    keys[i] = parsed.key;
    end_marker[i] = kind == upf::datapath::GtpuParseKind::kControl &&
                    parsed.info.message_type == kEndMarker;
  }
  const uint64_t hits = table.index->LookupBatch(
      reinterpret_cast<const std::byte *>(keys), sizeof(keys[0]), values,
      burst.size());
  struct Relayed {
    std::vector<uint8_t> frame;
    uint32_t domain;
  };
  std::vector<Relayed> relayed;
  for (size_t i = 0; i < burst.size(); ++i) {
    if (!end_marker[i]) continue;
    const auto *relays = upf::datapath::FteidRelays(((hits >> i) & 1) != 0, values[i]);
    for (size_t r = 0; relays != nullptr && r < relays->size(); ++r) {
      const auto &relay = (*relays)[r];
      std::vector<uint8_t> frame(upf::datapath::EndMarkerFrameBytes(relay.family));
      ASSERT_TRUE(upf::datapath::WriteEndMarker(frame.data(), relay.family,
          relay.local.data(), relay.peer.data(), relay.teid));
      relayed.push_back({std::move(frame), relay.transport_route_domain});
    }
  }
  ASSERT_EQ(relayed.size(), 1u);
  const uint8_t *ip = relayed[0].frame.data() + 14;
  EXPECT_EQ(std::vector<uint8_t>(ip + 12, ip + 16), (std::vector<uint8_t>{192, 0, 2, 1}));
  EXPECT_EQ(std::vector<uint8_t>(ip + 16, ip + 20), (std::vector<uint8_t>{10, 20, 30, 9}));
  const uint8_t *gtpu = ip + 20 + 8;
  EXPECT_EQ(gtpu[1], kEndMarker);
  EXPECT_EQ(std::vector<uint8_t>(gtpu + 4, gtpu + 8),
            (std::vector<uint8_t>{0x55, 0x66, 0x77, 0x8b}));
  EXPECT_EQ(relayed[0].domain, 3u);
  pending->staged->Abort();
}

// The F-TEID's FAR moved to another tunnel: the same admission upserted with
// other relays replaces the list (retiring the old one), reads back, and an
// unchanged one is a no-op; a FAR that stops forwarding leaves none.
TEST(FteidResource, AnUpsertReplacesTheEndMarkerRelays) {
  TestIndex table(2);
  ASSERT_NE(table.index, nullptr);
  upf::datapath::FteidResource resource("decap/fteids", *table.index,
                                        table.domain, 2);
  const auto key = Key(1, 4, 55, 1);
  auto relays_now = [&] {
    bool hit = false;
    const uint64_t value = TableValue(*table.index, key, &hit);
    return upf::datapath::FteidRelays(hit, value);
  };
  auto upsert = [&](upf::datapath::EndMarkerRelays relays) {
    return resource.Reserve(bess::dataplane::Op::Upsert(
        resource.name(), bess::dataplane::EncodeKey(key),
        std::any(upf::datapath::FteidRecord{1, 7, std::move(relays)})));
  };
  Publish(resource, key, 1, 7, {Relay4(0x10, 1)});
  ASSERT_NE(relays_now(), nullptr);
  EXPECT_EQ(relays_now()->front().teid, 0x10u);

  auto moved = upsert({Relay4(0x20, 2)});
  ASSERT_TRUE(moved.has_value());
  EXPECT_TRUE(moved->existed);
  EXPECT_EQ(moved->footprint.retires, 1u);
  EXPECT_EQ(relays_now()->front().teid, 0x10u) << "visible before its publish";
  {
    bess::dataplane::Retirer retirer;
    moved->staged->Publish(retirer);
  }
  ASSERT_NE(relays_now(), nullptr);
  EXPECT_EQ(*relays_now(), upf::datapath::EndMarkerRelays{Relay4(0x20, 2)});

  auto same = upsert({Relay4(0x20, 2)});
  ASSERT_TRUE(same.has_value());
  EXPECT_EQ(same->footprint.retires, 0u);
  std::vector<upf::datapath::FteidRecord> read;
  resource.ForEach([&read](const FteidId &, const upf::datapath::FteidRecord &r) {
    read.push_back(r);
  });
  ASSERT_EQ(read.size(), 1u);
  EXPECT_EQ(read[0].relays, upf::datapath::EndMarkerRelays{Relay4(0x20, 2)});

  Publish(resource, key, 1, 7);
  EXPECT_EQ(relays_now(), nullptr);
  EXPECT_EQ(resource.LiveCount(), 1u);
}

using upf::datapath::EndMarkerEvent;
using upf::datapath::EndMarkerLog;

TEST(EndMarkerLog, DeliversEachEventOnceInArrivalOrder) {
  EndMarkerLog log(2);
  EXPECT_EQ(EndMarkerLog::Bytes(2), log.bytes());
  log.Record(0, {1, 0x11});
  log.Record(1, {2, 0x11});
  log.Record(0, {1, 0x22});
  const std::vector<EndMarkerEvent> want = {{1, 0x11}, {1, 0x22}, {2, 0x11}};
  EXPECT_EQ(log.Drain(), want) << "worker 0's events in order, then worker 1's";
  EXPECT_TRUE(log.Drain().empty()) << "a drained event is not delivered again";
  log.Record(1, {2, 0x33});
  EXPECT_EQ(log.Drain(), (std::vector<EndMarkerEvent>{{2, 0x33}}));
  EXPECT_EQ(log.Dropped(), 0u);
}

TEST(EndMarkerLog, AFullRingDropsAndCountsUntilDrained) {
  EndMarkerLog log(1);
  for (uint32_t i = 1; i <= EndMarkerLog::kRingSize + 3; ++i) {
    log.Record(0, {1, i});
  }
  EXPECT_EQ(log.Dropped(), 3u);
  const auto first = log.Drain();
  ASSERT_EQ(first.size(), EndMarkerLog::kRingSize);
  EXPECT_EQ(first.front().teid, 1u) << "the ring keeps the oldest, drops the newest";
  EXPECT_EQ(first.back().teid, EndMarkerLog::kRingSize);
  log.Record(0, {1, 0xabc});  // the drain freed the ring
  EXPECT_EQ(log.Drain(), (std::vector<EndMarkerEvent>{{1, 0xabc}}));
  log.Record(5, {1, 1});  // a slot past the log's workers
  EXPECT_EQ(log.Dropped(), 4u);
}

// Producers race a drainer: every recorded event is delivered exactly once,
// and recorded plus dropped is everything produced.
TEST(EndMarkerLog, ConcurrentWorkersAndDrainLoseAndRepeatNothing) {
  constexpr size_t kWorkers = 4;
  constexpr uint32_t kPerWorker = 20000;
  EndMarkerLog log(kWorkers);
  std::atomic<size_t> done{0};
  std::vector<std::thread> workers;
  for (size_t w = 0; w < kWorkers; ++w) {
    workers.emplace_back([&log, &done, w] {
      for (uint32_t i = 1; i <= kPerWorker; ++i) {
        log.Record(w, {static_cast<uint32_t>(w + 1), i});
      }
      done.fetch_add(1);
    });
  }
  std::vector<std::vector<uint32_t>> seen(kWorkers);
  auto take = [&] {
    for (const auto &e : log.Drain()) {
      seen[e.endpoint_id - 1].push_back(e.teid);
    }
  };
  while (done.load() < kWorkers) take();
  for (auto &t : workers) t.join();
  take();
  uint64_t delivered = 0;
  for (const auto &teids : seen) {
    delivered += teids.size();
    EXPECT_TRUE(std::is_sorted(teids.begin(), teids.end()));
    EXPECT_EQ(std::adjacent_find(teids.begin(), teids.end()), teids.end())
        << "an event delivered twice";
  }
  EXPECT_EQ(delivered + log.Dropped(), uint64_t{kWorkers} * kPerWorker);
}

}  // namespace

int main(int argc, char **argv) {
  // The first SharedExactIndex brings the EAL up without hugepages
  // (bess_eal's lazy bring-up); the test must not initialize it first.
  google::InitGoogleLogging(argv[0]);
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
