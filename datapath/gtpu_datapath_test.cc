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
#include <vector>

#include "utils/logging.h"
#include "dataplane/resource.h"
#include "fteid_resource.h"
#include "flow/shared_exact_index.h"
#include "gtpu_admission.h"
#include "gtpu_wire.h"
#include "rcu/rcu_domain.h"
#include "tunnel/tunnel.h"
#include "utils/checksum.h"
#include "utils/endian.h"
#include "utils/ether.h"

namespace {
using bess::flow::SharedExactIndex;
using bess::utils::be16_t;
using upf::datapath::FteidId;

struct TestIndex {
  explicit TestIndex(size_t capacity)
      : domain(64), index(SharedExactIndex::Create(
            sizeof(FteidId), capacity, domain, -1)) {}
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
             uint8_t direction, uint32_t context = 7) {
  auto reservation = resource.Reserve(bess::dataplane::Op::Upsert(
      resource.name(), bess::dataplane::EncodeKey(id),
      std::any(upf::datapath::FteidRecord{direction, context})));
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

}  // namespace

int main(int argc, char **argv) {
  // The first SharedExactIndex brings the EAL up without hugepages
  // (bess_eal's lazy bring-up); the test must not initialize it first.
  google::InitGoogleLogging(argv[0]);
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
