// SPDX-License-Identifier: BSD-3-Clause
// The appliance's packet-path key and usage helpers; no EAL needed.
#include <gtest/gtest.h>

#include <array>
#include <cstring>

#include "upf_appliance_frame.h"

namespace {
std::array<uint8_t, 64> Frame() {
  std::array<uint8_t, 64> f{};
  f[12] = 0x08; f[14] = 0x45; f[16] = 0; f[17] = 50; f[23] = 6;
  f[26] = 10; f[29] = 2; f[30] = 8; f[33] = 8; f[34] = 0x30; f[35] = 0x39; f[36] = 0x01; f[37] = 0xbb;
  return f;
}
}  // namespace

TEST(ApplianceFrame, UlKeyFollowsCompilerFieldOrder) {
  std::array<std::byte, 22> key{};
  auto f = Frame();
  ASSERT_TRUE(upf::appliance::BuildPdrKey(f, false, 99, 0x01020304, 7, key));
  const auto *k = reinterpret_cast<const uint8_t *>(key.data());
  EXPECT_EQ(std::memcmp(k, &f[26], 4), 0);   // source
  EXPECT_EQ(std::memcmp(k + 4, &f[30], 4), 0);  // destination
  EXPECT_EQ(k[8], 6);                           // protocol
  EXPECT_EQ(std::memcmp(k + 9, &f[34], 4), 0);  // ports
  EXPECT_EQ(k[13], 1); EXPECT_EQ(k[16], 4);     // context, no domain
  EXPECT_EQ(k[17], 7);                          // qfi
}

TEST(ApplianceFrame, DlKeyCarriesDomainBeforeContext) {
  std::array<std::byte, 22> key{};
  ASSERT_TRUE(upf::appliance::BuildPdrKey(Frame(), true, 0x0a0b0c0d, 0x01020304, 0xff, key));
  const auto *k = reinterpret_cast<const uint8_t *>(key.data());
  EXPECT_EQ(k[13], 0x0a); EXPECT_EQ(k[16], 0x0d);
  EXPECT_EQ(k[17], 1); EXPECT_EQ(k[20], 4);
  EXPECT_EQ(k[21], 0xff);
}

TEST(ApplianceFrame, ShortFrameHasNoKey) {
  std::array<std::byte, 22> key{};
  std::array<uint8_t, 37> f{};
  EXPECT_FALSE(upf::appliance::BuildPdrKey(f, false, 0, 0, 0, key));
}

TEST(ApplianceFrame, UsageOctetsAreTheIpv4TotalLengthElseTheFrame) {
  auto f = Frame();
  EXPECT_EQ(upf::appliance::UsageOctets(f, 64), 50u);
  f[17] = 200;  // beyond the frame
  EXPECT_EQ(upf::appliance::UsageOctets(f, 64), 64u);
  f[12] = 0x86;
  EXPECT_EQ(upf::appliance::UsageOctets(f, 64), 64u);
}
