// SPDX-License-Identifier: BSD-3-Clause

#include "packet_rate_quota.h"

#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <ctime>
#include <thread>
#include <vector>

namespace {

using upf::datapath::PacketRateConfig;
using upf::datapath::PacketRateQuota;
using Verdict = PacketRateQuota::Verdict;

constexpr uint64_t kSecond = 1000000000ull;
constexpr uint64_t kMinute = 60 * kSecond;

uint64_t WallNowNs() {
  timespec ts{};
  clock_gettime(CLOCK_REALTIME, &ts);
  return static_cast<uint64_t>(ts.tv_sec) * kSecond +
         static_cast<uint64_t>(ts.tv_nsec);
}

PacketRateConfig Primary(uint32_t allowed, uint64_t period_ns,
                         uint64_t epoch = 1) {
  PacketRateConfig config;
  config.allowed = allowed;
  config.primary_period_ns = period_ns;
  config.epoch = epoch;
  return config;
}

// 8.2.63: a primary maximum of 10 per minute plus 5 per hour -- the shape a
// token bucket in packets/second cannot express.
PacketRateConfig TwoWindows() {
  PacketRateConfig config = Primary(10, kMinute);
  config.additional = 5;
  config.additional_period_ns = 60 * kMinute;
  return config;
}

}  // namespace

TEST(PacketRateQuota, PrimaryWindowCapsAndRefills) {
  PacketRateQuota quota;
  const PacketRateConfig config = Primary(2, kMinute);

  EXPECT_EQ(quota.Check(config, 0), Verdict::kPass);
  EXPECT_EQ(quota.Check(config, 0), Verdict::kPass);
  EXPECT_EQ(quota.Check(config, 0), Verdict::kDrop);
  // The next period starts with the first packet charged to it.
  EXPECT_EQ(quota.Check(config, kMinute), Verdict::kPass);
  EXPECT_EQ(quota.Check(config, kMinute), Verdict::kPass);
  EXPECT_EQ(quota.Check(config, kMinute), Verdict::kDrop);
}

TEST(PacketRateQuota, AdditionalWindowRunsItsOwnPeriod) {
  PacketRateQuota quota;
  const PacketRateConfig config = TwoWindows();

  // Primary first, then the additional allowance.
  for (int i = 0; i < 10; i++) {
    EXPECT_EQ(quota.Check(config, 0), Verdict::kPass);
  }
  for (int i = 0; i < 5; i++) {
    EXPECT_EQ(quota.Check(config, 0), Verdict::kPass);
  }
  EXPECT_EQ(quota.Check(config, 0), Verdict::kDrop);

  // The primary window rolls after a minute; the additional still holds.
  for (int i = 0; i < 10; i++) {
    EXPECT_EQ(quota.Check(config, kMinute), Verdict::kPass);
  }
  EXPECT_EQ(quota.Check(config, kMinute), Verdict::kDrop);

  // An hour after the first packets both windows roll over.
  for (int i = 0; i < 10; i++) {
    EXPECT_EQ(quota.Check(config, 60 * kMinute), Verdict::kPass);
  }
  for (int i = 0; i < 5; i++) {
    EXPECT_EQ(quota.Check(config, 60 * kMinute), Verdict::kPass);
  }
  EXPECT_EQ(quota.Check(config, 60 * kMinute), Verdict::kDrop);
}

TEST(PacketRateQuota, SeedIsEnforcedBeforeThePacketRate) {
  PacketRateQuota quota;
  PacketRateConfig config = Primary(1, kMinute);
  config.seed_remaining = 2;
  config.seed_remaining_additional = 1;
  config.seed_validity_unix_ns = WallNowNs() + 10 * kSecond;

  // The CP's remaining counts are spent first (5.4.15.2 rule 4).
  EXPECT_EQ(quota.Check(config, 0), Verdict::kPass);
  EXPECT_EQ(quota.Check(config, 0), Verdict::kPass);
  EXPECT_EQ(quota.Check(config, 0), Verdict::kPass);  // additional seed
  // Then the QER's own maximum applies.
  EXPECT_EQ(quota.Check(config, 0), Verdict::kPass);
  EXPECT_EQ(quota.Check(config, 0), Verdict::kDrop);
}

TEST(PacketRateQuota, SeedValidityHandsOverToThePacketRate) {
  PacketRateQuota quota;
  PacketRateConfig config = Primary(1, kMinute);
  config.seed_remaining = 1;
  config.seed_validity_unix_ns = WallNowNs() + kSecond;

  EXPECT_EQ(quota.Check(config, 0), Verdict::kPass);  // seed
  EXPECT_EQ(quota.Check(config, 2 * kSecond), Verdict::kPass);  // expired: window
  EXPECT_EQ(quota.Check(config, 2 * kSecond), Verdict::kDrop);
}

TEST(PacketRateQuota, EpochChangeRestartsTheWindows) {
  PacketRateQuota quota;
  PacketRateConfig config = Primary(1, kMinute);

  EXPECT_EQ(quota.Check(config, 0), Verdict::kPass);
  EXPECT_EQ(quota.Check(config, 0), Verdict::kDrop);

  config.epoch = 2;
  EXPECT_EQ(quota.Check(config, 0), Verdict::kPass);
  EXPECT_EQ(quota.Check(config, 0), Verdict::kDrop);
}

TEST(PacketRateQuota, StatusReportsRemainingAndWindowEnd) {
  PacketRateQuota quota;
  const PacketRateConfig config = Primary(3, kMinute);
  EXPECT_EQ(quota.Check(config, 0), Verdict::kPass);

  const auto live = quota.Status(config, 5 * kSecond, 1000);
  EXPECT_EQ(live.remaining, 2);
  EXPECT_EQ(live.used, 1);
  EXPECT_EQ(live.validity_unix_ns, 1000 + (kMinute - 5 * kSecond));

  EXPECT_EQ(quota.Check(config, 5 * kSecond), Verdict::kPass);
  EXPECT_EQ(quota.Check(config, 5 * kSecond), Verdict::kPass);
  const auto exhausted = quota.Status(config, 5 * kSecond, 1000);
  EXPECT_EQ(exhausted.remaining, 0);
  EXPECT_EQ(exhausted.used, 3);

  // A window that has rolled over reports its full allowance without a
  // packet having started the next one.
  const auto fresh = quota.Status(config, 2 * kMinute, 1000);
  EXPECT_EQ(fresh.remaining, 3);
  EXPECT_EQ(fresh.used, 0);
  EXPECT_EQ(fresh.validity_unix_ns, 1000 + kMinute);
}

TEST(PacketRateQuota, StatusUsesTheEarlierOfTwoWindowEnds) {
  PacketRateQuota quota;
  const PacketRateConfig config = TwoWindows();
  // No packet yet: the primary's minute is the earlier validity.
  const auto reading = quota.Status(config, 0, 0);
  EXPECT_EQ(reading.remaining, 10);
  EXPECT_EQ(reading.remaining_additional, 5);
  EXPECT_EQ(reading.validity_unix_ns, kMinute);
}

TEST(PacketRateQuota, StatusReportsTheSeedWhileItIsLive) {
  PacketRateQuota quota;
  PacketRateConfig config = Primary(1, kMinute);
  config.seed_remaining = 4;
  const uint64_t before = WallNowNs();
  config.seed_validity_unix_ns = before + 10 * kSecond;

  EXPECT_EQ(quota.Check(config, 0), Verdict::kPass);
  const auto reading = quota.Status(config, 0, before);
  EXPECT_EQ(reading.remaining, 3);
  EXPECT_EQ(reading.used, 1);
  // The seed started at the first check, between `before` and now.
  EXPECT_GE(reading.validity_unix_ns, before + 9 * kSecond);
  EXPECT_LE(reading.validity_unix_ns, WallNowNs() + 11 * kSecond);
}

TEST(PacketRateQuota, ConcurrentChecksNeverExceedTheLimit) {
  PacketRateQuota quota;
  const PacketRateConfig config = Primary(10, 60 * kMinute);
  std::atomic<int> passes{0};
  std::vector<std::thread> workers;
  for (int w = 0; w < 4; w++) {
    workers.emplace_back([&] {
      for (int i = 0; i < 100; i++) {
        if (quota.Check(config, 0) == Verdict::kPass) {
          passes.fetch_add(1, std::memory_order_relaxed);
        }
      }
    });
  }
  for (auto &worker : workers) {
    worker.join();
  }
  EXPECT_EQ(passes.load(), 10);
}
