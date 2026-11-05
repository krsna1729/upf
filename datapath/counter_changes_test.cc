// SPDX-License-Identifier: BSD-3-Clause
#include "counter_changes.h"

#include <gtest/gtest.h>
#include <atomic>
#include <thread>
#include <vector>

namespace {
using upf::datapath::CounterChanges;
using Arg = upf::pb::UrrCountCommandGetChangesArg;
using Reply = upf::pb::UrrCountCommandGetChangesResponse;

TEST(CounterChanges, RetryPaginationAndAcknowledgementDoNotLoseActivity) {
  constexpr uint32_t kRules = 131073;
  bess::rcu::RcuDomain domain(2);
  CounterChanges changes(kRules, 2, domain);
  EXPECT_EQ(changes.bytes(), CounterChanges::Bytes(kRules, 2, domain));
  const auto initial = changes.ForWorker(0);
  for (uint32_t id = 1; id <= kRules; ++id) initial.Mark(id);
  changes.ForWorker(1).Mark(7); // The second worker must not replace the first.
  Arg arg;
  Reply first;
  ASSERT_TRUE(changes.Read(arg, &first));
  ASSERT_EQ(first.action_ids_size(), 65536);
  ASSERT_NE(first.next_after(), 0u);
  Reply replay;
  ASSERT_TRUE(changes.Read(arg, &replay));
  EXPECT_EQ(replay.SerializeAsString(), first.SerializeAsString());
  // Packets arriving while pages are in flight enter the other bank.
  changes.ForWorker(1).Mark(9);
  std::vector<bool> seen(kRules + 1);
  size_t notifications = 0;
  Reply page = first;
  for (;;) {
    for (uint32_t id : page.action_ids()) {
      ASSERT_GT(id, 0u);
      ASSERT_LE(id, kRules);
      seen[id] = true;
      ++notifications;
    }
    if (page.next_after() == 0) break;
    arg.set_sequence(page.sequence());
    arg.set_after(page.next_after());
    page.Clear();
    ASSERT_TRUE(changes.Read(arg, &page));
  }
  EXPECT_EQ(notifications, kRules + 1);
  for (uint32_t id = 1; id <= kRules; ++id) ASSERT_TRUE(seen[id]) << id;
  arg.Clear();
  arg.set_acknowledge(first.sequence());
  page.Clear();
  ASSERT_TRUE(changes.Read(arg, &page));
  ASSERT_EQ(page.action_ids_size(), 1);
  EXPECT_EQ(page.action_ids(0), 9u);
  EXPECT_GT(page.sequence(), first.sequence());
  // An invalid acknowledgement must not consume this pending packet.
  arg.set_acknowledge(page.sequence() + 1);
  Reply refused;
  EXPECT_FALSE(changes.Read(arg, &refused));
  arg.set_acknowledge(first.sequence());
  Reply retained;
  ASSERT_TRUE(changes.Read(arg, &retained));
  ASSERT_EQ(retained.action_ids_size(), 1);
  EXPECT_EQ(retained.action_ids(0), 9u);
}

TEST(CounterChanges, BatchGracePeriodsNeverLoseTheLastPacketOfARule) {
  constexpr uint32_t kRules = 200000;
  bess::rcu::RcuDomain domain(2);
  CounterChanges changes(kRules, 2, domain);
  ASSERT_TRUE(domain.Register(0));
  ASSERT_TRUE(domain.Register(1));
  std::atomic<unsigned> done{0};
  const auto produce = [&](unsigned worker) {
    domain.Online(worker);
    for (uint32_t start = 1 + worker; start <= kRules; start += 64) {
      const auto writer = changes.ForWorker(worker);
      for (uint32_t id = start; id < start + 64 && id <= kRules; id += 2)
        writer.Mark(id); // Every rule has exactly one packet, never a retry.
      domain.Quiescent(worker);
    }
    domain.Offline(worker);
    domain.Unregister(worker);
    done.fetch_add(1, std::memory_order_release);
  };
  std::thread a(produce, 0), b(produce, 1);
  std::vector<bool> seen(kRules + 1);
  uint64_t acknowledge = 0;
  auto drain = [&] {
    Arg arg;
    arg.set_acknowledge(acknowledge);
    for (;;) {
      Reply page;
      ASSERT_TRUE(changes.Read(arg, &page));
      for (uint32_t id : page.action_ids()) {
        ASSERT_GT(id, 0u);
        ASSERT_LE(id, kRules);
        seen[id] = true;
      }
      if (page.next_after() == 0) {
        acknowledge = page.sequence();
        break;
      }
      arg.set_sequence(page.sequence());
      arg.set_after(page.next_after());
    }
  };
  while (done.load(std::memory_order_acquire) != 2) drain();
  a.join();
  b.join();
  drain();
  drain(); // Flush either bank after both producers became quiescent.
  for (uint32_t id = 1; id <= kRules; ++id) ASSERT_TRUE(seen[id]) << id;
}
}  // namespace
