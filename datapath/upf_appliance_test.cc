// SPDX-License-Identifier: BSD-3-Clause
//
// UpfAppliance's counter banks (counter_ids.h): one worker plane by default,
// and a get_counts without ids that walks the live ids in bounded pages.

#include <gtest/gtest.h>

#include <algorithm>
#include <any>
#include <cstdint>
#include <memory>
#include <vector>

#include "counter_ids.h"
#include "dataplane/action_id.h"
#include "flow/shared_exact_index.h"
#include "rcu/rcu_domain.h"
#include "stats/keyed_counters.h"

namespace {
namespace dp = bess::dataplane;
using Id = bess::dataplane::ActionId;
struct CounterEntry {};

// DPDK memory needs the EAL, which the first SharedExactIndex brings up.
void BringUpEal() {
  static bess::rcu::RcuDomain domain(4);
  static auto index = bess::flow::SharedExactIndex::Create(8, 64, domain, bess::utils::MemoryNode());
}

TEST(ApplianceCounters, DefaultsGiveOnePlaneOf16BytesPerId) {
  BringUpEal();
  constexpr size_t kCapacity = 1000000;
  const size_t planes = upf::appliance::CounterPlanes(0);  // worker_planes unset
  EXPECT_EQ(bess::stats::KeyedCounters::Bytes(kCapacity, 2, planes), kCapacity * 16);
  bess::stats::KeyedCounters cells(kCapacity, 2, planes);
  EXPECT_EQ(cells.workers(), 1u);
  EXPECT_EQ(cells.bytes(), kCapacity * 16);
  // An explicit worker_planes still sizes one plane per worker id.
  EXPECT_EQ(upf::appliance::CounterPlanes(4), 4u);
}

TEST(ApplianceCounters, ReadWithoutIdsWalksLiveIdsInPages) {
  BringUpEal();
  constexpr size_t kCapacity = 1000000;
  dp::SlotTable<Id, CounterEntry> table(kCapacity);
  upf::appliance::LiveIds live(kCapacity, bess::utils::MemoryNode());
  upf::appliance::TrackedSlotResource<Id, CounterEntry> resource("counters_ul", table, live);
  const auto apply = [&](const dp::Op &op) {
    auto r = resource.Reserve(op);
    ASSERT_TRUE(r.has_value()) << r.error();
    dp::Retirer retirer;
    r->staged->Publish(retirer);
  };
  // 2500 ids spread over the id space, then 500 of them erased.
  std::vector<uint32_t> want;
  for (uint32_t i = 0; i < 2500; ++i) {
    const uint32_t id = 1 + i * 397;
    apply(dp::Op::Upsert("counters_ul", dp::EncodeKey(Id(id)), std::any(CounterEntry{})));
    if (i % 5 == 0) apply(dp::Op::Erase("counters_ul", dp::EncodeKey(Id(id))));
    else want.push_back(id);
  }
  ASSERT_EQ(want.size(), 2000u);
  // Pages of 700: 3 pages, each id once, in order, and nothing else visited.
  std::vector<uint32_t> got;
  int pages = 0;
  size_t largest = 0;
  uint32_t after = 0;
  do {
    const size_t before = got.size();
    after = live.Walk(after, 700, [&](uint32_t id) { got.push_back(id); });
    largest = std::max(largest, got.size() - before);
    ++pages;
  } while (after != 0 && pages < 100);
  EXPECT_EQ(got, want);
  EXPECT_EQ(pages, 3);
  EXPECT_LE(largest, 700u);
}

}  // namespace
