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
#include "framework/memory_scope.h"
#include "upf_datapath.pb.h"
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

struct BufferBudget final : bess::utils::MemoryGrowth {
  bool refuse = false;
  size_t grown = 0;
  void Grow(size_t bytes, size_t glibc = 0) override {
    EXPECT_EQ(0u, glibc);
    if (refuse) throw bess::utils::MemoryRefused(
        bess::utils::MemoryRefused::Reason::kNormalLimit, bytes, "buffer test budget");
    grown += bytes;
  }
  void Shrink(size_t bytes, size_t = 0) noexcept override { grown -= bytes; }
};

// Run the engine's deferred removal cascade, as the session resource tests do.
struct BufferRemovalsTag {};
auto Member(BufferRemovalsTag);
template <auto M>
struct ExposeBufferRemovals {
  friend auto Member(BufferRemovalsTag) { return M; }
};
template struct ExposeBufferRemovals<&dp::Retirer::removals_>;
void FinishBufferRemovals(bess::rcu::RcuDomain &domain, dp::Retirer &retirer) {
  domain.Synchronize();
  for (auto &removal : retirer.*Member(BufferRemovalsTag{})) {
    dp::Retirer next;
    removal.step(next);
    FinishBufferRemovals(domain, next);
  }
}

TEST(ApplianceCounters, SparseBufferPagesKeepHistoryAcrossDeleteReuseAndGrace) {
  BringUpEal();
  constexpr uint32_t kCapacity = 1000000;
  using Table = dp::SlotTable<Id, CounterEntry, true>;
  BufferBudget budget;
  upf::appliance::BufferCounterPages cells(kCapacity, 2);
  cells.set_memory_growth(&budget);
  Table table(kCapacity);
  upf::appliance::LiveIds live(kCapacity, bess::utils::MemoryNode());
  upf::appliance::TrackedSlotResource<Id, CounterEntry, true> resource(
      "buffer_counters", table, live, [&](uint32_t id) { cells.Prepare(id); });
  const auto upsert = [](uint32_t id) {
    return dp::Op::Upsert("buffer_counters", dp::EncodeKey(Id(id)), std::any(CounterEntry{}));
  };
  const auto apply = [&](const dp::Op &op) {
    auto r = resource.Reserve(op);
    ASSERT_TRUE(r.has_value()) << r.error();
    dp::Retirer retirer;
    r->staged->Publish(retirer);
    bess::rcu::RcuDomain domain(2);
    FinishBufferRemovals(domain, retirer);
  };
  const size_t initial = cells.bytes();
  budget.refuse = true;
  EXPECT_THROW((void)resource.Reserve(upsert(kCapacity)), bess::utils::MemoryRefused);
  EXPECT_EQ(initial, cells.bytes()) << "a refused page is never published";
  EXPECT_EQ(0u, resource.LiveCount());
  EXPECT_EQ(nullptr, table.Lookup(Id(kCapacity)));
  budget.refuse = false;
  EXPECT_FALSE(resource.Reserve(upsert(kCapacity + 1)));
  for (uint32_t id : {1023u, 1024u, kCapacity}) apply(upsert(id));
  const auto worker0 = bess::dataplane::WorkerId(uint16_t{0});
  const auto worker1 = bess::dataplane::WorkerId(uint16_t{1});
  cells.Add(worker0, 1023, 60);
  cells.Add(worker1, 1023, 70);
  cells.Add(worker1, 1024, 80);
  cells.Add(worker0, kCapacity, 90);
  cells.Stamp(1023).first.store(100);
  cells.Stamp(1023).last.store(110);
  auto *const stable_stamp = &cells.Stamp(1023);
  const size_t held = cells.bytes();
  auto erase = resource.Reserve(dp::Op::Erase("buffer_counters", dp::EncodeKey(Id(1023))));
  ASSERT_TRUE(erase);
  dp::Retirer retirer;
  erase->staged->Publish(retirer);
  EXPECT_FALSE(resource.Contains(dp::EncodeKey(Id(1023))));
  EXPECT_NE(nullptr, table.Lookup(Id(1023))) << "old packets retain their counter during grace";
  EXPECT_FALSE(resource.Reserve(upsert(1023))) << "retiring IDs cannot be reused";
  cells.Add(worker0, 1023, 100);
  upf::pb::UrrCountCommandGetCountsResponse counts;
  auto *count = counts.add_counts();
  cells.Read(1023, true, count);
  EXPECT_EQ(3u, count->packets());
  EXPECT_EQ(230u, count->octets());
  EXPECT_EQ(100u, count->first_packet_ns());
  EXPECT_EQ(110u, count->last_packet_ns());
  bess::rcu::RcuDomain domain(2);
  FinishBufferRemovals(domain, retirer);
  EXPECT_EQ(nullptr, table.Lookup(Id(1023)));
  apply(upsert(1023));
  EXPECT_EQ(stable_stamp, &cells.Stamp(1023));
  EXPECT_EQ(held, cells.bytes());
  cells.Add(worker1, 1023, 120);
  count->Clear();
  cells.Read(1023, false, count);
  EXPECT_EQ(4u, count->packets());
  EXPECT_EQ(350u, count->octets());
  EXPECT_EQ(0u, count->first_packet_ns()) << "restart affects the window, not historical counts";
  count->Clear(); cells.Read(1024, false, count);
  EXPECT_EQ(1u, count->packets()); EXPECT_EQ(80u, count->octets());
  count->Clear(); cells.Read(kCapacity, false, count);
  EXPECT_EQ(1u, count->packets()); EXPECT_EQ(90u, count->octets());
  std::vector<uint32_t> ids;
  live.Walk(0, SIZE_MAX, [&](uint32_t id) { ids.push_back(id); });
  EXPECT_EQ((std::vector<uint32_t>{1023, 1024, kCapacity}), ids);
  EXPECT_EQ(initial + budget.grown, cells.bytes());
}

TEST(ApplianceCounters, BufferPagesAreRetainedOnAbortAndReleasedWithTheirScope) {
  BringUpEal();
  const std::string owner = "buffer_page_teardown";
  bess::framework::MemoryScope memory(&owner);
  {
    auto cells = memory.Create<upf::appliance::BufferCounterPages>("buffer_cells", 1000000, 1);
    auto table = memory.Create<dp::SlotTable<Id, CounterEntry, true>>("buffer_entries", 1000000);
    upf::appliance::LiveIds live(1000000, bess::utils::MemoryNode());
    upf::appliance::TrackedSlotResource<Id, CounterEntry, true> resource(
        "buffer_counters", *table, live, [&](uint32_t id) { cells->Prepare(id); });
    const auto op = dp::Op::Upsert("buffer_counters", dp::EncodeKey(Id(999999)), std::any(CounterEntry{}));
    const size_t initial = memory.admitted_bytes();
    {
      auto pending = resource.Reserve(op);
      ASSERT_TRUE(pending);
      pending->staged->Abort();
    }
    EXPECT_FALSE(resource.Contains(op.key));
    EXPECT_EQ(nullptr, table->Lookup(Id(999999)));
    const size_t retained = memory.admitted_bytes();
    EXPECT_GT(retained, initial);
    auto retried = resource.Reserve(op);
    ASSERT_TRUE(retried);
    EXPECT_EQ(retained, memory.admitted_bytes()) << "aborted capacity is reusable, not leaked";
    dp::Retirer retirer;
    retried->staged->Publish(retirer);
    EXPECT_EQ(cells->bytes() + table->bytes(), memory.admitted_bytes());
  }
  EXPECT_EQ(0u, memory.admitted_bytes()) << "table teardown releases pages and their admission";
}

}  // namespace
