// SPDX-License-Identifier: BSD-3-Clause

// The ARP responder's entries table (arp_responder_resource.h). Linked into
// gtpu_datapath_test, whose main() runs it.

#include <gtest/gtest.h>

#include <algorithm>
#include <any>
#include <cstddef>
#include <cstdint>

#include "arp_responder_resource.h"
#include "dataplane/resource.h"
#include "utils/ether.h"

namespace {

using upf::arp::EntriesResource;

void Apply(EntriesResource &table, const bess::dataplane::Op &op) {
  auto reservation = table.Reserve(op);
  ASSERT_TRUE(reservation.has_value()) << reservation.error();
  bess::dataplane::Retirer retirer;
  reservation->staged->Publish(retirer);
}

// A distinct nonzero address per n, through a bijective mix: consecutive
// addresses would each get a slot of their own and never share a probe.
uint32_t Address(uint32_t n) {
  uint32_t x = n + 1;
  x ^= x >> 16;
  x *= 0x45d9f3bu;
  x ^= x >> 16;
  x *= 0x45d9f3bu;
  x ^= x >> 16;
  return x;
}

// UD-B4: an erase leaves nothing a later miss walks past. 100K distinct
// addresses churn through 1024 slots with at most 256 live, and every erased
// address then misses within 16 slots.
TEST(ArpEntriesResource, ChurnKeepsMissesShort) {
  constexpr uint32_t kAddresses = 100000;
  constexpr uint32_t kLive = 256;
  EntriesResource table("entries", 512);  // 1024 slots
  const std::any mac = bess::utils::Ethernet::Address();
  for (uint32_t n = 0; n < kAddresses; n++) {
    if (n >= kLive) {
      Apply(table, bess::dataplane::Op::Erase(
                       table.name(),
                       bess::dataplane::EncodeKey(Address(n - kLive))));
    }
    Apply(table, bess::dataplane::Op::Upsert(
                     table.name(), bess::dataplane::EncodeKey(Address(n)), mac));
  }
  ASSERT_EQ(table.LiveCount(), kLive);
  for (uint32_t n = kAddresses - kLive; n < kAddresses; n++) {
    const upf::arp::Entry *entry = table.Lookup(Address(n));
    ASSERT_NE(entry, nullptr);
    EXPECT_EQ(entry->ip, Address(n));
  }
  size_t found = 0;
  size_t worst = 0;
  for (uint32_t n = 0; n < kAddresses - kLive; n++) {
    found += table.Lookup(Address(n)) != nullptr;
    worst = std::max(worst, table.ProbeLength(Address(n)));
  }
  RecordProperty("worst_miss_probes", static_cast<int>(worst));
  EXPECT_EQ(found, 0u);
  EXPECT_LE(worst, 16u);
}

}  // namespace
