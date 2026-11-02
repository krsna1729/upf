// SPDX-License-Identifier: BSD-3-Clause
//
// What the A/B bench's F-TEID index costs per session (bench/bench_sizing.h):
// the bytes GtpuDecap and UpfAppliance admit for it (SharedExactIndex::Bytes,
// BESS D-198) at the strict-budget grid's two limits, 746K sessions (the
// session layout at 2048 MiB) and 1.494M (the graph at 3072 MiB).

#include <gtest/gtest.h>

#include <cstdint>

#include "bench/bench_sizing.h"
#include "fteid_resource.h"
#include "flow/shared_exact_index.h"
#include "rcu/rcu_domain.h"

namespace {

TEST(BenchSizing, FteidIndexHoldsOneKeyPerSession) {
  const bess::rcu::RcuDomain domain(4);
  for (const uint32_t n : {746000u, 1494000u}) {
    // Every layout writes one F-TEID key per bench session.
    EXPECT_LE(upf::bench::FteidCapacity(n, false), uint64_t{n} + 16) << n;
    const size_t bytes = bess::flow::SharedExactIndex::Bytes(
        sizeof(upf::datapath::FteidId), upf::bench::FteidCapacity(n, false), domain, 0);
    // One key per session plus the table's headroom (3/4 of a power of two,
    // less 5%) is at most 72 B per bucket position / (0.75 x 0.95) = 101 B.
    EXPECT_LE(bytes / n, 102u) << n << " sessions: " << bytes << " B";
  }
}

}  // namespace
