// SPDX-License-Identifier: BSD-3-Clause
//
// The A/B bench's table sizes for N sessions (upf_ab.cc's Apply), kept apart
// so a unit test can pin what each table costs per session
// (gtpu_datapath_test: BenchSizing).

#ifndef UPF_DATAPATH_BENCH_SIZING_H_
#define UPF_DATAPATH_BENCH_SIZING_H_

#include <algorithm>
#include <cstdint>

namespace upf::bench {

// Per-action tables (ActionIds, PDR rules, meters, counters, tunnels): two
// actions per session, UL = 2s+1 and DL = 2s+2, plus room for churn's 1024
// extra sessions or the self tests' ids.
inline uint64_t ActionCapacity(uint32_t sessions, bool churn) {
  return std::max<uint64_t>(65536, 2 * uint64_t{sessions} + (churn ? 2048 : 16));
}

// Per-session tables: session ids 1..N, and N+1..N+1024 for churn; the self
// test uses the last id.
inline uint64_t SessionCapacity(uint32_t sessions, bool churn) {
  return std::max<uint64_t>(65536, uint64_t{sessions} + (churn ? 2048 : 16));
}

// The F-TEID index (decap max_fteids): every layout writes one F-TEID key per
// bench session -- the uplink N3 F-TEID; graph and masked as a decap entry,
// session-major inside the session's entry -- so it is a per-session table,
// not one per action. max_fteids is the live cap; BESS adds the hash table's
// own headroom (ConcurrentExactTable::CapacityFor: 3/4 of a power of two,
// less 5%).
inline uint64_t FteidCapacity(uint32_t sessions, bool churn) { return SessionCapacity(sessions, churn); }

}  // namespace upf::bench

#endif  // UPF_DATAPATH_BENCH_SIZING_H_
