// SPDX-License-Identifier: BSD-3-Clause

#ifndef UPF_DATAPATH_URR_COUNT_H_
#define UPF_DATAPATH_URR_COUNT_H_

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

#include "dataplane/action_id.h"
#include "dataplane/slot_resource.h"
#include "dataplane/slot_table.h"
#include "framework/resource_bindings.h"
#include "module.h"
#include "stats/worker_local.h"
#include "upf_datapath.pb.h"

// Counts the packets and octets of the rules a URR measures: the data half of
// usage reporting (TS 29.244 7.5.2.4).
//
// The module sits in a chain behind the PDR table, so the packet it sees is one
// a rule selected -- and behind the meter, so a policed packet is counted when
// it is forwarded. The `action_id` metadata (BESS D-141) is the rule's
// ActionId, and an entry in "<name>/counters" for that id is what says the
// rule's traffic is measured: a packet whose action id has no entry is counted
// by nobody, which is what keeps a session without a URR off this module's
// cost (one lookup).
//
// The counts are per worker and per rule: a worker adds to its own plane with a
// relaxed load-add-store -- never a locked instruction, and never a shared line
// -- and the control side reads the cells of the rules it asks about, one
// relaxed load per cell (the two cells of one packet need not be seen together:
// they are additive counters, and the design prices a URR at two additions into
// worker-local counters). The planes hold two cells per ActionId up to the
// graph's id space, so the memory is capacity x 2 x 8 bytes x the worker count
// (docs/design.md, "Where a table lives" and wall 2).
//
// The time a rule's traffic ran (TS 29.244 5.2.2.2.1) is a fact about the rule,
// not about a worker, so it is *not* per-worker: one stamp pair per rule,
// written by whichever worker conveyed a counted packet -- once per batch that
// counted one, never once per packet -- and read by the control side. That is
// this module's one shared packet-path write; a store lost to a concurrent
// reader costs one packet's stamp, never a count (the cells stay worker-local
// and additive). A reading clears the first stamp, so the next window's first
// stamp is the next window's own packet.
//
// What is counted is the IP packet's octets -- the IPv4 header's Total Length
// -- not the frame's: the graph carries frames, and a data volume an SMF
// compares against its own count of the UE's octets must not carry the
// Ethernet header the framing adds. A frame that is not a linear IPv4 frame is
// counted as it is; no rule of this graph selects one.
class UrrCount final : public Module {
 public:
  static const gate_idx_t kNumOGates = 1;

  using ActionId = bess::dataplane::ActionId;

  struct Entry {};

  // "<module>/counters": CounterKey -> CounterEntry.
  static const ResourceTables resource_tables;

  UrrCount() : Module() { max_allowed_workers_ = Worker::kMaxWorkers; }

  CommandResponse Init(const upf::pb::UrrCountArg &arg);
  void DeInit() override;

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  // One reading of one rule's counters, summed over the workers: what a report
  // is built from. Reads no entry's existence -- a rule whose entry is gone
  // keeps whatever was counted before it went, which is what the reporting
  // side's own baseline makes harmless -- and answers zeros for an id outside
  // the space.
  std::pair<uint64_t, uint64_t> Counts(ActionId id) const noexcept;

  // One rule's timestamps, in the reading's monotonic domain
  // (read_monotonic_ns): the first packet counted since the previous reading
  // and the last packet counted at all. restart clears the first, which is what
  // the reporting side asks for -- a report opens the next window -- while a
  // diagnostic read leaves the window's first packet where it is. Zeros mean no
  // packet was counted.
  std::pair<uint64_t, uint64_t> ReadTimes(ActionId id, bool restart) noexcept;

  CommandResponse CommandGetCounts(
      const upf::pb::UrrCountCommandGetCountsArg &arg);

  static const Commands cmds;

  std::string GetDesc() const override;

 private:
  enum Cell : size_t { kPackets, kBytes };

  static constexpr size_t kCellsPerRule = 2;

  // One cache line of cells: a worker's plane starts on a line boundary and its
  // stride is whole lines, so no two workers share one (the reason
  // stats/worker_slots.h exists; this module reads cells one at a time, which
  // WorkerSlots' per-slot ReadSlot cannot do, so the layout is its own).
  static constexpr size_t kCellsPerLine = bess::stats::kCacheLine / sizeof(uint64_t);
  struct alignas(bess::stats::kCacheLine) Line {
    std::atomic<uint64_t> cells[kCellsPerLine];
  };

  // The stamps of one rule's counted traffic: shared, because the fact is the
  // rule's own, and written once per batch that counted a packet of it.
  struct Stamps {
    std::atomic<uint64_t> first_ns{0};
    std::atomic<uint64_t> last_ns{0};
  };

  // One worker's plane: its own cache lines, and only its own worker writes
  // them, so an add is a plain load-add-store (stats/worker_slots.h's rule).
  void Add(size_t cell, uint64_t n) noexcept {
    std::atomic<uint64_t> &c = lines_[cell / kCellsPerLine].cells[cell % kCellsPerLine];
    c.store(c.load(std::memory_order_relaxed) + n, std::memory_order_relaxed);
  }

  size_t offset_of(size_t action_id) const noexcept {
    return (action_id - 1) * kCellsPerRule;
  }

  size_t capacity_ = 0;  // the graph's ActionId space
  // Cells per worker, rounded up to a whole number of cache lines so every
  // plane is line-aligned (and its last line is nobody else's).
  size_t cells_per_worker_ = 0;

  // The planes: worker-major, one Line at a time, so a plane's base is line
  // aligned by construction.
  std::vector<Line> lines_;

  // One stamp pair per rule, indexed by ActionId - 1: module state like the
  // cells, not part of "<name>/counters" (a reading is a question, not a
  // resource write).
  std::vector<Stamps> stamps_;

  std::unique_ptr<bess::dataplane::SlotTable<ActionId, Entry>> entries_;
  std::unique_ptr<bess::dataplane::SlotResource<ActionId, Entry>> resource_;
  bess::framework::ResourceBinding binding_;  // after resource_ (D-044)
  int action_attr_ = -1;                      // the "action_id" attribute id
};

#endif  // UPF_DATAPATH_URR_COUNT_H_
