// SPDX-License-Identifier: BSD-3-Clause
//
// The ids a counter bank holds, one bit each, kept by its resource's
// publishes, so a get_counts without ids walks the live ids in pages instead
// of probing every id up to the capacity (UG-B1).

#ifndef UPF_DATAPATH_COUNTER_IDS_H_
#define UPF_DATAPATH_COUNTER_IDS_H_

#include <atomic>
#include <array>
#include <functional>
#include <bit>
#include <cstdint>
#include <memory>
#include <utility>

#include "dataplane/slot_resource.h"
#include "stats/keyed_counters.h"
#include "utils/dpdk_memory.h"

namespace upf::appliance {

// A counter bank's worker planes in UpfAppliance, a single-worker module:
// one, written by whichever worker runs it, unless worker_planes asks for
// one per worker id (U-6).
inline size_t CounterPlanes(uint32_t worker_planes) noexcept { return worker_planes ? worker_planes : 1; }

struct Stamps { std::atomic<uint64_t> first{0}, last{0}; };

// Buffer counters have an ActionId-sized address space, but ordinary
// forwarding provisions none. Pages are admitted during resource Reserve,
// never from the worker. Keep historical counts and stable addresses through
// deletion, reuse and RCU grace; retained pages are freed only at teardown,
// including pages prepared by a subsequently aborted transaction.
class BufferCounterPages {
 public:
  static constexpr size_t kPageSize = 1024;
  static size_t Bytes(size_t capacity, size_t) noexcept {
    return (capacity / kPageSize + 1) * sizeof(std::atomic<Page *>);
  }
  BufferCounterPages(size_t capacity, size_t workers)
      : pages_(capacity / kPageSize + 1), workers_(workers) {}
  ~BufferCounterPages() {
    for (size_t i = 0; i < pages_.size(); ++i)
      bess::utils::DpdkDelete<Page>{}(pages_[i].load(std::memory_order_relaxed));
  }
  void set_memory_growth(bess::utils::MemoryGrowth *growth) noexcept { growth_ = growth; }
  size_t workers() const noexcept { return workers_; }
  size_t bytes() const noexcept { return pages_.bytes() + page_bytes_; }
  void Prepare(uint32_t id) {
    auto &entry = pages_[id / kPageSize];
    if (entry.load(std::memory_order_relaxed) != nullptr) return;
    const size_t bytes = sizeof(Page) + bess::stats::KeyedCounters::Bytes(kPageSize, 2, workers_);
    if (growth_ != nullptr) growth_->Grow(bytes);
    bess::utils::DpdkUnique<Page> page;
    try {
      page = bess::utils::MakeDpdk<Page>(bess::utils::MemoryNode(), workers_);
    } catch (...) {
      if (growth_ != nullptr) growth_->Shrink(bytes);
      throw;
    }
    entry.store(page.release(), std::memory_order_release);
    page_bytes_ += bytes;
  }
  void Add(bess::dataplane::WorkerId worker, uint32_t id, uint64_t octets) noexcept {
    auto *page = Find(id);
    const auto plane = page->cells.ForWorker(worker);
    plane.Add(id % kPageSize, 0, 1);
    plane.Add(id % kPageSize, 1, octets);
  }
  Stamps &Stamp(uint32_t id) noexcept { return Find(id)->stamps[id % kPageSize]; }
  template <typename Count>
  void Read(uint32_t id, bool restart, Count *out) const noexcept {
    auto *page = Find(id);
    if (page == nullptr) return;
    uint64_t packets = 0, octets = 0;
    for (size_t w = 0; w < workers_; ++w) {
      const bess::dataplane::WorkerId worker(static_cast<uint16_t>(w));
      packets += page->cells.Read(worker, id % kPageSize, 0);
      octets += page->cells.Read(worker, id % kPageSize, 1);
    }
    out->set_packets(packets);
    out->set_octets(octets);
    auto &stamp = page->stamps[id % kPageSize];
    out->set_first_packet_ns(restart ? stamp.first.exchange(0, std::memory_order_relaxed) :
                                     stamp.first.load(std::memory_order_relaxed));
    out->set_last_packet_ns(stamp.last.load(std::memory_order_relaxed));
  }
 private:
  struct Page {
    explicit Page(size_t workers) : cells(kPageSize, 2, workers) {}
    bess::stats::KeyedCounters cells;
    std::array<Stamps, kPageSize> stamps{};
  };
  Page *Find(uint32_t id) const noexcept {
    return pages_[id / kPageSize].load(std::memory_order_acquire);
  }
  bess::utils::DpdkArray<std::atomic<Page *>> pages_;
  size_t workers_, page_bytes_ = 0;
  bess::utils::MemoryGrowth *growth_ = nullptr;
};

class LiveIds {
 public:
  static size_t Bytes(size_t capacity, int socket) noexcept {
    return bess::utils::DpdkArray<std::atomic<uint64_t>>::Bytes(Words(capacity), socket);
  }
  LiveIds(size_t capacity, int socket) : words_(Words(capacity), socket) {}

  // Ids 1..capacity. Called by the bank's resource at publish (one writer);
  // get_counts reads beside it.
  void Set(uint32_t id, bool live) noexcept {
    const uint64_t bit = uint64_t{1} << (id % 64);
    auto &word = words_[id / 64];
    if (live) word.fetch_or(bit, std::memory_order_relaxed);
    else word.fetch_and(~bit, std::memory_order_relaxed);
  }

  // Visits the live ids above `after` in ascending order, at most `limit` of
  // them. Returns the id to resume after, or 0 when none are left.
  template <typename Visit>
  uint32_t Walk(uint32_t after, size_t limit, Visit &&visit) const {
    size_t visited = 0;
    for (size_t w = (after + 1) / 64; w < words_.size(); ++w) {
      uint64_t bits = words_[w].load(std::memory_order_relaxed);
      if (w == (after + 1) / 64) bits &= ~uint64_t{0} << ((after + 1) % 64);
      for (; bits != 0; bits &= bits - 1) {
        const auto id = static_cast<uint32_t>(w * 64 + std::countr_zero(bits));
        if (visited == limit) return id - 1;
        visit(id);
        ++visited;
      }
    }
    return 0;
  }

  const bess::utils::DpdkArray<std::atomic<uint64_t>> &array() const noexcept { return words_; }

 private:
  static size_t Words(size_t capacity) noexcept { return capacity / 64 + 1; }
  bess::utils::DpdkArray<std::atomic<uint64_t>> words_;
};

// A SlotResource that keeps a LiveIds current: an upsert's id is live from
// its publish, an erase's id is not.
template <typename Id, typename T, bool kPaged = false>
class TrackedSlotResource final : public bess::dataplane::SlotResource<Id, T, kPaged> {
 public:
  TrackedSlotResource(std::string name, bess::dataplane::SlotTable<Id, T, kPaged> &table,
                      LiveIds &ids, std::function<void(uint32_t)> prepare = {})
      : bess::dataplane::SlotResource<Id, T, kPaged>(std::move(name), table),
        ids_(ids), prepare_(std::move(prepare)) {}

  std::expected<bess::dataplane::Resource::Reservation, std::string> Reserve(
      const bess::dataplane::Op &op) override {
    auto r = bess::dataplane::SlotResource<Id, T, kPaged>::Reserve(op);
    Id id;
    if (r && bess::dataplane::DecodeKey(op.key, &id)) {
      if (prepare_ && op.kind == bess::dataplane::OpKind::kUpsert) prepare_(id.value());
      r->staged = std::make_unique<Tracked>(std::move(r->staged), ids_, id.value(),
                                            op.kind == bess::dataplane::OpKind::kUpsert);
    }
    return r;
  }

 private:
  class Tracked final : public bess::dataplane::StagedOp {
   public:
    Tracked(std::unique_ptr<bess::dataplane::StagedOp> inner, LiveIds &ids, uint32_t id, bool live)
        : inner_(std::move(inner)), ids_(ids), id_(id), live_(live) {}
    void Publish(bess::dataplane::Retirer &retirer) noexcept override {
      inner_->Publish(retirer);
      ids_.Set(id_, live_);
    }
    void Abort() noexcept override { inner_->Abort(); }

   private:
    std::unique_ptr<bess::dataplane::StagedOp> inner_;
    LiveIds &ids_;
    uint32_t id_;
    bool live_;
  };
  LiveIds &ids_;
  std::function<void(uint32_t)> prepare_;
};

}  // namespace upf::appliance

#endif  // UPF_DATAPATH_COUNTER_IDS_H_
