// SPDX-License-Identifier: BSD-3-Clause
//
// The ids a counter bank holds, one bit each, kept by its resource's
// publishes, so a get_counts without ids walks the live ids in pages instead
// of probing every id up to the capacity (UG-B1).

#ifndef UPF_DATAPATH_COUNTER_IDS_H_
#define UPF_DATAPATH_COUNTER_IDS_H_

#include <atomic>
#include <bit>
#include <cstdint>
#include <memory>
#include <utility>

#include "dataplane/slot_resource.h"
#include "utils/dpdk_memory.h"

namespace upf::appliance {

// A counter bank's worker planes in UpfAppliance, a single-worker module:
// one, written by whichever worker runs it, unless worker_planes asks for
// one per worker id (U-6).
inline size_t CounterPlanes(uint32_t worker_planes) noexcept { return worker_planes ? worker_planes : 1; }

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
template <typename Id, typename T>
class TrackedSlotResource final : public bess::dataplane::SlotResource<Id, T> {
 public:
  TrackedSlotResource(std::string name, bess::dataplane::SlotTable<Id, T> &table, LiveIds &ids)
      : bess::dataplane::SlotResource<Id, T>(std::move(name), table), ids_(ids) {}

  std::expected<bess::dataplane::Resource::Reservation, std::string> Reserve(
      const bess::dataplane::Op &op) override {
    auto r = bess::dataplane::SlotResource<Id, T>::Reserve(op);
    Id id;
    if (r && bess::dataplane::DecodeKey(op.key, &id))
      r->staged = std::make_unique<Tracked>(std::move(r->staged), ids_, id.value(),
                                            op.kind == bess::dataplane::OpKind::kUpsert);
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
};

}  // namespace upf::appliance

#endif  // UPF_DATAPATH_COUNTER_IDS_H_
