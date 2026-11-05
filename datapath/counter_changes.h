// SPDX-License-Identifier: BSD-3-Clause
#ifndef UPF_DATAPATH_COUNTER_CHANGES_H_
#define UPF_DATAPATH_COUNTER_CHANGES_H_

#include <atomic>
#include <cassert>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <mutex>
#include <string>

#include "rcu/rcu_domain.h"
#include "upf_datapath.pb.h"
#include "utils/dpdk_memory.h"

namespace upf::datapath {

// Activity, not counter values. Each worker owns two bitmap banks and the list
// of words it touched. Mark allocates nothing and uses no atomic RMW. The
// controller publishes the other bank, waits for the runtime's batch-boundary
// grace period, then pages the frozen bank. A lost reply replays that same
// snapshot: only a subsequent acknowledgement releases it. The other bank can
// accumulate indefinitely without a queue overflowing or a capacity-sized scan.
class CounterChanges {
 public:
  static size_t Bytes(size_t capacity, size_t workers,
                      const bess::rcu::RcuDomain &, int = 0) noexcept {
    return sizeof(CounterChanges) + workers * 2 *
        (Words(capacity) * (sizeof(uint64_t) + sizeof(uint32_t)) + sizeof(Plane));
  }
  static size_t GlibcBytes(size_t, size_t, const bess::rcu::RcuDomain &, int = 0) noexcept {
    return sizeof(CounterChanges);
  }
  CounterChanges(size_t capacity, size_t workers, bess::rcu::RcuDomain &domain,
                 int socket = bess::utils::MemoryNode())
      : capacity_(capacity), workers_(workers), words_(Words(capacity)), domain_(domain),
        bits_(workers * 2 * words_, socket), touched_(workers * 2 * words_, socket),
        planes_(workers * 2, socket) {}

  size_t bytes() const noexcept {
    return sizeof(*this) + bits_.bytes() + touched_.bytes() + planes_.bytes();
  }

  class Writer {
   public:
    void Mark(uint32_t id) const noexcept {
      assert(id > 0 && id <= capacity_);
      auto &word = bits_[id / 64];
      const uint64_t bit = uint64_t{1} << (id % 64);
      if (word & bit) return;
      if (word == 0) touched_[(*size_)++] = id / 64;
      word |= bit;
    }
   private:
    friend class CounterChanges;
    Writer(size_t capacity, uint64_t *bits, uint32_t *touched, uint32_t *size)
        : capacity_(capacity), bits_(bits), touched_(touched), size_(size) {}
    size_t capacity_;
    uint64_t *bits_;
    uint32_t *touched_, *size_;
  };

  // Acquire once per batch; this handle must not outlive the worker's task.
  Writer ForWorker(size_t worker) noexcept {
    assert(worker < workers_);
    const size_t plane = worker * 2 + active_.load(std::memory_order_acquire);
    const size_t base = plane * words_;
    return Writer(capacity_, &bits_[base], &touched_[base], &planes_[plane].size);
  }

  std::expected<void, std::string> Read(
      const upf::pb::UrrCountCommandGetChangesArg &arg,
      upf::pb::UrrCountCommandGetChangesResponse *out) {
    std::lock_guard lock(mu_);
    if (arg.after() != 0 && arg.sequence() == 0)
      return std::unexpected("a continuation requires its snapshot sequence");
    if (arg.sequence() != 0 && (!frozen_ || arg.sequence() != sequence_))
      return std::unexpected("snapshot sequence is not current");
    if (arg.acknowledge() != acknowledged_) {
      if (!frozen_ || arg.acknowledge() != sequence_ || arg.sequence() || arg.after())
        return std::unexpected("only a completed current snapshot can be acknowledged");
      Clear();
      acknowledged_ = sequence_;
      frozen_ = false;
    }
    if (!frozen_) {
      frozen_bank_ = active_.fetch_xor(1, std::memory_order_release);
      domain_.Synchronize();
      ++sequence_;
      frozen_ = true;
    }
    out->set_sequence(sequence_);
    const uint64_t start = arg.after();
    const size_t start_worker = start / (words_ * 64);
    const size_t start_word = (start / 64) % words_;
    const unsigned start_bit = start % 64;
    if (start_worker >= workers_)
      return std::unexpected("snapshot cursor is outside the worker planes");
    if (start != 0) {
      const size_t plane = start_worker * 2 + frozen_bank_;
      const size_t base = plane * words_;
      if (start_word >= planes_[plane].size ||
          !(bits_[base + touched_[base + start_word]] & (uint64_t{1} << start_bit)))
        return std::unexpected("snapshot cursor does not name a pending bit");
    }
    constexpr size_t kPage = 1 << 16;
    for (size_t worker = start_worker; worker < workers_; ++worker) {
      const size_t plane = worker * 2 + frozen_bank_;
      const size_t base = plane * words_;
      for (size_t at = worker == start_worker ? start_word : 0; at < planes_[plane].size; ++at) {
        const uint32_t word = touched_[base + at];
        uint64_t bits = bits_[base + word];
        if (worker == start_worker && at == start_word) bits &= ~uint64_t{0} << start_bit;
        for (; bits; bits &= bits - 1) {
          const unsigned bit = std::countr_zero(bits);
          if (out->action_ids_size() == kPage) {
            out->set_next_after((worker * words_ + at) * 64 + bit);
            return {};
          }
          out->add_action_ids(static_cast<uint32_t>(uint64_t{word} * 64 + bit));
        }
      }
    }
    return {};
  }

 private:
  struct alignas(64) Plane { uint32_t size = 0; };
  // Both the uint64 bitmap and uint32 word list have cache-line-private banks.
  static size_t Words(size_t capacity) noexcept { return (capacity / 64 + 16) & ~size_t{15}; }
  void Clear() noexcept {
    for (size_t worker = 0; worker < workers_; ++worker) {
      const size_t plane = worker * 2 + frozen_bank_;
      const size_t base = plane * words_;
      for (size_t i = 0; i < planes_[plane].size; ++i)
        bits_[base + touched_[base + i]] = 0;
      planes_[plane].size = 0;
    }
  }

  const size_t capacity_, workers_, words_;
  bess::rcu::RcuDomain &domain_;
  bess::utils::DpdkArray<uint64_t> bits_;
  bess::utils::DpdkArray<uint32_t> touched_;
  bess::utils::DpdkArray<Plane> planes_;
  alignas(64) std::atomic<unsigned> active_{0};
  std::mutex mu_;
  uint64_t sequence_ = 0, acknowledged_ = 0;
  unsigned frozen_bank_ = 0;
  bool frozen_ = false;
};

}  // namespace upf::datapath
#endif  // UPF_DATAPATH_COUNTER_CHANGES_H_
