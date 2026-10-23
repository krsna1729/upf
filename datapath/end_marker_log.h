// SPDX-License-Identifier: BSD-3-Clause

#ifndef UPF_DATAPATH_END_MARKER_LOG_H_
#define UPF_DATAPATH_END_MARKER_LOG_H_

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

namespace upf::datapath {

// One End Marker that arrived (TS 29.281 7.3.2): the logical endpoint it came
// in on and the TEID its header names -- this UPF's own local TEID, which is
// unique per endpoint, not across them.
struct EndMarkerEvent {
  uint32_t endpoint_id = 0;
  uint32_t teid = 0;
  bool operator==(const EndMarkerEvent &) const = default;
};

// EndMarkerLog hands End Markers from the workers to the control side as
// events, each delivered once. One single-producer ring per worker slot: the
// worker writes its slot and publishes the head with release; the drain reads
// up to that head and publishes the tail with release, so a worker reuses a
// slot only after the drain is done with it. A full ring drops the event and
// counts it, so a slow reader costs reports, never a worker.
//
// Events rather than counters: a counter table keyed by (endpoint, TEID) never
// learns when a key is gone, fills as TEIDs churn, and hands a reused TEID the
// count of its last holder. A drained event has no history to go stale.
class EndMarkerLog {
 public:
  static constexpr size_t kRingSize = 256;  // per worker; a power of two

  explicit EndMarkerLog(size_t workers)
      : rings_(std::make_unique<Ring[]>(workers)), workers_(workers) {}

  // Record is the worker's half: one event into its own ring.
  void Record(size_t worker, EndMarkerEvent event) noexcept {
    if (worker >= workers_) {
      dropped_.fetch_add(1, std::memory_order_relaxed);
      return;
    }
    Ring &ring = rings_[worker];
    const uint64_t head = ring.head.load(std::memory_order_relaxed);
    if (head - ring.tail.load(std::memory_order_acquire) >= kRingSize) {
      dropped_.fetch_add(1, std::memory_order_relaxed);
      return;
    }
    ring.events[head % kRingSize] = event;
    ring.head.store(head + 1, std::memory_order_release);
  }

  // Drain is the control side's half: every event recorded since the last
  // drain, worker by worker in arrival order within a worker. Drains are
  // serialized, so two commands never consume the same event.
  std::vector<EndMarkerEvent> Drain() {
    std::lock_guard<std::mutex> lock(drain_mu_);
    std::vector<EndMarkerEvent> out;
    for (size_t w = 0; w < workers_; ++w) {
      Ring &ring = rings_[w];
      const uint64_t head = ring.head.load(std::memory_order_acquire);
      uint64_t tail = ring.tail.load(std::memory_order_relaxed);
      for (; tail != head; ++tail) {
        out.push_back(ring.events[tail % kRingSize]);
      }
      ring.tail.store(tail, std::memory_order_release);
    }
    return out;
  }

  // Dropped is the events lost to a full ring or an unknown worker slot since
  // the log was made: what a reader compares to see that it fell behind.
  uint64_t Dropped() const noexcept { return dropped_.load(std::memory_order_relaxed); }

 private:
  struct alignas(64) Ring {
    std::atomic<uint64_t> head{0};
    alignas(64) std::atomic<uint64_t> tail{0};
    EndMarkerEvent events[kRingSize];
  };

  std::unique_ptr<Ring[]> rings_;
  size_t workers_;
  std::atomic<uint64_t> dropped_{0};
  std::mutex drain_mu_;
};

}  // namespace upf::datapath

#endif  // UPF_DATAPATH_END_MARKER_LOG_H_
