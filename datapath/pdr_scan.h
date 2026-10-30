// SPDX-License-Identifier: BSD-3-Clause
#ifndef UPF_DATAPATH_PDR_SCAN_H_
#define UPF_DATAPATH_PDR_SCAN_H_

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "classifier/firewall_table.h"
#include "dataplane/resource.h"
#include "flow/shared_exact_index.h"
#include "rcu/rcu_domain.h"
#include "utils/dpdk_memory.h"

namespace upf::appliance {

// The wildcard wire's range: the `width` bytes at `offset` of the PDR key,
// big-endian, lie in [low, high]. Same 24 bytes as the masked table's
// KeyRange, so the resource key is the one MaskedRuleResource used:
// mask ++ value ++ ranges (sorted by offset).
struct PdrRange {
  uint32_t offset = 0;
  uint32_t width = 0;
  uint64_t low = 0;
  uint64_t high = 0;
  bool operator==(const PdrRange &) const = default;
};
static_assert(sizeof(PdrRange) == 24);

struct PdrValue {
  int64_t priority = 0;
  uint16_t gate = 0;
  std::vector<std::byte> result;  // zero-padded to the record size
};

// One installed rule, as a lookup returns it.
struct PdrRule {
  int64_t priority = 0;
  uint64_t sequence = 0;  // command order: equal priorities go to the later
  uint16_t gate = 0;
  uint8_t form = 0;  // bit 0/1: source/destination port written as a range
  std::array<uint8_t, 24> result{};
};

// PDR rules as per-session FirewallScan policies (idea 2), with the
// wildcard-match wire and semantics of the masked table it replaces: the
// winner is the matching rule of highest priority, equal priorities going to
// the later command (a replacement counts as later), as ConcurrentMaskedTable.
//
// Placement. A UL rule whose F-TEID context field is fully masked lives in
// that context's bucket; a DL rule whose destination (UE) IPv4 is fully
// masked lives in that address's bucket. Every other rule lives in the one
// shared bucket. A packet looks up its anchor in an exact index (one batch
// lookup), then evaluates its session bucket and the shared bucket and keeps
// the better winner. The anchor field is dropped from an anchored rule: the
// index already matched it exactly.
//
// Inside a bucket, one immutable Policy: rules grouped by their guard -- every
// constraint FirewallScan cannot state (context, route domain, QFI, a
// non-prefix address mask, an address or protocol range, protocol exactly 0
// or partly masked, a partly masked port), checked exactly as a masked
// compare over the key plus field ranges. What FirewallScan states (address
// prefixes, protocol exact or any, port ranges) goes into the group's scan,
// rules in rank order so its first match is the group's winner. Groups are
// ordered by their best rule; a lookup stops at the first group whose best
// rule cannot beat the winner in hand. No shape the wire accepts is refused
// or widened.
//
// Transactions: Reserve() validates and records an op, Prepare() rebuilds
// each touched bucket's policy once (and inserts a new anchor into the index,
// reading as "no session rules" until publish), the first Publish() swaps
// every touched bucket's policy pointer, erasing emptied anchors from the
// index, and retires what it replaced through the Retirer. EndTransaction()
// undoes what an unpublished transaction prepared.
//
// Memory (D-198): sizeof(*this) is leased by the owner; every Policy and
// Bucket is admitted through set_memory_growth's hook before it is allocated
// and given back when freed (a retired one when its grace period ends). The
// anchor index is the owner's (fixed size, leased separately). There is no
// other copy of the rules: read-back and Contains reconstruct keys from the
// policies.
class PdrScanResource final : public bess::dataplane::Resource {
 public:
  static constexpr size_t kKeyStride = 24;
  using Key = std::array<std::byte, kKeyStride>;  // BuildPdrKey, zero-padded

  struct Hooks {
    std::function<std::expected<void, std::string>(const PdrValue &)> check_value;
    std::function<std::vector<bess::dataplane::Reference>(std::span<const uint8_t> result)>
        references;
    std::vector<std::string> may_reference;
  };

  PdrScanResource(std::string name, bool downlink, size_t record_size,
                  bess::flow::SharedExactIndex &anchors, bess::rcu::RcuDomain &domain,
                  Hooks hooks);
  ~PdrScanResource() override;

  size_t bytes() const noexcept {
    return sizeof(*this) + held_.load(std::memory_order_relaxed);
  }
  void set_memory_growth(bess::utils::MemoryGrowth *growth) noexcept { growth_ = growth; }

  static bess::dataplane::ResourceKey EncodeKey(std::span<const uint8_t> mask,
                                                std::span<const uint8_t> value,
                                                std::span<const PdrRange> ranges);

  // Packet path: winners[i] is the rule keys[i] matches, or null. n <= 64.
  void Classify(const Key *keys, size_t n, const PdrRule **winners) const noexcept;

  // Control path: every committed rule with its key.
  void ForEach(const std::function<void(const bess::dataplane::ResourceKey &,
                                        const PdrRule &)> &visit) const;
  size_t record_size() const noexcept { return record_size_; }

  size_t LiveCount() const override { return live_; }
  bool Contains(const bess::dataplane::ResourceKey &key) const override;
  std::vector<bess::dataplane::Reference> ReferencesOf(
      const bess::dataplane::ResourceKey &key) const override;
  void VisitReferences(
      const std::function<void(const bess::dataplane::Reference &)> &visit) const override;
  std::expected<Reservation, std::string> Reserve(const bess::dataplane::Op &op) override;
  std::expected<void, std::string> Prepare() override;
  void EndTransaction() noexcept override;

 private:
  struct Policy;
  struct Group;
  struct Spec;
  struct Bucket {
    std::atomic<const Policy *> policy{nullptr};
    uint32_t anchor = 0;  // the key's 4 anchor bytes, as stored
    Bucket *prev = nullptr, *next = nullptr;
  };
  struct PolicyDelete {
    PdrScanResource *owner;
    void operator()(const Policy *policy) const noexcept;
  };
  struct BucketDelete {
    PdrScanResource *owner;
    void operator()(Bucket *bucket) const noexcept;
  };
  using PolicyPtr = std::unique_ptr<const Policy, PolicyDelete>;
  using BucketPtr = std::unique_ptr<Bucket, BucketDelete>;
  struct Change;
  struct ReservedBucket {
    size_t remaining = 0;
    bool retirement_counted = false;  // an emptied anchored bucket
  };
  struct Staged {
    Bucket *bucket = nullptr;  // null for a new anchor until Prepare made it
    BucketPtr created{nullptr, BucketDelete{nullptr}};
    PolicyPtr policy{nullptr, PolicyDelete{nullptr}};
    size_t old_rules = 0, new_rules = 0;
  };
  class PublishOp;

  std::expected<void, std::string> Decompose(const bess::dataplane::ResourceKey &key, Spec *spec,
                                             bool *anchored, uint32_t *anchor) const;
  bess::dataplane::ResourceKey KeyOf(bool anchored, uint32_t anchor, const Group &group,
                                     const bess::classifier::FirewallRule &fw,
                                     uint8_t form) const;
  Bucket *FindBucket(bool anchored, uint32_t anchor) const noexcept;
  // The committed rule a decomposed key names: its policy and index, or false.
  bool Locate(bool anchored, uint32_t anchor, const Spec &spec, const Policy **policy,
              size_t *index) const;
  bool Find(const bess::dataplane::ResourceKey &key, const Policy **policy, size_t *index) const;
  static const PdrRule *Match(const Policy &policy, const uint8_t *key,
                              const bess::classifier::FirewallKey &fkey,
                              const PdrRule *best) noexcept;
  std::expected<PolicyPtr, std::string> Build(std::vector<Spec> specs);
  void Admit(size_t bytes);
  void Release(size_t bytes) noexcept;
  void PublishStaged(bess::dataplane::Retirer &retirer) noexcept;

  const bool downlink_;
  const size_t key_len_, record_size_, anchor_offset_;
  bess::flow::SharedExactIndex &anchors_;
  bess::rcu::RcuDomain &domain_;
  Hooks hooks_;
  bess::utils::MemoryGrowth *growth_ = nullptr;
  std::atomic<size_t> held_{0};
  Bucket shared_;
  Bucket *head_ = nullptr;  // anchored buckets, for read-back
  size_t live_ = 0;
  uint64_t next_sequence_ = 1;
  // Transaction-local counts: an old policy is charged once per bucket,
  // and an old anchor only when the reservations can leave it empty.
  std::map<std::pair<bool, uint32_t>, ReservedBucket> reserved_;
  std::vector<Change> changes_;
  std::vector<Staged> staged_;
  bool published_ = false;
};

}  // namespace upf::appliance

#endif  // UPF_DATAPATH_PDR_SCAN_H_
