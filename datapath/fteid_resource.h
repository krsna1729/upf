// SPDX-License-Identifier: BSD-3-Clause

#ifndef UPF_DATAPATH_FTEID_RESOURCE_H_
#define UPF_DATAPATH_FTEID_RESOURCE_H_

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "dataplane/resource.h"
#include "flow/shared_exact_index.h"
#include "rcu/rcu_domain.h"

namespace upf::datapath {

// Canonical key bytes: endpoint BE32, family U8, 16-byte canonical local IP,
// and TEID BE32.
using FteidId = std::array<uint8_t, 25>;

// One GTP-U tunnel a received End Marker on the F-TEID is relayed through
// (TS 29.244 Table 8.2.64-1 NOTE 2): the outgoing TEID, the tunnel's local and
// peer addresses (16 bytes; IPv4 is the last four), and the transport route
// domain the relayed marker is routed in.
struct EndMarkerRelay {
  uint32_t teid = 0;
  uint8_t family = 0;
  std::array<uint8_t, 16> local{};
  std::array<uint8_t, 16> peer{};
  uint32_t transport_route_domain = 0;
  bool operator==(const EndMarkerRelay &) const = default;
};
using EndMarkerRelays = std::vector<EndMarkerRelay>;

struct FteidRecord {
  uint8_t direction = 0;
  uint32_t context_id = 0;
  EndMarkerRelays relays;
};

class FteidResource final : public bess::dataplane::Resource {
 public:
  // The worker-visible record the exact index points at. context_id is set
  // before the index insert and never changes; state's release store (Publish)
  // is what makes the record, and so its context, admissible.
  struct DirectionRecord {
    std::atomic<uint8_t> state{0};  // 0 pending, 1 UL, 2 DL
    uint32_t context_id = 0;
    // The End Marker relays, null for none. An upsert replaces the list whole
    // and retires the one it replaced; the record frees the last one.
    std::atomic<const EndMarkerRelays *> relays{nullptr};
    ~DirectionRecord() { delete relays.load(std::memory_order_relaxed); }
  };

  FteidResource(std::string name, bess::flow::SharedExactIndex &index,
                bess::rcu::RcuDomain &domain, size_t max_entries)
      : Resource(std::move(name)),
        index_(index),
        domain_(domain),
        max_entries_(max_entries) {}

  size_t LiveCount() const override {
    return live_.load(std::memory_order_relaxed);
  }
  std::optional<uint64_t> Capacity() const override { return max_entries_; }

  template <typename Fn>
  void ForEach(Fn &&visit) const {
    std::lock_guard lock(control_mu_);
    for (const auto &[id, entry] : entries_) {
      if (!entry.live) continue;
      const auto *relays = entry.record->relays.load(std::memory_order_relaxed);
      visit(id, FteidRecord{entry.direction, entry.context_id,
                            relays ? *relays : EndMarkerRelays{}});
    }
  }

  bool Contains(const bess::dataplane::ResourceKey &key) const override {
    uint64_t value = 0;
    if (!Lookup(key, &value)) return false;
    const auto *record = reinterpret_cast<const DirectionRecord *>(
        static_cast<uintptr_t>(value));
    return record != nullptr && record->state.load(std::memory_order_acquire) > 0;
  }

  std::expected<Reservation, std::string> Reserve(
      const bess::dataplane::Op &op) override {
    FteidId id{};
    if (!bess::dataplane::DecodeKey(op.key, &id))
      return std::unexpected("F-TEID key must be 25 bytes");
    const bool endpoint_set = id[0] | id[1] | id[2] | id[3];
    const bool teid_set = id[21] | id[22] | id[23] | id[24];
    if (!endpoint_set || !teid_set || (id[4] != 4 && id[4] != 6))
      return std::unexpected("invalid endpoint, family, or TEID in F-TEID key");
    if (id[4] == 4) {
      for (size_t i = 5; i < 17; ++i)
        if (id[i] != 0)
          return std::unexpected("IPv4 F-TEID address is not canonical");
    }

    std::lock_guard lock(control_mu_);
    const auto mirror = entries_.find(id);
    uint64_t packed = 0;
    const bool found = Lookup(op.key, &packed);
    if (mirror != entries_.end() && !mirror->second.live)
      return std::unexpected("F-TEID key already has a pending insert");
    if (op.kind == bess::dataplane::OpKind::kErase) {
      if (!found || mirror == entries_.end())
        return std::unexpected("not found");
      if (mirror->second.erase_pending)
        return std::unexpected("F-TEID key already has a pending erase");
      mirror->second.erase_pending = true;
      Reservation erase{std::make_unique<EraseOp>(*this, id), {}, {.retires = 1}};
      erase.existed = true;
      return erase;
    }

    const auto *value = std::any_cast<FteidRecord>(&op.value);
    if (value == nullptr || value->direction > 1)
      return std::unexpected("FteidEntry.direction must be 0 (UL) or 1 (DL)");
    if (value->context_id == 0)
      return std::unexpected("FteidEntry.context_id must be nonzero");
    if (found) {
      if (mirror == entries_.end() || !mirror->second.live ||
          mirror->second.direction != value->direction)
        return std::unexpected("F-TEID key is already assigned to the opposite direction");
      if (mirror->second.context_id != value->context_id)
        return std::unexpected("F-TEID key is already assigned another context");
      if (mirror->second.erase_pending)
        return std::unexpected("F-TEID key already has a pending erase");
      // The same admission with other relays: the tunnels the F-TEID's PDRs
      // forward into changed, so the list is replaced.
      const auto *relays =
          mirror->second.record->relays.load(std::memory_order_relaxed);
      if (relays ? *relays == value->relays : value->relays.empty()) {
        Reservation no_op{std::make_unique<NoopOp>(), {}, {}};
        no_op.existed = true;
        return no_op;
      }
      Reservation replace{std::make_unique<RelaysOp>(*this, id, value->relays),
                          {}, {.retires = 1}};
      replace.existed = true;
      return replace;
    }
    if (mirror != entries_.end())
      return std::unexpected("F-TEID key reservation is inconsistent");
    if (live_.load(std::memory_order_relaxed) + pending_inserts_ >= max_entries_)
      return std::unexpected("fteids resource reached max_fteids capacity");
    domain_.ReserveRetirements(1);
    Entry entry;
    entry.direction = value->direction;
    entry.context_id = value->context_id;
    entry.record = std::make_unique<DirectionRecord>();
    entry.record->context_id = value->context_id;
    if (!value->relays.empty())
      entry.record->relays.store(new EndMarkerRelays(value->relays),
                                 std::memory_order_relaxed);
    auto [it, inserted] = entries_.emplace(id, std::move(entry));
    if (!inserted)
      return std::unexpected("F-TEID key reservation is inconsistent");
    const uint64_t record_word = static_cast<uint64_t>(
        reinterpret_cast<uintptr_t>(it->second.record.get()));
    const auto status = index_.InsertIfAbsent(
        reinterpret_cast<const std::byte *>(id.data()), record_word);
    if (status != bess::flow::SharedExactIndex::InsertStatus::kInserted) {
      entries_.erase(it);
      return std::unexpected(
          status == bess::flow::SharedExactIndex::InsertStatus::kFull
              ? "fteids exact index is full"
              : "F-TEID key already exists in the exact index");
    }
    ++pending_inserts_;
    return Reservation{std::make_unique<UpsertOp>(*this, id), {}, {}};
  }

 private:
  struct Entry {
    uint8_t direction = 0;
    uint32_t context_id = 0;
    bool live = false;
    bool erase_pending = false;
    std::unique_ptr<DirectionRecord> record;
  };

  bool Lookup(const bess::dataplane::ResourceKey &key,
              uint64_t *value) const noexcept {
    if (key.size() != FteidId{}.size()) return false;
    uint64_t result = 0;
    const bool found = index_.LookupBatch(
        reinterpret_cast<const std::byte *>(key.data()), key.size(), &result, 1) != 0;
    if (found && value != nullptr) *value = result;
    return found;
  }

  class NoopOp final : public bess::dataplane::StagedOp {
   public:
    void Publish(bess::dataplane::Retirer &) noexcept override {}
  };

  class RelaysOp final : public bess::dataplane::StagedOp {
   public:
    RelaysOp(FteidResource &owner, FteidId id, const EndMarkerRelays &relays)
        : owner_(owner),
          id_(id),
          relays_(relays.empty() ? nullptr : new EndMarkerRelays(relays)) {}
    void Publish(bess::dataplane::Retirer &retirer) noexcept override {
      std::lock_guard lock(owner_.control_mu_);
      auto it = owner_.entries_.find(id_);
      CHECK(it != owner_.entries_.end() && it->second.live);
      retirer.Retire(std::unique_ptr<const EndMarkerRelays>(
          it->second.record->relays.exchange(relays_.release(),
                                             std::memory_order_acq_rel)));
    }
   private:
    FteidResource &owner_;
    FteidId id_;
    std::unique_ptr<const EndMarkerRelays> relays_;
  };

  class UpsertOp final : public bess::dataplane::StagedOp {
   public:
    UpsertOp(FteidResource &owner, FteidId id) : owner_(owner), id_(id) {}
    ~UpsertOp() noexcept override { Abort(); }
    void Publish(bess::dataplane::Retirer &) noexcept override {
      std::lock_guard lock(owner_.control_mu_);
      auto it = owner_.entries_.find(id_);
      CHECK(it != owner_.entries_.end() && !it->second.live);
      it->second.record->state.store(
          static_cast<uint8_t>(it->second.direction + 1),
          std::memory_order_release);
      it->second.live = true;
      --owner_.pending_inserts_;
      owner_.live_.fetch_add(1, std::memory_order_relaxed);
      finished_ = true;
    }
    void Abort() noexcept override {
      if (finished_) return;
      std::lock_guard lock(owner_.control_mu_);
      const auto it = owner_.entries_.find(id_);
      if (it != owner_.entries_.end() && !it->second.live) {
        CHECK(owner_.index_.Erase(
            reinterpret_cast<const std::byte *>(id_.data())));
        const auto token = owner_.domain_.StartGracePeriod();
        owner_.domain_.Retire(token, std::move(it->second.record));
        owner_.entries_.erase(it);
        --owner_.pending_inserts_;
      }
      finished_ = true;
    }
   private:
    FteidResource &owner_;
    FteidId id_;
    bool finished_ = false;
  };

  class EraseOp final : public bess::dataplane::StagedOp {
   public:
    EraseOp(FteidResource &owner, FteidId id) : owner_(owner), id_(id) {}
    ~EraseOp() noexcept override { Abort(); }
    void Publish(bess::dataplane::Retirer &retirer) noexcept override {
      std::lock_guard lock(owner_.control_mu_);
      auto it = owner_.entries_.find(id_);
      CHECK(it != owner_.entries_.end() && it->second.live &&
            it->second.erase_pending);
      CHECK(owner_.index_.Erase(reinterpret_cast<const std::byte *>(id_.data())));
      retirer.Retire(std::move(it->second.record));
      owner_.entries_.erase(it);
      owner_.live_.fetch_sub(1, std::memory_order_relaxed);
      finished_ = true;
    }
    void Abort() noexcept override {
      if (finished_) return;
      std::lock_guard lock(owner_.control_mu_);
      const auto it = owner_.entries_.find(id_);
      if (it != owner_.entries_.end()) it->second.erase_pending = false;
      finished_ = true;
    }
   private:
    FteidResource &owner_;
    FteidId id_;
    bool finished_ = false;
  };

  bess::flow::SharedExactIndex &index_;
  bess::rcu::RcuDomain &domain_;
  size_t max_entries_;
  mutable std::mutex control_mu_;
  std::map<FteidId, Entry> entries_;
  std::atomic<size_t> live_{0};
  size_t pending_inserts_ = 0;
};

}  // namespace upf::datapath

#endif  // UPF_DATAPATH_FTEID_RESOURCE_H_
