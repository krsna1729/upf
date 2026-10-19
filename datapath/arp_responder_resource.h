// SPDX-License-Identifier: BSD-3-Clause

#ifndef UPF_DATAPATH_ARP_RESPONDER_RESOURCE_H_
#define UPF_DATAPATH_ARP_RESPONDER_RESOURCE_H_

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "dataplane/resource.h"
#include "utils/ether.h"

namespace upf {
namespace arp {

// One answer: the address and the Ethernet address its replies carry. The
// address is kept beside the MAC the way the fork's ArpResponder keeps its
// entries (core/modules/arp_responder.h): a reply's sender address is the
// entry's own.
struct Entry {
  uint32_t ip = 0;                    // host order
  bess::utils::Ethernet::Address mac;  // the interface's own
};

// "<module>/entries": IPv4 (host order) -> MAC, live.
//
// The fork's ArpResponder holds its table in a std::map whose resource
// requires paused workers (core/modules/arp_responder.cc: "Workers read the
// map without synchronization, so this runs with them paused"), and so do
// Vif's interfaces and Rewrite's templates -- a *running* daemon refuses an
// entry, so a subscriber address provisioned at session time could never be
// answered. This is the same table as an open-addressed slot table whose slots
// are atomic (the idiom pdr_match_resource.h uses): a worker reads a published
// pointer with one acquire load, a transaction claims a slot and installs its
// value under the engine's lock, and the value a reader may still hold is
// retired, not freed, when it is replaced.
class EntriesResource final : public bess::dataplane::Resource {
 public:
  EntriesResource(std::string name, size_t max_entries);

  // The entry for an address, or nullptr: the packet path's whole lookup (one
  // acquire load of a published pointer).
  const Entry *Lookup(uint32_t ip) const noexcept;

  size_t LiveCount() const override { return live_; }

  bool Contains(const bess::dataplane::ResourceKey &key) const override;

  std::expected<Reservation, std::string> Reserve(
      const bess::dataplane::Op &op) override;

  // No per-transaction state is kept: a slot a Reserve claimed holds its claim
  // (as a tombstone, if the transaction never publishes), and the room that
  // makes the claim is the table's.
  void EndTransaction() noexcept override {}

  // Every live entry, control side: what "<module>/entries" reads back.
  template <typename Fn>
  void ForEach(Fn &&visit) const {
    for (size_t i = 0; i <= mask_; i++) {
      const uint32_t key = slots_[i].key.load(std::memory_order_acquire);
      const Entry *value = slots_[i].value.load(std::memory_order_acquire);
      if (key != 0 && value != nullptr) {
        visit(*value);
      }
    }
  }

 private:
  static constexpr size_t kNoSlot = ~size_t{0};

  struct Slot {
    // 0 is never an address this resource holds (the codec refuses it): a slot
    // no key has used.
    std::atomic<uint32_t> key{0};
    std::atomic<const Entry *> value{nullptr};
  };

  size_t Hash(uint32_t ip) const noexcept {
    // One multiplicative mix: subscriber addresses are structured (a pool is a
    // prefix), and their low bits alone would cluster.
    return (static_cast<size_t>(ip) * 2654435761u) & mask_;
  }

  // The slot holding `ip`, or kNoSlot. Control side.
  size_t Find(uint32_t ip) const noexcept;

  // The slot holding `ip`, claiming one for it when it has none: the first
  // tombstone the probe passes, else the empty slot it stops at. kNoSlot when
  // every slot is claimed and none is a tombstone.
  size_t Claim(uint32_t ip) noexcept;

  // Empties `ip`'s slot, returning what was there.
  const Entry *Clear(uint32_t ip) noexcept;

  class UpsertOp final : public bess::dataplane::StagedOp {
   public:
    UpsertOp(EntriesResource &owner, size_t slot,
             std::unique_ptr<const Entry> entry)
        : owner_(owner), slot_(slot), entry_(std::move(entry)) {}

    void Publish(bess::dataplane::Retirer &retirer) noexcept override {
      // The slot owns the entry from here, so this op gives it up: its
      // destructor would otherwise free what the packet path is about to read,
      // and a later erase would retire the same pointer twice.
      const Entry *old = owner_.Publish(slot_, entry_.release());
      if (old != nullptr) {
        retirer.Retire(std::unique_ptr<const Entry>(old));
      }
    }

   private:
    EntriesResource &owner_;
    size_t slot_;
    std::unique_ptr<const Entry> entry_;
  };

  class EraseOp final : public bess::dataplane::StagedOp {
   public:
    EraseOp(EntriesResource &owner, uint32_t ip) : owner_(owner), ip_(ip) {}

    void Publish(bess::dataplane::Retirer &retirer) noexcept override {
      if (const Entry *old = owner_.Clear(ip_); old != nullptr) {
        retirer.Retire(std::unique_ptr<const Entry>(old));
      }
    }

   private:
    EntriesResource &owner_;
    uint32_t ip_;
  };

  // The slot's own install, called by UpsertOp under the engine's lock.
  const Entry *Publish(size_t slot, const Entry *entry) noexcept {
    const Entry *old =
        slots_[slot].value.exchange(entry, std::memory_order_acq_rel);
    if (old == nullptr) {
      live_++;
    }
    return old;
  }

  std::vector<Slot> slots_;
  size_t mask_ = 0;
  // Control side, under the engine's lock: the slots that hold a value. A slot
  // holding a key and no value is a tombstone, not an entry.
  size_t live_ = 0;
};

inline EntriesResource::EntriesResource(std::string name, size_t max_entries)
    : Resource(std::move(name)) {
  size_t slots = 2;
  while (slots < max_entries * 2) {
    slots <<= 1;
  }
  slots_ = std::vector<Slot>(slots);
  mask_ = slots - 1;
}

inline const Entry *EntriesResource::Lookup(uint32_t ip) const noexcept {
  if (ip == 0) {
    return nullptr;
  }
  size_t i = Hash(ip);
  for (size_t n = 0; n <= mask_; n++) {
    const uint32_t key = slots_[i].key.load(std::memory_order_acquire);
    if (key == 0) {
      return nullptr;
    }
    if (key == ip) {
      return slots_[i].value.load(std::memory_order_acquire);
    }
    i = (i + 1) & mask_;
  }
  return nullptr;
}

inline size_t EntriesResource::Find(uint32_t ip) const noexcept {
  size_t i = Hash(ip);
  for (size_t n = 0; n <= mask_; n++) {
    const uint32_t key = slots_[i].key.load(std::memory_order_acquire);
    if (key == 0) {
      break;
    }
    if (key == ip) {
      return i;
    }
    i = (i + 1) & mask_;
  }
  return kNoSlot;
}

inline size_t EntriesResource::Claim(uint32_t ip) noexcept {
  size_t i = Hash(ip);
  size_t dead = kNoSlot;
  for (size_t n = 0; n <= mask_; n++) {
    const uint32_t key = slots_[i].key.load(std::memory_order_relaxed);
    if (key == ip) {
      return i;
    }
    if (key == 0) {
      // A slot no key has used: the probe's end. Take the first tombstone
      // passed (it costs the table nothing) or this one.
      const size_t target = dead != kNoSlot ? dead : i;
      slots_[target].key.store(ip, std::memory_order_release);
      return target;
    }
    if (dead == kNoSlot &&
        slots_[i].value.load(std::memory_order_relaxed) == nullptr) {
      dead = i;
    }
    i = (i + 1) & mask_;
  }
  // Every slot holds a key: the only room is a tombstone, and the probe has
  // passed all of them.
  if (dead == kNoSlot) {
    return kNoSlot;
  }
  slots_[dead].key.store(ip, std::memory_order_release);
  return dead;
}

inline const Entry *EntriesResource::Clear(uint32_t ip) noexcept {
  const size_t slot = Find(ip);
  if (slot == kNoSlot) {
    return nullptr;
  }
  if (const Entry *old =
          slots_[slot].value.exchange(nullptr, std::memory_order_acq_rel);
      old != nullptr) {
    live_--;
    return old;
  }
  return nullptr;
}

inline bool EntriesResource::Contains(
    const bess::dataplane::ResourceKey &key) const {
  uint32_t ip = 0;
  if (!bess::dataplane::DecodeKey(key, &ip)) {
    return false;
  }
  return Lookup(ip) != nullptr;
}

inline std::expected<bess::dataplane::Resource::Reservation, std::string>
EntriesResource::Reserve(const bess::dataplane::Op &op) {
  uint32_t ip = 0;
  if (!bess::dataplane::DecodeKey(op.key, &ip)) {
    return std::unexpected("the key is " + std::to_string(op.key.size()) +
                           " bytes, and an IPv4 address is 4");
  }
  if (ip == 0) {
    return std::unexpected("0.0.0.0 names no subscriber address");
  }

  if (op.kind == bess::dataplane::OpKind::kErase) {
    if (Lookup(ip) == nullptr) {
      return std::unexpected("not found");
    }
    Reservation erase{std::make_unique<EraseOp>(*this, ip), {},
                      {.retires = 1}};
    erase.existed = true;
    return erase;
  }

  const bess::utils::Ethernet::Address *mac =
      std::any_cast<bess::utils::Ethernet::Address>(&op.value);
  if (mac == nullptr) {
    return std::unexpected("wrong value type (want a MAC address)");
  }

  // The slot the entry will be published in, claimed now: the room it needs is
  // the table's, and this is the only step that can find none. A key the table
  // already holds needs nothing -- Claim returns its slot, a tombstone's
  // included.
  const size_t slot = Claim(ip);
  if (slot == kNoSlot) {
    return std::unexpected("the entries table is full (" +
                           std::to_string(mask_ + 1) + " slots)");
  }
  const bool existed =
      slots_[slot].value.load(std::memory_order_acquire) != nullptr;
  auto entry = std::make_unique<const Entry>(Entry{ip, *mac});
  Reservation reservation{
      std::make_unique<UpsertOp>(*this, slot, std::move(entry)),
      {},
      {.retires = existed ? 1u : 0u}};
  reservation.existed = existed;
  return reservation;
}

}  // namespace arp
}  // namespace upf

#endif  // UPF_DATAPATH_ARP_RESPONDER_RESOURCE_H_
