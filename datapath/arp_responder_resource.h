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
#include "utils/dpdk_memory.h"
#include "utils/dpdk_slab.h"
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
// are atomic: a worker reads a published
// pointer with one acquire load, a transaction claims a slot and installs its
// value under the engine's lock, and the value a reader may still hold is
// retired, not freed, when it is replaced.
//
// An erase empties its slot and moves nothing: each slot counts the claimed
// keys whose probe went past it, a probe stops at the first slot none went
// past, and an erase takes its passes back (core/flow/flow_index.h's overflow
// counts). Back-shift deletion would move a live key behind a worker that is
// mid-probe, which then misses it; a tombstone kept its key, so under address
// churn every slot ended up keyed and each miss walked the whole table.
//
// Memory (BESS D-198): the slot array is glibc memory (a std::vector) made by
// the constructor, sized from max_entries and never grown; Bytes/GlibcBytes is
// what the constructor allocates, for framework::MemoryCost. The entries a
// worker reads come from an ObjectSlab (DPDK heap on the memory node, 1024
// entries per chunk rather than one malloc each); each new chunk is growth,
// admitted through set_memory_growth before Reserve allocates it, so a refused
// chunk refuses that transaction.
class EntriesResource final : public bess::dataplane::Resource {
 public:
  EntriesResource(std::string name, size_t max_entries);
  ~EntriesResource() override;

  static size_t Bytes(const std::string &name, size_t max_entries) noexcept {
    return GlibcBytes(name, max_entries) + bess::utils::ObjectSlab<Entry>::Bytes();
  }
  static size_t GlibcBytes(const std::string & /*name*/,
                           size_t max_entries) noexcept {
    return SlotCount(max_entries) * sizeof(Slot);
  }
  // The slot array plus the entry chunks made so far.
  size_t bytes() const noexcept {
    return slots_.size() * sizeof(Slot) + slab_->bytes();
  }
  // The admission each new entry chunk asks first (D-198).
  void set_memory_growth(bess::utils::MemoryGrowth *growth) noexcept {
    slab_->set_memory_growth(growth);
  }

  // The entry for an address, or nullptr: the packet path's whole lookup (one
  // acquire load of a published pointer).
  const Entry *Lookup(uint32_t ip) const noexcept { return Probe(ip).entry; }

  // The slots a lookup of `ip` examines (1: its home slot decides).
  size_t ProbeLength(uint32_t ip) const noexcept { return Probe(ip).slots; }

  size_t LiveCount() const override { return live_; }

  bool Contains(const bess::dataplane::ResourceKey &key) const override;

  std::expected<Reservation, std::string> Reserve(
      const bess::dataplane::Op &op) override;

  // No per-transaction state is kept: a slot a Reserve claimed holds its claim
  // (with no value, if the transaction never publishes, until a later claim
  // takes it over), and the room that makes the claim is the table's.
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

  using Owned = bess::utils::SlabUnique<const Entry>;

  // The smallest power of two at least max(2, 2 x max_entries).
  static size_t SlotCount(size_t max_entries) noexcept {
    size_t slots = 2;
    while (slots < max_entries * 2) {
      slots <<= 1;
    }
    return slots;
  }

  struct Slot {
    // 0 is never an address this resource holds (the codec refuses it): a slot
    // that holds no key.
    std::atomic<uint32_t> key{0};
    // The claimed keys whose probe went past this slot to a later one.
    std::atomic<uint32_t> passed{0};
    std::atomic<const Entry *> value{nullptr};
  };

  // A lookup's walk: what it found, and the slots it examined.
  struct Walk {
    const Entry *entry;
    size_t slots;
  };

  size_t Hash(uint32_t ip) const noexcept {
    // One multiplicative mix: subscriber addresses are structured (a pool is a
    // prefix), and their low bits alone would cluster.
    return (static_cast<size_t>(ip) * 2654435761u) & mask_;
  }

  Walk Probe(uint32_t ip) const noexcept;

  // The slot holding `ip`, or kNoSlot. Control side.
  size_t Find(uint32_t ip) const noexcept;

  // The slot holding `ip`, claiming one for it when it has none: the first
  // from its home that holds no value (empty, or a claim no transaction
  // published). kNoSlot when every slot holds a value.
  size_t Claim(uint32_t ip) noexcept;

  // Empties `ip`'s slot, returning what was there.
  const Entry *Clear(uint32_t ip) noexcept;

  // Gives up `ip`'s claim of `slot`: the passes it counted are taken back, and
  // the slot holds no key.
  void Release(uint32_t ip, size_t slot) noexcept;

  class UpsertOp final : public bess::dataplane::StagedOp {
   public:
    UpsertOp(EntriesResource &owner, uint32_t ip, Owned entry)
        : owner_(owner), ip_(ip), entry_(std::move(entry)) {}

    void Publish(bess::dataplane::Retirer &retirer) noexcept override {
      // The key, claimed again *now*: Reserve's claim of it is not the one this
      // op can publish into. A sibling op of the same transaction -- another
      // address of the same session, whose probe passes a slot this op claimed
      // and left value-less -- may have taken it over and stored its own key
      // there (`Claim`), so publishing into the slot Reserve recorded
      // would put both addresses in one slot and lose one of them (and retire
      // one entry more than the transaction declared room for, which the
      // engine treats as a fatal footprint violation). Re-claiming by key is
      // what the slot-table op does, and it repairs exactly this:
      // a key the table no longer holds gets a fresh slot, and its value is
      // published where the key is. Both phases run under the engine's lock, so
      // nothing else moves in between.
      const size_t slot = owner_.Claim(ip_);
      if (slot == kNoSlot) {
        // Every slot holds a value: Reserve established room, so this is
        // unreachable -- and if it ever happens, the entry must still be
        // freed, which retiring it does (nothing has seen it).
        retirer.Retire(std::move(entry_));
        return;
      }
      // The slot owns the entry from here, so this op gives it up: its
      // destructor would otherwise free what the packet path is about to read,
      // and a later erase would retire the same pointer twice.
      if (const Entry *old = owner_.Publish(slot, entry_.release());
          old != nullptr) {
        retirer.Retire(owner_.Own(old));
      }
    }

   private:
    EntriesResource &owner_;
    uint32_t ip_;
    Owned entry_;
  };

  class EraseOp final : public bess::dataplane::StagedOp {
   public:
    EraseOp(EntriesResource &owner, uint32_t ip) : owner_(owner), ip_(ip) {}

    void Publish(bess::dataplane::Retirer &retirer) noexcept override {
      if (const Entry *old = owner_.Clear(ip_); old != nullptr) {
        retirer.Retire(owner_.Own(old));
      }
    }

   private:
    EntriesResource &owner_;
    uint32_t ip_;
  };

  // An entry this table's slab made, owned again (to retire it).
  Owned Own(const Entry *entry) noexcept {
    return Owned(entry, bess::utils::SlabDelete<const Entry>(slab_.get()));
  }

  // The slot's own install, called by UpsertOp under the engine's lock.
  const Entry *Publish(size_t slot, const Entry *entry) noexcept {
    const Entry *old =
        slots_[slot].value.exchange(entry, std::memory_order_acq_rel);
    if (old == nullptr) {
      live_++;
    }
    return old;
  }

  // Released after the destructor body has destroyed the live entries; the
  // retired ones may outlive the table, and the slab goes with the last.
  bess::utils::ObjectSlab<Entry>::Owner slab_;
  std::vector<Slot> slots_;
  size_t mask_ = 0;
  // Control side, under the engine's lock: the slots that hold a value. A slot
  // holding a key and no value is a claim, not an entry.
  size_t live_ = 0;
};

inline EntriesResource::~EntriesResource() {
  // Frees the entries the slots still hold: module teardown, after the workers
  // have stopped reading them (as the fork's own SlotTable destructor does). A
  // table destroyed with live entries is expected
  // -- ReleaseForTeardown is the path that tolerates them -- so what a
  // retirement would have freed is freed here.
  for (const Slot &slot : slots_) {
    if (const Entry *entry = slot.value.load(std::memory_order_relaxed)) {
      slab_->Destroy(entry);
    }
  }
}

inline EntriesResource::EntriesResource(std::string name, size_t max_entries)
    : Resource(std::move(name)),
      slab_(bess::utils::ObjectSlab<Entry>::Create()),
      slots_(SlotCount(max_entries)),
      mask_(slots_.size() - 1) {}

inline EntriesResource::Walk EntriesResource::Probe(uint32_t ip) const noexcept {
  if (ip == 0) {
    return {nullptr, 0};
  }
  size_t i = Hash(ip);
  for (size_t n = 1; n <= mask_ + 1; n++) {
    const uint32_t key = slots_[i].key.load(std::memory_order_acquire);
    if (key == ip) {
      const Entry *entry = slots_[i].value.load(std::memory_order_acquire);
      // The entry carries its own address, and the packet path reads it (the
      // reply's sender address): between the two loads a later transaction may
      // reuse this slot for another address -- an erased key's slot, or a key
      // that held no value, is what a claim takes -- so an entry for a
      // *different* address is not this key's and the probe goes on. Both
      // loads are acquire: the value a worker gets is either this key's entry
      // or the next transaction's.
      if (entry != nullptr && entry->ip == ip) {
        return {entry, n};
      }
    }
    if (slots_[i].passed.load(std::memory_order_acquire) == 0) {
      return {nullptr, n};
    }
    i = (i + 1) & mask_;
  }
  return {nullptr, mask_ + 1};
}

inline size_t EntriesResource::Find(uint32_t ip) const noexcept {
  size_t i = Hash(ip);
  for (size_t n = 0; n <= mask_; n++) {
    if (slots_[i].key.load(std::memory_order_acquire) == ip) {
      return i;
    }
    if (slots_[i].passed.load(std::memory_order_acquire) == 0) {
      break;
    }
    i = (i + 1) & mask_;
  }
  return kNoSlot;
}

inline size_t EntriesResource::Claim(uint32_t ip) noexcept {
  if (const size_t held = Find(ip); held != kNoSlot) {
    return held;
  }
  const size_t home = Hash(ip);
  size_t i = home;
  for (size_t n = 0; n <= mask_; n++) {
    const uint32_t key = slots_[i].key.load(std::memory_order_relaxed);
    if (key == 0 ||
        slots_[i].value.load(std::memory_order_relaxed) == nullptr) {
      // Empty, or a claim no transaction published (it costs the table
      // nothing). Every slot before it counts the pass, so a probe for `ip`
      // goes on to it; the counts precede the key's release store.
      if (key != 0) {
        Release(key, i);
      }
      for (size_t j = home; j != i; j = (j + 1) & mask_) {
        slots_[j].passed.fetch_add(1, std::memory_order_relaxed);
      }
      slots_[i].key.store(ip, std::memory_order_release);
      return i;
    }
    i = (i + 1) & mask_;
  }
  return kNoSlot;
}

inline const Entry *EntriesResource::Clear(uint32_t ip) noexcept {
  const size_t slot = Find(ip);
  if (slot == kNoSlot) {
    return nullptr;
  }
  const Entry *old =
      slots_[slot].value.exchange(nullptr, std::memory_order_acq_rel);
  if (old != nullptr) {
    live_--;
  }
  Release(ip, slot);
  return old;
}

inline void EntriesResource::Release(uint32_t ip, size_t slot) noexcept {
  // Only `ip`'s own passes go: a live key's probe still counts in every slot
  // before its own, so a worker mid-probe for it walks on to it.
  for (size_t j = Hash(ip); j != slot; j = (j + 1) & mask_) {
    slots_[j].passed.fetch_sub(1, std::memory_order_relaxed);
  }
  slots_[slot].key.store(0, std::memory_order_release);
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
  // already holds needs nothing -- Claim returns its slot, an unpublished
  // claim's included.
  const size_t slot = Claim(ip);
  if (slot == kNoSlot) {
    return std::unexpected("the entries table is full (" +
                           std::to_string(mask_ + 1) + " slots)");
  }
  const bool existed =
      slots_[slot].value.load(std::memory_order_acquire) != nullptr;
  // From the table's slab: may add a chunk, admitted first (a refusal throws
  // utils::MemoryRefused and refuses the transaction; the claim above keeps no
  // value, and a later claim takes it over).
  Owned entry = slab_->Make(Entry{ip, *mac});
  // Room for one replacement, always: what an upsert publishes over is only
  // known when it publishes (a sibling op of the same transaction may have put
  // a value under this key first), and a transaction that retires more than it
  // declared is a fatal footprint violation, while one that retires less
  // simply reserved what it did not use.
  Reservation reservation{std::make_unique<UpsertOp>(*this, ip, std::move(entry)),
                          {},
                          {.retires = 1}};
  reservation.existed = existed;
  return reservation;
}

}  // namespace arp
}  // namespace upf

#endif  // UPF_DATAPATH_ARP_RESPONDER_RESOURCE_H_
