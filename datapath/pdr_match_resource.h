// SPDX-License-Identifier: BSD-3-Clause

#ifndef UPF_DATAPATH_PDR_MATCH_RESOURCE_H_
#define UPF_DATAPATH_PDR_MATCH_RESOURCE_H_

#include <arpa/inet.h>
#include <netinet/in.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "dataplane/resource.h"
#include "pdr_match_matcher.h"
#include "upf_datapath.pb.h"

namespace upf {
namespace pdr_match {

// What a rule's verdict is, in the table's own `action` field: the library
// carries the caller's action untouched, and the module names its own (the
// same two values the `firewall` module uses, and for the same reason).
inline constexpr uint16_t kDrop = 0xFFFF;
inline constexpr uint16_t kPass = 0;

// The rules that can apply to packets of one QFI, as one matcher over them in
// the session's order, with the ActionId of each in the matcher's own
// numbering (rule_id - 1): the packet path reads the id here, not out of the
// protobuf.
struct QfiRules {
  std::unique_ptr<const SessionMatcher> matcher;
  std::vector<uint32_t> action_ids;
  // The MAR ID of each rule, in the same order: 0 for a rule that names none.
  std::vector<uint32_t> steering_ids;
  // The Router next hop of each rule, 0 for none.
  std::vector<uint32_t> next_hop_ids;
  // The two meter levels of each rule, in policing order (own, then shared).
  std::vector<std::array<uint32_t, 2>> meter_ids;
};

// One session's rules, published whole: the structures that match them, and
// the entry the controller wrote, kept so "<module>/rules" reads back as given.
//
// A rule may name a QFI (TS 29.244 8.2.89), and the first rule that matches a
// packet's tuple *and* its QFI wins, which one scan over the tuple cannot say:
// so a packet of QFI q is matched by the list of the rules that name q or
// nothing, in the session's order. `named` holds one such list per QFI some
// rule names, and `any` the rules that name none -- what a packet of every
// other QFI (and of none) can match. A session with no QFI-naming rule has
// `any` and an empty `named`, and the packet path never reads the QFI.
struct Rules {
  QfiRules any;
  std::vector<std::pair<uint8_t, QfiRules>> named;  // sorted by QFI; a few
  upf::pb::PdrMatchEntry arg;
};

// The prefix a rule names, parsed: the family, the address and the length. A
// prefix's length is mandatory, so nothing is ambiguous ("10.0.0.0/8" is a /8;
// "10.0.0.0" is not a rule).
struct Cidr {
  bess::classifier::FirewallFamily family;
  bess::classifier::FirewallAddr addr;
  uint8_t len;
};

// Parses "a.b.c.d/len" or "x::y/len" (firewall.cc's own parser, same form: the
// firewall path writes these strings and the compiler writes the same ones
// here).
inline std::optional<Cidr> ParseCidr(const std::string &text) {
  const size_t slash = text.find('/');
  if (slash == std::string::npos || slash + 1 >= text.size()) {
    return std::nullopt;
  }
  const std::string addr_text = text.substr(0, slash);
  const std::string len_text = text.substr(slash + 1);
  if (len_text.size() > 3 ||
      len_text.find_first_not_of("0123456789") != std::string::npos) {
    return std::nullopt;
  }
  const int len = std::stoi(len_text);

  Cidr out{};
  in_addr v4{};
  in6_addr v6{};
  if (inet_pton(AF_INET, addr_text.c_str(), &v4) == 1) {
    out.family = bess::classifier::FirewallFamily::kIpv4;
    std::memcpy(out.addr.data(), &v4, 4);
    if (len > 32) {
      return std::nullopt;
    }
  } else if (inet_pton(AF_INET6, addr_text.c_str(), &v6) == 1) {
    out.family = bess::classifier::FirewallFamily::kIpv6;
    std::memcpy(out.addr.data(), &v6, 16);
    if (len > 128) {
      return std::nullopt;
    }
  } else {
    return std::nullopt;
  }
  out.len = static_cast<uint8_t>(len);
  return out;
}

// Compiles one session's entry into what the packet path reads: the rules in
// the order the controller wrote them (the first that matches wins) and the
// structure over them. Every refusal the structure makes is this function's,
// rule for rule: a session is either programmed exactly or not at all.
inline std::expected<std::unique_ptr<const Rules>, std::string> CompileRules(
    const upf::pb::PdrMatchEntry &entry) {
  using bess::classifier::FirewallFamily;
  using bess::classifier::FirewallRule;

  // A rule as the structure takes it, and the QFI it names, if any.
  struct Parsed {
    FirewallRule rule;
    std::optional<uint8_t> qfi;
    uint32_t steering_id = 0;
    uint32_t next_hop_id = 0;
    std::array<uint32_t, 2> meter_ids{0, 0};
  };
  std::vector<Parsed> rules;
  rules.reserve(static_cast<size_t>(entry.rules_size()));
  int i = 0;
  for (const auto &rule : entry.rules()) {
    // The rule's own number, 1-based, as BESS's structures number the rules
    // they build: a list they refuse reports the same rule by the same name as
    // this function does.
    const std::string where = "rule " + std::to_string(i + 1) + ": ";
    std::optional<Cidr> src;
    std::optional<Cidr> dst;
    if (!rule.src_ip().empty()) {
      src = ParseCidr(rule.src_ip());
      if (!src) {
        return std::unexpected(where + "invalid IP prefix '" + rule.src_ip() +
                               "'");
      }
    }
    if (!rule.dst_ip().empty()) {
      dst = ParseCidr(rule.dst_ip());
      if (!dst) {
        return std::unexpected(where + "invalid IP prefix '" + rule.dst_ip() +
                               "'");
      }
    }
    // The prefixes decide the rule's family. A rule with neither matches both
    // families; "any IPv4" is "0.0.0.0/0" and "any IPv6" is "::/0".
    FirewallFamily family = FirewallFamily::kAny;
    if (src && dst) {
      if (src->family != dst->family) {
        return std::unexpected(where + "'" + rule.src_ip() + "' and '" +
                               rule.dst_ip() + "' are different families");
      }
      family = src->family;
    } else if (src) {
      family = src->family;
    } else if (dst) {
      family = dst->family;
    }

    if (rule.proto() > 0xff) {
      return std::unexpected(where + "protocol " +
                             std::to_string(rule.proto()) + " is out of range");
    }
    // Ports are uint32 on the wire: check before narrowing, or 65616 would
    // quietly become port 80. An unset high bound is the full range, which is
    // why it is `optional` in the message.
    const uint32_t src_high =
        rule.has_src_port_high() ? rule.src_port_high() : 0xffff;
    const uint32_t dst_high =
        rule.has_dst_port_high() ? rule.dst_port_high() : 0xffff;
    if (rule.src_port_low() > 0xffff || src_high > 0xffff ||
        rule.dst_port_low() > 0xffff || dst_high > 0xffff) {
      return std::unexpected(where + "a port is out of range");
    }
    if (rule.drop() && rule.action_id() != 0) {
      return std::unexpected(
          where + "a rule that drops cannot name an action - the packet never "
                  "reaches the ActionTable that would resolve it");
    }
    if (rule.drop() && rule.steering_policy_id() != 0) {
      return std::unexpected(
          where + "a rule that drops cannot name a MAR - the packet never "
                  "reaches the steering module");
    }
    if (rule.drop() &&
        (rule.next_hop_id() != 0 || rule.meter_ids_size() != 0)) {
      return std::unexpected(
          where + "a rule that drops cannot name a meter or next hop - the "
                  "packet never reaches the module that would enforce it");
    }
    if (rule.meter_ids_size() > 2) {
      return std::unexpected(where + "at most two meter levels fit a rule");
    }

    std::optional<uint8_t> qfi;
    if (rule.has_qfi()) {
      if (rule.qfi() > 63) {
        return std::unexpected(where + "QFI " + std::to_string(rule.qfi()) +
                               " is out of range (0..63)");
      }
      qfi = static_cast<uint8_t>(rule.qfi());
    }

    FirewallRule parsed;
    parsed.family = family;
    if (src) {
      parsed.src_net = src->addr;
      parsed.src_len = src->len;
    }
    if (dst) {
      parsed.dst_net = dst->addr;
      parsed.dst_len = dst->len;
    }
    parsed.proto = static_cast<uint8_t>(rule.proto());
    parsed.src_port_low = static_cast<uint16_t>(rule.src_port_low());
    parsed.src_port_high = static_cast<uint16_t>(src_high);
    parsed.dst_port_low = static_cast<uint16_t>(rule.dst_port_low());
    parsed.dst_port_high = static_cast<uint16_t>(dst_high);
    parsed.action = rule.drop() ? kDrop : kPass;
    parsed.action_id = rule.action_id();
    Parsed out_rule{parsed, qfi, rule.steering_policy_id(),
                    rule.next_hop_id(), {0, 0}};
    for (int m = 0; m < rule.meter_ids_size(); m++) {
      out_rule.meter_ids[m] = rule.meter_ids(m);
    }
    rules.push_back(out_rule);
    i++;
  }

  // One matcher over the rules a packet of `q` can match: those naming it, and
  // those naming none, in the session's order. nullopt is "no QFI": the rules
  // that name none.
  auto build = [&rules](std::optional<uint8_t> q)
      -> std::expected<QfiRules, std::string> {
    std::vector<FirewallRule> list;
    QfiRules out;
    for (const Parsed &p : rules) {
      if (!p.qfi || (q && *p.qfi == *q)) {
        list.push_back(p.rule);
        out.action_ids.push_back(p.rule.action_id);
        out.steering_ids.push_back(p.steering_id);
        out.next_hop_ids.push_back(p.next_hop_id);
        out.meter_ids.push_back(p.meter_ids);
      }
    }
    auto matcher = MakeSessionMatcher(std::move(list));
    if (!matcher) {
      return std::unexpected(matcher.error());
    }
    out.matcher = std::move(*matcher);
    return out;
  };

  auto out = std::make_unique<Rules>();
  auto any = build(std::nullopt);
  if (!any) {
    return std::unexpected(any.error());
  }
  out->any = std::move(*any);
  std::vector<uint8_t> qfis;
  for (const Parsed &p : rules) {
    if (p.qfi) {
      qfis.push_back(*p.qfi);
    }
  }
  std::sort(qfis.begin(), qfis.end());
  qfis.erase(std::unique(qfis.begin(), qfis.end()), qfis.end());
  for (const uint8_t q : qfis) {
    auto list = build(q);
    if (!list) {
      return std::unexpected("for QFI " + std::to_string(q) + ": " +
                             list.error());
    }
    out->named.emplace_back(q, std::move(*list));
  }
  out->arg = entry;
  return out;
}

// "<module>/rules": the session id -> that session's rules. A map resource in
// the sense the transaction engine means (D-129): the engine applies one
// operation per key, so a session change is one upsert of O(that session's
// rules), never a rewrite of a table every session shares -- which is the
// whole reason this module exists (docs/design.md, "the keyed write").
//
// The store is one open-addressed table, allocated once (control side, at
// creation) and never resized. Two invariants make the packet path a plain
// acquire load per probe step, with no lock and no reclamation of its own:
//
//   - a slot's key is written before its value (release/acquire), so a reader
//     that sees a key and not yet its value reads a miss -- the same
//     "invisible until published" a key being added has always had here;
//   - a slot is never emptied. An erase stores a null value and keeps the key
//     as a tombstone, so no probe chain is ever broken, and a later key may
//     take the tombstone's slot (a slot whose key a probe passes is one it
//     looks past, never one it stops at).
//
// The object a store replaces goes to the transaction's Retirer and is freed a
// grace period later (dataplane/resource.h), exactly as SlotResource's does.
// The resource references nothing and nothing references it: a rule's action id
// is a value, and the compiler writes the action record before the rule that
// names it (docs/design.md, install order).
class SessionResource final : public bess::dataplane::Resource {
 public:
  // `max_sessions` sessions fit: the table is sized to twice that, so the
  // probe stays short at the load a session graph actually runs at.
  explicit SessionResource(std::string name, size_t max_sessions);

  // Frees the rules the slots still hold: module teardown, after the workers
  // stopped reading them (SlotTable's destructor does the same). What was
  // retired is the Retirer's, not the slots'.
  ~SessionResource() override {
    for (Slot &slot : slots_) {
      delete slot.value.load(std::memory_order_relaxed);
    }
  }

  // The rules for `session`, or nullptr. One acquire load per probe step; the
  // pointer stays valid until the transaction that replaced it has finished
  // its grace period.
  const Rules *Lookup(uint32_t session) const noexcept;

  size_t LiveCount() const override { return live_; }

  // Every live value, control side: what "<module>/rules" reads back. A scan of
  // the slots, not a lookup per possible key.
  template <typename Fn>
  void ForEach(Fn &&visit) const {
    for (size_t i = 0; i <= mask_; i++) {
      const uint32_t key = slots_[i].key.load(std::memory_order_acquire);
      const Rules *value = slots_[i].value.load(std::memory_order_acquire);
      if (key != 0 && value != nullptr) {
        visit(key, *value);
      }
    }
  }

  bool Contains(const bess::dataplane::ResourceKey &key) const override;

  std::expected<Reservation, std::string> Reserve(
      const bess::dataplane::Op &op) override;

  // No per-transaction state is kept: a slot a Reserve claimed is claimed for
  // good (it is a tombstone if the transaction never published), and the room
  // that makes the claim is the table's, not the transaction's.
  void EndTransaction() noexcept override {}

 private:
  static constexpr size_t kNoSlot = ~size_t{0};

  struct Slot {
    // 0 is never a session (and never claimed): a slot no key has used.
    std::atomic<uint32_t> key{0};
    std::atomic<const Rules *> value{nullptr};
  };

  size_t Hash(uint32_t session) const noexcept {
    // One multiplicative mix: a session id is an F-TEID, whose low bits an SMF
    // or a deployment may well leave structured.
    return (static_cast<size_t>(session) * 2654435761u) & mask_;
  }

  // The slot holding `session`, or kNoSlot. Control side.
  size_t Find(uint32_t session) const noexcept;

  // The slot holding `session`, claiming one for it when it has none: the
  // first tombstone the probe passes, else the empty slot it stops at.
  // kNoSlot when every slot is claimed and none is a tombstone. A slot claimed
  // here is never given back, so a Reserve that aborts leaves a tombstone
  // rather than a hole.
  size_t Claim(uint32_t session) noexcept;

  // Installs `rules` at the slot holding `session` (which Claim or an earlier
  // transaction must have established), returning what it replaced.
  const Rules *Store(uint32_t session, const Rules *rules) noexcept;

  // Empties the slot holding `session`, returning what was there.
  const Rules *Clear(uint32_t session) noexcept;

  class UpsertOp final : public bess::dataplane::StagedOp {
   public:
    UpsertOp(SessionResource &owner, uint32_t session,
             std::unique_ptr<const Rules> rules)
        : owner_(owner), session_(session), rules_(std::move(rules)) {}

    void Publish(bess::dataplane::Retirer &retirer) noexcept override {
      // The slot owns the rules from here, so this op gives them up: its
      // destructor would otherwise free what the packet path is about to read,
      // and a later erase would retire the same pointer a second time
      // (SlotTable::Publish does the same with object.release()).
      const Rules *old = owner_.Store(session_, rules_.release());
      if (old != nullptr) {
        retirer.Retire(std::unique_ptr<const Rules>(const_cast<Rules *>(old)));
      }
    }

   private:
    SessionResource &owner_;
    uint32_t session_;
    std::unique_ptr<const Rules> rules_;
  };

  class EraseOp final : public bess::dataplane::StagedOp {
   public:
    EraseOp(SessionResource &owner, uint32_t session)
        : owner_(owner), session_(session) {}

    void Publish(bess::dataplane::Retirer &retirer) noexcept override {
      if (const Rules *old = owner_.Clear(session_); old != nullptr) {
        retirer.Retire(std::unique_ptr<const Rules>(const_cast<Rules *>(old)));
      }
    }

   private:
    SessionResource &owner_;
    uint32_t session_;
  };

  std::vector<Slot> slots_;
  size_t mask_ = 0;
  // Control side, under the engine's lock: the slots that hold a value. A slot
  // holding a key and no value is a tombstone, not a session.
  size_t live_ = 0;
};

inline SessionResource::SessionResource(std::string name, size_t max_sessions)
    : Resource(std::move(name)) {
  size_t slots = 2;
  while (slots < max_sessions * 2) {
    slots <<= 1;
  }
  slots_ = std::vector<Slot>(slots);
  mask_ = slots - 1;
}

inline const Rules *SessionResource::Lookup(uint32_t session) const noexcept {
  if (session == 0) {
    return nullptr;
  }
  size_t i = Hash(session);
  for (size_t n = 0; n <= mask_; n++) {
    const uint32_t key = slots_[i].key.load(std::memory_order_acquire);
    if (key == 0) {
      return nullptr;
    }
    if (key == session) {
      return slots_[i].value.load(std::memory_order_acquire);
    }
    i = (i + 1) & mask_;
  }
  return nullptr;
}

inline size_t SessionResource::Find(uint32_t session) const noexcept {
  const Slot *slot = nullptr;
  size_t i = Hash(session);
  for (size_t n = 0; n <= mask_; n++) {
    const uint32_t key = slots_[i].key.load(std::memory_order_acquire);
    if (key == 0) {
      break;
    }
    if (key == session) {
      slot = &slots_[i];
      break;
    }
    i = (i + 1) & mask_;
  }
  return slot == nullptr ? kNoSlot : i;
}

inline size_t SessionResource::Claim(uint32_t session) noexcept {
  size_t i = Hash(session);
  size_t dead = kNoSlot;
  for (size_t n = 0; n <= mask_; n++) {
    const uint32_t key = slots_[i].key.load(std::memory_order_relaxed);
    if (key == session) {
      return i;
    }
    if (key == 0) {
      // A slot no key has used: the probe's end. Take the first tombstone
      // passed (it costs the table nothing) or this one.
      const size_t target = dead != kNoSlot ? dead : i;
      slots_[target].key.store(session, std::memory_order_release);
      return target;
    }
    if (dead == kNoSlot && slots_[i].value.load(std::memory_order_relaxed) == nullptr) {
      dead = i;
    }
    i = (i + 1) & mask_;
  }
  // Every slot holds a key: the only room is a tombstone, and the probe has
  // passed all of them.
  if (dead == kNoSlot) {
    return kNoSlot;
  }
  slots_[dead].key.store(session, std::memory_order_release);
  return dead;
}

inline const Rules *SessionResource::Store(uint32_t session,
                                           const Rules *rules) noexcept {
  const size_t slot = Claim(session);
  if (slot == kNoSlot) {
    return nullptr;  // Reserve established room; this cannot happen
  }
  const Rules *old = slots_[slot].value.exchange(rules, std::memory_order_acq_rel);
  if (old == nullptr) {
    live_++;
  }
  return old;
}

inline const Rules *SessionResource::Clear(uint32_t session) noexcept {
  const size_t slot = Find(session);
  if (slot == kNoSlot) {
    return nullptr;
  }
  const Rules *old = slots_[slot].value.exchange(nullptr, std::memory_order_acq_rel);
  if (old != nullptr) {
    live_--;
  }
  return old;
}

inline bool SessionResource::Contains(
    const bess::dataplane::ResourceKey &key) const {
  uint32_t session = 0;
  if (!bess::dataplane::DecodeKey(key, &session)) {
    return false;
  }
  const size_t slot = Find(session);
  return slot != kNoSlot &&
         slots_[slot].value.load(std::memory_order_acquire) != nullptr;
}

inline std::expected<bess::dataplane::Resource::Reservation, std::string>
SessionResource::Reserve(const bess::dataplane::Op &op) {
  uint32_t session = 0;
  if (!bess::dataplane::DecodeKey(op.key, &session)) {
    return std::unexpected("the key is " + std::to_string(op.key.size()) +
                           " bytes, and a session id is 4");
  }
  if (session == 0) {
    return std::unexpected("session 0 names no session");
  }

  if (op.kind == bess::dataplane::OpKind::kErase) {
    const size_t slot = Find(session);
    if (slot == kNoSlot ||
        slots_[slot].value.load(std::memory_order_acquire) == nullptr) {
      return std::unexpected("not found");
    }
    Reservation erase{std::make_unique<EraseOp>(*this, session), {},
                      {.retires = 1}};
    erase.existed = true;
    return erase;
  }

  const upf::pb::PdrMatchEntry *entry =
      std::any_cast<upf::pb::PdrMatchEntry>(&op.value);
  if (entry == nullptr) {
    return std::unexpected("wrong value type (want PdrMatchEntry)");
  }
  auto rules = CompileRules(*entry);
  if (!rules) {
    return std::unexpected(rules.error());
  }

  // The slot the value will be published in, claimed now: the room it needs is
  // the table's, and this is the only step that can find none. A key the table
  // already holds needs nothing -- Claim returns its slot, a tombstone's
  // included.
  const size_t slot = Claim(session);
  if (slot == kNoSlot) {
    return std::unexpected("the session table is full (" +
                           std::to_string(mask_ + 1) + " slots)");
  }
  // Whether a value was there, as the library's own resources report it
  // (dataplane/slot_resource.h): a slot holding a tombstone held none, so this
  // upsert replaces nothing and retires nothing.
  const bool existed =
      slots_[slot].value.load(std::memory_order_acquire) != nullptr;
  Reservation reservation{
      std::make_unique<UpsertOp>(*this, session, std::move(*rules)),
      {},
      {.retires = existed ? 1u : 0u}};
  reservation.existed = existed;
  return reservation;
}

}  // namespace pdr_match
}  // namespace upf

#endif  // UPF_DATAPATH_PDR_MATCH_RESOURCE_H_
