// SPDX-License-Identifier: BSD-3-Clause
//
// The session-major layout (UpfSessionAppliance). One resource,
// "<module>/sessions", carries a PFCP session's whole compiled user plane --
// its F-TEIDs, PDR rules, actions (FAR + URR + tunnel) and QERs -- as ONE
// entry, and the session's hot state lives together: session id s owns the
// stride at (s - 1) * stride of one flat DPDK array:
//
//   config[0]  max_actions lines   the actions as session version 0 has them
//   config[1]  max_actions lines   ... and version 1
//   cells      2 x max_actions     URR cell slots (UL bank, DL bank)
//   meters     2 x max_qers        meter slots: a MeterState (the session's
//                                  own bucket) or a SharedRef (a meter of
//                                  "<module>/meters", shared across sessions)
//
// An action's configuration (FAR, tunnel, its meter and cell slots) is one
// cache line. A PDR rule's result id is session << 5 | version << 4 | index:
// a match reaches config[version][index] with no index or record load, and
// every later stage of the packet reads the slots that config names. A
// packet therefore never combines one version's PDR with another version's
// FAR, QER, URR or tunnel.
//
// The F-TEID exact index and the UL/DL masked PDR tables remain lookup
// structures; this resource drives them (FteidResource's staged operations,
// ConcurrentMaskedTable's Prepare/Commit) inside its own operation.
//
// Contract (D-021):
//   insert  Reserve writes version 0 and prepares the rules (pending,
//           invisible) and F-TEIDs; no reader can reach the stride: a free id
//           has no rule naming it, and its previous session's removal
//           cascade has finished. Publish makes the F-TEIDs admissible and
//           commits the rules.
//   update  beside running workers. Reserve first waits, if it must, for the
//           grace period of this session's previous update (one worker
//           batch; never a refusal), so the other version and every slot
//           only it names are unreachable; frees those slots; assigns slots
//           by identity -- an action that keeps its action_id keeps its cell
//           slot (both directional banks, wherever it moves), a QER that
//           keeps its qer_id and profile (or shared meter) keeps its meter
//           slot and so its buckets; anything new takes a free slot, a new
//           bucket starting full -- writes the other version, and prepares
//           every rule again with that version's result. Publish commits the
//           rules make-before-break: inserts and priority-raising
//           replacements by descending priority, the F-TEID inserts, then
//           erases and priority-lowering replacements by ascending priority,
//           then the F-TEID erases. Nothing is copied: cells and buckets are
//           shared by both versions, so a rewrite neither loses nor
//           double-counts usage, and a kept bucket keeps its tokens.
//   erase   Publish removes the F-TEIDs and rules at once and marks the
//           session gone for held packets; the stride stays readable and the
//           id unusable until the removal cascade frees it.
// An action id belongs to one session; a PDR key and an F-TEID to one rule.
// ATSSS access.tunnel_id is local: 0 keeps the matched action's tunnel;
// 1..max_actions selects that 1-based action's tunnel in the packet's
// session version. Missing local actions/tunnels drop no_tunnel.

#ifndef UPF_DATAPATH_UPF_APPLIANCE_SESSIONS_H_
#define UPF_DATAPATH_UPF_APPLIANCE_SESSIONS_H_

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <mutex>
#include <new>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <type_traits>
#include <vector>

#include "classifier/concurrent_masked.h"
#include "dataplane/resource.h"
#include "fteid_resource.h"
#include "meter/meter.h"
#include "rcu/rcu_domain.h"
#include "upf_datapath.pb.h"
#include "utils/dpdk_memory.h"

namespace upf::appliance {

struct Tunnel {
  uint32_t teid = 0;
  uint8_t family = 0;
  uint8_t local[16]{}, peer[16]{};
  uint32_t transport_route_domain = 0;
  uint8_t qfi = 0;
  uint16_t marking = 0;
  bool has_qfi = false;
};

// One action of one session version: exactly one cache line, the FAR and its
// tunnel together. IPv4 addresses sit in the last four bytes of local/peer.
struct alignas(RTE_CACHE_LINE_SIZE) ActionConfig {
  static constexpr uint16_t kSharedMeter = 0x8000;  // meter[]: slot holds a SharedRef
  static constexpr uint8_t kCellSlot = 0x1f, kCount = 0x20, kHasTunnel = 0x40;
  static constexpr uint8_t kQfi = 0x3f, kHasQfi = 0x40, kIpv6 = 0x80;
  uint32_t action_id = 0;  // 0: no action at this position
  uint32_t next_hop_id = 0, route_domain = 0, policy_id = 0;
  uint32_t teid = 0, transport_route_domain = 0;
  // Per meter level: 0 none, else meter slot + 1, kSharedMeter if shared.
  std::array<uint16_t, 2> meter{};
  uint16_t marking = 0;
  uint8_t qfi = 0;   // kQfi | kHasQfi | kIpv6 (tunnel family)
  uint8_t cell = 0;  // kCellSlot | kCount | kHasTunnel
  uint8_t local[16]{}, peer[16]{};

  bool has_tunnel() const noexcept { return cell & kHasTunnel; }
  Tunnel tunnel() const noexcept;
};
static_assert(sizeof(ActionConfig) == RTE_CACHE_LINE_SIZE);

// Independent directional histories: written by the one worker (atomic
// load/store, never a read-modify-write), read by get_counts.
struct SessionUrr {
  std::atomic<uint64_t> packets{0}, octets{0}, first_ns{0}, last_ns{0};
  void Add(uint64_t bytes, uint64_t now_ns) noexcept {
    constexpr auto relaxed = std::memory_order_relaxed;
    packets.store(packets.load(relaxed) + 1, relaxed);
    octets.store(octets.load(relaxed) + bytes, relaxed);
    if (first_ns.load(relaxed) == 0) first_ns.store(now_ns, relaxed);
    last_ns.store(now_ns, relaxed);
  }
  void Reset() noexcept {
    for (auto *cell : {&packets, &octets, &first_ns, &last_ns}) cell->store(0, std::memory_order_relaxed);
  }
};
struct alignas(RTE_CACHE_LINE_SIZE) SessionCells {
  std::array<SessionUrr, 2> urr;  // UL, DL
};
static_assert(sizeof(SessionCells) == RTE_CACHE_LINE_SIZE);

// A meter slot: a MeterState built in place (the session's own bucket) or the
// id of a shared meter. Which one is the referring config's kSharedMeter bit.
struct alignas(RTE_CACHE_LINE_SIZE) MeterSlot {
  alignas(bess::meter::MeterState) std::byte bytes[sizeof(bess::meter::MeterState)];
  bess::meter::MeterState &meter() noexcept {
    return *std::launder(reinterpret_cast<bess::meter::MeterState *>(bytes));
  }
  uint32_t shared() const noexcept {
    uint32_t id;
    std::memcpy(&id, bytes, sizeof(id));
    return id;
  }
  void set_shared(uint32_t id) noexcept { std::memcpy(bytes, &id, sizeof(id)); }
};
static_assert(sizeof(MeterSlot) == RTE_CACHE_LINE_SIZE);
static_assert(std::is_trivially_destructible_v<bess::meter::MeterState>);

// A session as the resource takes it (the codec's decode of UpfSession).
struct SessionValue {
  static constexpr uint8_t kNoAction = 0xff;
  struct Fteid {
    upf::datapath::FteidId id{};
    upf::datapath::FteidRecord record;
  };
  struct Qer {
    uint32_t qer_id = 0;
    std::optional<bess::meter::MeterProfileSpec> spec;  // engaged: own bucket
    uint32_t shared = 0;                                // else this meter id
  };
  struct Action {
    uint32_t action_id = 0, next_hop_id = 0, route_domain = 0, policy_id = 0;
    std::array<uint8_t, 2> qer{};  // per level: 1-based QER position, 0 none
    bool count = false;
    std::optional<Tunnel> tunnel;
  };
  struct Pdr {
    bool dl = false;
    std::vector<std::byte> mask, value;
    std::vector<bess::classifier::ConcurrentMaskedTable::KeyRange> ranges;
    int64_t priority = 0;
    uint16_t gate = 0;
    uint8_t action = kNoAction;  // 0-based; kNoAction only with the drop gate
  };
  std::vector<Fteid> fteids;
  std::vector<Qer> qers;
  std::vector<Action> actions;
  std::vector<Pdr> pdrs;
};

std::expected<upf::datapath::FteidId, std::string> DecodeFteidKey(const upf::pb::FteidKey &key);
upf::pb::FteidKey EncodeFteidKey(const upf::datapath::FteidId &id);
std::expected<Tunnel, std::string> DecodeTunnel(const upf::pb::TunnelEntry &value);
upf::pb::TunnelEntry EncodeTunnel(const Tunnel &tunnel);
// End Marker relays (an F-TEID entry's end_marker_relays) are not ported to
// the session-major path: a session that names them is accepted -- refusing
// it would fail a Mode 4/6 handover's whole Session Modification -- its
// F-TEIDs carry none, and each relay is added to `unsupported_relays` once the
// session decodes (a refused one counts nothing).
std::expected<SessionValue, std::string> DecodeSession(const upf::pb::UpfSession &session,
                                                       std::atomic<uint64_t> &unsupported_relays);

class SessionResource final : public bess::dataplane::Resource {
 public:
  using Table = bess::classifier::ConcurrentMaskedTable;
  static constexpr uint32_t kActionBits = 4;
  static constexpr size_t kMaxActions = size_t{1} << kActionBits;
  static constexpr size_t kMaxQers = 16;
  static constexpr uint8_t kGone = 0xff;  // Active(): no live version
  // result ids are session << 5 | ...; kPendingResult-free and nonzero.
  static constexpr size_t kMaxCapacity = (size_t{1} << (32 - kActionBits - 1)) - 2;

  struct Limits {
    size_t capacity = 0, max_actions = 0, max_qers = 0;
  };
  static size_t Stride(const Limits &l) noexcept {
    return 2 * l.max_actions * (sizeof(ActionConfig) + sizeof(SessionCells)) +
           2 * l.max_qers * sizeof(MeterSlot);
  }
  // Admitted before construction (D-198): the flat array and the active
  // versions (DPDK), and the control-side record per id (glibc). Per-session
  // control growth -- slot owners, rule keys, F-TEIDs, action-index nodes,
  // interned meter profiles -- is admitted per transaction.
  static size_t GlibcBytes(const Limits &l) noexcept;
  static size_t Bytes(const Limits &l) noexcept {
    return l.capacity * (Stride(l) + sizeof(std::atomic<uint8_t>)) + GlibcBytes(l);
  }

  // `meters`: the shared meters' resource name, which a session's
  // shared_meter_id references.
  SessionResource(std::string name, std::string next_hops, std::string meters, Limits limits,
                  Table &ul, Table &dl, upf::datapath::FteidResource &fteids,
                  bess::rcu::RcuDomain &domain);
  ~SessionResource() override;

  // -- packet path -------------------------------------------------------------
  static uint32_t SessionOf(uint32_t result) noexcept { return result >> (kActionBits + 1); }
  static uint8_t VersionOf(uint32_t result) noexcept { return (result >> kActionBits) & 1; }
  static uint8_t IndexOf(uint32_t result) noexcept { return result & (kMaxActions - 1); }
  static uint32_t ResultOf(uint32_t session, uint8_t version, uint8_t index) noexcept {
    return session << (kActionBits + 1) | uint32_t{version} << kActionBits | index;
  }
  const ActionConfig &Config(uint32_t session, uint8_t version, uint8_t index) const noexcept {
    return *std::launder(reinterpret_cast<const ActionConfig *>(
        Stride(session) + (version * limits_.max_actions + index) * sizeof(ActionConfig)));
  }
  SessionCells &Cells(uint32_t session, uint8_t slot) const noexcept {
    return *std::launder(reinterpret_cast<SessionCells *>(
        Stride(session) + cells_at_ + slot * sizeof(SessionCells)));
  }
  MeterSlot &Meter(uint32_t session, uint16_t slot) const noexcept {
    return *std::launder(reinterpret_cast<MeterSlot *>(
        Stride(session) + meters_at_ + slot * sizeof(MeterSlot)));
  }
  // The version a held packet resumes against, kGone once erased.
  uint8_t Active(uint32_t session) const noexcept {
    return active_[session - 1].load(std::memory_order_acquire);
  }
  // `action_id`'s position in `version`, or -1.
  int Find(uint32_t session, uint8_t version, uint32_t action_id) const noexcept {
    for (uint8_t i = 0; i < limits_.max_actions; ++i)
      if (Config(session, version, i).action_id == action_id) return i;
    return -1;
  }

  // -- control -----------------------------------------------------------------
  const Limits &limits() const noexcept { return limits_; }
  size_t bytes() const noexcept;
  void set_memory_growth(bess::utils::MemoryGrowth *growth) noexcept { growth_ = growth; }
  // Every live session as a client writes it.
  void ForEachLive(const std::function<void(uint32_t, const upf::pb::UpfSession &)> &visit) const;
  // get_counts for counters_ul (dl false) or counters_dl: every action ever
  // provisioned for counting that direction (ids empty), else the ids asked for.
  void Counts(bool dl, std::span<const uint32_t> ids, bool restart,
              upf::pb::UrrCountCommandGetCountsResponse *out) const;

  bool Contains(const bess::dataplane::ResourceKey &key) const override;
  std::vector<bess::dataplane::Reference> ReferencesOf(
      const bess::dataplane::ResourceKey &key) const override;
  void VisitReferences(
      const std::function<void(const bess::dataplane::Reference &)> &visit) const override;
  std::expected<Reservation, std::string> Reserve(const bess::dataplane::Op &op) override;
  void EndTransaction() noexcept override;
  size_t LiveCount() const override { return live_.load(std::memory_order_relaxed); }
  std::optional<uint64_t> Capacity() const override { return limits_.capacity; }

 private:
  class Staged;
  struct Rule {
    bool dl = false;
    std::string key;  // mask | value | ranges, as a MaskedRuleResource key
  };
  // One interned profile: the MeterStates built under it point here.
  struct Profile {
    bess::meter::MeterProfile profile;
    size_t refs = 0;
  };
  using ProfileKey = std::array<uint64_t, 5>;
  struct Mirror {
    enum class State : uint8_t { kFree, kLive, kRetiring };
    State state = State::kFree;
    uint8_t active = 0;           // the version new rules carry
    uint8_t actions = 0, qers = 0;  // in that version
    bool flipped = false;         // an update published; `flip` once its grace period started
    bess::rcu::GracePeriod flip = 0;
    // Slot bitmaps: used by the active version / by the previous one only
    // (unreachable once `flip` completes); meters_shared: holds a SharedRef.
    uint32_t cells_live = 0, cells_old = 0, meters_live = 0, meters_old = 0, meters_shared = 0;
    uint32_t banks[2] = {0, 0};   // per direction: cell slots ever counted
    size_t bytes = 0;             // admitted glibc bytes of the vectors and index nodes
    // 2 x max_actions cell owners (action ids), 2 x max_qers meter owners
    // (qer ids), then the active version's QER refs by position.
    std::vector<uint32_t> slots;
    std::vector<Rule> rules;
    std::vector<SessionValue::Fteid> fteids;
  };
  // An action-index node's and a profile node's glibc cost, estimates.
  static constexpr size_t kNodeBytes = sizeof(std::pair<const uint32_t, uint32_t>) + 4 * sizeof(void *);
  static constexpr size_t kProfileBytes = sizeof(std::pair<const ProfileKey, Profile>) + 4 * sizeof(void *);

  std::byte *Stride(uint32_t session) const noexcept { return base_ + (session - 1) * stride_; }
  uint32_t &CellOwner(Mirror &m, size_t slot) const noexcept { return m.slots[slot]; }
  uint32_t &MeterOwner(Mirror &m, size_t slot) const noexcept { return m.slots[2 * limits_.max_actions + slot]; }
  uint32_t &QerRef(Mirror &m, size_t position) const noexcept {
    return m.slots[2 * limits_.max_actions + 2 * limits_.max_qers + position];
  }
  size_t SlotsSize() const noexcept { return 2 * limits_.max_actions + 3 * limits_.max_qers; }

  Table &TableOf(bool dl) const noexcept { return dl ? dl_ : ul_; }
  size_t KeyLen(bool dl) const noexcept { return dl ? 22 : 18; }
  static std::string RuleKey(const SessionValue::Pdr &pdr);
  std::optional<Table::Prepared> PrepareErase(const Rule &rule) const;
  std::expected<std::vector<uint8_t>, std::string> Validate(const SessionValue &v) const;
  std::vector<bess::dataplane::Reference> References(uint32_t session) const;
  std::vector<bess::dataplane::Reference> References(const SessionValue &v) const;
  // Interned profiles (control side; mu_ held). Acquire may throw what the
  // growth hook throws; Release drops a reference and frees the last.
  std::expected<const bess::meter::MeterProfile *, std::string> AcquireProfile(
      const bess::meter::MeterProfileSpec &spec);
  void ReleaseProfile(const bess::meter::MeterProfile &profile) noexcept;
  // Frees the slots only the previous version named: their readers are gone.
  void ReleaseOld(Mirror &m, uint32_t session) noexcept;
  // The removal step of an erase: every slot, the active version gone.
  void Free(uint32_t session) noexcept;
  upf::pb::UpfSession Read(uint32_t session) const;
  void Report(uint32_t action_id, bool dl, bool restart,
              upf::pb::UrrCountCommandGetCountsResponse *out) const;

  const Limits limits_;
  const size_t stride_, cells_at_, meters_at_;
  const std::string next_hops_, meters_;
  Table &ul_, &dl_;
  upf::datapath::FteidResource &fteids_;
  bess::rcu::RcuDomain &domain_;
  struct alignas(RTE_CACHE_LINE_SIZE) Line {
    std::byte bytes[RTE_CACHE_LINE_SIZE];
  };
  bess::utils::DpdkArray<Line> storage_;
  bess::utils::DpdkArray<std::atomic<uint8_t>> active_;
  std::byte *base_ = nullptr;
  bess::utils::MemoryGrowth *growth_ = nullptr;

  // Guards everything below; get_counts reads beside a transaction.
  mutable std::mutex mu_;
  std::vector<Mirror> mirrors_;  // index session - 1
  std::map<uint32_t, uint32_t> actions_;  // action id -> session << 5 | cell slot
  std::map<ProfileKey, Profile> profiles_;
  std::set<uint32_t> tx_sessions_, tx_actions_;  // this transaction's
  std::set<std::string> tx_rules_;
  std::atomic<size_t> live_{0}, mirror_bytes_{0};
};

}  // namespace upf::appliance

#endif  // UPF_DATAPATH_UPF_APPLIANCE_SESSIONS_H_
