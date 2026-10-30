// SPDX-License-Identifier: BSD-3-Clause
//
// Session-major layout (appliance study, scratch). One resource,
// "<module>/sessions", carries a PFCP session's whole compiled user plane --
// its F-TEIDs, PDR rules, actions (FAR + URR + tunnel) and QERs -- as ONE
// entry, and the session's hot state lives together: session id s owns the
// stride at (s - 1) * stride of one flat DPDK array, its QERs first (the
// rte_meter token buckets, built in place by MeterState::ConstructAt, beside
// the compiled profile they run under), then its actions (what
// classification copies, the URR packet/octet/time cells, the encap tunnel).
// A PDR rule's result id is (session id << 3 | action index), so a match
// reaches the session's state with no index lookup in between.
//
// The F-TEID exact index and the UL/DL masked PDR tables remain lookup
// structures; this resource drives them (FteidResource's staged operations,
// ConcurrentMaskedTable's Prepare/Commit) inside its own operation.
//
// Contract (D-021):
//   insert  Reserve compiles the profiles, prepares the rules (pending,
//           invisible) and F-TEIDs, and writes the stride, which no reader
//           can reach: a free id has no rule naming it, and its previous
//           session's removal cascade has finished. Publish makes the
//           F-TEIDs admissible and commits the rules. Workers keep running.
//   erase   Publish removes the F-TEIDs and rules at once; the stride stays
//           readable and the id unusable until the removal cascade frees it
//           (a packet that matched a rule just before finishes first).
//           Workers keep running.
//   update  (the id is live) rewrites the stride IN PLACE, so it REQUIRES
//           PAUSED WORKERS: Reserve refuses it while a worker runs the
//           module, never downgrading to a racy write. A QER that keeps its
//           position and profile keeps its token buckets; an action that
//           keeps its position and action id keeps BOTH directional URR banks,
//           even across PDR direction changes. A changed profile starts full.
//           Rules and F-TEIDs are diffed: unchanged ones are not touched.
// An action id belongs to one session; a PDR key and an F-TEID to one rule.
// ATSSS access.tunnel_id is local: 0 keeps the matched action's tunnel;
// 1..max_actions selects that 1-based action's tunnel in the matched session.
// A tunnel-only action may have no PDR, but must have count=false and no QERs.
// Policies can be shared when their sessions use the same positional layout.
// Missing local actions/tunnels drop no_tunnel, never fall back to another.

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

// One QER: the token buckets and, beside them, the profile they run under
// (it outlives the state: both live and die with the stride).
struct alignas(RTE_CACHE_LINE_SIZE) SessionQer {
  alignas(bess::meter::MeterState) std::byte state[sizeof(bess::meter::MeterState)];
  std::optional<bess::meter::MeterProfile> profile;  // engaged iff state is built
  bess::meter::MeterState &meter() noexcept {
    return *std::launder(reinterpret_cast<bess::meter::MeterState *>(state));
  }
};

// Independent directional histories follow stable action_id + position,
// including while an action's current PDR direction changes.
struct SessionUrr {
  std::atomic<uint64_t> packets{0}, octets{0}, first_ns{0}, last_ns{0};
  void Add(uint64_t bytes, uint64_t now_ns) noexcept {
    constexpr auto relaxed = std::memory_order_relaxed;
    packets.store(packets.load(relaxed) + 1, relaxed);
    octets.store(octets.load(relaxed) + bytes, relaxed);
    if (first_ns.load(relaxed) == 0) first_ns.store(now_ns, relaxed);
    last_ns.store(now_ns, relaxed);
  }
};
static_assert(sizeof(SessionUrr) == 32);

// Lines one/two hold classification state and UL/DL atomic URR cells;
// line three is the tunnel, read only by the encap lane.
struct alignas(RTE_CACHE_LINE_SIZE) SessionAction {
  // 0: no action (a resumed buffered packet compares it with its own).
  std::atomic<uint32_t> action_id{0};
  uint32_t next_hop_id = 0, route_domain = 0, policy_id = 0;
  std::array<uint8_t, 2> qer{};  // per meter level: 1-based QER, 0 none
  uint8_t counter_banks = 0;  // ever provisioned for counting: bit 0 UL, bit 1 DL
  bool count = false, has_tunnel = false;
  std::array<SessionUrr, 2> urr;
  alignas(RTE_CACHE_LINE_SIZE) Tunnel tunnel;
};
static_assert(sizeof(SessionAction) == 3 * RTE_CACHE_LINE_SIZE);

// Every stride is built once, at construction; nothing in it needs a
// destructor (MeterState's is trivial; its storage is the caller's).
static_assert(std::is_trivially_destructible_v<SessionQer>);
static_assert(std::is_trivially_destructible_v<SessionAction>);

// A session as the resource takes it (the codec's decode of UpfSession).
struct SessionValue {
  struct Fteid {
    upf::datapath::FteidId id{};
    upf::datapath::FteidRecord record;
  };
  struct Action {
    uint32_t action_id = 0, next_hop_id = 0, route_domain = 0, policy_id = 0;
    std::array<uint8_t, 2> qer{};
    bool count = false;
    std::optional<Tunnel> tunnel;
  };
  struct Pdr {
    bool dl = false;
    std::vector<std::byte> mask, value;
    std::vector<bess::classifier::ConcurrentMaskedTable::KeyRange> ranges;
    int64_t priority = 0;
    uint16_t gate = 0;
    uint8_t action = 0;  // 0-based
  };
  std::vector<Fteid> fteids;
  std::vector<bess::meter::MeterProfileSpec> qers;
  std::vector<Action> actions;
  std::vector<Pdr> pdrs;
};

std::expected<upf::datapath::FteidId, std::string> DecodeFteidKey(const upf::pb::FteidKey &key);
upf::pb::FteidKey EncodeFteidKey(const upf::datapath::FteidId &id);
std::expected<Tunnel, std::string> DecodeTunnel(const upf::pb::TunnelEntry &value);
upf::pb::TunnelEntry EncodeTunnel(const Tunnel &tunnel);
std::expected<SessionValue, std::string> DecodeSession(const upf::pb::UpfSession &session);

class SessionResource final : public bess::dataplane::Resource {
 public:
  using Table = bess::classifier::ConcurrentMaskedTable;
  static constexpr uint32_t kActionBits = 3;
  static constexpr size_t kMaxActions = size_t{1} << kActionBits;

  struct Limits {
    size_t capacity = 0, max_actions = 0, max_qers = 0;
  };
  static size_t Stride(const Limits &l) noexcept {
    return l.max_qers * sizeof(SessionQer) + l.max_actions * sizeof(SessionAction);
  }
  // Admitted before construction (D-198): the whole flat array (DPDK) and
  // the control-side record per id (glibc). Per-session control growth --
  // rule keys, F-TEIDs, action-index nodes -- is admitted per transaction.
  static size_t GlibcBytes(const Limits &l) noexcept;
  static size_t Bytes(const Limits &l) noexcept { return l.capacity * Stride(l) + GlibcBytes(l); }

  SessionResource(std::string name, std::string next_hops, Limits limits, Table &ul,
                  Table &dl, upf::datapath::FteidResource &fteids,
                  std::function<bool()> worker_running);

  // -- packet path -------------------------------------------------------------
  static uint32_t SessionOf(uint32_t result) noexcept { return result >> kActionBits; }
  static uint32_t IndexOf(uint32_t result) noexcept { return result & (kMaxActions - 1); }
  SessionAction &Action(uint32_t session, uint32_t index) const noexcept {
    return *std::launder(reinterpret_cast<SessionAction *>(
        base_ + (session - 1) * stride_ + qer_bytes_ + index * sizeof(SessionAction)));
  }
  const Tunnel *TunnelAt(uint32_t session, uint32_t index) const noexcept {
    if (index >= limits_.max_actions) return nullptr;
    const SessionAction &a = Action(session, index);
    return a.action_id.load(std::memory_order_relaxed) != 0 && a.has_tunnel ? &a.tunnel : nullptr;
  }
  SessionQer &Qer(uint32_t session, uint32_t index) const noexcept {
    return *std::launder(reinterpret_cast<SessionQer *>(
        base_ + (session - 1) * stride_ + index * sizeof(SessionQer)));
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
  struct Mirror {
    enum class State : uint8_t { kFree, kLive, kRetiring };
    State state = State::kFree;
    uint8_t actions = 0, qers = 0;
    size_t bytes = 0;  // admitted glibc bytes of the vectors and index nodes
    std::vector<Rule> rules;
    std::vector<SessionValue::Fteid> fteids;
  };
  // An action-index node's glibc cost, an estimate (as FteidResource's).
  static constexpr size_t kNodeBytes = sizeof(std::pair<const uint32_t, uint32_t>) + 4 * sizeof(void *);

  Table &TableOf(bool dl) const noexcept { return dl ? dl_ : ul_; }
  size_t KeyLen(bool dl) const noexcept { return dl ? 22 : 18; }
  static std::string RuleKey(const SessionValue::Pdr &pdr);
  std::optional<Table::Prepared> PrepareErase(const Rule &rule) const;
  std::expected<std::vector<uint8_t>, std::string> Validate(const SessionValue &v) const;
  std::vector<bess::dataplane::Reference> References(uint32_t session) const;
  std::vector<bess::dataplane::Reference> References(const SessionValue &v) const;
  // Writes `v` into `session`'s stride over what `old_qers`/`old_actions`
  // it held (kept where unchanged). Infallible: Reserve built every state
  // once already.
  void Install(uint32_t session, const SessionValue &v,
               const std::vector<bess::meter::MeterProfile> &profiles,
               const std::vector<uint8_t> &directions, size_t old_qers,
               size_t old_actions) noexcept;
  void Free(uint32_t session) noexcept;  // the erase's removal step
  upf::pb::UpfSession Read(uint32_t session) const;
  void Report(uint32_t action_id, bool dl, bool restart,
              upf::pb::UrrCountCommandGetCountsResponse *out) const;

  const Limits limits_;
  const size_t stride_, qer_bytes_;
  const std::string next_hops_;
  Table &ul_, &dl_;
  upf::datapath::FteidResource &fteids_;
  const std::function<bool()> worker_running_;
  struct alignas(RTE_CACHE_LINE_SIZE) Line {
    std::byte bytes[RTE_CACHE_LINE_SIZE];
  };
  bess::utils::DpdkArray<Line> storage_;
  std::byte *base_ = nullptr;
  bess::utils::MemoryGrowth *growth_ = nullptr;

  // Guards everything below; get_counts reads beside a transaction.
  mutable std::mutex mu_;
  std::vector<Mirror> mirrors_;  // index session - 1
  std::map<uint32_t, uint32_t> actions_;  // action id -> session << 3 | index
  std::set<uint32_t> tx_sessions_, tx_actions_;  // this transaction's
  std::set<std::string> tx_rules_;
  std::atomic<size_t> live_{0}, mirror_bytes_{0};
};

}  // namespace upf::appliance

#endif  // UPF_DATAPATH_UPF_APPLIANCE_SESSIONS_H_
