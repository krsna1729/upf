// SPDX-License-Identifier: BSD-3-Clause
#include "upf_appliance_sessions.h"

#include <algorithm>
#include <cstring>
#include <format>
#include <limits>
#include <utility>

#include "dataplane/action_id.h"
#include "gate.h"
#include "utils/logging.h"

namespace upf::appliance {
namespace {
namespace dp = bess::dataplane;
namespace meter = bess::meter;
using KeyRange = bess::classifier::ConcurrentMaskedTable::KeyRange;
using bess::classifier::ConstBytes;

// The PDR key fields' widths, in key order (upf_appliance_frame.h's BuildPdrKey).
std::span<const size_t> Widths(bool dl) {
  static constexpr size_t ul[] = {4, 4, 1, 2, 2, 4, 1};
  static constexpr size_t dl_widths[] = {4, 4, 1, 2, 2, 4, 4, 1};
  return dl ? std::span<const size_t>(dl_widths) : std::span<const size_t>(ul);
}

std::expected<meter::MeterProfileSpec, std::string> DecodeQer(const upf::pb::UpfSessionQer &q) {
  switch (q.profile_case()) {
    case upf::pb::UpfSessionQer::kSrTcm:
      return meter::SrTcmSpec{q.sr_tcm().committed_rate(), q.sr_tcm().committed_burst(),
                              q.sr_tcm().excess_burst()};
    case upf::pb::UpfSessionQer::kTrTcm:
      return meter::TrTcmSpec{q.tr_tcm().committed_rate(), q.tr_tcm().committed_burst(),
                              q.tr_tcm().peak_rate(), q.tr_tcm().peak_burst()};
    case upf::pb::UpfSessionQer::kTrTcmRfc4115:
      return meter::TrTcmRfc4115Spec{
          q.tr_tcm_rfc4115().committed_rate(), q.tr_tcm_rfc4115().committed_burst(),
          q.tr_tcm_rfc4115().excess_rate(), q.tr_tcm_rfc4115().excess_burst()};
    case upf::pb::UpfSessionQer::PROFILE_NOT_SET:
      break;
  }
  return std::unexpected("QER has no profile set");
}

upf::pb::UpfSessionQer EncodeQer(const meter::MeterProfileSpec &spec) {
  upf::pb::UpfSessionQer q;
  if (const auto *sr = std::get_if<meter::SrTcmSpec>(&spec)) {
    auto *p = q.mutable_sr_tcm();
    p->set_committed_rate(sr->committed_rate);
    p->set_committed_burst(sr->committed_burst);
    p->set_excess_burst(sr->excess_burst);
  } else if (const auto *tr = std::get_if<meter::TrTcmSpec>(&spec)) {
    auto *p = q.mutable_tr_tcm();
    p->set_committed_rate(tr->committed_rate);
    p->set_committed_burst(tr->committed_burst);
    p->set_peak_rate(tr->peak_rate);
    p->set_peak_burst(tr->peak_burst);
  } else if (const auto *rfc = std::get_if<meter::TrTcmRfc4115Spec>(&spec)) {
    auto *p = q.mutable_tr_tcm_rfc4115();
    p->set_committed_rate(rfc->committed_rate);
    p->set_committed_burst(rfc->committed_burst);
    p->set_excess_rate(rfc->excess_rate);
    p->set_excess_burst(rfc->excess_burst);
  }
  return q;
}

std::expected<SessionValue::Pdr, std::string> DecodePdr(const upf::pb::UpfSessionPdr &in) {
  SessionValue::Pdr pdr;
  pdr.dl = in.downlink();
  const auto widths = Widths(pdr.dl);
  size_t len = 0;
  for (size_t w : widths) len += w;
  if (in.value().size() != len || in.mask().size() != len)
    return std::unexpected(std::format("PDR value and mask must be {} bytes", len));
  const auto *v = reinterpret_cast<const std::byte *>(in.value().data());
  const auto *m = reinterpret_cast<const std::byte *>(in.mask().data());
  pdr.value.assign(v, v + len);
  pdr.mask.assign(m, m + len);
  for (size_t i = 0; i < len; ++i)
    if ((pdr.value[i] & ~pdr.mask[i]) != std::byte{0})
      return std::unexpected("PDR value has bits outside its mask");
  std::vector<bool> ranged(widths.size(), false);
  for (const auto &r : in.ranges()) {
    const size_t f = r.field();
    if (f >= widths.size() || ranged[f]) return std::unexpected("invalid or duplicate range field");
    ranged[f] = true;
    size_t offset = 0;
    for (size_t i = 0; i < f; ++i) offset += widths[i];
    const uint64_t max = (uint64_t{1} << (8 * widths[f])) - 1;
    if (r.low() > r.high() || r.high() > max)
      return std::unexpected("range is empty or wider than its field");
    for (size_t j = 0; j < widths[f]; ++j)
      if (pdr.mask[offset + j] != std::byte{0})
        return std::unexpected("range field has a nonzero mask");
    if (r.low() == 0 && r.high() == max) continue;  // the whole field: no range
    pdr.ranges.push_back({static_cast<uint32_t>(offset), static_cast<uint32_t>(widths[f]),
                          r.low(), r.high()});
  }
  std::ranges::sort(pdr.ranges, {}, &KeyRange::offset);
  if (in.gate() > 0xffff || !bess::IsValidGateValue(in.gate()))
    return std::unexpected("invalid PDR gate");
  if (in.action() == 0 || in.action() > SessionResource::kMaxActions)
    return std::unexpected("PDR action must name an action (1-based)");
  pdr.priority = in.priority();
  pdr.gate = static_cast<uint16_t>(in.gate());
  pdr.action = static_cast<uint8_t>(in.action() - 1);
  return pdr;
}
}  // namespace

std::expected<upf::datapath::FteidId, std::string> DecodeFteidKey(const upf::pb::FteidKey &key) {
  if (key.endpoint_id() == 0 || key.teid() == 0)
    return std::unexpected("endpoint_id and teid must be nonzero");
  const size_t bytes = key.address_family() == 4 ? 4 : key.address_family() == 6 ? 16 : 0;
  if (bytes == 0 || key.local_address().size() != bytes)
    return std::unexpected("local_address length must match family 4 or 6");
  upf::datapath::FteidId id{};
  id[0] = static_cast<uint8_t>(key.endpoint_id() >> 24);
  id[1] = static_cast<uint8_t>(key.endpoint_id() >> 16);
  id[2] = static_cast<uint8_t>(key.endpoint_id() >> 8);
  id[3] = static_cast<uint8_t>(key.endpoint_id());
  id[4] = static_cast<uint8_t>(key.address_family());
  std::memcpy(id.data() + (bytes == 4 ? 17 : 5), key.local_address().data(), bytes);
  id[21] = static_cast<uint8_t>(key.teid() >> 24);
  id[22] = static_cast<uint8_t>(key.teid() >> 16);
  id[23] = static_cast<uint8_t>(key.teid() >> 8);
  id[24] = static_cast<uint8_t>(key.teid());
  return id;
}

upf::pb::FteidKey EncodeFteidKey(const upf::datapath::FteidId &id) {
  upf::pb::FteidKey key;
  key.set_endpoint_id(uint32_t{id[0]} << 24 | uint32_t{id[1]} << 16 | uint32_t{id[2]} << 8 | id[3]);
  key.set_address_family(id[4]);
  key.set_teid(uint32_t{id[21]} << 24 | uint32_t{id[22]} << 16 | uint32_t{id[23]} << 8 | id[24]);
  const size_t off = id[4] == 4 ? 17 : 5;
  key.set_local_address(reinterpret_cast<const char *>(id.data() + off), id[4] == 4 ? 4 : 16);
  return key;
}

std::expected<Tunnel, std::string> DecodeTunnel(const upf::pb::TunnelEntry &value) {
  if (value.teid() == 0) return std::unexpected("the 'teid' field is required");
  const size_t length = value.local_address().size();
  if ((length != 4 && length != 16) || value.peer_address().size() != length)
    return std::unexpected("local_address and peer_address must both be 4 or 16 bytes");
  if (value.qfi() > 63) return std::unexpected("invalid 'qfi' field");
  if (!value.qfi_present() && value.qfi() != 0)
    return std::unexpected("qfi must be zero when qfi_present is false");
  if (value.marking() > 0xffff) return std::unexpected("invalid 'marking' field");
  Tunnel tunnel{};
  tunnel.teid = value.teid();
  tunnel.family = length == 4 ? 4 : 6;
  const size_t offset = length == 4 ? 12 : 0;
  std::memcpy(tunnel.local + offset, value.local_address().data(), length);
  std::memcpy(tunnel.peer + offset, value.peer_address().data(), length);
  const auto zero = [](const uint8_t *a) { return std::all_of(a, a + 16, [](uint8_t b) { return b == 0; }); };
  if (zero(tunnel.local) || zero(tunnel.peer))
    return std::unexpected("tunnel addresses must not be unspecified");
  tunnel.transport_route_domain = value.transport_route_domain();
  tunnel.qfi = static_cast<uint8_t>(value.qfi());
  tunnel.has_qfi = value.qfi_present();
  tunnel.marking = static_cast<uint16_t>(value.marking());
  return tunnel;
}

upf::pb::TunnelEntry EncodeTunnel(const Tunnel &tunnel) {
  upf::pb::TunnelEntry value;
  value.set_teid(tunnel.teid);
  const size_t offset = tunnel.family == 4 ? 12 : 0, length = tunnel.family == 4 ? 4 : 16;
  value.set_local_address(reinterpret_cast<const char *>(tunnel.local + offset), length);
  value.set_peer_address(reinterpret_cast<const char *>(tunnel.peer + offset), length);
  value.set_qfi(tunnel.qfi);
  value.set_qfi_present(tunnel.has_qfi);
  value.set_marking(tunnel.marking);
  value.set_transport_route_domain(tunnel.transport_route_domain);
  return value;
}

std::expected<SessionValue, std::string> DecodeSession(const upf::pb::UpfSession &in) {
  SessionValue v;
  for (const auto &f : in.fteids()) {
    auto id = DecodeFteidKey(f.key());
    if (!id) return std::unexpected("F-TEID: " + id.error());
    if (f.entry().direction() > 1) return std::unexpected("F-TEID direction must be 0 (UL) or 1 (DL)");
    v.fteids.push_back({*id, {static_cast<uint8_t>(f.entry().direction()), f.entry().context_id()}});
  }
  for (const auto &q : in.qers()) {
    auto spec = DecodeQer(q);
    if (!spec) return std::unexpected(spec.error());
    v.qers.push_back(*spec);
  }
  for (const auto &a : in.actions()) {
    if (a.pdr_qer() > 255 || a.session_qer() > 255) return std::unexpected("QER position out of range");
    SessionValue::Action out{.action_id = a.action_id(), .next_hop_id = a.next_hop_id(),
                             .route_domain = a.route_domain(), .policy_id = a.steering_policy_id(),
                             .qer = {static_cast<uint8_t>(a.pdr_qer()), static_cast<uint8_t>(a.session_qer())},
                             .count = a.count()};
    if (a.has_tunnel()) {
      auto t = DecodeTunnel(a.tunnel());
      if (!t) return std::unexpected("tunnel: " + t.error());
      out.tunnel = *t;
    }
    v.actions.push_back(std::move(out));
  }
  for (const auto &p : in.pdrs()) {
    auto pdr = DecodePdr(p);
    if (!pdr) return std::unexpected(pdr.error());
    v.pdrs.push_back(std::move(*pdr));
  }
  return v;
}

// -- the resource ---------------------------------------------------------------

size_t SessionResource::GlibcBytes(const Limits &l) noexcept { return l.capacity * sizeof(Mirror); }

SessionResource::SessionResource(std::string name, std::string next_hops, Limits limits,
                                 Table &ul, Table &dl, upf::datapath::FteidResource &fteids,
                                 std::function<bool()> worker_running)
    : Resource(std::move(name), {next_hops}),
      limits_(limits),
      stride_(Stride(limits)),
      qer_bytes_(limits.max_qers * sizeof(SessionQer)),
      next_hops_(std::move(next_hops)),
      ul_(ul),
      dl_(dl),
      fteids_(fteids),
      worker_running_(std::move(worker_running)),
      storage_(limits.capacity * Stride(limits) / sizeof(Line)),
      mirrors_(limits.capacity) {
  static_assert(sizeof(SessionQer) % sizeof(Line) == 0 && sizeof(SessionAction) % sizeof(Line) == 0);
  CHECK(limits.max_actions >= 1 && limits.max_actions <= kMaxActions && limits.max_qers <= 255);
  CHECK(limits.capacity <= (std::numeric_limits<uint32_t>::max() >> kActionBits));
  base_ = storage_.size() ? reinterpret_cast<std::byte *>(storage_.data()) : nullptr;
  for (uint32_t s = 1; s <= limits.capacity; ++s) {
    for (uint32_t q = 0; q < limits.max_qers; ++q) new (&Qer(s, q)) SessionQer();
    for (uint32_t a = 0; a < limits.max_actions; ++a) new (&Action(s, a)) SessionAction();
  }
}

size_t SessionResource::bytes() const noexcept {
  return limits_.capacity * stride_ + GlibcBytes(limits_) + mirror_bytes_.load(std::memory_order_relaxed);
}

std::string SessionResource::RuleKey(const SessionValue::Pdr &pdr) {
  std::string key(reinterpret_cast<const char *>(pdr.mask.data()), pdr.mask.size());
  key.append(reinterpret_cast<const char *>(pdr.value.data()), pdr.value.size());
  key.append(reinterpret_cast<const char *>(pdr.ranges.data()), pdr.ranges.size() * sizeof(KeyRange));
  return key;
}

std::optional<SessionResource::Table::Prepared> SessionResource::PrepareErase(const Rule &rule) const {
  const size_t len = KeyLen(rule.dl);
  std::vector<KeyRange> ranges((rule.key.size() - 2 * len) / sizeof(KeyRange));
  if (!ranges.empty()) std::memcpy(ranges.data(), rule.key.data() + 2 * len, ranges.size() * sizeof(KeyRange));
  const auto *bytes = reinterpret_cast<const std::byte *>(rule.key.data());
  return TableOf(rule.dl).PrepareErase(ConstBytes(bytes, len), ConstBytes(bytes + len, len), ranges);
}

std::expected<std::vector<uint8_t>, std::string> SessionResource::Validate(const SessionValue &v) const {
  if (v.actions.size() > limits_.max_actions)
    return std::unexpected(std::format("{} actions exceed max_actions {}", v.actions.size(), limits_.max_actions));
  if (v.qers.size() > limits_.max_qers)
    return std::unexpected(std::format("{} QERs exceed max_qers {}", v.qers.size(), limits_.max_qers));
  for (size_t q = 0; q < v.qers.size(); ++q)
    if (auto ok = meter::ValidateMeterProfileSpec(v.qers[q]); !ok)
      return std::unexpected(std::format("QER {}: {}", q + 1, meter::MeterErrorName(ok.error())));
  std::set<uint32_t> ids;
  for (const auto &a : v.actions) {
    if (a.action_id == 0) return std::unexpected("action id 0 names no action");
    if (!ids.insert(a.action_id).second) return std::unexpected(std::format("action id {} twice", a.action_id));
    for (uint8_t q : a.qer)
      if (q > v.qers.size()) return std::unexpected(std::format("action {} names QER {} of {}", a.action_id, q, v.qers.size()));
  }
  constexpr uint8_t kUnused = 2;
  std::vector<uint8_t> directions(v.actions.size(), kUnused);
  std::set<std::string> keys;
  for (const auto &p : v.pdrs) {
    const size_t len = KeyLen(p.dl);
    if (p.mask.size() != len || p.value.size() != len) return std::unexpected("PDR key length differs from its table");
    if (p.action >= v.actions.size()) return std::unexpected("PDR names a missing action");
    if (!bess::IsValidGateValue(p.gate)) return std::unexpected("invalid PDR gate");
    if (!keys.insert(std::string(p.dl ? "d" : "u") + RuleKey(p)).second)
      return std::unexpected("two PDRs of the session have one key");
    uint8_t &d = directions[p.action];
    if (d != kUnused && d != uint8_t{p.dl})
      return std::unexpected(std::format("action {} is used by UL and DL PDRs: its URR bank must be one",
                                         v.actions[p.action].action_id));
    d = p.dl;
  }
  for (size_t i = 0; i < directions.size(); ++i) {
    if (directions[i] != kUnused) continue;
    const auto &a = v.actions[i];
    if (!a.tunnel || a.count || a.qer[0] != 0 || a.qer[1] != 0)
      return std::unexpected(std::format(
          "action {} has no PDR: it must be tunnel-only (tunnel, no count, no QERs)", a.action_id));
    directions[i] = 1;
  }
  std::set<upf::datapath::FteidId> fteids;
  for (const auto &f : v.fteids) {
    if (f.record.direction > 1 || f.record.context_id == 0)
      return std::unexpected("F-TEID needs direction 0/1 and a nonzero context");
    if (!fteids.insert(f.id).second) return std::unexpected("one F-TEID twice");
  }
  return directions;
}

std::vector<dp::Reference> SessionResource::References(uint32_t session) const {
  std::vector<dp::Reference> refs;
  for (uint32_t i = 0; i < mirrors_[session - 1].actions; ++i)
    if (const uint32_t hop = Action(session, i).next_hop_id)
      refs.push_back({next_hops_, dp::EncodeKey(dp::ActionId(hop))});
  return refs;
}

std::vector<dp::Reference> SessionResource::References(const SessionValue &v) const {
  std::vector<dp::Reference> refs;
  for (const auto &a : v.actions)
    if (a.next_hop_id) refs.push_back({next_hops_, dp::EncodeKey(dp::ActionId(a.next_hop_id))});
  return refs;
}

bool SessionResource::Contains(const dp::ResourceKey &key) const {
  uint32_t session = 0;
  if (!dp::DecodeKey(key, &session) || session == 0 || session > limits_.capacity) return false;
  std::lock_guard lock(mu_);
  return mirrors_[session - 1].state == Mirror::State::kLive;
}

std::vector<dp::Reference> SessionResource::ReferencesOf(const dp::ResourceKey &key) const {
  uint32_t session = 0;
  if (!dp::DecodeKey(key, &session) || session == 0 || session > limits_.capacity) return {};
  std::lock_guard lock(mu_);
  if (mirrors_[session - 1].state != Mirror::State::kLive) return {};
  return References(session);
}

void SessionResource::VisitReferences(const std::function<void(const dp::Reference &)> &visit) const {
  std::lock_guard lock(mu_);
  for (uint32_t s = 1; s <= limits_.capacity; ++s)
    if (mirrors_[s - 1].state == Mirror::State::kLive)
      for (const auto &r : References(s)) visit(r);
}

void SessionResource::Install(uint32_t session, const SessionValue &v,
                              const std::vector<meter::MeterProfile> &profiles,
                              const std::vector<uint8_t> &directions, size_t old_qers,
                              size_t old_actions) noexcept {
  for (size_t q = 0; q < v.qers.size(); ++q) {
    SessionQer &slot = Qer(session, q);
    if (q < old_qers && slot.profile->spec() == v.qers[q]) continue;  // the bucket stays
    if (q < old_qers) slot.meter().~MeterState();
    slot.profile.emplace(profiles[q]);
    CHECK(meter::MeterState::ConstructAt(slot.state, *slot.profile, meter::MeterSharing::kShared))
        << "a profile Reserve built a state for failed now";
  }
  for (size_t q = v.qers.size(); q < old_qers; ++q) {
    Qer(session, q).meter().~MeterState();
    Qer(session, q).profile.reset();
  }
  for (size_t i = 0; i < v.actions.size(); ++i) {
    SessionAction &a = Action(session, i);
    const auto &in = v.actions[i];
    if (i >= old_actions || a.action_id.load(std::memory_order_relaxed) != in.action_id) {
      a.counter_banks = 0;
      for (auto &bank : a.urr)
        for (auto *cell : {&bank.packets, &bank.octets, &bank.first_ns, &bank.last_ns})
          cell->store(0, std::memory_order_relaxed);
    }
    a.next_hop_id = in.next_hop_id;
    a.route_domain = in.route_domain;
    a.policy_id = in.policy_id;
    a.qer = in.qer;
    if (in.count) a.counter_banks |= uint8_t{1} << directions[i];
    a.count = in.count;
    a.has_tunnel = in.tunnel.has_value();
    a.tunnel = in.tunnel.value_or(Tunnel{});
    a.action_id.store(in.action_id, std::memory_order_relaxed);
  }
  for (size_t i = v.actions.size(); i < old_actions; ++i)
    Action(session, i).action_id.store(0, std::memory_order_relaxed);
}

void SessionResource::Free(uint32_t session) noexcept {
  std::lock_guard lock(mu_);
  Mirror &m = mirrors_[session - 1];
  CHECK(m.state == Mirror::State::kRetiring);
  for (uint32_t q = 0; q < m.qers; ++q) {
    Qer(session, q).meter().~MeterState();
    Qer(session, q).profile.reset();
  }
  // A buffered packet of the erased session resumes against id 0: dropped.
  for (uint32_t i = 0; i < m.actions; ++i) Action(session, i).action_id.store(0, std::memory_order_relaxed);
  m.actions = m.qers = 0;
  m.state = Mirror::State::kFree;
}

// One session's change. Everything fallible happened in Reserve; Publish
// stores, commits and swaps prebuilt state without allocating.
class SessionResource::Staged final : public dp::StagedOp {
 public:
  enum class Kind : uint8_t { kInsert, kUpdate, kErase };
  Staged(SessionResource &owner, uint32_t session, Kind kind)
      : owner_(owner), session_(session), kind_(kind) {}
  ~Staged() noexcept override {
    Abort();
    // Published: the replaced mirror's bytes; aborted: the new mirror's.
    if (bytes_ != 0 && owner_.growth_ != nullptr) owner_.growth_->Shrink(bytes_, bytes_);
  }

  void Publish(dp::Retirer &retirer) noexcept override {
    std::lock_guard lock(owner_.mu_);
    Mirror &m = owner_.mirrors_[session_ - 1];
    for (auto &f : fteids_) f->Publish(retirer);
    // The session's old action ids leave the index, its new ones enter it.
    for (uint32_t i = 0; i < m.actions; ++i) {
      auto node = owner_.actions_.extract(owner_.Action(session_, i).action_id.load(std::memory_order_relaxed));
      if (!node.empty()) removed_.insert(std::move(node));
    }
    while (!added_.empty()) owner_.actions_.insert(added_.extract(added_.begin()));
    switch (kind_) {
      case Kind::kInsert:
        m.state = Mirror::State::kLive;
        owner_.live_.fetch_add(1, std::memory_order_relaxed);
        break;
      case Kind::kUpdate:  // workers are paused (Reserve refused otherwise)
        owner_.Install(session_, value_, profiles_, directions_, m.qers, m.actions);
        break;
      case Kind::kErase:
        m.state = Mirror::State::kRetiring;
        owner_.live_.fetch_sub(1, std::memory_order_relaxed);
        break;
    }
    if (kind_ != Kind::kErase) {
      m.actions = actions_count_;
      m.qers = qers_count_;
    }
    for (auto &c : rules_) {
      if (const Table::RuleId freed = c.table->Commit(c.prepared))
        retirer.RemoveLater([table = c.table, freed](dp::Retirer &) { table->Recycle(freed); });
    }
    published_ = true;
    std::swap(m.rules, rules_mirror_);
    std::swap(m.fteids, fteids_mirror_);
    std::swap(m.bytes, bytes_);
    owner_.mirror_bytes_.fetch_add(m.bytes, std::memory_order_relaxed);
    owner_.mirror_bytes_.fetch_sub(bytes_, std::memory_order_relaxed);
    if (kind_ == Kind::kErase)
      retirer.RemoveLater([&owner = owner_, session = session_](dp::Retirer &) { owner.Free(session); });
  }

  void Abort() noexcept override {
    if (published_ || aborted_) return;
    aborted_ = true;
    for (auto &c : rules_) c.table->Cancel(c.prepared);
    for (auto &f : fteids_) f->Abort();
    // Reserve wrote an insert's stride; nothing reached it, but a held
    // packet must not match its action ids.
    if (kind_ == Kind::kInsert)
      for (uint32_t i = 0; i < actions_count_; ++i)
        owner_.Action(session_, i).action_id.store(0, std::memory_order_relaxed);
  }

  struct RuleChange {
    Table *table;
    Table::Prepared prepared;
  };
  std::vector<RuleChange> rules_;
  std::vector<std::unique_ptr<dp::StagedOp>> fteids_;
  std::map<uint32_t, uint32_t> added_, removed_;
  SessionValue value_;
  std::vector<meter::MeterProfile> profiles_;
  std::vector<uint8_t> directions_;
  std::vector<Rule> rules_mirror_;
  std::vector<SessionValue::Fteid> fteids_mirror_;
  size_t bytes_ = 0;
  uint8_t actions_count_ = 0, qers_count_ = 0;

 private:
  SessionResource &owner_;
  const uint32_t session_;
  const Kind kind_;
  bool published_ = false, aborted_ = false;
};

std::expected<dp::Resource::Reservation, std::string> SessionResource::Reserve(const dp::Op &op) {
  uint32_t session = 0;
  if (!dp::DecodeKey(op.key, &session) || session == 0 || session > limits_.capacity)
    return std::unexpected(std::format("session id must be 1..{}", limits_.capacity));
  std::lock_guard lock(mu_);
  if (tx_sessions_.contains(session)) return std::unexpected("session changed twice in one transaction");
  Mirror &m = mirrors_[session - 1];
  if (m.state == Mirror::State::kRetiring)
    return std::unexpected("session id is still retiring (erased less than a grace period ago)");
  const bool live = m.state == Mirror::State::kLive;
  Reservation r;
  r.existed = live;
  if (live) r.previous_references = References(session);
  const auto add_fteid = [&](Staged &staged, dp::Op fop) -> std::expected<void, std::string> {
    auto res = fteids_.Reserve(fop);
    if (!res) return std::unexpected("F-TEID: " + res.error());
    r.footprint.retires += res->footprint.retires;
    r.footprint.removals += res->footprint.removals;
    r.footprint.callbacks += res->footprint.callbacks;
    staged.fteids_.push_back(std::move(res->staged));
    return {};
  };

  if (op.kind == dp::OpKind::kErase) {
    if (!live) return std::unexpected("not found");
    auto staged = std::make_unique<Staged>(*this, session, Staged::Kind::kErase);
    for (const Rule &rule : m.rules) {
      auto prepared = PrepareErase(rule);
      CHECK(prepared) << "a live session's rule is missing from its table";
      staged->rules_.push_back({&TableOf(rule.dl), std::move(*prepared)});
    }
    for (const auto &f : m.fteids)
      if (auto ok = add_fteid(*staged, dp::Op::Erase({}, dp::EncodeKey(f.id))); !ok)
        return std::unexpected(ok.error());
    r.footprint.removals += static_cast<uint32_t>(m.rules.size()) + 1;
    tx_sessions_.insert(session);
    r.staged = std::move(staged);
    return r;
  }

  const auto *v = std::any_cast<SessionValue>(&op.value);
  if (v == nullptr) return std::unexpected("wrong value type (want SessionValue)");
  auto directions = Validate(*v);
  if (!directions) return std::unexpected(directions.error());
  if (live && worker_running_())
    return std::unexpected(
        "updating a live session rewrites its co-located state in place: pause the workers first");
  std::vector<meter::MeterProfile> profiles;
  for (size_t q = 0; q < v->qers.size(); ++q) {
    auto profile = meter::MeterProfile::Create(v->qers[q]);
    if (!profile) return std::unexpected(std::format("QER {}: {}", q + 1, meter::MeterErrorName(profile.error())));
    // Build one state now, so Install's in-place build cannot fail.
    alignas(meter::MeterState) std::byte probe[sizeof(meter::MeterState)];
    auto built = meter::MeterState::ConstructAt(probe, *profile, meter::MeterSharing::kShared);
    if (!built) return std::unexpected(std::format("QER {}: {}", q + 1, meter::MeterErrorName(built.error())));
    (*built)->~MeterState();
    profiles.push_back(std::move(*profile));
  }
  for (const auto &a : v->actions) {
    const auto it = actions_.find(a.action_id);
    if ((it != actions_.end() && SessionOf(it->second) != session) || tx_actions_.contains(a.action_id))
      return std::unexpected(std::format("action id {} belongs to another session", a.action_id));
  }
  std::vector<Rule> rules;
  for (const auto &p : v->pdrs) {
    Rule rule{p.dl, RuleKey(p)};
    const auto found = TableOf(p.dl).FindRule(p.mask, p.value, p.ranges);
    if ((found && SessionOf(found->result_id) != session) ||
        tx_rules_.contains((p.dl ? "d" : "u") + rule.key))
      return std::unexpected("a PDR key belongs to another session");
    rules.push_back(std::move(rule));
  }

  auto staged = std::make_unique<Staged>(*this, session, live ? Staged::Kind::kUpdate : Staged::Kind::kInsert);
  // F-TEIDs: unchanged ones untouched, gone ones erased, new ones inserted.
  for (const auto &old : m.fteids) {
    const auto it = std::ranges::find(v->fteids, old.id, &SessionValue::Fteid::id);
    if (it == v->fteids.end()) {
      if (auto ok = add_fteid(*staged, dp::Op::Erase({}, dp::EncodeKey(old.id))); !ok)
        return std::unexpected(ok.error());
    } else if (it->record.direction != old.record.direction ||
               it->record.context_id != old.record.context_id) {
      return std::unexpected("an F-TEID keeps its direction and context; erase the session to change them");
    }
  }
  for (const auto &f : v->fteids) {
    if (std::ranges::find(m.fteids, f.id, &SessionValue::Fteid::id) != m.fteids.end()) continue;
    // A live F-TEID outside this session's set is another session's (the
    // index would answer an identical insert as a no-op, sharing it).
    if (fteids_.Contains(dp::EncodeKey(f.id))) return std::unexpected("an F-TEID belongs to another session");
    if (auto ok = add_fteid(*staged, dp::Op::Upsert({}, dp::EncodeKey(f.id), std::any(f.record))); !ok)
      return std::unexpected(ok.error());
  }
  // Rules: gone ones erased; every one upserted (a replacement keeps no
  // stale result). Distinct keys: Validate and the ownership check above.
  for (const Rule &old : m.rules) {
    if (std::ranges::any_of(rules, [&](const Rule &n) { return n.dl == old.dl && n.key == old.key; })) continue;
    auto prepared = PrepareErase(old);
    CHECK(prepared) << "a live session's rule is missing from its table";
    staged->rules_.push_back({&TableOf(old.dl), std::move(*prepared)});
    ++r.footprint.removals;
  }
  for (const auto &p : v->pdrs) {
    const uint32_t result = session << kActionBits | p.action;
    auto prepared = TableOf(p.dl).PrepareUpsert(p.mask, p.value, p.priority, p.gate, result, p.ranges);
    if (!prepared) {
      using R = Table::UpsertResult;
      const R e = prepared.error();
      return std::unexpected(e == R::kTooManyTuples ? "too many distinct PDR masks"
                             : e == R::kFull        ? "PDR table is full"
                             : e == R::kBadRange    ? "a PDR range is not canonical"
                             : e == R::kReservedResult ? "PDR gate is reserved"
                                                    : "PDR key is not canonical");
    }
    if (prepared->old != 0) ++r.footprint.removals;
    staged->rules_.push_back({&TableOf(p.dl), std::move(*prepared)});
  }
  for (size_t i = 0; i < v->actions.size(); ++i)
    staged->added_.emplace(v->actions[i].action_id, session << kActionBits | static_cast<uint32_t>(i));
  staged->rules_mirror_ = rules;
  staged->fteids_mirror_ = v->fteids;
  size_t bytes = staged->rules_mirror_.capacity() * sizeof(Rule) +
                 staged->fteids_mirror_.capacity() * sizeof(SessionValue::Fteid) +
                 v->actions.size() * kNodeBytes;
  for (const Rule &rule : staged->rules_mirror_) bytes += rule.key.capacity() + 1;
  if (growth_ != nullptr) growth_->Grow(bytes, bytes);
  staged->bytes_ = bytes;
  if (!live) {
    // Unreachable until Publish commits the rules: write it now.
    Install(session, *v, profiles, *directions, 0, 0);
  } else {
    staged->value_ = *v;
    staged->profiles_ = std::move(profiles);
    staged->directions_ = std::move(*directions);
  }
  staged->actions_count_ = static_cast<uint8_t>(v->actions.size());
  staged->qers_count_ = static_cast<uint8_t>(v->qers.size());
  r.references = References(*v);
  tx_sessions_.insert(session);
  for (const auto &a : v->actions) tx_actions_.insert(a.action_id);
  for (const auto &p : v->pdrs) tx_rules_.insert((p.dl ? "d" : "u") + RuleKey(p));
  r.staged = std::move(staged);
  return r;
}

void SessionResource::EndTransaction() noexcept {
  std::lock_guard lock(mu_);
  tx_sessions_.clear();
  tx_actions_.clear();
  tx_rules_.clear();
}

upf::pb::UpfSession SessionResource::Read(uint32_t session) const {
  const Mirror &m = mirrors_[session - 1];
  upf::pb::UpfSession out;
  for (const auto &f : m.fteids) {
    auto *o = out.add_fteids();
    *o->mutable_key() = EncodeFteidKey(f.id);
    o->mutable_entry()->set_direction(f.record.direction);
    o->mutable_entry()->set_context_id(f.record.context_id);
  }
  for (uint32_t q = 0; q < m.qers; ++q) *out.add_qers() = EncodeQer(Qer(session, q).profile->spec());
  for (uint32_t i = 0; i < m.actions; ++i) {
    const SessionAction &a = Action(session, i);
    auto *o = out.add_actions();
    o->set_action_id(a.action_id.load(std::memory_order_relaxed));
    o->set_next_hop_id(a.next_hop_id);
    o->set_route_domain(a.route_domain);
    o->set_steering_policy_id(a.policy_id);
    o->set_pdr_qer(a.qer[0]);
    o->set_session_qer(a.qer[1]);
    o->set_count(a.count);
    if (a.has_tunnel) *o->mutable_tunnel() = EncodeTunnel(a.tunnel);
  }
  for (const Rule &rule : m.rules) {
    const size_t len = KeyLen(rule.dl);
    std::vector<KeyRange> ranges((rule.key.size() - 2 * len) / sizeof(KeyRange));
    if (!ranges.empty()) std::memcpy(ranges.data(), rule.key.data() + 2 * len, ranges.size() * sizeof(KeyRange));
    const auto *bytes = reinterpret_cast<const std::byte *>(rule.key.data());
    const auto found = TableOf(rule.dl).FindRule(ConstBytes(bytes, len), ConstBytes(bytes + len, len), ranges);
    CHECK(found) << "a live session's rule is missing from its table";
    auto *o = out.add_pdrs();
    o->set_downlink(rule.dl);
    o->set_mask(rule.key.data(), len);
    o->set_value(rule.key.data() + len, len);
    for (const KeyRange &kr : ranges) {
      auto *pr = o->add_ranges();
      size_t offset = 0, field = 0;
      for (const auto widths = Widths(rule.dl); offset < kr.offset; offset += widths[field++]) {}
      pr->set_field(field);
      pr->set_low(kr.low);
      pr->set_high(kr.high);
    }
    o->set_priority(found->priority);
    o->set_gate(found->gate);
    o->set_action(IndexOf(found->result_id) + 1);
  }
  return out;
}

void SessionResource::ForEachLive(const std::function<void(uint32_t, const upf::pb::UpfSession &)> &visit) const {
  std::lock_guard lock(mu_);
  for (uint32_t s = 1; s <= limits_.capacity; ++s)
    if (mirrors_[s - 1].state == Mirror::State::kLive) visit(s, Read(s));
}

void SessionResource::Report(uint32_t action_id, bool dl, bool restart,
                             upf::pb::UrrCountCommandGetCountsResponse *out) const {
  auto *count = out->add_counts();
  count->set_action_id(action_id);
  const auto it = actions_.find(action_id);
  if (it == actions_.end()) return;
  SessionAction &a = Action(SessionOf(it->second), IndexOf(it->second));
  if (!(a.counter_banks & (uint8_t{1} << uint8_t{dl}))) return;
  SessionUrr &bank = a.urr[dl];
  count->set_packets(bank.packets.load(std::memory_order_relaxed));
  count->set_octets(bank.octets.load(std::memory_order_relaxed));
  count->set_first_packet_ns(restart ? bank.first_ns.exchange(0, std::memory_order_relaxed)
                                     : bank.first_ns.load(std::memory_order_relaxed));
  count->set_last_packet_ns(bank.last_ns.load(std::memory_order_relaxed));
}

void SessionResource::Counts(bool dl, std::span<const uint32_t> ids, bool restart,
                             upf::pb::UrrCountCommandGetCountsResponse *out) const {
  std::lock_guard lock(mu_);
  if (!ids.empty()) {
    for (uint32_t id : ids) Report(id, dl, restart, out);
    return;
  }
  for (const auto &[id, at] : actions_) {
    const SessionAction &a = Action(SessionOf(at), IndexOf(at));
    if (a.counter_banks & (uint8_t{1} << uint8_t{dl})) Report(id, dl, restart, out);
  }
}

}  // namespace upf::appliance
