// SPDX-License-Identifier: BSD-3-Clause
#include "upf_appliance_sessions.h"

#include <algorithm>
#include <cstring>
#include <format>
#include <limits>
#include <utility>

#include "dataplane/action_id.h"
#include "gate.h"
#include "fteid_codec.h"
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

constexpr uint16_t SlotRef(size_t slot, bool shared) {
  return static_cast<uint16_t>((slot + 1) | (shared ? ActionConfig::kSharedMeter : 0));
}
constexpr size_t SlotOf(uint32_t ref) { return (ref & ~uint32_t{ActionConfig::kSharedMeter}) - 1; }
constexpr bool SharedRef(uint32_t ref) { return ref & ActionConfig::kSharedMeter; }

// The lowest slot below `limit` in neither bitmap.
size_t FreeSlot(uint32_t a, uint32_t b, size_t limit) {
  const uint32_t used = a | b;
  for (size_t k = 0; k < limit; ++k)
    if (!(used >> k & 1)) return k;
  LOG(FATAL) << "no free slot: two versions use at most half each";
  return 0;
}

std::expected<SessionValue::Qer, std::string> DecodeQer(const upf::pb::UpfSessionQer &q) {
  SessionValue::Qer out{.qer_id = q.qer_id()};
  if (out.qer_id == 0) return std::unexpected("QER needs a nonzero qer_id");
  switch (q.profile_case()) {
    case upf::pb::UpfSessionQer::kSrTcm:
      out.spec = meter::SrTcmSpec{q.sr_tcm().committed_rate(), q.sr_tcm().committed_burst(),
                                  q.sr_tcm().excess_burst()};
      return out;
    case upf::pb::UpfSessionQer::kTrTcm:
      out.spec = meter::TrTcmSpec{q.tr_tcm().committed_rate(), q.tr_tcm().committed_burst(),
                                  q.tr_tcm().peak_rate(), q.tr_tcm().peak_burst()};
      return out;
    case upf::pb::UpfSessionQer::kTrTcmRfc4115:
      out.spec = meter::TrTcmRfc4115Spec{
          q.tr_tcm_rfc4115().committed_rate(), q.tr_tcm_rfc4115().committed_burst(),
          q.tr_tcm_rfc4115().excess_rate(), q.tr_tcm_rfc4115().excess_burst()};
      return out;
    case upf::pb::UpfSessionQer::kSharedMeterId:
      if (q.shared_meter_id() == 0) return std::unexpected("shared_meter_id 0 names no meter");
      out.shared = q.shared_meter_id();
      return out;
    case upf::pb::UpfSessionQer::PROFILE_NOT_SET:
      break;
  }
  return std::unexpected("QER has neither a profile nor a shared meter");
}

void EncodeSpec(const meter::MeterProfileSpec &spec, upf::pb::UpfSessionQer *q) {
  if (const auto *sr = std::get_if<meter::SrTcmSpec>(&spec)) {
    auto *p = q->mutable_sr_tcm();
    p->set_committed_rate(sr->committed_rate);
    p->set_committed_burst(sr->committed_burst);
    p->set_excess_burst(sr->excess_burst);
  } else if (const auto *tr = std::get_if<meter::TrTcmSpec>(&spec)) {
    auto *p = q->mutable_tr_tcm();
    p->set_committed_rate(tr->committed_rate);
    p->set_committed_burst(tr->committed_burst);
    p->set_peak_rate(tr->peak_rate);
    p->set_peak_burst(tr->peak_burst);
  } else if (const auto *rfc = std::get_if<meter::TrTcmRfc4115Spec>(&spec)) {
    auto *p = q->mutable_tr_tcm_rfc4115();
    p->set_committed_rate(rfc->committed_rate);
    p->set_committed_burst(rfc->committed_burst);
    p->set_excess_rate(rfc->excess_rate);
    p->set_excess_burst(rfc->excess_burst);
  }
}

std::array<uint64_t, 5> KeyOf(const meter::MeterProfileSpec &spec) {
  return std::visit(
      [&](const auto &s) -> std::array<uint64_t, 5> {
        using S = std::decay_t<decltype(s)>;
        if constexpr (std::is_same_v<S, meter::SrTcmSpec>)
          return {spec.index(), s.committed_rate, s.committed_burst, s.excess_burst, 0};
        else if constexpr (std::is_same_v<S, meter::TrTcmSpec>)
          return {spec.index(), s.committed_rate, s.committed_burst, s.peak_rate, s.peak_burst};
        else
          return {spec.index(), s.committed_rate, s.committed_burst, s.excess_rate, s.excess_burst};
      },
      spec);
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
  if (in.action() > SessionResource::kMaxActions)
    return std::unexpected("PDR action names no action (1-based position)");
  if (in.action() == 0 && in.gate() != DROP_GATE)
    return std::unexpected("a PDR without an action must take the drop gate");
  pdr.priority = in.priority();
  pdr.gate = static_cast<uint16_t>(in.gate());
  pdr.action = in.action() ? static_cast<uint8_t>(in.action() - 1) : SessionValue::kNoAction;
  return pdr;
}
}  // namespace

Tunnel ActionConfig::tunnel() const noexcept {
  Tunnel t;
  t.teid = teid;
  t.family = qfi & kIpv6 ? 6 : 4;
  std::memcpy(t.local, local, 16);
  std::memcpy(t.peer, peer, 16);
  t.transport_route_domain = transport_route_domain;
  t.qfi = qfi & kQfi;
  t.has_qfi = qfi & kHasQfi;
  t.marking = marking;
  return t;
}

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
    auto record = upf::datapath::DecodeFteidEntry(f.entry());
    if (!record) return std::unexpected("F-TEID: " + record.error());
    v.fteids.push_back({*id, std::move(*record)});
  }
  for (const auto &q : in.qers()) {
    auto qer = DecodeQer(q);
    if (!qer) return std::unexpected(qer.error());
    v.qers.push_back(std::move(*qer));
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

SessionResource::SessionResource(std::string name, std::string next_hops, std::string meters,
                                 Limits limits, Table &ul, Table &dl,
                                 upf::datapath::FteidResource &fteids, bess::rcu::RcuDomain &domain)
    : Resource(std::move(name), {next_hops, meters}),
      limits_(limits),
      stride_(Stride(limits)),
      cells_at_(2 * limits.max_actions * sizeof(ActionConfig)),
      meters_at_(cells_at_ + 2 * limits.max_actions * sizeof(SessionCells)),
      next_hops_(std::move(next_hops)),
      meters_(std::move(meters)),
      ul_(ul),
      dl_(dl),
      fteids_(fteids),
      domain_(domain),
      storage_(limits.capacity * Stride(limits) / sizeof(Line)),
      active_(limits.capacity),
      mirrors_(limits.capacity) {
  CHECK(limits.max_actions >= 1 && limits.max_actions <= kMaxActions && limits.max_qers <= kMaxQers);
  CHECK(limits.capacity <= kMaxCapacity);
  base_ = storage_.size() ? reinterpret_cast<std::byte *>(storage_.data()) : nullptr;
  for (uint32_t s = 1; s <= limits.capacity; ++s) {
    active_[s - 1].store(kGone, std::memory_order_relaxed);
    for (uint8_t v = 0; v < 2; ++v)
      for (uint8_t i = 0; i < limits.max_actions; ++i)
        new (const_cast<ActionConfig *>(&Config(s, v, i))) ActionConfig();
    for (uint8_t c = 0; c < 2 * limits.max_actions; ++c) new (&Cells(s, c)) SessionCells();
  }
}

SessionResource::~SessionResource() = default;

size_t SessionResource::bytes() const noexcept {
  return limits_.capacity * (stride_ + sizeof(std::atomic<uint8_t>)) + GlibcBytes(limits_) +
         mirror_bytes_.load(std::memory_order_relaxed);
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
  std::set<uint32_t> qer_ids;
  for (size_t q = 0; q < v.qers.size(); ++q) {
    if (!qer_ids.insert(v.qers[q].qer_id).second)
      return std::unexpected(std::format("QER id {} twice", v.qers[q].qer_id));
    if (v.qers[q].spec)
      if (auto ok = meter::ValidateMeterProfileSpec(*v.qers[q].spec); !ok)
        return std::unexpected(std::format("QER {}: {}", q + 1, meter::MeterErrorName(ok.error())));
  }
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
    if (!bess::IsValidGateValue(p.gate)) return std::unexpected("invalid PDR gate");
    if (!keys.insert(std::string(p.dl ? "d" : "u") + RuleKey(p)).second)
      return std::unexpected("two PDRs of the session have one key");
    if (p.action == SessionValue::kNoAction) {
      if (p.gate != DROP_GATE) return std::unexpected("a PDR without an action must take the drop gate");
      continue;
    }
    if (p.action >= v.actions.size()) return std::unexpected("PDR names a missing action");
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
  const Mirror &m = mirrors_[session - 1];
  std::vector<dp::Reference> refs;
  for (uint8_t i = 0; i < m.actions; ++i)
    if (const uint32_t hop = Config(session, m.active, i).next_hop_id)
      refs.push_back({next_hops_, dp::EncodeKey(dp::ActionId(hop))});
  for (uint8_t q = 0; q < m.qers; ++q) {
    const uint32_t ref = m.slots[2 * limits_.max_actions + 2 * limits_.max_qers + q];
    if (SharedRef(ref)) refs.push_back({meters_, dp::EncodeKey(Meter(session, SlotOf(ref)).shared())});
  }
  return refs;
}

std::vector<dp::Reference> SessionResource::References(const SessionValue &v) const {
  std::vector<dp::Reference> refs;
  for (const auto &a : v.actions)
    if (a.next_hop_id) refs.push_back({next_hops_, dp::EncodeKey(dp::ActionId(a.next_hop_id))});
  for (const auto &q : v.qers)
    if (!q.spec) refs.push_back({meters_, dp::EncodeKey(q.shared)});
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

std::expected<const meter::MeterProfile *, std::string> SessionResource::AcquireProfile(
    const meter::MeterProfileSpec &spec) {
  const ProfileKey key = KeyOf(spec);
  auto it = profiles_.find(key);
  if (it == profiles_.end()) {
    auto made = meter::MeterProfile::Create(spec);
    if (!made) return std::unexpected(meter::MeterErrorName(made.error()));
    if (growth_ != nullptr) growth_->Grow(kProfileBytes, kProfileBytes);
    try {
      it = profiles_.emplace(key, Profile{std::move(*made), 0}).first;
    } catch (...) {
      if (growth_ != nullptr) growth_->Shrink(kProfileBytes, kProfileBytes);
      throw;
    }
    mirror_bytes_.fetch_add(kProfileBytes, std::memory_order_relaxed);
  }
  ++it->second.refs;
  return &it->second.profile;
}

void SessionResource::ReleaseProfile(const meter::MeterProfile &profile) noexcept {
  const auto it = profiles_.find(KeyOf(profile.spec()));
  CHECK(it != profiles_.end() && it->second.refs > 0) << "an unknown meter profile";
  if (--it->second.refs != 0) return;
  profiles_.erase(it);
  mirror_bytes_.fetch_sub(kProfileBytes, std::memory_order_relaxed);
  if (growth_ != nullptr) growth_->Shrink(kProfileBytes, kProfileBytes);
}

void SessionResource::ReleaseOld(Mirror &m, uint32_t session) noexcept {
  for (size_t k = 0; k < 2 * limits_.max_qers; ++k) {
    if (!(m.meters_old >> k & 1)) continue;
    if (!(m.meters_shared >> k & 1)) {
      ReleaseProfile(Meter(session, k).meter().profile());
      Meter(session, k).meter().~MeterState();
    }
    MeterOwner(m, k) = 0;
  }
  m.meters_shared &= ~m.meters_old;
  m.meters_old = 0;
  for (size_t k = 0; k < 2 * limits_.max_actions; ++k)
    if (m.cells_old >> k & 1) CellOwner(m, k) = 0;
  m.banks[0] &= ~m.cells_old;
  m.banks[1] &= ~m.cells_old;
  m.cells_old = 0;
}

void SessionResource::Free(uint32_t session) noexcept {
  std::lock_guard lock(mu_);
  Mirror &m = mirrors_[session - 1];
  CHECK(m.state == Mirror::State::kRetiring);
  m.meters_old |= m.meters_live;
  m.cells_old |= m.cells_live;
  m.meters_live = m.cells_live = 0;
  // The erase gave the mirror's bytes back at publish; its slot owners stay
  // until here, so this release can name the slots.
  ReleaseOld(m, session);
  m.slots = {};
  m.actions = m.qers = 0;
  m.flipped = false;
  m.flip = 0;
  m.banks[0] = m.banks[1] = 0;
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
    // Never published: the new mirror's bytes (Publish releases its own).
    if (bytes_ != 0 && owner_.growth_ != nullptr) owner_.growth_->Shrink(bytes_, bytes_);
  }

  void Publish(dp::Retirer &retirer) noexcept override {
    std::lock_guard lock(owner_.mu_);
    Mirror &m = owner_.mirrors_[session_ - 1];
    const auto commit = [&](std::vector<RuleChange> &changes) {
      for (auto &c : changes)
        if (const Table::RuleId freed = c.table->Commit(c.prepared))
          retirer.RemoveLater([table = c.table, freed](dp::Retirer &) { table->Recycle(freed); });
    };
    // Make before break (see the header): a packet's rule is old or new.
    commit(make_);
    for (auto &f : fteid_upserts_) f->Publish(retirer);
    commit(break_);
    for (auto &f : fteid_erases_) f->Publish(retirer);
    // The session's old action ids leave the index, its new ones enter it.
    for (uint8_t i = 0; i < m.actions; ++i) {
      auto node = owner_.actions_.extract(owner_.Config(session_, m.active, i).action_id);
      if (!node.empty()) removed_.insert(std::move(node));
    }
    while (!added_.empty()) owner_.actions_.insert(added_.extract(added_.begin()));
    switch (kind_) {
      case Kind::kInsert:
        m.state = Mirror::State::kLive;
        owner_.live_.fetch_add(1, std::memory_order_relaxed);
        break;
      case Kind::kUpdate:
        // The previous version's slots stay readable until this update's
        // grace period; the next Reserve frees them once it has passed.
        m.cells_old = m.cells_live & ~cells_live_;
        m.meters_old = m.meters_live & ~meters_live_;
        m.flipped = true;
        retirer.AfterGracePeriodStarts([&owner = owner_, &m](bess::rcu::GracePeriod token) {
          std::lock_guard relock(owner.mu_);
          m.flip = token;
        });
        break;
      case Kind::kErase:
        m.state = Mirror::State::kRetiring;
        owner_.active_[session_ - 1].store(kGone, std::memory_order_release);
        owner_.live_.fetch_sub(1, std::memory_order_relaxed);
        retirer.RemoveLater([&owner = owner_, session = session_](dp::Retirer &) { owner.Free(session); });
        break;
    }
    if (kind_ != Kind::kErase) {
      m.active = version_;
      m.actions = actions_count_;
      m.qers = qers_count_;
      m.cells_live = cells_live_;
      m.meters_live = meters_live_;
      m.meters_shared = (m.meters_shared & m.meters_old) | meters_shared_;
      m.banks[0] = banks_[0];
      m.banks[1] = banks_[1];
      owner_.active_[session_ - 1].store(version_, std::memory_order_release);
    }
    published_ = true;
    if (kind_ != Kind::kErase) std::swap(m.slots, slots_);
    std::swap(m.rules, rules_mirror_);
    std::swap(m.fteids, fteids_mirror_);
    std::swap(m.bytes, bytes_);
    owner_.mirror_bytes_.fetch_add(m.bytes, std::memory_order_relaxed);
    owner_.mirror_bytes_.fetch_sub(bytes_, std::memory_order_relaxed);
    // The replaced mirror is control-side state no packet reads: free and
    // unaccount it here (freeing does not allocate). The engine may keep a
    // published op past the module's teardown, so its destructor must not
    // reach the owner.
    slots_ = {};
    rules_mirror_ = {};
    fteids_mirror_ = {};
    if (bytes_ != 0 && owner_.growth_ != nullptr) owner_.growth_->Shrink(bytes_, bytes_);
    bytes_ = 0;
  }

  void Abort() noexcept override {
    if (published_ || aborted_) return;
    aborted_ = true;
    for (auto *changes : {&make_, &break_})
      for (auto &c : *changes) c.table->Cancel(c.prepared);
    for (auto &f : fteid_upserts_) f->Abort();
    for (auto &f : fteid_erases_) f->Abort();
    // The buckets Reserve built in free slots run under profiles it acquired.
    // (Reserve's own failures release them before the staged op is handed out.)
    if (!acquired_.empty()) {
      std::lock_guard lock(owner_.mu_);
      for (const auto *profile : acquired_) owner_.ReleaseProfile(*profile);
    }
    acquired_.clear();
  }

  struct RuleChange {
    Table *table;
    Table::Prepared prepared;
    int64_t order;  // make_: new priority; break_: old priority
  };
  std::vector<RuleChange> make_, break_;
  std::vector<std::unique_ptr<dp::StagedOp>> fteid_upserts_, fteid_erases_;
  std::map<uint32_t, uint32_t> added_, removed_;
  std::vector<const meter::MeterProfile *> acquired_;
  std::vector<uint32_t> slots_;
  std::vector<Rule> rules_mirror_;
  std::vector<SessionValue::Fteid> fteids_mirror_;
  size_t bytes_ = 0;
  uint32_t cells_live_ = 0, meters_live_ = 0, meters_shared_ = 0, banks_[2] = {0, 0};
  uint8_t version_ = 0, actions_count_ = 0, qers_count_ = 0;

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
  // A staged op Reserve refuses is destroyed (Abort) only after mu_ is
  // released: it is declared first.
  std::unique_ptr<Staged> staged;
  std::unique_lock lock(mu_);
  if (tx_sessions_.contains(session)) return std::unexpected("session changed twice in one transaction");
  Mirror &m = mirrors_[session - 1];
  if (m.state == Mirror::State::kRetiring)
    return std::unexpected("session id is still retiring (erased less than a grace period ago)");
  const bool live = m.state == Mirror::State::kLive;
  Reservation r;
  r.existed = live;
  if (live) r.previous_references = References(session);
  const auto add_fteid = [&](std::vector<std::unique_ptr<dp::StagedOp>> &into,
                             dp::Op fop) -> std::expected<void, std::string> {
    auto res = fteids_.Reserve(fop);
    if (!res) return std::unexpected("F-TEID: " + res.error());
    r.footprint.retires += res->footprint.retires;
    r.footprint.removals += res->footprint.removals;
    r.footprint.callbacks += res->footprint.callbacks;
    into.push_back(std::move(res->staged));
    return {};
  };

  if (op.kind == dp::OpKind::kErase) {
    if (!live) return std::unexpected("not found");
    staged = std::make_unique<Staged>(*this, session, Staged::Kind::kErase);
    for (const Rule &rule : m.rules) {
      auto prepared = PrepareErase(rule);
      CHECK(prepared) << "a live session's rule is missing from its table";
      staged->break_.push_back({&TableOf(rule.dl), std::move(*prepared), 0});
    }
    for (const auto &f : m.fteids)
      if (auto ok = add_fteid(staged->fteid_erases_, dp::Op::Erase({}, dp::EncodeKey(f.id))); !ok)
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
  for (const auto &a : v->actions) {
    const auto it = actions_.find(a.action_id);
    if ((it != actions_.end() && SessionOf(it->second) != session) || tx_actions_.contains(a.action_id))
      return std::unexpected(std::format("action id {} belongs to another session", a.action_id));
  }
  std::vector<Rule> rules;
  for (const auto &p : v->pdrs) {
    Rule rule{p.dl, RuleKey(p)};
    const auto found = TableOf(p.dl).FindRule(p.mask, p.value, p.ranges);
    if ((found && SessionOf(found->result_id) != session && !(live && std::ranges::any_of(
             m.rules, [&](const Rule &o) { return o.dl == rule.dl && o.key == rule.key; }))) ||
        tx_rules_.contains((p.dl ? "d" : "u") + rule.key))
      return std::unexpected("a PDR key belongs to another session");
    rules.push_back(std::move(rule));
  }

  // The previous update's version, and every slot only it names, must be
  // unreachable before this one writes over them: one grace period after
  // its publish. Waiting is bounded by a worker batch; refusing would be
  // the controller's problem for no reason. Nothing of this transaction has
  // published yet, so one wait covers every session it re-updates.
  if (live && m.flipped) {
    if (!tx_synchronized_ && (m.flip == 0 || !domain_.IsComplete(m.flip))) {
      domain_.Synchronize();
      tx_synchronized_ = true;
      ++work_.synchronizes;
    }
    m.flipped = false;
    m.flip = 0;
  }
  if (live) ReleaseOld(m, session);
  const uint8_t version = live ? m.active ^ 1 : 0;
  staged = std::make_unique<Staged>(*this, session, live ? Staged::Kind::kUpdate : Staged::Kind::kInsert);
  staged->version_ = version;
  staged->slots_ = live ? m.slots : std::vector<uint32_t>(SlotsSize(), 0);
  const auto owner = [&](size_t index) -> uint32_t & { return staged->slots_[index]; };
  const size_t cell_owners = 0, meter_owners = 2 * limits_.max_actions,
               qer_refs = 2 * limits_.max_actions + 2 * limits_.max_qers;
  const uint32_t meters_busy = live ? m.meters_live : 0, cells_busy = live ? m.cells_live : 0;
  if (live) {
    staged->banks_[0] = m.banks[0];
    staged->banks_[1] = m.banks[1];
  }

  // QERs: a kept identity (qer_id and the same profile or shared meter) keeps
  // its slot and so its buckets; anything else is built in a free slot.
  std::vector<uint16_t> refs(v->qers.size());
  for (size_t j = 0; j < v->qers.size(); ++j) {
    const auto &q = v->qers[j];
    std::optional<size_t> keep;
    for (size_t p = 0; live && p < m.qers; ++p) {
      const uint32_t ref = QerRef(m, p);
      const size_t slot = SlotOf(ref);
      if (MeterOwner(m, slot) != q.qer_id) continue;
      if (q.spec ? !SharedRef(ref) && Meter(session, slot).meter().profile().spec() == *q.spec
                 : SharedRef(ref) && Meter(session, slot).shared() == q.shared)
        keep = slot;
      break;
    }
    size_t slot;
    if (keep) {
      slot = *keep;
    } else {
      slot = FreeSlot(meters_busy, staged->meters_live_, 2 * limits_.max_qers);
      if (q.spec) {
        auto profile = AcquireProfile(*q.spec);
        if (!profile) return std::unexpected(std::format("QER {}: {}", j + 1, profile.error()));
        staged->acquired_.push_back(*profile);
        // Exclusive: the module runs on one worker (max_allowed_workers_ 1),
        // the only writer of its own buckets.
        auto built = meter::MeterState::ConstructAt(Meter(session, slot).bytes, **profile,
                                                    meter::MeterSharing::kWorkerExclusive);
        if (!built) return std::unexpected(std::format("QER {}: {}", j + 1, meter::MeterErrorName(built.error())));
      } else {
        Meter(session, slot).set_shared(q.shared);
      }
      owner(meter_owners + slot) = q.qer_id;
    }
    staged->meters_live_ |= uint32_t{1} << slot;
    if (!q.spec) staged->meters_shared_ |= uint32_t{1} << slot;
    refs[j] = SlotRef(slot, !q.spec);
  }
  for (size_t j = 0; j < limits_.max_qers; ++j) owner(qer_refs + j) = j < refs.size() ? refs[j] : 0;

  // Actions: a kept action id keeps its cell slot, so both banks continue.
  for (size_t i = 0; i < v->actions.size(); ++i) {
    const auto &a = v->actions[i];
    std::optional<size_t> keep;
    for (size_t k = 0; live && k < 2 * limits_.max_actions; ++k)
      if ((cells_busy >> k & 1) && CellOwner(m, k) == a.action_id) { keep = k; break; }
    const size_t slot = keep ? *keep : FreeSlot(cells_busy, staged->cells_live_, 2 * limits_.max_actions);
    const uint32_t bit = uint32_t{1} << slot;
    if (!keep) {
      for (auto &bank : Cells(session, static_cast<uint8_t>(slot)).urr) bank.Reset();
      owner(cell_owners + slot) = a.action_id;
      staged->banks_[0] &= ~bit;
      staged->banks_[1] &= ~bit;
    }
    staged->cells_live_ |= bit;
    if (a.count) staged->banks_[(*directions)[i]] |= bit;
    ActionConfig c;
    c.action_id = a.action_id;
    c.next_hop_id = a.next_hop_id;
    c.route_domain = a.route_domain;
    c.policy_id = a.policy_id;
    for (size_t level = 0; level < 2; ++level) c.meter[level] = a.qer[level] ? refs[a.qer[level] - 1] : 0;
    c.cell = static_cast<uint8_t>(slot) | (a.count ? ActionConfig::kCount : 0);
    if (a.tunnel) {
      const Tunnel &t = *a.tunnel;
      c.cell |= ActionConfig::kHasTunnel;
      c.teid = t.teid;
      c.transport_route_domain = t.transport_route_domain;
      c.marking = t.marking;
      c.qfi = static_cast<uint8_t>((t.qfi & ActionConfig::kQfi) | (t.has_qfi ? ActionConfig::kHasQfi : 0) |
                                   (t.family == 6 ? ActionConfig::kIpv6 : 0));
      std::memcpy(c.local, t.local, 16);
      std::memcpy(c.peer, t.peer, 16);
    }
    // Unreachable: no rule carries `version` (insert: no rule at all), and
    // the last packet that read it has passed a quiescent state.
    const_cast<ActionConfig &>(Config(session, version, static_cast<uint8_t>(i))) = c;
  }
  for (size_t i = v->actions.size(); i < limits_.max_actions; ++i)
    const_cast<ActionConfig &>(Config(session, version, static_cast<uint8_t>(i))) = ActionConfig{};

  // F-TEIDs: gone ones erased, new ones inserted, kept ones untouched unless
  // their End Marker relays changed -- the tunnels the F-TEID's PDRs forward
  // into moved -- which the F-TEID resource replaces whole.
  for (const auto &old : m.fteids) {
    const auto it = std::ranges::find(v->fteids, old.id, &SessionValue::Fteid::id);
    if (it == v->fteids.end()) {
      if (auto ok = add_fteid(staged->fteid_erases_, dp::Op::Erase({}, dp::EncodeKey(old.id))); !ok)
        return std::unexpected(ok.error());
    } else if (it->record.direction != old.record.direction ||
               it->record.context_id != old.record.context_id) {
      return std::unexpected("an F-TEID keeps its direction and context; erase the session to change them");
    } else if (it->record.relays != old.record.relays) {
      if (auto ok = add_fteid(staged->fteid_upserts_, dp::Op::Upsert({}, dp::EncodeKey(it->id), std::any(it->record))); !ok)
        return std::unexpected(ok.error());
    }
  }
  for (const auto &f : v->fteids) {
    if (std::ranges::find(m.fteids, f.id, &SessionValue::Fteid::id) != m.fteids.end()) continue;
    // A live F-TEID outside this session's set is another session's (the
    // index would answer an identical insert as a no-op, sharing it).
    if (fteids_.Contains(dp::EncodeKey(f.id))) return std::unexpected("an F-TEID belongs to another session");
    if (auto ok = add_fteid(staged->fteid_upserts_, dp::Op::Upsert({}, dp::EncodeKey(f.id), std::any(f.record))); !ok)
      return std::unexpected(ok.error());
  }
  // Rules: gone ones erased (break, by ascending old priority); every kept or
  // new one upserted with this version's result -- raises and new rules make
  // (by descending new priority), lowerings break. Distinct keys: Validate
  // and the ownership check above.
  for (const Rule &old : m.rules) {
    if (std::ranges::any_of(rules, [&](const Rule &n) { return n.dl == old.dl && n.key == old.key; })) continue;
    auto prepared = PrepareErase(old);
    CHECK(prepared) << "a live session's rule is missing from its table";
    const int64_t priority = TableOf(old.dl).RuleAt(prepared->old).priority;
    staged->break_.push_back({&TableOf(old.dl), std::move(*prepared), priority});
    ++r.footprint.removals;
  }
  for (const auto &p : v->pdrs) {
    const uint32_t result = p.action == SessionValue::kNoAction ? 0 : ResultOf(session, version, p.action);
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
    Table &table = TableOf(p.dl);
    if (prepared->old != 0) {
      ++r.footprint.removals;
      const int64_t was = table.RuleAt(prepared->old).priority;
      if (p.priority < was) {
        staged->break_.push_back({&table, std::move(*prepared), was});
        continue;
      }
    }
    staged->make_.push_back({&table, std::move(*prepared), p.priority});
  }
  std::ranges::stable_sort(staged->make_, std::ranges::greater{}, &Staged::RuleChange::order);
  std::ranges::stable_sort(staged->break_, std::ranges::less{}, &Staged::RuleChange::order);
  for (size_t k = 0; k < 2 * limits_.max_actions; ++k)
    if (staged->cells_live_ >> k & 1) staged->added_.emplace(owner(cell_owners + k), session << (kActionBits + 1) | static_cast<uint32_t>(k));
  if (live) ++r.footprint.callbacks;
  staged->rules_mirror_ = rules;
  staged->fteids_mirror_ = v->fteids;
  size_t bytes = staged->rules_mirror_.capacity() * sizeof(Rule) +
                 staged->fteids_mirror_.capacity() * sizeof(SessionValue::Fteid) +
                 staged->slots_.capacity() * sizeof(uint32_t) + v->actions.size() * kNodeBytes;
  for (const Rule &rule : staged->rules_mirror_) bytes += rule.key.capacity() + 1;
  for (const auto &f : staged->fteids_mirror_) bytes += f.record.relays.capacity() * sizeof(upf::datapath::EndMarkerRelay);
  if (growth_ != nullptr) growth_->Grow(bytes, bytes);
  staged->bytes_ = bytes;
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
  tx_synchronized_ = false;
}

upf::pb::UpfSession SessionResource::Read(uint32_t session) const {
  const Mirror &m = mirrors_[session - 1];
  const auto ref_at = [&](size_t q) { return m.slots[2 * limits_.max_actions + 2 * limits_.max_qers + q]; };
  upf::pb::UpfSession out;
  for (const auto &f : m.fteids) {
    auto *o = out.add_fteids();
    *o->mutable_key() = EncodeFteidKey(f.id);
    *o->mutable_entry() = upf::datapath::EncodeFteidEntry(f.record);
  }
  for (uint8_t q = 0; q < m.qers; ++q) {
    const uint32_t ref = ref_at(q);
    auto *o = out.add_qers();
    o->set_qer_id(m.slots[2 * limits_.max_actions + SlotOf(ref)]);
    if (SharedRef(ref)) o->set_shared_meter_id(Meter(session, SlotOf(ref)).shared());
    else EncodeSpec(Meter(session, SlotOf(ref)).meter().profile().spec(), o);
  }
  for (uint8_t i = 0; i < m.actions; ++i) {
    const ActionConfig &a = Config(session, m.active, i);
    auto *o = out.add_actions();
    o->set_action_id(a.action_id);
    o->set_next_hop_id(a.next_hop_id);
    o->set_route_domain(a.route_domain);
    o->set_steering_policy_id(a.policy_id);
    for (size_t level = 0; level < 2; ++level) {
      uint32_t position = 0;
      for (uint8_t q = 0; a.meter[level] && q < m.qers; ++q)
        if (ref_at(q) == a.meter[level]) { position = q + 1u; break; }
      level == 0 ? o->set_pdr_qer(position) : o->set_session_qer(position);
    }
    o->set_count(a.cell & ActionConfig::kCount);
    if (a.has_tunnel()) *o->mutable_tunnel() = EncodeTunnel(a.tunnel());
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
    o->set_action(found->result_id ? IndexOf(found->result_id) + 1u : 0u);
  }
  return out;
}

void SessionResource::ForEachLive(const std::function<void(uint32_t, const upf::pb::UpfSession &)> &visit) const {
  // At most kEntriesPerHold sessions read per mu_ hold, visited after it is
  // released (the visitor may block on the client's stream).
  std::vector<std::pair<uint32_t, upf::pb::UpfSession>> batch;
  for (uint32_t s = 1; s <= limits_.capacity;) {
    batch.clear();
    {
      std::lock_guard lock(mu_);
      for (; s <= limits_.capacity && batch.size() < kEntriesPerHold; ++s)
        if (mirrors_[s - 1].state == Mirror::State::kLive) batch.emplace_back(s, Read(s));
      work_.max_per_hold = std::max(work_.max_per_hold, batch.size());
    }
    for (const auto &[id, value] : batch) visit(id, value);
  }
}

void SessionResource::Report(uint32_t action_id, uint32_t at, bool dl, bool restart,
                             upf::pb::UrrCountCommandGetCountsResponse *out) const {
  auto *count = out->add_counts();
  count->set_action_id(action_id);
  if (at == 0) return;
  const uint32_t session = SessionOf(at);
  const uint8_t slot = static_cast<uint8_t>(at & ((uint32_t{1} << (kActionBits + 1)) - 1));
  if (!(mirrors_[session - 1].banks[dl] >> slot & 1)) return;
  SessionUrr &bank = Cells(session, slot).urr[dl];
  count->set_packets(bank.packets.load(std::memory_order_relaxed));
  count->set_octets(bank.octets.load(std::memory_order_relaxed));
  count->set_first_packet_ns(restart ? bank.first_ns.exchange(0, std::memory_order_relaxed)
                                     : bank.first_ns.load(std::memory_order_relaxed));
  count->set_last_packet_ns(bank.last_ns.load(std::memory_order_relaxed));
}

uint32_t SessionResource::Counts(bool dl, std::span<const uint32_t> ids, bool restart, uint32_t after,
                                 size_t limit, upf::pb::UrrCountCommandGetCountsResponse *out) const {
  // At most kEntriesPerHold entries per mu_ hold, so a transaction waits for
  // one chunk, not the whole read.
  if (!ids.empty()) {
    for (size_t i = 0; i < ids.size();) {
      std::lock_guard lock(mu_);
      const size_t end = std::min(ids.size(), i + kEntriesPerHold);
      work_.max_per_hold = std::max(work_.max_per_hold, end - i);
      for (; i < end; ++i) {
        ++work_.action_finds;
        const auto it = actions_.find(ids[i]);
        Report(ids[i], it == actions_.end() ? 0 : it->second, dl, restart, out);
      }
    }
    return 0;
  }
  // Every counted action above `after` in id order, at most `limit`,
  // resuming each hold where the last stopped: one index walk, no lookup
  // per entry.
  size_t reported = 0;
  uint32_t last = after;
  for (std::optional<uint64_t> next = uint64_t{after} + 1; next;) {
    std::lock_guard lock(mu_);
    auto it = actions_.lower_bound(static_cast<uint32_t>(std::min<uint64_t>(*next, UINT32_MAX)));
    if (*next > UINT32_MAX) it = actions_.end();
    size_t n = 0;
    for (; it != actions_.end() && n < kEntriesPerHold; ++it, ++n) {
      const uint8_t slot = static_cast<uint8_t>(it->second & ((uint32_t{1} << (kActionBits + 1)) - 1));
      if (!(mirrors_[SessionOf(it->second) - 1].banks[dl] >> slot & 1)) continue;
      if (reported == limit) return last;
      Report(it->first, it->second, dl, restart, out);
      ++reported;
      last = it->first;
    }
    work_.max_per_hold = std::max(work_.max_per_hold, n);
    next = it == actions_.end() ? std::nullopt : std::optional<uint64_t>(it->first);
  }
  return 0;
}

}  // namespace upf::appliance
