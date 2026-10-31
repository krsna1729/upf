// SPDX-License-Identifier: BSD-3-Clause
//
// `self_test`: the module's own tables, driven without frames or a graph (the
// R4 pattern). It writes one UL PDR through the engine exactly as a
// controller's transaction does (Reserve/Publish via ApplyOwned), classifies
// keys built by the packet path's own BuildPdrKey from a synthetic frame
// through the installed masked table, reads the result record back, and
// erases the rule. UpfSessionAppliance writes one session instead (F-TEID,
// UL PDR, a counting action with its own QER), follows the rule's result
// into the session's stride, rewrites it live (a tunnel added: the other
// version, same cells and bucket; then a shared meter of "<module>/meters"
// in place of its own) and erases it. Run it on an idle appliance with
// workers paused (the command is THREAD_UNSAFE): it uses action id 0x7e57,
// context 0x7e57, and for the session layout the last session id and the
// last shared meter id. The frame-level lanes (decap, meters, ATSSS, router,
// encap, transport) are checked by upf_appliance_frame_test.cc and the live
// harness; the session store's concurrency by upf_appliance_sessions_test.cc.

#include <cstring>
#include <string>

#include "upf_appliance.h"
#include "dataplane/resource_registry.h"
#include "upf_appliance_frame.h"

CommandResponse UpfAppliance::CommandSelfTest(const bess::pb::EmptyArg &) {
  namespace dp = bess::dataplane;
  using bess::classifier::ConstBytes;
  using bess::classifier::MaskedRuleResource;
  if (!pdr_ul_.table || !(session_layout_ ? static_cast<bool>(sessions_) : static_cast<bool>(pdr_ul_.resource)))
    return CommandFailure(EINVAL, "not initialised");

  std::array<uint8_t, 64> frame{};
  frame[12] = 0x08;
  frame[14] = 0x45;
  frame[23] = 17;
  const uint8_t src[4] = {10, 45, 0, 2}, dst[4] = {198, 51, 100, 1};
  std::memcpy(&frame[26], src, 4);
  std::memcpy(&frame[30], dst, 4);
  frame[34] = 0x30; frame[35] = 0x39;  // sport 12345
  frame[36] = 0x01; frame[37] = 0xbb;  // dport 443
  constexpr uint32_t kId = 0x7e57;

  std::array<std::byte, 22> key{};
  if (!upf::appliance::BuildPdrKey(frame, false, 0, kId, 5, key))
    return CommandFailure(EINVAL, "BuildPdrKey refused a full frame");
  const auto *k = reinterpret_cast<const uint8_t *>(key.data());
  if (std::memcmp(k, src, 4) || std::memcmp(k + 4, dst, 4) || k[8] != 17 ||
      k[9] != 0x30 || k[12] != 0xbb || k[15] != 0x7e || k[16] != 0x57 || k[17] != 5)
    return CommandFailure(EINVAL, "UL PDR key layout differs from compile.go's fields");
  std::array<std::byte, 22> dl{};
  upf::appliance::BuildPdrKey(frame, true, 3, kId, 5, dl);
  if (static_cast<uint8_t>(dl[16]) != 3 || static_cast<uint8_t>(dl[21]) != 5)
    return CommandFailure(EINVAL, "DL PDR key layout (domain, context, qfi) is wrong");
  if (upf::appliance::UsageOctets(frame, frame.size()) != frame.size())
    return CommandFailure(EINVAL, "usage octets: non-IPv4 length must fall back to the frame");
  if (session_layout_) return SessionSelfTest(key);

  const size_t len = 18;
  std::vector<std::byte> mask(len, std::byte{0xff});
  ConstBytes value(key.data(), len);
  MaskedRuleResource::Value rule{.priority = 100, .gate = 0,
                                  .result = std::vector<std::byte>(20, std::byte{0})};
  rule.result[2] = std::byte{0x7e};
  rule.result[3] = std::byte{0x57};  // action_id, big endian
  const dp::ResourceKey rule_key = MaskedRuleResource::Key(ConstBytes(mask.data(), len), value);
  const dp::Resource *const owned[] = {pdr_ul_.resource.get()};
  const auto applied = init_context().resources().ApplyOwned(
      owned, std::array{dp::Op::Upsert(pdr_ul_.resource->name(), rule_key, std::any(rule))});
  if (applied.outcome != dp::ResourceRegistry::OwnedApplyResult::Outcome::kApplied)
    return CommandFailure(EINVAL, "PDR upsert refused: %s", applied.error.c_str());

  bess::classifier::ConcurrentMaskedTable::Match hit[2];
  std::array<std::byte, 36> keys{};
  std::memcpy(keys.data(), key.data(), 18);
  std::memcpy(keys.data() + 18, key.data(), 18);
  keys[18 + 16] = std::byte{0x01};  // a different admission context: must miss
  const uint64_t found = pdr_ul_.table->LookupBatch(ConstBytes(keys.data(), keys.size()), 18, hit, 2);
  std::string failure;
  if (found != 1) failure = "batch lookup: want hit for the rule's key and a miss for another context";
  else if (hit[0].gate != 0) failure = "rule gate was not returned";
  else {
    const auto record = pdr_ul_.records->Lookup(pdr_ul_.table->RuleAt(hit[0].rule_id).result_id);
    if (static_cast<uint8_t>(record[2]) != 0x7e || static_cast<uint8_t>(record[3]) != 0x57)
      failure = "result record did not round-trip";
  }

  const auto erased = init_context().resources().ApplyOwned(
      owned, std::array{dp::Op::Erase(pdr_ul_.resource->name(), rule_key)});
  if (erased.outcome != dp::ResourceRegistry::OwnedApplyResult::Outcome::kApplied && failure.empty())
    failure = "PDR erase refused: " + erased.error;
  if (!failure.empty()) return CommandFailure(EINVAL, "%s", failure.c_str());
  return CommandSuccess();
}

CommandResponse UpfAppliance::SessionSelfTest(const std::array<std::byte, 22> &key) {
  namespace dp = bess::dataplane;
  namespace meter = bess::meter;
  using bess::classifier::ConstBytes;
  using upf::appliance::ActionConfig;
  using upf::appliance::SessionResource;
  using upf::appliance::SessionValue;
  constexpr uint32_t kId = 0x7e57;
  const uint32_t sid = static_cast<uint32_t>(sessions_->limits().capacity);
  const meter::MeterId shared_id(static_cast<uint32_t>(meters_->Capacity().value_or(1)));
  const dp::ResourceKey session_key = dp::EncodeKey(sid);
  const dp::ResourceKey meter_key = dp::EncodeKey(shared_id);
  upf::datapath::FteidId fteid{};
  fteid[2] = 0x7e; fteid[3] = 0x57;  // endpoint 0x7e57
  fteid[4] = 4;
  fteid[17] = 192; fteid[19] = 2; fteid[20] = 254;  // 192.0.2.254
  fteid[23] = 0x7e; fteid[24] = 0x57;  // TEID 0x7e57
  SessionValue v;
  v.fteids = {{fteid, {0, kId}}};
  v.qers = {{.qer_id = 1, .spec = meter::TrTcmSpec{1000, 1000, 1000, 1000}}};
  v.actions = {{.action_id = kId, .qer = {1, 0}, .count = true}};
  v.pdrs = {{.dl = false, .mask = std::vector<std::byte>(18, std::byte{0xff}),
             .value = std::vector<std::byte>(key.begin(), key.begin() + 18),
             .priority = 100, .gate = 0, .action = 0}};
  const dp::Resource *const owned[] = {sessions_.get(), meters_.get()};
  const auto apply = [&](dp::Op op) {
    return init_context().resources().ApplyOwned(owned, std::array{std::move(op)});
  };
  const auto applied = [](const auto &r) {
    return r.outcome == dp::ResourceRegistry::OwnedApplyResult::Outcome::kApplied;
  };
  if (auto r = apply(dp::Op::Upsert(sessions_->name(), session_key, std::any(v))); !applied(r))
    return CommandFailure(EINVAL, "session upsert refused: %s", r.error.c_str());

  std::string failure;
  // The worker's view: rule -> (session, version, position) -> config.
  struct Seen { bool hit; uint32_t result; ActionConfig config; };
  const auto classify = [&]() {
    bess::classifier::ConcurrentMaskedTable::Match hit;
    Seen seen{pdr_ul_.table->LookupBatch(ConstBytes(key.data(), 18), 18, &hit, 1) == 1, 0, {}};
    if (seen.hit) {
      seen.result = pdr_ul_.table->RuleAt(hit.rule_id).result_id;
      seen.config = sessions_->Config(SessionResource::SessionOf(seen.result),
                                      SessionResource::VersionOf(seen.result),
                                      SessionResource::IndexOf(seen.result));
    }
    return seen;
  };
  const Seen first = classify();
  if (!first.hit) failure = "the session's PDR does not answer";
  else if (SessionResource::SessionOf(first.result) != sid || SessionResource::VersionOf(first.result) != 0 ||
           SessionResource::IndexOf(first.result) != 0)
    failure = "rule result does not name the session's version 0, action 0";
  else if (first.config.action_id != kId || !(first.config.cell & ActionConfig::kCount) ||
           first.config.meter[0] == 0 || (first.config.meter[0] & ActionConfig::kSharedMeter))
    failure = "action did not round-trip into the session's stride";
  else if (!fteid_resource_->Contains(dp::EncodeKey(fteid)))
    failure = "the session's F-TEID was not admitted";

  // Live rewrite: a tunnel added. The other version answers; cells and the
  // bucket are the same ones.
  if (failure.empty()) {
    auto &cells = sessions_->Cells(sid, first.config.cell & ActionConfig::kCellSlot);
    auto &bucket = sessions_->Meter(sid, first.config.meter[0] - 1).meter();
    (void)bucket.Check(meter::MeterNow(), 600);
    const auto before = bucket.Inspect();
    for (unsigned i = 0; i < 7; ++i) cells.urr[0].Add(64, 100 + i);
    SessionValue tunnelled = v;
    upf::appliance::Tunnel t{.teid = 9, .family = 4};
    t.local[12] = 192; t.local[15] = 1; t.peer[12] = 10; t.peer[15] = 2;
    tunnelled.actions[0].tunnel = t;
    const auto r = apply(dp::Op::Upsert(sessions_->name(), session_key, std::any(tunnelled)));
    const Seen second = classify();
    const auto after = bucket.Inspect();
    if (!applied(r))
      failure = "live session update refused: " + r.error;
    else if (!second.hit || SessionResource::VersionOf(second.result) != 1 || sessions_->Active(sid) != 1)
      failure = "the update did not switch the rule to version 1";
    else if (!second.config.has_tunnel() || second.config.teid != 9 ||
             sessions_->Config(sid, 0, 0).has_tunnel())
      failure = "the versions' configs are not each their own";
    else if ((second.config.cell & ActionConfig::kCellSlot) != (first.config.cell & ActionConfig::kCellSlot) ||
             cells.urr[0].packets.load() != 7)
      failure = "an unrelated update moved or lost the URR cells";
    else if (second.config.meter[0] != first.config.meter[0] ||
             after.buckets[0].tokens != before.buckets[0].tokens ||
             after.last_update_tsc != before.last_update_tsc)
      failure = "an unrelated update reset the session's token bucket";
  }

  // A shared meter in place of its own bucket, held by the engine's ledger
  // while the session names it; and back.
  if (failure.empty()) {
    if (auto r = apply(dp::Op::Upsert(meters_->name(), meter_key,
                                      std::any(meter::MeterProfileSpec(meter::TrTcmSpec{1000, 1000, 1000, 1000}))));
        !applied(r))
      failure = "shared meter upsert refused: " + r.error;
  }
  if (failure.empty()) {
    SessionValue shared = v;
    shared.qers[0] = {.qer_id = 1, .shared = shared_id.value()};
    if (auto r = apply(dp::Op::Upsert(sessions_->name(), session_key, std::any(shared))); !applied(r))
      failure = "own-to-shared QER update refused: " + r.error;
    else if (const Seen s = classify(); !(s.config.meter[0] & ActionConfig::kSharedMeter) ||
             sessions_->Meter(sid, (s.config.meter[0] & ~ActionConfig::kSharedMeter) - 1).shared() !=
                 shared_id.value())
      failure = "the session does not name the shared meter";
    else if (applied(apply(dp::Op::Erase(meters_->name(), meter_key))))
      failure = "a shared meter a session names was erased";
    else if (auto back = apply(dp::Op::Upsert(sessions_->name(), session_key, std::any(v))); !applied(back))
      failure = "shared-to-own QER update refused: " + back.error;
    else if (classify().config.meter[0] & ActionConfig::kSharedMeter)
      failure = "the session still names the shared meter";
  }

  if (auto r = apply(dp::Op::Erase(sessions_->name(), session_key)); !applied(r) && failure.empty())
    failure = "session erase refused: " + r.error;
  if (meters_->Contains(meter_key))
    if (auto r = apply(dp::Op::Erase(meters_->name(), meter_key)); !applied(r) && failure.empty())
      failure = "shared meter erase refused: " + r.error;
  if (failure.empty() && (classify().hit || fteid_resource_->Contains(dp::EncodeKey(fteid)) ||
                          sessions_->Active(sid) != SessionResource::kGone))
    failure = "the erased session's rule or F-TEID still answers";
  if (!failure.empty()) return CommandFailure(EINVAL, "%s", failure.c_str());
  return CommandSuccess();
}
