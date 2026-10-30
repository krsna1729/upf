// SPDX-License-Identifier: BSD-3-Clause
//
// `self_test`: the module's own tables, driven without frames or a graph (the
// R4 pattern). It writes one session through the engine exactly as a
// controller's transaction does (Reserve/Publish via ApplyOwned): an F-TEID,
// a UL PDR, an action with URR cells and a QER. It classifies keys built by
// the packet path's own BuildPdrKey through the installed masked table and
// follows the result id into the session's stride; then updates the session
// in place (a tunnel added: the token bucket and the URR cells must stay),
// updates its QER profile (the bucket must start full), and erases it. Run it
// on an idle appliance with workers paused (the command is THREAD_UNSAFE):
// it uses the last session id, action id 0x7e57 and context 0x7e57. The
// frame-level lanes (decap, meters, ATSSS, router, encap, transport) are
// checked by upf_appliance_frame_test.cc and the live harness.

#include <cstring>
#include <string>

#include "upf_appliance.h"
#include "dataplane/resource_registry.h"
#include "upf_appliance_frame.h"

CommandResponse UpfAppliance::CommandSelfTest(const bess::pb::EmptyArg &) {
  namespace dp = bess::dataplane;
  namespace meter = bess::meter;
  using bess::classifier::ConstBytes;
  using upf::appliance::SessionResource;
  using upf::appliance::SessionValue;
  if (!sessions_ || !pdr_ul_) return CommandFailure(EINVAL, "not initialised");

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
  if (sessions_->limits().max_qers == 0)
    return CommandFailure(EINVAL, "self_test needs max_qers >= 1");

  const uint32_t sid = static_cast<uint32_t>(sessions_->limits().capacity);
  const dp::ResourceKey session_key = dp::EncodeKey(sid);
  upf::datapath::FteidId fteid{};
  fteid[3] = 0x57; fteid[2] = 0x7e;  // endpoint 0x7e57
  fteid[4] = 4;
  fteid[17] = 192; fteid[19] = 2; fteid[20] = 254;  // 192.0.2.254
  fteid[23] = 0x7e; fteid[24] = 0x57;  // TEID 0x7e57
  const meter::TrTcmSpec small{1000, 1000, 1000, 1000};
  SessionValue v;
  v.fteids = {{fteid, {0, kId}}};
  v.qers = {small};
  v.actions = {{.action_id = kId, .qer = {1, 0}, .count = true}};
  v.pdrs = {{.dl = false, .mask = std::vector<std::byte>(18, std::byte{0xff}),
             .value = std::vector<std::byte>(key.begin(), key.begin() + 18),
             .priority = 100, .gate = 0, .action = 0}};
  const dp::Resource *const owned[] = {sessions_.get()};
  const auto apply = [&](dp::Op op) {
    return init_context().resources().ApplyOwned(owned, std::array{std::move(op)});
  };
  const auto applied = [](const auto &r) {
    return r.outcome == dp::ResourceRegistry::OwnedApplyResult::Outcome::kApplied;
  };
  if (auto r = apply(dp::Op::Upsert(sessions_->name(), session_key, std::any(v))); !applied(r))
    return CommandFailure(EINVAL, "session upsert refused: %s", r.error.c_str());

  std::string failure;
  bess::classifier::ConcurrentMaskedTable::Match hit[2];
  std::array<std::byte, 36> keys{};
  std::memcpy(keys.data(), key.data(), 18);
  std::memcpy(keys.data() + 18, key.data(), 18);
  keys[18 + 16] = std::byte{0x01};  // a different admission context: must miss
  const uint64_t found = pdr_ul_->LookupBatch(ConstBytes(keys.data(), keys.size()), 18, hit, 2);
  auto &qer = sessions_->Qer(sid, 0);
  auto &action = sessions_->Action(sid, 0);
  if (found != 1) failure = "batch lookup: want hit for the rule's key and a miss for another context";
  else if (hit[0].gate != 0) failure = "rule gate was not returned";
  else if (const uint32_t r = pdr_ul_->RuleAt(hit[0].rule_id).result_id;
           SessionResource::SessionOf(r) != sid || SessionResource::IndexOf(r) != 0)
    failure = "rule result does not name the session's action";
  else if (action.action_id.load() != kId || !action.count || action.qer[0] != 1)
    failure = "action did not round-trip into the session's stride";
  else if (!fteid_resource_->Contains(dp::EncodeKey(fteid)))
    failure = "the session's F-TEID was not admitted";

  // An unrelated update (a tunnel added) keeps the bucket and the cells.
  const uint64_t now = meter::MeterNow();
  if (failure.empty() && qer.meter().Check(now, 600) != meter::MeterColor::kGreen)
    failure = "a full bucket did not pass 600 bytes green";
  const auto before = qer.meter().Inspect();
  for (unsigned i = 0; i < 7; ++i) action.urr[0].Add(64, 100 + i);
  SessionValue tunnelled = v;
  upf::appliance::Tunnel t{.teid = 9, .family = 4};
  t.local[12] = 192; t.local[15] = 1; t.peer[12] = 10; t.peer[15] = 2;
  tunnelled.actions[0].tunnel = t;
  if (failure.empty()) {
    if (auto r = apply(dp::Op::Upsert(sessions_->name(), session_key, std::any(tunnelled))); !applied(r))
      failure = "in-place session update refused: " + r.error;
    else if (const auto after = qer.meter().Inspect();
             after.buckets[0].tokens != before.buckets[0].tokens ||
             after.last_update_tsc != before.last_update_tsc)
      failure = "an unrelated update reset the session's token bucket";
    else if (action.urr[0].packets.load() != 7 || !action.has_tunnel || action.tunnel.teid != 9)
      failure = "an unrelated update lost the URR cells or the tunnel";
  }
  // Alternate ATSSS tunnels live in this same session, not a global table.
  // Missing/unprovisioned selectors fail closed; unrelated slots keep URRs.
  if (failure.empty() && sessions_->limits().max_actions >= 2) {
    auto alternate = t;
    alternate.teid = 10;
    tunnelled.actions.push_back({.action_id = kId + 1, .tunnel = alternate});
    if (auto r = apply(dp::Op::Upsert(sessions_->name(), session_key, std::any(tunnelled))); !applied(r))
      failure = "tunnel-only action refused: " + r.error;
    else if (const auto *selected = sessions_->TunnelAt(sid, 1);
             selected == nullptr || selected->teid != 10 || selected == sessions_->TunnelAt(sid, 0))
      failure = "ATSSS local tunnel selector did not resolve the alternate action";
    else if (sessions_->TunnelAt(sid, sessions_->limits().max_actions) != nullptr ||
             action.urr[0].packets.load(std::memory_order_relaxed) != 7)
      failure = "ATSSS selector escaped the stride or reset unrelated counters";
  }
  // The compiler can move a stable action between UL and DL. The two banks
  // must not inherit/reset one another, including through get_counts while
  // the opposite direction is current. Use the packet path's own Add.
  const auto history = [&](bool downlink, uint64_t packets, uint64_t octets,
                           uint64_t first, uint64_t last) {
    upf::pb::UrrCountCommandGetCountsResponse out;
    const std::array<uint32_t, 1> ids{kId};
    sessions_->Counts(downlink, ids, false, &out);
    return out.counts_size() == 1 && out.counts(0).action_id() == kId &&
           out.counts(0).packets() == packets && out.counts(0).octets() == octets &&
           out.counts(0).first_packet_ns() == first && out.counts(0).last_packet_ns() == last;
  };
  if (failure.empty()) {
    SessionValue downlink = tunnelled;
    downlink.pdrs[0].dl = true;
    downlink.pdrs[0].mask.assign(22, std::byte{0xff});
    downlink.pdrs[0].value.assign(dl.begin(), dl.end());
    if (auto r = apply(dp::Op::Upsert(sessions_->name(), session_key, std::any(downlink))); !applied(r))
      failure = "UL-to-DL action rewrite refused: " + r.error;
    else if (!history(true, 0, 0, 0, 0) || !history(false, 7, 448, 100, 106))
      failure = "UL-to-DL rewrite carried UL totals into DL or hid UL history";
    if (failure.empty()) {
      action.urr[1].Add(80, 200);
      action.urr[1].Add(80, 201);
      if (auto r = apply(dp::Op::Upsert(sessions_->name(), session_key, std::any(tunnelled))); !applied(r))
        failure = "DL-to-UL action rewrite refused: " + r.error;
      else if (!history(false, 7, 448, 100, 106) || !history(true, 2, 160, 200, 201))
        failure = "DL-to-UL rewrite did not retain both directional URR histories";
      else {
        action.urr[0].Add(64, 107);
        if (!history(false, 8, 512, 100, 107) || !history(true, 2, 160, 200, 201))
          failure = "UL counting did not resume its own bank after switching back";
      }
    }
    if (failure.empty()) {
      const auto after = qer.meter().Inspect();
      if (after.buckets[0].tokens != before.buckets[0].tokens ||
          after.last_update_tsc != before.last_update_tsc)
        failure = "action/tunnel/direction rewrites reset an unchanged QER bucket";
    }
  }
  // A changed profile starts with full buckets.
  if (failure.empty()) {
    tunnelled.qers[0] = meter::TrTcmSpec{1000, 1500, 1000, 1500};
    if (auto r = apply(dp::Op::Upsert(sessions_->name(), session_key, std::any(tunnelled))); !applied(r))
      failure = "QER profile update refused: " + r.error;
    else if (qer.meter().Inspect().buckets[0].tokens != 1500)
      failure = "a changed QER profile did not start with full buckets";
  }

  if (auto r = apply(dp::Op::Erase(sessions_->name(), session_key)); !applied(r) && failure.empty())
    failure = "session erase refused: " + r.error;
  if (failure.empty() && (pdr_ul_->LookupBatch(ConstBytes(keys.data(), 18), 18, hit, 1) != 0 ||
                          fteid_resource_->Contains(dp::EncodeKey(fteid))))
    failure = "the erased session's rule or F-TEID still answers";
  if (!failure.empty()) return CommandFailure(EINVAL, "%s", failure.c_str());
  return CommandSuccess();
}
