// SPDX-License-Identifier: BSD-3-Clause
//
// `self_test`: the module's own tables, driven without frames or a graph (the
// R4 pattern). It writes one UL PDR through the engine exactly as a
// controller's transaction does (Reserve/Publish via ApplyOwned), classifies
// keys built by the packet path's own BuildPdrKey from a synthetic frame
// through the installed masked table, reads the result record back, and
// erases the rule. Run it on an idle appliance with workers paused (the
// command is THREAD_UNSAFE): it uses action id 0x7e57 and context 0x7e57.
// The frame-level lanes (decap, meters, ATSSS, router, encap, transport) are
// checked by upf_appliance_frame_test.cc and the live harness.

#include <cstring>
#include <string>

#include "upf_appliance.h"
#include "dataplane/resource_registry.h"
#include "upf_appliance_frame.h"

CommandResponse UpfAppliance::CommandSelfTest(const bess::pb::EmptyArg &) {
  namespace dp = bess::dataplane;
  using bess::classifier::ConstBytes;
  using bess::classifier::MaskedRuleResource;
  if (!pdr_ul_.resource || !pdr_ul_.table) return CommandFailure(EINVAL, "not initialised");

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
