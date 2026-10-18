// SPDX-License-Identifier: BSD-3-Clause

#include "pdr_match.h"

#include <cstddef>
#include <format>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

// Before every other BESS header: glog must win over protobuf's absl logging
// in this translation unit (docs/plugin-api.md, "Logging").
#include "utils/logging.h"

#include "conntrack/packet_parse.h"
#include "dataplane/resource.h"
#include "dataplane/resource_registry.h"
#include "framework/plugin.h"
#include "framework/resource_codec.h"
#include "utils/endian.h"

using bess::utils::be32_t;

namespace dataplane = bess::dataplane;
namespace pdr_match = upf::pdr_match;

// 0 means "the argument did not say": a session record per slot of a large
// access network (the map is a few tens of bytes per session, and a session's
// rules are the memory that matters).
constexpr size_t kDefaultMaxSessions = 65536;

const ResourceTables PdrMatch::resource_tables = {
    ResourceTable::Map<upf::pb::PdrMatchKey, upf::pb::PdrMatchEntry>("rules"),
    ResourceTable::Singleton<upf::pb::PdrMatchSettings>("settings"),
};

int PdrMatch::AttrIdOf(const std::string &name) const {
  const std::vector<bess::metadata::Attribute> &attrs = all_attrs();
  for (size_t i = 0; i < attrs.size(); i++) {
    if (attrs[i].name == name) {
      return static_cast<int>(i);
    }
  }
  return -1;
}

CommandResponse PdrMatch::Init(const upf::pb::PdrMatchArg &arg) {
  using AccessMode = bess::metadata::Attribute::AccessMode;

  if (arg.key_attr().empty()) {
    return CommandFailure(EINVAL, "the 'key_attr' field is required");
  }
  // The session key is read from the packet's metadata, where the module that
  // owns it wrote it -- the decap, on the uplink. A read-only attribute no
  // module writes has no offset (core/metadata.cc), and a packet then names no
  // session: it is dropped, as a packet whose session the map does not hold is.
  key_attr_ = AddMetadataAttr(arg.key_attr(), sizeof(be32_t), AccessMode::kRead);
  if (key_attr_ < 0) {
    return CommandFailure(-key_attr_, "add_metadata_attr() failed");
  }
  key_attr_name_ = arg.key_attr();

  action_attr_ = AddMetadataAttr("action_id", sizeof(be32_t), AccessMode::kWrite);
  if (action_attr_ < 0) {
    return CommandFailure(-action_attr_, "add_metadata_attr() failed");
  }

  // The QoS flow, as the decap read it out of the PDU Session Container (0 when
  // none was carried): what a rule that names a QFI is matched against. Read
  // only by sessions that have such a rule; declared here so the attribute has
  // an offset when the decap writes it.
  qfi_attr_ = AddMetadataAttr("qfi", sizeof(uint8_t), AccessMode::kRead);
  if (qfi_attr_ < 0) {
    return CommandFailure(-qfi_attr_, "add_metadata_attr() failed");
  }

  const size_t max_sessions =
      arg.max_sessions() == 0 ? kDefaultMaxSessions : arg.max_sessions();
  resource_ = std::make_unique<pdr_match::SessionResource>(name() + "/rules",
                                                           max_sessions);

  // Typed keys and values over the RPC (D-025), so the controller can write a
  // session's rules without generated code for this plugin's protobufs.
  binding_ = init_context().codecs().Bind(
      *resource_,
      std::make_shared<
          bess::framework::TypedCodec<upf::pb::PdrMatchKey,
                                      upf::pb::PdrMatchEntry>>(
          [](const upf::pb::PdrMatchKey &key)
              -> std::expected<dataplane::ResourceKey, std::string> {
            if (key.session() == 0) {
              return std::unexpected("session 0 names no session");
            }
            return dataplane::EncodeKey(key.session());
          },
          [](const upf::pb::PdrMatchEntry &value)
              -> std::expected<std::any, std::string> {
            // The rules are compiled in the resource's Reserve (and the
            // codec's job is the wire shape): what is checked here is what no
            // rule list can say -- the wrong type, which the codec has already
            // refused -- so the entry travels as it arrived, and
            // "<module>/rules" reads back what the controller wrote.
            return std::any(value);
          },
          // Every live session, as its key names it: the rules as given.
          [this](const auto &visit) {
            resource_->ForEach([&visit](uint32_t session,
                                        const pdr_match::Rules &rules) {
              upf::pb::PdrMatchKey key;
              key.set_session(session);
              visit(key, rules.arg);
            });
          }));
  if (auto registered = init_context().resources().Register(resource_.get());
      !registered) {
    binding_.Reset();
    resource_.reset();
    return CommandFailure(EEXIST, "%s", registered.error().c_str());
  }

  LOG(INFO) << name() << ": " << resource_->name() << " over "
            << pdr_match::MatcherName() << ", keyed by '" << arg.key_attr()
            << "', up to " << max_sessions << " sessions";

  // The module's own settings, beside the map. Setting them re-points the
  // packet path at another key attribute; the sessions already written keep
  // their keys.
  auto settings = settings_.Register(
      init_context().resources(), init_context().codecs(), name() + "/settings",
      [this](const upf::pb::PdrMatchSettings &v)
          -> std::expected<Settings, std::string> {
        if (v.key_attr().empty()) {
          return std::unexpected("the 'key_attr' field is required");
        }
        const int id = AttrIdOf(v.key_attr());
        if (id < 0) {
          return std::unexpected(std::format(
              "this module does not read '{}': its key attribute is declared "
              "by the module's own argument, and a graph change is what adds "
              "another",
              v.key_attr()));
        }
        return Settings{id, v.key_attr()};
      },
      [this](Settings &s) {
        key_attr_ = s.attr;
        key_attr_name_ = s.name;
      },
      [this]() {
        upf::pb::PdrMatchSettings v;
        v.set_key_attr(key_attr_name_);
        return v;
      },
      nullptr);
  if (!settings) {
    // The map is registered and bound by now, and a module whose Init returns
    // a failure is not one the graph keeps: leave nothing of it behind, as
    // the registration above does (core/modules/exact_match.cc).
    const std::string map = resource_->name();
    CHECK(init_context().resources().Unregister(map));
    binding_.Reset();
    resource_.reset();
    return CommandFailure(EEXIST, "%s", settings.error().c_str());
  }
  return CommandSuccess();
}

void PdrMatch::DeInit() {
  settings_.Release();
  if (resource_ == nullptr) {
    return;
  }
  binding_.Reset();
  // The rules a session's map holds reference nothing: a rule's action id comes
  // from packet metadata, not from a ledger, so the compiler writes the action
  // record before the rule that names it (docs/design.md, install order).
  const std::string name = resource_->name();
  auto unregistered = init_context().resources().Unregister(name);
  CHECK(unregistered) << unregistered.error();
  resource_.reset();
}

bool PdrMatch::KeyOf(bess::PacketRef pkt, bess::classifier::FirewallKey *key) {
  using bess::classifier::FirewallFamily;
  using bess::conntrack::L3Kind;
  using bess::conntrack::ParseStatus;

  // The frame the graph carries: an Ethernet frame whose payload is the IP
  // packet (the decap replaced the outer headers with a frame around the inner
  // packet). The parse is the conntrack codec's -- the same one the decap and
  // the tunnel library use -- so the two cannot disagree about where a packet's
  // addresses and ports are: up to two VLAN tags, IPv4 with options, IPv6 with
  // its extension headers, and lengths checked against the packet rather than
  // the segment.
  bess::conntrack::ParsedFlowPacket parsed;
  const std::span<const uint8_t> frame(pkt.head_data<const uint8_t *>(),
                                      pkt.head_len());
  const ParseStatus status = bess::conntrack::ParseFrame(frame, parsed,
                                                        pkt.total_len());
  if (status != ParseStatus::kOk && status != ParseStatus::kFragment) {
    return false;
  }
  key->family =
      parsed.l3 == L3Kind::kIpv4 ? FirewallFamily::kIpv4 : FirewallFamily::kIpv6;
  key->proto = parsed.protocol;
  key->src = parsed.src;
  key->dst = parsed.dst;
  key->src_port = parsed.src_port;
  key->dst_port = parsed.dst_port;
  return true;
}

void PdrMatch::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  // One offset load per batch: the layout does not change under a batch.
  const bess::metadata::mt_offset_t key_offset = attr_offset(key_attr_);
  const bess::metadata::mt_offset_t action_offset = attr_offset(action_attr_);
  const bool key_valid = bess::metadata::IsValidOffset(key_offset);
  // D-141: the ActionId a matching rule names goes to the packet's "action_id",
  // which the meter, the counter and the ActionTable downstream read. The
  // offset is valid only when something reads the attribute; with no reader
  // there is nothing to resolve the action for, and nothing to write.
  const bool publish_action = bess::metadata::IsValidOffset(action_offset);
  // The QFI is read only for a session that has a rule naming one; with no
  // writer the attribute has no offset and a packet is of no QFI (0), which
  // no rule names.
  const bess::metadata::mt_offset_t qfi_offset = attr_offset(qfi_attr_);
  const bool qfi_valid = bess::metadata::IsValidOffset(qfi_offset);

  gate_idx_t ogates[bess::PacketBatch::kMaxBurst];
  const size_t cnt = batch->cnt();

  for (size_t i = 0; i < cnt; i++) {
    bess::PacketRef pkt = batch->packet(i);
    ogates[i] = DROP_GATE;

    // The session first: a packet whose key names one the map does not hold is
    // not this module's to match, and its rules are what the match is against.
    // One acquire load; nullptr covers an unknown session and an attribute the
    // graph wrote nowhere.
    const pdr_match::Rules *rules = nullptr;
    if (key_valid) [[likely]] {
      const be32_t session = get_attr_with_offset<be32_t>(key_offset, pkt);
      rules = resource_->Lookup(session.value());
    }
    if (rules == nullptr) [[unlikely]] {
      continue;
    }

    bess::classifier::FirewallKey key;
    bess::classifier::FirewallTable::Match match;
    // The rules this packet can match: the session's list for its QFI where
    // some rule names it, else the rules that name none.
    const pdr_match::QfiRules *list = &rules->any;
    if (!rules->named.empty()) [[unlikely]] {
      const uint8_t qfi =
          qfi_valid ? get_attr_with_offset<uint8_t>(qfi_offset, pkt) : 0;
      for (const auto &[q, named] : rules->named) {
        if (q == qfi) {
          list = &named;
          break;
        }
      }
    }
    // The family first: a session whose rules name no rule for this packet's
    // family cannot match it, and saying so costs no lookup.
    if (not KeyOf(pkt, &key) ||
        not list->matcher->HasFamily(key.family) ||
        not list->matcher->Lookup(key, &match)) [[unlikely]] {
      continue;
    }
    if (match.action == pdr_match::kDrop) [[unlikely]] {
      continue;  // the PDR's FAR drops: the rule is the whole result
    }

    if (publish_action) {
      // rule_id is 1-based, in the list the packet was matched against.
      const uint32_t id = list->action_ids[match.rule_id - 1];
      _set_attr_with_offset<be32_t>(action_offset, pkt, be32_t(id));
    }
    ogates[i] = 0;
  }

  // One call for the batch; a dropped packet costs the drop and nothing else
  // (core/module.h:EmitBatch).
  EmitBatch(ctx, batch, ogates);
}

std::string PdrMatch::GetDesc() const {
  return std::format("{} sessions, key '{}'",
                     resource_ == nullptr ? 0 : resource_->LiveCount(),
                     key_attr_name_);
}

ADD_MODULE(PdrMatch, "pdr_match",
           "matches a packet against its session's PDR rules (one map key per "
           "session, the action id carried on)")
