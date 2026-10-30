// SPDX-License-Identifier: BSD-3-Clause

#include "atsss_steer.h"

#include <format>
#include <string>
#include <utility>
#include <vector>

// Before every other BESS header: glog must win over protobuf's absl logging
// in this translation unit (docs/plugin-api.md, "Logging").
#include "utils/logging.h"

#include "dataplane/resource.h"
#include "dataplane/resource_registry.h"
#include "framework/plugin.h"
#include "framework/resource_codec.h"
#include "utils/endian.h"

using bess::utils::be32_t;
using upf::atsss::AccessAction;
using upf::atsss::AccessHealth;
using upf::atsss::SteeringPolicy;

namespace dataplane = bess::dataplane;

constexpr size_t kDefaultCapacity = 65536;

const ResourceTables AtsssSteer::resource_tables = {
    ResourceTable::Map<upf::pb::AtsssSteeringPolicyKey,
                       upf::pb::AtsssSteeringPolicy>("policies"),
    ResourceTable::Map<upf::pb::AtsssAccessHealthKey,
                       upf::pb::AtsssAccessHealth>("health"),
};

namespace {

std::expected<dataplane::ResourceKey, std::string> HealthKey(
    const upf::pb::AtsssAccessHealthKey &key) {
  if (key.health_id() == 0) {
    return std::unexpected("health id 0 names no access");
  }
  return dataplane::EncodeKey(AtsssSteer::Id(key.health_id()));
}

std::expected<std::any, std::string> HealthValue(
    const upf::pb::AtsssAccessHealth &value) {
  return std::any(AccessHealth{.available = value.available()});
}

std::expected<std::any, std::string> PolicyValue(
    const upf::pb::AtsssSteeringPolicy &value) {
  if (value.mode() != upf::pb::ATSSS_ACTIVE_STANDBY) {
    return std::unexpected(std::format(
        "steering mode {} is not supported (only active/standby)", static_cast<int>(value.mode())));
  }
  if (value.access_size() != 2) {
    return std::unexpected(std::format(
        "a policy has two accesses, the message has {}", value.access_size()));
  }
  if (value.preferred() > 1) {
    return std::unexpected("'preferred' must be 0 or 1");
  }
  SteeringPolicy policy;
  policy.mode = static_cast<uint8_t>(value.mode());
  policy.preferred = value.preferred();
  for (int i = 0; i < value.access_size(); i++) {
    const auto &in = value.access(i);
    if (in.next_hop_id() == 0 && in.health_id() == 0) {
      // An access the SMF did not provision (active/standby allows one
      // access and no standby): the selection loop skips it.
      policy.access[static_cast<size_t>(i)] = AccessAction{};
      continue;
    }
    if (in.next_hop_id() == 0) {
      return std::unexpected(std::format(
          "access {} names next hop 0, which no Router resolves", i));
    }
    if (in.health_id() == 0) {
      return std::unexpected(std::format(
          "access {} names health id 0, which no access record answers", i));
    }
    policy.access[static_cast<size_t>(i)] = AccessAction{
        .next_hop_id = in.next_hop_id(),
        .tunnel_id = in.tunnel_id(),
        .accounting_id = in.accounting_id(),
        .health_id = in.health_id(),
    };
  }
  return std::any(policy);
}

}  // namespace

const SteeringPolicy *AtsssSteer::LookupPolicy(
    uint32_t policy_id) const noexcept {
  return policies_ ? policies_->Lookup(Id(policy_id)) : nullptr;
}

const AccessHealth *AtsssSteer::LookupHealth(
    uint32_t health_id) const noexcept {
  return health_ ? health_->Lookup(Id(health_id)) : nullptr;
}

CommandResponse AtsssSteer::Init(const upf::pb::AtsssSteerArg &arg) {
  capacity_ = arg.capacity() == 0 ? kDefaultCapacity : arg.capacity();
  if (arg.policy_attr().empty()) {
    return CommandFailure(EINVAL, "the 'policy_attr' field is required");
  }
  if (arg.next_hop_attr().empty()) {
    return CommandFailure(EINVAL, "the 'next_hop_attr' field is required");
  }
  if (arg.policy_attr() == arg.next_hop_attr() ||
      (!arg.tunnel_attr().empty() &&
       (arg.tunnel_attr() == arg.policy_attr() ||
        arg.tunnel_attr() == arg.next_hop_attr())) ||
      (!arg.accounting_attr().empty() &&
       (arg.accounting_attr() == arg.policy_attr() ||
        arg.accounting_attr() == arg.next_hop_attr() ||
        arg.accounting_attr() == arg.tunnel_attr()))) {
    return CommandFailure(EINVAL, "the metadata attribute names are not distinct");
  }

  // Both tables are admitted and made before either is registered (D-198):
  // a refusal throws utils::MemoryRefused, Init answers RESOURCE_EXHAUSTED,
  // and nothing is registered yet.
  auto &memory = init_context().memory();
  health_ = memory.Create<dataplane::SlotTable<Id, AccessHealth>>("health",
                                                                 capacity_);
  policies_ = memory.Create<dataplane::SlotTable<Id, SteeringPolicy>>(
      "policies", capacity_);

  // Health first: a policy references it, and the transaction engine orders a
  // referrer after its referent.
  health_res_ = std::make_unique<dataplane::SlotResource<Id, AccessHealth>>(
      name() + "/health", *health_);
  health_binding_ = init_context().codecs().Bind(
      *health_res_,
      std::make_shared<bess::framework::TypedCodec<
          upf::pb::AtsssAccessHealthKey, upf::pb::AtsssAccessHealth>>(
          HealthKey, HealthValue, [this](const auto &visit) {
            for (size_t i = 1; i <= health_->capacity(); i++) {
              const Id id(static_cast<Id::rep_type>(i));
              const AccessHealth *entry = health_->Current(id);
              if (entry == nullptr) {
                continue;
              }
              upf::pb::AtsssAccessHealthKey key;
              key.set_health_id(id.value());
              upf::pb::AtsssAccessHealth value;
              value.set_available(entry->available);
              visit(key, value);
            }
          }));
  if (auto registered = init_context().resources().Register(health_res_.get());
      !registered) {
    health_binding_.Reset();
    health_res_.reset();
    health_.reset();
    policies_.reset();
    return CommandFailure(EEXIST, "%s", registered.error().c_str());
  }

  // A policy does not reference its health records: the health table is
  // deployment state, not part of a session's transaction, and a record that
  // is absent means "not monitored" rather than "unusable" -- otherwise a
  // deployment that never writes the table would drop every steered packet.
  policy_res_ =
      std::make_unique<dataplane::SlotResource<Id, SteeringPolicy>>(
          name() + "/policies", *policies_);
  policy_binding_ = init_context().codecs().Bind(
      *policy_res_,
      std::make_shared<bess::framework::TypedCodec<
          upf::pb::AtsssSteeringPolicyKey, upf::pb::AtsssSteeringPolicy>>(
          [](const upf::pb::AtsssSteeringPolicyKey &key)
              -> std::expected<dataplane::ResourceKey, std::string> {
            if (key.policy_id() == 0) {
              return std::unexpected("policy id 0 names no policy");
            }
            return dataplane::EncodeKey(Id(key.policy_id()));
          },
          PolicyValue, [this](const auto &visit) {
            for (size_t i = 1; i <= policies_->capacity(); i++) {
              const Id id(static_cast<Id::rep_type>(i));
              const SteeringPolicy *entry = policies_->Current(id);
              if (entry == nullptr) {
                continue;
              }
              upf::pb::AtsssSteeringPolicyKey key;
              key.set_policy_id(id.value());
              upf::pb::AtsssSteeringPolicy value;
              value.set_mode(
                  static_cast<upf::pb::AtsssSteeringMode>(entry->mode));
              value.set_preferred(entry->preferred);
              for (const AccessAction &access : entry->access) {
                auto *out = value.add_access();
                out->set_next_hop_id(access.next_hop_id);
                out->set_tunnel_id(access.tunnel_id);
                out->set_accounting_id(access.accounting_id);
                out->set_health_id(access.health_id);
              }
              visit(key, value);
            }
          }));
  if (auto registered = init_context().resources().Register(policy_res_.get());
      !registered) {
    policy_binding_.Reset();
    policy_res_.reset();
    policies_.reset();
    const std::string health_name = health_res_->name();
    health_binding_.Reset();
    CHECK(init_context().resources().Unregister(health_name));
    health_res_.reset();
    health_.reset();
    return CommandFailure(EEXIST, "%s", registered.error().c_str());
  }

  using AccessMode = bess::metadata::Attribute::AccessMode;
  policy_attr_ = AddMetadataAttr(arg.policy_attr(), sizeof(be32_t),
                                AccessMode::kRead);
  // kUpdate, not kWrite: the ActionTable upstream has already written this
  // attribute for a non-MAR packet. A kWrite here would start a new metadata
  // scope and cut that writer off, so the ActionTable would drop every packet
  // before steering ran.
  next_hop_attr_ = AddMetadataAttr(arg.next_hop_attr(), sizeof(be32_t),
                                  AccessMode::kUpdate);
  has_tunnel_ = !arg.tunnel_attr().empty();
  has_accounting_ = !arg.accounting_attr().empty();
  if (has_tunnel_) {
    tunnel_attr_ = AddMetadataAttr(arg.tunnel_attr(), sizeof(be32_t),
                                  AccessMode::kWrite);
  }
  if (has_accounting_) {
    accounting_attr_ = AddMetadataAttr(arg.accounting_attr(), sizeof(be32_t),
                                      AccessMode::kWrite);
  }
  int error = 0;
  if (policy_attr_ < 0) {
    error = policy_attr_;
  } else if (next_hop_attr_ < 0) {
    error = next_hop_attr_;
  } else if (has_tunnel_ && tunnel_attr_ < 0) {
    error = tunnel_attr_;
  } else if (has_accounting_ && accounting_attr_ < 0) {
    error = accounting_attr_;
  }
  if (error != 0) {
    DeInit();
    return CommandFailure(-error, "add_metadata_attr() failed");
  }

  return CommandSuccess();
}

void AtsssSteer::DeInit() {
  if (policy_res_ != nullptr) {
    policy_binding_.Reset();
    const std::string policy_name = policy_res_->name();
    auto unregistered = init_context().resources().Unregister(policy_name);
    CHECK(unregistered) << unregistered.error();
    policy_res_.reset();
    policies_.reset();
  }
  if (health_res_ != nullptr) {
    health_binding_.Reset();
    const std::string health_name = health_res_->name();
    auto unregistered = init_context().resources().Unregister(health_name);
    CHECK(unregistered) << unregistered.error();
    health_res_.reset();
    health_.reset();
  }
}

void AtsssSteer::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  const auto policy_offset = attr_offset(policy_attr_);
  const auto hop_offset = attr_offset(next_hop_attr_);
  const auto tunnel_offset =
      has_tunnel_ ? attr_offset(tunnel_attr_) : -1;
  const auto accounting_offset =
      has_accounting_ ? attr_offset(accounting_attr_) : -1;
  if (!bess::metadata::IsValidOffset(policy_offset) ||
      !bess::metadata::IsValidOffset(hop_offset)) {
    for (bess::PacketRef pkt : batch->packets()) {
      EmitPacket(ctx, pkt, DROP_GATE);
    }
    return;
  }

  gate_idx_t ogates[bess::PacketBatch::kMaxBurst];
  for (int i = 0; i < batch->cnt(); i++) {
    bess::PacketRef pkt = batch->packet(i);
    ogates[i] = DROP_GATE;
    const upf::atsss::Steering steering = upf::atsss::Steer(
        get_attr_with_offset<be32_t>(policy_offset, pkt).value(),
        [this](uint32_t id) { return LookupPolicy(id); },
        [this](uint32_t id) { return LookupHealth(id); });
    switch (steering.verdict) {
      case upf::atsss::SteerVerdict::kNotSteered:
        // The action table's next hop and tunnel stand. Clear the override
        // sentinels explicitly: packet metadata is reused storage, and a zero
        // tunnel id is what makes GtpuEncap fall back to action_id.
        if (bess::metadata::IsValidOffset(tunnel_offset)) {
          _set_attr_with_offset<be32_t>(tunnel_offset, pkt, be32_t(0));
        }
        if (bess::metadata::IsValidOffset(accounting_offset)) {
          _set_attr_with_offset<be32_t>(accounting_offset, pkt, be32_t(0));
        }
        ogates[i] = 0;
        break;
      case upf::atsss::SteerVerdict::kSteered:
        _set_attr_with_offset<be32_t>(hop_offset, pkt,
                                      be32_t(steering.access->next_hop_id));
        if (bess::metadata::IsValidOffset(tunnel_offset)) {
          _set_attr_with_offset<be32_t>(tunnel_offset, pkt,
                                        be32_t(steering.access->tunnel_id));
        }
        if (bess::metadata::IsValidOffset(accounting_offset)) {
          _set_attr_with_offset<be32_t>(accounting_offset, pkt,
                                        be32_t(steering.access->accounting_id));
        }
        ogates[i] = 0;
        break;
      case upf::atsss::SteerVerdict::kNoPolicy:
      case upf::atsss::SteerVerdict::kNoAccess:
        break;  // ogates[i] stays DROP_GATE
    }
  }
  EmitBatch(ctx, batch, ogates);
}

ADD_MODULE(AtsssSteer, "atsss_steer",
           "steers a packet between two accesses by MAR policy and health")
