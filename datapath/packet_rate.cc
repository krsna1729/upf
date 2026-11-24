// SPDX-License-Identifier: BSD-3-Clause

#include "packet_rate.h"

#include <sys/time.h>

#include <format>
#include <string>

// Before every other BESS header: glog must win over protobuf's absl logging
// in this translation unit (docs/plugin-api.md, "Logging").
#include "utils/logging.h"

#include "commands.h"
#include "dataplane/resource.h"
#include "dataplane/resource_registry.h"
#include "framework/plugin.h"
#include "framework/resource_codec.h"
#include "utils/endian.h"
#include "utils/time.h"

using bess::utils::be32_t;

namespace dataplane = bess::dataplane;

enum {
  ATTR_R_PACKET_RATE_ID,
};

// The id space the controller allocates packet-rate quotas from: the same
// bound as the meter tables, since a quota id is one QER direction's.
constexpr size_t kDefaultCapacity = 65536;

// 8.2.63's longest time unit is a week.
constexpr uint32_t kMaxPeriodSeconds = 604800;
constexpr uint64_t kNsPerSecond = 1000000000ull;

const ResourceTables PacketRate::resource_tables = {
    ResourceTable::Map<upf::pb::PacketRateKey, upf::pb::PacketRateValue>(
        "rates"),
};

const Commands PacketRate::cmds = {
    {"get_status", "upf.pb.PacketRateCommandGetStatusArg",
     MODULE_CMD_FUNC(&PacketRate::CommandGetStatus), Command::THREAD_SAFE,
     "upf.pb.PacketRateCommandGetStatusResponse"},
};

CommandResponse PacketRate::Init(const upf::pb::PacketRateArg &arg) {
  capacity_ = arg.capacity() == 0 ? kDefaultCapacity : arg.capacity();
  // Every allocation below is admitted first (D-198): a refusal throws
  // utils::MemoryRefused, Init answers RESOURCE_EXHAUSTED, and the module's
  // destruction frees and releases what was already made.
  auto &memory = init_context().memory();
  entries_ =
      memory.Create<dataplane::SlotTable<PacketRateId, Entry>>("rates",
                                                                capacity_);
  resource_ = std::make_unique<dataplane::SlotResource<PacketRateId, Entry>>(
      name() + "/rates", *entries_);

  binding_ = init_context().codecs().Bind(
      *resource_,
      std::make_shared<
          bess::framework::TypedCodec<upf::pb::PacketRateKey,
                                      upf::pb::PacketRateValue>>(
          [](const upf::pb::PacketRateKey &key)
              -> std::expected<dataplane::ResourceKey, std::string> {
            if (key.id() == 0) {
              return std::unexpected("packet-rate id 0 is invalid");
            }
            return dataplane::EncodeKey(
                PacketRateId(static_cast<uint32_t>(key.id())));
          },
          [](const upf::pb::PacketRateValue &value)
              -> std::expected<std::any, std::string> {
            if (value.allowed() == 0 && value.additional() == 0) {
              return std::unexpected("a quota with no packet rate");
            }
            // 8.2.63's APRC bits add a rate beyond a maximum; there is no
            // maximum here for it to extend.
            if (value.additional() > 0 && value.allowed() == 0) {
              return std::unexpected(
                  "an additional rate without a maximum packet rate");
            }
            if (value.allowed() > 0 && value.period_seconds() == 0) {
              return std::unexpected("a packet rate without a time unit");
            }
            if (value.additional() > 0 &&
                value.additional_period_seconds() == 0) {
              return std::unexpected(
                  "an additional rate without its time unit");
            }
            if (value.period_seconds() > kMaxPeriodSeconds ||
                value.additional_period_seconds() > kMaxPeriodSeconds) {
              return std::unexpected("a time unit longer than a week");
            }
            if (value.seed_remaining() + value.seed_remaining_additional() >
                    0 &&
                value.seed_validity_unix_ns() == 0) {
              return std::unexpected(
                  "a status seed without a validity time");
            }
            Entry entry;
            entry.config.allowed = value.allowed();
            entry.config.primary_period_ns =
                static_cast<uint64_t>(value.period_seconds()) * kNsPerSecond;
            entry.config.additional = value.additional();
            entry.config.additional_period_ns =
                static_cast<uint64_t>(value.additional_period_seconds()) *
                kNsPerSecond;
            entry.config.epoch = value.epoch();
            entry.config.seed_remaining = value.seed_remaining();
            entry.config.seed_remaining_additional =
                value.seed_remaining_additional();
            entry.config.seed_validity_unix_ns =
                value.seed_validity_unix_ns();
            return std::any(entry);
          },
          // Every live quota, as its key names it.
          [this](const auto &visit) {
            for (size_t i = 1; i <= entries_->capacity(); i++) {
              const PacketRateId id(
                  static_cast<PacketRateId::rep_type>(i));
              if (entries_->Current(id) == nullptr) {
                continue;
              }
              upf::pb::PacketRateKey key;
              key.set_id(static_cast<uint32_t>(id.value()));
              upf::pb::PacketRateValue value;
              const Entry *entry = entries_->Current(id);
              value.set_allowed(entry->config.allowed);
              value.set_period_seconds(static_cast<uint32_t>(
                  entry->config.primary_period_ns / kNsPerSecond));
              value.set_additional(entry->config.additional);
              value.set_additional_period_seconds(static_cast<uint32_t>(
                  entry->config.additional_period_ns / kNsPerSecond));
              value.set_epoch(entry->config.epoch);
              value.set_seed_remaining(entry->config.seed_remaining);
              value.set_seed_remaining_additional(
                  entry->config.seed_remaining_additional);
              value.set_seed_validity_unix_ns(
                  entry->config.seed_validity_unix_ns);
              visit(key, value);
            }
          }));
  if (auto registered = init_context().resources().Register(resource_.get());
      !registered) {
    binding_.Reset();
    resource_.reset();
    return CommandFailure(EEXIST, "%s", registered.error().c_str());
  }

  // One quota state per id, nothing per worker: the windows are the quota's
  // own, and workers share them under the quota's flag (packet_rate_quota.h).
  states_lease_ = memory.Lease(
      "quota_states",
      bess::utils::DpdkArray<upf::datapath::PacketRateQuota>::Bytes(
          capacity_, memory.socket()));
  states_ = bess::utils::DpdkArray<upf::datapath::PacketRateQuota>(
      capacity_, memory.socket());
  states_lease_.Track(states_);

  using AccessMode = bess::metadata::Attribute::AccessMode;
  rate_attr_ =
      AddMetadataAttr("packet_rate_id", sizeof(be32_t), AccessMode::kRead);
  if (rate_attr_ < 0) {
    const std::string name = resource_->name();
    CHECK(init_context().resources().Unregister(name));
    binding_.Reset();
    resource_.reset();
    return CommandFailure(-rate_attr_, "add_metadata_attr() failed");
  }

  return CommandSuccess();
}

void PacketRate::DeInit() {
  if (resource_ == nullptr) {
    return;
  }
  binding_.Reset();
  const std::string name = resource_->name();
  auto unregistered = init_context().resources().Unregister(name);
  CHECK(unregistered) << unregistered.error();
  resource_.reset();
}

void PacketRate::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  const auto rate_offset = attr_offset(rate_attr_);
  const uint64_t now_ns = ctx->current_ns;
  gate_idx_t ogates[bess::PacketBatch::kMaxBurst];
  const size_t cnt = batch->cnt();

  for (size_t i = 0; i < cnt; i++) {
    bess::PacketRef pkt = batch->packet(i);
    ogates[i] = 0;

    const be32_t raw = get_attr_with_offset<be32_t>(rate_offset, pkt);
    const uint32_t id = raw.value();
    // A packet whose QER carries no packet rate names no quota: the common
    // case, and the only work it costs.
    if (id == 0 || id > capacity_) {
      continue;
    }
    const PacketRateId rid(static_cast<PacketRateId::rep_type>(id));
    const Entry *entry = entries_->Lookup(rid);
    if (entry == nullptr) {
      continue;
    }
    if (states_[id - 1].Check(entry->config, now_ns) ==
        upf::datapath::PacketRateQuota::Verdict::kDrop) {
      ogates[i] = DROP_GATE;
    }
  }

  EmitBatch(ctx, batch, ogates);
}

CommandResponse PacketRate::CommandGetStatus(
    const upf::pb::PacketRateCommandGetStatusArg &arg) {
  upf::pb::PacketRateCommandGetStatusResponse response;
  // The reading's clock: the controller places the remaining validity on the
  // absolute clock a PFCP timestamp carries.
  struct timeval wall {};
  gettimeofday(&wall, nullptr);
  const uint64_t wall_unix_ns =
      static_cast<uint64_t>(wall.tv_sec) * 1000000000ull +
      static_cast<uint64_t>(wall.tv_usec) * 1000ull;
  const uint64_t now_ns = tsc_to_ns(rdtsc());
  response.set_read_wall_unix_ns(wall_unix_ns);
  response.set_read_monotonic_ns(now_ns);

  auto report = [&](uint32_t id) {
    upf::pb::PacketRateStatus *status = response.add_rates();
    status->set_id(id);
    if (id == 0 || id > capacity_) {
      return;
    }
    const PacketRateId rid(static_cast<PacketRateId::rep_type>(id));
    const Entry *entry = entries_->Lookup(rid);
    if (entry == nullptr) {
      return;
    }
    const auto reading =
        states_[id - 1].Status(entry->config, now_ns, wall_unix_ns);
    status->set_remaining(reading.remaining);
    status->set_remaining_additional(reading.remaining_additional);
    status->set_validity_unix_ns(reading.validity_unix_ns);
    status->set_used(reading.used);
    status->set_used_additional(reading.used_additional);
  };

  if (arg.ids_size() == 0) {
    for (size_t i = 1; i <= capacity_; i++) {
      const PacketRateId id(static_cast<PacketRateId::rep_type>(i));
      if (entries_->Current(id) != nullptr) {
        report(static_cast<uint32_t>(i));
      }
    }
    return CommandSuccess(response);
  }
  for (uint32_t id : arg.ids()) {
    report(id);
  }
  return CommandSuccess(response);
}

std::string PacketRate::GetDesc() const {
  return std::format("{} quotas of {}", entries_ ? entries_->size() : 0,
                     capacity_);
}

ADD_MODULE(PacketRate, "packet_rate",
           "enforces a QER's packet rate and reports its remaining allowance")
