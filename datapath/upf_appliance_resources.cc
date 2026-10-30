// SPDX-License-Identifier: BSD-3-Clause
#include "upf_appliance.h"
#include <algorithm>
#include <any>
#include <cerrno>
#include <cstring>
#include <format>
#include <limits>
#include <sys/time.h>
#include "commands.h"
#include "dataplane/resource_registry.h"
#include "framework/resource_codec.h"
#include "utils/endian.h"
#include "utils/ip.h"
#include "utils/time.h"

namespace dataplane = bess::dataplane;
namespace {
using namespace upf::appliance;
using upf::atsss::AccessHealth;
using upf::atsss::AccessAction;
using upf::atsss::SteeringPolicy;
std::expected<dataplane::ResourceKey, std::string> HealthKey(
    const upf::pb::AtsssAccessHealthKey &key) {
  if (key.health_id() == 0) {
    return std::unexpected("health id 0 names no access");
  }
  return dataplane::EncodeKey(Id(key.health_id()));
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
    // Session-local 1-based action position; zero retains the PDR action.
    // Existence is checked in the matched session by the encap lane.
    if (in.tunnel_id() > SessionResource::kMaxActions)
      return std::unexpected(std::format("access {} tunnel selector exceeds {}", i, SessionResource::kMaxActions));
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

CommandResponse UpfAppliance::InitResources(const upf::pb::UpfApplianceArg &arg) {
  auto &memory = init_context().memory();
  capacity_ = arg.counters().capacity() ? arg.counters().capacity() : 65536;
  const size_t planes = arg.counters().worker_planes() ? arg.counters().worker_planes()
                                                     : dataplane::kMaxWorkers;
  if (planes > dataplane::kMaxWorkers)
    return CommandFailure(EINVAL, "worker_planes exceeds maximum");
  if (arg.meter().levels() != 0 && arg.meter().levels() != 2)
    return CommandFailure(EINVAL, "meter levels must be 2");
  // Session-major layout: QERs and tunnels live in each session's stride.
  if (arg.meter().capacity() != 0 || arg.encap().max_tunnels() != 0)
    return CommandFailure(EINVAL, "the session layout sizes QERs and tunnels per session "
                                  "(session.max_qers/max_actions): meter.capacity and "
                                  "encap.max_tunnels must be 0");
  const SessionResource::Limits limits{
      .capacity = arg.session().capacity() ? arg.session().capacity() : 65536,
      .max_actions = arg.session().max_actions() ? arg.session().max_actions() : 4,
      .max_qers = arg.session().max_qers() ? arg.session().max_qers() : 4};
  if (limits.max_actions > SessionResource::kMaxActions || limits.max_qers > 255 ||
      limits.capacity > (std::numeric_limits<uint32_t>::max() >> SessionResource::kActionBits))
    return CommandFailure(EINVAL, "session capacity, max_actions (1..8) or max_qers (0..255) out of range");
  const size_t fteid_capacity = arg.decap().max_fteids() ? arg.decap().max_fteids() : 65536;
  if (fteid_capacity > std::numeric_limits<uint32_t>::max() / 2)
    return CommandFailure(EINVAL, "max_fteids exceeds exact-index limits");
  if (arg.decap().port() > 65535 || arg.encap().src_port() > 65535 ||
      arg.encap().dst_port() > 65535)
    return CommandFailure(EINVAL, "invalid UDP port");
  port_ = arg.decap().port() ? arg.decap().port() : 2152;
  src_port_ = arg.encap().src_port();
  dst_port_ = arg.encap().dst_port() ? arg.encap().dst_port() : 2152;
  auto enroll = [this](dataplane::Resource *r) -> std::expected<void, std::string> {
    auto result = init_context().resources().Register(r);
    if (!result) return std::unexpected(result.error());
    registered_.push_back(r->name());
    return {};
  };
  fteids_ = memory.Create<bess::flow::SharedExactIndex>(
      "fteids", static_cast<uint32_t>(sizeof(upf::datapath::FteidId)),
      fteid_capacity, init_context().rcu(), memory.socket());
  fteid_resource_ = memory.Create<upf::datapath::FteidResource>(
      "fteid_records", name() + "/fteids", *fteids_, init_context().rcu(), fteid_capacity);
  // The PDR tables stay lookup structures; a rule's result id names its
  // session and action, which the session resource writes.
  using Table = bess::classifier::ConcurrentMaskedTable;
  auto make_table = [&](const char *table_name, uint32_t key_len, size_t tuples)
      -> std::expected<Sized<Table>, std::string> {
    auto lease = memory.LeaseFor<Table>(table_name, key_len, tuples, init_context().rcu());
    auto table = Table::Create(key_len, tuples, init_context().rcu());
    if (!table) return std::unexpected(table.error());
    return bess::framework::MemoryScope::Adopt(std::move(lease), std::move(*table));
  };
  auto ul = make_table("pdr_ul", 18, arg.pdr_ul().max_tuples() ? arg.pdr_ul().max_tuples() : 16);
  if (!ul) return CommandFailure(EINVAL, "%s", ul.error().c_str());
  pdr_ul_ = std::move(*ul);
  auto dl = make_table("pdr_dl", 22, arg.pdr_dl().max_tuples() ? arg.pdr_dl().max_tuples() : 8);
  if (!dl) return CommandFailure(EINVAL, "%s", dl.error().c_str());
  pdr_dl_ = std::move(*dl);
  auto session_lease = memory.Lease("sessions", SessionResource::Bytes(limits),
                                    SessionResource::GlibcBytes(limits));
  sessions_ = bess::framework::MemoryScope::Adopt(
      std::move(session_lease),
      std::make_unique<SessionResource>(name() + "/sessions", name() + "/next_hops", limits,
                                        *pdr_ul_, *pdr_dl_, *fteid_resource_,
                                        [this] { return HasRunningWorker(); }));
  bindings_.push_back(init_context().codecs().Bind(
      *sessions_,
      std::make_shared<bess::framework::TypedCodec<upf::pb::UpfSessionKey, upf::pb::UpfSession>>(
          [](const upf::pb::UpfSessionKey &key) -> std::expected<dataplane::ResourceKey, std::string> {
            if (key.session_id() == 0) return std::unexpected("session id 0 names no session");
            return dataplane::EncodeKey(key.session_id());
          },
          [](const upf::pb::UpfSession &value) -> std::expected<std::any, std::string> {
            auto decoded = DecodeSession(value);
            if (!decoded) return std::unexpected(decoded.error());
            return std::any(std::move(*decoded));
          },
          [this](const auto &visit) {
            sessions_->ForEachLive([&visit](uint32_t id, const upf::pb::UpfSession &value) {
              upf::pb::UpfSessionKey key;
              key.set_session_id(id);
              visit(key, value);
            });
          })));
  if (auto r = enroll(sessions_.get()); !r)
    return CommandFailure(EEXIST, "%s", r.error().c_str());
  auto init_counter = [&](Counters &bank, const char *table) -> std::expected<void, std::string> {
    bank.cells = memory.Create<bess::stats::KeyedCounters>(std::string(table) + "_cells", capacity_, 2, planes);
    bank.stamps_lease = memory.Lease(std::string(table) + "_stamps", bess::utils::DpdkArray<Stamps>::Bytes(capacity_, memory.socket()));
    bank.stamps = bess::utils::DpdkArray<Stamps>(capacity_, memory.socket());
    bank.stamps_lease.Track(bank.stamps);
    bank.entries = memory.Create<dataplane::SlotTable<Id, CounterEntry>>(table, capacity_);
    bank.resource = std::make_unique<dataplane::SlotResource<Id, CounterEntry>>(name() + "/" + table, *bank.entries);
    bindings_.push_back(init_context().codecs().Bind(*bank.resource,
      std::make_shared<bess::framework::TypedCodec<upf::pb::CounterKey, upf::pb::CounterEntry>>(
        [](const upf::pb::CounterKey &key) -> std::expected<dataplane::ResourceKey, std::string> {
          if (!key.action_id()) return std::unexpected("action id 0 names no rule");
          return dataplane::EncodeKey(Id(key.action_id()));
        },
        [](const upf::pb::CounterEntry &) -> std::expected<std::any, std::string> { return std::any(CounterEntry{}); },
        [&bank](const auto &visit) {
          for (size_t i = 1; i <= bank.entries->capacity(); ++i) {
            const Id id(static_cast<Id::rep_type>(i));
            if (!bank.entries->Current(id)) continue;
            upf::pb::CounterKey key; key.set_action_id(i);
            visit(key, upf::pb::CounterEntry{});
          }
        })));
    return enroll(bank.resource.get());
  };
  if (auto r = init_counter(buffer_counters_, "buffer_counters"); !r)
    return CommandFailure(EEXIST, "%s", r.error().c_str());
  const size_t atsss_capacity = arg.atsss().capacity() ? arg.atsss().capacity() : 65536;
  health_ = memory.Create<dataplane::SlotTable<Id, AccessHealth>>("health", atsss_capacity);
  policies_ = memory.Create<dataplane::SlotTable<Id, SteeringPolicy>>("policies", atsss_capacity);
  health_resource_ = std::make_unique<dataplane::SlotResource<Id, AccessHealth>>(
      name() + "/health", *health_);
  bindings_.push_back( init_context().codecs().Bind(
      *health_resource_,
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
          })));
  if (auto r = enroll(health_resource_.get()); !r) return CommandFailure(EEXIST, "%s", r.error().c_str());
  policy_resource_ = std::make_unique<dataplane::SlotResource<Id, SteeringPolicy>>(
      name() + "/policies", *policies_, [this](const SteeringPolicy &p) {
        std::vector<dataplane::Reference> refs;
        for (const auto &a : p.access)
          if (a.next_hop_id) refs.push_back({name() + "/next_hops", dataplane::EncodeKey(Id(a.next_hop_id))});
        return refs;
      }, std::vector<std::string>{name() + "/next_hops"});
  bindings_.push_back( init_context().codecs().Bind(
      *policy_resource_,
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
          })));
  if (auto r = enroll(policy_resource_.get()); !r) return CommandFailure(EEXIST, "%s", r.error().c_str());
  entries_ = memory.Create<upf::arp::EntriesResource>("entries", name() + "/entries", arg.arp().max_entries() ? arg.arp().max_entries() : 65536);
  bindings_.push_back( init_context().codecs().Bind(
      *entries_,
      std::make_shared<bess::framework::TypedCodec<
          upf::pb::UpfArpResponderEntryKey, upf::pb::UpfArpResponderEntryValue>>(
          [](const upf::pb::UpfArpResponderEntryKey &key)
              -> std::expected<dataplane::ResourceKey, std::string> {
            bess::utils::be32_t ip;
            if (key.ip().empty()) {
              return std::unexpected("IP address is missing");
            }
            if (!bess::utils::ParseIpv4Address(key.ip(), &ip)) {
              return std::unexpected("Invalid IP address: " + key.ip());
            }
            if (ip.value() == 0) {
              return std::unexpected("0.0.0.0 names no subscriber address");
            }
            return dataplane::EncodeKey(ip.value());
          },
          [](const upf::pb::UpfArpResponderEntryValue &value)
              -> std::expected<std::any, std::string> {
            bess::utils::Ethernet::Address mac;
            if (!mac.FromString(value.mac_addr())) {
              return std::unexpected("Invalid MAC address: " + value.mac_addr());
            }
            return std::any(mac);
          },
          // Read back as a client writes an entry: the address in dotted
          // decimal, the MAC in lower case.
          [this](const auto &visit) {
            entries_->ForEach([&visit](const upf::arp::Entry &entry) {
              upf::pb::UpfArpResponderEntryKey key;
              key.set_ip(bess::utils::ToIpv4Address(
                  bess::utils::be32_t(entry.ip)));
              upf::pb::UpfArpResponderEntryValue value;
              value.set_mac_addr(entry.mac.ToString());
              visit(key, value);
            });
          })));
  if (auto r = enroll(entries_.get()); !r) return CommandFailure(EEXIST, "%s", r.error().c_str());
  errors_ = memory.Create<upf::datapath::GtpuErrorCounts>("errors", upf::datapath::GtpuErrorCounts::kDefaultSlots);
  end_markers_ = memory.Create<upf::datapath::EndMarkerLog>("end_markers", dataplane::kMaxWorkers);
  return CommandSuccess();
}

void UpfAppliance::ReleaseResources() {
  if (!registered_.empty()) {
    auto released = init_context().resources().ReleaseForTeardown(registered_);
    CHECK(released) << released.error();
    registered_.clear();
  }
  for (auto &binding : bindings_) binding.Reset();
  bindings_.clear();
  // The session store before the tables and F-TEID index it drives.
  sessions_.reset();
  pdr_ul_.reset(); pdr_dl_.reset();
  policy_resource_.reset(); health_resource_.reset();
  policies_.reset(); health_.reset();
  buffer_counters_.resource.reset(); buffer_counters_.entries.reset(); buffer_counters_.cells.reset();
  buffer_counters_.stamps = {}; buffer_counters_.stamps_lease.reset();
  fteid_resource_.reset(); fteids_.reset(); entries_.reset();
  errors_.reset(); end_markers_.reset();
}

CommandResponse UpfAppliance::CommandGetCounts(const upf::pb::UrrCountCommandGetCountsArg &arg) {
  const bool session_bank = arg.table() == "counters_ul" || arg.table() == "counters_dl";
  if (!session_bank && arg.table() != "buffer_counters")
    return CommandFailure(EINVAL, "table must be counters_ul, counters_dl, or buffer_counters");
  upf::appliance::Counters *bank = &buffer_counters_;
  upf::pb::UrrCountCommandGetCountsResponse response;
  struct timeval wall {};
  gettimeofday(&wall, nullptr);
  response.set_read_wall_unix_ns(static_cast<uint64_t>(wall.tv_sec) * 1000000000ull + static_cast<uint64_t>(wall.tv_usec) * 1000ull);
  response.set_read_monotonic_ns(tsc_to_ns(rdtsc()));
  if (session_bank) {
    // The URR cells live in the sessions' strides.
    sessions_->Counts(arg.table() == "counters_dl",
                      std::span<const uint32_t>(arg.action_ids().data(), arg.action_ids_size()),
                      arg.restart_window(), &response);
    return CommandSuccess(response);
  }
  auto report = [&](uint32_t id) {
    auto *count = response.add_counts();
    count->set_action_id(id);
    if (!id || id > capacity_) return;
    // Plane by plane, the pair a worker added together (UrrCount::Counts).
    uint64_t packets = 0, octets = 0;
    for (size_t w = 0; w < bank->cells->workers(); ++w) {
      const bess::dataplane::WorkerId worker(static_cast<uint16_t>(w));
      packets += bank->cells->Read(worker, id - 1, 0);
      octets += bank->cells->Read(worker, id - 1, 1);
    }
    count->set_packets(packets);
    count->set_octets(octets);
    auto &stamp = bank->stamps[id - 1];
    count->set_first_packet_ns(arg.restart_window() ? stamp.first.exchange(0, std::memory_order_relaxed) : stamp.first.load(std::memory_order_relaxed));
    count->set_last_packet_ns(stamp.last.load(std::memory_order_relaxed));
  };
  if (arg.action_ids_size() == 0) {
    for (size_t i = 1; i <= capacity_; ++i)
      if (bank->entries->Current(Id(static_cast<Id::rep_type>(i)))) report(i);
  } else {
    for (uint32_t id : arg.action_ids()) report(id);
  }
  return CommandSuccess(response);
}
