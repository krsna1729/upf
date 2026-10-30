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
#include "meter/meter_resource_codec.h"
#include "utils/endian.h"
#include <format>
#include "utils/ip.h"
#include "utils/time.h"

namespace dataplane = bess::dataplane;
namespace {
using namespace upf::appliance;
using upf::atsss::AccessHealth;
using upf::atsss::AccessAction;
using upf::atsss::SteeringPolicy;
using Error = std::pair<int, std::string>;
bool DecodeFieldData(const bess::pb::FieldData &data, int field_size,
                     std::vector<uint8_t> *out, const char *what, size_t idx,
                     Error *err) {
  const size_t want = static_cast<size_t>(field_size);
  out->assign(want, 0);
  if (data.encoding_case() == bess::pb::FieldData::kValueBin) {
    const std::string &bin = data.value_bin();
    if (bin.size() > want) {
      *err = std::make_pair(
          EINVAL,
          std::format("idx {}: {} is {} bytes, field is {}", idx,
                              what, bin.size(), want));
      return false;
    }
    std::memcpy(out->data(), bin.data(), bin.size());
    return true;
  }
  uint64_t value = data.value_int();
  if (!bess::utils::uint64_to_bin(out->data(), value, field_size,
                                  /*big_endian=*/true)) {
    *err = std::make_pair(EINVAL,
                          std::format("idx {}: not a correct {}-byte {}",
                                              idx, field_size, what));
    return false;
  }
  return true;
}
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
    policy.access[static_cast<size_t>(i)] = AccessAction{
        .next_hop_id = in.next_hop_id(),
        .tunnel_id = in.tunnel_id(),
        .accounting_id = in.accounting_id(),
        .health_id = in.health_id(),
    };
  }
  return std::any(policy);
}
std::vector<size_t> Widths(bool dl) {
  return dl ? std::vector<size_t>{4,4,1,2,2,4,4,1}
            : std::vector<size_t>{4,4,1,2,2,4,1};
}
std::expected<dataplane::ResourceKey, std::string> PdrKey(
    const bess::pb::WildcardMatchRuleKey &key, bool dl) {
  const auto widths = Widths(dl);
  if (key.values_size() != static_cast<int>(widths.size()) ||
      key.masks_size() != static_cast<int>(widths.size()))
    return std::unexpected("incorrect number of PDR values or masks");
  std::vector<std::byte> value, mask;
  std::vector<size_t> offsets;
  for (size_t i = 0; i < widths.size(); ++i) {
    offsets.push_back(value.size());
    std::vector<uint8_t> v, m;
    Error error;
    if (!DecodeFieldData(key.values(i), widths[i], &v, "field", i, &error) ||
        !DecodeFieldData(key.masks(i), widths[i], &m, "field", i, &error))
      return std::unexpected(error.second);
    for (size_t j = 0; j < widths[i]; ++j) {
      if ((v[j] & static_cast<uint8_t>(~m[j])) != 0)
        return std::unexpected("invalid pair of value and mask");
      value.push_back(std::byte(v[j])); mask.push_back(std::byte(m[j]));
    }
  }
  std::vector<bool> ranged(widths.size(), false);
  std::vector<bess::classifier::ConcurrentMaskedTable::KeyRange> ranges;
  for (const auto &r : key.ranges()) {
    const size_t f = r.field();
    if (f >= widths.size() || ranged[f])
      return std::unexpected("invalid or duplicate range field");
    ranged[f] = true;
    const uint64_t max = (uint64_t{1} << (8 * widths[f])) - 1;
    if (r.low() > r.high() || r.high() > max)
      return std::unexpected("range is empty or wider than its field");
    for (size_t j = 0; j < widths[f]; ++j)
      if (mask[offsets[f] + j] != std::byte{0})
        return std::unexpected("range field has a nonzero mask");
    if (r.low() == 0 && r.high() == max) continue;
    ranges.push_back({static_cast<uint32_t>(offsets[f]),
                      static_cast<uint32_t>(widths[f]), r.low(), r.high()});
  }
  std::ranges::sort(ranges, {}, &bess::classifier::ConcurrentMaskedTable::KeyRange::offset);
  return bess::classifier::MaskedRuleResource::Key(mask, value, ranges);
}
uint32_t Read32(const std::vector<std::byte> &v, size_t off) {
  uint32_t n = 0;
  for (size_t i = off; i < off + 4; ++i)
    n = (n << 8) | (i < v.size() ? std::to_integer<uint8_t>(v[i]) : 0);
  return n;
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
  bindings_.push_back( init_context().codecs().Bind(
      *fteid_resource_,
      std::make_shared<bess::framework::TypedCodec<
          upf::pb::FteidKey, upf::pb::FteidEntry>>(
          [](const upf::pb::FteidKey &key)
              -> std::expected<dataplane::ResourceKey, std::string> {
            if (key.endpoint_id() == 0 || key.teid() == 0)
              return std::unexpected("endpoint_id and teid must be nonzero");
            const size_t bytes = key.address_family() == 4 ? 4 :
                                 key.address_family() == 6 ? 16 : 0;
            if (bytes == 0 || key.local_address().size() != bytes)
              return std::unexpected("local_address length must match family 4 or 6");
            upf::datapath::FteidId id{};
            id[0] = static_cast<uint8_t>(key.endpoint_id() >> 24);
            id[1] = static_cast<uint8_t>(key.endpoint_id() >> 16);
            id[2] = static_cast<uint8_t>(key.endpoint_id() >> 8);
            id[3] = static_cast<uint8_t>(key.endpoint_id());
            id[4] = static_cast<uint8_t>(key.address_family());
            std::memcpy(id.data() + (bytes == 4 ? 17 : 5),
                        key.local_address().data(), bytes);
            id[21] = static_cast<uint8_t>(key.teid() >> 24);
            id[22] = static_cast<uint8_t>(key.teid() >> 16);
            id[23] = static_cast<uint8_t>(key.teid() >> 8);
            id[24] = static_cast<uint8_t>(key.teid());
            return dataplane::EncodeKey(id);
          },
          [](const upf::pb::FteidEntry &value)
              -> std::expected<std::any, std::string> {
            if (value.direction() > 1)
              return std::unexpected("direction must be 0 (UL) or 1 (DL)");
            if (value.context_id() == 0)
              return std::unexpected("context_id must be nonzero");
            return std::any(upf::datapath::FteidRecord{
                static_cast<uint8_t>(value.direction()), value.context_id()});
          },
          [this](const auto &visit) {
            fteid_resource_->ForEach([&visit](const upf::datapath::FteidId &id,
                                         const upf::datapath::FteidRecord &record) {
              upf::pb::FteidKey key;
              const uint32_t endpoint = uint32_t{id[0]} << 24 |
                                        uint32_t{id[1]} << 16 |
                                        uint32_t{id[2]} << 8 | id[3];
              const uint32_t teid = uint32_t{id[21]} << 24 |
                                    uint32_t{id[22]} << 16 |
                                    uint32_t{id[23]} << 8 | id[24];
              key.set_endpoint_id(endpoint);
              key.set_address_family(id[4]);
              key.set_teid(teid);
              const size_t off = id[4] == 4 ? 17 : 5;
              key.set_local_address(
                  reinterpret_cast<const char *>(id.data() + off),
                  id[4] == 4 ? 4 : 16);
              upf::pb::FteidEntry value;
              value.set_direction(record.direction);
              value.set_context_id(record.context_id);
              visit(key, value);
            });
          })));
  if (auto r = enroll(fteid_resource_.get()); !r)
    return CommandFailure(EEXIST, "%s", r.error().c_str());
  const size_t meter_capacity = arg.meter().capacity() ? arg.meter().capacity() : 65536;
  auto meter_lease = memory.LeaseFor<bess::meter::MeterResource>("meters", meter_capacity);
  auto meter = std::make_unique<bess::meter::MeterResource>(
      name() + "/meters", meter_capacity, meter_set_, meter_lease.growth());
  meters_ = bess::framework::MemoryScope::Adopt(std::move(meter_lease), std::move(meter));
  bindings_.push_back(init_context().codecs().Bind(*meters_, bess::meter::MakeMeterResourceCodec(*meters_)));
  if (auto r = enroll(meters_.get()); !r)
    return CommandFailure(EEXIST, "%s", r.error().c_str());
  auto init_pdr = [&](Pdr &pdr, const char *table_name, bool dl, size_t tuples)
      -> std::expected<void, std::string> {
    using Table = bess::classifier::ConcurrentMaskedTable;
    using Resource = bess::classifier::MaskedRuleResource;
    const size_t key_len = dl ? 22 : 18;
    const size_t record_size = dl ? 24 : 20;
    pdr.table_lease = memory.LeaseFor<Table>(table_name, static_cast<uint32_t>(key_len), tuples, init_context().rcu());
    auto table = Table::Create(key_len, tuples, init_context().rcu());
    if (!table) return std::unexpected(table.error());
    // Retire callbacks can retain the table beyond teardown; its admission
    // must travel with that final owner, as in WildcardMatch.
    auto table_owner = std::make_shared<bess::framework::Sized<Table>>(
        bess::framework::MemoryScope::Adopt(std::move(pdr.table_lease), std::move(*table)));
    Table *table_raw = table_owner->get();
    pdr.table = std::shared_ptr<Table>(std::move(table_owner), table_raw);
    pdr.records_lease = memory.LeaseFor<bess::classifier::RecordArena>(
        std::string(table_name) + "_results", record_size, init_context().rcu());
    auto records_owner = std::make_shared<bess::framework::Sized<bess::classifier::RecordArena>>(
        bess::framework::MemoryScope::Adopt(std::move(pdr.records_lease),
          std::make_unique<bess::classifier::RecordArena>(record_size, init_context().rcu())));
    auto *records_raw = records_owner->get();
    pdr.records = std::shared_ptr<bess::classifier::RecordArena>(std::move(records_owner), records_raw);
    auto check = [record_size](const Resource::Value &v) -> Resource::Result {
      if (!bess::IsValidGateValue(v.gate)) return std::unexpected("invalid gate");
      if (v.result.size() > record_size) return std::unexpected("PDR result too large");
      return {};
    };
    pdr.resource = std::make_unique<Resource>(name() + "/" + table_name, Resource::Hooks{
      .table = [&pdr] { return pdr.table; },
      .check_value = check,
      .references = [this](const Resource::Value &v) {
        std::vector<dataplane::Reference> refs;
        for (size_t offset : {size_t{4}, size_t{8}, size_t{12}}) {
          const uint32_t id = Read32(v.result, offset);
          if (id) refs.push_back({name() + (offset == 12 ? "/next_hops" : "/meters"),
                                 dataplane::EncodeKey(Id(id))});
        }
        return refs;
      },
      .records = pdr.records,
      .may_reference = {name() + "/meters", name() + "/next_hops"}});
    bindings_.push_back(init_context().codecs().Bind(*pdr.resource,
      std::make_shared<bess::framework::TypedCodec<bess::pb::WildcardMatchRuleKey, bess::pb::WildcardMatchRuleValue>>(
        [dl](const auto &key) { return PdrKey(key, dl); },
        [check](const bess::pb::WildcardMatchRuleValue &v) -> std::expected<std::any, std::string> {
          if (!bess::IsValidGateValue(v.gate())) return std::unexpected("invalid gate");
          Resource::Value value{v.priority(), static_cast<uint16_t>(v.gate()),
            std::vector<std::byte>(reinterpret_cast<const std::byte *>(v.result().data()),
                                  reinterpret_cast<const std::byte *>(v.result().data()) + v.result().size())};
          if (auto ok = check(value); !ok) return std::unexpected(ok.error());
          return std::any(std::move(value));
        },
        [&pdr, dl](const auto &visit) {
          const auto widths = Widths(dl);
          pdr.table->ForEach([&](auto mask, auto bytes, const auto &r, auto ranges) {
            bess::pb::WildcardMatchRuleKey key;
            bess::pb::WildcardMatchRuleValue value;
            size_t pos = 0;
            auto range = ranges.begin();
            for (size_t i = 0; i < widths.size(); ++i) {
              key.add_values()->set_value_bin(reinterpret_cast<const char *>(bytes.data() + pos), widths[i]);
              key.add_masks()->set_value_bin(reinterpret_cast<const char *>(mask.data() + pos), widths[i]);
              if (range != ranges.end() && range->offset == pos) {
                auto *out = key.add_ranges();
                out->set_field(i); out->set_low(range->low); out->set_high(range->high); ++range;
              }
              pos += widths[i];
            }
            value.set_priority(r.priority); value.set_gate(r.gate);
            const auto record = pdr.records->Lookup(r.result_id);
            value.set_result(reinterpret_cast<const char *>(record.data()), record.size());
            visit(key, value);
          });
        })));
    return enroll(pdr.resource.get());
  };
  if (auto r = init_pdr(pdr_ul_, "pdr_ul", false, arg.pdr_ul().max_tuples() ? arg.pdr_ul().max_tuples() : 16); !r)
    return CommandFailure(EINVAL, "%s", r.error().c_str());
  if (auto r = init_pdr(pdr_dl_, "pdr_dl", true, arg.pdr_dl().max_tuples() ? arg.pdr_dl().max_tuples() : 8); !r)
    return CommandFailure(EINVAL, "%s", r.error().c_str());
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
  for (auto pair : {std::pair{&counters_ul_, "counters_ul"},
                    std::pair{&counters_dl_, "counters_dl"},
                    std::pair{&buffer_counters_, "buffer_counters"}})
    if (auto r = init_counter(*pair.first, pair.second); !r)
      return CommandFailure(EEXIST, "%s", r.error().c_str());
  tunnels_ = memory.Create<dataplane::SlotTable<Id, Tunnel>>("tunnels", arg.encap().max_tunnels() ? arg.encap().max_tunnels() : 65536);
  tunnel_resource_ = std::make_unique<dataplane::SlotResource<Id, Tunnel>>(
      name() + "/tunnels", *tunnels_);
  bindings_.push_back( init_context().codecs().Bind(
      *tunnel_resource_,
      std::make_shared<bess::framework::TypedCodec<upf::pb::TunnelKey,
                                                    upf::pb::TunnelEntry>>(
          [](const upf::pb::TunnelKey &key)
              -> std::expected<dataplane::ResourceKey, std::string> {
            if (key.action_id() == 0)
              return std::unexpected("action id 0 names no tunnel");
            return dataplane::EncodeKey(Id(key.action_id()));
          },
          [](const upf::pb::TunnelEntry &value)
              -> std::expected<std::any, std::string> {
            if (value.teid() == 0)
              return std::unexpected("the 'teid' field is required");
            const size_t length = value.local_address().size();
            if ((length != 4 && length != 16) ||
                value.peer_address().size() != length)
              return std::unexpected("local_address and peer_address must both be 4 or 16 bytes");
            if (value.qfi() > 63)
              return std::unexpected("invalid 'qfi' field");
            if (!value.qfi_present() && value.qfi() != 0)
              return std::unexpected("qfi must be zero when qfi_present is false");
            if (value.marking() > 0xffff)
              return std::unexpected("invalid 'marking' field");
            Tunnel tunnel{};
            tunnel.teid = value.teid();
            tunnel.family = length == 4 ? 4 : 6;
            const size_t offset = length == 4 ? 12 : 0;
            std::memcpy(tunnel.local + offset, value.local_address().data(), length);
            std::memcpy(tunnel.peer + offset, value.peer_address().data(), length);
            if (std::all_of(tunnel.local, tunnel.local + 16,
                            [](uint8_t byte) { return byte == 0; }) ||
                std::all_of(tunnel.peer, tunnel.peer + 16,
                            [](uint8_t byte) { return byte == 0; }))
              return std::unexpected("tunnel addresses must not be unspecified");
            tunnel.transport_route_domain = value.transport_route_domain();
            tunnel.qfi = static_cast<uint8_t>(value.qfi());
            tunnel.has_qfi = value.qfi_present();
            tunnel.marking = static_cast<uint16_t>(value.marking());
            return std::any(tunnel);
          },
          [this](const auto &visit) {
            for (size_t i = 1; i <= tunnels_->capacity(); ++i) {
              const Id id(static_cast<Id::rep_type>(i));
              const Tunnel *tunnel = tunnels_->Current(id);
              if (tunnel == nullptr) continue;
              upf::pb::TunnelKey key;
              key.set_action_id(id.value());
              upf::pb::TunnelEntry value;
              value.set_teid(tunnel->teid);
              const size_t offset = tunnel->family == 4 ? 12 : 0;
              const size_t length = tunnel->family == 4 ? 4 : 16;
              value.set_local_address(
                  reinterpret_cast<const char *>(tunnel->local + offset), length);
              value.set_peer_address(
                  reinterpret_cast<const char *>(tunnel->peer + offset), length);
              value.set_qfi(tunnel->qfi);
              value.set_qfi_present(tunnel->has_qfi);
              value.set_marking(tunnel->marking);
              value.set_transport_route_domain(tunnel->transport_route_domain);
              visit(key, value);
            }
          })));
  if (auto r = enroll(tunnel_resource_.get()); !r) return CommandFailure(EEXIST, "%s", r.error().c_str());
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
        for (const auto &a : p.access) {
          if (a.next_hop_id) refs.push_back({name() + "/next_hops", dataplane::EncodeKey(Id(a.next_hop_id))});
          if (a.tunnel_id) refs.push_back({name() + "/tunnels", dataplane::EncodeKey(Id(a.tunnel_id))});
        }
        return refs;
      }, std::vector<std::string>{name() + "/next_hops", name() + "/tunnels"});
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
  pdr_ul_.resource.reset(); pdr_dl_.resource.reset();
  pdr_ul_.table.reset(); pdr_dl_.table.reset();
  pdr_ul_.records.reset(); pdr_dl_.records.reset();
  pdr_ul_.table_lease.reset(); pdr_dl_.table_lease.reset();
  pdr_ul_.records_lease.reset(); pdr_dl_.records_lease.reset();
  policy_resource_.reset(); health_resource_.reset(); tunnel_resource_.reset();
  policies_.reset(); health_.reset(); tunnels_.reset();
  for (auto *bank : {&counters_ul_, &counters_dl_, &buffer_counters_}) {
    bank->resource.reset(); bank->entries.reset(); bank->cells.reset();
    bank->stamps = {}; bank->stamps_lease.reset();
  }
  fteid_resource_.reset(); fteids_.reset(); entries_.reset();
  meters_.reset(); errors_.reset(); end_markers_.reset();
}

CommandResponse UpfAppliance::CommandGetCounts(const upf::pb::UrrCountCommandGetCountsArg &arg) {
  upf::appliance::Counters *bank = nullptr;
  if (arg.table() == "counters_ul") bank = &counters_ul_;
  else if (arg.table() == "counters_dl") bank = &counters_dl_;
  else if (arg.table() == "buffer_counters") bank = &buffer_counters_;
  else return CommandFailure(EINVAL, "table must be counters_ul, counters_dl, or buffer_counters");
  upf::pb::UrrCountCommandGetCountsResponse response;
  struct timeval wall {};
  gettimeofday(&wall, nullptr);
  response.set_read_wall_unix_ns(static_cast<uint64_t>(wall.tv_sec) * 1000000000ull + static_cast<uint64_t>(wall.tv_usec) * 1000ull);
  response.set_read_monotonic_ns(tsc_to_ns(rdtsc()));
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
