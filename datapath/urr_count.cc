// SPDX-License-Identifier: BSD-3-Clause

#include "urr_count.h"

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
#include "utils/ether.h"
#include "utils/ip.h"
#include "utils/time.h"

using bess::utils::be16_t;
using bess::utils::be32_t;

namespace dataplane = bess::dataplane;

enum {
  ATTR_R_ACTION_ID,
};

// The ActionId space of a deployment graph: the ActionTable's capacity, and
// with it the compiler's MaxActions.
constexpr size_t kDefaultCapacity = 65536;

const ResourceTables UrrCount::resource_tables = {
    ResourceTable::Map<upf::pb::CounterKey, upf::pb::CounterEntry>("counters"),
};

const Commands UrrCount::cmds = {
    {"get_counts", "upf.pb.UrrCountCommandGetCountsArg",
     MODULE_CMD_FUNC(&UrrCount::CommandGetCounts), Command::THREAD_SAFE,
     "upf.pb.UrrCountCommandGetCountsResponse"},
};

namespace {

// The IP packet's octets: the IPv4 header's Total Length. The graph carries
// frames -- an Ethernet header the framing adds -- and the volume an SMF
// compares against its own count of the UE's octets must not carry it. A frame
// this cannot read is counted as it is (no rule of this graph selects one).
uint64_t Octets(bess::PacketRef pkt) {
  // The IPv4 header only has to sit in the first segment: a chained frame's
  // header is in the head, which is what `head_len` measures.
  constexpr size_t kHeaders = sizeof(bess::utils::Ethernet) + sizeof(bess::utils::Ipv4);
  if (pkt.head_len() >= kHeaders) {
    const auto *eth = pkt.head_data<const bess::utils::Ethernet *>();
    if (eth->ether_type == be16_t(bess::utils::Ethernet::Type::kIpv4)) {
      const auto *ip =
          pkt.head_data<const bess::utils::Ipv4 *>(sizeof(*eth));
      const uint16_t length = be16_t(ip->length).value();
      if (length >= sizeof(bess::utils::Ipv4) &&
          length <= pkt.total_len() - sizeof(*eth)) {
        return length;
      }
    }
  }
  return pkt.total_len();
}

}  // namespace

CommandResponse UrrCount::Init(const upf::pb::UrrCountArg &arg) {
  capacity_ = arg.capacity() == 0 ? kDefaultCapacity : arg.capacity();
  // A whole number of cache lines per worker, so every plane starts on a line
  // and no two workers share one: capacity x 2 cells, rounded up.
  const size_t cells = capacity_ * kCellsPerRule;
  cells_per_worker_ = (cells + kCellsPerLine - 1) / kCellsPerLine * kCellsPerLine;
  lines_ = std::vector<Line>(static_cast<size_t>(bess::dataplane::kMaxWorkers) *
                             (cells_per_worker_ / kCellsPerLine));
  // One stamp pair per rule: 16 bytes x capacity (1 MiB at the default), and
  // nothing per worker -- the stamps are the rule's own fact.
  stamps_ = std::vector<Stamps>(capacity_);

  entries_ = std::make_unique<dataplane::SlotTable<ActionId, Entry>>(capacity_);
  resource_ = std::make_unique<dataplane::SlotResource<ActionId, Entry>>(
      name() + "/counters", *entries_);

  binding_ = init_context().codecs().Bind(
      *resource_,
      std::make_shared<
          bess::framework::TypedCodec<upf::pb::CounterKey, upf::pb::CounterEntry>>(
          [](const upf::pb::CounterKey &key)
              -> std::expected<dataplane::ResourceKey, std::string> {
            if (key.action_id() == 0) {
              return std::unexpected("action id 0 names no rule");
            }
            return dataplane::EncodeKey(ActionId(key.action_id()));
          },
          [](const upf::pb::CounterEntry &)
              -> std::expected<std::any, std::string> {
            return std::any(Entry{});
          },
          // Every measured rule, as its key names it.
          [this](const auto &visit) {
            for (size_t i = 1; i <= entries_->capacity(); i++) {
              const ActionId id(static_cast<ActionId::rep_type>(i));
              if (entries_->Current(id) == nullptr) {
                continue;
              }
              upf::pb::CounterKey key;
              key.set_action_id(id.value());
              upf::pb::CounterEntry value;
              visit(key, value);
            }
          }));
  if (auto registered = init_context().resources().Register(resource_.get());
      !registered) {
    binding_.Reset();
    resource_.reset();
    return CommandFailure(EEXIST, "%s", registered.error().c_str());
  }

  using AccessMode = bess::metadata::Attribute::AccessMode;
  action_attr_ = AddMetadataAttr("action_id", sizeof(be32_t),
                                 AccessMode::kRead);
  if (action_attr_ < 0) {
    const std::string name = resource_->name();
    CHECK(init_context().resources().Unregister(name));
    binding_.Reset();
    resource_.reset();
    return CommandFailure(-action_attr_, "add_metadata_attr() failed");
  }

  return CommandSuccess();
}

void UrrCount::DeInit() {
  if (resource_ == nullptr) {
    return;
  }
  binding_.Reset();
  const std::string name = resource_->name();
  auto unregistered = init_context().resources().Unregister(name);
  CHECK(unregistered) << unregistered.error();
  resource_.reset();
}

void UrrCount::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  // One offset load per batch: the layout does not change under a batch.
  const auto action_offset = attr_offset(action_attr_);
  // This worker's plane, once per batch rather than once per packet.
  const size_t base = static_cast<size_t>(ctx->wid.value()) * cells_per_worker_;
  gate_idx_t ogates[bess::PacketBatch::kMaxBurst];
  const size_t cnt = batch->cnt();
  // The rules this batch counted, in arrival order and each once: what the
  // stamps are written for, after the loop.
  ActionId counted[bess::PacketBatch::kMaxBurst];
  size_t counted_n = 0;

  for (size_t i = 0; i < cnt; i++) {
    bess::PacketRef pkt = batch->packet(i);
    ogates[i] = 0;  // counting never drops and never diverts a packet

    const be32_t action_id = get_attr_with_offset<be32_t>(action_offset, pkt);
    const ActionId id(action_id.value());
    if (id.value() == 0 || id.value() > capacity_ ||
        entries_->Lookup(id) == nullptr) {
      // No rule, or no URR measuring it: the common case for a deployment
      // whose sessions do not all charge, and the only work this module costs
      // them.
      continue;
    }
    const size_t cell = base + offset_of(id.value());
    Add(cell + kPackets, 1);
    Add(cell + kBytes, Octets(pkt));
    // This batch counted the rule: remember it, once, and stamp it after the
    // loop. The stamps are shared state, so a batch writes them once per rule
    // and never once per packet.
    bool already = false;
    for (size_t j = 0; j < counted_n; j++) {
      if (counted[j].value() == id.value()) {
        already = true;
        break;
      }
    }
    if (!already) {
      counted[counted_n++] = id;
    }
  }

  if (counted_n > 0) {
    // The worker's own loop timestamp (module.h's Context, set from the
    // scheduler's rdtsc): the same monotonic domain the reading reports, and no
    // clock read of this module's own on the packet path.
    const uint64_t now_ns = ctx->current_ns;
    for (size_t j = 0; j < counted_n; j++) {
      Stamps &s = stamps_[counted[j].value() - 1];
      if (s.first_ns.load(std::memory_order_relaxed) == 0) {
        s.first_ns.store(now_ns, std::memory_order_relaxed);
      }
      s.last_ns.store(now_ns, std::memory_order_relaxed);
    }
  }

  EmitBatch(ctx, batch, ogates);
}

std::pair<uint64_t, uint64_t> UrrCount::Counts(ActionId id) const noexcept {
  if (id.value() == 0 || id.value() > capacity_) {
    return {0, 0};
  }
  const size_t offset = offset_of(id.value());
  uint64_t packets = 0;
  uint64_t octets = 0;
  for (size_t w = 0; w < bess::dataplane::kMaxWorkers; w++) {
    const size_t cell = w * cells_per_worker_ + offset;
    packets += lines_[cell / kCellsPerLine].cells[cell % kCellsPerLine].load(
        std::memory_order_relaxed);
    octets += lines_[(cell + kBytes) / kCellsPerLine]
                  .cells[(cell + kBytes) % kCellsPerLine]
                  .load(std::memory_order_relaxed);
  }
  return {packets, octets};
}

std::pair<uint64_t, uint64_t> UrrCount::ReadTimes(ActionId id, bool restart) noexcept {
  if (id.value() == 0 || id.value() > capacity_) {
    return {0, 0};
  }
  Stamps &s = stamps_[id.value() - 1];
  // The first stamp of the next window starts with the next packet: the
  // reporting side clears it in one step, and a diagnostic read only looks.
  const uint64_t first =
      restart ? s.first_ns.exchange(0, std::memory_order_relaxed)
              : s.first_ns.load(std::memory_order_relaxed);
  const uint64_t last = s.last_ns.load(std::memory_order_relaxed);
  return {first, last};
}

CommandResponse UrrCount::CommandGetCounts(
    const upf::pb::UrrCountCommandGetCountsArg &arg) {
  upf::pb::UrrCountCommandGetCountsResponse response;
  // The reading's clock: the stamps below are in this monotonic domain, and the
  // control side places them on the absolute clock a PFCP timestamp carries
  // (TS 29.244 8.2.44, 8.2.45) with the wall clock taken at the same instant.
  struct timeval wall {};
  gettimeofday(&wall, nullptr);
  response.set_read_wall_unix_ns(
      static_cast<uint64_t>(wall.tv_sec) * 1000000000ull +
      static_cast<uint64_t>(wall.tv_usec) * 1000ull);
  response.set_read_monotonic_ns(tsc_to_ns(rdtsc()));
  // Every id asked for is reported, entry or no entry: the cells outlive the
  // entry (the erase keeps them), so the control side can still read a rule's
  // final counts after the transaction that removed it -- which is what a
  // termination report is made of.
  auto report = [&](ActionId id) {
    auto [packets, octets] = Counts(id);
    auto [first_ns, last_ns] = ReadTimes(id, arg.restart_window());
    auto *count = response.add_counts();
    count->set_action_id(id.value());
    count->set_packets(packets);
    count->set_octets(octets);
    count->set_first_packet_ns(first_ns);
    count->set_last_packet_ns(last_ns);
  };

  if (arg.action_ids_size() == 0) {
    // Every rule the table holds: an operator's question, not the reporting
    // side's (which knows the ids it owns and keeps its own baselines).
    for (size_t i = 1; i <= capacity_; i++) {
      const ActionId id(static_cast<ActionId::rep_type>(i));
      if (entries_->Current(id) != nullptr) {
        report(id);
      }
    }
    return CommandSuccess(response);
  }

  for (uint32_t id : arg.action_ids()) {
    report(ActionId(id));
  }
  return CommandSuccess(response);
}

std::string UrrCount::GetDesc() const {
  return std::format("{} rules counted of {}", entries_ == nullptr ? 0 : entries_->size(),
                     capacity_);
}

ADD_MODULE(UrrCount, "urr_count",
           "counts the packets and octets of the rules a URR measures")
