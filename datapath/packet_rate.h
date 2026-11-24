// SPDX-License-Identifier: BSD-3-Clause

#ifndef UPF_DATAPATH_PACKET_RATE_H_
#define UPF_DATAPATH_PACKET_RATE_H_

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include "dataplane/slot_resource.h"
#include "dataplane/slot_table.h"
#include "dataplane/strong_id.h"
#include "framework/memory_scope.h"
#include "framework/resource_bindings.h"
#include "module.h"
#include "packet_rate_quota.h"
#include "upf_datapath.pb.h"
#include "utils/dpdk_memory.h"

struct PacketRateIdTag;
using PacketRateId = bess::dataplane::StrongId<PacketRateIdTag, uint32_t>;

// Enforces a QER's Packet Rate (TS 29.244 8.2.63): the primary maximum and
// the additional maximum, each over its own time unit, plus the CP's seeded
// Packet Rate Status (8.2.139) as 5.4.15.2 rule 4 orders.
//
// The module sits in a chain behind the PDR table. The classifier result's
// `packet_rate_id` names the quota for the packet's QER and direction; 0 (the
// common case) is one load and no lookup, so a deployment without packet-rate
// control pays almost nothing. `get_status` answers the remaining counts and
// their validity for the Query Packet Rate Status exchange (7.5.5.4) and the
// release report (5.4.15.2 rule 3).
//
// Memory: the quotas' immutable configs are a SlotTable, and the mutable
// window state is one fixed array, both admitted through
// init_context().memory() (D-198).
class PacketRate final : public Module {
 public:
  static const gate_idx_t kNumOGates = 1;

  struct Entry {
    upf::datapath::PacketRateConfig config;
  };

  static const ResourceTables resource_tables;

  PacketRate() : Module() {}

  CommandResponse Init(const upf::pb::PacketRateArg &arg);
  void DeInit() override;

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  CommandResponse CommandGetStatus(
      const upf::pb::PacketRateCommandGetStatusArg &arg);

  static const Commands cmds;

  std::string GetDesc() const override;

 private:
  size_t capacity_ = 0;

  bess::framework::Sized<bess::dataplane::SlotTable<PacketRateId, Entry>>
      entries_;
  std::unique_ptr<bess::dataplane::SlotResource<PacketRateId, Entry>>
      resource_;
  bess::framework::ResourceBinding binding_;  // after resource_ (D-044)
  int rate_attr_ = -1;                        // "packet_rate_id"

  // One quota's mutable windows, indexed by id - 1. Admitted as
  // "quota_states" (D-198); by value, so the packet path indexes it directly.
  bess::framework::MemoryLease states_lease_;
  bess::utils::DpdkArray<upf::datapath::PacketRateQuota> states_;
};

#endif  // UPF_DATAPATH_PACKET_RATE_H_
