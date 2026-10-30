// SPDX-License-Identifier: BSD-3-Clause

#ifndef UPF_DATAPATH_ATSSS_STEER_H_
#define UPF_DATAPATH_ATSSS_STEER_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include "dataplane/action_id.h"
#include "dataplane/slot_resource.h"
#include "dataplane/slot_table.h"
#include "framework/memory_scope.h"
#include "framework/resource_bindings.h"
#include "module.h"
#include "upf_datapath.pb.h"

// Steers a downlink packet between the two accesses of an ATSSS session: the
// 3GPP access and the non-3GPP access (TS 29.244 7.5.2.8). The PDR matcher
// writes the packet's global policy id into the policy attribute; this module selects the
// access, writes the selected access's Router next hop, tunnel record and
// (optionally) accounting record, and emits the packet on one gate.
//
// The policy is one immutable object in "<name>/policies", keyed by the global
// policy id the compiler allocates for one session's MAR. Its
// two access actions are fixed at programming time, so a packet costs one
// policy lookup and no control-plane relation. Health is a separate table,
// "<name>/health", keyed by access: an access is shared by every policy that
// uses it, and a report updates one entry rather than every policy. A policy
// references its two health records; the transaction engine refuses a health
// erase while a live policy names it.
//
// Selection is active/standby: the preferred access if its health record says
// available, else the other access if it does, else the packet is dropped. A
// missing *policy* is fail-closed. A missing *health* record means "not
// monitored" and counts as available: health is deployment state, not a
// session's, and a deployment that never writes the table must still steer.
// Policy id 0 is the exception -- it means "not steered", and the packet passes
// through with the action table's own next hop and tunnel.
class AtsssSteer final : public Module {
 public:
  static const gate_idx_t kNumOGates = 1;

  using Id = bess::dataplane::ActionId;

  struct AccessAction {
    uint32_t next_hop_id = 0;
    uint32_t tunnel_id = 0;
    uint32_t accounting_id = 0;
    uint32_t health_id = 0;
  };

  struct SteeringPolicy {
    uint8_t mode = 0;       // upf::pb::ATSSS_ACTIVE_STANDBY
    uint32_t preferred = 0; // index into access
    std::array<AccessAction, 2> access{};
  };

  struct AccessHealth {
    bool available = false;
  };

  // "<module>/policies" and "<module>/health".
  static const ResourceTables resource_tables;

  AtsssSteer() : Module() { max_allowed_workers_ = Worker::kMaxWorkers; }

  CommandResponse Init(const upf::pb::AtsssSteerArg &arg);
  void DeInit() override;

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  const SteeringPolicy *LookupPolicy(uint32_t policy_id) const noexcept;
  const AccessHealth *LookupHealth(uint32_t health_id) const noexcept;

 private:
  void RegisterHealth(std::string name);
  void RegisterPolicies(std::string name);

  size_t capacity_ = 0;
  bess::framework::Sized<bess::dataplane::SlotTable<Id, AccessHealth>> health_;
  bess::framework::Sized<bess::dataplane::SlotTable<Id, SteeringPolicy>> policies_;
  std::unique_ptr<bess::dataplane::SlotResource<Id, AccessHealth>> health_res_;
  std::unique_ptr<bess::dataplane::SlotResource<Id, SteeringPolicy>> policy_res_;
  bess::framework::ResourceBinding health_binding_;
  bess::framework::ResourceBinding policy_binding_;  // after its resources (D-044)

  int policy_attr_ = -1;
  int next_hop_attr_ = -1;
  int tunnel_attr_ = -1;
  int accounting_attr_ = -1;
  bool has_tunnel_ = false;
  bool has_accounting_ = false;
};

#endif  // UPF_DATAPATH_ATSSS_STEER_H_
