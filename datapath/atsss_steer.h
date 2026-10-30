// SPDX-License-Identifier: BSD-3-Clause

#ifndef UPF_DATAPATH_ATSSS_STEER_H_
#define UPF_DATAPATH_ATSSS_STEER_H_

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include "atsss_select.h"
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
// Selection is upf::atsss::Steer (atsss_select.h, which states the rule),
// shared with UpfAppliance: active/standby by health, fail-closed on a missing
// policy, and policy id 0 passes through unsteered.
class AtsssSteer final : public Module {
 public:
  static const gate_idx_t kNumOGates = 1;

  using Id = bess::dataplane::ActionId;

  // "<module>/policies" and "<module>/health".
  static const ResourceTables resource_tables;

  AtsssSteer() : Module() { max_allowed_workers_ = Worker::kMaxWorkers; }

  CommandResponse Init(const upf::pb::AtsssSteerArg &arg);
  void DeInit() override;

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  const upf::atsss::SteeringPolicy *LookupPolicy(uint32_t policy_id) const noexcept;
  const upf::atsss::AccessHealth *LookupHealth(uint32_t health_id) const noexcept;

 private:
  void RegisterHealth(std::string name);
  void RegisterPolicies(std::string name);

  size_t capacity_ = 0;
  bess::framework::Sized<bess::dataplane::SlotTable<Id, upf::atsss::AccessHealth>> health_;
  bess::framework::Sized<bess::dataplane::SlotTable<Id, upf::atsss::SteeringPolicy>> policies_;
  std::unique_ptr<bess::dataplane::SlotResource<Id, upf::atsss::AccessHealth>> health_res_;
  std::unique_ptr<bess::dataplane::SlotResource<Id, upf::atsss::SteeringPolicy>> policy_res_;
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
