// SPDX-License-Identifier: BSD-3-Clause

#ifndef UPF_DATAPATH_GTPU_ENCAP_H_
#define UPF_DATAPATH_GTPU_ENCAP_H_

#include <memory>

#include "dataplane/action_id.h"
#include "dataplane/slot_resource.h"
#include "dataplane/slot_table.h"
#include "framework/resource_bindings.h"
#include "module.h"
#include "upf_datapath.pb.h"
#include "utils/ether.h"

// Builds outer IPv4 or IPv6 GTP-U headers; routing and L2 rewrite are
// downstream responsibilities.

class GtpuEncap final : public Module {
 public:
  static const gate_idx_t kNumOGates = 1;
  using ActionId = bess::dataplane::ActionId;
  static const ResourceTables resource_tables;

  struct Tunnel {
    uint32_t teid;
    uint8_t family;
    uint8_t local[16];
    uint8_t peer[16];
    uint32_t transport_route_domain;
    uint8_t qfi;
    uint16_t marking;
    bool has_qfi;
  };

  GtpuEncap() : Module() { max_allowed_workers_ = Worker::kMaxWorkers; }
  CommandResponse Init(const upf::pb::GtpuEncapArg &arg);
  void DeInit() override;
  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;
  std::string GetDesc() const override;
  const Tunnel *LookupTunnel(ActionId id) const noexcept {
    return id.value() == 0 ? nullptr : tunnels_->Lookup(id);
  }

 private:
  uint16_t src_port_ = 0;
  uint16_t dst_port_ = 0;
  int action_attr_ = -1;
  int tunnel_attr_ = -1;
  int domain_attr_ = -1;
  bool has_tunnel_ = false;
  std::unique_ptr<bess::dataplane::SlotTable<ActionId, Tunnel>> tunnels_;
  std::unique_ptr<bess::dataplane::SlotResource<ActionId, Tunnel>> resource_;
  bess::framework::ResourceBinding binding_;
};

#endif  // UPF_DATAPATH_GTPU_ENCAP_H_
