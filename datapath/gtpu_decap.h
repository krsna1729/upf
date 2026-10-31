// SPDX-License-Identifier: BSD-3-Clause

#ifndef UPF_DATAPATH_GTPU_DECAP_H_
#define UPF_DATAPATH_GTPU_DECAP_H_

#include <cstddef>
#include "flow/shared_exact_index.h"
#include "fteid_resource.h"
#include <memory>

#include "dataplane/resource.h"
#include "framework/resource_bindings.h"
#include "module.h"
#include "upf_datapath.pb.h"

// Strips outer Ethernet/IP/UDP/GTP-U headers after endpoint-scoped admission.
// The selected local endpoint and TEID are written to metadata; no payload is
// copied. An End Marker on an admitted F-TEID is relayed out gate 3 through
// the tunnels its entry names, one new frame each.
class GtpuDecap final : public Module {
 public:
  static const gate_idx_t kNumOGates = 4;

  static const ResourceTables resource_tables;


  GtpuDecap() : Module() { max_allowed_workers_ = Worker::kMaxWorkers; }

  CommandResponse Init(const upf::pb::GtpuDecapArg &arg);
  void DeInit() override;

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  std::string GetDesc() const override;

 private:
  uint16_t port_ = 0;
  int context_attr_ = -1;
  int qfi_attr_ = -1;
  int endpoint_attr_ = -1;
  int domain_attr_ = -1;  // transport_route_domain, written on the relays
  std::unique_ptr<upf::datapath::FteidResource> resource_;
  std::unique_ptr<bess::flow::SharedExactIndex> fteid_table_;
  size_t max_fteids_ = 0;
  bess::framework::ResourceBinding binding_;
};

#endif  // UPF_DATAPATH_GTPU_DECAP_H_
