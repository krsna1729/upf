// SPDX-License-Identifier: BSD-3-Clause

#ifndef UPF_DATAPATH_GTPU_DECAP_H_
#define UPF_DATAPATH_GTPU_DECAP_H_

#include <cstdint>

#include "module.h"
#include "upf_datapath.pb.h"

// Strips the outer Ethernet/IPv4-or-IPv6/UDP/GTP-U headers after checking them
// through the tunnel library (M19, D-069): the GTP version and P bit, the
// message type (G-PDU only), the optional fields and the extension chain, and
// the inner packet's presence. A packet that does not check is dropped.
//
// It writes one metadata attribute:
//
//   upf_teid   4 bytes, write   the tunnel endpoint identifier of the G-PDU
//
// The TEID is what the controller keys the session on (the PDR's F-TEID), and
// what the encapsulation side puts back into the outer header.
class GtpuDecap final : public Module {
 public:
  GtpuDecap() : Module() { max_allowed_workers_ = Worker::kMaxWorkers; }

  CommandResponse Init(const upf::pb::GtpuDecapArg &arg);

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

 private:
  // The UDP port a G-PDU must arrive on. DecapGtpu compares it exactly (the
  // graph's classification has already decided the packet is GTP-U, but the
  // codec still checks), so 0 in the argument means the standard 2152.
  uint16_t port_ = 0;
};

#endif  // UPF_DATAPATH_GTPU_DECAP_H_
