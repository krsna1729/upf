// SPDX-License-Identifier: BSD-3-Clause

#ifndef UPF_DATAPATH_GTPU_ENCAP_H_
#define UPF_DATAPATH_GTPU_ENCAP_H_

#include "module.h"
#include "upf_datapath.pb.h"

// Writes the outer Ethernet/IPv4/UDP/GTP-U headers of a G-PDU in front of the
// inner IP packet, through the tunnel library (M19, D-069). A packet whose
// session metadata is not set, or that has no headroom, is dropped: a packet
// that cannot be tunnelled must not go out unencapsulated.
//
// It reads four metadata attributes, two of them BESS's own:
//
//   ether_src   6 bytes, read   the outer Ethernet source (the N3 interface)
//   ether_dst   6 bytes, read   the outer Ethernet destination (the gNB)
//   upf_teid    4 bytes, read   the tunnel endpoint identifier (0: no session)
//   upf_gnb_ip  4 bytes, read   the gNB's outer IPv4 address (0: unresolved)
//
// The outer IPv4 source address and the UDP ports are the graph's, so they are
// arguments of the module, not metadata: `src_ip`, `src_port`, `dst_port`.
class GtpuEncap final : public Module {
 public:
  GtpuEncap() : Module() { max_allowed_workers_ = Worker::kMaxWorkers; }

  CommandResponse Init(const upf::pb::GtpuEncapArg &arg);

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

 private:
  uint32_t src_ip_ = 0;   // network order
  uint16_t src_port_ = 0;  // host order; 0 means a per-flow hash
  uint16_t dst_port_ = 0;  // host order
};

#endif  // UPF_DATAPATH_GTPU_ENCAP_H_
