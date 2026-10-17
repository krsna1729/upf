// SPDX-License-Identifier: BSD-3-Clause

#ifndef UPF_DATAPATH_GTPU_DECAP_H_
#define UPF_DATAPATH_GTPU_DECAP_H_

#include "module.h"
#include "upf_datapath.pb.h"

// Strips the outer Ethernet/IPv4/UDP/GTP-U headers (TS 29.281) and leaves the
// packet framed, writing the TEID it carried, and the QFI of the PDU Session
// Container when the G-PDU carried one, to packet metadata.
//
// The F-TEID match is the graph's, not this module's: the compiler writes one
// rule per session into the rule table the graph puts in front of this module,
// keyed by the TEID's own offset in the outer frame, so a G-PDU whose TEID is
// no session's never reaches here (the table's default gate drops it). The
// module keeps no session state, and its packet path is a header strip and two
// metadata writes: the TEID, and the QFI -- 0 when the G-PDU's extension
// header chain carried no PDU Session Container, so a downstream match on the
// attribute never sees the previous packet's QFI.
//
// The graph carries Ethernet frames: BESS's core modules (the router's
// lookup, the classifiers) read IPv4 behind an Ethernet header, so the outer
// frame's own header is what the inner packet is left behind, and the graph
// rewrites its addresses for the link it sends on (a Rewrite module, or the
// egress port's own configuration). Decapsulation copies nothing: the outer
// IP/UDP/GTP-U headers become headroom. The port the module accepts G-PDUs on
// is its argument; everything else about a session is a rule or a record the
// controller writes.
class GtpuDecap final : public Module {
 public:
  static const gate_idx_t kNumOGates = 1;

  // The module owns no resource tables: a session's TEID is a rule of the
  // classifier in front of it.
  static const ResourceTables resource_tables;

  GtpuDecap() : Module() { max_allowed_workers_ = Worker::kMaxWorkers; }

  CommandResponse Init(const upf::pb::GtpuDecapArg &arg);

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  std::string GetDesc() const override;

 private:
  uint16_t port_ = 0;
  int teid_attr_ = -1;  // the "upf_teid" attribute id
  int qfi_attr_ = -1;   // the "qfi" attribute id
};

#endif  // UPF_DATAPATH_GTPU_DECAP_H_
