// SPDX-License-Identifier: BSD-3-Clause

#ifndef UPF_DATAPATH_GTPU_ECHO_H_
#define UPF_DATAPATH_GTPU_ECHO_H_

#include "module.h"
#include "upf_datapath.pb.h"

// Answers the two GTP-U messages a UPF is handed on a TEID that names no
// session, and drops everything else it is given (TS 29.281 7.2 and 7.3.1).
//
// The graph hands it whatever the rule table in front of it routes to the
// default gate. A G-PDU's TEID is a session's rule; two messages reach a UPF
// outside one: an Echo Request, always on TEID 0, whose reply the peer's path
// management needs -- a peer that gets none reads the N3 path as down, with no
// packet loss to point at -- and a G-PDU whose TEID no session names, which
// 7.3.1 answers with an Error Indication so the peer learns the tunnel is
// gone instead of sending into it.
//
// Both replies are the request with its Ethernet, IPv4 and UDP addresses
// swapped, the type replaced, and the lengths recomputed. An Echo Response
// keeps the S-flag field (5.1: an echo sets it), sends TEID 0, and carries the
// two IEs 7.2.2 names: the mandatory Recovery IE with a zero restart counter,
// and this node's Recovery Time Stamp -- 17 bytes after the header. An Error
// Indication has S clear, TEID 0 (the peer knows no tunnel toward this node),
// and one TEID IE naming the TEID it used -- 5 bytes after the header. Both
// copy nothing but their tail, allocate nothing, and read no session state.
class GtpuResponder final : public Module {
 public:
  static const gate_idx_t kNumOGates = 1;

  // No resource table: an echo belongs to the path, not to a session.
  static const ResourceTables resource_tables;

  GtpuResponder() : Module() { max_allowed_workers_ = Worker::kMaxWorkers; }

  CommandResponse Init(const upf::pb::GtpuResponderArg &arg);

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  std::string GetDesc() const override;

 private:
  uint16_t port_ = 0;  // the UDP port the messages must arrive on
  uint32_t stamp_ = 0; // seconds from 1900 to this entity's start (8.7)
};

#endif  // UPF_DATAPATH_GTPU_ECHO_H_
