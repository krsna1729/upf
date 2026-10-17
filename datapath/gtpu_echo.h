// SPDX-License-Identifier: BSD-3-Clause

#ifndef UPF_DATAPATH_GTPU_ECHO_H_
#define UPF_DATAPATH_GTPU_ECHO_H_

#include "module.h"
#include "upf_datapath.pb.h"

// Answers a GTP-U Echo Request (TS 29.281 7.2, message type 1) with the reply
// the peer's path management needs (type 2), and drops everything else it is
// handed.
//
// The graph hands it one kind of packet: whatever the rule table in front of it
// routes to this gate. A G-PDU's TEID is a session's rule; the only other
// message that reaches a UPF on TEID 0 is an Echo Request, which names no
// session and which the table would otherwise drop. A peer that gets no reply
// reads the N3 path as down, with no packet loss to point at.
//
// The reply is the request with its Ethernet, IPv4 and UDP addresses swapped,
// the type set to 2, the S-flag field kept (5.1: an echo sets it), the
// payload replaced by the two IEs 7.2.2 names -- the mandatory Recovery IE
// with a zero restart counter, and this node's Recovery Time Stamp -- and the
// lengths recomputed: 20 bytes of IPv4, 8 of UDP, 8 of GTP-U and 17 after it.
// It copies nothing but those 17 bytes, allocates nothing, and reads no
// session state.
class GtpuEcho final : public Module {
 public:
  static const gate_idx_t kNumOGates = 1;

  // No resource table: an echo belongs to the path, not to a session.
  static const ResourceTables resource_tables;

  GtpuEcho() : Module() { max_allowed_workers_ = Worker::kMaxWorkers; }

  CommandResponse Init(const upf::pb::GtpuEchoArg &arg);

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  std::string GetDesc() const override;

 private:
  uint16_t port_ = 0;  // the UDP port an Echo Request must arrive on
  uint32_t stamp_ = 0; // seconds from 1900 to this entity's start (8.7)
};

#endif  // UPF_DATAPATH_GTPU_ECHO_H_
