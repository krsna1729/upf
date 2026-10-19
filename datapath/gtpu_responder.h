// SPDX-License-Identifier: BSD-3-Clause

#ifndef UPF_DATAPATH_GTPU_ECHO_H_
#define UPF_DATAPATH_GTPU_ECHO_H_

#include <atomic>
#include <cstddef>
#include <memory>

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

  static const Commands cmds;

  CommandResponse Init(const upf::pb::GtpuResponderArg &arg);

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  std::string GetDesc() const override;

  // The Error Indications the peer sent (7.3.1), one monotonic count per TEID.
  // A reading is what the controller's report compares with the count it last
  // reported, so nothing here is cleared: the writes are relaxed adds and the
  // read never takes a lock.
  CommandResponse CommandGetErrors(
      const upf::pb::GtpuResponderCommandGetErrorsArg &arg);

 private:
  // One entry: 0 is empty (an Error Indication never names TEID 0 -- that is
  // the echo path), and the count only grows.
  struct ErrorSlot {
    std::atomic<uint32_t> teid{0};
    std::atomic<uint64_t> count{0};
  };
  // Small on purpose: a flood of distinct TEIDs is a scan, not a tunnel loss.
  // 64 slots are 1 KiB, and a full table is counted rather than dropped
  // silently.
  static constexpr size_t kErrorSlots = 64;

  void RecordError(uint32_t teid);

  uint16_t port_ = 0;  // the UDP port the messages must arrive on
  uint32_t stamp_ = 0; // seconds from 1900 to this entity's start (8.7)
  std::unique_ptr<ErrorSlot[]> errors_;
  std::atomic<uint64_t> untracked_{0};
};

#endif  // UPF_DATAPATH_GTPU_ECHO_H_
