// SPDX-License-Identifier: BSD-3-Clause

#ifndef UPF_DATAPATH_GTPU_ECHO_H_
#define UPF_DATAPATH_GTPU_ECHO_H_

#include <atomic>
#include <cstddef>
#include <memory>

#include "end_marker_log.h"
#include "framework/memory_scope.h"
#include "module.h"
#include "upf_datapath.pb.h"

// Handles GTP-U control and unadmitted G-PDU traffic sent to GtpuDecap gate 2
// (TS 29.281 7.2 and 7.3.1).
//
// GtpuDecap sends Echo Requests, peer Error Indications and valid G-PDUs whose
// endpoint-scoped F-TEID is not admitted. This module answers Echo Requests,
// returns an Error Indication for an unadmitted G-PDU, counts peer Error
// Indications for Session Report generation, and records End Markers as events
// for End Marker Reception Reports. Other control types are dropped.
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
  static const gate_idx_t kNumOGates = MAX_GATES;

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

  // The End Markers recorded since the previous drain (TS 29.281 7.3.2), each
  // returned once, with the count lost to a full ring.
  CommandResponse CommandDrainEndMarkers(
      const upf::pb::GtpuResponderCommandDrainEndMarkersArg &arg);

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
  int reply_gate_attr_ = -1;  // optional ingress BE32 output gate
  std::unique_ptr<ErrorSlot[]> errors_;
  std::atomic<uint64_t> untracked_{0};
  int endpoint_attr_ = -1;  // "endpoint_id", read when End Markers are tracked
  // Admitted as "end_markers" (D-198).
  bess::framework::Sized<upf::datapath::EndMarkerLog> end_markers_;
};

#endif  // UPF_DATAPATH_GTPU_ECHO_H_
