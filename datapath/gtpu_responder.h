// SPDX-License-Identifier: BSD-3-Clause

#ifndef UPF_DATAPATH_GTPU_ECHO_H_
#define UPF_DATAPATH_GTPU_ECHO_H_

#include <cstddef>
#include <memory>

#include "end_marker_log.h"
#include "framework/memory_scope.h"
#include "gtpu_control.h"
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
// The packet path is upf::datapath::AnswerGtpuControl (gtpu_control.h, which
// carries the wire format), shared with UpfAppliance; this module owns the
// counts and the log and sends a reply on its reply gate.
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

  // The Error Indications recorded since the previous drain (TS 29.281
  // 7.3.1), each returned once, with the count lost to a full ring.
  CommandResponse CommandDrainErrors(
      const upf::pb::GtpuResponderCommandDrainErrorsArg &arg);

  // The End Markers recorded since the previous drain (TS 29.281 7.3.2), each
  // returned once, with the count lost to a full ring.
  CommandResponse CommandDrainEndMarkers(
      const upf::pb::GtpuResponderCommandDrainEndMarkersArg &arg);

 private:
  uint16_t port_ = 0;  // the UDP port the messages must arrive on
  uint32_t stamp_ = 0; // seconds from 1900 to this entity's start (8.7)
  int reply_gate_attr_ = -1;  // optional ingress BE32 output gate
  // Admitted as "errors" (D-198).
  bess::framework::Sized<upf::datapath::ErrorIndicationLog> errors_;
  int endpoint_attr_ = -1;  // "endpoint_id", read when End Markers are tracked
  // Admitted as "end_markers" (D-198).
  bess::framework::Sized<upf::datapath::EndMarkerLog> end_markers_;
};

#endif  // UPF_DATAPATH_GTPU_ECHO_H_
