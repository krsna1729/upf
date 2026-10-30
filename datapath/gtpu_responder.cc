// SPDX-License-Identifier: BSD-3-Clause

#include "gtpu_responder.h"

#include <cstdint>
#include <ctime>
#include <string>

// Before every other BESS header: glog must win over protobuf's absl logging
// in this translation unit (docs/plugin-api.md, "Logging").
#include "utils/logging.h"

#include "commands.h"
#include "framework/plugin.h"
#include "tunnel/tunnel.h"
#include "utils/endian.h"

using bess::utils::be32_t;

const ResourceTables GtpuResponder::resource_tables = {};

const Commands GtpuResponder::cmds = {
    {"get_errors", "upf.pb.GtpuResponderCommandGetErrorsArg",
     MODULE_CMD_FUNC(&GtpuResponder::CommandGetErrors), Command::THREAD_SAFE,
     "upf.pb.GtpuResponderCommandGetErrorsResponse"},
    {"drain_end_markers", "upf.pb.GtpuResponderCommandDrainEndMarkersArg",
     MODULE_CMD_FUNC(&GtpuResponder::CommandDrainEndMarkers), Command::THREAD_SAFE,
     "upf.pb.GtpuResponderCommandDrainEndMarkersResponse"},
};

CommandResponse GtpuResponder::Init(const upf::pb::GtpuResponderArg &arg) {
  if (arg.port() != 0) {
    if (arg.port() > 65535) {
      return CommandFailure(EINVAL, "invalid 'port' field");
    }
    port_ = static_cast<uint16_t>(arg.port());
  } else {
    port_ = bess::tunnel::kGtpuPort;
  }

  // The stamp names when this GTP-U entity started (8.7). The graph's start
  // is the entity's, so the clock at Init is the honest default; a deployment
  // that keeps a node's identity across a graph replay -- `upfd -checkpoint`
  // does that for the PFCP side -- passes the value it means.
  const uint64_t seconds =
      arg.recovery_time_stamp() != 0
          ? arg.recovery_time_stamp()
          : static_cast<uint64_t>(std::time(nullptr)) + upf::datapath::kGtpuEpoch1900;
  if (seconds > 0xffffffffULL) {
    return CommandFailure(EINVAL, "invalid 'recovery_time_stamp' field");
  }
  stamp_ = static_cast<uint32_t>(seconds);
  if (arg.track_errors()) {
    errors_ = std::make_unique<upf::datapath::GtpuErrorCounts>();
  }
  if (arg.track_end_markers()) {
    // Admitted before it is made (D-198): a refusal throws
    // utils::MemoryRefused and Init answers RESOURCE_EXHAUSTED.
    end_markers_ = init_context().memory().Create<upf::datapath::EndMarkerLog>(
        "end_markers", static_cast<size_t>(Worker::kMaxWorkers));
    endpoint_attr_ = AddMetadataAttr("endpoint_id", sizeof(be32_t),
                                     bess::metadata::Attribute::AccessMode::kRead);
    if (endpoint_attr_ < 0) {
      return CommandFailure(-endpoint_attr_, "add_metadata_attr() failed");
    }
  }
  if (!arg.reply_gate_attr().empty()) {
    reply_gate_attr_ = AddMetadataAttr(
        arg.reply_gate_attr(), sizeof(be32_t),
        bess::metadata::Attribute::AccessMode::kRead);
    if (reply_gate_attr_ < 0) {
      return CommandFailure(-reply_gate_attr_, "add_metadata_attr() failed");
    }
  }
  return CommandSuccess();
}

CommandResponse GtpuResponder::CommandGetErrors(
    const upf::pb::GtpuResponderCommandGetErrorsArg &arg) {
  upf::pb::GtpuResponderCommandGetErrorsResponse response;
  if (errors_ == nullptr) {
    return CommandSuccess(response);
  }
  auto report = [&](uint32_t teid, uint64_t count) {
    auto *entry = response.add_errors();
    entry->set_teid(teid);
    entry->set_count(count);
  };
  if (arg.teids_size() == 0) {
    errors_->ForEach(report);
  } else {
    for (uint32_t teid : arg.teids()) {
      if (const auto count = errors_->Count(teid)) {
        report(teid, *count);
      }
    }
  }
  response.set_untracked(errors_->Untracked());
  return CommandSuccess(response);
}

CommandResponse GtpuResponder::CommandDrainEndMarkers(
    const upf::pb::GtpuResponderCommandDrainEndMarkersArg &) {
  upf::pb::GtpuResponderCommandDrainEndMarkersResponse response;
  if (!end_markers_) {
    return CommandSuccess(response);
  }
  for (const auto &event : end_markers_->Drain()) {
    auto *entry = response.add_end_markers();
    entry->set_endpoint_id(event.endpoint_id);
    entry->set_teid(event.teid);
  }
  response.set_dropped(end_markers_->Dropped());
  return CommandSuccess(response);
}

void GtpuResponder::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  gate_idx_t ogates[bess::PacketBatch::kMaxBurst];
  const size_t cnt = batch->cnt();
  const auto reply_offset =
      reply_gate_attr_ >= 0 ? attr_offset(reply_gate_attr_) : -1;
  const auto endpoint_offset =
      endpoint_attr_ >= 0 ? attr_offset(endpoint_attr_) : -1;
  const upf::datapath::GtpuControlContext control{
      .port = port_,
      .recovery_time_stamp = stamp_,
      .errors = errors_.get(),
      .end_markers = end_markers_.get(),
      .worker = ctx->wid.value(),
  };

  for (size_t i = 0; i < cnt; i++) {
    bess::PacketRef pkt = batch->packet(i);
    ogates[i] = DROP_GATE;
    uint32_t reply_gate = 0;
    if (reply_gate_attr_ >= 0) {
      if (!bess::metadata::IsValidOffset(reply_offset)) continue;
      reply_gate = get_attr_with_offset<be32_t>(reply_offset, pkt).value();
      if (reply_gate >= MAX_GATES) continue;
    }
    const auto verdict = upf::datapath::AnswerGtpuControl(pkt, control, [&]() -> uint32_t {
      return bess::metadata::IsValidOffset(endpoint_offset)
                 ? get_attr_with_offset<be32_t>(endpoint_offset, pkt).value()
                 : 0;
    });
    if (upf::datapath::IsGtpuReply(verdict)) {
      ogates[i] = static_cast<gate_idx_t>(reply_gate);
    }
  }

  EmitBatch(ctx, batch, ogates);
}

std::string GtpuResponder::GetDesc() const { return std::format("port {}", port_); }

ADD_MODULE(GtpuResponder, "gtpu_responder",
           "answers GTP-U Echo Requests and unknown G-PDUs on IPv4/IPv6; "
           "tracks peer Error Indications when enabled; drops other messages")
