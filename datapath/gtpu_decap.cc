// SPDX-License-Identifier: BSD-3-Clause

#include "gtpu_decap.h"

#include <limits>
#include <array>
#include <algorithm>
#include <cstdint>
#include <format>
#include <span>
#include <cstring>
#include <string>

// Before every other BESS header: glog must win over protobuf's absl logging
// in this translation unit (docs/plugin-api.md, "Logging").
#include "utils/logging.h"

#include "commands.h"
#include "framework/plugin.h"
#include "dataplane/resource_registry.h"
#include "framework/resource_codec.h"
#include "gtpu_wire.h"
#include "packet_pool.h"
#include "pdu_session_qfi.h"
#include "tunnel/tunnel.h"
#include "utils/endian.h"
#include "utils/dpdk_memory.h"
#include "utils/ether.h"
#include "gtpu_admission.h"
#include "worker.h"
namespace dataplane = bess::dataplane;

const ResourceTables GtpuDecap::resource_tables = {
    ResourceTable::Map<upf::pb::FteidKey, upf::pb::FteidEntry>("fteids"),
};

CommandResponse GtpuDecap::Init(const upf::pb::GtpuDecapArg &arg) {
  if (arg.port() != 0) {
    if (arg.port() > 65535) {
      return CommandFailure(EINVAL, "invalid 'port' field");
    }
    port_ = static_cast<uint16_t>(arg.port());
  } else {
    port_ = bess::tunnel::kGtpuPort;
  }
  constexpr size_t kDefaultMaxFteids = 65536;
  max_fteids_ = arg.max_fteids() == 0 ? kDefaultMaxFteids
                                      : arg.max_fteids();
  if (max_fteids_ > std::numeric_limits<uint32_t>::max() / 2)
    return CommandFailure(EINVAL, "max_fteids exceeds exact-index limits");
  // SharedExactIndex sizes its underlying ConcurrentExactTable for the live
  // limit plus QSBR deletion headroom; max_fteids_ is the admitted live cap.
  // On the memory node (BESS D-123), admitted first (D-198): a refusal throws
  // utils::MemoryRefused and Init answers RESOURCE_EXHAUSTED. A null index
  // (Create's std::bad_alloc) keeps its own answer.
  auto &memory = init_context().memory();
  try {
    fteid_table_ = memory.Create<bess::flow::SharedExactIndex>(
        "fteids", static_cast<uint32_t>(sizeof(upf::datapath::FteidId)),
        max_fteids_, init_context().rcu(), memory.socket());
  } catch (const bess::utils::MemoryRefused &) {
    throw;
  } catch (const std::bad_alloc &) {
    return CommandFailure(ENOMEM, "cannot create the fteids exact index");
  }
  resource_ = memory.Create<upf::datapath::FteidResource>(
      "records", name() + "/fteids", *fteid_table_, init_context().rcu(),
      max_fteids_);

  binding_ = init_context().codecs().Bind(
      *resource_,
      std::make_shared<bess::framework::TypedCodec<
          upf::pb::FteidKey, upf::pb::FteidEntry>>(
          [](const upf::pb::FteidKey &key)
              -> std::expected<dataplane::ResourceKey, std::string> {
            if (key.endpoint_id() == 0 || key.teid() == 0)
              return std::unexpected("endpoint_id and teid must be nonzero");
            const size_t bytes = key.address_family() == 4 ? 4 :
                                 key.address_family() == 6 ? 16 : 0;
            if (bytes == 0 || key.local_address().size() != bytes)
              return std::unexpected("local_address length must match family 4 or 6");
            upf::datapath::FteidId id{};
            id[0] = static_cast<uint8_t>(key.endpoint_id() >> 24);
            id[1] = static_cast<uint8_t>(key.endpoint_id() >> 16);
            id[2] = static_cast<uint8_t>(key.endpoint_id() >> 8);
            id[3] = static_cast<uint8_t>(key.endpoint_id());
            id[4] = static_cast<uint8_t>(key.address_family());
            std::memcpy(id.data() + (bytes == 4 ? 17 : 5),
                        key.local_address().data(), bytes);
            id[21] = static_cast<uint8_t>(key.teid() >> 24);
            id[22] = static_cast<uint8_t>(key.teid() >> 16);
            id[23] = static_cast<uint8_t>(key.teid() >> 8);
            id[24] = static_cast<uint8_t>(key.teid());
            return dataplane::EncodeKey(id);
          },
          [](const upf::pb::FteidEntry &value)
              -> std::expected<std::any, std::string> {
            if (value.direction() > 1)
              return std::unexpected("direction must be 0 (UL) or 1 (DL)");
            if (value.context_id() == 0)
              return std::unexpected("context_id must be nonzero");
            upf::datapath::FteidRecord record{
                static_cast<uint8_t>(value.direction()), value.context_id(), {}};
            for (const auto &relay : value.end_marker_relays()) {
              const size_t length = relay.local_address().size();
              if (relay.teid() == 0 || (length != 4 && length != 16) ||
                  relay.peer_address().size() != length)
                return std::unexpected(
                    "an end_marker_relays entry needs a teid and a local and peer "
                    "address of one family (4 or 16 bytes)");
              upf::datapath::EndMarkerRelay r;
              r.teid = relay.teid();
              r.family = length == 4 ? 4 : 6;
              std::memcpy(r.local.data() + 16 - length,
                          relay.local_address().data(), length);
              std::memcpy(r.peer.data() + 16 - length,
                          relay.peer_address().data(), length);
              r.transport_route_domain = relay.transport_route_domain();
              record.relays.push_back(r);
            }
            return std::any(std::move(record));
          },
          [this](const auto &visit) {
            resource_->ForEach([&visit](const upf::datapath::FteidId &id,
                                         const upf::datapath::FteidRecord &record) {
              upf::pb::FteidKey key;
              const uint32_t endpoint = uint32_t{id[0]} << 24 |
                                        uint32_t{id[1]} << 16 |
                                        uint32_t{id[2]} << 8 | id[3];
              const uint32_t teid = uint32_t{id[21]} << 24 |
                                    uint32_t{id[22]} << 16 |
                                    uint32_t{id[23]} << 8 | id[24];
              key.set_endpoint_id(endpoint);
              key.set_address_family(id[4]);
              key.set_teid(teid);
              const size_t off = id[4] == 4 ? 17 : 5;
              key.set_local_address(
                  reinterpret_cast<const char *>(id.data() + off),
                  id[4] == 4 ? 4 : 16);
              upf::pb::FteidEntry value;
              value.set_direction(record.direction);
              value.set_context_id(record.context_id);
              for (const auto &r : record.relays) {
                const size_t length = r.family == 4 ? 4 : 16;
                auto *relay = value.add_end_marker_relays();
                relay->set_teid(r.teid);
                relay->set_local_address(
                    reinterpret_cast<const char *>(r.local.data() + 16 - length), length);
                relay->set_peer_address(
                    reinterpret_cast<const char *>(r.peer.data() + 16 - length), length);
                relay->set_transport_route_domain(r.transport_route_domain);
              }
              visit(key, value);
            });
          }));
  if (auto registered = init_context().resources().Register(resource_.get());
      !registered) {
    binding_.Reset();
    resource_.reset();
    return CommandFailure(EEXIST, "%s", registered.error().c_str());
  }
  auto unwind_resource = [this] {
    const std::string resource_name = resource_->name();
    CHECK(init_context().resources().Unregister(resource_name));
    binding_.Reset();
    resource_.reset();
  };
  using AccessMode = bess::metadata::Attribute::AccessMode;
  context_attr_ = AddMetadataAttr("fteid_context", sizeof(bess::utils::be32_t),
                                  AccessMode::kWrite);
  if (context_attr_ < 0) {
    unwind_resource();
    return CommandFailure(-context_attr_, "add_metadata_attr() failed");
  }
  qfi_attr_ = AddMetadataAttr("qfi", sizeof(uint8_t), AccessMode::kWrite);
  if (qfi_attr_ < 0) {
    unwind_resource();
    return CommandFailure(-qfi_attr_, "add_metadata_attr() failed");
  }
  endpoint_attr_ = AddMetadataAttr("endpoint_id", sizeof(bess::utils::be32_t),
                                   AccessMode::kRead);
  if (endpoint_attr_ < 0) {
    unwind_resource();
    return CommandFailure(-endpoint_attr_, "add_metadata_attr() failed");
  }
  // The relays' transport route domain, for the transport Router. An update:
  // the ingress tag's value passes through on everything else this module
  // emits (the responder's replies on gate 2 are routed by it).
  domain_attr_ = AddMetadataAttr("transport_route_domain", sizeof(bess::utils::be32_t),
                                 AccessMode::kUpdate,
                                 bess::metadata::Attribute::Contract::kDefault);
  if (domain_attr_ < 0) {
    unwind_resource();
    return CommandFailure(-domain_attr_, "add_metadata_attr() failed");
  }

  return CommandSuccess();
}

void GtpuDecap::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  const auto context_offset = attr_offset(context_attr_);
  const auto endpoint_offset = attr_offset(endpoint_attr_);
  const auto qfi_offset = attr_offset(qfi_attr_);
  const auto domain_offset = attr_offset(domain_attr_);
  const size_t cnt = batch->cnt();
  gate_idx_t ogates[bess::PacketBatch::kMaxBurst];
  upf::datapath::FteidId keys[bess::PacketBatch::kMaxBurst]{};
  bess::packet::ParsedFrame outer[bess::PacketBatch::kMaxBurst]{};
  bess::tunnel::GtpuInfo info[bess::PacketBatch::kMaxBurst]{};
  bool candidate[bess::PacketBatch::kMaxBurst]{};
  bool end_marker[bess::PacketBatch::kMaxBurst]{};
  uint64_t values[bess::PacketBatch::kMaxBurst]{};

  // Parse all frames first; the fixed-width exact table then admits the burst
  // with one lock-free batch lookup.
  for (size_t i = 0; i < cnt; ++i) {
    bess::PacketRef pkt = batch->packet(i);
    ogates[i] = DROP_GATE;
    const uint32_t endpoint_id =
        get_attr_with_offset<bess::utils::be32_t>(endpoint_offset, pkt).value();
    if (endpoint_id == 0) continue;
    const std::span<const uint8_t> frame(pkt.head_data<const uint8_t *>(),
                                         pkt.head_len());
    upf::datapath::ParsedGtpu parsed;
    const auto kind = upf::datapath::ParseGtpuAdmission(
        frame, pkt.total_len(), port_, endpoint_id, &parsed);
    if (kind != upf::datapath::GtpuParseKind::kGpdu) {
      // Control frames go to the responder; malformed frames drop here.
      if (kind != upf::datapath::GtpuParseKind::kControl) continue;
      ogates[i] = 2;
      // An End Marker is looked up too: its F-TEID's entry names the tunnels
      // it is relayed through.
      if (parsed.info.message_type == upf::datapath::kGtpuEndMarker) {
        keys[i] = parsed.key;
        end_marker[i] = true;
      }
      continue;
    }
    outer[i] = parsed.outer;
    info[i] = parsed.info;
    keys[i] = parsed.key;
    candidate[i] = true;
  }

  const auto *key_bytes = reinterpret_cast<const std::byte *>(keys);
  const uint64_t hits = cnt == 0 ? 0 : fteid_table_->LookupBatch(
      key_bytes, sizeof(keys[0]), values, cnt);

  for (size_t i = 0; i < cnt; ++i) {
    const uint64_t bit = uint64_t{1} << i;
    // The received End Marker still leaves on gate 2, where the responder
    // records it; each relay is a new frame on gate 3, in this batch, routed
    // by its tunnel's transport domain (TS 29.244 Table 8.2.64-1 NOTE 2).
    if (end_marker[i]) {
      const auto *relays =
          upf::datapath::FteidRelays((hits & bit) != 0, values[i]);
      for (size_t r = 0; relays != nullptr && r < relays->size(); ++r) {
        const auto &relay = (*relays)[r];
        bess::PacketHandle handle = current_worker.packet_pool()->Alloc(
            upf::datapath::EndMarkerFrameBytes(relay.family));
        if (handle == nullptr) continue;
        bess::PacketRef out(handle);
        if (!upf::datapath::WriteEndMarker(out.head_data<uint8_t *>(), relay.family,
                                           relay.local.data(), relay.peer.data(),
                                           relay.teid)) {
          bess::PacketFree(handle);
          continue;
        }
        set_attr_with_offset<bess::utils::be32_t>(
            domain_offset, out, bess::utils::be32_t(relay.transport_route_domain));
        EmitPacket(ctx, out, 3);
      }
      continue;
    }
    if (!candidate[i]) continue;
    uint32_t context = 0;
    const uint8_t gate = upf::datapath::FteidOutputGate(
        (hits & bit) != 0, values[i], &context);
    if (gate == 2) {
      ogates[i] = gate;
      continue;
    }
    bess::PacketRef pkt = batch->packet(i);
    if (not pkt.is_linear()) continue;

    const auto &gtpu = info[i];
    const std::span<const uint8_t> frame(pkt.head_data<const uint8_t *>(),
                                         pkt.head_len());
    const uint8_t version = frame[gtpu.tunnel.inner_offset] >> 4;
    if (version != 4 && version != 6) continue;

    upf::datapath::ParsedGtpu parsed;
    parsed.outer = outer[i];
    parsed.info = gtpu;
    const auto decap_metadata =
        upf::datapath::BuildGtpuDecapMetadata(frame, parsed, context);

    set_attr_with_offset<bess::utils::be32_t>(
        context_offset, pkt, bess::utils::be32_t(decap_metadata.fteid_context));
    set_attr_with_offset<uint8_t>(qfi_offset, pkt, decap_metadata.qfi);

    const auto *outer_eth = pkt.head_data<const uint8_t *>();
    pkt.adj(static_cast<uint16_t>(gtpu.tunnel.inner_offset));
    auto *eth = static_cast<uint8_t *>(
        pkt.prepend(bess::tunnel::kEthernetBytes));
    if (eth == nullptr) continue;
    upf::datapath::WriteDecapsulatedEthernetHeader(eth, outer_eth, version);
    ogates[i] = gate;
  }
  EmitBatch(ctx, batch, ogates);
}

void GtpuDecap::DeInit() {
  if (!resource_) return;
  binding_.Reset();
  const std::string resource_name = resource_->name();
  auto unregistered = init_context().resources().Unregister(resource_name);
  CHECK(unregistered) << unregistered.error();
  resource_.reset();
}

std::string GtpuDecap::GetDesc() const {
  return std::format("{} F-TEIDs, UDP {}", resource_ ? resource_->LiveCount() : 0,
                     port_);
}

// One plugin descriptor for the whole library (gtpu_encap.cc carries the other
// module; BESS_PLUGIN must appear exactly once per .so).
// The capabilities every module of the library uses between them: UpfAppliance
// reaches the runtime (init context, codecs/resources), the periodic tick, the
// owner-applied transactions for its two routers, and the memory scope; the
// graph modules use the first, second and fourth already.
BESS_PLUGIN_REQUIRES("upf_datapath", "0.3.0",
                     BESS_CAP_INIT_CONTEXT | BESS_CAP_RESOURCES | BESS_CAP_TICKS |
                         BESS_CAP_OWNED_APPLY | BESS_CAP_MEMORY);

ADD_MODULE(GtpuDecap, "gtpu_decap",
           "admits G-PDUs by endpoint/family/local-address/TEID; known UL and DL "
           "frames leave gates 0 and 1, unknown G-PDUs and control frames leave "
           "gate 2, End Markers relayed through their F-TEID's tunnels gate 3, "
           "and malformed packets drop")
