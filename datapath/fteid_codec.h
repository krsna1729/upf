// SPDX-License-Identifier: BSD-3-Clause
// An F-TEID admission entry's wire codec (upf.pb.FteidEntry), shared by
// GtpuDecap's `<decap>/fteids`, UpfAppliance's `<appliance>/fteids` and the
// F-TEIDs of an UpfSessionAppliance session.

#ifndef UPF_DATAPATH_FTEID_CODEC_H_
#define UPF_DATAPATH_FTEID_CODEC_H_

#include <cstring>
#include <expected>
#include <string>

#include "fteid_resource.h"
#include "upf_datapath.pb.h"

namespace upf::datapath {

// The entry's direction (0 UL, 1 DL), its nonzero admission context and its
// End Marker relays (TS 29.244 Table 8.2.64-1 NOTE 2), each a nonzero TEID
// and a local and peer address of one family.
inline std::expected<FteidRecord, std::string> DecodeFteidEntry(
    const upf::pb::FteidEntry &value) {
  if (value.direction() > 1)
    return std::unexpected("direction must be 0 (UL) or 1 (DL)");
  if (value.context_id() == 0)
    return std::unexpected("context_id must be nonzero");
  FteidRecord record{static_cast<uint8_t>(value.direction()), value.context_id(), {}};
  record.relays.reserve(static_cast<size_t>(value.end_marker_relays_size()));
  for (const auto &relay : value.end_marker_relays()) {
    const size_t length = relay.local_address().size();
    if (relay.teid() == 0 || (length != 4 && length != 16) ||
        relay.peer_address().size() != length)
      return std::unexpected(
          "an end_marker_relays entry needs a teid and a local and peer "
          "address of one family (4 or 16 bytes)");
    EndMarkerRelay r;
    r.teid = relay.teid();
    r.family = length == 4 ? 4 : 6;
    std::memcpy(r.local.data() + 16 - length, relay.local_address().data(), length);
    std::memcpy(r.peer.data() + 16 - length, relay.peer_address().data(), length);
    r.transport_route_domain = relay.transport_route_domain();
    record.relays.push_back(r);
  }
  return record;
}

// The entry as a client writes it: DecodeFteidEntry's inverse.
inline upf::pb::FteidEntry EncodeFteidEntry(const FteidRecord &record) {
  upf::pb::FteidEntry value;
  value.set_direction(record.direction);
  value.set_context_id(record.context_id);
  for (const auto &r : record.relays) {
    const size_t length = r.family == 4 ? 4 : 16;
    auto *relay = value.add_end_marker_relays();
    relay->set_teid(r.teid);
    relay->set_local_address(reinterpret_cast<const char *>(r.local.data() + 16 - length), length);
    relay->set_peer_address(reinterpret_cast<const char *>(r.peer.data() + 16 - length), length);
    relay->set_transport_route_domain(r.transport_route_domain);
  }
  return value;
}

}  // namespace upf::datapath

#endif  // UPF_DATAPATH_FTEID_CODEC_H_
