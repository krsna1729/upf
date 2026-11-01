// SPDX-License-Identifier: BSD-3-Clause
// The appliance's decode of an F-TEID admission entry (`<appliance>/fteids`).

#ifndef UPF_DATAPATH_UPF_APPLIANCE_FTEID_H_
#define UPF_DATAPATH_UPF_APPLIANCE_FTEID_H_

#include <any>
#include <atomic>
#include <cstdint>
#include <expected>
#include <string>

#include "fteid_resource.h"
#include "upf_datapath.pb.h"

namespace upf::appliance {

// Direction and context are checked as GtpuDecap checks them. The End Marker
// relays (TS 29.244 Table 8.2.64-1 NOTE 2) are not ported to the appliance's
// packet path: the entry is accepted -- refusing it would fail the whole
// Session Modification of a Mode 4 or Mode 6 handover, where a missing End
// Marker only leaves the peer to its timer -- and each relay it names is added
// to `unsupported` instead of being stored or performed.
inline std::expected<std::any, std::string> DecodeFteidEntry(
    const upf::pb::FteidEntry &value, std::atomic<uint64_t> &unsupported) {
  if (value.direction() > 1)
    return std::unexpected("direction must be 0 (UL) or 1 (DL)");
  if (value.context_id() == 0)
    return std::unexpected("context_id must be nonzero");
  if (const int relays = value.end_marker_relays_size(); relays > 0)
    unsupported.fetch_add(static_cast<uint64_t>(relays), std::memory_order_relaxed);
  return std::any(upf::datapath::FteidRecord{
      static_cast<uint8_t>(value.direction()), value.context_id()});
}

}  // namespace upf::appliance

#endif  // UPF_DATAPATH_UPF_APPLIANCE_FTEID_H_
