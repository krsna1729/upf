// SPDX-License-Identifier: BSD-3-Clause

// The `qfi` metadata attribute's wire contract, in one place: the decap writes
// it, the PDR matcher reads it, and the controllers that key a rule on it (`upfd
// -pdr-fields-*`, the graphs' WildcardMatch fields) assume the same byte.
//
// The attribute holds the QFI of the G-PDU's PDU Session Container. That field
// is six bits -- TS 38.415 5.5.3.3's range is 0..63, and TS 29.244 8.2.89 (the
// PFCP QFI IE) refers to it -- so 0 is a QoS flow a real gNB can put a packet
// on, and "no container" needs a value of its own. It is kNoPduSessionQfi
// below: above the range, so no container's QFI can be it, and one byte wide,
// which is all the attribute has.
//
// Why it matters: a G-PDU without a container and one whose container said QFI 0
// are different packets, and a PDI that names QFI 0 must match only the second
// (TS 29.244 7.5.2.2: the PDI's QFI selects a QoS flow, and 5.2.1 makes the
// session's rules the match). With a shared 0 the first packet would match a
// QFI-0 rule, and the SMF would be told a flow is policed that is not.
//
// The writer always writes: a packet's metadata is reused buffer space that
// nothing clears between packets (core/metadata.cc), so a skipped write would
// hand the previous packet's QFI to the next rule lookup.
#ifndef UPF_PDU_SESSION_QFI_H_
#define UPF_PDU_SESSION_QFI_H_

#include <cstdint>

namespace upf {

// The `qfi` attribute's value for a packet whose GTP-U chain carries no PDU
// Session Container. Outside TS 38.415 5.5.3.3's 0..63 range on purpose.
inline constexpr uint8_t kNoPduSessionQfi = 0xff;

}  // namespace upf

#endif  // UPF_PDU_SESSION_QFI_H_
