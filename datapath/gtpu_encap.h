// SPDX-License-Identifier: BSD-3-Clause

#ifndef UPF_DATAPATH_GTPU_ENCAP_H_
#define UPF_DATAPATH_GTPU_ENCAP_H_

#include <memory>

#include "dataplane/action_id.h"
#include "dataplane/slot_resource.h"
#include "dataplane/slot_table.h"
#include "framework/resource_bindings.h"
#include "module.h"
#include "upf_datapath.pb.h"
#include "utils/ether.h"

// Writes the outer Ethernet/IPv4/UDP/GTP-U headers of a G-PDU in front of the
// inner IP packet, through the tunnel library (M19, D-069).
//
// The packet arrives framed (the graph carries Ethernet frames): a G-PDU's
// payload is the inner IP packet, so the inner frame's header is skipped and
// its bytes become headroom for the outer headers -- nothing is copied. A
// frame that carries anything but IPv4 is dropped: the outer header this
// module writes is IPv4-only.
//
// The per-session parameters are a transactional resource the controller
// writes, "<name>/tunnels" (TunnelKey -> TunnelEntry), keyed by the ActionId
// the PDR rule named and the classifier wrote into the packet's `action_id`
// metadata (BESS D-141). One lookup therefore resolves the session's tunnel,
// next to the action record's meter and next hop: the packet path holds no
// relation between PFCP objects.
//
// A packet whose action id is 0, has no tunnel record, or has no headroom is
// dropped: a packet that cannot be tunnelled must not leave unencapsulated.
// The outer IPv4 source address and the UDP ports are the graph's -- arguments
// of the module, not session state -- while the TEID, the gNB's address, the
// two Ethernet addresses, the QFI and the Transport Level Marking are the
// session's.
//
// The outer IPv4 header's ToS/Traffic Class is the inner packet's own unless
// the session's record names a Transport Level Marking (TS 29.244 8.2.42), in
// which case the marking's DSCP wins and the mask names which of the inner
// header's class bits survive (the ECN bits, with the spec's 0xFC). Either way
// the class the RAN's transport is marked by reaches the outer header.
//
// A session whose record names a QFI gets a PDU Session Container after the
// GTP-U header (TS 29.281 5.2.2.7; the content is TS 38.415's): the E flag
// set, the 4-octet optional tail that names the extension header, and the
// container -- 8 bytes the packet pays for only when it has a QFI to carry, so
// a session without one leaves the wire byte for byte as it was before the
// field existed.
class GtpuEncap final : public Module {
 public:
  static const gate_idx_t kNumOGates = 1;

  using ActionId = bess::dataplane::ActionId;

  // One session's downlink path (TS 29.244 8.2.56, Outer Header Creation).
  struct Tunnel {
    uint32_t teid;    // network order
    uint32_t gnb_ip;  // network order
    bess::utils::Ethernet::Address ether_src;
    bess::utils::Ethernet::Address ether_dst;
    uint8_t qfi;      // 0: write no PDU Session Container
    // The SMF's Transport Level Marking (TS 29.244 8.2.42): the ToS/Traffic
    // Class the outer IPv4 header is marked with, the DSCP in the high byte
    // and the mask in the low one (the bits the inner header keeps, the ECN
    // bits with the spec's 0xFC). 0: no marking, copy the inner TOS.
    uint16_t marking;
  };

  // "<module>/tunnels": TunnelKey -> TunnelEntry.
  static const ResourceTables resource_tables;

  GtpuEncap() : Module() { max_allowed_workers_ = Worker::kMaxWorkers; }

  CommandResponse Init(const upf::pb::GtpuEncapArg &arg);
  void DeInit() override;

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  std::string GetDesc() const override;

  // The tunnel an action id names, or nullptr (one acquire load). The packet
  // path makes exactly this lookup; tests and introspection use it directly.
  const Tunnel *LookupTunnel(ActionId id) const noexcept {
    return id.value() == 0 ? nullptr : tunnels_->Lookup(id);
  }

 private:
  uint32_t src_ip_ = 0;    // network order
  uint16_t src_port_ = 0;  // host order; 0 means a per-flow hash
  uint16_t dst_port_ = 0;  // host order
  int action_attr_ = -1;   // the "action_id" attribute id
  std::unique_ptr<bess::dataplane::SlotTable<ActionId, Tunnel>> tunnels_;
  std::unique_ptr<bess::dataplane::SlotResource<ActionId, Tunnel>> resource_;
  bess::framework::ResourceBinding binding_;  // after resource_ (D-044)
};

#endif  // UPF_DATAPATH_GTPU_ENCAP_H_
