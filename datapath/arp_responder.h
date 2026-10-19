// SPDX-License-Identifier: BSD-3-Clause

#ifndef UPF_DATAPATH_ARP_RESPONDER_H_
#define UPF_DATAPATH_ARP_RESPONDER_H_

#include <memory>

#include "arp_responder_resource.h"
#include "framework/resource_bindings.h"
#include "module.h"
#include "upf_datapath.pb.h"

// Answers ARP requests for the addresses the deployment holds, rewriting each
// request in place into the reply (the fork's ArpResponder, core/modules/
// arp_responder.cc, whose packet path and wire shape this keeps) -- with one
// difference that is the whole reason the module exists here: its entries are
// a *live* resource.
//
// The fork's own ArpResponder requires paused workers for a write, and so do
// every other per-address identity in the graph (Vif's `interfaces`, Rewrite's
// `templates`). A UPF provisions a subscriber's address at session time, while
// the dataplane runs: the address must be answered from that moment, and
// nothing in the fork can hold a per-session entry. This module's
// "<module>/entries" is a slot table of atomic slots (arp_responder_resource.h
// carries the reasoning), so a session's entry is one live transaction and the
// packet path pays one acquire load.
//
// The packet path drops what it cannot answer for: a packet that is not an ARP
// request, and a request whose target address the table does not hold. Every
// other packet is the graph's business -- the module belongs on the ARP branch
// of the ingress (deploy/upf.yaml's l2_sort), and a deployment that sent it the
// rest of the traffic would drop it all.
class UpfArpResponder final : public Module {
 public:
  static const gate_idx_t kNumIGates = 1;
  static const gate_idx_t kNumOGates = 1;

  static const ResourceTables resource_tables;

  UpfArpResponder() : Module() { max_allowed_workers_ = Worker::kMaxWorkers; }

  CommandResponse Init(const upf::pb::UpfArpResponderArg &arg);
  void DeInit() override;

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  std::string GetDesc() const override;

  // The entry for an address, or nullptr: what the packet path looks up, for
  // tests and introspection.
  const upf::arp::Entry *Lookup(uint32_t ip) const noexcept {
    return resource_ == nullptr ? nullptr : resource_->Lookup(ip);
  }

 private:
  std::unique_ptr<upf::arp::EntriesResource> resource_;
  bess::framework::ResourceBinding binding_;  // after resource_ (D-044)
};

#endif  // UPF_DATAPATH_ARP_RESPONDER_H_
