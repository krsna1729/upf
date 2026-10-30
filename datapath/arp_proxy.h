// SPDX-License-Identifier: BSD-3-Clause

#ifndef UPF_DATAPATH_ARP_PROXY_H_
#define UPF_DATAPATH_ARP_PROXY_H_

#include <cstdint>
#include <span>

#include "arp_responder_resource.h"
#include "utils/arp.h"
#include "utils/endian.h"
#include "utils/ether.h"

// The subscriber ARP proxy: an ARP request for an address a session holds is
// answered in place with the address's entry. One implementation for the
// UpfArpResponder module and UpfAppliance; each owns its entries and passes
// their lookup in.
//
// Not route::AnswerArpRequest (route/l3_packet.h), whose reply differs: that
// one refuses a request whose hardware/protocol type or address lengths are
// not Ethernet/IPv4, rewrites those fields, and sends the reply to the ARP
// sender hardware address; this one checks the EtherType and opcode only,
// leaves those fields as the request had them, and sends the reply to the
// frame's Ethernet source -- the fork's ArpResponder packet path, which
// UpfArpResponder keeps.

namespace upf::arp {

// What AnswerProxyRequest did with a frame.
enum class ProxyVerdict : uint8_t {
  kReply,          // the frame now holds the reply; send it back
  kTooShort,       // drop: too short to hold the request it claims to be
  kNotArp,         // drop: not an ARP frame
  kNotRequest,     // drop: a reply, or an opcode nothing is answered for
  kUnknownTarget,  // drop: no session holds the target address
};

// Answers the ARP request in `frame` (one contiguous Ethernet frame) in place.
// `lookup(ip)` returns the const Entry * for an IPv4 address in host order,
// nullptr when none holds it. The requester's addresses become the reply's
// target; the entry's MAC and address become its sender and the frame's
// Ethernet source.
template <typename Lookup>
ProxyVerdict AnswerProxyRequest(std::span<uint8_t> frame, Lookup &&lookup) noexcept {
  using bess::utils::Arp;
  using bess::utils::Ethernet;
  using bess::utils::be16_t;
  if (frame.size() < sizeof(Ethernet) + sizeof(Arp)) {
    return ProxyVerdict::kTooShort;
  }
  auto *eth = reinterpret_cast<Ethernet *>(frame.data());
  if (eth->ether_type != be16_t(Ethernet::Type::kArp)) {
    return ProxyVerdict::kNotArp;
  }
  auto *req = reinterpret_cast<Arp *>(eth + 1);
  if (req->opcode != be16_t(Arp::Opcode::kRequest)) {
    return ProxyVerdict::kNotRequest;
  }
  const Entry *entry = lookup(req->target_ip_addr.value());
  if (entry == nullptr) {
    return ProxyVerdict::kUnknownTarget;
  }
  // The request's fields hold everything the answer needs.
  req->opcode = be16_t(Arp::Opcode::kReply);
  eth->dst_addr = eth->src_addr;
  eth->src_addr = entry->mac;
  req->target_hw_addr = req->sender_hw_addr;
  req->sender_hw_addr = entry->mac;
  req->target_ip_addr = req->sender_ip_addr;
  req->sender_ip_addr = bess::utils::be32_t(entry->ip);
  return ProxyVerdict::kReply;
}

}  // namespace upf::arp

#endif  // UPF_DATAPATH_ARP_PROXY_H_
