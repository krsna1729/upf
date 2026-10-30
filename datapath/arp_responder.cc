// SPDX-License-Identifier: BSD-3-Clause

#include "arp_responder.h"

#include <cstdint>
#include <format>
#include <memory>
#include <span>
#include <string>
#include <utility>

// Before every other BESS header: glog must win over protobuf's absl logging
// in this translation unit (docs/plugin-api.md, "Logging").
#include "utils/logging.h"

#include "arp_proxy.h"
#include "dataplane/resource_registry.h"
#include "framework/resource_codec.h"
#include "utils/endian.h"
#include "utils/ether.h"
#include "utils/ip.h"

using bess::utils::Ethernet;

namespace dataplane = bess::dataplane;
namespace arp = upf::arp;

// A subscriber address per slot of a large access network (an entry is a
// 4-byte key and a 6-byte MAC, plus the two atomics).
constexpr size_t kDefaultMaxEntries = 1 << 16;

const ResourceTables UpfArpResponder::resource_tables = {
    ResourceTable::Map<upf::pb::UpfArpResponderEntryKey,
                       upf::pb::UpfArpResponderEntryValue>("entries"),
};

CommandResponse UpfArpResponder::Init(const upf::pb::UpfArpResponderArg &arg) {
  const size_t max_entries =
      arg.max_entries() == 0 ? kDefaultMaxEntries : arg.max_entries();
  // Admitted before it is made (D-198): a refusal throws
  // utils::MemoryRefused and Init answers RESOURCE_EXHAUSTED.
  resource_ = init_context().memory().Create<arp::EntriesResource>(
      "entries", name() + "/entries", max_entries);

  // Typed keys and values (D-025), the wire shape the fork's ArpResponder
  // declares: the controller writes {"ip": "10.45.0.2"} ->
  // {"mac_addr": "02:00:00:00:06:01"} either way, so a graph that moves to
  // this module needs no other change.
  binding_ = init_context().codecs().Bind(
      *resource_,
      std::make_shared<bess::framework::TypedCodec<
          upf::pb::UpfArpResponderEntryKey, upf::pb::UpfArpResponderEntryValue>>(
          [](const upf::pb::UpfArpResponderEntryKey &key)
              -> std::expected<dataplane::ResourceKey, std::string> {
            bess::utils::be32_t ip;
            if (key.ip().empty()) {
              return std::unexpected("IP address is missing");
            }
            if (!bess::utils::ParseIpv4Address(key.ip(), &ip)) {
              return std::unexpected("Invalid IP address: " + key.ip());
            }
            if (ip.value() == 0) {
              return std::unexpected("0.0.0.0 names no subscriber address");
            }
            return dataplane::EncodeKey(ip.value());
          },
          [](const upf::pb::UpfArpResponderEntryValue &value)
              -> std::expected<std::any, std::string> {
            Ethernet::Address mac;
            if (!mac.FromString(value.mac_addr())) {
              return std::unexpected("Invalid MAC address: " + value.mac_addr());
            }
            return std::any(mac);
          },
          // Read back as a client writes an entry: the address in dotted
          // decimal, the MAC in lower case.
          [this](const auto &visit) {
            resource_->ForEach([&visit](const arp::Entry &entry) {
              upf::pb::UpfArpResponderEntryKey key;
              key.set_ip(bess::utils::ToIpv4Address(
                  bess::utils::be32_t(entry.ip)));
              upf::pb::UpfArpResponderEntryValue value;
              value.set_mac_addr(entry.mac.ToString());
              visit(key, value);
            });
          }));
  if (auto registered = init_context().resources().Register(resource_.get());
      !registered) {
    binding_.Reset();
    resource_.reset();
    return CommandFailure(EEXIST, "%s", registered.error().c_str());
  }

  LOG(INFO) << name() << ": " << resource_->name() << " up to " << max_entries
            << " entries, live";
  return CommandSuccess();
}

void UpfArpResponder::DeInit() {
  if (!resource_) {
    return;
  }
  const std::string resource_name = resource_->name();
  auto released = init_context().resources().ReleaseForTeardown(
      std::span<const std::string>(&resource_name, 1));
  CHECK(released) << released.error();
  binding_.Reset();
  resource_.reset();
}

void UpfArpResponder::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  const size_t cnt = batch->cnt();
  gate_idx_t ogates[bess::PacketBatch::kMaxBurst];

  for (size_t i = 0; i < cnt; i++) {
    bess::PacketRef pkt = batch->packet(i);
    // One acquire load per request: the entry the session's transaction
    // published.
    const arp::ProxyVerdict verdict = arp::AnswerProxyRequest(
        std::span<uint8_t>(pkt.head_data<uint8_t *>(), pkt.head_len()),
        [this](uint32_t ip) { return resource_->Lookup(ip); });
    ogates[i] = verdict == arp::ProxyVerdict::kReply ? 0 : DROP_GATE;
  }

  EmitBatch(ctx, batch, ogates);
}

std::string UpfArpResponder::GetDesc() const {
  return std::format("{} entries, live",
                     resource_ ? resource_->LiveCount() : 0);
}

ADD_MODULE(UpfArpResponder, "upf_arp_responder",
           "answers ARP requests for the addresses its live \"entries\" "
           "resource holds")
