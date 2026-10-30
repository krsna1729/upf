// SPDX-License-Identifier: BSD-3-Clause
#ifndef UPF_DATAPATH_UPF_APPLIANCE_H_
#define UPF_DATAPATH_UPF_APPLIANCE_H_

#include <array>
#include <atomic>
#include <memory>
#include <span>
#include <string>
#include <vector>
#include "utils/logging.h"
#include "module.h"
#include "pb/module_msg.pb.h"
#include "upf_datapath.pb.h"
#include "arp_responder_resource.h"
#include "atsss_select.h"
#include "fteid_resource.h"
#include "gtpu_control.h"
#include "pdr_scan.h"
#include "dataplane/action_id.h"
#include "dataplane/slot_resource.h"
#include "dataplane/slot_table.h"
#include "framework/memory_scope.h"
#include "framework/resource_bindings.h"
#include "meter/meter_resource.h"
#include "rcu/rcu_ptr.h"
#include "route/router.h"
#include "stats/keyed_counters.h"
#include "stats/metric_registry.h"
#include "utils/dpdk_memory.h"

namespace upf::appliance {
using Id = bess::dataplane::ActionId;
using bess::framework::Sized;
struct Tunnel {
  uint32_t teid = 0;
  uint8_t family = 0;
  uint8_t local[16]{}, peer[16]{};
  uint32_t transport_route_domain = 0;
  uint8_t qfi = 0;
  uint16_t marking = 0;
  bool has_qfi = false;
};
struct CounterEntry {};
struct Stamps { std::atomic<uint64_t> first{0}, last{0}; };
struct Counters {
  Sized<bess::dataplane::SlotTable<Id, CounterEntry>> entries;
  Sized<bess::stats::KeyedCounters> cells;
  bess::framework::MemoryLease stamps_lease;
  bess::utils::DpdkArray<Stamps> stamps;
  std::unique_ptr<bess::dataplane::SlotResource<Id, CounterEntry>> resource;
};
// A direction's PDRs: per-anchor FirewallScan policies (pdr_scan.h). The
// anchor index is declared first: the resource points into it.
struct Pdr {
  bess::framework::Sized<bess::flow::SharedExactIndex> anchors;
  bess::framework::Sized<PdrScanResource> resource;
};
struct Interface {
  uint16_t ingress_gate = 0, output_gate = 0, vlan = 0, id = 0;
  bool n6 = false;
  uint32_t endpoint_id = 0, route_domain = 0, transport_route_domain = 0;
  bess::utils::Ethernet::Address mac;
  bess::utils::be32_t ipv4{};
  bess::utils::Ipv6Address ipv6{};
};
enum class Lane : uint8_t { kDrop, kUl, kDl, kTransport, kOutput, kBuffer, kHeld };
struct FrameState {
  Lane lane = Lane::kDrop;
  const Interface *interface = nullptr;
  uint32_t endpoint_id = 0, fteid_context = 0;
  uint32_t route_domain = 0, transport_route_domain = 0;
  uint32_t action_id = 0, meters[2]{}, next_hop_id = 0, policy_id = 0;
  uint8_t qfi = 0xff, direction = 0, repass = 0;
  gate_idx_t output_gate = DROP_GATE;
};
// Stable operational reason ids; consumed control frames are counted too.
enum class Reason : size_t {
  kUnknownInput, kShortEthernet, kUnknownMac, kBadVlan, kNotWritable,
  kMalformedGtpu, kNonlinear, kBadInner, kDecapNoRoom,
  kPdrShort, kPdrMiss, kPdrDrop, kPdrGate, kMeterUnknown, kMeterRed,
  kNoPolicy, kNoAccess, kNoNextHop, kUnresolved, kLocalHop, kRouterMalformed,
  kTtlExpired, kBadEgress, kRepassLimit, kNoTunnel, kEncapFailed,
  kTransportNotIp, kTransportMalformed, kTransportFragment, kTransportFamily,
  kTransportLinkScope, kTransportNoRoute, kTransportUnresolved,
  kTransportLocal, kTransportTtl, kTransportEgress,
  kControlPeerError, kControlEndMarker, kControlNonlinear, kControlMalformed,
  kControlPort, kControlType, kControlZeroTeid, kControlL3, kControlNoRoom,
  kArpShort, kArpNotRequest, kArpUnknown, kNdUnknown, kNeighborInputFull,
  kNeighborTxFull, kNeighborAlloc, kNeighborPublish, kBufferEvicted,
  kBufferExpired, kBufferDropped, kBufferRequestFull, kBufferStateFull,
  kNeighborConsumed,
  kCount
};
}  // namespace upf::appliance

class UpfAppliance final : public Module {
 public:
  static const gate_idx_t kNumIGates = MAX_GATES;
  static const gate_idx_t kNumOGates = MAX_GATES;
  static constexpr ModuleCapabilities kCapabilities{
      ModuleCapabilities::State::kSingleWorker, ModuleCapabilities::FlowAffinity::kNone};
  static const ResourceTables resource_tables;
  static const Commands cmds;
  UpfAppliance();
  ~UpfAppliance() override;
  CommandResponse Init(const upf::pb::UpfApplianceArg &arg);
  void DeInit() override;
  void ProcessBatch(Context *, bess::PacketBatch *) override;
  struct task_result RunTask(Context *, bess::PacketBatch *, void *) override;
  std::string GetDesc() const override;
  CheckConstraintResult CheckModuleConstraints() const override;
  CommandResponse CommandGetCounts(const upf::pb::UrrCountCommandGetCountsArg &);
  CommandResponse CommandGetErrors(const upf::pb::GtpuResponderCommandGetErrorsArg &);
  CommandResponse CommandDrainEndMarkers(const upf::pb::GtpuResponderCommandDrainEndMarkersArg &);
  CommandResponse CommandRelease(const bess::pb::PacketStoreCommandReleaseArg &);
  CommandResponse CommandDrop(const bess::pb::PacketStoreCommandDropArg &);
  CommandResponse CommandClear(const bess::pb::PacketStoreCommandClearArg &);
  CommandResponse CommandSelfTest(const bess::pb::EmptyArg &);
  CommandResponse CommandGetDrops(const bess::pb::EmptyArg &);

 private:
  using State = upf::appliance::FrameState;
  using Reason = upf::appliance::Reason;
  using Id = upf::appliance::Id;
  // A command/tick can count alongside the one worker.
  void Count(Reason reason, uint64_t n = 1) noexcept {
    reasons_[static_cast<size_t>(reason)].fetch_add(n, std::memory_order_relaxed);
  }
  void Drop(State &s, Reason r) noexcept { Count(r); s.lane = upf::appliance::Lane::kDrop; }
  CommandResponse InitResources(const upf::pb::UpfApplianceArg &);
  void ReleaseResources();
  CommandResponse InitSlow(const upf::pb::UpfApplianceArg &);
  void ReleaseSlow();
  // Called after VLAN stripping, before destination MAC admission. True means
  // handled (answer/output, resolver consume/drop); false is ordinary IP/data.
  bool SlowIngress(Context *, bess::PacketRef, uint16_t ingress, uint16_t vlan, State &);
  void ControlGtpu(Context *, bess::PacketRef, State &);
  void Transport(bess::PacketBatch *, State *, size_t);
  void ClassifyPdr(bess::PacketBatch *, State *, size_t, bool downlink);
  void MeterCountRoute(Context *, bess::PacketBatch *, State *, size_t);
  void Finish(Context *, bess::PacketBatch *, State *, size_t);
  void Resume(Context *, bess::PacketBatch *, State *, size_t);
  void CountUsage(Context *, bess::PacketBatch *, State *, size_t,
                  upf::appliance::Counters &, bool buffer);
  void Hold(Context *, bess::PacketRef, const State &);
  CommandResponse InitBuffer(const upf::pb::UpfApplianceArg &);
  void BufferTask(Context *, bess::PacketBatch *);
  void ReleaseBuffer();
  bool Encap(bess::PacketRef, const upf::appliance::Tunnel &) const;
  const upf::appliance::Interface *FindInterface(uint16_t ingress, uint16_t vlan,
      const bess::utils::Ethernet::Address &) const noexcept;

  bess::framework::MemoryLease interfaces_lease_;
  std::vector<upf::appliance::Interface> interfaces_;
  std::vector<upf::pb::UpfApplianceNextHopClass> next_hop_classes_;
  std::vector<upf::pb::UpfApplianceMarkerInput> marker_inputs_;
  uint16_t port_ = 2152, src_port_ = 0, dst_port_ = 2152;
  uint32_t stamp_ = 0;
  size_t capacity_ = 65536;
  std::array<std::atomic<uint64_t>, static_cast<size_t>(Reason::kCount)> reasons_{};
  std::array<std::array<std::atomic<uint64_t>, 3>, 2> meter_colors_{};
  bess::stats::MetricSource meter_metric_;
  bess::framework::Sized<bess::flow::SharedExactIndex> fteids_;
  bess::framework::Sized<upf::datapath::FteidResource> fteid_resource_;
  upf::appliance::Pdr pdr_ul_, pdr_dl_;
  bess::framework::Sized<bess::meter::MeterResource> meters_;
  bess::rcu::RcuPtr<bess::meter::MeterSet> meter_set_{init_context().rcu()};
  upf::appliance::Counters counters_ul_, counters_dl_, buffer_counters_;
  bess::framework::Sized<bess::dataplane::SlotTable<Id, upf::appliance::Tunnel>> tunnels_;
  std::unique_ptr<bess::dataplane::SlotResource<Id, upf::appliance::Tunnel>> tunnel_resource_;
  bess::framework::Sized<bess::dataplane::SlotTable<Id, upf::atsss::SteeringPolicy>> policies_;
  bess::framework::Sized<bess::dataplane::SlotTable<Id, upf::atsss::AccessHealth>> health_;
  std::unique_ptr<bess::dataplane::SlotResource<Id, upf::atsss::SteeringPolicy>> policy_resource_;
  std::unique_ptr<bess::dataplane::SlotResource<Id, upf::atsss::AccessHealth>> health_resource_;
  bess::framework::Sized<upf::arp::EntriesResource> entries_;
  bess::framework::Sized<upf::datapath::GtpuErrorCounts> errors_;
  bess::framework::Sized<upf::datapath::EndMarkerLog> end_markers_;
  bess::framework::Sized<bess::route::Router> router_, transport_router_;
  std::vector<bess::framework::ResourceBinding> bindings_;
  std::vector<std::string> registered_;
  struct Slow;
  std::shared_ptr<Slow> slow_;
  struct Buffer;
  std::shared_ptr<Buffer> buffer_;
};
#endif
