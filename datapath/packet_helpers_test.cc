// SPDX-License-Identifier: BSD-3-Clause

// The per-packet helpers the graph modules and UpfAppliance share: the GTP-U
// control path (gtpu_control.h), ATSSS access selection (atsss_select.h) and
// the subscriber ARP proxy (arp_proxy.h). Linked into gtpu_datapath_test,
// whose main() runs them; nothing here needs the EAL.

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <span>
#include <utility>
#include <vector>

#include "utils/logging.h"

#include "arp_proxy.h"
#include "atsss_select.h"
#include "end_marker_log.h"
#include "gtpu_control.h"
#include "gtpu_wire.h"
#include "tunnel/tunnel.h"
#include "utils/arp.h"
#include "utils/checksum.h"
#include "utils/endian.h"
#include "utils/ether.h"
#include "utils/ip.h"

namespace {

using bess::utils::be16_t;
using bess::utils::be32_t;
using upf::datapath::AnswerGtpuControlFrame;
using upf::datapath::GetWire16;
using upf::datapath::GetWire32;
using upf::datapath::GtpuControlContext;
using upf::datapath::GtpuControlVerdict;
using upf::datapath::GtpuErrorCounts;
using upf::datapath::PutWire16;
using upf::datapath::PutWire32;

constexpr size_t kEth = 14;
constexpr size_t kIpv4 = 20;
constexpr size_t kIpv6 = 40;
constexpr size_t kUdp = 8;
constexpr size_t kGtpu = 8;
constexpr uint16_t kPeerPort = 40000;
constexpr uint32_t kStamp = 0xe1d2c3b4;

// One segment as a packet holds it: the frame, then its tailroom.
struct Frame {
  std::vector<uint8_t> bytes;
  size_t len = 0;
  std::span<uint8_t> frame() { return {bytes.data(), len}; }
  size_t room() const { return bytes.size() - len; }
};

uint32_t NoEndpoint() { return 0; }

// This UPF is 10:..:15, the peer 20:..:25.
void WriteEthernet(uint8_t *p, uint16_t type) {
  for (size_t i = 0; i < 6; ++i) {
    p[i] = static_cast<uint8_t>(0x10 + i);
    p[6 + i] = static_cast<uint8_t>(0x20 + i);
  }
  PutWire16(p + 12, type);
}

void WriteGtpuMessage(uint8_t *g, uint8_t flags, uint8_t type, uint32_t teid,
                      const std::vector<uint8_t> &body) {
  g[0] = flags;
  g[1] = type;
  PutWire16(g + 2, static_cast<uint16_t>(body.size()));
  PutWire32(g + 4, teid);
  std::copy(body.begin(), body.end(), g + kGtpu);
}

// A GTP-U message from the peer (10.0.0.2:40000) to this UPF (10.0.0.1).
Frame Gtpu4(uint8_t flags, uint8_t type, uint32_t teid, const std::vector<uint8_t> &body,
            size_t room = 64, uint16_t dst_port = bess::tunnel::kGtpuPort) {
  const size_t gtpu = kGtpu + body.size();
  Frame f{std::vector<uint8_t>(kEth + kIpv4 + kUdp + gtpu + room), kEth + kIpv4 + kUdp + gtpu};
  uint8_t *p = f.bytes.data();
  WriteEthernet(p, 0x0800);
  bess::tunnel::WriteIpv4(p + kEth, be32_t(0x0a000002), be32_t(0x0a000001), 17,
                          static_cast<uint16_t>(kUdp + gtpu));
  bess::tunnel::WriteUdp(p + kEth + kIpv4, kPeerPort, dst_port, static_cast<uint16_t>(gtpu));
  WriteGtpuMessage(p + kEth + kIpv4 + kUdp, flags, type, teid, body);
  return f;
}

// The same from 2001:db8::2 to 2001:db8::1.
Frame Gtpu6(uint8_t flags, uint8_t type, uint32_t teid, const std::vector<uint8_t> &body,
            size_t room = 64) {
  const size_t gtpu = kGtpu + body.size();
  Frame f{std::vector<uint8_t>(kEth + kIpv6 + kUdp + gtpu + room), kEth + kIpv6 + kUdp + gtpu};
  uint8_t *p = f.bytes.data();
  WriteEthernet(p, 0x86dd);
  uint8_t *ip = p + kEth;
  ip[0] = 0x60;
  PutWire16(ip + 4, static_cast<uint16_t>(kUdp + gtpu));
  ip[6] = 17;
  ip[7] = 64;
  ip[8] = 0x20, ip[9] = 0x01, ip[10] = 0x0d, ip[11] = 0xb8, ip[23] = 2;
  ip[24] = 0x20, ip[25] = 0x01, ip[26] = 0x0d, ip[27] = 0xb8, ip[39] = 1;
  uint8_t *udp = ip + kIpv6;
  bess::tunnel::WriteUdp(udp, kPeerPort, bess::tunnel::kGtpuPort, static_cast<uint16_t>(gtpu));
  WriteGtpuMessage(udp + kUdp, flags, type, teid, body);
  PutWire16(udp + 6, upf::datapath::Ipv6UdpChecksum(ip + 8, ip + 24, udp, kUdp + gtpu));
  return f;
}

// An inner IPv4 packet's first bytes: a G-PDU must carry a T-PDU.
std::vector<uint8_t> Inner() {
  std::vector<uint8_t> inner(20);
  inner[0] = 0x45;
  return inner;
}

TEST(GtpuControl, AnswersAnEchoRequestWithRecoveryIesInPlace) {
  // S set, sequence 0x1234, and the peer's own Recovery IE, which the reply
  // replaces with this node's.
  Frame f = Gtpu4(0x32, upf::datapath::kGtpuEchoRequest, 0, {0x12, 0x34, 0, 0, 14, 7});
  const GtpuControlContext ctx{.recovery_time_stamp = kStamp};
  const auto result = AnswerGtpuControlFrame(f.frame(), f.room(), ctx, NoEndpoint);
  ASSERT_EQ(result.verdict, GtpuControlVerdict::kEchoResponse);
  const size_t gtp = kEth + kIpv4 + kUdp;
  ASSERT_EQ(result.reply_len, gtp + kGtpu + upf::datapath::kGtpuEchoResponseTail);

  const uint8_t *p = f.bytes.data();
  EXPECT_EQ(p[0], 0x20);  // back to the peer
  EXPECT_EQ(p[6], 0x10);
  const auto *ip = reinterpret_cast<const bess::utils::Ipv4 *>(p + kEth);
  EXPECT_EQ(ip->src.value(), 0x0a000001u);
  EXPECT_EQ(ip->dst.value(), 0x0a000002u);
  EXPECT_EQ(ip->length.value(), kIpv4 + kUdp + kGtpu + 17);
  EXPECT_TRUE(bess::utils::VerifyIpv4NoOptChecksum(*ip));
  const uint8_t *udp = p + kEth + kIpv4;
  EXPECT_EQ(GetWire16(udp), bess::tunnel::kGtpuPort);
  EXPECT_EQ(GetWire16(udp + 2), kPeerPort);
  EXPECT_EQ(GetWire16(udp + 4), kUdp + kGtpu + 17);
  EXPECT_EQ(GetWire16(udp + 6), 0);  // IPv4 permits zero
  const uint8_t *g = p + gtp;
  EXPECT_EQ(g[0], 0x32);
  EXPECT_EQ(g[1], upf::datapath::kGtpuEchoResponse);
  EXPECT_EQ(GetWire16(g + 2), 17);
  EXPECT_EQ(GetWire32(g + 4), 0u);
  const std::array<uint8_t, 17> tail = {0x12, 0x34, 0, 0,  // sequence, N-PDU, next ext
                                        14,   0,           // Recovery, restart 0
                                        231,  0,    8,     // Recovery Time Stamp
                                        0xe1, 0xd2, 0xc3, 0xb4, 0, 0, 0, 0};
  EXPECT_TRUE(std::equal(tail.begin(), tail.end(), g + kGtpu));
}

TEST(GtpuControl, AnEchoWithoutSequenceAnswersZeroAndGrowsIntoTailroom) {
  Frame f = Gtpu4(0x30, upf::datapath::kGtpuEchoRequest, 0, {});
  const size_t request = f.len;
  const auto result =
      AnswerGtpuControlFrame(f.frame(), f.room(), GtpuControlContext{}, NoEndpoint);
  ASSERT_EQ(result.verdict, GtpuControlVerdict::kEchoResponse);
  EXPECT_EQ(result.reply_len, request + 17);
  const uint8_t *g = f.bytes.data() + kEth + kIpv4 + kUdp;
  EXPECT_EQ(g[0], 0x32);  // the response sets S even so
  EXPECT_EQ(GetWire16(g + kGtpu), 0);
}

TEST(GtpuControl, AnswersAnUnknownIpv6GpduWithAnErrorIndication) {
  Frame f = Gtpu6(0x30, bess::tunnel::kGtpuGpdu, 0x0a0b0c0d, Inner());
  const auto result =
      AnswerGtpuControlFrame(f.frame(), f.room(), GtpuControlContext{}, NoEndpoint);
  ASSERT_EQ(result.verdict, GtpuControlVerdict::kErrorIndication);
  const size_t gtp = kEth + kIpv6 + kUdp;
  ASSERT_EQ(result.reply_len, gtp + kGtpu + upf::datapath::kGtpuErrorIndicationTail);
  EXPECT_LT(result.reply_len, f.len);  // the T-PDU is cut

  uint8_t *p = f.bytes.data();
  const uint8_t *ip = p + kEth;
  EXPECT_EQ(ip[23], 1);  // source is now this UPF
  EXPECT_EQ(ip[39], 2);
  EXPECT_EQ(GetWire16(ip + 4), kUdp + kGtpu + 5);
  uint8_t *udp = p + kEth + kIpv6;
  EXPECT_EQ(GetWire16(udp), bess::tunnel::kGtpuPort);
  EXPECT_EQ(GetWire16(udp + 2), kPeerPort);
  EXPECT_EQ(GetWire16(udp + 4), kUdp + kGtpu + 5);
  const uint16_t checksum = GetWire16(udp + 6);
  PutWire16(udp + 6, 0);
  EXPECT_EQ(checksum, upf::datapath::Ipv6UdpChecksum(ip + 8, ip + 24, udp, kUdp + kGtpu + 5));
  const uint8_t *g = p + gtp;
  EXPECT_EQ(g[0], 0x30);
  EXPECT_EQ(g[1], upf::datapath::kGtpuErrorIndication);
  EXPECT_EQ(GetWire16(g + 2), 5);
  EXPECT_EQ(GetWire32(g + 4), 0u);
  EXPECT_EQ(g[kGtpu], upf::datapath::kGtpuTeidIe);
  EXPECT_EQ(GetWire32(g + kGtpu + 1), 0x0a0b0c0du);
}

TEST(GtpuControl, DropsWhatItDoesNotAnswerAndLeavesItUnchanged) {
  struct Case {
    Frame frame;
    GtpuControlVerdict verdict;
  };
  Frame long_length = Gtpu4(0x30, bess::tunnel::kGtpuGpdu, 7, Inner());
  PutWire16(long_length.bytes.data() + kEth + kIpv4 + kUdp + 2, 21);  // past the UDP datagram
  std::vector<Case> cases;
  cases.push_back({Gtpu4(0x30, bess::tunnel::kGtpuGpdu, 0, Inner()),
                   GtpuControlVerdict::kZeroTeid});
  cases.push_back({Gtpu4(0x30, bess::tunnel::kGtpuGpdu, 7, Inner(), 64, 2153),
                   GtpuControlVerdict::kNotOurPort});
  cases.push_back({Gtpu4(0x30, 31, 0, {}), GtpuControlVerdict::kUnsupportedType});
  cases.push_back({Gtpu4(0x30, upf::datapath::kGtpuEchoRequest, 0, {}, 16),
                   GtpuControlVerdict::kNoRoom});
  cases.push_back({std::move(long_length), GtpuControlVerdict::kMalformed});
  for (Case &c : cases) {
    const std::vector<uint8_t> before = c.frame.bytes;
    const auto result =
        AnswerGtpuControlFrame(c.frame.frame(), c.frame.room(), GtpuControlContext{}, NoEndpoint);
    EXPECT_EQ(result.verdict, c.verdict);
    EXPECT_FALSE(upf::datapath::IsGtpuReply(result.verdict));
    EXPECT_EQ(c.frame.bytes, before);
  }
}

TEST(GtpuControl, CountsPeerErrorIndicationsByTheTeidIe) {
  // S set: the sequence field, then the TEID Data I IE.
  const std::vector<uint8_t> body = {0, 1, 0, 0, upf::datapath::kGtpuTeidIe, 0, 0, 0x12, 0x34};
  GtpuErrorCounts errors;
  const GtpuControlContext ctx{.errors = &errors};
  for (int n = 0; n < 2; n++) {
    Frame f = Gtpu4(0x32, upf::datapath::kGtpuErrorIndication, 0, body);
    const std::vector<uint8_t> before = f.bytes;
    EXPECT_EQ(AnswerGtpuControlFrame(f.frame(), f.room(), ctx, NoEndpoint).verdict,
              GtpuControlVerdict::kPeerErrorIndication);
    EXPECT_EQ(f.bytes, before);  // never answered
  }
  EXPECT_EQ(errors.Count(0x1234), 2u);
  EXPECT_EQ(errors.Untracked(), 0u);

  // Not tracked: the same verdict, nothing counted anywhere.
  Frame f = Gtpu4(0x32, upf::datapath::kGtpuErrorIndication, 0, body);
  EXPECT_EQ(AnswerGtpuControlFrame(f.frame(), f.room(), GtpuControlContext{}, NoEndpoint).verdict,
            GtpuControlVerdict::kPeerErrorIndication);
  EXPECT_EQ(errors.Count(0x1234), 2u);
}

TEST(GtpuControl, LogsEndMarkersWithTheirEndpoint) {
  upf::datapath::EndMarkerLog log(2);
  const GtpuControlContext ctx{.end_markers = &log, .worker = 1};
  int asked = 0;
  auto endpoint = [&asked](uint32_t id) {
    return [&asked, id] {
      ++asked;
      return id;
    };
  };

  Frame f = Gtpu4(0x30, upf::datapath::kGtpuEndMarker, 0x55, {});
  EXPECT_EQ(AnswerGtpuControlFrame(f.frame(), f.room(), ctx, endpoint(9)).verdict,
            GtpuControlVerdict::kEndMarker);
  // Endpoint 0 is unknown: not logged.
  Frame unknown = Gtpu4(0x30, upf::datapath::kGtpuEndMarker, 0x56, {});
  EXPECT_EQ(AnswerGtpuControlFrame(unknown.frame(), unknown.room(), ctx, endpoint(0)).verdict,
            GtpuControlVerdict::kEndMarker);
  EXPECT_EQ(log.Drain(), (std::vector<upf::datapath::EndMarkerEvent>{{9, 0x55}}));
  EXPECT_EQ(asked, 2);

  // Not tracked: the endpoint is never read.
  Frame untracked = Gtpu4(0x30, upf::datapath::kGtpuEndMarker, 0x57, {});
  EXPECT_EQ(AnswerGtpuControlFrame(untracked.frame(), untracked.room(), GtpuControlContext{},
                                   endpoint(9))
                .verdict,
            GtpuControlVerdict::kEndMarker);
  EXPECT_EQ(asked, 2);
}

TEST(GtpuErrorCounts, CountsPerTeidAndCountsAFullTable) {
  GtpuErrorCounts counts(2);
  EXPECT_EQ(GtpuErrorCounts::Bytes(2), counts.bytes());
  counts.Record(1);
  counts.Record(2);
  counts.Record(2);
  counts.Record(3);  // no slot left
  EXPECT_EQ(counts.Count(1), 1u);
  EXPECT_EQ(counts.Count(2), 2u);
  EXPECT_FALSE(counts.Count(3).has_value());
  EXPECT_FALSE(counts.Count(0).has_value());
  EXPECT_EQ(counts.Untracked(), 1u);
  std::map<uint32_t, uint64_t> seen;
  counts.ForEach([&seen](uint32_t teid, uint64_t count) { seen[teid] = count; });
  EXPECT_EQ(seen, (std::map<uint32_t, uint64_t>{{1, 1}, {2, 2}}));

  GtpuErrorCounts empty;
  EXPECT_FALSE(empty.Count(0).has_value());  // an empty slot is not TEID 0's
}

// -- ATSSS ------------------------------------------------------------------------

using upf::atsss::AccessHealth;
using upf::atsss::SteeringPolicy;
using upf::atsss::SteerVerdict;

struct AtsssTables {
  std::map<uint32_t, SteeringPolicy> policies;
  std::map<uint32_t, AccessHealth> health;
  int policy_lookups = 0;

  upf::atsss::Steering Steer(uint32_t policy_id) {
    return upf::atsss::Steer(
        policy_id,
        [this](uint32_t id) -> const SteeringPolicy * {
          ++policy_lookups;
          auto it = policies.find(id);
          return it == policies.end() ? nullptr : &it->second;
        },
        [this](uint32_t id) -> const AccessHealth * {
          auto it = health.find(id);
          return it == health.end() ? nullptr : &it->second;
        });
  }
};

SteeringPolicy TwoAccesses(uint32_t preferred) {
  SteeringPolicy policy;
  policy.preferred = preferred;
  policy.access[0] = {.next_hop_id = 10, .tunnel_id = 11, .accounting_id = 12, .health_id = 1};
  policy.access[1] = {.next_hop_id = 20, .tunnel_id = 21, .accounting_id = 22, .health_id = 2};
  return policy;
}

TEST(AtsssSelect, PolicyZeroIsNotSteeredAndAMissingPolicyFailsClosed) {
  AtsssTables tables;
  EXPECT_EQ(tables.Steer(0).verdict, SteerVerdict::kNotSteered);
  EXPECT_EQ(tables.policy_lookups, 0);
  const auto missing = tables.Steer(5);
  EXPECT_EQ(missing.verdict, SteerVerdict::kNoPolicy);
  EXPECT_EQ(missing.access, nullptr);
}

TEST(AtsssSelect, PrefersTheAvailableAccessAndFallsBackToTheOther) {
  AtsssTables tables;
  tables.policies[5] = TwoAccesses(1);

  // No health record is "not monitored": the preferred access.
  auto steering = tables.Steer(5);
  ASSERT_EQ(steering.verdict, SteerVerdict::kSteered);
  EXPECT_EQ(steering.access->next_hop_id, 20u);
  EXPECT_EQ(steering.access->tunnel_id, 21u);
  EXPECT_EQ(steering.access->accounting_id, 22u);

  tables.health[2] = {.available = false};
  steering = tables.Steer(5);
  ASSERT_EQ(steering.verdict, SteerVerdict::kSteered);
  EXPECT_EQ(steering.access->next_hop_id, 10u);

  tables.health[1] = {.available = false};
  EXPECT_EQ(tables.Steer(5).verdict, SteerVerdict::kNoAccess);

  tables.health[2] = {.available = true};
  steering = tables.Steer(5);
  ASSERT_EQ(steering.verdict, SteerVerdict::kSteered);
  EXPECT_EQ(steering.access->next_hop_id, 20u);
}

TEST(AtsssSelect, SkipsAnUnprovisionedAccess) {
  SteeringPolicy policy = TwoAccesses(0);
  policy.access[0] = {};  // active/standby with one access
  const upf::atsss::AccessAction *selected =
      upf::atsss::SelectAccess(policy, [](uint32_t) -> const AccessHealth * { return nullptr; });
  ASSERT_NE(selected, nullptr);
  EXPECT_EQ(selected->next_hop_id, 20u);

  policy.access[1] = {};
  EXPECT_EQ(upf::atsss::SelectAccess(
                policy, [](uint32_t) -> const AccessHealth * { return nullptr; }),
            nullptr);
}

// -- ARP proxy --------------------------------------------------------------------

using bess::utils::Arp;
using bess::utils::Ethernet;
using upf::arp::ProxyVerdict;

constexpr size_t kArpFrame = sizeof(Ethernet) + sizeof(Arp);

Ethernet::Address Mac(uint8_t last) {
  Ethernet::Address mac;
  for (size_t i = 0; i < 6; ++i) {
    mac.bytes[i] = static_cast<uint8_t>(0x02 + i);
  }
  mac.bytes[5] = last;
  return mac;
}

// who-has 10.45.0.2 tell 10.45.0.1, from a requester whose frame source is
// `frame_src` and whose ARP sender hardware address is `sender`.
std::vector<uint8_t> ArpRequest(const Ethernet::Address &frame_src,
                                const Ethernet::Address &sender) {
  std::vector<uint8_t> frame(kArpFrame);
  auto *eth = reinterpret_cast<Ethernet *>(frame.data());
  std::memset(eth->dst_addr.bytes, 0xff, 6);
  eth->src_addr = frame_src;
  eth->ether_type = be16_t(Ethernet::Type::kArp);
  auto *arp = reinterpret_cast<Arp *>(eth + 1);
  arp->hw_addr = be16_t(Arp::kEthernet);
  arp->proto_addr = be16_t(Ethernet::Type::kIpv4);
  arp->hw_addr_length = 6;
  arp->proto_addr_length = 4;
  arp->opcode = be16_t(Arp::Opcode::kRequest);
  arp->sender_hw_addr = sender;
  arp->sender_ip_addr = be32_t(0x0a2d0001);
  std::memset(arp->target_hw_addr.bytes, 0, 6);
  arp->target_ip_addr = be32_t(0x0a2d0002);
  return frame;
}

struct ArpTable {
  upf::arp::Entry entry{.ip = 0x0a2d0002, .mac = Mac(0x99)};
  const upf::arp::Entry *operator()(uint32_t ip) const { return ip == entry.ip ? &entry : nullptr; }
};

TEST(ArpProxy, AnswersARequestForAHeldAddressInPlace) {
  std::vector<uint8_t> frame = ArpRequest(Mac(0x01), Mac(0x01));
  ASSERT_EQ(upf::arp::AnswerProxyRequest(frame, ArpTable{}), ProxyVerdict::kReply);
  const auto *eth = reinterpret_cast<const Ethernet *>(frame.data());
  const auto *arp = reinterpret_cast<const Arp *>(eth + 1);
  EXPECT_EQ(eth->dst_addr, Mac(0x01));
  EXPECT_EQ(eth->src_addr, Mac(0x99));
  EXPECT_EQ(arp->opcode.value(), Arp::Opcode::kReply);
  EXPECT_EQ(arp->sender_hw_addr, Mac(0x99));
  EXPECT_EQ(arp->sender_ip_addr.value(), 0x0a2d0002u);
  EXPECT_EQ(arp->target_hw_addr, Mac(0x01));
  EXPECT_EQ(arp->target_ip_addr.value(), 0x0a2d0001u);
  EXPECT_EQ(arp->hw_addr.value(), Arp::kEthernet);
  EXPECT_EQ(arp->proto_addr.value(), Ethernet::Type::kIpv4);
}

TEST(ArpProxy, RepliesToTheFrameSourceNotTheArpSender) {
  // Where this differs from route::AnswerArpRequest: the reply's Ethernet
  // destination is the request's Ethernet source.
  std::vector<uint8_t> frame = ArpRequest(Mac(0x01), Mac(0x02));
  ASSERT_EQ(upf::arp::AnswerProxyRequest(frame, ArpTable{}), ProxyVerdict::kReply);
  const auto *eth = reinterpret_cast<const Ethernet *>(frame.data());
  const auto *arp = reinterpret_cast<const Arp *>(eth + 1);
  EXPECT_EQ(eth->dst_addr, Mac(0x01));
  EXPECT_EQ(arp->target_hw_addr, Mac(0x02));
}

TEST(ArpProxy, DropsWhatItDoesNotAnswerAndLeavesItUnchanged) {
  std::vector<uint8_t> unknown = ArpRequest(Mac(0x01), Mac(0x01));
  reinterpret_cast<Arp *>(unknown.data() + sizeof(Ethernet))->target_ip_addr = be32_t(0x0a2d0003);
  std::vector<uint8_t> reply = ArpRequest(Mac(0x01), Mac(0x01));
  reinterpret_cast<Arp *>(reply.data() + sizeof(Ethernet))->opcode =
      be16_t(Arp::Opcode::kReply);
  std::vector<uint8_t> ipv4 = ArpRequest(Mac(0x01), Mac(0x01));
  reinterpret_cast<Ethernet *>(ipv4.data())->ether_type = be16_t(Ethernet::Type::kIpv4);
  std::vector<uint8_t> shorter = ArpRequest(Mac(0x01), Mac(0x01));
  shorter.pop_back();

  const std::pair<std::vector<uint8_t> *, ProxyVerdict> cases[] = {
      {&unknown, ProxyVerdict::kUnknownTarget},
      {&reply, ProxyVerdict::kNotRequest},
      {&ipv4, ProxyVerdict::kNotArp},
      {&shorter, ProxyVerdict::kTooShort},
  };
  for (const auto &[frame, verdict] : cases) {
    const std::vector<uint8_t> before = *frame;
    EXPECT_EQ(upf::arp::AnswerProxyRequest(*frame, ArpTable{}), verdict);
    EXPECT_EQ(*frame, before);
  }
}

}  // namespace
