// SPDX-License-Identifier: BSD-3-Clause

// The A/B bench: independent graph (A) and owned UpfAppliance (B), or, with
// --baseline-plugin, two builds of the appliance (parent and commit).
// Each arm has its own daemon lifetime and independently programmed session
// tables. Only one arm exists at a time, including at one million sessions.
// Packets remain in-process: Source -> Rewrite -> UpfBenchGen -> arm ->
// UpfHashSink; the SDK carries configuration and measurements, never packets.
//
// Before timing either arm, exact seeded streams must have identical external
// byte digests and every rule's packet/octet delta. Measurement then uses ABBA
// windows, restarting/reloading on arm changes so no graph is available to B.
//
//   upf_ab --bessd B --plugin DIR --sessions N [--rounds R] [--duration S]
//          [--burst 32] [--miss PERMILLE] [--worker-cpu 11] [--control-cpu 9]
//          [--mem-backing auto|hugepages|normal] [--mem-hugepage-mb MB]
//          [--bessd-arg ARG]... [--verify K] [--churn TX_PER_S] [--counters]
//          [--layout masked|session] [--only graph|appliance] [--updates U]
//          [--mask-mix K]
//          [--baseline-plugin DIR --baseline-layout masked|session]
//          [--graph-plugin DIR]
//
// --graph-plugin DIR runs the graph arm from another plugin build (a parent
// that has no appliance yet, against the commit that adds it).
//
// --baseline-plugin replaces the graph arm with another independent owned
// appliance. Reports call that arm "baseline"; the candidate still uses
// --plugin and --layout. Both must pass the same exact-stream checks.
//
// --mem-backing and --mem-hugepage-mb pass through as bessd's --mem_backing
// and --mem_hugepage_mb; size a normal-page heap with
// --bessd-arg --mem_limit_mb=N (heap = limit - reserve).
//
// --layout selects the appliance's session representation: masked (default)
// programs the owned plugin's fteids/pdr_ul/pdr_dl/meters/counters_ul/counters_dl/
// tunnels resources, eight entries per session without --mask-mix, as the graph
// does; session
// programs a session-major plugin's "upf/sessions" with ONE entry per session
// carrying the same F-TEID, PDRs, actions, QERs and tunnel. --plugin names
// the matching plugin build. --only runs one arm (load, exact-stream packet
// and counter assertions, memory) with --rounds 0: there is no cross-arm
// comparison then. After each load the daemon's VmRSS/VmHWM/HugetlbPages are
// printed; a refused load commit prints its error and whether the daemon
// still answers before it is stopped. --updates U re-upserts U sessions with
// their current values while UL traffic runs, after an arm's verification:
// the masked layouts commit beside the workers; the session layout rewrites
// the session's stride in place, which its resource refuses while a worker
// runs (shown once), so each update pauses, commits and resumes the workers.
//
// --mask-mix K (0 default, 1..64 enabled) adds one higher-priority SDF PDR
// per direction/session, with K distinct mask shapes distributed by s%K.
// Remote prefix /16../31, protocol UDP/any, QFI absent/any, inclusive source
// and destination port ranges, plus the DL route domain, all match the
// replay. Both PDRs still name the session's original action. Thus graph,
// masked, scan and session layouts keep exactly the original expected byte
// stream and per-action packet/octet deltas. Graph/masked/scan write ten
// entries instead of eight; session bundles all four PDRs in its one entry.
// Churn, re-upserts, erases and wire-byte accounting use the same rule builder.
// At least K sessions are needed to instantiate all K shapes. No unanchored
// rules are introduced, preserving the explicit --miss population.

#include <fcntl.h>
#include <google/protobuf/util/json_util.h>
#include <netinet/in.h>
#include <sched.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <iterator>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "bess/sdk/client.h"
#include "schema_types.h"

extern char **environ;

namespace {

namespace gp = google::protobuf;
namespace v2 = bess::pb::v2;
using bess::perf::Base64;
using bess::perf::Be32;
using Clock = std::chrono::steady_clock;

struct Opt {
  std::string bessd, plugin, ld;
  uint32_t sessions = 1000;
  int rounds = 4;
  double duration = 1.0, warmup = 0.3;
  int burst = 32;
  int miss = 0;
  int worker_cpu = 11, control_cpu = 9;
  std::string mem_backing = "auto";  // bessd --mem_backing
  int mem_hugepage_mb = 0;            // > 0: bessd --mem_hugepage_mb
  std::vector<std::string> bessd_args;  // appended to bessd's command line
  int buffers = 32768;
  uint64_t verify = 0;  // 0: max(4N, 200000)
  double churn = 0;
  bool counters = false;
  std::string dirs = "ul,dl";
  std::string layout = "masked";  // appliance arm: masked | session
  std::string baseline_plugin;  // empty: graph; otherwise an owned baseline
  std::string graph_plugin;     // the graph arm's plugin build; empty: --plugin
  std::string baseline_layout = "masked";
  std::string only = "both";      // both | graph | appliance
  uint32_t updates = 0;           // update-cost samples per arm
  uint32_t mask_mix = 0;          // 0 unchanged; 1..64 SDF mask shapes across sessions
  std::string memory_report;      // study: script PORT PID LABEL OUT, run at memory samples
  uint32_t report_every = 100000; // strict budget: memory sample every K loaded sessions
  bool after_refusal = false;     // strict budget: probe the live daemon after a refused load
  bool teardown = false;          // strict budget: erase every session after updates
};

// Scratch files (the daemon's log, its pid file, perf output): $TMPDIR, else /tmp.
std::string TmpPath(const std::string &name) {
  const char *dir = std::getenv("TMPDIR");
  return std::string(dir != nullptr && *dir != '\0' ? dir : "/tmp") + "/" + name;
}

constexpr uint32_t kUeBase = 0x0a000001;    // 10.0.0.1 + s
constexpr uint32_t kTeidBase = 0x10000000;  // uplink F-TEID
constexpr uint32_t kPeerTeidBase = 0x55000000;
// Three action-position bits in session result ids, plus churn headroom.
constexpr uint32_t kMaxStudySessions = (uint32_t{1} << 29) - 2049;

// -- process plumbing (live_perf's) ----------------------------------------------

int FreePort() {
  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  socklen_t len = sizeof(a);
  bind(fd, reinterpret_cast<sockaddr *>(&a), sizeof(a));
  getsockname(fd, reinterpret_cast<sockaddr *>(&a), &len);
  close(fd);
  return ntohs(a.sin_port);
}

bool Listening(int port) {
  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  a.sin_port = htons(port);
  const bool ok = connect(fd, reinterpret_cast<sockaddr *>(&a), sizeof(a)) == 0;
  close(fd);
  return ok;
}

pid_t Spawn(const std::vector<std::string> &argv, const std::string &log = "") {
  std::vector<char *> args;
  for (const std::string &a : argv) args.push_back(const_cast<char *>(a.c_str()));
  args.push_back(nullptr);
  posix_spawn_file_actions_t fa;
  posix_spawn_file_actions_init(&fa);
  const int out = open(log.empty() ? "/dev/null" : log.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
  posix_spawn_file_actions_adddup2(&fa, out, 1);
  posix_spawn_file_actions_adddup2(&fa, out, 2);
  pid_t pid = -1;
  const int rc = posix_spawnp(&pid, args[0], &fa, nullptr, args.data(), environ);
  posix_spawn_file_actions_destroy(&fa);
  close(out);
  if (rc != 0) throw std::runtime_error("cannot run " + argv[0]);
  return pid;
}

int Run(const std::vector<std::string> &argv) {
  int status = 0;
  waitpid(Spawn(argv), &status, 0);
  return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

template <typename T>
T Must(bess::sdk::Result<T> r, const std::string &what) {
  if (!r) throw std::runtime_error(what + ": " + r.error().message + " [grpc " +
                                   std::to_string(static_cast<int>(r.error().code)) + "]");
  return std::move(*r);
}
void Must(const bess::sdk::Result<void> &r, const std::string &what) {
  if (!r) throw std::runtime_error(what + ": " + r.error().message + " [grpc " +
                                   std::to_string(static_cast<int>(r.error().code)) + "]");
}

// Packets out of `module` (gate -1: every gate).
double GatePackets(const std::vector<v2::MetricSample> &samples, const std::string &module,
                   int gate = -1) {
  double total = 0;
  for (const v2::MetricSample &s : samples) {
    const auto &l = s.labels();
    if (s.name() == "bess_gate_packets_total" && l.contains("direction") &&
        l.at("direction") == "out" && l.contains("module") && l.at("module") == module &&
        (gate < 0 || (l.contains("gate") && l.at("gate") == std::to_string(gate)))) {
      total += s.value();
    }
  }
  return total;
}

uint64_t JsonU64(const std::string &json, const std::string &key) {
  const auto at = json.find("\"" + key + "\":");
  if (at == std::string::npos) return 0;
  size_t p = at + key.size() + 3;
  while (p < json.size() && (json[p] == '"' || json[p] == ' ')) p++;
  return std::strtoull(json.c_str() + p, nullptr, 10);
}

std::string FromBase64(const std::string &in) {
  static const std::string d =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  uint32_t buf = 0;
  int bits = 0;
  for (char c : in) {
    const auto v = d.find(c);
    if (v == std::string::npos) break;
    buf = (buf << 6) | static_cast<uint32_t>(v);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<char>((buf >> bits) & 0xff));
    }
  }
  return out;
}

// -- the study's daemon ------------------------------------------------------------

class Study {
 public:
  Study(const Opt &o, std::string arm) : o_(o), arm_(std::move(arm)) {}
  ~Study() { Stop(); }

  void Start() {
    port_ = FreePort();
    pidfile_ = TmpPath("upf_ab_" + std::to_string(port_) + ".pid");
    std::vector<std::string> cmd = {"sudo", "-n", "env", "LD_LIBRARY_PATH=" + o_.ld,
                                  "TMPDIR=" + TmpPath(""),
                                  "GLOG_log_dir=" + TmpPath("")};
    const std::string cpus = std::to_string(o_.control_cpu) + "," + std::to_string(o_.worker_cpu);
    const std::string &plugin = arm_ != "g"                   ? o_.plugin
                                : !o_.baseline_plugin.empty() ? o_.baseline_plugin
                                : !o_.graph_plugin.empty()    ? o_.graph_plugin
                                                              : o_.plugin;
    cmd.insert(cmd.end(), {"taskset", "-c", cpus, o_.bessd, "-f", "-p", std::to_string(port_),
                           "--skip_root_check", "--mem_backing=" + o_.mem_backing, "--buffers",
                           std::to_string(o_.buffers), "-i", pidfile_, "-c",
                           std::to_string(o_.worker_cpu), "--control_cpus",
                           std::to_string(o_.control_cpu), "--modules=" + plugin});
    if (o_.mem_hugepage_mb > 0) cmd.push_back("--mem_hugepage_mb=" + std::to_string(o_.mem_hugepage_mb));
    cmd.insert(cmd.end(), o_.bessd_args.begin(), o_.bessd_args.end());
    const std::string logfile = TmpPath("upf_ab_bessd_" + arm_ + "_" + std::to_string(port_) + ".log");
    daemon_ = Spawn(cmd, logfile);
    for (int i = 0; i < 240 && !Listening(port_); i++) {
      std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
    if (!Listening(port_)) throw std::runtime_error("bessd did not listen (see " + logfile + ")");
    client_ = bess::sdk::Client::Dial("localhost:" + std::to_string(port_));
    types_ = std::make_unique<bess::perf::Types>(*client_);
    std::printf("bessd port %d pid file %s\n", port_, pidfile_.c_str());
  }

  void Stop() {
    if (daemon_ <= 0) return;
    client_.reset();
    const std::string pattern = "bessd .* -p " + std::to_string(port_) + " ";
    Run({"sudo", "-n", "pkill", "-f", pattern});
    int status = 0;
    for (int i = 0; i < 100 && waitpid(daemon_, &status, WNOHANG) == 0; i++) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      if (i == 99) {
        Run({"sudo", "-n", "pkill", "-KILL", "-f", pattern});
        waitpid(daemon_, &status, 0);
      }
    }
    Run({"sudo", "-n", "rm", "-f", pidfile_});
    daemon_ = -1;
  }

  std::unique_ptr<gp::Message> M(const std::string &type, const std::string &json) {
    return types_->Make(type, json);
  }

  void Mod(bess::sdk::PipelineBuilder &b, const std::string &name, const std::string &mclass,
           const std::string &json) {
    args_.push_back(M(types_->InitType(mclass), json));
    b.Module(name, mclass, args_.back().get());
  }
  void Entry(bess::sdk::PipelineBuilder &b, const std::string &res, const std::string &kt,
             const std::string &k, const std::string &vt, const std::string &v) {
    auto key = M(kt, k);
    auto val = M(vt, v);
    b.Entry(res, *key, *val);
  }

  // Exactly one packet path, with no graph modules in the appliance lifetime.
  void Apply() {
    const uint32_t n = o_.sessions;
    // ActionIds are global across directions: UL=2s+1, DL=2s+2.
    const uint64_t cap = std::max<uint64_t>(
        65536, 2 * uint64_t{n} + (o_.churn > 0 ? 2048 : 16));
    const std::string capj = std::to_string(cap);
    const std::string ul_tuples = std::to_string(std::max(uint32_t{16}, o_.mask_mix + 1));
    const std::string dl_tuples = std::to_string(std::max(uint32_t{8}, o_.mask_mix + 1));
    bess::sdk::PipelineBuilder b;
    b.Worker(0, o_.worker_cpu, "");

    // Front ends: Source -> Rewrite(template) -> UpfBenchGen, burst 0 until used.
    std::string ul = FromBase64(
        "AgAAAAACAgAAAAABCABFAABJAAFAAEARUIwKFB4CwAACAQhoCGgANQAAMP8AJREiM0RFAAAlAAFAAEARIIkKLQACCAgICBOIADUAEQAAaGVsbG8tdXBm");
    ul.replace(0, 6, std::string("\x02\x00\x00\x00\x03\x01", 6));  // the N3 interface's MAC
    const std::string dl = FromBase64(
        "AgAAAAYBAgAAAAYCCABFuAAlAAFAAEARH9EICAgICi0AAhOIADUAEQAAaGVsbG8tdXBm");
    for (const std::string &arm : {arm_}) {
      for (const char *dir : {"ul", "dl"}) {
        const std::string sfx = std::string(dir) + "_" + arm;
        const std::string &frame = std::string(dir) == "ul" ? ul : dl;
        Mod(b, "src_" + sfx, "Source",
            R"({"pkt_size": )" + std::to_string(frame.size()) + R"(, "burst": 0})");
        Mod(b, "rw_" + sfx, "Rewrite", R"({"templates": [")" + Base64(frame) + R"("]})");
        Mod(b, "gen_" + sfx, "UpfBenchGen",
            R"({"mode": )" + std::string(std::string(dir) == "ul" ? "0" : "1") +
                R"(, "sessions": )" + std::to_string(n) + R"(, "teid_base": )" +
                std::to_string(kTeidBase) + R"(, "ue_base": )" + std::to_string(kUeBase) +
                R"(, "miss_per_mille": )" + std::to_string(o_.miss) + R"(, "seed": 12345})");
        b.Connect("src_" + sfx, 0, "rw_" + sfx, 0);
        b.Connect("rw_" + sfx, 0, "gen_" + sfx, 0);
      }
    }

    // Exits.
    Mod(b, "sink_n6", "UpfHashSink", "{}");
    Mod(b, "sink_n3", "UpfHashSink", "{}");
    Mod(b, "sink_resp", "UpfHashSink", "{}");
    Mod(b, "sink_other", "UpfHashSink", "{}");

    if (!appliance()) {
    // N3/N9 ingress.
    Mod(b, "vif_n3n9", "Vif",
        R"({"default_gate": 0, "interfaces": [)"
        R"({"id": 1, "vlan": 0, "mac_addr": "02:00:00:00:03:01", "ip_addr": "192.0.2.1", "route_domain": 0, "gate": 1},)"
        R"({"id": 2, "vlan": 0, "mac_addr": "02:00:00:00:09:01", "ip_addr": "192.0.2.3", "route_domain": 0, "gate": 2}]})");
    Mod(b, "tag_n3", "SetMetadata",
        R"({"attrs": [{"name": "endpoint_id", "size": 4, "value_int": 1},)"
        R"( {"name": "transport_route_domain", "size": 4, "value_int": 1}]})");
    Mod(b, "tag_n9", "SetMetadata",
        R"({"attrs": [{"name": "endpoint_id", "size": 4, "value_int": 2},)"
        R"( {"name": "transport_route_domain", "size": 4, "value_int": 2}]})");
    Mod(b, "n3_eth_sort", "ExactMatch",
        R"({"fields": [{"offset": 12, "num_bytes": 2}], "default_gate": 1})");
    Mod(b, "n3_ipv6_sort", "ExactMatch",
        R"({"fields": [{"offset": 12, "num_bytes": 2}], "default_gate": 1})");
    Mod(b, "decap0", "GtpuDecap", R"({"max_fteids": )" + capj + "}");
    Mod(b, "mt_ul_read", "MetadataTest",
        R"({"read": {"endpoint_id": 4, "fteid_context": 4, "qfi": 1}})");
    const std::string tuple =
        R"({"offset": 26, "num_bytes": 4}, {"offset": 30, "num_bytes": 4}, {"offset": 23, "num_bytes": 1},)"
        R"( {"offset": 34, "num_bytes": 2}, {"offset": 36, "num_bytes": 2})";
    Mod(b, "pdr_ul", "WildcardMatch",
        R"({"fields": [)" + tuple +
            R"(, {"attr_name": "fteid_context", "num_bytes": 4}, {"attr_name": "qfi", "num_bytes": 1}],)"
            R"( "max_tuples": )" + ul_tuples + R"(, "result_fields": [)"
            R"({"attr_name": "action_id", "value_offset": 0, "num_bytes": 4},)"
            R"( {"attr_name": "meter_id", "value_offset": 4, "num_bytes": 8, "reference": "mt_ul/meters", "reference_key": "BE32", "reference_count": 2},)"
            R"( {"attr_name": "next_hop_id", "value_offset": 12, "num_bytes": 4, "reference": "rt/next_hops", "reference_key": "BE32"},)"
            R"( {"attr_name": "route_domain", "value_offset": 16, "num_bytes": 4}]})");
    Mod(b, "mt_ul", "Meter", R"({"capacity": )" + capj + R"(, "levels": 2})");
    Mod(b, "cnt_ul", "UrrCount", R"({"capacity": )" + capj + R"(, "worker_planes": 1})");

    // N6 ingress.
    Mod(b, "tag_n6", "SetMetadata",
        R"({"attrs": [{"name": "vif_id", "size": 4, "value_int": 1}, {"name": "route_domain", "size": 4, "value_int": 0},)"
        R"( {"name": "fteid_context", "size": 4, "value_int": 0}, {"name": "qfi", "size": 1, "value_int": 255},)"
        R"( {"name": "action_id", "size": 4, "value_int": 0}, {"name": "next_hop_id", "size": 4, "value_int": 0}]})");
    Mod(b, "l2_sort", "ExactMatch",
        R"({"fields": [{"offset": 12, "num_bytes": 2}], "default_gate": 1})");
    Mod(b, "vif_n6", "Vif",
        R"({"default_gate": 0, "interfaces": [)"
        R"({"id": 1, "vlan": 0, "mac_addr": "02:00:00:00:06:01", "ip_addr": "192.0.2.2", "route_domain": 0, "gate": 1}]})");
    Mod(b, "n6_ipv6_sort", "ExactMatch",
        R"({"fields": [{"offset": 12, "num_bytes": 2}], "default_gate": 1})");
    Mod(b, "pdr_dl", "WildcardMatch",
        R"({"fields": [)" + tuple +
            R"(, {"attr_name": "route_domain", "num_bytes": 4}, {"attr_name": "fteid_context", "num_bytes": 4},)"
            R"( {"attr_name": "qfi", "num_bytes": 1}], "max_tuples": )" + dl_tuples +
            R"(, "result_fields": [)"
            R"({"attr_name": "action_id", "value_offset": 0, "num_bytes": 4},)"
            R"( {"attr_name": "meter_id", "value_offset": 4, "num_bytes": 8, "reference": "mt_dl/meters", "reference_key": "BE32", "reference_count": 2},)"
            R"( {"attr_name": "next_hop_id", "value_offset": 12, "num_bytes": 4, "reference": "rt/next_hops", "reference_key": "BE32"},)"
            R"( {"attr_name": "route_domain", "value_offset": 16, "num_bytes": 4},)"
            R"( {"attr_name": "steering_policy_id", "value_offset": 20, "num_bytes": 4}]})");
    Mod(b, "mt_dl", "Meter", R"({"capacity": )" + capj + R"(, "levels": 2})");
    Mod(b, "cnt_dl", "UrrCount", R"({"capacity": )" + capj + R"(, "worker_planes": 1})");
    Mod(b, "atsss", "AtsssSteer",
        R"({"policy_attr": "steering_policy_id", "next_hop_attr": "next_hop_id"})");
    Mod(b, "rt", "Router", "{}");
    Mod(b, "enc", "GtpuEncap", R"({"max_tunnels": )" + capj + "}");
    Mod(b, "rt_transport", "Router",
        R"({"mode": "ROUTE_MODE_DESTINATION", "max_domains": 3, "max_ipv4_routes": 64,)"
        R"( "max_ipv6_routes": 64, "domain_attr": "transport_route_domain"})");


    // The graph (deploy/upf.yaml's connections on the IPv4 path).
    const auto C = [&](const std::string &a, int og, const std::string &d, int ig = 0) {
      b.Connect(a, og, d, ig);
    };
    C("gen_ul_g", 0, "vif_n3n9");
    C("vif_n3n9", 0, "sink_other");
    C("vif_n3n9", 1, "tag_n3");
    C("vif_n3n9", 2, "tag_n9");
    C("tag_n3", 0, "n3_eth_sort");
    C("tag_n9", 0, "n3_eth_sort");
    C("n3_eth_sort", 0, "sink_other");  // ARP: the graph's ARP branch
    C("n3_eth_sort", 1, "n3_ipv6_sort");
    C("n3_ipv6_sort", 0, "sink_other");  // IPv6 ND: the graph's ND branch
    C("n3_ipv6_sort", 1, "decap0");
    C("decap0", 0, "mt_ul_read");
    C("mt_ul_read", 0, "pdr_ul");
    C("decap0", 1, "pdr_dl");
    C("decap0", 2, "sink_resp");  // echo0 in the deployment
    C("pdr_ul", 0, "mt_ul");
    C("mt_ul", 0, "cnt_ul");
    C("mt_ul", 1, "cnt_ul");
    C("cnt_ul", 0, "rt");
    C("rt", 0, "sink_n6");
    C("gen_dl_g", 0, "tag_n6");
    C("tag_n6", 0, "l2_sort");
    C("l2_sort", 0, "sink_other");  // ARP: replicate -> rt, arp_n6
    C("l2_sort", 1, "vif_n6");
    C("vif_n6", 0, "sink_other");
    C("vif_n6", 1, "n6_ipv6_sort");
    C("n6_ipv6_sort", 0, "sink_other");
    C("n6_ipv6_sort", 1, "pdr_dl");
    C("pdr_dl", 0, "mt_dl");
    C("mt_dl", 0, "cnt_dl");
    C("mt_dl", 1, "cnt_dl");
    C("cnt_dl", 0, "atsss");
    C("atsss", 0, "rt");
    C("rt", 1, "enc");
    C("rt", 2, "enc");
    C("enc", 0, "rt_transport");
    C("rt_transport", 0, "sink_n3");
    C("rt_transport", 1, "sink_n3");

    // Deployment-owned entries.
    for (const char *em : {"n3_eth_sort", "l2_sort"}) {
      Entry(b, std::string(em) + "/rules", "ExactMatchRuleKey", R"({"fields": [{"value_bin": "CAY="}]})",
            "ExactMatchRuleValue", R"({"gate": 0})");
    }
    for (const char *em : {"n3_ipv6_sort", "n6_ipv6_sort"}) {
      Entry(b, std::string(em) + "/rules", "ExactMatchRuleKey", R"({"fields": [{"value_bin": "ht0="}]})",
            "ExactMatchRuleValue", R"({"gate": 0})");
    }
    }
    else {
      // Session layout: QERs and tunnels are sized per session (two of
      // each per session here), so meter.capacity and encap.max_tunnels
      // stay 0; the session ids need N (+1024 churn) slots, the action-id
      // spaces (F-TEIDs, buffer_counters) keep `cap`.
      const std::string sized =
          session_layout()
              ? R"({"decap": {"max_fteids": )" + capj + R"(}, "counters": {"capacity": )" + capj +
                    R"(, "worker_planes": 1}, "meter": {"levels": 2}, "session": {"capacity": )" +
                    std::to_string(SessionCapacity()) + R"(, "max_actions": 2, "max_qers": 2},)"
              : R"({"decap": {"max_fteids": )" + capj + R"(}, "encap": {"max_tunnels": )" + capj +
                    R"(}, "counters": {"capacity": )" + capj +
                    R"(, "worker_planes": 1}, "meter": {"capacity": )" + capj + R"(, "levels": 2},)";
      Mod(b, "upf", session_layout() ? "UpfSessionAppliance" : "UpfAppliance",
          sized + R"( "pdr_ul": {"max_tuples": )" + ul_tuples +
          R"(}, "pdr_dl": {"max_tuples": )" + dl_tuples +
          R"(}, "router": {"max_next_hops": 4096},)"
          R"( "transport_router": {"max_next_hops": 4096, "max_domains": 3,)"
          R"( "max_ipv4_routes": 64, "max_ipv6_routes": 64}, "interfaces": [)"
          R"({"ingress_gate": 0, "output_gate": 1, "id": 1, "endpoint_id": 1,)"
          R"( "mac_addr": "02:00:00:00:03:01", "ip_addr": "192.0.2.1",)"
          R"( "addresses": ["192.0.2.1/24"], "transport_route_domain": 1},)"
          R"({"ingress_gate": 0, "output_gate": 2, "id": 2, "endpoint_id": 2,)"
          R"( "mac_addr": "02:00:00:00:09:01", "ip_addr": "192.0.2.3",)"
          R"( "addresses": ["192.0.2.3/24"], "transport_route_domain": 2},)"
          R"({"ingress_gate": 4, "output_gate": 0, "id": 1, "n6": true,)"
          R"( "mac_addr": "02:00:00:00:06:01", "ip_addr": "192.0.2.2",)"
          R"( "addresses": ["192.0.2.2/24"], "route_domain": 0}],)"
          R"( "next_hop_classes": [{"egress_gate": 0, "action": "OUTPUT", "output_gate": 0},)"
          R"( {"egress_gate": 1, "action": "ENCAP"}, {"egress_gate": 2, "action": "ENCAP"}]})");
      b.Connect("gen_ul_" + arm_, 0, "upf", 0);
      b.Connect("gen_dl_" + arm_, 0, "upf", 4);
      b.Connect("upf", 0, "sink_n6", 0);
      b.Connect("upf", 1, "sink_n3", 0);
      b.Connect("upf", 2, "sink_n3", 0);
    }
    Entry(b, ResourceName("rt/next_hops"), "RouterNextHopIdKey", R"({"id": 1})", "RouterNextHopValue",
          R"({"egress_gate": 0, "dst_mac": "AgAAAAYC", "src_mac": "AgAAAAYB"})");
    Entry(b, ResourceName("rt/next_hops"), "RouterNextHopIdKey", R"({"id": 2})", "RouterNextHopValue",
          R"({"egress_gate": 1})");
    Entry(b, ResourceName("rt_transport/next_hops"), "RouterNextHopIdKey", R"({"id": 1})", "RouterNextHopValue",
          R"({"egress_gate": 1, "dst_mac": "AgAAAAMC", "src_mac": "AgAAAAMB"})");
    Entry(b, ResourceName("rt_transport/routes"), "RouterRouteKey",
          R"({"ipv4": "0.0.0.0", "prefix_length": 0, "domain": 1})", "RouterRouteValue",
          R"({"next_hop_id": 1})");

    auto p = b.Build();
    if (!p) throw std::runtime_error("pipeline: " + p.error().message);
    Must(client_->PauseWorkers(), "pause");
    Must(client_->ApplyPipeline(*p), "apply pipeline");
    if (appliance()) {
      auto empty = M("EmptyArg", "{}");
      Must(client_->InvokeAction("upf", "self_test", *empty), "upf self_test");
      std::printf("appliance self_test: PASS\n");
    }
  }

  // The 8 entries one compiler session writes (internal/session, dumped by
  // the study's TestZZDumpSession), for session s -- or, for the
  // session-layout appliance, the same session as ONE "upf/sessions" entry.
  void SessionOps(bess::sdk::Transaction &tx, uint32_t s, bool erase) {
    Entries(s, erase, [&](const std::string &res, const gp::Message &key, const gp::Message *value) {
      if (value != nullptr) Must(tx.Upsert(R(res), key, *value), "upsert " + res);
      else Must(tx.Erase(R(res), key), "erase " + res);
    });
  }
  // Protobuf key + value bytes of session s's upserts: the write's payload.
  size_t WireBytes(uint32_t s) {
    size_t bytes = 0;
    Entries(s, false, [&](const std::string &, const gp::Message &key, const gp::Message *value) {
      bytes += key.ByteSizeLong() + value->ByteSizeLong();
    });
    return bytes;
  }
  using Emit = std::function<void(const std::string &resource, const gp::Message &key,
                                  const gp::Message *value)>;  // value null: erase

  struct SdfPdr {
    struct Range { uint32_t field, low, high; };
    bool dl;
    std::string mask, value;
    std::vector<Range> ranges;

    std::string RangesJson() const {
      std::string out = "[";
      for (const auto &r : ranges) {
        if (out.size() != 1) out += ",";
        out += R"({"field": )" + std::to_string(r.field) + R"(, "low": )" +
               std::to_string(r.low) + R"(, "high": )" + std::to_string(r.high) + "}";
      }
      return out + "]";
    }
    std::string WildcardKey() const {
      const std::vector<size_t> widths = dl ? std::vector<size_t>{4,4,1,2,2,4,4,1}
                                             : std::vector<size_t>{4,4,1,2,2,4,1};
      auto fields = [&](const std::string &bytes) {
        std::string out = "[";
        size_t off = 0;
        for (size_t width : widths) {
          if (off != 0) out += ",";
          out += R"({"value_bin": ")" + Base64(bytes.substr(off, width)) + R"("})";
          off += width;
        }
        return out + "]";
      };
      return R"({"masks": )" + fields(mask) + R"(, "values": )" + fields(value) +
             R"(, "ranges": )" + RangesJson() + "}";
    }
    std::string SessionPdr() const {
      return R"({"downlink": )" + std::string(dl ? "true" : "false") +
             R"(, "mask": ")" + Base64(mask) + R"(", "value": ")" + Base64(value) +
             R"(", "ranges": )" + RangesJson() +
             R"(, "priority": 4294967294, "gate": 0, "action": )" + (dl ? "2}" : "1}");
    }
  };

  // Keep each session's default PDR and add one overlapping, winning SDF PDR
  // per direction. The same packed rule feeds both wire contracts. Shape
  // s%K varies a remote /16../31 prefix, protocol UDP/any and absent-QFI/any:
  // 16*2*2 distinct masks, always with the exact session anchor. Both port
  // ranges include the replay's sport 5000 and dport 53, but vary their
  // bounds too. Actions remain the original session's, so the independent
  // expected per-action counters and exact byte stream remain unchanged.
  // No shared rule is added: it would change the controlled miss population.
  SdfPdr MixedPdr(uint32_t s, bool dl) const {
    const uint32_t shape = s % o_.mask_mix;
    SdfPdr p{dl, std::string(dl ? 22 : 18, '\0'), std::string(dl ? 22 : 18, '\0'), {}};
    auto field32 = [&](size_t off, uint32_t mask, uint32_t value) {
      p.mask.replace(off, 4, Be32(mask));
      p.value.replace(off, 4, Be32(value & mask));
    };
    field32(dl ? 4 : 0, 0xffffffffu, kUeBase + s);
    if (!dl) field32(13, 0xffffffffu, s + 1);  // admitted F-TEID context
    else field32(13, 0xffffffffu, 0);          // route-domain guard
    const unsigned prefix = 16 + (shape & 15);
    field32(dl ? 0 : 4, 0xffffffffu << (32 - prefix), 0x08080808u);
    if ((shape & 16) == 0) {
      p.mask[8] = static_cast<char>(0xff);
      p.value[8] = 17;
    }
    if ((shape & 32) == 0) {
      p.mask.back() = p.value.back() = static_cast<char>(0xff);  // absent QFI
    }
    p.ranges = {{3, 4096 + (shape & 15), 8191 - (shape & 15)},
                {4, 48 + (shape % 4), 63 - (shape % 4)}};
    return p;
  }
  void Entries(uint32_t s, bool erase, const Emit &emit) {
    const uint32_t ue = kUeBase + s, teid = kTeidBase + s, ctx = s + 1;
    const uint32_t a_ul = 2 * s + 1, a_dl = 2 * s + 2;
    const std::string meterv =
        R"({"tr_tcm": {"committed_rate": "1000000000000", "committed_burst": "1000000000",)"
        R"( "peak_rate": "1000000000000", "peak_burst": "1000000000"}})";
    // A session's QER: the profile and the qer_id that is its bucket's
    // identity (UpfSessionQer), nonzero and unique in the session.
    const auto QerOf = [](const std::string &profile, int qer_id) {
      return profile.substr(0, profile.size() - 1) + R"(, "qer_id": )" + std::to_string(qer_id) + "}";
    };
    if (session_layout()) {
      // Session id s + 1. The PDR keys are the packed bytes of the masked
      // layout's keys (UL: UE source, admission context; DL: UE
      // destination); the actions carry what the masked PDR result records,
      // counter entries and tunnel entry carry; QER 1 is the UL meter a_ul,
      // QER 2 the DL meter a_dl.
      auto key = M("upf.pb.UpfSessionKey", R"({"session_id": )" + std::to_string(s + 1) + "}");
      if (erase) {
        emit("upf/sessions", *key, nullptr);
        return;
      }
      const std::string f4("\xff\xff\xff\xff", 4), z(22, '\0');
      const std::string ul_mask = f4 + z.substr(0, 9) + f4 + z.substr(0, 1);
      const std::string ul_value = Be32(ue) + z.substr(0, 9) + Be32(ctx) + z.substr(0, 1);
      const std::string dl_mask = z.substr(0, 4) + f4 + z.substr(0, 14);
      const std::string dl_value = z.substr(0, 4) + Be32(ue) + z.substr(0, 14);
      const std::string value =
          R"({"fteids": [{"key": {"address_family": 4, "endpoint_id": 1, "local_address": "wAACAQ==", "teid": )" +
          std::to_string(teid) + R"(}, "entry": {"context_id": )" + std::to_string(ctx) +
          R"(, "direction": 0}}], "qers": [)" + QerOf(meterv, 1) + ", " + QerOf(meterv, 2) +
          R"(], "actions": [{"action_id": )" + std::to_string(a_ul) +
          R"(, "next_hop_id": 1, "pdr_qer": 1, "count": true}, {"action_id": )" + std::to_string(a_dl) +
          R"(, "next_hop_id": 2, "pdr_qer": 2, "count": true, "tunnel": {"local_address": "wAACAQ==",)"
          R"( "peer_address": "ChQeAg==", "teid": )" + std::to_string(kPeerTeidBase + s) +
          R"(, "transport_route_domain": 1}}], "pdrs": [{"value": ")" + Base64(ul_value) +
          R"(", "mask": ")" + Base64(ul_mask) + R"(", "priority": 4294967195, "gate": 0, "action": 1},)"
          R"( {"downlink": true, "value": ")" + Base64(dl_value) + R"(", "mask": ")" + Base64(dl_mask) +
          R"(", "priority": 4294967195, "gate": 0, "action": 2})" +
          (o_.mask_mix ? ", " + MixedPdr(s, false).SessionPdr() + ", " +
                             MixedPdr(s, true).SessionPdr() : "") + "]}";
      auto val = M("upf.pb.UpfSession", value);
      emit("upf/sessions", *key, val.get());
      return;
    }
    const auto op = [&](const std::string &res, const std::string &kt, const std::string &k,
                        const std::string &vt, const std::string &v) {
      auto key = M(kt, k);
      if (erase) {
        emit(res, *key, nullptr);
      } else {
        auto val = M(vt, v);
        emit(res, *key, val.get());
      }
    };
    op("mt_ul/meters", "MeterIdKey", R"({"id": )" + std::to_string(a_ul) + "}", "MeterPolicyValue", meterv);
    op("mt_dl/meters", "MeterIdKey", R"({"id": )" + std::to_string(a_dl) + "}", "MeterPolicyValue", meterv);
    op("decap0/fteids", "upf.pb.FteidKey",
       R"({"address_family": 4, "endpoint_id": 1, "local_address": "wAACAQ==", "teid": )" +
           std::to_string(teid) + "}",
       "upf.pb.FteidEntry", R"({"context_id": )" + std::to_string(ctx) + R"(, "direction": 0})");
    op("cnt_ul/counters", "upf.pb.CounterKey", R"({"action_id": )" + std::to_string(a_ul) + "}",
       "upf.pb.CounterEntry", "{}");
    const std::string z4 = R"({"value_bin": "AAAAAA=="})", z2 = R"({"value_bin": "AAA="})",
                      z1 = R"({"value_bin": "AA=="})", f4 = R"({"value_bin": "/////w=="})";
    const auto bin = [](const std::string &s) { return R"({"value_bin": ")" + Base64(s) + R"("})"; };
    op("pdr_ul/rules", "WildcardMatchRuleKey",
       R"({"masks": [)" + f4 + "," + z4 + "," + z1 + "," + z2 + "," + z2 + "," + f4 + "," + z1 +
           R"(], "values": [)" + bin(Be32(ue)) + "," + z4 + "," + z1 + "," + z2 + "," + z2 + "," +
           bin(Be32(ctx)) + "," + z1 + "]}",
       "WildcardMatchRuleValue",
       R"({"gate": 0, "priority": 4294967195, "result": ")" +
           Base64(Be32(a_ul) + Be32(a_ul) + Be32(0) + Be32(1) + Be32(0)) + R"("})");
    op("cnt_dl/counters", "upf.pb.CounterKey", R"({"action_id": )" + std::to_string(a_dl) + "}",
       "upf.pb.CounterEntry", "{}");
    op("enc/tunnels", "upf.pb.TunnelKey", R"({"action_id": )" + std::to_string(a_dl) + "}",
       "upf.pb.TunnelEntry",
       R"({"local_address": "wAACAQ==", "peer_address": "ChQeAg==", "teid": )" +
           std::to_string(kPeerTeidBase + s) + R"(, "transport_route_domain": 1})");
    op("pdr_dl/rules", "WildcardMatchRuleKey",
       R"({"masks": [)" + z4 + "," + f4 + "," + z1 + "," + z2 + "," + z2 + "," + z4 + "," + z4 +
           "," + z1 + R"(], "values": [)" + z4 + "," + bin(Be32(ue)) + "," + z1 + "," + z2 + "," +
           z2 + "," + z4 + "," + z4 + "," + z1 + "]}",
       "WildcardMatchRuleValue",
       R"({"gate": 0, "priority": 4294967195, "result": ")" +
           Base64(Be32(a_dl) + Be32(a_dl) + Be32(0) + Be32(2) + Be32(0) + Be32(0)) + R"("})");
    if (o_.mask_mix) {
      for (bool dl : {false, true}) {
        const SdfPdr p = MixedPdr(s, dl);
        const uint32_t action = dl ? a_dl : a_ul;
        std::string result = Be32(action) + Be32(action) + Be32(0) +
                             Be32(dl ? 2 : 1) + Be32(0);
        if (dl) result += Be32(0);
        op(dl ? "pdr_dl/rules" : "pdr_ul/rules", "WildcardMatchRuleKey",
           p.WildcardKey(), "WildcardMatchRuleValue",
           R"({"gate": 0, "priority": 4294967294, "result": ")" + Base64(result) + R"("})");
      }
    }
  }

  bool appliance() const { return arm_ == "a" || !o_.baseline_plugin.empty(); }
  bool session_layout() const {
    const std::string &layout = arm_ == "g" && !o_.baseline_plugin.empty()
                                    ? o_.baseline_layout : o_.layout;
    return appliance() && layout == "session";
  }
  const std::string &arm() const { return arm_; }
  std::string ArmName() const {
    return !appliance() ? "graph" : session_layout() ? "appliance(session)" : "appliance(masked)";
  }
  // A mixed session adds two SDF PDRs; the session layout bundles them too.
  uint32_t EntriesPerSession() const { return session_layout() ? 1 : o_.mask_mix ? 10 : 8; }
  // Session ids 1..N, and N+1..N+1024 for churn; self_test uses the last id.
  uint64_t SessionCapacity() const {
    return std::max<uint64_t>(65536, uint64_t{o_.sessions} + (o_.churn > 0 ? 2048 : 16));
  }

  // The daemon's memory as the kernel reports it (/proc/<pid>/status, the
  // pid from bessd's pid file), tagged with this arm.
  void PrintMemory(const std::string &when) const {
    long pid = 0;
    std::ifstream(pidfile_) >> pid;
    std::string fields;
    std::ifstream status("/proc/" + std::to_string(pid) + "/status");
    for (std::string line; pid > 0 && std::getline(status, line);) {
      for (const char *f : {"VmRSS:", "VmHWM:", "HugetlbPages:"}) {
        if (line.rfind(f, 0) != 0) continue;
        std::string v = line.substr(std::strlen(f));
        v.erase(0, v.find_first_not_of(" \t"));
        fields += std::string(" ") + f + " " + v;
      }
    }
    std::printf("memory %s %s: pid %ld%s\n", ArmName().c_str(), when.c_str(), pid,
                fields.empty() ? " (status unreadable)" : fields.c_str());
    std::fflush(stdout);
    MemoryReport(when);
  }

  // Study only (--memory-report): the daemon's own admitted-bytes breakdown
  // and its kernel page composition, appended to $TMPDIR/memstatus.jsonl.
  void MemoryReport(const std::string &when) const {
    if (o_.memory_report.empty()) return;
    long pid = 0;
    std::ifstream(pidfile_) >> pid;
    if (pid <= 0) return;
    Run({o_.memory_report, std::to_string(port_), std::to_string(pid), ArmName() + " " + when,
         TmpPath("memstatus.jsonl")});
  }

  std::string ResourceName(const std::string &name) const {
    if (!appliance()) return name;
    static const std::map<std::string, std::string> tables = {
        {"mt_ul/meters", "meters"}, {"mt_dl/meters", "meters"},
        {"decap0/fteids", "fteids"}, {"pdr_ul/rules", "pdr_ul"},
        {"pdr_dl/rules", "pdr_dl"}, {"cnt_ul/counters", "counters_ul"},
        {"cnt_dl/counters", "counters_dl"}, {"enc/tunnels", "tunnels"},
        {"rt/next_hops", "next_hops"}, {"rt_transport/next_hops", "transport_next_hops"},
        {"rt_transport/routes", "transport_routes"}};
    const auto it = tables.find(name);
    return it == tables.end() ? name : "upf/" + it->second;
  }

  const bess::sdk::Resource &R(const std::string &name) {
    const std::string actual = ResourceName(name);
    auto it = res_.find(actual);
    if (it == res_.end()) it = res_.emplace(actual, Must(client_->Resource(actual), actual)).first;
    return it->second;
  }

  // Erases are ordered referrers first (rules before the meters and next hops
  // they name); one transaction holds both, so the engine orders it. A
  // refused commit is reported with its error and whether the daemon still
  // answers (a Metrics call, before anything stops it), then thrown.
  double Load(uint32_t first, uint32_t count, uint32_t per_tx) {
    const auto t0 = Clock::now();
    for (uint32_t s = first; s < first + count; s += per_tx) {
      auto tx = client_->NewTransaction();
      for (uint32_t k = s; k < std::min(first + count, s + per_tx); k++) SessionOps(tx, k, false);
      auto committed = tx.Commit();
      if (committed) {
        const uint32_t done = std::min(first + count, s + per_tx) - first;
        if (done % o_.report_every == 0) MemoryReport("loaded " + std::to_string(done));
        continue;
      }
      const bess::sdk::Error &e = committed.error();
      std::printf("load %s REFUSED at sessions %u..%u: kind %s grpc %s (%d): %s\n", ArmName().c_str(),
                  s, std::min(first + count, s + per_tx) - 1, KindName(e.kind),
                  CodeName(e.code), static_cast<int>(e.code), e.message.c_str());
      if (e.detail) std::printf("  detail: %s\n", e.detail->ShortDebugString().c_str());
      if (e.record)
        std::printf("  outcome: %s\n", v2::TransactionRecord::Outcome_Name(e.record->outcome()).c_str());
      for (const auto &f : e.failures) std::printf("  op %d: %s\n", f.index, f.error.c_str());
      const bool alive = client_->Metrics().has_value();
      std::printf("daemon_alive=%s\n", alive ? "true" : "false");
      PrintMemory("after refusal");
      if (o_.after_refusal) ProbeAfterRefusal(s - first, e.code);
      throw std::runtime_error("commit sessions from " + std::to_string(s) + ": " + e.message +
                               " [grpc " + std::to_string(static_cast<int>(e.code)) + "]");
    }
    return std::chrono::duration<double>(Clock::now() - t0).count();
  }

  // Strict budget: the daemon a refusal left must still serve its existing
  // sessions: retry the refused batch (refused again, not killed), one-session
  // updates, then erase everything and load a fresh batch. Workers stay
  // paused (Apply leaves them so). Refusals are counted, not thrown.
  void ProbeAfterRefusal(uint32_t loaded, grpc::StatusCode code) {
    std::printf("probe liveness: %s\n", client_->Metrics().has_value() ? "PASS" : "FAIL");
    {
      auto tx = client_->NewTransaction();
      for (uint32_t k = loaded; k < std::min(o_.sessions, loaded + 200); k++) SessionOps(tx, k, false);
      auto r = tx.Commit();
      std::printf("probe retry refused batch: %s (grpc %d, first refusal grpc %d)\n",
                  r ? "COMMITTED" : "REFUSED", r ? 0 : static_cast<int>(r.error().code),
                  static_cast<int>(code));
    }
    const uint32_t u = std::min(loaded, o_.updates != 0 ? o_.updates : 1000u);
    uint32_t ok = 0;
    std::string first_error;
    for (uint32_t i = 0; i < u; ++i) {
      auto tx = client_->NewTransaction();
      SessionOps(tx, i, false);
      auto r = tx.Commit();
      if (r) ok++;
      else if (first_error.empty()) first_error = r.error().message;
    }
    std::printf("probe updates: %u of %u committed%s%s\n", ok, u,
                first_error.empty() ? "" : "; first refusal: ", first_error.c_str());
    PrintMemory("after probe updates");
    const uint32_t refused = Teardown(loaded);
    std::printf("probe teardown: %u sessions, %u batches refused\n", loaded, refused);
    const uint32_t again = std::min(loaded, 10000u);
    uint32_t reloaded = 0;
    for (uint32_t s = 0; s < again; s += 200) {
      auto tx = client_->NewTransaction();
      for (uint32_t k = s; k < std::min(again, s + 200); k++) SessionOps(tx, k, false);
      if (tx.Commit()) reloaded = std::min(again, s + 200);
    }
    std::printf("probe reload: %u of %u sessions %s\n", reloaded, again,
                reloaded == again ? "PASS" : "FAIL");
    std::printf("probe liveness after: %s\n", client_->Metrics().has_value() ? "PASS" : "FAIL");
    PrintMemory("after probe reload");
  }

  // Erases sessions 0..n-1 in 200-session transactions; returns refused batches.
  uint32_t Teardown(uint32_t n) {
    uint32_t refused = 0;
    for (uint32_t s = 0; s < n; s += 200) {
      auto tx = client_->NewTransaction();
      for (uint32_t k = s; k < std::min(n, s + 200); k++) SessionOps(tx, k, true);
      if (!tx.Commit()) refused++;
    }
    PrintMemory("after teardown");
    return refused;
  }

  // After a passing arm: its memory, then (--teardown) every session erased.
  void Finish() {
    PrintMemory("after updates");
    if (!o_.teardown) return;
    const uint32_t refused = Teardown(o_.sessions);
    std::printf("teardown %s: %u sessions erased, %u batches refused\n", ArmName().c_str(),
                o_.sessions, refused);
    std::fflush(stdout);
  }

  bool Alive() { return client_ != nullptr && client_->Metrics().has_value(); }

  static const char *KindName(bess::sdk::ErrorKind k) {
    using K = bess::sdk::ErrorKind;
    switch (k) {
      case K::kInvalidRequest: return "INVALID_REQUEST";
      case K::kConflict: return "CONFLICT";
      case K::kRejected: return "REJECTED";
      case K::kBusy: return "BUSY";
      case K::kTransport: return "TRANSPORT";
      case K::kPipelineConflict: return "PIPELINE_CONFLICT";
      case K::kDaemonRestarted: return "DAEMON_RESTARTED";
      case K::kStaleResource: return "STALE_RESOURCE";
      case K::kCancelled: return "CANCELLED";
    }
    return "?";
  }
  static const char *CodeName(grpc::StatusCode c) {
    static const char *const names[] = {
        "OK", "CANCELLED", "UNKNOWN", "INVALID_ARGUMENT", "DEADLINE_EXCEEDED", "NOT_FOUND",
        "ALREADY_EXISTS", "PERMISSION_DENIED", "RESOURCE_EXHAUSTED", "FAILED_PRECONDITION",
        "ABORTED", "OUT_OF_RANGE", "UNIMPLEMENTED", "INTERNAL", "UNAVAILABLE", "DATA_LOSS",
        "UNAUTHENTICATED"};
    const auto i = static_cast<size_t>(c);
    return i < std::size(names) ? names[i] : "?";
  }

  void Burst(const std::string &src, int burst) {
    auto tx = client_->NewTransaction();
    auto v = M("SourceSettings", R"({"pkt_size": )" + std::to_string(src.find("ul") != std::string::npos ? 87 : 51) +
                                     R"(, "burst": )" + std::to_string(burst) + "}");
    Must(tx.Set(R(src + "/settings"), *v), "set " + src);
    Must(tx.Commit(), "burst " + src);
  }

  std::string Action(const std::string &module, const std::string &action, const std::string &argt,
                     const std::string &arg, const std::string &respt) {
    auto a = M(argt, arg);
    gp::Any any = Must(client_->InvokeAction(module, action, *a), module + " " + action);
    auto r = M(respt, "{}");
    if (!any.UnpackTo(r.get())) throw std::runtime_error("unpack " + respt);
    std::string json;
    gp::util::JsonPrintOptions po;
    po.always_print_fields_with_no_presence = true;
    (void)gp::util::MessageToJsonString(*r, &json, po);
    return json;
  }

  // Every rule's (packets, octets) in counter module `cnt`.
  std::map<uint32_t, std::pair<uint64_t, uint64_t>> Counts(const std::string &dir) {
    const std::string cnt = appliance() ? "upf" : "cnt_" + dir;
    auto a = M("upf.pb.UrrCountCommandGetCountsArg",
               appliance() ? R"({"table": "counters_)" + dir + R"("})" : "{}");
    gp::Any any = Must(client_->InvokeAction(cnt, "get_counts", *a), cnt + " get_counts");
    auto r = M("upf.pb.UrrCountCommandGetCountsResponse", "{}");
    if (!any.UnpackTo(r.get())) throw std::runtime_error(cnt + " get_counts: unexpected response type");
    std::map<uint32_t, std::pair<uint64_t, uint64_t>> out;
    const gp::Reflection *rf = r->GetReflection();
    const gp::FieldDescriptor *counts = r->GetDescriptor()->FindFieldByName("counts");
    for (int i = 0; i < rf->FieldSize(*r, counts); i++) {
      const gp::Message &c = rf->GetRepeatedMessage(*r, counts, i);
      const gp::Reflection *cr = c.GetReflection();
      const auto *d = c.GetDescriptor();
      out[cr->GetUInt32(c, d->FindFieldByName("action_id"))] = {
          cr->GetUInt64(c, d->FindFieldByName("packets")),
          cr->GetUInt64(c, d->FindFieldByName("octets"))};
    }
    return out;
  }

  std::vector<v2::MetricSample> Metrics() { return Must(client_->Metrics(), "metrics"); }

  bess::sdk::Client &client() { return *client_; }
  const Opt &o_;

 private:
  int port_ = 0;
  pid_t daemon_ = -1;
  std::string pidfile_;
  std::string arm_;
  std::unique_ptr<bess::sdk::Client> client_;
  std::unique_ptr<bess::perf::Types> types_;
  std::vector<std::unique_ptr<gp::Message>> args_;
  std::map<std::string, bess::sdk::Resource> res_;
};

struct Digest {
  uint64_t packets = 0, sum = 0, xsum = 0, bytes = 0;
  bool operator==(const Digest &) const = default;
};

Digest ReadDigest(Study &st, const std::string &sink, bool reset, bool enable) {
  const std::string j = st.Action(sink, "digest", "upf.pb.UpfHashSinkCommandDigestArg",
                                  std::string(R"({"reset": )") + (reset ? "true" : "false") +
                                      R"(, "enable": )" + (enable ? "true" : "false") + "}",
                                  "upf.pb.UpfHashSinkCommandDigestResponse");
  return {JsonU64(j, "packets"), JsonU64(j, "sum"), JsonU64(j, "xsum"), JsonU64(j, "bytes")};
}

// One arm's exact stream: every external sink and every rule's delta.
struct ArmResult {
  std::map<std::string, Digest> sinks;
  std::map<uint32_t, std::pair<uint64_t, uint64_t>> delta;
};

ArmResult RunExact(Study &st, const std::string &dir, uint64_t k) {
  const std::string sfx = dir + "_" + st.arm();
  st.Action("gen_" + sfx, "arm", "upf.pb.UpfBenchGenCommandArmArg",
            R"({"seed": 777, "limit": )" + std::to_string(k) + "}",
            "upf.pb.UpfBenchGenCommandArmResponse");
  for (const char *s : {"sink_n6", "sink_n3", "sink_resp", "sink_other"}) ReadDigest(st, s, true, true);
  const auto before = st.Counts(dir);
  if (before.size() != st.o_.sessions) throw std::runtime_error("missing provisioned rule counters");
  const auto m0 = st.Metrics();
  const double g0 = GatePackets(m0, "gen_" + sfx);
  Must(st.client().ResumeWorkers(), "resume");
  st.Burst("src_" + sfx, 32);
  const auto t0 = Clock::now();
  while (GatePackets(st.Metrics(), "gen_" + sfx) - g0 < static_cast<double>(k)) {
    if (Clock::now() - t0 > std::chrono::seconds(120)) throw std::runtime_error("exact run stalled");
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  st.Burst("src_" + sfx, 0);
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  Must(st.client().PauseWorkers(), "pause");
  ArmResult r;
  for (const char *s : {"sink_n6", "sink_n3", "sink_resp", "sink_other"}) r.sinks[s] = ReadDigest(st, s, true, false);
  const auto after = st.Counts(dir);
  if (before.size() != after.size()) throw std::runtime_error("counter bank changed during verification");
  for (const auto &[id, c] : after) {
    if (!before.contains(id)) throw std::runtime_error("unexpected rule counter");
    const auto b = before.at(id);
    if (c.first < b.first || c.second < b.second) throw std::runtime_error("counter regressed");
    if (c != b) r.delta[id] = {c.first - b.first, c.second - b.second};
  }
  const auto m1 = st.Metrics();
  if (GatePackets(m1, "gen_" + sfx) - g0 != static_cast<double>(k))
    throw std::runtime_error("generator did not forward the exact requested count");
  // Independently replay UpfBenchGen's seeded selection. Equality must not
  // pass because both arms accidentally dropped all traffic or skipped URRs.
  std::vector<uint64_t> expected(st.o_.sessions, 0);
  uint64_t state = 777, hits = 0;
  for (uint64_t i = 0; i < k; ++i) {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    const uint32_t s = static_cast<uint32_t>((state >> 16) % st.o_.sessions);
    if (st.o_.miss != 0 && (state & 0xffff) % 1000 < static_cast<uint64_t>(st.o_.miss)) continue;
    ++expected[s];
    ++hits;
  }
  size_t touched = 0;
  for (uint32_t s = 0; s < st.o_.sessions; ++s) {
    const uint32_t id = 2 * s + (dir == "ul" ? 1 : 2);
    if (!before.contains(id)) throw std::runtime_error("missing rule id " + std::to_string(id));
    if (expected[s] == 0) continue;
    ++touched;
    if (!r.delta.contains(id) ||
        r.delta.at(id) != std::pair<uint64_t, uint64_t>{expected[s], 37 * expected[s]})
      throw std::runtime_error("incorrect packet/octet delta for rule " + std::to_string(id));
  }
  const Digest &out = r.sinks.at(dir == "ul" ? "sink_n6" : "sink_n3");
  if (r.delta.size() != touched || hits == 0 || out.packets != hits ||
      out.bytes != hits * (dir == "ul" ? 51 : 87))
    throw std::runtime_error("verification output/count assertions failed");
  // Disarm: unlimited from now on.
  st.Action("gen_" + sfx, "arm", "upf.pb.UpfBenchGenCommandArmArg", R"({"seed": 12345, "limit": 0})",
            "upf.pb.UpfBenchGenCommandArmResponse");
  return r;
}

// Update cost (--updates U): sessions 0..U-1 re-upserted with their current
// values (an update of a live session; packets and counters unchanged) while
// the UL source runs at --burst. Leaves the workers paused, as RunExact does.
void UpdateCost(Study &st, uint32_t u) {
  if (u == 0) return;
  const std::string sfx = "ul_" + st.arm();
  const bool pause = st.session_layout();
  Must(st.client().ResumeWorkers(), "resume");
  st.Burst("src_" + sfx, st.o_.burst);
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  if (pause) {
    // The resource contract: an in-place update is refused beside a running worker.
    auto tx = st.client().NewTransaction();
    st.SessionOps(tx, 0, false);
    auto r = tx.Commit();
    if (r) throw std::runtime_error("session-layout update applied while a worker ran");
    std::printf("update %s beside running workers: refused (%s)\n", st.ArmName().c_str(),
                r.error().message.c_str());
  }
  std::vector<double> total, commit;
  for (uint32_t i = 0; i < u; ++i) {
    auto tx = st.client().NewTransaction();
    st.SessionOps(tx, i % st.o_.sessions, false);
    const auto t0 = Clock::now();
    if (pause) Must(st.client().PauseWorkers(), "pause for update");
    const auto t1 = Clock::now();
    Must(tx.Commit(), "update commit");
    const auto t2 = Clock::now();
    if (pause) Must(st.client().ResumeWorkers(), "resume after update");
    const auto t3 = Clock::now();
    commit.push_back(std::chrono::duration<double, std::micro>(t2 - t1).count());
    total.push_back(std::chrono::duration<double, std::micro>(t3 - t0).count());
  }
  st.Burst("src_" + sfx, 0);
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  Must(st.client().PauseWorkers(), "pause");
  std::sort(total.begin(), total.end());
  std::sort(commit.begin(), commit.end());
  std::printf("update %s: %u one-session updates (%u entries each)%s: total p50 %.0f us p99 %.0f us,"
              " commit p50 %.0f us p99 %.0f us\n",
              st.ArmName().c_str(), u, st.EntriesPerSession(),
              pause ? ", each pause+commit+resume" : ", beside running workers",
              total[total.size() / 2], total[total.size() * 99 / 100],
              commit[commit.size() / 2], commit[commit.size() * 99 / 100]);
  std::fflush(stdout);
}

double Median(std::vector<double> v) {
  if (v.empty()) return 0;
  std::sort(v.begin(), v.end());
  const size_t n = v.size();
  return n % 2 ? v[n / 2] : (v[n / 2 - 1] + v[n / 2]) / 2;
}

struct Window {
  double ns = 0, out_ratio = 0;
  std::map<std::string, double> counters;
};

// One window owns its churn thread. Stop and erase its extra sessions before
// pausing/replacing the arm; failures must never silently bias the comparison.
class Churn {
 public:
  explicit Churn(Study &st) : st_(st), live_(1024, false) {
    if (st.o_.churn <= 0) return;
    thread_ = std::jthread([this](std::stop_token stop) {
      try {
        const auto period = std::chrono::duration<double>(1.0 / st_.o_.churn);
        auto next = Clock::now();
        for (uint64_t i = 0; !stop.stop_requested(); ++i) {
          const size_t slot = i % live_.size();
          auto tx = st_.client().NewTransaction();
          st_.SessionOps(tx, st_.o_.sessions + slot, live_[slot]);
          const auto start = Clock::now();
          Must(tx.Commit(), "churn commit");
          live_[slot] = !live_[slot];
          lat_.push_back(std::chrono::duration<double, std::micro>(Clock::now() - start).count());
          next += std::chrono::duration_cast<Clock::duration>(period);
          while (!stop.stop_requested() && Clock::now() < next)
            std::this_thread::sleep_for(std::min(next - Clock::now(),
                std::chrono::duration_cast<Clock::duration>(std::chrono::milliseconds(10))));
        }
      } catch (const std::exception &e) {
        error_ = e.what();
      }
    });
  }
  ~Churn() {
    if (thread_.joinable()) { thread_.request_stop(); thread_.join(); }
  }
  void Finish() {
    if (!thread_.joinable()) return;
    thread_.request_stop();
    thread_.join();
    if (!error_.empty()) throw std::runtime_error(error_);
    for (size_t i = 0; i < live_.size(); ++i) {
      if (!live_[i]) continue;
      auto tx = st_.client().NewTransaction();
      st_.SessionOps(tx, st_.o_.sessions + i, true);
      Must(tx.Commit(), "churn cleanup");
    }
    if (!lat_.empty()) {
      std::sort(lat_.begin(), lat_.end());
      std::printf("churn %s: %zu transactions, p50 %.0f us p99 %.0f us\n",
                  st_.arm().c_str(), lat_.size(), lat_[lat_.size() / 2],
                  lat_[lat_.size() * 99 / 100]);
    }
  }
 private:
  Study &st_;
  std::vector<bool> live_;
  std::vector<double> lat_;
  std::string error_;
  std::jthread thread_;
};

Window Measure(Study &st, const std::string &dir) {
  const Opt &o = st.o_;
  const std::string sfx = dir + "_" + st.arm();
  st.Action("gen_" + sfx, "arm", "upf.pb.UpfBenchGenCommandArmArg",
            R"({"seed": 12345, "limit": 0})", "upf.pb.UpfBenchGenCommandArmResponse");
  Must(st.client().ResumeWorkers(), "resume");
  st.Burst("src_" + sfx, o.burst);
  Churn churn(st);
  std::this_thread::sleep_for(std::chrono::duration<double>(o.warmup));
  pid_t perf = -1;
  const std::string perf_out = TmpPath("upf_ab_perf_" + std::to_string(getpid()));
  if (o.counters) {
    perf = Spawn({"perf", "stat", "-x", ",", "-o", perf_out, "-C", std::to_string(o.worker_cpu),
                  "-e",
                  "cycles,instructions,branch-misses,L1-dcache-load-misses,LLC-load-misses,dTLB-load-misses",
                  "sleep", std::to_string(o.duration)});
  }
  const auto m0 = st.Metrics();
  const auto t0 = Clock::now();
  std::this_thread::sleep_for(std::chrono::duration<double>(o.duration));
  const auto m1 = st.Metrics();
  const double secs = std::chrono::duration<double>(Clock::now() - t0).count();
  st.Burst("src_" + sfx, 0);
  churn.Finish();
  Must(st.client().PauseWorkers(), "pause");
  Window w;
  const double in = GatePackets(m1, "src_" + sfx) - GatePackets(m0, "src_" + sfx);
  if (in <= 0) throw std::runtime_error("timing window forwarded no packets");
  w.ns = secs * 1e9 / in;
  const auto outp = [&](const std::vector<v2::MetricSample> &m) {
    return !st.appliance() ? GatePackets(m, dir == "ul" ? "rt" : "rt_transport")
                          : GatePackets(m, "upf", dir == "ul" ? 0 : 1) +
                                (dir == "ul" ? 0 : GatePackets(m, "upf", 2));
  };
  w.out_ratio = in > 0 ? (outp(m1) - outp(m0)) / in : 0;
  if (perf > 0) {
    int status = 0;
    waitpid(perf, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
      throw std::runtime_error("perf stat failed; see " + perf_out);
    std::ifstream f(perf_out);
    std::string line;
    while (std::getline(f, line)) {
      std::vector<std::string> v;
      std::stringstream ss(line);
      for (std::string x; std::getline(ss, x, ',');) v.push_back(x);
      if (v.size() > 2 && !v[0].empty() && std::isdigit(static_cast<unsigned char>(v[0][0]))) {
        std::string ev = v[2];
        if (auto sl = ev.find('/'); sl != std::string::npos) ev = ev.substr(sl + 1, ev.find('/', sl + 1) - sl - 1);
        w.counters[ev] += std::stod(v[0]) / std::max(1.0, in);
      }
    }
    std::remove(perf_out.c_str());
    if (!w.counters.contains("cycles") || !w.counters.contains("LLC-load-misses"))
      throw std::runtime_error("perf stat did not report cycles and LLC-load-misses");
  }
  return w;
}

}  // namespace

int main(int argc, char **argv) {
  Opt o;
  o.ld = std::getenv("LD_LIBRARY_PATH") ? std::getenv("LD_LIBRARY_PATH") : "";
  for (int i = 1; i < argc; i++) {
    const std::string a = argv[i];
    const auto val = [&]() -> std::string {
      if (i + 1 >= argc) throw std::runtime_error(a + " needs a value");
      return argv[++i];
    };
    if (a == "--bessd") o.bessd = val();
    else if (a == "--plugin") o.plugin = val();
    else if (a == "--sessions") o.sessions = static_cast<uint32_t>(std::stoul(val()));
    else if (a == "--rounds") o.rounds = std::stoi(val());
    else if (a == "--duration") o.duration = std::stod(val());
    else if (a == "--warmup") o.warmup = std::stod(val());
    else if (a == "--burst") o.burst = std::stoi(val());
    else if (a == "--miss") o.miss = std::stoi(val());
    else if (a == "--worker-cpu") o.worker_cpu = std::stoi(val());
    else if (a == "--control-cpu") o.control_cpu = std::stoi(val());
    else if (a == "--mem-backing") o.mem_backing = val();
    else if (a == "--mem-hugepage-mb") o.mem_hugepage_mb = std::stoi(val());
    else if (a == "--bessd-arg") o.bessd_args.push_back(val());
    else if (a == "--buffers") o.buffers = std::stoi(val());
    else if (a == "--verify") o.verify = std::stoull(val());
    else if (a == "--churn") o.churn = std::stod(val());
    else if (a == "--dirs") o.dirs = val();
    else if (a == "--counters") o.counters = true;
    else if (a == "--layout") o.layout = val();
    else if (a == "--baseline-plugin") o.baseline_plugin = val();
    else if (a == "--graph-plugin") o.graph_plugin = val();
    else if (a == "--baseline-layout") o.baseline_layout = val();
    else if (a == "--only") o.only = val();
    else if (a == "--memory-report") o.memory_report = val();
    else if (a == "--report-every") o.report_every = static_cast<uint32_t>(std::stoul(val()));
    else if (a == "--after-refusal") o.after_refusal = true;
    else if (a == "--teardown") o.teardown = true;
    else if (a == "--updates") o.updates = static_cast<uint32_t>(std::stoul(val()));
    else if (a == "--mask-mix") o.mask_mix = static_cast<uint32_t>(std::stoul(val()));
    else throw std::runtime_error("unknown flag " + a);
  }
  if (o.mem_backing != "auto" && o.mem_backing != "hugepages" && o.mem_backing != "normal") {
    throw std::runtime_error("--mem-backing " + o.mem_backing + ": auto, hugepages or normal");
  }
  if (o.bessd.empty() || o.plugin.empty()) {
    std::fprintf(stderr, "usage: upf_ab --bessd B --plugin DIR --sessions N ...\n");
    return 2;
  }
  std::vector<std::string> dirs;
  {
    std::stringstream ss(o.dirs);
    for (std::string d; std::getline(ss, d, ',');) dirs.push_back(d);
  }
  if (o.sessions == 0 || o.sessions > kMaxStudySessions || o.rounds < 0 || o.duration <= 0 ||
      o.warmup < 0 || o.burst < 1 || o.burst > 32 || o.miss < 0 || o.miss >= 1000 ||
      o.churn < 0 || dirs.empty() ||
      std::any_of(dirs.begin(), dirs.end(), [](const auto &d) { return d != "ul" && d != "dl"; }))
    throw std::runtime_error("invalid sessions/rounds/duration/warmup/burst/miss/churn/dirs");
  if (o.mask_mix > 64)
    throw std::runtime_error("--mask-mix K: 0 (unchanged) or 1..64 distinct SDF mask shapes");
  if (o.layout != "masked" && o.layout != "session")
    throw std::runtime_error("--layout " + o.layout + ": masked or session");
  if (o.baseline_layout != "masked" && o.baseline_layout != "session")
    throw std::runtime_error("--baseline-layout " + o.baseline_layout + ": masked or session");
  if (o.only != "both" && o.only != "graph" && o.only != "appliance")
    throw std::runtime_error("--only " + o.only + ": graph or appliance");
  if (o.only != "both" && o.rounds != 0)
    throw std::runtime_error("--only runs one arm: timing needs both, so it needs --rounds 0");
  if (o.control_cpu < 0 || o.control_cpu >= CPU_SETSIZE ||
      o.worker_cpu < 0 || o.worker_cpu >= CPU_SETSIZE || o.control_cpu == o.worker_cpu)
    throw std::runtime_error("worker/control CPUs must be distinct valid CPU ids");
  cpu_set_t control;
  CPU_ZERO(&control);
  CPU_SET(o.control_cpu, &control);
  if (sched_setaffinity(0, sizeof(control), &control) != 0)
    throw std::runtime_error("cannot pin benchmark to control CPU");
  const char *baseline_name = o.baseline_plugin.empty() ? "graph" : "baseline";
  if (o.baseline_plugin.empty() && !o.graph_plugin.empty())
    std::printf("COMPARE graph plugin=%s appliance(%s) plugin=%s\n", o.graph_plugin.c_str(),
                o.layout.c_str(), o.plugin.c_str());
  if (!o.baseline_plugin.empty())
    std::printf("COMPARE baseline=appliance(%s) plugin=%s candidate=appliance(%s) plugin=%s\n",
                o.baseline_layout.c_str(), o.baseline_plugin.c_str(),
                o.layout.c_str(), o.plugin.c_str());
  std::unique_ptr<Study> st;
  int rc = 0;
  try {
    const auto activate = [&](const std::string &arm) -> Study & {
      if (st && st->arm() == arm) return *st;
      st.reset();  // wait for the old daemon to exit before allocating the next
      st = std::make_unique<Study>(o, arm);
      st->Start();
      st->Apply();
      st->MemoryReport("after apply");
      const double load = st->Load(0, o.sessions, 200);
      std::printf("load %s: %u sessions (%llu entries) in %.2f s: %.0f sessions/s\n",
                  st->ArmName().c_str(), o.sessions,
                  (unsigned long long)o.sessions * st->EntriesPerSession(), load, o.sessions / load);
      st->PrintMemory("after load");
      std::printf("wire %s: %u entries per session, %zu protobuf key+value bytes (session 0)\n",
                  st->ArmName().c_str(), st->EntriesPerSession(), st->WireBytes(0));
      return *st;
    };
    // No timing until both independent arms pass exact-stream verification.
    const uint64_t k = o.verify != 0 ? o.verify : std::max<uint64_t>(200000, 4ull * o.sessions);
    const bool run_g = o.only != "appliance", run_a = o.only != "graph";
    std::map<std::string, ArmResult> graph;
    // RunExact asserts each arm's sink bytes and every rule's packet/octet
    // delta against an independent replay of the seeded generator.
    if (run_g) {
      for (const std::string &d : dirs) graph[d] = RunExact(activate("g"), d, k);
      UpdateCost(activate("g"), o.updates);
      activate("g").Finish();
      if (!run_a)
        for (const std::string &d : dirs)
          std::printf("verify %s %s: exact stream and per-rule counters PASS (K = %llu; --only graph, no comparison)\n",
                      d.c_str(), baseline_name, (unsigned long long)k);
    }
    for (const std::string &d : run_a ? dirs : std::vector<std::string>{}) {
      const ArmResult a = RunExact(activate("a"), d, k);
      if (!run_g) {
        std::printf("verify %s %s: exact stream and per-rule counters PASS (K = %llu; --only appliance, no comparison)\n",
                    d.c_str(), st->ArmName().c_str(), (unsigned long long)k);
        continue;
      }
      const ArmResult &g = graph.at(d);
      bool same = g.delta == a.delta;
      for (const auto &[s, dg] : g.sinks) {
        const Digest &da = a.sinks.at(s);
        same &= dg == da;
        std::printf("verify %s %-10s %s pkts %llu bytes %llu sum %016llx xor %016llx | appliance pkts %llu bytes %llu sum %016llx xor %016llx\n",
                    d.c_str(), s.c_str(), baseline_name, (unsigned long long)dg.packets, (unsigned long long)dg.bytes,
                    (unsigned long long)dg.sum, (unsigned long long)dg.xsum, (unsigned long long)da.packets,
                    (unsigned long long)da.bytes, (unsigned long long)da.sum, (unsigned long long)da.xsum);
      }
      uint64_t gp = 0, go = 0, ap = 0, ao = 0;
      for (const auto &[id, c] : g.delta) gp += c.first, go += c.second;
      for (const auto &[id, c] : a.delta) ap += c.first, ao += c.second;
      std::printf("verify %s counters: %s %zu rules %llu pkts %llu octets | appliance %zu rules %llu pkts %llu octets\n",
                  d.c_str(), baseline_name, g.delta.size(), (unsigned long long)gp, (unsigned long long)go,
                  a.delta.size(), (unsigned long long)ap, (unsigned long long)ao);
      std::printf("verify %s: %s (K = %llu, appliance layout %s)\n", d.c_str(), same ? "IDENTICAL" : "DIFFERENT",
                  (unsigned long long)k, o.layout.c_str());
      if (!same) throw std::runtime_error(o.baseline_plugin.empty()
          ? "graph/appliance external bytes or per-rule counters differ"
          : "baseline/appliance external bytes or per-rule counters differ");
    }
    if (run_a) {
      UpdateCost(activate("a"), o.updates);
      activate("a").Finish();
    }
    graph.clear();

    // -- ABBA windows (both arms; --rounds 0 verifies only) ----------------------
    if (o.rounds > 0)
    for (const std::string &d : dirs) {
      std::vector<double> g_ns, a_ns, ratios;
      std::map<std::string, std::vector<double>> g_c, a_c;
      for (int r = 0; r < o.rounds; r++) {
        const bool g_first = r % 2 == 0;
        Window wg, wf;
        for (int half = 0; half < 2; half++) {
          const bool do_g = (half == 0) == g_first;
          Window w = Measure(activate(do_g ? "g" : "a"), d);
          std::printf("%s round %d %-9s %.2f ns/pkt (%.2f Mpps) out/in %.4f",
                      d.c_str(), r, do_g ? baseline_name : "appliance", w.ns, 1e3 / w.ns, w.out_ratio);
          for (const auto &[e, v] : w.counters) std::printf(" %s %.2f", e.c_str(), v);
          std::printf("\n");
          std::fflush(stdout);
          (do_g ? wg : wf) = w;
        }
        g_ns.push_back(wg.ns);
        a_ns.push_back(wf.ns);
        ratios.push_back(wf.ns / wg.ns);
        for (const auto &[e, v] : wg.counters) g_c[e].push_back(v);
        for (const auto &[e, v] : wf.counters) a_c[e].push_back(v);
      }
      const int faster = static_cast<int>(std::count_if(ratios.begin(), ratios.end(), [](double x) { return x < 1; }));
      std::printf("SUMMARY %s N=%u burst=%d miss=%d: %s %.2f ns [%.2f-%.2f]  appliance %.2f ns [%.2f-%.2f]  appliance/%s %.3f [%.3f-%.3f] appliance faster in %d/%zu\n",
                  d.c_str(), o.sessions, o.burst, o.miss, baseline_name, Median(g_ns),
                  *std::min_element(g_ns.begin(), g_ns.end()), *std::max_element(g_ns.begin(), g_ns.end()),
                  Median(a_ns), *std::min_element(a_ns.begin(), a_ns.end()),
                  *std::max_element(a_ns.begin(), a_ns.end()), baseline_name, Median(ratios),
                  *std::min_element(ratios.begin(), ratios.end()),
                  *std::max_element(ratios.begin(), ratios.end()), faster, ratios.size());
      for (const auto &[e, v] : g_c) {
        std::printf("SUMMARY %s counter %s per pkt: %s %.2f appliance %.2f\n", d.c_str(), e.c_str(),
                    baseline_name, Median(v), Median(a_c[e]));
      }
    }
  } catch (const std::exception &e) {
    std::fprintf(stderr, "upf_ab: %s\n", e.what());
    if (st) std::printf("daemon_alive=%s\n", st->Alive() ? "true" : "false");
    rc = 2;
  }
  st.reset();
  return rc;
}
