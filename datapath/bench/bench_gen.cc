// SPDX-License-Identifier: BSD-3-Clause

// The A/B bench's modules (built with -Dbench=true): the traffic and the
// evidence for comparing two datapaths -- the graph and UpfAppliance, or two
// builds of one -- on identical inputs (bench/upf_ab.cc drives them).
//
// UpfBenchGen spreads a template frame over N sessions: each packet draws a
// session s uniformly (xorshift) and gets that session's TEID and UE address,
// with the IPv4 checksum recomputed; with miss_per_mille it draws N + s
// instead (no such session). `arm` restarts the stream from a seed and can
// cap it at an exact packet count, so two arms see the same packets.
//
// UpfHashSink frees what it gets and, when enabled, keeps an order-insensitive
// digest of the packets' bytes: two arms fed the same stream must agree.

#include <cstring>

#include "utils/logging.h"

#include "commands.h"
#include "module.h"
#include "upf_datapath.pb.h"

class UpfBenchGen final : public Module {
 public:
  static const gate_idx_t kNumOGates = 1;
  static const Commands cmds;
  UpfBenchGen() : Module() { max_allowed_workers_ = Worker::kMaxWorkers; }

  CommandResponse Init(const upf::pb::UpfBenchGenArg &arg) {
    if (arg.sessions() == 0) return CommandFailure(EINVAL, "sessions must be > 0");
    mode_ = arg.mode();
    n_ = arg.sessions();
    teid_base_ = arg.teid_base();
    ue_base_ = arg.ue_base();
    miss_ = arg.miss_per_mille();
    seed_ = arg.seed() != 0 ? arg.seed() : 0x9e3779b97f4a7c15ull;
    state_ = seed_;
    return CommandSuccess();
  }

  CommandResponse CommandArm(const upf::pb::UpfBenchGenCommandArmArg &arg) {
    upf::pb::UpfBenchGenCommandArmResponse r;
    r.set_forwarded(forwarded_);
    state_ = arg.seed() != 0 ? arg.seed() : seed_;
    limit_ = arg.limit();
    forwarded_ = 0;
    return CommandSuccess(r);
  }

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override {
    if (limit_ != 0 && forwarded_ >= limit_) {
      bess::PacketFreeBatch(batch);
      batch->clear();
      return;
    }
    if (limit_ != 0 && forwarded_ + batch->cnt() > limit_) {
      const int keep = static_cast<int>(limit_ - forwarded_);
      bess::PacketFreeBulk(batch->handles() + keep, static_cast<size_t>(batch->cnt() - keep));
      batch->set_cnt(keep);
    }
    for (int i = 0; i < batch->cnt(); i++) {
      bess::PacketRef pkt = batch->packet(i);
      uint8_t *f = pkt.head_data<uint8_t *>();
      state_ ^= state_ << 13;
      state_ ^= state_ >> 7;
      state_ ^= state_ << 17;
      uint32_t s = static_cast<uint32_t>((state_ >> 16) % n_);
      if (miss_ != 0 && (state_ & 0xffff) % 1000 < miss_) s += n_;
      if (mode_ == 0) {
        // Eth / IPv4 / UDP / GTP-U (8) / inner IPv4: TEID at 46, inner at 50.
        if (pkt.head_len() < 70) continue;
        Put32(f + 46, teid_base_ + s);
        Put32(f + 50 + 12, ue_base_ + s);
        Checksum(f + 50);
      } else {
        // Eth / IPv4: destination at 30.
        if (pkt.head_len() < 34) continue;
        Put32(f + 30, ue_base_ + s);
        Checksum(f + 14);
      }
    }
    forwarded_ += batch->cnt();
    RunNextModule(ctx, batch);
  }

 private:
  static void Put32(uint8_t *p, uint32_t v) {
    v = __builtin_bswap32(v);
    std::memcpy(p, &v, 4);
  }
  static void Checksum(uint8_t *ip) {
    ip[10] = ip[11] = 0;
    uint32_t sum = 0;
    for (int k = 0; k < 20; k += 2) sum += (uint32_t{ip[k]} << 8) | ip[k + 1];
    sum = (sum & 0xffff) + (sum >> 16);
    sum = ~((sum & 0xffff) + (sum >> 16)) & 0xffff;
    ip[10] = static_cast<uint8_t>(sum >> 8);
    ip[11] = static_cast<uint8_t>(sum);
  }

  uint32_t mode_ = 0, n_ = 1, teid_base_ = 0, ue_base_ = 0, miss_ = 0;
  uint64_t seed_ = 1, state_ = 1, limit_ = 0, forwarded_ = 0;
};

const Commands UpfBenchGen::cmds = {
    {"arm", "upf.pb.UpfBenchGenCommandArmArg", MODULE_CMD_FUNC(&UpfBenchGen::CommandArm),
     Command::THREAD_UNSAFE, "upf.pb.UpfBenchGenCommandArmResponse"},
};

class UpfHashSink final : public Module {
 public:
  static const gate_idx_t kNumIGates = MAX_GATES;
  static const gate_idx_t kNumOGates = 0;
  static const Commands cmds;
  UpfHashSink() : Module() { max_allowed_workers_ = Worker::kMaxWorkers; }

  CommandResponse Init(const upf::pb::UpfHashSinkArg &) { return CommandSuccess(); }

  CommandResponse CommandDigest(const upf::pb::UpfHashSinkCommandDigestArg &arg) {
    upf::pb::UpfHashSinkCommandDigestResponse r;
    r.set_packets(packets_);
    r.set_sum(sum_);
    r.set_xsum(xsum_);
    r.set_bytes(bytes_);
    if (arg.reset()) packets_ = sum_ = xsum_ = bytes_ = 0;
    enabled_ = arg.enable();
    return CommandSuccess(r);
  }

  void ProcessBatch(Context *, bess::PacketBatch *batch) override {
    if (enabled_) {
      for (int i = 0; i < batch->cnt(); i++) {
        bess::PacketRef pkt = batch->packet(i);
        const auto *p = pkt.head_data<const uint8_t *>();
        uint64_t h = 0xcbf29ce484222325ull;  // FNV-1a over the first segment
        for (uint32_t k = 0; k < pkt.head_len(); k++) h = (h ^ p[k]) * 0x100000001b3ull;
        h ^= uint64_t{pkt.total_len()} << 48;
        packets_++;
        sum_ += h;
        xsum_ ^= h * 0x9e3779b97f4a7c15ull;
        bytes_ += pkt.total_len();
      }
    }
    bess::PacketFreeBatch(batch);
    batch->clear();
  }

 private:
  bool enabled_ = false;
  uint64_t packets_ = 0, sum_ = 0, xsum_ = 0, bytes_ = 0;
};

const Commands UpfHashSink::cmds = {
    {"digest", "upf.pb.UpfHashSinkCommandDigestArg",
     MODULE_CMD_FUNC(&UpfHashSink::CommandDigest), Command::THREAD_UNSAFE,
     "upf.pb.UpfHashSinkCommandDigestResponse"},
};

ADD_MODULE(UpfBenchGen, "upf_bench_gen", "spreads a template frame over N sessions (bench)")
ADD_MODULE(UpfHashSink, "upf_hash_sink", "frees packets, digesting their bytes (bench)")
