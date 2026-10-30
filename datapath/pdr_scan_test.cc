// SPDX-License-Identifier: BSD-3-Clause
//
// PdrScanResource against the masked table it replaces: random wildcard rules
// (exact, prefix, arbitrary masks, ranges; priority ties; replacements,
// erases, refused and aborted transactions) through Reserve/Prepare/Publish,
// and every lookup must name the rule ConcurrentMaskedTable names. Read-back,
// Contains and the memory given back after erasing everything are checked too.

#include <gtest/gtest.h>

#include <algorithm>
#include <any>
#include <cstring>
#include <map>
#include <memory>
#include <random>
#include <set>
#include <string>
#include <vector>

#include "classifier/concurrent_masked.h"
#include "flow/shared_exact_index.h"
#include "pdr_scan.h"
#include "rcu/rcu_domain.h"
#include "utils/dpdk_memory.h"

namespace {
namespace dp = bess::dataplane;
using bess::classifier::ConcurrentMaskedTable;
using upf::appliance::PdrRange;
using upf::appliance::PdrRule;
using upf::appliance::PdrScanResource;
using upf::appliance::PdrValue;

struct Field {
  uint32_t offset, width;
};
const std::vector<Field> kUl = {{0, 4}, {4, 4}, {8, 1}, {9, 2}, {11, 2}, {13, 4}, {17, 1}};
const std::vector<Field> kDl = {{0, 4}, {4, 4}, {8, 1}, {9, 2}, {11, 2}, {13, 4}, {17, 4}, {21, 1}};

struct Growth final : bess::utils::MemoryGrowth {
  size_t held = 0;
  void Grow(size_t bytes, size_t) override { held += bytes; }
  void Shrink(size_t bytes, size_t) noexcept override { held -= bytes; }
};

uint64_t Max(uint32_t width) { return (uint64_t{1} << 8 * width) - 1; }
void Put(std::vector<uint8_t> &out, Field f, uint64_t x) {
  for (uint32_t i = 0; i < f.width; ++i)
    out[f.offset + i] = static_cast<uint8_t>(x >> 8 * (f.width - 1 - i));
}

class Universe {
 public:
  explicit Universe(bool dl) : dl_(dl), fields_(dl ? kDl : kUl), rng_(dl ? 7 : 3) {}
  size_t len() const { return dl_ ? 22 : 18; }

  uint64_t Pick(size_t f) {
    static const uint64_t src[] = {0x0a000001, 0x0a000101, 0x0a010001, 0xc0a80001};
    static const uint64_t dst[] = {0x0a2d0002, 0x0a2d0003, 0x0a2e0002, 0xc6336401};
    static const uint64_t proto[] = {6, 17, 0, 1};
    static const uint64_t port[] = {0, 53, 80, 443, 0x1234, 0xff35};
    static const uint64_t small[] = {0, 1, 2, 3, 5, 9};
    if (rng_() % 10 == 0) return rng_() & Max(fields_[f].width);
    switch (f) {
      case 0: return src[rng_() % 4];
      case 1: return dst[rng_() % 4];
      case 2: return proto[rng_() % 4];
      case 3: case 4: return port[rng_() % 6];
      default: return small[rng_() % 6];
    }
  }

  std::vector<uint8_t> Key() {
    std::vector<uint8_t> key(len());
    for (size_t f = 0; f < fields_.size(); ++f) Put(key, fields_[f], Pick(f));
    return key;
  }

  // A wire-legal rule key: per field wildcard, exact, prefix, any mask or a range.
  dp::ResourceKey Rule() {
    std::vector<uint8_t> mask(len()), value(len());
    std::vector<PdrRange> ranges;
    const size_t anchor = dl_ ? 1 : 5;
    for (size_t f = 0; f < fields_.size(); ++f) {
      const Field fd = fields_[f];
      const uint64_t max = Max(fd.width);
      int shape = static_cast<int>(rng_() % 5);
      if (f == anchor && rng_() % 10 < 6) shape = 1;
      uint64_t m = 0;
      const uint64_t v = Pick(f);
      switch (shape) {
        case 1: m = max; break;
        case 2: m = (max << (rng_() % (8 * fd.width))) & max; break;
        case 3: m = rng_() & max; break;
        case 4: {
          uint64_t lo = Pick(f), hi = Pick(f);
          if (lo > hi) std::swap(lo, hi);
          if (lo == 0 && hi == max) hi = max - 1;
          ranges.push_back({fd.offset, fd.width, lo, hi});
          break;
        }
        default: break;
      }
      Put(mask, fd, m);
      Put(value, fd, v & m);
    }
    return PdrScanResource::EncodeKey(mask, value, ranges);
  }

  std::mt19937_64 &rng() { return rng_; }

 private:
  bool dl_;
  std::vector<Field> fields_;
  std::mt19937_64 rng_;
};

// One transaction as the engine runs it; `abort` refuses it after Prepare (as
// another resource's refusal would). False when it did not publish.
bool Apply(PdrScanResource &resource, const std::vector<dp::Op> &ops, bool abort = false) {
  std::vector<std::unique_ptr<dp::StagedOp>> staged;
  bool ok = true;
  for (const auto &op : ops) {
    auto reserved = resource.Reserve(op);
    if (!reserved) {
      ok = false;
      break;
    }
    staged.push_back(std::move(reserved->staged));
  }
  ok = ok && resource.Prepare().has_value() && !abort;
  if (ok) {
    dp::Retirer retirer;  // no readers: what it holds is freed with it
    for (auto &s : staged) s->Publish(retirer);
  } else {
    for (auto it = staged.rbegin(); it != staged.rend(); ++it) (*it)->Abort();
  }
  resource.EndTransaction();
  return ok;
}

class PdrScanVsMasked : public ::testing::TestWithParam<bool> {};

TEST_P(PdrScanVsMasked, SameWinnerReadBackAndRelease) {
  const bool dl = GetParam();
  Universe u(dl);
  const size_t len = u.len();
  bess::rcu::RcuDomain domain(64);
  auto anchors = bess::flow::SharedExactIndex::Create(4, 1024, domain, bess::utils::MemoryNode());
  ASSERT_NE(anchors, nullptr);
  Growth growth;
  {
    PdrScanResource resource(dl ? "a/pdr_dl" : "a/pdr_ul", dl, dl ? 24 : 20, *anchors, domain, {});
    resource.set_memory_growth(&growth);
    auto oracle = ConcurrentMaskedTable::Create(static_cast<uint32_t>(len), 4096, domain);
    ASSERT_TRUE(oracle.has_value());
    std::map<dp::ResourceKey, uint16_t> live;  // rule key -> its tag (gate)
    uint16_t next_tag = 1;
    auto span_of = [len](const dp::ResourceKey &k, size_t at) {
      return bess::classifier::ConstBytes(reinterpret_cast<const std::byte *>(k.data()) + at, len);
    };
    auto ranges_of = [len](const dp::ResourceKey &k) {
      std::vector<ConcurrentMaskedTable::KeyRange> r((k.size() - 2 * len) / 24);
      if (!r.empty()) std::memcpy(r.data(), k.data() + 2 * len, r.size() * 24);
      return r;
    };

    auto compare = [&](int round) {
      for (int batch = 0; batch < 8; ++batch) {
        std::vector<std::byte> flat(64 * len);
        PdrScanResource::Key keys[64]{};
        for (size_t i = 0; i < 64; ++i) {
          const auto key = u.Key();
          std::memcpy(flat.data() + i * len, key.data(), len);
          std::memcpy(keys[i].data(), key.data(), len);
        }
        ConcurrentMaskedTable::Match want[64];
        const uint64_t hits = (*oracle)->LookupBatch(flat, len, want, 64);
        const PdrRule *got[64];
        resource.Classify(keys, 64, got);
        for (size_t i = 0; i < 64; ++i) {
          const bool hit = (hits >> i & 1) != 0;
          ASSERT_EQ(hit, got[i] != nullptr) << "round " << round << " key " << i;
          if (hit) ASSERT_EQ(want[i].gate, got[i]->gate) << "round " << round << " key " << i;
        }
      }
    };

    for (int round = 0; round < 120; ++round) {
      std::vector<dp::Op> ops;
      std::vector<std::pair<dp::ResourceKey, int64_t>> upserts;  // priority, -1 = erase
      std::set<dp::ResourceKey> touched;
      std::map<dp::ResourceKey, uint16_t> tags;
      const size_t n = 1 + u.rng()() % 6;
      for (size_t k = 0; k < n; ++k) {
        dp::ResourceKey key;
        const unsigned roll = u.rng()() % 20;
        const bool erase = roll < 5 && !live.empty();
        if ((erase || roll < 8) && !live.empty()) {
          auto it = live.begin();
          std::advance(it, u.rng()() % live.size());
          key = it->first;
        } else {
          key = u.Rule();
        }
        if (!touched.insert(key).second) continue;
        if (erase) {
          ops.push_back(dp::Op::Erase("p", key));
          upserts.emplace_back(key, -1);
        } else {
          const int64_t priority = static_cast<int64_t>(u.rng()() % 3);
          const uint16_t tag = next_tag++;
          tags[key] = tag;
          ops.push_back(dp::Op::Upsert("p", key, std::any(PdrValue{priority, tag, {}})));
          upserts.emplace_back(key, priority);
        }
      }
      const unsigned fate = u.rng()() % 10;
      if (fate == 0) ops.push_back(dp::Op::Erase("p", u.Rule() + "x"));  // refused at Reserve
      const bool abort = fate == 1;
      const bool applied = Apply(resource, ops, abort);
      ASSERT_EQ(applied, fate > 1) << "round " << round;
      domain.ReclaimReady();
      if (applied) {
        for (const auto &[key, priority] : upserts) {
          if (priority < 0) {
            ASSERT_TRUE((*oracle)->Erase(span_of(key, 0), span_of(key, len), ranges_of(key)));
            live.erase(key);
          } else {
            const auto r = (*oracle)->Upsert(span_of(key, 0), span_of(key, len), priority,
                                             tags[key], 0, ranges_of(key));
            ASSERT_TRUE(r == ConcurrentMaskedTable::UpsertResult::kInserted ||
                        r == ConcurrentMaskedTable::UpsertResult::kUpdated);
            live[key] = tags[key];
          }
        }
      }
      ASSERT_EQ(resource.LiveCount(), live.size());
      compare(round);
      if (round % 10 == 9) {
        std::map<dp::ResourceKey, uint16_t> read;
        resource.ForEach([&](const dp::ResourceKey &k, const PdrRule &r) { read[k] = r.gate; });
        ASSERT_EQ(read, live) << "round " << round;
        for (const auto &[key, tag] : live) ASSERT_TRUE(resource.Contains(key));
      }
    }

    // Erase everything: no anchor left, every byte given back.
    std::vector<dp::Op> erase;
    for (const auto &[key, tag] : live) erase.push_back(dp::Op::Erase("p", key));
    ASSERT_TRUE(Apply(resource, erase));
    domain.ReclaimReady();
    EXPECT_EQ(resource.LiveCount(), 0u);
    EXPECT_EQ(anchors->size(), 0u);
    EXPECT_EQ(growth.held, 0u);
    EXPECT_EQ(resource.bytes(), sizeof(PdrScanResource));
  }
  domain.Drain();
}

INSTANTIATE_TEST_SUITE_P(Directions, PdrScanVsMasked, ::testing::Bool());

}  // namespace
