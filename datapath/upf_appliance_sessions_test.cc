// SPDX-License-Identifier: BSD-3-Clause
//
// The session-major store (upf_appliance_sessions.h) under the real RCU
// domain, masked table and F-TEID index, driven by hand through Reserve and
// Publish as the transaction engine drives a resource (as
// gtpu_datapath_test.cc does; the engine's header is not installed). A
// reader thread plays the worker (lookup -> result -> config -> slots,
// quiescent between batches) while the control side rewrites the session it
// reads. What a consumer would see goes wrong is what these check: a packet
// that combines two versions, a miss while a rule is replaced, a counter that
// loses or double-counts across a rewrite, a token bucket that refills on an
// unrelated rewrite, a refused update, a shared meter the session does not
// declare as a reference, and a memory refusal that leaves anything behind.

#include "upf_appliance_sessions.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <bit>
#include <chrono>
#include <cstring>
#include <memory>
#include <thread>

#include "dataplane/resource.h"
#include "flow/shared_exact_index.h"
#include "gate.h"
#include "meter/meter_resource.h"
#include "rcu/rcu_ptr.h"
#include "utils/logging.h"

namespace {
namespace dp = bess::dataplane;
namespace meter = bess::meter;
using bess::classifier::ConstBytes;
using upf::appliance::ActionConfig;
using upf::appliance::SessionResource;
using upf::appliance::SessionValue;
using Reference = dp::Reference;
using Table = bess::classifier::ConcurrentMaskedTable;

constexpr uint32_t kSession = 3, kId = 0x7e57;
constexpr uint32_t kSharedMeter = 77;

// A memory scope's growth hook with a budget (D-198's refusal).
class Budget final : public bess::utils::MemoryGrowth {
 public:
  void Grow(size_t bytes, size_t) override {
    if (bytes > left) throw bess::utils::MemoryRefused(
        bess::utils::MemoryRefused::Reason::kNormalLimit, bytes, "test budget");
    left -= bytes;
  }
  void Shrink(size_t bytes, size_t) noexcept override { left += bytes; }
  size_t left = SIZE_MAX / 2;
};

// Retirer hands its deferred steps only to the engine (a friend). The test
// runs them itself, reached the way the standard allows: access checking
// does not apply to the names in an explicit instantiation.
struct RemovalsTag {};
struct AfterTag {};
auto Member(RemovalsTag);
auto Member(AfterTag);
template <auto M, typename Tag>
struct Expose {
  friend auto Member(Tag) { return M; }
};
template struct Expose<&dp::Retirer::removals_, RemovalsTag>;
template struct Expose<&dp::Retirer::after_, AfterTag>;

// What the engine reports for one op: the refusal, or the references the
// new value holds (the engine's ledger checks them; the test checks them).
struct Result {
  std::string error;
  std::vector<Reference> references;
};

struct Store {
  explicit Store(SessionResource::Limits limits = {.capacity = 8, .max_actions = 4, .max_qers = 4})
      : domain(64),
        index(bess::flow::SharedExactIndex::Create(sizeof(upf::datapath::FteidId), 64, domain,
                                                   bess::utils::MemoryNode())),
        ul(std::move(*Table::Create(18, 16, domain))),
        dl(std::move(*Table::Create(22, 8, domain))),
        fteids(std::make_unique<upf::datapath::FteidResource>("upf/fteids", *index, domain, 64)),
        meters(std::make_unique<meter::MeterResource>("upf/meters", 128, meter_set, &meter_budget)),
        sessions(std::make_unique<SessionResource>("upf/sessions", "upf/next_hops", "upf/meters",
                                                   limits, *ul, *dl, *fteids, domain)) {
    sessions->set_memory_growth(&budget);
  }
  ~Store() { domain.Drain(); }

  // The engine's sequence for a one-op transaction: reserve and prepare (may
  // refuse or throw MemoryRefused, publishing nothing), publish, end the
  // transaction (also when refused), start the grace period, then -- once it
  // has passed -- free what was replaced and run the deferred removals, each
  // a grace period after the last.
  Result Drive(dp::Resource &resource, const dp::Op &op) {
    struct End {
      dp::Resource &resource;
      ~End() { resource.EndTransaction(); }
    };
    std::optional<End> end(std::in_place, resource);
    auto r = resource.Reserve(op);
    if (!r) return {.error = r.error()};
    if (auto prepared = resource.Prepare(); !prepared) {
      r->staged->Abort();
      return {.error = prepared.error()};
    }
    dp::Retirer retirer;
    r->staged->Publish(retirer);
    end.reset();
    Finish(retirer);
    return {.references = std::move(r->references)};
  }
  void Finish(dp::Retirer &retirer) {
    const bess::rcu::GracePeriod token = domain.StartGracePeriod();
    for (auto &fn : retirer.*Member(AfterTag{})) fn(token);
    domain.Synchronize();
    for (auto &removal : retirer.*Member(RemovalsTag{})) {
      dp::Retirer next;
      removal.step(next);
      Finish(next);
    }
  }
  Result Apply(const dp::Op &op) {
    return Drive(op.resource == meters->name() ? static_cast<dp::Resource &>(*meters) : *sessions, op);
  }
  Result Put(const SessionValue &v, uint32_t id = kSession) {
    return Apply(dp::Op::Upsert(sessions->name(), dp::EncodeKey(id), std::any(v)));
  }

  bess::rcu::RcuDomain domain;
  std::unique_ptr<bess::flow::SharedExactIndex> index;
  std::unique_ptr<Table> ul, dl;
  std::unique_ptr<upf::datapath::FteidResource> fteids;
  Budget meter_budget, budget;
  // Before the resource that publishes through it (MeterResource's ctor).
  bess::rcu::RcuPtr<meter::MeterSet> meter_set{domain};
  std::unique_ptr<meter::MeterResource> meters;
  std::unique_ptr<SessionResource> sessions;
};

bool Applied(const Result &r) { return r.error.empty(); }
std::string Why(const Result &r) { return r.error; }
bool Names(const Result &r, uint32_t meter_id) {
  const Reference ref{"upf/meters", dp::EncodeKey(meter::MeterId(meter_id))};
  return std::ranges::find(r.references, ref) != r.references.end();
}

std::array<std::byte, 18> UlKey(uint8_t host) {
  std::array<std::byte, 18> key{};
  key[0] = std::byte{10}; key[3] = std::byte{host};  // UE source
  key[4] = std::byte{198}; key[7] = std::byte{1};    // destination
  key[8] = std::byte{17};
  key[15] = std::byte{0x7e}; key[16] = std::byte{0x57};  // F-TEID context
  return key;
}

SessionValue::Pdr UlPdr(uint8_t action, uint8_t host = 2, int64_t priority = 100) {
  const auto key = UlKey(host);
  return {.dl = false, .mask = std::vector<std::byte>(18, std::byte{0xff}),
          .value = std::vector<std::byte>(key.begin(), key.end()), .priority = priority,
          .gate = 0, .action = action};
}

upf::appliance::Tunnel MakeTunnel(uint32_t teid, uint16_t marking) {
  upf::appliance::Tunnel t{.teid = teid, .family = 4, .marking = marking};
  t.local[12] = 192; t.local[15] = 1; t.peer[12] = 10; t.peer[15] = 2;
  return t;
}

const meter::TrTcmSpec kSlow{1000, 10000, 1000, 10000};

// Version A: kId at position 0. Version B: a tunnel-only action first, so
// kId moves to position 1 -- its cell and meter slots must not.
SessionValue Image(bool b, std::optional<meter::MeterProfileSpec> spec = kSlow) {
  SessionValue v;
  upf::datapath::FteidId fteid{};
  fteid[3] = 0x57; fteid[4] = 4; fteid[24] = 0x57;
  v.fteids = {{fteid, {0, kId}}};
  v.qers = {spec ? SessionValue::Qer{.qer_id = 1, .spec = spec}
                 : SessionValue::Qer{.qer_id = 1, .shared = kSharedMeter}};
  SessionValue::Action main{.action_id = kId, .next_hop_id = 0, .route_domain = b ? 2u : 1u,
                            .qer = {1, 0}, .count = true,
                            .tunnel = MakeTunnel(b ? 0xb : 0xa, b ? 0xbb : 0xaa)};
  if (b) {
    v.actions = {{.action_id = kId + 1, .tunnel = MakeTunnel(0xc, 0xcc)}, main};
    v.pdrs = {UlPdr(1)};
  } else {
    v.actions = {main};
    v.pdrs = {UlPdr(0)};
  }
  return v;
}

// One worker-side read of the rule: what a frame would bind.
struct Seen {
  bool hit = false;
  uint32_t session = 0;
  uint8_t version = 0, index = 0;
  ActionConfig config;
};
Seen Classify(const Store &s, uint8_t host = 2) {
  const auto key = UlKey(host);
  Table::Match match;
  Seen seen;
  if (s.ul->LookupBatch(ConstBytes(key.data(), key.size()), key.size(), &match, 1) == 0) return seen;
  const uint32_t r = s.ul->RuleAt(match.rule_id).result_id;
  seen = {.hit = true, .session = SessionResource::SessionOf(r),
          .version = SessionResource::VersionOf(r), .index = SessionResource::IndexOf(r)};
  if (seen.session != 0)
    seen.config = s.sessions->Config(seen.session, seen.version, seen.index);
  return seen;
}

uint64_t Packets(const SessionResource &s, uint32_t id, bool dl) {
  upf::pb::UrrCountCommandGetCountsResponse out;
  const uint32_t ids[] = {id};
  s.Counts(dl, ids, false, &out);
  return out.counts_size() == 1 ? out.counts(0).packets() : ~uint64_t{0};
}

// The worker side: lookups in batches of 32, quiescent between them, as
// UpfSessionAppliance's ClassifyPdr -> MeterSessions -> CountSessions.
struct Reader {
  explicit Reader(Store &s) : store(s), thread([this] { Run(); }) {}
  ~Reader() { Stop(); }
  void Stop() {
    stop.store(true, std::memory_order_release);
    if (thread.joinable()) thread.join();
  }
  void Run() {
    auto &domain = store.domain;
    ASSERT_TRUE(domain.Register(1).has_value());
    domain.Online(1);
    while (!stop.load(std::memory_order_acquire)) {
      for (int i = 0; i < 32; ++i) {
        const Seen seen = Classify(store);
        if (!seen.hit) { ++misses; continue; }
        const ActionConfig &c = seen.config;
        // One version's image: A's or B's fields together, never a mix.
        const bool a = c.teid == 0xa && c.marking == 0xaa && c.route_domain == 1 && seen.index == 0;
        const bool b = c.teid == 0xb && c.marking == 0xbb && c.route_domain == 2 && seen.index == 1;
        if (seen.session != kSession || c.action_id != kId || !(a || b) || !c.has_tunnel() ||
            !(c.cell & ActionConfig::kCount) || c.meter[0] == 0) {
          ++mixed;
          continue;
        }
        cell_slots |= 1u << (c.cell & ActionConfig::kCellSlot);
        const uint16_t slot = (c.meter[0] & ~ActionConfig::kSharedMeter) - 1;
        auto &m = store.sessions->Meter(kSession, slot);
        if (c.meter[0] & ActionConfig::kSharedMeter) {
          ++shared;
          if (m.shared() != kSharedMeter) ++mixed;
        } else {
          own_slots |= 1u << slot;
          if (!std::holds_alternative<meter::TrTcmSpec>(m.meter().profile().spec())) ++mixed;
          else if (m.meter().Check(meter::MeterNow(), 100) == meter::MeterColor::kGreen) ++green;
        }
        store.sessions->Cells(kSession, c.cell & ActionConfig::kCellSlot).urr[0].Add(100, ++hits);
      }
      domain.Quiescent(1);
    }
    domain.Offline(1);
    domain.Unregister(1);
  }

  Store &store;
  std::atomic<bool> stop{false};
  std::atomic<uint64_t> hits{0}, misses{0}, mixed{0}, green{0}, shared{0};
  std::atomic<uint32_t> cell_slots{0}, own_slots{0};
  std::thread thread;
};

TEST(SessionStore, InsertUpdateEraseDriveTheTablesAndVersions) {
  Store s;
  ASSERT_TRUE(Applied(s.Put(Image(false))));
  Seen seen = Classify(s);
  ASSERT_TRUE(seen.hit);
  EXPECT_EQ(seen.session, kSession);
  EXPECT_EQ(seen.version, 0);
  EXPECT_EQ(s.sessions->Active(kSession), 0);
  EXPECT_EQ(seen.config.teid, 0xau);
  EXPECT_TRUE(s.fteids->Contains(dp::EncodeKey(Image(false).fteids[0].id)));

  ASSERT_TRUE(Applied(s.Put(Image(true))));
  seen = Classify(s);
  EXPECT_EQ(seen.version, 1);
  EXPECT_EQ(seen.index, 1);
  EXPECT_EQ(seen.config.teid, 0xbu);
  EXPECT_EQ(s.sessions->Active(kSession), 1);
  // The version a frame classified before the update still reads whole.
  EXPECT_EQ(s.sessions->Config(kSession, 0, 0).teid, 0xau);
  EXPECT_EQ(s.sessions->Find(kSession, 1, kId), 1);

  // Two updates back to back (no grace period between them in the test:
  // no reader online) are applied, never refused.
  ASSERT_TRUE(Applied(s.Put(Image(false))));
  ASSERT_TRUE(Applied(s.Put(Image(true))));

  ASSERT_TRUE(Applied(s.Apply(dp::Op::Erase(s.sessions->name(), dp::EncodeKey(kSession)))));
  EXPECT_FALSE(Classify(s).hit);
  EXPECT_FALSE(s.fteids->Contains(dp::EncodeKey(Image(false).fteids[0].id)));
  EXPECT_EQ(s.sessions->Active(kSession), SessionResource::kGone);
  EXPECT_FALSE(s.sessions->Contains(dp::EncodeKey(kSession)));
}

TEST(SessionStore, OwnershipAndShapeRefusals) {
  Store s;
  ASSERT_TRUE(Applied(s.Put(Image(false))));
  // Another session naming the same action id, PDR key or F-TEID.
  SessionValue other = Image(false);
  other.fteids.clear();
  EXPECT_FALSE(Applied(s.Put(other, kSession + 1)));
  other.actions[0].action_id = kId + 9;
  EXPECT_FALSE(Applied(s.Put(other, kSession + 1)));  // the PDR key is taken
  other.pdrs = {UlPdr(0, 9)};
  other.fteids = Image(false).fteids;
  EXPECT_FALSE(Applied(s.Put(other, kSession + 1)));  // the F-TEID is taken
  other.fteids.clear();
  EXPECT_TRUE(Applied(s.Put(other, kSession + 1)));
  // An F-TEID keeps its direction and context in a modification (as the
  // graph's FteidResource refuses it).
  SessionValue moved = Image(false);
  moved.fteids[0].record.context_id = 9;
  EXPECT_FALSE(Applied(s.Put(moved)));
  // Shapes.
  SessionValue wide = Image(false);
  for (uint32_t i = 1; i <= 4; ++i) wide.actions.push_back({.action_id = kId + 100 + i, .tunnel = MakeTunnel(i, 0)});
  EXPECT_FALSE(Applied(s.Put(wide)));  // 5 actions > max_actions 4
  SessionValue drop = Image(false);
  drop.pdrs.push_back(UlPdr(SessionValue::kNoAction, 3));
  EXPECT_FALSE(Applied(s.Put(drop)));  // no action needs the drop gate
  drop.pdrs.back().gate = DROP_GATE;
  ASSERT_TRUE(Applied(s.Put(drop)));
  Table::Match match;
  const auto key = UlKey(3);
  ASSERT_EQ(s.ul->LookupBatch(ConstBytes(key.data(), key.size()), key.size(), &match, 1), 1u);
  EXPECT_EQ(match.gate, DROP_GATE);
  // Nothing refused above left a pending rule or F-TEID behind.
  EXPECT_TRUE(Classify(s).hit);
  EXPECT_TRUE(Classify(s, 9).hit);
}

TEST(SessionStore, CellsAndBucketsFollowIdentityNotPosition) {
  Store s;
  ASSERT_TRUE(Applied(s.Put(Image(false))));
  const ActionConfig a = Classify(s).config;
  auto &cells = s.sessions->Cells(kSession, a.cell & ActionConfig::kCellSlot);
  for (int i = 0; i < 7; ++i) cells.urr[0].Add(64, 100 + i);
  auto &bucket = s.sessions->Meter(kSession, a.meter[0] - 1).meter();
  ASSERT_EQ(bucket.Check(meter::MeterNow(), 6000), meter::MeterColor::kGreen);
  const auto before = bucket.Inspect();

  ASSERT_TRUE(Applied(s.Put(Image(true))));  // kId moves to position 1
  const ActionConfig b = Classify(s).config;
  EXPECT_EQ(b.cell & ActionConfig::kCellSlot, a.cell & ActionConfig::kCellSlot);
  EXPECT_EQ(b.meter[0], a.meter[0]);
  EXPECT_EQ(Packets(*s.sessions, kId, false), 7u);
  const auto after = bucket.Inspect();
  EXPECT_EQ(after.buckets[0].tokens, before.buckets[0].tokens);
  EXPECT_EQ(after.last_update_tsc, before.last_update_tsc);
  // The tunnel-only action got its own, zeroed cell slot.
  const ActionConfig &tunnel_only = s.sessions->Config(kSession, 1, 0);
  EXPECT_NE(tunnel_only.cell & ActionConfig::kCellSlot, b.cell & ActionConfig::kCellSlot);
  EXPECT_FALSE(tunnel_only.cell & ActionConfig::kCount);

  // A changed profile is a new bucket (full); the old one stays as the old
  // version left it until that version is unreachable.
  ASSERT_TRUE(Applied(s.Put(Image(false, meter::TrTcmSpec{1000, 1500, 1000, 1500}))));
  const ActionConfig c = Classify(s).config;
  EXPECT_NE(c.meter[0], b.meter[0]);
  EXPECT_EQ(s.sessions->Meter(kSession, c.meter[0] - 1).meter().Inspect().buckets[0].tokens, 1500u);
  EXPECT_EQ(Packets(*s.sessions, kId, false), 7u);
  EXPECT_EQ(bucket.Inspect().buckets[0].tokens, after.buckets[0].tokens);

  // A UL action rewritten to DL starts its DL bank at zero and keeps UL
  // history; back to UL resumes the UL bank.
  SessionValue down = Image(false, meter::TrTcmSpec{1000, 1500, 1000, 1500});
  down.pdrs[0].dl = true;
  down.pdrs[0].mask.assign(22, std::byte{0xff});
  down.pdrs[0].value.assign(22, std::byte{0});
  ASSERT_TRUE(Applied(s.Put(down)));
  EXPECT_EQ(Packets(*s.sessions, kId, true), 0u);
  EXPECT_EQ(Packets(*s.sessions, kId, false), 7u);
  ASSERT_TRUE(Applied(s.Put(Image(false, meter::TrTcmSpec{1000, 1500, 1000, 1500}))));
  cells.urr[0].Add(64, 200);
  EXPECT_EQ(Packets(*s.sessions, kId, false), 8u);

  // An action that leaves and comes back is a new action: zeroed cells.
  SessionValue without = Image(false);
  without.actions[0].action_id = kId + 5;
  ASSERT_TRUE(Applied(s.Put(without)));
  ASSERT_TRUE(Applied(s.Put(Image(false))));
  EXPECT_EQ(Packets(*s.sessions, kId, false), 0u);
}

TEST(SessionStore, SharedMeterIsReferencedAndTransitionsBothWays) {
  Store s;
  ASSERT_TRUE(Applied(s.Apply(dp::Op::Upsert("upf/meters", dp::EncodeKey(meter::MeterId(kSharedMeter)),
                                             std::any(meter::MeterProfileSpec(kSlow))))));
  ASSERT_TRUE(Applied(s.Put(Image(false))));
  const Result shared = s.Put(Image(true, std::nullopt));  // own -> shared
  ASSERT_TRUE(Applied(shared)) << Why(shared);
  const ActionConfig c = Classify(s).config;
  ASSERT_TRUE(c.meter[0] & ActionConfig::kSharedMeter);
  EXPECT_EQ(s.sessions->Meter(kSession, (c.meter[0] & ~ActionConfig::kSharedMeter) - 1).shared(),
            kSharedMeter);
  // The session declares the meter, so the engine's ledger refuses to erase
  // it while named, and refuses a session naming one that does not exist.
  EXPECT_TRUE(Names(shared, kSharedMeter));
  const Reference ref{"upf/meters", dp::EncodeKey(meter::MeterId(kSharedMeter))};
  EXPECT_EQ(s.sessions->ReferencesOf(dp::EncodeKey(kSession)), std::vector<Reference>{ref});
  SessionValue missing = Image(false, std::nullopt);
  missing.qers[0].shared = kSharedMeter + 1;
  EXPECT_TRUE(Names(s.Put(missing), kSharedMeter + 1));
  ASSERT_TRUE(Applied(s.Put(Image(false))));  // shared -> own: a full bucket
  EXPECT_TRUE(s.sessions->ReferencesOf(dp::EncodeKey(kSession)).empty());
  const ActionConfig d = Classify(s).config;
  ASSERT_FALSE(d.meter[0] & ActionConfig::kSharedMeter);
  EXPECT_EQ(s.sessions->Meter(kSession, d.meter[0] - 1).meter().Inspect().buckets[0].tokens, 10000u);
  EXPECT_TRUE(Applied(s.Apply(dp::Op::Erase("upf/meters", dp::EncodeKey(meter::MeterId(kSharedMeter))))));
}

TEST(SessionStore, RewriteUnderTrafficNeverMixesVersionsOrLosesState) {
  Store s;
  ASSERT_TRUE(Applied(s.Put(Image(false))));
  const auto start = std::chrono::steady_clock::now();
  Reader reader(s);
  size_t updates = 0;
  for (; updates < 2000; ++updates) {
    const auto r = s.Put(Image(updates % 2 == 0));
    ASSERT_TRUE(Applied(r)) << "update " << updates << ": " << Why(r);
  }
  reader.Stop();
  const double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
  EXPECT_GT(reader.hits.load(), 0u);
  EXPECT_EQ(reader.misses.load(), 0u) << "a rewritten rule missed";
  EXPECT_EQ(reader.mixed.load(), 0u) << "a frame combined two versions";
  // One cell slot and one bucket for the whole run: every count landed in
  // the same place and get_counts reads exactly what the reader added.
  EXPECT_EQ(std::popcount(reader.cell_slots.load()), 1);
  EXPECT_EQ(std::popcount(reader.own_slots.load()), 1);
  EXPECT_EQ(Packets(*s.sessions, kId, false), reader.hits.load());
  // The bucket kept its tokens through 2000 rewrites: greens are bounded by
  // the burst plus the rate over the run (a refill per rewrite would pass
  // up to 100 greens each).
  const double bound = (10000 + 1000 * (seconds + 1)) / 100;
  EXPECT_LE(static_cast<double>(reader.green.load()), bound);
}

TEST(SessionStore, SharedAndOwnTransitionsUnderTraffic) {
  Store s;
  ASSERT_TRUE(Applied(s.Apply(dp::Op::Upsert("upf/meters", dp::EncodeKey(meter::MeterId(kSharedMeter)),
                                             std::any(meter::MeterProfileSpec(kSlow))))));
  ASSERT_TRUE(Applied(s.Put(Image(false))));
  Reader reader(s);
  for (size_t i = 0; i < 1000; ++i) {
    // A: own bucket; B: the shared meter.
    const bool b = i % 2 == 0;
    const auto r = s.Put(Image(b, b ? std::nullopt : std::optional<meter::MeterProfileSpec>(kSlow)));
    ASSERT_TRUE(Applied(r)) << "update " << i << ": " << Why(r);
  }
  reader.Stop();
  EXPECT_EQ(reader.misses.load(), 0u);
  EXPECT_EQ(reader.mixed.load(), 0u) << "a frame read a slot the other version was building";
  EXPECT_EQ(std::popcount(reader.cell_slots.load()), 1);
  EXPECT_EQ(Packets(*s.sessions, kId, false), reader.hits.load());
}

TEST(SessionStore, MemoryRefusalLeavesNothingAndTheLiveVersionServing) {
  Store s;
  s.budget.left = 0;
  EXPECT_THROW(s.Put(Image(false)), bess::utils::MemoryRefused);
  EXPECT_FALSE(Classify(s).hit);
  EXPECT_FALSE(s.sessions->Contains(dp::EncodeKey(kSession)));
  EXPECT_FALSE(s.fteids->Contains(dp::EncodeKey(Image(false).fteids[0].id)));
  EXPECT_EQ(s.sessions->Active(kSession), SessionResource::kGone);
  s.budget.left = SIZE_MAX / 2;
  ASSERT_TRUE(Applied(s.Put(Image(false))));  // no transaction state left behind
  const Seen live = Classify(s);
  s.budget.left = 0;
  EXPECT_THROW(s.Put(Image(true)), bess::utils::MemoryRefused);
  const Seen after = Classify(s);
  EXPECT_EQ(after.version, live.version);
  EXPECT_EQ(after.config.teid, live.config.teid);
  EXPECT_EQ(s.sessions->Active(kSession), live.version);
  s.budget.left = SIZE_MAX / 2;
  EXPECT_TRUE(Applied(s.Put(Image(true))));
}

}  // namespace

int main(int argc, char **argv) {
  // The first SharedExactIndex brings the EAL up without hugepages
  // (bess_eal's lazy bring-up); the test must not initialize it first.
  google::InitGoogleLogging(argv[0]);
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
