// SPDX-License-Identifier: BSD-3-Clause
#include "pdr_scan.h"

#include <algorithm>
#include <bit>
#include <cstring>
#include <format>
#include <span>
#include <tuple>
#include <utility>

#include "utils/logging.h"

namespace upf::appliance {
namespace {
using bess::classifier::FirewallFamily;
using bess::classifier::FirewallKey;
using bess::classifier::FirewallRule;
using bess::classifier::FirewallScan;
using bess::classifier::FirewallTable;
namespace dp = bess::dataplane;

// The PDR key's fields (compile.go's order). 0 source, 1 destination,
// 2 protocol, 3/4 ports; the rest -- UL context, QFI; DL route domain,
// context, QFI -- are guards only.
struct Field {
  uint32_t offset, width;
};
constexpr Field kUl[] = {{0, 4}, {4, 4}, {8, 1}, {9, 2}, {11, 2}, {13, 4}, {17, 1}};
constexpr Field kDl[] = {{0, 4}, {4, 4}, {8, 1}, {9, 2}, {11, 2}, {13, 4}, {17, 4}, {21, 1}};
std::span<const Field> Fields(bool dl) { return dl ? std::span<const Field>(kDl) : kUl; }
// UL: the F-TEID context; DL: the destination (UE) address.
size_t AnchorField(bool dl) { return dl ? 1 : 5; }

uint64_t Read(const uint8_t *p, size_t width) noexcept {
  uint64_t x = 0;
  for (size_t i = 0; i < width; ++i) x = x << 8 | p[i];
  return x;
}
uint64_t FieldMax(size_t width) { return width == 8 ? ~uint64_t{0} : (uint64_t{1} << 8 * width) - 1; }

// ConcurrentMaskedTable's order: higher priority, then the later command.
bool Better(const PdrRule &a, const PdrRule &b) noexcept {
  return a.priority != b.priority ? a.priority > b.priority : a.sequence > b.sequence;
}
bool RangeLess(const PdrRange &a, const PdrRange &b) noexcept {
  return std::tie(a.offset, a.width, a.low, a.high) < std::tie(b.offset, b.width, b.low, b.high);
}
}  // namespace

// A rule as the control side handles it: its guard, its scan rule, its result.
struct PdrScanResource::Spec {
  std::array<uint64_t, 3> mask{}, value{};  // guard: masked compare over the key
  std::vector<PdrRange> ranges;             // guard: field ranges
  FirewallRule fw;
  PdrRule rule;
};
struct PdrScanResource::Group {
  std::array<uint64_t, 3> mask, value;
  std::vector<PdrRange> ranges;
  FirewallScan scan;  // rules best first
  uint32_t first;     // the scan's rule i is Policy::rules[first + i - 1]
};
struct PdrScanResource::Policy {
  std::vector<Group> groups;  // by their best rule, best first
  std::vector<PdrRule> rules;
  size_t bytes = 0;  // admitted for this policy
};
struct PdrScanResource::Change {
  bool anchored = false;
  uint32_t anchor = 0;
  bool erase = false;
  size_t previous = SIZE_MAX;  // the committed rule replaced or erased
  Spec spec;                   // an upsert's rule
};

class PdrScanResource::PublishOp final : public dp::StagedOp {
 public:
  explicit PublishOp(PdrScanResource &owner) : owner_(owner) {}
  void Publish(dp::Retirer &retirer) noexcept override { owner_.PublishStaged(retirer); }

 private:
  PdrScanResource &owner_;
};

void PdrScanResource::PolicyDelete::operator()(const Policy *policy) const noexcept {
  const size_t bytes = policy->bytes;
  delete policy;
  owner->Release(bytes);
}
void PdrScanResource::BucketDelete::operator()(Bucket *bucket) const noexcept {
  delete bucket;
  owner->Release(sizeof(Bucket));
}

PdrScanResource::PdrScanResource(std::string name, bool downlink, size_t record_size,
                                 bess::flow::SharedExactIndex &anchors,
                                 bess::rcu::RcuDomain &domain, Hooks hooks)
    : Resource(std::move(name), std::move(hooks.may_reference)),
      downlink_(downlink),
      key_len_(downlink ? 22 : 18),
      record_size_(record_size),
      anchor_offset_(Fields(downlink)[AnchorField(downlink)].offset),
      anchors_(anchors),
      domain_(domain),
      hooks_(std::move(hooks)) {
  CHECK_LE(record_size_, PdrRule{}.result.size());
}

// Teardown: workers are stopped, so nothing can still hold a policy.
PdrScanResource::~PdrScanResource() {
  if (const Policy *p = shared_.policy.load(std::memory_order_relaxed)) PolicyDelete{this}(p);
  for (Bucket *b = head_; b != nullptr;) {
    Bucket *next = b->next;
    if (const Policy *p = b->policy.load(std::memory_order_relaxed)) PolicyDelete{this}(p);
    BucketDelete{this}(b);
    b = next;
  }
}

void PdrScanResource::Admit(size_t bytes) {
  if (growth_ != nullptr) growth_->Grow(bytes, bytes);
  held_.fetch_add(bytes, std::memory_order_relaxed);
}
void PdrScanResource::Release(size_t bytes) noexcept {
  held_.fetch_sub(bytes, std::memory_order_relaxed);
  if (growth_ != nullptr) growth_->Shrink(bytes, bytes);
}

dp::ResourceKey PdrScanResource::EncodeKey(std::span<const uint8_t> mask,
                                           std::span<const uint8_t> value,
                                           std::span<const PdrRange> ranges) {
  dp::ResourceKey key(reinterpret_cast<const char *>(mask.data()), mask.size());
  key.append(reinterpret_cast<const char *>(value.data()), value.size());
  key.append(reinterpret_cast<const char *>(ranges.data()), ranges.size_bytes());
  return key;
}

std::expected<void, std::string> PdrScanResource::Decompose(const dp::ResourceKey &key, Spec *s,
                                                            bool *anchored,
                                                            uint32_t *anchor) const {
  const size_t len = key_len_;
  if (key.size() < 2 * len || (key.size() - 2 * len) % sizeof(PdrRange) != 0)
    return std::unexpected(std::format(
        "key is {} bytes, want mask and value of {} each, then whole ranges", key.size(), len));
  const auto *mask = reinterpret_cast<const uint8_t *>(key.data());
  const uint8_t *value = mask + len;
  std::vector<PdrRange> ranges((key.size() - 2 * len) / sizeof(PdrRange));
  if (!ranges.empty())
    std::memcpy(ranges.data(), key.data() + 2 * len, ranges.size() * sizeof(PdrRange));
  for (size_t i = 0; i < len; ++i)
    if ((value[i] & ~mask[i]) != 0) return std::unexpected("invalid pair of value and mask");

  uint8_t gm[kKeyStride]{}, gv[kKeyStride]{};
  *anchored = false;
  *anchor = 0;
  s->ranges.clear();
  s->fw = FirewallRule{};
  s->fw.family = FirewallFamily::kIpv4;  // the key is IPv4-shaped (BuildPdrKey)
  s->rule.form = 0;
  const auto fields = Fields(downlink_);
  size_t next = 0;
  for (size_t f = 0; f < fields.size(); ++f) {
    const auto [off, width] = fields[f];
    const PdrRange *range = nullptr;
    if (next < ranges.size() && ranges[next].offset < off + width) {
      const PdrRange &r = ranges[next++];
      if (r.offset != off || r.width != width)
        return std::unexpected("a range must cover exactly one field, in field order");
      if (r.low > r.high || r.high > FieldMax(width))
        return std::unexpected("range is empty or wider than its field");
      if (r.low == 0 && r.high == FieldMax(width))
        return std::unexpected("a range covering its whole field is no range");
      if (Read(mask + off, width) != 0) return std::unexpected("range field has a nonzero mask");
      range = &r;
    }
    const uint64_t m = Read(mask + off, width), v = Read(value + off, width);
    auto guard_mask = [&] {
      std::memcpy(gm + off, mask + off, width);
      std::memcpy(gv + off, value + off, width);
    };
    if (f == AnchorField(downlink_) && range == nullptr && m == FieldMax(width)) {
      *anchored = true;
      std::memcpy(anchor, value + off, sizeof(*anchor));
      continue;
    }
    switch (f) {
      case 0:
      case 1: {
        if (range != nullptr) {
          s->ranges.push_back(*range);
          break;
        }
        const uint32_t inverse = ~static_cast<uint32_t>(m);
        if ((inverse & (inverse + 1)) != 0) {  // not ones then zeros
          guard_mask();
          break;
        }
        std::memcpy((f == 0 ? s->fw.src_net : s->fw.dst_net).data(), value + off, 4);
        (f == 0 ? s->fw.src_len : s->fw.dst_len) = static_cast<uint8_t>(std::popcount(m));
        break;
      }
      case 2:  // FirewallRule's proto 0 is "any": exactly 0 stays a guard
        if (range != nullptr) s->ranges.push_back(*range);
        else if (m == 0xff && v != 0) s->fw.proto = static_cast<uint8_t>(v);
        else if (m != 0) guard_mask();
        break;
      case 3:
      case 4: {
        uint16_t &low = f == 3 ? s->fw.src_port_low : s->fw.dst_port_low;
        uint16_t &high = f == 3 ? s->fw.src_port_high : s->fw.dst_port_high;
        if (range != nullptr) {
          low = static_cast<uint16_t>(range->low);
          high = static_cast<uint16_t>(range->high);
          s->rule.form |= static_cast<uint8_t>(1u << (f - 3));
        } else if (m == 0xffff) {
          low = high = static_cast<uint16_t>(v);
        } else if (m != 0) {
          guard_mask();
        }
        break;
      }
      default:
        if (range != nullptr) s->ranges.push_back(*range);
        else if (m != 0) guard_mask();
    }
  }
  if (next != ranges.size())
    return std::unexpected("a range must cover exactly one field, in field order");
  std::memcpy(s->mask.data(), gm, sizeof(gm));
  std::memcpy(s->value.data(), gv, sizeof(gv));
  return {};
}

dp::ResourceKey PdrScanResource::KeyOf(bool anchored, uint32_t anchor, const Group &g,
                                       const FirewallRule &fw, uint8_t form) const {
  uint8_t m[kKeyStride], v[kKeyStride];
  std::memcpy(m, g.mask.data(), sizeof(m));
  std::memcpy(v, g.value.data(), sizeof(v));
  std::vector<PdrRange> ranges = g.ranges;
  if (anchored) {
    std::memset(m + anchor_offset_, 0xff, 4);
    std::memcpy(v + anchor_offset_, &anchor, 4);
  }
  auto prefix = [&](size_t off, const bess::classifier::FirewallAddr &net, uint8_t len) {
    if (len == 0) return;
    const uint32_t bits = ~uint32_t{0} << (32 - len);
    for (size_t i = 0; i < 4; ++i) m[off + i] = static_cast<uint8_t>(bits >> (24 - 8 * i));
    std::memcpy(v + off, net.data(), 4);
  };
  prefix(0, fw.src_net, fw.src_len);
  prefix(4, fw.dst_net, fw.dst_len);
  if (fw.proto != 0) {
    m[8] = 0xff;
    v[8] = fw.proto;
  }
  auto port = [&](uint32_t off, uint16_t low, uint16_t high, bool range) {
    if (range) {
      ranges.push_back({off, 2, low, high});
    } else if (low == high) {
      m[off] = m[off + 1] = 0xff;
      v[off] = static_cast<uint8_t>(low >> 8);
      v[off + 1] = static_cast<uint8_t>(low);
    }
  };
  port(9, fw.src_port_low, fw.src_port_high, form & 1);
  port(11, fw.dst_port_low, fw.dst_port_high, form & 2);
  std::ranges::sort(ranges, {}, &PdrRange::offset);
  return EncodeKey({m, key_len_}, {v, key_len_}, ranges);
}

PdrScanResource::Bucket *PdrScanResource::FindBucket(bool anchored,
                                                     uint32_t anchor) const noexcept {
  if (!anchored) return const_cast<Bucket *>(&shared_);
  uint64_t value = 0;
  if (!anchors_.Lookup(reinterpret_cast<const std::byte *>(&anchor), &value)) return nullptr;
  return reinterpret_cast<Bucket *>(static_cast<uintptr_t>(value));
}

bool PdrScanResource::Locate(bool anchored, uint32_t anchor, const Spec &spec,
                             const Policy **policy, size_t *index) const {
  const Bucket *b = FindBucket(anchored, anchor);
  const Policy *p = b != nullptr ? b->policy.load(std::memory_order_relaxed) : nullptr;
  if (p == nullptr) return false;
  // ponytail: linear in the bucket's rules; the shared bucket is the ceiling.
  for (const Group &g : p->groups) {
    if (g.mask != spec.mask || g.value != spec.value || g.ranges != spec.ranges) continue;
    const auto &rules = g.scan.rules();
    for (size_t k = 0; k < rules.size(); ++k) {
      const FirewallRule &r = rules[k], &w = spec.fw;
      if (r.src_len == w.src_len && r.dst_len == w.dst_len && r.src_net == w.src_net &&
          r.dst_net == w.dst_net && r.proto == w.proto && r.src_port_low == w.src_port_low &&
          r.src_port_high == w.src_port_high && r.dst_port_low == w.dst_port_low &&
          r.dst_port_high == w.dst_port_high && p->rules[g.first + k].form == spec.rule.form) {
        *policy = p;
        *index = g.first + k;
        return true;
      }
    }
  }
  return false;
}

bool PdrScanResource::Find(const dp::ResourceKey &key, const Policy **policy,
                           size_t *index) const {
  Spec spec;
  bool anchored = false;
  uint32_t anchor = 0;
  return Decompose(key, &spec, &anchored, &anchor) &&
         Locate(anchored, anchor, spec, policy, index);
}

const PdrRule *PdrScanResource::Match(const Policy &p, const uint8_t *key,
                                      const FirewallKey &fkey, const PdrRule *best) noexcept {
  uint64_t k[3];
  std::memcpy(k, key, sizeof(k));
  for (const Group &g : p.groups) {
    if (best != nullptr && !Better(p.rules[g.first], *best)) break;  // nothing here can win
    if ((((k[0] & g.mask[0]) ^ g.value[0]) | ((k[1] & g.mask[1]) ^ g.value[1]) |
         ((k[2] & g.mask[2]) ^ g.value[2])) != 0)
      continue;
    bool in = true;
    for (const PdrRange &r : g.ranges) {
      const uint64_t x = Read(key + r.offset, r.width);
      if (x < r.low || x > r.high) {
        in = false;
        break;
      }
    }
    FirewallTable::Match m;
    if (!in || !g.scan.Lookup(fkey, &m)) continue;
    const PdrRule &rule = p.rules[g.first + m.rule_id - 1];
    if (best == nullptr || Better(rule, *best)) best = &rule;
  }
  return best;
}

void PdrScanResource::Classify(const Key *keys, size_t n, const PdrRule **winners) const noexcept {
  uint64_t buckets[64];
  const uint64_t hits =
      n != 0 ? anchors_.LookupBatch(keys[0].data() + anchor_offset_, kKeyStride, buckets, n) : 0;
  const Policy *shared = shared_.policy.load(std::memory_order_acquire);
  for (size_t i = 0; i < n; ++i) {
    const auto *k = reinterpret_cast<const uint8_t *>(keys[i].data());
    FirewallKey fkey;
    fkey.family = FirewallFamily::kIpv4;
    fkey.proto = k[8];
    std::memcpy(fkey.src.data(), k, 4);
    std::memcpy(fkey.dst.data(), k + 4, 4);
    fkey.src_port = static_cast<uint16_t>(k[9] << 8 | k[10]);
    fkey.dst_port = static_cast<uint16_t>(k[11] << 8 | k[12]);
    const PdrRule *best = nullptr;
    if ((hits >> i & 1) != 0) {
      const auto *bucket = reinterpret_cast<const Bucket *>(static_cast<uintptr_t>(buckets[i]));
      if (const Policy *own = bucket->policy.load(std::memory_order_acquire))
        best = Match(*own, k, fkey, nullptr);
    }
    if (shared != nullptr) best = Match(*shared, k, fkey, best);
    winners[i] = best;
  }
}

void PdrScanResource::ForEach(
    const std::function<void(const dp::ResourceKey &, const PdrRule &)> &visit) const {
  auto each = [&](const Bucket &b, bool anchored) {
    const Policy *p = b.policy.load(std::memory_order_relaxed);
    if (p == nullptr) return;
    for (const Group &g : p->groups)
      for (size_t k = 0; k < g.scan.rule_count(); ++k)
        visit(KeyOf(anchored, b.anchor, g, g.scan.rules()[k], p->rules[g.first + k].form),
              p->rules[g.first + k]);
  };
  each(shared_, false);
  for (const Bucket *b = head_; b != nullptr; b = b->next) each(*b, true);
}

bool PdrScanResource::Contains(const dp::ResourceKey &key) const {
  const Policy *p = nullptr;
  size_t index = 0;
  return Find(key, &p, &index);
}

std::vector<dp::Reference> PdrScanResource::ReferencesOf(const dp::ResourceKey &key) const {
  const Policy *p = nullptr;
  size_t index = 0;
  if (!hooks_.references || !Find(key, &p, &index)) return {};
  return hooks_.references(std::span(p->rules[index].result).first(record_size_));
}

void PdrScanResource::VisitReferences(
    const std::function<void(const dp::Reference &)> &visit) const {
  if (!hooks_.references) return;
  ForEach([&](const dp::ResourceKey &, const PdrRule &rule) {
    for (const auto &ref : hooks_.references(std::span(rule.result).first(record_size_)))
      visit(ref);
  });
}

std::expected<dp::Resource::Reservation, std::string> PdrScanResource::Reserve(
    const dp::Op &op) {
  Change c;
  if (auto ok = Decompose(op.key, &c.spec, &c.anchored, &c.anchor); !ok)
    return std::unexpected(ok.error());
  const Policy *policy = nullptr;
  size_t index = 0;
  const bool existed = Locate(c.anchored, c.anchor, c.spec, &policy, &index);
  Reservation r{std::make_unique<PublishOp>(*this), {}, {}, existed, {}};
  if (existed) {
    c.previous = index;
    if (hooks_.references)
      r.previous_references =
          hooks_.references(std::span(policy->rules[index].result).first(record_size_));
  }
  if (op.kind == dp::OpKind::kErase) {
    if (!existed) return std::unexpected("not found");
    c.erase = true;
  } else {
    const auto *v = std::any_cast<PdrValue>(&op.value);
    if (v == nullptr) return std::unexpected("wrong value type (want PdrValue)");
    if (hooks_.check_value)
      if (auto ok = hooks_.check_value(*v); !ok) return std::unexpected(ok.error());
    if (v->result.size() > record_size_)
      return std::unexpected(std::format("result is {} bytes, the record is {}",
                                         v->result.size(), record_size_));
    c.spec.rule.priority = v->priority;
    c.spec.rule.gate = v->gate;
    c.spec.rule.result = {};
    if (!v->result.empty()) std::memcpy(c.spec.rule.result.data(), v->result.data(), v->result.size());
    // The masked table numbers commands as they are prepared: same order.
    c.spec.rule.sequence = next_sequence_++;
    if (hooks_.references)
      r.references = hooks_.references(std::span(c.spec.rule.result).first(record_size_));
  }
  // The engine checks the SUM of Reserve footprints before Prepare. One
  // policy is rebuilt per bucket, not per rule: initial loads retire none,
  // replacements retire its committed policy once. Count a bucket itself
  // only once, when the ops reserved so far empty an existing anchor. A
  // later insertion may make that charge unnecessary, but never too small.
  const Bucket *bucket = FindBucket(c.anchored, c.anchor);
  const Policy *old = bucket ? bucket->policy.load(std::memory_order_relaxed) : nullptr;
  auto [it, first] = reserved_.try_emplace(
      std::pair(c.anchored, c.anchor), ReservedBucket{old ? old->rules.size() : 0, false});
  ReservedBucket &reserved = it->second;
  if (first && old != nullptr) ++r.footprint.retires;
  if (c.erase) {
    CHECK_GT(reserved.remaining, 0u);
    --reserved.remaining;
  } else if (!existed) {
    ++reserved.remaining;
  }
  if (c.anchored && bucket != nullptr && reserved.remaining == 0 &&
      !reserved.retirement_counted) {
    ++r.footprint.retires;
    reserved.retirement_counted = true;
  }
  changes_.push_back(std::move(c));
  return r;
}

std::expected<PdrScanResource::PolicyPtr, std::string> PdrScanResource::Build(
    std::vector<Spec> specs) {
  auto same_guard = [](const Spec &a, const Spec &b) {
    return a.mask == b.mask && a.value == b.value && a.ranges == b.ranges;
  };
  std::ranges::sort(specs, [&](const Spec &a, const Spec &b) {
    if (same_guard(a, b)) return Better(a.rule, b.rule);
    if (a.mask != b.mask) return a.mask < b.mask;
    if (a.value != b.value) return a.value < b.value;
    return std::ranges::lexicographical_compare(a.ranges, b.ranges, RangeLess);
  });
  std::vector<std::pair<size_t, size_t>> spans;
  for (size_t i = 0; i < specs.size();) {
    size_t j = i + 1;
    while (j < specs.size() && same_guard(specs[i], specs[j])) ++j;
    spans.emplace_back(i, j);
    i = j;
  }
  std::ranges::sort(spans, [&](const auto &a, const auto &b) {
    return Better(specs[a.first].rule, specs[b.first].rule);
  });
  size_t bytes = sizeof(Policy) + spans.size() * sizeof(Group) +
                 specs.size() * (sizeof(PdrRule) + sizeof(FirewallRule));
  for (const auto &[b, e] : spans) bytes += specs[b].ranges.size() * sizeof(PdrRange);
  Admit(bytes);  // throws MemoryRefused: nothing allocated
  try {
    auto p = std::make_unique<Policy>();
    p->bytes = bytes;
    p->groups.reserve(spans.size());
    p->rules.reserve(specs.size());
    for (const auto &[b, e] : spans) {
      std::vector<FirewallRule> fw;
      fw.reserve(e - b);
      const auto first = static_cast<uint32_t>(p->rules.size());
      for (size_t k = b; k < e; ++k) {
        fw.push_back(specs[k].fw);
        p->rules.push_back(specs[k].rule);
      }
      auto scan = FirewallScan::Create(std::move(fw));
      if (!scan) {
        Release(bytes);
        return std::unexpected("PDR scan refused a rule: " + scan.error());
      }
      p->groups.push_back(Group{specs[b].mask, specs[b].value,
                                std::vector<PdrRange>(specs[b].ranges.begin(),
                                                      specs[b].ranges.end()),
                                std::move(*scan), first});
    }
    return PolicyPtr(p.release(), PolicyDelete{this});
  } catch (...) {
    Release(bytes);
    throw;
  }
}

std::expected<void, std::string> PdrScanResource::Prepare() {
  auto anchor_of = [](const Change &c) { return std::pair(c.anchored, c.anchor); };
  std::ranges::stable_sort(changes_, {}, anchor_of);
  staged_.reserve(changes_.size());
  for (size_t i = 0; i < changes_.size();) {
    size_t j = i + 1;
    while (j < changes_.size() && anchor_of(changes_[j]) == anchor_of(changes_[i])) ++j;
    const auto changes = std::span(changes_).subspan(i, j - i);
    i = j;
    Staged st;
    st.bucket = FindBucket(changes[0].anchored, changes[0].anchor);
    const Policy *old = st.bucket ? st.bucket->policy.load(std::memory_order_relaxed) : nullptr;
    std::vector<Spec> specs;
    if (old != nullptr) {
      st.old_rules = old->rules.size();
      for (const Group &g : old->groups)
        for (size_t k = 0; k < g.scan.rule_count(); ++k) {
          const size_t at = g.first + k;
          if (std::ranges::any_of(changes, [at](const Change &c) { return c.previous == at; }))
            continue;
          specs.push_back(Spec{g.mask, g.value, g.ranges, g.scan.rules()[k], old->rules[at]});
        }
    }
    for (Change &c : changes)
      if (!c.erase) specs.push_back(std::move(c.spec));
    st.new_rules = specs.size();
    if (!specs.empty()) {
      auto built = Build(std::move(specs));
      if (!built) return std::unexpected(built.error());
      st.policy = std::move(*built);
    }
    if (st.bucket == nullptr) {  // a new anchor: indexed now, empty until publish
      Admit(sizeof(Bucket));
      BucketPtr bucket(nullptr, BucketDelete{this});
      try {
        bucket.reset(new Bucket);
      } catch (...) {
        Release(sizeof(Bucket));
        throw;
      }
      bucket->anchor = changes[0].anchor;
      domain_.ReserveRetirements(1);  // an abort retires it without allocating
      const auto status = anchors_.InsertIfAbsent(
          reinterpret_cast<const std::byte *>(&bucket->anchor),
          static_cast<uint64_t>(reinterpret_cast<uintptr_t>(bucket.get())));
      if (status != bess::flow::SharedExactIndex::InsertStatus::kInserted)
        return std::unexpected(status == bess::flow::SharedExactIndex::InsertStatus::kFull
                                   ? "the PDR anchor index is full"
                                   : "the PDR anchor index already holds this anchor");
      st.bucket = bucket.get();
      st.created = std::move(bucket);
    }
    staged_.push_back(std::move(st));
  }
  return {};
}

void PdrScanResource::PublishStaged(dp::Retirer &retirer) noexcept {
  if (published_) return;
  published_ = true;
  for (Staged &st : staged_) {
    Bucket *b = st.bucket;
    const Policy *old = b->policy.load(std::memory_order_relaxed);
    b->policy.store(st.policy.release(), std::memory_order_release);
    retirer.Retire(PolicyPtr(old, PolicyDelete{this}));
    live_ = live_ - st.old_rules + st.new_rules;
    if (st.created) {
      Bucket *added = st.created.release();
      added->next = head_;
      if (head_ != nullptr) head_->prev = added;
      head_ = added;
    } else if (b != &shared_ && st.new_rules == 0) {
      CHECK(anchors_.Erase(reinterpret_cast<const std::byte *>(&b->anchor)));
      (b->prev != nullptr ? b->prev->next : head_) = b->next;
      if (b->next != nullptr) b->next->prev = b->prev;
      retirer.Retire(BucketPtr(b, BucketDelete{this}));
    }
  }
}

void PdrScanResource::EndTransaction() noexcept {
  if (!published_) {
    for (Staged &st : staged_) {
      if (!st.created) continue;
      // A reader may have found the bucket (reading no policy): a grace
      // period before it goes. Its bytes are given back now.
      anchors_.Erase(reinterpret_cast<const std::byte *>(&st.created->anchor));
      std::unique_ptr<Bucket> bucket(st.created.release());
      Release(sizeof(Bucket));
      domain_.Retire(domain_.StartGracePeriod(), std::move(bucket));
    }
  }
  staged_.clear();  // unpublished policies are freed (and given back) here
  changes_.clear();
  reserved_.clear();
  published_ = false;
}

}  // namespace upf::appliance
