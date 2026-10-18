// SPDX-License-Identifier: BSD-3-Clause

// The seam, built over BESS's `FirewallScan`: the small-policy matcher beside
// `FirewallTable` in core/classifier/firewall_table.h. One session's rules are
// a handful -- a PDR each, two to four in the common case -- and a policy that
// small is cheaper to scan than to index, which is what this file exists for.
//
// It is the seam's only implementation (datapath/meson.build compiles it into
// the plugin): the indexed `FirewallTable` is the same predicate over an index
// a session's handful of rules does not amortize.

#include "pdr_match_matcher.h"

#include <utility>

namespace upf {
namespace pdr_match {

namespace {

using bess::classifier::FirewallKey;
using bess::classifier::FirewallScan;
using bess::classifier::FirewallTable;
using bess::classifier::FirewallFamily;

class ScanMatcher final : public SessionMatcher {
 public:
  explicit ScanMatcher(FirewallScan scan) : scan_(std::move(scan)) {}

  bool Lookup(const FirewallKey &key, FirewallTable::Match *match)
      const noexcept override {
    return scan_.Lookup(key, match);
  }

  bool HasFamily(FirewallFamily family) const noexcept override {
    return scan_.HasFamily(family);
  }

  size_t rule_count() const noexcept override { return scan_.rule_count(); }

 private:
  FirewallScan scan_;
};

}  // namespace

std::expected<std::unique_ptr<const SessionMatcher>, std::string>
MakeSessionMatcher(std::vector<bess::classifier::FirewallRule> rules) {
  auto scan = FirewallScan::Create(std::move(rules));
  if (!scan) {
    return std::unexpected(scan.error());
  }
  return std::make_unique<const ScanMatcher>(std::move(*scan));
}

const char *MatcherName() noexcept { return "firewall_scan"; }

}  // namespace pdr_match
}  // namespace upf
