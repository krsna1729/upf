// SPDX-License-Identifier: BSD-3-Clause

#ifndef UPF_DATAPATH_PDR_MATCH_MATCHER_H_
#define UPF_DATAPATH_PDR_MATCH_MATCHER_H_

#include <cstddef>
#include <expected>
#include <memory>
#include <string>
#include <vector>

#include "classifier/firewall_table.h"

namespace upf {
namespace pdr_match {

// The seam between PdrMatch and the structure that matches one session's rules
// (docs/design.md, "the keyed write"): one session's rule list, compiled once
// when the resource publishes it and matched once per packet.
//
// The structure is BESS's `FirewallScan` -- the scan over a policy, beside the
// indexed `FirewallTable` in core/classifier/firewall_table.h, built and
// validated by the same predicate and the same normalization, so the two cannot
// disagree about a rule. The scan is what a session wants: two to four rules in
// the common case, which is cheaper to walk than to index, and the index's
// groups are per (family, protocol, prefix lengths) -- structure a session's
// handful of rules never amortizes. pdr_match_scan.cc is the whole
// implementation; the module and the compiler see only this interface.
//
// The result type is BESS's `FirewallTable::Match` -- the action and the
// 1-based id of the rule that matched -- in the rule list's own order, the
// first rule that matches winning.
class SessionMatcher {
 public:
  virtual ~SessionMatcher() = default;

  // The first rule of the list that matches `key`, in policy order; false when
  // none does. `match` is written only on a hit.
  virtual bool Lookup(const bess::classifier::FirewallKey &key,
                      bess::classifier::FirewallTable::Match *match)
      const noexcept = 0;

  // False when no rule of the list can judge a packet of `family`, so the
  // caller can drop such a packet without a lookup.
  virtual bool HasFamily(bess::classifier::FirewallFamily family)
      const noexcept = 0;

  virtual size_t rule_count() const noexcept = 0;
};

// Compiles `rules`, a session's rules in policy order (the first that matches
// wins). A rule the structure cannot express refuses the whole list: nothing
// about the rules is relaxed here, so a session is either programmed exactly or
// not at all.
std::expected<std::unique_ptr<const SessionMatcher>, std::string>
MakeSessionMatcher(std::vector<bess::classifier::FirewallRule> rules);

// Which structure matches a session's rules: "firewall_scan", the name the
// module's startup log gives it, so a graph's log and a graph's behaviour name
// the same thing.
const char *MatcherName() noexcept;

}  // namespace pdr_match
}  // namespace upf

#endif  // UPF_DATAPATH_PDR_MATCH_MATCHER_H_
