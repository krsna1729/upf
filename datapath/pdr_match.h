// SPDX-License-Identifier: BSD-3-Clause

#ifndef UPF_DATAPATH_PDR_MATCH_H_
#define UPF_DATAPATH_PDR_MATCH_H_

#include <memory>
#include <string>

#include "classifier/firewall_table.h"
#include "framework/resource_bindings.h"
#include "framework/singleton_resource.h"
#include "module.h"
#include "pdr_match_resource.h"
#include "upf_datapath.pb.h"

// Matches a packet against its *session's* rules: the PDR table as a map
// resource keyed by session, one key per session whose value is that session's
// rule list (docs/design.md, "the keyed write").
//
// The transaction engine applies map operations per key (D-129), so a session
// change is one upsert of O(that session's rules). The table every session
// shares -- the WildcardMatch path, still the default and unchanged -- is
// O(all rules) per change, because one rule of one session is one key of one
// table: at the session counts a UPF is asked for, that is the difference
// between one rule and a million. This module is the same matching, keyed so
// the write is per session.
//
// The session is the id the packet carries, read from the module's own key
// attribute: on the uplink the F-TEID the decap wrote ("upf_teid"), which is
// what identifies a session on N3. The downlink needs a *selector* rather than
// a key -- an N6 packet carries no tunnel, so the session is the one whose UE
// address/prefix is the longest match on the packet's destination -- and that
// is the next step, not this.
//
// A packet whose key names a session the map does not hold, whose 5-tuple the
// session's rules do not match, or whose matched rule drops, is dropped: a
// packet that cannot be matched must not leave unmatched. A match carries the
// rule's ActionId on ("action_id", BESS D-141), so the rest of the chain --
// meter, counter, action table, router, tunnel -- reads exactly what the
// WildcardMatch path hands it and no module downstream changes.
//
// The match itself is not this module's: the session's rule list goes to the
// seam in pdr_match_matcher.h -- BESS's small-policy scan -- and the module
// sees only its result.
class PdrMatch final : public Module {
 public:
  static const gate_idx_t kNumOGates = 1;

  // "<module>/rules": PdrMatchKey (the session) -> PdrMatchEntry (its rules),
  // and the module's own settings beside it.
  static const ResourceTables resource_tables;

  PdrMatch() : Module() { max_allowed_workers_ = Worker::kMaxWorkers; }

  CommandResponse Init(const upf::pb::PdrMatchArg &arg);
  void DeInit() override;

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  std::string GetDesc() const override;

  // The session's rules, by the id the packet carried (one acquire load, or
  // nullptr). Tests and introspection use it directly; the packet path makes
  // exactly this lookup.
  const upf::pdr_match::Rules *LookupSession(uint32_t session) const noexcept {
    return resource_ == nullptr ? nullptr : resource_->Lookup(session);
  }

 private:
  // The packet's 5-tuple. False for a packet this module cannot judge: not an
  // Ethernet frame, not IPv4 or IPv6, or a header it cannot read (a truncated
  // one). A packet whose ports are not in the frame -- a non-first fragment --
  // is judged with both ports 0, which only a rule whose port range starts at
  // 0 can match.
  static bool KeyOf(bess::PacketRef pkt, bess::classifier::FirewallKey *key);

  // The attribute `name` holds, as this module's own id, or -1 when it has
  // none: the attributes this module declares, in id order (module.h).
  int AttrIdOf(const std::string &name) const;

  // The module's own settings, as they are staged: the attribute id the packet
  // path reads and the name the module was pointed at (what "<module>/settings"
  // reads back).
  struct Settings {
    int attr = -1;
    std::string name;
  };

  int key_attr_ = -1;       // the session key, read
  int action_attr_ = -1;    // the "action_id" the match carries, written
  int qfi_attr_ = -1;       // the decap's "qfi", read only when a rule names one
  int steering_attr_ = -1;  // the MAR ID a match carries, written when configured
  int meter_attr_ = -1;     // the two meter ids, written when configured
  int next_hop_attr_ = -1;  // the Router next hop, written when configured
  std::string key_attr_name_;
  std::unique_ptr<upf::pdr_match::SessionResource> resource_;
  bess::framework::ResourceBinding binding_;  // after resource_ (D-044)
  // "<module>/settings" (D-129): the module's own settings. The map is the
  // sessions; this is the module.
  bess::framework::Singleton<upf::pb::PdrMatchSettings, Settings> settings_;
};

#endif  // UPF_DATAPATH_PDR_MATCH_H_
