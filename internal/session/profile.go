// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"fmt"
	"strings"
)

// Profile is the dataplane strategy a deployment runs, as a *start-time*
// choice: where each direction's PDR rules live, which graph carries that
// composition, and the module list the daemon must have loaded for it
// (docs/design.md, "Profiles: one compiler, two dataplane strategies").
//
// A profile is resolved once, before the controller serves PFCP and before the
// daemon's graph is applied, into the strategies its Config's directions carry
// -- so the compiler writes a rule where the profile says, and the packet path
// holds no profile check and the session path holds no profile branch. The
// profile *is* the graph and the strategy; it is never a layer consulted per
// packet or per PDR.
type Profile struct {
	// Name is what -profile selects, and what a measured row is labelled with.
	Name string

	// Graph is the manifest carrying this profile's composition -- the matcher
	// module in each direction's chain and how its output is wired -- as a path
	// from the repository root. It is the graph the deployment applies for this
	// profile, not a fragment: the two directions' chains, the tables the
	// compiler writes to and the graph's own next hops from one file.
	Graph string

	// Modules is the module list the daemon must have loaded for that graph:
	// the classes this profile's dataplane needs that a stock bessd does not
	// carry, which are this tree's plugin's (datapath/, built against the
	// installed bess-dev stage and loaded with --modules=<its directory>). It is
	// a start-time fact like the graph -- a class the daemon does not have is a
	// graph this profile cannot run -- and it is where the plugin's
	// build-and-load cost lives (docs/design.md).
	Modules []string

	// Up and Down are the per-direction strategies: where that direction's PDR
	// rules live. Both are set, because a profile covers the whole chain.
	Up, Down Strategy
}

// Strategy is where one direction's PDR rules live: exactly one of the three
// structures a deployment can hold them in.
//
//   - Table is BESS's WildcardMatch: one masked key per rule in one table every
//     session shares. It refuses a port range and an IPv6 prefix (a mask cannot
//     carry either), which is the shipped default's envelope.
//   - Firewall is BESS's `firewall`: one ordered policy for the whole
//     deployment, whose rules carry CIDR prefixes of both families and port
//     ranges, and which a session change rewrites whole.
//   - PdrMatch is this tree's keyed per-session matcher: one map key per
//     session -- keyed by its F-TEID -- whose value is that session's rules in
//     SMF precedence order, so a session change writes O(its rules).
//
// A Strategy is a selection, not a second compiler: parsing, validation and the
// PFCP semantics are the compiler's one copy whatever the rules land in. The
// unset fields are empty.
type Strategy struct {
	Table    string
	Firewall string
	PdrMatch string
	// Selector is the module that names a session for a packet that carries no
	// tunnel (the downlink's): the keyed map holds one key per session, and
	// something has to turn a packet into that key. SelectorActions is the
	// ActionTable its rules reference, and SelectorFields the key it matches,
	// as the graph declares it.
	Selector        string
	SelectorActions string
	SelectorFields  []Field
}

// String is the strategy as an operator reads it: the structure and the module
// the rules land in, and the selector that names a session where the structure
// needs one.
func (s Strategy) String() string {
	switch {
	case s.Firewall != "":
		return "firewall " + s.Firewall
	case s.PdrMatch != "":
		if s.Selector != "" {
			return "keyed map " + s.PdrMatch + " selected by " + s.Selector
		}
		return "keyed map " + s.PdrMatch
	default:
		return "wildcard table " + s.Table
	}
}

// Strategy is the strategy this direction carries, as the compiler reads it:
// the one of the direction's three rule homes that is set. A Config is built
// from a profile's strategies and the deployment's own module names, so this is
// what the run actually writes rules into -- which is what the startup log
// reports, rather than the profile it was selected from.
func (d Direction) Strategy() Strategy {
	return Strategy{
		Table: d.PDRTable, Firewall: d.Firewall, PdrMatch: d.PdrMatch,
		Selector: d.Selector, SelectorActions: d.SelectorActions, SelectorFields: d.SelectorFields,
	}
}

// The profiles -profile selects. Generic is the shipped default and produces
// today's graph, today's rules and today's packet path; custom is the keyed
// per-session matcher in both directions, with the downlink's session named by
// the selector in front of it (selector.go: the module is no longer uplink-only).
const (
	GenericProfile = "generic"
	CustomProfile  = "custom"
)

// ProfileNames is every profile, in the order the -profile help names them.
func ProfileNames() []string {
	return []string{GenericProfile, CustomProfile}
}

// ProfileFor resolves a -profile name. The names are exact and the refusal
// lists them: a mistyped profile that silently selected the default would be a
// deployment whose rules land in a structure nobody chose.
func ProfileFor(name string) (Profile, error) {
	switch name {
	case GenericProfile:
		// Stock BESS holds every rule: the wildcard table by default, and the
		// firewall module when a deployment names one (-firewall-ul/-dl), which
		// is this profile's other structure rather than a third profile. Both
		// structures are the daemon's own, so only this tree's modules -- the
		// GTP-U codec, the echo and the per-rule counters -- are loaded from the
		// plugin.
		return Profile{
			Name:    GenericProfile,
			Graph:   "deploy/upf.yaml",
			Modules: []string{"GtpuDecap", "GtpuEncap", "GtpuResponder", "UrrCount"},
			Up:      Strategy{Table: "pdr_ul"},
			Down:    Strategy{Table: "pdr_dl"},
		}, nil
	case CustomProfile:
		// The uplink's rules are one keyed map per session, so the uplink's
		// wildcard table (`pdr_ul`) is not in the graph and not in the Config:
		// the F-TEID the decap wrote is the session, and a session change is one
		// upsert of that session's rules (docs/design.md, "the keyed write").
		// The downlink is keyed the same way, and its session is named by the
		// selector in front of the matcher: the UE address the packet is
		// addressed to (this graph is a one-instance deployment, so the route
		// domain is not a field of the key).
		return Profile{
			Name:    CustomProfile,
			Graph:   "deploy/custom-pdrmatch.yaml",
			Modules: []string{"GtpuDecap", "GtpuEncap", "GtpuResponder", "UrrCount", "PdrMatch"},
			Up:      Strategy{PdrMatch: "pdr_match_ul"},
			Down: Strategy{
				PdrMatch:        "pdr_match_dl",
				Selector:        "sel_dl",
				SelectorActions: "sel_at",
				SelectorFields:  []Field{DstIP},
			},
		}, nil
	}
	return Profile{}, fmt.Errorf("unknown profile %q: one of %s",
		name, strings.Join(ProfileNames(), ", "))
}
