// SPDX-License-Identifier: BSD-3-Clause

// The profile mechanism: -profile is a start-time choice of where each
// direction's rules live (docs/design.md, "Profiles"). These tests pin the two
// things a deployment depends on -- that a profile names the strategies its
// directions carry, and that a name which is not a profile is refused rather
// than silently selecting the default.

package session

import (
	"os"
	"strings"
	"testing"
)

func TestAProfileNamesItsStrategies(t *testing.T) {
	generic, err := ProfileFor(GenericProfile)
	if err != nil {
		t.Fatalf("ProfileFor(%q): %v", GenericProfile, err)
	}
	if generic.Up.PdrMatch != "" || generic.Down.PdrMatch != "" {
		t.Errorf("the generic profile keys its rules by session: %v / %v",
			generic.Up, generic.Down)
	}
	if generic.Up.Table == "" || generic.Down.Table == "" {
		t.Errorf("the generic profile writes no wildcard table: %v / %v",
			generic.Up, generic.Down)
	}
	if generic.Graph == "" || len(generic.Modules) == 0 {
		t.Errorf("the generic profile names no graph or no modules: %q %v",
			generic.Graph, generic.Modules)
	}

	custom, err := ProfileFor(CustomProfile)
	if err != nil {
		t.Fatalf("ProfileFor(%q): %v", CustomProfile, err)
	}
	if custom.Up.PdrMatch == "" {
		t.Errorf("the custom profile's uplink is not the keyed map: %v", custom.Up)
	}
	if custom.Up.Table != "" {
		t.Errorf("the custom profile still writes the uplink's shared table: %v", custom.Up)
	}
	if custom.Down.PdrMatch == "" || custom.Down.Table != "" {
		t.Errorf("the custom profile's downlink is not the keyed map: %v", custom.Down)
	}
	if custom.Down.Selector == "" || custom.Down.SelectorActions == "" {
		t.Errorf("the custom profile's downlink names no selector, and a keyed map needs one: %v", custom.Down)
	}
	if len(custom.Down.SelectorFields) == 0 {
		t.Errorf("the custom profile's selector declares no key: %v", custom.Down)
	}
	if custom.Graph == generic.Graph {
		t.Errorf("both profiles name one graph: %q", custom.Graph)
	}
}

// A profile's graph is a path this repository ships. `-profile custom` naming a
// graph a fresh checkout does not have would be a deployment whose composition
// nobody can apply -- and nothing else would notice, because upfd names the
// graph rather than applying it.
func TestAProfilesGraphIsInTheTree(t *testing.T) {
	for _, name := range ProfileNames() {
		p, err := ProfileFor(name)
		if err != nil {
			t.Fatalf("ProfileFor(%q): %v", name, err)
		}
		if _, err := os.Stat("../../" + p.Graph); err != nil {
			t.Errorf("profile %q names %s, which the tree does not have: %v",
				name, p.Graph, err)
		}
	}
}

// A name that is not a profile is refused, and the refusal lists the names: a
// mistyped profile that silently selected the default would put a deployment's
// rules in a structure nobody chose.
func TestAProfileIsSelectedByNameOnly(t *testing.T) {
	_, err := ProfileFor("generic-wildcard")
	if err == nil {
		t.Fatal("a name that is not a profile was accepted")
	}
	for _, name := range ProfileNames() {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("the refusal does not name %q: %v", name, err)
		}
	}
}

// A direction whose PDRTable is the flag default reads as the wildcard table,
// and an unset Strategy renders as one -- so an implementation that dropped the
// field, or the default branch of String, leaves this red rather than green.
func TestAnUnsetDirectionIsTheWildcardTable(t *testing.T) {
	d := Direction{PDRTable: "pdr_ul"}
	s := d.Strategy()
	if s.Table != "pdr_ul" || s.PdrMatch != "" || s.Firewall != "" {
		t.Errorf("a direction with the default table does not read as the wildcard table: %v", s)
	}
	if got := s.String(); !strings.Contains(got, "wildcard table") || !strings.Contains(got, "pdr_ul") {
		t.Errorf("the default direction renders as %q", got)
	}
	if got := (Strategy{}).String(); !strings.Contains(got, "wildcard table") {
		t.Errorf("an unset strategy renders as %q, not the wildcard table", got)
	}
	if got := (Strategy{Firewall: "fw"}).String(); !strings.Contains(got, "firewall") {
		t.Errorf("a firewall strategy reads as %q", got)
	}
	if got := (Strategy{PdrMatch: "pm"}).String(); !strings.Contains(got, "keyed map") {
		t.Errorf("a keyed strategy reads as %q", got)
	}
}
