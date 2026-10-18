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
	if custom.Down.PdrMatch != "" || custom.Down.Table == "" {
		t.Errorf("the custom profile's downlink is not the shared table: %v", custom.Down)
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

// A direction built without a profile still reads as the wildcard table, so an
// unconfigured run writes its rules where it always did.
func TestAnUnsetDirectionIsTheWildcardTable(t *testing.T) {
	var d Direction
	if s := d.Strategy(); s.PdrMatch != "" || s.Firewall != "" {
		t.Errorf("an unset direction is not the wildcard table: %v", s)
	}
	if s := (Strategy{Firewall: "fw"}).String(); !strings.Contains(s, "firewall") {
		t.Errorf("a firewall strategy reads as %q", s)
	}
	if s := (Strategy{PdrMatch: "pm"}).String(); !strings.Contains(s, "keyed map") {
		t.Errorf("a keyed strategy reads as %q", s)
	}
}
