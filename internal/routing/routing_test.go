// SPDX-License-Identifier: BSD-3-Clause
package routing

import (
	"net/netip"
	"strings"
	"testing"
)

func pool(prefixes ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(prefixes))
	for _, p := range prefixes {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}

// TestTwoInstancesMayServeTheSamePool is the design's reason for the package:
// two subscribers behind the same private prefix, on two network instances.
func TestTwoInstancesMayServeTheSamePool(t *testing.T) {
	d, err := New([]Interface{
		{Instance: "internet", Domain: 0, NextHop: 1, Pool: pool("10.45.0.0/16")},
		{Instance: "ims", Domain: 1, NextHop: 3, Pool: pool("10.45.0.0/16", "10.46.0.0/16")},
	}, 4)
	if err != nil {
		t.Fatalf("two instances with one pool are the design's own case and were refused: %v", err)
	}
	internet, ok := d.Lookup("internet")
	if !ok || internet.Domain != 0 || internet.NextHop != 1 {
		t.Errorf("internet resolved to %+v (found %v), want domain 0 and next hop 1", internet, ok)
	}
	ims, ok := d.Lookup("ims")
	if !ok || ims.Domain != 1 || ims.NextHop != 3 {
		t.Errorf("ims resolved to %+v (found %v), want domain 1 and next hop 3", ims, ok)
	}
	if !internet.Serves(netip.MustParseAddr("10.45.0.2")) || !ims.Serves(netip.MustParseAddr("10.45.0.2")) {
		t.Error("10.45.0.2 is in both instances' pool, and one of them says it does not serve it")
	}
	if internet.Serves(netip.MustParseAddr("10.46.0.2")) {
		t.Error("internet serves 10.46.0.2, which only ims declares")
	}
	if internet.Serves(netip.MustParseAddr("192.0.2.1")) {
		t.Error("an address outside every pool is served")
	}
	if got := d.Default().Instance; got != "internet" {
		t.Errorf("the default interface is %q, want the first configured (internet)", got)
	}
	if got := strings.Join(d.Names(), ","); got != "internet,ims" {
		t.Errorf("the instance names are %q, want the deployment's order", got)
	}
	if d.MaxDomains() != 4 {
		t.Errorf("MaxDomains is %d, want the 4 the router was given", d.MaxDomains())
	}
	if _, ok := d.Lookup("n9"); ok {
		t.Error("an instance the deployment does not configure resolved")
	}
}

// TestAnInterfaceServesAPrefixOnce: overlapping pools on *one* interface are
// what the domains exist to avoid, and a rule on that interface would be
// ambiguous about which session an address belongs to.
func TestAnInterfaceServesAPrefixOnce(t *testing.T) {
	for _, c := range []struct {
		name string
		pool []string
	}{
		{"the same prefix twice", []string{"10.45.0.0/16", "10.45.0.0/16"}},
		{"a wider prefix over a narrower one", []string{"10.45.0.0/16", "10.45.1.0/24"}},
		{"a narrower prefix inside a wider one", []string{"10.45.1.0/24", "10.45.0.0/16"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := New([]Interface{{Instance: "internet", Domain: 0, Pool: pool(c.pool...)}}, 4)
			if err == nil {
				t.Fatalf("the pool %v was accepted", c.pool)
			}
			if !strings.Contains(err.Error(), "ambiguous") {
				t.Errorf("the refusal says %q, want what makes it ambiguous", err)
			}
		})
	}
}

// TestADeploymentTheRouterCannotHaveIsRefused: the domains the vif writes and
// the domains the Router has must agree, or a packet classified in one
// instance resolves to no table.
func TestADeploymentTheRouterCannotHaveIsRefused(t *testing.T) {
	for _, c := range []struct {
		name       string
		ifaces     []Interface
		maxDomains uint32
		want       string
	}{
		{"no interfaces", nil, 4, "no network instance"},
		{"no name", []Interface{{Domain: 0}}, 4, "names no network instance"},
		{"a name twice", []Interface{
			{Instance: "internet", Domain: 0}, {Instance: "internet", Domain: 1}}, 4, "configured twice"},
		{"a domain twice", []Interface{
			{Instance: "internet", Domain: 0}, {Instance: "ims", Domain: 0}}, 4, "share route domain 0"},
		{"a domain beyond the router's", []Interface{{Instance: "internet", Domain: 4}}, 4, "beyond the router's 4"},
		{"no domains at all", []Interface{{Instance: "internet", Domain: 0}}, 0, "outside 1.."},
		{"more domains than BESS has", []Interface{{Instance: "internet", Domain: 1}}, MaxDomains + 1, "outside 1.."},
		{"an IPv6 pool", []Interface{{Instance: "internet", Pool: pool("2001:db8::/32")}}, 4, "not an IPv4 prefix"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := New(c.ifaces, c.maxDomains)
			if err == nil {
				t.Fatalf("%s was accepted", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the refusal says %q, want it to mention %q", err, c.want)
			}
		})
	}
}

// TestADomainAtTheBoundIsAccepted: BESS's `max_domains` is the count, so the
// highest usable id is one below it.
func TestADomainAtTheBoundIsAccepted(t *testing.T) {
	d, err := New([]Interface{
		{Instance: "internet", Domain: 0},
		{Instance: "n9", Domain: 3},
	}, 4)
	if err != nil {
		t.Fatalf("domain 3 of 4 was refused: %v", err)
	}
	if _, ok := d.Lookup("n9"); !ok {
		t.Error("the interface at the bound did not resolve")
	}
}

// TestANilDeploymentResolvesNothing: the compiler asks a deployment it was not
// given about its instances, and the answer is that it has none rather than a
// panic.
func TestANilDeploymentResolvesNothing(t *testing.T) {
	var d *Domains
	if _, ok := d.Lookup("internet"); ok {
		t.Error("a nil deployment resolved an instance")
	}
	if got := d.Default(); got.Instance != "" {
		t.Errorf("a nil deployment's default is %+v, want the zero interface", got)
	}
	if got := d.Interfaces(); got != nil {
		t.Errorf("a nil deployment lists %v interfaces, want none", got)
	}
	if got := d.MaxDomains(); got != 0 {
		t.Errorf("a nil deployment's bound is %d, want 0", got)
	}
	if got := d.Names(); got != nil {
		t.Errorf("a nil deployment's names are %v, want none", got)
	}
}
