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
		t.Error("an address outside every declared pool is served")
	}
	unconstrained, err := New([]Interface{{Instance: "n9", Domain: 0}}, 1)
	if err != nil {
		t.Fatalf("an interface with no pool was refused: %v", err)
	}
	if ifc, _ := unconstrained.Lookup("n9"); !ifc.Serves(netip.MustParseAddr("192.0.2.1")) {
		t.Error("an interface the deployment declares no pool for serves nothing: a flag left out would refuse every session")
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

// TestAnInterfacesEgressesAreItsOwn is the egress table: the same Destination
// Interface value means two exits, plain and tunneled, and the deployment's
// table tells them apart.
func TestAnInterfacesEgressesAreItsOwn(t *testing.T) {
	mac := [6]byte{0x02, 0, 0, 0, 6, 1}
	d, err := New([]Interface{{
		Instance: "internet", Domain: 0, NextHop: 1,
		Hops: map[Egress]uint32{
			{DestIfc: 1, Tunnel: false}: 1,
			{DestIfc: 1, Tunnel: true}:  3,
			{DestIfc: 2, Tunnel: false}: 4,
			{DestIfc: 5, Tunnel: false}: 5,
		},
		ARP: "arp_n6", ARPMAC: mac,
	}}, 4)
	if err != nil {
		t.Fatalf("the egress table was refused: %v", err)
	}
	ifc, ok := d.Lookup("internet")
	if !ok {
		t.Fatal("the instance did not resolve")
	}
	for _, c := range []struct {
		e    Egress
		want uint32
	}{
		{Egress{DestIfc: 1}, 1},
		{Egress{DestIfc: 1, Tunnel: true}, 3},
		{Egress{DestIfc: 2}, 4},
		{Egress{DestIfc: 5}, 5},
	} {
		if hop, ok := ifc.Hop(c.e); !ok || hop != c.want {
			t.Errorf("the hop for %+v is %d (found %v), want %d", c.e, hop, ok, c.want)
		}
		if got := ifc.HopOr(c.e, 99); got != c.want {
			t.Errorf("HopOr(%+v, 99) is %d, want the declared %d", c.e, got, c.want)
		}
	}
	if hop, ok := ifc.Hop(Egress{DestIfc: 3}); ok || hop != 0 {
		t.Errorf("a destination interface the table does not declare resolved to %d (found %v)", hop, ok)
	}
	if got := ifc.HopOr(Egress{DestIfc: 3}, 7); got != 7 {
		t.Errorf("HopOr of an undeclared egress is %d, want the fallback 7", got)
	}
	if got := ifc.HopOr(Egress{DestIfc: 2, Tunnel: true}, 7); got != 7 {
		t.Errorf("a tunneled service-LAN egress the table does not declare is %d, want the fallback 7", got)
	}
	// An interface that declares no table at all: every lookup is the
	// fallback, which is what a deployment with one egress per instance has.
	plain, err := New([]Interface{{Instance: "n9", Domain: 0, NextHop: 2}}, 1)
	if err != nil {
		t.Fatalf("an interface with no egress table was refused: %v", err)
	}
	n9, _ := plain.Lookup("n9")
	if hop, ok := n9.Hop(Egress{DestIfc: 1}); ok || hop != 0 {
		t.Errorf("an interface with no egress table declares a hop: %d (found %v)", hop, ok)
	}
	if got := n9.HopOr(Egress{DestIfc: 1}, n9.NextHop); got != 2 {
		t.Errorf("the fallback for a plain forward is %d, want the instance's own 2", got)
	}
	if _, err := New([]Interface{{Instance: "internet", Domain: 0, ARP: "arp_n6", ARPMAC: mac}}, 1); err != nil {
		t.Fatalf("an interface with no pool was refused: %v", err)
	}
}

// TestAnEgressTableTheDeploymentCannotHaveIsRefused: the table is the
// deployment's own grammar, and a key or a value the dataplane could not carry
// is refused where the operator can fix it.
func TestAnEgressTableTheDeploymentCannotHaveIsRefused(t *testing.T) {
	mac := [6]byte{0x02, 0, 0, 0, 6, 1}
	for _, c := range []struct {
		name string
		ifc  Interface
		want string
	}{
		{"a destination interface above the spec's values",
			Interface{Instance: "internet", Hops: map[Egress]uint32{{DestIfc: 6}: 1}}, "above the values the spec defines"},
		{"the access side",
			Interface{Instance: "internet", Hops: map[Egress]uint32{{DestIfc: 0}: 1}}, "destination interface 0 (access)"},
		{"a tunneled access side",
			Interface{Instance: "internet", Hops: map[Egress]uint32{{DestIfc: 0, Tunnel: true}: 1}}, "destination interface 0 (access)"},
		{"a next hop of 0",
			Interface{Instance: "internet", Hops: map[Egress]uint32{{DestIfc: 1}: 0}}, "is 0, which is no next hop"},
		{"an ARP responder with no MAC",
			Interface{Instance: "internet", ARP: "arp_n6"}, "no ARP MAC"},
		{"an ARP MAC with no responder",
			Interface{Instance: "internet", ARPMAC: mac}, "no ARP responder module"},
	} {
		t.Run(c.name, func(t *testing.T) {
			c.ifc.Domain = 0
			_, err := New([]Interface{c.ifc}, 4)
			if err == nil {
				t.Fatalf("%s was accepted", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the refusal says %q, want it to mention %q", err, c.want)
			}
		})
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
