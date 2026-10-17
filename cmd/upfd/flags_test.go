// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/krsna1729/upf/internal/session"
)

// TestParseInstancesReadsTheDeployment: the flag is the deployment's interfaces,
// and what it builds is what the compiler resolves a PDI's Network Instance
// against.
func TestParseInstancesReadsTheDeployment(t *testing.T) {
	d, err := parseInstances(
		"name=internet,domain=0,next-hop=1,pool=10.45.0.0/16; name=ims, domain=1, next-hop=3, pool=10.45.0.0/16",
		2)
	if err != nil {
		t.Fatalf("the deployment was refused: %v", err)
	}
	if got := strings.Join(d.Names(), ","); got != "internet,ims" {
		t.Errorf("the instances are %q, want the flag's order", got)
	}
	internet, ok := d.Lookup("internet")
	if !ok {
		t.Fatal("internet did not resolve")
	}
	if internet.Domain != 0 || internet.NextHop != 1 {
		t.Errorf("internet is %+v, want domain 0 and next hop 1", internet)
	}
	if !internet.Serves(netip.MustParseAddr("10.45.0.2")) {
		t.Error("internet does not serve the pool the flag gave it")
	}
	ims, ok := d.Lookup("ims")
	if !ok || ims.Domain != 1 || ims.NextHop != 3 {
		t.Errorf("ims is %+v (found %v), want domain 1 and next hop 3", ims, ok)
	}
	// No pool is an interface that serves nothing but still resolves.
	bare, err := parseInstances("name=n9,domain=3", 4)
	if err != nil {
		t.Fatalf("an interface with no pool was refused: %v", err)
	}
	if ifc, ok := bare.Lookup("n9"); !ok || ifc.NextHop != 0 || ifc.Serves(netip.MustParseAddr("10.45.0.2")) {
		t.Errorf("n9 is %+v, want a nameless hop and an empty pool", ifc)
	}
}

// TestParseInstancesRefuses: a flag that would not be a deployment is refused
// with what is wrong, before a dataplane is dialed.
func TestParseInstancesRefuses(t *testing.T) {
	for _, c := range []struct {
		name string
		spec string
		max  uint32
		want string
	}{
		{"no interface", "", 2, "no network instance"},
		{"no name", "domain=0", 2, "needs name="},
		{"no domain", "name=internet", 2, "needs domain="},
		{"a field that is not key=value", "name=internet,domain", 2, "is not key=value"},
		{"an unknown field", "name=internet,domain=0,vif=1", 2, "is not name, domain, next-hop or pool"},
		{"a domain that is not a number", "name=internet,domain=one", 2, "domain \"one\""},
		{"a next hop that is not a number", "name=internet,domain=0,next-hop=two", 2, "next-hop \"two\""},
		{"a pool that is not a prefix", "name=internet,domain=0,pool=10.0.0.0", 2, "pool \"10.0.0.0\""},
		{"a domain beyond the router's", "name=internet,domain=2", 2, "beyond the router's 2"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseInstances(c.spec, c.max)
			if err == nil {
				t.Fatalf("%q was accepted", c.spec)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the refusal says %q, want it to mention %q", err, c.want)
			}
		})
	}
}

// TestParsePDRFieldsNamesTheGraphsKey: the flag names the fields the manifest
// declares, in its order, and a name that is not one of them is refused rather
// than silently dropped -- a dropped field is a rule keyed on less than the
// table matches.
func TestParsePDRFieldsNamesTheGraphsKey(t *testing.T) {
	got, err := parsePDRFields("src, dst, proto, sport, dport, teid")
	if err != nil {
		t.Fatalf("the graph's six fields were refused: %v", err)
	}
	want := []session.Field{session.SrcIP, session.DstIP, session.Proto,
		session.SrcPort, session.DstPort, session.UpfTEID}
	if len(got) != len(want) {
		t.Fatalf("the flag parsed %d fields, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("field %d is %v, want %v", i, got[i], want[i])
		}
	}
	if _, err := parsePDRFields("src,domain,tunnel"); err == nil {
		t.Error("a field name the graph has no such field for was accepted")
	} else if !strings.Contains(err.Error(), "\"tunnel\"") {
		t.Errorf("the refusal says %v, want it to name the field", err)
	}
	if _, err := parsePDRFields(" , "); err == nil {
		t.Error("a flag naming no field was accepted")
	}
}
