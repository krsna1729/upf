// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/krsna1729/upf/internal/routing"
	"github.com/krsna1729/upf/internal/session"
	"github.com/wmnsk/go-pfcp/ie"
)

// TestParseInstancesReadsTheEgresses: each *-next-hop key is one egress of the
// instance, keyed by the FAR Destination Interface value and by whether the
// forward adds an outer header, and the ARP pair is the interface's identity
// on the data network.
func TestParseInstancesReadsTheEgresses(t *testing.T) {
	d, err := parseInstances(
		"name=internet,domain=1,next-hop=1,tunnel-next-hop=3,access-next-hop=6,sgi-lan-next-hop=4,arp=arp_n6,arp-mac=02:00:00:00:06:01;"+
			" name=vn,domain=2,vn-next-hop=5", 4, session.RouteByHop)
	if err != nil {
		t.Fatalf("the deployment was refused: %v", err)
	}
	internet, ok := d.Lookup("internet")
	if !ok {
		t.Fatal("internet did not resolve")
	}
	for _, c := range []struct {
		name string
		e    routing.Egress
		want uint32
	}{
		{"a plain forward toward the data network", routing.Egress{DestIfc: 1}, 1},
		{"a tunnel out of the instance", routing.Egress{DestIfc: 1, Tunnel: true}, 3},
		{"a tunnel toward Access", routing.Egress{DestIfc: 0, Tunnel: true}, 6},
		{"a forward to the service LAN", routing.Egress{DestIfc: 2}, 4},
	} {
		if hop, ok := internet.Hop(c.e); !ok || hop != c.want {
			t.Errorf("%s: hop %d (found %v), want %d", c.name, hop, ok, c.want)
		}
	}
	if internet.NextHop != 1 {
		t.Errorf("the instance's own next hop is %d, want next-hop=1", internet.NextHop)
	}
	if internet.ARP != "arp_n6" || internet.ARPMAC != [6]byte{0x02, 0, 0, 0, 6, 1} {
		t.Errorf("the ARP identity is %q %x, want arp_n6 and 02:00:00:00:06:01", internet.ARP, internet.ARPMAC)
	}
	if hop, ok := internet.Hop(routing.Egress{DestIfc: 5}); ok || hop != 0 {
		t.Errorf("internet declares a 5G VN egress it did not ask for: %d (found %v)", hop, ok)
	}
	vn, ok := d.Lookup("vn")
	if !ok {
		t.Fatal("vn did not resolve")
	}
	if hop, ok := vn.Hop(routing.Egress{DestIfc: 5}); !ok || hop != 5 {
		t.Errorf("the 5G VN instance's re-injection hop is %d (found %v), want 5", hop, ok)
	}
	if hop, ok := vn.Hop(routing.Egress{DestIfc: 1}); ok || hop != 0 {
		t.Errorf("vn declares a data-network egress it did not ask for: %d (found %v)", hop, ok)
	}
}

// TestParseInstancesReadsTheDeployment: the flag is the deployment's interfaces,
// and what it builds is what the compiler resolves a PDI's Network Instance
// against.
func TestParseInstancesReadsTheDeployment(t *testing.T) {
	d, err := parseInstances(
		"name=internet,domain=0,next-hop=1,pool=10.45.0.0/16; name=ims, domain=1, next-hop=3, pool=10.45.0.0/16",
		2, session.RouteByHop)
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
	// No pool is an interface that serves every address until the deployment
	// says otherwise: the flag's omission is not an outage. No next-hop is an
	// instance whose forwards all tunnel, or that only re-injects: it needs an
	// egress of some kind, not that one.
	bare, err := parseInstances("name=n9,domain=3,tunnel-next-hop=3", 4, session.RouteByHop)
	if err != nil {
		t.Fatalf("an interface with no pool was refused: %v", err)
	}
	if ifc, ok := bare.Lookup("n9"); !ok || ifc.NextHop != 0 || !ifc.Serves(netip.MustParseAddr("10.45.0.2")) {
		t.Errorf("n9 is %+v, want no plain hop (the egress is a tunnel) and an unconstrained pool", ifc)
	}
}

// TestParseInstancesRoutedModeNeedsNoEgress: with a Router in destination mode
// the deployment's routes are the egress table, so an instance line names its
// domain and pool and no next hop; the parser must not demand one.
func TestParseInstancesRoutedModeNeedsNoEgress(t *testing.T) {
	d, err := parseInstances("name=n6,domain=0,pool=10.45.0.0/16", 1, session.RouteByDestination)
	if err != nil {
		t.Fatalf("a routed instance with no egress key was refused: %v", err)
	}
	ifc, ok := d.Lookup("n6")
	if !ok || ifc.Domain != 0 || ifc.NextHop != 0 {
		t.Errorf("the routed interface is %+v (found %v), want domain 0 and no policy hop", ifc, ok)
	}
}

// TestParseRouteModeNamesTheTwoModes: the flag's value is the Router's mode,
// and a typo is refused rather than defaulted to the mode that would drop the
// deployment's packets.
func TestParseRouteModeNamesTheTwoModes(t *testing.T) {
	for _, c := range []struct {
		in   string
		want session.RouteMode
	}{
		{"hop", session.RouteByHop},
		{"destination", session.RouteByDestination},
	} {
		got, err := session.ParseRouteMode(c.in)
		if err != nil || got != c.want {
			t.Errorf("ParseRouteMode(%q) = %v, %v; want %v", c.in, got, err, c.want)
		}
	}
	if _, err := session.ParseRouteMode("fib"); err == nil {
		t.Error("an unknown mode was accepted")
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
		{"an unknown field", "name=internet,domain=0,vif=1", 2, "is not name, domain, next-hop"},
		{"a domain that is not a number", "name=internet,domain=one", 2, "domain \"one\""},
		{"a next hop that is not a number", "name=internet,domain=0,next-hop=two", 2, "next-hop \"two\""},
		{"a tunnel hop that is not a number", "name=internet,domain=0,tunnel-next-hop=x", 2, "tunnel-next-hop \"x\""},
		{"an egress whose hop is 0", "name=internet,domain=0,sgi-lan-next-hop=0", 2,
			"next hop for destination interface 2 is 0"},
		{"an ARP responder with no MAC", "name=internet,domain=0,arp=arp_n6", 2, "needs arp-mac"},
		{"an ARP MAC with no responder", "name=internet,domain=0,arp-mac=02:00:00:00:06:01", 2,
			"no arp=<module> to answer"},
		{"an ARP MAC that is not a MAC", "name=internet,domain=0,arp=arp_n6,arp-mac=arp", 2,
			"arp-mac \"arp\""},
		{"a pool that is not a prefix", "name=internet,domain=0,pool=10.0.0.0", 2, "pool \"10.0.0.0\""},
		{"a domain beyond the router's", "name=internet,domain=2,next-hop=1", 2, "beyond the router's 2"},
		{"an interface with no egress", "name=internet,domain=0,pool=10.45.0.0/16", 2, "needs an egress"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseInstances(c.spec, c.max, session.RouteByHop)
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
	got, err := parsePDRFields("src, dst, proto, sport, dport, fteid, qfi")
	if err != nil {
		t.Fatalf("the graph's seven fields were refused: %v", err)
	}
	want := []session.Field{session.SrcIP, session.DstIP, session.Proto,
		session.SrcPort, session.DstPort, session.FTEIDContext, session.QFI}
	if len(got) != len(want) {
		t.Fatalf("the flag parsed %d fields, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("field %d is %v, want %v", i, got[i], want[i])
		}
	}
	// The admission context replaced the per-endpoint key fields; a profile
	// still naming them must not quietly key less than it says.
	if _, err := parsePDRFields("teid,endpoint"); err == nil {
		t.Error("the removed endpoint key fields were accepted")
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

func TestParseFTEIDAddresses(t *testing.T) {
	entries := entryList{
		"endpoint=7,reference=n3,transport-domain=1,source=access,instance=foo,ipv4=192.0.2.9,ipv6=2001:db8::9",
		"endpoint=8,reference=n9,transport-domain=2,source=core,instance=bar,ipv4=192.0.2.10",
	}
	endpoints, err := parseFTEIDAddresses(entries, true)
	if err != nil || len(endpoints) != 2 || endpoints[0].ID != 7 ||
		endpoints[0].ReferencePoint != "n3" || endpoints[0].TransportRouteDomain != 1 ||
		endpoints[0].SourceInterface != ie.SrcInterfaceAccess ||
		endpoints[0].IPv4 != netip.MustParseAddr("192.0.2.9") ||
		endpoints[0].IPv6 != netip.MustParseAddr("2001:db8::9") ||
		endpoints[1].ID != 8 || endpoints[1].ReferencePoint != "n9" ||
		endpoints[1].TransportRouteDomain != 2 ||
		endpoints[1].SourceInterface != ie.SrcInterfaceCore {
		t.Fatalf("F-TEID endpoints: %+v, error %v", endpoints, err)
	}
	for _, bad := range []string{
		"reference=n3,transport-domain=1,source=access,ipv4=192.0.2.9",
		"endpoint=0,reference=n3,transport-domain=1,source=access,ipv4=192.0.2.9",
		"endpoint=7,reference=n3,transport-domain=0,source=access,ipv4=192.0.2.9",
		"endpoint=4294967296,reference=n3,transport-domain=1,source=access,ipv4=192.0.2.9",
		"endpoint=7,reference=n3,transport-domain=1,source=core,ipv4=192.0.2.9",
		"endpoint=7,reference=n19,transport-domain=1,source=access,ipv4=192.0.2.9",
		"endpoint=7,reference=n3,transport-domain=1,source=access,ipv4=::1",
		"endpoint=7,reference=n3,transport-domain=1,source=access,ipv6=::ffff:192.0.2.1",
		"endpoint=7,reference=n3,transport-domain=1,source=access,ipv4=0.0.0.0",
		"endpoint=7,reference=n3,transport-domain=1,source=access,ipv4=169.254.1.1",
		"endpoint=7,reference=n3,transport-domain=1,source=access,ipv6=2001:db8::1%eth0",
	} {
		if _, err := parseFTEIDAddresses(entryList{bad}, false); err == nil {
			t.Errorf("invalid F-TEID endpoint accepted: %s", bad)
		}
	}
	if _, err := parseFTEIDAddresses(entryList{
		"endpoint=7,reference=n3,transport-domain=1,source=access,ipv4=192.0.2.9",
	}, true); err == nil {
		t.Error("multi-instance endpoint without instance was accepted")
	}
	if _, err := parseFTEIDAddresses(entryList{
		"endpoint=7,reference=n3,transport-domain=1,source=access,instance=foo,ipv4=192.0.2.9",
		"endpoint=7,reference=n9,transport-domain=2,source=core,instance=bar,ipv4=192.0.2.10",
	}, true); err == nil {
		t.Error("duplicate endpoint ID was accepted")
	}
	if got, err := parseFTEIDAddresses(entryList{
		"endpoint=9,reference=n3,transport-domain=3,source=access,ipv6=fd00::1",
	}, false); err != nil || got[0].IPv6 != netip.MustParseAddr("fd00::1") {
		t.Errorf("valid ULA endpoint rejected: %+v, %v", got, err)
	}
}

func TestParseInstancesAccessTunnelEgress(t *testing.T) {
	domains, err := parseInstances("name=direct,domain=0,access-next-hop=2;name=indirect,domain=1,access-next-hop=3", 2, session.RouteByHop)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]uint32{"direct": 2, "indirect": 3} {
		ifc, ok := domains.Lookup(name)
		if !ok {
			t.Fatalf("missing instance %q", name)
		}
		if got, ok := ifc.Hop(routing.Egress{DestIfc: 0, Tunnel: true}); !ok || got != want {
			t.Errorf("%s Access tunnel hop %d (found %v), want %d", name, got, ok, want)
		}
		if _, ok := ifc.Hop(routing.Egress{DestIfc: 0}); ok {
			t.Errorf("%s tunnel-only Access mapping also matched plain Access", name)
		}
	}
	for _, value := range []string{"-1", "4294967296", "not-a-hop"} {
		if _, err := parseInstances("name=invalid,domain=0,access-next-hop="+value, 1, session.RouteByHop); err == nil {
			t.Errorf("invalid Access hop %q accepted", value)
		}
	}
}
