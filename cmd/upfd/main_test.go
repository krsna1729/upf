// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"strings"
	"testing"

	"github.com/krsna1729/upf/internal/session"
)

// validArgs is the flag set a deployment passes: every field graphConfig reads
// has a value, so a test can change one at a time.
func validArgs() graphArgs {
	return graphArgs{
		target: "graph",
		fteidAddresses: entryList{
			"endpoint=1,reference=n3,transport-domain=1,source=access,ipv4=192.0.2.9",
		},
		capacity:   4096,
		n6NextHop:  1,
		n3NextHop:  2,
		pdrTableUL: "pdr_ul", pdrTableDL: "pdr_dl",
		pdrFieldsUL: "src,dst,proto,sport,dport,fteid,qfi",
		pdrFieldsDL: "src,dst,proto,sport,dport,domain,fteid,qfi",
		gtpuDecap:   "decap",
		metersUL:    "mt_ul", metersDL: "mt_dl",
		// One encap module, both directions: the deployed daemon writes an
		// uplink forward's tunnel record there too.
		tunnels: "enc", tunnelsUL: "enc",
	}
}

// TestGraphConfigMapsTheFlags: the flags are the deployed graph's names, and a
// session is programmed at exactly these names. The endpoint and transport
// domain must both reach the compiler; Ethernet peer resolution belongs to the
// routed Router, not to the session controller.
func TestGraphConfigMapsTheFlags(t *testing.T) {
	cfg, err := graphConfig(validArgs())
	if err != nil {
		t.Fatalf("graphConfig: %v", err)
	}
	if cfg.Up.PDRTable != "pdr_ul" || cfg.Down.PDRTable != "pdr_dl" {
		t.Errorf("rule tables: up %q, down %q", cfg.Up.PDRTable, cfg.Down.PDRTable)
	}
	if cfg.Up.Meters != "mt_ul" || cfg.Down.Meters != "mt_dl" {
		t.Errorf("meters: up %q, down %q", cfg.Up.Meters, cfg.Down.Meters)
	}
	// Both directions name the encap: the downlink's tunnel toward the gNB,
	// and an uplink forward that adds an outer header of its own (indirect
	// data forwarding, the uplink of an N9 tunnel). A direction with no module
	// refuses such a forward rather than writing a record nobody holds.
	if cfg.Down.Tunnels != "enc" || cfg.Up.Tunnels != "enc" {
		t.Errorf("tunnels: up %q, down %q", cfg.Up.Tunnels, cfg.Down.Tunnels)
	}
	// The uplink's module is its own flag: a deployment with two encap modules
	// names each, and one that names none for the uplink keeps the refusal.
	ulArgs := validArgs()
	ulArgs.tunnelsUL = ""
	withoutUL, err := graphConfig(ulArgs)
	if err != nil || withoutUL.Up.Tunnels != "" {
		t.Errorf("an empty -tunnels-ul gave the uplink the module %q (err %v)", withoutUL.Up.Tunnels, err)
	}
	// The two next hops are the router's, one per direction, and the access
	// side's is its own: a forward whose FAR names Destination Interface
	// Access leaves by it whichever direction the PDR is on, which is what
	// indirect data forwarding needs. 0 leaves it to the downlink's.
	if cfg.Up.NextHop != 1 || cfg.Down.NextHop != 2 {
		t.Errorf("next hops: up %d, down %d", cfg.Up.NextHop, cfg.Down.NextHop)
	}
	if cfg.AccessNextHop != 0 {
		t.Errorf("the access next hop is %d, want the flag's 0 by default", cfg.AccessNextHop)
	}
	args := validArgs()
	args.accessNextHop = 3
	args.maxDomains = 2
	args.instances = "name=internet,domain=1,next-hop=1,tunnel-next-hop=3,sgi-lan-next-hop=4,arp=arp_n6,arp-mac=02:00:00:00:06:01"
	args.fteidAddresses = entryList{
		"endpoint=1,reference=n3,transport-domain=1,source=access,instance=internet,ipv4=192.0.2.9",
	}
	if cfg, err = graphConfig(args); err != nil {
		t.Fatalf("graphConfig with -access-next-hop and -instances: %v", err)
	}
	if cfg.AccessNextHop != 3 {
		t.Errorf("the access next hop is %d, want the flag's 3", cfg.AccessNextHop)
	}
	if ifc, ok := cfg.Instances.Lookup("internet"); !ok || ifc.ARP != "arp_n6" {
		t.Errorf("the instance's ARP identity did not reach the compiler: %+v (found %v)", ifc, ok)
	}
	// One capacity, three id spaces: the modules refuse an id beyond it.
	if cfg.MaxActions != 4096 || cfg.MaxMeters != 4096 || cfg.MaxTEIDs != 4096 {
		t.Errorf("id spaces: actions %d, meters %d, teids %d",
			cfg.MaxActions, cfg.MaxMeters, cfg.MaxTEIDs)
	}
	if cfg.GTPUDecap != "decap" {
		t.Errorf("GTP-U decap %q", cfg.GTPUDecap)
	}
	if len(cfg.FTEIDEndpoints) != 1 || cfg.FTEIDEndpoints[0].ID != 1 ||
		cfg.FTEIDEndpoints[0].TransportRouteDomain != 1 ||
		cfg.FTEIDEndpoints[0].IPv4.String() != "192.0.2.9" {
		t.Errorf("F-TEID endpoint mapping: %+v", cfg.FTEIDEndpoints)
	}
	if len(cfg.Up.PDRFields) != 7 || cfg.Up.PDRFields[5] != session.FTEIDContext ||
		len(cfg.Down.PDRFields) != 8 || cfg.Down.PDRFields[5] != session.RouteDomain ||
		cfg.Down.PDRFields[6] != session.FTEIDContext {
		t.Errorf("PDR table fields: up %v, down %v", cfg.Up.PDRFields, cfg.Down.PDRFields)
	}
}

// TestGraphConfigRefusesBadInput: what cannot be a graph is refused with the flag
// that caused it, because the alternative is a daemon that comes up and then
// rejects every session.
func TestGraphConfigRefusesBadInput(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*graphArgs)
		want   string
	}{
		{"no F-TEID endpoint", func(a *graphArgs) { a.fteidAddresses = nil }, "-fteid-address"},
		{"only N9 endpoint", func(a *graphArgs) {
			a.fteidAddresses = entryList{"endpoint=2,reference=n9,transport-domain=2,source=core,ipv4=192.0.2.10"}
		}, "N3 endpoint"},
		{"zero transport domain", func(a *graphArgs) {
			a.fteidAddresses = entryList{"endpoint=1,reference=n3,transport-domain=0,source=access,ipv4=192.0.2.9"}
		}, "-fteid-address"},
		{"N3 endpoint on Core source", func(a *graphArgs) {
			a.fteidAddresses = entryList{"endpoint=1,reference=n3,transport-domain=1,source=core,ipv4=192.0.2.9"}
		}, "-fteid-address"},
		{"IPv6 supplied as IPv4", func(a *graphArgs) {
			a.fteidAddresses = entryList{"endpoint=1,reference=n3,transport-domain=1,source=access,ipv4=2001:db8::9"}
		}, "-fteid-address"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := validArgs()
			tc.mutate(&args)
			_, err := graphConfig(args)
			if err == nil {
				t.Fatalf("graphConfig accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name %s", err, tc.want)
			}
		})
	}
}

// TestParseMAC: net.ParseMAC also accepts 8-byte (EUI-64) addresses and
// dash-separated ones; the graph's ports are 6-byte Ethernet addresses, so the
// parser is what decides, not the caller.
func TestParseMAC(t *testing.T) {
	ok := []struct {
		in   string
		want [6]byte
	}{
		{"02:00:00:00:00:01", [6]byte{0x02, 0, 0, 0, 0, 0x01}},
		{"02-00-00-00-00-01", [6]byte{0x02, 0, 0, 0, 0, 0x01}},
		{"02:00:00:00:00:01", [6]byte{0x02, 0, 0, 0, 0, 0x01}},
		{"ff:ff:ff:ff:ff:ff", [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
	}
	for _, tc := range ok {
		got, err := parseMAC(tc.in)
		if err != nil {
			t.Errorf("parseMAC(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseMAC(%q) = %x, want %x", tc.in, got, tc.want)
		}
	}
	bad := []string{"", "02:00:00:00:00", "02:00:00:00:00:01:02", "not:a:mac"}
	for _, in := range bad {
		if got, err := parseMAC(in); err == nil {
			t.Errorf("parseMAC(%q) accepted it as %x", in, got)
		}
	}
}

// TestAtsssNeedsNothingElse: the downlink table's result carries the MAR
// steering policy id in addition to the action record, so naming an AtsssSteer
// module is all a deployment adds.
func TestAtsssStandsOnItsOwnResultSlot(t *testing.T) {
	args := validArgs()
	args.atsss = "atsss_dl"
	cfg, err := graphConfig(args)
	if err != nil {
		t.Fatalf("graphConfig refused -atsss: %v", err)
	}
	if cfg.Atsss != "atsss_dl" {
		t.Errorf("the config carries Atsss %q, want the module the flag names", cfg.Atsss)
	}
}

func TestGraphConfigMapsTransportDomains(t *testing.T) {
	args := validArgs()
	args.fteidAddresses = entryList{
		"endpoint=1,reference=n3,transport-domain=7,source=access,ipv4=192.0.2.9,ipv6=2001:db8:1::1",
		"endpoint=2,reference=n9,transport-domain=9,source=core,ipv4=192.0.2.19",
	}
	cfg, err := graphConfig(args)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.FTEIDEndpoints) != 2 ||
		cfg.FTEIDEndpoints[0].ReferencePoint != "n3" ||
		cfg.FTEIDEndpoints[0].TransportRouteDomain != 7 ||
		cfg.FTEIDEndpoints[0].IPv6.String() != "2001:db8:1::1" ||
		cfg.FTEIDEndpoints[1].ReferencePoint != "n9" ||
		cfg.FTEIDEndpoints[1].TransportRouteDomain != 9 {
		t.Fatalf("transport endpoint mappings were lost: %+v", cfg.FTEIDEndpoints)
	}
	if cfg.EndMarker != "" || hasEndMarker(cfg) {
		t.Fatal("an unconfigured End Marker path was enabled")
	}
	cfg.EndMarker = "/tmp/upf-end-marker.sock"
	if !hasEndMarker(cfg) {
		t.Fatal("a configured End Marker base path must advertise EMPU")
	}
}

func TestGraphConfigRejectsInvalidTransportEndpoint(t *testing.T) {
	for _, entry := range []string{
		"endpoint=1,reference=n3,source=access,ipv4=192.0.2.1",
		"endpoint=1,reference=n9,transport-domain=2,source=access,ipv4=192.0.2.1",
		"endpoint=1,reference=n3,transport-domain=1,source=access,ipv4=127.0.0.1",
		"endpoint=1,reference=n3,transport-domain=1,source=access,ipv6=::1",
		"endpoint=1,reference=n3,transport-domain=1,source=access,instance=internet,ipv4=192.0.2.1",
	} {
		t.Run(entry, func(t *testing.T) {
			args := validArgs()
			args.fteidAddresses = entryList{entry}
			if _, err := graphConfig(args); err == nil ||
				!strings.Contains(err.Error(), "-fteid-address") {
				t.Fatalf("invalid endpoint %q produced error %v", entry, err)
			}
		})
	}
}

func TestGraphConfigRefusesWhatNoTargetIs(t *testing.T) {
	for name, change := range map[string]func(*graphArgs){
		"unknown target": func(a *graphArgs) { a.target = "fused" },
		"no appliance module": func(a *graphArgs) {
			a.target, a.appliance = "appliance", ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			args := validArgs()
			change(&args)
			if _, err := graphConfig(args); err == nil {
				t.Fatal("graphConfig accepted it")
			}
		})
	}
}
