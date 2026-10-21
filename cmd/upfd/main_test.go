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
		n3: "192.0.2.9", n3MAC: "02:00:00:00:00:01", peerMAC: "02:00:00:00:00:02",
		capacity:   4096,
		n6NextHop:  1,
		n3NextHop:  2,
		pdrTableUL: "pdr_ul", pdrTableDL: "pdr_dl",
		pdrFieldsUL: "src,dst,proto,sport,dport,qfi", pdrFieldsDL: "src,dst,proto,sport,dport",
		teidTable: "teid",
		metersUL:  "mt_ul", metersDL: "mt_dl",
		// One encap module, both directions: the deployed daemon writes an
		// uplink forward's tunnel record there too.
		tunnels: "enc", tunnelsUL: "enc",
	}
}

// TestGraphConfigMapsTheFlags: the flags are the deployed graph's names, and a
// session is programmed at exactly these names. A swap between the chains, a
// capacity that reaches one table but not another, or a MAC parsed in the wrong
// byte order are all failures that only show up as a session that forwards
// nothing, so they are checked here in the values the compiler receives.
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
	if cfg.TEIDTable != "teid" {
		t.Errorf("teid table %q", cfg.TEIDTable)
	}
	if got := cfg.N3Addr.String(); got != "192.0.2.9" {
		t.Errorf("n3 address %q", got)
	}
	if cfg.N3MAC != [6]byte{0x02, 0, 0, 0, 0, 0x01} {
		t.Errorf("n3 mac %x", cfg.N3MAC)
	}
	if cfg.PeerMAC != [6]byte{0x02, 0, 0, 0, 0, 0x02} {
		t.Errorf("peer mac %x", cfg.PeerMAC)
	}
	if len(cfg.Up.PDRFields) != 6 || cfg.Up.PDRFields[0] != session.SrcIP ||
		cfg.Up.PDRFields[5] != session.QFI || cfg.Down.PDRFields[0] != session.SrcIP {
		t.Errorf("both chains match the inner packet: up %v, down %v",
			cfg.Up.PDRFields, cfg.Down.PDRFields)
	}
	// The firewall path is opt-in: with no module named, both directions are
	// the WildcardMatch table, and a named module is what the direction's PDRs
	// go into instead.
	if cfg.Up.Firewall != "" || cfg.Down.Firewall != "" {
		t.Errorf("the default graph opts into a firewall path: up %q, down %q",
			cfg.Up.Firewall, cfg.Down.Firewall)
	}
	args = validArgs()
	args.firewallUL, args.firewallDL = "fw_ul", "fw_dl"
	if cfg, err = graphConfig(args); err != nil {
		t.Fatalf("graphConfig with firewall modules: %v", err)
	}
	if cfg.Up.Firewall != "fw_ul" || cfg.Down.Firewall != "fw_dl" {
		t.Errorf("firewall modules: up %q, down %q", cfg.Up.Firewall, cfg.Down.Firewall)
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
		{"no n3 address", func(a *graphArgs) { a.n3 = "" }, "-n3-addr"},
		{"an IPv6 n3 address", func(a *graphArgs) { a.n3 = "2001:db8::9" }, "-n3-addr"},
		{"an n3 name", func(a *graphArgs) { a.n3 = "upf.example" }, "-n3-addr"},
		{"a short port mac", func(a *graphArgs) { a.n3MAC = "02:00:00:00:00" }, "-n3-mac"},
		{"a port mac that is not hex", func(a *graphArgs) { a.n3MAC = "zz:00:00:00:00:01" }, "-n3-mac"},
		{"a peer mac of the wrong length", func(a *graphArgs) { a.peerMAC = "02:00:00:00:00:00:02" }, "-peer-mac"},
		{"a peer mac that is not a mac", func(a *graphArgs) { a.peerMAC = "enc" }, "-peer-mac"},
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

func TestGraphConfigTunnelTransports(t *testing.T) {
	args := validArgs()
	args.n9 = "192.0.2.19"
	args.transports = entryList{"next-hop=3,gate=1,addr=192.0.2.19,mac=02:00:00:00:00:09,peer-mac=02:00:00:00:00:0a,end-marker=/tmp/upf-end-marker-n9.sock"}
	args.fteidAddresses = entryList{"instance=foo,addr=192.0.2.19"}
	cfg, err := graphConfig(args)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.N9Addr.String() != args.n9 || cfg.FTEIDAddrs["foo"] != cfg.N9Addr {
		t.Fatalf("local tunnel addresses lost: N9 %v, overrides %v", cfg.N9Addr, cfg.FTEIDAddrs)
	}
	transport, ok := cfg.Transports[3]
	if !ok || transport.Gate != 1 || transport.Addr != cfg.N9Addr ||
		transport.MAC != [6]byte{2, 0, 0, 0, 0, 9} ||
		transport.PeerMAC != [6]byte{2, 0, 0, 0, 0, 10} ||
		transport.EndMarker != "/tmp/upf-end-marker-n9.sock" {
		t.Fatalf("transport did not reach compiler: %+v", transport)
	}
	if cfg.EndMarker != "" || !hasEndMarker(cfg) {
		t.Fatal("a mapped End Marker socket must advertise EMPU without a default socket")
	}
	cfg, err = graphConfig(validArgs())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.N9Addr.IsValid() || len(cfg.Transports) != 0 || len(cfg.FTEIDAddrs) != 0 || hasEndMarker(cfg) {
		t.Fatalf("default N3 deployment gained N9 configuration: %+v", cfg)
	}
	cfg.EndMarker = "/tmp/upf-end-marker.sock"
	if !hasEndMarker(cfg) {
		t.Fatal("default N3 End Marker socket must still advertise EMPU")
	}
}

func TestGraphConfigRejectsInvalidN9Flags(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*graphArgs)
		want   string
	}{
		{"IPv6 N9", func(a *graphArgs) { a.n9 = "2001:db8::9" }, "-n9-addr"},
		{"unspecified N9", func(a *graphArgs) { a.n9 = "0.0.0.0" }, "-n9-addr"},
		{"invalid transport", func(a *graphArgs) { a.transports = entryList{"next-hop=3"} }, "-tunnel-transport"},
		{"invalid F-TEID", func(a *graphArgs) { a.fteidAddresses = entryList{"instance=foo,addr=::1"} }, "-fteid-address"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := validArgs()
			tc.change(&args)
			if _, err := graphConfig(args); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %s error, got %v", tc.want, err)
			}
		})
	}
}
