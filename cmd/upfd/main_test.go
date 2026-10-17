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
		teidTable: "teid", teidGate: 0,
		actionsUL: "at_ul", metersUL: "mt_ul",
		actionsDL: "at_dl", metersDL: "mt_dl",
		tunnels: "enc",
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
	if cfg.Up.Actions != "at_ul" || cfg.Down.Actions != "at_dl" {
		t.Errorf("action tables: up %q, down %q", cfg.Up.Actions, cfg.Down.Actions)
	}
	if cfg.Up.Meters != "mt_ul" || cfg.Down.Meters != "mt_dl" {
		t.Errorf("meters: up %q, down %q", cfg.Up.Meters, cfg.Down.Meters)
	}
	// The tunnels belong to the downlink chain: a session's uplink is decapped,
	// its downlink is encapsulated.
	if cfg.Down.Tunnels != "enc" || cfg.Up.Tunnels != "" {
		t.Errorf("tunnels: up %q, down %q", cfg.Up.Tunnels, cfg.Down.Tunnels)
	}
	// The two next hops are the router's, one per direction.
	if cfg.Up.NextHop != 1 || cfg.Down.NextHop != 2 {
		t.Errorf("next hops: up %d, down %d", cfg.Up.NextHop, cfg.Down.NextHop)
	}
	// One capacity, three id spaces: the modules refuse an id beyond it.
	if cfg.MaxActions != 4096 || cfg.MaxMeters != 4096 || cfg.MaxTEIDs != 4096 {
		t.Errorf("id spaces: actions %d, meters %d, teids %d",
			cfg.MaxActions, cfg.MaxMeters, cfg.MaxTEIDs)
	}
	if cfg.TEIDTable != "teid" || cfg.TEIDGate != 0 {
		t.Errorf("teid table %q gate %d", cfg.TEIDTable, cfg.TEIDGate)
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
}

// TestGraphConfigRefusesBadInput: what cannot be a graph is refused with the flag
// that caused it, because the alternative is a daemon that comes up and then
// rejects every session.
func TestGraphConfigRefusesBadInput(t *testing.T) {
	cases := []struct {
		name  string
		mutate func(*graphArgs)
		want  string
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
