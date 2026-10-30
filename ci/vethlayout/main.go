// SPDX-License-Identifier: BSD-3-Clause

// Command vethlayout is the Go half of ci/veth-layouts.sh. For one attachment
// layout it generates the production-shaped BESS graph -- decap0 and its GTP-U
// responder, the two PDR tables and chains, rt, enc, rt_transport and the End
// Marker ports -- with the layout's PMD ports spliced in front, and writes the
// shell's contract: every attachment, the logical endpoints' local addresses,
// the egress each scenario's tunnel takes, the packets each scenario phase
// sends, the End Markers that must leave relayed, and the upfd flags that
// configure a compiler for the same graph.
//
// With -drive it is that compiler: one session.Compiler over the BESS SDK,
// behind the UP function's N4 node, to which a stand-in SMF sends every
// Release 16 scenario's sessions over PFCP (ci/scenario: Modes 1 to 6 and the
// N19 group session). It waits for both Routers to resolve their neighbors,
// then hands the phases to the shell through handshake files, running Mode
// 6's indirect forwarding procedure (preparation, the switch of the target's
// downlink, its 4 s timer and the releases) itself. Every other session stays
// established until the shell has replayed every scenario after Mode 6.
//
// It also sends the lane's packets: -send-gpdu for G-PDUs to a local endpoint,
// -send-end-marker for End Markers to one, -send-udp for plain IP toward N6,
// all bound to one device, and -sink-udp absorbs the GTP-U the graph tunnels
// back to the host, printing the End Markers among it.
package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/wmnsk/go-pfcp/ie"

	"github.com/krsna1729/upf/ci/scenario"
	"github.com/krsna1729/upf/internal/bess"
	"github.com/krsna1729/upf/internal/routing"
	"github.com/krsna1729/upf/internal/session"
)

// unknownTEID is a TEID no session admits: the decap's unknown path.
const unknownTEID uint32 = 0xdeadbeef

// The deployment the compiler is configured with: two instances in one pool,
// the Router hops (rt/next_hops and the compiler's egress table name the same
// numbers), and the inner route domains. The internet instance's domain is the
// N6 attachments' own, so the Vif's domain is the downlink rule's key.
const (
	internet       = "internet"
	vn             = "vn"
	pool           = "10.44.0.0/14"
	internetDomain = 3
	vnDomain       = 4
	maxDomains     = 5

	hopN6     uint32 = 1 // rt gate 0: the first N6 attachment, resolved
	hopAccess uint32 = 2 // rt gate 1: the encap, toward the access side
	hopN9     uint32 = 3 // rt gate 2: the encap, a tunnel out of the instance
	hopVN     uint32 = 5 // rt gate 4: re-injection into pdr_dl

	// firstExtraN6Gate is where rt's further N6 attachments start: gates 1, 2
	// and 4 are the hops above, and an interface's id is its gate + 1.
	firstExtraN6Gate uint32 = 5
)

// The logical endpoints' local GTP-U addresses: one per endpoint, shared by
// every port it is attached to (the compiler holds one address per endpoint
// and family). They lie outside every port's test prefix, so the host reaches
// them only by the per-device routes the shell installs.
const (
	n3Local = "198.19.0.1"
	n9Local = "198.19.0.9"
	// dataNetwork is the uplink's inner destination: off every test prefix,
	// and dropped by the host, whose peer devices do not forward.
	dataNetwork = "198.19.53.53"
)

// endpoint is one attachment of a logical endpoint (n3, n6 or n9) to one PMD
// port. A layout may attach the same logical endpoint to several ports; every
// attachment carries the endpoint's id, route domain and gate, and its own
// port-local address (the Vif's ARP identity and the Router interface's).
type endpoint struct {
	name   string
	id     uint32
	domain uint32
	gate   uint32
	port   int
	vlan   uint32
	mac    string
	ip     string
	source string
	// router is the Router that sends out of this attachment (rt for N6,
	// rt_transport for N3 and N9) and egress its gate there; the Router
	// interface's id is egress + 1.
	router string
	egress uint32
}

type layout struct {
	groups       [][]string
	direct       bool
	sameN3N9Addr bool
	vlans        map[string]uint32
	sharedMAC    bool
	hybridMAC    bool
}

var endpointOrder = []string{"n3", "n6", "n9"}
var endpointDomain = map[string]uint32{"n3": 1, "n9": 2, "n6": internetDomain}
var endpointGate = map[string]uint32{"n3": 1, "n9": 2, "n6": 3}
var endpointID = map[string]uint32{"n3": 1, "n9": 2}
var endpointMAC = map[string]string{
	"n3": "02:00:00:00:03:01",
	"n6": "02:00:00:00:06:01",
	"n9": "02:00:00:00:09:01",
}
var endpointHostOctet = map[string]string{"n3": "101", "n6": "103", "n9": "102"}

// prefixFor is a port's test /24: the three documentation prefixes, then the
// benchmarking range (RFC 2544) for any further port, so no layout is bounded
// by a table of prefixes.
func prefixFor(port int) string {
	if docs := []string{"192.0.2", "198.51.100", "203.0.113"}; port < len(docs) {
		return docs[port]
	}
	return fmt.Sprintf("198.18.%d", port)
}

func layoutFor(name string) (layout, error) {
	all := [][]string{{"n3", "n6", "n9"}}
	switch name {
	case "one-mac":
		return layout{groups: all}, nil
	case "one-vlan":
		return layout{
			groups:       all,
			sameN3N9Addr: true,
			vlans:        map[string]uint32{"n3": 101, "n6": 106, "n9": 109},
			sharedMAC:    true,
		}, nil
	case "one-hybrid":
		return layout{
			groups:    all,
			vlans:     map[string]uint32{"n6": 106},
			hybridMAC: true,
		}, nil
	case "two-n3n9-n6":
		return layout{groups: [][]string{{"n3", "n9"}, {"n6"}}}, nil
	case "two-n3n6-n9":
		return layout{groups: [][]string{{"n3", "n6"}, {"n9"}}}, nil
	case "two-n6n9-n3":
		return layout{groups: [][]string{{"n6", "n9"}, {"n3"}}}, nil
	case "three-vif":
		return layout{groups: [][]string{{"n3"}, {"n6"}, {"n9"}}}, nil
	case "three-direct":
		return layout{groups: [][]string{{"n3"}, {"n6"}, {"n9"}}, direct: true}, nil
	case "four-fanin":
		// Four ports, every logical endpoint attached twice: fan-in from
		// several ports into one endpoint, and ports shared by two endpoints.
		return layout{groups: [][]string{{"n3"}, {"n3", "n9"}, {"n6"}, {"n9", "n6"}}}, nil
	default:
		return layout{}, fmt.Errorf("unknown layout %q", name)
	}
}

func makeEndpoints(cfg layout) ([]endpoint, error) {
	var out []endpoint
	seen := make(map[string]bool, len(endpointOrder))
	transportGate, extraN6Gate, firstN6 := uint32(0), firstExtraN6Gate, true
	for port, group := range cfg.groups {
		for _, name := range group {
			index := slices.Index(endpointOrder, name)
			if index < 0 {
				return nil, fmt.Errorf("layout names an unknown endpoint %q", name)
			}
			seen[name] = true
			sourceOctet := "2"
			if cfg.vlans[name] != 0 {
				sourceOctet = fmt.Sprint(index + 2)
			}
			mac := endpointMAC[name]
			if cfg.direct {
				mac = fmt.Sprintf("02:00:00:00:de:%02x", index+1)
			} else if cfg.sharedMAC {
				mac = "02:00:00:00:aa:01"
			} else if cfg.hybridMAC && name == "n6" {
				mac = endpointMAC["n3"]
			}
			ep := endpoint{
				name:   name,
				id:     endpointID[name],
				domain: endpointDomain[name],
				gate:   endpointGate[name],
				port:   port,
				vlan:   cfg.vlans[name],
				mac:    mac,
				ip:     prefixFor(port) + "." + endpointHostOctet[name],
				source: prefixFor(port) + "." + sourceOctet,
			}
			switch {
			case name != "n6":
				ep.router, ep.egress = "rt_transport", transportGate
				transportGate++
			case firstN6:
				// The instance's one N6 hop resolves on the first N6
				// attachment; the others receive only.
				ep.router, ep.egress = "rt", 0
				firstN6 = false
			default:
				ep.router, ep.egress = "rt", extraN6Gate
				extraN6Gate++
			}
			out = append(out, ep)
		}
	}
	for _, name := range endpointOrder {
		if !seen[name] {
			return nil, fmt.Errorf("layout omits endpoint %s", name)
		}
	}
	return out, nil
}

// attachments is the named endpoint's attachments, in port order.
func attachments(eps []endpoint, name string) []endpoint {
	var out []endpoint
	for _, ep := range eps {
		if ep.name == name {
			out = append(out, ep)
		}
	}
	return out
}

// plan is what the compiler and the shell agree on for one layout: the local
// endpoint addresses, the scenarios' tunnel peers, and the N6 hop's peer.
type plan struct {
	local  scenario.Local
	peers  scenario.Peers
	n6Peer string
	// endMarker is the End Marker ports' base path (upfd -end-marker): the
	// compiler relays a received End Marker to <base>.<transport domain>.
	endMarker string
}

// planFor names each side's first and last attachment's host as the
// scenarios' two peers, so a layout that attaches an endpoint twice carries
// egress on both attachments; the one-VLAN layout gives N3 and N9 one local
// address, which only the endpoint id tells apart.
func planFor(cfg layout, eps []endpoint) plan {
	n3, n6, n9 := attachments(eps, "n3"), attachments(eps, "n6"), attachments(eps, "n9")
	p := plan{
		local: scenario.Local{N3: n3Local, N9: n9Local},
		peers: scenario.Peers{
			GNB: n3[0].source, GNB2: n3[len(n3)-1].source,
			UPF: n9[0].source, UPF2: n9[len(n9)-1].source,
		},
		n6Peer: n6[0].source,
	}
	if cfg.sameN3N9Addr {
		p.local.N9 = n3Local
	}
	return p
}

// compilerConfig is the deployment in the compiler's terms: the graph's module
// names and table fields, the egress table, and the two endpoints.
func compilerConfig(p plan) (session.Config, error) {
	prefix := netip.MustParsePrefix(pool)
	instances, err := routing.New([]routing.Interface{
		{
			Instance: internet, Domain: internetDomain, NextHop: hopN6,
			Pool: []netip.Prefix{prefix},
			Hops: map[routing.Egress]uint32{
				{DestIfc: ie.DstInterfaceCore}:               hopN6,
				{DestIfc: ie.DstInterfaceCore, Tunnel: true}: hopN9,
			},
		},
		{
			Instance: vn, Domain: vnDomain,
			Pool: []netip.Prefix{prefix},
			Hops: map[routing.Egress]uint32{{DestIfc: ie.DstInterface5GVNInternal}: hopVN},
		},
	}, maxDomains)
	if err != nil {
		return session.Config{}, err
	}
	n3, err := netip.ParseAddr(p.local.N3)
	if err != nil {
		return session.Config{}, err
	}
	n9, err := netip.ParseAddr(p.local.N9)
	if err != nil {
		return session.Config{}, err
	}
	return session.Config{
		GTPUDecap: "decap0",
		Up: session.Direction{
			PDRTable:  "pdr_ul",
			PDRFields: []session.Field{session.SrcIP, session.DstIP, session.Proto, session.SrcPort, session.DstPort, session.FTEIDContext, session.QFI},
			Meters:    "mt_ul", Counters: "cnt_ul", NextHop: hopN6, Tunnels: "enc",
		},
		Down: session.Direction{
			PDRTable:  "pdr_dl",
			PDRFields: []session.Field{session.SrcIP, session.DstIP, session.Proto, session.SrcPort, session.DstPort, session.RouteDomain, session.FTEIDContext, session.QFI},
			Meters:    "mt_dl", Counters: "cnt_dl", NextHop: hopAccess, Tunnels: "enc",
		},
		Instances:     instances,
		AccessNextHop: hopAccess,
		// The responder's End Marker log, drained by the report tick, and
		// the ports the relays leave by.
		GTPUEndMarkers: "echo0",
		EndMarker:      p.endMarker,
		FTEIDEndpoints: []session.FTEIDEndpoint{
			{ID: 1, ReferencePoint: "n3", TransportRouteDomain: 1, SourceInterface: ie.SrcInterfaceAccess, IPv4: n3},
			{ID: 2, ReferencePoint: "n9", TransportRouteDomain: 2, SourceInterface: ie.SrcInterfaceCore,
				Instance: internet, IPv4: n9},
		},
	}, nil
}

// upfdFlags is compilerConfig as `upfd -config` spells it (only the flags
// whose defaults differ), so a run of the daemon against the same graph is
// configured from the contract.
func upfdFlags(p plan) [][2]string {
	return [][2]string{
		{"gtpu-decap", "decap0"},
		{"gtpu-end-markers", "echo0"},
		{"end-marker", p.endMarker},
		{"urr-interval", "100ms"},
		{"max-domains", fmt.Sprint(maxDomains)},
		{"n6-next-hop", fmt.Sprint(hopN6)},
		{"n3-next-hop", fmt.Sprint(hopAccess)},
		{"access-next-hop", fmt.Sprint(hopAccess)},
		{"instances", fmt.Sprintf("name=%s,domain=%d,next-hop=%d,tunnel-next-hop=%d,pool=%s;name=%s,domain=%d,vn-next-hop=%d,pool=%s",
			internet, internetDomain, hopN6, hopN9, pool, vn, vnDomain, hopVN, pool)},
		{"fteid-address", fmt.Sprintf("endpoint=1,reference=n3,transport-domain=1,source=access,ipv4=%s;"+
			"endpoint=2,reference=n9,transport-domain=2,source=core,instance=%s,ipv4=%s",
			p.local.N3, internet, p.local.N9)},
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func be16(v uint16) []byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return b[:]
}

func be32(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}

func attr(name string, size int) map[string]any {
	return map[string]any{"attr_name": name, "num_bytes": size}
}

func rule(values [][]byte, gate uint32) map[string]any {
	fields := make([]map[string]any, 0, len(values))
	for _, value := range values {
		fields = append(fields, map[string]any{"value_bin": b64(value)})
	}
	return map[string]any{
		"key":   map[string]any{"fields": fields},
		"value": map[string]any{"gate": gate},
	}
}

func module(name, class string, arg map[string]any) map[string]any {
	return map[string]any{"name": name, "mclass": class, "arg": arg}
}

func wire(upstream, downstream string, gate *uint32) map[string]any {
	c := map[string]any{"upstream": upstream, "downstream": downstream}
	if gate != nil {
		c["ogate"] = *gate
	}
	return c
}

// matchFields is a PDR table's key: the inner IPv4 5-tuple, then the
// attributes the direction keys on (the shapes of deploy/upf.yaml).
func matchFields(attrs ...map[string]any) []map[string]any {
	return append([]map[string]any{
		{"offset": 26, "num_bytes": 4},
		{"offset": 30, "num_bytes": 4},
		{"offset": 23, "num_bytes": 1},
		{"offset": 34, "num_bytes": 2},
		{"offset": 36, "num_bytes": 2},
	}, attrs...)
}

// graphFor is the production path with the layout's ports in front. Per
// attachment: the Vif's gate (or, on a direct layout, the port's destination
// MAC) feeds a tag that writes the attachment's metadata, then an EtherType
// split: ARP replies from a peer go to the attachment's Router resolver and
// the Vif's own replies out of the port, IPv4 goes to route_check, which
// keys on the Vif's route domain and sends N3/N9 into decap0 and N6 into
// pdr_dl. route_check, endpoint_check and endpoint_check_dl are the lane's
// observation points, each a pass-through for traffic that is classified
// right. Out of the graph, every Router gate that serves an attachment goes
// to that attachment's port, through a VLANPush when the attachment is tagged.
func graphFor(cfg layout, eps []endpoint, p plan, ifaces []string) (map[string]any, error) {
	if len(ifaces) < len(cfg.groups) {
		return nil, fmt.Errorf("layout requires %d PMD interfaces, got %d", len(cfg.groups), len(ifaces))
	}
	ports := make([]map[string]any, 0, len(cfg.groups))
	// Decap and its reader first: metadata storage is laid out in module
	// registration order (deploy/upf.yaml).
	modules := []map[string]any{
		module("decap0", "GtpuDecap", map[string]any{}),
		module("mt_md", "MetadataTest", map[string]any{"read": map[string]any{"endpoint_id": 4, "fteid_context": 4, "qfi": 1}}),
	}
	var connections []map[string]any
	resources := map[string]any{}
	gate := func(g uint32) *uint32 { return &g }

	var rtIfaces, transportIfaces, transportNeighbors, transportRoutes []map[string]any
	for i := range cfg.groups {
		pname := fmt.Sprintf("p%d", i)
		ports = append(ports, map[string]any{
			"name": pname, "driver": "PMDPort", "num_rx_queues": 1, "num_tx_queues": 1,
			"arg": map[string]any{"vdev": fmt.Sprintf("net_af_packet%d,iface=%s,qpairs=1,fanout_mode=hash", i, ifaces[i])},
		})
		inc, out := fmt.Sprintf("inc%d", i), fmt.Sprintf("out%d", i)
		modules = append(modules,
			module(inc, "QueueInc", map[string]any{"port": pname, "qid": 0}),
			module(out, "PortOut", map[string]any{"port": pname}))

		// ingress is where each attachment's frames leave the port's
		// classifier.
		ingress := map[string]struct {
			module string
			gate   uint32
		}{}
		if cfg.direct {
			// A dedicated port still accepts only frames addressed to its
			// endpoint's MAC, as the Vif does in the shared layouts; anything
			// else the host emits on the link is unclassified.
			ep := attachmentOn(eps, i, cfg.groups[i][0])
			mac, err := net.ParseMAC(ep.mac)
			if err != nil {
				return nil, fmt.Errorf("endpoint %s has invalid MAC %q: %w", ep.name, ep.mac, err)
			}
			l2 := "l2_" + ep.name
			modules = append(modules, module(l2, "ExactMatch", map[string]any{
				"fields":       []map[string]any{{"offset": 0, "num_bytes": 6}},
				"default_gate": 0,
			}))
			resources[l2+"/rules"] = []map[string]any{rule([][]byte{mac}, 1)}
			connections = append(connections, wire(inc, l2, nil), wire(l2, "sink_unclassified", gate(0)))
			ingress[ep.name] = struct {
				module string
				gate   uint32
			}{l2, 1}
		} else {
			vifName := fmt.Sprintf("vif%d", i)
			interfaces := make([]map[string]any, 0, len(cfg.groups[i]))
			for _, name := range cfg.groups[i] {
				ep := attachmentOn(eps, i, name)
				interfaces = append(interfaces, map[string]any{
					"id": ep.gate, "vlan": ep.vlan, "mac_addr": ep.mac, "ip_addr": ep.ip,
					"route_domain": ep.domain, "gate": ep.gate,
				})
				ingress[name] = struct {
					module string
					gate   uint32
				}{vifName, ep.gate}
			}
			modules = append(modules, module(vifName, "Vif", map[string]any{
				"default_gate": 0, "interfaces": interfaces,
			}))
			connections = append(connections, wire(inc, vifName, nil), wire(vifName, "sink_unclassified", gate(0)))
		}

		for _, name := range cfg.groups[i] {
			ep := attachmentOn(eps, i, name)
			key := fmt.Sprintf("%s_p%d", ep.name, ep.port)
			ip := net.ParseIP(ep.ip).To4()
			if ip == nil {
				return nil, fmt.Errorf("endpoint %s has invalid IPv4 address %q", ep.name, ep.ip)
			}
			// The tag: the Router interface the attachment's ARP replies
			// arrive on (vif_id), the route domain the direct layout has no
			// Vif to write, and per kind what the production ingress writes.
			attrs := []map[string]any{
				{"name": "vif_id", "size": 4, "value_int": ep.egress + 1},
				{"name": "route_domain", "size": 4, "value_int": ep.domain},
			}
			if ep.id != 0 {
				attrs = append(attrs,
					map[string]any{"name": "endpoint_id", "size": 4, "value_int": ep.id},
					map[string]any{"name": "transport_route_domain", "size": 4, "value_int": ep.id})
			} else {
				// A plain N6 packet carries no tunnel: context 0 and QFI 0xff
				// match the N6 rules and never an F-TEID rule; the ARP branch
				// reaches rt with no PDR result.
				attrs = append(attrs,
					map[string]any{"name": "fteid_context", "size": 4, "value_int": 0},
					map[string]any{"name": "qfi", "size": 1, "value_int": 255},
					map[string]any{"name": "action_id", "size": 4, "value_int": 0},
					map[string]any{"name": "next_hop_id", "size": 4, "value_int": 0})
			}
			tag, eth, op, sender := "tag_"+key, "eth_"+key, "arpop_"+key, "arpsnd_"+key
			modules = append(modules,
				module(tag, "SetMetadata", map[string]any{"attrs": attrs}),
				module(eth, "ExactMatch", map[string]any{"fields": []map[string]any{{"offset": 12, "num_bytes": 2}}, "default_gate": 1}),
				module(op, "ExactMatch", map[string]any{"fields": []map[string]any{{"offset": 20, "num_bytes": 2}}, "default_gate": 0}),
				module(sender, "ExactMatch", map[string]any{"fields": []map[string]any{{"offset": 28, "num_bytes": 4}}, "default_gate": 1}),
			)
			resources[eth+"/rules"] = []map[string]any{rule([][]byte{be16(0x0806)}, 0)}
			resources[op+"/rules"] = []map[string]any{rule([][]byte{be16(2)}, 1)}
			resources[sender+"/rules"] = []map[string]any{rule([][]byte{ip}, 0)}

			// The attachment's way out: its port, tagged when it is.
			egress := out
			if ep.vlan != 0 {
				egress = "vlan_" + key
				modules = append(modules, module(egress, "VLANPush", map[string]any{"tci": ep.vlan}))
				connections = append(connections, wire(egress, out, nil))
			}
			in := ingress[name]
			connections = append(connections,
				wire(in.module, tag, gate(in.gate)),
				wire(tag, eth, nil),
				wire(eth, op, gate(0)),
				// N3/N9 and N6 ingress never share a module before the PDR
				// path: N3/N9 write endpoint_id and decap0 writes the F-TEID
				// context, while N6 writes its own fteid_context and qfi. One
				// shared check would put two writer scopes on one reader, and
				// BESS gives such a reader no offset.
				wire(eth, routeCheckOf(name), gate(1)),
				wire(op, "sink_other", gate(0)),
				wire(op, sender, gate(1)),
				wire(sender, egress, gate(0)),
				wire(sender, ep.router, gate(1)),
				wire(ep.router, egress, gate(ep.egress)),
			)
			iface := map[string]any{
				"id": ep.egress + 1, "egress_gate": ep.egress, "mac_addr": ep.mac,
				"addresses": []string{ep.ip + "/24"},
			}
			if ep.router == "rt" {
				rtIfaces = append(rtIfaces, iface)
				continue
			}
			transportIfaces = append(transportIfaces, iface)
			transportNeighbors = append(transportNeighbors, map[string]any{
				"key":   map[string]any{"id": ep.egress + 1},
				"value": map[string]any{"interface_id": ep.egress + 1, "ipv4": ep.source},
			})
			transportRoutes = append(transportRoutes, map[string]any{
				"key":   map[string]any{"ipv4": ep.source, "prefix_length": 32, "domain": ep.id},
				"value": map[string]any{"next_hop_id": ep.egress + 1},
			})
		}
	}

	pdrResults := func(meters string, steering bool) []map[string]any {
		r := []map[string]any{
			{"attr_name": "action_id", "value_offset": 0, "num_bytes": 4},
			{"attr_name": "meter_id", "value_offset": 4, "num_bytes": 8, "reference": meters + "/meters", "reference_key": "BE32", "reference_count": 2},
			{"attr_name": "next_hop_id", "value_offset": 12, "num_bytes": 4, "reference": "rt/next_hops", "reference_key": "BE32"},
			{"attr_name": "route_domain", "value_offset": 16, "num_bytes": 4},
		}
		if steering {
			r = append(r, map[string]any{"attr_name": "steering_policy_id", "value_offset": 20, "num_bytes": 4})
		}
		return r
	}
	// Neither Router re-solicits a resolved neighbor (reachable lifetime 0),
	// so after the warm-up the gates the lane counts carry only its packets.
	modules = append(modules,
		module("route_check", "ExactMatch", map[string]any{
			"fields": []map[string]any{attr("route_domain", 4)}, "default_gate": 0,
		}),
		module("route_check_n6", "ExactMatch", map[string]any{
			"fields": []map[string]any{attr("route_domain", 4)}, "default_gate": 0,
		}),
		module("endpoint_check", "ExactMatch", map[string]any{
			"fields": []map[string]any{attr("endpoint_id", 4)}, "default_gate": 0,
		}),
		module("endpoint_check_dl", "ExactMatch", map[string]any{
			"fields": []map[string]any{attr("endpoint_id", 4)}, "default_gate": 0,
		}),
		module("pdr_ul", "WildcardMatch", map[string]any{
			"fields":        matchFields(attr("fteid_context", 4), attr("qfi", 1)),
			"max_tuples":    16,
			"result_fields": pdrResults("mt_ul", false),
		}),
		module("pdr_dl", "WildcardMatch", map[string]any{
			"fields":        matchFields(attr("route_domain", 4), attr("fteid_context", 4), attr("qfi", 1)),
			"max_tuples":    8,
			"result_fields": pdrResults("mt_dl", true),
		}),
		module("mt_ul", "Meter", map[string]any{"capacity": 65536, "levels": 2}),
		module("cnt_ul", "UrrCount", map[string]any{"capacity": 65536}),
		module("mt_dl", "Meter", map[string]any{"capacity": 65536, "levels": 2}),
		module("cnt_dl", "UrrCount", map[string]any{"capacity": 65536}),
		module("atsss", "AtsssSteer", map[string]any{"policy_attr": "steering_policy_id", "next_hop_attr": "next_hop_id"}),
		module("rt", "Router", map[string]any{
			"interfaces":                     rtIfaces,
			"neighbor_reachable_lifetime_ms": 0,
		}),
		// The re-injection clears the F-TEID context (deploy/upf.yaml's
		// tag_vn): an N19 arrival's PDR is keyed by that context alone.
		module("tag_vn", "SetMetadata", map[string]any{"attrs": []map[string]any{
			{"name": "fteid_context", "size": 4, "value_int": 0},
		}}),
		module("enc", "GtpuEncap", map[string]any{"max_tunnels": 65536}),
		module("rt_transport", "Router", map[string]any{
			"mode":                           "ROUTE_MODE_DESTINATION",
			"max_domains":                    3,
			"max_ipv4_routes":                16,
			"domain_attr":                    "transport_route_domain",
			"interfaces":                     transportIfaces,
			"neighbor_reachable_lifetime_ms": 0,
		}),
		// The GTP-U responder behind decap gate 2, as deploy/upf.yaml's echo0:
		// it records the End Markers the report tick drains and relays. Its
		// replies (Error Indications for the unknown G-PDUs) end in
		// sink_unknown, as the unknown path did before it.
		module("echo0", "GtpuResponder", map[string]any{"track_end_markers": true}),
	)
	for _, name := range []string{"sink_unclassified", "sink_other", "sink_bad", "sink_unknown"} {
		modules = append(modules, module(name, "Sink", map[string]any{}))
	}
	// The End Marker ports, as deploy/upf.yaml's cp_marker_n3/cp_marker_n9:
	// one per transport domain (the endpoint id here), at <base>.<domain>,
	// tagged with the domain and its first attachment's Router interface and
	// routed by rt_transport like the encap's tunnels.
	for _, name := range []string{"n3", "n9"} {
		first := attachments(eps, name)[0]
		port, in, tag := "cp_marker_"+name, "cp_in_"+name, "set_marker_"+name
		ports = append(ports, map[string]any{
			"name": port, "driver": "UnixSocketPort",
			"arg": map[string]any{"path": fmt.Sprintf("%s.%d", p.endMarker, first.id)},
		})
		modules = append(modules,
			module(in, "PortInc", map[string]any{"port": port}),
			module(tag, "SetMetadata", map[string]any{"attrs": []map[string]any{
				{"name": "transport_route_domain", "size": 4, "value_int": first.id},
				{"name": "vif_id", "size": 4, "value_int": first.egress + 1},
			}}))
		connections = append(connections, wire(in, tag, nil), wire(tag, "rt_transport", nil))
	}
	connections = append(connections,
		wire("route_check", "sink_bad", gate(0)),
		wire("route_check", "decap0", gate(endpointGate["n3"])),
		wire("route_check", "decap0", gate(endpointGate["n9"])),
		wire("route_check_n6", "sink_bad", gate(0)),
		wire("route_check_n6", "pdr_dl", gate(endpointGate["n6"])),
		wire("decap0", "endpoint_check", gate(0)),
		wire("decap0", "endpoint_check_dl", gate(1)),
		wire("decap0", "echo0", gate(2)),
		wire("echo0", "sink_unknown", nil),
		wire("endpoint_check", "sink_bad", gate(0)),
		wire("endpoint_check", "mt_md", gate(1)),
		wire("endpoint_check", "mt_md", gate(2)),
		wire("endpoint_check_dl", "sink_bad", gate(0)),
		wire("endpoint_check_dl", "pdr_dl", gate(1)),
		wire("endpoint_check_dl", "pdr_dl", gate(2)),
		wire("mt_md", "pdr_ul", nil),
		wire("pdr_ul", "mt_ul", nil),
		wire("mt_ul", "cnt_ul", gate(0)),
		wire("mt_ul", "cnt_ul", gate(1)),
		wire("cnt_ul", "rt", nil),
		wire("pdr_dl", "mt_dl", nil),
		wire("mt_dl", "cnt_dl", gate(0)),
		wire("mt_dl", "cnt_dl", gate(1)),
		wire("cnt_dl", "atsss", nil),
		wire("atsss", "rt", nil),
		wire("rt", "enc", gate(hopAccess-1)),
		wire("rt", "enc", gate(hopN9-1)),
		wire("rt", "tag_vn", gate(hopVN-1)),
		wire("tag_vn", "pdr_dl", nil),
		wire("enc", "rt_transport", nil),
	)

	resources["route_check/rules"] = []map[string]any{
		rule([][]byte{be32(endpointDomain["n3"])}, endpointGate["n3"]),
		rule([][]byte{be32(endpointDomain["n9"])}, endpointGate["n9"]),
	}
	resources["route_check_n6/rules"] = []map[string]any{
		rule([][]byte{be32(endpointDomain["n6"])}, endpointGate["n6"]),
	}
	endpointRules := []map[string]any{rule([][]byte{be32(1)}, 1), rule([][]byte{be32(2)}, 2)}
	resources["endpoint_check/rules"] = endpointRules
	resources["endpoint_check_dl/rules"] = endpointRules
	// Production's shape (deploy/upf.yaml): the N6 hop is resolver-owned, bound
	// to the first N6 attachment's peer, while the access, N9 and 5G VN hops are
	// static gates. One PDR result column names both kinds through
	// rt/next_hops; BESS counts a bound id on rt/neighbors (D-187).
	resources["rt/next_hops"] = []map[string]any{
		{"key": map[string]any{"id": hopAccess}, "value": map[string]any{"egress_gate": hopAccess - 1}},
		{"key": map[string]any{"id": hopN9}, "value": map[string]any{"egress_gate": hopN9 - 1}},
		{"key": map[string]any{"id": hopVN}, "value": map[string]any{"egress_gate": hopVN - 1}},
	}
	resources["rt/neighbors"] = []map[string]any{
		{"key": map[string]any{"id": hopN6}, "value": map[string]any{"interface_id": 1, "ipv4": p.n6Peer}},
	}
	resources["rt_transport/neighbors"] = transportNeighbors
	resources["rt_transport/routes"] = transportRoutes
	return map[string]any{
		"ports":       ports,
		"modules":     modules,
		"connections": connections,
		"workers":     []map[string]any{{"wid": 0, "core": 0}},
		"resources":   resources,
	}, nil
}

// attachmentOn is the named endpoint's attachment to one port.
func attachmentOn(eps []endpoint, port int, name string) endpoint {
	for _, ep := range eps {
		if ep.port == port && ep.name == name {
			return ep
		}
	}
	panic(fmt.Sprintf("layout attaches no %s to port %d", name, port))
}

// packet is one row of a scenario phase's sends: a G-PDU to the endpoint's
// local address on each of its attachments (teid, inner source and
// destination), or plain UDP from each N6 attachment's host (src "-"). A
// G-PDU to an F-TEID the UP chose names it instead of a TEID: the driver
// writes the Created PDR's TEID to the handshake directory as
// teid-<chosen>, and the contract's teid column is @<chosen>.
type packet struct {
	phase, endpoint, kind string
	teid                  uint32
	src, dst              string
	sport, dport          uint16
	chosen                string
}

// The F-TEIDs Mode 6's forwarding PDRs are given (scenario.CreateForwarding):
// S10's from the source RAN, S13's from the source UPF.
const (
	chosenS10 = "s10fwd"
	chosenS13 = "s13fwd"
)

// packets is every scenario phase's sends, in ci/scenario's identities:
//
//	unknown  a TEID no session admits
//	m1ul/m1dl  Mode 1: S1's uplink; the data network's answer to S1's UE
//	m2ul     Mode 2: S8's two uplink branches, one TEID
//	m2dl     Mode 2: the remote PSA's downlink on S8's N9 F-TEID
//	m3ul/m3dl  Mode 3: S9's uplink on its N9 F-TEID (S1's TEID); its downlink
//	m4ul/m4dl  Mode 4: S11's uplink from the upstream I-UPF, and the PSA's
//	         downlink, both on the N9 endpoint
//	m5       Mode 5: S4's UE to S5's, re-injected
//	n19in    N19: the other PSA's member to S5's UE on S12's N19 F-TEID
//	n19out   N19: S4's UE to the other PSA's member, through S12
//	m6ul/m6dl  Mode 6: S10's and S13's uplinks; S10's downlink from the PSA
//	m6t      Mode 6: S13's downlink from the PSA (held, then to the target RAN)
//	m6fwd    Mode 6: forwarded downlink on S10's and S13's chosen F-TEIDs
//	m6gone   Mode 6: S10's and the forwarding F-TEIDs after the release
//	m6em     End Markers (kind em, TS 29.281 7.3.2), between the target's
//	         switch and the timer: the PSA's on S10's N9 F-TEID, the source
//	         RAN's and the source UPF's on the two forwarding F-TEIDs, the
//	         PSA's on S11's N9 downlink F-TEID (Mode 4), and one on S1's
//	         uplink F-TEID, whose FAR ends at N6
func packets() []packet {
	return []packet{
		{"unknown", "n3", "gpdu", unknownTEID, scenario.UE1, dataNetwork, 40000, 53, ""},
		{"m1ul", "n3", "gpdu", scenario.UpTEID1, scenario.UE1, dataNetwork, 40000, 53, ""},
		{"m1dl", "n6", "udp", 0, "-", scenario.UE1, 5000, 53, ""},
		{"m2ul", "n3", "gpdu", scenario.UpTEID8, scenario.UE8, dataNetwork, 40000, 53, ""},
		{"m2ul", "n3", "gpdu", scenario.UpTEID8, scenario.UE8, scenario.ULCLBranch, 40000, 53, ""},
		{"m2dl", "n9", "gpdu", scenario.CoreTEID8, scenario.ULCLBranch, scenario.UE8, 53, 5000, ""},
		{"m3ul", "n9", "gpdu", scenario.UpTEID9, scenario.UE9, dataNetwork, 40000, 53, ""},
		{"m3dl", "n6", "udp", 0, "-", scenario.UE9, 5000, 53, ""},
		{"m4ul", "n9", "gpdu", scenario.UpTEID11, scenario.UE11, dataNetwork, 40000, 53, ""},
		{"m4dl", "n9", "gpdu", scenario.CoreTEID11, dataNetwork, scenario.UE11, 5000, 53, ""},
		{"m5", "n3", "gpdu", scenario.UpTEID4, scenario.UE4, scenario.UE5, 5000, 5000, ""},
		{"n19in", "n9", "gpdu", scenario.N19TEID, scenario.RemoteUE, scenario.UE5, 5000, 5000, ""},
		{"n19out", "n3", "gpdu", scenario.UpTEID4, scenario.UE4, scenario.RemoteUE, 5000, 5000, ""},
		{"m6ul", "n3", "gpdu", scenario.UpTEID10, scenario.UE10, dataNetwork, 40000, 53, ""},
		{"m6ul", "n3", "gpdu", scenario.UpTEID13, scenario.UE13, dataNetwork, 40000, 53, ""},
		{"m6dl", "n9", "gpdu", scenario.CoreTEID10, dataNetwork, scenario.UE10, 5000, 53, ""},
		{"m6t", "n9", "gpdu", scenario.CoreTEID13, dataNetwork, scenario.UE13, 5000, 53, ""},
		{"m6fwd", "n3", "gpdu", 0, dataNetwork, scenario.UE10, 5000, 53, chosenS10},
		{"m6fwd", "n3", "gpdu", 0, dataNetwork, scenario.UE13, 5000, 53, chosenS13},
		{"m6gone", "n3", "gpdu", 0, dataNetwork, scenario.UE10, 5000, 53, chosenS10},
		{"m6gone", "n3", "gpdu", 0, dataNetwork, scenario.UE13, 5000, 53, chosenS13},
		{"m6gone", "n3", "gpdu", scenario.UpTEID10, scenario.UE10, dataNetwork, 40000, 53, ""},
		{"m6gone", "n9", "gpdu", scenario.CoreTEID10, dataNetwork, scenario.UE10, 5000, 53, ""},
		{"m6em", "n9", "em", scenario.CoreTEID10, "-", "-", 0, 0, ""},
		{"m6em", "n3", "em", 0, "-", "-", 0, 0, chosenS10},
		{"m6em", "n3", "em", 0, "-", "-", 0, 0, chosenS13},
		{"m6em", "n9", "em", scenario.CoreTEID11, "-", "-", 0, 0, ""},
		{"m6em", "n3", "em", scenario.UpTEID1, "-", "-", 0, 0, ""},
	}
}

// relays are the End Markers the m6em phase must see leave relayed: the
// endpoint the marker arrives on, the outgoing tunnel's TEID, the local
// endpoint that tunnel is sourced from, and the egress it takes to its peer
// (TS 23.502 4.9.1.3.3 step 10b; TS 29.244 Table 8.2.64-1 NOTE 2). S1's
// marker has none.
var relays = []struct {
	in    string
	teid  uint32
	local string
	label string
}{
	{"n9", scenario.DLTEID10, "n3", "s10dl"},          // the PSA's, from S10 toward the source RAN
	{"n3", scenario.ForwardTEID, "n3", "m6fwd"},       // S10's forwarding tunnel, toward the target UPF
	{"n3", scenario.TargetForwardTEID, "n3", "m6fwd"}, // S13's, toward the target RAN
	{"n9", scenario.DLTEID11, "n9", "s11dl"},          // Mode 4, toward the upstream I-UPF over N9
}

// writeContract is the shell's view of the layout, one tab-separated row
// each:
//
//	ports     <count>
//	endpoint  <name> <port> <vlan> <mac> <ip> <domain> <id> <host> <router> <gate>
//	local     <n3|n9> <address>
//	egress    <label> <endpoint> <host>   (the attachment a scenario's egress takes)
//	packet    <phase> <endpoint> <gpdu|udp|em> <teid|@chosen> <src> <dst> <sport> <dport>
//	relay     <arrival endpoint> <teid> <local endpoint> <egress label>
//	upfd      <flag> <value>
func writeContract(path string, groups [][]string, eps []endpoint, p plan) error {
	var b strings.Builder
	fmt.Fprintf(&b, "ports\t%d\n", len(groups))
	for _, ep := range eps {
		fmt.Fprintf(&b, "endpoint\t%s\t%d\t%d\t%s\t%s\t%d\t%d\t%s\t%s\t%d\n",
			ep.name, ep.port, ep.vlan, ep.mac, ep.ip, ep.domain, ep.id, ep.source, ep.router, ep.egress)
	}
	fmt.Fprintf(&b, "local\tn3\t%s\nlocal\tn9\t%s\n", p.local.N3, p.local.N9)
	for _, e := range [][3]string{
		{"n6hop", "n6", p.n6Peer},
		{"s1dl", "n3", p.peers.GNB},
		{"s8n9", "n9", p.peers.UPF},
		{"s8dl", "n3", p.peers.GNB2},
		{"s9dl", "n9", p.peers.UPF2},
		{"s5dl", "n3", p.peers.GNB},
		{"s11n9", "n9", p.peers.UPF},
		{"s11dl", "n9", p.peers.UPF2},
		{"s12n19", "n9", p.peers.UPF},
		{"s10n9", "n9", p.peers.UPF},
		{"s10dl", "n3", p.peers.GNB},
		{"s13dl", "n3", p.peers.GNB2},
		{"m6fwd", "n3", p.peers.GNB2},
	} {
		fmt.Fprintf(&b, "egress\t%s\t%s\t%s\n", e[0], e[1], e[2])
	}
	for _, k := range packets() {
		teid := fmt.Sprint(k.teid)
		if k.chosen != "" {
			teid = "@" + k.chosen
		}
		fmt.Fprintf(&b, "packet\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\n",
			k.phase, k.endpoint, k.kind, teid, k.src, k.dst, k.sport, k.dport)
	}
	for _, r := range relays {
		fmt.Fprintf(&b, "relay\t%s\t%#x\t%s\t%s\n", r.in, r.teid, r.local, r.label)
	}
	for _, f := range upfdFlags(p) {
		fmt.Fprintf(&b, "upfd\t%s\t%s\n", f[0], f[1])
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// drive is the compiler for one layout: every permitted mode's sessions
// first, each established over N4 (scenario.Serve), both Routers resolved,
// then the shell's phases. Mode 6 runs on S10 and S13, their own sessions, so
// the other modes stay steady throughout.
func drive(name, target, handshake, endMarker string) error {
	cfg, err := layoutFor(name)
	if err != nil {
		return err
	}
	eps, err := makeEndpoints(cfg)
	if err != nil {
		return err
	}
	p := planFor(cfg, eps)
	p.endMarker = endMarker
	ccfg, err := compilerConfig(p)
	if err != nil {
		return err
	}
	ctx := context.Background()
	client, err := bess.Dial(ctx, target)
	if err != nil {
		return fmt.Errorf("dialing %s: %w", target, err)
	}
	defer client.Close()
	if err := client.Refresh(ctx); err != nil {
		return fmt.Errorf("reading the daemon's schema: %w", err)
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	smf, stop, err := scenario.Serve(session.New(ccfg, client, log), log)
	if err != nil {
		return err
	}
	defer stop()

	seids := map[uint64]uint64{}
	for _, m := range scenario.Modes(p.peers) {
		for _, s := range m.Sessions {
			seid, err := scenario.Establish(smf, s, p.local)
			if err != nil {
				return fmt.Errorf("mode %d: %w", m.Number, err)
			}
			seids[s.SEID] = seid
			fmt.Printf("vethlayout: established: Mode %d (%s): %s (SEID %d)\n", m.Number, m.Name, s.Name, seid)
		}
	}
	if err := awaitNeighbors(ctx, client, map[string]int{
		"rt":           1, // the N6 hop
		"rt_transport": len(eps) - len(attachments(eps, "n6")),
	}); err != nil {
		return err
	}
	// The shell drives Modes 1 to 5, N19, and Mode 6's steady state (S13's
	// downlink held) with every session above live.
	const within = 5 * time.Minute
	if err := scenario.Pass(handshake, "established", within); err != nil {
		return err
	}

	// Mode 6 preparation (TS 23.502 4.9.1.3.2): 11b at the target UPF (S13),
	// then 11d at the source UPF (S10), each answering the F-TEID it chose.
	seid10, seid13 := seids[scenario.SEID10], seids[scenario.SEID13]
	for _, f := range []struct {
		step, chosen string
		seid         uint64
		teid         uint32
	}{
		{"11b: S13's forwarding tunnel to the target RAN", chosenS13, seid13, scenario.TargetForwardTEID},
		{"11d: S10's forwarding tunnel to the target UPF", chosenS10, seid10, scenario.ForwardTEID},
	} {
		resp, err := scenario.Modify(smf, scenario.CreateForwarding(f.seid, internet, f.teid, p.peers.GNB2), "Mode 6 "+f.step)
		if err != nil {
			return err
		}
		teid, addr, err := scenario.Forwarding(resp)
		if err != nil {
			return fmt.Errorf("Mode 6 %s: %w", f.step, err)
		}
		// The forwarding PDR is typed N3 for data forwarding: its F-TEID is
		// the N3 endpoint's, where the forwarded downlink arrives.
		if addr != p.local.N3 {
			return fmt.Errorf("Mode 6 %s: the UP chose an F-TEID on %s, want the N3 endpoint %s", f.step, addr, p.local.N3)
		}
		if handshake != "" {
			if err := os.WriteFile(filepath.Join(handshake, "teid-"+f.chosen), []byte(fmt.Sprint(teid)), 0o644); err != nil {
				return err
			}
		}
		fmt.Printf("vethlayout: Mode 6 %s: the UP chose F-TEID %#x on %s\n", f.step, teid, addr)
	}
	// Execution (4.9.1.3.3): step 3b's forwarding, then 8a.
	if err := scenario.Pass(handshake, "forward", within); err != nil {
		return err
	}
	if _, err := scenario.Modify(smf, scenario.SwitchDownlink(seid13, scenario.DLTEID13, p.peers.GNB2),
		"Mode 6 8a: S13's downlink to the target RAN"); err != nil {
		return err
	}
	// Step 11: the SMF starts its indirect data forwarding timer.
	expiry := time.Now().Add(scenario.ForwardingTimer)
	fmt.Println("vethlayout: Mode 6 8a: S13's downlink FAR forwards to the target RAN; the forwarding timer started")
	if err := scenario.Pass(handshake, "switched", within); err != nil {
		return err
	}
	// The SMF's indirect data forwarding timer: 13a releases the source UPF's
	// session, 15a the target UPF's forwarding resources.
	time.Sleep(time.Until(expiry))
	if err := scenario.Release(smf, seid10, "Mode 6 13a: releasing S10"); err != nil {
		return err
	}
	if _, err := scenario.Modify(smf, scenario.ReleaseForwarding(seid13), "Mode 6 15a: releasing S13's forwarding PDR and FAR"); err != nil {
		return err
	}
	fmt.Println("vethlayout: Mode 6: timer expired; S10 released (13a), S13's forwarding resources removed (15a)")
	// The shell checks the release and replays every earlier phase: no later
	// session or modification may have overwritten an earlier one.
	if err := scenario.Pass(handshake, "released", within); err != nil {
		return err
	}
	fmt.Println("vethlayout: every mode's sessions were held live to the end: 1, 2, 3, 4, 5 with N19, 6")
	return nil
}

// awaitNeighbors waits until each Router's resolver reports the expected
// number of bound neighbors, all resolved (its get_neighbors action; a bound
// next hop is not in <router>/next_hops, BESS D-183): rt's N6 hop and one per
// N3/N9 attachment on rt_transport. The shell measures exact counts only after
// this, so no packet of its is dropped for an unresolved neighbor.
func awaitNeighbors(ctx context.Context, client *bess.Client, want map[string]int) error {
	const resolved = "ROUTER_NEIGHBOR_STATE_RESOLVED"
	deadline := time.Now().Add(30 * time.Second)
	for {
		var pending []string
		var readErr error
		got := make(map[string]map[uint32]string, len(want))
		for module, n := range want {
			states, err := neighborStates(ctx, client, module)
			if err != nil {
				readErr = err
				pending = append(pending, module+": unread")
				continue
			}
			got[module] = states
			if len(states) != n {
				pending = append(pending, fmt.Sprintf("%s: %d of %d bound", module, len(states), n))
			}
			for id, state := range states {
				if state != resolved {
					pending = append(pending, fmt.Sprintf("%s %d: %s", module, id, state))
				}
			}
		}
		if len(pending) == 0 {
			fmt.Printf("vethlayout: neighbors resolved: %v\n", got)
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("neighbors unresolved after 30s: %v (read error: %v)", pending, readErr)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// neighborStates is a Router's get_neighbors answer as next-hop id -> state
// name, read through the daemon's own schema.
func neighborStates(ctx context.Context, client *bess.Client, module string) (map[uint32]string, error) {
	arg, err := client.Message("bess.pb.EmptyArg", nil)
	if err != nil {
		return nil, err
	}
	result, err := client.SDK().InvokeAction(ctx, module, "get_neighbors", arg)
	if err != nil {
		return nil, err
	}
	response, err := client.Message("bess.pb.RouterCommandGetNeighborsResponse", nil)
	if err != nil {
		return nil, err
	}
	if err := result.UnmarshalTo(response); err != nil {
		return nil, err
	}
	list := response.ProtoReflect().Get(response.ProtoReflect().Descriptor().Fields().ByName("neighbors")).List()
	out := make(map[uint32]string, list.Len())
	for i := range list.Len() {
		entry := list.Get(i).Message()
		fields := entry.Descriptor().Fields()
		state := fields.ByName("state")
		id := uint32(entry.Get(fields.ByName("next_hop_id")).Uint())
		out[id] = string(state.Enum().Values().ByNumber(entry.Get(state).Enum()).Name())
	}
	return out, nil
}

// routeCheckOf is the check module an endpoint's ingress enters: the tunnel
// endpoints' (toward decap0) or N6's (toward pdr_dl), kept apart by writer scope.
func routeCheckOf(name string) string {
	if name == "n6" {
		return "route_check_n6"
	}
	return "route_check"
}

func checksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// payload is every packet's own bytes.
var payload = []byte("veth-layout")

func gpdu(teid uint32, ue, dst string, sport, dport uint16) ([]byte, error) {
	src := net.ParseIP(ue).To4()
	dstIP := net.ParseIP(dst).To4()
	if src == nil || dstIP == nil {
		return nil, fmt.Errorf("inner addresses must be IPv4: %q -> %q", ue, dst)
	}
	innerLen := 20 + 8 + len(payload)
	inner := make([]byte, innerLen)
	inner[0] = 0x45
	binary.BigEndian.PutUint16(inner[2:4], uint16(innerLen))
	binary.BigEndian.PutUint16(inner[4:6], 1)
	binary.BigEndian.PutUint16(inner[6:8], 0x4000)
	inner[8] = 64
	inner[9] = 17
	copy(inner[12:16], src)
	copy(inner[16:20], dstIP)
	binary.BigEndian.PutUint16(inner[10:12], checksum(inner[:20]))
	udp := inner[20:]
	binary.BigEndian.PutUint16(udp[0:2], sport)
	binary.BigEndian.PutUint16(udp[2:4], dport)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)

	packet := make([]byte, 8+len(inner))
	packet[0], packet[1] = 0x30, 0xff
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(inner)))
	binary.BigEndian.PutUint32(packet[4:8], teid)
	copy(packet[8:], inner)
	return packet, nil
}

// dialFrom is a UDP socket bound to one device and source: the host's route
// for the destination is the one on that device, so a send leaves by the
// attachment the shell names even when another device reaches the same
// address.
func dialFrom(device, local string, sport uint16, remote string, rport uint16) (net.Conn, error) {
	if device == "" {
		return nil, errors.New("a device is required")
	}
	localIP := net.ParseIP(local).To4()
	remoteIP := net.ParseIP(remote).To4()
	if localIP == nil || remoteIP == nil {
		return nil, fmt.Errorf("local and remote must be IPv4 addresses: %q, %q", local, remote)
	}
	dialer := net.Dialer{
		LocalAddr: &net.UDPAddr{IP: localIP, Port: int(sport)},
		Control: func(_, _ string, raw syscall.RawConn) error {
			var socketErr error
			if err := raw.Control(func(fd uintptr) {
				socketErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, device)
			}); err != nil {
				return err
			}
			return socketErr
		},
	}
	return dialer.Dial("udp4", net.JoinHostPort(remoteIP.String(), fmt.Sprint(rport)))
}

func sendCount(conn net.Conn, b []byte, count int) error {
	defer conn.Close()
	if count < 1 {
		return errors.New("count must be positive")
	}
	for range count {
		if _, err := conn.Write(b); err != nil {
			return err
		}
		time.Sleep(2 * time.Millisecond)
	}
	return nil
}

func sendGPDU(device, local, remote, ue, dst string, teid uint32, sport, dport uint16, count int) error {
	b, err := gpdu(teid, ue, dst, sport, dport)
	if err != nil {
		return err
	}
	conn, err := dialFrom(device, local, 0, remote, 2152)
	if err != nil {
		return err
	}
	return sendCount(conn, b, count)
}

func sendUDP(device, local, dst string, sport, dport uint16, count int) error {
	conn, err := dialFrom(device, local, sport, dst, dport)
	if err != nil {
		return err
	}
	return sendCount(conn, payload, count)
}

// sendEndMarker sends End Markers (TS 29.281 7.3.2) on teid to a local
// endpoint, as the old path's sender ends its tunnel.
func sendEndMarker(device, local, remote string, teid uint32, count int) error {
	conn, err := dialFrom(device, local, 0, remote, 2152)
	if err != nil {
		return err
	}
	return sendCount(conn, scenario.EndMarker(teid), count)
}

// sinkUDP holds the GTP-U port open on the host: the graph tunnels every
// scenario's egress to the peers' addresses, and a port with no socket would
// answer each with an ICMP error that re-enters the graph's unknown path. A
// port another process already holds is absorbed by that process. Beside it,
// printGTPU prints the End Markers the graph relays.
func sinkUDP(port int) error {
	errc := make(chan error, 2)
	go func() { errc <- printGTPU(port) }()
	conn, err := net.ListenPacket("udp4", fmt.Sprintf(":%d", port))
	if errors.Is(err, syscall.EADDRINUSE) {
		fmt.Fprintf(os.Stderr, "vethlayout: UDP %d is already bound; its owner absorbs the lane's tunnels\n", port)
		return <-errc
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	go func() {
		buf := make([]byte, 65536)
		for {
			if _, _, err := conn.ReadFrom(buf); err != nil {
				errc <- err
				return
			}
		}
	}()
	return <-errc
}

// printGTPU prints every GTP-U message other than a G-PDU that arrives
// addressed to the host on port -- the End Markers the graph relays -- with its
// type, TEID and outer addresses, one line each, for the shell to count. It
// reads an IPv4 packet socket, ahead of the host's firewall, which may drop
// the datagram before the UDP socket sees it; frames the host sends are not
// delivered to it.
func printGTPU(port int) error {
	const ethPIP = syscall.ETH_P_IP>>8 | syscall.ETH_P_IP&0xff<<8 // network order
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, ethPIP)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	buf := make([]byte, 65536)
	for {
		n, from, err := syscall.Recvfrom(fd, buf, 0)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		ll, ok := from.(*syscall.SockaddrLinklayer)
		if !ok || ll.Pkttype != syscall.PACKET_HOST || n < 20 || buf[0]>>4 != 4 || buf[9] != syscall.IPPROTO_UDP {
			continue
		}
		ihl := int(buf[0]&0x0f) * 4
		if n < ihl+16 || binary.BigEndian.Uint16(buf[ihl+2:]) != uint16(port) || buf[ihl+9] == 0xff {
			continue
		}
		fmt.Printf("vethlayout: sink: GTP-U type %d TEID %#x from %s to %s\n",
			buf[ihl+9], binary.BigEndian.Uint32(buf[ihl+12:]), net.IP(buf[12:16]), net.IP(buf[16:20]))
	}
}

func run() error {
	layoutName := flag.String("layout", "", "topology layout to generate or drive")
	ifacesFlag := flag.String("ifaces", "", "comma-separated PMD interface names")
	contract := flag.String("contract", "", "write the shell test contract here")
	portCount := flag.Bool("port-count", false, "print the layout's PMD port count and exit")
	driveMode := flag.Bool("drive", false, "establish every permitted mode's sessions on -target and run the phases")
	target := flag.String("target", "127.0.0.1:10514", "bessd's control_v2 gRPC address, for -drive")
	handshake := flag.String("handshake", "", "directory of the phase handshake with the shell, for -drive")
	send := flag.Bool("send-gpdu", false, "send G-PDUs instead of generating a graph")
	sendPlain := flag.Bool("send-udp", false, "send plain UDP datagrams instead of generating a graph")
	sendMarker := flag.Bool("send-end-marker", false, "send End Markers on -teid to -remote instead of generating a graph")
	sink := flag.Int("sink-udp", 0, "hold this UDP port open and print every GTP-U message that is not a G-PDU")
	endMarker := flag.String("end-marker", "", "the End Marker ports' base path (upfd -end-marker), for the graph and -drive")
	device := flag.String("device", "", "interface the sends are bound to")
	local := flag.String("local", "", "local IPv4 address of the sends")
	remote := flag.String("remote", "", "outer IPv4 destination of -send-gpdu (a local endpoint)")
	ue := flag.String("ue", scenario.UE1, "inner IPv4 source of -send-gpdu")
	dst := flag.String("dst", dataNetwork, "inner IPv4 destination of -send-gpdu, destination of -send-udp")
	sport := flag.Uint("sport", 40000, "UDP source port of the inner (or plain) datagram")
	dport := flag.Uint("dport", 53, "UDP destination port of the inner (or plain) datagram")
	teid := flag.Uint("teid", scenario.UpTEID1, "GTP-U TEID")
	count := flag.Int("count", 1, "number of packets to send")
	flag.Parse()
	switch {
	case *send:
		return sendGPDU(*device, *local, *remote, *ue, *dst, uint32(*teid), uint16(*sport), uint16(*dport), *count)
	case *sendPlain:
		return sendUDP(*device, *local, *dst, uint16(*sport), uint16(*dport), *count)
	case *sendMarker:
		return sendEndMarker(*device, *local, *remote, uint32(*teid), *count)
	case *sink != 0:
		return sinkUDP(*sink)
	case *driveMode:
		return drive(*layoutName, *target, *handshake, *endMarker)
	}
	cfg, err := layoutFor(*layoutName)
	if err != nil {
		return err
	}
	if *portCount {
		_, err := fmt.Println(len(cfg.groups))
		return err
	}
	eps, err := makeEndpoints(cfg)
	if err != nil {
		return err
	}
	p := planFor(cfg, eps)
	p.endMarker = *endMarker
	ifaces := strings.Split(*ifacesFlag, ",")
	if len(ifaces) == 1 && ifaces[0] == "" {
		ifaces = nil
	}
	g, err := graphFor(cfg, eps, p, ifaces)
	if err != nil {
		return err
	}
	if *contract != "" {
		if err := writeContract(*contract, cfg.groups, eps, p); err != nil {
			return err
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(g)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "vethlayout:", err)
		os.Exit(1)
	}
}
