// SPDX-License-Identifier: BSD-3-Clause

// Command vethlayout generates the small BESS graph used by ci/veth-layouts.sh.
// It also sends valid GTP-U packets so the fixture exercises endpoint-tagged
// admission through real AF_PACKET PMD ports, not only the Vif's output gates.
package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
)

const testTEID uint32 = 0x11223344

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
var endpointDomain = map[string]uint32{"n3": 1, "n9": 2, "n6": 3}
var endpointGate = map[string]uint32{"n3": 1, "n9": 2, "n6": 3}
var endpointID = map[string]uint32{"n3": 1, "n9": 2}
var endpointMAC = map[string]string{
	"n3": "02:00:00:00:03:01",
	"n6": "02:00:00:00:06:01",
	"n9": "02:00:00:00:09:01",
}
var endpointHostOctet = map[string]string{"n3": "101", "n6": "103", "n9": "102"}
var testPrefixes = []string{"192.0.2", "198.51.100", "203.0.113"}

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
	default:
		return layout{}, fmt.Errorf("unknown layout %q", name)
	}
}

func makeEndpoints(cfg layout) ([]endpoint, error) {
	portFor := make(map[string]int, len(endpointOrder))
	for port, group := range cfg.groups {
		for _, name := range group {
			portFor[name] = port
		}
	}
	for _, name := range endpointOrder {
		if _, ok := portFor[name]; !ok {
			return nil, fmt.Errorf("layout omits endpoint %s", name)
		}
	}

	out := make([]endpoint, 0, len(endpointOrder))
	for index, name := range endpointOrder {
		port := portFor[name]
		prefix := testPrefixes[port]
		ipOctet := endpointHostOctet[name]
		if cfg.sameN3N9Addr && (name == "n3" || name == "n9") {
			ipOctet = "101"
		}
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
		out = append(out, endpoint{
			name:   name,
			id:     endpointID[name],
			domain: endpointDomain[name],
			gate:   endpointGate[name],
			port:   port,
			vlan:   cfg.vlans[name],
			mac:    mac,
			ip:     prefix + "." + ipOctet,
			source: prefix + "." + sourceOctet,
		})
	}
	return out, nil
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

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

func graphFor(cfg layout, eps []endpoint, ifaces []string) (map[string]any, error) {
	if len(ifaces) < len(cfg.groups) {
		return nil, fmt.Errorf("layout requires %d PMD interfaces, got %d", len(cfg.groups), len(ifaces))
	}

	ports := make([]map[string]any, 0, len(cfg.groups))
	modules := make([]map[string]any, 0, len(cfg.groups)+16)
	connections := make([]map[string]any, 0, 24)
	resources := map[string]any{}
	for i := range cfg.groups {
		pname := fmt.Sprintf("p%d", i)
		ports = append(ports, map[string]any{
			"name": pname, "driver": "PMDPort", "num_rx_queues": 1, "num_tx_queues": 1,
			"arg": map[string]any{"vdev": fmt.Sprintf("net_af_packet%d,iface=%s,qpairs=1,fanout_mode=hash", i, ifaces[i])},
		})
		inc := fmt.Sprintf("inc%d", i)
		modules = append(modules, module(inc, "QueueInc", map[string]any{"port": pname, "qid": 0}))
		if cfg.direct {
			// A dedicated port still accepts only frames addressed to its
			// endpoint's MAC, as the Vif does in the shared layouts; anything
			// else the host emits on the link is unclassified, not tagged.
			ep := endpointByName(eps, cfg.groups[i][0])
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
			tag := "port_tag_" + ep.name
			attrs := []map[string]any{{"name": "route_domain", "size": 4, "value_int": ep.domain}}
			if ep.id != 0 {
				attrs = append(attrs, map[string]any{"name": "endpoint_id", "size": 4, "value_int": ep.id})
			}
			modules = append(modules, module(tag, "SetMetadata", map[string]any{"attrs": attrs}))
			connections = append(connections, wire(inc, l2, nil),
				wire(l2, "sink_unclassified", new(uint32(0))), wire(l2, tag, new(uint32(1))),
				wire(tag, "route_check", nil))
			continue
		}
		vifName := fmt.Sprintf("vif%d", i)
		interfaces := make([]map[string]any, 0, len(cfg.groups[i]))
		for _, name := range cfg.groups[i] {
			ep := endpointByName(eps, name)
			interfaces = append(interfaces, map[string]any{
				"id": ep.gate, "vlan": ep.vlan, "mac_addr": ep.mac, "ip_addr": ep.ip,
				"route_domain": ep.domain, "gate": ep.gate,
			})
		}
		modules = append(modules, module(vifName, "Vif", map[string]any{
			"default_gate": 0, "interfaces": interfaces,
		}))
		connections = append(connections, wire(inc, vifName, nil), wire(vifName, "sink_unclassified", new(uint32(0))))
		for _, name := range cfg.groups[i] {
			ep := endpointByName(eps, name)
			connections = append(connections, wire(vifName, "route_check", new(ep.gate)))
		}
	}

	modules = append(modules,
		module("route_check", "ExactMatch", map[string]any{
			"fields": []map[string]any{attr("route_domain", 4)}, "default_gate": 0,
		}),
		module("tag_n3", "SetMetadata", map[string]any{"attrs": []map[string]any{
			{"name": "endpoint_id", "size": 4, "value_int": uint32(1)},
		}}),
		module("tag_n9", "SetMetadata", map[string]any{"attrs": []map[string]any{
			{"name": "endpoint_id", "size": 4, "value_int": uint32(2)},
		}}),
		module("decap", "GtpuDecap", map[string]any{}),
		module("endpoint_check", "ExactMatch", map[string]any{
			"fields":       []map[string]any{attr("endpoint_id", 4), attr("fteid_context", 4)},
			"default_gate": 0,
		}),
	)
	for _, name := range []string{"sink_unclassified", "sink_bad", "sink_n6", "sink_n3", "sink_n9", "sink_unknown"} {
		modules = append(modules, module(name, "Sink", map[string]any{}))
	}

	connections = append(connections,
		wire("route_check", "sink_bad", new(uint32(0))),
		wire("route_check", "tag_n3", new(uint32(1))),
		wire("route_check", "tag_n9", new(uint32(2))),
		wire("route_check", "sink_n6", new(uint32(3))),
		wire("tag_n3", "decap", nil),
		wire("tag_n9", "decap", nil),
		wire("decap", "endpoint_check", new(uint32(0))),
		wire("decap", "sink_unknown", new(uint32(1))),
		wire("decap", "sink_unknown", new(uint32(2))),
		wire("endpoint_check", "sink_bad", new(uint32(0))),
		wire("endpoint_check", "sink_n3", new(uint32(1))),
		wire("endpoint_check", "sink_n9", new(uint32(2))),
	)

	routeRules := make([]map[string]any, 0, len(eps))
	fteids := make([]map[string]any, 0, 2)
	// Each endpoint's row for the shared testTEID carries its own context id,
	// so the same TEID on two endpoints reaches two distinct check rules.
	endpointRules := []map[string]any{
		rule([][]byte{be32(1), be32(fteidContext(1))}, 1),
		rule([][]byte{be32(2), be32(fteidContext(2))}, 2),
	}
	for _, ep := range eps {
		routeRules = append(routeRules, rule([][]byte{be32(ep.domain)}, ep.gate))
		if ep.id == 0 {
			continue
		}
		ip := net.ParseIP(ep.ip).To4()
		if ip == nil {
			return nil, fmt.Errorf("endpoint %s has invalid IPv4 address %q", ep.name, ep.ip)
		}
		fteids = append(fteids, map[string]any{
			"key": map[string]any{
				"endpoint_id": ep.id, "address_family": 4, "local_address": b64(ip), "teid": testTEID,
			},
			"value": map[string]any{"direction": 0, "context_id": fteidContext(ep.id)},
		})
	}

	resources["route_check/rules"] = routeRules
	resources["decap/fteids"] = fteids
	resources["endpoint_check/rules"] = endpointRules
	return map[string]any{
		"ports":       ports,
		"modules":     modules,
		"connections": connections,
		"workers":     []map[string]any{{"wid": 0, "core": 0}},
		"resources":   resources,
	}, nil
}

// fteidContext is the admission context id the lane assigns to endpoint id's
// testTEID row: nonzero and distinct per endpoint.
func fteidContext(endpointID uint32) uint32 { return 0x100 + endpointID }

func endpointByName(eps []endpoint, name string) endpoint {
	for _, ep := range eps {
		if ep.name == name {
			return ep
		}
	}
	panic("layout names an unknown endpoint: " + name)
}

func writeContract(path string, groups [][]string, eps []endpoint) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := fmt.Fprintf(f, "ports\t%d\n", len(groups)); err != nil {
		return err
	}
	for _, ep := range eps {
		if _, err := fmt.Fprintf(f, "endpoint\t%s\t%d\t%d\t%s\t%s\t%d\t%d\t%s\n",
			ep.name, ep.port, ep.vlan, ep.mac, ep.ip, ep.domain, ep.id, ep.source); err != nil {
			return err
		}
	}
	return nil
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

func gpdu(teid uint32, ue string) ([]byte, error) {
	src := net.ParseIP(ue).To4()
	if src == nil {
		return nil, fmt.Errorf("invalid IPv4 UE address %q", ue)
	}
	dst := net.ParseIP("198.51.100.53").To4()
	payload := []byte("veth-layout")
	innerLen := 20 + 8 + len(payload)
	inner := make([]byte, innerLen)
	inner[0] = 0x45
	binary.BigEndian.PutUint16(inner[2:4], uint16(innerLen))
	binary.BigEndian.PutUint16(inner[4:6], 1)
	binary.BigEndian.PutUint16(inner[6:8], 0x4000)
	inner[8] = 64
	inner[9] = 17
	copy(inner[12:16], src)
	copy(inner[16:20], dst)
	binary.BigEndian.PutUint16(inner[10:12], checksum(inner[:20]))
	udp := inner[20:]
	binary.BigEndian.PutUint16(udp[0:2], 40000)
	binary.BigEndian.PutUint16(udp[2:4], 53)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)

	packet := make([]byte, 8+len(inner))
	packet[0], packet[1] = 0x30, 0xff
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(inner)))
	binary.BigEndian.PutUint32(packet[4:8], teid)
	copy(packet[8:], inner)
	return packet, nil
}

func sendGPDU(device, local, remote, ue string, teid uint32, count int) error {
	if device == "" || count < 1 {
		return fmt.Errorf("device and positive count are required")
	}
	localIP := net.ParseIP(local).To4()
	remoteIP := net.ParseIP(remote).To4()
	if localIP == nil || remoteIP == nil {
		return fmt.Errorf("local and remote must be IPv4 addresses")
	}
	payload, err := gpdu(teid, ue)
	if err != nil {
		return err
	}
	dialer := net.Dialer{
		LocalAddr: &net.UDPAddr{IP: localIP},
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
	conn, err := dialer.Dial("udp4", net.JoinHostPort(remoteIP.String(), "2152"))
	if err != nil {
		return err
	}
	defer conn.Close()
	for i := 0; i < count; i++ {
		if _, err := conn.Write(payload); err != nil {
			return err
		}
		time.Sleep(2 * time.Millisecond)
	}
	return nil
}

func run() error {
	layoutName := flag.String("layout", "", "topology layout to generate")
	ifacesFlag := flag.String("ifaces", "", "comma-separated PMD interface names")
	contract := flag.String("contract", "", "write the shell test contract here")
	send := flag.Bool("send-gpdu", false, "send GTP-U packets instead of generating a graph")
	device := flag.String("device", "", "interface used by -send-gpdu")
	local := flag.String("local", "", "local IPv4 address used by -send-gpdu")
	remote := flag.String("remote", "", "remote IPv4 address used by -send-gpdu")
	ue := flag.String("ue", "10.45.0.2", "inner UE source address")
	teid := flag.Uint("teid", uint(testTEID), "GTP-U TEID")
	count := flag.Int("count", 1, "number of G-PDUs to send")
	flag.Parse()
	if *send {
		return sendGPDU(*device, *local, *remote, *ue, uint32(*teid), *count)
	}
	cfg, err := layoutFor(*layoutName)
	if err != nil {
		return err
	}
	eps, err := makeEndpoints(cfg)
	if err != nil {
		return err
	}
	ifaces := strings.Split(*ifacesFlag, ",")
	if len(ifaces) == 1 && ifaces[0] == "" {
		ifaces = nil
	}
	g, err := graphFor(cfg, eps, ifaces)
	if err != nil {
		return err
	}
	if *contract != "" {
		if err := writeContract(*contract, cfg.groups, eps); err != nil {
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
