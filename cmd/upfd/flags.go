// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/wmnsk/go-pfcp/ie"

	"github.com/krsna1729/upf/internal/routing"
	"github.com/krsna1729/upf/internal/session"
)

// entryList keeps repeatable flags in the same scalar, semicolon-separated
// representation used by config files and environment variables.
type entryList []string

func (v *entryList) String() string { return strings.Join(*v, ";") }

func (v *entryList) Set(value string) error {
	for _, entry := range strings.Split(value, ";") {
		if entry = strings.TrimSpace(entry); entry != "" {
			*v = append(*v, entry)
		}
	}
	return nil
}

func parseLocalIPv4(value string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(value)
	if err != nil || !addr.Is4() || addr.IsUnspecified() || addr.IsMulticast() ||
		addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return netip.Addr{}, fmt.Errorf("%q is not a local unicast IPv4 address", value)
	}
	return addr, nil
}

func parseTransports(entries entryList) (map[uint32]session.TunnelTransport, error) {
	transports := make(map[uint32]session.TunnelTransport, len(entries))
	for _, entry := range entries {
		var transport session.TunnelTransport
		var hop uint32
		seen := map[string]bool{}
		for _, field := range strings.Split(entry, ",") {
			key, value, ok := strings.Cut(strings.TrimSpace(field), "=")
			if !ok || seen[key] {
				return nil, fmt.Errorf("%q: expected distinct key=value fields", entry)
			}
			seen[key] = true
			var err error
			switch key {
			case "next-hop":
				var n uint64
				n, err = strconv.ParseUint(value, 10, 32)
				hop = uint32(n)
			case "gate":
				transport.Gate, err = strconv.ParseUint(value, 10, 64)
				if err == nil && transport.Gate >= 8192 {
					err = fmt.Errorf("gate must be below 8192")
				}
			case "addr":
				transport.Addr, err = parseLocalIPv4(value)
			case "mac":
				transport.MAC, err = parseMAC(value)
			case "peer-mac":
				transport.PeerMAC, err = parseMAC(value)
			case "end-marker":
				transport.EndMarker = value
			default:
				return nil, fmt.Errorf("%q: unknown transport field %q", entry, key)
			}
			if err != nil {
				return nil, fmt.Errorf("%q: %s: %w", entry, key, err)
			}
		}
		for _, key := range []string{"next-hop", "gate", "addr", "mac", "peer-mac"} {
			if !seen[key] {
				return nil, fmt.Errorf("%q: transport needs %s=", entry, key)
			}
		}
		if _, exists := transports[hop]; exists {
			return nil, fmt.Errorf("duplicate transport next-hop %d", hop)
		}
		transports[hop] = transport
	}
	return transports, nil
}

func parseFTEIDAddresses(entries entryList) (map[string]netip.Addr, error) {
	addresses := make(map[string]netip.Addr, len(entries))
	for _, entry := range entries {
		var instance string
		var addr netip.Addr
		seen := map[string]bool{}
		for _, field := range strings.Split(entry, ",") {
			key, value, ok := strings.Cut(strings.TrimSpace(field), "=")
			if !ok || seen[key] {
				return nil, fmt.Errorf("%q: expected distinct key=value fields", entry)
			}
			seen[key] = true
			switch key {
			case "instance":
				instance = value
			case "addr":
				var err error
				addr, err = parseLocalIPv4(value)
				if err != nil {
					return nil, fmt.Errorf("%q: addr: %w", entry, err)
				}
			default:
				return nil, fmt.Errorf("%q: unknown F-TEID address field %q", entry, key)
			}
		}
		if instance == "" || !addr.IsValid() {
			return nil, fmt.Errorf("%q: F-TEID address needs instance= and addr=", entry)
		}
		if _, exists := addresses[instance]; exists {
			return nil, fmt.Errorf("duplicate F-TEID address instance %q", instance)
		}
		addresses[instance] = addr
	}
	return addresses, nil
}

func hasEndMarker(cfg session.Config) bool {
	if cfg.EndMarker != "" {
		return true
	}
	for _, transport := range cfg.Transports {
		if transport.EndMarker != "" {
			return true
		}
	}
	return false
}

// parsePDRFields reads a -pdr-fields-* flag: the PDR table's key, in the order
// the graph declares its fields. A name that is not one of the graph's fields
// is refused here, where the operator can fix it, rather than keying every
// rule on a field the graph does not match.
func parsePDRFields(spec string) ([]session.Field, error) {
	names := map[string]session.Field{}
	for _, f := range []session.Field{
		session.SrcIP, session.DstIP, session.Proto, session.SrcPort,
		session.DstPort, session.RouteDomain, session.UpfTEID, session.QFI,
	} {
		names[f.FlagName()] = f
	}
	fields := make([]session.Field, 0, len(names))
	for _, name := range strings.Split(spec, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		f, ok := names[name]
		if !ok {
			return nil, fmt.Errorf("field %q is not one of src, dst, proto, sport, dport, domain, teid, qfi", name)
		}
		fields = append(fields, f)
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("%q names no field", spec)
	}
	return fields, nil
}

// parseInstances reads an -instances flag: the deployment's network instances
// (TS 29.244 8.2.4), ';'-separated, each a comma-separated list of
//
//	name=<instance>,domain=<route domain>[,next-hop=<id>][,tunnel-next-hop=<id>]
//	[,access-next-hop=<id>][,sgi-lan-next-hop=<id>][,vn-next-hop=<id>]
//	[,pool=<prefix>][,arp=<module>][,arp-mac=<xx:xx:xx:xx:xx:xx>]
//
// Each *-next-hop key is one egress of the instance: the Router next hop
// (the graph's next_hops resource id) a forward out of it leaves by, per the
// FAR's Destination Interface value (TS 29.244 8.2.24) and whether the FAR
// adds an outer header -- next-hop is a plain forward toward the data network
// (N6), tunnel-next-hop one in a tunnel toward Core (N9), access-next-hop a
// tunnel toward Access (N3 or N9), sgi-lan-next-hop one toward the service LAN
// (2) and vn-next-hop one that re-enters the subscriber-side chain (5). At least
// one egress is required: an instance with no egress at all serves nothing. next-hop is
// where a plain forward out of the instance goes, so an instance that serves
// one needs it (a forward it cannot place is refused with cause 73).
//
// arp names the module whose "<module>/entries" resource answers ARP requests
// for this instance's subscribers, and arp-mac is the Ethernet address those
// replies carry -- both or neither, because a responder with no address would
// answer with silence.
//
// The names, domains and pools are checked together by internal/routing: two
// instances may serve the same pool, but no two may share a domain.
func parseInstances(spec string, maxDomains uint32, routeMode session.RouteMode) (*routing.Domains, error) {
	var ifaces []routing.Interface
	for _, entry := range strings.Split(spec, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		var (
			ifc        routing.Interface
			hasDomain  bool
			hasEgress  bool
			hasARPMAC  bool
			arpMACText string
		)
		// hop reads one *-next-hop key's value.
		hop := func(key, value string) (uint32, error) {
			n, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return 0, fmt.Errorf("%q: %s %q: %w", entry, key, value, err)
			}
			return uint32(n), nil
		}
		for _, field := range strings.Split(entry, ",") {
			field = strings.TrimSpace(field)
			key, value, ok := strings.Cut(field, "=")
			if !ok {
				return nil, fmt.Errorf("%q: %q is not key=value", entry, field)
			}
			var n uint32
			var err error
			switch key {
			case "name":
				ifc.Instance = value
			case "domain":
				d, err := strconv.ParseUint(value, 10, 32)
				if err != nil {
					return nil, fmt.Errorf("%q: domain %q: %w", entry, value, err)
				}
				ifc.Domain, hasDomain = uint32(d), true
			case "next-hop":
				if n, err = hop(key, value); err != nil {
					return nil, err
				}
				if ifc.Hops == nil {
					ifc.Hops = map[routing.Egress]uint32{}
				}
				ifc.Hops[routing.Egress{DestIfc: ie.DstInterfaceCore}] = n
				ifc.NextHop, hasEgress = n, true
			case "tunnel-next-hop":
				if n, err = hop(key, value); err != nil {
					return nil, err
				}
				if ifc.Hops == nil {
					ifc.Hops = map[routing.Egress]uint32{}
				}
				ifc.Hops[routing.Egress{DestIfc: ie.DstInterfaceCore, Tunnel: true}] = n
				hasEgress = true
			case "access-next-hop":
				if n, err = hop(key, value); err != nil {
					return nil, err
				}
				if ifc.Hops == nil {
					ifc.Hops = map[routing.Egress]uint32{}
				}
				ifc.Hops[routing.Egress{DestIfc: ie.DstInterfaceAccess, Tunnel: true}] = n
				hasEgress = true
			case "sgi-lan-next-hop":
				if n, err = hop(key, value); err != nil {
					return nil, err
				}
				if ifc.Hops == nil {
					ifc.Hops = map[routing.Egress]uint32{}
				}
				ifc.Hops[routing.Egress{DestIfc: ie.DstInterfaceSGiLANN6LAN}] = n
				hasEgress = true
			case "vn-next-hop":
				if n, err = hop(key, value); err != nil {
					return nil, err
				}
				if ifc.Hops == nil {
					ifc.Hops = map[routing.Egress]uint32{}
				}
				ifc.Hops[routing.Egress{DestIfc: ie.DstInterface5GVNInternal}] = n
				hasEgress = true
			case "pool":
				p, err := netip.ParsePrefix(value)
				if err != nil {
					return nil, fmt.Errorf("%q: pool %q: %w", entry, value, err)
				}
				ifc.Pool = append(ifc.Pool, p)
			case "arp":
				ifc.ARP = value
			case "arp-mac":
				ifc.ARPMAC, err = parseMAC(value)
				if err != nil {
					return nil, fmt.Errorf("%q: arp-mac %q: %w", entry, value, err)
				}
				hasARPMAC, arpMACText = true, value
			default:
				return nil, fmt.Errorf(
					"%q: %q is not name, domain, next-hop, tunnel-next-hop, access-next-hop, sgi-lan-next-hop, vn-next-hop, pool, arp or arp-mac",
					entry, key)
			}
		}
		if ifc.Instance == "" {
			return nil, fmt.Errorf("%q: an interface needs name=", entry)
		}
		if !hasDomain {
			return nil, fmt.Errorf("%q: an interface needs domain= (0 is a domain)", entry)
		}
		if hasARPMAC && ifc.ARP == "" {
			return nil, fmt.Errorf("%q: arp-mac %s is declared with no arp=<module> to answer for it",
				entry, arpMACText)
		}
		if ifc.ARP != "" && !hasARPMAC {
			return nil, fmt.Errorf("%q: arp=%s needs arp-mac: a reply must carry the interface's own address",
				entry, ifc.ARP)
		}
		if !hasEgress && routeMode != session.RouteByDestination {
			// An interface with no egress key at all is a configuration
			// mistake in policy mode: every forward out of it is a forward the
			// deployment declares no way out of, and the SMF would hear cause
			// 73 for a session the operator meant to serve. Which keys an
			// instance needs is its own business -- one that only re-injects
			// into the subscriber side (vn-next-hop) has no data-network exit,
			// and one whose forwards all tunnel (tunnel-next-hop) needs no
			// plain hop. In destination mode the Router's routes are the
			// egress table, so none of these keys is required.
			return nil, fmt.Errorf("%q: an interface needs an egress: next-hop=, tunnel-next-hop=, access-next-hop=, sgi-lan-next-hop= or vn-next-hop= (or -route-mode=destination)", entry)
		}
		ifaces = append(ifaces, ifc)
	}
	return routing.New(ifaces, maxDomains)
}
