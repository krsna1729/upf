// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"net"
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

func parseFTEIDAddresses(entries entryList, multiInstance bool) ([]session.FTEIDEndpoint, error) {
	endpoints := make([]session.FTEIDEndpoint, 0, len(entries))
	ids := make(map[uint32]bool, len(entries))
	for _, entry := range entries {
		var ep session.FTEIDEndpoint
		seen := map[string]bool{}
		for _, field := range strings.Split(entry, ",") {
			key, value, ok := strings.Cut(strings.TrimSpace(field), "=")
			if !ok || seen[key] {
				return nil, fmt.Errorf("%q: expected distinct key=value fields", entry)
			}
			seen[key] = true
			var err error
			switch key {
			case "endpoint":
				var id uint64
				id, err = strconv.ParseUint(value, 10, 32)
				if err == nil && id == 0 {
					err = fmt.Errorf("must be nonzero")
				}
				ep.ID = uint32(id)
			case "reference":
				if value != "n3" && value != "n9" {
					err = fmt.Errorf("must be n3 or n9")
				}
				ep.ReferencePoint = value
			case "transport-domain":
				var domain uint64
				domain, err = strconv.ParseUint(value, 10, 32)
				if err == nil && domain == 0 {
					err = fmt.Errorf("must be nonzero")
				}
				ep.TransportRouteDomain = uint32(domain)
			case "source":
				switch value {
				case "access":
					ep.SourceInterface = ie.SrcInterfaceAccess
				case "core":
					ep.SourceInterface = ie.SrcInterfaceCore
				default:
					err = fmt.Errorf("must be access or core")
				}
			case "instance":
				if value == "" {
					err = fmt.Errorf("must not be empty")
				}
				ep.Instance = value
			case "ipv4", "ipv6":
				var addr netip.Addr
				addr, err = netip.ParseAddr(value)
				if err == nil && (addr.Zone() != "" || addr.IsUnspecified() || addr.IsMulticast() ||
					addr.IsLinkLocalUnicast() || addr.IsLoopback() ||
					addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}) ||
					(key == "ipv4" && !addr.Is4()) ||
					(key == "ipv6" && (!addr.Is6() || addr.Is4In6()))) {
					err = fmt.Errorf("%q is not a usable local IPv%s unicast address",
						value, map[bool]string{true: "4", false: "6"}[key == "ipv4"])
				}
				if err == nil {
					if key == "ipv4" {
						ep.IPv4 = addr
					} else {
						ep.IPv6 = addr
					}
				}
			default:
				return nil, fmt.Errorf("%q: unknown F-TEID field %q", entry, key)
			}
			if err != nil {
				return nil, fmt.Errorf("%q: %s: %w", entry, key, err)
			}
		}
		if !seen["endpoint"] || !seen["reference"] || !seen["transport-domain"] ||
			!seen["source"] || (!ep.IPv4.IsValid() && !ep.IPv6.IsValid()) ||
			(multiInstance && (!seen["instance"] || ep.Instance == "")) ||
			(!multiInstance && seen["instance"]) {
			return nil, fmt.Errorf(
				"%q: endpoint, reference, transport-domain, source and at least one address are required; instance is required only with -instances",
				entry)
		}
		if (ep.ReferencePoint == "n3" && ep.SourceInterface != ie.SrcInterfaceAccess) ||
			(ep.ReferencePoint == "n9" && ep.SourceInterface != ie.SrcInterfaceCore) {
			return nil, fmt.Errorf("%q: n3 requires source=access and n9 requires source=core", entry)
		}
		if ids[ep.ID] {
			return nil, fmt.Errorf("duplicate F-TEID endpoint ID %d", ep.ID)
		}
		ids[ep.ID] = true
		endpoints = append(endpoints, ep)
	}
	return endpoints, nil
}

func hasEndMarker(cfg session.Config) bool {
	return cfg.EndMarker != ""
}

func parseMAC(value string) ([6]byte, error) {
	var out [6]byte
	hw, err := net.ParseMAC(value)
	if err != nil {
		return out, err
	}
	if len(hw) != len(out) {
		return out, fmt.Errorf("%q is not a 6-byte address", value)
	}
	copy(out[:], hw)
	return out, nil
}

// parsePDRFields reads a -pdr-fields-* flag: the PDR table's key, in the order
// the graph declares its fields. A name that is not one of the graph's fields
// is refused here, where the operator can fix it, rather than keying every
// rule on a field the graph does not match.
func parsePDRFields(spec string) ([]session.Field, error) {
	names := map[string]session.Field{}
	for _, f := range []session.Field{
		session.SrcIP, session.DstIP, session.Proto, session.SrcPort,
		session.DstPort, session.RouteDomain, session.FTEIDContext, session.QFI,
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
			return nil, fmt.Errorf("field %q is not one of src, dst, proto, sport, dport, domain, fteid, qfi", name)
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
