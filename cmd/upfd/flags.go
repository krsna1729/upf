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
//	[,sgi-lan-next-hop=<id>][,vn-next-hop=<id>][,pool=<prefix>][,arp=<module>]
//	[,arp-mac=<xx:xx:xx:xx:xx:xx>]
//
// Each *-next-hop key is one egress of the instance: the Router next hop
// (the graph's next_hops resource id) a forward out of it leaves by, per the
// FAR's Destination Interface value (TS 29.244 8.2.24) and whether the FAR
// adds an outer header -- next-hop is a plain forward toward the data network
// (N6), tunnel-next-hop one in a tunnel (N9, or indirect data forwarding),
// sgi-lan-next-hop one toward the service LAN (2) and vn-next-hop one that
// re-enters the subscriber-side chain (5). next-hop is where a deployment
// without the others sends everything out of the instance.
//
// arp names the module whose "<module>/entries" resource answers ARP requests
// for this instance's subscribers, and arp-mac is the Ethernet address those
// replies carry -- both or neither, because a responder with no address would
// answer with silence.
//
// The names, domains and pools are checked together by internal/routing: two
// instances may serve the same pool, but no two may share a domain.
func parseInstances(spec string, maxDomains uint32) (*routing.Domains, error) {
	var ifaces []routing.Interface
	for _, entry := range strings.Split(spec, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		var (
			ifc        routing.Interface
			hasDomain  bool
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
				ifc.NextHop = n
			case "tunnel-next-hop":
				if n, err = hop(key, value); err != nil {
					return nil, err
				}
				if ifc.Hops == nil {
					ifc.Hops = map[routing.Egress]uint32{}
				}
				ifc.Hops[routing.Egress{DestIfc: ie.DstInterfaceCore, Tunnel: true}] = n
			case "sgi-lan-next-hop":
				if n, err = hop(key, value); err != nil {
					return nil, err
				}
				if ifc.Hops == nil {
					ifc.Hops = map[routing.Egress]uint32{}
				}
				ifc.Hops[routing.Egress{DestIfc: ie.DstInterfaceSGiLANN6LAN}] = n
			case "vn-next-hop":
				if n, err = hop(key, value); err != nil {
					return nil, err
				}
				if ifc.Hops == nil {
					ifc.Hops = map[routing.Egress]uint32{}
				}
				ifc.Hops[routing.Egress{DestIfc: ie.DstInterface5GVNInternal}] = n
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
					"%q: %q is not name, domain, next-hop, tunnel-next-hop, sgi-lan-next-hop, vn-next-hop, pool, arp or arp-mac",
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
		ifaces = append(ifaces, ifc)
	}
	return routing.New(ifaces, maxDomains)
}

// profileArgs applies a profile's strategy to the flags' own defaults: the
// profile is what a module flag that names nothing resolves to, and every flag
// the operator *did* name wins over it -- the flag is the override and the
// profile is the default, so a deployment can run a profile with its own module
// names without a second profile. A flag the operator did not name is its
// declared default, and the profile overrides that: that is the whole point (a
// profile that could not clear -pdr-table-ul's "pdr_ul" could not move the
// uplink's rules out of that table).
//
// Only the rule home is a profile's: the tables, meters, counters and next hops
// are the deployment's, and the profile leaves them as the flags gave them.
func profileArgs(p session.Profile, given map[string]bool, a graphArgs) graphArgs {
	if !given["pdr-table-ul"] {
		a.pdrTableUL = p.Up.Table
	}
	if !given["firewall-ul"] {
		a.firewallUL = p.Up.Firewall
	}
	if !given["pdr-match-ul"] {
		a.pdrMatchUL = p.Up.PdrMatch
	}
	if !given["pdr-table-dl"] {
		a.pdrTableDL = p.Down.Table
	}
	if !given["firewall-dl"] {
		a.firewallDL = p.Down.Firewall
	}
	if !given["pdr-match-dl"] {
		a.pdrMatchDL = p.Down.PdrMatch
	}
	if !given["select-dl"] {
		a.selectDL = p.Down.Selector
	}
	if !given["select-actions-dl"] {
		a.selectActionsDL = p.Down.SelectorActions
	}
	if !given["select-fields-dl"] {
		a.selectFieldsDL = fieldList(p.Down.SelectorFields, a.selectFieldsDL)
	}
	return a
}

// fieldList spells a strategy's selector fields as the flag's own syntax, so a
// profile's key is the default of the flag that declares it: the graph the
// profile names is what declares the selector's field list, and a deployment
// that runs that graph without naming the flag must not fall back to another
// key.
func fieldList(fields []session.Field, fallback string) string {
	if len(fields) == 0 {
		return fallback
	}
	names := make([]string, 0, len(fields))
	for _, f := range fields {
		names = append(names, f.FlagName())
	}
	return strings.Join(names, ",")
}
