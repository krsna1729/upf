// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/krsna1729/upf/internal/routing"
	"github.com/krsna1729/upf/internal/session"
)

// parsePDRFields reads a -pdr-fields-* flag: the PDR table's key, in the order
// the graph declares its fields. A name that is not one of the graph's fields
// is refused here, where the operator can fix it, rather than keying every
// rule on a field the graph does not match.
func parsePDRFields(spec string) ([]session.Field, error) {
	names := map[string]session.Field{
		"src":    session.SrcIP,
		"dst":    session.DstIP,
		"proto":  session.Proto,
		"sport":  session.SrcPort,
		"dport":  session.DstPort,
		"domain": session.RouteDomain,
		"teid":   session.UpfTEID,
		"qfi":    session.QFI,
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
//	name=<instance>,domain=<route domain>,next-hop=<id>,pool=<prefix>[,pool=<prefix>]
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
			ifc       routing.Interface
			hasDomain bool
		)
		for _, field := range strings.Split(entry, ",") {
			field = strings.TrimSpace(field)
			key, value, ok := strings.Cut(field, "=")
			if !ok {
				return nil, fmt.Errorf("%q: %q is not key=value", entry, field)
			}
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
				n, err := strconv.ParseUint(value, 10, 32)
				if err != nil {
					return nil, fmt.Errorf("%q: next-hop %q: %w", entry, value, err)
				}
				ifc.NextHop = uint32(n)
			case "pool":
				p, err := netip.ParsePrefix(value)
				if err != nil {
					return nil, fmt.Errorf("%q: pool %q: %w", entry, value, err)
				}
				ifc.Pool = append(ifc.Pool, p)
			default:
				return nil, fmt.Errorf("%q: %q is not name, domain, next-hop or pool", entry, key)
			}
		}
		if ifc.Instance == "" {
			return nil, fmt.Errorf("%q: an interface needs name=", entry)
		}
		if !hasDomain {
			return nil, fmt.Errorf("%q: an interface needs domain= (0 is a domain)", entry)
		}
		ifaces = append(ifaces, ifc)
	}
	return routing.New(ifaces, maxDomains)
}
