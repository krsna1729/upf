// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"fmt"
	"net/netip"
	"slices"

	"github.com/wmnsk/go-pfcp/ie"

	"github.com/krsna1729/upf/internal/routing"
)

// requestedFTEIDFamilies is the whole family set a PDI asks this UP function
// to allocate or admit. A zero family flag means IPv4 under the F-TEID IE.
func requestedFTEIDFamilies(p *pdr) []uint8 {
	families := make([]uint8, 0, 2)
	if p.wantIPv4 || p.fteidIPv4.IsValid() {
		families = append(families, 4)
	}
	if p.wantIPv6 || p.fteidIPv6.IsValid() {
		families = append(families, 6)
	}
	if len(families) == 0 {
		families = append(families, 4)
	}
	return families
}

// fteidEndpoint chooses one configured ingress endpoint for a request.
// Config order defines the CHOOSE preference; one endpoint must satisfy the
// entire requested family set.
func (c *Compiler) fteidEndpoint(p *pdr) (FTEIDEndpoint, error) {
	families := requestedFTEIDFamilies(p)
	referencePoint, ok := fteidReferencePoint(p.srcIfc)
	if !ok {
		return FTEIDEndpoint{}, fmt.Errorf("%w: source interface %d has no supported GTP-U endpoint",
			errNotExpressible, p.srcIfc)
	}
	instance := p.instance
	if instance == "" && c.cfg.Instances != nil {
		instance = c.cfg.Instances.Default().Instance
	}
	var chosen FTEIDEndpoint
	candidates := 0
	for _, endpoint := range c.cfg.FTEIDEndpoints {
		if endpoint.SourceInterface != p.srcIfc || endpoint.ReferencePoint != referencePoint ||
			(endpoint.Instance != "" && endpoint.Instance != instance) {
			continue
		}
		if slices.Contains(families, 4) && !endpoint.IPv4.IsValid() ||
			slices.Contains(families, 6) && !endpoint.IPv6.IsValid() {
			continue
		}
		if p.fteidIPv4.IsValid() && endpoint.IPv4 != p.fteidIPv4 ||
			p.fteidIPv6.IsValid() && endpoint.IPv6 != p.fteidIPv6 {
			continue
		}
		candidates++
		if candidates == 1 {
			chosen = endpoint
		}
		if p.teid == 0 {
			break
		}
	}
	if candidates == 1 {
		return chosen, nil
	}
	if candidates > 1 {
		return FTEIDEndpoint{}, fmt.Errorf("%w: the pinned F-TEID has no address and matches multiple endpoints",
			errNotExpressible)
	}
	return FTEIDEndpoint{}, fmt.Errorf("%w: no configured %s endpoint matches source interface, instance and requested address families",
		errNotExpressible, referencePoint)
}

func fteidReferencePoint(sourceInterface uint8) (string, bool) {
	switch sourceInterface {
	case ie.SrcInterfaceAccess:
		return "n3", true
	case ie.SrcInterfaceCore:
		return "n9", true
	default:
		return "", false
	}
}

func tunnelReferencePoint(destinationInterface uint8) (string, bool) {
	switch destinationInterface {
	case ie.DstInterfaceAccess:
		return "n3", true
	case ie.DstInterfaceCore:
		return "n9", true
	default:
		return "", false
	}
}

// tunnelEndpoint selects the local source address and route domain for one
// outer GTP-U tunnel. The peer's family is mandatory; a local address from the
// other family cannot form the same tunnel. A forwarding-instance-specific
// endpoint takes precedence over an unscoped endpoint.
func (c *Compiler) tunnelEndpoint(far *far, ifc routing.Interface) (FTEIDEndpoint, netip.Addr, error) {
	referencePoint, ok := tunnelReferencePoint(far.destIfc)
	if !ok {
		return FTEIDEndpoint{}, netip.Addr{}, fmt.Errorf(
			"%w: Destination Interface %d has no configured GTP-U reference point",
			errNotExpressible, far.destIfc)
	}
	if !far.peer.IsValid() || (!far.peer.Is4() && !far.peer.Is6()) {
		return FTEIDEndpoint{}, netip.Addr{}, fmt.Errorf("%w: the outer GTP-U peer address is invalid",
			errNotExpressible)
	}
	egress, err := c.forwardEgress(far, ifc)
	if err != nil {
		return FTEIDEndpoint{}, netip.Addr{}, err
	}
	var exact, fallback *FTEIDEndpoint
	var exactAddr, fallbackAddr netip.Addr
	for i := range c.cfg.FTEIDEndpoints {
		endpoint := &c.cfg.FTEIDEndpoints[i]
		endpointReference, supportedSource := fteidReferencePoint(endpoint.SourceInterface)
		if !supportedSource || endpoint.ReferencePoint != referencePoint ||
			endpointReference != endpoint.ReferencePoint || endpoint.TransportRouteDomain == 0 {
			continue
		}
		var address netip.Addr
		if far.peer.Is4() {
			address = endpoint.IPv4
		} else {
			address = endpoint.IPv6
		}
		if !address.IsValid() {
			continue
		}
		if endpoint.Instance == egress.Instance && endpoint.Instance != "" {
			if exact == nil {
				exact, exactAddr = endpoint, address
			}
			continue
		}
		if endpoint.Instance == "" && fallback == nil {
			fallback, fallbackAddr = endpoint, address
		}
	}
	if exact != nil {
		return *exact, exactAddr, nil
	}
	if fallback != nil {
		return *fallback, fallbackAddr, nil
	}
	return FTEIDEndpoint{}, netip.Addr{}, fmt.Errorf(
		"%w: no configured %s endpoint matches forwarding instance %q and peer address family",
		errNotExpressible, referencePoint, egress.Instance)
}

func (c *Compiler) fteidAddr(p *pdr) netip.Addr {
	for _, endpoint := range c.cfg.FTEIDEndpoints {
		if endpoint.ID != p.endpointID {
			continue
		}
		if p.endpointFamily == 4 {
			return endpoint.IPv4
		}
		if p.endpointFamily == 6 {
			return endpoint.IPv6
		}
	}
	return netip.Addr{}
}

func (c *Compiler) endMarkersConfigured() bool {
	return c.cfg.EndMarker != ""
}
