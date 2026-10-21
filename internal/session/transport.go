// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"net/netip"

	"github.com/wmnsk/go-pfcp/ie"
)

// TunnelTransport is the outer link used by a FAR's resolved Router next hop.
// It applies to tunnels toward either Access or Core; the PDR's ingress side
// does not decide which link the outgoing tunnel uses.
type TunnelTransport struct {
	Gate      uint64
	Addr      netip.Addr
	MAC       [6]byte
	PeerMAC   [6]byte
	EndMarker string
}

func (c *Compiler) tunnelTransport(hop uint32) TunnelTransport {
	if transport, ok := c.cfg.Transports[hop]; ok {
		return transport
	}
	return TunnelTransport{
		Addr:      c.cfg.N3Addr,
		MAC:       c.cfg.N3MAC,
		PeerMAC:   c.cfg.PeerMAC,
		EndMarker: c.cfg.EndMarker,
	}
}

// fteidAddr is the local address advertised for an incoming tunnel, not the
// source address of a FAR's outgoing tunnel. An instance override allows an
// Access-side PDR to receive on N9 without changing its PFCP direction.
func (c *Compiler) fteidAddr(p *pdr) netip.Addr {
	instance := p.instance
	if instance == "" && c.cfg.Instances != nil {
		instance = c.cfg.Instances.Default().Instance
	}
	if addr, ok := c.cfg.FTEIDAddrs[instance]; ok {
		return addr
	}
	if p.srcIfc == ie.SrcInterfaceCore {
		return c.cfg.N9Addr
	}
	return c.cfg.N3Addr
}

func (c *Compiler) endMarkersConfigured() bool {
	if c.cfg.EndMarker != "" {
		return true
	}
	for _, transport := range c.cfg.Transports {
		if transport.EndMarker != "" {
			return true
		}
	}
	return false
}
