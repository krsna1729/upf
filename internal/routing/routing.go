// SPDX-License-Identifier: BSD-3-Clause
// The deployment's three reference points as the controller needs them: N3
// (the access side), N6 (the data network) and N9 (a peer UPF), each a network
// instance (TS 29.244 8.2.4) with its own route domain, the subscriber
// prefixes it serves, and the Router next hop a forward out of it takes.
//
// The domain is what keeps two instances apart. Two subscribers may be behind
// the same private prefix on two instances -- that is what a network instance
// is for -- and their rules are told apart by the domain in the classifier's
// rule key rather than by the address. BESS's vif writes the domain into
// packet metadata (`route_domain`, core/route/route_domain.h) and the Router's
// routes are keyed by it; the classifier reads it (docs/design.md, "N3, N6,
// N9: one port, three interfaces").
package routing

import (
	"errors"
	"fmt"
	"net/netip"
)

// MaxDomains is BESS's bound on a Router's domains: core/route/route_domain.h
// puts the domain in a route's transaction-resource key, so a Router holds at
// most this many, and a deployment's domain ids are below it.
const MaxDomains = 1 << 24

// Interface is one interface of the deployment: a network instance, and what it
// takes to place a rule in it.
type Interface struct {
	// Instance is the Network Instance IE's value (TS 29.244 8.2.4): the name
	// the SMF writes in a PDI, and the name this deployment resolves.
	Instance string

	// Domain is the route domain this interface's packets are classified in
	// (0..MaxDomains-1): the vif's `route_domain` metadata attribute, and the
	// domain every rule placed on this interface carries.
	Domain uint32

	// NextHop is the Router next hop (the graph's next_hops resource id) a
	// forward out of this interface leaves by. 0 is a graph whose chain has no
	// Router next hop at all -- a deployment without an ActionTable -- and is
	// only correct there.
	NextHop uint32

	// Pool are the subscriber prefixes served through this interface: the UE
	// addresses an SMF may provision on it. Two interfaces may serve the same
	// prefix -- the domains are exactly what keeps those apart -- but one
	// interface may not serve a prefix twice: a rule on that interface would
	// be ambiguous about which session its packets belong to.
	Pool []netip.Prefix
}

// Serves reports whether an address belongs to this interface's pool. An
// interface the deployment declares no pool for serves every address: the flag
// has not said what it serves, and refusing every session because a line was
// left out would take the node down over an operator's omission. An address
// outside a pool that *is* declared is refused, because that is the deployment
// saying what it serves.
func (i Interface) Serves(a netip.Addr) bool {
	if len(i.Pool) == 0 {
		return true
	}
	a = a.Unmap()
	for _, p := range i.Pool {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Domains is a deployment's interfaces, resolved by network instance name.
type Domains struct {
	list   []Interface
	byName map[string]int
	max    uint32
}

// New resolves a deployment's interfaces. maxDomains is the Router's own bound
// (RouterArg.max_domains), which every domain id must be below: the interfaces
// the vif writes and the domains the Router has must agree, or a packet
// classified in one instance resolves to no table at all.
func New(ifaces []Interface, maxDomains uint32) (*Domains, error) {
	if len(ifaces) == 0 {
		return nil, errors.New("no network instance is configured, so a rule that names one cannot be placed")
	}
	if maxDomains == 0 || maxDomains > MaxDomains {
		return nil, fmt.Errorf("max domains %d is outside 1..%d", maxDomains, MaxDomains)
	}
	d := &Domains{
		list:   make([]Interface, 0, len(ifaces)),
		byName: make(map[string]int, len(ifaces)),
		max:    maxDomains,
	}
	domains := make(map[uint32]string, len(ifaces))
	for _, i := range ifaces {
		if i.Instance == "" {
			return nil, errors.New("an interface names no network instance")
		}
		if _, dup := d.byName[i.Instance]; dup {
			return nil, fmt.Errorf("network instance %q is configured twice", i.Instance)
		}
		if i.Domain >= maxDomains {
			return nil, fmt.Errorf("network instance %q: route domain %d is beyond the router's %d domains",
				i.Instance, i.Domain, maxDomains)
		}
		if other, dup := domains[i.Domain]; dup {
			return nil, fmt.Errorf("network instances %q and %q share route domain %d, and their rules would be one domain's",
				other, i.Instance, i.Domain)
		}
		for n, p := range i.Pool {
			if !p.IsValid() || !p.Addr().Unmap().Is4() {
				return nil, fmt.Errorf("network instance %q: the pool prefix %s is not an IPv4 prefix",
					i.Instance, p)
			}
			for _, q := range i.Pool[:n] {
				if q.Overlaps(p) {
					return nil, fmt.Errorf("network instance %q serves both %s and %s: a subscriber address in both is ambiguous on one interface",
						i.Instance, q, p)
				}
			}
		}
		d.byName[i.Instance] = len(d.list)
		d.list = append(d.list, i)
		domains[i.Domain] = i.Instance
	}
	return d, nil
}

// Lookup resolves a PDI's Network Instance (8.2.4) to the deployment's
// interface.
func (d *Domains) Lookup(instance string) (Interface, bool) {
	if d == nil {
		return Interface{}, false
	}
	n, ok := d.byName[instance]
	if !ok {
		return Interface{}, false
	}
	return d.list[n], true
}

// Default is the interface a PDI that names no instance is placed on: the
// first the deployment configured. TS 29.244 8.2.4 leaves the IE optional, and
// a rule that names none is a rule the one-instance deployment serves.
func (d *Domains) Default() Interface {
	if d == nil || len(d.list) == 0 {
		return Interface{}
	}
	return d.list[0]
}

// Interfaces lists them in the deployment's order.
func (d *Domains) Interfaces() []Interface {
	if d == nil {
		return nil
	}
	return append([]Interface(nil), d.list...)
}

// MaxDomains is the bound the interfaces were checked against.
func (d *Domains) MaxDomains() uint32 {
	if d == nil {
		return 0
	}
	return d.max
}

// Names lists the configured instance names, in order, for a log line or a
// refusal that has to say what this deployment does serve.
func (d *Domains) Names() []string {
	if d == nil {
		return nil
	}
	out := make([]string, 0, len(d.list))
	for _, i := range d.list {
		out = append(out, i.Instance)
	}
	return out
}
