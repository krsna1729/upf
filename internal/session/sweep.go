// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/krsna1729/upf/internal/bess"
)

// ContentReader reads back the entries of the dataplane's session tables: what
// a restarted controller has to find out before it can take an earlier run's
// sessions out. *bess.Client implements it (its Contents).
type ContentReader interface {
	Contents(ctx context.Context, names ...string) (map[string][]bess.Entry, error)
}

// sweepBatch bounds one erase transaction. A sweep at the 1M-session target
// has millions of entries to take out, and one transaction carrying them all
// meets two limits: the daemon's 64 MiB message limit (core/control/api_v2.h's
// kMaxMessageBytes -- a typed rule is 131 B, so one transaction holds roughly
// half a million of them, "beyond which a bulk load belongs on a streaming
// path"), and its engine's per-transaction retirement budget, which refuses one
// whose declared retirements exceed a batch with "transaction retires up to N
// objects, more than one batch allows (2048); split it"
// (core/dataplane/transaction_engine.cc, kBusy, retriable). 1000 changes per
// transaction stays below both -- below the retirement budget even if every
// change retires two objects -- and a sweep of a few hundred entries is still
// one transaction.
const sweepBatch = 1000

// resources is every resource the compiler writes, as the deployed graph
// spells them ("<module>/<table>"): the names a sweep reads and erases. A
// module name the graph does not declare (a graph that charges nothing
// declares no counter module) writes nothing and names nothing, so it is left
// out rather than read as "/counters".
func (c *Compiler) resources() []string {
	var names []string
	add := func(name string) {
		if name == "" || name[0] == '/' {
			return
		}
		for _, have := range names {
			if have == name {
				return
			}
		}
		names = append(names, name)
	}
	add(c.teidRes())
	for _, d := range []Direction{c.cfg.Up, c.cfg.Down} {
		if d.PDRTable != "" {
			add(rulesRes(d))
		}
		if d.Firewall != "" {
			add(firewallRes(d))
		}
		if d.PdrMatch != "" {
			// The opt-in map is the session layer's like the rest: an earlier
			// run's key is a session this process does not know, and the sweep
			// erases exactly the keys it read back (the resource is a map, so
			// this is the generic path below, not the firewall's whole-policy
			// one).
			add(pdrMatchRes(d))
		}
		if d.Actions != "" {
			add(actionsRes(d))
		}
		if d.Meters != "" {
			add(metersRes(d))
		}
		if d.Counters != "" {
			add(countersRes(d))
		}
	}
	for _, d := range []Direction{c.cfg.Up, c.cfg.Down} {
		if d.Tunnels != "" {
			add(tunnelsRes(d))
		}
	}
	if c.BufferingConfigured() {
		// The BUFF branch's counter entries are the session layer's too: an
		// earlier run's flow would otherwise keep counting into a rule this
		// process does not know about.
		add(countersRes(Direction{Counters: c.cfg.Buffering.Counter}))
		// And so are the store's per-flow "flows" entries: each carries the
		// SMF's own numbers (8.2.29, 8.2.30) for a flow an earlier run held, and
		// a later session that reuses the ActionId must not inherit them.
		add(flowsRes(c.cfg.Buffering))
	}
	return names
}

// inPools reports whether an address is one the interface's pools serve: the
// pool's own containment, with the mapped form of an IPv4-in-IPv6 address
// unmapped first, because the compiler writes subscriber addresses that way
// (resolve) and the responder's keys come from the same values.
func inPools(addr netip.Addr, pools []netip.Prefix) bool {
	addr = addr.Unmap()
	for _, p := range pools {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// arpSweep is the ARP responder table of one deployment interface, and the
// pools whose addresses are this process's to erase from it.
//
// The table is not only the session layer's: the deployment's own entry (the
// interface's address, and the MAC that answers for it) is written by the
// graph and shares the resource, so a whole-table erase would stop the
// interface answering for itself until the graph is applied again. A session's
// entries are its subscribers' addresses, and the compiler refuses one outside
// the interface's pools (resolve) -- so the pools are exactly the line between
// the two writers. An interface that declares no pool serves every address, so
// its entries cannot be told apart from the deployment's and the sweep leaves
// them: the caller logs it, and the operator's remedy is the pool that names
// which addresses are the subscribers' (the flag says so).
type arpSweep struct {
	resource string
	pools    []netip.Prefix
}

// arpSweeps lists the ARP tables the deployment declared, one per interface.
func (c *Compiler) arpSweeps() []arpSweep {
	if c.cfg.Instances == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []arpSweep
	for _, ifc := range c.cfg.Instances.Interfaces() {
		if ifc.ARP == "" || seen[ifc.ARP] {
			continue
		}
		seen[ifc.ARP] = true
		out = append(out, arpSweep{resource: ifc.ARP + "/entries", pools: ifc.Pool})
	}
	return out
}

// Sweep empties the session tables (docs/design.md's restart wall): a
// controller that comes up against a daemon still holding an earlier run's
// sessions takes them out before it serves PFCP, so no packet is matched by a
// session this process never established. Everything the sweep erases is a
// resource the compiler itself writes -- the graph's own resources (a router's
// next hops, the module arguments) are not the controller's to touch -- and it
// erases exactly what it read, key by key: nothing is emptied that the readback
// did not report.
//
// The erase is chunked: the changes go out in transactions of at most
// sweepBatch each, in sequence, rather than one transaction carrying every
// entry of a million-session table (see that constant for what one such
// transaction meets). The sweep stops at the first refused batch and returns
// an error naming it and how much was erased before it, because the batches
// before it are committed: a partial sweep is a dataplane holding some of an
// earlier run's sessions, and the caller has to refuse to serve PFCP beside it
// (upfd treats this error as fatal).
//
// The readback is one Contents call per resource, never one naming them all:
// every resource a call names is packed into one response, and the daemon
// refuses a response above its 64 MiB message limit (RESOURCE_EXHAUSTED, "name
// fewer resources"). At 1M sessions the session tables together are well past
// that limit; naming one resource at a time is the only lever the daemon
// offers, and it makes the bound the largest single table rather than the sum
// of them. A single read is still one message, so a table is readable to
// roughly 510K entries at 131 B each: the largest single table is the interim's
// ceiling, not the session count, and past that table's capacity the operator's
// escape is a `bessd` restart, which discards the warm dataplane. The target
// recorded in docs/design.md's restart wall is a bounded clear -- *clear this
// resource*, batched inside the daemon -- which removes this readback
// altogether: it exists only to name the keys to erase, a client-side
// enumeration of a table the daemon already owns. There is no paged read to use
// today: GetPipelineRequest carries a resource list and nothing else -- no
// cursor, offset or chunk size.
//
// It is deliberately not a pipeline reset: the graph stays, the session tables
// empty. And nothing is erased when there is nothing to erase, because an
// empty transaction is not one the daemon accepts.
func (c *Compiler) Sweep(ctx context.Context) error {
	// First, and before the readback check: what the store holds is a previous
	// run's packets, and this process knows neither the flows nor the episodes
	// they were held for. It is not a table of the session layer's, so it is
	// emptied whether or not this dataplane can be read back -- a store left
	// holding packets would hand a later session the previous one's.
	if c.store != nil && c.BufferingConfigured() {
		if err := c.store.ClearStore(ctx, c.cfg.Buffering.Store); err != nil {
			// A store that will not clear is a warning: the packets age out by
			// its own timeout, which is the same bound every other held packet
			// has, and refusing to serve PFCP over it would take the node down.
			c.log.Warn("session: the packet store was not cleared", "module", c.cfg.Buffering.Store, "error", err)
		}
	}
	if c.contents == nil {
		return errors.New("session: this dataplane cannot be read back, so an earlier run's sessions cannot be swept")
	}
	names := c.resources()
	// The ARP responder tables are read with the rest but erased selectively
	// (arpSweep): the deployment's own entry shares them.
	arps := c.arpSweeps()
	for _, a := range arps {
		names = append(names, a.resource)
	}
	// One resource per call, never one naming them all. The daemon packs every
	// resource named into one response, and a response above its 64 MiB message
	// limit is refused (RESOURCE_EXHAUSTED, "name fewer resources" --
	// core/control/api_v2.cc): at 1M sessions the session tables together are
	// well past it, so naming fewer resources is the only lever there is, and
	// naming one resource at a time is what makes the bound the largest single
	// table instead of the sum of them. Each read is still one message of its
	// own -- a table is readable to roughly 510K entries of 131 B each -- so
	// the largest single table is the interim's ceiling, and past it the
	// operator's escape is a `bessd` restart, which discards the warm
	// dataplane. The target (docs/design.md's restart wall) is a bounded clear
	// in the daemon, which removes this readback altogether: it exists only to
	// name the keys to erase.
	contents := make(map[string][]bess.Entry, len(names))
	for _, name := range names {
		read, err := c.contents.Contents(ctx, name)
		if err != nil {
			return fmt.Errorf("reading the session table %s: %w", name, err)
		}
		for n, entries := range read {
			contents[n] = entries
		}
	}
	// A firewall policy is a singleton ("<module>/rules" holds the whole
	// policy, D-147): it has no key to erase, and the write is the whole
	// policy. An earlier run's policy matches packets this process has no
	// session for -- and *passes* them, a rule's verdict being pass or drop --
	// so it is replaced by an empty one, which no rule matches. An empty policy
	// is left alone: it is what this process would write anyway, and a
	// transaction that changes nothing is not one the daemon needs.
	firewalls := map[string]bool{}
	for _, d := range []Direction{c.cfg.Up, c.cfg.Down} {
		if d.Firewall != "" {
			firewalls[firewallRes(d)] = true
		}
	}
	// Which resources are ARP tables, and whose addresses are the session
	// layer's to erase.
	arpPools := make(map[string][]netip.Prefix, len(arps))
	for _, a := range arps {
		arpPools[a.resource] = a.pools
	}
	changes := make([]bess.Change, 0, len(contents))
	for name, entries := range contents {
		if pools, isARP := arpPools[name]; isARP {
			if len(pools) == 0 {
				// Every address is served (the pool's omission means that), so
				// nothing tells a session's entry from the deployment's own:
				// the sweep leaves the table and says so.
				c.log.Warn("session: the ARP table of an interface that declares no pool is left as it was: an earlier run's subscriber entries may answer until the graph is applied again",
					"resource", name)
				continue
			}
			for _, e := range entries {
				ip, _ := e.Key["ip"].(string)
				if addr, err := netip.ParseAddr(ip); err == nil && inPools(addr, pools) {
					changes = append(changes, bess.Change{Resource: name, Key: e.Key})
				}
			}
			continue
		}
		if firewalls[name] {
			for _, e := range entries {
				if rules, _ := e.Value["rules"].([]any); len(rules) > 0 {
					changes = append(changes, bess.Change{
						Resource: name,
						Value:    map[string]any{"rules": []map[string]any{}},
					})
				}
			}
			continue
		}
		for _, e := range entries {
			changes = append(changes, bess.Change{Resource: name, Key: e.Key})
		}
	}
	if len(changes) == 0 {
		c.log.Info("no earlier session left anything to erase", "tables", len(names))
		return nil
	}
	// One transaction per sweepBatch changes, in sequence, stopping at the
	// first the daemon refuses: what it committed stays committed, so the error
	// says which batch failed and how much is already gone.
	batches := (len(changes) + sweepBatch - 1) / sweepBatch
	for start := 0; start < len(changes); start += sweepBatch {
		end := min(start+sweepBatch, len(changes))
		if err := c.ap.Apply(ctx, changes[start:end]...); err != nil {
			return fmt.Errorf("erasing an earlier run's sessions: batch %d of %d failed, with %d of %d entries erased: %w",
				start/sweepBatch+1, batches, start, len(changes), err)
		}
	}
	c.log.Warn("erased an earlier run's session entries before serving",
		"entries", len(changes), "tables", len(names), "transactions", batches)
	return nil
}
