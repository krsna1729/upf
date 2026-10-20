// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/krsna1729/upf/internal/bess"
)

// ContentReader reads and empties the dataplane's session tables: what a
// restarted controller has to do before it can serve PFCP. *bess.Client
// implements it (Contents, ResourcePages, ResetResources).
type ContentReader interface {
	Contents(ctx context.Context, names ...string) (map[string][]bess.Entry, error)
	// ResourcePages reads one resource in bounded pages, for a table too large
	// for one Contents response (the ARP tables' selective sweep).
	ResourcePages(ctx context.Context, name string, visit func(bess.Entry) error) error
	// ResetResources empties map resources in the daemon without sending their
	// keys to the client, returning the entries it removed.
	ResetResources(ctx context.Context, names ...string) (uint64, error)
}

// sweepBatch bounds one selective erase transaction (the ARP entries the pool
// filter keeps, and a firewall's empty policy). Whole session maps are reset
// inside the daemon, whose ApplyBatched splits them; this bound remains for
// the reads whose keys the sweep must name. 1000 changes stays below the
// engine's per-transaction retirement budget (2048 objects) even if every
// change retires two, and a sweep of a few hundred entries is still one
// transaction.
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
// next hops, the module arguments) are not the controller's to touch.
//
// The maps are emptied in the daemon, not key by key: ResetResources converges
// each named resource to no entries and applies the erases in batches, so the
// controller never reads a session key only to send it back, and the daemon's
// 64 MiB response limit no longer bounds the largest table. Two resources are
// not whole-table clears: a firewall is a singleton (its policy is one value,
// replaced by an empty one), and an ARP responder table holds the deployment's
// own entry beside the subscribers' (it is read with ReadResource's pages and
// filtered by the interface's pool). The store is cleared by its module's own
// command.
//
// The selective erases go out in transactions of at most sweepBatch each, in
// sequence. The sweep stops at the first refused transaction and returns an
// error naming it and how much was erased before it, because the transactions
// before it are committed: a partial sweep is a dataplane holding some of an
// earlier run's sessions, and the caller has to refuse to serve PFCP beside it
// (upfd treats this error as fatal). A reset refused after some of its batches
// are applied is the same partial state.
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
	// The ARP responder tables are not in names: they are cleared selectively
	// (arpSweep), because the deployment's own entry shares them.
	arps := c.arpSweeps()
	// A firewall is a singleton ("<module>/rules" holds the whole policy,
	// D-147): it has no key to erase, and the write is the whole policy. An
	// earlier run's policy matches packets this process has no session for --
	// and *passes* them, a rule's verdict being pass or drop -- so it is
	// replaced by an empty one, which no rule matches.
	firewalls := map[string]bool{}
	for _, d := range []Direction{c.cfg.Up, c.cfg.Down} {
		if d.Firewall != "" {
			firewalls[firewallRes(d)] = true
		}
	}
	// Everything else is a map the compiler owns: empty it in the daemon. An
	// empty list is not a request the daemon accepts.
	resettable := make([]string, 0, len(names))
	for _, name := range names {
		if !firewalls[name] {
			resettable = append(resettable, name)
		}
	}
	removed := uint64(0)
	if len(resettable) > 0 {
		n, err := c.contents.ResetResources(ctx, resettable...)
		if err != nil {
			return fmt.Errorf("emptying the session tables: %w", err)
		}
		removed = n
	}
	changes := make([]bess.Change, 0, len(firewalls)+len(arps))
	// A firewall's contents are one value, not a table: read it and replace a
	// non-empty policy. An empty policy is left alone, because it is what this
	// process would write anyway and a transaction that changes nothing is not
	// one the daemon needs.
	for name := range firewalls {
		read, err := c.contents.Contents(ctx, name)
		if err != nil {
			return fmt.Errorf("reading the firewall policy %s: %w", name, err)
		}
		for _, e := range read[name] {
			if rules, _ := e.Value["rules"].([]any); len(rules) > 0 {
				changes = append(changes, bess.Change{
					Resource: name,
					Value:    map[string]any{"rules": []map[string]any{}},
				})
			}
		}
	}
	// The ARP tables are filtered by the interface's pool: a subscriber
	// address is in it by construction, the deployment's own need not be.
	for _, a := range arps {
		if len(a.pools) == 0 {
			// Every address is served (the pool's omission means that), so
			// nothing tells a session's entry from the deployment's own:
			// the sweep leaves the table and says so.
			c.log.Warn("session: the ARP table of an interface that declares no pool is left as it was: an earlier run's subscriber entries may answer until the graph is applied again",
				"resource", a.resource)
			continue
		}
		err := c.contents.ResourcePages(ctx, a.resource, func(e bess.Entry) error {
			ip, _ := e.Key["ip"].(string)
			if addr, err := netip.ParseAddr(ip); err == nil && inPools(addr, a.pools) {
				changes = append(changes, bess.Change{Resource: a.resource, Key: e.Key})
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("reading the ARP table %s: %w", a.resource, err)
		}
	}
	if removed == 0 && len(changes) == 0 {
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
		"entries", removed+uint64(len(changes)), "tables", len(names), "transactions", batches)
	return nil
}
