// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/krsna1729/upf/internal/bess"
)

// ContentReader reads and empties the dataplane's session tables: what a
// restarted controller has to do before it can serve PFCP. *bess.Client
// implements it (ResourcePages, ResetResources).
type ContentReader interface {
	// ResourcePages reads one resource in bounded pages (the ARP tables'
	// selective sweep).
	ResourcePages(ctx context.Context, name string, visit func(bess.Entry) error) error
	// ResetResources empties map resources in the daemon without sending their
	// keys to the client, returning the entries it removed.
	ResetResources(ctx context.Context, names ...string) (uint64, error)
}

// sweepBatch bounds one selective erase transaction (the ARP entries the pool
// filter keeps). Whole session maps are reset
// inside the daemon, whose ApplyBatched splits them; this bound remains for
// the reads whose keys the sweep must name. 1000 changes stays below the
// engine's per-transaction retirement budget (2048 objects) even if every
// change retires two, and a sweep of a few hundred entries is still one
// transaction.
const sweepBatch = 1000

// resources is the target's startup reset list. ARP entries are handled
// separately because deployment-owned addresses share their table.
func (c *Compiler) resources() []string { return c.target.SweepResources() }

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

// arpSweeps names ARP tables and subscriber pools. Graph mode preserves the
// historical first-interface-per-responder behavior. Appliance mode combines
// every enabled interface's pools because all entries share one table.
func (c *Compiler) arpSweeps() []arpSweep {
	if c.cfg.Instances == nil {
		return nil
	}
	index := map[string]int{}
	var out []arpSweep
	for _, ifc := range c.cfg.Instances.Interfaces() {
		if ifc.ARP == "" {
			continue
		}
		resource := c.target.Entries(ifc.ARP)
		i, seen := index[resource]
		switch {
		case !seen:
			index[resource] = len(out)
			out = append(out, arpSweep{resource: resource, pools: slices.Clone(ifc.Pool)})
		case c.cfg.Appliance == "":
			// Graph mode keeps the first interface's pool.
		case len(out[i].pools) == 0:
			// Already every address.
		case len(ifc.Pool) == 0:
			out[i].pools = nil
		default:
			out[i].pools = append(out[i].pools, ifc.Pool...)
		}
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
// 64 MiB response limit no longer bounds the largest table. One resource is
// not a whole-table clear: an ARP responder table holds the deployment's own
// entry beside the subscribers' (it is read with ReadResource's pages and
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
		if err := c.store.ClearStore(ctx, c.target.Store()); err != nil {
			// A store that will not clear is a warning: the packets age out by
			// its own timeout, which is the same bound every other held packet
			// has, and refusing to serve PFCP over it would take the node down.
			c.log.Warn("session: the packet store was not cleared", "module", c.target.Store(), "error", err)
		}
	}
	if c.contents == nil {
		return errors.New("session: this dataplane cannot be read back, so an earlier run's sessions cannot be swept")
	}
	names := c.resources()
	// The ARP responder tables are not in names: they are cleared selectively
	// (arpSweep), because the deployment's own entry shares them.
	arps := c.arpSweeps()
	// Everything else is a map the compiler owns: empty it in the daemon. An
	// empty list is not a request the daemon accepts.
	removed := uint64(0)
	if len(names) > 0 {
		n, err := c.contents.ResetResources(ctx, names...)
		if err != nil {
			return fmt.Errorf("emptying the session tables: %w", err)
		}
		removed = n
	}
	changes := make([]bess.Change, 0, len(arps))
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
