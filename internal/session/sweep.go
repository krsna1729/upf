// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"context"
	"errors"
	"fmt"

	"github.com/krsna1729/upf/internal/bess"
)

// ContentReader reads back the entries of the dataplane's session tables: what
// a restarted controller has to find out before it can take an earlier run's
// sessions out. *bess.Client implements it (its Contents).
type ContentReader interface {
	Contents(ctx context.Context, names ...string) (map[string][]bess.Entry, error)
}

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
	if c.cfg.Down.Tunnels != "" {
		add(tunnelsRes(c.cfg.Down))
	}
	if c.BufferingConfigured() {
		// The BUFF branch's counter entries are the session layer's too: an
		// earlier run's flow would otherwise keep counting into a rule this
		// process does not know about.
		add(countersRes(Direction{Counters: c.cfg.Buffering.Counter}))
	}
	return names
}

// Sweep empties the session tables in one transaction (docs/design.md's
// restart wall): a controller that comes up against a daemon still holding an
// earlier run's sessions takes them out before it serves PFCP, so no packet is
// matched by a session this process never established. Everything the sweep
// erases is a resource the compiler itself writes -- the graph's own resources
// (a router's next hops, the module arguments) are not the controller's to
// touch -- and it erases exactly what it read, key by key: nothing is emptied
// that the readback did not report.
//
// It is deliberately not a pipeline reset: the graph stays, the session tables
// empty. And nothing is erased when there is nothing to erase, because an
// empty transaction is not one the daemon accepts.
func (c *Compiler) Sweep(ctx context.Context) error {
	if c.contents == nil {
		return errors.New("session: this dataplane cannot be read back, so an earlier run's sessions cannot be swept")
	}
	// Before the tables: what the store holds is a previous run's packets, and
	// this process knows neither the flows nor the episodes they were held for.
	// It is not a table and cannot be read back per key -- the module's own
	// clear is the only way to empty it, and the id it takes is unused (the
	// command's field exists for the release and drop commands).
	if c.store != nil && c.BufferingConfigured() {
		if err := c.store.ClearStore(ctx, c.cfg.Buffering.Store, 0); err != nil {
			// A store that will not clear is a warning: the packets age out by
			// its own timeout, which is the same bound every other held packet
			// has, and refusing to serve PFCP over it would take the node down.
			c.log.Warn("session: the packet store was not cleared", "module", c.cfg.Buffering.Store, "error", err)
		}
	}
	names := c.resources()
	contents, err := c.contents.Contents(ctx, names...)
	if err != nil {
		return fmt.Errorf("reading the session tables: %w", err)
	}
	changes := make([]bess.Change, 0, len(contents))
	for name, entries := range contents {
		for _, e := range entries {
			changes = append(changes, bess.Change{Resource: name, Key: e.Key})
		}
	}
	if len(changes) == 0 {
		c.log.Info("no earlier session left anything to erase", "tables", len(names))
		return nil
	}
	if err := c.ap.Apply(ctx, changes...); err != nil {
		return fmt.Errorf("erasing %d entries of an earlier run's sessions: %w", len(changes), err)
	}
	c.log.Warn("erased an earlier run's session entries before serving",
		"entries", len(changes), "tables", len(names))
	return nil
}
