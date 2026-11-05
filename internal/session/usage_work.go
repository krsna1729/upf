// SPDX-License-Identifier: BSD-3-Clause
package session

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/krsna1729/upf/internal/bess"
)

// Owner pages contain SEIDs, not pointers into the session graph. They are
// noscan, allocated only for issued action ids, and bounded by the id space.
// Stale ids select at most an unnecessary evaluation: deletion removes the
// session, and reuse overwrites the owner before the new rules are settled.
const counterOwnerPage = 1024

// Separate arrays avoid padding every (uint64, uint32) pair to 16 bytes.
type counterOwnerBlock struct {
	seids    [counterOwnerPage]uint64
	readings [counterOwnerPage]uint32
}

type usageWork struct {
	owners  []*counterOwnerBlock
	pending map[uint64]struct{}
	spare   map[uint64]struct{}
	acks    map[string]uint64
	changes []uint32
	seids   []uint64
	ids     map[string][]uint32
	read    []bess.RuleCount
	enforce map[uint64]struct{}
	timers  usageDeadlines
	clock   time.Time
}

func (c *Compiler) queueUsage(s *Session) {
	if s.URRs.len() == 0 {
		return
	}
	if c.usage.pending == nil {
		c.usage.pending = make(map[uint64]struct{})
	}
	c.usage.pending[s.LocalSEID] = struct{}{}
}

func (c *Compiler) ownUsage(s *Session) {
	for _, p := range s.PDRs.all() {
		if _, ok := c.countedModule(p); !ok {
			continue
		}
		page := int(p.actionID / counterOwnerPage)
		if page >= len(c.usage.owners) {
			c.usage.owners = slices.Grow(c.usage.owners, page+1-len(c.usage.owners))
			c.usage.owners = c.usage.owners[:page+1]
		}
		if c.usage.owners[page] == nil {
			c.usage.owners[page] = new(counterOwnerBlock)
		}
		c.usage.owners[page].seids[p.actionID%counterOwnerPage] = s.LocalSEID
	}
}

func (u *usageWork) counterIndex(id uint32) *uint32 {
	page := int(id / counterOwnerPage)
	if page < len(u.owners) && u.owners[page] != nil {
		return &u.owners[page].readings[id%counterOwnerPage]
	}
	return nil
}

// The decision runs under mu. Readings point into the bounded RPC receive
// buffer, not a second copy or a pointerful array covering the whole id space.
func (u *usageWork) reading(id uint32) reading {
	if index := u.counterIndex(id); index != nil && *index != 0 {
		return readingOf(u.read[*index-1])
	}
	return reading{}
}

func (c *Compiler) indexUsageRead(start int) {
	for start < len(c.usage.read) {
		end := min(start+tickHold, len(c.usage.read))
		c.mu.Lock()
		for i := start; i < end; i++ {
			if index := c.usage.counterIndex(c.usage.read[i].ActionID); index != nil {
				*index = uint32(i + 1)
			}
		}
		c.mu.Unlock()
		start = end
	}
}

func (c *Compiler) clearUsageRead() {
	for start := 0; start < len(c.usage.read); start += tickHold {
		c.mu.Lock()
		for _, rule := range c.usage.read[start:min(start+tickHold, len(c.usage.read))] {
			if index := c.usage.counterIndex(rule.ActionID); index != nil {
				*index = 0
			}
		}
		c.mu.Unlock()
	}
	c.usage.read = c.usage.read[:0]
}

// scheduleUsage preserves time.Time's monotonic clock. Packet-stamped time
// limits advance only on activity; a backend without stamps retains the
// existing wall-window fallback. Linked URRs suppress their own reporting,
// never their quota enforcement. The caller holds mu.
func (c *Compiler) scheduleUsage(s *Session) {
	var earliest time.Time
	add := func(at time.Time) {
		if earliest.IsZero() || at.Before(earliest) {
			earliest = at
		}
	}
	for _, u := range s.URRs.all() {
		if !u.baselined {
			c.queueUsage(s)
			continue
		}
		if !u.linkedReporting && u.periodic {
			add(u.reported.Add(u.period))
		}
		if !u.stamped && u.duration {
			if !u.linkedReporting && u.onTimeTh && u.hasTimeTh {
				add(u.reported.Add(u.timeThreshold))
			}
			if u.onTimeQuota && u.hasTimeQuota && (!u.linkedReporting || !u.enforcing) {
				add(u.reported.Add(u.timeQuota))
			}
		}
		// Zero limits are already reached even without new packets. Requeue
		// once for the next poll, never repeatedly inside this poll's heap walk.
		if (!u.enforcing && u.quotaReached(Usage{}, Usage{}, 0)) ||
			(!u.linkedReporting && ((u.onVolumeTh && u.volume && u.volThreshold.reached(0, 0)) ||
				(u.onVolQuota && u.volume && u.volQuota.reached(0, 0)) ||
				(u.onTimeTh && u.duration && u.hasTimeTh && u.timeThreshold <= 0) ||
				(u.onTimeQuota && u.duration && u.hasTimeQuota && u.timeQuota <= 0))) {
			c.queueUsage(s)
		}
	}
	if !earliest.IsZero() && !earliest.After(c.usage.clock) {
		c.queueUsage(s)
		earliest = time.Time{}
	}
	c.usage.timers.set(s.LocalSEID, earliest)
}

func (c *Compiler) collectUsageChanges(ctx context.Context) {
	c.mu.Lock()
	active := len(c.measured) != 0
	c.mu.Unlock()
	if !active || c.counters == nil {
		return
	}
	if c.usage.acks == nil {
		c.usage.acks = make(map[string]uint64)
	}
	var names [2]string
	n := 0
	for _, table := range []struct {
		enabled bool
		table   Table
	}{
		{c.cfg.Up.Counters != "", CountersUplink},
		{c.cfg.Down.Counters != "", CountersDownlink},
	} {
		if table.enabled {
			module := c.target.Counts(table.table)
			if n == 0 || names[0] != module {
				names[n] = module
				n++
			}
		}
	}
	for _, module := range names[:n] {
		ack := c.usage.acks[module]
		var sequence, after uint64
		for {
			page, err := c.counters.AppendRuleChanges(ctx, c.usage.changes[:0], module, ack, sequence, after)
			if err == nil && sequence != 0 && sequence != page.Sequence {
				err = fmt.Errorf("counter snapshot changed during pagination")
			}
			if err == nil && page.NextAfter != 0 && page.NextAfter == after {
				err = fmt.Errorf("counter snapshot cursor did not advance")
			}
			if err != nil {
				c.log.Warn("session: usage activity", "module", module, "error", err)
				break // Already queued pages stay queued; do not acknowledge.
			}
			c.usage.changes = page.ActionIDs
			for start := 0; start < len(page.ActionIDs); start += tickHold {
				c.mu.Lock()
				for _, id := range page.ActionIDs[start:min(start+tickHold, len(page.ActionIDs))] {
					p := int(id / counterOwnerPage)
					if p < len(c.usage.owners) && c.usage.owners[p] != nil {
						if s := c.sessions[c.usage.owners[p].seids[id%counterOwnerPage]]; s != nil {
							c.queueUsage(s)
						}
					}
				}
				c.mu.Unlock()
			}
			sequence = page.Sequence
			if page.NextAfter == 0 {
				c.usage.acks[module] = sequence
				break
			}
			after = page.NextAfter
		}
	}
}

func (c *Compiler) takeUsageWork(now time.Time) map[uint64]struct{} {
	c.mu.Lock()
	// Concurrent changes enqueue already-due timers directly. They cannot
	// consume this bounded heap walk's budget and delay an older quota.
	c.usage.clock = now
	budget := len(c.usage.timers.items)
	c.mu.Unlock()
	for budget > 0 {
		c.mu.Lock()
		done := false
		for range min(budget, tickHold) {
			h := &c.usage.timers
			if len(h.items) == 0 || h.items[0].at.After(now) {
				done = true
				break
			}
			seid := h.items[0].seid
			h.remove(0)
			if s := c.sessions[seid]; s != nil {
				c.queueUsage(s)
			}
		}
		c.mu.Unlock()
		if done {
			break
		}
		budget -= min(budget, tickHold)
	}
	c.mu.Lock()
	work := c.usage.pending
	c.usage.pending, c.usage.spare = c.usage.spare, nil
	c.mu.Unlock()
	return work
}

// A typed binary heap avoids an interface allocation per expired deadline.
// Only sessions with clock-driven work enter it; updates replace, not append,
// so repeated PFCP changes cannot leave stale timers proportional to churn.
type usageDeadline struct {
	seid uint64
	at   time.Time
}
type usageDeadlines struct {
	items []usageDeadline
	index map[uint64]int
}

func (h *usageDeadlines) swap(a, b int) {
	h.items[a], h.items[b] = h.items[b], h.items[a]
	h.index[h.items[a].seid], h.index[h.items[b].seid] = a, b
}
func (h *usageDeadlines) fix(i int) {
	for i > 0 {
		p := (i - 1) / 2
		if !h.items[i].at.Before(h.items[p].at) {
			break
		}
		h.swap(i, p)
		i = p
	}
	for {
		child := i*2 + 1
		if child >= len(h.items) {
			return
		}
		if child+1 < len(h.items) && h.items[child+1].at.Before(h.items[child].at) {
			child++
		}
		if !h.items[child].at.Before(h.items[i].at) {
			return
		}
		h.swap(i, child)
		i = child
	}
}
func (h *usageDeadlines) remove(i int) {
	last := len(h.items) - 1
	seid := h.items[i].seid
	if i != last {
		h.swap(i, last)
	}
	h.items[last] = usageDeadline{}
	h.items = h.items[:last]
	delete(h.index, seid)
	if i != last {
		h.fix(i)
	}
}
func (h *usageDeadlines) set(seid uint64, at time.Time) {
	i, exists := h.index[seid]
	if at.IsZero() {
		if exists {
			h.remove(i)
		}
		return
	}
	if exists {
		h.items[i].at = at
		h.fix(i)
		return
	}
	if h.index == nil {
		h.index = make(map[uint64]int)
	}
	i = len(h.items)
	h.items = append(h.items, usageDeadline{seid, at})
	h.index[seid] = i
	h.fix(i)
}
