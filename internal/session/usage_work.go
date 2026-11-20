// SPDX-License-Identifier: BSD-3-Clause
package session

import (
	"context"
	"fmt"
	"math/bits"
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
	owners []*counterOwnerBlock
	// pending is the sessions the next usage tick reads; spare is the set
	// the previous tick took, emptied, waiting to be pending again.
	pending sessionSet
	spare   sessionSet
	acks    map[string]uint64
	changes []uint32
	seids   []uint64
	slots   []uint32 // seids' slots, in step
	ids     map[string][]uint32
	read    []bess.RuleCount
	enforce sessionSet
	timers  usageDeadlines
	clock   time.Time
}

// sessionSlots numbers live sessions densely from 1 (Session.slot), so a set
// of sessions is a bitset over slots (sessionSet) rather than a map of SEIDs:
// a bit per session where a map[uint64]struct{} entry cost 27 B at 20,000
// entries and 38 B at a million. seids[slot] is the slot's session, 0 while
// the slot is free; a freed slot is the next one taken. A session takes its
// slot when it first joins a set (slotOf) and gives it back in
// releaseSession, so both arrays are bounded by the most sessions live at
// once. An establishment whose transaction went unanswered is never released
// (its ids stay allocated, the safe failure) and keeps its slot too.
type sessionSlots struct {
	seids []uint64
	free  []uint32
}

func (x *sessionSlots) take(seid uint64) uint32 {
	if n := len(x.free); n != 0 {
		slot := x.free[n-1]
		x.free = x.free[:n-1]
		x.seids[slot] = seid
		return slot
	}
	if len(x.seids) == 0 {
		x.seids = append(x.seids, 0) // slot 0 is no slot
	}
	x.seids = append(x.seids, seid)
	return uint32(len(x.seids) - 1)
}

func (x *sessionSlots) release(slot uint32) {
	x.seids[slot] = 0
	x.free = append(x.free, slot)
}

// slotOf is s's slot, taken if it has none. The caller holds the lock.
func (c *Compiler) slotOf(s *Session) uint32 {
	if s.slot == 0 {
		s.slot = c.slots.take(s.LocalSEID)
	}
	return s.slot
}

// sessionSet is a set of sessions by slot: a bitset, noscan, with its
// member count. It grows to the highest slot added and is cleared in place.
type sessionSet struct {
	words []uint64
	n     int
}

func (b *sessionSet) add(slot uint32) {
	w := int(slot / 64)
	if w >= len(b.words) {
		b.words = append(b.words, make([]uint64, w+1-len(b.words))...)
	}
	if bit := uint64(1) << (slot % 64); b.words[w]&bit == 0 {
		b.words[w] |= bit
		b.n++
	}
}

func (b *sessionSet) remove(slot uint32) {
	if w := int(slot / 64); w < len(b.words) {
		if bit := uint64(1) << (slot % 64); b.words[w]&bit != 0 {
			b.words[w] &^= bit
			b.n--
		}
	}
}

func (b *sessionSet) has(slot uint32) bool {
	w := int(slot / 64)
	return w < len(b.words) && b.words[w]&(uint64(1)<<(slot%64)) != 0
}

func (b *sessionSet) len() int { return b.n }

func (b *sessionSet) clear() {
	clear(b.words)
	b.n = 0
}

// union adds every member of o.
func (b *sessionSet) union(o *sessionSet) {
	for w, word := range o.words {
		for ; word != 0; word &= word - 1 {
			b.add(uint32(w*64 + bits.TrailingZeros64(word)))
		}
	}
}

// page appends to slots up to limit members at or after slot from, in slot
// order, and returns where the next page starts: 0 once none is left (slot 0
// is never a member). A tick takes a set in pages so that no hold of the lock
// walks it whole.
func (b *sessionSet) page(slots []uint32, from uint32, limit int) ([]uint32, uint32) {
	for w := int(from / 64); w < len(b.words); w++ {
		word := b.words[w]
		if w == int(from/64) {
			word &^= uint64(1)<<(from%64) - 1
		}
		for ; word != 0; word &= word - 1 {
			slot := uint32(w*64 + bits.TrailingZeros64(word))
			if limit == 0 {
				return slots, slot
			}
			slots = append(slots, slot)
			limit--
		}
	}
	return slots, 0
}

func (c *Compiler) queueUsage(s *Session) {
	if s.URRs.len() == 0 {
		return
	}
	c.usage.pending.add(c.slotOf(s))
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
		l := c.limits(u)
		if !l.linkedReporting && l.periodic {
			add(u.reported.time().Add(l.period))
		}
		if !u.stamped && l.duration {
			if !l.linkedReporting && l.onTimeTh && l.hasTimeTh {
				add(u.reported.time().Add(l.timeThreshold))
			}
			if l.onTimeQuota && l.hasTimeQuota && (!l.linkedReporting || !u.enforcing) {
				add(u.reported.time().Add(l.timeQuota))
			}
		}
		// Zero limits are already reached even without new packets. Requeue
		// once for the next poll, never repeatedly inside this poll's heap walk.
		if (!u.enforcing && l.quotaReached(Usage{}, Usage{}, 0)) ||
			(!l.linkedReporting && ((l.onVolumeTh && l.volume && l.volThreshold.reached(0, 0)) ||
				(l.onVolQuota && l.volume && l.volQuota.reached(0, 0)) ||
				(l.onTimeTh && l.duration && l.hasTimeTh && l.timeThreshold <= 0) ||
				(l.onTimeQuota && l.duration && l.hasTimeQuota && l.timeQuota <= 0))) {
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
	active := c.measured.len() != 0
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

func (c *Compiler) takeUsageWork(now time.Time) sessionSet {
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
	c.usage.pending, c.usage.spare = c.usage.spare, sessionSet{}
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
