// SPDX-License-Identifier: BSD-3-Clause

// The Downlink Data Report half of the reporting path (TS 29.244 5.2.4.1 and
// 7.5.8.2): the SMF asked, with a FAR whose Apply Action is BUFF, for the
// packets of a downlink PDR to be held and for the first one to be reported, so
// that it can page the UE and move the path to it.
//
// Two facts make this the layer for it. The store itself is the datapath's --
// BESS's packet store holds the packets and releases or drops them on command --
// and what the control plane owns is *when* and *what* to report, which is PFCP:
// a Downlink Data Report IE naming the PDR(s) whose traffic arrived.
//
// The trigger is a poll, not a push. The counting module in front of the store
// counts each rule's arrivals, and this side reads those counters once per tick
// of the caller's clock (upfd's -urr-interval): a deployment that wants
// Downlink Data Reports must set that interval, and the report's latency is up
// to one tick. BESS's bounded dataplane->control event channel (its G1.4) is
// what replaces the counter hop when it lands; the shape here -- a report per
// rule, decided from what the dataplane counted -- is what it would carry.
//
// The reading is windowed: the counting module clears each rule's first-packet
// stamp when a reading asks it to, so a stamp means "a packet arrived since the
// previous reading". That is the spec's trigger ("the first buffered DL packet
// for each service data flow identified by a PDR"), and it keeps a fresh rule
// whose ActionId held an evicted rule's counters from reporting traffic it
// never saw.
package session

import (
	"cmp"
	"context"
	"slices"

	"github.com/wmnsk/go-pfcp/ie"

	"github.com/krsna1729/upf/internal/bess"
)

// Downlink is one session's owed Downlink Data Report: the PDRs whose first
// buffered downlink packet has arrived since the previous reading.
type Downlink struct {
	SEID   uint64
	CPSEID uint64
	// PDRs are the service data flows the report names, in the order their
	// rules are written.
	PDRs []uint16
}

// IEs is the report's IE list: the Report Type (8.2.21, with the DLDR bit -- the
// first thing an SMF reads, and the only thing that says what the rest of the
// message is) and the Downlink Data Report naming the PDRs. The DL Data Status
// is not included: it is the Downlink data delivery status notification
// feature's (DDDS, 8.2.25), which this UPF does not advertise, and claiming its
// fields without the notification semantics would be a report an SMF reads more
// strictly than it was written.
func (d Downlink) IEs() []*ie.IE {
	ids := make([]*ie.IE, 0, len(d.PDRs))
	for _, id := range d.PDRs {
		ids = append(ids, ie.NewPDRID(id))
	}
	return []*ie.IE{
		ie.NewReportType(0, 0, 0, 1), // USAR 0, ERIR 0, DLDR 1: this report is a downlink one
		ie.NewDownlinkDataReport(ids...),
	}
}

// BufferingConfigured reports whether this deployment has a store: the fact the
// association answer's own feature bits and the compiler's BUFF handling turn
// on (cmd/upfd sets the bit with the same config).
func (c *Compiler) BufferingConfigured() bool {
	return c.cfg.Buffering != nil && c.cfg.Buffering.Store != "" && c.cfg.Buffering.Counter != ""
}

// EvaluateDownlinks reads the BUFF branch's counters for every session that
// may owe one and returns the Downlink Data Reports they owe, low SEID first --
// one call per tick, the way EvaluateAll is. A flow is reported once per
// buffering episode: the flag stands until the SMF's next instruction stops the
// PDR buffering (resolve clears it), which is what "the first buffered DL
// packet" means when the SMF may leave a UE idle for hours.
//
// The tick walks the buffering set (Compiler.buffering), not every session, a
// bounded batch of sessions per hold of the lock, and reads every flow it asks
// about in one reading -- chunked by countChunk like the usage tick's -- rather
// than one per session: at the 1M target that was up to a million serial round
// trips per tick. With nothing to ask about it makes no RPC.
func (c *Compiler) EvaluateDownlinks(ctx context.Context) []Downlink {
	if !c.BufferingConfigured() || c.counters == nil {
		return nil
	}
	c.mu.Lock()
	seids := make([]uint64, 0, len(c.buffering))
	for seid := range c.buffering {
		seids = append(seids, seid)
	}
	c.mu.Unlock()
	slices.Sort(seids)

	// The flows to read: the buffering PDRs whose report has not been sent
	// yet, and whose they are. A flow already reported is left out -- its
	// arrivals are no longer news -- and a session that no longer buffers
	// leaves the set.
	var ids []uint32
	owners := map[uint32]downlinkFlow{}
	for start := 0; start < len(seids); start += tickHold {
		c.mu.Lock()
		for _, seid := range seids[start:min(start+tickHold, len(seids))] {
			buffering := false
			for _, p := range pdrsInOrder(c.sessions[seid]) {
				if !p.buffer || !p.notify {
					continue
				}
				buffering = true
				if p.actionID != 0 && !p.ddnSent {
					ids = append(ids, p.actionID)
					owners[p.actionID] = downlinkFlow{seid: seid, pdr: p.id, action: p.actionID}
				}
			}
			if !buffering {
				delete(c.buffering, seid)
			}
		}
		c.mu.Unlock()
	}

	// A stamp means a packet arrived since the previous reading: the rule
	// counted one, and the store is holding it. A chunk that cannot be read
	// leaves its flows owed, and the next tick tries again.
	var arrived []downlinkFlow
	for rest := ids; len(rest) > 0; {
		chunk := rest[:min(len(rest), countChunk)]
		rest = rest[len(chunk):]
		read, err := c.peekBuffering(ctx, chunk)
		if err != nil {
			c.log.Warn("session: reading the buffering counters", "flows", len(chunk), "error", err)
			continue
		}
		for _, rule := range read {
			if f, ok := owners[rule.ActionID]; ok && !rule.First.IsZero() {
				arrived = append(arrived, f)
			}
		}
	}
	// The reading answers in the order it was asked, low SEID first; the sort
	// keeps each session's flows in that order whatever the reply's.
	slices.SortStableFunc(arrived, func(a, b downlinkFlow) int { return cmp.Compare(a.seid, b.seid) })

	var out []Downlink
	for len(arrived) > 0 {
		seid := arrived[0].seid
		n := 1
		for n < len(arrived) && arrived[n].seid == seid {
			n++
		}
		flows := arrived[:n]
		arrived = arrived[n:]
		c.mu.Lock()
		s := c.sessions[seid]
		if s == nil {
			// The SMF deleted the session while the counters were being read.
			c.mu.Unlock()
			continue
		}
		d := Downlink{SEID: seid, CPSEID: s.CPSEID}
		for _, f := range flows {
			// Not marked here: the caller confirms what the SMF took
			// (ConfirmDownlinks), so a report nobody received is offered
			// again instead of being lost.
			if p := s.PDRs[f.pdr]; p != nil && p.actionID == f.action && !p.ddnSent {
				d.PDRs = append(d.PDRs, p.id)
			}
		}
		c.mu.Unlock()
		if len(d.PDRs) > 0 {
			out = append(out, d)
		}
	}
	return out
}

// tickHold is the most sessions one hold of the compiler's lock walks in a
// tick (EvaluateAll, EvaluateDownlinks): a tick over a million sessions must
// not stall every establishment behind it.
const tickHold = 1024

// downlinkFlow is one buffering PDR a tick asks about: its session, its id and
// the ActionId its counter is read by.
type downlinkFlow struct {
	seid   uint64
	pdr    uint16
	action uint32
}

// peekBuffering reads the branch's counters without opening the next window: a
// report nobody took has to be readable again (WindowReader). A dataplane that
// offers only the ordinary reading is used as it is, and the cost is the retry
// of a report whose send failed.
func (c *Compiler) peekBuffering(ctx context.Context, ids []uint32) ([]bess.RuleCount, error) {
	if c.peek != nil {
		return c.peek.PeekRuleCounts(ctx, c.target.Counts(BufferCounters), ids...)
	}
	return c.counters.RuleCounts(ctx, c.target.Counts(BufferCounters), ids...)
}

// ConfirmDownlinks marks the reports a caller has delivered, which is what stops
// the next tick from offering them again: a flow owes one Downlink Data Report
// per buffering episode ("the first buffered DL packet", 5.2.4.1). A caller that
// could not deliver one leaves it unconfirmed and the next tick offers it again
// -- what the flag stands for is the SMF knowing, not this node sending.
//
// The reading that clears the rules' first-packet stamps happens here, and only
// for the flows a report was delivered for: until then the stamps say "these
// flows' packets are still news".
func (c *Compiler) ConfirmDownlinks(ctx context.Context, seid uint64, pdrs []uint16) {
	if len(pdrs) == 0 {
		return
	}
	c.mu.Lock()
	s := c.sessions[seid]
	if s == nil {
		c.mu.Unlock()
		return
	}
	var ids []uint32
	for _, id := range pdrs {
		if p := s.PDRs[id]; p != nil && p.actionID != 0 {
			p.ddnSent = true
			ids = append(ids, p.actionID)
			continue
		}
	}
	c.mu.Unlock()
	if c.counters != nil && len(ids) > 0 {
		if _, err := c.counters.RuleCounts(ctx, c.target.Counts(BufferCounters), ids...); err != nil {
			// The stamps stay where they are, so this flow's report is offered
			// again: a duplicate report is better than one nobody took.
			c.log.Warn("session: the buffering counters were not read back", "seid", seid, "error", err)
		}
	}
}

// barHoldsAFlow reports whether a PDR of the session buffers under this BAR: a
// downlink FAR that names it with Apply Action BUFF and not FORW (8.2.26), the
// state resolve writes for the idle-UE case. The caller holds the lock.
func barHoldsAFlow(s *Session, id uint8) bool {
	for _, p := range s.PDRs {
		if !p.buffer {
			continue
		}
		if f := s.FARs[p.farID]; f != nil && f.hasBAR && f.barID == id {
			return true
		}
	}
	return false
}

// ApplyUpdateBAR applies the Update BAR a Session Report Response carried
// (TS 29.244 5.2.4.1): when the CP function answers a Downlink Data Report it
// may extend the buffering of the flow that held the packets, and those numbers
// replace the ones a Session Modification set for the same BAR ID. It writes the
// same model a modification's Update BAR does -- the DL Buffering Duration
// (8.2.29, with its stopped-timer and infinite codes) and the DL Buffering
// Suggested Packet Count (8.2.30) -- under the compiler's lock and in one step.
//
// The numbers then reach the store's per-flow "flows" entry of every PDR that
// buffers under this BAR (writeFlowEntry): the entry carries the timeout and the
// cap the SMF just sent, so its extension is what expires and caps the flow that
// is holding packets now, rather than the next time a request compiles the
// session. That is one transaction of those entries alone.
//
// This call runs on the reporting goroutine, not the PFCP read loop, so it holds
// the compiler's lock only long enough to read the model and build the changes,
// and applies them after releasing it. A session the SMF deleted meanwhile is
// already out of c.sessions and is caught above; the worst a late landing leaves
// is a per-flow entry for an ActionId no live rule names -- the sweep takes it
// at the next restart, and a later session that reuses the id overwrites it, so
// nothing is served the numbers of an episode it never had. A response is not a
// request: nothing here is ever refused to the SMF, because there is no answer
// to an answer.
//
// A response that carries no BAR, names a BAR the session does not hold, or
// arrives after the flow's buffering episode has ended is a logged no-op -- the
// treatment a stray report response gets (internal/n4.onReportResponse) --
// rather than a write to some other BAR or a resurrection of an episode that is
// over.
func (c *Compiler) ApplyUpdateBAR(_ context.Context, seid uint64, update *ie.IE) {
	if update == nil {
		return
	}
	b, err := parseBAR(update)
	if err != nil {
		c.log.Warn("session: cannot read the Update BAR of a Session Report Response",
			"seid", seid, "error", err)
		return
	}
	c.mu.Lock()
	s := c.sessions[seid]
	if s == nil {
		c.mu.Unlock()
		c.log.Info("session: an Update BAR names a session that is gone; it is ignored",
			"seid", seid, "bar", b.id)
		return
	}
	if s.BARs[b.id] == nil {
		// The SMF named a BAR this session does not hold. Applying it would
		// create one under numbers nobody provisioned -- the guess a FAR naming
		// an unknown BAR is refused for -- so it is dropped.
		c.mu.Unlock()
		c.log.Info("session: an Update BAR names a BAR the session does not hold; it is ignored",
			"seid", seid, "bar", b.id)
		return
	}
	if !barHoldsAFlow(s, b.id) {
		// The episode this report answered is over: the SMF's own instruction
		// moved the PDR off buffering (or the PDR went), and applying the
		// numbers now would leave them for a later episode they were never sent
		// for. 5.2.4.1's "stop applying buffering when new instruction is
		// received" is that move, and this response does not undo it.
		c.mu.Unlock()
		c.log.Info("session: an Update BAR arrives after its flow stopped buffering; it is ignored",
			"seid", seid, "bar", b.id)
		return
	}
	mergeBars(s, []barReq{b})
	var changes []bess.Change
	if c.cfg.Buffering != nil && c.cfg.Buffering.Store != "" {
		for _, p := range pdrsInOrder(s) {
			if !p.buffer {
				continue
			}
			if f := s.FARs[p.farID]; f == nil || !f.hasBAR || f.barID != b.id {
				continue
			}
			changes = append(changes, c.writeFlowEntry(s.BARs[b.id], p)...)
		}
	}
	c.mu.Unlock()
	if len(changes) > 0 {
		if err := c.ap.Apply(context.Background(), changes...); err != nil {
			c.log.Warn("session: the store's per-flow entry was not rewritten for an Update BAR",
				"seid", seid, "bar", b.id, "error", err)
		}
	}
	c.log.Info("session: an Update BAR in a Session Report Response was applied",
		"seid", seid, "bar", b.id, "duration", b.duration, "infinite", b.infinite, "count", b.count)
}

// endedFlows is the flows whose buffering episode the model has just ended
// (resolve recorded them): the packets they hold are released once the
// transaction that carried the change has landed, not before. The caller holds
// the lock and reads this before settle clears the list.
func endedFlows(s *Session) []uint32 {
	return append([]uint32(nil), s.ending...)
}

// removedFlows is the flows a modification took off the graph: their PDRs are
// gone, so there is no path to forward what they held over and the packets are
// dropped instead. The caller holds the lock, before settle clears the list.
func removedFlows(s *Session) []uint32 {
	var out []uint32
	for _, old := range s.removed {
		if old.buffer && old.actionID != 0 {
			out = append(out, old.actionID)
		}
	}
	return out
}

// releaseFlows tells the store to send what each flow holds, and counts the
// commands the daemon took. A store that is not there, or a command the daemon
// refuses, is a warning: the SMF's instruction is in force either way, and the
// held packets age out of the store by its own timeout if nobody collects them.
// The only refusal left is ENOSPC, the store's request ring being full. The call
// is accepted, not completed -- the store applies the request on a later task
// run -- so buffersReleased counts *accepted* release commands; what the
// packets did is read back from the store (`ps/flows`, the release counters).
// A flow the store holds nothing for is a no-op, not a refusal: the ids come
// from the labels of PDRs that had a BUFF FAR (removedFlows, endedFlows), which
// is buffering being *in force*, not a downlink packet having arrived -- so on
// the common idle-to-service-request path there is simply nothing to release.
func (c *Compiler) releaseFlows(ctx context.Context, seid uint64, ids []uint32) {
	if !c.BufferingConfigured() || c.store == nil || len(ids) == 0 {
		return
	}
	for _, id := range ids {
		err := c.store.ReleaseFlow(ctx, c.target.Store(), id)
		if err != nil {
			c.stats.bufferFailures.Add(1)
			c.log.Warn("session: a buffering flow was not released", "seid", seid, "flow", id, "error", err)
			continue
		}
		c.stats.buffersReleased.Add(1)
	}
}

// dropFlows is releaseFlows' other half for a session that is going away
// (TS 29.244 5.2.4.1: the packets "shall be either dropped or forwarded"):
// forwarding them would need a path the session no longer has. It is accepted
// the same way -- buffersDropped counts accepted drop commands, and the store
// frees the packets on a later task run -- and a flow the store holds nothing
// for is the same no-op as it is for a release.
func (c *Compiler) dropFlows(ctx context.Context, seid uint64, ids []uint32) {
	if !c.BufferingConfigured() || c.store == nil || len(ids) == 0 {
		return
	}
	for _, id := range ids {
		err := c.store.DropFlow(ctx, c.target.Store(), id)
		if err != nil {
			c.stats.bufferFailures.Add(1)
			c.log.Warn("session: a buffering flow was not dropped", "seid", seid, "flow", id, "error", err)
			continue
		}
		c.stats.buffersDropped.Add(1)
	}
}
