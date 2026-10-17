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
	"context"
	"errors"
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

// EvaluateDownlinks reads the BUFF branch's counters for every session and
// returns the Downlink Data Reports they owe, low SEID first -- one call per
// tick, the way EvaluateAll is. A flow is reported once per buffering episode:
// the flag stands until the SMF's next instruction stops the PDR buffering
// (resolve clears it), which is what "the first buffered DL packet" means when
// the SMF may leave a UE idle for hours.
//
// The reading is skipped when there is nothing to ask about, so a deployment
// with a store but no buffering session pays one map walk per tick and no RPC.
func (c *Compiler) EvaluateDownlinks(ctx context.Context) []Downlink {
	if !c.BufferingConfigured() || c.counters == nil {
		return nil
	}
	c.mu.Lock()
	// The rules to read, per session: the buffering PDRs whose report has not
	// been sent yet. A flow already reported is left out -- its arrivals are no
	// longer news -- so the RPC carries only what could change the answer.
	asks := make([]downlinkAsk, 0, len(c.sessions))
	for seid, s := range c.sessions {
		var ids []uint32
		for _, p := range pdrsInOrder(s) {
			if p.buffer && p.actionID != 0 && !p.ddnSent {
				ids = append(ids, p.actionID)
			}
		}
		if len(ids) > 0 {
			asks = append(asks, downlinkAsk{seid: seid, cpseid: s.CPSEID, ids: ids})
		}
	}
	c.mu.Unlock()
	// The asks are built by walking a map: the tick reads the sessions low SEID
	// first, so two runs against the same state ask in the same order.
	slices.SortFunc(asks, func(a, b downlinkAsk) int {
		switch {
		case a.seid < b.seid:
			return -1
		case a.seid > b.seid:
			return 1
		}
		return 0
	})

	var out []Downlink
	for _, a := range asks {
		read, err := c.peekBuffering(ctx, a.ids)
		if err != nil {
			// The counters could not be read: the report is owed but cannot be
			// decided, and the next tick tries again. Saying so is the caller's
			// log's business (upfd logs the tick's error), so the session is
			// skipped rather than failed.
			c.log.Warn("session: reading the buffering counters", "seid", a.seid, "error", err)
			continue
		}
		c.mu.Lock()
		s := c.sessions[a.seid]
		if s == nil {
			// The SMF deleted the session while the counters were being read.
			c.mu.Unlock()
			continue
		}
		d := Downlink{SEID: a.seid, CPSEID: s.CPSEID}
		for _, rule := range read {
			p := pdrByAction(s, rule.ActionID)
			// A stamp means a packet arrived since the previous reading: the
			// rule counted one, and the store is holding it.
			if p == nil || p.ddnSent || rule.First.IsZero() {
				continue
			}
			// Not marked here: the caller confirms what the SMF took
			// (ConfirmDownlinks), so a report nobody received is offered
			// again instead of being lost.
			d.PDRs = append(d.PDRs, p.id)
		}
		c.mu.Unlock()
		if len(d.PDRs) > 0 {
			out = append(out, d)
		}
	}
	return out
}

// peekBuffering reads the branch's counters without opening the next window: a
// report nobody took has to be readable again (WindowReader). A dataplane that
// offers only the ordinary reading is used as it is, and the cost is the retry
// of a report whose send failed.
func (c *Compiler) peekBuffering(ctx context.Context, ids []uint32) ([]bess.RuleCount, error) {
	if c.peek != nil {
		return c.peek.PeekRuleCounts(ctx, c.cfg.Buffering.Counter, ids...)
	}
	return c.counters.RuleCounts(ctx, c.cfg.Buffering.Counter, ids...)
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
		if _, err := c.counters.RuleCounts(ctx, c.cfg.Buffering.Counter, ids...); err != nil {
			// The stamps stay where they are, so this flow's report is offered
			// again: a duplicate report is better than one nobody took.
			c.log.Warn("session: the buffering counters were not read back", "seid", seid, "error", err)
		}
	}
}

// pdrByAction is the PDR a rule's ActionId names. The caller holds the lock.
func pdrByAction(s *Session, actionID uint32) *pdr {
	for _, p := range pdrsInOrder(s) {
		if p.actionID != 0 && p.actionID == actionID {
			return p
		}
	}
	return nil
}

// downlinkAsk is one tick's worth of work per session: the flows to read.
type downlinkAsk struct {
	seid   uint64
	cpseid uint64
	ids    []uint32
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

// releaseFlows tells the store to send what each flow holds, and counts what the
// datapath did not take. A store that is not there, or a command the daemon
// refuses, is a warning: the SMF's instruction is in force either way, and the
// held packets age out of the store by its own timeout if nobody collects them.
// A flow the store holds nothing for is neither: the ids come from the labels
// of PDRs that had a BUFF FAR (removedFlows, endedFlows), which is buffering
// being *in force*, not a downlink packet having arrived -- so on the common
// idle-to-service-request path there is simply nothing to release.
func (c *Compiler) releaseFlows(ctx context.Context, seid uint64, ids []uint32) {
	if !c.BufferingConfigured() || c.store == nil || len(ids) == 0 {
		return
	}
	for _, id := range ids {
		err := c.store.ReleaseFlow(ctx, c.cfg.Buffering.Store, id)
		if errors.Is(err, bess.ErrFlowNotHeld) {
			c.log.Debug("session: nothing was buffered for a flow whose buffering ended",
				"seid", seid, "flow", id)
			continue
		}
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
// forwarding them would need a path the session no longer has. Nothing held is
// the same non-event as it is for a release.
func (c *Compiler) dropFlows(ctx context.Context, seid uint64, ids []uint32) {
	if !c.BufferingConfigured() || c.store == nil || len(ids) == 0 {
		return
	}
	for _, id := range ids {
		err := c.store.DropFlow(ctx, c.cfg.Buffering.Store, id)
		if errors.Is(err, bess.ErrFlowNotHeld) {
			c.log.Debug("session: nothing was buffered for a flow of a session that went away",
				"seid", seid, "flow", id)
			continue
		}
		if err != nil {
			c.stats.bufferFailures.Add(1)
			c.log.Warn("session: a buffering flow was not dropped", "seid", seid, "flow", id, "error", err)
			continue
		}
		c.stats.buffersDropped.Add(1)
	}
}
