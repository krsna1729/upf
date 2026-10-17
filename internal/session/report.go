// SPDX-License-Identifier: BSD-3-Clause
// Usage reporting: reading the dataplane's counters (the module the compiler
// writes an entry into for every rule a URR measures), deciding what the SMF
// must hear (TS 29.244 5.2.2.2.1, 5.2.2.3), and what a used-up quota does to
// the traffic. The decision is here, where the session model is; the report
// itself is a PFCP Session Report Request, which is the n4 layer's to send, so
// Evaluate hands over what is owed instead of sending it.
//
// **The window.** Every limit and the period are measured over the usage since
// the URR's last report, and a report opens a new window. A volume threshold
// that fired therefore does not fire again on the traffic it already reported,
// and a quota that stopped the traffic re-opens it only when the SMF
// provisions a new quota or threshold (an Update URR clears the flag, the same
// lever 5.2.2.2.1 gives it). The alternative reading -- accumulate from
// provisioning and compare the running total -- needs a second base per URR to
// keep the report's own window apart from the limit's, and this one gives the
// SMF the same control with the one base the model already has.
package session

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
)

// Usage is what crossed the rules a URR measures: the packets and the octets of
// their IP packets, as the counting module holds them.
type Usage struct {
	Packets uint64
	Octets  uint64
}

// add is the sum of two readings.
func (u Usage) add(v Usage) Usage {
	return Usage{Packets: u.Packets + v.Packets, Octets: u.Octets + v.Octets}
}

// since is the usage between two readings of the same counters. A worker that
// restarted reads lower than before, and a difference that is not an increase
// is no usage at all: this way usage can be under-reported, never invented.
func (u Usage) since(prev Usage) Usage {
	if u.Packets <= prev.Packets || u.Octets <= prev.Octets {
		return Usage{}
	}
	return Usage{Packets: u.Packets - prev.Packets, Octets: u.Octets - prev.Octets}
}

// Trigger is why a report is on its way: the reporting trigger that fired
// (TS 29.244 8.2.19).
type Trigger uint8

const (
	TriggerPeriod Trigger = iota
	TriggerVolumeThreshold
	TriggerTimeThreshold
	TriggerVolumeQuota
	TriggerTimeQuota
)

// String names the trigger as a log line and a failure message do.
func (t Trigger) String() string {
	switch t {
	case TriggerPeriod:
		return "period"
	case TriggerVolumeThreshold:
		return "volume threshold"
	case TriggerTimeThreshold:
		return "time threshold"
	case TriggerVolumeQuota:
		return "volume quota"
	case TriggerTimeQuota:
		return "time quota"
	}
	return "unknown trigger"
}

// Report is one report this UPF owes the SMF for one URR: why it is due, and
// the usage of the window it covers.
type Report struct {
	SEID   uint64 // the UP F-SEID, as the SMF knows it
	CPSEID uint64 // the CP function's, for the message's F-SEID
	URRID  uint32

	// Trigger is the reason this report is due. One reason is carried even
	// where a window satisfies several (the SMF asked for whichever fires
	// first); a report that carries its own usage says what the others would.
	Trigger Trigger

	// Seqn is the UR-SEQN: the first report of a URR is 0 (5.2.2.3).
	Seqn uint32

	// Up and Down are the window's usage, by the direction the PDRs face.
	Up, Down Usage

	// Duration is the window's length: what a URR that measures time reports.
	Duration time.Duration

	// Enforcing says this report stops the traffic: a quota it carries is used
	// up, and the PDRs that name the URR now compile to a drop.
	Enforcing bool
}

// Evaluate reads the counters of one session's URRs and decides what is due:
// each URR whose period has passed or whose threshold or quota is reached gets
// a Report, and a URR whose quota is used up stops the traffic of its PDRs --
// one transaction, the same way a modification writes them.
//
// The counters are read before the model is judged, so a session the SMF
// modified or deleted while the reading was on the wire is checked again after
// it; a report for a session the SMF no longer has would be worse than none.
// The error is returned *alongside* whatever reports were decided: an
// enforcement the dataplane refused still leaves the SMF owed the report that
// says the quota is spent.
func (c *Compiler) Evaluate(ctx context.Context, seid uint64, now time.Time) ([]Report, error) {
	c.mu.Lock()
	s := c.sessions[seid]
	if s == nil {
		c.mu.Unlock()
		return nil, fmt.Errorf("no session with local SEID %d", seid)
	}
	// The rules to read, by the module that counts them: one per PDR a URR
	// measures. A PDR a used-up quota already stopped has no counter of its
	// own and nothing to report.
	ids := map[string][]uint32{}
	for _, p := range pdrsInOrder(s) {
		if len(p.urrIDs) == 0 || p.actionID == 0 || p.drop {
			continue
		}
		if dir := c.direction(p.srcIfc); dir.Counters != "" {
			ids[dir.Counters] = append(ids[dir.Counters], p.actionID)
		}
	}
	c.mu.Unlock()

	if len(ids) == 0 {
		return nil, nil
	}
	reader := c.counters
	if reader == nil {
		// The graph has no counting module this control plane can read, and the
		// session's URRs would report nothing: saying so is better than
		// reporting zero forever (the compiler refuses such a session when it
		// is established; this is the same fact found later).
		return nil, fmt.Errorf("the dataplane of this graph holds no usage counters")
	}
	counts := make(map[string]map[uint32]Usage, len(ids))
	for module, rules := range ids {
		read, err := reader.RuleCounts(ctx, module, rules...)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", module, err)
		}
		cells := make(map[uint32]Usage, len(read))
		for _, rule := range read {
			cells[rule.ActionID] = Usage{Packets: rule.Packets, Octets: rule.Octets}
		}
		counts[module] = cells
	}

	c.mu.Lock()
	if c.sessions[seid] != s {
		c.mu.Unlock()
		// The session went away while its counters were being read: the usage
		// belongs to a session the SMF no longer has.
		return nil, nil
	}
	reports, stopped := c.decide(s, counts, now)
	c.mu.Unlock()

	if !stopped {
		return reports, nil
	}
	// The enforcement is a dataplane change, and it is compiled the way a
	// modification compiles one: the PDRs that name the URR come out as drops.
	changes, _, err := c.compile(s)
	if err != nil {
		return reports, fmt.Errorf("compiling the enforcement: %w", err)
	}
	if err := c.ap.Apply(ctx, changes...); err != nil {
		// The flag stays in the model, so the next evaluation compiles the same
		// enforcement again; until it lands the traffic keeps flowing over a
		// quota, which the report says.
		return reports, fmt.Errorf("the dataplane refused the enforcement: %w", err)
	}
	c.settle(s)
	return reports, nil
}

// decide updates every URR's bookkeeping and returns the reports they owe, and
// whether any of them is enforcing something the dataplane has not been told
// yet. The caller holds the lock.
func (c *Compiler) decide(s *Session, counts map[string]map[uint32]Usage, now time.Time) ([]Report, bool) {
	var reports []Report
	stopped := false
	for _, uid := range urrIDsInOrder(s) {
		u := s.URRs[uid]
		up, down := c.countsOf(s, uid, counts)
		if !u.hasSeen && (up.Packets > 0 || down.Packets > 0) {
			// The measurement starts with the first packet that arrives: the
			// duration of a URR that measures time is the time its traffic has
			// been running (5.2.2.2.1).
			u.hasSeen, u.firstSeen = true, now
		}
		window := now.Sub(u.reported)
		if window < 0 {
			window = 0
		}
		upWindow, downWindow := up.since(u.lastUp), down.since(u.lastDown)
		trigger, due := u.due(upWindow, downWindow, window)
		if !due {
			continue
		}
		if trigger == TriggerVolumeQuota || trigger == TriggerTimeQuota {
			if !u.enforcing {
				u.enforcing = true
				stopped = true
			}
		}
		reports = append(reports, Report{
			SEID: s.LocalSEID, CPSEID: s.CPSEID, URRID: uid,
			Trigger: trigger, Seqn: u.seqn,
			Up: upWindow, Down: downWindow,
			Duration: window, Enforcing: u.enforcing,
		})
		// The report opens the URR's next window, and it is the SMF's message
		// that carries this usage: the counters are not reset (the dataplane
		// knows nothing of reports), so the base is what moves.
		u.reported, u.lastUp, u.lastDown = now, up, down
		u.seqn++
	}
	return reports, stopped
}

// countsOf is what the rules a URR measures have counted, per direction: the
// sum of their counters, keyed by each rule's own ActionId. The caller holds
// the lock.
func (c *Compiler) countsOf(s *Session, uid uint32, counts map[string]map[uint32]Usage) (up, down Usage) {
	for _, p := range pdrsInOrder(s) {
		if p.actionID == 0 || p.drop || !slices.Contains(p.urrIDs, uid) {
			continue
		}
		dir := c.direction(p.srcIfc)
		if dir.Counters == "" {
			continue
		}
		cell := counts[dir.Counters][p.actionID]
		if p.srcIfc == ie.SrcInterfaceAccess {
			up = up.add(cell)
		} else {
			down = down.add(cell)
		}
	}
	return up, down
}

// due is the reason this URR owes a report now, if it owes one: its period has
// passed, or a limit it measures is reached. The triggers are tried in the
// URR's own order, so a window that satisfies several reports the first of
// them.
func (u *urr) due(up, down Usage, window time.Duration) (Trigger, bool) {
	if u.periodic && window >= u.period {
		return TriggerPeriod, true
	}
	if u.onVolumeTh && u.volume && u.volThreshold.reached(up.Octets, down.Octets) {
		return TriggerVolumeThreshold, true
	}
	if u.onTimeTh && u.duration && u.hasTimeTh && window >= u.timeThreshold {
		return TriggerTimeThreshold, true
	}
	if u.onVolQuota && u.volume && u.volQuota.reached(up.Octets, down.Octets) {
		return TriggerVolumeQuota, true
	}
	if u.onTimeQuota && u.duration && u.hasTimeQuota && window >= u.timeQuota {
		return TriggerTimeQuota, true
	}
	return 0, false
}

// urrIDsInOrder is a session's URR ids, low to high: a session with several
// URRs reports them in one order whatever the map's is.
func urrIDsInOrder(s *Session) []uint32 {
	ids := make([]uint32, 0, len(s.URRs))
	for id := range s.URRs {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}
