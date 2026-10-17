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
// lever 5.2.2.2.1 gives it). The window's base is taken from the counters as
// they are read: the first reading of a URR *is* its baseline, because the
// module's cells outlive an erased entry and the pool reissues action ids --
// the totals a fresh rule's ActionId holds may be the previous rule's, and a
// quota must not be spent by traffic that is not this URR's. The alternative
// reading -- accumulate from provisioning and compare the running total --
// needs a second base per URR to keep the report's own window apart from the
// limit's, and this one gives the SMF the same control with the one base the
// model already has.
//
// **Time.** The counting module stamps each rule's first packet since a reading
// and its last one, and a reading that asks for the next window clears the
// first. The controller therefore measures a time threshold and a time quota
// against the time the *window's* traffic ran -- the window's own first packet
// to the reading's last one -- which is the base the volume limits use, with
// the idle gaps taken out. A graph whose counters carry no stamp falls back to
// the window's length, the number the clock gives while the traffic is
// continuous.
package session

import (
	"context"
	"errors"
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

// errNoSession marks a session the compiler does not hold: the SMF deleted it,
// which a caller that walks every session (EvaluateAll) meets as a race rather
// than as a failure.
var errNoSession = errors.New("no such session")

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

// reading is one rule's answer from a counting module: what it counted, and
// when its first and last counted packet crossed. The stamps cover the tick the
// reading was taken in -- a reading clears the first one -- and are zero when
// the module carries none (a plugin built before them) or nothing was counted
// since the previous reading.
type reading struct {
	Usage
	First, Last time.Time
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

	// First and Last are when the window's first and last counted packet
	// crossed, from the dataplane's own stamps (TS 29.244 8.2.44, 8.2.45). A
	// graph whose counters carry no stamp leaves them zero, and the report then
	// omits them rather than inventing a time.
	First, Last time.Time

	// Enforcing says this report stops the traffic: a quota it carries is used
	// up, and the PDRs that name the URR now compile to a drop.
	Enforcing bool
}

// flags is the Reporting Trigger this report carries (8.2.19), as the two
// octets the IE holds: the bits are the ones a URR's own request sets, so the
// SMF reads back the trigger it asked for.
func (t Trigger) flags() (octet5, octet6 uint8) {
	switch t {
	case TriggerPeriod:
		return trigPeriodic, 0
	case TriggerVolumeThreshold:
		return trigVolumeTh, 0
	case TriggerTimeThreshold:
		return trigTimeTh, 0
	case TriggerVolumeQuota:
		return 0, trigVolQuota
	case TriggerTimeQuota:
		return 0, trigTimeQuota
	}
	return 0, 0
}

// IEs is this report as the IEs a Session Report Request carries (7.5.8.2): the
// Report Type, and the Usage Report with the URR, the UR-SEQN, the trigger and
// the volume measured. They are built here, in the package that decided the
// numbers, so the n4 layer sends what it is given and nothing else has to know
// which bit means which trigger.
func (r Report) IEs() []*ie.IE {
	total := r.Up.add(r.Down)
	octet5, octet6 := r.Trigger.flags()
	// The IE holds the octets it needs: a quota's trigger is in octet 6, and
	// leading with an empty octet 5 would be a bit the SMF did not ask for.
	trigger := []uint8{octet5}
	if octet5 == 0 {
		trigger = []uint8{octet6}
	} else if octet6 != 0 {
		trigger = append(trigger, octet6)
	}
	usage := []*ie.IE{
		ie.NewURRID(r.URRID),
		ie.NewURSEQN(r.Seqn),
		ie.NewUsageReportTrigger(trigger...),
		// All six counts: the SMF may bill either the total or the
		// directions, and the UPF knows all of them (8.2.44).
		ie.NewVolumeMeasurement(0x3f,
			total.Octets, r.Up.Octets, r.Down.Octets,
			total.Packets, r.Up.Packets, r.Down.Packets),
		ie.NewDurationMeasurement(r.Duration),
	}
	// When the window's traffic ran, from the dataplane's own stamps: optional
	// IEs an SMF reads for a duration measurement (8.2.44, 8.2.45), omitted
	// rather than guessed when the counters carry none.
	if !r.First.IsZero() {
		usage = append(usage, ie.NewTimeOfFirstPacket(r.First))
	}
	if !r.Last.IsZero() {
		usage = append(usage, ie.NewTimeOfLastPacket(r.Last))
	}
	return []*ie.IE{
		// A usage report for this URR, not an event report and not a
		// downlink-data report: what the counters measured (8.2.18).
		ie.NewReportType(0, 0, 1, 0),
		ie.NewUsageReportWithinSessionReportRequest(usage...),
	}
}

// EvaluateAll is Evaluate for every session the compiler holds, low SEID first,
// so one tick of a caller that owns the clock (upfd's reporting loop) is one
// call. A session the SMF deleted while the counters were being read is skipped
// rather than failed: the usage belongs to a session nobody has.
func (c *Compiler) EvaluateAll(ctx context.Context, now time.Time) []Report {
	c.mu.Lock()
	seids := make([]uint64, 0, len(c.sessions))
	for seid := range c.sessions {
		seids = append(seids, seid)
	}
	c.mu.Unlock()
	slices.Sort(seids)

	var out []Report
	for _, seid := range seids {
		reports, err := c.Evaluate(ctx, seid, now)
		if err != nil {
			if errors.Is(err, errNoSession) {
				// The SMF deleted it between the list above and this call: the
				// usage belongs to a session nobody has.
				continue
			}
			// The counters could not be read, or the dataplane refused the
			// enforcement: the caller's log is where an operator sees it, and
			// the reports decided before the failure are still owed.
			c.log.Warn("session: usage evaluation", "seid", seid, "error", err)
		}
		out = append(out, reports...)
	}
	return out
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
		return nil, fmt.Errorf("no session with local SEID %d: %w", seid, errNoSession)
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
	counts := make(map[string]map[uint32]reading, len(ids))
	for module, rules := range ids {
		read, err := reader.RuleCounts(ctx, module, rules...)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", module, err)
		}
		cells := make(map[uint32]reading, len(read))
		for _, rule := range read {
			cells[rule.ActionID] = reading{
				Usage: Usage{Packets: rule.Packets, Octets: rule.Octets},
				First: rule.First, Last: rule.Last,
			}
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
func (c *Compiler) decide(s *Session, counts map[string]map[uint32]reading, now time.Time) ([]Report, bool) {
	var reports []Report
	stopped := false
	for _, uid := range urrIDsInOrder(s) {
		u := s.URRs[uid]
		up, down, first, last := c.countsOf(s, uid, counts)
		// The first reading of a URR is its baseline, not its usage. The
		// counting module's cells outlive an erased entry and the action pool
		// reissues ids, so a fresh rule's ActionId can still hold the totals of
		// the rule that had it before -- and a quota must not be spent by
		// traffic that is not this URR's. What this costs is the usage between
		// the URR's provisioning and the first reading: one evaluation
		// interval, under-counted rather than invented.
		if !u.baselined {
			u.baselined = true
			u.reported, u.lastUp, u.lastDown = now, up, down
			continue
		}
		window := now.Sub(u.reported)
		if window < 0 {
			window = 0
		}
		upWindow, downWindow := up.since(u.lastUp), down.since(u.lastDown)
		if !first.IsZero() && !last.Before(first) {
			// This reading counted packets: it is the window's first activity
			// when the window has none yet, and it is its last one.
			u.stamped = true
			if u.windowFirst.IsZero() {
				u.windowFirst = first
			}
			u.windowLast = last
		}
		// The time a window's traffic ran is what a time limit is measured
		// against -- the window's own first counted packet to its own last one,
		// the same base the volume limits use, with the idle between them taken
		// out. A graph whose counters carry no stamp at all falls back to the
		// window's length, the number the clock gives while the traffic runs.
		windowActive := window
		if u.stamped {
			windowActive = 0
			if !u.windowFirst.IsZero() {
				windowActive = u.windowLast.Sub(u.windowFirst)
			}
		}
		first, last = windowTimes(u.windowFirst, u.windowLast, upWindow, downWindow)
		// A limit that is reached stops the traffic whether or not it is the
		// reason this report is going: a period that ends in the same window as
		// a quota must not swallow the enforcement, and the window the report
		// opens would otherwise put the quota out of reach of the next one.
		if u.quotaReached(upWindow, downWindow, windowActive) && !u.enforcing {
			u.enforcing = true
			stopped = true
		}
		trigger, due := u.due(upWindow, downWindow, window, windowActive)
		if !due {
			continue
		}
		reports = append(reports, Report{
			SEID: s.LocalSEID, CPSEID: s.CPSEID, URRID: uid,
			Trigger: trigger, Seqn: u.seqn,
			Up: upWindow, Down: downWindow,
			Duration: window, First: first, Last: last, Enforcing: u.enforcing,
		})
		// The report opens the URR's next window, and it is the SMF's message
		// that carries this usage: the counters are not reset (the dataplane
		// knows nothing of reports), so the base is what moves -- and with it
		// the window's own stamps, which the next tick writes afresh.
		u.reported, u.lastUp, u.lastDown = now, up, down
		u.windowFirst, u.windowLast = time.Time{}, time.Time{}
		u.seqn++
	}
	return reports, stopped
}

// windowTimes are the stamps a report carries: the window's own first packet
// and the reading's last one, and none at all when the window counted nothing
// -- the dataplane's last stamp outlives the window that wrote it, and a report
// must not claim it as this window's.
func windowTimes(first, last time.Time, up, down Usage) (time.Time, time.Time) {
	if up.Packets == 0 && down.Packets == 0 {
		return time.Time{}, time.Time{}
	}
	return first, last
}

// countsOf is what the rules a URR measures have counted, per direction: the
// sum of their counters, keyed by each rule's own ActionId, and the window's
// own stamps: the earliest first packet and the latest last one among them. The
// caller holds the lock.
func (c *Compiler) countsOf(s *Session, uid uint32, counts map[string]map[uint32]reading) (up, down Usage, first, last time.Time) {
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
			up = up.add(cell.Usage)
		} else {
			down = down.add(cell.Usage)
		}
		// The stamps of the rules that counted in this tick -- the ones whose
		// first stamp is set, because a reading clears it -- give the earliest
		// first packet and the latest last one. A rule that counted nothing
		// keeps its last stamp from an earlier tick, and that one is not this
		// window's.
		if !cell.First.IsZero() {
			if first.IsZero() || cell.First.Before(first) {
				first = cell.First
			}
			if cell.Last.After(last) {
				last = cell.Last
			}
		}
	}
	return up, down, first, last
}

// quotaReached reports whether a quota this URR measures is used up: the
// enforcement is the UPF's own doing (5.2.2.2.1), so the traffic stops whether
// or not the SMF asked for a report of it. windowActive is the time the
// window's traffic ran (for a time quota) and the counters are the window's.
func (u *urr) quotaReached(up, down Usage, windowActive time.Duration) bool {
	if u.onVolQuota && u.volume && u.volQuota.reached(up.Octets, down.Octets) {
		return true
	}
	return u.onTimeQuota && u.duration && u.hasTimeQuota && windowActive >= u.timeQuota
}

// due is the reason this URR owes a report now, if it owes one: its period has
// passed, or a limit it measures is reached. window is the clock's length since
// the last report (what a period means) and windowActive the time the window's
// traffic ran (what a time limit means). The triggers are tried in the URR's
// own order, so a window that satisfies several reports the first of them.
func (u *urr) due(up, down Usage, window, windowActive time.Duration) (Trigger, bool) {
	if u.periodic && window >= u.period {
		return TriggerPeriod, true
	}
	if u.onVolumeTh && u.volume && u.volThreshold.reached(up.Octets, down.Octets) {
		return TriggerVolumeThreshold, true
	}
	if u.onTimeTh && u.duration && u.hasTimeTh && windowActive >= u.timeThreshold {
		return TriggerTimeThreshold, true
	}
	if u.onVolQuota && u.volume && u.volQuota.reached(up.Octets, down.Octets) {
		return TriggerVolumeQuota, true
	}
	if u.onTimeQuota && u.duration && u.hasTimeQuota && windowActive >= u.timeQuota {
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
