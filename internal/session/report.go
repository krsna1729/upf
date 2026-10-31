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
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/wmnsk/go-pfcp/ie"

	"github.com/krsna1729/upf/internal/bess"
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

// errNoCounters marks a graph with no counting module this control plane can
// read: a URR of such a session would report nothing, and saying so is better
// than reporting zero forever (the compiler refuses such a session when it is
// established; an evaluation is the same fact found later).
var errNoCounters = errors.New("the dataplane of this graph holds no usage counters")

// Trigger is why a report is on its way: the reporting trigger that fired
// (TS 29.244 8.2.19).
type Trigger uint8

const (
	TriggerPeriod Trigger = iota
	TriggerVolumeThreshold
	TriggerTimeThreshold
	TriggerVolumeQuota
	TriggerTimeQuota
	// TriggerTermination is the report a deletion carries (TERMR, 8.2.41): the
	// usage a URR measured since its last report, given with the session's end.
	TriggerTermination
	// TriggerImmediate is the report a Query URR or QAURR asks for (IMMER).
	TriggerImmediate
	// TriggerEndMarker is EMRRE (8.2.41): an End Marker arrived on a local
	// F-TEID of a PDR the URR measures, and nothing else is due. A report due
	// for another reason carries EMRRE beside it (Report.EndMarker).
	TriggerEndMarker
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
	case TriggerTermination:
		return "termination"
	case TriggerImmediate:
		return "immediate"
	case TriggerEndMarker:
		return "end marker"
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

// readings is a reading's answers as a decision looks them up: by the ActionId
// of the rule each belongs to. An ActionId is one PDR's and a PDR is counted by
// one module, so the modules' answers share the one index.
type readings func(actionID uint32) reading

// countChunk is the most rules one get_counts names. The daemon refuses a
// message over 64 MiB, and one reading of every counted rule passes that at
// ~2M rules (34 B a rule on the wire): that tick's reading failed every time,
// and no URR reported. A rule is at most 52 B on the wire (five varints at
// their widest, its tag and length), so a chunk's reply is at most ~3.3 MiB,
// and 2M rules are ~32 round trips per module.
const countChunk = 1 << 16

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

	// RawUp, RawDown and DecidedAt are the reading this window was made from
	// and when it was decided: the base and the time the next window starts at.
	// They travel with the report because the base moves at decision time while
	// the message is delivered later, and the layer that delivers it is the one
	// that moves the *delivered* base (Compiler.ConfirmReport).
	RawUp, RawDown Usage
	DecidedAt      time.Time

	// Errors are the peer's Error Indications this report tells the SMF about:
	// tunnels this UPF sends into that the peer could not reach (TS 29.244
	// 5.10). A report that carries them and no URR is an Error Indication
	// Report -- the Report Type's ERIR bit and one Error Indication Report IE
	// per remote F-TEID, with no Usage Report IE -- and a URR report may carry
	// both, one message per tick. It is what the peer sent and this side has
	// not reported yet (erir.go).
	Errors []ErrorIndication

	// Linked is the rest of a linked group, when this report is the group's:
	// each is its own Usage Report IE, and every one of them -- this report's
	// URR included -- carries this report's UR-SEQN, which is what 8.2.71 means
	// by linked URRs sharing a sequence. It is empty for an unlinked URR, whose
	// report is exactly one Usage Report IE.
	Linked []LinkedUsage

	// EndMarker says an End Marker arrived on a local F-TEID of a PDR this
	// report's URR measures and asks for REEMR: the Usage Report Trigger
	// carries EMRRE (8.2.41, octet 7) whatever else it carries.
	EndMarker bool

	// bases are each member's base as this report found it, in the group's
	// order (the UR-SEQN's holder first): what Compiler.Unreport puts back.
	bases []urrBase
}

// urrBase is the part of a URR a report moves: the base its next window is
// measured from, and that window's stamps.
type urrBase struct {
	uid                     uint32
	reported                time.Time
	lastUp, lastDown        Usage
	windowFirst, windowLast time.Time
}

// Absorb adds another undelivered report of the same session to r, URR by
// URR: the usage the other one carried reaches the SMF in r instead of being
// lost. r keeps its UR-SEQN; the reading the delivered base moves to on
// acceptance (ConfirmReport) is the later report's, and the base Unreport
// would put back is the earlier one's.
func (r *Report) Absorb(o Report) {
	window := func(up, down *Usage, d *time.Duration, first, last *time.Time,
		oUp, oDown Usage, oD time.Duration, oFirst, oLast time.Time) {
		*up, *down, *d = up.add(oUp), down.add(oDown), *d+oD
		if !oFirst.IsZero() && (first.IsZero() || oFirst.Before(*first)) {
			*first = oFirst
		}
		if oLast.After(*last) {
			*last = oLast
		}
	}
	later := o.DecidedAt.After(r.DecidedAt)
	merge := func(uid uint32, up, down Usage, d time.Duration, first, last time.Time, rawUp, rawDown Usage) {
		if uid == r.URRID {
			window(&r.Up, &r.Down, &r.Duration, &r.First, &r.Last, up, down, d, first, last)
			if later {
				r.RawUp, r.RawDown = rawUp, rawDown
			}
			return
		}
		for i := range r.Linked {
			l := &r.Linked[i]
			if l.URRID == uid {
				window(&l.Up, &l.Down, &l.Duration, &l.First, &l.Last, up, down, d, first, last)
				if later {
					l.RawUp, l.RawDown = rawUp, rawDown
				}
			}
		}
	}
	merge(o.URRID, o.Up, o.Down, o.Duration, o.First, o.Last, o.RawUp, o.RawDown)
	for _, l := range o.Linked {
		merge(l.URRID, l.Up, l.Down, l.Duration, l.First, l.Last, l.RawUp, l.RawDown)
	}
	r.Enforcing = r.Enforcing || o.Enforcing
	if later {
		r.DecidedAt = o.DecidedAt
	} else {
		r.bases = o.bases
	}
}

// LinkedUsage is one URR of a linked group (8.2.55) as the group's report
// carries it: the window its own rules measured, reported under the group's one
// UR-SEQN.
type LinkedUsage struct {
	URRID uint32

	// Up and Down are this URR's window's usage, by the direction the PDRs
	// face, and Duration, First and Last are that window, as Report's are.
	Up, Down Usage
	Duration time.Duration
	First    time.Time
	Last     time.Time

	// Enforcing says this URR's own quota brought the traffic down, so the SMF
	// knows which member of the group spent its quota.
	Enforcing bool

	// RawUp and RawDown are this member's own reading, as Report's are: the
	// group's report opens every member's next window, so the delivered base
	// moves for each of them.
	RawUp, RawDown Usage

	// EndMarker is Report.EndMarker for this member: its own REEMR saw one.
	EndMarker bool
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
	case TriggerTermination:
		return 0, trigTermination
	case TriggerImmediate:
		return trigImmediate, 0
	}
	return 0, 0
}

// IEs is this report as the IEs a Session Report Request carries (7.5.8.2): the
// Report Type, and the Usage Report with the URR, the UR-SEQN, the trigger and
// the volume measured. They are built here, in the package that decided the
// numbers, so the n4 layer sends what it is given and nothing else has to know
// which bit means which trigger.
func (r Report) IEs() []*ie.IE {
	// What this message carries decides its Report Type (8.2.21): a usage
	// report for the URR it leads with -- not an event report and not a
	// downlink-data report -- an Error Indication Report for a tunnel the peer
	// could not reach (5.10), and both when one tick owes both.
	erir, usar := 0, 0
	if len(r.Errors) > 0 {
		erir = 1
	}
	if r.URRID != 0 || len(r.Errors) == 0 {
		usar = 1
	}
	ies := []*ie.IE{ie.NewReportType(0, erir, usar, 0)}
	for _, e := range r.Errors {
		// One Error Indication Report per remote F-TEID (7.5.8.4): the F-TEID
		// the peer named, built the way this UPF advertises one, so the SMF
		// matches it to the FAR it provisioned.
		ies = append(ies, ie.NewErrorIndicationReport(createdFTEID(e.TEID, e.Addr)))
	}
	if usar == 0 {
		return ies
	}
	ies = append(ies, usageReportIE(ie.UsageReportWithinSessionReportRequest, r.URRID, r.Seqn, r.Trigger, r.EndMarker, r.Up, r.Down, r.Duration, r.First, r.Last))
	// A linked group is reported whole: each of the rest is its own Usage
	// Report IE, and every one of them carries this report's UR-SEQN -- the one
	// sequence the group shares (8.2.71).
	for _, g := range r.Linked {
		ies = append(ies, usageReportIE(ie.UsageReportWithinSessionReportRequest, g.URRID, r.Seqn, r.Trigger, g.EndMarker, g.Up, g.Down, g.Duration, g.First, g.Last))
	}
	return ies
}

// usageReportIE is one Usage Report within a Session Report Request (7.5.8.2):
// the URR, the UR-SEQN it is reported under, the trigger, and the volume and
// duration its window measured. Every Usage Report of one report shares that
// report's UR-SEQN, which is what links a group's URRs to the SMF. endMarker
// adds EMRRE to whatever trigger the report leads with.
func usageReportIE(typ ie.IEType, urrID, seqn uint32, trigger Trigger, endMarker bool, up, down Usage, duration time.Duration, first, last time.Time) *ie.IE {
	total := up.add(down)
	octet5, octet6 := trigger.flags()
	var octet7 uint8
	if endMarker {
		octet7 = trigEndMarkerReceived
	}
	usage := []*ie.IE{
		ie.NewURRID(urrID),
		ie.NewURSEQN(seqn),
		// Octets 5 to 7 of Figure 8.2.41-1, all three: a quota's or a
		// termination's bit is in octet 6, EMRRE in octet 7, and an IE that left
		// an octet out for being empty would move the later bits.
		ie.NewUsageReportTrigger(octet5, octet6, octet7),
		// All six counts: the SMF may bill either the total or the
		// directions, and the UPF knows all of them (8.2.44).
		ie.NewVolumeMeasurement(0x3f,
			total.Octets, up.Octets, down.Octets,
			total.Packets, up.Packets, down.Packets),
		ie.NewDurationMeasurement(duration),
	}
	// When the window's traffic ran, from the dataplane's own stamps: optional
	// IEs an SMF reads for a duration measurement (8.2.44, 8.2.45), omitted
	// rather than guessed when the counters carry none.
	if !first.IsZero() {
		usage = append(usage, ie.NewTimeOfFirstPacket(first))
	}
	if !last.IsZero() {
		usage = append(usage, ie.NewTimeOfLastPacket(last))
	}
	return ie.NewUsageReport(typ, usage...)
}

// EvaluateAll is Evaluate for every session the compiler holds, low SEID first,
// so one tick of a caller that owns the clock (upfd's reporting loop) is one
// call.
//
// It is not Evaluate in a loop, and that is the point: the counters are read
// **per counter module** before any session is judged -- every rule of the
// tick's sessions the module counts, named in chunks of countChunk -- and each
// session is then decided in memory against what was read. A tick at the
// 1M-session target is therefore a few dozen calls per counter module rather
// than one or two million (the per-session read this replaced), which is
// docs/design.md's control-plane O(total sessions) item 3; what is read is
// still every counted rule of every session, so the tick's read is O(all
// sessions) in bytes, not in round trips.
//
// A module whose reading fails costs the sessions that measure through it and
// nothing else, the way a per-session read that failed cost its own session,
// and a session the SMF deleted while the counters were being read is skipped
// rather than failed: the usage belongs to a session nobody has.
func (c *Compiler) EvaluateAll(ctx context.Context, now time.Time) []Report {
	// The sessions with a URR (Compiler.measured), not every session, and
	// their rules a bounded batch of sessions per hold of the lock: a tick
	// must not stall every establishment behind a walk of the whole table.
	c.mu.Lock()
	seids := make([]uint64, 0, len(c.measured))
	for seid := range c.measured {
		seids = append(seids, seid)
	}
	if c.tickIDs == nil {
		c.tickIDs = map[string][]uint32{}
	}
	ids := c.tickIDs
	for module, rules := range ids {
		ids[module] = rules[:0]
	}
	c.mu.Unlock()
	slices.Sort(seids)
	for start := 0; start < len(seids); start += tickHold {
		c.mu.Lock()
		for _, seid := range seids[start:min(start+tickHold, len(seids))] {
			s := c.sessions[seid]
			if s == nil || len(s.URRs) == 0 {
				delete(c.measured, seid)
				continue
			}
			c.appendMeasuredRules(s, ids)
		}
		c.mu.Unlock()
	}
	names := make([]string, 0, len(ids))
	top := uint32(0)
	for module, rules := range ids {
		if len(rules) > 0 {
			names = append(names, module)
			top = max(top, slices.Max(rules))
		}
	}
	readsErrors := c.cfg.GTPUErrors != ""
	// The End Marker log is drained every tick it is configured, whether or
	// not any session asks: a drain is what frees the ring, and an End Marker
	// no REEMR URR names is one nobody asked to hear about.
	readsMarkers := c.cfg.GTPUEndMarkers != ""
	if len(names) == 0 && !readsErrors && !readsMarkers {
		// No session measures anything: nothing to read, and nothing owed --
		// the per-session path returns before its own read on exactly this
		// fact.
		return nil
	}
	counters, errorReader, markerReader := c.counters, ErrorReader(nil), EndMarkerReader(nil)
	if r, ok := c.counters.(ErrorReader); ok {
		errorReader = r
	}
	if r, ok := c.counters.(EndMarkerReader); ok {
		markerReader = r
	}
	if counters == nil || (readsErrors && errorReader == nil) || (readsMarkers && markerReader == nil) {
		// The graph has no counting module this control plane can read, and
		// every session's URRs would report nothing: the caller's log is where
		// an operator sees it. The error table is read through the same
		// dataplane, so a responder this control plane cannot ask is one whose
		// reports would be owed forever.
		for _, seid := range seids {
			c.log.Warn("session: usage evaluation", "seid", seid, "error", errNoCounters)
		}
		return nil
	}
	// Each module in a fixed order, its rules in chunks: one reply holding
	// every rule would pass the daemon's 64 MiB bound (countChunk). The
	// answers land in the one slice indexed by ActionId the report loop keeps.
	slices.Sort(names)
	if need := int(top) + 1; len(c.tickCounts) < need {
		c.tickCounts = make([]reading, need)
	}
	cells := c.tickCounts
	failed := make([]string, 0, len(names))
	failures := make(map[string]error, len(names))
	for _, module := range names {
		for rules := ids[module]; len(rules) > 0; {
			chunk := rules[:min(len(rules), countChunk)]
			rules = rules[len(chunk):]
			read, err := counters.RuleCounts(ctx, module, chunk...)
			if err != nil {
				failed = append(failed, module)
				failures[module] = fmt.Errorf("reading %s: %w", module, err)
				break
			}
			for _, rule := range read {
				if int(rule.ActionID) < len(cells) {
					cells[rule.ActionID] = readingOf(rule)
				}
			}
		}
	}
	counts := readings(func(id uint32) reading {
		if int(id) < len(cells) {
			return cells[id]
		}
		return reading{}
	})

	// The peer's Error Indications (5.10) since the last tick, each delivered
	// once by the drain: one responder module logs every indication, and the
	// sessions below report the ones that name their tunnels. A drain that
	// fails loses nothing -- the events stay in the ring for the next one.
	var indications map[uint32]bool
	if readsErrors {
		read, dropped, err := errorReader.DrainErrors(ctx, c.target.Errors())
		if err != nil {
			c.log.Warn("session: error indications", "module", c.target.Errors(), "error", err)
		} else {
			if dropped > c.errorsDropped {
				c.log.Warn("session: error indications lost to a full ring", "module", c.target.Errors(),
					"lost", dropped-c.errorsDropped)
				c.errorsDropped = dropped
			}
			if len(read) > 0 {
				indications = make(map[uint32]bool, len(read))
				for _, teid := range read {
					indications[teid] = true
				}
			}
			if len(indications) > 0 {
				// Error Indications are owed by any session whose tunnel the
				// peer named, measured or not: this tick judges them all.
				c.mu.Lock()
				seids = seids[:0]
				for seid := range c.sessions {
					seids = append(seids, seid)
				}
				c.mu.Unlock()
				slices.Sort(seids)
			}
		}
	}

	// The End Markers since the last tick (TS 29.281 7.3.2), each delivered
	// once by the drain: the keys a REEMR URR's PDRs are judged against. A
	// drain that fails loses nothing -- the events stay in the ring for the
	// next one.
	var markers map[endMarkerKey]bool
	if readsMarkers {
		read, dropped, err := markerReader.DrainEndMarkers(ctx, c.target.EndMarkers())
		if err != nil {
			c.log.Warn("session: end markers", "module", c.target.EndMarkers(), "error", err)
		} else {
			if dropped > c.markersDropped {
				c.log.Warn("session: end markers lost to a full ring", "module", c.target.EndMarkers(),
					"lost", dropped-c.markersDropped)
				c.markersDropped = dropped
			}
			markers = make(map[endMarkerKey]bool, len(read))
			for _, m := range read {
				markers[endMarkerKey{endpoint: m.EndpointID, teid: m.TEID}] = true
			}
		}
	}

	var out []Report
	for _, seid := range seids {
		c.mu.Lock()
		s := c.sessions[seid]
		if s == nil {
			// The SMF deleted it between the list above and this call: the
			// usage belongs to a session nobody has.
			c.mu.Unlock()
			continue
		}
		var unread error
		if len(failed) > 0 {
			// Only a session whose own rules are counted by a module whose
			// reading failed is skipped; the rest of the tick is unaffected.
			measured := map[string]bool{}
			c.measuredModules(s, measured)
			for _, module := range failed {
				if measured[module] {
					unread = failures[module]
					break
				}
			}
		}
		c.mu.Unlock()
		if unread != nil {
			c.log.Warn("session: usage evaluation", "seid", seid, "error", unread)
			continue
		}
		reports, err := c.judge(ctx, seid, s, counts, markers, now)
		if err != nil {
			// The dataplane refused the enforcement: the caller's log is where
			// an operator sees it, and the reports decided before the failure
			// are still owed.
			c.log.Warn("session: usage evaluation", "seid", seid, "error", err)
		}
		out = append(out, reports...)
		if len(indications) > 0 {
			// The session's own tunnels the peer reported, which is a report
			// of its own rather than part of the usage (erir.go).
			out = append(out, c.errorReports(seid, s, indications)...)
		}
	}
	// The cells go back to zero for the next tick: a rule it does not read --
	// one a modification added after its list was taken -- reads zero, as a
	// rule no reading answered always has.
	for _, module := range names {
		for _, id := range ids[module] {
			cells[id] = reading{}
		}
	}
	return out
}

// Evaluate reads the counters of one session's URRs and decides what is due:
// each URR whose period has passed or whose threshold or quota is reached gets
// a Report, and a URR whose quota is used up stops the traffic of its PDRs --
// one transaction, the same way a modification writes them.
//
// This is the single-session reading: it asks the counting modules for exactly
// the rules this session measures, so it is the call a caller that has one
// session to judge makes. A caller that owns the clock judges every session
// with EvaluateAll, which reads each counter module once for the whole tick
// instead of once per session.
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
	ids := c.measuredRules(s)
	c.mu.Unlock()

	if len(ids) == 0 {
		return nil, nil
	}
	reader := c.counters
	if reader == nil {
		// The graph has no counting module this control plane can read, and the
		// session's URRs would report nothing: an error, not zero forever.
		return nil, errNoCounters
	}
	counts, err := readRules(ctx, reader, ids)
	if err != nil {
		return nil, err
	}
	return c.judge(ctx, seid, s, counts, nil, now)
}

// judge is the half of an evaluation that runs with the counters in hand:
// decide what this session's URRs owe from them, and, when a quota is spent,
// compile and apply the enforcement that stops its traffic -- one transaction,
// the same way a modification writes them. The read is the caller's: Evaluate
// reads one session's rules, EvaluateAll reads each counter module once for
// every session of the tick.
func (c *Compiler) judge(ctx context.Context, seid uint64, s *Session, counts readings, markers map[endMarkerKey]bool, now time.Time) ([]Report, error) {
	c.mu.Lock()
	if c.sessions[seid] != s {
		c.mu.Unlock()
		// The session went away while its counters were being read: the usage
		// belongs to a session the SMF no longer has.
		return nil, nil
	}
	reports, stopped := c.decide(s, counts, markers, now)
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

// readingOf is one rule's answer from a counting module as the decision reads
// it.
func readingOf(rule bess.RuleCount) reading {
	return reading{
		Usage: Usage{Packets: rule.Packets, Octets: rule.Octets},
		First: rule.First, Last: rule.Last,
	}
}

// readRules reads the rules one session measures (measuredRules), one call
// per module: the single-session reading Evaluate and windowsOf make.
func readRules(ctx context.Context, reader CounterReader, ids map[string][]uint32) (readings, error) {
	cells := map[uint32]reading{}
	for module, rules := range ids {
		read, err := reader.RuleCounts(ctx, module, rules...)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", module, err)
		}
		for _, rule := range read {
			cells[rule.ActionID] = readingOf(rule)
		}
	}
	return func(id uint32) reading { return cells[id] }, nil
}

// countedModule is where this PDR's counters are read (Target.Counts), when the
// PDR has any: one entry per measured PDR is what compile.go writes, and a
// PDR a used-up quota already stopped is compiled as a drop with nothing to
// report. It is the one predicate measuredRules and measuredModules walk the
// PDRs by, so a tick reads exactly the rules a per-session evaluation reads.
func (c *Compiler) countedModule(p *pdr) (string, bool) {
	if len(p.urrIDs) == 0 || p.actionID == 0 || p.drop {
		return "", false
	}
	if c.direction(p).Counters == "" {
		return "", false
	}
	return c.target.Counts(counterTable(p.downlink())), true
}

// measuredRules is the rules a session's URRs measure, by the module that
// counts them: one entry per PDR a URR measures. The caller holds the lock.
func (c *Compiler) measuredRules(s *Session) map[string][]uint32 {
	ids := map[string][]uint32{}
	c.appendMeasuredRules(s, ids)
	return ids
}

// appendMeasuredRules appends the rules s's URRs measure to ids, by the module
// that counts them. The caller holds the lock.
func (c *Compiler) appendMeasuredRules(s *Session, ids map[string][]uint32) {
	for _, p := range pdrsInOrder(s) {
		if module, ok := c.countedModule(p); ok {
			ids[module] = append(ids[module], p.actionID)
		}
	}
}

// measuredModules adds the counting modules a session's measured PDRs read
// from to modules: the modules a tick has to read for it. The caller holds the
// lock.
func (c *Compiler) measuredModules(s *Session, modules map[string]bool) {
	for _, p := range pdrsInOrder(s) {
		if module, ok := c.countedModule(p); ok {
			modules[module] = true
		}
	}
}

// decide updates every URR's bookkeeping and returns the reports they owe, and
// whether any of them is enforcing something the dataplane has not been told
// yet. The caller holds the lock.
//
// URRs are judged one linked group at a time (8.2.55): a URR and the URRs it
// links to, directly or through others, are one group, and when any member owes
// a report the group is reported whole -- each member's own window, all under
// the one UR-SEQN the group shares (8.2.71). A URR with no link is a group of
// one and is reported exactly as it was before linking existed.
//
// A member whose triggers carry LIUSA (8.2.19) is the exception that proves the
// link: it is reported through the link, never on its own measurement, so it
// owes nothing itself and the group is due only where another member is. Its
// window still moves with the group's report, and its own limits still stop the
// traffic (quotaReached above), which is what the SMF reads in the report.
//
// markers are the End Markers that arrived since the last tick: a URR that
// asks for REEMR is due when one came in on a PDR it measures, from its first
// tick on -- an End Marker is an event, not a measurement, so it needs no
// baseline -- and a report due for another reason carries it too.
func (c *Compiler) decide(s *Session, counts readings, markers map[endMarkerKey]bool, now time.Time) ([]Report, bool) {
	var reports []Report
	stopped := false
	for _, members := range linkedGroups(s) {
		// One tick's reading per member, and what each owes from it.
		type memberState struct {
			uid            uint32
			trigger        Trigger
			due            bool
			endMarker      bool
			up, down       Usage // the window's usage
			rawUp, rawDown Usage // the cumulative reading, the next window's base
			window         time.Duration
			first, last    time.Time
		}
		// On the stack for the groups a session has in practice: this runs
		// for every measured session every tick.
		var held [4]memberState
		states := held[:0]
		anyDue := false
		for _, uid := range members {
			u := s.URRs[uid]
			up, down, first, last := c.countsOf(s, uid, counts)
			st := memberState{uid: uid, rawUp: up, rawDown: down}
			st.endMarker = endMarkerArrived(s, uid, markers)
			if !u.baselined {
				// The first reading of a URR is its baseline, not its usage
				// (report.go, "the window"). It owes nothing itself, but the
				// group it belongs to may still be reported, and then it is
				// carried with a zero window.
				u.baselined = true
				u.reported, u.lastUp, u.lastDown = now, up, down
				u.deliveredUp, u.deliveredDown, u.deliveredAt = up, down, now
				if st.endMarker && !u.linkedReporting {
					st.trigger, st.due, anyDue = TriggerEndMarker, true, true
				}
				states = append(states, st)
				continue
			}
			window := now.Sub(u.reported)
			if window < 0 {
				window = 0
			}
			upWindow, downWindow := up.since(u.lastUp), down.since(u.lastDown)
			if !first.IsZero() && !last.Before(first) {
				// This reading counted packets: it is the window's first
				// activity when the window has none yet, and it is its last one.
				u.stamped = true
				if u.windowFirst.IsZero() {
					u.windowFirst = first
				}
				u.windowLast = last
			}
			// The time a window's traffic ran is what a time limit is measured
			// against -- the window's own first counted packet to its own last
			// one, the same base the volume limits use, with the idle between
			// them taken out. A graph whose counters carry no stamp at all
			// falls back to the window's length, the number the clock gives
			// while the traffic runs.
			windowActive := window
			if u.stamped {
				windowActive = 0
				if !u.windowFirst.IsZero() {
					windowActive = u.windowLast.Sub(u.windowFirst)
				}
			}
			st.up, st.down = upWindow, downWindow
			st.window = window
			st.first, st.last = windowTimes(u.windowFirst, u.windowLast, upWindow, downWindow)
			// A limit that is reached stops the traffic whether or not it is
			// the reason this report is going: a period that ends in the same
			// window as a quota must not swallow the enforcement.
			if u.quotaReached(upWindow, downWindow, windowActive) && !u.enforcing {
				u.enforcing = true
				stopped = true
			}
			trigger, due := u.due(upWindow, downWindow, window, windowActive)
			if u.linkedReporting {
				// LIUSA (8.2.19): this URR's report is the link's, owed when a
				// URR it is linked to is due, so its own triggers generate
				// nothing. Its window is still what the group's report carries
				// for it, and it is still opened by that report below.
				trigger, due = 0, false
			}
			if !due && st.endMarker && !u.linkedReporting {
				trigger, due = TriggerEndMarker, true
			}
			st.trigger, st.due = trigger, due
			if due {
				anyDue = true
			}
			states = append(states, st)
		}
		if !anyDue {
			continue
		}
		// The group is reported whole: the first member in order that is due
		// leads (its reason is the group's), the rest are carried with it, and
		// all of them share the group's one UR-SEQN -- the lowest id's, so it
		// is the same sequence however the members are ordered.
		seqn := s.URRs[members[0]].seqn
		lead := 0
		for i := range states {
			if states[i].due {
				lead = i
				break
			}
		}
		l := states[lead]
		r := Report{
			SEID: s.LocalSEID, CPSEID: s.CPSEID, URRID: l.uid,
			Trigger: l.trigger, Seqn: seqn,
			Up: l.up, Down: l.down,
			Duration: l.window, First: l.first, Last: l.last, Enforcing: s.URRs[l.uid].enforcing,
			RawUp: l.rawUp, RawDown: l.rawDown, DecidedAt: now, EndMarker: l.endMarker,
		}
		for i, st := range states {
			if i == lead {
				continue
			}
			r.Linked = append(r.Linked, LinkedUsage{
				URRID: st.uid, Up: st.up, Down: st.down,
				Duration: st.window, First: st.first, Last: st.last,
				Enforcing: s.URRs[st.uid].enforcing,
				RawUp:     st.rawUp, RawDown: st.rawDown, EndMarker: st.endMarker,
			})
			if s.URRs[st.uid].enforcing {
				r.Enforcing = true
			}
		}
		// The report opens every member's next window, and it is the SMF's
		// message that carries this usage: the counters are not reset (the
		// dataplane knows nothing of reports), so the base is what moves -- and
		// with it the window's own stamps, which the next tick writes afresh.
		// Where it was is kept with the report, for a report the SMF never
		// gets (Unreport).
		for _, st := range states {
			u := s.URRs[st.uid]
			r.bases = append(r.bases, urrBase{uid: st.uid, reported: u.reported, lastUp: u.lastUp,
				lastDown: u.lastDown, windowFirst: u.windowFirst, windowLast: u.windowLast})
			u.reported, u.lastUp, u.lastDown = now, st.rawUp, st.rawDown
			u.windowFirst, u.windowLast = time.Time{}, time.Time{}
		}
		reports = append(reports, r)
		s.URRs[members[0]].seqn++
	}
	return reports, stopped
}

// linkedGroups partitions a session's URRs into linked groups: the connected
// components of the Linked URR ID edges (8.2.55), each group's members sorted
// low to high, and the groups sorted by their first member, so a session
// reports them in one order whatever the map's is. The link is undirected for
// grouping -- a URR "Y" may itself link to more URRs, and 5.2.2.4 makes the
// group everything reachable from any of them. A URR with no link is a group of
// one. The answer is cached until the model changes (invalidateOrderCache).
// The caller holds the lock.
func linkedGroups(s *Session) [][]uint32 {
	if s.cachedGroups != nil {
		return s.cachedGroups
	}
	ids := urrIDsInOrder(s)
	parent := make(map[uint32]uint32, len(ids))
	for _, id := range ids {
		parent[id] = id
	}
	var find func(uint32) uint32
	find = func(x uint32) uint32 {
		for parent[x] != x {
			parent[x] = parent[parent[x]]
			x = parent[x]
		}
		return x
	}
	for _, id := range ids {
		for _, lid := range s.URRs[id].linked {
			if _, ok := parent[lid]; ok {
				// resolve refuses a link the session cannot resolve, so a
				// missing one here is a session that never compiled; the guard
				// keeps such a link from inventing a group.
				parent[find(id)] = find(lid)
			}
		}
	}
	grouped := make(map[uint32][]uint32, len(ids))
	for _, id := range ids {
		root := find(id)
		grouped[root] = append(grouped[root], id)
	}
	groups := make([][]uint32, 0, len(grouped))
	for _, g := range grouped {
		groups = append(groups, g)
	}
	slices.SortFunc(groups, func(a, b []uint32) int { return cmp.Compare(a[0], b[0]) })
	s.cachedGroups = groups
	return groups
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
func (c *Compiler) countsOf(s *Session, uid uint32, counts readings) (up, down Usage, first, last time.Time) {
	for _, p := range pdrsInOrder(s) {
		if p.actionID == 0 || p.drop || !slices.Contains(p.urrIDs, uid) {
			continue
		}
		dir := c.direction(p)
		if dir.Counters == "" {
			continue
		}
		cell := counts(p.actionID)
		if !p.downlink() {
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

// windowBase is which reading a window opens from (windowsOf): the base of the
// last report, delivered or not, or the last reading the SMF was told up to.
type windowBase int

const (
	sinceReport windowBase = iota
	sinceDelivery
)

// urrWindow is one URR's window as of a reading: the usage since its last
// report, and the cumulative reading the next window would start from.
type urrWindow struct {
	uid         uint32
	seqn        uint32 // the UR-SEQN the report carries: the group's
	up, down    Usage
	rawUp       Usage // the cumulative reading, the next window's base
	rawDown     Usage
	duration    time.Duration
	first, last time.Time
	groupLeader uint32
	reportedAt  time.Time // the URR's base time when read: a tick that reported since has moved it
}

// windowsOf reads the counters of the URRs a session holds and returns the
// requested ones' windows, in id order (nil asks for every URR). It is what a
// report the CP function asked for -- or the session's end -- is made of: the
// usage since the URR's last report, under the group's UR-SEQN (8.2.71).
//
// A URR that never had a reading has no base, and its first reading is not
// usage (the cells of a reused ActionId are another rule's totals), so its
// window is empty: usage under-reported, never invented, as everywhere in
// this file. Counters that cannot be read are an error and the caller sends no
// report: one built from nothing would be a figure the SMF bills.
//
// It changes nothing in the model: a window the SMF is told about opens the
// next one only when the message that carried it has been answered
// (advanceAfter).
//
// base says which reading a window opens from: sinceReport for a window the
// caller is about to send (the last report's base, whether or not that report
// has been delivered yet), sinceDelivery for the session's last window, which
// must carry what the SMF has not been told rather than what the queue already
// holds (finding 20).
func (c *Compiler) windowsOf(ctx context.Context, s *Session, uids []uint32, now time.Time, base windowBase) ([]urrWindow, error) {
	c.mu.Lock()
	ids := c.measuredRules(s)
	c.mu.Unlock()
	if len(ids) > 0 && c.counters == nil {
		return nil, errNoCounters
	}
	counts, err := readRules(ctx, c.counters, ids)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []urrWindow
	for _, members := range linkedGroups(s) {
		seqn := s.URRs[members[0]].seqn
		for _, uid := range members {
			if uids != nil && !slices.Contains(uids, uid) {
				continue
			}
			u := s.URRs[uid]
			nowUp, nowDown, f, l := c.countsOf(s, uid, counts)
			fromUp, fromDown, fromAt := u.lastUp, u.lastDown, u.reported
			if base == sinceDelivery {
				// The session is ending: what the SMF has not been told is the
				// window, whatever the queue still holds (finding 20).
				fromUp, fromDown, fromAt = u.deliveredUp, u.deliveredDown, u.deliveredAt
			}
			w := urrWindow{
				uid: uid, seqn: seqn, rawUp: nowUp, rawDown: nowDown,
				duration: max(now.Sub(fromAt), 0), groupLeader: members[0], reportedAt: u.reported,
			}
			if u.baselined {
				w.up, w.down = nowUp.since(fromUp), nowDown.since(fromDown)
				first, last := u.windowFirst, u.windowLast
				if !f.IsZero() && !l.Before(f) {
					if first.IsZero() {
						first = f
					}
					last = l
				}
				w.first, w.last = windowTimes(first, last, w.up, w.down)
			}
			out = append(out, w)
		}
	}
	slices.SortFunc(out, func(a, b urrWindow) int { return cmp.Compare(a.uid, b.uid) })
	return out, nil
}

// usageReports is the windows as Usage Report IEs of the message type typ,
// under one trigger.
func usageReports(typ ie.IEType, trigger Trigger, windows []urrWindow) []*ie.IE {
	out := make([]*ie.IE, 0, len(windows))
	for _, w := range windows {
		out = append(out, usageReportIE(typ, w.uid, w.seqn, trigger, false, w.up, w.down, w.duration, w.first, w.last))
	}
	return out
}

// advanceAfter opens the next window of every URR a report was sent for: the
// report carried the usage since the base, so the base moves to the reading
// the report was made from, and the group's UR-SEQN moves on once (the same
// rule decide applies to a report of its own). It is called after the message
// that carried the report was accepted, so a refused modification leaves the
// SMF's next report covering the usage this one did not deliver.
func (c *Compiler) advanceAfter(s *Session, windows []urrWindow, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	bumped := map[uint32]bool{}
	for _, w := range windows {
		u := s.URRs[w.uid]
		if u == nil || !u.reported.Equal(w.reportedAt) {
			// Gone, or a reporting tick reported it since this reading: moving
			// the base back would report the same usage twice.
			continue
		}
		u.baselined = true
		u.reported, u.lastUp, u.lastDown = now, w.rawUp, w.rawDown
		u.deliveredUp, u.deliveredDown, u.deliveredAt = w.rawUp, w.rawDown, now
		u.windowFirst, u.windowLast = time.Time{}, time.Time{}
		if lead := s.URRs[w.groupLeader]; lead != nil && !bumped[w.groupLeader] {
			bumped[w.groupLeader] = true
			lead.seqn++
		}
	}
}

// Unreport takes back the decision of a report that will never be sent -- the
// session's queue had no room for it -- while it is still the latest its URRs
// made: their base, window stamps and the group's UR-SEQN go back to where the
// report found them, so the next tick decides that usage again rather than
// losing it, and the SMF sees no gap in the sequence. A report something later
// has already moved past (a modification that carried the window, a later
// tick) cannot be taken back, and the answer is false: the caller keeps its
// usage some other way (Report.Absorb).
func (c *Compiler) Unreport(r Report) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.sessions[r.SEID]
	if s == nil || len(r.bases) == 0 {
		return false
	}
	for _, b := range r.bases {
		if u := s.URRs[b.uid]; u == nil || !u.reported.Equal(r.DecidedAt) {
			return false
		}
	}
	for _, b := range r.bases {
		u := s.URRs[b.uid]
		u.reported, u.lastUp, u.lastDown = b.reported, b.lastUp, b.lastDown
		u.windowFirst, u.windowLast = b.windowFirst, b.windowLast
	}
	if holder := s.URRs[r.bases[0].uid]; holder.seqn == r.Seqn+1 {
		holder.seqn--
	}
	return true
}

// ConfirmReport moves the delivered base of the URRs a report carried: the
// message that carried them was accepted, so the SMF has now been told that
// usage. decide moves lastUp/lastDown when a report is *decided*, because the
// queue holds it and the next tick must not report the same usage twice; this
// pair moves only here (and in advanceAfter, for a report a modification
// carried), so a session that ends while a report is still queued is reported
// from the last delivered reading and the usage that report held is not lost
// (docs/claims.md, finding 20).
//
// A session's reports are delivered in order -- the loop sends the head of the
// session's queue and holds the rest behind it -- so a delivery never moves the
// base back; a report whose URR is gone (the SMF removed it) moves nothing.
func (c *Compiler) ConfirmReport(ctx context.Context, r Report) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.sessions[r.SEID]
	if s == nil {
		return
	}
	delivered := func(uid uint32, up, down Usage) {
		u := s.URRs[uid]
		if u == nil {
			return
		}
		u.deliveredUp, u.deliveredDown, u.deliveredAt = up, down, r.DecidedAt
	}
	delivered(r.URRID, r.RawUp, r.RawDown)
	for _, l := range r.Linked {
		delivered(l.URRID, l.RawUp, l.RawDown)
	}
}

// terminationReports is the Usage Report IE of every URR of a session that is
// ending, for the Session Deletion Response: "the UP function shall report the
// usage of each URR to the CP function in the Session Deletion Response"
// (TS 29.244 5.2.2.3.1, Table 7.5.7.2-1), trigger TERMR. It is what an SMF
// bills a session's last window from -- nothing else carries it, because the
// URR goes with the session. The reading happens before the dataplane erases
// the session's rules; the caller sends the answer only if the erase succeeds.
func (c *Compiler) terminationReports(ctx context.Context, s *Session, now time.Time) []*ie.IE {
	if len(s.URRs) == 0 {
		return nil
	}
	windows, err := c.windowsOf(ctx, s, nil, now, sinceDelivery)
	if err != nil {
		c.log.Warn("session: no termination usage report", "seid", s.LocalSEID, "error", err)
		return nil
	}
	return usageReports(ie.UsageReportWithinSessionDeletionResponse, TriggerTermination, windows)
}
