// SPDX-License-Identifier: BSD-3-Clause

// The PFCP side of the session layer: reading a session message into the
// model below, resolving it into dataplane resources, and answering.
//
// The rule shapes are the ones deploy/upf.yaml declares: a WildcardMatch table
// whose rule value is {priority, gate, action_id} (BESS D-141), an ActionTable
// whose action names a meter and a next hop, a Meter per policed direction, the
// plugin's per-session tunnel record for the downlink, and its per-TEID session
// entry for the uplink.

package session

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/bess"
)

// The Apply Action flags a FAR can carry (TS 29.244 8.2.26, octet 5).
const (
	applyDrop = 0x01
	applyForw = 0x02
	applyBuff = 0x04
)

// The bytes a rule whose FAR drops leaves on.
const dropGate = 8192 // DROP_GATE (core/gate.h)

// errNotExpressible marks a well-formed rule the dataplane cannot carry: a port
// range needs the range kernel of the roadmap's classifier work, and an address
// or prefix that is not IPv4 has no four-byte form at all. The request is not
// malformed, so the SMF is told the rule failed, not that the message was
// wrong.
var errNotExpressible = errors.New("the rule cannot be expressed by a mask")

// errNoResources marks a session the UPF cannot carry for want of a resource:
// an F-TEID the allocator has none of, or one another session already holds.
// The SMF is told cause 75 ("no resources available"), which is what it retries
// or reconciles against; a rule failure (cause 73) would say the filter was
// wrong, and an accepted answer with no usable F-TEID would blackhole the
// uplink while claiming success. (Cause 74 is PFCP Entity In Congestion: the
// answer for a *busy* UPF, not for one whose id space is empty.)
var errNoResources = errors.New("no resources available")

// idsOf returns a table's keys in order. Every transaction this compiler
// writes is built from these: a map's iteration order must never decide what
// the dataplane is told, or which id an object gets.
func idsOf[K ~uint16 | ~uint32, V any](m map[K]V) []K {
	out := make([]K, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

// pdrsInOrder and qersInOrder are the session's objects in id order.
func pdrsInOrder(s *Session) []*pdr {
	out := make([]*pdr, 0, len(s.PDRs))
	for _, id := range idsOf(s.PDRs) {
		out = append(out, s.PDRs[id])
	}
	return out
}

func qersInOrder(s *Session) []*qer {
	out := make([]*qer, 0, len(s.QERs))
	for _, id := range idsOf(s.QERs) {
		out = append(out, s.QERs[id])
	}
	return out
}

// pdrReq is a Create PDR or an Update PDR, as the SMF sent it.
type pdrReq struct {
	id         uint16
	precedence uint32
	srcIfc     uint8
	ueIP       netip.Addr
	sdf        *sdfFilter
	farID      uint32
	qerIDs     []uint32
	urrIDs     []uint32

	// An uplink PDR's PDI names an F-TEID: the TEID the SMF expects us to
	// use (0: ours to choose) and, for the address, usually 0.
	hasFTEID bool
	teid     uint32
	// hasCHID is the F-TEID's CHOOSE ID flag (TS 29.244 8.2.3) with the CH
	// flag that makes it meaningful: PDIs that carry the same value are one
	// tunnel endpoint, and the session allocates one F-TEID for all of them.
	// Zero is a legal CHOOSE ID, so the flag and the value are two fields.
	hasCHID bool
	chid    uint8
}

type farReq struct {
	id       uint32
	apply    uint8
	destIfc  uint8
	teid     uint32
	peer     netip.Addr
	hasOuter bool
}

type qerReq struct {
	id      uint32
	gateUL  uint8
	gateDL  uint8
	mbUL    uint64
	mbDL    uint64
	hasRate bool
}

type urrReq struct {
	id uint32

	// create is a Create URR (7.5.2.4), whose Measurement Method and Reporting
	// Triggers are mandatory; an Update URR carries only what changes, so the
	// has* flags below say what it named.
	create      bool
	hasMethod   bool
	volume      bool
	duration    bool
	hasTriggers bool
	periodic    bool
	onVolumeTh  bool
	onTimeTh    bool
	onVolQuota  bool
	onTimeQuota bool
	hasPeriod   bool
	period      time.Duration

	hasVolThreshold bool
	volThreshold    volumeLimit
	hasTimeTh       bool
	timeThreshold   time.Duration
	hasVolQuota     bool
	volQuota        volumeLimit
	hasTimeQuota    bool
	timeQuota       time.Duration
}

// The Measurement Method bits (TS 29.244 8.2.40, octet 5).
const (
	methodDuration = 0x01 // DURAT
	methodVolume   = 0x02 // VOLUM
	methodEvent    = 0x04 // EVENT
)

// The Reporting Triggers bits this UP implements (TS 29.244 8.2.19), one octet
// at a time: PERIO, VOLTH and TIMTH in the first, VOLQU and TIMQU in the
// second. Every other bit -- QUHTI, START, STOPT, DROTH, LIUSA, ENVCL, MACAR,
// EVETH, EVEQU, IPMJL, QUVTI, REEMR, UPINT, and the spares -- is refused when
// the URR is read: a trigger the SMF asked for and this UP quietly ignores is a
// report the SMF never gets, and it bills from them.
var (
	triggersImplemented = [2]uint8{trigPeriodic | trigVolumeTh | trigTimeTh, trigVolQuota | trigTimeQuota}
	triggersFirstOctet  = map[uint8]string{0x08: "QUHTI", 0x10: "START", 0x20: "STOPT", 0x40: "DROTH", 0x80: "LIUSA"}
	triggersSecondOctet = map[uint8]string{0x04: "ENVCL", 0x08: "MACAR", 0x10: "EVETH", 0x20: "EVEQU", 0x40: "IPMJL", 0x80: "QUVTI"}
	triggersThirdOctet  = map[uint8]string{0x01: "REEMR", 0x02: "UPINT"}
)

const (
	trigPeriodic  = 0x01 // PERIO (octet 5 bit 1)
	trigVolumeTh  = 0x02 // VOLTH (octet 5 bit 2)
	trigTimeTh    = 0x04 // TIMTH (octet 5 bit 3)
	trigVolQuota  = 0x01 // VOLQU (octet 6 bit 1)
	trigTimeQuota = 0x02 // TIMQU (octet 6 bit 2)
)

// triggerName names a bit the UP function does not implement, for the refusal.
func triggerName(octet byte, bit uint8) string {
	switch octet {
	case 5:
		return triggersFirstOctet[bit]
	case 6:
		return triggersSecondOctet[bit]
	default:
		return triggersThirdOctet[bit]
	}
}

// urrUnsupported is the IEs of a URR that change what the SMF would read from a
// report and that this UP does not implement: an event count, a monitoring
// time, an inactivity detector, a quota that expires on a timer, a link to
// another URR's report, a limit on how many reports to send, a dropped-traffic
// threshold. Each is refused when the URR is read rather than silently not
// measured: the SMF bills from these reports, and one that arrives without what
// was asked for is worse than a rule failure it can act on. (The list is by IE
// name: the clause numbers of the refused ones are not this milestone's, and a
// wrong number in a refusal is worse than none.)
var urrUnsupported = map[uint16]string{
	ie.MeasurementInformation:    "Measurement Information",
	ie.MonitoringTime:            "Monitoring Time",
	ie.InactivityDetectionTime:   "Inactivity Detection Time",
	ie.QuotaHoldingTime:          "Quota Holding Time",
	ie.QuotaValidityTime:         "Quota Validity Time",
	ie.DroppedDLTrafficThreshold: "Dropped DL Traffic Threshold",
	ie.UserPlaneInactivityTimer:  "User Plane Inactivity Timer",
	ie.NumberOfReports:           "Number of Reports",
	ie.LinkedURRID:               "Linked URR ID",
	ie.AggregatedURRs:            "Aggregated URRs",
	ie.TimeQuotaMechanism:        "Time Quota Mechanism",
	ie.EventThreshold:            "Event Threshold",
	ie.EventQuota:                "Event Quota",
	ie.SubsequentVolumeThreshold: "Subsequent Volume Threshold",
	ie.SubsequentTimeThreshold:   "Subsequent Time Threshold",
	ie.SubsequentVolumeQuota:     "Subsequent Volume Quota",
	ie.SubsequentTimeQuota:       "Subsequent Time Quota",
	ie.SubsequentEventThreshold:  "Subsequent Event Threshold",
	ie.SubsequentEventQuota:      "Subsequent Event Quota",
	ie.AdditionalMonitoringTime:  "Additional Monitoring Time",
}

// Establish implements n4.SessionHandler.
func (c *Compiler) Establish(req *message.SessionEstablishmentRequest) message.Message {
	ies := establishmentIEs(req)
	cpSEID, err := cpFSEID(ies)
	if err != nil {
		c.log.Warn("session: the establishment request names no CP F-SEID", "error", err)
		return establishResponse(req, 0, ie.CauseMandatoryIEMissing, nil)
	}
	pdrs, fars, qers, urrs, err := parseCreate(ies)
	if err != nil {
		c.log.Warn("session: cannot read the establishment request", "error", err)
		return establishResponse(req, 0, parseCause(err), nil)
	}

	c.mu.Lock()
	// A retransmission of an establishment we already applied: answer as
	// before rather than allocating a second session for it.
	if s := c.findByCP(cpSEID); s != nil {
		created := s.createdPDRs(c.cfg)
		c.mu.Unlock()
		c.log.Info("session: establishment repeated", "cp_seid", cpSEID, "seid", s.LocalSEID)
		return establishResponse(req, s.LocalSEID, ie.CauseRequestAccepted, created)
	}
	local := c.nextSEID
	c.nextSEID++
	c.mu.Unlock()

	s := &Session{
		LocalSEID: local,
		CPSEID:    cpSEID,
		PDRs:      map[uint16]*pdr{},
		FARs:      map[uint32]*far{},
		QERs:      map[uint32]*qer{},
		URRs:      map[uint32]*urr{},
		chids:     map[uint8]uint32{},
	}
	if err := c.merge(s, pdrs, fars, qers, urrs, nil, nil, nil); err != nil {
		c.log.Warn("session: cannot carry the establishment request",
			"cp_seid", cpSEID, "error", err)
		// merge allocates as it goes (the F-TEID among them) and refuses when a
		// later PDR names something the table cannot carry, or a value another
		// session holds: what it got through is this session's and is not going
		// anywhere.
		c.mu.Lock()
		c.releaseSession(s)
		c.mu.Unlock()
		return establishResponse(req, local, compileCause(err), nil)
	}

	changes, created, err := c.compile(s)
	if err != nil {
		c.log.Warn("session: cannot compile the establishment request",
			"cp_seid", cpSEID, "error", err)
		// The compile allocated ids before it hit the error: they are this
		// session's and it is not becoming a session, so nothing else can
		// release them.
		c.mu.Lock()
		c.releaseSession(s)
		c.mu.Unlock()
		return establishResponse(req, local, compileCause(err), nil)
	}
	if err := c.ap.Apply(context.Background(), changes...); err != nil {
		c.log.Warn("session: the dataplane refused the session",
			"cp_seid", cpSEID, "seid", local, "error", err)
		// A definite refusal means nothing of this session is in the dataplane,
		// so its ids are free again. An *unanswered* request is different: the
		// transaction may have committed, and handing those ids to the next
		// session would let it overwrite records this request's rules still
		// select -- so they stay allocated, and the leak is the safe failure.
		if definiteRefusal(err) {
			c.mu.Lock()
			c.releaseSession(s)
			c.mu.Unlock()
		}
		return establishResponse(req, local, causeOf(err), nil)
	}

	c.mu.Lock()
	c.sessions[local] = s
	for _, p := range pdrsInOrder(s) {
		if p.teid != 0 {
			c.byTEID[p.teid] = s
		}
	}
	c.mu.Unlock()

	c.log.Info("session: established", "cp_seid", cpSEID, "seid", local,
		"ue_ip", s.UEIP.String(), "pdrs", len(s.PDRs), "changes", len(changes))
	return establishResponse(req, local, ie.CauseRequestAccepted, created)
}

// Modify implements n4.SessionHandler: the request's lists are merged into the
// session and the whole session is rewritten in one transaction. Rewriting
// what did not change is idempotent (the daemon applies resource contents, not
// commands), and it keeps one code path for every modification shape; the
// per-record optimizations of docs/design.md ("Modification semantics") can
// narrow it later without changing what the dataplane holds.
func (c *Compiler) Modify(req *message.SessionModificationRequest) message.Message {
	seid := req.SEID()
	c.mu.Lock()
	s := c.sessions[seid]
	c.mu.Unlock()
	if s == nil {
		return modifyResponse(req, seid, ie.CauseSessionContextNotFound, nil)
	}

	ies := modificationIEs(req)
	pdrs, fars, qers, urrs, err := parseCreate(ies)
	if err != nil {
		c.log.Warn("session: cannot read the modification request", "seid", seid, "error", err)
		return modifyResponse(req, seid, parseCause(err), nil)
	}
	removePDRs, removeFARs, removeURRs := parseRemovals(ies)

	// merge takes the lock itself.
	if err := c.merge(s, pdrs, fars, qers, urrs, removePDRs, removeFARs, removeURRs); err != nil {
		c.log.Warn("session: cannot carry the modification request", "seid", seid, "error", err)
		return modifyResponse(req, seid, compileCause(err), nil)
	}

	changes, created, err := c.compile(s)
	if err != nil {
		c.log.Warn("session: cannot compile the modification request", "seid", seid, "error", err)
		// What this compile allocated is not released: the session is live and
		// its records name those ids, so freeing them would let the pool hand
		// them to a session whose record the live one still selects. The ids of
		// objects a modification removed are held for the same reason -- safe,
		// not implemented: those objects' records stay in the dataplane too,
		// and a naive release would free ids that a live record still names. A
		// provenance-tracked release is the fix (docs/design.md).
		return modifyResponse(req, seid, compileCause(err), nil)
	}
	if err := c.ap.Apply(context.Background(), changes...); err != nil {
		c.log.Warn("session: the dataplane refused the modification", "seid", seid, "error", err)
		return modifyResponse(req, seid, causeOf(err), nil)
	}
	c.settle(s)

	c.mu.Lock()
	for _, p := range pdrsInOrder(s) {
		if p.teid != 0 {
			c.byTEID[p.teid] = s
		}
	}
	c.mu.Unlock()

	c.log.Info("session: modified", "seid", seid, "pdrs", len(s.PDRs), "changes", len(changes))
	return modifyResponse(req, seid, ie.CauseRequestAccepted, created)
}

// Delete implements n4.SessionHandler.
func (c *Compiler) Delete(req *message.SessionDeletionRequest) message.Message {
	seid := req.SEID()
	c.mu.Lock()
	s := c.sessions[seid]
	c.mu.Unlock()
	if s == nil {
		// Already gone: the SMF gets the answer it wanted (a retransmitted
		// deletion must not be an error).
		return deleteResponse(req, seid, ie.CauseSessionContextNotFound)
	}
	if err := c.remove(context.Background(), s); err != nil {
		c.log.Warn("session: the dataplane refused the deletion", "seid", seid, "error", err)
		return deleteResponse(req, seid, causeOf(err))
	}
	c.log.Info("session: deleted", "seid", seid)
	return deleteResponse(req, seid, ie.CauseRequestAccepted)
}

// merge folds a request's objects into the session's model.
func (c *Compiler) merge(s *Session, pdrs []pdrReq, fars []farReq, qers []qerReq,
	urrs []urrReq, removePDRs []uint16, removeFARs []uint32, removeURRs []uint32) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, q := range qers {
		entry := s.QERs[q.id]
		if entry == nil {
			entry = &qer{id: q.id}
			s.QERs[q.id] = entry
		}
		// An Update QER carries what changed; every field it names replaces
		// the one before it.
		entry.gateUL, entry.gateDL = q.gateUL, q.gateDL
		if q.hasRate {
			entry.mbUL, entry.mbDL, entry.hasRate = q.mbUL, q.mbDL, true
			if entry.meterUL == 0 {
				if id, err := c.meters.alloc(); err != nil {
					c.log.Warn("session: no meter id left for a QER", "qer", q.id)
				} else {
					entry.meterUL = id
				}
			}
			if entry.meterDL == 0 {
				if id, err := c.meters.alloc(); err != nil {
					c.log.Warn("session: no meter id left for a QER", "qer", q.id)
				} else {
					entry.meterDL = id
				}
			}
		}
	}
	for _, f := range fars {
		entry := s.FARs[f.id]
		if entry == nil {
			entry = &far{id: f.id}
			s.FARs[f.id] = entry
		}
		entry.apply, entry.destIfc = f.apply, f.destIfc
		if f.hasOuter {
			entry.teid, entry.peer, entry.hasOuter = f.teid, f.peer, true
		}
	}
	for _, u := range urrs {
		entry := s.URRs[u.id]
		if entry == nil {
			if !u.create {
				// An Update URR for a URR the session does not hold: the SMF
				// named something that is not there, and accepting it would
				// make a URR out of half a request.
				return fmt.Errorf("%w: the URR %d is not in the session", errNotExpressible, u.id)
			}
			entry = &urr{id: u.id, reported: time.Now()}
			s.URRs[u.id] = entry
		}
		// An Update URR carries what changed (7.5.4.4); the fields it names
		// replace the ones before, and the ones it leaves out stay.
		if u.hasMethod {
			entry.volume, entry.duration = u.volume, u.duration
		}
		if u.hasTriggers {
			entry.periodic, entry.onVolumeTh, entry.onTimeTh = u.periodic, u.onVolumeTh, u.onTimeTh
			entry.onVolQuota, entry.onTimeQuota = u.onVolQuota, u.onTimeQuota
		}
		if u.hasPeriod {
			entry.period = u.period
		}
		if u.hasVolThreshold {
			entry.volThreshold = u.volThreshold
		}
		if u.hasTimeTh {
			entry.timeThreshold, entry.hasTimeTh = u.timeThreshold, true
		}
		if u.hasVolQuota {
			entry.volQuota = u.volQuota
		}
		if u.hasTimeQuota {
			entry.timeQuota, entry.hasTimeQuota = u.timeQuota, true
		}
		if u.hasVolQuota || u.hasTimeQuota || u.hasVolThreshold || u.hasTimeTh {
			// A new quota (or threshold) is the SMF granting more usage: the
			// drop a quota exhaustion put on this URR's PDRs is lifted, and the
			// next evaluation puts it back if the new limit is already reached.
			// This is the one place a provisioned quota re-opens the traffic
			// short of the session being deleted.
			entry.enforcing = false
		}
	}
	for _, id := range removeURRs {
		if urrHeldByAPDR(s, id) {
			// The URR measures the traffic of the PDRs that name it, and a
			// report for a URR whose PDRs are still programmed would name a
			// URR the SMF has removed. The CP function disassociates the PDRs
			// first (an Update PDR that does not name the URR), which is the
			// order a modification takes.
			return fmt.Errorf("%w: the URR %d is still named by a PDR of the session",
				errNotExpressible, id)
		}
		delete(s.URRs, id)
	}
	for _, id := range removePDRs {
		if old := s.PDRs[id]; old != nil {
			// The records stay in the dataplane until the next compile erases
			// them: it is the transaction that carries the removal out, so a
			// refused modification leaves both the PDR and its records.
			s.removed = append(s.removed, old)
		}
		delete(s.PDRs, id)
	}
	for _, id := range removeFARs {
		delete(s.FARs, id)
	}
	for _, p := range pdrs {
		old := s.PDRs[p.id]
		// A request may remove a PDR and create it again; the removal folded in
		// above then says nothing about the PDR that is live now.
		s.forgetRemoval(p.id)
		pdr := &pdr{
			id: p.id, precedence: p.precedence, srcIfc: p.srcIfc,
			ueIP: p.ueIP, sdf: p.sdf, farID: p.farID,
			qerIDs: p.qerIDs, urrIDs: p.urrIDs,
		}
		if old != nil {
			// An update keeps the dataplane identity: the rule that already
			// selects this PDR keeps its action id, so a worker switching
			// between old and new state never sees a dangling reference.
			pdr.actionID = old.actionID
			pdr.teid = old.teid
			pdr.meterID = old.meterID
		}
		if p.hasFTEID && p.srcIfc == ie.SrcInterfaceAccess {
			if p.teid != 0 {
				// An F-TEID the SMF pinned is ours to use and ours to keep out
				// of the allocator's way: another session handed the same
				// value would share the TEID rule, and its uplink packets
				// would land in whichever session wrote the rule last.
				//
				if other := c.byTEID[p.teid]; other != nil && other != s {
					return fmt.Errorf(
						"%w: the pinned F-TEID %#x is session %d's",
						errNoResources, p.teid, other.LocalSEID)
				}
				pdr.teid = p.teid
				c.teids.reserve(p.teid)
				// The mapping goes in here, under merge's lock, not after the
				// Apply: that is what makes the check above atomic. Two
				// concurrent establishments that pin one value would otherwise
				// both pass (the mapping is written later), and the second
				// Apply would overwrite the first's TEID rule. It also means a
				// session's *own* two uplink PDRs that share a pinned value
				// see their own mapping and are accepted. releaseSession rolls
				// it back when the session is refused, and Establish's write
				// after the Apply is the no-op it always was.
				c.byTEID[p.teid] = s
			} else if p.hasCHID {
				// The SMF grouped this PDI with the session's others that carry
				// the same CHOOSE ID (TS 29.244 8.2.3): they are one tunnel
				// endpoint, so the session allocates one F-TEID for the group
				// and hands it to each of them, in this request or in a later
				// one. A pin is not overridden by the group: the pin branch
				// above is the SMF naming the TEID itself, and the two cannot
				// agree on one value by accident.
				teid, ok := s.chids[p.chid]
				if !ok {
					id, err := c.teids.alloc()
					if err != nil {
						return fmt.Errorf("%w: %v", errNoResources, err)
					}
					teid = id
					s.chids[p.chid] = id
				}
				pdr.teid = teid
			} else if pdr.teid == 0 {
				// The SMF left the F-TEID to us (TEID 0): allocate one and
				// report it in the Created PDR. Failing to is not something to
				// shrug at -- a session with TEID 0 has no rule to be selected
				// by, so the uplink would blackhole while the SMF was told the
				// establishment succeeded.
				id, err := c.teids.alloc()
				if err != nil {
					return fmt.Errorf("%w: %v", errNoResources, err)
				}
				pdr.teid = id
			}
		}
		if p.ueIP.IsValid() {
			s.UEIP = p.ueIP
		}
		if old != nil {
			// The form being replaced: its rule key, and the TEID it held, are
			// erased unless the transaction that carries this update writes them
			// (compile).
			s.stale = append(s.stale, old)
		}
		s.PDRs[p.id] = pdr
	}
	// What the request's objects mean for each PDR (resolve): a modification
	// that leaves the model unfaithful to itself is refused before the compile
	// that would write it.
	if err := c.resolve(s); err != nil {
		return err
	}
	return nil
}

// resolve derives what each PDR's FAR and QERs mean for the dataplane: a
// forward or a drop, the meter of the QER this direction is policed by, and
// (downlink) the tunnel record the FAR's outer header creation names. compile
// calls it too, and that is not redundancy: a URR's enforcement changes the
// model with no message from the SMF (report.go), so what a transaction writes
// must follow the model as it is now rather than as the last message left it.
// The caller holds the lock.
func (c *Compiler) resolve(s *Session) error {
	for _, p := range pdrsInOrder(s) {
		far := s.FARs[p.farID]
		dir := c.direction(p.srcIfc)
		p.drop = far == nil || far.apply&applyForw == 0
		p.meterID = 0
		p.tunnels = nil
		for _, qid := range p.qerIDs {
			entry := s.QERs[qid]
			if entry == nil {
				continue
			}
			if p.srcIfc == ie.SrcInterfaceAccess {
				if entry.gateUL == ie.GateStatusClosed {
					p.drop = true
				}
				if entry.hasRate {
					p.meterID = entry.meterUL
				}
			} else {
				if entry.gateDL == ie.GateStatusClosed {
					p.drop = true
				}
				if entry.hasRate {
					p.meterID = entry.meterDL
				}
			}
		}
		if dir.Tunnels != "" && far != nil && far.hasOuter {
			p.tunnels = []string{tunnelsRes(dir)}
		}
		for _, uid := range p.urrIDs {
			if s.URRs[uid] == nil {
				// A PDR the SMF associated with a URR it did not provision (or
				// removed in the same message): the traffic would be counted by
				// nobody, and the report the SMF expects for that URR would
				// never arrive. A URR that exists but measures nothing is the
				// other half of this check, below.
				return fmt.Errorf("%w: PDR %d names the URR %d, which the session does not have",
					errNotExpressible, p.id, uid)
			}
			if dir.Counters == "" {
				// The graph has no counting module for this direction (a
				// deployment that does not charge, or a flag left empty): the
				// session would compile with a URR that measures nothing, and
				// every report from it would say zero -- the quietly-wrong
				// report this refusal exists to avoid.
				return fmt.Errorf(
					"%w: PDR %d names the URR %d, and this graph has no usage counters in that direction",
					errNotExpressible, p.id, uid)
			}
			if s.URRs[uid].enforcing {
				// The URR's quota is used up (5.2.2.2.1): the traffic of every
				// PDR that names it stops, by compiling to the drop gate. A
				// modification that provisions a new quota or threshold clears
				// the flag, which is how the SMF re-opens the traffic, and the
				// next transaction then writes the rule again with its action.
				p.drop = true
			}
		}
		if !p.ueIP.IsValid() {
			// The PDI names no address of its own, so the session's is the one
			// an SMF means (it may send the address on one direction only). An
			// uplink rule with the address masked out instead would match every
			// session's decapsulated packets at that precedence.
			p.ueIP = s.UEIP
		}
	}
	return nil
}

// urrHeldByAPDR reports whether a PDR the session still has names this URR.
// Removing a URR the session's PDRs still measure would leave those PDRs
// counted by a rule the SMF has taken away.
func urrHeldByAPDR(s *Session, id uint32) bool {
	for _, p := range s.PDRs {
		for _, uid := range p.urrIDs {
			if uid == id {
				return true
			}
		}
	}
	return false
}

// teidNamed reports whether a PDR the session still has names this F-TEID. The
// TEID rule is the session's, not the PDR's: several uplink PDRs may share one
// F-TEID, so removing or replacing one of them does not remove the rule.
func teidNamed(s *Session, teid uint32) bool {
	for _, p := range s.PDRs {
		if p.teid == teid {
			return true
		}
	}
	return false
}

// writeCounter writes the counting module's entry for a PDR a URR measures: the
// entry is the whole test, keyed by the ActionId the rule carries, and its
// existence follows the PDR -- a rule that drops keeps it too, so that an erase
// always finds it (the engine refuses an erase of a key that is not there).
func writeCounter(p *pdr, dir Direction) []bess.Change {
	if dir.Counters == "" || len(p.urrIDs) == 0 || p.actionID == 0 {
		return nil
	}
	return []bess.Change{{
		Resource: countersRes(dir),
		Key:      map[string]any{"action_id": p.actionID},
		Value:    map[string]any{},
	}}
}

// qerHoldsMeter reports whether the meter a removed PDR was policed by still
// belongs to a QER the session holds. compile writes a meter for every QER with
// a rate whether or not a PDR names it, so erasing one of those in the same
// transaction would be a second operation on its key -- the engine rejects it.
func qerHoldsMeter(s *Session, removed *pdr) bool {
	for _, q := range s.QERs {
		if q.meterUL == removed.meterID || q.meterDL == removed.meterID {
			return true
		}
	}
	return false
}

// compile turns a session's model into the resource changes that program it,
// and the Created PDRs the answer carries. Every action and meter id the
// session needs is allocated here, once.
func (c *Compiler) compile(s *Session) ([]bess.Change, []*ie.IE, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// What this transaction writes follows the model as it is now: a URR's
	// enforcement changes it without a message from the SMF (report.go).
	if err := c.resolve(s); err != nil {
		return nil, nil, err
	}

	changes := make([]bess.Change, 0, 4*len(s.PDRs)+len(s.QERs))
	created := make([]*ie.IE, 0, len(s.PDRs))

	// A TEID rule is the session's, not the PDR's: two uplink PDRs that share an
	// F-TEID name it twice, and the engine rejects a second operation on one
	// (resource, key) in a transaction. It is written once, with the first PDR's
	// precedence (pdrsInOrder is an order, so that is the lowest).
	writtenTEIDs := map[uint32]bool{}
	// Two PDRs whose filters compile to one rule key are one rule the dataplane
	// cannot tell apart -- precedence is part of the rule's value, not its key,
	// so differing precedence does not separate them. Writing both would be
	// rejected by the engine, and writing either would silently drop the other's
	// action. The case that reaches this is an SMF that programs several uplink
	// PDRs onto one F-TEID with no SDF, distinguishing them only by QFI: this UP
	// does not read QFI (docs/compliance.md), so they are one key, and the
	// session is refused with a rule failure rather than half-programmed.
	writtenRules := map[string]bool{}
	// The rule keys the session still holds, as the transaction will write them.
	live := map[string]bool{}
	for _, p := range s.PDRs {
		dir := c.direction(p.srcIfc)
		if key, err := p.ruleKey(dir.PDRFields); err == nil {
			live[rulesRes(dir)+"\x00"+fmt.Sprint(key)] = true
		}
	}
	// The counter entries the session still needs, as the transaction will write
	// them: one per forwarding PDR a URR measures. A removal or a replaced form
	// whose entry is in this set is not erased -- the write follows, and the
	// engine rejects both operations on one key.
	liveCounters := map[string]bool{}
	for _, p := range s.PDRs {
		dir := c.direction(p.srcIfc)
		// A dropped rule keeps its entry: the entry's existence follows the
		// PDR (a URR still measures it, and the id is still its own), not the
		// rule's effect. Excluding the dropped ones here is what made a second
		// modification erase an entry that was already gone -- which the engine
		// refuses, and which then left the session neither modifiable nor
		// deletable (the drop branch below writes the entry for the same
		// reason).
		if dir.Counters != "" && len(p.urrIDs) > 0 && p.actionID != 0 {
			liveCounters[countersRes(dir)+"\x00"+strconv.FormatUint(uint64(p.actionID), 10)] = true
		}
	}
	// PDRs a modification removed are erased by the same transaction that
	// writes the rest of the session: the SMF is told they are gone, so their
	// rules must stop selecting packets. Three of the records a PDR names can
	// belong to what stays, and the engine rejects a second operation on one
	// (resource, key) -- an erase of a key this transaction also writes, or a
	// second erase of the same key -- so:
	//
	//   - a rule key another PDR compiles to is not erased (the write follows);
	//   - a QER's meter is erased only when the QER went with the PDR, because
	//     compile writes a meter for every QER the session still holds;
	//   - the TEID rule only when no PDR of the session still shares the F-TEID.
	//
	// The action record and the tunnel keyed by it are per-PDR: those always go.
	erased := map[string]bool{}
	erase := func(ch bess.Change) {
		k := ch.Resource + "\x00" + fmt.Sprint(ch.Key)
		if erased[k] {
			return
		}
		erased[k] = true
		changes = append(changes, ch)
	}
	// counterErase takes out the counter entry of a PDR that is going away or
	// that no URR measures any more: the module would go on counting a rule
	// nobody reports, and the rule's id is about to be free.
	counterErase := func(p *pdr) {
		dir := c.direction(p.srcIfc)
		if dir.Counters == "" || len(p.urrIDs) == 0 || p.actionID == 0 {
			return
		}
		if liveCounters[countersRes(dir)+"\x00"+strconv.FormatUint(uint64(p.actionID), 10)] {
			return
		}
		erase(bess.Change{Resource: countersRes(dir), Key: map[string]any{"action_id": p.actionID}})
	}
	for _, p := range s.removed {
		dir := c.direction(p.srcIfc)
		key, err := p.ruleKey(dir.PDRFields)
		if err != nil {
			return nil, nil, fmt.Errorf("removed PDR %d: %w", p.id, err)
		}
		if !live[rulesRes(dir)+"\x00"+fmt.Sprint(key)] {
			erase(bess.Change{Resource: rulesRes(dir), Key: key})
		}
		if p.actionID != 0 {
			erase(bess.Change{Resource: actionsRes(dir), Key: map[string]any{"id": p.actionID}})
		}
		for _, t := range p.tunnels {
			erase(bess.Change{Resource: t, Key: map[string]any{"action_id": p.actionID}})
		}
		if p.teid != 0 && !teidNamed(s, p.teid) {
			erase(bess.Change{Resource: c.teidRes(), Key: teidRuleKey(p.teid)})
		}
		if p.meterID != 0 && !qerHoldsMeter(s, p) {
			erase(bess.Change{Resource: metersRes(dir), Key: map[string]any{"id": p.meterID}})
		}
		counterErase(p)
	}
	// A PDR a modification replaced keeps its action and its tunnel, but its
	// rule key can change under it (a new filter, a new address): the old key
	// would go on selecting that action for packets the PDR no longer describes.
	// It is erased unless the same transaction writes it, which is the update
	// that changed nothing about the key -- and the reason this cannot collide
	// with a write (the engine rejects two operations on one key).
	for _, old := range s.stale {
		dir := c.direction(old.srcIfc)
		key, err := old.ruleKey(dir.PDRFields)
		if err != nil {
			return nil, nil, fmt.Errorf("PDR %d: %w", old.id, err)
		}
		if !live[rulesRes(dir)+"\x00"+fmt.Sprint(key)] {
			erase(bess.Change{Resource: rulesRes(dir), Key: key})
		}
		if old.teid != 0 && !teidNamed(s, old.teid) {
			erase(bess.Change{Resource: c.teidRes(), Key: teidRuleKey(old.teid)})
		}
		counterErase(old)
	}

	// Meters first: an action references the meter its QER resolved to. One
	// record per policed direction, each a two-rate three-colour meter with the
	// QER's own rate committed and peak (the same value twice: a QER's MBR
	// allows a rate, not an excess), and a tenth of a second of burst.
	for _, q := range qersInOrder(s) {
		if !q.hasRate {
			continue
		}
		if q.meterUL != 0 {
			changes = append(changes, meterChange(metersRes(c.cfg.Up), q.meterUL, q.mbUL))
		}
		if q.meterDL != 0 {
			changes = append(changes, meterChange(metersRes(c.cfg.Down), q.meterDL, q.mbDL))
		}
	}

	for _, p := range pdrsInOrder(s) {
		dir := c.direction(p.srcIfc)
		key, err := p.ruleKey(dir.PDRFields)
		if err != nil {
			return nil, nil, fmt.Errorf("PDR %d: %w", p.id, err)
		}
		rkey := rulesRes(dir) + "\x00" + fmt.Sprint(key)
		if writtenRules[rkey] {
			// The rule table knows PDR ids no better than the SMF's filters do:
			// one key is one rule, and the engine would reject the second
			// write. Saying so is better than handing the SMF a session whose
			// second PDR silently has no rule of its own.
			return nil, nil, fmt.Errorf("%w: two PDRs compile to one rule key", errNotExpressible)
		}
		writtenRules[rkey] = true
		if p.drop {
			// A drop needs no action record: the rule's gate is the whole
			// result, and the packet path pays for nothing else. The PDR may
			// hold an action id from the form being replaced (a modification
			// that closed a gate or stopped forwarding); the rule written here
			// names none, so that record is what the PDR no longer uses -- kept
			// in the model, and erased when the PDR is (a PDR that stops
			// forwarding and starts again keeps its identity, docs/design.md).
			changes = append(changes, bess.Change{
				Resource: rulesRes(dir),
				Key:      key,
				Value: map[string]any{
					"priority":  p.precedence,
					"gate":      uint64(dropGate),
					"action_id": uint32(0),
				},
			})
			// A URR that measures this PDR still holds its counter entry: the
			// entry says the rule is measured (the reporting side reads it), and
			// its existence must follow the PDR rather than the rule's effect,
			// so that a later erase has something to erase. The counter counts
			// nothing while the rule drops: no packet reaches the action.
			changes = append(changes, writeCounter(p, dir)...)
			continue
		}
		if p.actionID == 0 {
			id, err := c.actions.alloc()
			if err != nil {
				return nil, nil, fmt.Errorf("allocating an action for PDR %d: %w", p.id, err)
			}
			p.actionID = id
		}

		changes = append(changes, bess.Change{
			Resource: actionsRes(dir),
			Key:      map[string]any{"id": p.actionID},
			Value:    map[string]any{"meter_id": p.meterID, "next_hop_id": dir.NextHop},
		})

		// A PDR a URR measures carries one counter entry, keyed by the same
		// ActionId: the module counts what the chain forwards for that rule,
		// and the reporting side sums the entries of the URR's PDRs. The entry
		// is what keeps a session without a URR off the counting module's cost.
		changes = append(changes, writeCounter(p, dir)...)

		// A downlink PDR's FAR names the tunnel this session's packets leave
		// by: the record is keyed by the same action id the rule carries.
		for _, resource := range p.tunnels {
			far := s.FARs[p.farID]
			changes = append(changes, bess.Change{
				Resource: resource,
				Key:      map[string]any{"action_id": p.actionID},
				Value: map[string]any{
					"teid":      far.teid,
					"gnb_ip":    far.peer.String(),
					"ether_src": c.cfg.N3MAC[:],
					"ether_dst": c.cfg.PeerMAC[:],
				},
			})
		}

		changes = append(changes, bess.Change{
			Resource: rulesRes(dir),
			Key:      key,
			Value: map[string]any{
				// The table's own output gate: one chain per direction.
				"priority":  p.precedence,
				"gate":      uint64(0),
				"action_id": p.actionID,
			},
		})

		// An uplink PDR's F-TEID is what makes the TEID ours: a rule of the
		// table in front of the decap, which delivers matching G-PDUs to it.
		// A TEID no rule names is dropped there (the table's default gate),
		// so the decap itself needs no session state.
		if p.teid != 0 {
			if !writtenTEIDs[p.teid] {
				writtenTEIDs[p.teid] = true
				changes = append(changes, bess.Change{
					Resource: c.teidRes(),
					Key:      teidRuleKey(p.teid),
					Value: map[string]any{
						"priority": p.precedence,
						"gate":     uint64(c.cfg.TEIDGate),
					},
				})
			}
			created = append(created, ie.NewCreatedPDR(
				ie.NewPDRID(p.id),
				createdFTEID(p.teid, c.cfg.N3Addr)))
		}
	}
	return changes, created, nil
}

// ruleKey is the WildcardMatch rule key for a PDR: for every field of the
// table, the mask the PDI constrains it with, and the value the packet must
// carry. A field the PDI does not name is masked out, which is what lets one
// table hold PDRs of different shapes.
//
// The value must be canonical (value & ^mask == 0), and the key is the
// concatenation of mask then value per field.
func (p *pdr) ruleKey(fields []Field) (map[string]any, error) {
	// The table's key message is WildcardMatchRuleKey: one FieldData per
	// field, values and masks in two parallel lists (protobuf JSON, which is
	// how the SDK builds it: a bytes field is base64).
	values := make([]map[string]any, 0, len(fields))
	masks := make([]map[string]any, 0, len(fields))
	for _, f := range fields {
		width := f.width()
		mask := make([]byte, width)
		value := make([]byte, width)
		m, ok, err := p.matchValue(f)
		if err != nil {
			return nil, fmt.Errorf("the PDI's %s: %w", f, err)
		}
		if ok {
			copy(mask, m.mask)
			copy(value, m.value)
		}
		values = append(values, map[string]any{"value_bin": value})
		masks = append(masks, map[string]any{"value_bin": mask})
	}
	return map[string]any{"values": values, "masks": masks}, nil
}

// match is one field's constraint: the bits a PDI fixes, and the mask that says
// which of them matter. The two differ where the PDI names a prefix -- an SDF
// filter's "to 10.10.0.0/16" is a rule about a /16, not about the address
// 10.10.0.0 -- and the mask is what makes it so.
type match struct {
	value []byte
	mask  []byte
}

// ones is a mask of n bytes, all bits set.
func ones(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = 0xff
	}
	return b
}

// host is a field constrained to one IPv4 address: the UE's, where a PDI names
// it. Both ways of not having one are inexpressible. An address the table's
// four bytes cannot carry would otherwise be *unconstrained*, and a masked-out
// address matches every address -- another session's packets included. An
// invalid one means the session has no UE address anywhere: merge fills a PDI's
// address in from the session's when the PDI names none, so nothing is left to
// key the rule on, and an unconstrained uplink rule would match every session's
// decapsulated packets at its precedence.
func host(a netip.Addr) (match, bool, error) {
	if !a.IsValid() {
		// merge fills a PDR's address in from the session's when its own PDI
		// names none, so this is a session with no UE address anywhere: there
		// is nothing to key the rule on, and leaving the field open would let
		// the rule match every session's decapsulated packets.
		return match{}, false, fmt.Errorf("%w: no UE address for the rule's key", errNotExpressible)
	}
	a = a.Unmap()
	if !a.Is4() {
		return match{}, false, fmt.Errorf("%w: address %s is not IPv4", errNotExpressible, a)
	}
	b := a.As4()
	return match{value: b[:], mask: ones(4)}, true, nil
}

// pref is a field constrained to an IPv4 prefix: the value is its network
// address (the canonical form the classifier requires, value & ^mask == 0) and
// the mask its length, bit by bit so a /12 is as expressible as a /16. A
// filter whose address carries host bits ("10.10.1.5/16") means the network:
// the Flow Description's form is address/mask, and the mask is what the table
// carries.
func pref(p netip.Prefix) (match, error) {
	a := p.Addr().Unmap()
	if !a.Is4() {
		return match{}, fmt.Errorf("%w: prefix %s is not IPv4", errNotExpressible, p)
	}
	bits := p.Bits()
	if bits < 0 || bits > 32 {
		return match{}, fmt.Errorf("%w: prefix %s has no IPv4 length", errNotExpressible, p)
	}
	b := a.As4()
	m := make([]byte, 4)
	for i := 0; i < bits; i++ {
		m[i/8] |= 0x80 >> (i % 8)
	}
	for i := range b {
		b[i] &= m[i]
	}
	return match{value: b[:], mask: m}, nil
}

// matchValue is the constraint a PDR puts on one field of its table, whether it
// constrains it at all, and whether the PDI names something the table cannot
// express. The three states are distinct on purpose: a field the PDI leaves
// open is masked out (an uplink PDR is chosen by its UE address, not its
// destination); a field the PDI names is constrained; and one it names in a
// form a 4-byte mask cannot carry is a session the SMF is told to fix, not one
// whose rule quietly matches everything.
func (p *pdr) matchValue(f Field) (match, bool, error) {
	switch f {
	case SrcIP:
		// The uplink's UE address is the source. A downlink PDR's SDF may name
		// either side; when it names no source, the source stays unconstrained
		// -- the peer on the data network is not the UE, so constraining this
		// field to the SDF's *destination* would demand the UE's address on
		// both sides and match no packet at all.
		if p.srcIfc == ie.SrcInterfaceAccess {
			if p.sdf != nil && p.sdf.srcOK {
				m, err := pref(p.sdf.src)
				return m, err == nil, err
			}
			return host(p.ueIP)
		}
		if p.sdf != nil && p.sdf.srcAssigned {
			// "from assigned": the UE is the flow's source. On the uplink that
			// is the fallback below; on the downlink it must be said here,
			// because the SDF carries no address of its own for this side.
			return host(p.ueIP)
		}
		if p.sdf != nil && p.sdf.srcOK {
			m, err := pref(p.sdf.src)
			return m, err == nil, err
		}
		return match{}, false, nil
	case DstIP:
		if p.srcIfc == ie.SrcInterfaceAccess {
			return match{}, false, nil // the uplink is chosen by its UE address
		}
		if p.sdf != nil && p.sdf.dstOK {
			m, err := pref(p.sdf.dst)
			return m, err == nil, err
		}
		return host(p.ueIP)
	case Proto:
		if p.sdf != nil && p.sdf.protoOK {
			return match{value: []byte{p.sdf.proto}, mask: ones(1)}, true, nil
		}
		return match{}, false, nil
	case SrcPort:
		if p.sdf != nil && p.sdf.sportOK {
			b := make([]byte, 2)
			binary.BigEndian.PutUint16(b, p.sdf.sport)
			return match{value: b, mask: ones(2)}, true, nil
		}
		return match{}, false, nil
	case DstPort:
		if p.sdf != nil && p.sdf.dportOK {
			b := make([]byte, 2)
			binary.BigEndian.PutUint16(b, p.sdf.dport)
			return match{value: b, mask: ones(2)}, true, nil
		}
		return match{}, false, nil
	default:
		return match{}, false, nil
	}
}

// createdPDRs is what the response re-states on a retransmission.
func (s *Session) createdPDRs(cfg Config) []*ie.IE {
	out := make([]*ie.IE, 0, len(s.PDRs))
	for _, p := range pdrsInOrder(s) {
		if p.teid != 0 {
			out = append(out, ie.NewCreatedPDR(
				ie.NewPDRID(p.id),
				createdFTEID(p.teid, cfg.N3Addr)))
		}
	}
	return out
}

// -- reading the request ------------------------------------------------------

// requestIEs is a message's IEs in one list. go-pfcp's constructors and its own
// parser put the IEs the header names into typed fields, so a handler never
// sees them in req.IEs: the typed fields *are* the request. Absent fields are
// nil, and a nil IE is not an IE.
func requestIEs(lists ...[]*ie.IE) []*ie.IE {
	var out []*ie.IE
	for _, list := range lists {
		for _, i := range list {
			if i != nil {
				out = append(out, i)
			}
		}
	}
	return out
}

// establishmentIEs is what an establishment request carries.
func establishmentIEs(req *message.SessionEstablishmentRequest) []*ie.IE {
	return requestIEs(
		[]*ie.IE{req.NodeID, req.CPFSEID},
		req.CreatePDR, req.CreateFAR, req.CreateQER, req.CreateURR,
	)
}

// modificationIEs is what a modification request carries: what it creates,
// what it updates, and what it removes.
func modificationIEs(req *message.SessionModificationRequest) []*ie.IE {
	return requestIEs(
		[]*ie.IE{req.NodeID, req.CPFSEID},
		req.CreatePDR, req.CreateFAR, req.CreateQER, req.CreateURR,
		req.UpdatePDR, req.UpdateFAR, req.UpdateQER, req.UpdateURR,
		req.RemovePDR, req.RemoveFAR, req.RemoveQER, req.RemoveURR,
	)
}

func cpFSEID(ies []*ie.IE) (uint64, error) {
	for _, i := range ies {
		if i.Type != ie.FSEID {
			continue
		}
		fields, err := i.FSEID()
		if err != nil {
			return 0, err
		}
		return fields.SEID, nil
	}
	return 0, errors.New("no CP F-SEID")
}

// parseCreate reads the Create/Update lists a session message carries.
func parseCreate(ies []*ie.IE) ([]pdrReq, []farReq, []qerReq, []urrReq, error) {
	var pdrs []pdrReq
	var fars []farReq
	var qers []qerReq
	var urrs []urrReq
	for _, i := range ies {
		switch i.Type {
		case ie.CreatePDR, ie.UpdatePDR:
			p, err := parsePDR(i)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			pdrs = append(pdrs, p)
		case ie.CreateFAR, ie.UpdateFAR:
			f, err := parseFAR(i)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			fars = append(fars, f)
		case ie.CreateQER, ie.UpdateQER:
			q, err := parseQER(i)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			qers = append(qers, q)
		case ie.CreateURR, ie.UpdateURR:
			u, err := parseURR(i)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			urrs = append(urrs, u)
		}
	}
	return pdrs, fars, qers, urrs, nil
}

// parseRemovals reads the PDR, FAR and URR ids a modification removes.
func parseRemovals(ies []*ie.IE) ([]uint16, []uint32, []uint32) {
	var pdrs []uint16
	var fars []uint32
	var urrs []uint32
	for _, i := range ies {
		switch i.Type {
		case ie.RemovePDR:
			children, err := i.RemovePDR()
			if err != nil {
				continue
			}
			for _, c := range children {
				if c.Type != ie.PDRID {
					continue
				}
				if id, err := c.PDRID(); err == nil {
					pdrs = append(pdrs, id)
				}
			}
		case ie.RemoveFAR:
			children, err := i.RemoveFAR()
			if err != nil {
				continue
			}
			for _, c := range children {
				if c.Type != ie.FARID {
					continue
				}
				if id, err := c.FARID(); err == nil {
					fars = append(fars, id)
				}
			}
		case ie.RemoveURR:
			children, err := i.RemoveURR()
			if err != nil {
				continue
			}
			for _, c := range children {
				if c.Type != ie.URRID {
					continue
				}
				if id, err := c.URRID(); err == nil {
					urrs = append(urrs, id)
				}
			}
		}
	}
	return pdrs, fars, urrs
}

func parsePDR(i *ie.IE) (pdrReq, error) {
	children, err := i.CreatePDR()
	what := "Create PDR"
	if i.Type == ie.UpdatePDR {
		children, err = i.UpdatePDR()
		what = "Update PDR"
	}
	if err != nil {
		return pdrReq{}, fmt.Errorf("%s: %w", what, err)
	}
	p := pdrReq{}
	for _, c := range children {
		switch c.Type {
		case ie.PDRID:
			if id, err := c.PDRID(); err == nil {
				p.id = id
			}
		case ie.Precedence:
			if v, err := c.Precedence(); err == nil {
				p.precedence = v
			}
		case ie.FARID:
			if id, err := c.FARID(); err == nil {
				p.farID = id
			}
		case ie.QERID:
			if id, err := c.QERID(); err == nil {
				p.qerIDs = append(p.qerIDs, id)
			}
		case ie.URRID:
			// The URRs this PDR's traffic is measured by (7.5.2.2). An Update
			// PDR replaces the list, like every other field it carries: the
			// request is the PDR's whole new form.
			if id, err := c.URRID(); err == nil {
				p.urrIDs = append(p.urrIDs, id)
			}
		case ie.PDI:
			pdiChildren, err := c.PDI()
			if err != nil {
				return pdrReq{}, fmt.Errorf("PDI: %w", err)
			}
			if err := parsePDI(&p, pdiChildren); err != nil {
				return pdrReq{}, err
			}
		}
	}
	if p.id == 0 {
		return pdrReq{}, errors.New("PDR without a PDR ID")
	}
	return p, nil
}

func parsePDI(p *pdrReq, children []*ie.IE) error {
	for _, c := range children {
		switch c.Type {
		case ie.SourceInterface:
			if v, err := c.SourceInterface(); err == nil {
				p.srcIfc = v
			}
		case ie.FTEID:
			fields, err := c.FTEID()
			if err != nil {
				return fmt.Errorf("F-TEID: %w", err)
			}
			p.hasFTEID = true
			p.teid = fields.TEID
			// CHOOSE ID (8.2.3): with the CH flag the PDI asks us to allocate,
			// and PDIs that carry the same CHOOSE ID are one tunnel endpoint.
			// Without CH the IE carries a TEID the SMF pinned, so there is no
			// allocation for a group to share, and the field's own rule ("this
			// bit may only be set to 1 if the CH bit is set to 1") has it that
			// such a request is malformed: reading a value the library does not
			// parse there would be guessing at an octet the spec puts after the
			// addresses. It is ignored, and the pin is used as it always was.
			if fields.HasCh() && fields.HasChID() {
				p.hasCHID = true
				p.chid = fields.ChooseID
			}
			if fields.HasCh() && fields.HasIPv6() && !fields.HasIPv4() {
				// V6 with no V4 flag is a request for an IPv6 F-TEID (8.2.3:
				// the UP function "shall assign an F-TEID with an IP4 or an
				// IPv6 address if the V4 or V6 bit is set respectively"), and
				// the address this UP advertises on N3 is IPv4: answering with
				// one would hand the SMF a family it did not ask for. IPv6 is
				// an explicit refusal everywhere else too (a PDI naming an IPv6
				// address or prefix is cause 73, docs/compliance.md). V4|V6
				// names both families -- either will do -- and a CH bit with no
				// family at all names none (a shape 8.2.3 does not allow and no
				// SMF sends), so those are answered with the IPv4 F-TEID.
				return fmt.Errorf("%w: the F-TEID IE asks for an IPv6 address, and this UP's N3 address is IPv4", errNotExpressible)
			}
		case ie.UEIPAddress:
			fields, err := c.UEIPAddress()
			if err != nil {
				return fmt.Errorf("UE IP address: %w", err)
			}
			if c.HasCHV4() || c.HasCHV6() {
				// CHV4/CHV6 (TS 29.244 8.2.62): the SMF asks the UP function to
				// choose an address of that family -- the UEIP feature, which
				// this UP neither implements nor advertises. The other family's
				// address may well be present, as it is in a dual-stack session
				// where the SMF gives V4 and asks for V6, so these bits are what
				// says a request was made at all: reading the IE by its
				// addresses accepts the session and answers a success the SMF
				// reads as "the UP chose one", an address it would never learn.
				return fmt.Errorf("%w: the UE IP address IE asks the UP function to allocate an address", errNotExpressible)
			}
			switch {
			case len(fields.IPv4Address) == 4:
				if a, ok := netip.AddrFromSlice(fields.IPv4Address); ok {
					if a.IsUnspecified() {
						// The V4 flag with no address bytes parses as 0.0.0.0:
						// a rule keyed on that matches no packet, so the session
						// would stand while carrying nothing at all.
						return fmt.Errorf("%w: the UE IP address is 0.0.0.0", errNotExpressible)
					}
					p.ueIP = a.Unmap()
				}
			case len(fields.IPv4Address) != 0:
				return fmt.Errorf("%w: the UE IP address is %d bytes", errNotExpressible, len(fields.IPv4Address))
			case len(fields.IPv6Address) != 0:
				// The tables' address fields are four bytes: an IPv6 UE address
				// has no form here, and reading the IE as "no address" would
				// compile a rule that matches every session's packets.
				return fmt.Errorf("%w: the UE IP address is IPv6", errNotExpressible)
			default:
				// Neither address is present. For CHV4/CHV6 (TS 29.244 8.2.62)
				// that is the SMF asking the UP function to choose the address
				// -- the UEIP feature, which this UP neither implements nor
				// advertises -- because those bits suppress the address field.
				// Reading it as "no address constraint" lets the session
				// compile with the other direction's address and answers a
				// success the SMF reads as "the UP chose one", an address it
				// would never learn. An IE with nothing in it at all is no
				// better.
				return fmt.Errorf("%w: the UE IP address IE carries no address, and this UP does not allocate one", errNotExpressible)
			}
		case ie.SDFFilter:
			fields, err := c.SDFFilter()
			if err != nil {
				return fmt.Errorf("SDF filter: %w", err)
			}
			filter, err := parseFlowDescription(fields.FlowDescription)
			if err != nil {
				return fmt.Errorf("SDF filter: %w", err)
			}
			p.sdf = filter
		}
	}
	return nil
}

func parseFAR(i *ie.IE) (farReq, error) {
	children, err := i.CreateFAR()
	what := "Create FAR"
	if i.Type == ie.UpdateFAR {
		children, err = i.UpdateFAR()
		what = "Update FAR"
	}
	if err != nil {
		return farReq{}, fmt.Errorf("%s: %w", what, err)
	}
	f := farReq{}
	for _, c := range children {
		switch c.Type {
		case ie.FARID:
			if id, err := c.FARID(); err == nil {
				f.id = id
			}
		case ie.ApplyAction:
			flags, err := c.ApplyAction()
			if err != nil {
				return farReq{}, fmt.Errorf("Apply Action: %w", err)
			}
			if len(flags) > 0 {
				f.apply = flags[0]
			}
		case ie.ForwardingParameters:
			fwd, err := c.ForwardingParameters()
			if err != nil {
				return farReq{}, fmt.Errorf("Forwarding Parameters: %w", err)
			}
			for _, fp := range fwd {
				switch fp.Type {
				case ie.DestinationInterface:
					if v, err := fp.DestinationInterface(); err == nil {
						f.destIfc = v
					}
				case ie.OuterHeaderCreation:
					fields, err := fp.OuterHeaderCreation()
					if err != nil {
						return farReq{}, fmt.Errorf("Outer Header Creation: %w", err)
					}
					if fields.TEID == 0 {
						return farReq{}, errors.New(
							"Outer Header Creation without a TEID")
					}
					peer, ok := netip.AddrFromSlice(fields.IPv4Address)
					if !ok {
						return farReq{}, errors.New(
							"Outer Header Creation without an IPv4 address")
					}
					f.hasOuter, f.teid, f.peer = true, fields.TEID, peer.Unmap()
				}
			}
		}
	}
	if f.id == 0 {
		return farReq{}, errors.New("FAR without a FAR ID")
	}
	return f, nil
}

// parseURR reads a Create URR or an Update URR (TS 29.244 7.5.2.4): what the
// rule measures, when it reports, and its thresholds and quota. Anything this UP
// does not implement is refused here -- see urrUnsupported for why a silently
// ignored URR field is not an option.
func parseURR(i *ie.IE) (urrReq, error) {
	children, err := i.CreateURR()
	what := "Create URR"
	u := urrReq{create: true}
	if i.Type == ie.UpdateURR {
		children, err = i.UpdateURR()
		what, u.create = "Update URR", false
	}
	if err != nil {
		return urrReq{}, fmt.Errorf("%s: %w", what, err)
	}
	for _, c := range children {
		if name, ok := urrUnsupported[c.Type]; ok {
			return urrReq{}, fmt.Errorf("%w: the URR names %s, and this UP does not implement it",
				errNotExpressible, name)
		}
		switch c.Type {
		case ie.URRID:
			if id, err := c.URRID(); err == nil {
				u.id = id
			}
		case ie.MeasurementMethod:
			flags, err := c.MeasurementMethod()
			if err != nil {
				return urrReq{}, fmt.Errorf("Measurement Method: %w", err)
			}
			if flags&methodEvent != 0 {
				// An event is preconfigured detection logic in the UPF
				// (5.2.2.2.1, note 7); this UP has none, and a report whose
				// event count never moves is worse than the refusal.
				return urrReq{}, fmt.Errorf("%w: the URR asks for event measurement, and this UP detects no events",
					errNotExpressible)
			}
			if flags&(methodVolume|methodDuration) == 0 {
				return urrReq{}, fmt.Errorf("%w: the Measurement Method names no measurement", errNotExpressible)
			}
			u.hasMethod = true
			u.volume = flags&methodVolume != 0
			u.duration = flags&methodDuration != 0
		case ie.ReportingTriggers:
			// The IE's own payload, not the library's ReportingTriggers():
			// that accessor wants two octets, while 8.2.19's octets 6 and 7 are
			// present only when the SMF sets a bit in them -- a periodic-only
			// URR is one octet, which the accessor reads as a malformed IE.
			flags := c.Payload
			if len(flags) == 0 {
				return urrReq{}, fmt.Errorf("%w: the Reporting Triggers IE is empty", errNotExpressible)
			}
			// 8.2.19: "At least one bit shall be set to 1", and the octets are
			// coded in order -- the first is octet 5, the next octet 6.
			any := false
			for n, octet := range flags {
				for bit := uint8(1); bit != 0; bit <<= 1 {
					if octet&bit == 0 {
						continue
					}
					any = true
					if n < len(triggersImplemented) && triggersImplemented[n]&bit != 0 {
						continue
					}
					name := triggerName(byte(5+n), bit)
					if name == "" {
						name = fmt.Sprintf("the spare bit %#x of octet %d", bit, 5+n)
					}
					return urrReq{}, fmt.Errorf(
						"%w: the URR asks for the %s reporting trigger, and this UP does not implement it",
						errNotExpressible, name)
				}
			}
			if !any {
				return urrReq{}, fmt.Errorf("%w: the Reporting Triggers IE names no trigger", errNotExpressible)
			}
			u.hasTriggers = true
			u.periodic = flags[0]&trigPeriodic != 0
			u.onVolumeTh = flags[0]&trigVolumeTh != 0
			u.onTimeTh = flags[0]&trigTimeTh != 0
			if len(flags) > 1 {
				u.onVolQuota = flags[1]&trigVolQuota != 0
				u.onTimeQuota = flags[1]&trigTimeQuota != 0
			}
		case ie.MeasurementPeriod:
			v, err := c.MeasurementPeriod()
			if err != nil {
				return urrReq{}, fmt.Errorf("Measurement Period: %w", err)
			}
			u.hasPeriod = true
			u.period = v
		case ie.VolumeThreshold:
			fields, err := c.VolumeThreshold()
			if err != nil {
				return urrReq{}, fmt.Errorf("Volume Threshold: %w", err)
			}
			u.hasVolThreshold = true
			u.volThreshold = volumeLimit{
				hasTotal: fields.Flags&0x01 != 0, total: fields.TotalVolume,
				hasUL: fields.Flags&0x02 != 0, ul: fields.UplinkVolume,
				hasDL: fields.Flags&0x04 != 0, dl: fields.DownlinkVolume,
			}
		case ie.TimeThreshold:
			v, err := c.TimeThreshold()
			if err != nil {
				return urrReq{}, fmt.Errorf("Time Threshold: %w", err)
			}
			u.hasTimeTh, u.timeThreshold = true, v
		case ie.VolumeQuota:
			fields, err := c.VolumeQuota()
			if err != nil {
				return urrReq{}, fmt.Errorf("Volume Quota: %w", err)
			}
			u.hasVolQuota = true
			u.volQuota = volumeLimit{
				hasTotal: fields.Flags&0x01 != 0, total: fields.TotalVolume,
				hasUL: fields.Flags&0x02 != 0, ul: fields.UplinkVolume,
				hasDL: fields.Flags&0x04 != 0, dl: fields.DownlinkVolume,
			}
		case ie.TimeQuota:
			v, err := c.TimeQuota()
			if err != nil {
				return urrReq{}, fmt.Errorf("Time Quota: %w", err)
			}
			u.hasTimeQuota, u.timeQuota = true, v
		}
	}
	if u.id == 0 {
		return urrReq{}, errors.New("URR without a URR ID")
	}
	if u.create && (!u.hasMethod || !u.hasTriggers) {
		// Both are mandatory in a Create URR (7.5.2.4's table). Accepting a URR
		// with neither would leave a rule nobody can report from.
		return urrReq{}, fmt.Errorf("%w: a Create URR needs a Measurement Method and Reporting Triggers",
			errNotExpressible)
	}
	if u.hasPeriod && !u.periodic {
		// The period is what the periodic trigger fires on; without the trigger
		// it is a value the SMF would never see acted on.
		return urrReq{}, fmt.Errorf("%w: a Measurement Period without the periodic trigger",
			errNotExpressible)
	}
	return u, nil
}

func parseQER(i *ie.IE) (qerReq, error) {
	children, err := i.CreateQER()
	what := "Create QER"
	if i.Type == ie.UpdateQER {
		children, err = i.UpdateQER()
		what = "Update QER"
	}
	if err != nil {
		return qerReq{}, fmt.Errorf("%s: %w", what, err)
	}
	q := qerReq{gateUL: ie.GateStatusOpen, gateDL: ie.GateStatusOpen}
	for _, c := range children {
		switch c.Type {
		case ie.QERID:
			if id, err := c.QERID(); err == nil {
				q.id = id
			}
		case ie.GateStatus:
			if ul, err := c.GateStatusUL(); err == nil {
				q.gateUL = ul
			}
			if dl, err := c.GateStatusDL(); err == nil {
				q.gateDL = dl
			}
		case ie.MBR:
			payload, err := c.MBR()
			if err != nil || len(payload) < 10 {
				return qerReq{}, errors.New("MBR: malformed")
			}
			q.mbUL = uint40(payload[0:5])
			q.mbDL = uint40(payload[5:10])
			q.hasRate = true
		}
	}
	if q.id == 0 {
		return qerReq{}, errors.New("QER without a QER ID")
	}
	return q, nil
}

// meterChange is the resource for one policed direction: a two-rate three-colour
// meter at `rate` bytes per second, with a tenth of a second of burst.
func meterChange(resource string, id uint32, rate uint64) bess.Change {
	burst := rate / 10
	return bess.Change{
		Resource: resource,
		Key:      map[string]any{"id": id},
		Value: map[string]any{
			"tr_tcm": map[string]any{
				"committed_rate":  rate,
				"committed_burst": burst,
				"peak_rate":       rate,
				"peak_burst":      burst,
			},
		},
	}
}

// uint40 reads the 5-octet, octet-aligned integer the MBR IE carries. Its unit
// is kb/s (TS 29.244 8.2.8); the meter's rates are bytes per second.
func uint40(b []byte) uint64 {
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v * 1000 / 8
}

// ----------------------------------------------------------------------------

// sdfFilter is a parsed IPFilterRule: what the PDR's rule must match, and what
// it leaves to the PDI's own fields.
type sdfFilter struct {
	proto   uint8
	protoOK bool
	src     netip.Prefix
	srcOK   bool
	dst     netip.Prefix
	dstOK   bool
	// "assigned" is the session's UE address rather than a value the filter
	// carries, and a PDI's IEs are a set: the SDF filter may be read before the
	// UE IP address is known. So the word is kept, and the key builder -- which
	// runs once the whole session is read -- is where the address is filled in.
	srcAssigned bool
	dstAssigned bool
	sport       uint16
	sportOK     bool
	dport       uint16
	dportOK     bool
}

// parseFlowDescription reads the IPFilterRule form the SDF Filter IE carries
// (TS 29.244 8.2.5): "permit <dir> <proto> from <src> [<port>] to <dst>
// [<port>]". "assigned" is the PDI's UE address, "any" leaves the field
// unconstrained.
//
// A range that is not one value cannot be expressed by a mask, so it is
// refused here rather than silently matched too widely: the dataplane needs the
// range kernel of the roadmap's classifier work for that.
func parseFlowDescription(fd string) (*sdfFilter, error) {
	fields := strings.Fields(fd)
	if len(fields) < 4 {
		return nil, fmt.Errorf("flow description %q is too short", fd)
	}
	if fields[0] != "permit" {
		return nil, fmt.Errorf("flow description %q: only 'permit' rules can be a PDR", fd)
	}
	// permit [in|out] <proto> from <src> [port] to <dst> [port]
	i := 1
	if fields[i] == "in" || fields[i] == "out" {
		i++
	}
	if len(fields) < i+4 {
		return nil, fmt.Errorf("flow description %q is too short", fd)
	}

	f := &sdfFilter{}
	switch strings.ToLower(fields[i]) {
	case "ip", "any":
		// nothing to constrain
	case "tcp":
		f.proto, f.protoOK = 6, true
	case "udp":
		f.proto, f.protoOK = 17, true
	case "icmp":
		f.proto, f.protoOK = 1, true
	default:
		n, err := strconv.ParseUint(fields[i], 10, 8)
		if err != nil {
			return nil, fmt.Errorf("flow description %q: unknown protocol %q", fd, fields[i])
		}
		f.proto, f.protoOK = uint8(n), true
	}
	i++
	if fields[i] != "from" {
		return nil, fmt.Errorf("flow description %q: expected 'from'", fd)
	}
	i++
	addr, assigned, next, err := parseFilterAddr(fields[i])
	if err != nil {
		return nil, fmt.Errorf("flow description %q: %w", fd, err)
	}
	f.src, f.srcOK, f.srcAssigned = addr, addr.IsValid(), assigned
	i += next
	if i < len(fields) && fields[i] != "to" {
		port, err := parseFilterPort(fields[i])
		if err != nil {
			return nil, fmt.Errorf("flow description %q: %w", fd, err)
		}
		f.sport, f.sportOK = port, true
		i++
	}
	if i >= len(fields) || fields[i] != "to" {
		return nil, fmt.Errorf("flow description %q: expected 'to'", fd)
	}
	i++
	if i >= len(fields) {
		return nil, fmt.Errorf("flow description %q: no destination", fd)
	}
	addr, assigned, next, err = parseFilterAddr(fields[i])
	if err != nil {
		return nil, fmt.Errorf("flow description %q: %w", fd, err)
	}
	f.dst, f.dstOK, f.dstAssigned = addr, addr.IsValid(), assigned
	i += next
	if i < len(fields) {
		port, err := parseFilterPort(fields[i])
		if err != nil {
			return nil, fmt.Errorf("flow description %q: %w", fd, err)
		}
		f.dport, f.dportOK = port, true
		i++
	}
	if i != len(fields) {
		return nil, fmt.Errorf("flow description %q: trailing %q", fd, strings.Join(fields[i:], " "))
	}
	return f, nil
}

// parseFilterAddr reads one address of a flow description: "any", "assigned",
// an address, or a prefix. It returns the prefix (invalid for "any", which
// leaves the field unconstrained, and for "assigned", which is the session's UE
// address and is filled in later), whether the word was "assigned", and how
// many words it consumed.
func parseFilterAddr(word string) (netip.Prefix, bool, int, error) {
	switch strings.ToLower(word) {
	case "any":
		return netip.Prefix{}, false, 1, nil
	case "assigned":
		return netip.Prefix{}, true, 1, nil
	}
	if strings.Contains(word, "/") {
		p, err := netip.ParsePrefix(word)
		if err != nil {
			return netip.Prefix{}, false, 0, fmt.Errorf("invalid address %q", word)
		}
		// A Flow Description is address/mask (TS 29.244 8.2.2, by way of TS
		// 29.212 5.4.2): host bits in the address are not a different filter,
		// they are bits the mask ignores. The rule the table gets carries the
		// network address and the mask (compile.go, pref).
		return p, false, 1, nil
	}
	a, err := netip.ParseAddr(word)
	if err != nil {
		return netip.Prefix{}, false, 0, fmt.Errorf("invalid address %q", word)
	}
	return netip.PrefixFrom(a.Unmap(), a.BitLen()), false, 1, nil
}

// parseFilterPort reads one port of a flow description: a number, or a range
// that collapses to one.
func parseFilterPort(word string) (uint16, error) {
	if lo, hi, ok := strings.Cut(word, "-"); ok {
		a, err := strconv.ParseUint(lo, 10, 16)
		if err != nil {
			return 0, fmt.Errorf("invalid port %q", word)
		}
		b, err := strconv.ParseUint(hi, 10, 16)
		if err != nil {
			return 0, fmt.Errorf("invalid port %q", word)
		}
		if a != b {
			return 0, fmt.Errorf("%w: port range %q", errNotExpressible, word)
		}
		return uint16(a), nil
	}
	v, err := strconv.ParseUint(word, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", word)
	}
	return uint16(v), nil
}

// -- answers ------------------------------------------------------------------

func establishResponse(req *message.SessionEstablishmentRequest, seid uint64,
	cause uint8, created []*ie.IE) message.Message {
	ies := []*ie.IE{ie.NewCause(cause)}
	if cause == ie.CauseRequestAccepted {
		ies = append(ies, ie.NewFSEID(seid, nil, nil))
		ies = append(ies, created...)
	}
	return message.NewSessionEstablishmentResponse(0, 0, seid, req.Sequence(), 0, ies...)
}

func modifyResponse(req *message.SessionModificationRequest, seid uint64,
	cause uint8, created []*ie.IE) message.Message {
	ies := []*ie.IE{ie.NewCause(cause)}
	if cause == ie.CauseRequestAccepted {
		ies = append(ies, created...)
	}
	return message.NewSessionModificationResponse(0, 0, seid, req.Sequence(), 0, ies...)
}

func deleteResponse(req *message.SessionDeletionRequest, seid uint64, cause uint8) message.Message {
	return message.NewSessionDeletionResponse(0, 0, seid, req.Sequence(), 0,
		ie.NewCause(cause))
}

// parseCause maps a request-reading failure to the cause the SMF sees: a
// well-formed rule the dataplane cannot carry is a rule failure (what a
// retransmission of it would hit again), while an unreadable message is a
// rejection.
func parseCause(err error) uint8 {
	if errors.Is(err, errNotExpressible) {
		return ie.CauseRuleCreationModificationFailure
	}
	return ie.CauseRequestRejected
}

// compileCause maps a compile failure to the cause the SMF sees. A rule the
// mask cannot express is a rule failure; a resource the UPF has none of is
// cause 75 ("no resources available"), which is what an SMF retries or
// reconciles against.
func compileCause(err error) uint8 {
	if errors.Is(err, errNoResources) {
		return ie.CauseNoResourcesAvailable
	}
	return ie.CauseRuleCreationModificationFailure
}

// causeOf maps a failed transaction to the cause the SMF sees. The SDK's
// errors say *what* failed, and a refusal must not look like a success: the
// dataplane is all-or-nothing, so nothing of the session is in place when one
// of these returns.
func causeOf(err error) uint8 {
	switch {
	case definiteRefusal(err):
		return ie.CauseRuleCreationModificationFailure
	default:
		// A conflict, a busy dataplane, a restarted daemon or an unanswered
		// request: the SMF retries, and the retry finds the state this attempt
		// did or did not leave (a repeated establishment is answered with what
		// is in place).
		return ie.CauseRequestRejected
	}
}

// definiteRefusal reports whether the SDK's error says the daemon refused the
// transaction outright. The alternative is an outcome that is unknown (no
// answer, a transport error): the transaction may have committed, so a caller
// must not treat the session's ids or records as its own to undo.
func definiteRefusal(err error) bool {
	var invalid *bess.InvalidRequestError
	var rejected *bess.RejectedError
	return errors.As(err, &invalid) || errors.As(err, &rejected)
}

// createdFTEID is the F-TEID of a Created PDR: our own TEID and the N3
// address, with the flags telling the SMF which address family the field
// carries (an F-TEID's IPv4 flag is bit 1; the zero flags of a field built by
// hand would drop the address).
func createdFTEID(teid uint32, addr netip.Addr) *ie.IE {
	ip := net.IP(nil)
	if addr.Is4() {
		b := addr.As4()
		ip = b[:]
	}
	fields := ie.NewFTEIDFields(0, teid, ip, nil, 0)
	if ip != nil {
		fields.SetIPv4Flag()
	}
	return ie.NewFTEID(fields.Flags, teid, ip, nil, 0)
}
