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
	"math"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/bess"
	"github.com/krsna1729/upf/internal/routing"
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

// heldFlows is what a session's buffering holds right now: the ActionIds of the
// PDRs whose FAR asks for the packets to be held (p.buffer), plus the flows a
// modification already took off the graph whose records the dataplane still
// holds. It is the set a deletion and a DROBU modification both discard. The
// caller holds the lock.
func heldFlows(s *Session) []uint32 {
	var out []uint32
	for _, p := range s.PDRs {
		if p.buffer && p.actionID != 0 {
			out = append(out, p.actionID)
		}
	}
	return append(out, removedFlows(s)...)
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

	// instance is the PDI's Network Instance (TS 29.244 8.2.4): the deployment
	// interface this rule belongs to, empty when the SMF named none.
	instance string

	// hasQFI and qfi are the PDI's QFI (TS 29.244 8.2.89): the QoS flow this
	// rule selects, one of 1..63. A PDI that names none is the session's
	// general rule for the flow, and the uplink table's qfi field is masked out
	// of its key -- so it keeps matching where a QFI-specific rule does not.
	hasQFI bool
	qfi    uint8

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

	// hasApply, hasDestIfc and hasInstance say which fields the message
	// carried. An Update FAR carries what changes (7.5.4.3), so a field it
	// leaves out keeps the value the session has: treating its zero as the new
	// value would stop a forward (no Apply Action), send an uplink forward back
	// out of N3 (destination interface 0 is the access side), or drop the
	// instance the forward leaves by (an empty one falls back to the PDI's).
	hasApply    bool
	hasDestIfc  bool
	hasInstance bool

	// instance is the Network Instance inside the Forwarding Parameters
	// (8.2.4): the interface this forward leaves by, empty when the SMF named
	// none. It is not the PDI's instance -- that one says which flow the rule
	// selects.
	instance string

	// hasBAR and barID are the FAR's BAR ID (8.2.55, one octet): the buffering
	// instruction this FAR's held packets live under.
	hasBAR bool
	barID  uint8

	// hasMarking and marking are the FAR's Transport Level Marking
	// (8.2.42, inside the Forwarding Parameters): what the SMF asks the outer
	// header's ToS/Traffic Class to carry, the DSCP in the high octet and the
	// mask in the low one. An Update FAR's omission keeps the value the
	// session has, the way the instance's does.
	hasMarking bool
	marking    uint16
}

// barReq is a Create BAR or Update BAR as the message carried it (TS 29.244
// 7.5.2.6): the session's buffering instruction for the FARs that name it.
type barReq struct {
	id uint8

	// hasDuration says the message carried the DL Buffering Duration IE
	// (8.2.29). The IE is a timer: a unit in bits 8-6 and a value in bits 5-1.
	// Two of its codes are not durations: unit and value both zero is the
	// deactivated code ("the timer is stopped"), which clears the session's
	// override rather than setting a zero duration, and the infinite unit is
	// hold-without-expiry, the one value that reaches the store as a timeout of
	// zero ("hold until the SMF says what to do"). The two are separate fields
	// because zero is a legal value of neither.
	hasDuration bool
	deactivated bool
	duration    time.Duration
	infinite    bool

	// hasCount says the message carried the DL Buffering Suggested Packet Count
	// (8.2.30). A zero is folded into "not instructed" by merge: a cap of no
	// packets is not an instruction an SMF sends.
	hasCount bool
	count    uint32
}

type qerReq struct {
	id      uint32
	gateUL  uint8
	gateDL  uint8
	mbUL    uint64
	mbDL    uint64
	hasRate bool

	// hasQFI and qfi are the QER's QFI (TS 29.244 8.2.89): the QoS flow this
	// QER polices. It is optional -- Gate Status is the QER's one mandatory IE
	// -- so an Update QER that leaves it out keeps the flow the session holds.
	hasQFI bool
	qfi    uint8
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

	// hasLinked and linked are the URR's Linked URR IDs (TS 29.244 8.2.55): the
	// other URRs it reports with, which the session groups and reports under one
	// UR-SEQN. An Update URR that names any replaces the set; one that names
	// none keeps it.
	hasLinked bool
	linked    []uint32
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
// time, an inactivity detector, a quota that expires on a timer, a limit on how
// many reports to send, a dropped-traffic threshold. Each is refused when the
// URR is read rather than silently not measured: the SMF bills from these
// reports, and one that arrives without what was asked for is worse than a rule
// failure it can act on. (The list is by IE name: the clause numbers of the
// refused ones are not this milestone's, and a wrong number in a refusal is
// worse than none.)
var urrUnsupported = map[uint16]string{
	ie.MeasurementInformation:    "Measurement Information",
	ie.MonitoringTime:            "Monitoring Time",
	ie.InactivityDetectionTime:   "Inactivity Detection Time",
	ie.QuotaHoldingTime:          "Quota Holding Time",
	ie.QuotaValidityTime:         "Quota Validity Time",
	ie.DroppedDLTrafficThreshold: "Dropped DL Traffic Threshold",
	ie.UserPlaneInactivityTimer:  "User Plane Inactivity Timer",
	ie.NumberOfReports:           "Number of Reports",
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
	resp := c.establish(req)
	if answerCause(resp) != ie.CauseRequestAccepted {
		c.stats.refused.Add(1)
	}
	return resp
}

// establish is the establishment itself; Establish counts what it answered.
func (c *Compiler) establish(req *message.SessionEstablishmentRequest) message.Message {
	ies := establishmentIEs(req)
	cpSEID, err := cpFSEID(ies)
	if err != nil {
		c.log.Warn("session: the establishment request names no CP F-SEID", "error", err)
		// The request carries no CP F-SEID at all, so there is none to answer
		// under either: the header's SEID is 0 (a session message always carries
		// the SEID field, and 0 names no session).
		return establishResponse(req, 0, 0, ie.CauseMandatoryIEMissing, nil)
	}
	pdrs, fars, bars, qers, urrs, err := parseCreate(ies)
	if err != nil {
		c.log.Warn("session: cannot read the establishment request", "error", err)
		return establishResponse(req, cpSEID, 0, parseCause(err), nil)
	}

	c.mu.Lock()
	// A retransmission of an establishment we already applied: answer as
	// before rather than allocating a second session for it.
	if s := c.findByCP(cpSEID); s != nil {
		created := s.createdPDRs(c.cfg)
		c.mu.Unlock()
		c.log.Info("session: establishment repeated", "cp_seid", cpSEID, "seid", s.LocalSEID)
		return establishResponse(req, s.CPSEID, s.LocalSEID, ie.CauseRequestAccepted, created)
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
		BARs:      map[uint8]*bar{},
		chids:     map[uint8]uint32{},
	}
	if err := c.merge(s, pdrs, fars, bars, qers, urrs, nil, nil, nil, nil); err != nil {
		c.log.Warn("session: cannot carry the establishment request",
			"cp_seid", cpSEID, "error", err)
		// merge allocates as it goes (the F-TEID among them) and refuses when a
		// later PDR names something the table cannot carry, or a value another
		// session holds: what it got through is this session's and is not going
		// anywhere.
		c.mu.Lock()
		c.releaseSession(s)
		c.mu.Unlock()
		return establishResponse(req, cpSEID, local, compileCause(err), nil)
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
		return establishResponse(req, cpSEID, local, compileCause(err), nil)
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
		return establishResponse(req, cpSEID, local, causeOf(err), nil)
	}

	c.mu.Lock()
	c.sessions[local] = s
	for _, p := range pdrsInOrder(s) {
		if p.teid != 0 {
			c.byTEID[p.teid] = s
		}
	}
	c.mu.Unlock()
	c.stats.established.Add(1)
	c.checkpoint(kindEstablish, local, req)

	c.log.Info("session: established", "cp_seid", cpSEID, "seid", local,
		"ue_ip", s.UEIP.String(), "pdrs", len(s.PDRs), "changes", len(changes))
	return establishResponse(req, cpSEID, local, ie.CauseRequestAccepted, created)
}

// Modify implements n4.SessionHandler: the request's lists are merged into the
// session and the whole session is rewritten in one transaction. Rewriting
// what did not change is idempotent (the daemon applies resource contents, not
// commands), and it keeps one code path for every modification shape; the
// per-record optimizations of docs/design.md ("Modification semantics") can
// narrow it later without changing what the dataplane holds.
// Modify implements n4.SessionHandler.
func (c *Compiler) Modify(req *message.SessionModificationRequest) message.Message {
	resp := c.modify(req)
	if answerCause(resp) == ie.CauseRequestAccepted {
		c.stats.modified.Add(1)
	} else {
		c.stats.refused.Add(1)
	}
	return resp
}

// modify is the modification itself; Modify counts what it answered.
func (c *Compiler) modify(req *message.SessionModificationRequest) message.Message {
	seid := req.SEID()
	c.mu.Lock()
	s := c.sessions[seid]
	c.mu.Unlock()
	// The header of the answer carries the SEID the SMF knows the session by,
	// and with no session in hand the only value left is the one it sent.
	hdr := seid
	if s != nil {
		hdr = s.CPSEID
	}
	if s == nil {
		return modifyResponse(req, hdr, ie.CauseSessionContextNotFound, nil)
	}

	ies := modificationIEs(req)
	pdrs, fars, bars, qers, urrs, err := parseCreate(ies)
	if err != nil {
		c.log.Warn("session: cannot read the modification request", "seid", seid, "error", err)
		return modifyResponse(req, hdr, parseCause(err), nil)
	}
	removePDRs, removeFARs, removeBARs, removeURRs := parseRemovals(ies)

	// TS 29.244 5.3.2: a modification that carries FAR(s) with a new
	// downstream F-TEID and the SNDEM flag asks this UPF to construct and send
	// End Marker packets on the tunnels it is leaving. The old tunnels are
	// read out of the session before the merge folds the new ones in, and the
	// markers go out after the transaction lands -- TS 29.281 7.3.2.2: "after
	// sending the last G-PDU that needs to be sent on a GTP-U tunnel" -- and
	// before this request is answered.
	var leaving []far
	if c.cfg.EndMarker != "" && sndem(modificationFlags(req)) {
		leaving = s.leavingTunnels(fars)
	}

	// TS 29.244 8.2.31: DROBU asks this UPF to discard every packet the
	// session buffers, "prior to further applying the action specified in the
	// Apply Action value of the FARs". The flows are read out of the session
	// before the merge folds the new instruction in -- they are what is held
	// now, not what the request leaves buffering -- and are dropped once the
	// transaction has landed, the way a deletion's are (5.2.4.1 gives drop and
	// forward as the two ends of an instruction that stops buffering).
	var dropBuffered bool
	var buffered []uint32
	if drobu(modificationFlags(req)) {
		dropBuffered = true
		if c.BufferingConfigured() {
			c.mu.Lock()
			buffered = heldFlows(s)
			c.mu.Unlock()
		}
	}

	// merge takes the lock itself.
	if err := c.merge(s, pdrs, fars, bars, qers, urrs, removePDRs, removeFARs, removeBARs, removeURRs); err != nil {
		c.log.Warn("session: cannot carry the modification request", "seid", seid, "error", err)
		return modifyResponse(req, hdr, compileCause(err), nil)
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
		return modifyResponse(req, hdr, compileCause(err), nil)
	}
	if err := c.ap.Apply(context.Background(), changes...); err != nil {
		c.log.Warn("session: the dataplane refused the modification", "seid", seid, "error", err)
		return modifyResponse(req, hdr, causeOf(err), nil)
	}
	// The flows this request took out of buffering, read before settle clears
	// the replaced and removed forms: the packets they hold are released once
	// the transaction has landed, so that they leave under the instruction this
	// very request wrote.
	var ending, discarded []uint32
	if c.BufferingConfigured() {
		c.mu.Lock()
		ending = endedFlows(s)
		discarded = removedFlows(s)
		c.mu.Unlock()
	}
	c.settle(s)

	// The switch has landed: the last G-PDU on each old tunnel preceded this
	// point in the graph's own order, so the marker is what 7.3.2.2 asks for.
	// A marker that cannot be sent is a warning and a count, never a refusal:
	// the SMF's modification did take effect, and answering a failure would
	// make it re-apply a change that is already in force.
	//
	// A replayed journal sends none (c.restoring): those handovers happened in
	// an earlier run, and the TEID they named may since have been handed to
	// another subscriber -- a marker toward a context that now exists would
	// tell that peer a stream it is carrying has ended.
	if !c.restoring {
		for _, tunnel := range leaving {
			frame := endMarkerFrame(tunnel.teid, tunnel.peer, c.cfg.N3Addr, c.cfg.N3MAC, c.cfg.PeerMAC)
			if err := c.sendEndMarker(frame); err != nil {
				c.stats.markerFailures.Add(1)
				c.log.Warn("session: an end marker was not sent", "seid", seid, "teid", tunnel.teid,
					"error", err)
				continue
			}
			c.stats.markers.Add(1)
		}
	}

	// The held packets go out now, for the same reason the end marker does: the
	// switch has landed. A replayed journal releases nothing -- the store's
	// contents died with the daemon that held them, and the flows it names may
	// since have been handed to another subscriber.
	if !c.restoring {
		if dropBuffered {
			// DROBU is the discard 8.2.31 asks for, and it covers the flows
			// this very request takes out of buffering too: the flag sends a
			// drop, so none of what was held is released.
			c.dropFlows(context.Background(), seid, buffered)
		} else {
			c.releaseFlows(context.Background(), seid, ending)
			// A PDR the request removed leaves nothing to forward to, so what
			// it held is dropped rather than released (5.2.4.1 gives the two
			// as the alternatives).
			c.dropFlows(context.Background(), seid, discarded)
		}
	}

	c.mu.Lock()
	for _, p := range pdrsInOrder(s) {
		if p.teid != 0 {
			c.byTEID[p.teid] = s
		}
	}
	c.mu.Unlock()

	c.log.Info("session: modified", "seid", seid, "pdrs", len(s.PDRs), "changes", len(changes))
	c.checkpoint(kindModify, s.LocalSEID, req)
	return modifyResponse(req, hdr, ie.CauseRequestAccepted, created)
}

// Delete implements n4.SessionHandler.
func (c *Compiler) Delete(req *message.SessionDeletionRequest) message.Message {
	resp := c.delete(req)
	switch answerCause(resp) {
	case ie.CauseRequestAccepted:
		c.stats.deleted.Add(1)
	case ie.CauseSessionContextNotFound:
		// A retransmitted deletion: the session is already gone, which is what
		// the SMF asked for, so it is neither a deletion nor a refusal.
	default:
		c.stats.refused.Add(1)
	}
	return resp
}

// delete is the deletion itself; Delete counts what it answered.
func (c *Compiler) delete(req *message.SessionDeletionRequest) message.Message {
	seid := req.SEID()
	c.mu.Lock()
	s := c.sessions[seid]
	c.mu.Unlock()
	hdr := seid
	if s != nil {
		hdr = s.CPSEID
	}
	if s == nil {
		// Already gone: the SMF gets the answer it wanted (a retransmitted
		// deletion must not be an error).
		return deleteResponse(req, hdr, ie.CauseSessionContextNotFound)
	}
	// The held packets go with the session: 5.2.4.1 has them "either dropped or
	// forwarded", and a session that no longer exists has no path to forward
	// them over. Read before remove erases the model.
	c.mu.Lock()
	held := heldFlows(s)
	c.mu.Unlock()
	if err := c.remove(context.Background(), s); err != nil {
		c.log.Warn("session: the dataplane refused the deletion", "seid", seid, "error", err)
		return deleteResponse(req, hdr, causeOf(err))
	}
	if !c.restoring {
		c.dropFlows(context.Background(), seid, held)
	}
	c.log.Info("session: deleted", "seid", seid)
	c.checkpoint(kindDelete, seid, req)
	return deleteResponse(req, hdr, ie.CauseRequestAccepted)
}

// mergeBars folds a message's Create BAR / Update BAR parameters into the
// session's BARs. The caller holds the lock.
//
// An Update BAR carries what changes (7.5.4.3's update form is how a Session
// Modification Request or a Session Report Response hands the SMF's next
// instruction over): the parameters it names replace the ones before. All-zero
// Duration is the deactivated code rather than a value -- 8.2.29's timer is
// stopped -- so it clears the override, and a Suggested Packet Count of zero
// does the same, since "hold no packets" is not an instruction anyone sends.
func mergeBars(s *Session, bars []barReq) {
	for _, b := range bars {
		entry := s.BARs[b.id]
		if entry == nil {
			entry = &bar{id: b.id}
			s.BARs[b.id] = entry
		}
		if b.hasDuration {
			if b.deactivated {
				entry.hasDuration = false
			} else {
				entry.hasDuration, entry.duration, entry.infinite = true, b.duration, b.infinite
			}
		}
		if b.hasCount {
			entry.hasCount, entry.count = b.count > 0, b.count
		}
	}
}

// merge folds a request's objects into the session's model.
func (c *Compiler) merge(s *Session, pdrs []pdrReq, fars []farReq, bars []barReq, qers []qerReq,
	urrs []urrReq, removePDRs []uint16, removeFARs []uint32, removeBARs []uint8,
	removeURRs []uint32) error {
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
		if q.hasQFI {
			// The QFI is optional in a QER (Gate Status is its one mandatory
			// IE), so an Update that leaves it out keeps the flow the session
			// holds: a QER that stopped naming its flow would quietly stop
			// marking the packets of it.
			entry.hasQFI, entry.qfi = true, q.qfi
		}
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
			// A Create FAR: every field the message carries is the record's.
			entry = &far{id: f.id, apply: f.apply, destIfc: f.destIfc, instance: f.instance}
			s.FARs[f.id] = entry
		} else {
			// An Update FAR carries what changes (7.5.4.3): a field the message
			// leaves out keeps the value the session has. The zero values are
			// not neutral here -- no Apply Action stops the forward,
			// destination interface 0 is the access side, which would send an
			// uplink forward back out of N3, and an empty instance falls back
			// to the PDI's -- so each of the three is merged only where the
			// message named it.
			if f.hasApply {
				entry.apply = f.apply
			}
			if f.hasDestIfc {
				entry.destIfc = f.destIfc
			}
			if f.hasInstance {
				entry.instance = f.instance
			}
		}
		if f.hasOuter {
			entry.teid, entry.peer, entry.hasOuter = f.teid, f.peer, true
		}
		if f.hasBAR {
			entry.hasBAR, entry.barID = true, f.barID
		}
		if f.hasMarking {
			// The Transport Level Marking (8.2.42) merges like the instance: an
			// Update FAR that names none keeps the value the session has.
			entry.hasMarking, entry.marking = true, f.marking
		}
	}
	mergeBars(s, bars)
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
		if u.hasLinked {
			// The Linked URR IDs the update named replace the set; the links
			// themselves are checked once the whole message is folded in.
			entry.linked = u.linked
		}
		if u.hasVolQuota || u.hasTimeQuota || u.hasVolThreshold || u.hasTimeTh {
			// A new quota (or threshold) is the SMF granting more usage: the
			// drop a quota exhaustion put on this URR's PDRs is lifted, and the
			// next evaluation puts it back if the new limit is already reached.
			// This is the one place a provisioned quota re-opens the traffic
			// short of the session being deleted: a re-provisioned quota is not
			// spent by the traffic the old one paid for.
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
		if urrLinkedByAnotherURR(s, id) {
			// Another URR of the session still links to this one (8.2.55):
			// removing it would leave that link dangling and the group's report
			// short a URR. The SMF updates the linking URR first, the way it
			// disassociates a PDR before removing the URR the PDR names.
			return fmt.Errorf("%w: the URR %d is still linked by another URR of the session",
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
	for _, id := range removeBARs {
		for _, f := range s.FARs {
			if f.hasBAR && f.barID == id {
				// The FAR still asks to buffer under a BAR the SMF has taken
				// away: the instruction is gone, so the association is dropped
				// rather than left dangling -- resolve writes the flow with the
				// store's own defaults, and the parameters the CP function
				// removes stop being applied, which is what 5.2.4.1 says
				// happens when the numbers end.
				f.hasBAR, f.barID = false, 0
			}
		}
		delete(s.BARs, id)
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
			instance: p.instance, hasQFI: p.hasQFI, qfi: p.qfi,
		}
		if old != nil {
			// An update keeps the dataplane identity: the rule that already
			// selects this PDR keeps its action id, so a worker switching
			// between old and new state never sees a dangling reference.
			pdr.actionID = old.actionID
			pdr.teid = old.teid
			pdr.meterID = old.meterID
			// A PDR that keeps buffering keeps its episode: the SMF is owed one
			// Downlink Data Report per episode ("the first buffered DL packet"),
			// not one per modification. The buffering state itself is carried
			// over too, so that resolve can see a transition -- a PDR the
			// message rebuilds would otherwise look like it never buffered, and
			// the release its instruction owes would be missed.
			pdr.ddnSent, pdr.buffer = old.ddnSent, old.buffer
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
	for _, uid := range urrIDsInOrder(s) {
		for _, lid := range s.URRs[uid].linked {
			if s.URRs[lid] == nil {
				// The link names a URR the session does not hold (the SMF
				// created or updated the URR with a Linked URR ID for something
				// it did not provision, or removed the target in the same
				// message): the group's report would name a URR nobody knows,
				// refused the way a PDR naming an unknown URR is.
				return fmt.Errorf(
					"%w: URR %d's Linked URR ID names URR %d, which the session does not hold",
					errNotExpressible, uid, lid)
			}
		}
	}
	for _, p := range pdrsInOrder(s) {
		far := s.FARs[p.farID]
		dir := c.direction(p.srcIfc)
		ifc, err := c.interfaceFor(p)
		if err != nil {
			return err
		}
		p.domain = ifc.Domain
		p.nextHop = dir.NextHop
		if c.cfg.Instances != nil && far != nil && far.destIfc != ie.DstInterfaceAccess {
			// A forward toward the data network leaves by the instance's own
			// next hop -- the deployment's N6, or the peer UPF an N9 instance
			// names -- rather than by the direction's. The access side is the
			// exception: a forward toward the UE leaves through the encap, and
			// that is the direction's hop whatever instance was named.
			egress := ifc
			if far.instance != "" {
				// The FAR's own Network Instance (8.2.4) is where the traffic
				// leaves by, and it need not be the one the PDI selected: an
				// uplink rule can select a flow in one instance and send it out
				// of N9 toward another.
				found, ok := c.cfg.Instances.Lookup(far.instance)
				if !ok {
					return fmt.Errorf(
						"%w: the FAR's forwarding parameters name the network instance %q, and this deployment serves %s",
						errNotExpressible, far.instance, strings.Join(c.cfg.Instances.Names(), ", "))
				}
				egress = found
			}
			p.nextHop = egress.NextHop
		}
		// A FAR that asks for buffering and not for forwarding (Apply Action
		// BUFF, 8.2.26) is the idle-UE downlink case: the packets are held and
		// the SMF is told they arrived. Where the deployment has a store
		// (Config.Buffering), the rule delivers them on that branch; where it
		// has none, they are dropped, because delivering traffic the SMF asked
		// to hold would be worse than dropping it (docs/compliance.md's row
		// over 7.5.2.6).
		wasBuffering := p.buffer
		// Buffering is the downlink's: a BAR is the instruction for downlink data
		// (5.2.4.1), and only the downlink chain has the branch. A BUFF-only FAR
		// on an uplink PDR -- which no SMF should send -- keeps the drop it had,
		// rather than gating to a branch that is not in its chain.
		p.buffer = c.cfg.Buffering != nil && far != nil && p.srcIfc != ie.SrcInterfaceAccess &&
			far.apply&applyForw == 0 && far.apply&applyBuff != 0
		p.drop = far == nil || (far.apply&applyForw == 0 && !p.buffer)
		if !p.buffer {
			// The episode is over: this PDR no longer holds packets, so a later
			// BUFF is a new one and owes its own first-packet report (5.2.4.1),
			// and what the flow held is released once the transaction that
			// ended it has landed (5.2.4.1's "stop applying buffering when new
			// instruction is received").
			p.ddnSent = false
			if wasBuffering && p.actionID != 0 {
				s.ending = append(s.ending, p.actionID)
			}
		}
		if p.buffer && far.hasBAR && s.BARs[far.barID] == nil {
			// The FAR names a BAR the session does not hold. 5.2.4.1 makes the
			// BAR the CP function's instruction ("the CP function needs to
			// provision a (possibly empty) BAR and associate it to the FARs"),
			// so buffering under numbers nobody sent is a guess -- refused the
			// way a PDR naming a URR the session does not have is.
			return fmt.Errorf("%w: PDR %d's FAR names BAR %d, which the session does not hold",
				errNotExpressible, p.id, far.barID)
		}
		p.meterID = 0
		p.tunnels = nil
		p.encapQFI = 0
		for _, qid := range p.qerIDs {
			entry := s.QERs[qid]
			if entry == nil {
				continue
			}
			if p.srcIfc == ie.SrcInterfaceAccess {
				if entry.gateUL == ie.GateStatusClosed {
					// A closed gate is an instruction to stop, not to hold: it
					// outranks the FAR's BUFF for this PDR.
					p.drop, p.buffer = true, false
				}
				if entry.hasRate {
					p.meterID = entry.meterUL
				}
			} else {
				if entry.gateDL == ie.GateStatusClosed {
					p.drop, p.buffer = true, false
				}
				if entry.hasRate {
					p.meterID = entry.meterDL
				}
				if entry.hasQFI {
					// The QER's QFI (8.2.89) is the flow the gNB reads out of
					// the PDU Session Container of a downlink packet: it goes
					// into the tunnel record the FAR's outer header creation
					// writes, so the encap marks every packet of this flow
					// with the id the SMF programmed (the last QER that names
					// one, as the meter is the last that polices).
					p.encapQFI = entry.qfi
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
		if c.cfg.Instances != nil && p.ueIP.IsValid() && !ifc.Serves(p.ueIP) {
			// The deployment says what each interface serves: an address
			// outside its pool is a session this UPF places nowhere, and
			// answering a success would leave the SMF believing in a path no
			// packet takes (docs/design.md: "the UPF maps it to an interface
			// and an address pool").
			return fmt.Errorf("%w: PDR %d's address %s is outside the pool of the network instance %q",
				errNotExpressible, p.id, p.ueIP, ifc.Instance)
		}
	}
	return nil
}

// interfaceFor resolves a PDR's PDI to the deployment's interface: the network
// instance the SMF named (TS 29.244 8.2.4), or the deployment's default when it
// named none. A name the deployment does not configure is a rule it cannot
// place -- before this was read, a PDI naming another instance was
// indistinguishable from one naming ours (docs/compliance.md's row over
// 8.2.89/8.2.4).
func (c *Compiler) interfaceFor(p *pdr) (routing.Interface, error) {
	if c.cfg.Instances == nil {
		// The one-instance deployment: every rule is domain 0, and each
		// forward takes the direction's own next hop.
		return routing.Interface{}, nil
	}
	ifc := c.cfg.Instances.Default()
	if p.instance != "" {
		found, ok := c.cfg.Instances.Lookup(p.instance)
		if !ok {
			return routing.Interface{}, fmt.Errorf(
				"%w: the PDI names the network instance %q, and this deployment serves %s",
				errNotExpressible, p.instance, strings.Join(c.cfg.Instances.Names(), ", "))
		}
		ifc = found
	}
	return ifc, nil
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

// urrLinkedByAnotherURR reports whether another URR of the session links to
// this one (8.2.55). Removing a URR a live link still names would leave that
// link dangling, and the group's report would be missing the URR the SMF asked
// to hear about with it.
func urrLinkedByAnotherURR(s *Session, id uint32) bool {
	for uid, u := range s.URRs {
		if uid == id {
			continue
		}
		for _, lid := range u.linked {
			if lid == id {
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

// bufferCountersRes is the BUFF branch's counting module's counter resource.
func bufferCountersRes(b *Buffering) string { return b.Counter + "/counters" }

// flowRes is the store's per-flow resource: what the SMF's BAR asks this flow to
// hold (8.2.29's duration and 8.2.30's count), keyed by the rule's ActionId.
func flowsRes(b *Buffering) string { return b.Store + "/flows" }

// writeBufferCounter writes the counting module's entry for a PDR that buffers.
// The module sits on the BUFF branch, in front of the store, so its counters are
// what makes "the first buffered DL packet for this PDR" visible to the
// reporting side (TS 29.244 5.2.4.1) -- the direction's URR counter is a
// different instance, and a buffered packet leaves the chain at the rule's gate
// without ever reaching it.
func writeBufferCounter(b *Buffering, p *pdr) []bess.Change {
	if b == nil || b.Counter == "" || p.actionID == 0 {
		return nil
	}
	return []bess.Change{{
		Resource: bufferCountersRes(b),
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

	// The rule keys this compile is the first to claim, and whether it got as
	// far as writing them: a compile that returns an error wrote nothing (its
	// transaction never reached the dataplane), so those claims are given back
	// here rather than left refusing keys no session holds. Only the keys this
	// compile took from nobody are in the list: a key the session already held
	// has its rule in the dataplane, and giving that up would let another
	// session take a rule that is still selecting this one's packets. A
	// transaction the dataplane *refuses* is the caller's business, exactly as
	// an allocated id is: what may have committed stays claimed.
	claimed := make([]string, 0, len(s.PDRs))
	committed := false
	defer func() {
		if committed {
			return
		}
		for _, key := range claimed {
			delete(c.rules, key)
			s.forgetRuleKey(key)
		}
	}()

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
	// action. An SMF that programs several uplink PDRs onto one F-TEID with no
	// SDF tells them apart by their QFIs, and the uplink table carries the QFI
	// in its key: those are two rules, and the SMF's own precedences decide
	// which serves a packet both match (the priority written below is the
	// PDR's precedence, doctored by nothing). What reaches this is the rest of
	// that case -- two PDRs with the same filter *and* the same QFI, or a
	// deployment whose uplink table declares no qfi field, the PDI's QFI then
	// being no part of the key -- and the session is refused with a rule
	// failure rather than half-programmed.
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
	//   - the TEID rule only when no PDR of the session still shares the F-TEID;
	//   - the claim on an erased rule key goes in settle, not here: this is a
	//     transaction that may still be refused, and a claim dropped while it is
	//     being built would let another session write over the rule this one's
	//     retry then erases.
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
	// liveBufferCounters is the same set for the BUFF branch's counter: a PDR
	// that buffers is counted by the module in front of the store, and an entry
	// a live PDR still needs must not be erased in the transaction that writes
	// it.
	liveBufferCounters := map[string]bool{}
	if c.cfg.Buffering != nil && c.cfg.Buffering.Counter != "" {
		for _, p := range s.PDRs {
			if p.buffer && p.actionID != 0 {
				liveBufferCounters[bufferCountersRes(c.cfg.Buffering)+"\x00"+
					strconv.FormatUint(uint64(p.actionID), 10)] = true
			}
		}
	}
	// bufferCounterErase takes the BUFF branch's counter entry out for a PDR
	// that is going away or that no longer buffers: the entry is what makes the
	// rule's arrivals visible, and a rule that no longer holds packets has
	// nothing to report.
	bufferCounterErase := func(p *pdr) {
		if !p.buffer || p.actionID == 0 || c.cfg.Buffering == nil || c.cfg.Buffering.Counter == "" {
			return
		}
		if liveBufferCounters[bufferCountersRes(c.cfg.Buffering)+"\x00"+
			strconv.FormatUint(uint64(p.actionID), 10)] {
			return
		}
		erase(bess.Change{Resource: bufferCountersRes(c.cfg.Buffering),
			Key: map[string]any{"action_id": p.actionID}})
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
		bufferCounterErase(p)
	}
	// A PDR a modification replaced keeps its action and its tunnel, but its
	// rule key can change under it (a new filter, a new address): the old key
	// would go on selecting that action for packets the PDR no longer describes.
	// It is erased unless the same transaction writes it, which is the update
	// that changed nothing about the key -- and the reason this cannot collide
	// with a write (the engine rejects two operations on one key).
	// The flows whose episode this model ended (resolve), which a FAR-only
	// modification leaves out of removed/stale entirely: their counter entry is
	// what said "arrivals are news", and a flow that no longer holds anything
	// must not go on being read.
	for _, id := range s.ending {
		if liveBufferCounters[bufferCountersRes(c.cfg.Buffering)+"\x00"+
			strconv.FormatUint(uint64(id), 10)] {
			continue
		}
		if c.BufferingConfigured() && id != 0 {
			erase(bess.Change{Resource: bufferCountersRes(c.cfg.Buffering),
				Key: map[string]any{"action_id": id}})
		}
	}
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
		bufferCounterErase(old)
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
			// second PDR silently has no rule of its own -- and the message
			// names the two shapes that reach it, because the fix differs: an
			// SMF that sent two identical PDRs, or a deployment whose uplink
			// table carries no qfi field (see the note above).
			return nil, nil, fmt.Errorf(
				"%w: two PDRs compile to one rule key (the same filter and the same QFI, or a graph whose uplink table declares no qfi field)",
				errNotExpressible)
		}
		writtenRules[rkey] = true
		if owner, taken := c.rules[rkey]; taken && owner != s.LocalSEID {
			// Another session holds this rule. Writing it would take that
			// session's packets -- and, when this one went, erase the rule the
			// other still holds -- so the SMF is told the rule failed rather
			// than served a session that quietly shares another's. A graph
			// whose key carries the tunnel or the domain does not collide here
			// for sessions that share a UE address; one that classifies by the
			// tuple alone does, and this is where it says so.
			return nil, nil, fmt.Errorf("%w: the rule is session %d's", errNotExpressible, owner)
		}
		if _, held := c.rules[rkey]; !held {
			// This compile is the first to claim the key for the session. A key
			// the session already holds stays this session's even if a later
			// step of this compile fails: its rule is in the dataplane.
			claimed = append(claimed, rkey)
			if !s.holdsRuleKey(rkey) {
				s.ruleKeys = append(s.ruleKeys, rkey)
			}
		}
		c.rules[rkey] = s.LocalSEID
		if p.drop || p.buffer {
			// A drop needs no action record: the rule's gate is the whole
			// result, and the packet path pays for nothing else. The PDR may
			// hold an action id from the form being replaced (a modification
			// that closed a gate or stopped forwarding); the rule written here
			// names none, so that record is what the PDR no longer uses -- kept
			// in the model, and erased when the PDR is (a PDR that stops
			// forwarding and starts again keeps its identity, docs/design.md).
			gate, action := uint64(dropGate), uint32(0)
			if p.buffer {
				// A buffering rule does carry an ActionId: it is the flow's key
				// in the store and in the counter in front of it -- the store is
				// keyed by the same value the classifier wrote (BESS D-141), so
				// one id resolves the rule, its flow and, once the SMF has said
				// what to do with the packets, its action. The record is written
				// here even though this rule does not read it while it buffers:
				// the engine validates a rule's action_id as a *reference*
				// whatever gate the rule takes (D-021, transaction_engine.cc's
				// reference check, on the transaction's end state), so a rule
				// naming an id nothing upserts is refused and the session is
				// lost -- which is exactly what the live arm found. It is also
				// the record the release path reads: the store's gate 0
				// re-enters the action path, and the modification that stops
				// buffering updates this same key in place.
				gate = uint64(c.cfg.Buffering.Gate)
				if p.actionID == 0 {
					id, err := c.actions.alloc()
					if err != nil {
						return nil, nil, fmt.Errorf("allocating an action for PDR %d: %w", p.id, err)
					}
					p.actionID = id
				}
				action = p.actionID
				// The record is written here, after the id exists, because the
				// engine validates a rule's action_id as a *reference* whatever
				// gate the rule takes (D-021, transaction_engine.cc's reference
				// check on the transaction's end state): a rule naming an id
				// nothing upserts is refused and the session is lost, which is
				// what the live arm found. It is also the record the release
				// path reads -- the store's gate 0 re-enters the action path --
				// and the modification that stops buffering updates this same
				// key in place.
				changes = append(changes, bess.Change{
					Resource: actionsRes(dir),
					Key:      map[string]any{"id": p.actionID},
					Value:    map[string]any{"meter_id": p.meterID, "next_hop_id": p.nextHop},
				})
			}
			changes = append(changes, bess.Change{
				Resource: rulesRes(dir),
				Key:      key,
				Value: map[string]any{
					"priority":  rulePriority(p.precedence),
					"gate":      gate,
					"action_id": action,
				},
			})
			// A URR that measures this PDR still holds its counter entry: the
			// entry says the rule is measured (the reporting side reads it), and
			// its existence must follow the PDR rather than the rule's effect,
			// so that a later erase has something to erase. The counter counts
			// nothing while the rule drops: no packet reaches the action.
			changes = append(changes, writeCounter(p, dir)...)
			if p.buffer {
				changes = append(changes, writeBufferCounter(c.cfg.Buffering, p)...)
			}
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
			Value:    map[string]any{"meter_id": p.meterID, "next_hop_id": p.nextHop},
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
			value := map[string]any{
				"teid":      far.teid,
				"gnb_ip":    far.peer.String(),
				"ether_src": c.cfg.N3MAC[:],
				"ether_dst": c.cfg.PeerMAC[:],
			}
			if p.encapQFI != 0 {
				// The QER's QFI (8.2.89): the QoS flow the encap writes into
				// the PDU Session Container of every packet it tunnels, which
				// is the flow the gNB schedules the packet on. Written only
				// where the SMF's QER named one -- 0 is not a QFI, so a record
				// without the field says the session has no flow of its own.
				value["qfi"] = uint32(p.encapQFI)
			}
			if far.hasMarking {
				// The FAR's Transport Level Marking (8.2.42): the ToS/Traffic
				// Class the SMF asked this session's outer IPv4 headers to
				// carry -- the DSCP in the high octet, the mask in the low one
				// -- which the encap applies over the inner packet's own class
				// (the mask keeps the bits it names, the ECN bits with the
				// spec's 0xFC). Written only where the SMF named one: without
				// the field the encap copies the inner TOS, the behaviour the
				// session had before this field existed.
				value["marking"] = uint32(far.marking)
			}
			changes = append(changes, bess.Change{
				Resource: resource,
				Key:      map[string]any{"action_id": p.actionID},
				Value:    value,
			})
		}

		changes = append(changes, bess.Change{
			Resource: rulesRes(dir),
			Key:      key,
			Value: map[string]any{
				// The table's own output gate: one chain per direction.
				//
				// The priority is the PDR's Precedence (8.2.11) inverted into
				// the classifier's own ordering (rulePriority), QFI or not: a
				// session's general rule (the QFI field masked out) and its
				// flow's rule (the field required) both match a packet of that
				// flow, and which PDR serves it stays the SMF's decision --
				// the more specific rule is not raised above the one the SMF
				// gave the higher Precedence.
				"priority":  rulePriority(p.precedence),
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
						"priority": rulePriority(p.precedence),
						"gate":     uint64(c.cfg.TEIDGate),
					},
				})
			}
			created = append(created, ie.NewCreatedPDR(
				ie.NewPDRID(p.id),
				createdFTEID(p.teid, c.cfg.N3Addr)))
		}
	}
	committed = true
	return changes, created, nil
}

// rulePriority is the classifier's priority for a PDR's Precedence (TS 29.244
// 8.2.11): the two orderings are opposite. The spec has the *lower* Precedence
// value win -- "the lower precedence values indicate higher precedence of the
// PDR, and the higher precedence values indicate lower precedence of the PDR
// when matching a packet" -- while WildcardMatch applies the rule with the
// *higher* priority ("If a packet matches multiple rules, the rule with higher
// priority will be applied", module_msg.proto:347). The Precedence is therefore
// inverted into the classifier's space, and it is inverted here, in one place,
// because every rule the deployment programs carries the value: a session's PDR
// rules and the TEID rule in front of the decap alike. Precedence 0, the
// highest there is, takes the classifier's largest priority, and distinct
// Precedences stay distinct priorities -- in the opposite direction, which is
// the SMF's.
func rulePriority(precedence uint32) int64 {
	return math.MaxUint32 - int64(precedence)
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
	case QFI:
		// The PDI's QFI (8.2.89), as the decap wrote it into the packet's
		// `qfi` attribute. A PDI that names none leaves the field open: the
		// rule selects the flow by its address and filter alone, and keeps
		// matching where a later PDR of the session names a QFI -- which is
		// what the masked-out byte says (its value is 0, the canonical form
		// under a zero mask).
		if p.hasQFI {
			return match{value: []byte{p.qfi}, mask: ones(1)}, true, nil
		}
		return match{}, false, nil
	case RouteDomain:
		// The interface the PDI's network instance resolved to (resolve): the
		// domain the deployment's interface writes into the packet that arrives
		// on it, so a rule placed in one instance never selects another's
		// packets -- which is what lets two instances serve the same subscriber
		// prefix.
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, p.domain)
		return match{value: b, mask: ones(4)}, true, nil
	case UpfTEID:
		if p.teid == 0 {
			// The table declares the tunnel as part of the key and the PDI
			// names none: a rule keyed on TEID 0 would be claimed by every
			// session that has no tunnel of its own.
			return match{}, false, fmt.Errorf("%w: the PDI names no F-TEID, so the rule has no tunnel to select by",
				errNotExpressible)
		}
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, p.teid)
		return match{value: b, mask: ones(4)}, true, nil
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
		[]*ie.IE{req.NodeID, req.CPFSEID, req.CreateBAR},
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
		[]*ie.IE{req.CreateBAR, req.UpdateBAR, req.RemoveBAR},
		req.RemovePDR, req.RemoveFAR, req.RemoveQER, req.RemoveURR,
	)
}

// modificationFlags is where a Session Modification Request's per-message
// flags can sit: the message's own PFCPSMReq-Flags IE and the FARs the message
// carries, whose forwarding parameters may hold one instead (TS 29.244 5.3.2
// and 8.2.31 both appear in the field).
func modificationFlags(req *message.SessionModificationRequest) []*ie.IE {
	ies := make([]*ie.IE, 0, 1+len(req.CreateFAR)+len(req.UpdateFAR))
	ies = append(ies, req.PFCPSMReqFlags)
	ies = append(ies, req.CreateFAR...)
	ies = append(ies, req.UpdateFAR...)
	return ies
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
func parseCreate(ies []*ie.IE) ([]pdrReq, []farReq, []barReq, []qerReq, []urrReq, error) {
	var pdrs []pdrReq
	var fars []farReq
	var bars []barReq
	var qers []qerReq
	var urrs []urrReq
	for _, i := range ies {
		switch i.Type {
		case ie.CreatePDR, ie.UpdatePDR:
			p, err := parsePDR(i)
			if err != nil {
				return nil, nil, nil, nil, nil, err
			}
			pdrs = append(pdrs, p)
		case ie.CreateFAR, ie.UpdateFAR:
			f, err := parseFAR(i)
			if err != nil {
				return nil, nil, nil, nil, nil, err
			}
			fars = append(fars, f)
		case ie.CreateBAR, ie.UpdateBARWithinSessionModificationRequest,
			ie.UpdateBARWithinSessionReportResponse:
			b, err := parseBAR(i)
			if err != nil {
				return nil, nil, nil, nil, nil, err
			}
			bars = append(bars, b)
		case ie.CreateQER, ie.UpdateQER:
			q, err := parseQER(i)
			if err != nil {
				return nil, nil, nil, nil, nil, err
			}
			qers = append(qers, q)
		case ie.CreateURR, ie.UpdateURR:
			u, err := parseURR(i)
			if err != nil {
				return nil, nil, nil, nil, nil, err
			}
			urrs = append(urrs, u)
		}
	}
	return pdrs, fars, bars, qers, urrs, nil
}

// parseRemovals reads the PDR, FAR, BAR and URR ids a modification removes.
func parseRemovals(ies []*ie.IE) ([]uint16, []uint32, []uint8, []uint32) {
	var pdrs []uint16
	var fars []uint32
	var bars []uint8
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
		case ie.RemoveBAR:
			children, err := i.RemoveBAR()
			if err != nil {
				continue
			}
			for _, c := range children {
				if c.Type != ie.BARID {
					continue
				}
				if id, err := c.BARID(); err == nil {
					bars = append(bars, id)
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
	return pdrs, fars, bars, urrs
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

// qfiIE reads a QFI IE (TS 29.244 8.2.89): the six-bit QoS Flow Identifier a
// PDI or a QER names, one of 1..63. 0 is not a QFI, and the IE's spare bits
// make any byte above 63 a flow no packet carries -- a rule keyed on one would
// match nothing at all, and the session would stand while its uplink
// blackholed -- so both are refused with the cause the SMF can fix rather than
// carried into a key.
func qfiIE(c *ie.IE, what string) (uint8, error) {
	v, err := c.QFI()
	if err != nil {
		return 0, fmt.Errorf("QFI: %w", err)
	}
	if v == 0 || v > 63 {
		return 0, fmt.Errorf("%w: %s QFI is %d, and a QFI is one of 1..63 (8.2.89)",
			errNotExpressible, what, v)
	}
	return v, nil
}

func parsePDI(p *pdrReq, children []*ie.IE) error {
	for _, c := range children {
		switch c.Type {
		case ie.SourceInterface:
			if v, err := c.SourceInterface(); err == nil {
				p.srcIfc = v
			}
		case ie.NetworkInstance:
			// The PDI's Network Instance (TS 29.244 8.2.4), read here and
			// resolved in resolve: the deployment maps the name to an
			// interface, its route domain and its pool. A name the deployment
			// does not configure is refused there rather than served by the
			// wrong interface -- with one instance configured, a rule naming
			// another used to be indistinguishable from one naming ours.
			p.instance = networkInstanceName(c.Payload)
		case ie.QFI:
			// The PDI's QFI (TS 29.244 8.2.89): the QoS flow this rule
			// selects. It goes into the uplink table's key (matchValue), so
			// the SMF's several uplink PDRs for one F-TEID -- the session's
			// general rule and one per QoS flow -- are several rules.
			qfi, err := qfiIE(c, "the PDI's")
			if err != nil {
				return err
			}
			p.hasQFI, p.qfi = true, qfi
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

// networkInstanceName is the Network Instance IE's value (TS 29.244 8.2.4).
// The IE carries an OctetString, and an SMF may write the name in either of
// the clause's forms: its own bytes, or the DNS-label form where every label is
// a length octet followed by its bytes (open5gs writes its DNN APN-style, so
// "internet" arrives as 0x08 followed by the letters). Reading only the raw
// bytes would turn every session from such an SMF into a refusal naming an
// instance nobody configured, and the library's own heuristic would cut a plain
// name at whatever its first byte happens to be, so the label form is used only
// when its labels are exactly the payload: a plain name is read whole unless
// its bytes happen to parse as labels ("5gc" is a name -- its first byte would
// announce a 53-byte label and only two bytes follow -- so the parse fails and
// the bytes are taken as they are). A trailing zero octet is the root label,
// which some stacks write, and it is not part of the name.
func networkInstanceName(payload []byte) string {
	b := payload
	if n := len(b); n > 0 && b[n-1] == 0 {
		b = b[:n-1]
	}
	if name, ok := decodeDNSLabels(b); ok {
		return name
	}
	return string(b)
}

// decodeDNSLabels reads the length-prefixed labels of a DNS name and reports
// whether they are the given bytes exactly: a partial read is not a name, and
// this is what keeps the label form from being guessed at.
func decodeDNSLabels(b []byte) (string, bool) {
	var labels []string
	for i := 0; i < len(b); {
		n := int(b[i])
		if n == 0 || n > 63 || i+1+n > len(b) {
			return "", false
		}
		labels = append(labels, string(b[i+1:i+1+n]))
		i += 1 + n
	}
	if len(labels) == 0 {
		return "", false
	}
	return strings.Join(labels, "."), true
}

// parseBAR reads a Create BAR or an Update BAR (TS 29.244 7.5.2.6): the BAR ID
// and the two parameters this UP function can honour. The BAR is what a
// buffering FAR's packets live under, so a value that is not a duration and not
// a count is refused the way every other unplaceable value is -- the SMF is
// told the rule failed rather than getting buffering it did not ask for.
func parseBAR(i *ie.IE) (barReq, error) {
	children, err := i.CreateBAR()
	what := "Create BAR"
	if i.Type == ie.UpdateBARWithinSessionModificationRequest ||
		i.Type == ie.UpdateBARWithinSessionReportResponse {
		children, err = i.UpdateBAR()
		what = "Update BAR"
	}
	if err != nil {
		return barReq{}, fmt.Errorf("%s: %w", what, err)
	}
	b := barReq{}
	for _, c := range children {
		switch c.Type {
		case ie.BARID:
			if id, err := c.BARID(); err == nil {
				b.id = id
			}
		case ie.DLBufferingDuration:
			d, err := c.DLBufferingDuration()
			if err != nil {
				return barReq{}, fmt.Errorf("DL Buffering Duration: %w", err)
			}
			b.hasDuration = true
			switch {
			case d == 0:
				// The timer is stopped (8.2.29: unit and value both zero): no
				// duration is instructed, so this clears the session's override
				// instead of holding packets for zero seconds.
				b.deactivated = true
			case d == time.Duration(math.MaxInt64):
				b.infinite = true
			default:
				b.duration = d
			}
		case ie.DLBufferingSuggestedPacketCount:
			n, err := c.DLBufferingSuggestedPacketCount()
			if err != nil {
				return barReq{}, fmt.Errorf("DL Buffering Suggested Packet Count: %w", err)
			}
			b.hasCount, b.count = true, uint32(n)
		}
	}
	if b.id == 0 {
		return barReq{}, errors.New("BAR without a BAR ID")
	}
	return b, nil
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
			f.hasApply = true
			if len(flags) > 0 {
				f.apply = flags[0]
			}
		case ie.ForwardingParameters:
			fwd, err := c.ForwardingParameters()
			if err != nil {
				return farReq{}, fmt.Errorf("Forwarding Parameters: %w", err)
			}
			if err := parseForwardingParameters(&f, fwd); err != nil {
				return farReq{}, err
			}
		case ie.BARID:
			// The FAR's BAR ID (8.2.55): what this FAR's buffered packets are
			// held under. resolve refuses a reference the session cannot
			// resolve, the way it refuses a PDR naming an unprovisioned URR.
			if id, err := c.BARID(); err == nil {
				f.hasBAR, f.barID = true, id
			}
		case ie.UpdateForwardingParameters:
			// An Update FAR carries the same fields in the update form (7.5.4.3
			// and 7.5.4.4): without this case the message's destination
			// interface and network instance would be read as absent, and a
			// merge that overwrote them with the zero values would move the
			// forward -- 0 is the access side.
			fwd, err := c.UpdateForwardingParameters()
			if err != nil {
				return farReq{}, fmt.Errorf("Update Forwarding Parameters: %w", err)
			}
			if err := parseForwardingParameters(&f, fwd); err != nil {
				return farReq{}, err
			}
		}
	}
	if f.id == 0 {
		return farReq{}, errors.New("FAR without a FAR ID")
	}
	return f, nil
}

// parseForwardingParameters reads the forwarding parameters of a Create FAR or
// an Update FAR: where the forward goes, the instance it goes by, the outer
// header creation of the tunnel it leaves through, and the Transport Level
// Marking the outer headers of that tunnel carry.
func parseForwardingParameters(f *farReq, fwd []*ie.IE) error {
	for _, fp := range fwd {
		switch fp.Type {
		case ie.DestinationInterface:
			if v, err := fp.DestinationInterface(); err == nil {
				f.destIfc, f.hasDestIfc = v, true
			}
		case ie.NetworkInstance:
			// The forward's own Network Instance (TS 29.244 8.2.4 inside the
			// Forwarding Parameters): the instance the traffic leaves by, which
			// is what N9's peer UPF is named with. A PDI's instance says where
			// the flow came from; this one says where it goes, and an SMF may
			// name either or both.
			f.instance, f.hasInstance = networkInstanceName(fp.Payload), true
		case ie.OuterHeaderCreation:
			fields, err := fp.OuterHeaderCreation()
			if err != nil {
				return fmt.Errorf("Outer Header Creation: %w", err)
			}
			if fields.TEID == 0 {
				return errors.New("Outer Header Creation without a TEID")
			}
			peer, ok := netip.AddrFromSlice(fields.IPv4Address)
			if !ok {
				return errors.New("Outer Header Creation without an IPv4 address")
			}
			f.hasOuter, f.teid, f.peer = true, fields.TEID, peer.Unmap()
		case ie.TransportLevelMarking:
			// The FAR's Transport Level Marking (8.2.42): the SMF asking this
			// FAR's outer headers to bear a ToS/Traffic Class of its choosing
			// rather than the inner packet's. The IE is the two octets as an
			// OctetString -- the DSCP in the first, the mask in the second --
			// which is the uint16 the library reads, and whose mask says which
			// bits of the inner packet's own class survive the marking.
			marking, err := fp.TransportLevelMarking()
			if err != nil {
				return fmt.Errorf("Transport Level Marking: %w", err)
			}
			f.hasMarking, f.marking = true, marking
		}
	}
	return nil
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
		case ie.LinkedURRID:
			// The URR this one reports with (8.2.55). The IE may repeat: a URR
			// may link to more than one other. Whether the link names a URR the
			// session holds is checked once the whole message is folded in
			// (resolve), because the target may be created in the same message.
			id, err := c.LinkedURRID()
			if err != nil {
				return urrReq{}, fmt.Errorf("Linked URR ID: %w", err)
			}
			u.hasLinked = true
			u.linked = append(u.linked, id)
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
		case ie.QFI:
			// The QER's QFI (TS 29.244 8.2.89): the QoS flow this QER
			// polices, and the one a downlink packet's PDU Session Container
			// must name. resolve carries it into the tunnel record the PDR's
			// FAR writes.
			qfi, err := qfiIE(c, "the QER's")
			if err != nil {
				return qerReq{}, err
			}
			q.hasQFI, q.qfi = true, qfi
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

// The three answers below carry the SEID the *SMF* knows the session by in the
// message header, and ours only in the F-SEID IE the establishment answer
// returns (TS 29.244 7.2.2.4.2: the header's SEID is the one the receiving node
// allocated -- for a message to the CP function that is its own F-SEID, which
// it sent in the request's F-SEID IE). An SMF looks a session up by that value,
// so answering under our own F-SEID is an answer to a session it does not have.
func establishResponse(req *message.SessionEstablishmentRequest, cpSEID, local uint64,
	cause uint8, created []*ie.IE) message.Message {
	ies := []*ie.IE{ie.NewCause(cause)}
	if cause == ie.CauseRequestAccepted {
		ies = append(ies, ie.NewFSEID(local, nil, nil))
		ies = append(ies, created...)
	}
	return message.NewSessionEstablishmentResponse(0, 0, cpSEID, req.Sequence(), 0, ies...)
}

// modifyResponse answers a modification; cpSEID is the session's CP F-SEID, or
// the SEID the request itself carried when there is no session any more (a
// Session Context Not Found has nowhere else to read it from).
func modifyResponse(req *message.SessionModificationRequest, cpSEID uint64,
	cause uint8, created []*ie.IE) message.Message {
	ies := []*ie.IE{ie.NewCause(cause)}
	if cause == ie.CauseRequestAccepted {
		ies = append(ies, created...)
	}
	return message.NewSessionModificationResponse(0, 0, cpSEID, req.Sequence(), 0, ies...)
}

// deleteResponse answers a deletion, with the same rule for its SEID.
func deleteResponse(req *message.SessionDeletionRequest, cpSEID uint64, cause uint8) message.Message {
	return message.NewSessionDeletionResponse(0, 0, cpSEID, req.Sequence(), 0,
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
