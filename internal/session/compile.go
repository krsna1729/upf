// SPDX-License-Identifier: BSD-3-Clause

// The PFCP side of the session layer: reading a session message into the
// model below, resolving it into dataplane resources, and answering.
//
// The graph's rule shapes come from `deploy/upf.yaml`: `WildcardMatch` rules
// carry `{priority, gate, result}`; `result_fields` write the ActionId, meter
// IDs and next hop into metadata. One `Meter` handles each direction; session
// changes also write tunnel records and endpoint-scoped F-TEID admission keys.

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
	"google.golang.org/grpc/codes"

	"github.com/krsna1729/upf/internal/bess"
	"github.com/krsna1729/upf/internal/routing"
)

// The Apply Action flags a FAR can carry (TS 29.244 8.2.26, octet 5).
const (
	applyDrop = 0x01
	applyForw = 0x02
	applyBuff = 0x04
	// applyNOCP is "Notify CP function when the first downlink packet is
	// buffered": BUFF without it is an instruction to hold the packets and say
	// nothing, so the report is owed only when the SMF asked for it.
	applyNOCP = 0x08
	// applyDUPL is "Duplicate" (8.2.26 bit 5): the FAR names a second
	// forwarding FAR and every packet goes out both. No chain here branches a
	// packet to two actions, so the instruction cannot be honoured.
	applyDUPL = 0x10
)

// The bytes a rule whose FAR drops leaves on.
const dropGate = 8192 // DROP_GATE (core/gate.h)

// errNotExpressible marks a well-formed rule the dataplane cannot carry: a port
// *range* has no mask in a WildcardMatch key, and an address or prefix that is
// not IPv4 has no four-byte form in that key at all. The request is not
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

// errMandatoryIE marks a request that omits an IE the spec makes mandatory in
// the shape it was sent: a FAR that forwards must carry forwarding parameters
// and those must name a Destination Interface (Tables 7.5.2.3-1 and
// 7.5.2.3-2), and a forward toward SGi-LAN/N6-LAN must carry a Forwarding
// Policy. The SMF is told cause 61 ("mandatory IE missing"), which names the
// fault the way cause 73 does not: the message is incomplete, and the SMF can
// send it again whole.
var errMandatoryIE = errors.New("a mandatory IE is missing")

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

// pdrsInOrder, marsInOrder and qersInOrder are the session's objects in id order,
// cached on the session for repeated accesses within a compilation.
func pdrsInOrder(s *Session) []*pdr {
	if s == nil {
		return nil
	}
	if s.cachedPDRs != nil {
		return s.cachedPDRs
	}
	out := make([]*pdr, 0, len(s.PDRs))
	for _, id := range idsOf(s.PDRs) {
		out = append(out, s.PDRs[id])
	}
	s.cachedPDRs = out
	return out
}

func marsInOrder(s *Session) []*mar {
	if s == nil {
		return nil
	}
	if s.cachedMARs != nil {
		return s.cachedMARs
	}
	out := make([]*mar, 0, len(s.MARs))
	for _, id := range idsOf(s.MARs) {
		out = append(out, s.MARs[id])
	}
	s.cachedMARs = out
	return out
}

func qersInOrder(s *Session) []*qer {
	if s == nil {
		return nil
	}
	if s.cachedQERs != nil {
		return s.cachedQERs
	}
	out := make([]*qer, 0, len(s.QERs))
	for _, id := range idsOf(s.QERs) {
		out = append(out, s.QERs[id])
	}
	s.cachedQERs = out
	return out
}

// sharedRateQER is the one QER a PDR's rates are enforced from: among the
// session's QERs that carry a rate, the one the most PDRs name -- ties going to
// the lower id, since the ids are walked in order.
//
// A PDR may name several QERs (7.5.2.2-1), each with its own gate and rates,
// but one rule's action carries one meter id: enforcing every QER's own bucket
// over one packet needs the dataplane to hold a bucket per QER and measure the
// packet against all of them, which this meter cannot do yet (finding 6,
// docs/claims.md). So the session picks one, and it picks deliberately:
// 5.2.1 attaches the session's own rate to a QER "associated to all the DL/UL
// PDRs of the PDU session", so the most-referenced QER is the aggregate cap --
// the one whose absence would let a session exceed its subscription -- while
// the last one the SMF happened to list is a rule nobody can predict.
//
// The gates are not this helper's business: every QER of a PDR is folded into
// the rule (a closed gate of any of them stops it).
func sharedRateQER(s *Session) (uint32, bool) {
	// One association per (PDR, QER): a PDR that names the same QER twice names
	// one rule, and counting it twice would let a duplication decide which
	// QER polices the session.
	refs := make(map[uint32]int, len(s.QERs))
	for _, p := range pdrsInOrder(s) {
		seen := make(map[uint32]bool, len(p.qerIDs))
		for _, qid := range p.qerIDs {
			if seen[qid] {
				continue
			}
			seen[qid] = true
			refs[qid]++
		}
	}
	best, bestRefs, found := uint32(0), 0, false
	for _, q := range qersInOrder(s) {
		if !q.hasRate {
			continue
		}
		// Ties fall to the lower id (the walk is in id order): where two QERs
		// are associated with the same PDRs -- a one-PDR session naming both,
		// say -- the message says nothing about which one the CP function meant
		// as the aggregate, and this is the only deterministic choice left.
		if refs[q.id] > bestRefs || !found {
			best, bestRefs, found = q.id, refs[q.id], true
		}
	}
	return best, found
}

// pdrReq is a Create PDR or an Update PDR, as the SMF sent it.
type pdrReq struct {
	// hasID says the PDR ID IE was there: 0 is a legal PDR ID (8.2.73's
	// sixteen-bit field has no reserved value), so the flag and the value are
	// two fields, the way the PDR's FAR reference is below.
	hasID      bool
	id         uint16
	precedence uint32
	srcIfc     uint8
	ueIP       netip.Addr
	hasUEIP    bool
	// ueIPDst is the PDI's 8.2.62 S/D bit: 1 names a destination IP address,
	// 0 names a source IP address. It is distinct from PDR direction; Access
	// traffic remains uplink even if this IE names a destination address.
	ueIPDst bool
	sdfs    []*sdfFilter // the PDI's SDF filters, any of which matches
	// hasFarID says the FAR ID IE was there; the FAR it names is mandatory in
	// a Create PDR (Table 7.5.2.2-1), and FAR 0 is a legal FAR, so a PDR that
	// named none must not resolve to it.
	hasFarID bool
	farID    uint32
	// hasMAR and marID are the PDR's MAR ID (TS 29.244 8.2.34): when set, the
	// MAR's two accesses decide where the packet goes and the PDR's own FAR
	// must be absent. MAR 0 is not a policy this side serves.
	hasMAR bool
	marID  uint16
	qerIDs []uint32
	urrIDs []uint32

	// instance is the PDI's Network Instance (TS 29.244 8.2.4): the deployment
	// interface this rule belongs to, empty when the SMF named none.
	instance string

	// qfis are the PDI's QFIs (TS 29.244 8.2.89): the QoS flows this rule
	// selects, each one of 0..63, any of which matches. A PDI that names none
	// is the session's general rule for the flow, and the uplink table's qfi
	// field is masked out of its key -- so it keeps matching where a
	// QFI-specific rule does not. A named 0 is a flow like any other: the
	// decap writes a value above the range for a packet with no container
	// (datapath/pdu_session_qfi.h).
	qfis []uint8

	// An uplink PDR's PDI names an F-TEID: the TEID the SMF expects us to
	// use (0: ours to choose) and, for the address, usually 0.
	hasFTEID, hasChoose  bool
	teid                 uint32
	fteidIPv4, fteidIPv6 netip.Addr
	wantIPv4, wantIPv6   bool
	hasCHID              bool
	chid                 uint8
}

// marReq is one Create MAR or Update MAR (TS 29.244 7.5.2.8): the access
// forwarding action information for the 3GPP and non-3GPP accesses, and the
// mode that says how they are chosen between.
type marReq struct {
	create bool
	hasID  bool
	id     uint16

	hasFunctionality bool
	functionality    uint8
	hasMode          bool
	mode             uint8

	// haveAccess says which access IEs the message carried: an Update MAR may
	// name one access and keep the other as the session has it. removeAccess
	// is a null-length Update access IE, which deregisters that access.
	haveAccess   [2]bool
	removeAccess [2]bool
	access       [2]marAccess
}

type farReq struct {
	// hasID says the FAR ID IE was there; 0 is a legal FAR ID (8.2.74), so the
	// flag and the value are two fields.
	hasID    bool
	id       uint32
	apply    uint8
	destIfc  uint8
	teid     uint32
	peer     netip.Addr
	hasOuter bool

	// hasFwd says the message named the Forwarding Parameters IE at all: a
	// FAR that forwards must carry it (Table 7.5.2.3-1), and an IE with
	// nothing in it is still the IE -- the record it fills is what the checks
	// read.
	hasFwd bool

	// policy is the Forwarding Policy identifier (TS 29.244 8.2.23, IE type 41) the
	// forwarding parameters carried, and hasPolicy says they named one: it is
	// mandatory for a forward toward SGi-LAN/N6-LAN (Table 7.5.2.3-2), and it
	// is what the service fabric applies to the flow.
	policy    string
	hasPolicy bool

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
	// (8.2.12, inside the Forwarding Parameters): what the SMF asks the outer
	// header's ToS/Traffic Class to carry, the DSCP in the high octet and the
	// mask in the low one. An Update FAR's omission keeps the value the
	// session has, the way the instance's does.
	hasMarking bool
	marking    uint16
}

// barReq is a Create BAR or Update BAR as the message carried it (TS 29.244
// 7.5.2.6): the session's buffering instruction for the FARs that name it.
type barReq struct {
	// hasID says the BAR ID IE was there; 0 is a legal BAR ID (8.2.75).
	hasID bool
	id    uint8

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

	// hasGBR and hasWindow say the message named 8.2.7's guaranteed rate and
	// 8.2.115's averaging window: both are optional, and an Update QER that
	// names neither keeps the session's.
	hasGBR    bool
	gbUL      uint64
	gbDL      uint64
	hasWindow bool
	window    time.Duration

	// hasQFI and qfi are the QER's QFI (TS 29.244 8.2.89): the QoS flow this
	// QER polices. It is optional -- Gate Status is the QER's one mandatory IE
	// -- so an Update QER that leaves it out keeps the flow the session holds.
	hasQFI bool
	qfi    uint8
}

type urrReq struct {
	// hasID says the URR ID IE was there; 0 is a legal URR ID (8.2.76).
	hasID bool
	id    uint32

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
	onEndMarker bool
	// linkedReporting is LIUSA (8.2.19): the URR reports through its link
	// rather than on its own triggers. Which URRs that is is `linked` below.
	linkedReporting bool
	hasPeriod       bool
	period          time.Duration

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
// at a time: PERIO, VOLTH, TIMTH and LIUSA in the first, VOLQU and TIMQU in the
// second, REEMR in the third. Every other bit -- QUHTI, START, STOPT, DROTH,
// ENVCL, MACAR, EVETH, EVEQU, IPMJL, QUVTI, UPINT, and the spares -- is refused
// when the URR is read: a trigger the SMF asked for and this UP quietly ignores
// is a report the SMF never gets, and it bills from them. REEMR is further
// refused when the deployment drains no End Marker log (resolve).
var (
	triggersImplemented = [3]uint8{trigPeriodic | trigVolumeTh | trigTimeTh | trigLiusa, trigVolQuota | trigTimeQuota, trigEndMarker}
	triggersFirstOctet  = map[uint8]string{0x08: "QUHTI", 0x10: "START", 0x20: "STOPT", 0x40: "DROTH"}
	triggersSecondOctet = map[uint8]string{0x04: "ENVCL", 0x08: "MACAR", 0x10: "EVETH", 0x20: "EVEQU", 0x40: "IPMJL", 0x80: "QUVTI"}
	triggersThirdOctet  = map[uint8]string{0x01: "REEMR", 0x02: "UPINT"}
)

const (
	trigPeriodic  = 0x01 // PERIO (octet 5 bit 1)
	trigVolumeTh  = 0x02 // VOLTH (octet 5 bit 2)
	trigTimeTh    = 0x04 // TIMTH (octet 5 bit 3)
	trigLiusa     = 0x80 // LIUSA (octet 5 bit 8)
	trigVolQuota  = 0x01 // VOLQU (octet 6 bit 1)
	trigTimeQuota = 0x02 // TIMQU (octet 6 bit 2)
	trigEndMarker = 0x01 // REEMR (octet 7 bit 1)
	// trigEndMarkerReceived is EMRRE in the Usage Report Trigger (8.2.41,
	// octet 7 bit 5): the report REEMR asks for.
	trigEndMarkerReceived = 0x10
	// trigTermination is TERMR in the Usage Report Trigger (8.2.41, octet 6
	// bit 4). It is a *report's* trigger, not one an SMF can ask for, so
	// triggersImplemented does not carry it.
	trigTermination = 0x08
	// trigImmediate is IMMER in the Usage Report Trigger (octet 5 bit 8): a
	// report the CP function asked for with a Query URR.
	trigImmediate = 0x80
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
var urrUnsupported = map[ie.IEType]string{
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
		return c.establishResponse(req, 0, 0, ie.CauseMandatoryIEMissing, nil)
	}
	pdrs, fars, bars, qers, urrs, mars, err := parseCreate(ies)
	if err != nil {
		c.log.Warn("session: cannot read the establishment request", "error", err)
		return c.establishResponse(req, cpSEID, 0, parseCause(err), nil)
	}

	c.mu.Lock()
	// A retransmission of an establishment we already applied: answer as
	// before rather than allocating a second session for it.
	if s := c.findByCP(cpSEID); s != nil {
		created := s.createdPDRs(c.cfg)
		c.mu.Unlock()
		c.log.Info("session: establishment repeated", "cp_seid", cpSEID, "seid", s.LocalSEID)
		return c.establishResponse(req, s.CPSEID, s.LocalSEID, ie.CauseRequestAccepted, created)
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
		MARs:      map[uint16]*mar{},
		chids:     map[uint8]chosenFTEID{},
	}
	if err := c.merge(s, pdrs, fars, bars, qers, urrs, mars, removals{}); err != nil {
		c.log.Warn("session: cannot carry the establishment request",
			"cp_seid", cpSEID, "error", err)
		// merge allocates as it goes (the F-TEID among them) and refuses when a
		// later PDR names something the table cannot carry, or a value another
		// session holds: what it got through is this session's and is not going
		// anywhere.
		c.mu.Lock()
		c.releaseSession(s)
		c.mu.Unlock()
		return c.establishResponse(req, cpSEID, local, compileCause(err), nil)
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
		return c.establishResponse(req, cpSEID, local, compileCause(err), nil)
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
		return c.establishResponse(req, cpSEID, local, causeOf(err), nil)
	}

	c.mu.Lock()
	c.sessions[local] = s
	c.mu.Unlock()
	c.stats.established.Add(1)
	c.checkpoint(kindEstablish, local, req)

	c.log.Info("session: established", "cp_seid", cpSEID, "seid", local,
		"ue_ip", s.UEIP.String(), "pdrs", len(s.PDRs), "changes", len(changes))
	return c.establishResponse(req, cpSEID, local, ie.CauseRequestAccepted, created)
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
	pdrs, fars, bars, qers, urrs, mars, err := parseCreate(ies)
	if err != nil {
		c.log.Warn("session: cannot read the modification request", "seid", seid, "error", err)
		return modifyResponse(req, hdr, parseCause(err), nil)
	}
	rm := parseRemovals(ies)

	// Table 7.5.5.1-1: a Created PDR rides on a Modification Response only for
	// a PDI that asked the UP function to choose its F-TEID. The compile
	// re-states every PDR's tunnel, which is right for an establishment's
	// answer and wrong here: a real SMF's modification (free5GC's downlink
	// Update PDR) asked for none, and was answered with one.
	asked := map[uint16]bool{}
	for _, p := range pdrs {
		if p.hasFTEID && p.teid == 0 {
			asked[p.id] = true
		}
	}

	// The usage reports this request owes (TS 29.244 5.2.2.3, 7.5.5.2): what a
	// Query URR or the QAURR flag asks for -- trigger IMMER -- and what a URR
	// the request removes measured since its last report -- TERMR. Both are
	// read before the merge, while the rules that count them still exist. A
	// replayed journal reports nothing: the counters it would read are not the
	// ones the original request saw.
	var queried, removed []urrWindow
	reportAt := time.Now()
	if !c.restoring {
		var err error
		if queried, removed, err = c.requestedWindows(context.Background(), req, s, rm.urrs, reportAt); err != nil {
			c.log.Warn("session: cannot report the usage the modification asked for", "seid", seid, "error", err)
			return modifyResponse(req, hdr, ie.CauseRuleCreationModificationFailure, nil)
		}
	}

	// TS 29.244 5.3.2: a modification that carries FAR(s) with a new
	// downstream F-TEID and the SNDEM flag asks this UPF to construct and send
	// End Marker packets on the tunnels it is leaving. The old tunnels are
	// read out of the session before the merge folds the new ones in, and the
	// markers go out after the transaction lands -- TS 29.281 7.3.2.2: "after
	// sending the last G-PDU that needs to be sent on a GTP-U tunnel" -- and
	// before this request is answered.
	var leaving []tunnelEndMarker
	if c.endMarkersConfigured() && sndem(modificationFlags(req)) {
		leaving = c.leavingTunnels(s, fars)
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

	// merge takes the lock itself. A merge that fails validation goes back to
	// the model it started from: left half-applied, it would fail every later
	// message of the session the same way.
	c.mu.Lock()
	before := s.snapshot()
	c.mu.Unlock()
	if err := c.merge(s, pdrs, fars, bars, qers, urrs, mars, rm); err != nil {
		c.mu.Lock()
		c.rollback(s, before)
		c.mu.Unlock()
		c.log.Warn("session: cannot carry the modification request", "seid", seid, "error", err)
		return modifyResponse(req, hdr, compileCause(err), nil)
	}

	changes, _, err := c.compile(s)
	if err != nil {
		c.mu.Lock()
		c.rollback(s, before)
		c.mu.Unlock()
		c.log.Warn("session: cannot compile the modification request", "seid", seid, "error", err)
		return modifyResponse(req, hdr, compileCause(err), nil)
	}
	created := s.createdPDRsFor(c.cfg, asked)
	if err := c.ap.Apply(context.Background(), changes...); err != nil {
		if definiteRefusal(err) {
			c.mu.Lock()
			c.rollback(s, before)
			c.mu.Unlock()
		}
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
			if err := c.sendTunnelEndMarker(tunnel); err != nil {
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
	c.mu.Unlock()

	c.log.Info("session: modified", "seid", seid, "pdrs", len(s.PDRs), "changes", len(changes))
	c.checkpoint(kindModify, s.LocalSEID, req)
	// The queried URRs' next window opens now that the SMF has what this one
	// held; a request that failed above leaves it open, so the usage is
	// reported by the next one.
	c.advanceAfter(s, queried, reportAt)
	usage := usageReports(ie.UsageReportWithinSessionModificationResponse, TriggerImmediate, queried)
	usage = append(usage, usageReports(ie.UsageReportWithinSessionModificationResponse, TriggerTermination, removed)...)
	return modifyResponse(req, hdr, ie.CauseRequestAccepted, created, usage...)
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
	// What each URR measured since its last report goes in the answer
	// (5.2.2.3.1): read now, while the rules that count it still exist.
	var usage []*ie.IE
	if !c.restoring {
		usage = c.terminationReports(context.Background(), s, time.Now())
	}
	if err := c.remove(context.Background(), s); err != nil {
		c.log.Warn("session: the dataplane refused the deletion", "seid", seid, "error", err)
		return deleteResponse(req, hdr, causeOf(err))
	}
	if !c.restoring {
		c.dropFlows(context.Background(), seid, held)
	}
	c.log.Info("session: deleted", "seid", seid)
	c.checkpoint(kindDelete, seid, req)
	return deleteResponse(req, hdr, ie.CauseRequestAccepted, usage...)
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
	urrs []urrReq, mars []marReq, rm removals) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	s.invalidateOrderCache()
	defer s.invalidateOrderCache()

	for _, q := range qers {
		entry := s.QERs[q.id]
		// A GBR above the MBR is not a policy this side can hold: the committed
		// rate of a two-rate meter may not exceed its peak, and the SMF would
		// have asked for a guarantee above the ceiling (8.2.7, 8.2.8). The
		// comparison is against what the session would hold after this message,
		// because an Update QER that names only one of the two keeps the other.
		gbUL, gbDL, hasGBR := q.gbUL, q.gbDL, q.hasGBR
		mbUL, mbDL, hasRate := q.mbUL, q.mbDL, q.hasRate
		if entry != nil {
			if !hasGBR {
				gbUL, gbDL, hasGBR = entry.gbUL, entry.gbDL, entry.hasGBR
			}
			if !hasRate {
				mbUL, mbDL, hasRate = entry.mbUL, entry.mbDL, entry.hasRate
			}
		}
		if hasGBR && hasRate && (gbUL > mbUL || gbDL > mbDL) {
			return fmt.Errorf("%w: the QER %d's GBR is above its MBR, which no meter holds",
				errNotExpressible, q.id)
		}
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
		if q.hasGBR {
			entry.gbUL, entry.gbDL, entry.hasGBR = q.gbUL, q.gbDL, true
		}
		if q.hasWindow {
			entry.window, entry.hasWindow = q.window, true
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
		// What the forwarding parameters named, whether this message carried
		// the IE or an earlier one did: a forward's record is complete only
		// once something named each part of it.
		if f.hasFwd {
			entry.hasFwd = true
		}
		if f.hasDestIfc {
			entry.hasDestIfc = true
		}
		if f.hasPolicy {
			entry.hasPolicy, entry.policy = true, f.policy
		}
		if f.hasOuter {
			entry.teid, entry.peer, entry.hasOuter = f.teid, f.peer, true
		}
		if f.hasBAR {
			entry.hasBAR, entry.barID = true, f.barID
		}
		if f.hasMarking {
			// The Transport Level Marking (8.2.12) merges like the instance: an
			// Update FAR that names none keeps the value the session has.
			entry.hasMarking, entry.marking = true, f.marking
		}
	}
	// What a FAR that forwards must carry (Tables 7.5.2.3-1 and 7.5.2.3-2),
	// read from the merged record: an Update FAR carries what changed, so a FAR
	// that forwards because of this message and named its forwarding
	// parameters in an earlier one is a complete FAR. A FAR that does not
	// forward is not checked -- there is no forward for the parameters to
	// describe, and a dropping FAR is how this UP is told to stop.
	for _, f := range fars {
		entry := s.FARs[f.id]
		if entry == nil || entry.apply&applyForw == 0 {
			continue
		}
		switch {
		case !entry.hasFwd:
			return fmt.Errorf(
				"%w: FAR %d's Apply Action forwards, and the Forwarding Parameters IE is mandatory then (Table 7.5.2.3-1)",
				errMandatoryIE, entry.id)
		case !entry.hasDestIfc:
			return fmt.Errorf(
				"%w: FAR %d's forwarding parameters name no Destination Interface, which is mandatory (Table 7.5.2.3-2)",
				errMandatoryIE, entry.id)
		case entry.destIfc > ie.DstInterface5GVNInternal:
			// The value is a 4-bit integer of which 0..5 are defined and 6..15
			// are Spare (Table 8.2.24-1): a forward toward a value no interface
			// names is a rule this UP cannot place, and the SMF is told so
			// rather than handed the direction's own hop.
			return fmt.Errorf(
				"%w: FAR %d names Destination Interface value %d, which the spec leaves spare (Table 8.2.24-1)",
				errNotExpressible, entry.id, entry.destIfc)
		case entry.destIfc == ie.DstInterfaceSGiLANN6LAN && !entry.hasPolicy:
			return fmt.Errorf(
				"%w: FAR %d forwards toward SGi-LAN/N6-LAN, and the Forwarding Policy IE is mandatory then (Table 7.5.2.3-2)",
				errMandatoryIE, entry.id)
		}
	}
	for _, m := range mars {
		entry := s.MARs[m.id]
		if entry == nil {
			if !m.create {
				return fmt.Errorf("%w: the MAR %d is not in the session", errNotExpressible, m.id)
			}
			entry = &mar{id: m.id}
			s.MARs[m.id] = entry
		}
		if m.hasFunctionality {
			if m.functionality != ie.SteeringFunctionalityATSSSLL {
				return fmt.Errorf(
					"%w: MAR %d asks for Steering Functionality %d; this UP applies ATSSS-LL only",
					errNotExpressible, m.id, m.functionality)
			}
		} else if m.create {
			return fmt.Errorf(
				"%w: Create MAR %d names no Steering Functionality (Table 7.5.2.8-1)",
				errMandatoryIE, m.id)
		}
		if m.hasMode {
			if m.mode != ie.SteeringModeActiveStandby {
				return fmt.Errorf(
					"%w: MAR %d asks for Steering Mode %d; this UP applies active/standby only",
					errNotExpressible, m.id, m.mode)
			}
			entry.mode = m.mode
		} else if m.create {
			return fmt.Errorf(
				"%w: Create MAR %d names no Steering Mode (Table 7.5.2.8-1)",
				errMandatoryIE, m.id)
		}
		for which := 0; which < 2; which++ {
			if !m.haveAccess[which] {
				continue
			}
			if m.removeAccess[which] {
				entry.accesses[which] = marAccess{}
				continue
			}
			if m.create {
				entry.accesses[which] = m.access[which]
				continue
			}
			// Update access IEs carry only the fields that changed
			// (Table 7.5.4.16-2): merge those, keep the rest.
			access := entry.accesses[which]
			if m.access[which].hasFarID {
				access.farID, access.hasFarID = m.access[which].farID, true
			}
			if m.access[which].hasPrior {
				access.priority, access.hasPrior = m.access[which].priority, true
			}
			if m.access[which].hasWeight {
				access.weight, access.hasWeight = m.access[which].weight, true
			}
			entry.accesses[which] = access
		}
		if !entry.accesses[0].hasFarID && !entry.accesses[1].hasFarID {
			return fmt.Errorf(
				"%w: MAR %d names no access forwarding action information", errMandatoryIE, m.id)
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
			entry.onEndMarker = u.onEndMarker
			entry.linkedReporting = u.linkedReporting
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
	for _, id := range rm.pdrs {
		if old := s.PDRs[id]; old != nil {
			// The records stay in the dataplane until the next compile erases
			// them: it is the transaction that carries the removal out, so a
			// refused modification leaves both the PDR and its records.
			s.removed = append(s.removed, old)
		}
		delete(s.PDRs, id)
	}
	for _, id := range rm.fars {
		delete(s.FARs, id)
	}
	for _, id := range rm.bars {
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
			ueIP: p.ueIP, hasUEIP: p.hasUEIP, ueIPDst: p.ueIPDst,
			sdfs: p.sdfs, farID: p.farID,
			hasMAR: p.hasMAR, marID: p.marID, qerIDs: p.qerIDs, urrIDs: p.urrIDs,
			instance: p.instance, qfis: p.qfis,
			hasFTEID: p.hasFTEID, hasChoose: p.hasChoose, hasCHID: p.hasCHID, chid: p.chid,
			fteidIPv4: p.fteidIPv4, fteidIPv6: p.fteidIPv6,
			wantIPv4: p.wantIPv4, wantIPv6: p.wantIPv6,
		}
		var err error
		pdr.down, err = pdrDownlink(pdr.srcIfc, pdr.hasUEIP, pdr.ueIPDst, pdr.sdfs)
		if err != nil {
			return fmt.Errorf("PDR %d: %w", p.id, err)
		}
		if old != nil {
			// An update keeps the dataplane identity: the rule that already
			// selects this PDR keeps its action id, so a worker switching
			// between old and new state never sees a dangling reference.
			pdr.actionID = old.actionID
			pdr.writtenTunnels = old.writtenTunnels
			if !p.hasFTEID || old.down == pdr.down {
				pdr.teid = old.teid
				pdr.hasFTEID = old.hasFTEID
				pdr.endpointID, pdr.endpointFamily = old.endpointID, old.endpointFamily
				pdr.endpointIPv4, pdr.endpointIPv6 = old.endpointIPv4, old.endpointIPv6
				pdr.endpointFamilies = slices.Clone(old.endpointFamilies)
				pdr.wantIPv4, pdr.wantIPv6 = old.wantIPv4, old.wantIPv6
				pdr.hasChoose, pdr.hasCHID, pdr.chid = old.hasChoose, old.hasCHID, old.chid
			}
			pdr.meterID = old.meterID
			// A PDR that keeps buffering keeps its episode: the SMF is owed one
			// Downlink Data Report per episode ("the first buffered DL packet"),
			// not one per modification. The buffering state itself is carried
			// over too, so that resolve can see a transition -- a PDR the
			// message rebuilds would otherwise look like it never buffered, and
			// the release its instruction owes would be missed.
			pdr.ddnSent, pdr.buffer = old.ddnSent, old.buffer
		}
		if p.hasFTEID {
			families := requestedFTEIDFamilies(pdr)
			var endpoint FTEIDEndpoint
			if p.hasCHID && p.teid == 0 {
				if chosen, ok := s.chids[p.chid]; ok {
					if chosen.SourceInterface != pdr.srcIfc || chosen.Instance != pdr.instance ||
						!slices.Equal(chosen.Families, families) {
						return fmt.Errorf("%w: CHOOSE ID %d was reused with a different endpoint or family set", errNotExpressible, p.chid)
					}
					for _, candidate := range c.cfg.FTEIDEndpoints {
						if candidate.ID == chosen.EndpointID {
							endpoint = candidate
							break
						}
					}
					if endpoint.ID == 0 {
						return fmt.Errorf("%w: CHOOSE ID %d references an unavailable endpoint", errNotExpressible, p.chid)
					}
				} else {
					endpoint, err = c.fteidEndpoint(pdr)
				}
			} else {
				endpoint, err = c.fteidEndpoint(pdr)
			}
			if err != nil {
				return fmt.Errorf("PDR %d: %w", p.id, err)
			}
			for _, family := range families {
				if (family == 4 && !endpoint.IPv4.IsValid()) || (family == 6 && !endpoint.IPv6.IsValid()) {
					return fmt.Errorf("%w: CHOOSE ID %d endpoint lacks requested family %d", errNotExpressible, p.chid, family)
				}
			}
			if (pdr.fteidIPv4.IsValid() && endpoint.IPv4 != pdr.fteidIPv4) ||
				(pdr.fteidIPv6.IsValid() && endpoint.IPv6 != pdr.fteidIPv6) {
				return fmt.Errorf("%w: CHOOSE ID %d was reused with a different endpoint address", errNotExpressible, p.chid)
			}
			pdr.endpointID = endpoint.ID
			pdr.endpointIPv4, pdr.endpointIPv6 = endpoint.IPv4, endpoint.IPv6
			pdr.endpointFamilies = slices.Clone(families)
			pdr.wantIPv4, pdr.wantIPv6 = slices.Contains(families, 4), slices.Contains(families, 6)
			pdr.endpointFamily = families[0]
			if p.teid != 0 {
				pdr.teid = p.teid
				c.teids.reserve(p.teid)
			} else if p.hasChoose {
				if p.hasCHID {
					chosen, ok := s.chids[p.chid]
					if !ok {
						teid, err := c.teids.alloc()
						if err != nil {
							return fmt.Errorf("%w: %v", errNoResources, err)
						}
						chosen = chosenFTEID{
							TEID: teid, EndpointID: endpoint.ID,
							Families: slices.Clone(families), SourceInterface: pdr.srcIfc,
							Instance: pdr.instance,
						}
						s.chids[p.chid] = chosen
					}
					pdr.teid = chosen.TEID
				} else {
					teid, err := c.teids.alloc()
					if err != nil {
						return fmt.Errorf("%w: %v", errNoResources, err)
					}
					pdr.teid = teid
				}
			} else {
				return fmt.Errorf("%w: an F-TEID with TEID zero must carry CHOOSE", errNotExpressible)
			}
		}
		// The session's UE address is named by a PDI whose address is on the
		// UE's side of the packet (ueAddr); an Access PDI's destination is
		// some other node's address.
		if p.ueIP.IsValid() && (p.srcIfc != ie.SrcInterfaceAccess || !p.ueIPDst) {
			s.UEIP = p.ueIP
		}
		if old != nil {
			// The form being replaced: its rule key, and the TEID it held, are
			// erased unless the transaction that carries this update writes them
			// (compile).
			s.stale = append(s.stale, old)
		}
		s.PDRs[p.id] = pdr
		if pdr.teid != 0 {
			if err := c.claimFTEID(s, pdr); err != nil {
				return err
			}
		}
	}
	// A removed MAR that a PDR still names is refused: the PDR's only egress
	// would be gone, and the packet path would drop it with no cause the SMF
	// could see. This is read after the PDRs are folded in, so a message that
	// removes the PDR and its MAR together is accepted.
	for _, id := range rm.mars {
		for _, p := range s.PDRs {
			if p.hasMAR && p.marID == id {
				return fmt.Errorf(
					"%w: MAR %d is still named by PDR %d", errNotExpressible, id, p.id)
			}
		}
		if old := s.MARs[id]; old != nil {
			s.removedMARs = append(s.removedMARs, old)
			delete(s.MARs, id)
		}
	}
	createdQERs := make(map[uint32]bool, len(qers))
	for _, q := range qers {
		createdQERs[q.id] = true
	}
	for _, id := range rm.qers {
		if createdQERs[id] {
			// The message also brings this QER (a replacement): the removal
			// says nothing about the QER that is live now, the way a PDR
			// removed and created again is not a removal (forgetRemoval).
			continue
		}
		if qerHeldByAPDR(s, id) {
			// A PDR of the session names this QER, so its traffic is gated and
			// metered by it: the CP function disassociates the PDRs first (an
			// Update PDR that does not name the QER), the order the URR removal
			// takes below and a dangling reference is refused in (resolve).
			return fmt.Errorf("%w: the QER %d is still named by a PDR of the session",
				errNotExpressible, id)
		}
		if entry := s.QERs[id]; entry != nil {
			// The QER goes, and its meters go with the session's other ids at
			// teardown (releaseSession): releasing them here would hand an id
			// back to the pool that a refused modification restores the QER
			// to -- and that another session would then police with while this
			// one still names it.
			s.removedQERs = append(s.removedQERs, entry)
			delete(s.QERs, id)
		}
	}
	for _, id := range rm.urrs {
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
	if err := resolveSDFIDs(s); err != nil {
		return err
	}
	for _, p := range s.PDRs {
		down, err := pdrDownlink(p.srcIfc, p.hasUEIP, p.ueIPDst, p.sdfs)
		if err != nil {
			return fmt.Errorf("PDR %d: %w", p.id, err)
		}
		p.down = down
	}
	tunnelDirections := map[uint32]bool{}
	for _, p := range s.PDRs {
		if p.teid == 0 {
			continue
		}
		if down, exists := tunnelDirections[p.teid]; exists && down != p.down {
			return fmt.Errorf("%w: F-TEID %#x has conflicting ingress directions", errNotExpressible, p.teid)
		}
		tunnelDirections[p.teid] = p.down
	}
	// What the request's objects mean for each PDR (resolve): a modification
	// that leaves the model unfaithful to itself is refused before the compile
	// that would write it.
	if err := c.resolve(s); err != nil {
		return err
	}
	return nil
}

// pdrDownlink resolves packet direction from the PDI's UE-address side when it
// is explicit, or from an SDF "assigned" side when the PDI omits that IE.
// Source Interface is only the ordinary fallback; Access is always uplink.
func pdrDownlink(srcIfc uint8, hasUEIP, ueIPDst bool, sdfs []*sdfFilter) (bool, error) {
	if srcIfc == ie.SrcInterfaceAccess {
		return false, nil
	}
	if hasUEIP {
		return ueIPDst, nil
	}

	hasDirection, down := false, false
	for _, sdf := range sdfs {
		if sdf == nil || sdf.bare {
			continue
		}
		if sdf.srcAssigned && sdf.dstAssigned {
			return false, fmt.Errorf("%w: an SDF filter marks the UE as both source and destination",
				errNotExpressible)
		}
		if !sdf.srcAssigned && !sdf.dstAssigned {
			continue
		}
		candidate := sdf.dstAssigned
		if hasDirection && down != candidate {
			return false, fmt.Errorf("%w: PDI SDF filters imply conflicting packet directions",
				errNotExpressible)
		}
		hasDirection, down = true, candidate
	}
	if hasDirection {
		return down, nil
	}
	return true, nil
}

// resolveMAR derives one MAR's two accesses into the packet path's numbers: the
// Router next hop each FAR leaves by, the tunnel record an access that adds an
// outer header names, and the preferred access the priority IE selects. It is
// called for every MAR the session holds, and is idempotent: a tunnel id
// allocated by an earlier compile is kept.
func (c *Compiler) resolveMAR(s *Session, m *mar) error {
	if m.mode != ie.SteeringModeActiveStandby {
		return fmt.Errorf("%w: MAR %d uses Steering Mode %d; this UP applies active/standby only",
			errNotExpressible, m.id, m.mode)
	}
	if m.policyID == 0 {
		id, err := c.policies.alloc()
		if err != nil {
			return fmt.Errorf("MAR %d: allocating a steering policy: %w", m.id, err)
		}
		m.policyID = id
	}
	ifc, err := c.marInterface(s, m.id)
	if err != nil {
		return err
	}
	active := -1
	for which := 0; which < 2; which++ {
		access := &m.accesses[which]
		if !access.hasFarID {
			// The access is not provisioned (the SMF omitted it, which
			// active/standby allows for an access with no standby).
			continue
		}
		switch access.priority {
		case ie.PriorityActive:
			if active != -1 {
				return fmt.Errorf("%w: MAR %d names both accesses active", errNotExpressible, m.id)
			}
			active = which
		case ie.PriorityStandby, ie.PriorityNoStandby:
			// No Standby is an access that is present but never selected as
			// the standby (Table 7.5.2.8-2). It remains a valid active/standby
			// access; it is not one of the unsupported modes.
		default:
			return fmt.Errorf(
				"%w: MAR %d's %s access has Priority %d; active/standby needs PriorityActive and PriorityStandby",
				errNotExpressible, m.id, []string{"3GPP", "non-3GPP"}[which], access.priority)
		}
	}
	if active == -1 {
		return fmt.Errorf("%w: MAR %d names no active access", errNotExpressible, m.id)
	}
	for which := 0; which < 2; which++ {
		access := &m.accesses[which]
		m.tunnelLocalAddresses[which] = netip.Addr{}
		m.transportRouteDomains[which] = 0
		if !access.hasFarID || access.priority == ie.PriorityNoStandby {
			s.retireTunnel(m.tunnelIDs[which])
			m.nextHops[which] = 0
			m.tunnelIDs[which] = 0
			continue
		}
		far := s.FARs[access.farID]
		if far == nil {
			return fmt.Errorf("%w: MAR %d's %s access names FAR %d, which the session does not hold",
				errNotExpressible, m.id, []string{"3GPP", "non-3GPP"}[which], access.farID)
		}
		if far.apply&applyForw == 0 {
			return fmt.Errorf("%w: MAR %d's %s access names FAR %d, which does not forward",
				errNotExpressible, m.id, []string{"3GPP", "non-3GPP"}[which], access.farID)
		}
		hop, err := c.egressHop(far, ifc, c.cfg.Down)
		if err != nil {
			return err
		}
		if hop == 0 {
			return fmt.Errorf(
				"%w: MAR %d's %s access has no Router next hop", errNotExpressible,
				m.id, []string{"3GPP", "non-3GPP"}[which])
		}
		m.nextHops[which] = hop
		if far.hasOuter {
			if c.cfg.Down.Tunnels == "" {
				return fmt.Errorf(
					"%w: MAR %d's %s access adds an outer header, and this deployment's downlink tunnel module is unset (-tunnels)",
					errNotExpressible, m.id, []string{"3GPP", "non-3GPP"}[which])
			}
			if m.tunnelIDs[which] == 0 {
				id, err := c.actions.alloc()
				if err != nil {
					return fmt.Errorf("MAR %d: allocating a tunnel for the %s access: %w",
						m.id, []string{"3GPP", "non-3GPP"}[which], err)
				}
				m.tunnelIDs[which] = id
			}
			endpoint, local, err := c.tunnelEndpoint(far, ifc)
			if err != nil {
				return fmt.Errorf("MAR %d's %s access: %w", m.id,
					[]string{"3GPP", "non-3GPP"}[which], err)
			}
			m.tunnelLocalAddresses[which] = local
			m.transportRouteDomains[which] = endpoint.TransportRouteDomain
		} else {
			s.retireTunnel(m.tunnelIDs[which])
			m.tunnelIDs[which] = 0
		}
	}
	// The preferred access is the active one; the field is an index because
	// that is what the packet path reads.
	m.preferred = uint32(active)
	// The PDR matcher writes the shared policy id, not the session-local MAR
	// id: two sessions may both use MAR 7 without sharing a policy.
	for _, p := range pdrsInOrder(s) {
		if p.hasMAR && p.marID == m.id {
			p.policyID = m.policyID
		}
	}
	return nil
}

// marInterface is the deployment interface a MAR's accesses leave by: the PDI
// interface of the PDR that names it. One MAR is one policy, so every PDR
// naming it must be in the same interface; two interfaces would need two
// policies for one pfcp MAR.
func (c *Compiler) marInterface(s *Session, id uint16) (routing.Interface, error) {
	var chosen routing.Interface
	found := false
	for _, p := range pdrsInOrder(s) {
		if !p.hasMAR || p.marID != id {
			continue
		}
		ifc, err := c.interfaceFor(p)
		if err != nil {
			return routing.Interface{}, err
		}
		if !found {
			chosen, found = ifc, true
			continue
		}
		if ifc.Instance != chosen.Instance || ifc.Domain != chosen.Domain {
			return routing.Interface{}, fmt.Errorf(
				"%w: MAR %d is named by PDRs in two network instances (%q and %q)",
				errNotExpressible, id, chosen.Instance, ifc.Instance)
		}
	}
	if found {
		return chosen, nil
	}
	if c.cfg.Instances != nil {
		return c.cfg.Instances.Default(), nil
	}
	return routing.Interface{}, nil
}

// retireTunnel records a tunnel record that an update stopped using. compile
// erases it and settle returns its id after the transaction lands; keeping it
// only on the MAR would lose it, because resolve overwrites the field.
func (s *Session) retireTunnel(id uint32) {
	if id == 0 {
		return
	}
	for _, old := range s.retiredTunnels {
		if old == id {
			return
		}
	}
	s.retiredTunnels = append(s.retiredTunnels, id)
}

// resolve derives what each PDR's FAR and QERs mean for the dataplane: a
// forward or a drop, the meter of the QER this direction is policed by, and
// (downlink) the tunnel record the FAR's outer header creation names. compile
// calls it too, and that is not redundancy: a URR's enforcement changes the
// model with no message from the SMF (report.go), so what a transaction writes
// must follow the model as it is now rather than as the last message left it.
// The caller holds the lock.
func (c *Compiler) resolve(s *Session) error {
	// The one QER each PDR's rates come from, chosen for the session (finding
	// 6: one rule's action carries one meter id, so a PDR naming several
	// rate-bearing QERs is policed by one of them -- sharedRateQER says which
	// and why).
	shared, hasShared := sharedRateQER(s)
	linkedTo := make(map[uint32]bool, len(s.URRs))
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
			linkedTo[lid] = true
		}
	}
	for _, id := range idsOf(s.MARs) {
		if err := c.resolveMAR(s, s.MARs[id]); err != nil {
			return err
		}
	}
	for _, uid := range urrIDsInOrder(s) {
		// LIUSA (8.2.19) is the link itself: a URR that asks for Linked Usage
		// Reporting has no report of its own -- the group's is owed when a URR
		// it is linked to is due -- so a LIUSA URR with no link in either
		// direction is a URR the SMF asked to hear about and never would.
		if u := s.URRs[uid]; u.linkedReporting && len(u.linked) == 0 && !linkedTo[uid] {
			return fmt.Errorf(
				"%w: URR %d asks for Linked Usage Reporting (LIUSA), and no URR of the session is linked to it",
				errNotExpressible, uid)
		}
		// REEMR asks to hear of an End Marker, which only a drained End Marker
		// log sees: accepted without one, the report could never be sent.
		if s.URRs[uid].onEndMarker && c.cfg.GTPUEndMarkers == "" {
			return fmt.Errorf(
				"%w: URR %d asks for End Marker reception reports (REEMR), and this deployment tracks no End Markers",
				errNotExpressible, uid)
		}
	}
	for _, p := range pdrsInOrder(s) {
		far := s.FARs[p.farID]
		dir := c.direction(p)
		ifc, err := c.interfaceFor(p)
		if err != nil {
			return err
		}
		p.domain = ifc.Domain
		wasBuffering := p.buffer
		if p.hasMAR {
			// A MAR PDR has no FAR of its own: the MAR's selected access is
			// the egress, and AtsssSteer writes the next hop and tunnel it
			// names. The rule's action record still carries the PDR's meter
			// and counters, so this branch only decides the egress.
			if !p.down {
				return fmt.Errorf(
					"%w: PDR %d names a MAR on the uplink; this UP steers downlink accesses only",
					errNotExpressible, p.id)
			}
			if c.cfg.Atsss == "" {
				return fmt.Errorf(
					"%w: PDR %d names MAR %d, and this deployment has no AtsssSteer module (-atsss)",
					errNotExpressible, p.id, p.marID)
			}
			m := s.MARs[p.marID]
			if m == nil {
				return fmt.Errorf("%w: PDR %d names MAR %d, which the session does not hold",
					errNotExpressible, p.id, p.marID)
			}
			if err := c.resolveMAR(s, m); err != nil {
				return err
			}
			p.nextHop = 0
			p.drop, p.buffer, p.tunnels = false, false, nil
		} else {
			hop, err := c.egressHop(far, ifc, dir)
			if err != nil {
				return err
			}
			p.nextHop = hop
			// A FAR that asks for buffering and not for forwarding (Apply Action
			// BUFF, 8.2.26) is the idle-UE downlink case: the packets are held and
			// the SMF is told they arrived. Where the deployment has a store
			// (Config.Buffering), the rule delivers them on that branch; where it
			// has none, they are dropped, because delivering traffic the SMF asked
			// to hold would be worse than dropping it (docs/claims.md's row
			// over 7.5.2.6).
			// Buffering is the downlink's: a BAR is the instruction for downlink data
			// (5.2.4.1), and only the downlink chain has the branch. A BUFF-only FAR
			// on an uplink PDR -- which no SMF should send -- keeps the drop it had,
			// rather than gating to a branch that is not in its chain.
			p.buffer = c.cfg.Buffering != nil && far != nil && p.downlink() &&
				far.apply&applyForw == 0 && far.apply&applyBuff != 0
			// The report is the SMF's to ask for: NOCP is set with BUFF (8.2.26),
			// and without it the held packets are reported to nobody.
			p.notify = p.buffer && far.apply&applyNOCP != 0
			p.drop = far == nil || (far.apply&applyForw == 0 && !p.buffer)
		}
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
		p.tunnelLocalAddress = netip.Addr{}
		p.transportRouteDomain = 0
		p.encapQFI = 0
		p.hasEncapQFI = false
		var sharedUL, ownUL, sharedDL, ownDL uint32
		for _, qid := range p.qerIDs {
			entry := s.QERs[qid]
			if entry == nil {
				// A PDR naming a QER the session does not hold: the SMF named
				// something that is not there, and carrying the rule on without
				// it would give the flow no gate and no meter -- enforcement
				// the CP function asked for and silently did not get. Refused
				// the way a dangling URR or BAR reference is.
				return fmt.Errorf("%w: PDR %d's QER %d is not in the session",
					errNotExpressible, p.id, qid)
			}
			if !p.downlink() {
				if entry.gateUL == ie.GateStatusClosed {
					// A closed gate is an instruction to stop, not to hold: it
					// outranks the FAR's BUFF for this PDR. Every QER the PDR
					// names is folded this way -- a gate that is closed in any
					// of them stops the traffic, whichever one's rates win.
					p.drop, p.buffer = true, false
				}
				if entry.hasRate && entry.mbUL != 0 {
					// The direction's own rate: a QER that caps nothing
					// uplink (an MBR of zero there) leaves the PDR unmetered
					// rather than writing a meter that caps nothing. The
					// session's shared QER wins when the PDR names it; a PDR
					// that names only its own flow's QER keeps that QER's
					// meter, which is the enforcement it would have had
					// before the shared one was preferred.
					if hasShared && qid == shared {
						sharedUL = entry.meterUL
					} else {
						ownUL = entry.meterUL
					}
				}
			} else {
				if entry.gateDL == ie.GateStatusClosed {
					p.drop, p.buffer = true, false
				}
				if entry.hasRate && entry.mbDL != 0 {
					if hasShared && qid == shared {
						sharedDL = entry.meterDL
					} else {
						ownDL = entry.meterDL
					}
				}
				if entry.hasQFI {
					// The QER's QFI (8.2.89) is the flow the gNB reads out of
					// the PDU Session Container of a downlink packet: it goes
					// into the tunnel record the FAR's outer header creation
					// writes, so the encap marks every packet of this flow
					// with the id the SMF programmed (the last QER that names
					// one, as the meter is the last that polices).
					p.encapQFI = entry.qfi
					p.hasEncapQFI = true
				}
			}
		}
		if p.hasMAR && p.hasEncapQFI {
			return fmt.Errorf(
				"%w: PDR %d names MAR %d and a QER with a QFI; one MAR tunnel is shared by its PDRs, so a per-PDR QFI has no record to carry it",
				errNotExpressible, p.id, p.marID)
		}
		// The meter this PDR is policed by: the session's shared QER when the
		// PDR names it, else the last rate-bearing QER of its own (which is
		// what a PDR that names only a flow QER had before). The two are kept
		// apart as well, for a two-level Meter: the PDR result writes the flow
		// meter ID first, so a red flow bucket does not charge the shared session
		// bucket.
		switch {
		case p.downlink():
			p.ownMeterID, p.sharedMeterID = ownDL, sharedDL
			if sharedDL != 0 {
				p.meterID = sharedDL
			} else {
				p.meterID = ownDL
			}
		default:
			p.ownMeterID, p.sharedMeterID = ownUL, sharedUL
			if sharedUL != 0 {
				p.meterID = sharedUL
			} else {
				p.meterID = ownUL
			}
		}
		if !p.hasMAR && far != nil && far.hasOuter && far.apply&applyForw != 0 && !p.drop {
			if dir.Tunnels == "" {
				// The FAR adds an outer header, so the forward's packets must
				// leave in a tunnel -- indirect data forwarding (Destination
				// Interface Access) or an N9 uplink (Destination Interface Core
				// with an Outer Header Creation). The tunnel's parameters are a
				// per-session record in the direction's encap module, and this
				// deployment names none: compiling the rule anyway would send
				// the packets to an encap that has no session for them, which
				// drops them (datapath/gtpu_encap.cc) -- a silent blackhole the
				// SMF never hears about. Cause 73 names the flag instead.
				flagName := "-tunnels-ul"
				if p.downlink() {
					flagName = "-tunnels"
				}
				return fmt.Errorf(
					"%w: PDR %d's FAR adds an outer header, and this deployment's tunnel module for this direction is unset (%s)",
					errNotExpressible, p.id, flagName)
			}
			endpoint, local, err := c.tunnelEndpoint(far, ifc)
			if err != nil {
				return fmt.Errorf("PDR %d's outer GTP-U tunnel: %w", p.id, err)
			}
			p.tunnelLocalAddress = local
			p.transportRouteDomain = endpoint.TransportRouteDomain
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
		if c.cfg.Instances != nil && p.ueAddr() && !ifc.Serves(p.ueIP) {
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
// indistinguishable from one naming ours (docs/claims.md's row over
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

// forwardEgress is the interface a forward leaves by: the FAR's own Network
// Instance when it names one (TS 29.244 8.2.4 inside the Forwarding
// Parameters), and the PDI's interface otherwise. The two need not agree -- an
// uplink rule may select a flow in one instance and send it out of N9 toward
// another -- and a deployment that resolves no instances at all (no -instances)
// has the one interface, whose hop is the direction's own.
func (c *Compiler) forwardEgress(far *far, ifc routing.Interface) (routing.Interface, error) {
	if far.instance == "" || c.cfg.Instances == nil {
		return ifc, nil
	}
	found, ok := c.cfg.Instances.Lookup(far.instance)
	if !ok {
		return routing.Interface{}, fmt.Errorf(
			"%w: the FAR's forwarding parameters name the network instance %q, and this deployment serves %s",
			errNotExpressible, far.instance, strings.Join(c.cfg.Instances.Names(), ", "))
	}
	return found, nil
}

// egressHop is where a PDR's forward leaves by: the deployment's egress table
// (internal/routing), read by the FAR's Destination Interface value (TS 29.244
// 8.2.24, Table 8.2.24-1) and by whether the FAR adds an outer header. It
// replaces the direction's own hop, which is what every forward took before the
// value was read at all: an uplink forward toward the access side used to leave
// for N6, and a forward toward the service LAN or the 5G VN silently took the
// data network's exit.
//
// The deployment declares what each egress is (the -instances flag's
// *-next-hop keys); a forward whose egress it declares nothing for is refused
// with the rule-failure cause, because sending it anywhere else would be
// forwarding traffic toward an interface the deployment never built.
//
// A FAR that does not forward -- a drop, or a BUFF-only FAR -- makes no egress
// decision: there is no forward to place, and in hop mode the hop returned here
// is unused (its rule delivers on the drop gate). In destination mode it is not
// unused: the action record names it as a reference to the routes table, and a
// nonzero one would name a route the deployment need not have (a routed graph
// with no hop for the direction's fallback hands the packet to a Router that
// never sees the buffering branch). Hop 0 is the mode's "no next hop", so a
// non-forwarding FAR in destination mode names that.
func (c *Compiler) egressHop(far *far, ifc routing.Interface, dir Direction) (uint32, error) {
	if far == nil || far.apply&applyForw == 0 {
		if c.cfg.RouteMode == RouteByDestination {
			return 0, nil
		}
		return dir.NextHop, nil
	}
	if c.cfg.RouteMode == RouteByDestination {
		return c.destinationHop(far, ifc)
	}
	switch far.destIfc {
	case ie.DstInterfaceAccess:
		egress, err := c.forwardEgress(far, ifc)
		if err != nil {
			return 0, err
		}
		if hop, ok := egress.Hop(routing.Egress{DestIfc: ie.DstInterfaceAccess, Tunnel: far.hasOuter}); ok {
			return hop, nil
		}
		// The access side: whichever direction the PDR is on, the forward
		// leaves through the encap, and a deployment that names no
		// -access-next-hop takes the downlink direction's own hop, which is the
		// encap's gate in every deployed graph.
		//
		// An uplink PDR forwarding toward the access side is indirect data
		// forwarding (TS 29.244 8.2.2 NOTE 2): the packets go back out of N3,
		// in a tunnel, toward the target gNB.
		if c.cfg.AccessNextHop != 0 {
			return c.cfg.AccessNextHop, nil
		}
		return c.cfg.Down.NextHop, nil

	case ie.DstInterfaceCore:
		egress, err := c.forwardEgress(far, ifc)
		if err != nil {
			return 0, err
		}
		if far.hasOuter {
			// An outer header and the core side is a tunnel out of the
			// instance: the far end of an N9 link, or the tunnel of an
			// indirect forward.
			if hop, ok := egress.Hop(routing.Egress{DestIfc: ie.DstInterfaceCore, Tunnel: true}); ok {
				return hop, nil
			}
			return 0, fmt.Errorf(
				"%w: the forward adds a tunnel out of %s, and this deployment declares no tunnel egress for it",
				errNotExpressible, egressName(egress, c.cfg.Instances))
		}
		// Plain IP out of the instance: the instance's own next hop is the
		// fallback, so a deployment that declares one egress per instance needs
		// no more keys than it always did.
		hop, ok := egress.Hop(routing.Egress{DestIfc: ie.DstInterfaceCore})
		if !ok {
			hop = c.baseHop(egress, dir)
		}
		if hop == 0 {
			// Nothing to forward by. An instance that declares no plain egress
			// is legal -- one that only re-injects (vn-next-hop) or only
			// tunnels has no data-network exit -- but a forward that needs one
			// has nowhere to go, and 0 is no Router next hop: the action record
			// would name a hop the Router drops, and the SMF's traffic would
			// disappear with no cause at the interface that could have named
			// the key. (For the one-instance deployment the hop is the
			// direction's own flag, which the same reasoning applies to.)
			what := "next-hop="
			if c.cfg.Instances == nil {
				what = "-n6-next-hop/-n3-next-hop"
			}
			return 0, fmt.Errorf(
				"%w: the forward leaves %s as plain IP, and this deployment declares no next hop for it (%s)",
				errNotExpressible, egressName(egress, c.cfg.Instances), what)
		}
		return hop, nil

	case ie.DstInterfaceSGiLANN6LAN:
		egress, err := c.forwardEgress(far, ifc)
		if err != nil {
			return 0, err
		}
		if hop, ok := egress.Hop(routing.Egress{DestIfc: ie.DstInterfaceSGiLANN6LAN, Tunnel: far.hasOuter}); ok {
			return hop, nil
		}
		if far.hasOuter {
			return 0, fmt.Errorf(
				"%w: the forward adds a tunnel toward SGi-LAN/N6-LAN, and this deployment declares no tunneled service-LAN egress for %s",
				errNotExpressible, egressName(egress, c.cfg.Instances))
		}
		return 0, fmt.Errorf(
			"%w: the forward names Destination Interface 2 (SGi-LAN/N6-LAN), and this deployment declares no service-LAN egress for %s",
			errNotExpressible, egressName(egress, c.cfg.Instances))

	case ie.DstInterface5GVNInternal:
		if far.hasOuter {
			// A re-injection is this UPF's own path: the packet goes back into
			// the subscriber-side chain, and there is no tunnel to add on the
			// way.
			return 0, fmt.Errorf(
				"%w: a forward toward 5G VN Internal (Destination Interface 5) re-enters this UP's own chain and adds no outer header",
				errNotExpressible)
		}
		egress, err := c.forwardEgress(far, ifc)
		if err != nil {
			return 0, err
		}
		if hop, ok := egress.Hop(routing.Egress{DestIfc: ie.DstInterface5GVNInternal}); ok {
			return hop, nil
		}
		return 0, fmt.Errorf(
			"%w: the forward names Destination Interface 5 (5G VN Internal), and this deployment declares no 5G VN egress for %s",
			errNotExpressible, egressName(egress, c.cfg.Instances))

	case ie.DstInterfaceCPFunction:
		// The CP function's own path (Table 8.2.24-1, value 3): a user plane
		// packet is not sent along it, and this UP has no such exit.
		return 0, fmt.Errorf(
			"%w: Destination Interface 3 (CP-function) is not one this UP serves", errNotExpressible)

	case ie.DstInterfaceLIFunction:
		// The lawful-interception exit (value 4): an X3 copy is a duplication
		// action, which is a different instruction from the forward this FAR
		// asks for.
		return 0, fmt.Errorf(
			"%w: Destination Interface 4 (LI Function) is not one this UP serves", errNotExpressible)

	default:
		// 6..15 are Spare (Table 8.2.24-1). merge refuses them for a FAR that
		// forwards; this is the same refusal for a record that reached resolve
		// by another path.
		return 0, fmt.Errorf(
			"%w: the FAR names Destination Interface value %d, which the spec leaves spare (Table 8.2.24-1)",
			errNotExpressible, far.destIfc)
	}
}

// destinationHop is egressHop for a Router in destination mode: the FAR's
// egress is not resolved to a next hop here -- the Router looks the packet's
// own destination up in its route domain -- so every forward that is
// expressible names hop 0. What stays this function's is the part the FIB
// cannot say: whether the Destination Interface value is one this UP serves,
// whether a re-injection adds an outer header, and whether the FAR forwards
// into the instance the packet was classified in.
//
// That last check is the mode's one real limit: the Router routes in the
// domain the packet carries (the ingress Vif wrote it), so a FAR that names a
// different egress instance would need the packet's domain rewritten between
// the table and the Router, which no module here does. Policy hops can express
// it; destination mode refuses it rather than routing in the wrong table.
func (c *Compiler) destinationHop(far *far, ifc routing.Interface) (uint32, error) {
	switch far.destIfc {
	case ie.DstInterfaceCPFunction, ie.DstInterfaceLIFunction:
		// CP-function and LI are refusals, as in hop mode.
		return c.destinationRefusal(far)

	case ie.DstInterfaceAccess, ie.DstInterfaceCore, ie.DstInterfaceSGiLANN6LAN, ie.DstInterface5GVNInternal:
		// Every expressible forward names hop 0: Access is the deployment's own
		// exit (the encap, or the indirect tunnel) and destination mode reaches
		// it by a route to its hop, so the action names none. The instance
		// check applies to Access too -- an Access FAR that names another
		// instance is exactly as unexpressible as a Core one: the Router routes
		// in the packet's own domain, and only the FAR's own egress being in
		// that domain keeps the access exit reachable.
		if far.destIfc == ie.DstInterface5GVNInternal && far.hasOuter {
			return 0, fmt.Errorf(
				"%w: a forward toward 5G VN Internal (Destination Interface 5) re-enters this UP's own chain and adds no outer header",
				errNotExpressible)
		}
		egress, err := c.forwardEgress(far, ifc)
		if err != nil {
			return 0, err
		}
		if egress.Domain != ifc.Domain {
			return 0, fmt.Errorf(
				"%w: the forward leaves %s, and destination routing looks the packet up in its own route domain (%s): a FAR that forwards into another instance needs policy next hops",
				errNotExpressible, egressName(egress, c.cfg.Instances),
				egressName(ifc, c.cfg.Instances))
		}
		return 0, nil
	}
	return c.destinationRefusal(far)
}

// destinationRefusal is the Destination Interface values destination mode
// refuses: the two this UP does not serve and the spare values, with the same
// wording hop mode uses.
func (c *Compiler) destinationRefusal(far *far) (uint32, error) {
	switch far.destIfc {
	case ie.DstInterfaceCPFunction:
		return 0, fmt.Errorf(
			"%w: Destination Interface 3 (CP-function) is not one this UP serves", errNotExpressible)
	case ie.DstInterfaceLIFunction:
		return 0, fmt.Errorf(
			"%w: Destination Interface 4 (LI Function) is not one this UP serves", errNotExpressible)
	}
	return 0, fmt.Errorf(
		"%w: the FAR names Destination Interface value %d, which the spec leaves spare (Table 8.2.24-1)",
		errNotExpressible, far.destIfc)
}

// baseHop is the hop an interface's plain egress falls back to when the
// deployment declares none for it: the instance's own next hop, and -- for the
// one-instance deployment, whose interface is the zero value -- the direction's.
func (c *Compiler) baseHop(ifc routing.Interface, dir Direction) uint32 {
	if c.cfg.Instances == nil {
		return dir.NextHop
	}
	return ifc.NextHop
}

// egressName names where a forward was to leave by, for a refusal: the network
// instance it resolved to, or the one-instance deployment when the deployment
// resolves no instances at all.
func egressName(ifc routing.Interface, d *routing.Domains) string {
	if d == nil {
		return "the network instance"
	}
	return fmt.Sprintf("the network instance %q", ifc.Instance)
}

// qerHeldByAPDR reports whether a PDR the session still has names this QER.
// Removing a QER the traffic of a live PDR is gated and metered by would leave
// that PDR with no gate and no meter -- enforcement the SMF asked for and
// silently did not get.
func qerHeldByAPDR(s *Session, id uint32) bool {
	for _, p := range s.PDRs {
		for _, qid := range p.qerIDs {
			if qid == id {
				return true
			}
		}
	}
	return false
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

func chosenNamed(s *Session, chosen chosenFTEID) bool {
	for _, p := range s.PDRs {
		if p.hasCHID && p.teid == chosen.TEID && p.endpointID == chosen.EndpointID &&
			p.srcIfc == chosen.SourceInterface && p.instance == chosen.Instance &&
			slices.Equal(p.endpointFamilies, chosen.Families) {
			return true
		}
	}
	return false
}

// fteidKeyNamed reports whether any live PDR in the session still references an
// exact family/address/endpoint/TEID admission key.
func fteidKeyNamed(s *Session, key map[string]any) bool {
	identity := fmt.Sprint(key)
	for _, p := range s.PDRs {
		if p.teid == 0 {
			continue
		}
		for _, owned := range fteidKeysOf(p) {
			if fmt.Sprint(owned) == identity {
				return true
			}
		}
	}
	return false
}

func (c *Compiler) claimFTEID(s *Session, p *pdr) error {
	keys := fteidKeysOf(p)
	identities := make([]string, len(keys))
	for i, key := range keys {
		identities[i] = fmt.Sprint(key)
		if owner, ok := c.byFTEID[identities[i]]; ok &&
			(owner.session != s || owner.down != p.down) {
			return fmt.Errorf("%w: F-TEID endpoint key is already owned", errNoResources)
		}
	}
	ctxKey := fteidContextKey{session: s, down: p.down, endpoint: p.endpointID, teid: p.teid}
	ctx := c.fteidContexts[ctxKey]
	if ctx == nil {
		id, err := c.contexts.alloc()
		if err != nil {
			return fmt.Errorf("%w: F-TEID context: %v", errNoResources, err)
		}
		ctx = &fteidContext{id: id}
		c.fteidContexts[ctxKey] = ctx
	}
	for _, key := range identities {
		if _, exists := c.byFTEID[key]; exists {
			continue
		}
		c.byFTEID[key] = fteidOwner{session: s, down: p.down}
		ctx.keys++
		if c.fteidTEIDKeys[p.teid] == nil {
			c.fteidTEIDKeys[p.teid] = map[string]bool{}
		}
		c.fteidTEIDKeys[p.teid][key] = true
	}
	p.fteidContext = ctx.id
	c.teids.reserve(p.teid)
	return nil
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
func (c *Compiler) releaseFTEIDClaim(s *Session, p *pdr, force bool) {
	if p.teid == 0 {
		return
	}
	removed := false
	for _, key := range fteidKeysOf(p) {
		identity := fmt.Sprint(key)
		if !force && fteidKeyNamed(s, key) {
			continue
		}
		owner, ok := c.byFTEID[identity]
		if !ok || owner.session != s {
			continue
		}
		delete(c.byFTEID, identity)
		delete(c.fteidTEIDKeys[p.teid], identity)
		removed = true
		ctxKey := fteidContextKey{session: s, down: owner.down, endpoint: p.endpointID, teid: p.teid}
		if ctx := c.fteidContexts[ctxKey]; ctx != nil {
			if ctx.keys--; ctx.keys <= 0 {
				delete(c.fteidContexts, ctxKey)
				c.contexts.release(ctx.id)
			}
		}
	}
	if removed && len(c.fteidTEIDKeys[p.teid]) == 0 {
		delete(c.fteidTEIDKeys, p.teid)
		if !sessionHasCHIDTEID(s, p.teid) {
			c.teids.release(p.teid)
		}
	}
}
func sessionHasCHIDTEID(s *Session, teid uint32) bool {
	for _, chosen := range s.chids {
		if chosen.TEID == teid {
			return true
		}
	}
	return false
}

// bufferCountersRes is the BUFF branch's counting module's counter resource.
func bufferCountersRes(b *Buffering) string { return b.Counter + "/counters" }

// flowRes is the store's per-flow resource: what the SMF's BAR asks this flow to
// hold (8.2.29's duration and 8.2.30's count), keyed by the rule's ActionId.
func flowsRes(b *Buffering) string { return b.Store + "/flows" }

// barOf is the BAR a PDR's FAR names, or nil when the FAR names none: the
// buffering instruction this flow's packets live under (TS 29.244 5.2.4.1,
// 8.2.55). A FAR that names no BAR has no SMF numbers of its own, and the
// store's module-wide arguments are the instruction for its flow.
func barOf(s *Session, far *far) *bar {
	if far == nil || !far.hasBAR {
		return nil
	}
	return s.BARs[far.barID]
}

// writeFlowEntry writes the store's per-flow "flows" entry for a PDR that
// buffers: the numbers the SMF's BAR gives this flow -- 8.2.29's DL Buffering
// Duration as the store's timeout_ns and 8.2.30's DL Buffering Suggested Packet
// Count as its max_packets_per_flow -- keyed by the same ActionId the rule
// carries and the counter in front of the store is keyed by (BESS D-129), so
// one id resolves the rule, its flow and the SMF's own numbers for it.
//
// A parameter the SMF did not name is left out of the entry rather than written
// as zero: an absent field leaves the module's argument in force, a present
// timeout_ns of zero means this flow never expires, and a present
// max_packets_per_flow of zero means the module-wide per-flow default. The
// deactivated timer and the infinite unit are exactly that distinction, so the
// entry carries whatever the model holds and nothing more. The entry itself is
// written with the rule either way, so its life follows the PDR's (compile and
// a deletion erase it with the branch's counter).
func writeFlowEntry(b *Buffering, bar *bar, p *pdr) []bess.Change {
	if b == nil || b.Store == "" || p.actionID == 0 {
		return nil
	}
	value := map[string]any{}
	if ns, ok := bar.timeoutNS(); ok {
		value["timeout_ns"] = ns
	}
	if bar != nil && bar.hasCount {
		value["max_packets_per_flow"] = bar.count
	}
	return []bess.Change{{
		Resource: flowsRes(b),
		Key:      map[string]any{"id": p.actionID},
		Value:    value,
	}}
}

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
// qerHoldsMeter says a session's QERs still resolve to a meter id: the
// removal's erase of a PDR's meters is guarded by it, so a meter another PDR's
// QER still polices stays.
func qerHoldsMeter(s *Session, id uint32) bool {
	for _, q := range s.QERs {
		if q.meterUL == id || q.meterDL == id {
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

	// Admission is keyed by the complete endpoint/family/local-address/TEID
	// tuple. PDRs in one session that share that F-TEID write one resource row;
	// direction is its only value.
	writtenFTEIDs := map[string]bool{}
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
		dir := c.direction(p)
		if keys, err := p.ruleKeys(dir.PDRFields); err == nil {
			for _, key := range keys {
				live[rulesRes(dir)+"\x00"+fmt.Sprint(key)] = true
			}
		}
	}
	// The ARP entries the session still holds: one per subscriber address its
	// subscriber-side PDRs name, where the interface declares a responder. A
	// replaced form whose address is in this set is not erased -- the entry is
	// the same entry, written again.
	liveARP := map[string]bool{}
	for _, p := range s.PDRs {
		if e, ok := c.arpEntryOf(p); ok {
			liveARP[e.claim()] = true
		}
	}
	// The counter entries the session still needs, as the transaction will write
	// them: one per forwarding PDR a URR measures. A removal or a replaced form
	// whose entry is in this set is not erased -- the write follows, and the
	// engine rejects both operations on one key.
	liveCounters := map[string]bool{}
	for _, p := range s.PDRs {
		dir := c.direction(p)
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
	//   - an F-TEID admission entry only when no PDR of the session still uses
	//     its full key;
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
		dir := c.direction(p)
		if dir.Counters == "" || len(p.urrIDs) == 0 || p.actionID == 0 {
			return
		}
		if liveCounters[countersRes(dir)+"\x00"+strconv.FormatUint(uint64(p.actionID), 10)] {
			return
		}
		erase(bess.Change{Resource: countersRes(dir), Key: map[string]any{"action_id": p.actionID}})
	}
	// liveBuffering is the set of ActionIds a live PDR of this session buffers
	// under: the entries of both the BUFF branch's counter and the store's
	// "flows" table follow that PDR, and an entry a live flow still needs must
	// not be erased in the transaction that writes it.
	liveBuffering := map[uint32]bool{}
	if c.cfg.Buffering != nil {
		for _, p := range s.PDRs {
			if p.buffer && p.actionID != 0 {
				liveBuffering[p.actionID] = true
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
		if liveBuffering[p.actionID] {
			return
		}
		erase(bess.Change{Resource: bufferCountersRes(c.cfg.Buffering),
			Key: map[string]any{"action_id": p.actionID}})
	}
	// flowEntryErase is the same for the store's "flows" entry: it holds the
	// SMF's own numbers for the flow, and a flow that no longer buffers (or
	// goes) must not leave them behind for the next session that reuses the id.
	// It is configuration only -- the store's release and drop commands are what
	// free the packets a flow held (5.2.4.1).
	flowEntryErase := func(p *pdr) {
		if !p.buffer || p.actionID == 0 || c.cfg.Buffering == nil || c.cfg.Buffering.Store == "" {
			return
		}
		if liveBuffering[p.actionID] {
			return
		}
		erase(bess.Change{Resource: flowsRes(c.cfg.Buffering),
			Key: map[string]any{"id": p.actionID}})
	}
	for _, p := range s.removed {
		dir := c.direction(p)
		keys, err := p.ruleKeys(dir.PDRFields)
		if err != nil {
			return nil, nil, fmt.Errorf("removed PDR %d: %w", p.id, err)
		}
		for _, key := range keys {
			if !live[rulesRes(dir)+"\x00"+fmt.Sprint(key)] {
				erase(bess.Change{Resource: rulesRes(dir), Key: key})
			}
		}
		if e, ok := c.arpEntryOf(p); ok && !liveARP[e.claim()] {
			// The subscriber address this PDR answered for is gone from the
			// session: the entry goes with it, or the segment would keep
			// resolving an address this UPF no longer carries.
			erase(e.erasure())
		}
		for _, t := range p.tunnels {
			erase(bess.Change{Resource: t, Key: map[string]any{"action_id": p.actionID}})
		}
		for _, t := range p.writtenTunnels {
			erase(bess.Change{Resource: t, Key: map[string]any{"action_id": p.actionID}})
		}
		if p.teid != 0 {
			for _, key := range fteidKeysOf(p) {
				if !fteidKeyNamed(s, key) {
					erase(bess.Change{Resource: c.teidRes(), Key: key})
				}
			}
		}
		// A removed PDR's meters go only when no QER of the session still holds
		// them. The PDR result carries both meter IDs; the chosen one may be the
		// own one (a PDR naming no shared QER), so a repeat is skipped rather than
		// erased twice.
		prev := uint32(0)
		for _, id := range []uint32{p.meterID, p.ownMeterID} {
			if id != 0 && id != prev && !qerHoldsMeter(s, id) {
				erase(bess.Change{Resource: metersRes(dir), Key: map[string]any{"id": id}})
			}
			prev = id
		}
		counterErase(p)
		bufferCounterErase(p)
		flowEntryErase(p)
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
	// must not go on being read. The store's "flows" entry goes with it: the
	// numbers are the instruction for an episode that is over.
	for _, id := range s.ending {
		if liveBuffering[id] {
			continue
		}
		if c.BufferingConfigured() && id != 0 {
			erase(bess.Change{Resource: bufferCountersRes(c.cfg.Buffering),
				Key: map[string]any{"action_id": id}})
		}
		if c.cfg.Buffering != nil && c.cfg.Buffering.Store != "" && id != 0 {
			erase(bess.Change{Resource: flowsRes(c.cfg.Buffering),
				Key: map[string]any{"id": id}})
		}
	}
	for _, old := range s.stale {
		dir := c.direction(old)
		keys, err := old.ruleKeys(dir.PDRFields)
		if err != nil {
			return nil, nil, fmt.Errorf("PDR %d: %w", old.id, err)
		}
		for _, key := range keys {
			if !live[rulesRes(dir)+"\x00"+fmt.Sprint(key)] {
				erase(bess.Change{Resource: rulesRes(dir), Key: key})
			}
		}
		if e, ok := c.arpEntryOf(old); ok && !liveARP[e.claim()] {
			// A replaced form whose subscriber address moved: the entry it
			// answered for goes, the same guard as the removed form above.
			erase(e.erasure())
		}
		if old.teid != 0 {
			for _, key := range fteidKeysOf(old) {
				if !fteidKeyNamed(s, key) {
					erase(bess.Change{Resource: c.teidRes(), Key: key})
				}
			}
		}
		counterErase(old)
		bufferCounterErase(old)
		flowEntryErase(old)
	}

	// Meters first: an action references the meter its QER resolved to. One
	// record per policed direction, each a two-rate three-colour meter with the
	// QER's own rate committed and peak (the same value twice: a QER's MBR
	// allows a rate, not an excess), and a tenth of a second of burst.
	for _, q := range qersInOrder(s) {
		if !q.hasRate {
			continue
		}
		// One entry per policed direction, and only where the SMF capped
		// something: a zero rate is not a profile any meter holds (the
		// module refuses a zero committed rate), and a direction with no cap
		// is exactly that -- nothing to enforce.
		if q.meterUL != 0 && q.mbUL != 0 {
			changes = append(changes, meterChange(metersRes(c.cfg.Up), q.meterUL, q.gbUL, q.mbUL, q.window))
		}
		if q.meterDL != 0 && q.mbDL != 0 {
			changes = append(changes, meterChange(metersRes(c.cfg.Down), q.meterDL, q.gbDL, q.mbDL, q.window))
		}
	}

	for _, p := range pdrsInOrder(s) {
		// Admission remains live even while a PDR drops or buffers. It is
		// ingress ownership, not a forwarding action.
		if p.teid != 0 {
			direction := uint32(0)
			if p.down {
				direction = 1
			}
			for _, key := range fteidKeysOf(p) {
				keyID := fmt.Sprint(key)
				if writtenFTEIDs[keyID] {
					continue
				}
				writtenFTEIDs[keyID] = true
				changes = append(changes, bess.Change{
					Resource: c.teidRes(), Key: key,
					Value: map[string]any{"direction": direction, "context_id": p.fteidContext},
				})
			}
			created = append(created, ie.NewCreatedPDR(
				ie.NewPDRID(p.id), c.createdFTEID(p)))
		}
		dir := c.direction(p)
		keys, err := p.ruleKeys(dir.PDRFields)
		if err != nil {
			return nil, nil, fmt.Errorf("PDR %d: %w", p.id, err)
		}
		for _, key := range keys {
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
		}
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
			}
			result := make([]byte, p.resultSize())
			if action != 0 {
				result = pdrResult(p)
			}
			for _, key := range keys {
				changes = append(changes, bess.Change{
					Resource: rulesRes(dir),
					Key:      key,
					Value: map[string]any{
						"priority": rulePriority(p.precedence),
						"gate":     gate,
						"result":   result,
					},
				})
			}
			// A URR that measures this PDR still holds its counter entry: the
			// entry says the rule is measured (the reporting side reads it), and
			// its existence must follow the PDR rather than the rule's effect,
			// so that a later erase has something to erase. The counter counts
			// nothing while the rule drops: no packet reaches the action.
			changes = append(changes, writeCounter(p, dir)...)
			if p.buffer {
				changes = append(changes, writeBufferCounter(c.cfg.Buffering, p)...)
				changes = append(changes, writeFlowEntry(c.cfg.Buffering, barOf(s, s.FARs[p.farID]), p)...)
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

		// A PDR a URR measures carries one counter entry, keyed by the same
		// ActionId: the module counts what the chain forwards for that rule,
		// and the reporting side sums the entries of the URR's PDRs. The entry
		// is what keeps a session without a URR off the counting module's cost.
		changes = append(changes, writeCounter(p, dir)...)

		// An outer GTP-U tunnel is routed by the post-encap Router. The
		// record carries only the local/peer IP endpoints and the transport
		// route domain; the Router resolves the neighbor and rewrites Ethernet.
		// A record the action held under its previous FAR and no longer needs
		// goes, or a later rebind to an encap path would find it stale.
		for _, resource := range p.writtenTunnels {
			if !slices.Contains(p.tunnels, resource) {
				erase(bess.Change{Resource: resource, Key: map[string]any{"action_id": p.actionID}})
			}
		}
		p.writtenTunnels = p.tunnels
		for _, resource := range p.tunnels {
			far := s.FARs[p.farID]
			value := map[string]any{
				"teid":                   far.teid,
				"local_address":          p.tunnelLocalAddress.AsSlice(),
				"peer_address":           far.peer.AsSlice(),
				"transport_route_domain": p.transportRouteDomain,
			}
			if p.hasEncapQFI {
				// QFI 0 is valid; qfi_present distinguishes it from no QFI.
				value["qfi"] = uint32(p.encapQFI)
				value["qfi_present"] = true
			}
			if far.hasMarking {
				// The FAR's Transport Level Marking (8.2.12): the ToS/Traffic
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

		// One rule per (SDF filter, QFI) the PDI names -- TS 29.244 7.5.2.2
		// NOTE 4: several of either match any -- all with this PDR's
		// Precedence and its one action.
		for _, key := range keys {
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
					"priority": rulePriority(p.precedence),
					"gate":     uint64(0),
					"result":   pdrResult(p),
				},
			})
		}

	}
	// The MAR policies and the tunnel records their accesses name, before the
	// DL rules whose result carries the policy id: a rule's steering id is
	// read by AtsssSteer, whose policy must be live by the time the rule
	// selects a packet.
	marWrites, err := c.marChanges(s)
	if err != nil {
		return nil, nil, err
	}
	changes = append(changes, marWrites...)
	// The subscriber's ARP entries, claimed the same way: one per address the
	// session's subscriber-side PDRs name, on the interface that declares a
	// responder. An address another session answers for is refused here rather
	// than written -- the second write would take the first session's traffic,
	// and by the time the mistake showed, the SMF would have been told both
	// sessions stand.
	for _, e := range c.arpEntries(s) {
		claim := e.claim()
		if owner, taken := c.rules[claim]; taken && owner != s.LocalSEID {
			return nil, nil, fmt.Errorf(
				"%w: the subscriber address %s on %s is session %d's", errNotExpressible, e.addr, e.module, owner)
		}
		if _, held := c.rules[claim]; !held {
			claimed = append(claimed, claim)
			if !s.holdsRuleKey(claim) {
				s.ruleKeys = append(s.ruleKeys, claim)
			}
		}
		c.rules[claim] = s.LocalSEID
		changes = append(changes, e.change())
	}
	committed = true
	return changes, created, nil
}

// marChanges writes the session's MAR policies and the tunnel records their
// accesses name. It is a no-op for a deployment without steering, which is
// every deployment before -atsss; a MAR PDR is refused in resolve when the
// module is absent.
func (c *Compiler) marChanges(s *Session) ([]bess.Change, error) {
	if c.cfg.Atsss == "" || (len(s.MARs) == 0 && len(s.removedMARs) == 0) {
		return nil, nil
	}
	changes := make([]bess.Change, 0, 2*len(s.MARs)+1)
	seen := map[string]bool{}
	add := func(ch bess.Change) {
		key := ch.Resource + "\x00" + fmt.Sprint(ch.Key)
		if seen[key] {
			return
		}
		seen[key] = true
		changes = append(changes, ch)
	}
	policyRes := c.cfg.Atsss + "/policies"
	for _, id := range idsOf(s.MARs) {
		m := s.MARs[id]
		accesses := make([]map[string]any, 0, 2)
		for which := 0; which < 2; which++ {
			access := m.accesses[which]
			healthID := uint32(0)
			nextHop, tunnelID := m.nextHops[which], m.tunnelIDs[which]
			if access.hasFarID && access.priority != ie.PriorityNoStandby {
				healthID = uint32(which + 1)
			} else {
				// A missing access and a "No Standby" access are both
				// ineligible; the packet path skips a zero health id.
				nextHop, tunnelID = 0, 0
			}
			accesses = append(accesses, map[string]any{
				"next_hop_id":   nextHop,
				"tunnel_id":     tunnelID,
				"accounting_id": uint32(0),
				// The deployment's two access health records. The compiler
				// does not write them: their availability is the controller's
				// or operator's observation, not the SMF's session.
				"health_id": healthID,
			})
			if m.tunnelIDs[which] == 0 {
				continue
			}
			far := s.FARs[access.farID]
			if far == nil {
				return nil, fmt.Errorf("MAR %d's %s access names FAR %d, which the session does not hold",
					m.id, []string{"3GPP", "non-3GPP"}[which], access.farID)
			}
			value := map[string]any{
				"teid":                   far.teid,
				"local_address":          m.tunnelLocalAddresses[which].AsSlice(),
				"peer_address":           far.peer.AsSlice(),
				"transport_route_domain": m.transportRouteDomains[which],
			}
			if far.hasMarking {
				value["marking"] = uint32(far.marking)
			}
			add(bess.Change{
				Resource: tunnelsRes(c.cfg.Down),
				Key:      map[string]any{"action_id": m.tunnelIDs[which]},
				Value:    value,
			})
		}
		add(bess.Change{
			Resource: policyRes,
			Key:      map[string]any{"policy_id": m.policyID},
			Value: map[string]any{
				"mode":      uint32(0),
				"preferred": m.preferred,
				"access":    accesses,
			},
		})
	}
	for _, m := range s.removedMARs {
		if m.policyID != 0 {
			add(bess.Change{Resource: policyRes, Key: map[string]any{"policy_id": m.policyID}})
		}
		for _, id := range m.tunnelIDs {
			if id != 0 {
				add(bess.Change{Resource: tunnelsRes(c.cfg.Down), Key: map[string]any{"action_id": id}})
			}
		}
	}
	for _, id := range s.retiredTunnels {
		add(bess.Change{Resource: tunnelsRes(c.cfg.Down), Key: map[string]any{"action_id": id}})
	}
	return changes, nil
}

// rulePriority is the classifier's priority for a PDR's Precedence (TS 29.244
// 8.2.11): the two orderings are opposite. The spec has the *lower* Precedence
// value win -- "the lower precedence values indicate higher precedence of the
// PDR, and the higher precedence values indicate lower precedence of the PDR
// when matching a packet" -- while WildcardMatch applies the rule with the
// *higher* priority ("If a packet matches multiple rules, the rule with higher
// priority will be applied", module_msg.proto:347). The Precedence is therefore
// inverted into the classifier's space, and it is inverted here, in one place,
// The two PDR tables use this value; F-TEID admission entries are not classifier
// rules and carry no precedence.
func rulePriority(precedence uint32) int64 {
	return math.MaxUint32 - int64(precedence)
}

// ruleKey is the WildcardMatch rule key for a PDR: for every field of the
// table, the mask the PDI constrains it with, and the value the packet must
// carry. A field the PDI does not name is masked out, which is what lets one
// table hold PDRs of different shapes. A field the PDI constrains to a range
// (an SDF filter's ports) is masked out too and named in the key's ranges
// (BESS D-186: a ranged field's mask is zero, so the range costs no tuple).
//
// The value must be canonical (value & ^mask == 0), and the key is the
// concatenation of mask then value per field, then the ranges.
func (p *pdr) ruleKey(fields []Field) (map[string]any, error) {
	// The table's key message is WildcardMatchRuleKey: one FieldData per
	// field, values and masks in two parallel lists, and the ranges by field
	// index (protobuf JSON, which is how the SDK builds it: a bytes field is
	// base64).
	values := make([]map[string]any, 0, len(fields))
	masks := make([]map[string]any, 0, len(fields))
	var ranges []map[string]any
	for i, f := range fields {
		width := f.width()
		mask := make([]byte, width)
		value := make([]byte, width)
		m, ok, err := p.matchValue(f)
		if err != nil {
			return nil, fmt.Errorf("the PDI's %s: %w", f, err)
		}
		switch {
		case ok && m.ranged:
			ranges = append(ranges, map[string]any{"field": uint32(i), "low": m.low, "high": m.high})
		case ok:
			copy(mask, m.mask)
			copy(value, m.value)
		}
		values = append(values, map[string]any{"value_bin": value})
		masks = append(masks, map[string]any{"value_bin": mask})
	}
	key := map[string]any{"values": values, "masks": masks}
	if len(ranges) > 0 {
		key["ranges"] = ranges
	}
	return key, nil
}

// variants is the PDR as one match per (SDF filter, QFI) its PDI names. A PDI
// may carry several SDF Filter IEs and several QFI IEs, and "match any" is the
// rule for each (TS 29.244 7.5.2.2-2, NOTE 4): the PDR matches a packet that
// any filter and any QFI of it matches. A matcher holds one filter and one QFI
// per rule, so the PDR is a set of rules that share its Precedence and its one
// action. Each variant is a copy whose sdf, hasQFI and qfi are the one it
// stands for; a PDI that names neither is the single variant that constrains
// nothing, which is what a PDR always was.
func (p *pdr) variants() []*pdr {
	sdfs := p.sdfs
	if len(sdfs) == 0 {
		sdfs = []*sdfFilter{nil}
	}
	qfis := max(len(p.qfis), 1)
	out := make([]*pdr, 0, len(sdfs)*qfis)
	for _, sd := range sdfs {
		for i := range qfis {
			v := *p
			v.sdf = sd
			v.hasQFI = len(p.qfis) > 0
			v.qfi = 0
			if v.hasQFI {
				v.qfi = p.qfis[i]
			}
			out = append(out, &v)
		}
	}
	return out
}

// ruleKeys is the WildcardMatch rule key of each variant, without the repeats:
// two identical filters in one PDI are one rule, not a key written twice.
func (p *pdr) ruleKeys(fields []Field) ([]map[string]any, error) {
	variants := p.variants()
	keys := make([]map[string]any, 0, len(variants))
	seen := make(map[string]bool, len(variants))
	for _, v := range variants {
		key, err := v.ruleKey(fields)
		if err != nil {
			return nil, err
		}
		id := fmt.Sprint(key)
		if seen[id] {
			continue
		}
		seen[id] = true
		keys = append(keys, key)
	}
	return keys, nil
}

// match is one field's constraint: the bits a PDI fixes, and the mask that says
// which of them matter. The two differ where the PDI names a prefix -- an SDF
// filter's "to 10.10.0.0/16" is a rule about a /16, not about the address
// 10.10.0.0 -- and the mask is what makes it so. A ranged constraint (an SDF
// filter's "1000-2000") is the inclusive bounds instead, with no mask.
type match struct {
	value     []byte
	mask      []byte
	ranged    bool
	low, high uint64
}

// ones is a mask of n bytes, all bits set.
func ones(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = 0xff
	}
	return b
}

// portMatch is an SDF filter's port constraint (8.2.5's "port" or
// "port-port"): one port is a masked value, a range is a WildcardMatch range,
// and the whole domain constrains nothing -- the form BESS reads back, since it
// drops a range over a field's whole domain (D-186).
func portMatch(lo, hi uint16) (match, bool, error) {
	switch {
	case lo == hi:
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, lo)
		return match{value: b, mask: ones(2)}, true, nil
	case lo == 0 && hi == math.MaxUint16:
		return match{}, false, nil
	default:
		return match{ranged: true, low: uint64(lo), high: uint64(hi)}, true, nil
	}
}

// ueAddr reports whether this PDI address names the subscriber's address.
// The Access-side destination form can instead name another node (e.g. a CP
// function); all other explicit UE IP addresses, and an inherited address,
// identify the subscriber.
func (p *pdr) ueAddr() bool {
	if !p.ueIP.IsValid() {
		return false
	}
	return p.srcIfc != ie.SrcInterfaceAccess || !p.hasUEIP || !p.ueIPDst
}

// ueIPIsDestination is the packet side constrained by the PDI's UE address.
// An inherited address follows the resolved packet direction.
func (p *pdr) ueIPIsDestination() bool {
	if p.hasUEIP {
		return p.ueIPDst
	}
	return p.downlink()
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
	if p.sdf != nil && p.sdf.bare {
		return match{}, false, fmt.Errorf("%w: SDF Filter ID %d was never resolved to a flow description", errNotExpressible, p.sdf.id)
	}
	// The filter as the packets this PDR selects carry it: the SMF provisions
	// the downlink form on both PDRs, and an ACCESS PDR's is swapped (5.2.1A.2A).
	sd := p.oriented()
	switch f {
	case SrcIP:
		// The uplink's UE address is the source unless the (swapped) filter
		// names another. A downlink PDR's SDF may name either side; when it
		// names no source, the source stays unconstrained -- the peer on the
		// data network is not the UE, so constraining this field to the SDF's
		// *destination* would demand the UE's address on both sides and match
		// no packet at all.
		if p.srcIfc == ie.SrcInterfaceAccess {
			if sd != nil && sd.srcOK && !sd.srcAssigned {
				m, err := pref(sd.src)
				return m, err == nil, err
			}
			if p.ueIPDst {
				// 8.2.62's bit 3: this PDI's address is a destination, so
				// this side is whatever the filter names or open -- the
				// address belongs in the other field.
				return match{}, false, nil
			}
			return host(p.ueIP)
		}
		if sd != nil && sd.srcAssigned {
			if p.ueIPIsDestination() {
				return match{}, false, fmt.Errorf(
					"%w: the PDI's UE IP address %s is the destination and the SDF filter makes it the source",
					errNotExpressible, p.ueIP)
			}
			return host(p.ueIP)
		}
		if sd != nil && sd.srcOK {
			m, err := pref(sd.src)
			return m, err == nil, err
		}
		if !p.ueIPIsDestination() {
			return host(p.ueIP)
		}
		return match{}, false, nil
	case DstIP:
		if p.srcIfc == ie.SrcInterfaceAccess {
			// The address this PDI named as its destination (8.2.62 bit 3) is
			// this field's, and a filter naming another destination is a
			// contradiction one key cannot carry.
			if p.ueIPDst {
				// A filter that names a destination containing this address
				// says nothing the exact address does not (the tighter of the
				// two is the address); one naming a destination outside it
				// describes a packet the key has no room for.
				if sd != nil && sd.dstOK && !sd.dstAssigned && !sd.dst.Contains(p.ueIP) {
					return match{}, false, fmt.Errorf(
						"%w: the PDI's UE IP address %s is the destination and the SDF filter names %s",
						errNotExpressible, p.ueIP, sd.dst)
				}
				return host(p.ueIP)
			}
			// The uplink is chosen by its UE address (the source); its
			// destination is whatever the swapped filter names -- the peer on
			// the data network -- or open.
			if sd != nil && sd.dstAssigned {
				return host(p.ueIP)
			}
			if sd != nil && sd.dstOK {
				m, err := pref(sd.dst)
				return m, err == nil, err
			}
			return match{}, false, nil
		}
		if sd != nil && sd.dstAssigned {
			if !p.ueIPIsDestination() {
				return match{}, false, fmt.Errorf(
					"%w: the PDI's UE IP address %s is the source and the SDF filter makes it the destination",
					errNotExpressible, p.ueIP)
			}
			return host(p.ueIP)
		}
		if sd != nil && sd.dstOK {
			m, err := pref(sd.dst)
			return m, err == nil, err
		}
		if p.ueIPIsDestination() {
			return host(p.ueIP)
		}
		return match{}, false, nil
	case Proto:
		if sd != nil && sd.protoOK {
			return match{value: []byte{sd.proto}, mask: ones(1)}, true, nil
		}
		return match{}, false, nil
	case SrcPort:
		if sd != nil && sd.sportOK {
			return portMatch(sd.sportLo, sd.sportHi)
		}
		return match{}, false, nil
	case DstPort:
		if sd != nil && sd.dportOK {
			return portMatch(sd.dportLo, sd.dportHi)
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
		// A tunneled packet has no inner route-domain tag before its PDR is
		// selected; the PDI's Network Instance is written as the result below.
		// Plain-interface ingress receives its route domain from the attachment
		// and uses it to keep overlapping instances apart.
		if p.hasFTEID {
			return match{}, false, nil
		}
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, p.domain)
		return match{value: b, mask: ones(4)}, true, nil
	case FTEIDContext:
		// The decap's exact admission (endpoint, family, local address, TEID)
		// already ran; its entry's context id is the whole tunnel identity.
		if p.teid == 0 {
			return match{}, false, nil
		}
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, p.fteidContext)
		return match{value: b, mask: ones(4)}, true, nil
	default:
		return match{}, false, nil
	}
}

// createdPDRsFor is the Created PDRs of a Modification Response: the tunnel of
// each PDR whose PDI asked the UP function to choose it in this request.
func (s *Session) createdPDRsFor(cfg Config, asked map[uint16]bool) []*ie.IE {
	c := &Compiler{cfg: cfg}
	var out []*ie.IE
	for _, p := range pdrsInOrder(s) {
		if p.teid != 0 && asked[p.id] {
			out = append(out, ie.NewCreatedPDR(ie.NewPDRID(p.id), c.createdFTEID(p)))
		}
	}
	return out
}

// createdPDRs is what the response re-states on a retransmission.
func (s *Session) createdPDRs(cfg Config) []*ie.IE {
	c := &Compiler{cfg: cfg}
	out := make([]*ie.IE, 0, len(s.PDRs))
	for _, p := range pdrsInOrder(s) {
		if p.teid != 0 {
			out = append(out, ie.NewCreatedPDR(ie.NewPDRID(p.id), c.createdFTEID(p)))
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
		req.CreateMAR,
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
		req.CreateMAR, req.UpdateMAR, req.RemoveMAR,
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
func parseCreate(ies []*ie.IE) ([]pdrReq, []farReq, []barReq, []qerReq, []urrReq, []marReq, error) {
	var pdrs []pdrReq
	var fars []farReq
	var bars []barReq
	var qers []qerReq
	var urrs []urrReq
	var mars []marReq
	for _, i := range ies {
		switch i.Type {
		case ie.CreatePDR, ie.UpdatePDR:
			p, err := parsePDR(i)
			if err != nil {
				return nil, nil, nil, nil, nil, nil, err
			}
			pdrs = append(pdrs, p)
		case ie.CreateFAR, ie.UpdateFAR:
			f, err := parseFAR(i)
			if err != nil {
				return nil, nil, nil, nil, nil, nil, err
			}
			fars = append(fars, f)
		case ie.CreateBAR, ie.UpdateBARWithinSessionModificationRequest,
			ie.UpdateBARWithinSessionReportResponse:
			b, err := parseBAR(i)
			if err != nil {
				return nil, nil, nil, nil, nil, nil, err
			}
			bars = append(bars, b)
		case ie.CreateQER, ie.UpdateQER:
			q, err := parseQER(i)
			if err != nil {
				return nil, nil, nil, nil, nil, nil, err
			}
			qers = append(qers, q)
		case ie.CreateURR, ie.UpdateURR:
			u, err := parseURR(i)
			if err != nil {
				return nil, nil, nil, nil, nil, nil, err
			}
			urrs = append(urrs, u)
		case ie.CreateMAR, ie.UpdateMAR:
			m, err := parseMAR(i)
			if err != nil {
				return nil, nil, nil, nil, nil, nil, err
			}
			mars = append(mars, m)
		}
	}
	return pdrs, fars, bars, qers, urrs, mars, nil
}

// parseRemovals reads the PDR, FAR, BAR and URR ids a modification removes.
// requestedWindows is the windows of the URRs a modification asks the usage of:
// the ones a Query URR IE names, or all of them for the QAURR flag, and the
// ones the request removes (a URR "removed" that the session never held is the
// merge's to refuse, not a report). A queried URR the session does not hold is
// refused: an SMF that asks for the usage of a URR this UP lacks has the
// wrong picture of the session. A URR both queried and removed is reported
// once, as removed.
func (c *Compiler) requestedWindows(ctx context.Context, req *message.SessionModificationRequest, s *Session,
	removeURRs []uint32, now time.Time) (queried, removed []urrWindow, err error) {
	var ask []uint32
	for _, f := range modificationFlags(req) {
		if f != nil && f.HasQAURR() {
			ask = urrIDsInOrder(s)
			break
		}
	}
	if ask == nil {
		for _, q := range req.QueryURR {
			children, err := q.QueryURR()
			if err != nil {
				return nil, nil, fmt.Errorf("%w: Query URR: %v", errNotExpressible, err)
			}
			for _, child := range children {
				if child.Type != ie.URRID {
					continue
				}
				id, err := child.URRID()
				if err != nil {
					return nil, nil, fmt.Errorf("%w: Query URR: %v", errNotExpressible, err)
				}
				if s.URRs[id] == nil {
					return nil, nil, fmt.Errorf("%w: Query URR names URR %d, which the session does not hold", errNotExpressible, id)
				}
				ask = append(ask, id)
			}
		}
	}
	ask = slices.DeleteFunc(ask, func(id uint32) bool { return slices.Contains(removeURRs, id) })
	if len(ask) > 0 {
		if queried, err = c.windowsOf(ctx, s, ask, now, sinceReport); err != nil {
			return nil, nil, err
		}
	}
	held := make([]uint32, 0, len(removeURRs))
	for _, id := range removeURRs {
		if s.URRs[id] != nil {
			held = append(held, id)
		}
	}
	if len(held) > 0 {
		// The removal goes ahead whatever the counters say: the URR is going,
		// and an unreadable one leaves the response without its report.
		if removed, err = c.windowsOf(ctx, s, held, now, sinceReport); err != nil {
			c.log.Warn("session: no termination usage report for a removed URR", "seid", s.LocalSEID, "error", err)
			removed, err = nil, nil
		}
	}
	return queried, removed, nil
}

// removals is the objects a Session Modification Request removes: the four
// kinds of rule the session holds, each by its own id. A struct rather than a
// list of returns because a message may remove any mixture of them, and the
// order they are folded in is merge's business, not the parser's.
type removals struct {
	pdrs []uint16 // Remove PDR (7.5.4.1)
	fars []uint32 // Remove FAR (7.5.4.3)
	bars []uint8  // Remove BAR (7.5.4.5)
	qers []uint32 // Remove QER (7.5.4.6)
	urrs []uint32 // Remove URR (7.5.4.4)
	mars []uint16 // Remove MAR (7.5.4.7)
}

func parseRemovals(ies []*ie.IE) removals {
	var rm removals
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
					rm.pdrs = append(rm.pdrs, id)
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
					rm.fars = append(rm.fars, id)
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
					rm.bars = append(rm.bars, id)
				}
			}
		case ie.RemoveQER:
			children, err := i.RemoveQER()
			if err != nil {
				continue
			}
			for _, c := range children {
				if c.Type != ie.QERID {
					continue
				}
				if id, err := c.QERID(); err == nil {
					rm.qers = append(rm.qers, id)
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
					rm.urrs = append(rm.urrs, id)
				}
			}
		case ie.RemoveMAR:
			children, err := i.RemoveMAR()
			if err != nil {
				continue
			}
			for _, c := range children {
				if c.Type != ie.MARID {
					continue
				}
				if id, err := c.MARID(); err == nil {
					rm.mars = append(rm.mars, id)
				}
			}
		}
	}
	return rm
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
				p.id, p.hasID = id, true
			}
		case ie.Precedence:
			if v, err := c.Precedence(); err == nil {
				p.precedence = v
			}
		case ie.FARID:
			if id, err := c.FARID(); err == nil {
				p.farID, p.hasFarID = id, true
			}
		case ie.MARID:
			// The MAR this PDR is steered by (8.2.34). The MAR's two access
			// actions replace the PDR's own FAR; a message that names both is
			// refused below rather than choosing one silently.
			if id, err := c.MARID(); err == nil {
				p.marID, p.hasMAR = id, true
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
	if !p.hasID {
		return pdrReq{}, errors.New("PDR without a PDR ID")
	}
	if p.hasMAR {
		if p.marID == 0 {
			return pdrReq{}, fmt.Errorf(
				"%w: PDR %d names MAR 0, which is no policy", errNotExpressible, p.id)
		}
		if p.hasFarID {
			return pdrReq{}, fmt.Errorf(
				"%w: PDR %d names both a FAR and a MAR; the MAR's access actions are the egress (TS 29.244 7.5.2.8)",
				errNotExpressible, p.id)
		}
		return p, nil
	}
	if !p.hasFarID {
		// The PDR's FAR ID is mandatory (Table 7.5.2.2-1), and it is read as a
		// flag because FAR 0 is a legal FAR: a PDR that carried none would
		// otherwise resolve to the session's FAR 0 and forward, drop or buffer
		// by another rule's instruction.
		return pdrReq{}, fmt.Errorf(
			"%w: PDR %d names no FAR, and the FAR ID is mandatory (Table 7.5.2.2-1)",
			errMandatoryIE, p.id)
	}
	return p, nil
}

// parseMAR reads a Create MAR or Update MAR. Only the active/standby steering
// mode and ATSSS-LL are compiled: the other modes choose an access by a rule
// this datapath does not have, and accepting one would program a policy that
// steers differently from the SMF's instruction.
func parseMAR(i *ie.IE) (marReq, error) {
	m := marReq{create: i.Type == ie.CreateMAR}
	children, err := i.CreateMAR()
	what := "Create MAR"
	if i.Type == ie.UpdateMAR {
		children, err = i.UpdateMAR()
		what = "Update MAR"
	}
	if err != nil {
		return marReq{}, fmt.Errorf("%s: %w", what, err)
	}
	for _, c := range children {
		switch c.Type {
		case ie.MARID:
			if id, err := c.MARID(); err == nil {
				m.id, m.hasID = id, true
			}
		case ie.SteeringFunctionality:
			v, err := c.SteeringFunctionality()
			if err != nil {
				return marReq{}, fmt.Errorf("Steering Functionality: %w", err)
			}
			m.hasFunctionality, m.functionality = true, v
		case ie.SteeringMode:
			v, err := c.SteeringMode()
			if err != nil {
				return marReq{}, fmt.Errorf("Steering Mode: %w", err)
			}
			m.hasMode, m.mode = true, v
		case ie.TGPPAccessForwardingActionInformation,
			ie.UpdateTGPPAccessForwardingActionInformation:
			partial := !m.create && c.Type == ie.UpdateTGPPAccessForwardingActionInformation
			if err := parseMARAccess(&m, 0, c, partial); err != nil {
				return marReq{}, fmt.Errorf("3GPP access forwarding action information: %w", err)
			}
		case ie.NonTGPPAccessForwardingActionInformation,
			ie.UpdateNonTGPPAccessForwardingActionInformation:
			partial := !m.create && c.Type == ie.UpdateNonTGPPAccessForwardingActionInformation
			if err := parseMARAccess(&m, 1, c, partial); err != nil {
				return marReq{}, fmt.Errorf("non-3GPP access forwarding action information: %w", err)
			}
		case ie.AccessAvailabilityControlInformation:
			// The UPF has no access-availability measurement to apply it to,
			// and accepting the instruction while ignoring it would leave the
			// SMF believing the UP reports availability it never measures.
			// Health updates are a deployment/controller input in this tree;
			// cause 73 is the honest answer until that reporting exists.
			return marReq{}, fmt.Errorf(
				"%w: MAR access availability control is not implemented", errNotExpressible)
		}
	}
	if !m.hasID {
		return marReq{}, fmt.Errorf("%w: %s without a MAR ID", errMandatoryIE, what)
	}
	return m, nil
}

// parseMARAccess reads one access's forwarding action information: the FAR it
// forwards through, the weight the load-balancing modes use and the priority
// that makes it active or standby. The FAR ID and the priority are the fields
// active/standby needs; a message that leaves either out cannot say which
// access is the preferred one and is refused here.
func parseMARAccess(m *marReq, which int, i *ie.IE, partial bool) error {
	if m.haveAccess[which] {
		return fmt.Errorf("%w: the MAR names the access twice", errNotExpressible)
	}
	var children []*ie.IE
	var err error
	switch i.Type {
	case ie.TGPPAccessForwardingActionInformation:
		children, err = i.TGPPAccessForwardingActionInformation()
	case ie.UpdateTGPPAccessForwardingActionInformation:
		children, err = i.UpdateTGPPAccessForwardingActionInformation()
	case ie.NonTGPPAccessForwardingActionInformation:
		children, err = i.NonTGPPAccessForwardingActionInformation()
	case ie.UpdateNonTGPPAccessForwardingActionInformation:
		children, err = i.UpdateNonTGPPAccessForwardingActionInformation()
	}
	if err != nil {
		return err
	}
	if partial && len(children) == 0 {
		// A null-length Update access IE deregisters the access
		// (Table 7.5.4.16-1): the other access stays, and the active/standby
		// selection must still name an active one.
		m.removeAccess[which] = true
		m.haveAccess[which] = true
		return nil
	}
	var access marAccess
	for _, c := range children {
		switch c.Type {
		case ie.FARID:
			if id, err := c.FARID(); err == nil {
				access.farID, access.hasFarID = id, true
			}
		case ie.Priority:
			v, err := c.Priority()
			if err != nil {
				return fmt.Errorf("Priority: %w", err)
			}
			access.priority, access.hasPrior = v, true
		case ie.Weight:
			v, err := c.Weight()
			if err != nil {
				return fmt.Errorf("Weight: %w", err)
			}
			access.weight, access.hasWeight = v, true
		}
	}
	if !partial {
		if !access.hasFarID {
			return fmt.Errorf("%w: the access names no FAR ID", errMandatoryIE)
		}
		if !access.hasPrior {
			return fmt.Errorf("%w: the access names no Priority", errMandatoryIE)
		}
	}
	m.access[which], m.haveAccess[which] = access, true
	return nil
}

// qfiIE reads a QFI IE (TS 29.244 8.2.89): the six-bit QoS Flow Identifier a
// PDI or a QER names. The spec's value range is 0..63 (TS 38.415 5.5.3.3, to
// which 8.2.89 refers), and 0 is a flow a gNB can send, so it is taken like
// any other: the decap writes 255 into the `qfi` attribute for a packet whose
// G-PDU carries no PDU Session Container (datapath/pdu_session_qfi.h), which
// is above the range, so a rule keyed on 0 matches only a packet that really
// carried QFI 0. A byte above 63 is a flow no packet can carry: a rule keyed
// on one would match nothing, and the session would stand while its uplink
// blackholed. Both refusals carry the cause the SMF can fix.
func qfiIE(c *ie.IE, what string) (uint8, error) {
	v, err := c.QFI()
	if err != nil {
		return 0, fmt.Errorf("QFI: %w", err)
	}
	if v > 63 {
		return 0, fmt.Errorf("%w: %s QFI is %d; the spec's range is 0..63",
			errNotExpressible, what, v)
	}
	return v, nil
}

func parsePDI(p *pdrReq, children []*ie.IE) error {
	for _, c := range children {
		switch c.Type {
		case ie.SourceInterface:
			v, err := c.SourceInterface()
			if err != nil {
				return fmt.Errorf("Source Interface: %w", err)
			}
			// The value names the side the packet came from (TS 29.244
			// 8.2.2, Table 8.2.2-1): Access is the access side, and Core, the
			// service LAN's interface and the 5G VN's internal interface are
			// the sides toward the subscriber -- the last of them is where a
			// packet re-injected by a FAR comes back in. CP-function is the CP
			// function's own path, which is no user plane of this UP's, and
			// 5..15 are Spare. A rule on one of those would be a rule the SMF
			// asked for and nothing serves, so the value is refused rather
			// than carried into a chain (an unread value used to become
			// Access, which is what put CP-function traffic on the uplink).
			switch v {
			case ie.SrcInterfaceAccess, ie.SrcInterfaceCore,
				ie.SrcInterfaceSGiLANN6LAN, ie.SrcInterface5GVNInternal:
			default:
				return fmt.Errorf("%w: the PDI's Source Interface value %d is not one this UP serves",
					errNotExpressible, v)
			}
			p.srcIfc = v
		case ie.NetworkInstance:
			// The PDI's Network Instance (TS 29.244 8.2.4): the instance "to
			// match for the incoming packet", read here and resolved in
			// resolve. With -instances, the deployment maps the name to an
			// interface, its route domain and its pool, and a name it does
			// not configure is refused rather than served by the wrong
			// interface. Without -instances (the default, deploy/upf.yaml)
			// there is one instance: every name is accepted and ignored, so
			// the default deployment gives no isolation between instances.
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
			// Several QFI IEs are several QoS flows, any of which matches
			// (7.5.2.2-2 NOTE 4): all are kept, once each.
			if !slices.Contains(p.qfis, qfi) {
				p.qfis = append(p.qfis, qfi)
			}
		case ie.FTEID:
			fields, err := c.FTEID()
			if err != nil {
				return fmt.Errorf("F-TEID: %w", err)
			}
			p.hasFTEID = true
			p.teid = fields.TEID
			p.wantIPv4, p.wantIPv6 = fields.HasIPv4(), fields.HasIPv6()
			if fields.HasIPv4() && len(fields.IPv4Address) == net.IPv4len {
				v := fields.IPv4Address.To4()
				if v != nil && !net.IP(v).IsUnspecified() {
					p.fteidIPv4 = netip.AddrFrom4([4]byte(v))
				}
			}
			if fields.HasIPv6() && len(fields.IPv6Address) == net.IPv6len {
				v := fields.IPv6Address.To16()
				if v != nil && !net.IP(v).IsUnspecified() && !netip.AddrFrom16([16]byte(v)).Is4In6() {
					p.fteidIPv6 = netip.AddrFrom16([16]byte(v))
				}
			}
			// CH requests allocation. If CHID is present, every PDR carrying
			// that identifier shares this endpoint and its family set.
			p.hasChoose = fields.HasCh()
			if p.hasChoose && fields.HasChID() {
				p.hasCHID = true
				p.chid = fields.ChooseID
			}
		case ie.UEIPAddress:
			fields, err := c.UEIPAddress()
			if err != nil {
				return fmt.Errorf("UE IP address: %w", err)
			}
			// 8.2.62's bit 3 names the side the address appears on; it is only
			// read here, in the PDI (the spec says to set it 0 elsewhere).
			p.ueIPDst = c.HasSD()
			p.hasUEIP = true
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
			if fields.HasTTC() || fields.HasSPI() || fields.HasFL() {
				// The ToS/Traffic Class, the SPI and the flow label are parts
				// of the filter the matchers carry no field for. Reading the
				// filter without them is a rule wider than the SMF asked.
				return fmt.Errorf("%w: the SDF filter carries a ToS/Traffic Class, SPI or flow label, which no matcher here constrains", errNotExpressible)
			}
			var filter *sdfFilter
			switch {
			case fields.HasFD():
				if filter, err = parseFlowDescription(fields.FlowDescription); err != nil {
					return fmt.Errorf("SDF filter: %w", err)
				}
			case fields.HasBID():
				// A bidirectional SDF filter's later PDRs name the ID alone
				// (TS 29.244 5.2.1A.3); resolveSDFIDs fills the filter in once
				// the whole session is read.
				filter = &sdfFilter{bare: true}
			default:
				return fmt.Errorf("%w: the SDF filter carries neither a flow description nor an SDF Filter ID", errNotExpressible)
			}
			if fields.HasBID() {
				filter.id, filter.hasID = fields.SDFFilterID, true
			}
			p.sdfs = append(p.sdfs, filter)
		case ie.ApplicationID, ie.TrafficEndpointID, ie.EthernetPacketFilter,
			ie.EthernetPDUSessionInformation, ie.FramedRoute, ie.FramedRouting,
			ie.FramedIPv6Route, ie.IPMulticastAddressingInfo:
			// A PDI match this UP does not implement. Dropping it would make
			// the rule match what the IE was there to exclude, so it is
			// refused; the IEs that merely inform (the PDI's other optional
			// parts) still pass.
			return fmt.Errorf("%w: the PDI carries IE type %d, which this UP does not match on", errNotExpressible, c.Type)
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
				b.id, b.hasID = id, true
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
	if !b.hasID {
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
				f.id, f.hasID = id, true
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
			if f.apply&applyDUPL != 0 {
				return farReq{}, fmt.Errorf(
					"%w: the Apply Action asks for DUPL, and this UP forwards to one action per packet",
					errNotExpressible)
			}
		case ie.ForwardingParameters:
			fwd, err := c.ForwardingParameters()
			if err != nil {
				return farReq{}, fmt.Errorf("Forwarding Parameters: %w", err)
			}
			f.hasFwd = true
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
			f.hasFwd = true
			if err := parseForwardingParameters(&f, fwd); err != nil {
				return farReq{}, err
			}
		}
	}
	if !f.hasID {
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
		case ie.ForwardingPolicy:
			// The Forwarding Policy IE (TS 29.244 8.2.23, IE type 41, inside the
			// Forwarding Parameters): the identifier of the policy the service
			// fabric applies to this flow. It is mandatory for a forward
			// toward SGi-LAN/N6-LAN (Table 7.5.2.3-2) and may be present
			// otherwise; a graph carries no service-fabric classifier for it,
			// so what this UP does with it is hold it -- the presence is the
			// contract, and a message that omits it where it is mandatory is
			// refused (merge) rather than forwarded into a fabric that would
			// apply nothing.
			id, err := fp.ForwardingPolicyIdentifier()
			if err != nil {
				return fmt.Errorf("Forwarding Policy: %w", err)
			}
			f.policy, f.hasPolicy = id, true
		case ie.HeaderEnrichment, ie.RedirectInformation, ie.Proxying:
			// Header Enrichment (8.2.67), Redirect Information (8.2.20) and
			// Proxying (8.2.97) all instruct the UP to *write* something into
			// the subscriber's traffic -- an HTTP header, a redirect, a proxy
			// address. Nothing in this datapath reads or rewrites L7, so a
			// FAR carrying one is refused rather than forwarded as if it were
			// absent: the SMF would have no way to learn the instruction was
			// not applied.
			return fmt.Errorf(
				"%w: the Forwarding Parameters carry an IE this UP does not apply (type %d: Header Enrichment, Redirect Information or Proxying)",
				errNotExpressible, fp.Type)
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
			// The peer is the IPv4 address when the IE carries one (the
			// description's 0x0100), else the IPv6 address (0x0200): the
			// tunnel's local endpoint is chosen by the peer's family
			// (tunnelEndpoint), so either family is carried as is.
			peer, ok := netip.AddrFromSlice(fields.IPv4Address)
			if !ok {
				peer, ok = netip.AddrFromSlice(fields.IPv6Address)
				if ok && peer.Is4In6() {
					return fmt.Errorf("Outer Header Creation names the IPv4-mapped IPv6 address %s", peer)
				}
			}
			if fields.TEID == 0 {
				if ok && peer.Unmap().IsUnspecified() {
					// A zero TEID with the unspecified address is no tunnel:
					// the SMF has not learned the gNB's yet (OMEC's pfcpsim
					// creates a dropping downlink FAR this way, and a
					// modification names the real one). It reads as a FAR
					// with no Outer Header Creation, which is what the
					// compile already carries as "no tunnel known" -- and
					// an Update FAR's placeholder leaves the tunnel it had.
					continue
				}
				return errors.New("Outer Header Creation without a TEID")
			}
			if !ok {
				return errors.New("Outer Header Creation without an IPv4 or IPv6 address")
			}
			f.hasOuter, f.teid, f.peer = true, fields.TEID, peer.Unmap()
		case ie.TransportLevelMarking:
			// The FAR's Transport Level Marking (8.2.12): the SMF asking this
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
		if c.Type == ie.MeasurementInformation {
			// 8.2.68, octet 5: MBQE 0x01, INAM 0x02, RADI 0x04, ISTM 0x08,
			// MNOP 0x10. A report always carries the packet counts (MNOP) and
			// a duration that starts when the URR is created (ISTM), so those
			// ask for what is already done, and 0 asks for nothing. MBQE asks
			// to count before QoS enforcement, which no graph can: the
			// counter sits after the meter, so a throttled flow's usage is the
			// forwarded part (docs/claims.md). Real SMFs set it on every
			// URR (free5GC does), so refusing it refuses every real session.
			// INAM (a paused URR) and RADI (application detection) are not
			// built and are refused.
			if len(c.Payload) == 0 {
				return urrReq{}, fmt.Errorf("%w: the URR's Measurement Information is empty", errNotExpressible)
			}
			if c.Payload[0]&^(0x01|0x08|0x10) != 0 || len(c.Payload) > 1 && c.Payload[1] != 0 {
				return urrReq{}, fmt.Errorf("%w: the URR's Measurement Information %#x asks for INAM, RADI or a later flag, which this UP does not implement",
					errNotExpressible, c.Payload)
			}
			continue
		}
		if name, ok := urrUnsupported[c.Type]; ok {
			return urrReq{}, fmt.Errorf("%w: the URR names %s, and this UP does not implement it",
				errNotExpressible, name)
		}
		switch c.Type {
		case ie.URRID:
			if id, err := c.URRID(); err == nil {
				u.id, u.hasID = id, true
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
			u.linkedReporting = flags[0]&trigLiusa != 0
			if len(flags) > 1 {
				u.onVolQuota = flags[1]&trigVolQuota != 0
				u.onTimeQuota = flags[1]&trigTimeQuota != 0
			}
			if len(flags) > 2 {
				u.onEndMarker = flags[2]&trigEndMarker != 0
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
	if !u.hasID {
		return urrReq{}, errors.New("URR without a URR ID")
	}
	if u.create && (!u.hasMethod || !u.hasTriggers) {
		// Both are mandatory in a Create URR (7.5.2.4's table). Accepting a URR
		// with neither would leave a rule nobody can report from.
		return urrReq{}, fmt.Errorf("%w: a Create URR needs a Measurement Method and Reporting Triggers",
			errNotExpressible)
	}
	// A Measurement Period with no periodic trigger is accepted and never acted
	// on: 7.5.2.4 makes the period conditional on PERIO, and says nothing
	// against one without it (OMEC's pfcpsim sends a period on a volume-
	// threshold URR). The report only fires on u.periodic.
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
	// QER ID 0 is a value like any other (8.2.75 reserves none; OMEC's pfcpsim
	// numbers its session-level QER 0), so absence is tracked, not inferred
	// from a zero.
	seenID := false
	for _, c := range children {
		switch c.Type {
		case ie.QERID:
			if id, err := c.QERID(); err == nil {
				q.id, seenID = id, true
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
			// FAR writes. QFI 0 is in the spec's range (TS 38.415 5.5.3.3):
			// the record's qfi_present keeps it distinct from a QER with no
			// QFI IE, so the encap writes a container carrying 0.
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
		case ie.GBR:
			// 8.2.7: two octet-aligned five-octet fields, uplink then
			// downlink, in the same unit the MBR carries.
			payload, err := c.GBR()
			if err != nil || len(payload) < 10 {
				return qerReq{}, errors.New("GBR: malformed")
			}
			q.gbUL = uint40(payload[0:5])
			q.gbDL = uint40(payload[5:10])
			q.hasGBR = true
		case ie.AveragingWindow:
			// 8.2.115: the duration in milliseconds the rates are calculated
			// over. Zero is no window at all, and the meter's own burst stands.
			if v, err := c.AveragingWindow(); err == nil && v > 0 {
				q.window, q.hasWindow = time.Duration(v)*time.Millisecond, true
			}
		}
	}
	if !seenID {
		return qerReq{}, errors.New("QER without a QER ID")
	}
	return q, nil
}

// meterChange is the resource for one policed direction: a two-rate
// three-colour meter whose peak is the QER's MBR (8.2.8, the ceiling) and
// whose committed rate is its GBR (8.2.7, the guarantee) -- the band between
// the two is yellow, which is what a QER with both rates means. A QER with no
// GBR, or a GBR not below the MBR, gets the flat meter this tree always wrote:
// committed rate = peak, so nothing is yellow and the ceiling is the only
// policy. The burst is the rate over the QER's Averaging Window (8.2.115) when
// the SMF named one, and a tenth of a second when it named none.
func meterChange(resource string, id uint32, committed, peak uint64, window time.Duration) bess.Change {
	if committed == 0 || committed > peak {
		committed = peak
	}
	burst := func(rate uint64) uint64 {
		if window > 0 {
			if b := rate * uint64(window/time.Millisecond) / 1000; b > 0 {
				return b
			}
			return 1
		}
		if b := rate / 10; b > 0 {
			return b
		}
		return 1
	}
	return bess.Change{
		Resource: resource,
		Key:      map[string]any{"id": id},
		Value: map[string]any{
			"tr_tcm": map[string]any{
				"committed_rate":  committed,
				"committed_burst": burst(committed),
				"peak_rate":       peak,
				"peak_burst":      burst(peak),
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
	// sportLo/sportHi and dportLo/dportHi are the SDF filter's port *ranges*,
	// inclusive, with sportOK/dportOK saying the filter named one at all
	// (TS 29.244 8.2.5's IPFilterRule carries "port" or "port-port"). The key
	// builder writes one port as a masked value and a range as a WildcardMatch
	// range (portMatch).
	sportLo, sportHi uint16
	sportOK          bool
	dportLo, dportHi uint16
	dportOK          bool

	// id and hasID are the SDF Filter ID of a bidirectional filter (TS 29.244
	// 5.2.1A.3, 8.2.5): one PDR carries the flow description and the ID, the
	// other PDRs of the flow name the ID alone. bare is such a reference, until
	// resolveSDFIDs has copied the definition into it; via marks the copy, so
	// that only a PDR's own flow description is a definition.
	id    uint32
	hasID bool
	bare  bool
	via   bool
}

// resolveSDFIDs fills in the PDRs that name a bidirectional SDF filter by its
// ID alone (TS 29.244 5.2.1A.3: "the SDF Filter ID ... shall be provided in
// the PDI of the PDR(s) that use the same filter"). Open5GS provisions every
// bidirectional flow this way: the downlink PDR carries the flow description
// and the ID, the uplink PDR carries the ID. The copy is the filter as
// written; the PDR's own orientation (oriented) then reads it the way it
// reads any other. Every request's merge re-resolves the references, so a definition
// that changed in another PDR reaches the PDRs that use it (5.2.1A.3: the ID
// "shall be provided in the PDI of the PDR(s) that use the same filter"); a
// reference whose copy changed also leaves its previous form in stale, so the
// rule it no longer describes is erased with the rewrite.
func resolveSDFIDs(s *Session) error {
	defs := map[uint32]*sdfFilter{}
	for _, p := range pdrsInOrder(s) {
		for _, f := range p.sdfs {
			if !f.hasID || f.bare || f.via {
				continue
			}
			if d, ok := defs[f.id]; ok && *d != *f {
				return fmt.Errorf("%w: SDF Filter ID %d is defined by two different flow descriptions",
					errNotExpressible, f.id)
			}
			defs[f.id] = f
		}
	}
	for _, p := range pdrsInOrder(s) {
		for i, f := range p.sdfs {
			// A reference is a bare filter or the copy a previous compile
			// resolved it to (via): the copy is re-resolved every compile, so
			// a definition that changed in another PDR reaches the PDRs that
			// use it (5.2.1A.3's "the PDR(s) that use the same filter").
			if !f.bare && !f.via {
				continue
			}
			d, ok := defs[f.id]
			if !ok {
				return fmt.Errorf("%w: PDR %d names SDF Filter ID %d, which no PDR of the session defines",
					errNotExpressible, p.id, f.id)
			}
			c := *d
			c.via = true
			if f.via && *f != c {
				// The definition changed under a PDR this message does not
				// touch. Its rule was written from the copy it carried, so
				// that rule is stale: the previous form joins the removed and
				// replaced ones, and compile erases its key unless the new
				// copy writes the same one.
				old := *p
				old.sdfs = append([]*sdfFilter(nil), p.sdfs...)
				s.stale = append(s.stale, &old)
			}
			p.sdfs[i] = &c
		}
	}
	return nil
}

// oriented is the PDR's SDF filter as the packets it selects carry it. The CP
// function provisions the PCF's Flow Description -- always the downlink form,
// "from the remote side to the UE" -- in the PDI of the uplink and the downlink
// PDR alike, and the UP function applies it as is for a CORE PDR and with the
// source and destination, address and port, swapped for an ACCESS one (TS
// 29.244 5.2.1A.2A: "shall swap the source and destination address/port in the
// Flow Description"). Open5GS's UPF does the same (lib/pfcp/handler.c,
// ogs_ipfw_rule_swap, for a PDR whose source interface is ACCESS).
func (p *pdr) oriented() *sdfFilter {
	if p.sdf == nil || p.srcIfc != ie.SrcInterfaceAccess {
		return p.sdf
	}
	f := *p.sdf
	f.src, f.srcOK, f.srcAssigned = p.sdf.dst, p.sdf.dstOK, p.sdf.dstAssigned
	f.dst, f.dstOK, f.dstAssigned = p.sdf.src, p.sdf.srcOK, p.sdf.srcAssigned
	f.sportLo, f.sportHi, f.sportOK = p.sdf.dportLo, p.sdf.dportHi, p.sdf.dportOK
	f.dportLo, f.dportHi, f.dportOK = p.sdf.sportLo, p.sdf.sportHi, p.sdf.sportOK
	return &f
}

// parseFlowDescription reads the IPFilterRule form the SDF Filter IE carries
// (TS 29.244 8.2.5): "permit <dir> <proto> from <src> [<port>] to <dst>
// [<port>]". "assigned" is the PDI's UE address, "any" leaves the field
// unconstrained.
//
// A port the filter names is kept as a range here, whether it is one value or
// two: which shapes the deployment's table can carry is a question about the
// table, and the WildcardMatch key answers it where the key is built.
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
		f.sportLo, f.sportHi, f.sportOK = port.lo, port.hi, true
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
		f.dportLo, f.dportHi, f.dportOK = port.lo, port.hi, true
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

// portRange is one port of a flow description: an inclusive range whose two
// ends are equal for the single-port form.
type portRange struct {
	lo, hi uint16
}

// parseFilterPort reads one port of a flow description: a number, or the
// inclusive range "low-high". The range is kept whole; the key builder
// decides its form (portMatch).
func parseFilterPort(word string) (portRange, error) {
	if lo, hi, ok := strings.Cut(word, "-"); ok {
		a, err := strconv.ParseUint(lo, 10, 16)
		if err != nil {
			return portRange{}, fmt.Errorf("invalid port %q", word)
		}
		b, err := strconv.ParseUint(hi, 10, 16)
		if err != nil {
			return portRange{}, fmt.Errorf("invalid port %q", word)
		}
		if a > b {
			return portRange{}, fmt.Errorf("invalid port range %q: %d is above %d", word, a, b)
		}
		return portRange{lo: uint16(a), hi: uint16(b)}, nil
	}
	v, err := strconv.ParseUint(word, 10, 16)
	if err != nil {
		return portRange{}, fmt.Errorf("invalid port %q", word)
	}
	return portRange{lo: uint16(v), hi: uint16(v)}, nil
}

// -- answers ------------------------------------------------------------------

// The three answers below carry the SEID the *SMF* knows the session by in the
// message header, and ours only in the F-SEID IE the establishment answer
// returns (TS 29.244 7.2.2.4.2: the header's SEID is the one the receiving node
// allocated -- for a message to the CP function that is its own F-SEID, which
// it sent in the request's F-SEID IE). An SMF looks a session up by that value,
// so answering under our own F-SEID is an answer to a session it does not have.
func (c *Compiler) establishResponse(req *message.SessionEstablishmentRequest, cpSEID, local uint64,
	cause uint8, created []*ie.IE) message.Message {
	// The Node ID is mandatory in the response (TS 29.244 Table 7.5.3.1-1) and
	// the UP F-SEID carries this UP's address (8.2.37): an SMF that finds
	// either missing refuses the response, and the session it describes stays
	// programmed here with nobody to delete it.
	var ies []*ie.IE
	if c.cfg.NodeID != "" {
		ies = append(ies, ie.NewNodeIDHeuristic(c.cfg.NodeID))
	}
	ies = append(ies, ie.NewCause(cause))
	if cause == ie.CauseRequestAccepted {
		if c.cfg.N4Addr.Is4() {
			ies = append(ies, ie.NewFSEID(local, net.IP(c.cfg.N4Addr.AsSlice()), nil))
		} else {
			ies = append(ies, ie.NewFSEID(local, nil, nil))
		}
		ies = append(ies, created...)
	}
	return message.NewSessionEstablishmentResponse(0, 0, cpSEID, req.Sequence(), 0, ies...)
}

// modifyResponse answers a modification; cpSEID is the session's CP F-SEID, or
// the SEID the request itself carried when there is no session any more (a
// Session Context Not Found has nowhere else to read it from).
func modifyResponse(req *message.SessionModificationRequest, cpSEID uint64,
	cause uint8, created []*ie.IE, usage ...*ie.IE) message.Message {
	ies := []*ie.IE{ie.NewCause(cause)}
	if cause == ie.CauseRequestAccepted {
		ies = append(ies, created...)
		ies = append(ies, usage...)
	}
	return message.NewSessionModificationResponse(0, 0, cpSEID, req.Sequence(), 0, ies...)
}

// deleteResponse answers a deletion, with the same rule for its SEID.
//
// The Usage Reports are the session's last window, one per URR (TS 29.244
// 7.5.7.2): an answer that refuses the deletion carries none.
func deleteResponse(req *message.SessionDeletionRequest, cpSEID uint64, cause uint8, usage ...*ie.IE) message.Message {
	ies := make([]*ie.IE, 0, 1+len(usage))
	ies = append(ies, ie.NewCause(cause))
	ies = append(ies, usage...)
	return message.NewSessionDeletionResponse(0, 0, cpSEID, req.Sequence(), 0, ies...)
}

// parseCause maps a request-reading failure to the cause the SMF sees: a
// well-formed rule the dataplane cannot carry is a rule failure (what a
// retransmission of it would hit again), while an unreadable message is a
// rejection.
func parseCause(err error) uint8 {
	if errors.Is(err, errMandatoryIE) {
		return ie.CauseMandatoryIEMissing
	}
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
	if errors.Is(err, errMandatoryIE) {
		return ie.CauseMandatoryIEMissing
	}
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
	var invalid *bess.InvalidRequestError
	switch {
	case errors.As(err, &invalid) && invalid.Code == codes.ResourceExhausted:
		// The daemon refused for lack of memory or capacity (BESS D-198): a
		// definite refusal, nothing was applied, and TS 29.244 has a cause
		// for it.
		return ie.CauseNoResourcesAvailable
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
	var ipv4, ipv6 net.IP
	if addr.Is4() {
		v := addr.As4()
		ipv4 = v[:]
	} else if addr.Is6() {
		v := addr.As16()
		ipv6 = v[:]
	}
	fields := ie.NewFTEIDFields(0, teid, ipv4, ipv6, 0)
	if ipv4 != nil {
		fields.SetIPv4Flag()
	}
	if ipv6 != nil {
		fields.SetIPv6Flag()
	}
	return ie.NewFTEID(fields.Flags, teid, ipv4, ipv6, 0)
}
func (c *Compiler) createdFTEID(p *pdr) *ie.IE {
	var ipv4, ipv6 net.IP
	for _, endpoint := range c.cfg.FTEIDEndpoints {
		if endpoint.ID != p.endpointID {
			continue
		}
		if p.wantIPv4 && endpoint.IPv4.Is4() {
			v := endpoint.IPv4.As4()
			ipv4 = v[:]
		}
		if p.wantIPv6 && endpoint.IPv6.Is6() {
			v := endpoint.IPv6.As16()
			ipv6 = v[:]
		}
	}
	if ipv4 == nil && ipv6 == nil {
		return createdFTEID(p.teid, c.fteidAddr(p))
	}
	fields := ie.NewFTEIDFields(0, p.teid, ipv4, ipv6, 0)
	if ipv4 != nil {
		fields.SetIPv4Flag()
	}
	if ipv6 != nil {
		fields.SetIPv6Flag()
	}
	return ie.NewFTEID(fields.Flags, p.teid, ipv4, ipv6, 0)
}
