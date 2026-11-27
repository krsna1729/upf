// SPDX-License-Identifier: BSD-3-Clause
package session

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/bess"
)

// packetRateIE is 8.2.63's Packet Rate IE, including the additional maximum
// (flag bit 3) whose fields the library's constructor does not take.
func packetRateIE(flags, ulUnit uint8, ul uint16, dlUnit uint8, dl uint16,
	addULUnit uint8, addUL uint16, addDLUnit uint8, addDL uint16) *ie.IE {
	b := []byte{flags}
	put := func(unit uint8, v uint16) {
		b = append(b, unit, byte(v>>8), byte(v))
	}
	if flags&0x01 != 0 {
		put(ulUnit, ul)
	}
	if flags&0x02 != 0 {
		put(dlUnit, dl)
	}
	if flags&0x04 != 0 {
		if flags&0x01 != 0 {
			put(addULUnit, addUL)
		}
		if flags&0x02 != 0 {
			put(addDLUnit, addDL)
		}
	}
	return ie.New(ie.PacketRate, b)
}

// packetRateEstablishment is one uplink PDR policed by qer.
func packetRateEstablishment(cpSEID uint64, qer *ie.IE) *message.SessionEstablishmentRequest {
	return message.NewSessionEstablishmentRequest(0, 0, cpSEID, 1, 0,
		ie.NewNodeID("", "", "smf"),
		ie.NewFSEID(cpSEID, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				testFTEID(0),
				ie.NewUEIPAddress(0x02, "10.45.0.9", "", 0, 0)),
			ie.NewFARID(1), ie.NewQERID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
		qer)
}

// TestPacketRateQuotaCompiles: a QER's Packet Rate and Packet Rate Status
// become the direction's quota record, the PDR result carries its id, and an
// unchanged profile on a later Update QER rewrites nothing while a changed one
// bumps the epoch and a dropped direction's record is erased.
func TestPacketRateQuotaCompiles(t *testing.T) {
	cfg := testConfig()
	cfg.Up.PacketRates = "pr_ul"
	cfg.Down.PacketRates = "pr_dl"
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())
	validity := time.Unix(1893456000, 0) // 2030-01-01, 8.2.139's NTP time
	qer := ie.NewCreateQER(ie.NewQERID(1), ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
		packetRateIE(0x07, 1, 100, 0, 200, 2, 5000, 0, 2000),
		ie.NewPacketRateStatus(0x07, 40, 4, 50, 5, validity),
		ie.NewQERControlIndications(0, 0, 1))
	resp := c.Establish(packetRateEstablishment(0x7801, qer)).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	changes := rec.last()
	var ul rule
	for _, got := range rules(changes) {
		if strings.HasPrefix(got.change.Resource, rulesRes(cfg.Up)) {
			ul = got
			break
		}
	}
	if ul.change.Resource == "" {
		t.Fatal("the establishment wrote no uplink rule")
	}
	rateID := ul.packetRateID()
	if rateID == 0 {
		t.Fatal("the uplink rule carries no packet-rate id")
	}
	ulChange := find(t, changes, ratesRes(cfg.Up), "id", rateID)
	want := PacketRateEntry{
		Allowed: 100, PeriodSeconds: 360,
		Additional: 5000, AdditionalPeriodSeconds: 3600,
		Epoch:         1,
		SeedRemaining: 40, SeedRemainingAdditional: 4,
		SeedValidityUnixNS: uint64(validity.UnixNano()),
		SeedEpoch:          2,
	}
	if got := payload[PacketRateEntry](ulChange.Value); got != want {
		t.Errorf("uplink quota = %+v, want %+v", got, want)
	}
	dl := changesFor(changes, ratesRes(cfg.Down))
	if len(dl) != 1 {
		t.Fatalf("the QER's downlink rate wrote %d quota records, want one", len(dl))
	}
	dlID := keyFieldValue(dl[0].Key, "id").(uint32)
	wantDL := PacketRateEntry{
		Allowed: 200, PeriodSeconds: 60,
		Additional: 2000, AdditionalPeriodSeconds: 60,
		Epoch:         1,
		SeedRemaining: 50, SeedRemainingAdditional: 5,
		SeedValidityUnixNS: uint64(validity.UnixNano()),
		SeedEpoch:          2,
	}
	if got := payload[PacketRateEntry](dl[0].Value); got != wantDL {
		t.Errorf("downlink quota = %+v, want %+v", got, wantDL)
	}

	// The same profile and seed again: no quota record is rewritten.
	seid := upFSEID(t, resp)
	written := len(rec.txns)
	same := message.NewSessionModificationRequest(0, 0, seid, 2, 0,
		ie.NewUpdateQER(ie.NewQERID(1),
			packetRateIE(0x07, 1, 100, 0, 200, 2, 5000, 0, 2000)))
	if got := cause(t, c.Modify(same)); got != ie.CauseRequestAccepted {
		t.Fatalf("the unchanged update answered cause %d", got)
	}
	if len(rec.txns) > written && len(changesFor(rec.last(), ratesRes(cfg.Up))) != 0 {
		t.Error("an unchanged Packet Rate rewrote its quota")
	}

	// A new uplink profile names only ULPR: the uplink quota is rewritten with
	// a new epoch, while the seed keeps its epoch -- the module restarts the
	// windows, not a seed already used (5.4.15.2 rule 4) -- and the downlink
	// one goes.
	changed := message.NewSessionModificationRequest(0, 0, seid, 3, 0,
		ie.NewUpdateQER(ie.NewQERID(1), packetRateIE(0x01, 0, 150, 0, 0, 0, 0, 0, 0)))
	if got := cause(t, c.Modify(changed)); got != ie.CauseRequestAccepted {
		t.Fatalf("the changed update answered cause %d", got)
	}
	ulChange = find(t, rec.last(), ratesRes(cfg.Up), "id", rateID)
	want = PacketRateEntry{
		Allowed: 150, PeriodSeconds: 60, Epoch: 3,
		SeedRemaining: 40, SeedRemainingAdditional: 4,
		SeedValidityUnixNS: uint64(validity.UnixNano()),
		SeedEpoch:          2,
	}
	if got := payload[PacketRateEntry](ulChange.Value); got != want {
		t.Errorf("the changed uplink quota = %+v, want %+v", got, want)
	}
	gone, ok := find0(rec.last(), ratesRes(cfg.Down), "id", dlID)
	if !ok || gone.Value != nil {
		t.Errorf("a dropped downlink rate left its quota record: %v", gone)
	}
}

// TestPacketRateZeroMaximumStillCaps: a present flag with a maximum of zero is
// a quota that passes nothing, not an absent one: the record is written and
// the rule names it.
func TestPacketRateZeroMaximumStillCaps(t *testing.T) {
	cfg := testConfig()
	cfg.Up.PacketRates = "pr_ul"
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())
	resp := c.Establish(packetRateEstablishment(0x7802,
		ie.NewCreateQER(ie.NewQERID(1), ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
			packetRateIE(0x01, 0, 0, 0, 0, 0, 0, 0, 0)))).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	var ul rule
	for _, got := range rules(rec.last()) {
		if strings.HasPrefix(got.change.Resource, rulesRes(cfg.Up)) {
			ul = got
		}
	}
	rateID := ul.packetRateID()
	if rateID == 0 {
		t.Fatal("a zero maximum wrote no quota and left the rule uncapped")
	}
	ch := find(t, rec.last(), ratesRes(cfg.Up), "id", rateID)
	if got := payload[PacketRateEntry](ch.Value); got.Allowed != 0 || got.PeriodSeconds != 60 || got.Epoch != 1 {
		t.Errorf("zero-maximum quota = %+v, want allowed 0 over one minute", got)
	}
}

// TestPacketRateWithoutItsModuleIsRefused: a deployment that names no
// PacketRate module cannot enforce the cap, and compiling the rule anyway
// would tell the SMF a limit it does not have. Cause 73 names the flag.
func TestPacketRateWithoutItsModuleIsRefused(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(packetRateEstablishment(0x7803,
		ie.NewCreateQER(ie.NewQERID(1), ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
			packetRateIE(0x01, 0, 10, 0, 0, 0, 0, 0, 0)))).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a Packet Rate with no PacketRate module answered cause %d, want 73", got)
	}
	if len(rec.txns) != 0 {
		t.Error("a refused session wrote to the dataplane")
	}
}

// packetRateReport finds the grouped report of one type in a response's
// unclassified IEs (the library predates the modification-response type, so it
// arrives there).
func packetRateReport(t *testing.T, ies []*ie.IE, typ ie.IEType) *ie.IE {
	t.Helper()
	for _, i := range ies {
		if i.Type == typ {
			return i
		}
	}
	t.Fatalf("the answer carries no IE type %d", typ)
	return nil
}

// quotaIDs reads the two quota ids an establishment wrote.
func quotaIDs(t *testing.T, changes []bess.Change, cfg Config) (ul, dl uint32) {
	t.Helper()
	ulChanges := changesFor(changes, ratesRes(cfg.Up))
	dlChanges := changesFor(changes, ratesRes(cfg.Down))
	if len(ulChanges) != 1 || len(dlChanges) != 1 {
		t.Fatalf("the establishment wrote %d/%d quotas, want one per direction",
			len(ulChanges), len(dlChanges))
	}
	return keyFieldValue(ulChanges[0].Key, "id").(uint32),
		keyFieldValue(dlChanges[0].Key, "id").(uint32)
}

// TestPacketRateQueryAnswersInTheModificationResponse: a Query Packet Rate
// Status names a QER, and the Modification Response carries that QER's
// remaining counts and validity read from the module (7.5.4.22, 7.5.5.4).
func TestPacketRateQueryAnswersInTheModificationResponse(t *testing.T) {
	cfg := testConfig()
	cfg.Up.PacketRates = "pr_ul"
	cfg.Down.PacketRates = "pr_dl"
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())
	validity := time.Unix(2000000000, 0)
	resp := c.Establish(packetRateEstablishment(0x7804,
		ie.NewCreateQER(ie.NewQERID(1), ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
			packetRateIE(0x07, 0, 10, 0, 20, 0, 5, 0, 5),
			ie.NewPacketRateStatus(0x07, 4, 1, 6, 1, validity),
			ie.NewQERControlIndications(0, 0, 0)))).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	ulID, dlID := quotaIDs(t, rec.last(), cfg)
	rec.rates = map[string][]bess.PacketRateStatus{
		"pr_ul": {{ID: ulID, Remaining: 7, RemainingAdditional: 2, ValidityUnixNS: uint64(validity.UnixNano())}},
		"pr_dl": {{ID: dlID, Remaining: 9, RemainingAdditional: 3, ValidityUnixNS: uint64(validity.UnixNano())}},
	}
	query := message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 2, 0,
		ie.NewQueryPacketRateStatusWithinSessionModificationRequest(ie.NewQERID(1)))
	answer := c.Modify(query).(*message.SessionModificationResponse)
	if got := cause(t, answer); got != ie.CauseRequestAccepted {
		t.Fatalf("the query answered cause %d", got)
	}
	report := packetRateReport(t, answer.IEs, ie.PacketRateStatusReportWithinSessionModificationResponse)
	children, err := report.PacketRateStatusReport()
	if err != nil {
		t.Fatal(err)
	}
	if len(children) != 2 || children[0].Type != ie.QERID || children[1].Type != ie.PacketRateStatus {
		t.Fatalf("the report's children are %d IEs, want QER ID and Packet Rate Status", len(children))
	}
	if id, err := children[0].QERID(); err != nil || id != 1 {
		t.Errorf("the report names QER %d (err %v), want 1", id, err)
	}
	fields, err := children[1].PacketRateStatus()
	if err != nil {
		t.Fatal(err)
	}
	if !fields.HasUL() || !fields.HasDL() || !fields.HasAPR() {
		t.Errorf("the status flags are %#x, want UL, DL and APR", fields.Flags)
	}
	if got := fields.NumberOfRemainingUplinkPacketsAllowed; got != 7 {
		t.Errorf("remaining uplink = %d, want 7", got)
	}
	if got := fields.NumberOfRemainingAdditionalUplinkPacketsAllowed; got != 2 {
		t.Errorf("remaining additional uplink = %d, want 2", got)
	}
	if got := fields.NumberOfRemainingDownlinkPacketsAllowed; got != 9 {
		t.Errorf("remaining downlink = %d, want 9", got)
	}
	if got := fields.NumberOfRemainingAdditionalDownlinkPacketsAllowed; got != 3 {
		t.Errorf("remaining additional downlink = %d, want 3", got)
	}
	if got := fields.RateControlStatusValidityTime.Unix(); got != validity.Unix() {
		t.Errorf("validity = %s, want %s", fields.RateControlStatusValidityTime, validity)
	}
}

// TestPacketRateReleaseReportPrecedesTheErase: a QER with RCSR gets its status
// in the Session Deletion Response (5.4.15.2 rule 3, 7.5.7.1-2), read before
// the transaction that erases its quota record.
func TestPacketRateReleaseReportPrecedesTheErase(t *testing.T) {
	cfg := testConfig()
	cfg.Up.PacketRates = "pr_ul"
	cfg.Down.PacketRates = "pr_dl"
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())
	validity := time.Unix(2000000100, 0)
	resp := c.Establish(packetRateEstablishment(0x7805,
		ie.NewCreateQER(ie.NewQERID(1), ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
			packetRateIE(0x03, 0, 10, 0, 20, 0, 0, 0, 0),
			ie.NewQERControlIndications(0, 0, 1)))).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	ulID, dlID := quotaIDs(t, rec.last(), cfg)
	rec.rates = map[string][]bess.PacketRateStatus{
		"pr_ul": {{ID: ulID, Remaining: 3, ValidityUnixNS: uint64(validity.UnixNano())}},
		"pr_dl": {{ID: dlID, Remaining: 4, ValidityUnixNS: uint64(validity.UnixNano())}},
	}
	answer := c.Delete(message.NewSessionDeletionRequest(0, 0, upFSEID(t, resp), 2, 0)).(*message.SessionDeletionResponse)
	if got := cause(t, answer); got != ie.CauseRequestAccepted {
		t.Fatalf("the deletion answered cause %d", got)
	}
	report := packetRateReport(t, answer.IEs, ie.PacketRateStatusReport)
	children, err := report.PacketRateStatusReport()
	if err != nil {
		t.Fatal(err)
	}
	if len(children) != 2 {
		t.Fatalf("the release report has %d IEs, want QER ID and status", len(children))
	}
	fields, err := children[1].PacketRateStatus()
	if err != nil {
		t.Fatal(err)
	}
	if fields.NumberOfRemainingUplinkPacketsAllowed != 3 ||
		fields.NumberOfRemainingDownlinkPacketsAllowed != 4 {
		t.Errorf("the release report reads %d/%d, want 3/4",
			fields.NumberOfRemainingUplinkPacketsAllowed,
			fields.NumberOfRemainingDownlinkPacketsAllowed)
	}
}

// pdrWithQERs is one uplink PDR policed by qers, filtered on a source port.
func pdrWithQERs(id uint16, port uint16, qers ...uint32) *ie.IE {
	ies := []*ie.IE{
		ie.NewPDRID(id), ie.NewPrecedence(100),
		ie.NewPDI(
			ie.NewSourceInterface(ie.SrcInterfaceAccess),
			testFTEID(0),
			ie.NewUEIPAddress(0x02, "10.45.0.9", "", 0, 0),
			ie.NewSDFFilter(fmt.Sprintf("permit out udp from any %d to any", port), "", "", "", 0),
		),
		ie.NewFARID(1),
	}
	for _, q := range qers {
		ies = append(ies, ie.NewQERID(q))
	}
	return ie.NewCreatePDR(ies...)
}

// packetRateQER is a QER with one ten-a-minute uplink packet rate.
func packetRateQER(id uint32) *ie.IE {
	return ie.NewCreateQER(ie.NewQERID(id), ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
		packetRateIE(0x01, 0, 10, 0, 0, 0, 0, 0, 0))
}

// rulePort is the destination port a compiled uplink rule keys on.
func rulePort(r rule) uint16 {
	if len(r.values) < 5 || len(r.values[4]) != 2 {
		return 0
	}
	return binary.BigEndian.Uint16(r.values[4])
}

// TestPacketRateTwoCapsOnOnePDRAreRefused: 5.4.15.3 lets an SMF associate
// DL PDRs to both a Serving PLMN rate control QER and a Small Data Rate
// Control QER, and each caps the traffic. One rule carries one quota id, so
// a PDR naming two QERs that cap its direction is refused rather than
// accepted with one of the two caps silently dropped -- at the establishment,
// and at a modification that would make it so, which leaves the session as it
// was.
func TestPacketRateTwoCapsOnOnePDRAreRefused(t *testing.T) {
	cfg := testConfig()
	cfg.Up.PacketRates = "pr_ul"
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())
	establish := func(cp uint64, first ...uint32) message.Message {
		return c.Establish(message.NewSessionEstablishmentRequest(0, 0, cp, 1, 0,
			ie.NewNodeID("", "", "smf"),
			ie.NewFSEID(cp, nil, nil),
			pdrWithQERs(1, 1000, first...),
			pdrWithQERs(2, 2000, 2),
			ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
				ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
			packetRateQER(1), packetRateQER(2),
		))
	}
	if got := cause(t, establish(0x7810, 1, 2)); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a PDR under two uplink packet rates answered cause %d, want 73", got)
	}
	if len(rec.txns) != 0 {
		t.Error("the refused session wrote to the dataplane")
	}

	resp := establish(0x7811, 1).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	quotas := changesFor(rec.last(), ratesRes(cfg.Up))
	if len(quotas) != 2 {
		t.Fatalf("the establishment wrote %d quotas, want one per QER", len(quotas))
	}
	q1 := keyFieldValue(quotas[0].Key, "id").(uint32)
	q2 := keyFieldValue(quotas[1].Key, "id").(uint32)
	ports := func(changes []bess.Change) map[uint16]uint32 {
		byPort := map[uint16]uint32{}
		for _, r := range rules(changes) {
			if strings.HasPrefix(r.change.Resource, rulesRes(cfg.Up)) {
				byPort[rulePort(r)] = r.packetRateID()
			}
		}
		return byPort
	}
	if got := ports(rec.last()); got[1000] != q1 || got[2000] != q2 {
		t.Fatalf("the rules name quotas %v, want each PDR its own QER's (%d, %d)", got, q1, q2)
	}
	seid := upFSEID(t, resp)
	written := len(rec.txns)
	both := message.NewSessionModificationRequest(0, 0, seid, 2, 0,
		ie.NewUpdatePDR(ie.NewPDRID(2), ie.NewQERID(1), ie.NewQERID(2)))
	if got := cause(t, c.Modify(both)); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("an update putting PDR 2 under two packet rates answered cause %d, want 73", got)
	}
	if len(rec.txns) != written {
		t.Error("the refused update wrote to the dataplane")
	}

	// Moving PDR 2 to the other QER rewrites its rule with that quota even
	// though its action, meters and next hop are unchanged (samePDRRule's
	// packetRateID).
	move := message.NewSessionModificationRequest(0, 0, seid, 3, 0,
		ie.NewUpdatePDR(ie.NewPDRID(2), ie.NewQERID(1)))
	if got := cause(t, c.Modify(move)); got != ie.CauseRequestAccepted {
		t.Fatalf("the move answered cause %d", got)
	}
	if got := ports(rec.last()); got[2000] != q1 {
		t.Errorf("after the move PDR 2's rule names quotas %v, want QER 1's %d", got, q1)
	}
}

// TestPacketRateQueryReadsBeforeTheOverwrite: 5.4.15.3 NOTE 2 -- the query
// retrieves "the current rate status applicable to the source system before
// the UPF/PGW-U overwrites the QER parameters". A message that queries QER 1
// and drops its downlink rate answers the downlink status as it stood; read
// after the transaction, the record was gone (the fake forgets an erased
// quota, as the module does).
func TestPacketRateQueryReadsBeforeTheOverwrite(t *testing.T) {
	cfg := testConfig()
	cfg.Up.PacketRates = "pr_ul"
	cfg.Down.PacketRates = "pr_dl"
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())
	validity := time.Unix(2000000000, 0)
	resp := c.Establish(packetRateEstablishment(0x7812,
		ie.NewCreateQER(ie.NewQERID(1), ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
			packetRateIE(0x03, 0, 10, 0, 20, 0, 0, 0, 0)))).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	ulID, dlID := quotaIDs(t, rec.last(), cfg)
	rec.rates = map[string][]bess.PacketRateStatus{
		"pr_ul": {{ID: ulID, Remaining: 7, ValidityUnixNS: uint64(validity.UnixNano())}},
		"pr_dl": {{ID: dlID, Remaining: 9, ValidityUnixNS: uint64(validity.UnixNano())}},
	}
	query := message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 2, 0,
		ie.NewUpdateQER(ie.NewQERID(1), packetRateIE(0x01, 0, 10, 0, 0, 0, 0, 0, 0)),
		ie.NewQueryPacketRateStatusWithinSessionModificationRequest(ie.NewQERID(1)))
	answer := c.Modify(query).(*message.SessionModificationResponse)
	if got := cause(t, answer); got != ie.CauseRequestAccepted {
		t.Fatalf("the query answered cause %d", got)
	}
	report := packetRateReport(t, answer.IEs, ie.PacketRateStatusReportWithinSessionModificationResponse)
	children, err := report.PacketRateStatusReport()
	if err != nil || len(children) != 2 {
		t.Fatalf("the report holds %d IEs (%v), want QER ID and Packet Rate Status", len(children), err)
	}
	fields, err := children[1].PacketRateStatus()
	if err != nil {
		t.Fatal(err)
	}
	if !fields.HasDL() || fields.NumberOfRemainingDownlinkPacketsAllowed != 9 {
		t.Errorf("the report's downlink status is flags %#x, remaining %d; want the 9 that stood before the overwrite",
			fields.Flags, fields.NumberOfRemainingDownlinkPacketsAllowed)
	}
}
