// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/krsna1729/upf/internal/bess"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// The Session Deletion Response carries each URR's last window (TS 29.244
// 5.2.2.3.1, Table 7.5.7.2-1), trigger TERMR: the URR goes with the session,
// so nothing else can tell the SMF what the last window measured.

// deleteAndParse sends the deletion and returns the response as an SMF parses
// it from the wire.
func deleteAndParse(t *testing.T, c *Compiler, seid uint64) *message.SessionDeletionResponse {
	t.Helper()
	resp := c.Delete(message.NewSessionDeletionRequest(0, 0, seid, 9, 0))
	b := make([]byte, resp.MarshalLen())
	if err := resp.MarshalTo(b); err != nil {
		t.Fatalf("marshalling the deletion response: %v", err)
	}
	parsed, err := message.Parse(b)
	if err != nil {
		t.Fatalf("parsing the deletion response: %v", err)
	}
	out, ok := parsed.(*message.SessionDeletionResponse)
	if !ok {
		t.Fatalf("the answer parsed as %s", parsed.MessageTypeName())
	}
	return out
}

func TestTheDeletionResponseCarriesTheLastWindowOfEachURR(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(urrEstablishment(0x3051, 7, quotaURR(7, 1<<30))).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	seid := upFSEID(t, resp)
	rule := ruleCarrying(t, rec.last(), fieldSrcIP, []byte{10, 45, 0, 2})
	module := testConfig().Up.Counters
	// The first reading is the base (TestEvaluateTakesTheFirstReadingAsItsBaseline)...
	rec.counts = map[string][]bess.RuleCount{module: {{ActionID: rule.actionID(), Packets: 100, Octets: 10000}}}
	if reports := evaluate(t, c, seid); len(reports) != 0 {
		t.Fatalf("the baseline reading reported %+v", reports)
	}
	// ...and the last window is what came after it.
	rec.counts = map[string][]bess.RuleCount{module: {{ActionID: rule.actionID(), Packets: 110, Octets: 11500}}}
	out := deleteAndParse(t, c, seid)
	if got, _ := out.Cause.Cause(); got != ie.CauseRequestAccepted {
		t.Fatalf("the deletion answered cause %d", got)
	}
	if len(out.UsageReport) != 1 {
		t.Fatalf("the response carries %d usage reports, want one for URR 7", len(out.UsageReport))
	}
	children, err := out.UsageReport[0].UsageReport()
	if err != nil {
		t.Fatalf("the usage report: %v", err)
	}
	byType := map[ie.IEType]*ie.IE{}
	for _, ch := range children {
		byType[ch.Type] = ch
	}
	if id, err := byType[ie.URRID].URRID(); err != nil || id != 7 {
		t.Errorf("the report names URR %d (%v), want 7", id, err)
	}
	if seqn, err := byType[ie.URSEQN].URSEQN(); err != nil || seqn != 0 {
		t.Errorf("the report carries UR-SEQN %d (%v), want the first, 0", seqn, err)
	}
	flags, err := byType[ie.UsageReportTrigger].UsageReportTrigger()
	if err != nil || len(flags) < 2 || flags[0] != 0 || flags[1] != 0x08 {
		t.Errorf("the trigger is %#v (%v), want only TERMR: octet 6 bit 4", flags, err)
	}
	if !out.UsageReport[0].HasTERMR() {
		t.Error("the library does not read the trigger as TERMR")
	}
	vol, err := byType[ie.VolumeMeasurement].VolumeMeasurement()
	if err != nil {
		t.Fatalf("the volume measurement: %v", err)
	}
	if vol.UplinkVolume != 1500 || vol.UplinkNumberOfPackets != 10 || vol.DownlinkVolume != 0 || vol.TotalVolume != 1500 {
		t.Errorf("the report holds %+v, want the 1500 octets and 10 packets after the baseline, all uplink", vol)
	}
}

func TestAURRThatNeverHadAReadingReportsAnEmptyWindow(t *testing.T) {
	// No base, so no usage: the cells may be another rule's totals.
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(urrEstablishment(0x3052, 7, quotaURR(7, 1<<30))).(*message.SessionEstablishmentResponse)
	rule := ruleCarrying(t, rec.last(), fieldSrcIP, []byte{10, 45, 0, 2})
	rec.counts = map[string][]bess.RuleCount{testConfig().Up.Counters: {{ActionID: rule.actionID(), Packets: 55, Octets: 5000}}}
	out := deleteAndParse(t, c, upFSEID(t, resp))
	if len(out.UsageReport) != 1 {
		t.Fatalf("%d usage reports, want one", len(out.UsageReport))
	}
	children, _ := out.UsageReport[0].UsageReport()
	for _, ch := range children {
		if ch.Type == ie.VolumeMeasurement {
			if vol, _ := ch.VolumeMeasurement(); vol.TotalVolume != 0 {
				t.Errorf("the report holds %+v, want none of the inherited totals", vol)
			}
		}
	}
}

func TestADeletionWhoseCountersCannotBeReadStillSucceedsWithoutReports(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(urrEstablishment(0x3053, 7, quotaURR(7, 1<<30))).(*message.SessionEstablishmentResponse)
	rec.readFail = errors.New("the module did not answer")
	out := deleteAndParse(t, c, upFSEID(t, resp))
	if got, _ := out.Cause.Cause(); got != ie.CauseRequestAccepted {
		t.Errorf("the deletion answered cause %d, want it accepted: the session is going whatever the counters say", got)
	}
	if len(out.UsageReport) != 0 {
		t.Errorf("the response carries %d usage reports built from no reading", len(out.UsageReport))
	}
}

func TestASessionWithoutAURRHasNoUsageToReportAtItsEnd(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(uplinkPDI(0x3054, []string{udp53}, nil)).(*message.SessionEstablishmentResponse)
	if out := deleteAndParse(t, c, upFSEID(t, resp)); len(out.UsageReport) != 0 {
		t.Errorf("%d usage reports for a session with no URR", len(out.UsageReport))
	}
}

// -- Query URR, QAURR and Remove URR (TS 29.244 5.2.2.3, 7.5.5.2) ------------

// measured establishes URR 7's session, takes the baseline reading, and moves
// the counters on by `octets` and `packets`: what the next report must carry.
func measured(t *testing.T, cp uint64, octets, packets uint64) (*Compiler, *recorder, uint64, func(octets, packets uint64)) {
	t.Helper()
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(urrEstablishment(cp, 7, quotaURR(7, 1<<30))).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	seid := upFSEID(t, resp)
	rule := ruleCarrying(t, rec.last(), fieldSrcIP, []byte{10, 45, 0, 2})
	module := testConfig().Up.Counters
	set := func(o, p uint64) {
		rec.counts = map[string][]bess.RuleCount{module: {{ActionID: rule.actionID(), Packets: p, Octets: o}}}
	}
	set(10000, 100)
	if reports := evaluate(t, c, seid); len(reports) != 0 {
		t.Fatalf("the baseline reading reported %+v", reports)
	}
	set(10000+octets, 100+packets)
	return c, rec, seid, set
}

// reportOf is the one usage report of a modification response: its URR, UR-SEQN,
// trigger octets and uplink volume.
func reportOf(t *testing.T, resp message.Message) (urr, seqn uint32, trig []byte, upOctets uint64) {
	t.Helper()
	b := make([]byte, resp.MarshalLen())
	if err := resp.MarshalTo(b); err != nil {
		t.Fatal(err)
	}
	parsed, err := message.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	m := parsed.(*message.SessionModificationResponse)
	if got, _ := m.Cause.Cause(); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification answered cause %d", got)
	}
	if len(m.UsageReport) != 1 {
		t.Fatalf("the response carries %d usage reports, want one", len(m.UsageReport))
	}
	children, err := m.UsageReport[0].UsageReport()
	if err != nil {
		t.Fatal(err)
	}
	for _, ch := range children {
		switch ch.Type {
		case ie.URRID:
			urr, _ = ch.URRID()
		case ie.URSEQN:
			seqn, _ = ch.URSEQN()
		case ie.UsageReportTrigger:
			trig, _ = ch.UsageReportTrigger()
		case ie.VolumeMeasurement:
			v, _ := ch.VolumeMeasurement()
			upOctets = v.UplinkVolume
		}
	}
	return
}

func query(seid uint64, seq uint32, ies ...*ie.IE) *message.SessionModificationRequest {
	return message.NewSessionModificationRequest(0, 0, seid, seq, 0, ies...)
}

func TestQueryURRReportsTheUsageSinceTheLastReportAndOpensTheNextWindow(t *testing.T) {
	c, _, seid, set := measured(t, 0x3061, 1500, 10)
	urr, seqn, trig, up := reportOf(t, c.Modify(query(seid, 2, ie.NewQueryURR(ie.NewURRID(7)))))
	if urr != 7 || seqn != 0 || up != 1500 {
		t.Errorf("the report is URR %d, UR-SEQN %d, %d uplink octets; want URR 7, 0, 1500", urr, seqn, up)
	}
	if len(trig) < 2 || trig[0] != 0x80 || trig[1] != 0 {
		t.Errorf("the trigger is %#v, want only IMMER: octet 5 bit 8", trig)
	}
	// The report opened the next window: a second query is what came after.
	set(10000+1500+400, 100+10+3)
	urr, seqn, _, up = reportOf(t, c.Modify(query(seid, 3, ie.NewQueryURR(ie.NewURRID(7)))))
	if urr != 7 || seqn != 1 || up != 400 {
		t.Errorf("the second report is URR %d, UR-SEQN %d, %d uplink octets; want URR 7, 1, 400", urr, seqn, up)
	}
}

func TestTheQAURRFlagQueriesEveryURR(t *testing.T) {
	c, _, seid, _ := measured(t, 0x3062, 700, 5)
	const qaurr = 0x04 // PFCPSMReq-Flags bit 3 (8.2.25)
	urr, _, _, up := reportOf(t, c.Modify(query(seid, 2, ie.NewPFCPSMReqFlags(qaurr))))
	if urr != 7 || up != 700 {
		t.Errorf("the report is URR %d with %d uplink octets; want URR 7 with 700", urr, up)
	}
}

func TestAQueryForAURRTheSessionLacksIsRefused(t *testing.T) {
	c, _, seid, _ := measured(t, 0x3063, 1, 1)
	if got := cause(t, c.Modify(query(seid, 2, ie.NewQueryURR(ie.NewURRID(99))))); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a Query URR for URR 99 answered cause %d, want a rule failure", got)
	}
}

func TestARefusedModificationDoesNotSpendTheWindowItWasToReport(t *testing.T) {
	c, _, seid, _ := measured(t, 0x3064, 1500, 10)
	// The query rides with a PDR update the merge refuses (it names a URR the
	// session does not hold), after the windows were read: the SMF got no
	// report, so the usage stays owed.
	bad := query(seid, 2, ie.NewQueryURR(ie.NewURRID(7)),
		ie.NewUpdatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, 0x1000, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.2", "", 0, 0)),
			ie.NewFARID(1), ie.NewURRID(55)))
	if got := cause(t, c.Modify(bad)); got != ie.CauseRuleCreationModificationFailure {
		t.Fatalf("the PDR naming URR 55 answered cause %d, want a rule failure", got)
	}
	_, seqn, _, up := reportOf(t, c.Modify(query(seid, 3, ie.NewQueryURR(ie.NewURRID(7)))))
	if seqn != 0 || up != 1500 {
		t.Errorf("after the refused request the report is UR-SEQN %d with %d octets; want the window intact: 0 and 1500", seqn, up)
	}
}

func TestRemovingAURRReportsItsLastWindowAsATerminationReport(t *testing.T) {
	c, _, seid, _ := measured(t, 0x3065, 900, 6)
	mod := query(seid, 2,
		ie.NewUpdatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, 0x1000, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.2", "", 0, 0)),
			ie.NewFARID(1)),
		ie.NewRemoveURR(ie.NewURRID(7)))
	urr, _, trig, up := reportOf(t, c.Modify(mod))
	if urr != 7 || up != 900 {
		t.Errorf("the report is URR %d with %d uplink octets; want URR 7 with 900", urr, up)
	}
	if len(trig) < 2 || trig[0] != 0 || trig[1] != 0x08 {
		t.Errorf("the trigger is %#v, want only TERMR", trig)
	}
}

func TestMeasurementInformationThatAsksForWhatIsDoneIsAccepted(t *testing.T) {
	// free5GC sets MBQE|MNOP on every URR it sends (0x11) and 0 elsewhere; a
	// real SMF's session is refused by the old blanket refusal. 0, MNOP, ISTM
	// and MBQE are accepted; INAM and RADI stay refused.
	for value, want := range map[uint8]uint8{
		0x00: ie.CauseRequestAccepted, 0x10: ie.CauseRequestAccepted, 0x11: ie.CauseRequestAccepted,
		0x08: ie.CauseRequestAccepted, 0x02: ie.CauseRuleCreationModificationFailure,
		0x04: ie.CauseRuleCreationModificationFailure, 0x13: ie.CauseRuleCreationModificationFailure,
	} {
		c := New(testConfig(), &recorder{}, quietLogger())
		urr := ie.NewCreateURR(ie.NewURRID(7), ie.NewMeasurementMethod(0, 1, 0), ie.NewReportingTriggers(0x02, 0x00),
			ie.NewVolumeThreshold(0x01, 1<<20, 0, 0), ie.NewMeasurementInformation(value))
		if got := cause(t, c.Establish(urrEstablishment(0x3081+uint64(value), 7, urr))); got != want {
			t.Errorf("Measurement Information %#x answered cause %d, want %d", value, got, want)
		}
	}
}

func TestTheEstablishmentResponseNamesTheNodeAndTheUPFSEIDAddress(t *testing.T) {
	cfg := testConfig()
	cfg.NodeID, cfg.N4Addr = "10.77.88.1", netip.MustParseAddr("10.77.88.1")
	c := New(cfg, &recorder{}, quietLogger())
	resp := c.Establish(urrEstablishment(0x3091, 7, quotaURR(7, 1<<30))).(*message.SessionEstablishmentResponse)
	if resp.NodeID == nil {
		t.Fatal("no Node ID in the response (mandatory, Table 7.5.3.1-1)")
	}
	if id, _ := resp.NodeID.NodeID(); id != "10.77.88.1" {
		t.Errorf("Node ID %q, want 10.77.88.1", id)
	}
	f, err := resp.UPFSEID.FSEID()
	if err != nil || f.IPv4Address == nil || f.IPv4Address.String() != "10.77.88.1" {
		t.Errorf("UP F-SEID %+v (%v), want it to carry 10.77.88.1", f, err)
	}
}
