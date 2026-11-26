// The delivered base: what a report the session's end overtook still holds.
//
// A tick opens a report's window when it *decides* the report (decide), not
// when the message is delivered: the queue holds the message and the next tick
// must not report the same usage twice. The loop sends one report per session
// per tick, so a session whose two URRs are both due has one message in flight
// and the other queued behind it. A session that ends in between must report the
// queued report's usage in its termination report -- the base of the last
// *delivered* report, not the last one a report was made from
// (docs/claims.md, finding 20).
package session

import (
	"context"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/krsna1729/upf/internal/bess"
)

// twoURREstablishment is free5GC's stock shape: one PDR measured by two URRs
// (its URR 1 and URR 2), each with a volume threshold and a period.
func twoURREstablishment(cpSEID, threshold uint64) *message.SessionEstablishmentRequest {
	volth := func(id uint32) *ie.IE {
		return ie.NewCreateURR(
			ie.NewURRID(id),
			ie.NewMeasurementMethod(0, 1, 0),    // VOLUM
			ie.NewReportingTriggers(0x03, 0x00), // PERIO and VOLTH
			ie.NewMeasurementPeriod(10*time.Second),
			ie.NewVolumeThreshold(0x01, threshold, 0, 0), // TOVOL
		)
	}
	return message.NewSessionEstablishmentRequest(0, 0, cpSEID, 1, 0,
		ie.NewFSEID(cpSEID, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, 0x1000, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.2", "", 0, 0)),
			ie.NewFARID(1), ie.NewURRID(7), ie.NewURRID(8)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
		volth(7), volth(8),
	)
}

// terminationWindows is a deletion response's Usage Report IEs by URR: each
// URR's last window, as the SMF bills it.
func terminationWindows(t *testing.T, out *message.SessionDeletionResponse) map[uint32]Usage {
	t.Helper()
	got := make(map[uint32]Usage, len(out.UsageReport))
	for _, report := range out.UsageReport {
		children, err := report.UsageReport()
		if err != nil {
			t.Fatal(err)
		}
		var uid uint32
		var use Usage
		for _, ch := range children {
			switch ch.Type {
			case ie.URRID:
				uid, _ = ch.URRID()
			case ie.VolumeMeasurement:
				vol, _ := ch.VolumeMeasurement()
				use = Usage{Packets: vol.UplinkNumberOfPackets, Octets: vol.UplinkVolume}
			}
		}
		got[uid] = use
	}
	return got
}

// eraseCounts is what the daemon sends with a session's entry erase (BESS
// D-210): a SessionEraseCounts with the counts in the uplink reading, and a
// downlink reading that names the same actions with nothing counted -- the
// shape a daemon that reports every action in both directions answers. The
// controller must read each direction's entries for that direction's rules
// only: folded into one table, the zero downlink entries overwrote the uplink
// usage.
func eraseCounts(counts map[string][]bess.RuleCount) []byte {
	var up, down []byte
	for _, module := range counts {
		for _, c := range module {
			var rc []byte
			rc = protowire.AppendVarint(protowire.AppendTag(rc, 1, protowire.VarintType), uint64(c.ActionID))
			down = protowire.AppendBytes(protowire.AppendTag(down, 1, protowire.BytesType), rc)
			rc = protowire.AppendVarint(protowire.AppendTag(rc, 2, protowire.VarintType), c.Packets)
			rc = protowire.AppendVarint(protowire.AppendTag(rc, 3, protowire.VarintType), c.Octets)
			up = protowire.AppendBytes(protowire.AppendTag(up, 1, protowire.BytesType), rc)
		}
	}
	reply := protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), up)
	return protowire.AppendBytes(protowire.AppendTag(reply, 2, protowire.BytesType), down)
}

// A termination report built from the erase's own reading says exactly what a
// get_counts call before the erase says, and makes no call.
func TestTheTerminationReportFromAnEraseMatchesOneFromAReading(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(twoURREstablishment(0x4011, 1000)).(*message.SessionEstablishmentResponse)
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
	set(10000+2052, 109)
	reports := evaluate(t, c, seid)
	if len(reports) != 2 {
		t.Fatalf("%d reports from one tick, want one per URR (7 and 8)", len(reports))
	}
	for _, r := range reports {
		if r.URRID == 7 {
			c.ConfirmReport(context.Background(), r)
		}
	}
	set(10000+4560, 120)

	c.mu.Lock()
	s := c.sessions[seid]
	c.mu.Unlock()
	now := time.Now()
	const sessions = "upf/sessions"
	reads := len(rec.calls)
	fromErase := c.terminationReportsFrom(s, now, []bess.Observed{{Resource: sessions, Bytes: eraseCounts(rec.counts)}}, sessions)
	if len(rec.calls) != reads {
		t.Fatalf("the erase report made %d counter reads, want none", len(rec.calls)-reads)
	}
	fromRead := c.terminationReports(context.Background(), s, now)

	if len(fromErase) != len(fromRead) {
		t.Fatalf("the erase report has %d IEs, the reading %d", len(fromErase), len(fromRead))
	}
	for i := range fromErase {
		want, got := fromRead[i], fromErase[i]
		if got.Type != want.Type {
			t.Fatalf("IE %d is type %d, want %d", i, got.Type, want.Type)
		}
		w, err := want.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		g, err := got.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(g, w) {
			t.Errorf("IE %d differs: erase %x, reading %x", i, g, w)
		}
	}
}

func TestTheTerminationReportCarriesWhatADecidedReportStillHolds(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(twoURREstablishment(0x4011, 1000)).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	seid := upFSEID(t, resp)
	rule := ruleCarrying(t, rec.last(), fieldSrcIP, []byte{10, 45, 0, 2})
	module := testConfig().Up.Counters
	set := func(o, p uint64) {
		rec.counts = map[string][]bess.RuleCount{module: {{ActionID: rule.actionID(), Packets: p, Octets: o}}}
	}
	set(10000, 100) // the baseline: the first reading of a URR is not usage
	if reports := evaluate(t, c, seid); len(reports) != 0 {
		t.Fatalf("the baseline reading reported %+v", reports)
	}

	// 9 packets each way, over both URRs' 1000-octet threshold: both are due in
	// one tick, and the loop delivers one report per session per tick.
	set(10000+2052, 109)
	reports := evaluate(t, c, seid)
	if len(reports) != 2 {
		t.Fatalf("%d reports from one tick, want one per URR (7 and 8)", len(reports))
	}
	for _, r := range reports {
		if r.URRID == 7 {
			c.ConfirmReport(context.Background(), r) // the one the SMF answered
		}
	}

	// The traffic runs on: 11 more packets each way, and the session ends
	// before URR 8's queued report is delivered.
	set(10000+4560, 120)
	got := terminationWindows(t, deleteAndParse(t, c, seid))
	if want := (Usage{Packets: 11, Octets: 2508}); got[7] != want {
		t.Errorf("URR 7's termination window is %+v, want %+v: the usage after the report the SMF answered", got[7], want)
	}
	if want := (Usage{Packets: 20, Octets: 4560}); got[8] != want {
		t.Errorf("URR 8's termination window is %+v, want %+v: nothing of its usage was ever delivered", got[8], want)
	}
}
