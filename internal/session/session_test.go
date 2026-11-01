// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
	"google.golang.org/grpc/codes"

	"github.com/krsna1729/upf/internal/bess"
	"github.com/krsna1729/upf/internal/scaletest"
)

// recorder is an Applier that keeps every transaction, so a test can read what
// the compiler would have written to bessd.
type recorder struct {
	txns [][]bess.Change
	fail error
	// counts is the fake dataplane's counting modules, by module name: what
	// RuleCounts answers, and the failure it answers with when readFail is set.
	counts   map[string][]bess.RuleCount
	readFail error
	// errors is the fake GTP-U responders' Error Indication logs, by module
	// name: what DrainErrors answers once and then forgets, as the module does
	// (finding 15).
	errors map[string][]uint32
	// endMarkers is the fake responders' End Marker logs, by module name: what
	// DrainEndMarkers answers once and then forgets, as the module does.
	endMarkers map[string][]bess.EndMarker
	// calls is every counter reading the compiler made, in order: what the
	// usage-report tick's cost is measured by (one read per module rather than
	// one per session, report_test.go).
	calls []readCall
	// ops counts what the fake served, by name: "Apply" for each transaction
	// it took, and a counting module's name for each reading of it (a peek
	// included), so a scale test bounds them with scaletest.RPCsAtMost.
	ops scaletest.Ops
	// entries is the fake's own state for the counting modules: what Apply has
	// written and not erased (see Apply).
	entries map[string]bool
	// released and dropped are the store commands the compiler sent, as
	// "module/id": what the SMF's instruction did to the packets a buffering
	// flow held (5.2.4.1), and storeFail is what the fake store answers with
	// when a test wants the refusal path.
	released  []string
	dropped   []string
	cleared   []string
	storeFail error
}

// ReleaseFlow and DropFlow are the packet store's commands (StoreCommands): the
// fake records them, so a test can see a modification's instruction reach the
// packets.
func (r *recorder) ReleaseFlow(_ context.Context, module string, id uint32) error {
	if r.storeFail != nil {
		return r.storeFail
	}
	r.released = append(r.released, fmt.Sprintf("%s/%d", module, id))
	return nil
}

// ClearStore is the restart wall's call (StoreCommands): the fake records it the
// way it records the release and drop commands.
func (r *recorder) ClearStore(_ context.Context, module string) error {
	if r.storeFail != nil {
		return r.storeFail
	}
	r.cleared = append(r.cleared, module)
	return nil
}

func (r *recorder) DropFlow(_ context.Context, module string, id uint32) error {
	if r.storeFail != nil {
		return r.storeFail
	}
	r.dropped = append(r.dropped, fmt.Sprintf("%s/%d", module, id))
	return nil
}

func (r *recorder) Apply(_ context.Context, changes ...bess.Change) error {
	if r.fail != nil {
		return r.fail
	}
	// The counting modules are modelled, because their entries are the one
	// resource family where a transaction can erase something that is not
	// there: the engine refuses that outright (bess's erase_missing), and a
	// fake that accepts it cannot see the bug that leaves a session neither
	// modifiable nor deletable.
	if r.entries == nil {
		r.entries = map[string]bool{}
	}
	// A second operation on one (resource, key) in one transaction is what the
	// engine rejects (the compiler works around it for rules, actions and
	// counters); the counting modules are where the fake models it, because
	// their erases are the ones a session's lifetime walks.
	touched := map[string]bool{}
	for i, ch := range changes {
		if !strings.Contains(ch.Resource, "counters") {
			continue
		}
		key := ch.Resource + "\x00" + fmt.Sprint(ch.Key)
		if touched[key] {
			return fmt.Errorf("change %d touches %s twice in one transaction: %w",
				i, key, errRepeatedOperation)
		}
		touched[key] = true
		if ch.Value == nil {
			if !r.entries[key] {
				return fmt.Errorf("change %d erases %s, which is not there: %w",
					i, key, errEraseMissing)
			}
			delete(r.entries, key)
			continue
		}
		r.entries[key] = true
	}
	r.txns = append(r.txns, changes)
	r.ops.Add("Apply")
	return nil
}

// errEraseMissing is what the fake dataplane answers for an erase of a key it
// does not hold: bess refuses the whole transaction, exactly as this does.
var errEraseMissing = errors.New("the key is not there to erase")

// errRepeatedOperation is what it answers for two operations on one key in one
// transaction: the engine refuses that too (the compiler's bookkeeping exists
// to avoid it).
var errRepeatedOperation = errors.New("one key touched twice in one transaction")

// readCall is one counter reading the compiler made: the module it named and
// how many of that module's rules it named. A reading that names no rule is the
// module's own bulk read -- every rule it holds, in one round trip.
type readCall struct {
	module string
	rules  int
}

// RuleCounts answers the rules asked for; a rule the fake does not hold reads
// zero, which is what a module with no traffic says. Naming no rule is the
// module's own reading of **every rule it holds**, which is what the daemon's
// get_counts answers for an empty action_ids (urr_count.cc). The call is
// recorded either way, so a test can count them.
func (r *recorder) RuleCounts(_ context.Context, module string, actionIDs ...uint32) ([]bess.RuleCount, error) {
	r.calls = append(r.calls, readCall{module: module, rules: len(actionIDs)})
	r.ops.Add(module)
	if r.readFail != nil {
		return nil, r.readFail
	}
	if len(actionIDs) == 0 {
		out := make([]bess.RuleCount, 0, len(r.counts[module]))
		out = append(out, r.counts[module]...)
		return out, nil
	}
	held := map[uint32]bess.RuleCount{}
	for _, count := range r.counts[module] {
		held[count.ActionID] = count
	}
	out := make([]bess.RuleCount, 0, len(actionIDs))
	for _, id := range actionIDs {
		count := held[id]
		count.ActionID = id
		out = append(out, count)
	}
	return out, nil
}

// DrainErrors answers a GtpuResponder's Error Indication log (ErrorReader): the
// TEIDs the test seeded, each returned once, as drain_errors does.
func (r *recorder) DrainErrors(_ context.Context, module string) ([]uint32, uint64, error) {
	if r.readFail != nil {
		return nil, 0, r.readFail
	}
	out := r.errors[module]
	delete(r.errors, module)
	return out, 0, nil
}

// DrainEndMarkers answers a GtpuResponder's End Marker log (EndMarkerReader):
// the events the test seeded, each returned once, as drain_end_markers does.
func (r *recorder) DrainEndMarkers(_ context.Context, module string) ([]bess.EndMarker, uint64, error) {
	if r.readFail != nil {
		return nil, 0, r.readFail
	}
	out := r.endMarkers[module]
	delete(r.endMarkers, module)
	return out, 0, nil
}

// PeekRuleCounts is RuleCounts without the window restart (WindowReader): the
// DDN path's reading, which the fake answers from the same table.
func (r *recorder) PeekRuleCounts(_ context.Context, module string, actionIDs ...uint32) ([]bess.RuleCount, error) {
	if r.readFail != nil {
		return nil, r.readFail
	}
	return r.RuleCounts(context.Background(), module, actionIDs...)
}

func (r *recorder) last() []bess.Change {
	if len(r.txns) == 0 {
		return nil
	}
	return r.txns[len(r.txns)-1]
}

// find returns the change for a resource and a key field value, or fails.
func find(t *testing.T, changes []bess.Change, resource string, keyField string, keyValue any) bess.Change {
	t.Helper()
	c, ok := find0(changes, resource, keyField, keyValue)
	if !ok {
		t.Fatalf("no change for %s with %s=%v among %d changes", resource, keyField, keyValue, len(changes))
	}
	return c
}

// find0 is find without failing, for negative assertions.
func find0(changes []bess.Change, resource string, keyField string, keyValue any) (bess.Change, bool) {
	for _, c := range changes {
		if c.Resource == resource && c.Key != nil && c.Key[keyField] == keyValue {
			return c, true
		}
	}
	return bess.Change{}, false
}

// rules is every rule change of a transaction, with its key decoded: the key
// message (WildcardMatchRuleKey) carries one FieldData per field, values and
// masks in two parallel lists.
func rules(changes []bess.Change) []rule {
	out := make([]rule, 0, len(changes))
	for _, c := range changes {
		if !strings.HasPrefix(c.Resource, "pdr_") || !strings.HasSuffix(c.Resource, "/rules") {
			continue
		}
		values, _ := c.Key["values"].([]map[string]any)
		masks, _ := c.Key["masks"].([]map[string]any)
		out = append(out, rule{change: c, values: values, masks: masks})
	}
	return out
}

// changesFor is every change of a transaction naming one resource.
func changesFor(changes []bess.Change, resource string) []bess.Change {
	var out []bess.Change
	for _, ch := range changes {
		if ch.Resource == resource {
			out = append(out, ch)
		}
	}
	return out
}

type rule struct {
	change bess.Change
	values []map[string]any
	masks  []map[string]any
}

// mask is the mask of the rule's field at index i.
func (r rule) mask(i int) []byte { b, _ := r.masks[i]["value_bin"].([]byte); return b }

// value is the value of the rule's field at index i.
func (r rule) value(i int) []byte { b, _ := r.values[i]["value_bin"].([]byte); return b }

// result is the classifier's result record: what a matching packet carries
// into the downstream modules (action id, two meter levels, next hop, and --
// on the downlink -- the steering policy id).
func (r rule) result() []byte { b, _ := r.change.Value["result"].([]byte); return b }

// actionID is the ActionId the rule's result carries.
func (r rule) actionID() uint32 {
	b := r.result()
	if len(b) < 4 {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}

// meterIDs are the two meter levels the rule's result carries, in policing
// order.
func (r rule) meterIDs() [2]uint32 {
	var ids [2]uint32
	b := r.result()
	if len(b) < 12 {
		return ids
	}
	ids[0] = binary.BigEndian.Uint32(b[4:])
	ids[1] = binary.BigEndian.Uint32(b[8:])
	return ids
}

// nextHop is the Router next hop the rule's result carries.
func (r rule) nextHop() uint32 {
	b := r.result()
	if len(b) < 16 {
		return 0
	}
	return binary.BigEndian.Uint32(b[12:])
}

// steeringID is the MAR steering policy id a downlink rule's result carries
// (0 without a MAR).
func (r rule) steeringID() uint32 {
	b := r.result()
	if len(b) < 24 {
		return 0
	}
	return binary.BigEndian.Uint32(b[20:])
}

// gate is the gate the rule delivers.
func (r rule) gate() uint64 { v, _ := r.change.Value["gate"].(uint64); return v }

// priority is the rule's priority in its table: the classifier's reading of the
// PDR's Precedence (8.2.11, inverted by rulePriority), which is what decides
// between two rules of the table that both match a packet.
func (r rule) priority() int64 { v, _ := r.change.Value["priority"].(int64); return v }

// metersErased is actionsErased for meters.
func metersErased(changes []bess.Change) []bess.Change {
	var out []bess.Change
	for _, ch := range changes {
		if ch.Value == nil && strings.HasSuffix(ch.Resource, "/meters") {
			out = append(out, ch)
		}
	}
	return out
}

// assertNoRepeat fails when a transaction names one (resource, key) twice. The
// engine rejects such a list ("second operation on ... in one transaction") and
// the recorder used by these tests would take it, so this is where a change
// list that only a fake accepts is caught.
func assertNoRepeat(t *testing.T, changes []bess.Change) {
	t.Helper()
	seen := map[string]int{}
	for _, ch := range changes {
		seen[ch.Resource+"\x00"+fmt.Sprint(ch.Key)]++
	}
	for k, n := range seen {
		if n != 1 {
			t.Errorf("the transaction names %s %d times, which the engine rejects", k, n)
		}
	}
}

// onlyErases is the changes that take records out: a change carries no value
// when it erases, and a transaction that removes an object while rewriting
// others holds both kinds.
func onlyErases(changes []bess.Change) []bess.Change {
	var out []bess.Change
	for _, ch := range changes {
		if ch.Value == nil {
			out = append(out, ch)
		}
	}
	return out
}

// teidRule is the change carrying the requested composite-key admission.
func teidRule(changes []bess.Change, resource string, teid uint32) (bess.Change, bool) {
	for _, c := range changes {
		if c.Resource == resource && c.Key["teid"] == teid {
			return c, true
		}
	}
	return bess.Change{}, false
}

// fteidContextOf is the admission context the transaction's F-TEID entry for
// teid carries: the value the decap writes and the PDR key must match.
func fteidContextOf(t *testing.T, changes []bess.Change, teid uint32) uint32 {
	t.Helper()
	ch, ok := teidRule(changes, testConfig().GTPUDecap+"/fteids", teid)
	if !ok {
		t.Fatalf("no F-TEID admission entry for %#x", teid)
	}
	id, _ := ch.Value["context_id"].(uint32)
	if id == 0 {
		t.Fatalf("the admission entry for %#x carries no context: %v", teid, ch.Value)
	}
	return id
}

// ruleCarrying finds the rule whose field i carries `want` exactly.
func ruleCarrying(t *testing.T, changes []bess.Change, i int, want []byte) rule {
	t.Helper()
	for _, r := range rules(changes) {
		if i < len(r.values) && bytes.Equal(r.value(i), want) {
			return r
		}
	}
	t.Fatalf("no rule whose field %d carries %v", i, want)
	return rule{}
}

// theFieldIndex names the fields of the test graph's key.
const (
	fieldSrcIP = iota
	fieldDstIP
)

func testConfig() Config {
	return Config{
		// Both tables match the inner IPv4 packet, the admission context the
		// decap wrote and the QFI it read; the downlink also keys the route domain.
		Up: Direction{
			PDRTable:  "pdr_ul",
			PDRFields: []Field{SrcIP, DstIP, Proto, SrcPort, DstPort, FTEIDContext, QFI},
			Meters:    "mt_ul",
			Counters:  "cnt_ul",
			NextHop:   1,
			// An uplink forward can add an outer header of its own (indirect
			// data forwarding, the uplink of an N9 tunnel): its record goes in
			// the deployment's one encap module, the same the downlink uses.
			Tunnels: "enc",
		},
		Down: Direction{
			PDRTable: "pdr_dl",
			PDRFields: []Field{SrcIP, DstIP, Proto, SrcPort, DstPort, RouteDomain,
				FTEIDContext, QFI},
			Meters: "mt_dl",
			// The downlink PDR result writes the next-hop ID the Router reads.
			// A missing `next_hop_id` fails closed; this test uses hop 2, whose
			// connection in `deploy/session-path.yaml` leads to the encap module.
			// The tunnel record is selected by the PDR result's ActionId.
			NextHop:  2,
			Tunnels:  "enc",
			Counters: "cnt_dl",
		},
		// The configured local F-TEID endpoint.
		GTPUDecap: "decap",
		FTEIDEndpoints: []FTEIDEndpoint{{
			ID: 1, ReferencePoint: "n3", TransportRouteDomain: 1,
			SourceInterface: ie.SrcInterfaceAccess, IPv4: netip.MustParseAddr("192.0.2.1"),
		}},
	}
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// establishment is the session a real SMF sends: an uplink PDR whose F-TEID is
// the UPF's to choose, and a downlink one whose FAR carries the gNB's tunnel
// endpoint and whose SDF filter names a port.
func establishment(cpSEID uint64, ueIP string) *message.SessionEstablishmentRequest {
	return establishmentWithFTEID(cpSEID, ueIP, 0)
}

// establishmentWithFTEID is establishment with the uplink F-TEID spelled out: 0
// sends CHOOSE (the UPF allocates), and a value pins it.
func establishmentWithFTEID(cpSEID uint64, ueIP string, fteid uint32) *message.SessionEstablishmentRequest {
	return message.NewSessionEstablishmentRequest(0, 0, cpSEID, 1, 0,
		ie.NewNodeID("", "", "smf"),
		ie.NewFSEID(cpSEID, nil, nil),
		ie.NewCreatePDR(
			ie.NewPDRID(1),
			ie.NewPrecedence(100),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceAccess),
				testFTEID(fteid),
				ie.NewUEIPAddress(0x02, ueIP, "", 0, 0),
			),
			ie.NewFARID(1),
			ie.NewQERID(1),
		),
		ie.NewCreatePDR(
			ie.NewPDRID(2),
			ie.NewPrecedence(100),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x06, ueIP, "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to assigned 53", "", "", "", 0),
			),
			ie.NewFARID(2),
		),
		ie.NewCreateFAR(
			ie.NewFARID(1),
			ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore)),
		),
		ie.NewCreateFAR(
			ie.NewFARID(2),
			ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceAccess),
				ie.NewOuterHeaderCreation(0x0100, 0x11223344, "10.20.30.2", "", 0, 0, 0),
			),
		),
		ie.NewCreateQER(
			ie.NewQERID(1),
			ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
			ie.NewMBR(1000, 2000),
		),
	)
}

// testFTEID is an Access PDI's F-TEID: 0 asks the UPF to choose an IPv4
// F-TEID (TS 29.244 8.2.3 CH), and any other value pins that TEID on the
// configured N3 address.
func testFTEID(teid uint32) *ie.IE {
	if teid == 0 {
		return ie.NewFTEID(0x05, 0, nil, nil, 0)
	}
	return ie.NewFTEID(0x01, teid, net.ParseIP("192.0.2.1"), nil, 0)
}

// TestABuffOnlyFARIsADrop pins what this UPF does with the one Apply Action it
// reads but cannot honour. There is no downlink buffer (docs/claims.md, gap
// 4), so a FAR that asks for BUFF and not FORW takes the drop the uplink's
// closed gate also takes. The alternative -- falling through to the forward
// path -- would deliver the packet the SMF asked to hold, which is worse than
// not buffering it.
func TestABuffOnlyFARIsADrop(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	req := establishment(0x5561, "10.45.0.7")
	// The downlink FAR asks for buffering and nothing else.
	req.CreateFAR[1] = ie.NewCreateFAR(
		ie.NewFARID(2),
		ie.NewApplyAction(applyBuff),
		ie.NewForwardingParameters(
			ie.NewDestinationInterface(ie.DstInterfaceAccess),
			ie.NewOuterHeaderCreation(0x0100, 0x11223344, "10.20.30.2", "", 0, 0, 0),
		),
	)
	if got := cause(t, c.Establish(req)); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	r := ruleCarrying(t, rec.last(), fieldDstIP, []byte{10, 45, 0, 7})
	if got := r.gate(); got != dropGate {
		t.Errorf("a BUFF-only FAR gates %d, want the drop gate %d", got, dropGate)
	}
	for _, ch := range rec.last() {
		if strings.HasSuffix(ch.Resource, "/actions") {
			t.Errorf("a BUFF-only FAR wrote an action record in %s", ch.Resource)
		}
		if ch.Resource == c.cfg.Down.Tunnels {
			t.Errorf("a BUFF-only FAR wrote a tunnel record in %s", ch.Resource)
		}
	}
}

func TestADeletionErasesEachSharedRecordOnce(t *testing.T) {
	// A session's PDRs name the same records: the meter of a QER in each
	// direction, and one F-TEID when two uplink PDRs carry it. The deletion
	// named each of them once per PDR, so one record appeared several times in
	// a single transaction -- and a second erase of a record a later change in
	// the same transaction had rewritten is not a no-op a reader can reason
	// about.
	//
	// Meters go through the QER list, where compile writes them, so a direction
	// no PDR of this session uses is erased too -- and two PDRs sharing a QER do
	// not name its meter twice.
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	req := sharedFTEIDEstablishment(0x6660, "10.45.0.5", 0x00000011)
	resp := c.Establish(req).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	del := c.Delete(message.NewSessionDeletionRequest(0, 0, upFSEID(t, resp), 2, 0)).(*message.SessionDeletionResponse)
	if got := cause(t, del); got != ie.CauseRequestAccepted {
		t.Fatalf("the deletion answered cause %d", got)
	}
	meters, fteidEntries := 0, 0
	for _, ch := range rec.last() {
		if strings.HasSuffix(ch.Resource, "/meters") {
			meters++
		}
		if ch.Resource == testConfig().GTPUDecap+"/fteids" {
			fteidEntries++
		}
	}
	if meters != 2 {
		t.Errorf("the deletion erases %d meter records, want the QER's two (one per policed direction)", meters)
	}
	if fteidEntries != 1 {
		t.Errorf("the deletion erases %d F-TEID admission entries, want one (two uplink PDRs share the F-TEID)", fteidEntries)
	}
}

// sharedFTEIDEstablishment is a session whose two uplink PDRs share one F-TEID
// and one QER: what a real session looks like when an SMF programs several
// uplink filters onto one tunnel. The two PDRs differ only in the source port
// their SDF names, so their rule keys differ while the records they name do not.
func sharedFTEIDEstablishment(cpSEID uint64, ueIP string, fteid uint32) *message.SessionEstablishmentRequest {
	return message.NewSessionEstablishmentRequest(0, 0, cpSEID, 1, 0,
		ie.NewFSEID(cpSEID, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				testFTEID(fteid),
				ie.NewUEIPAddress(0x02, ueIP, "", 0, 0),
				ie.NewSDFFilter("permit out udp from any 1000 to any", "", "", "", 0)),
			ie.NewFARID(1), ie.NewQERID(1)),
		ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(20),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				testFTEID(fteid),
				ie.NewUEIPAddress(0x02, ueIP, "", 0, 0),
				ie.NewSDFFilter("permit out udp from any 2000 to any", "", "", "", 0)),
			ie.NewFARID(1), ie.NewQERID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
		ie.NewCreateQER(ie.NewQERID(1),
			ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
			ie.NewMBR(1000, 2000)),
	)
}

// A closed gate is compiled as the PDR rule's gate with no forwarding result;
// the packet drops at the classifier before it reaches Meter or Router.
func TestModifyRemovingAPDRErasesItsRecords(t *testing.T) {
	// A Modify that removes a PDR must erase what that PDR programmed, in the
	// same transaction as the rest of the change: a rule that keeps selecting
	// packets after the SMF has been told the PDR is gone forwards them under
	// an action the session no longer has a PDR for, and the answer the SMF got
	// gives it no way to learn that.
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(establishmentWithFTEID(0x7770, "10.45.0.7", 0x22222222)).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}

	// PDR 1 is the session's only uplink PDR, so its rule, its action, the
	// session's F-TEID admission entry and its uplink meter are all its.
	mod := message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 2, 0,
		ie.NewRemovePDR(ie.NewPDRID(1)),
	)
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification answered cause %d", got)
	}
	erases := rec.last()
	r := ruleCarrying(t, erases, fieldSrcIP, []byte{10, 45, 0, 7})
	if r.change.Value != nil {
		t.Error("the removed PDR's rule was rewritten rather than erased")
	}
	if _, ok := teidRule(onlyErases(erases), testConfig().GTPUDecap+"/fteids", 0x22222222); !ok {
		t.Error("the removed PDR's F-TEID admission entry is still programmed")
	}
	// The QER outlives the PDR, and compile writes a meter for every QER the
	// session still holds: erasing that meter here would name one key twice in
	// one transaction, which the engine rejects. It goes when the session does.
	if n := len(metersErased(erases)); n != 0 {
		t.Errorf("%d meter records erased, want none while the QER is held", n)
	}
	assertNoRepeat(t, erases)

	// And the records it left behind go when the session does: the removed PDR
	// is out of the model, so a deletion that walked only the model would leave
	// its meter and any F-TEID admission entry no one else used programmed.
	del := c.Delete(message.NewSessionDeletionRequest(0, 0, upFSEID(t, resp), 3, 0)).(*message.SessionDeletionResponse)
	if got := cause(t, del); got != ie.CauseRequestAccepted {
		t.Fatalf("the deletion answered cause %d", got)
	}
	if n := len(metersErased(rec.last())); n != 2 {
		t.Errorf("%d meter records erased by the deletion, want the QER's two", n)
	}
	assertNoRepeat(t, rec.last())
	// The downlink PDR stays, so its rule is rewritten in the same transaction.
	written := 0
	for _, ch := range rules(erases) {
		if ch.change.Value != nil {
			written++
		}
	}
	if written != 1 {
		t.Errorf("%d rules written, want the surviving PDR's one", written)
	}

	// Now the shared case: two uplink PDRs on one F-TEID and one QER, one of
	// them removed. The shared admission entry and meter remain for the PDR that
	// stays; erasing either would bypass decapsulation or policing.
	rec = &recorder{}
	c = New(testConfig(), rec, quietLogger())
	resp = c.Establish(sharedFTEIDEstablishment(0x7771, "10.45.0.7", 0x33333333)).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	mod = message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 2, 0,
		ie.NewRemovePDR(ie.NewPDRID(2)),
	)
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification answered cause %d", got)
	}
	erases = rec.last()
	if _, ok := teidRule(onlyErases(erases), testConfig().GTPUDecap+"/fteids", 0x33333333); ok {
		t.Error("the removal erased an F-TEID admission entry the surviving PDR still needs")
	}
	if n := len(metersErased(erases)); n != 0 {
		t.Errorf("%d meter records erased, want none: the surviving PDR uses the meter", n)
	}
}

func TestAReleasedPinInsideTheRangeComesBack(t *testing.T) {
	// The walk visits each id once and never comes round again, and a reserved
	// id is skipped wherever the walk meets it. So a pin the walk has already
	// passed is gone for the life of the pool unless the release queues it --
	// the SMF that pinned it could not pin it again, because the pool would
	// never offer it and the pin would be refused as another session's.
	p := newIDPool(64, 0)
	p.reserve(5)

	for {
		id, err := p.alloc()
		if err != nil {
			break
		}
		if id == 5 {
			t.Fatal("the walk handed out a reserved id")
		}
	}
	if !p.walked {
		t.Fatal("the walk did not finish")
	}
	p.release(5)
	if id, err := p.alloc(); err != nil || id != 5 {
		t.Errorf("the released pin answered (%d, %v), want the value back", id, err)
	}

	// A value outside the range is a pin the pool could not have made: ending
	// its reservation must not put it in the free list, because the next
	// allocation would then carry a TEID the deployment's peer never expects.
	q := newIDPool(64, 0)
	q.reserve(0x11223344)
	for {
		if _, err := q.alloc(); err != nil {
			break
		}
	}
	q.release(0x11223344)
	if id, err := q.alloc(); err == nil {
		t.Errorf("an out-of-range pin was handed out as id %d", id)
	}
}

func TestAQueuedPinIsNotHandedOutByTheWalk(t *testing.T) {
	// A pin released before the walk reaches it is still ahead of the walk, and
	// the walk offers it; queuing it too would let both paths offer it, and one
	// id would be handed to two sessions: once here, once from the free list.
	p := newIDPool(64, 0)
	p.reserve(5)
	p.release(5)
	seen := map[uint32]int{}
	for {
		id, err := p.alloc()
		if err != nil {
			break
		}
		seen[id]++
	}
	if seen[5] != 1 {
		t.Errorf("the released pin was handed out %d times, want once", seen[5])
	}
	if len(seen) != 63 {
		t.Errorf("the pool yielded %d ids, want the whole space (63)", len(seen))
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("id %d was handed out %d times", id, n)
		}
	}
}

func TestAnUpdateThatChangesTheKeyErasesTheOldRule(t *testing.T) {
	// An update keeps a PDR's action -- the rule that already selected it keeps
	// its action id, so a worker switching between old and new state never sees
	// a dangling reference -- but the rule is keyed on the filter, and a new
	// filter is a new key. The old rule would go on selecting that action for
	// packets the PDR no longer describes, and the answer the SMF gets would
	// not say so.
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	req := message.NewSessionEstablishmentRequest(0, 0, 0x8880, 1, 0,
		ie.NewFSEID(0x8880, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x06, "10.45.0.6", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to 10.10.0.0/16 1000", "", "", "", 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess))),
	)
	resp := c.Establish(req).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	old := ruleCarrying(t, rec.last(), fieldDstIP, []byte{10, 10, 0, 0})
	actionID := old.actionID()
	if actionID == 0 {
		t.Fatalf("the establishment gave the PDR no action (%v)", actionID)
	}

	mod := message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 2, 0,
		ie.NewUpdatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x06, "10.45.0.6", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to 10.20.0.0/16 1000", "", "", "", 0)),
			ie.NewFARID(1)),
	)
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification answered cause %d", got)
	}
	txn := rec.last()
	if erased := ruleCarrying(t, txn, fieldDstIP, []byte{10, 10, 0, 0}); erased.change.Value != nil {
		t.Error("the old key was rewritten rather than erased")
	}
	written := ruleCarrying(t, txn, fieldDstIP, []byte{10, 20, 0, 0})
	if written.change.Value == nil {
		t.Fatal("the new key was not written")
	}
	if got := written.actionID(); got != actionID {
		t.Errorf("the update gave the PDR action %v, want the one it had (%v)", got, actionID)
	}
	assertNoRepeat(t, txn)
}

func TestADeletionErasesTheOldKeyOfARefusedUpdate(t *testing.T) {
	// A refused modification leaves the model holding what the SMF asked for --
	// merge folds it in before the transaction is applied -- and the dataplane
	// holding what it had, so the replaced form is the only record of the rule
	// that is still programmed. A deletion that walked only the model would
	// leave that rule selecting the PDR's action for the old filter's packets,
	// for the life of the dataplane.
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	req := message.NewSessionEstablishmentRequest(0, 0, 0x8890, 1, 0,
		ie.NewFSEID(0x8890, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x06, "10.45.0.6", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to 10.10.0.0/16 1000", "", "", "", 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess))),
	)
	resp := c.Establish(req).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}

	rec.fail = &bess.RejectedError{}
	mod := message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 2, 0,
		ie.NewUpdatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x06, "10.45.0.6", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to 10.20.0.0/16 1000", "", "", "", 0)),
			ie.NewFARID(1)),
	)
	if got := cause(t, c.Modify(mod)); got == ie.CauseRequestAccepted {
		t.Fatal("a refused modification was answered as accepted")
	}
	rec.fail = nil

	del := c.Delete(message.NewSessionDeletionRequest(0, 0, upFSEID(t, resp), 3, 0)).(*message.SessionDeletionResponse)
	if got := cause(t, del); got != ie.CauseRequestAccepted {
		t.Fatalf("the deletion answered cause %d", got)
	}
	txn := rec.last()
	old := ruleCarrying(t, txn, fieldDstIP, []byte{10, 10, 0, 0})
	if old.change.Value != nil {
		t.Error("the key the refused update left programmed was rewritten, not erased")
	}
	assertNoRepeat(t, txn)
}

func TestAnUpdateThatKeepsTheKeyWritesItOnce(t *testing.T) {
	// The other half of the stale-key rule: an update that changes something
	// else about the PDR -- its FAR here -- keeps the rule's key, and the
	// replaced form's key is the same key. Without the live-set guard the
	// transaction would erase and write one key, which the engine rejects.
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	req := message.NewSessionEstablishmentRequest(0, 0, 0x8891, 1, 0,
		ie.NewFSEID(0x8891, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x06, "10.45.0.6", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to 10.10.0.0/16 1000", "", "", "", 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess))),
	)
	resp := c.Establish(req).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	actionID := ruleCarrying(t, rec.last(), fieldDstIP, []byte{10, 10, 0, 0}).actionID()

	mod := message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 2, 0,
		ie.NewUpdatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x06, "10.45.0.6", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to 10.10.0.0/16 1000", "", "", "", 0)),
			ie.NewFARID(2)),
		ie.NewCreateFAR(ie.NewFARID(2), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess))),
	)
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification answered cause %d", got)
	}
	txn := rec.last()
	// One key, one operation: an erase of the key the write below carries is
	// what the engine rejects, so this is the assertion that names the fault.
	assertNoRepeat(t, txn)
	written := ruleCarrying(t, txn, fieldDstIP, []byte{10, 10, 0, 0})
	if written.change.Value == nil {
		t.Fatal("the update did not write the rule")
	}
	if got := written.actionID(); got != actionID {
		t.Errorf("the update gave the PDR action %v, want the one it had (%v)", got, actionID)
	}
}

func TestACHRequestIsAllocatedWhateverItsFamilyFlag(t *testing.T) {
	// TS 29.244 8.2.3: with the CH bit set, the V4/V6 bits say which address
	// family the UP function is to assign, so a real request reads 0x05 (CH|V4)
	// and carries no TEID. What makes it a request here is the absent TEID, and
	// the family bit must not be read as a value the SMF pinned: the session is
	// accepted and the Created PDR carries a TEID the SMF did not send.
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	req := message.NewSessionEstablishmentRequest(0, 0, 0x9990, 1, 0,
		ie.NewFSEID(0x9990, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x05, 0, nil, nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
	)
	resp := c.Establish(req).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("a CH request answered cause %d", got)
	}
	if n := len(resp.CreatedPDR); n != 1 {
		t.Fatalf("%d Created PDRs in the answer, want the one PDR", n)
	}
	created, err := resp.CreatedPDR[0].CreatedPDR()
	if err != nil {
		t.Fatalf("reading the Created PDR: %v", err)
	}
	var teid uint32
	for _, child := range created {
		if child.Type != ie.FTEID {
			continue
		}
		fields, err := child.FTEID()
		if err != nil {
			t.Fatalf("reading the Created PDR's F-TEID: %v", err)
		}
		if !fields.HasIPv4() || fields.HasIPv6() ||
			!net.IP(fields.IPv4Address).Equal(net.ParseIP("192.0.2.1")) {
			t.Errorf("Created PDR family/address flags are V4=%v V6=%v IPv4=%v",
				fields.HasIPv4(), fields.HasIPv6(), fields.IPv4Address)
		}
		teid = fields.TEID
	}
	if teid == 0 {
		t.Error("the answer carries no allocated TEID")
	}
}
func TestCHOOSEV6AndDualStackCreatedFTEIDFlags(t *testing.T) {
	for _, tc := range []struct {
		name         string
		flags        uint8
		want4, want6 bool
	}{
		{"IPv6", 0x06, false, true},
		{"dual stack", 0x07, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.FTEIDEndpoints = []FTEIDEndpoint{{
				ID: 1, ReferencePoint: "n3", TransportRouteDomain: 1,
				SourceInterface: ie.SrcInterfaceAccess,
				IPv4:            netip.MustParseAddr("192.0.2.1"),
				IPv6:            netip.MustParseAddr("2001:4860::1"),
			}}
			c := New(cfg, &recorder{}, quietLogger())
			cpSEID := uint64(0x9991)
			req := message.NewSessionEstablishmentRequest(0, 0, cpSEID, 1, 0,
				ie.NewFSEID(cpSEID, nil, nil),
				ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
					ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
						ie.NewFTEID(tc.flags, 0, nil, nil, 0),
						ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0)),
					ie.NewFARID(1)),
				ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
					ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
			)
			resp := c.Establish(req).(*message.SessionEstablishmentResponse)
			if got := cause(t, resp); got != ie.CauseRequestAccepted {
				t.Fatalf("CH request answered cause %d", got)
			}
			children, err := resp.CreatedPDR[0].CreatedPDR()
			if err != nil {
				t.Fatal(err)
			}
			for _, child := range children {
				if child.Type != ie.FTEID {
					continue
				}
				fields, err := child.FTEID()
				if err != nil {
					t.Fatal(err)
				}
				if fields.HasIPv4() != tc.want4 || fields.HasIPv6() != tc.want6 {
					t.Errorf("flags V4=%v V6=%v, want %v/%v", fields.HasIPv4(), fields.HasIPv6(), tc.want4, tc.want6)
				}
				if tc.want4 && !net.IP(fields.IPv4Address).Equal(net.ParseIP("192.0.2.1")) {
					t.Errorf("IPv4 address %v is incorrect", fields.IPv4Address)
				}
				if tc.want6 && !net.IP(fields.IPv6Address).Equal(net.ParseIP("2001:4860::1")) {
					t.Errorf("IPv6 address %v is incorrect", fields.IPv6Address)
				}
			}
		})
	}
}

// createdTEID is the F-TEID the answer reports for one PDR, from the answer's
// Created PDR list. Zero means the answer carries no Created PDR for that PDR,
// which is what a downlink PDR looks like: only a PDR we gave a TEID has one.
func createdTEID(t *testing.T, created []*ie.IE, pdrID uint16) uint32 {
	t.Helper()
	for _, i := range created {
		children, err := i.CreatedPDR()
		if err != nil {
			t.Fatal(err)
		}
		var id uint16
		var teid uint32
		for _, ch := range children {
			switch ch.Type {
			case ie.PDRID:
				if v, err := ch.PDRID(); err == nil {
					id = v
				}
			case ie.FTEID:
				f, err := ch.FTEID()
				if err != nil {
					t.Fatal(err)
				}
				teid = f.TEID
			}
		}
		if id == pdrID {
			return teid
		}
	}
	return 0
}

// chidEstablishment is a session whose two uplink PDIs each ask us to allocate
// an F-TEID and carry a CHOOSE ID (TS 29.244 8.2.3: V4|CH|CHID = 0x0d, no
// TEID field). The two filters name different source ports, so the PDIs are two
// rules while their F-TEID IEs are two requests for a tunnel endpoint.
func chidEstablishment(cpSEID uint64, ueIP string, first, second uint8) *message.SessionEstablishmentRequest {
	uplink := func(id uint16, port int, chid uint8) *ie.IE {
		return ie.NewCreatePDR(ie.NewPDRID(id), ie.NewPrecedence(uint32(10*id)),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x0d, 0, nil, nil, chid),
				ie.NewUEIPAddress(0x02, ueIP, "", 0, 0),
				ie.NewSDFFilter(fmt.Sprintf("permit out udp from any %d to any", port), "", "", "", 0)),
			ie.NewFARID(1), ie.NewQERID(1))
	}
	return message.NewSessionEstablishmentRequest(0, 0, cpSEID, 1, 0,
		ie.NewFSEID(cpSEID, nil, nil),
		uplink(1, 1000, first),
		uplink(2, 2000, second),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
		ie.NewCreateQER(ie.NewQERID(1),
			ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
			ie.NewMBR(1000, 2000)),
	)
}

// TestARefusedModificationKeepsTheCHIDItAllocated is the refusal case of the
// CHOOSE ID path, where merge allocates the F-TEID and writes s.chids *before*
// Apply and a refused transaction runs no settle (compile.go:341-356). Two
// things are claimed here, and they are what makes the reservation safe rather
// than a leak: the pool does not hand the value to another session, and the
// model keeps the CHOOSE ID's F-TEID, so the SMF's retry -- the next message,
// which is what a refusal invites -- names the value it was already given
// instead of allocating a second one.
func TestARefusedModificationKeepsTheCHIDItAllocated(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(chidEstablishment(0x9993, "10.45.0.6", 5, 5)).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	// A third uplink PDI on a CHOOSE ID the session does not have yet.
	addPDR := func() *message.SessionModificationRequest {
		return message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 2, 0,
			ie.NewCreatePDR(ie.NewPDRID(3), ie.NewPrecedence(30),
				ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
					ie.NewFTEID(0x0d, 0, nil, nil, 9),
					ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0),
					ie.NewSDFFilter("permit out udp from any 3000 to any", "", "", "", 0)),
				ie.NewFARID(1), ie.NewQERID(1)),
		)
	}

	rec.fail = &bess.RejectedError{}
	if got := cause(t, c.Modify(addPDR())); got == ie.CauseRequestAccepted {
		t.Fatalf("the dataplane refused the modification and the SMF was told cause %d", got)
	}
	c.mu.Lock()
	chosen, has := c.sessions[upFSEID(t, resp)].chids[9]
	held := chosen.TEID
	queued := len(c.teids.freed)
	c.mu.Unlock()
	if !has {
		t.Error("the refused modification left CHOOSE ID 9 with no F-TEID: the retry would ask the pool again")
	}
	if queued != 0 {
		t.Errorf("a refused modification put %d F-TEIDs back in the pool: another session could take a value this one holds", queued)
	}

	// The retry is the message a refusal invites, and it must hand the SMF the
	// value the session already holds -- one F-TEID per CHOOSE ID, not a second
	// one for the same ID.
	rec.fail = nil
	retry := c.Modify(addPDR()).(*message.SessionModificationResponse)
	if got := cause(t, retry); got != ie.CauseRequestAccepted {
		t.Fatalf("the retry answered cause %d", got)
	}
	if got := createdTEID(t, retry.CreatedPDR, 3); got != held {
		t.Errorf("the retry answered TEID %#x for PDR 3, want the %#x the refused request reserved", got, held)
	}

	// And the reservation ends with the session, not with the process.
	if got := cause(t, c.Delete(message.NewSessionDeletionRequest(0, 0, upFSEID(t, resp), 3, 0))); got != ie.CauseRequestAccepted {
		t.Fatalf("the deletion answered cause %d", got)
	}
	c.mu.Lock()
	_, mapped := c.fteidTEIDKeys[held]
	queued = len(c.teids.freed)
	c.mu.Unlock()
	if mapped {
		t.Error("the deleted session left its F-TEID mapping behind")
	}
	if queued == 0 {
		t.Error("the deleted session's F-TEIDs did not go back to the pool")
	}
}

func TestUplinkPDIsWithOneCHOOSEIDShareOneFTEID(t *testing.T) {
	// TS 29.244 8.2.3: with the CHID flag set, the UP function "shall assign
	// the same F-TEID to the PDRs requested to be created ... with the same
	// CHOOSE ID value". Two uplink PDIs that are two filters on one tunnel are
	// the shape that asks for it, and without the CHOOSE ID each would get a
	// TEID of its own: the answer names one TEID in both Created PDRs, and the
	// transaction writes one composite F-TEID admission entry for the group.
	// The transaction engine accepts one operation per (resource, key).
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(chidEstablishment(0x9992, "10.45.0.6", 5, 5)).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	one, two := createdTEID(t, resp.CreatedPDR, 1), createdTEID(t, resp.CreatedPDR, 2)
	if one == 0 || two == 0 {
		t.Fatalf("the answer carries no F-TEID for one of the two PDIs (%#x, %#x)", one, two)
	}
	if one != two {
		t.Errorf("two PDIs with CHOOSE ID 5 got TEIDs %#x and %#x: they asked for one tunnel", one, two)
	}
	changes := rec.last()
	assertNoRepeat(t, changes)
	entries := 0
	for _, ch := range changes {
		if ch.Resource == testConfig().GTPUDecap+"/fteids" {
			entries++
		}
	}
	if entries != 1 {
		t.Errorf("the transaction writes %d F-TEID admission entries, want one for the group", entries)
	}
	if _, ok := teidRule(changes, testConfig().GTPUDecap+"/fteids", one); !ok {
		t.Errorf("the transaction writes no F-TEID admission entry for %#x", one)
	}
	// The group is the tunnel, not the filter: each PDI still has its own rule.
	if n := len(rules(changes)); n != 2 {
		t.Errorf("%d PDR rules in the transaction, want one per PDI", n)
	}
}

func TestTwoCHOOSEIDsGetTwoFTEIDs(t *testing.T) {
	// Two CHOOSE IDs are two groups, and nothing in 8.2.3 makes two values one
	// tunnel: an SMF that asks for two gets two, each shared by the PDIs that
	// name it. (An implementation that gave every CHOOSE request in a session
	// one F-TEID would pass the single-group test above and fail this one.)
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(chidEstablishment(0x9993, "10.45.0.7", 5, 6)).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	one, two := createdTEID(t, resp.CreatedPDR, 1), createdTEID(t, resp.CreatedPDR, 2)
	if one == 0 || two == 0 {
		t.Fatalf("the answer carries no F-TEID for one of the two PDIs (%#x, %#x)", one, two)
	}
	if one == two {
		t.Errorf("CHOOSE IDs 5 and 6 share TEID %#x: they are two tunnels", one)
	}
	changes := rec.last()
	assertNoRepeat(t, changes)
	for _, teid := range []uint32{one, two} {
		if _, ok := teidRule(changes, testConfig().GTPUDecap+"/fteids", teid); !ok {
			t.Errorf("the transaction writes no F-TEID admission entry for %#x", teid)
		}
	}
}

func TestCHOOSEIDStateIsScopedToPFCPSession(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	first := c.Establish(chidEstablishment(0x99a1, "10.45.0.21", 5, 5)).(*message.SessionEstablishmentResponse)
	if got := cause(t, first); got != ie.CauseRequestAccepted {
		t.Fatalf("the first session answered cause %d", got)
	}
	firstTEID := createdTEID(t, first.CreatedPDR, 1)
	if firstTEID == 0 || createdTEID(t, first.CreatedPDR, 2) != firstTEID {
		t.Fatal("the first session did not receive one shared F-TEID for CHOOSE ID 5")
	}

	second := c.Establish(chidEstablishment(0x99a2, "10.45.0.22", 5, 5)).(*message.SessionEstablishmentResponse)
	if got := cause(t, second); got != ie.CauseRequestAccepted {
		t.Fatalf("a separate session reusing CHOOSE ID 5 answered cause %d", got)
	}
	secondTEID := createdTEID(t, second.CreatedPDR, 1)
	if secondTEID == 0 || createdTEID(t, second.CreatedPDR, 2) != secondTEID {
		t.Fatal("the second session did not receive one shared F-TEID for CHOOSE ID 5")
	}
	if secondTEID == firstTEID {
		t.Fatalf("separate PFCP sessions share F-TEID %#x for the same CHOOSE ID", secondTEID)
	}

	if got := cause(t, c.Delete(message.NewSessionDeletionRequest(0, 0, upFSEID(t, first), 3, 0))); got != ie.CauseRequestAccepted {
		t.Fatalf("deleting the first session answered cause %d", got)
	}
	reuse := c.Establish(establishmentWithFTEID(0x99a3, "10.45.0.23", firstTEID))
	if got := cause(t, reuse); got != ie.CauseRequestAccepted {
		t.Fatalf("the deleted session's F-TEID %#x was not released: cause %d", firstTEID, got)
	}

	writes := len(rec.txns)
	collision := c.Establish(establishmentWithFTEID(0x99a4, "10.45.0.24", secondTEID))
	if got := cause(t, collision); got != ie.CauseNoResourcesAvailable {
		t.Fatalf("a third session claimed the live second session's F-TEID %#x with cause %d, want 75",
			secondTEID, got)
	}
	if len(rec.txns) != writes {
		t.Fatal("the refused cross-session F-TEID claim reached the dataplane")
	}
}

func TestSharedCHIDMustKeepTheSameEndpointFamilySet(t *testing.T) {
	cfg := testConfig()
	cfg.FTEIDEndpoints[0].IPv6 = netip.MustParseAddr("2001:4860::1")
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())
	cpSEID := uint64(0x9998)
	req := message.NewSessionEstablishmentRequest(0, 0, cpSEID, 1, 0,
		ie.NewFSEID(cpSEID, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x0d, 0, nil, nil, 5),
				ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0)),
			ie.NewFARID(1)),
		ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(20),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x0e, 0, nil, nil, 5),
				ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
	)
	resp := c.Establish(req)
	if got := cause(t, resp); got == ie.CauseRequestAccepted {
		t.Fatal("shared CHID accepted different requested family sets")
	}
	if len(rec.txns) != 0 {
		t.Fatal("family-set mismatch reached Apply")
	}
	c.mu.Lock()
	owners, reserved := len(c.byFTEID), len(c.fteidTEIDKeys)
	c.mu.Unlock()
	if owners != 0 || reserved != 0 {
		t.Fatalf("failed shared CHID left ownership behind: owners=%d TEID refs=%d", owners, reserved)
	}
}
func TestZeroTEIDRequiresChooseFlag(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	cpSEID := uint64(0x9999)
	req := message.NewSessionEstablishmentRequest(0, 0, cpSEID, 1, 0,
		ie.NewFSEID(cpSEID, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, 0, nil, nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
	)
	if got := cause(t, c.Establish(req)); got == ie.CauseRequestAccepted {
		t.Fatal("TEID 0 without CHOOSE was accepted")
	}
	if len(rec.txns) != 0 {
		t.Fatal("invalid TEID 0 reached Apply")
	}
}

func TestACHOOSEIDIsTheSessionsFTEIDForThatGroup(t *testing.T) {
	// The CHOOSE ID names a group of PDIs, not one request: a PDI a later
	// modification creates with the ID the session has already used gets the
	// same F-TEID -- a group whose value changed per message would be no group
	// at all, and the SMF would have no way to learn that its second request
	// was answered with another tunnel.
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(chidEstablishment(0x9994, "10.45.0.8", 7, 7)).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	want := createdTEID(t, resp.CreatedPDR, 1)

	mod := message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 2, 0,
		ie.NewCreatePDR(ie.NewPDRID(3), ie.NewPrecedence(30),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x0d, 0, nil, nil, 7),
				ie.NewUEIPAddress(0x02, "10.45.0.8", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any 3000 to any", "", "", "", 0)),
			ie.NewFARID(1), ie.NewQERID(1)),
	)
	modified := c.Modify(mod).(*message.SessionModificationResponse)
	if got := cause(t, modified); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification answered cause %d", got)
	}
	if got := createdTEID(t, modified.CreatedPDR, 3); got != want {
		t.Errorf("the PDI created with CHOOSE ID 7 got TEID %#x, want the group's %#x", got, want)
	}
	assertNoRepeat(t, rec.last())
}

func TestAModificationThatAsksForNoFTEIDIsAnsweredWithNone(t *testing.T) {
	// Table 7.5.5.1-1: a Created PDR is in a Modification Response only for a
	// PDI that asked the UP function to choose its F-TEID. free5GC's second
	// message of a session (Update FAR with the gNB's tunnel) asks for none,
	// and used to be answered with the uplink tunnel the establishment had
	// already reported.
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(chidEstablishment(0x9995, "10.45.0.8", 7, 7)).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	if len(resp.CreatedPDR) == 0 {
		t.Fatal("the establishment, which asked for F-TEIDs, reported none")
	}

	mod := message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 2, 0,
		ie.NewUpdateFAR(ie.NewFARID(1), ie.NewApplyAction(0x02),
			ie.NewUpdateForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))))
	modified := c.Modify(mod).(*message.SessionModificationResponse)
	if got := cause(t, modified); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification answered cause %d", got)
	}
	if n := len(modified.CreatedPDR); n != 0 {
		t.Errorf("a modification that asked for no F-TEID was answered with %d Created PDR(s)", n)
	}
}

func TestACHOOSEIDsFTEIDIsLetGoWithItsLastPDI(t *testing.T) {
	// The session holds an F-TEID per group while a PDR of that group is live.
	// Once the last PDR is gone the TEID returns to the pool. A later PDR with
	// the same CHOOSE ID must not reuse it from a stale group: another session
	// may own the value by then, causing a cross-session full-key conflict that
	// the compiler must reject.
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(chidEstablishment(0x9995, "10.45.0.9", 9, 9)).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	gone := createdTEID(t, resp.CreatedPDR, 1)

	mod := message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 2, 0,
		ie.NewRemovePDR(ie.NewPDRID(1)), ie.NewRemovePDR(ie.NewPDRID(2)))
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the removal answered cause %d", got)
	}

	mod = message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 3, 0,
		ie.NewCreatePDR(ie.NewPDRID(3), ie.NewPrecedence(30),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x0d, 0, nil, nil, 9),
				ie.NewUEIPAddress(0x02, "10.45.0.9", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any 4000 to any", "", "", "", 0)),
			ie.NewFARID(1), ie.NewQERID(1)),
	)
	modified := c.Modify(mod).(*message.SessionModificationResponse)
	if got := cause(t, modified); got != ie.CauseRequestAccepted {
		t.Fatalf("the creation answered cause %d", got)
	}
	if got := createdTEID(t, modified.CreatedPDR, 3); got == gone {
		t.Errorf("a CHOOSE ID whose PDIs are gone kept TEID %#x, which the pool has taken back", gone)
	}
}

// testConfig configures N3 with IPv4 only. A V6-only CHOOSE request cannot be
// answered with that endpoint's IPv4 address; the compiler must refuse it.
// TestCHOOSEV6AndDualStackCreatedFTEIDFlags covers configured IPv6 endpoints.
func TestACHOOSEForIPv6RequiresConfiguredEndpoint(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	req := message.NewSessionEstablishmentRequest(0, 0, 0x9996, 1, 0,
		ie.NewFSEID(0x9996, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x06, 0, nil, nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
	)
	if got := cause(t, c.Establish(req)); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("an IPv6 CHOOSE request answered cause %d, want a rule failure", got)
	}
	if len(rec.txns) != 0 {
		t.Error("a refused session wrote to the dataplane")
	}
}

func TestCHOOSEFamiliesMustExistOnTheEndpoint(t *testing.T) {
	// TS 29.244 8.2.3 asks the UP to assign an IPv4 or IPv6 F-TEID address
	// when the V4 or V6 bit is set respectively. testConfig's N3 endpoint is
	// IPv4-only: V4 is served, a family-less CH is read as IPv4, and V4|V6 is
	// refused because the endpoint cannot supply the IPv6 half.
	for _, tc := range []struct {
		flags uint8
		want  uint8
	}{
		{0x05, ie.CauseRequestAccepted},
		{0x04, ie.CauseRequestAccepted},
		{0x07, ie.CauseRuleCreationModificationFailure},
	} {
		rec := &recorder{}
		c := New(testConfig(), rec, quietLogger())
		req := message.NewSessionEstablishmentRequest(0, 0, 0x9997, 1, 0,
			ie.NewFSEID(0x9997, nil, nil),
			ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
				ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
					ie.NewFTEID(tc.flags, 0, nil, nil, 0),
					ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0)),
				ie.NewFARID(1)),
			ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
				ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
		)
		resp := c.Establish(req).(*message.SessionEstablishmentResponse)
		if got := cause(t, resp); got != tc.want {
			t.Errorf("a CHOOSE request with flags %#x answered cause %d, want %d", tc.flags, got, tc.want)
			continue
		}
		if tc.want != ie.CauseRequestAccepted {
			if len(rec.txns) != 0 {
				t.Errorf("a refused CHOOSE request with flags %#x wrote to the dataplane", tc.flags)
			}
			continue
		}
		if teid := createdTEID(t, resp.CreatedPDR, 1); teid == 0 {
			t.Errorf("a CHOOSE request with flags %#x carries no allocated TEID", tc.flags)
		}
	}
}

// TestASecondSessionsRuleCannotTakeTheFirsts: the PDR tables are shared by every
// session and one key is one rule, so a graph whose key is the tuple alone makes
// two sessions for one UE address compile to the same key. Writing it would take
// the first session's packets, and the second session's deletion would erase the
// rule the first still holds -- so the second is refused, and the key is free
// again when the first goes.
func TestASecondSessionsRuleCannotTakeTheFirsts(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	if got := cause(t, c.Establish(establishmentWithFTEID(1, "10.45.0.2", 0x11223344))); got != ie.CauseRequestAccepted {
		t.Fatalf("the first establishment answered cause %d", got)
	}
	before := len(rec.txns)
	resp := c.Establish(establishmentWithFTEID(2, "10.45.0.2", 0x11223345))
	if got := cause(t, resp); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a second session for one UE address answered cause %d, want a rule failure", got)
	}
	if len(rec.txns) != before {
		t.Errorf("the refused session wrote %d transactions, want none", len(rec.txns)-before)
	}
	// The first session is untouched, and its own deletion works.
	if got := cause(t, c.Delete(message.NewSessionDeletionRequest(0, 0, 1, 2, 0))); got != ie.CauseRequestAccepted {
		t.Fatalf("deleting the first session answered cause %d", got)
	}
	// The key is free once its rule is erased: the same session is served now.
	if got := cause(t, c.Establish(establishmentWithFTEID(2, "10.45.0.2", 0x11223345))); got != ie.CauseRequestAccepted {
		t.Errorf("after the first session went, the second answered cause %d, want accepted", got)
	}
}

func TestAFailedCompileKeepsTheKeysTheSessionHeld(t *testing.T) {
	// A compile that fails partway gives up the claims it made on the way, and
	// only those: a key the session already held has its rule in the dataplane,
	// and freeing it would let the next session program over a rule that is
	// still selecting this one's packets.
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	// The F-TEID is pinned, so the modification can name the session's own.
	if got := cause(t, c.Establish(establishmentWithFTEID(0x9601, "10.45.0.2", 0x22222222))); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	// A third uplink PDR whose PDI compiles to the first's rule key: the
	// refusal lands in the middle of the compile, after the model's own keys
	// have been walked -- which is where a rollback that freed everything the
	// walk touched would free the keys the session really holds.
	same := message.NewSessionModificationRequest(0, 0, 1, 2, 0,
		ie.NewCreatePDR(ie.NewPDRID(3), ie.NewPrecedence(20),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, 0x22222222, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.2", "", 0, 0)),
			ie.NewFARID(1), ie.NewQERID(1)),
	)
	if got := cause(t, c.Modify(same)); got != ie.CauseRuleCreationModificationFailure {
		t.Fatalf("two PDRs compiling to one rule key answered cause %d, want a rule failure", got)
	}
	// The failed compile wrote nothing, and the session's keys are still its
	// own: a second session for the same address is refused. (With the claims
	// dropped on the way out, it was served -- and the first session's retry
	// would then have erased its rules.)
	if got := cause(t, c.Establish(establishment(0x9602, "10.45.0.2"))); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a session for an address a live session holds answered cause %d, want a rule failure", got)
	}
}

func TestARefusedMoveKeepsTheKeysRule(t *testing.T) {
	// A modification that moves a rule's key erases the rule it left behind.
	// The claim on that key goes when the erasing transaction has landed: a
	// refused transaction leaves the old rule programmed, so a claim dropped at
	// build time would let another session write over the rule -- and be erased
	// by this session's retry.
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(establishment(0x9701, "10.45.0.2")).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	// The downlink PDR moves to another UE address: the key it leaves
	// (-, 10.45.0.2, udp, -, 53) is erased by a transaction the dataplane then
	// refuses.
	move := func() *message.SessionModificationRequest {
		return message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 2, 0,
			ie.NewUpdatePDR(ie.NewPDRID(2), ie.NewPrecedence(100),
				ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
					ie.NewUEIPAddress(0x06, "10.45.0.7", "", 0, 0),
					ie.NewSDFFilter("permit out udp from any to assigned 53", "", "", "", 0)),
				ie.NewFARID(2)),
		)
	}
	rec.fail = &bess.RejectedError{}
	if got := cause(t, c.Modify(move())); got == ie.CauseRequestAccepted {
		t.Fatal("a refused modification was answered as accepted")
	}
	rec.fail = nil
	// Another session whose downlink rule is the key the refused transaction
	// would have erased: while the old rule is programmed the key is the first
	// session's, and this one is refused.
	other := func() *message.SessionEstablishmentRequest {
		return message.NewSessionEstablishmentRequest(0, 0, 0x9702, 1, 0,
			ie.NewFSEID(0x9702, nil, nil),
			ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100),
				ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
					ie.NewFTEID(0x01, 0x11223345, net.ParseIP("192.0.2.1"), nil, 0),
					ie.NewUEIPAddress(0x02, "10.45.0.5", "", 0, 0)),
				ie.NewFARID(1)),
			ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(100),
				ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
					ie.NewUEIPAddress(0x06, "10.45.0.5", "", 0, 0),
					ie.NewSDFFilter("permit out udp from any to 10.45.0.2/32 53", "", "", "", 0)),
				ie.NewFARID(2)),
			ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
				ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
			ie.NewCreateFAR(ie.NewFARID(2), ie.NewApplyAction(applyForw),
				ie.NewForwardingParameters(
					ie.NewDestinationInterface(ie.DstInterfaceAccess),
					ie.NewOuterHeaderCreation(0x0100, 0x55667788, "10.20.30.2", "", 0, 0, 0))),
		)
	}
	if got := cause(t, c.Establish(other())); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a session for a key a refused update left programmed answered cause %d, want a rule failure", got)
	}
	// The retry is what the refusal invites: once the erasing transaction has
	// landed, the key is given up and the same session is served.
	if got := cause(t, c.Modify(move())); got != ie.CauseRequestAccepted {
		t.Fatalf("the retry answered cause %d", got)
	}
	if got := cause(t, c.Establish(other())); got != ie.CauseRequestAccepted {
		t.Errorf("after the retry the second session answered cause %d, want accepted", got)
	}
}

func TestADeletionFreesOnlyItsOwnRuleKeys(t *testing.T) {
	// A release walks the deleted session's own key list rather than the
	// compiler's whole table of owners. A key another session holds is not the
	// deleted session's to free, and the list is what keeps a release from
	// costing every live key.
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	first := c.Establish(establishment(0x9b01, "10.45.0.2")).(*message.SessionEstablishmentResponse)
	if got := cause(t, first); got != ie.CauseRequestAccepted {
		t.Fatalf("the first establishment answered cause %d", got)
	}
	second := c.Establish(establishment(0x9b02, "10.45.0.3")).(*message.SessionEstablishmentResponse)
	if got := cause(t, second); got != ie.CauseRequestAccepted {
		t.Fatalf("the second establishment answered cause %d", got)
	}
	if got := cause(t, c.Delete(message.NewSessionDeletionRequest(0, 0, upFSEID(t, first), 3, 0))); got != ie.CauseRequestAccepted {
		t.Fatalf("the deletion answered cause %d", got)
	}
	// The second session's rules are still its own.
	if got := cause(t, c.Establish(establishment(0x9b03, "10.45.0.3"))); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a session for the live session's address answered cause %d, want a rule failure", got)
	}
	// And the deleted session's keys are free.
	if got := cause(t, c.Establish(establishment(0x9b04, "10.45.0.2"))); got != ie.CauseRequestAccepted {
		t.Errorf("after the deletion the address answered cause %d, want accepted", got)
	}
}

func TestAnUnansweredApplyKeepsTheSessionsKeys(t *testing.T) {
	// An Apply whose answer never came may have committed, so what it wrote may
	// be in the dataplane: the rule keys stay the session's, exactly as its
	// allocated ids do, and the SMF's retry is what reconciles the two. The
	// alternative -- freeing them -- would hand the next session a rule that
	// this request's packets may still be matching.
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	rec.fail = errors.New("the daemon did not answer")
	if got := cause(t, c.Establish(establishment(0x9801, "10.45.0.2"))); got == ie.CauseRequestAccepted {
		t.Fatal("an unanswered establishment was answered as accepted")
	}
	rec.fail = nil
	if got := cause(t, c.Establish(establishment(0x9802, "10.45.0.2"))); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a session for a rule a possibly-committed transaction wrote answered cause %d, want a rule failure", got)
	}
}

func TestTwoUplinkPDRsWithOneFilterAreRefused(t *testing.T) {
	// An SMF with several QoS flows programs several uplink PDRs onto one F-TEID
	// and tells them apart by their QFIs. The uplink table carries the QFI in
	// its key, so two PDRs that name *different* flows are two rules (the test
	// below); two that name the same PDI down to the QFI are one rule key, and
	// the session is refused with a rule failure: writing both would be refused
	// by the engine, and writing either would silently drop the other's action.
	// The SMF can then fix it, where a PDR that exists and matches nothing
	// would have looked like a working session.
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	req := message.NewSessionEstablishmentRequest(0, 0, 0x9991, 1, 0,
		ie.NewFSEID(0x9991, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, 0x40000001, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0)),
			ie.NewFARID(1)),
		ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(20),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, 0x40000001, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
	)
	if got := cause(t, c.Establish(req)); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("two PDRs with one filter answered cause %d, want a rule failure", got)
	}
	if len(rec.txns) != 0 {
		t.Error("a refused session wrote to the dataplane")
	}
}

// qfiField is the index of the QFI field in the test graph's uplink key: the
// graphs declare it last, and testConfig mirrors them.
func qfiField(t *testing.T) int {
	t.Helper()
	for i, f := range testConfig().Up.PDRFields {
		if f == QFI {
			return i
		}
	}
	t.Fatal("the test graph's uplink table declares no QFI field")
	return 0
}

// uplinkPDR is a Create PDR for the session's uplink: the PDI's source
// interface, pinned F-TEID (0 leaves the choice to us), UE address and SDF
// filter. This test helper uses a nonzero qfi argument to add a QFI IE; tests
// for valid QFI 0 construct `ie.NewQFI(0)` directly.
func uplinkPDR(id uint16, precedence uint32, ueIP string, fteid uint32, sdf string, qfi uint8) *ie.IE {
	pdi := []*ie.IE{
		ie.NewSourceInterface(ie.SrcInterfaceAccess),
		testFTEID(fteid),
		ie.NewUEIPAddress(0x02, ueIP, "", 0, 0),
	}
	if sdf != "" {
		pdi = append(pdi, ie.NewSDFFilter(sdf, "", "", "", 0))
	}
	if qfi != 0 {
		pdi = append(pdi, ie.NewQFI(qfi))
	}
	return ie.NewCreatePDR(
		ie.NewPDRID(id),
		ie.NewPrecedence(precedence),
		ie.NewPDI(pdi...),
		ie.NewFARID(1),
	)
}

// ruleWithQFI is the rule of a transaction whose QFI field carries a value
// under a mask, or false when no rule does.
func ruleWithQFI(changes []bess.Change, field int, value, mask []byte) (rule, bool) {
	for _, r := range rules(changes) {
		if field < len(r.masks) && bytes.Equal(r.value(field), value) && bytes.Equal(r.mask(field), mask) {
			return r, true
		}
	}
	return rule{}, false
}

// TestAPDINamingAQFIKeysTheRuleOnIt: the PDI's QFI (8.2.89) is the last field
// of the uplink table's key, so the PDR of one QoS flow is selected by the
// flow's own byte -- which is what lets one session hold a rule per flow.
func TestAPDINamingAQFIKeysTheRuleOnIt(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	req := establishment(0x9100, "10.45.0.2")
	req.CreatePDR[0] = uplinkPDR(1, 100, "10.45.0.2", 0x11223344, "", 5)
	if got := cause(t, c.Establish(req)); got != ie.CauseRequestAccepted {
		t.Fatalf("an uplink PDI naming a QFI answered cause %d, want accepted", got)
	}
	i := qfiField(t)
	r := ruleCarrying(t, rec.last(), fieldSrcIP, []byte{10, 45, 0, 2})
	if got := r.mask(i); !bytes.Equal(got, []byte{0xff}) {
		t.Errorf("the rule's QFI mask is %v, want all ones: the PDI named the flow", got)
	}
	if got := r.value(i); !bytes.Equal(got, []byte{5}) {
		t.Errorf("the rule's QFI value is %v, want the PDI's 5", got)
	}
	// The rule delivers on the action record written for this PDR, keyed by the
	// ActionId it carries: a rule whose action is another session's would send
	// its packets down the other's chain.
	if got := r.actionID(); got == 0 {
		t.Fatal("the rule names no action")
	}
	action := actionFields(t, rec.last(), testConfig().Up, r.actionID())
	if got := action["next_hop_id"]; got != uint32(1) {
		t.Errorf("the rule's action takes next hop %v, want the uplink's", got)
	}
}

// TestAPDIWithoutAQFIIsTheSessionsGeneralRule: a PDI that names no QFI leaves
// the field masked out of its key, so it keeps matching every flow of the
// session -- and still gets its rule.
func TestAPDIWithoutAQFIIsTheSessionsGeneralRule(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	if got := cause(t, c.Establish(establishment(0x9101, "10.45.0.2"))); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	i := qfiField(t)
	r := ruleCarrying(t, rec.last(), fieldSrcIP, []byte{10, 45, 0, 2})
	if got := r.mask(i); !bytes.Equal(got, []byte{0}) {
		t.Errorf("a PDI that names no QFI constrains it: mask %v", got)
	}
	if got := r.value(i); !bytes.Equal(got, []byte{0}) {
		t.Errorf("a PDI that names no QFI keys the field on %v, want the canonical zero", got)
	}
	if got := r.actionID(); got == 0 {
		t.Error("the session's general rule names no action")
	}
	if _, ok := ruleWithQFI(rec.last(), i, []byte{0}, []byte{0xff}); ok {
		t.Error("a PDI that names no QFI wrote a rule keyed on one")
	}
}

// TestTwoUplinkPDRsToldApartByQFIAreTwoRules is the case the compiler used to
// refuse: an SMF programs several uplink PDRs onto one F-TEID and one UE
// address and tells them apart by their QFIs. Each flow's PDR has a key of its
// own now: the flow's rule requires the QFI, the session's general rule masks it
// out, and a packet of the flow matches both -- so which one serves it is the
// SMF's Precedence and nothing else, carried into the classifier's opposite
// ordering (rulePriority). The SMF gave the flow's PDR the higher Precedence
// here (100 against the general rule's 200: 8.2.11's lower value is the higher
// precedence), so it is also the classifier's higher priority, exactly as the
// SMF wrote the two.
func TestTwoUplinkPDRsToldApartByQFIAreTwoRules(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	req := establishment(0x9102, "10.45.0.2")
	req.CreatePDR[0] = uplinkPDR(1, 200, "10.45.0.2", 0x11223344, "", 0)
	req.CreatePDR = append(req.CreatePDR, uplinkPDR(3, 100, "10.45.0.2", 0x11223344, "", 5))
	if got := cause(t, c.Establish(req)); got != ie.CauseRequestAccepted {
		t.Fatalf("two PDRs told apart by QFI answered cause %d, want accepted", got)
	}
	i := qfiField(t)
	specific, ok := ruleWithQFI(rec.last(), i, []byte{5}, []byte{0xff})
	if !ok {
		t.Fatalf("no rule keyed on QFI 5 among %d rules", len(rules(rec.last())))
	}
	general, ok := ruleWithQFI(rec.last(), i, []byte{0}, []byte{0})
	if !ok {
		t.Fatal("no rule for the PDR that names no QFI")
	}
	if specific.actionID() == general.actionID() {
		t.Error("the two PDRs share one action: the rules cannot be told apart")
	}
	// The SMF gave the flow's PDR the lower Precedence value (100 against the
	// general rule's 200), so it carries the classifier's higher priority: the
	// classifier applies the higher one of two rules that match, and the packet
	// that matches both takes the flow's action. The absolute numbers are the
	// inversion's own test below.
	if specific.priority() <= general.priority() {
		t.Errorf("the SMF's higher-Precedence PDR carries priority %d and the other %d: a packet both match would take the wrong action",
			specific.priority(), general.priority())
	}
}

// flowPDR is uplinkPDR with the QER the flow names. As a test helper, qfi=0
// means no QFI IE; tests for the valid QFI 0 use an explicit IE.
func flowPDR(id uint16, precedence uint32, ueIP string, fteid uint32, qfi uint8, qerID uint32) *ie.IE {
	pdi := []*ie.IE{
		ie.NewSourceInterface(ie.SrcInterfaceAccess),
		testFTEID(fteid),
		ie.NewUEIPAddress(0x02, ueIP, "", 0, 0),
	}
	if qfi != 0 {
		pdi = append(pdi, ie.NewQFI(qfi))
	}
	return ie.NewCreatePDR(
		ie.NewPDRID(id),
		ie.NewPrecedence(precedence),
		ie.NewPDI(pdi...),
		ie.NewFARID(1),
		ie.NewQERID(qerID),
	)
}

// TestTwoQFIKeyedPDRsGetTheirOwnMeters is the per-flow QER claim with its
// evidence: two PDRs of one session that differ only by QFI -- a PDU session's
// two QoS flows -- and that name their own QERs must compile to two rules, two
// actions and two meter ids. Without this, a QER reaches the session rather
// than the flow: the flows would be policed together by whichever meter the
// session's single QER named, and the "per-flow" half of the QER block's
// sub-feature would rest on the tunnel record alone.
func TestTwoQFIKeyedPDRsGetTheirOwnMeters(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	req := establishment(0x9103, "10.45.0.3")
	req.CreatePDR = []*ie.IE{
		flowPDR(1, 200, "10.45.0.3", 0x11223344, 0, 1),
		flowPDR(3, 100, "10.45.0.3", 0x11223344, 5, 2),
	}
	req.CreateQER = []*ie.IE{
		ie.NewCreateQER(ie.NewQERID(1), ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
			ie.NewMBR(1000, 2000)),
		ie.NewCreateQER(ie.NewQERID(2), ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
			ie.NewMBR(3000, 4000)),
	}
	if got := cause(t, c.Establish(req)); got != ie.CauseRequestAccepted {
		t.Fatalf("two flows naming their own QERs answered cause %d, want accepted", got)
	}
	i := qfiField(t)
	specific, ok := ruleWithQFI(rec.last(), i, []byte{5}, []byte{0xff})
	if !ok {
		t.Fatal("no rule keyed on QFI 5: the flow's rule is missing")
	}
	general, ok := ruleWithQFI(rec.last(), i, []byte{0}, []byte{0})
	if !ok {
		t.Fatal("no rule for the flow that names no QFI")
	}
	if specific.actionID() == general.actionID() {
		t.Fatal("the two flows share one action, so one QER would serve both")
	}
	meter := func(r rule) any {
		return actionFields(t, rec.last(), testConfig().Up, r.actionID())["meter_id"]
	}
	first, second := meter(specific), meter(general)
	if first == uint32(0) || second == uint32(0) {
		t.Fatalf("a flow's QER named no meter: %v and %v", first, second)
	}
	if first == second {
		t.Errorf("the two flows share meter %v: their own QERs police them together", first)
	}
}

func TestThePrecedenceIsInvertedIntoTheClassifiersPriority(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	req := establishment(0x9107, "10.45.0.2")
	// Two uplink PDRs that overlap: the flow's rule and the session's general
	// one. The SMF wants the flow's rule to win, so it carries the lower
	// Precedence value.
	req.CreatePDR[0] = uplinkPDR(1, 10, "10.45.0.2", 0x11223344, "", 9)
	req.CreatePDR = append(req.CreatePDR, uplinkPDR(3, 20, "10.45.0.2", 0x11223344, "", 0))
	if got := cause(t, c.Establish(req)); got != ie.CauseRequestAccepted {
		t.Fatalf("two PDRs of one tunnel answered cause %d, want accepted", got)
	}
	i := qfiField(t)
	flow, ok := ruleWithQFI(rec.last(), i, []byte{9}, []byte{0xff})
	if !ok {
		t.Fatal("no rule for the flow's PDR")
	}
	general, ok := ruleWithQFI(rec.last(), i, []byte{0}, []byte{0})
	if !ok {
		t.Fatal("no rule for the general PDR")
	}
	// The values are the inversion, not the Precedence: 10 maps to the larger
	// priority, 20 to the smaller.
	if want := int64(math.MaxUint32) - 10; flow.priority() != want {
		t.Errorf("Precedence 10's rule carries priority %d, want %d", flow.priority(), want)
	}
	if want := int64(math.MaxUint32) - 20; general.priority() != want {
		t.Errorf("Precedence 20's rule carries priority %d, want %d", general.priority(), want)
	}
	// The classifier applies the higher priority of two rules that match, so
	// the packet that matches both takes the action of the PDR the SMF gave the
	// lower Precedence value -- the flow's rule, and its own action record.
	if flow.priority() <= general.priority() {
		t.Errorf("the SMF's higher-precedence PDR carries priority %d, not above the other's %d: the ordering is inverted",
			flow.priority(), general.priority())
	}
	if action := actionFields(t, rec.last(), testConfig().Up, flow.actionID()); action["next_hop_id"] != uint32(1) {
		t.Errorf("the winning rule's result is not its PDR's: %v", action)
	}
	// F-TEID admission is an exact composite-key lookup, not a precedence
	// classifier. Its entry carries the direction for this endpoint key; PDR
	// precedence remains in the inner classifier.
	teid, ok := teidRule(rec.last(), testConfig().GTPUDecap+"/fteids", 0x11223344)
	if !ok {
		t.Fatal("no F-TEID admission entry for the pinned endpoint")
	}
	if got, _ := teid.Value["direction"].(uint32); got != 0 {
		t.Errorf("the admission direction is %v, want UL (0)", got)
	}
}

// TestAnUpdatePDRWithoutPrecedenceKeepsTheMatchingOrder: the Precedence IE of
// an Update PDR is there only when the precedence changes (Table 7.5.4.2-1),
// and the UP function keeps the stored value of an IE the update leaves out
// (NOTE 1). Read as 0, the session's general rule would outrank the flow's
// and take its packets.
func TestAnUpdatePDRWithoutPrecedenceKeepsTheMatchingOrder(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	req := establishment(0x9108, "10.45.0.2")
	req.CreatePDR[0] = uplinkPDR(1, 10, "10.45.0.2", 0x11223344, "", 9)
	req.CreatePDR = append(req.CreatePDR, uplinkPDR(3, 20, "10.45.0.2", 0x11223344, "", 0))
	resp := c.Establish(req).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	mod := message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 2, 0,
		ie.NewUpdatePDR(ie.NewPDRID(3),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				testFTEID(0x11223344),
				ie.NewUEIPAddress(0x02, "10.45.0.2", "", 0, 0)),
			ie.NewFARID(1)))
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the update answered cause %d", got)
	}
	if got := sessionOf(t, c, upFSEID(t, resp)).PDRs[3].precedence; got != 20 {
		t.Errorf("the updated PDR's precedence is %d, want the stored 20", got)
	}
	general, ok := ruleWithQFI(rec.last(), qfiField(t), []byte{0}, []byte{0})
	if !ok {
		t.Fatal("the update did not rewrite the general PDR's rule")
	}
	if want := int64(math.MaxUint32) - 20; general.priority() != want {
		t.Errorf("the general rule carries priority %d, want %d: it now outranks the flow's (%d)",
			general.priority(), want, int64(math.MaxUint32)-10)
	}
}

// TestAnUpdatePDRKeepsWhatItLeavesOut: every IE of an Update PDR is there only
// when its value changes (Table 7.5.4.2-1: Outer Header Removal, Precedence,
// PDI, FAR ID, URR ID, QER ID), and the UP function keeps the stored value of
// an IE the update leaves out (NOTE 1).
func TestAnUpdatePDRKeepsWhatItLeavesOut(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	req := establishment(0x9109, "10.45.0.2")
	req.CreatePDR[0] = ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100),
		ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
			testFTEID(0x11223344),
			ie.NewUEIPAddress(0x02, "10.45.0.2", "", 0, 0)),
		ie.NewFARID(1), ie.NewQERID(1), ie.NewURRID(7))
	req.CreateURR = append(req.CreateURR, fullURR(7))
	resp := c.Establish(req).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	seid := upFSEID(t, resp)

	mod := message.NewSessionModificationRequest(0, 0, seid, 2, 0,
		ie.NewUpdatePDR(ie.NewPDRID(1), ie.NewPrecedence(50)))
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("an Update PDR naming only the precedence answered cause %d", got)
	}
	p := sessionOf(t, c, seid).PDRs[1]
	if p.srcIfc != ie.SrcInterfaceAccess || p.ueIP != netip.MustParseAddr("10.45.0.2") || p.teid != 0x11223344 {
		t.Errorf("the PDI read as interface %d, UE %v, TEID %#x; want the stored Access, 10.45.0.2, 0x11223344",
			p.srcIfc, p.ueIP, p.teid)
	}
	if p.farID != 1 || !slices.Equal(p.qerIDs, []uint32{1}) || !slices.Equal(p.urrIDs, []uint32{7}) {
		t.Errorf("the PDR names FAR %d, QERs %v, URRs %v; want the stored 1, [1], [7]", p.farID, p.qerIDs, p.urrIDs)
	}
	r := ruleCarrying(t, rec.last(), fieldSrcIP, []byte{10, 45, 0, 2})
	if want := int64(math.MaxUint32) - 50; r.priority() != want {
		t.Errorf("the updated rule carries priority %d, want %d", r.priority(), want)
	}

	// The URR the update left out still measures the PDR: its counter entry
	// stays in the dataplane.
	if n := len(rec.entries); n != 1 {
		t.Errorf("%d counter entries after the update, want the one URR 7 measures by", n)
	}

	// An Update PDR for a PDR the session does not hold has nothing to keep.
	mod = message.NewSessionModificationRequest(0, 0, seid, 4, 0,
		ie.NewUpdatePDR(ie.NewPDRID(9), ie.NewPrecedence(50)))
	if got := cause(t, c.Modify(mod)); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("an Update PDR for an unknown PDR answered cause %d, want a rule failure", got)
	}
}

// TestAQFIIsInRangeOrRefused: a QFI is one of 0..63 (38.415 5.5.3.3, which
// 8.2.89 refers to), so 0 is a flow like any other -- the decap writes 255 for
// a G-PDU with no container at all (datapath/pdu_session_qfi.h), so a PDI
// naming 0 selects only a packet that really carried QFI 0. Above the range a
// rule would match nothing: the session would stand while its uplink
// blackholed, so those values are refused with the cause the SMF can fix.
func TestAQFIIsInRangeOrRefused(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	req := establishment(0x9103, "10.45.0.2")
	// The QFI IE with a zero in it: uplinkPDR's own qfi=0 means "the PDI names
	// no QFI at all", which is the other test's arm.
	req.CreatePDR[0] = ie.NewCreatePDR(
		ie.NewPDRID(1),
		ie.NewPrecedence(100),
		ie.NewPDI(
			ie.NewSourceInterface(ie.SrcInterfaceAccess),
			ie.NewFTEID(0x01, 0x11223344, net.ParseIP("192.0.2.1"), nil, 0),
			ie.NewUEIPAddress(0x02, "10.45.0.2", "", 0, 0),
			ie.NewQFI(0),
		),
		ie.NewFARID(1),
	)
	if got := cause(t, c.Establish(req)); got != ie.CauseRequestAccepted {
		t.Fatalf("a PDI naming QFI 0 answered cause %d, want accepted: 0 is in the spec's range", got)
	}
	i := qfiField(t)
	r := ruleCarrying(t, rec.last(), fieldSrcIP, []byte{10, 45, 0, 2})
	if got := r.value(i); !bytes.Equal(got, []byte{0}) {
		t.Errorf("the rule's QFI value is %v, want the PDI's 0", got)
	}
	if got := r.mask(i); !bytes.Equal(got, []byte{0xff}) {
		t.Errorf("the rule's QFI mask is %v, want all ones: the PDI named the flow", got)
	}

	for _, qfi := range []uint8{64, 255} {
		rec := &recorder{}
		c := New(testConfig(), rec, quietLogger())
		req := establishment(0x9104, "10.45.0.2")
		req.CreatePDR[0] = ie.NewCreatePDR(
			ie.NewPDRID(1),
			ie.NewPrecedence(100),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, 0x11223344, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.2", "", 0, 0),
				ie.NewQFI(qfi),
			),
			ie.NewFARID(1),
		)
		if got := cause(t, c.Establish(req)); got != ie.CauseRuleCreationModificationFailure {
			t.Errorf("a PDI naming QFI %d answered cause %d, want a rule failure", qfi, got)
		}
		if len(rec.txns) != 0 {
			t.Errorf("a PDI naming QFI %d wrote to the dataplane", qfi)
		}
	}
}

// downlinkPDRWithQER is a Create PDR for the session's downlink that the named
// QER polices: the QER's QFI reaches the dataplane through the tunnel record of
// the PDR that names it, because that is the record its rule's action resolves.
func downlinkPDRWithQER(id uint16, ueIP string, qerID uint32) *ie.IE {
	return ie.NewCreatePDR(
		ie.NewPDRID(id),
		ie.NewPrecedence(100),
		ie.NewPDI(
			ie.NewSourceInterface(ie.SrcInterfaceCore),
			ie.NewUEIPAddress(0x06, ueIP, "", 0, 0),
			ie.NewSDFFilter("permit out udp from any to assigned 53", "", "", "", 0),
		),
		ie.NewFARID(2),
		ie.NewQERID(qerID),
	)
}

// TestAQERsQFIReachesTheTunnelRecord: the QFI a downlink packet must carry in
// its PDU Session Container (8.2.89) is the QER's, and the graph's encap reads
// it from the tunnel record the FAR's outer header creation writes -- keyed, as
// the record is, by the ActionId the PDR's rule carries. `qfi_present` keeps a
// valid QFI 0 distinct from a QER that names no QFI (TS 38.415 5.5.3.3).
func TestAQERsQFIReachesTheTunnelRecord(t *testing.T) {
	tunnelOf := func(t *testing.T, rec *recorder, ue string) bess.Change {
		t.Helper()
		dl := ruleCarrying(t, rec.last(), fieldDstIP, netip.MustParseAddr(ue).AsSlice())
		return find(t, rec.last(), testConfig().Down.Tunnels+"/tunnels", "action_id", dl.actionID())
	}

	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	withFlow := establishment(0x9104, "10.45.0.2")
	withFlow.CreatePDR[1] = downlinkPDRWithQER(2, "10.45.0.2", 1)
	withFlow.CreateQER[0] = ie.NewCreateQER(
		ie.NewQERID(1),
		ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
		ie.NewQFI(5),
	)
	if got := cause(t, c.Establish(withFlow)); got != ie.CauseRequestAccepted {
		t.Fatalf("a QER naming a QFI answered cause %d, want accepted", got)
	}
	if got := tunnelOf(t, rec, "10.45.0.2").Value["qfi"]; got != uint32(5) {
		t.Errorf("the tunnel record carries QFI %v (%T), want the QER's 5", got, got)
	}
	if got := tunnelOf(t, rec, "10.45.0.2").Value["qfi_present"]; got != true {
		t.Errorf("the tunnel record qfi_present is %v, want true", got)
	}

	// A second session, whose QER names no flow: neither QFI field is present
	// in the resource, so the encap omits the PDU Session Container.
	noFlow := establishment(0x9105, "10.45.0.3")
	noFlow.CreatePDR[1] = downlinkPDRWithQER(2, "10.45.0.3", 1)
	if got := cause(t, c.Establish(noFlow)); got != ie.CauseRequestAccepted {
		t.Fatalf("a QER with no QFI answered cause %d, want accepted", got)
	}
	if got, ok := tunnelOf(t, rec, "10.45.0.3").Value["qfi"]; ok {
		t.Errorf("the tunnel record of a QER with no QFI carries %v, want no field", got)
	}
	if got, ok := tunnelOf(t, rec, "10.45.0.3").Value["qfi_present"]; ok {
		t.Errorf("the tunnel record of a QER with no QFI carries qfi_present=%v, want no field", got)
	}

	// A third, whose QER names QFI 0: it is a valid QFI, not absence. The
	// tunnel record must therefore request a PDU Session Container carrying 0.
	zero := establishment(0x9106, "10.45.0.4")
	zero.CreatePDR[1] = downlinkPDRWithQER(2, "10.45.0.4", 1)
	zero.CreateQER[0] = ie.NewCreateQER(
		ie.NewQERID(1),
		ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
		ie.NewQFI(0),
	)
	if got := cause(t, c.Establish(zero)); got != ie.CauseRequestAccepted {
		t.Fatalf("a QER naming QFI 0 answered cause %d, want accepted", got)
	}
	if got, ok := tunnelOf(t, rec, "10.45.0.4").Value["qfi"]; !ok || got != uint32(0) {
		t.Errorf("the tunnel record of a QER naming QFI 0 carries %v, present=%t; want present zero", got, ok)
	}
	if got := tunnelOf(t, rec, "10.45.0.4").Value["qfi_present"]; got != true {
		t.Errorf("the tunnel record qfi_present is %v, want true for QFI 0", got)
	}
}

// TestAFARsTransportLevelMarkingReachesTheTunnelRecord: the ToS/Traffic Class
// the SMF asks this session's outer headers to carry (TS 29.244 8.2.12, in the
// FAR's forwarding parameters) reaches the dataplane through the tunnel record
// the FAR's outer header creation writes -- the record whose "marking" the
// encap reads to mark the outer IPv4 header instead of copying the inner TOS.
// A FAR that names no marking leaves the field out of the record: the encap
// then copies the inner TOS, the behaviour the session had before the field
// existed, and 0 is never a marking the SMF asked for.
func TestAFARsTransportLevelMarkingReachesTheTunnelRecord(t *testing.T) {
	tunnelOf := func(t *testing.T, rec *recorder, ue string) bess.Change {
		t.Helper()
		dl := ruleCarrying(t, rec.last(), fieldDstIP, netip.MustParseAddr(ue).AsSlice())
		return find(t, rec.last(), testConfig().Down.Tunnels+"/tunnels", "action_id", dl.actionID())
	}

	// The SMF's marking as the IE encodes it: the DSCP of EF (46) in the ToS
	// octet, 46<<2 = 0xb8, and the spec's 0xFC mask (8.2.12).
	const ef = 0xb8fc

	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	marked := establishment(0x9204, "10.46.0.2")
	marked.CreateFAR[1] = ie.NewCreateFAR(
		ie.NewFARID(2),
		ie.NewApplyAction(applyForw),
		ie.NewForwardingParameters(
			ie.NewDestinationInterface(ie.DstInterfaceAccess),
			ie.NewOuterHeaderCreation(0x0100, 0x11223344, "10.20.30.2", "", 0, 0, 0),
			ie.NewTransportLevelMarking(ef),
		),
	)
	if got := cause(t, c.Establish(marked)); got != ie.CauseRequestAccepted {
		t.Fatalf("a FAR naming a Transport Level Marking answered cause %d, want accepted", got)
	}
	if got := tunnelOf(t, rec, "10.46.0.2").Value["marking"]; got != uint32(ef) {
		t.Errorf("the tunnel record carries marking %v (%T), want the FAR's %#x", got, got, ef)
	}

	// A second session whose FAR names none: the field is absent from its
	// record, so the encap copies the inner TOS rather than marking a zero.
	plain := establishment(0x9205, "10.46.0.3")
	if got := cause(t, c.Establish(plain)); got != ie.CauseRequestAccepted {
		t.Fatalf("a FAR with no marking answered cause %d, want accepted", got)
	}
	if got, ok := tunnelOf(t, rec, "10.46.0.3").Value["marking"]; ok {
		t.Errorf("the tunnel record of a FAR with no marking carries %v, want no field", got)
	}
}

// graphArg is the number a deploy graph declares for one argument of one
// module, as its own line (`max_tuples: 16`) or inside the module's flow-style
// arg map (`arg: {..., flow_capacity: 65536}`). It reads the manifest's own
// text, so the number a test holds the compiler against is the one the
// deployment actually carries.
func graphArg(t *testing.T, path, module, key string) int {
	t.Helper()
	text, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	in := false
	for _, line := range strings.Split(string(text), "\n") {
		line = strings.TrimSpace(line)
		if name, ok := strings.CutPrefix(line, "- name: "); ok {
			in = name == module
			continue
		}
		if !in || strings.HasPrefix(line, "#") {
			continue
		}
		for rest := line; ; {
			i := strings.Index(rest, key+":")
			if i < 0 {
				break
			}
			if i > 0 && !strings.ContainsRune(" {,", rune(rest[i-1])) {
				rest = rest[i+len(key)+1:]
				continue
			}
			value := strings.TrimSpace(rest[i+len(key)+1:])
			if end := strings.IndexAny(value, ",}"); end >= 0 {
				value = strings.TrimSpace(value[:end])
			}
			n, err := strconv.Atoi(value)
			if err != nil {
				t.Fatalf("%s: %s's %s is not a number: %v", path, module, key, err)
			}
			return n
		}
	}
	t.Fatalf("%s declares no %s for %s", path, key, module)
	return 0
}

// TestTheUplinkMaskBudgetCoversTheRuleShapes holds the compiler's rule shapes
// against the budget each graph declares. A WildcardMatch table keeps one hash
// table per distinct mask in use at once, and one more than max_tuples is
// refused with ENOSPC -- so the number a graph declares bounds the shapes the
// deployment can hold, and a session that needs more is refused by the daemon
// at its establishment rather than programmed. The mask a rule carries is the
// field pattern its PDI names: an address or a filter masked out, an exact
// address, a prefix, the ports, and the QFI named or left open. The qfi field
// doubled the shapes a session's rules take, which is why the graphs' budget
// doubled with it (8 to 16); this is the figure and the shapes kept together.
func TestTheUplinkMaskBudgetCoversTheRuleShapes(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	req := establishment(0x9106, "10.45.0.2")
	// Every shape a session's uplink can ask for: the address alone, an SDF of
	// exact addresses and ports, an SDF of prefixes, and each with the QoS flow
	// the SMF named and without it.
	req.CreatePDR[0] = uplinkPDR(1, 100, "10.45.0.2", 0x11223344, "", 0)
	req.CreatePDR = append(req.CreatePDR,
		uplinkPDR(3, 110, "10.45.0.2", 0x11223344, "", 9),
		uplinkPDR(4, 120, "10.45.0.2", 0x11223344,
			"permit out udp from 10.45.0.2/32 to 10.10.20.30/32 80", 0),
		uplinkPDR(5, 130, "10.45.0.2", 0x11223344,
			"permit out udp from 10.45.0.0/16 to 10.10.0.0/16 443", 9),
	)
	if got := cause(t, c.Establish(req)); got != ie.CauseRequestAccepted {
		t.Fatalf("the session of every shape answered cause %d, want accepted", got)
	}
	shapes := map[string]bool{}
	for _, r := range rules(rec.last()) {
		if r.change.Resource != rulesRes(testConfig().Up) {
			continue
		}
		shapes[fmt.Sprint(r.masks)] = true
	}
	// The shapes the session asked for are four distinct masks at least: a test
	// that compiled them to fewer would be holding the budget against nothing.
	if len(shapes) < 4 {
		t.Fatalf("the session's uplink rules carry %d mask shapes, want the four it asked for", len(shapes))
	}
	t.Logf("one session's uplink rules use %d distinct masks", len(shapes))
	for _, graph := range []string{"upf.yaml", "session-live.yaml", "session-path.yaml",
		"session-instances.yaml", "buffer-path.yaml"} {
		budget := graphArg(t, filepath.Join("..", "..", "deploy", graph), "pdr_ul", "max_tuples")
		if len(shapes) > budget {
			t.Errorf("%s declares max_tuples %d for pdr_ul, and one session's rules already use %d masks",
				graph, budget, len(shapes))
		}
	}
}

func TestAClosedGateDropsWithoutAnAction(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	req := establishment(0x5560, "10.45.0.6")
	// One QER per session, and the gate is its: the uplink's closed, the
	// downlink's open.
	req.CreateQER = []*ie.IE{ie.NewCreateQER(
		ie.NewQERID(1),
		ie.NewGateStatus(ie.GateStatusClosed, ie.GateStatusOpen),
	)}
	if got := cause(t, c.Establish(req)); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	r := ruleCarrying(t, rec.last(), fieldSrcIP, []byte{10, 45, 0, 6})
	if got := r.gate(); got != dropGate {
		t.Errorf("a closed gate's rule gates %d, want the drop gate %d", got, dropGate)
	}
	// A drop's result is all zero: no action id, no meter and no next hop.
	if got := r.actionID(); got != 0 {
		t.Errorf("a closed gate's rule names action %d, want none", got)
	}
	for _, ch := range rec.last() {
		if strings.HasSuffix(ch.Resource, "/actions") {
			t.Errorf("a closed gate wrote an action record in %s", ch.Resource)
		}
	}
}

// TestAQuotaExhaustedURRDropsItsPDRs is the enforcement half of 5.2.2.2.1: the
// flag the reporting task sets when a URR's quota is used up is what stops the
// traffic of the PDRs that name it. Nothing else changes -- no new filter, no
// message from the SMF that asks for a drop -- so the next transaction (any
// modification, even one that asks for nothing new) must write the PDR's rule
// as a drop. That is also what stops the counting: a dropped rule reaches no
// action, so its counter stands still.
func TestAQuotaExhaustedURRDropsItsPDRs(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(urrEstablishment(0x3021, 7, fullURR(7))).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	// The traffic flows to begin with: the rule names an action, so the packets
	// of this PDR reach the chain behind it.
	if before := ruleCarrying(t, rec.last(), fieldSrcIP, []byte{10, 45, 0, 2}); before.actionID() == 0 {
		t.Fatal("the PDR compiled to a drop before any quota was used up")
	}

	// The reporting task's flip, exactly as it leaves the model. (It is set
	// there because only the counter reading says a quota is used up; see
	// docs/design.md, "Usage".)
	c.mu.Lock()
	c.findByCP(0x3021).URRs[7].enforcing = true
	c.mu.Unlock()

	// An update that changes nothing about the PDR: whatever the SMF sends, the
	// session is recompiled, and the rule must come out as a drop.
	mod := message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 2, 0,
		ie.NewUpdateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
	)
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification answered cause %d", got)
	}
	enforced := ruleCarrying(t, rec.last(), fieldSrcIP, []byte{10, 45, 0, 2})
	if got := enforced.gate(); got != dropGate {
		t.Errorf("with the URR's quota used up the rule gates %d, want the drop gate %d", got, dropGate)
	}
	if got := enforced.actionID(); got != 0 {
		t.Errorf("the dropped rule names action %d, want none", got)
	}

	// A new quota is the SMF's own lever for re-opening the traffic
	// (5.2.2.2.1): provisioning one clears the flag, and the next transaction
	// writes the rule with its action again.
	reopen := message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 3, 0,
		ie.NewUpdateURR(ie.NewURRID(7), ie.NewVolumeQuota(0x01, 1<<40, 0, 0)),
	)
	if got := cause(t, c.Modify(reopen)); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification that provisions a new quota answered cause %d", got)
	}
	c.mu.Lock()
	enforcing := c.findByCP(0x3021).URRs[7].enforcing
	c.mu.Unlock()
	if enforcing {
		t.Error("a new quota left the URR enforcing: the traffic would never come back")
	}
	if back := ruleCarrying(t, rec.last(), fieldSrcIP, []byte{10, 45, 0, 2}); back.actionID() == 0 {
		t.Error("the rule is still a drop after the SMF provisioned a new quota")
	}
}

// cause is the Cause IE of any session-level response. go-pfcp's constructors
// distribute the IEs into typed fields, so the response's Cause is one.
func cause(t *testing.T, resp message.Message) uint8 {
	t.Helper()
	var i *ie.IE
	switch v := resp.(type) {
	case *message.SessionEstablishmentResponse:
		i = v.Cause
	case *message.SessionModificationResponse:
		i = v.Cause
	case *message.SessionDeletionResponse:
		i = v.Cause
	default:
		t.Fatalf("not a session-level response: %T", resp)
	}
	if i == nil {
		t.Fatalf("no Cause IE in %T", resp)
	}
	c, err := i.Cause()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestEstablishCompilesTheSessionIntoOneTransaction(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	ue := netip.MustParseAddr("10.45.0.2")

	resp := c.Establish(establishment(0x1111, ue.String())).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("establishment refused with cause %d", got)
	}
	if len(rec.txns) != 1 {
		t.Fatalf("%d transactions, want one: a session change is all or nothing", len(rec.txns))
	}
	changes := rec.last()

	// The uplink PDR's F-TEID: we chose it, and the answer tells the SMF which.
	var fteid *ie.FTEIDFields
	for _, i := range resp.CreatedPDR {
		children, err := i.CreatedPDR()
		if err != nil {
			t.Fatal(err)
		}
		for _, ch := range children {
			if ch.Type == ie.FTEID {
				if fteid, err = ch.FTEID(); err != nil {
					t.Fatal(err)
				}
			}
		}
		break
	}
	if fteid == nil {
		t.Fatal("the answer carries no Created PDR: the SMF cannot learn our F-TEID")
	}
	if fteid.TEID == 0 {
		t.Error("the Created PDR's F-TEID is 0")
	}
	if got := fteid.IPv4Address.String(); got != "192.0.2.1" {
		t.Errorf("the Created PDR's address is %s, want the UPF's N3 address", got)
	}

	// This uplink G-PDU is admitted only by its endpoint-scoped F-TEID key:
	// endpoint, family, local address and TEID.
	rule, ok := teidRule(changes, testConfig().GTPUDecap+"/fteids", fteid.TEID)
	if !ok {
		t.Fatalf("no F-TEID admission entry for %#x among %d changes", fteid.TEID, len(changes))
	}
	if got := rule.Value["direction"]; got != uint32(0) {
		t.Errorf("the admission direction is %v, want UL (0)", got)
	}
	if rule.Key["endpoint_id"] != uint32(1) || rule.Key["address_family"] != uint32(4) ||
		rule.Key["teid"] != fteid.TEID {
		t.Errorf("the admission key is not endpoint-scoped: %v", rule.Key)
	}
	local, _ := rule.Key["local_address"].([]byte)
	if len(local) != 4 || !bytes.Equal(local, netip.MustParseAddr("192.0.2.1").AsSlice()) {
		t.Errorf("the admission local address is %v, want 192.0.2.1", local)
	}

	// One rule per PDR: the uplink matches the UE as the source, the downlink
	// as the destination, and the SDF filter adds the port.
	ul := ruleCarrying(t, changes, fieldSrcIP, ue.AsSlice())
	dl := ruleCarrying(t, changes, fieldDstIP, ue.AsSlice())
	if ul.actionID() == 0 || dl.actionID() == 0 {
		t.Fatal("a forwarding PDR must name an action")
	}
	if ul.actionID() == dl.actionID() {
		t.Error("two PDRs with different FARs share one action")
	}
	ports := dl.value(4)
	if !bytes.Equal(ports, []byte{0, 53}) {
		t.Errorf("the downlink rule's destination port is %v, want 53", ports)
	}
	// The downlink SDF names the destination side only ("permit out udp from
	// any to assigned 53"), so its source must stay masked out: a rule that put
	// the UE's address on both sides of the tuple would match no packet at all,
	// and the traffic a session exists for would be dropped.
	if m := dl.mask(0); !bytes.Equal(m, []byte{0, 0, 0, 0}) {
		t.Errorf("the downlink rule constrains the source its SDF left open: mask %v", m)
	}
	if m := ul.mask(0); !bytes.Equal(m, []byte{0xff, 0xff, 0xff, 0xff}) {
		t.Errorf("the uplink rule does not constrain the UE's address: mask %v", m)
	}
	if m := ul.mask(4); !bytes.Equal(m, []byte{0, 0}) {
		t.Errorf("the uplink rule constrains a port it does not name: mask %v", m)
	}

	// The action resolves the FAR and the QER.
	ulAction := actionFields(t, changes, testConfig().Up, ul.actionID())
	if got := ulAction["next_hop_id"]; got != uint32(1) {
		t.Errorf("the uplink action's next hop is %v, want the N6 next hop", got)
	}
	if got := ulAction["meter_id"]; got == uint32(0) {
		t.Error("a PDR whose QER has an MBR must name its meter")
	}
	dlAction := actionFields(t, changes, testConfig().Down, dl.actionID())
	if got := dlAction["next_hop_id"]; got != uint32(2) {
		t.Errorf("the downlink action's next hop is %v, want the access side's (2)", got)
	}

	// The downlink FAR's tunnel is keyed by the same ActionId the rule carries.
	tunnel := find(t, changes, testConfig().Down.Tunnels+"/tunnels", "action_id", dl.actionID())
	if got := tunnel.Value["teid"]; got != uint32(0x11223344) {
		t.Errorf("the tunnel's TEID is %v, want the FAR's", got)
	}
	if got := tunnel.Value["local_address"]; !bytes.Equal(got.([]byte), netip.MustParseAddr("192.0.2.1").AsSlice()) {
		t.Errorf("the tunnel's local source is %v, want 192.0.2.1", got)
	}
	if got := tunnel.Value["peer_address"]; !bytes.Equal(got.([]byte), netip.MustParseAddr("10.20.30.2").AsSlice()) {
		t.Errorf("the tunnel's peer is %v, want 10.20.30.2", got)
	}
	if got := tunnel.Value["transport_route_domain"]; got != uint32(1) {
		t.Errorf("the tunnel transport route domain is %v, want 1", got)
	}
	if _, ok := find0(changes, testConfig().Down.Tunnels+"/tunnels", "action_id", ul.actionID()); ok {
		t.Error("an uplink PDR has no tunnel record")
	}

	// Both QER directions are policed.
	meters := 0
	for _, ch := range changes {
		if ch.Resource == testConfig().Up.Meters+"/meters" ||
			ch.Resource == testConfig().Down.Meters+"/meters" {
			meters++
		}
	}
	if meters != 2 {
		t.Errorf("%d meter records for a QER with both directions, want 2", meters)
	}

	// Each direction's table has one output chain, so every forwarding rule
	// delivers on gate 0 and the chain it enters is the table it is in.
	if got := ul.gate(); got != 0 {
		t.Errorf("the uplink rule's gate is %v, want its table's own chain", got)
	}
	if got := dl.gate(); got != 0 {
		t.Errorf("the downlink rule's gate is %v, want its table's own chain", got)
	}
}

func TestRepeatedEstablishmentAnswersWithTheSameSession(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())

	first := c.Establish(establishment(0x2222, "10.45.0.3")).(*message.SessionEstablishmentResponse)
	again := c.Establish(establishment(0x2222, "10.45.0.3")).(*message.SessionEstablishmentResponse)
	if got := cause(t, again); got != ie.CauseRequestAccepted {
		t.Errorf("a retransmitted establishment answered cause %d", got)
	}
	if upFSEID(t, first) != upFSEID(t, again) {
		t.Errorf("the retransmission got SEID %d, the first answered %d",
			upFSEID(t, again), upFSEID(t, first))
	}
	if len(rec.txns) != 1 {
		t.Errorf("%d transactions for one session, want 1", len(rec.txns))
	}
}

func TestDeleteRemovesWhatTheSessionProgrammed(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(establishment(0x3333, "10.45.0.4")).(*message.SessionEstablishmentResponse)

	del := c.Delete(message.NewSessionDeletionRequest(0, 0, upFSEID(t, resp), 2, 0)).(*message.SessionDeletionResponse)
	if got := cause(t, del); got != ie.CauseRequestAccepted {
		t.Fatalf("deletion refused with cause %d", got)
	}
	if len(rec.txns) != 2 {
		t.Fatalf("%d transactions, want an establishment then a deletion", len(rec.txns))
	}
	for _, ch := range rec.last() {
		if ch.Value != nil {
			t.Errorf("the deletion wrote a value for %s", ch.Resource)
		}
	}
	// The ids are the compiler's to choose (its pool walks the space), so the
	// reading is what the establishment wrote: a deletion that leaves any of
	// the session's records behind is state the dataplane keeps for a session
	// that is gone. PDR rules, meters, tunnels and F-TEID admission entries are
	// those records; the action id lives in a PDR rule's result, not a resource.
	est := rec.txns[0]
	for _, ch := range est {
		if ch.Resource != testConfig().GTPUDecap+"/fteids" {
			continue
		}
		teid, ok := ch.Key["teid"].(uint32)
		if !ok || teid == 0 {
			t.Fatalf("the FTEIDKey has no TEID: %v", ch.Key)
		}
		if _, ok := teidRule(rec.last(), testConfig().GTPUDecap+"/fteids", teid); !ok {
			t.Errorf("the deletion leaves the FTEIDKey for %#x behind", teid)
		}
	}
	if len(rules(rec.last())) != 2 {
		t.Error("the deletion does not remove both rules")
	}

	// A retransmitted deletion is not an error and writes nothing.
	again := c.Delete(message.NewSessionDeletionRequest(0, 0, upFSEID(t, resp), 3, 0)).(*message.SessionDeletionResponse)
	if got := cause(t, again); got != ie.CauseSessionContextNotFound {
		t.Errorf("a repeated deletion answered cause %d", got)
	}
	if len(rec.txns) != 2 {
		t.Error("a repeated deletion wrote to the dataplane")
	}
}

func TestDropFARNeedsNoActionRecord(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	req := message.NewSessionEstablishmentRequest(0, 0, 0x4444, 1, 0,
		ie.NewFSEID(0x4444, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x06, "10.45.0.5", "", 0, 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyDrop)),
	)
	if got := cause(t, c.Establish(req)); got != ie.CauseRequestAccepted {
		t.Fatalf("establishment refused with cause %d", got)
	}
	ul := rules(rec.last())
	if len(ul) != 1 {
		t.Fatalf("%d rules, want 1", len(ul))
	}
	if got := ul[0].gate(); got != dropGate {
		t.Errorf("a DROP FAR drops at the rule, but the gate is %v", got)
	}
	if got := ul[0].actionID(); got != 0 {
		t.Errorf("a DROP FAR needs no action record, but the rule names %v", got)
	}
	for _, ch := range rec.last() {
		if strings.HasSuffix(ch.Resource, "/actions") {
			t.Error("a DROP FAR wrote an action record")
		}
	}
}

// An SDF port range is a WildcardMatch range on its field (BESS D-186), with
// the field masked out: never a widened mask, never a refusal. A range over the
// whole port domain constrains nothing, the form BESS reads back.
func TestAPortRangeIsARangeOnItsField(t *testing.T) {
	const dstPort = 4 // testConfig's downlink fields: SrcIP DstIP Proto SrcPort DstPort ...
	for _, tc := range []struct {
		filter string
		ranges []map[string]any
	}{
		{"permit out udp from any to assigned 1000-2000",
			[]map[string]any{{"field": uint32(dstPort), "low": uint64(1000), "high": uint64(2000)}}},
		{"permit out udp from any to assigned 0-65535", nil},
	} {
		rec := &recorder{}
		c := New(testConfig(), rec, quietLogger())
		req := message.NewSessionEstablishmentRequest(0, 0, 0x5555, 1, 0,
			ie.NewFSEID(0x5555, nil, nil),
			ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
				ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
					ie.NewUEIPAddress(0x06, "10.45.0.6", "", 0, 0),
					ie.NewSDFFilter(tc.filter, "", "", "", 0)),
				ie.NewFARID(1)),
			ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
				ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess))),
		)
		if got := cause(t, c.Establish(req)); got != ie.CauseRequestAccepted {
			t.Fatalf("%q answered cause %d", tc.filter, got)
		}
		rs := rules(rec.last())
		if len(rs) != 1 {
			t.Fatalf("%q wrote %d rules, want 1", tc.filter, len(rs))
		}
		if m := rs[0].mask(dstPort); !bytes.Equal(m, []byte{0, 0}) {
			t.Errorf("%q: the destination port's mask is %x, want it masked out", tc.filter, m)
		}
		got, _ := rs[0].change.Key["ranges"].([]map[string]any)
		if !reflect.DeepEqual(got, tc.ranges) {
			t.Errorf("%q: the key's ranges are %v, want %v", tc.filter, got, tc.ranges)
		}
	}
}

// An Outer Header Creation toward an IPv6 peer (description 0x0200) is a tunnel
// whose outer header is IPv6 end to end: the peer as named, and the local
// address the N3 endpoint's IPv6 one. An IPv4-mapped address in the IPv6 field
// names no IPv6 peer and is refused.
func TestAnIPv6OuterHeaderCreationIsAnIPv6Tunnel(t *testing.T) {
	for _, tc := range []struct {
		peer   string
		accept bool
	}{
		{"2001:db8:3::2", true},
		{"::ffff:10.20.30.2", false},
	} {
		cfg := testConfig()
		cfg.FTEIDEndpoints[0].IPv6 = netip.MustParseAddr("2001:db8:3::1")
		rec := &recorder{}
		c := New(cfg, rec, quietLogger())
		req := message.NewSessionEstablishmentRequest(0, 0, 0x5557, 1, 0,
			ie.NewFSEID(0x5557, nil, nil),
			ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
				ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
					ie.NewUEIPAddress(0x06, "10.45.0.6", "", 0, 0)),
				ie.NewFARID(1)),
			ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
				ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess),
					ie.NewOuterHeaderCreation(0x0200, 0x11223344, "", tc.peer, 0, 0, 0))),
		)
		got := cause(t, c.Establish(req))
		if !tc.accept {
			if got == ie.CauseRequestAccepted {
				t.Errorf("an IPv4-mapped OHC peer %s was accepted", tc.peer)
			}
			continue
		}
		if got != ie.CauseRequestAccepted {
			t.Fatalf("an IPv6 OHC peer answered cause %d", got)
		}
		dl := rules(rec.last())[0]
		tunnel := find(t, rec.last(), cfg.Down.Tunnels+"/tunnels", "action_id", dl.actionID())
		if p := tunnel.Value["peer_address"]; !bytes.Equal(p.([]byte), netip.MustParseAddr(tc.peer).AsSlice()) {
			t.Errorf("the tunnel's peer is %x, want %s", p, tc.peer)
		}
		if l := tunnel.Value["local_address"]; !bytes.Equal(l.([]byte), netip.MustParseAddr("2001:db8:3::1").AsSlice()) {
			t.Errorf("the tunnel's local address is %x, want the endpoint's IPv6 2001:db8:3::1", l)
		}
	}
}

func TestAnSDFPrefixIsAPrefixNotAnAddress(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	req := message.NewSessionEstablishmentRequest(0, 0, 0x5556, 1, 0,
		ie.NewFSEID(0x5556, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x06, "10.45.0.6", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to 10.10.0.0/16", "", "", "", 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess))),
	)
	if got := cause(t, c.Establish(req)); got != ie.CauseRequestAccepted {
		t.Fatalf("an SDF prefix answered cause %d", got)
	}
	// The rule must match the whole prefix: the value is its network address and
	// the mask its length. With the address alone it would match 10.10.0.0 and
	// nothing else, which is a session that never carries a packet.
	rule := ruleCarrying(t, rec.last(), fieldDstIP, []byte{10, 10, 0, 0})
	if got := rule.value(fieldDstIP); !bytes.Equal(got, []byte{10, 10, 0, 0}) {
		t.Errorf("the prefix rule's destination value is %v, want the network address", got)
	}
	if got := rule.mask(fieldDstIP); !bytes.Equal(got, []byte{0xff, 0xff, 0, 0}) {
		t.Errorf("the prefix rule's destination mask is %v, want the /16", got)
	}

	// A filter whose address carries host bits means the network: address/mask
	// is the form, and the mask is what the rule carries. Refusing it would
	// turn an SMF's slightly sloppy filter into a session that cannot exist.
	// The prefix is another one: a rule is keyed by the prefix it names, so two
	// sessions naming one prefix hold one key and the second is refused
	// (TestASecondSessionsRuleCannotTakeTheFirsts).
	req = message.NewSessionEstablishmentRequest(0, 0, 0x5557, 1, 0,
		ie.NewFSEID(0x5557, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x06, "10.45.0.6", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to 10.11.1.5/16", "", "", "", 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess))),
	)
	if got := cause(t, c.Establish(req)); got != ie.CauseRequestAccepted {
		t.Fatalf("a filter with host bits answered cause %d", got)
	}
	sloppy := ruleCarrying(t, rec.last(), fieldDstIP, []byte{10, 11, 0, 0})
	if got := sloppy.value(fieldDstIP); !bytes.Equal(got, []byte{10, 11, 0, 0}) {
		t.Errorf("the sloppy prefix's value is %v, want the network address", got)
	}
	if got := sloppy.mask(fieldDstIP); !bytes.Equal(got, []byte{0xff, 0xff, 0, 0}) {
		t.Errorf("the sloppy prefix's mask is %v, want the /16", got)
	}
}

func TestAUEIPAllocationRequestIsRefused(t *testing.T) {
	// CHV4/CHV6 in a UE IP address IE (TS 29.244 8.2.62) is the SMF asking the
	// UP function to choose the address: the UEIP feature, which this UP does
	// not implement and does not advertise. The bits suppress the address
	// field, and reading the IE as "no address constraint" is worse than wrong
	// once the *other* direction carries an address -- the uplink rule compiles
	// with it and the answer says "the UP chose one", an address the SMF never
	// learns. So the request is refused where it is understood.
	//
	// The flags are the wire form an SMF sends: V4 (0x02) plus CHV4 (0x10), so
	// go-pfcp marshals the flags byte alone.
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	req := message.NewSessionEstablishmentRequest(0, 0, 0x5559, 1, 0,
		ie.NewFSEID(0x5559, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x06, "10.45.0.7", "", 0, 0)),
			ie.NewFARID(1)),
		ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(20),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewUEIPAddress(0x12, "", "", 0, 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess))),
	)
	if got := cause(t, c.Establish(req)); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a UE IP allocation request answered cause %d, want a rule failure", got)
	}
	if len(rec.txns) != 0 {
		t.Error("a refused session wrote to the dataplane")
	}

	// A dual-stack session, where the SMF gives the IPv4 address and asks the
	// UP to choose the IPv6 one: the flags are V4|V6|CHV6, so an IPv4 address
	// field is present and the CHV6 bit is the only sign that the SMF expects
	// an IPv6 address back. Reading the IE by its address alone accepts the
	// session and the SMF never learns what it was told to choose.
	req = message.NewSessionEstablishmentRequest(0, 0, 0x555b, 1, 0,
		ie.NewFSEID(0x555b, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x23, "10.45.0.8", "", 0, 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess))),
	)
	if got := cause(t, c.Establish(req)); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a V4 address with CHV6 answered cause %d, want a rule failure", got)
	}

	// The V4 flag with no address at all is a malformed IE rather than a
	// request: it parses as 0.0.0.0, and a rule keyed on that matches no
	// packet, so the session would stand while carrying nothing.
	req = message.NewSessionEstablishmentRequest(0, 0, 0x555c, 1, 0,
		ie.NewFSEID(0x555c, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x02, "", "", 0, 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess))),
	)
	if got := cause(t, c.Establish(req)); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("an empty V4 address answered cause %d, want a rule failure", got)
	}
}

func TestAnSDFBeforeTheUEIPResolvesTheSameWay(t *testing.T) {
	// A PDI's IEs are a set, not a sequence: an SMF may send the SDF filter
	// before the UE IP address. "assigned" means the PDI's UE address, and the
	// filter used to resolve it as it was read -- so this perfectly valid order
	// was refused. The word is kept now, and the key builder, which runs once
	// the whole session has been read, fills the address in.
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	req := message.NewSessionEstablishmentRequest(0, 0, 0x555a, 1, 0,
		ie.NewFSEID(0x555a, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewSDFFilter("permit out udp from assigned to any", "", "", "", 0),
				ie.NewUEIPAddress(0x02, "10.45.0.9", "", 0, 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess))),
	)
	if got := cause(t, c.Establish(req)); got != ie.CauseRequestAccepted {
		t.Fatalf("an SDF before the UE IP IE answered cause %d", got)
	}
	// A downlink PDR's SDF names a side by "assigned": the UE is the flow's
	// source here, so that is what the source field must carry.
	rule := ruleCarrying(t, rec.last(), fieldSrcIP, []byte{10, 45, 0, 9})
	if got := rule.value(fieldSrcIP); !bytes.Equal(got, []byte{10, 45, 0, 9}) {
		t.Errorf("the assigned rule's source value is %v, want the UE address", got)
	}
	if got := rule.mask(fieldSrcIP); !bytes.Equal(got, []byte{0xff, 0xff, 0xff, 0xff}) {
		t.Errorf("the assigned rule's source mask is %v, want a /32", got)
	}
}

func TestANonIPv4PDIIsRefusedNotWidened(t *testing.T) {
	// A table field is four bytes: an IPv6 UE address or SDF prefix cannot be
	// carried by it. Compiling one as "unconstrained" would write a rule that
	// matches every address, another session's packets included -- so the
	// session is refused, which is what the IPv6 gap in docs/claims.md
	// means for a PDI that names one.
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	req := message.NewSessionEstablishmentRequest(0, 0, 0x5558, 1, 0,
		ie.NewFSEID(0x5558, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x06, "10.45.0.6", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to 2001:db8::/32 53", "", "", "", 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess))),
	)
	if got := cause(t, c.Establish(req)); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("an IPv6 SDF answered cause %d, want a rule failure", got)
	}
	if len(rec.txns) != 0 {
		t.Error("a refused session wrote to the dataplane")
	}
}

func TestTheIDPoolWalksTheSpaceAndWaitsOutTheGrace(t *testing.T) {
	// The pool's two jobs: visit every id once before reusing any (so a
	// released id is out of circulation far longer than the dataplane's retire
	// period, and a restarted compiler does not walk its predecessor's order),
	// and then hand a released id back only once it has aged. What this
	// prevents: a session established right after a deletion was refused with
	// "the meter is still retiring (removed less than a grace period ago)",
	// because the pool had given it the deleted session's meter id.
	const limit = 8
	p := newIDPool(limit, time.Second)
	now := time.Unix(0, 0)
	p.now = func() time.Time { return now }

	first, err := p.alloc()
	if err != nil {
		t.Fatal(err)
	}
	held := map[uint32]bool{first: true}
	for i := 2; i < limit; i++ {
		id, err := p.alloc()
		if err != nil {
			t.Fatalf("allocation %d of a fresh space: %v", i, err)
		}
		if held[id] {
			t.Fatalf("allocation %d handed out %d, which is still held", i, id)
		}
		held[id] = true
	}
	if len(held) != limit-1 {
		t.Errorf("a walk of the space handed out %d of %d ids", len(held), limit-1)
	}

	// The walk is over and `first` was released a moment ago: nothing may come
	// back yet.
	p.release(first)
	if id, err := p.alloc(); err == nil {
		t.Errorf("an id released a moment ago was handed out again: %d", id)
	}

	// Once it has aged it comes back, and it is the released one.
	now = now.Add(time.Second)
	got, err := p.alloc()
	if err != nil {
		t.Fatalf("after the grace the released id must come back: %v", err)
	}
	if got != first {
		t.Errorf("after the grace the pool handed out %d, want the released %d", got, first)
	}

	// A released id never shares a number with one still held.
	if !held[first] {
		t.Fatal("the test lost track of the id it released")
	}
	for id := range held {
		if id == first {
			continue
		}
		if id == got {
			t.Errorf("the pool reissued %d, which a session still holds", id)
		}
	}
}

// reportedTEID is the F-TEID the answer reports for the uplink PDR, or 0.
func reportedTEID(t *testing.T, resp *message.SessionEstablishmentResponse) uint32 {
	t.Helper()
	for _, i := range resp.CreatedPDR {
		children, err := i.CreatedPDR()
		if err != nil {
			t.Fatal(err)
		}
		for _, ch := range children {
			if ch.Type != ie.FTEID {
				continue
			}
			f, err := ch.FTEID()
			if err != nil {
				t.Fatal(err)
			}
			return f.TEID
		}
	}
	return 0
}

func TestAnExhaustedFTEIDSpaceIsRefused(t *testing.T) {
	// A session whose uplink PDR has no rule to be selected by is a session
	// that blackholes the uplink while telling the SMF the establishment
	// succeeded. When the F-TEID space is empty the answer must be cause 74,
	// "no resources available", and nothing may reach the dataplane.
	cfg := testConfig()
	cfg.MaxTEIDs = 2 // the space is id 1 only (the slots are numbered from 1)
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())

	first := c.Establish(establishment(0x9101, "10.45.0.9")).(*message.SessionEstablishmentResponse)
	if got := cause(t, first); got != ie.CauseRequestAccepted {
		t.Fatalf("the first establishment answered cause %d", got)
	}
	before := len(rec.txns)

	second := c.Establish(establishment(0x9102, "10.45.0.10")).(*message.SessionEstablishmentResponse)
	if got := cause(t, second); got != ie.CauseNoResourcesAvailable {
		t.Errorf("an exhausted F-TEID space answered cause %d, want no-resources", got)
	}
	if len(rec.txns) != before {
		t.Error("a refused session wrote to the dataplane")
	}
}

func TestAPinnedFTEIDIsReservedAndOneCollisionIsRefused(t *testing.T) {
	cfg := testConfig()
	// A small space so the allocator's walk is easy to reason about.
	cfg.MaxTEIDs = 8
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())

	// Session 1 pins the F-TEID, as a compliant SMF does while FTUP is off.
	pinned := uint32(2)
	if got := cause(t, c.Establish(establishmentWithFTEID(0x9201, "10.45.0.9", pinned))); got != ie.CauseRequestAccepted {
		t.Fatalf("the pinned establishment answered cause %d", got)
	}

	// Session 2 leaves the choice to the UPF and must not get the pinned TEID.
	// Admission keys use endpoint, family, local address and TEID, not the UE
	// address; sharing one key across sessions is refused.
	for i := 0; i < 6; i++ {
		resp := c.Establish(establishment(0x9300+uint64(i), "10.45.0."+strconv.Itoa(20+i))).(*message.SessionEstablishmentResponse)
		if got := cause(t, resp); got != ie.CauseRequestAccepted {
			t.Fatalf("establishment %d answered cause %d", i, got)
		}
		if got := reportedTEID(t, resp); got == pinned {
			t.Fatalf("the allocator handed out the pinned F-TEID %#x", pinned)
		}
	}

	// A second session claiming the same endpoint-scoped F-TEID key is refused:
	// the SMF gets No Resources Available, not a shared admission entry.
	dup := c.Establish(establishmentWithFTEID(0x9401, "10.45.0.21", pinned)).(*message.SessionEstablishmentResponse)
	if got := cause(t, dup); got != ie.CauseNoResourcesAvailable {
		t.Errorf("a colliding F-TEID answered cause %d, want no-resources", got)
	}
}

// The session's UE address keys an uplink rule even when the uplink PDI does not
// name it: an F-TEID-selected uplink PDR is legal, and a rule with the address
// masked out would match every session's decapsulated packets at that
// precedence. A session with no UE address anywhere -- or one whose address the
// four-byte table cannot carry -- is refused with cause 73 rather than widened.
func TestTheUplinkRuleIsKeyedOnTheSessionsUEAddress(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())

	// The UE address arrives on the downlink PDI only.
	req := message.NewSessionEstablishmentRequest(0, 0, 0x5561, 1, 0,
		ie.NewNodeID("", "", "smf"),
		ie.NewFSEID(0x5561, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, 7, net.ParseIP("192.0.2.1"), nil, 0)),
			ie.NewFARID(1)),
		ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(20),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x06, "10.45.0.6", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to assigned 53", "", "", "", 0)),
			ie.NewFARID(2)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
		ie.NewCreateFAR(ie.NewFARID(2), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess),
				ie.NewOuterHeaderCreation(0x0100, 0x11223344, "10.20.30.2", "", 0, 0, 0))),
	)
	if got := cause(t, c.Establish(req)); got != ie.CauseRequestAccepted {
		t.Fatalf("a UE address on the downlink PDI only answered cause %d", got)
	}
	r := ruleCarrying(t, rec.last(), fieldSrcIP, []byte{10, 45, 0, 6})
	if got := r.mask(fieldSrcIP); !bytes.Equal(got, []byte{0xff, 0xff, 0xff, 0xff}) {
		t.Errorf("the uplink rule's address mask is %v, want the session's address keyed in", got)
	}

	// No UE address anywhere: the rule has no key, so the session is refused.
	bare := message.NewSessionEstablishmentRequest(0, 0, 0x5562, 1, 0,
		ie.NewNodeID("", "", "smf"),
		ie.NewFSEID(0x5562, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, 8, net.ParseIP("192.0.2.1"), nil, 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
	)
	before := len(rec.txns)
	if got := cause(t, c.Establish(bare)); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a session with no UE address at all answered cause %d, want a rule failure", got)
	}
	if len(rec.txns) != before {
		t.Error("a session with no UE address wrote to the dataplane")
	}

	// A UE IP IE carrying an IPv6 address is not "no address": reading it as
	// absent would key the uplink rule on the *other* PDI's IPv4 address, a
	// filter the SMF never asked for. The session is refused instead.
	v6 := message.NewSessionEstablishmentRequest(0, 0, 0x5563, 1, 0,
		ie.NewNodeID("", "", "smf"),
		ie.NewFSEID(0x5563, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, 9, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x01, "", "2001:db8::1", 0, 0)),
			ie.NewFARID(1)),
		ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(20),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x06, "10.45.0.6", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to assigned 53", "", "", "", 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
	)
	before = len(rec.txns)
	if got := cause(t, c.Establish(v6)); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("an IPv6 UE address answered cause %d, want a rule failure", got)
	}
	if len(rec.txns) != before {
		t.Error("a session with an IPv6 UE address wrote to the dataplane")
	}
}

// A refused establishment must not shrink the id space. The compile allocates
// the F-TEID before it can discover that a later PDR names something a
// four-byte field cannot carry, and nothing else would ever release it.
func TestARefusedEstablishmentReleasesItsIDs(t *testing.T) {
	cfg := testConfig()
	cfg.MaxTEIDs = 2 // one usable id: a leak shows up at once
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())

	// PDR 1 is fine and takes the id (its PDI asks the UPF to choose an
	// F-TEID, which is where the allocator runs); PDR 2's SDF names an IPv6
	// prefix, which the table cannot carry, so the whole session is refused.
	bad := message.NewSessionEstablishmentRequest(0, 0, 0x5562, 1, 0,
		ie.NewNodeID("", "", "smf"),
		ie.NewFSEID(0x5562, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				testFTEID(0),
				ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0)),
			ie.NewFARID(1)),
		ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(20),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x06, "10.45.0.6", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to 2001:db8::/32 53", "", "", "", 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
	)
	if got := cause(t, c.Establish(bad)); got != ie.CauseRuleCreationModificationFailure {
		t.Fatalf("the inexpressible PDI answered cause %d", got)
	}
	// With the id back the space still has one once the reuse delay has
	// passed; without it, the answer here is cause 75.
	c.teids.now = func() time.Time { return time.Now().Add(time.Minute) }
	good := c.Establish(establishment(0x5563, "10.45.0.7")).(*message.SessionEstablishmentResponse)
	if got := cause(t, good); got != ie.CauseRequestAccepted {
		t.Errorf("after a refused establishment the space answered cause %d", got)
	}
}

// A capacity of zero or one leaves no id at all: alloc answers no-resources,
// rather than handing out id 1 (which the modules would refuse) or panicking in
// the walk's arithmetic.
func TestAnEmptyIDPoolAnswersNoResources(t *testing.T) {
	for _, limit := range []uint32{0, 1} {
		p := newIDPool(limit, 0)
		if id, err := p.alloc(); err == nil {
			t.Errorf("a pool of limit %d handed out id %d", limit, id)
		}
	}
}

// A session releases an id once per PDR that names it -- a QER shared by three
// PDRs is one meter -- and the free list must hold one entry, or the same id is
// handed to two sessions later.
func TestARepeatedReleaseQueuesOneID(t *testing.T) {
	p := newIDPool(4, 0)
	for { // the walk passes every id: releases only queue ids it has passed
		if _, err := p.alloc(); err != nil {
			break
		}
	}
	p.release(3)
	p.release(3)
	p.release(3)
	if n := len(p.freed); n != 1 {
		t.Errorf("three releases of one id queued %d entries", n)
	}
}

// A refused establishment must not disturb the session that holds the value it
// pinned: the refused request's PDR keeps the SMF's TEID, and freeing the
// mapping would let a third session take the value and overwrite the holder's
// rule.
func TestARefusedCollisionLeavesTheHoldersFTEIDAlone(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	pinned := uint32(3)
	resp := c.Establish(establishmentWithFTEID(0x5701, "10.45.0.6", pinned)).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the holder's establishment answered cause %d", got)
	}
	// A second session pinning the same value: refused, not shared.
	if got := cause(t, c.Establish(establishmentWithFTEID(0x5702, "10.45.0.7", pinned))); got != ie.CauseNoResourcesAvailable {
		t.Fatalf("a colliding pin answered cause %d, want no-resources", got)
	}
	// The holder still holds it, so a third pin is refused too.
	third := c.Establish(establishmentWithFTEID(0x5703, "10.45.0.8", pinned)).(*message.SessionEstablishmentResponse)
	if got := cause(t, third); got != ie.CauseNoResourcesAvailable {
		t.Errorf("after a refused collision the value went to a third session (cause %d)", got)
	}
}

// A establishment that fails after allocating must give the id back: here the
// first PDR takes the only one (the UPF chooses its F-TEID) and the second pins
// a value another session holds, so merge refuses after the allocation.
func TestAMergeRefusalReleasesWhatItAllocated(t *testing.T) {
	cfg := testConfig()
	cfg.MaxTEIDs = 2 // one usable id
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())

	holder := c.Establish(establishmentWithFTEID(0x5710, "10.45.0.6", 0x77)).(*message.SessionEstablishmentResponse)
	if got := cause(t, holder); got != ie.CauseRequestAccepted {
		t.Fatalf("the holder answered cause %d", got)
	}

	clash := message.NewSessionEstablishmentRequest(0, 0, 0x5711, 1, 0,
		ie.NewNodeID("", "", "smf"),
		ie.NewFSEID(0x5711, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x04, 0, nil, nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.9", "", 0, 0)),
			ie.NewFARID(1)),
		ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(20),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, 0x77, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.9", "", 0, 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
	)
	if got := cause(t, c.Establish(clash)); got != ie.CauseNoResourcesAvailable {
		t.Fatalf("the clashing session answered cause %d", got)
	}
	// The id the refused session allocated is back: once the reuse delay has
	// passed, a new session gets it.
	c.teids.now = func() time.Time { return time.Now().Add(time.Minute) }
	next := c.Establish(establishment(0x5712, "10.45.0.10")).(*message.SessionEstablishmentResponse)
	if got := cause(t, next); got != ie.CauseRequestAccepted {
		t.Errorf("after a refused merge the single id was not given back (cause %d)", got)
	}
}

// An Apply whose outcome is unknown may have committed, so the ids stay
// allocated: that keeps the pool from handing a live record's id to the next
// session. The leak is deliberate, and this test is where it is written down.
func TestAnUnknownOutcomeKeepsTheIDs(t *testing.T) {
	cfg := testConfig()
	cfg.MaxTEIDs = 2 // one usable id
	rec := &recorder{fail: errors.New("transport")}
	c := New(cfg, rec, quietLogger())

	first := c.Establish(establishment(0x5720, "10.45.0.6")).(*message.SessionEstablishmentResponse)
	if got := cause(t, first); got != ie.CauseRequestRejected {
		t.Fatalf("an unknown outcome answered cause %d", got)
	}
	second := c.Establish(establishment(0x5721, "10.45.0.7")).(*message.SessionEstablishmentResponse)
	if got := cause(t, second); got != ie.CauseNoResourcesAvailable {
		t.Errorf("the id of an unknown outcome was reused (cause %d): a record may still select it", got)
	}
}

// One TEID can be reserved by several endpoint-scoped keys. Each owner gets its
// own admission context, so the PDR key cannot cross-match the two tunnels, and
// releasing one key must not return the TEID to the allocator while another
// endpoint still uses it.
func TestFTEIDOwnershipIsEndpointScopedAndRefcounted(t *testing.T) {
	c := New(testConfig(), &recorder{}, quietLogger())
	firstAddr := netip.MustParseAddr("192.0.2.1")
	secondAddr := netip.MustParseAddr("192.0.2.2")
	makePDR := func(id uint16, endpoint uint32, addr netip.Addr) *pdr {
		return &pdr{id: id, srcIfc: ie.SrcInterfaceAccess, teid: 0x77,
			endpointID: endpoint, endpointFamily: 4, endpointIPv4: addr,
			endpointFamilies: []uint8{4}}
	}
	first := &Session{LocalSEID: 1, PDRs: map[uint16]*pdr{}}
	firstPDR := makePDR(1, 1, firstAddr)
	first.PDRs[1] = firstPDR
	second := &Session{LocalSEID: 2, PDRs: map[uint16]*pdr{}}
	secondPDR := makePDR(1, 2, secondAddr)
	second.PDRs[1] = secondPDR

	c.mu.Lock()
	if err := c.claimFTEID(first, firstPDR); err != nil {
		t.Fatal(err)
	}
	if err := c.claimFTEID(second, secondPDR); err != nil {
		t.Fatal(err)
	}
	conflict := makePDR(2, 2, secondAddr)
	conflict.down = true
	if err := c.claimFTEID(&Session{LocalSEID: 3}, conflict); err == nil {
		t.Fatal("the same exact endpoint key was claimed for the opposite direction")
	}
	c.mu.Unlock()
	if firstPDR.fteidContext == 0 || firstPDR.fteidContext == secondPDR.fteidContext {
		t.Fatalf("TEID 0x77 on two endpoints shares context %d/%d: their PDR rules would cross-match",
			firstPDR.fteidContext, secondPDR.fteidContext)
	}

	if len(fteidKeysOf(firstPDR)) != 1 || len(fteidKeysOf(secondPDR)) != 1 ||
		fteidKeysOf(firstPDR)[0] == fteidKeysOf(secondPDR)[0] {
		t.Fatal("distinct endpoint keys collapsed despite sharing TEID 0x77")
	}
	c.mu.Lock()
	c.releaseSession(first)
	remaining := c.fteidTEIDKeys[0x77]
	_, secondStillOwned := c.byFTEID[fteidKeysOf(secondPDR)[0]]
	pinned := c.teids.taken[0x77]
	c.mu.Unlock()
	if remaining != 1 || !secondStillOwned || !pinned {
		t.Fatalf("releasing one endpoint prematurely freed the shared TEID: refs=%d owner=%v pinned=%v", remaining, secondStillOwned, pinned)
	}
	c.mu.Lock()
	c.releaseSession(second)
	remaining, pinned = c.fteidTEIDKeys[0x77], c.teids.taken[0x77]
	contexts := len(c.fteidContexts)
	c.mu.Unlock()
	if remaining != 0 || pinned || contexts != 0 {
		t.Fatalf("last endpoint did not release the TEID: refs=%d pinned=%v contexts=%d", remaining, pinned, contexts)
	}
}

// Two uplink PDRs that pin one F-TEID are ordinary SMF practice: the session is
// accepted, and when it goes the pinned value is free again -- but only once.
// Releasing it per PDR (instead of per id) deletes the reservation on the first
// call and queues the value on the second, so the pool hands the same id out
// twice.
func TestTwoPDRsMayShareOnePinnedFTEID(t *testing.T) {
	cfg := testConfig()
	cfg.MaxTEIDs = 0x100 // so 0x77 is inside the pool's range
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())

	const pinned = 0x77
	req := message.NewSessionEstablishmentRequest(0, 0, 0x5730, 1, 0,
		ie.NewNodeID("", "", "smf"),
		ie.NewFSEID(0x5730, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, pinned, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0)),
			ie.NewFARID(1)),
		ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(20),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, pinned, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to 8.8.8.8 53", "", "", "", 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
	)
	resp := c.Establish(req).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("two PDRs sharing the pinned F-TEID %#x answered cause %d", pinned, got)
	}
	if err := c.remove(context.Background(), c.sessions[upFSEID(t, resp)]); err != nil {
		t.Fatalf("the deletion failed: %v", err)
	}

	// Every id the space can yield, each exactly once.
	seen := map[uint32]bool{}
	n := 0
	for {
		id, err := c.teids.alloc()
		if err != nil {
			break
		}
		if seen[id] {
			t.Fatalf("after the pin was released, alloc handed out %#x twice", id)
		}
		seen[id] = true
		n++
	}
	if want := int(cfg.MaxTEIDs) - 1; n != want {
		t.Errorf("the space yielded %d ids, want %d: a shared pin was queued for allocation", n, want)
	}
}

// gatedApply parks the first Apply until the test lets it go, so a second
// establishment can run its merge while the first is in flight.
type gatedApply struct {
	inner   Applier
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (g *gatedApply) Apply(ctx context.Context, changes ...bess.Change) error {
	first := false
	g.once.Do(func() { first = true; close(g.entered) })
	if first {
		<-g.release
	}
	return g.inner.Apply(ctx, changes...)
}

// Exact composite-key ownership is claimed during merge, before Apply. Holding
// the first Apply open therefore cannot let a concurrent identical pin pass.
func TestAPinArrivingDuringAnApplyIsRefused(t *testing.T) {
	cfg := testConfig()
	cfg.MaxTEIDs = 0x100
	rec := &recorder{}
	gate := &gatedApply{inner: rec, entered: make(chan struct{}), release: make(chan struct{})}
	c := New(cfg, gate, quietLogger())

	const pinned = 0x55
	type result struct {
		resp message.Message
	}
	done := make(chan result, 1)
	go func() {
		done <- result{c.Establish(establishmentWithFTEID(0x5740, "10.45.0.6", pinned))}
	}()
	<-gate.entered // the first session is inside Apply: its rule, no mapping yet

	second := c.Establish(establishmentWithFTEID(0x5741, "10.45.0.7", pinned)).(*message.SessionEstablishmentResponse)
	if got := cause(t, second); got != ie.CauseNoResourcesAvailable {
		t.Errorf("a pin of a value whose holder is mid-Apply answered cause %d, want no-resources", got)
	}

	close(gate.release)
	first := (<-done).resp.(*message.SessionEstablishmentResponse)
	if got := cause(t, first); got != ie.CauseRequestAccepted {
		t.Errorf("the holder's establishment answered cause %d", got)
	}
}

func TestDataplaneRefusalBecomesACause(t *testing.T) {
	rec := &recorder{fail: &bess.RejectedError{}}
	c := New(testConfig(), rec, quietLogger())
	if got := cause(t, c.Establish(establishment(0x6666, "10.45.0.7"))); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a rejected transaction answered cause %d", got)
	}

	// A refusal for lack of memory (BESS D-198, RESOURCE_EXHAUSTED) is
	// definite: answered "no resources", and the session's address is free
	// again for a later attempt.
	rec.fail = &bess.InvalidRequestError{Code: codes.ResourceExhausted, Message: "memory"}
	if got := cause(t, c.Establish(establishment(0x6667, "10.45.0.9"))); got != ie.CauseNoResourcesAvailable {
		t.Errorf("a refusal for lack of memory answered cause %d, want no-resources", got)
	}
	rec.fail = nil
	if got := cause(t, c.Establish(establishment(0x6668, "10.45.0.9"))); got != ie.CauseRequestAccepted {
		t.Errorf("the address of a session refused for memory answered cause %d on retry", got)
	}

	rec.fail = errors.New("transport")
	if got := cause(t, c.Establish(establishment(0x7777, "10.45.0.8"))); got != ie.CauseRequestRejected {
		t.Errorf("an unknown outcome answered cause %d, want a plain rejection", got)
	}
}

func TestModifyRewritesTheWholeSession(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(establishment(0x8888, "10.45.0.9")).(*message.SessionEstablishmentResponse)

	mod := message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 2, 0,
		ie.NewUpdateFAR(ie.NewFARID(2), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceAccess),
				ie.NewOuterHeaderCreation(0x0100, 0x55667788, "10.20.30.9", "", 0, 0, 0),
			)),
	)
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("modification refused with cause %d", got)
	}
	var tunnel bess.Change
	for _, ch := range rec.last() {
		if ch.Resource == testConfig().Down.Tunnels+"/tunnels" {
			tunnel = ch
		}
	}
	if tunnel.Key == nil {
		t.Fatal("the modification did not rewrite the tunnel")
	}
	if got := tunnel.Value["teid"]; got != uint32(0x55667788) {
		t.Errorf("the tunnel's TEID is %v after the modification", got)
	}
	if n := len(rules(rec.last())); n != 2 {
		t.Errorf("%d rules rewritten, want both PDRs", n)
	}
}

// -- Usage Reporting Rules ----------------------------------------------------
//
// The URR IEs (TS 29.244 7.5.2.4 and 8.2.x) this UP reads, and what it refuses:
// a report is what the SMF bills from, so a URR field that cannot be honoured
// is a rule failure, never something quietly not measured.

func TestClosingAGateDropsThePacketsOfALivePDR(t *testing.T) {
	// A QER's gate is the rule's gate: a modification that closes it must take
	// the action away in the same transaction. The establishment path already
	// writes the drop gate (TestAClosedGateDropsWithoutAnAction); the update
	// path is the one that matters to a live session -- a handover's QER change
	// and a URR's exhausted quota both arrive as an update to a PDR that has an
	// action id already, and a PDR that keeps its action goes on forwarding.
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	req := establishment(0x6010, "10.45.0.6")
	req.CreateQER = []*ie.IE{ie.NewCreateQER(
		ie.NewQERID(1),
		ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
	)}
	resp := c.Establish(req).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	if got := ruleCarrying(t, rec.last(), fieldSrcIP, []byte{10, 45, 0, 6}).actionID(); got == 0 {
		t.Fatal("the uplink PDR has no action id to keep")
	}

	mod := message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 2, 0,
		ie.NewUpdateQER(ie.NewQERID(1),
			ie.NewGateStatus(ie.GateStatusClosed, ie.GateStatusOpen)),
	)
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification answered cause %d", got)
	}
	r := ruleCarrying(t, rec.last(), fieldSrcIP, []byte{10, 45, 0, 6})
	if got := r.gate(); got != dropGate {
		t.Errorf("a closed gate's rule gates %d, want the drop gate %d", got, dropGate)
	}
	if got := r.actionID(); got != 0 {
		t.Errorf("a closed gate's rule names action %d, want none", got)
	}
}

// counterKeys is the action ids a transaction carries to a direction's counter
// resource ("cnt_ul/counters"): one per rule a URR measures.
func counterKeys(changes []bess.Change, resource string) []uint32 {
	var out []uint32
	for _, ch := range changes {
		if ch.Resource != resource || ch.Value == nil {
			continue
		}
		if id, ok := ch.Key["action_id"].(uint32); ok {
			out = append(out, id)
		}
	}
	return out
}

func TestAPDRATURReasuresIsCounted(t *testing.T) {
	// What makes a rule's traffic measured is one entry in the direction's
	// counting module, keyed by the same ActionId the rule names. A PDR no URR
	// names gets none: the counting module then costs that session's packets
	// one lookup and nothing else (docs/design.md, "Per feature, per packet").
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	req := urrEstablishment(0x3010, 7, fullURR(7))
	// The downlink PDR of the usual establishment, so that "the not-measured
	// direction gets nothing" is answered from one session rather than two.
	req.CreatePDR = append(req.CreatePDR, establishment(0x3010, "10.45.0.2").CreatePDR[1])
	req.CreateFAR = append(req.CreateFAR, establishment(0x3010, "10.45.0.2").CreateFAR...)
	resp := c.Establish(req).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	changes := rec.last()
	up := counterKeys(changes, countersRes(testConfig().Up))
	if len(up) != 1 {
		t.Fatalf("the uplink PDR's URR wrote %d counter entries, want one", len(up))
	}
	actionID := ruleCarrying(t, changes, fieldSrcIP, []byte{10, 45, 0, 2}).actionID()
	if up[0] != actionID {
		t.Errorf("the counter entry names action %d, want the rule's %d", up[0], actionID)
	}
	if n := len(counterKeys(changes, countersRes(testConfig().Down))); n != 0 {
		t.Errorf("the downlink PDR, which no URR measures, wrote %d counter entries", n)
	}
	assertNoRepeat(t, changes)
}

func TestAURRWithoutACountingModuleIsRefused(t *testing.T) {
	// A graph with no counting module in that direction (a deployment that does
	// not charge, or a flag left empty) cannot measure anything: the session
	// must be refused with a rule failure rather than compiled with a URR whose
	// every report would say zero.
	cfg := testConfig()
	cfg.Up.Counters = ""
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())
	if got := cause(t, c.Establish(urrEstablishment(0x3011, 7, fullURR(7)))); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a URR against a graph with no counters answered cause %d, want a rule failure", got)
	}
	if len(rec.txns) != 0 {
		t.Error("a refused session wrote to the dataplane")
	}
}

func TestAnUpdateThatKeepsTheURRMovesTheCounterOnce(t *testing.T) {
	// The entry is keyed by the ActionId, which an update keeps: the replaced
	// form's entry must not be erased while the same transaction writes it, or
	// the engine rejects the list (the same rule as the PDR's own key).
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(urrEstablishment(0x3012, 7, fullURR(7))).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	mod := message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 2, 0,
		ie.NewUpdateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
	)
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification answered cause %d", got)
	}
	if n := len(counterKeys(rec.last(), countersRes(testConfig().Up))); n != 1 {
		t.Errorf("the update wrote %d counter entries, want the one it kept", n)
	}
	assertNoRepeat(t, rec.last())
}

// evaluate is Evaluate with the failure the tests do not expect folded away, so
// a test reads as the sequence of readings it sets up and the reports each
// earns.
func evaluate(t *testing.T, c *Compiler, seid uint64) []Report {
	t.Helper()
	reports, err := c.Evaluate(context.Background(), seid, time.Now())
	if err != nil {
		t.Fatalf("evaluating: %v", err)
	}
	return reports
}

// quotaURR is a URR that measures volume and stops the traffic when the quota
// is reached: the shape a quota test needs, without the threshold and period
// triggers of fullURR firing first.
func quotaURR(id uint32, total uint64) *ie.IE {
	return ie.NewCreateURR(
		ie.NewURRID(id),
		ie.NewMeasurementMethod(0, 1, 0),    // VOLUM
		ie.NewReportingTriggers(0x00, 0x01), // VOLQU
		ie.NewVolumeQuota(0x01, total, 0, 0),
	)
}

// timeQuotaURR is a URR that measures time only and stops the traffic when the
// time quota is reached: the shape the duration half of a measurement is judged
// by.
func timeQuotaURR(id uint32, quota time.Duration) *ie.IE {
	return ie.NewCreateURR(
		ie.NewURRID(id),
		ie.NewMeasurementMethod(0, 0, 1),             // DURAT
		ie.NewReportingTriggers(0x00, trigTimeQuota), // TIME_QUOTA
		ie.NewTimeQuota(quota),
	)
}

// TestATimeQuotaIsSpentByTheTimeTheTrafficRan is the duration half of a URR:
// the time a quota is measured against is the time the traffic ran (5.2.2.2.1),
// which the dataplane's own stamps say -- the window's own first packet to the
// reading's last one -- and not the clock. A quota longer than one tick is
// reached by running across several of them, a tick the traffic was quiet in
// spends nothing, and the report carries the window's first and last packet.
func TestATimeQuotaIsSpentByTheTimeTheTrafficRan(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(urrEstablishment(0x4040, 7, timeQuotaURR(7, 2500*time.Millisecond))).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	seid := upFSEID(t, resp)
	rule := ruleCarrying(t, rec.last(), fieldSrcIP, []byte{10, 45, 0, 2})
	module := testConfig().Up.Counters
	base := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

	// tick is one evaluation: the counters are cumulative (the module's reading
	// is), and the stamps are the tick's own traffic, ten milliseconds into it
	// and ten before its end.
	tick := func(i int, packets uint64, running bool) []Report {
		t.Helper()
		count := bess.RuleCount{ActionID: rule.actionID(), Packets: packets, Octets: packets * 100}
		if running {
			count.First = base.Add(time.Duration(i)*time.Second + 10*time.Millisecond)
			count.Last = base.Add(time.Duration(i)*time.Second + 990*time.Millisecond)
		}
		rec.counts = map[string][]bess.RuleCount{module: {count}}
		reports, err := c.Evaluate(context.Background(), seid, base.Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatalf("tick %d: %v", i, err)
		}
		return reports
	}

	tick(0, 0, false) // the first reading is the window's baseline
	if reports := tick(1, 10, true); len(reports) != 0 {
		t.Fatalf("one second of traffic reported %+v, want nothing under a 2.5 s quota", reports)
	}
	if reports := tick(2, 20, true); len(reports) != 0 {
		t.Fatalf("two seconds of traffic reported %+v, want nothing under a 2.5 s quota", reports)
	}
	// A second the traffic was quiet in spends nothing of the quota, whatever
	// the clock did with it.
	if reports := tick(3, 20, false); len(reports) != 0 {
		t.Fatalf("a quiet second reported %+v, want nothing", reports)
	}
	reports := tick(4, 30, true)
	if len(reports) != 1 {
		t.Fatalf("three running seconds reported %d reports, want the used-up quota's one", len(reports))
	}
	r := reports[0]
	if r.Trigger != TriggerTimeQuota {
		t.Errorf("the trigger is %v, want the time quota", r.Trigger)
	}
	if !r.Enforcing {
		t.Error("the report does not say the traffic is stopping")
	}
	// The window's own first packet opened it on the first tick that carried
	// traffic, and its last is the reading's -- not the last tick's first.
	wantFirst := base.Add(time.Second + 10*time.Millisecond)
	wantLast := base.Add(4*time.Second + 990*time.Millisecond)
	if !r.First.Equal(wantFirst) || !r.Last.Equal(wantLast) {
		t.Errorf("the report's stamps are %v..%v, want the window's %v..%v", r.First, r.Last, wantFirst, wantLast)
	}

	// And the IEs carry them (TS 29.244 8.2.44, 8.2.45), which is what an SMF
	// reads a duration measurement from.
	ies := r.IEs()
	if len(ies) != 2 {
		t.Fatalf("the report is %d IEs, want the report type and the usage report", len(ies))
	}
	var gotFirst, gotLast *ie.IE
	for _, child := range ies[1].ChildIEs {
		switch child.Type {
		case ie.TimeOfFirstPacket:
			gotFirst = child
		case ie.TimeOfLastPacket:
			gotLast = child
		}
	}
	if gotFirst == nil || gotLast == nil {
		t.Fatalf("the usage report carries no packet times (first %v, last %v)", gotFirst, gotLast)
	}
	// The IE carries whole seconds (its own resolution), so the check is that
	// the second it names is the stamp's.
	if ts, err := gotFirst.TimeOfFirstPacket(); err != nil || !ts.Equal(wantFirst.Truncate(time.Second)) {
		t.Errorf("the report's Time of First Packet is %v (%v), want %v", ts, err, wantFirst.Truncate(time.Second))
	}
	if ts, err := gotLast.TimeOfLastPacket(); err != nil || !ts.Equal(wantLast.Truncate(time.Second)) {
		t.Errorf("the report's Time of Last Packet is %v (%v), want %v", ts, err, wantLast.Truncate(time.Second))
	}
}

func TestEvaluateReportsAUsedUpQuotaAndStopsTheTraffic(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(urrEstablishment(0x3030, 7, quotaURR(7, 1000))).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	rule := ruleCarrying(t, rec.last(), fieldSrcIP, []byte{10, 45, 0, 2})
	// The dataplane has counted 1500 octets of 10 packets for that rule, over
	// the 1000 the SMF provisioned.
	// The dataplane's first reading is the window's base and reports nothing;
	// the traffic after it is what spends the quota.
	if reports := evaluate(t, c, upFSEID(t, resp)); len(reports) != 0 {
		t.Fatalf("the baseline reading reported %+v, want none", reports)
	}
	rec.counts = map[string][]bess.RuleCount{
		testConfig().Up.Counters: {{ActionID: rule.actionID(), Packets: 10, Octets: 1500}},
	}

	reports := evaluate(t, c, upFSEID(t, resp))
	if len(reports) != 1 {
		t.Fatalf("evaluation returned %d reports, want one for the used-up quota", len(reports))
	}
	r := reports[0]
	if r.Trigger != TriggerVolumeQuota {
		t.Errorf("the report's trigger is %v, want the volume quota", r.Trigger)
	}
	if r.Seqn != 0 {
		t.Errorf("the first report of a URR carries UR-SEQN %d, want 0", r.Seqn)
	}
	if r.Up != (Usage{Packets: 10, Octets: 1500}) {
		t.Errorf("the report carries %+v uplink, want the window's 10 packets and 1500 octets", r.Up)
	}
	if !r.Enforcing {
		t.Error("a report for a used-up quota is not marked as stopping the traffic")
	}
	if r.SEID != upFSEID(t, resp) || r.CPSEID != 0x3030 || r.URRID != 7 {
		t.Errorf("the report names SEID %d, CP SEID %d, URR %d; want %d, %#x, 7",
			r.SEID, r.CPSEID, r.URRID, upFSEID(t, resp), 0x3030)
	}

	// The enforcement reached the dataplane: the PDR's rule is a drop, so the
	// packets stop reaching the chain the URR measures.
	enforced := ruleCarrying(t, rec.last(), fieldSrcIP, []byte{10, 45, 0, 2})
	if got := enforced.gate(); got != dropGate {
		t.Errorf("after the quota ran out the rule gates %d, want the drop gate %d", got, dropGate)
	}

	// A second evaluation has nothing to say: the report is made, and the rule
	// it stopped is not counted any more.
	again, err := c.Evaluate(context.Background(), upFSEID(t, resp), time.Now())
	if err != nil {
		t.Fatalf("evaluating again: %v", err)
	}
	if len(again) != 0 {
		t.Errorf("the second evaluation returned %d reports, want none", len(again))
	}
}

func TestEvaluateReportsTheWindowItMeasured(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(urrEstablishment(0x3031, 7, fullURR(7))).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	rule := ruleCarrying(t, rec.last(), fieldSrcIP, []byte{10, 45, 0, 2})
	module := testConfig().Up.Counters

	// The volume threshold in fullURR is 1MiB: below it, and before the 30s
	// period, the URR owes nothing. This first reading is also the window's
	// baseline, so the 400 octets in it are not usage.
	rec.counts = map[string][]bess.RuleCount{module: {{ActionID: rule.actionID(), Packets: 4, Octets: 400}}}
	if reports := evaluate(t, c, upFSEID(t, resp)); len(reports) != 0 {
		t.Fatalf("the baseline reading returned %v, want none", reports)
	}

	// The threshold is reached: the report says which one and carries the
	// window, and the next one starts where this report ended -- the counter is
	// cumulative, so what arrives after it is what the following report covers.
	const threshold = 1 << 20
	rec.counts = map[string][]bess.RuleCount{module: {{ActionID: rule.actionID(), Packets: 9, Octets: threshold + 1000}}}
	reports := evaluate(t, c, upFSEID(t, resp))
	if len(reports) != 1 || reports[0].Trigger != TriggerVolumeThreshold {
		t.Fatalf("evaluation returned %+v, want one volume-threshold report", reports)
	}
	if got := reports[0].Up; got != (Usage{Packets: 5, Octets: threshold + 600}) {
		t.Errorf("the first report carries %+v, want the whole window", got)
	}

	// Another window: only what arrives after the first report counts, so the
	// threshold needs another 1MiB -- the 900 octets short of it earn nothing.
	rec.counts = map[string][]bess.RuleCount{module: {{ActionID: rule.actionID(), Packets: 10, Octets: threshold + 1900}}}
	if reports := evaluate(t, c, upFSEID(t, resp)); len(reports) != 0 {
		t.Fatalf("a window under the threshold returned %v, want none", reports)
	}

	rec.counts = map[string][]bess.RuleCount{module: {{ActionID: rule.actionID(), Packets: 11, Octets: 2*threshold + 2900}}}
	reports = evaluate(t, c, upFSEID(t, resp))
	if len(reports) != 1 {
		t.Fatalf("evaluation returned %d reports, want the one the new window earned", len(reports))
	}
	if got := reports[0].Up; got != (Usage{Packets: 2, Octets: threshold + 1900}) {
		t.Errorf("the second report carries %+v, want only what arrived since the first", got)
	}
	if reports[0].Seqn != 1 {
		t.Errorf("the second report carries UR-SEQN %d, want 1", reports[0].Seqn)
	}
}

// linkedEstablishment is the shape a linked pair needs: one PDR that both URRs
// measure, URR 7 with the quota that gets spent, and URR 9 linked to linkedTo
// (8.2.55) so the two report together.
func linkedEstablishment(cpSEID uint64, linkedTo uint32) *message.SessionEstablishmentRequest {
	return message.NewSessionEstablishmentRequest(0, 0, cpSEID, 1, 0,
		ie.NewFSEID(cpSEID, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, 0x1000, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.2", "", 0, 0)),
			ie.NewFARID(1), ie.NewURRID(7), ie.NewURRID(9)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
		quotaURR(7, 1000),
		ie.NewCreateURR(
			ie.NewURRID(9),
			ie.NewMeasurementMethod(0, 1, 0),     // VOLUM
			ie.NewReportingTriggers(0x00, 0x01),  // VOLQU
			ie.NewVolumeQuota(0x01, 1<<40, 0, 0), // a quota URR 9 will not spend
			ie.NewLinkedURRID(linkedTo),
		),
	)
}

// TestALinkedURRReportsItsGroupUnderOneURSEQN is the linked half of the URR
// block: a URR linked to another (8.2.55) is read and validated, and when one
// of the pair is due the report carries both, their usage under a single
// UR-SEQN that the SMF reads as one combined report (8.2.71). URR 9's own
// quota is never reached: it is reported because URR 7's is, which is what the
// link means.
func TestALinkedURRReportsItsGroupUnderOneURSEQN(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(linkedEstablishment(0x3033, 7)).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment of a linked pair answered cause %d", got)
	}
	rule := ruleCarrying(t, rec.last(), fieldSrcIP, []byte{10, 45, 0, 2})
	// The first reading of each URR is its baseline, not its usage.
	if reports := evaluate(t, c, upFSEID(t, resp)); len(reports) != 0 {
		t.Fatalf("the baseline reading returned %+v, want none", reports)
	}
	rec.counts = map[string][]bess.RuleCount{
		testConfig().Up.Counters: {{ActionID: rule.actionID(), Packets: 10, Octets: 1500}},
	}

	reports := evaluate(t, c, upFSEID(t, resp))
	if len(reports) != 1 {
		t.Fatalf("the linked pair owed %d reports, want the group's one", len(reports))
	}
	r := reports[0]
	if r.URRID != 7 || r.Trigger != TriggerVolumeQuota {
		t.Errorf("the group report names URR %d with trigger %v, want URR 7 and the volume quota",
			r.URRID, r.Trigger)
	}
	if !r.Enforcing {
		t.Error("the group report does not say the spent quota stops the traffic")
	}
	// The linked half is carried with it: URR 9 measures the same rule and is
	// reported beside URR 7, not on its own.
	if len(r.Linked) != 1 || r.Linked[0].URRID != 9 {
		t.Fatalf("the group report carries %+v linked, want URR 9", r.Linked)
	}
	if got := r.Linked[0].Up; got != (Usage{Packets: 10, Octets: 1500}) {
		t.Errorf("URR 9's linked usage is %+v, want the window's 10 packets and 1500 octets", got)
	}

	// One report, one UR-SEQN: both Usage Report IEs carry the same sequence,
	// which is what links the two URRs to the SMF (8.2.71).
	var usageReports []*ie.IE
	for _, i := range r.IEs() {
		if i.Type == ie.UsageReportWithinSessionReportRequest {
			usageReports = append(usageReports, i)
		}
	}
	if len(usageReports) != 2 {
		t.Fatalf("the report carries %d usage reports, want one for each linked URR", len(usageReports))
	}
	seqnOf := map[uint32]uint32{}
	for _, ur := range usageReports {
		var urrID, seqn uint32
		for _, child := range ur.ChildIEs {
			switch child.Type {
			case ie.URRID:
				urrID, _ = child.URRID()
			case ie.URSEQN:
				seqn, _ = child.URSEQN()
			}
		}
		seqnOf[urrID] = seqn
	}
	if _, ok := seqnOf[7]; !ok {
		t.Fatalf("the group's usage reports name %v, want URRs 7 and 9", seqnOf)
	}
	if seqnOf[7] != seqnOf[9] {
		t.Errorf("the linked URRs carry UR-SEQNs %d and %d, want one shared sequence", seqnOf[7], seqnOf[9])
	}
	if seqnOf[7] != 0 {
		t.Errorf("the group's first report carries UR-SEQN %d, want 0", seqnOf[7])
	}
}

// TestALinkedURRNamingAnUnknownURRIsRefused: a Linked URR ID the session does
// not hold is a link the SMF cannot get a report from, refused with cause 73
// naming what could not be found (the same refusal a PDR naming an unknown URR
// gets).
func TestALinkedURRNamingAnUnknownURRIsRefused(t *testing.T) {
	var logged bytes.Buffer
	rec := &recorder{}
	c := New(testConfig(), rec, slog.New(slog.NewTextHandler(&logged, nil)))
	resp := c.Establish(linkedEstablishment(0x3034, 99)).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRuleCreationModificationFailure {
		t.Fatalf("a link naming an unknown URR answered cause %d, want 73", got)
	}
	if !strings.Contains(logged.String(), "99") {
		t.Errorf("the refusal does not name the URR it could not find:\n%s", logged.String())
	}
}

// liusaEstablishment is the shape the LIUSA trigger needs: one PDR both URRs
// measure, URR 7 asking for Linked Usage Reporting (8.2.19, LIUSA) and linked
// to URR 9, and URR 9 carrying the volume quota that gets spent. URR 7 also
// carries a period that would report on its own if LIUSA were ignored.
func liusaEstablishment(cpSEID uint64, linkedTo uint32) *message.SessionEstablishmentRequest {
	return message.NewSessionEstablishmentRequest(0, 0, cpSEID, 1, 0,
		ie.NewFSEID(cpSEID, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, 0x1000, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.2", "", 0, 0)),
			ie.NewFARID(1), ie.NewURRID(7), ie.NewURRID(9)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
		ie.NewCreateURR(
			ie.NewURRID(7),
			ie.NewMeasurementMethod(0, 1, 0),         // VOLUM
			ie.NewReportingTriggers(0x80|0x01, 0x00), // LIUSA and PERIO
			ie.NewMeasurementPeriod(time.Second),
			ie.NewLinkedURRID(linkedTo),
		),
		quotaURR(9, 1000),
	)
}

// TestALiusaURRIsReportedWithTheURRItLinksTo: LIUSA (8.2.19) makes the link the
// trigger. URR 7 asks for it and links to URR 9; when URR 9's own quota is due
// the group's one report carries URR 7 with it, under the group's UR-SEQN --
// URR 7's own period never fires for it.
func TestALiusaURRIsReportedWithTheURRItLinksTo(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(liusaEstablishment(0x3041, 9)).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("a URR asking for Linked Usage Reporting answered cause %d, want accepted", got)
	}
	rule := ruleCarrying(t, rec.last(), fieldSrcIP, []byte{10, 45, 0, 2})
	// The first reading of each URR is its baseline, not its usage.
	if reports := evaluate(t, c, upFSEID(t, resp)); len(reports) != 0 {
		t.Fatalf("the baseline reading returned %+v, want none", reports)
	}
	rec.counts = map[string][]bess.RuleCount{
		testConfig().Up.Counters: {{ActionID: rule.actionID(), Packets: 10, Octets: 1500}},
	}

	reports := evaluate(t, c, upFSEID(t, resp))
	if len(reports) != 1 {
		t.Fatalf("the LIUSA pair owed %d reports, want the group's one", len(reports))
	}
	r := reports[0]
	// URR 9 is the reason the report is due; URR 7 is the LIUSA half, carried
	// in it rather than reported on its own.
	if r.URRID != 9 || r.Trigger != TriggerVolumeQuota {
		t.Errorf("the report names URR %d with trigger %v, want URR 9 and the volume quota",
			r.URRID, r.Trigger)
	}
	if len(r.Linked) != 1 || r.Linked[0].URRID != 7 {
		t.Fatalf("the report carries %+v linked, want the LIUSA URR 7", r.Linked)
	}
	if got := r.Linked[0].Up; got != (Usage{Packets: 10, Octets: 1500}) {
		t.Errorf("URR 7's linked usage is %+v, want the window's 10 packets and 1500 octets", got)
	}
}

// TestALiusaURRDoesNotReportOnItsOwnTrigger: URR 7's period passes with URR 9,
// the URR it links to, not due -- and nothing is owed, because LIUSA makes the
// link the trigger and not URR 7's own measurement.
func TestALiusaURRDoesNotReportOnItsOwnTrigger(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(liusaEstablishment(0x3042, 9)).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("a URR asking for Linked Usage Reporting answered cause %d, want accepted", got)
	}
	seid := upFSEID(t, resp)
	if reports := evaluate(t, c, seid); len(reports) != 0 {
		t.Fatalf("the baseline reading returned %+v, want none", reports)
	}
	// URR 7's one-second period is past and no traffic reached URR 9's quota.
	reports, err := c.Evaluate(context.Background(), seid, time.Now().Add(2*time.Second))
	if err != nil {
		t.Fatalf("evaluating: %v", err)
	}
	if len(reports) != 0 {
		t.Fatalf("the LIUSA URR reported on its own period: %+v", reports)
	}
}

// TestALiusaURRWithNoLinkIsRefused: LIUSA without a link is a trigger with
// nothing to fire on -- the report the SMF asked to be told about would never
// come -- so it is refused with cause 73 naming what is missing, like the
// link's own refusals.
func TestALiusaURRWithNoLinkIsRefused(t *testing.T) {
	cases := []struct {
		name string
		urr  *ie.IE
		want string // what the refusal must name
	}{
		{"no link at all", ie.NewCreateURR(
			ie.NewURRID(7),
			ie.NewMeasurementMethod(0, 1, 0),
			ie.NewReportingTriggers(0x80|0x01, 0x00), // LIUSA and PERIO
			ie.NewMeasurementPeriod(time.Second)), "Linked Usage Reporting"},
		{"a link naming an unknown URR", ie.NewCreateURR(
			ie.NewURRID(7),
			ie.NewMeasurementMethod(0, 1, 0),
			ie.NewReportingTriggers(0x80|0x01, 0x00), // LIUSA and PERIO
			ie.NewMeasurementPeriod(time.Second),
			ie.NewLinkedURRID(99)), "99"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var logged bytes.Buffer
			rec := &recorder{}
			c := New(testConfig(), rec, slog.New(slog.NewTextHandler(&logged, nil)))
			resp := c.Establish(urrEstablishment(0x3043, 7, tc.urr)).(*message.SessionEstablishmentResponse)
			if got := cause(t, resp); got != ie.CauseRuleCreationModificationFailure {
				t.Fatalf("a LIUSA URR with %s answered cause %d, want 73", tc.name, got)
			}
			if !strings.Contains(logged.String(), tc.want) {
				t.Errorf("the refusal does not name what is missing (%q):\n%s", tc.want, logged.String())
			}
			if len(rec.txns) != 0 {
				t.Error("a refused session wrote to the dataplane")
			}
		})
	}
}

func TestEvaluateReportsThePeriodEvenWithNoTraffic(t *testing.T) {
	// A periodic trigger reports while the URR is measured, traffic or none
	// (5.2.2.3): a session whose usage stopped must still be visible to the SMF
	// -- and a window with nothing in it is what says the traffic stopped.
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	periodic := ie.NewCreateURR(
		ie.NewURRID(7),
		ie.NewMeasurementMethod(0, 1, 0),    // VOLUM
		ie.NewReportingTriggers(0x01, 0x00), // PERIO alone
		ie.NewMeasurementPeriod(time.Second),
	)
	resp := c.Establish(urrEstablishment(0x3032, 7, periodic)).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	// The first reading is the window's base (and no report), so the period
	// below is measured from it: the same instant, a moment later.
	if reports := evaluate(t, c, upFSEID(t, resp)); len(reports) != 0 {
		t.Fatalf("the baseline reading returned %v, want none", reports)
	}
	// The URR's window starts when it is first read, so a moment later the
	// period has passed with nothing counted.
	reports, err := c.Evaluate(context.Background(), upFSEID(t, resp), time.Now().Add(2*time.Second))
	if err != nil {
		t.Fatalf("evaluating: %v", err)
	}
	if len(reports) != 1 || reports[0].Trigger != TriggerPeriod {
		t.Fatalf("evaluation returned %+v, want one periodic report", reports)
	}
	if got := reports[0].Up; got != (Usage{}) {
		t.Errorf("the periodic report carries %+v, want no usage", got)
	}
	if reports[0].Enforcing {
		t.Error("a periodic report with no quota stopped the traffic")
	}
	if reports[0].Duration < time.Second {
		t.Errorf("the report's window is %v, want at least the period", reports[0].Duration)
	}
}

func TestAMeasurementPeriodWithoutThePeriodicTriggerIsInert(t *testing.T) {
	// 7.5.2.4 makes the period conditional on PERIO and forbids nothing else:
	// OMEC's pfcpsim sends one on a volume-threshold URR. It is accepted, and
	// the window it would have set never reports on its own.
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	threshold := ie.NewCreateURR(
		ie.NewURRID(7),
		ie.NewMeasurementMethod(0, 1, 0),    // VOLUM
		ie.NewReportingTriggers(0x02, 0x00), // VOLTH, no PERIO
		ie.NewMeasurementPeriod(time.Second),
		ie.NewVolumeThreshold(0x07, 1<<40, 1<<40, 1<<40),
	)
	resp := c.Establish(urrEstablishment(0x3033, 7, threshold)).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d, want it accepted", got)
	}
	if reports := evaluate(t, c, upFSEID(t, resp)); len(reports) != 0 {
		t.Fatalf("the baseline reading returned %v, want none", reports)
	}
	reports, err := c.Evaluate(context.Background(), upFSEID(t, resp), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("evaluating: %v", err)
	}
	if len(reports) != 0 {
		t.Errorf("a period with no periodic trigger reported %+v, want none", reports)
	}
}

func TestEvaluateWithoutCountersInTheDataplaneSaysSo(t *testing.T) {
	// The graph answers no counters (the Applier has no CounterReader): a URR
	// whose every report would say zero is refused when it is established, and
	// this is the same fact found later -- an error, not silence.
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(urrEstablishment(0x3033, 7, fullURR(7))).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	c.counters = nil
	if _, err := c.Evaluate(context.Background(), upFSEID(t, resp), time.Now()); err == nil {
		t.Error("evaluating against a dataplane with no counters returned no error")
	}
}

// TestAMeasuredPDRThatDropsKeepsItsCounterEntry is the invariant behind the
// counting module: a counter entry exists exactly while the PDR is measured
// (the direction has counters, the PDR names a URR, and it has an ActionId),
// whatever the rule does. `!p.drop` in the entry's bookkeeping is the tempting
// version, and it breaks a session: the entry is written once, erased by the
// first modification that replaces the PDR, and a second modification or the
// deletion then erases a key that is already gone -- which the engine refuses,
// and the session can be neither modified nor deleted afterwards. The fake
// dataplane here refuses an erase-missing exactly as bess does.
func TestAMeasuredPDRThatDropsKeepsItsCounterEntry(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	// A PDR a URR measures that also names a QER, so the SMF can close the
	// gate on it (urrEstablishment has no QER, and a gate no PDR names is not
	// a gate this PDR's rule sees).
	req := message.NewSessionEstablishmentRequest(0, 0, 0x3040, 1, 0,
		ie.NewFSEID(0x3040, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, 0x2000, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.2", "", 0, 0)),
			ie.NewFARID(1), ie.NewQERID(1), ie.NewURRID(7)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
		ie.NewCreateQER(ie.NewQERID(1), ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen)),
		fullURR(7),
	)
	resp := c.Establish(req).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	if n := len(rec.entries); n != 1 {
		t.Fatalf("the establishment wrote %d counter entries, want the one its URR measures", n)
	}

	// The SMF closes the gate: the PDR's rule becomes a drop, and the entry it
	// still needs must not be erased (nothing would put it back, and the
	// deletion would then fail -- below).
	closeGr := message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 2, 0,
		ie.NewUpdateQER(ie.NewQERID(1), ie.NewGateStatus(ie.GateStatusClosed, ie.GateStatusClosed)),
	)
	if got := cause(t, c.Modify(closeGr)); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification that closes the gate answered cause %d", got)
	}
	if n := len(rec.entries); n != 1 {
		t.Errorf("the drop left %d counter entries, want the one the URR still measures", n)
	}
	if got := ruleCarrying(t, rec.last(), fieldSrcIP, []byte{10, 45, 0, 2}).gate(); got != dropGate {
		t.Fatalf("the closed gate's rule gates %d, want the drop gate %d", got, dropGate)
	}

	// A second modification, and then the deletion: both must reach the
	// dataplane. It takes a message that carries the PDR itself to reach the
	// erase at all -- a replaced PDR's old form is what `counterErase` walks --
	// so the two updates below are the shape that used to break the session:
	// the first erases the entry the drop branch no longer wrote, and the
	// second erases a key that is already gone, which the engine refuses (this
	// fake does too, through errEraseMissing).
	updatePDR := func(seq uint32) *message.SessionModificationRequest {
		return message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), seq, 0,
			ie.NewUpdatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
				ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
					ie.NewFTEID(0x01, 0x2000, net.ParseIP("192.0.2.1"), nil, 0),
					ie.NewUEIPAddress(0x02, "10.45.0.2", "", 0, 0)),
				ie.NewFARID(1), ie.NewQERID(1), ie.NewURRID(7)),
			ie.NewUpdateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
				ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
		)
	}
	if got := cause(t, c.Modify(updatePDR(3))); got != ie.CauseRequestAccepted {
		t.Fatalf("the first update of the dropped PDR answered cause %d", got)
	}
	if got := cause(t, c.Modify(updatePDR(4))); got != ie.CauseRequestAccepted {
		t.Fatalf("the second update of the dropped PDR answered cause %d", got)
	}
	if got := cause(t, c.Delete(message.NewSessionDeletionRequest(0, 0, upFSEID(t, resp), 5, 0))); got != ie.CauseRequestAccepted {
		t.Fatalf("the deletion answered cause %d", got)
	}
	if n := len(rec.entries); n != 0 {
		t.Errorf("%d counter entries outlived the session", n)
	}
}

func TestEvaluateTakesTheFirstReadingAsItsBaseline(t *testing.T) {
	// The counting module keeps a rule's cells after its entry is erased (the
	// id pool reissues ActionIds, and a session's deletion erases the entry),
	// so a fresh rule's first reading can hold the totals of the rule that had
	// that id before. A quota spent by another rule's traffic would stop this
	// session's traffic for good, so the first reading is the window's base.
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(urrEstablishment(0x3041, 7, quotaURR(7, 1000))).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	rule := ruleCarrying(t, rec.last(), fieldSrcIP, []byte{10, 45, 0, 2})
	module := testConfig().Up.Counters
	// A million octets the previous holder of this ActionId counted.
	const inherited = 1 << 20
	rec.counts = map[string][]bess.RuleCount{module: {{ActionID: rule.actionID(), Packets: 27100, Octets: inherited}}}

	if reports := evaluate(t, c, upFSEID(t, resp)); len(reports) != 0 {
		t.Fatalf("the first reading reported %+v: the inherited totals are not this URR's usage", reports)
	}
	c.mu.Lock()
	enforcing := c.findByCP(0x3041).URRs[7].enforcing
	c.mu.Unlock()
	if enforcing {
		t.Error("the inherited totals exhausted the quota: the window must start at the first reading")
	}
	if gate := ruleCarrying(t, rec.last(), fieldSrcIP, []byte{10, 45, 0, 2}).gate(); gate == dropGate {
		t.Error("the inherited totals dropped the traffic")
	}

	// What arrives after the baseline is this URR's usage, and the quota is
	// spent by that alone -- the inherited million is not in the window.
	rec.counts = map[string][]bess.RuleCount{module: {{ActionID: rule.actionID(), Packets: 27110, Octets: inherited + 1000}}}
	reports := evaluate(t, c, upFSEID(t, resp))
	if len(reports) != 1 || reports[0].Trigger != TriggerVolumeQuota {
		t.Fatalf("evaluation returned %+v, want one volume-quota report for the 1000 octets measured", reports)
	}
	if got := reports[0].Up; got != (Usage{Packets: 10, Octets: 1000}) {
		t.Errorf("the report carries %+v, want only the 1000 octets since the baseline", got)
	}
	if !reports[0].Enforcing {
		t.Error("the quota the report says is spent did not stop the traffic")
	}
	if gate := ruleCarrying(t, rec.last(), fieldSrcIP, []byte{10, 45, 0, 2}).gate(); gate != dropGate {
		t.Errorf("after the quota was spent the rule gates %d, want the drop gate %d", gate, dropGate)
	}
}

// TestAReportIsAUsageReportTheSMFCanRead checks the octets, not our structs: a
// Report is turned into the IEs of a Session Report Request, marshalled, parsed
// back as an SMF would (message.Parse), and every field the SMF bills from is
// read out of the parsed message.
func TestAReportIsAUsageReportTheSMFCanRead(t *testing.T) {
	report := Report{
		SEID: 0x1234, CPSEID: 0x99, URRID: 7, Trigger: TriggerVolumeQuota, Seqn: 3,
		Up:        Usage{Packets: 10, Octets: 1500},
		Down:      Usage{Packets: 4, Octets: 600},
		Duration:  2 * time.Second,
		Enforcing: true,
	}
	req := message.NewSessionReportRequest(0, 0, report.SEID, 42, 0, report.IEs()...)
	b := make([]byte, req.MarshalLen())
	if err := req.MarshalTo(b); err != nil {
		t.Fatalf("marshalling the session report: %v", err)
	}
	parsed, err := message.Parse(b)
	if err != nil {
		t.Fatalf("parsing the session report: %v", err)
	}
	out, ok := parsed.(*message.SessionReportRequest)
	if !ok {
		t.Fatalf("the report parsed as %s, want a Session Report Request", parsed.MessageTypeName())
	}
	if out.SEID() != report.SEID || out.Sequence() != 42 {
		t.Errorf("the report names SEID %#x seq %d, want %#x and 42", out.SEID(), out.Sequence(), report.SEID)
	}
	// The Report Type says "a usage report": the flag the SMF dispatches on.
	if !out.ReportType.HasUSAR() {
		t.Errorf("the Report Type does not say USAR: %+v", out.ReportType)
	}
	if len(out.UsageReport) != 1 {
		t.Fatalf("the report carries %d usage reports, want one", len(out.UsageReport))
	}
	usage := out.UsageReport[0]
	children, err := usage.UsageReport()
	if err != nil {
		t.Fatalf("the usage report's own IEs: %v", err)
	}
	byType := map[ie.IEType]*ie.IE{}
	for _, child := range children {
		byType[child.Type] = child
	}
	if id, err := byType[ie.URRID].URRID(); err != nil || id != 7 {
		t.Errorf("the usage report names URR %d (%v), want 7", id, err)
	}
	if seqn, err := byType[ie.URSEQN].URSEQN(); err != nil || seqn != 3 {
		t.Errorf("the usage report carries UR-SEQN %d (%v), want 3", seqn, err)
	}
	// The trigger is the report's own bit (8.2.41, Figure 8.2.41-1): VOLQU is
	// octet 6 bit 1, and octet 5 -- where PERIO, VOLTH and the rest sit --
	// stays empty rather than being left out, which would put VOLQU in PERIO's
	// place. The library's accessor reads the IE, as an SMF built on it does.
	flags, err := byType[ie.UsageReportTrigger].UsageReportTrigger()
	if err != nil || len(flags) < 2 || flags[0] != 0 || flags[1]&0x01 == 0 || flags[1]&^0x01 != 0 {
		t.Errorf("the usage report's trigger is %#v (%v), want only VOLQU: octet 5 empty, octet 6 bit 1", flags, err)
	}
	vol, err := byType[ie.VolumeMeasurement].VolumeMeasurement()
	if err != nil {
		t.Fatalf("the volume measurement: %v", err)
	}
	if !vol.HasTOVOL() || !vol.HasULVOL() || !vol.HasDLVOL() || vol.TotalVolume != 2100 ||
		vol.UplinkVolume != 1500 || vol.DownlinkVolume != 600 {
		t.Errorf("the volume measurement is %+v, want 2100 total, 1500 up and 600 down", vol)
	}
	if !vol.HasTONOP() || vol.TotalNumberOfPackets != 14 ||
		vol.UplinkNumberOfPackets != 10 || vol.DownlinkNumberOfPackets != 4 {
		t.Errorf("the packet counts are %+v, want 14 total, 10 up and 4 down", vol)
	}
	if d, err := byType[ie.DurationMeasurement].DurationMeasurement(); err != nil || d != 2*time.Second {
		t.Errorf("the duration measurement is %v (%v), want 2s", d, err)
	}
}

// TestEvaluateAllWalksEverySession is the arm upfd's loop depends on: one call
// reaps what every session's URRs owe, and a session with no URR (or none whose
// limit is reached) adds nothing.
func TestEvaluateAllWalksEverySession(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	withURR := c.Establish(urrEstablishment(0x3050, 7, quotaURR(7, 100))).(*message.SessionEstablishmentResponse)
	plain := c.Establish(establishment(0x3051, "10.45.0.9")).(*message.SessionEstablishmentResponse)
	if got := cause(t, withURR); got != ie.CauseRequestAccepted {
		t.Fatalf("the measured session answered cause %d", got)
	}
	if got := cause(t, plain); got != ie.CauseRequestAccepted {
		t.Fatalf("the plain session answered cause %d", got)
	}
	rule := ruleCarrying(t, rec.last(), fieldSrcIP, []byte{10, 45, 0, 9})
	_ = rule

	// The baseline reading, then the traffic that spends the one URR's quota.
	if reports := c.EvaluateAll(context.Background(), time.Now()); len(reports) != 0 {
		t.Fatalf("the baseline tick returned %+v, want none", reports)
	}
	var measured *pdr
	c.mu.Lock()
	for _, p := range c.findByCP(0x3050).PDRs {
		measured = p
	}
	c.mu.Unlock()
	rec.counts = map[string][]bess.RuleCount{
		testConfig().Up.Counters: {{ActionID: measured.actionID, Packets: 5, Octets: 500}},
	}
	reports := c.EvaluateAll(context.Background(), time.Now())
	if len(reports) != 1 {
		t.Fatalf("the second tick returned %d reports, want the measured session's one", len(reports))
	}
	if reports[0].SEID != upFSEID(t, withURR) || reports[0].URRID != 7 {
		t.Errorf("the tick reported SEID %d URR %d, want the measured session's %d/7",
			reports[0].SEID, reports[0].URRID, upFSEID(t, withURR))
	}
	if reports[0].Trigger != TriggerVolumeQuota || !reports[0].Enforcing {
		t.Errorf("the tick's report is %v (enforcing %v), want the spent volume quota", reports[0].Trigger, reports[0].Enforcing)
	}
	if reports[0].SEID == upFSEID(t, plain) {
		t.Error("the session with no URR was reported")
	}
}

// upSEID is the UP F-SEID an establishment answer carries: the value the SMF
// addresses the session with afterwards. The answer's *header* carries the CP
// F-SEID instead (the identity the SMF knows the session by), so a test that
// wants to modify or delete the session reads this IE, not the header.
func upFSEID(t testing.TB, resp *message.SessionEstablishmentResponse) uint64 {
	t.Helper()
	if resp.UPFSEID == nil {
		t.Fatal("the establishment answer carries no F-SEID IE")
	}
	fields, err := resp.UPFSEID.FSEID()
	if err != nil {
		t.Fatalf("the establishment answer's F-SEID: %v", err)
	}
	return fields.SEID
}

// TestAnswersAreAddressedByTheCPSEID pins the header rule of TS 29.244
// 7.2.2.4.2: a message to the SMF is addressed by the identity *the SMF* has
// for the session -- the CP F-SEID it sent -- while ours travels in the
// establishment answer's F-SEID IE, and is what addresses the session
// afterwards. Reading the header in place of the IE must not work: it is the
// difference between an answer the SMF can match to its session and one it
// cannot, so this test fails if any of the three answers goes back to naming
// our own F-SEID (or, for establishment, stops naming the CP one).
func TestAnswersAreAddressedByTheCPSEID(t *testing.T) {
	const cp = 0x9001
	c := New(testConfig(), &recorder{}, quietLogger())

	resp := c.Establish(establishment(cp, "10.45.0.2")).(*message.SessionEstablishmentResponse)
	if got := resp.Header.SEID; got != cp {
		t.Errorf("the establishment answer names SEID %#x, want the CP F-SEID %#x", got, cp)
	}
	up := upFSEID(t, resp)
	if up == cp {
		t.Fatal("the answer's F-SEID IE repeats the CP F-SEID, so nothing tells them apart")
	}

	mod := c.Modify(message.NewSessionModificationRequest(0, 0, up, 2, 0)).(*message.SessionModificationResponse)
	if got := mod.Header.SEID; got != cp {
		t.Errorf("the modification answer names SEID %#x, want the CP F-SEID %#x", got, cp)
	}
	if got := cause(t, mod); got != ie.CauseRequestAccepted {
		t.Errorf("the modification answered cause %d", got)
	}

	// A modification for a session this UP function does not have has no CP
	// F-SEID to read, so it echoes the SEID the request carried: the SMF still
	// gets an answer it can match to the request it made.
	lost := c.Modify(message.NewSessionModificationRequest(0, 0, 0xfeed, 3, 0)).(*message.SessionModificationResponse)
	if got := lost.Header.SEID; got != 0xfeed {
		t.Errorf("the not-found answer names SEID %#x, want the request's %#x", got, 0xfeed)
	}
	if got := cause(t, lost); got != ie.CauseSessionContextNotFound {
		t.Errorf("the unknown session answered cause %d", got)
	}

	del := c.Delete(message.NewSessionDeletionRequest(0, 0, up, 4, 0)).(*message.SessionDeletionResponse)
	if got := del.Header.SEID; got != cp {
		t.Errorf("the deletion answer names SEID %#x, want the CP F-SEID %#x", got, cp)
	}
}

func TestUnknownSessionIsNotFound(t *testing.T) {
	c := New(testConfig(), &recorder{}, quietLogger())
	resp := c.Modify(message.NewSessionModificationRequest(0, 0, 999, 1, 0)).(*message.SessionModificationResponse)
	if got := cause(t, resp); got != ie.CauseSessionContextNotFound {
		t.Errorf("modifying an unknown session answered cause %d", got)
	}
}

// urrEstablishment is a session with one uplink PDR that names a URR, so a test
// can vary the URR's own IEs.
func urrEstablishment(cpSEID uint64, urrID uint32, urr *ie.IE) *message.SessionEstablishmentRequest {
	return message.NewSessionEstablishmentRequest(0, 0, cpSEID, 1, 0,
		ie.NewFSEID(cpSEID, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, 0x1000, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.2", "", 0, 0)),
			ie.NewFARID(1), ie.NewURRID(urrID)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
		urr,
	)
}

// fullURR is the URR a charging SMF sends: both measurements, the triggers this
// UP implements, a period, and the four limits.
func fullURR(id uint32) *ie.IE {
	return ie.NewCreateURR(
		ie.NewURRID(id),
		ie.NewMeasurementMethod(0, 1, 1),    // VOLUM and DURAT
		ie.NewReportingTriggers(0x07, 0x03), // PERIO|VOLTH|TIMTH, VOLQU|TIMQU
		ie.NewMeasurementPeriod(30*time.Second),
		ie.NewVolumeThreshold(0x01, 1<<20, 0, 0), // TOVOL
		ie.NewTimeThreshold(60*time.Second),
		ie.NewVolumeQuota(0x06, 0, 1<<30, 1<<30), // ULVOL and DLVOL
		ie.NewTimeQuota(3600*time.Second),
	)
}

// sessionOf is the model the compiler holds for a session, for the tests that
// assert on what was read rather than on what was written to the dataplane.
func sessionOf(t *testing.T, c *Compiler, seid uint64) *Session {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.sessions[seid]
	if s == nil {
		t.Fatalf("the compiler holds no session %d", seid)
	}
	return s
}

func TestAURRIsReadIntoTheSession(t *testing.T) {
	// Every IE of the URR the milestone covers is read: the measurement method,
	// the triggers, the period, both thresholds and both quotas, with the
	// fields each of them named.
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(urrEstablishment(0x3001, 7, fullURR(7))).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	u := sessionOf(t, c, upFSEID(t, resp)).URRs[7]
	if u == nil {
		t.Fatal("the session holds no URR 7")
	}
	if !u.volume || !u.duration {
		t.Errorf("the measurement method read as volume=%v duration=%v, want both", u.volume, u.duration)
	}
	if !u.periodic || !u.onVolumeTh || !u.onTimeTh || !u.onVolQuota || !u.onTimeQuota {
		t.Errorf("the triggers read as %+v, want PERIO/VOLTH/TIMTH/VOLQU/TIMQU", u)
	}
	if u.period != 30*time.Second {
		t.Errorf("the measurement period read as %v, want 30s", u.period)
	}
	if !u.volThreshold.hasTotal || u.volThreshold.total != 1<<20 || u.volThreshold.hasUL || u.volThreshold.hasDL {
		t.Errorf("the volume threshold read as %+v, want TOVOL 1MiB alone", u.volThreshold)
	}
	if !u.hasTimeTh || u.timeThreshold != time.Minute {
		t.Errorf("the time threshold read as %v (set %v), want 60s", u.timeThreshold, u.hasTimeTh)
	}
	if u.volQuota.hasTotal || !u.volQuota.hasUL || u.volQuota.ul != 1<<30 || !u.volQuota.hasDL || u.volQuota.dl != 1<<30 {
		t.Errorf("the volume quota read as %+v, want ULVOL and DLVOL of 1GiB", u.volQuota)
	}
	if !u.hasTimeQuota || u.timeQuota != time.Hour {
		t.Errorf("the time quota read as %v (set %v), want 1h", u.timeQuota, u.hasTimeQuota)
	}
	if u.enforcing {
		t.Error("a URR that has never been evaluated is enforcing a quota")
	}
}

func TestAOneOctetReportingTriggersIsRead(t *testing.T) {
	// 8.2.19's octets 6 and 7 are "present only if explicitly specified": an SMF
	// that asks for periodic reporting alone sends one octet. The pinned
	// library's ReportingTriggers() reads that as a malformed IE -- it wants two
	// -- so the compiler reads the IE's payload itself (compile.go, parseURR).
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	urr := ie.NewCreateURR(ie.NewURRID(7),
		ie.NewMeasurementMethod(0, 1, 0), ie.NewReportingTriggers(0x01))
	resp := c.Establish(urrEstablishment(0x3007, 7, urr)).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("a one-octet Reporting Triggers answered cause %d", got)
	}
	u := sessionOf(t, c, upFSEID(t, resp)).URRs[7]
	if !u.periodic || u.onVolumeTh || u.onTimeTh || u.onVolQuota || u.onTimeQuota {
		t.Errorf("the triggers read as %+v, want PERIO alone", u)
	}
}

func TestAURRWithAnUnimplementedFieldIsRefused(t *testing.T) {
	// Each case is a URR a real SMF could send and this UP cannot honour. A
	// silently ignored field would leave the SMF waiting for a report (or
	// reading a measurement) that never comes, so each is a rule failure.
	cases := []struct {
		name string
		urr  *ie.IE
	}{
		{"event measurement", ie.NewCreateURR(
			ie.NewURRID(7), ie.NewMeasurementMethod(1, 0, 0), ie.NewReportingTriggers(0x02, 0x00))},
		{"QUHTI trigger", ie.NewCreateURR(
			ie.NewURRID(7), ie.NewMeasurementMethod(0, 1, 0), ie.NewReportingTriggers(0x02|0x08, 0x00))},
		{"a spare trigger bit", ie.NewCreateURR(
			ie.NewURRID(7), ie.NewMeasurementMethod(0, 1, 0), ie.NewReportingTriggers(0x02, 0x00, 0x00, 0x80))},
		{"no trigger at all", ie.NewCreateURR(
			ie.NewURRID(7), ie.NewMeasurementMethod(0, 1, 0), ie.NewReportingTriggers(0x00, 0x00))},
		{"no measurement method", ie.NewCreateURR(
			ie.NewURRID(7), ie.NewReportingTriggers(0x02, 0x00))},
		{"a monitoring time", ie.NewCreateURR(
			ie.NewURRID(7), ie.NewMeasurementMethod(0, 1, 0), ie.NewReportingTriggers(0x02, 0x00),
			ie.NewMonitoringTime(time.Now()))},
		{"quota holding time", ie.NewCreateURR(
			ie.NewURRID(7), ie.NewMeasurementMethod(0, 1, 0), ie.NewReportingTriggers(0x02, 0x00),
			ie.NewQuotaHoldingTime(10*time.Second))},
		{"measurement information asking for INAM", ie.NewCreateURR(
			ie.NewURRID(7), ie.NewMeasurementMethod(0, 1, 0), ie.NewReportingTriggers(0x02, 0x00),
			ie.NewMeasurementInformation(0x02))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{}
			c := New(testConfig(), rec, quietLogger())
			resp := c.Establish(urrEstablishment(0x3002, 7, tc.urr)).(*message.SessionEstablishmentResponse)
			if got := cause(t, resp); got != ie.CauseRuleCreationModificationFailure {
				t.Errorf("a URR with %s answered cause %d, want a rule failure", tc.name, got)
			}
			if len(rec.txns) != 0 {
				t.Error("a refused session wrote to the dataplane")
			}
		})
	}
}

func TestAPDRNamingAnUnknownQERIsRefused(t *testing.T) {
	// The PDR's QER ID is an association with a rule of the same session
	// (7.5.2.2), like its URR ID: an id the session does not hold means the
	// flow would carry on with no gate and no meter -- enforcement the SMF
	// asked for and would never see.
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	req := establishment(0x5f1c, "10.45.0.7")
	req.CreatePDR[0] = ie.NewCreatePDR(
		ie.NewPDRID(1),
		ie.NewPrecedence(100),
		ie.NewPDI(
			ie.NewSourceInterface(ie.SrcInterfaceAccess),
			testFTEID(0),
			ie.NewUEIPAddress(0x02, "10.45.0.7", "", 0, 0),
		),
		ie.NewFARID(1),
		ie.NewQERID(9),
	)
	resp := c.Establish(req).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a PDR naming an unprovisioned QER answered cause %d, want a rule failure", got)
	}
	if len(rec.txns) != 0 {
		t.Error("a refused session wrote to the dataplane")
	}
}

// TestZeroIsALegalRuleID is finding 19: 0 is a value of every one of the four
// ids (8.2.73's PDR ID, 8.2.74's FAR ID, 8.2.75's BAR ID, 8.2.76's URR ID),
// and what tells an id of 0 from an absent IE is the IE having been read -- the
// flag, not the value. The session below numbers all five rules 0 and must
// serve it; the second half is the other side of the same rule: a PDR that
// named no FAR at all is a missing mandatory IE, not a reference to FAR 0.
func TestZeroIsALegalRuleID(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	req := establishment(0, "10.45.0.7")
	req.CreatePDR[0] = ie.NewCreatePDR(
		ie.NewPDRID(0),
		ie.NewPrecedence(100),
		ie.NewPDI(
			ie.NewSourceInterface(ie.SrcInterfaceAccess),
			testFTEID(0),
			ie.NewUEIPAddress(0x02, "10.45.0.7", "", 0, 0),
		),
		ie.NewFARID(0),
		ie.NewQERID(0),
	)
	req.CreateFAR[0] = ie.NewCreateFAR(
		ie.NewFARID(0),
		ie.NewApplyAction(applyForw),
		ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore)),
	)
	req.CreateQER[0] = ie.NewCreateQER(
		ie.NewQERID(0),
		ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
		ie.NewMBR(1000, 2000),
	)
	resp := c.Establish(req).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("a session whose rules are numbered 0 answered cause %d", got)
	}
	seid := upFSEID(t, resp)
	s := c.sessions[seid]
	if s.PDRs[0] == nil {
		t.Fatal("the session holds no PDR 0")
	}
	// The uplink PDR's FAR is FAR 0's, and its QER is QER 0's: the ids are the
	// SMF's references, and a wrong one would be a rule the SMF did not send.
	if s.PDRs[0].farID != 0 || s.PDRs[0].meterID != s.QERs[0].meterUL {
		t.Errorf("PDR 0 resolved to FAR %d and meter %d, want FAR 0 and QER 0's meter %d",
			s.PDRs[0].farID, s.PDRs[0].meterID, s.QERs[0].meterUL)
	}
	if s.PDRs[0].drop {
		t.Error("the PDR drops although its FAR 0 forwards")
	}

	// A PDR with no FAR ID: Table 7.5.2.2-1 makes it mandatory, and with FAR 0
	// in the session an absent IE must not read as a reference to it.
	rec2 := &recorder{}
	c2 := New(testConfig(), rec2, quietLogger())
	req2 := establishment(0x5f1d, "10.45.0.7")
	req2.CreatePDR[0] = ie.NewCreatePDR(
		ie.NewPDRID(0),
		ie.NewPrecedence(100),
		ie.NewPDI(
			ie.NewSourceInterface(ie.SrcInterfaceAccess),
			testFTEID(0),
			ie.NewUEIPAddress(0x02, "10.45.0.7", "", 0, 0),
		),
		ie.NewQERID(0),
	)
	if got := cause(t, c2.Establish(req2).(*message.SessionEstablishmentResponse)); got != ie.CauseMandatoryIEMissing {
		t.Errorf("a PDR with no FAR ID answered cause %d, want a missing mandatory IE", got)
	}
	if len(rec2.txns) != 0 {
		t.Error("a refused session wrote to the dataplane")
	}
}

func TestARemovedQERsMeterReturnsAtTeardown(t *testing.T) {
	// 7.5.4.6: a Remove QER takes the QER out of the session, and a PDR's QER
	// ID is a reference to it. Here the SMF re-points the PDR first (an Update
	// PDR whose QER ID list leaves it out), and the removal then takes the QER
	// and the meters it was given.
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(establishment(0x5f1e, "10.45.0.7")).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	seid := upFSEID(t, resp)
	meter := c.sessions[seid].QERs[1].meterUL
	if meter == 0 {
		t.Fatal("the QER of the establishment has no uplink meter")
	}

	// The SMF re-points PDR 1 to a gate-only QER and removes QER 1 in one
	// message: the Update PDR's QER ID list replaces the stored one (Table
	// 7.5.4.2-1), and the removal then finds nothing that names QER 1.
	mod := message.NewSessionModificationRequest(0, 0, seid, 3, 0,
		ie.NewUpdatePDR(
			ie.NewPDRID(1),
			ie.NewPrecedence(100),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewUEIPAddress(0x02, "10.45.0.7", "", 0, 0),
			),
			ie.NewFARID(1),
			ie.NewQERID(2),
		),
		ie.NewCreateQER(ie.NewQERID(2), ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen)),
		ie.NewRemoveQER(ie.NewQERID(1)),
	)
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification that re-pointed the PDR answered cause %d", got)
	}
	s := c.sessions[seid]
	if s.QERs[1] != nil {
		t.Error("the removed QER is still in the session")
	}
	if s.PDRs[1].meterID != 0 {
		t.Errorf("the PDR still meters under %d, and the QER that owned it is gone", s.PDRs[1].meterID)
	}

	// A removal of a QER the session never held says nothing and changes
	// nothing: the request is not refused for naming a number that is gone.
	mod = message.NewSessionModificationRequest(0, 0, seid, 4, 0, ie.NewRemoveQER(ie.NewQERID(9)))
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Errorf("removing a QER the session never held answered cause %d", got)
	}

	// The QER's meter is the session's until the session is gone: a
	// modification that is refused puts the QER back, so an id returned at the
	// removal would be one another session could meter with while this one
	// still names it. The deletion is where the pool gets it back, which is
	// what releaseSession does for every id the session holds.
	if c.meters.queued(meter) {
		t.Error("the removed QER's meter was returned to the pool while the session lives")
	}
	del := message.NewSessionDeletionRequest(0, 0, seid, 5, 0)
	if got := cause(t, c.Delete(del)); got != ie.CauseRequestAccepted {
		t.Fatalf("the deletion answered cause %d", got)
	}
	if !c.meters.queued(meter) {
		t.Error("the removed QER's meter was not returned to the pool with the session")
	}
}

// TestRemovingAQERAPDRStillNamesUnlinksIt: TS 29.244 5.4.5 has the CP function
// stop a QER's function "by removing the related QER", and the UP function
// "shall then stop such function consequently". A Remove QER while PDR 1 still
// names the QER is accepted, and the PDR goes on forwarding without the QER's
// meter.
func TestRemovingAQERAPDRStillNamesUnlinksIt(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(establishment(0x5f1f, "10.45.0.8")).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	seid := upFSEID(t, resp)
	meterOf := func() uint32 {
		r := ruleCarrying(t, rec.last(), fieldSrcIP, []byte{10, 45, 0, 8})
		if r.gate() == dropGate {
			t.Error("the PDR's rule drops")
		}
		v, _ := actionFields(t, rec.last(), testConfig().Up, r.actionID())["meter_id"].(uint32)
		return v
	}
	if meterOf() == 0 {
		t.Fatal("the QER's MBR put no meter on the PDR")
	}

	mod := message.NewSessionModificationRequest(0, 0, seid, 2, 0, ie.NewRemoveQER(ie.NewQERID(1)))
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("removing the QER PDR 1 names answered cause %d", got)
	}
	if m := meterOf(); m != 0 {
		t.Errorf("the PDR still meters under %d after its QER was removed", m)
	}
	if s := sessionOf(t, c, seid); s.QERs[1] != nil || len(s.PDRs[1].qerIDs) != 0 {
		t.Errorf("the session holds QER 1 (%v) or PDR 1 still names %v", s.QERs[1] != nil, s.PDRs[1].qerIDs)
	}
}

func TestAPDRNamingAnUnknownURRIsRefused(t *testing.T) {
	// The PDR's URR ID is an association with a rule of the same session: an id
	// the session does not hold means the traffic would be counted by nothing
	// and the report the SMF expects would never arrive.
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(urrEstablishment(0x3003, 9, fullURR(7))).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a PDR naming an unprovisioned URR answered cause %d, want a rule failure", got)
	}
	if len(rec.txns) != 0 {
		t.Error("a refused session wrote to the dataplane")
	}
}

func TestAnUpdateURRReplacesOnlyWhatItNames(t *testing.T) {
	// An Update URR carries the fields that change (7.5.4.4): what it names
	// replaces the value before it, what it leaves out stays. The other half of
	// the same rule is that a new quota lifts the drop a quota exhaustion put
	// on the URR's PDRs, which is how an SMF re-opens the traffic.
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(urrEstablishment(0x3004, 7, fullURR(7))).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	s := sessionOf(t, c, upFSEID(t, resp))
	s.URRs[7].enforcing = true // as the reporter leaves it after a quota exhaustion

	mod := message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 2, 0,
		ie.NewUpdateURR(
			ie.NewURRID(7),
			ie.NewReportingTriggers(0x01),        // PERIO alone
			ie.NewVolumeQuota(0x02, 0, 1<<40, 0), // a new, larger ULVOL
		),
	)
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification answered cause %d", got)
	}
	u := sessionOf(t, c, upFSEID(t, resp)).URRs[7]
	if !u.periodic || u.onVolumeTh || u.onTimeTh || u.onVolQuota || u.onTimeQuota {
		t.Errorf("the triggers read as %+v, want PERIO alone", u)
	}
	if !u.volQuota.hasUL || u.volQuota.ul != 1<<40 || u.volQuota.hasDL {
		t.Errorf("the volume quota read as %+v, want ULVOL 1TiB alone", u.volQuota)
	}
	if !u.hasTimeQuota || u.timeQuota != time.Hour {
		t.Errorf("the time quota read as %v (set %v), want the 1h of the establishment", u.timeQuota, u.hasTimeQuota)
	}
	if !u.volume || !u.duration {
		t.Errorf("the measurement method read as volume=%v duration=%v, want the establishment's both", u.volume, u.duration)
	}
	if u.enforcing {
		t.Error("a new quota did not lift the quota exhaustion's drop")
	}
	if !u.hasTimeTh || u.volThreshold.total != 1<<20 {
		t.Error("the modification dropped a threshold it did not name")
	}
}

func TestRemoveURRAfterAnUpdatePDRDropsIt(t *testing.T) {
	// The SMF takes the URR off the PDR first (an Update PDR whose URR ID list
	// leaves it out), then removes it.
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(urrEstablishment(0x3005, 7, fullURR(7))).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}

	// The Update PDR's URR ID list replaces the stored one (Table 7.5.4.2-1):
	// naming URR 9 alone, the PDR no longer measures by URR 7.
	mod := message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 3, 0,
		ie.NewUpdatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, 0x1000, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.2", "", 0, 0)),
			ie.NewFARID(1), ie.NewURRID(9)),
		fullURR(9),
	)
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the PDR update answered cause %d", got)
	}
	mod = message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 4, 0,
		ie.NewRemoveURR(ie.NewURRID(7)))
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the removal answered cause %d", got)
	}
	if s := sessionOf(t, c, upFSEID(t, resp)); s.URRs[7] != nil {
		t.Error("the session still holds the removed URR")
	}
}

// TestARemoveURROfALinkedToURRIsRefused: a URR another URR links to (8.2.55) is
// not removed while that link stands -- the group's report would be short a URR
// -- refused with cause 73 the way a PDR still naming a URR is, and the URR
// stays in the session.
func TestARemoveURROfALinkedToURRIsRefused(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	// Only URR 9 is measured by the PDR; URR 7 exists so URR 9 can link to it
	// (5.2.2.2.1: a URR may be provisioned without a PDR). Removing URR 7 is
	// then refused for the link alone, not for a PDR still naming it.
	linkedTo := ie.NewCreateURR(
		ie.NewURRID(9),
		ie.NewMeasurementMethod(0, 1, 0),     // VOLUM
		ie.NewReportingTriggers(0x00, 0x01),  // VOLQU
		ie.NewVolumeQuota(0x01, 1<<40, 0, 0), // a quota URR 9 will not spend
		ie.NewLinkedURRID(7),
	)
	est := message.NewSessionEstablishmentRequest(0, 0, 0x3035, 1, 0,
		ie.NewFSEID(0x3035, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, 0x1000, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.2", "", 0, 0)),
			ie.NewFARID(1), ie.NewURRID(9)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
		quotaURR(7, 1000),
		linkedTo,
	)
	resp := c.Establish(est).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	mod := message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 2, 0,
		ie.NewRemoveURR(ie.NewURRID(7)))
	if got := cause(t, c.Modify(mod)); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("removing a URR another URR links to answered cause %d, want a rule failure", got)
	}
	if s := sessionOf(t, c, upFSEID(t, resp)); s.URRs[7] == nil {
		t.Fatal("the refused removal took the linked-to URR out of the model")
	}
}

func TestAnUpdateURRForAMissingURRIsRefused(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(establishment(0x3006, "10.45.0.2")).(*message.SessionEstablishmentResponse)
	mod := message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 2, 0,
		ie.NewUpdateURR(ie.NewURRID(4), ie.NewMeasurementMethod(0, 1, 0), ie.NewReportingTriggers(0x02)))
	if got := cause(t, c.Modify(mod)); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("an Update URR for a URR the session does not hold answered cause %d, want a rule failure", got)
	}
}

// A mask in the wrong field would match the wrong traffic, so every rule's key
// is checked here: exact fields carry an all-ones mask, wildcarded ones carry
// zero, and a value under a zero mask is zero.
func TestRuleKeysAreCanonical(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	c.Establish(establishment(0x9999, "10.45.0.10"))

	tables := map[string][]Field{
		testConfig().Up.PDRTable:   testConfig().Up.PDRFields,
		testConfig().Down.PDRTable: testConfig().Down.PDRFields,
	}
	rs := rules(rec.last())
	if len(rs) != 2 {
		t.Fatalf("%d rules, want 2", len(rs))
	}
	for _, r := range rs {
		fields := tables[strings.TrimSuffix(r.change.Resource, "/rules")]
		if len(r.values) != len(fields) {
			t.Fatalf("%s carries %d key fields, want %d", r.change.Resource, len(r.values), len(fields))
		}
		for i := range fields {
			mask, value := r.mask(i), r.value(i)
			if len(mask) != fields[i].width() || len(value) != fields[i].width() {
				t.Errorf("field %v has %d mask and %d value bytes, want %d",
					fields[i], len(mask), len(value), fields[i].width())
				continue
			}
			for j := range mask {
				if mask[j] != 0 && mask[j] != 0xff {
					t.Errorf("field %v byte %d: mask %#x is neither exact nor wildcard",
						fields[i], j, mask[j])
				}
				if mask[j] == 0 && value[j] != 0 {
					t.Errorf("field %v byte %d: value %#x under a zero mask is not canonical",
						fields[i], j, value[j])
				}
			}
		}
	}
}

// TestAPDIsDestinationAndTheSDFsMustAgree: for an Access PDR the SMF's filter
// is swapped (5.2.1A.2A), so its source is the side the packet's destination
// carries -- and a PDI whose UE IP address IE (8.2.62 bit 3) says its address
// is the destination names the same field. When the two agree (the prefix
// contains the address), the tighter of them, the address, is the field; when
// the filter names a source outside it, the SMF described a packet the rule
// cannot carry, and the session is refused rather than compiled from one of the
// two readings.
func TestAPDIsDestinationAndTheSDFsMustAgree(t *testing.T) {
	establish := func(sdf string) message.Message {
		t.Helper()
		c := New(testConfig(), &recorder{}, quietLogger())
		req := message.NewSessionEstablishmentRequest(0, 0, 0x5564, 1, 0,
			ie.NewFSEID(0x5564, nil, nil),
			ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
				ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
					ie.NewFTEID(0x01, 0x55667788, net.ParseIP("192.0.2.1"), nil, 0),
					// V4 | S/D: the address is the packet's destination.
					ie.NewUEIPAddress(0x06, "192.0.2.9", "", 0, 0),
					ie.NewSDFFilter(sdf, "", "", "", 0)),
				ie.NewFARID(1)),
			ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
				ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
		)
		return c.Establish(req)
	}
	if got := cause(t, establish("permit out udp from 192.0.2.9 67 to any")); got != ie.CauseRequestAccepted {
		t.Errorf("a filter naming the PDI's destination answered cause %d, want accepted", got)
	}
	if got := cause(t, establish("permit out udp from 198.51.100.1 67 to any")); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a filter naming another destination answered cause %d, want a rule failure", got)
	}
}

// TestAFARThatAsksForL7WorkIsRefused: Header Enrichment (8.2.67), Redirect
// Information (8.2.20) and Proxying (8.2.97) instruct the UP to write into the
// subscriber's traffic. Nothing here reads L7, and forwarding as if the IEs were
// absent would leave the SMF believing an instruction was applied.
func TestAFARThatAsksForL7WorkIsRefused(t *testing.T) {
	cases := []struct {
		name string
		ie   *ie.IE
	}{
		{"header enrichment", ie.NewHeaderEnrichment(0, "X-UPF", "1")},
		{"redirect", ie.NewRedirectInformation(2, "http://example.invalid/")},
		{"proxying", ie.NewProxying(0, 0)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{}
			c := New(testConfig(), rec, quietLogger())
			req := message.NewSessionEstablishmentRequest(0, 0, 0x5566, 1, 0,
				ie.NewFSEID(0x5566, nil, nil),
				ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
					ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
						ie.NewFTEID(0x01, 0x55667788, net.ParseIP("192.0.2.1"), nil, 0),
						ie.NewUEIPAddress(0x02, "10.45.0.2", "", 0, 0)),
					ie.NewFARID(1)),
				ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
					ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore), tc.ie)),
			)
			if got := cause(t, c.Establish(req)); got != ie.CauseRuleCreationModificationFailure {
				t.Errorf("a FAR carrying %s answered cause %d, want a rule failure", tc.name, got)
			}
			if len(rec.txns) != 0 {
				t.Error("a refused session wrote to the dataplane")
			}
		})
	}
}

// TestAFARThatAsksToDuplicateIsRefused: Apply Action's DUPL (8.2.26 bit 5)
// names a second forwarding FAR, and no chain here branches one packet to two
// actions.
func TestAFARThatAsksToDuplicateIsRefused(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	req := message.NewSessionEstablishmentRequest(0, 0, 0x5567, 1, 0,
		ie.NewFSEID(0x5567, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, 0x55667788, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.2", "", 0, 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw|applyDUPL),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
	)
	if got := cause(t, c.Establish(req)); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a FAR asking to duplicate answered cause %d, want a rule failure", got)
	}
	if len(rec.txns) != 0 {
		t.Error("a refused session wrote to the dataplane")
	}
}

// A dual-stack F-TEID is two admission keys but one tunnel: both keys carry the
// PDR's one context id, so its rules multiply by SDF and QFI only.
func TestDualStackFTEIDIsOneContextNotTwoRuleSets(t *testing.T) {
	p := &pdr{
		teid: 0x77, fteidContext: 5,
		endpointID: 17, endpointIPv4: netip.MustParseAddr("192.0.2.17"),
		endpointIPv6:     netip.MustParseAddr("2001:4860::17"),
		endpointFamilies: []uint8{4, 6}, qfis: []uint8{1, 9},
		sdfs: []*sdfFilter{{proto: 17, protoOK: true}, {proto: 6, protoOK: true}},
	}
	keys, err := p.ruleKeys([]Field{FTEIDContext, Proto, QFI})
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 4 {
		t.Fatalf("compiled %d keys, want 2 SDFs × 2 QFIs", len(keys))
	}
	for _, key := range keys {
		values, _ := key["values"].([]map[string]any)
		if got := values[0]["value_bin"].([]byte); !bytes.Equal(got, []byte{0, 0, 0, 5}) {
			t.Errorf("rule keys context %v, want the PDR's context 5", got)
		}
	}
}
