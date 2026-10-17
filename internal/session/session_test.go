// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/bess"
)

// recorder is an Applier that keeps every transaction, so a test can read what
// the compiler would have written to bessd.
type recorder struct {
	txns [][]bess.Change
	fail error
}

func (r *recorder) Apply(_ context.Context, changes ...bess.Change) error {
	if r.fail != nil {
		return r.fail
	}
	r.txns = append(r.txns, changes)
	return nil
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

type rule struct {
	change bess.Change
	values []map[string]any
	masks  []map[string]any
}

// mask is the mask of the rule's field at index i.
func (r rule) mask(i int) []byte { b, _ := r.masks[i]["value_bin"].([]byte); return b }

// value is the value of the rule's field at index i.
func (r rule) value(i int) []byte { b, _ := r.values[i]["value_bin"].([]byte); return b }

// actionID is the ActionId the rule delivers.
func (r rule) actionID() uint32 { v, _ := r.change.Value["action_id"].(uint32); return v }

// gate is the gate the rule delivers.
func (r rule) gate() uint64 { v, _ := r.change.Value["gate"].(uint64); return v }

// actionsErased is the action records a transaction takes out: a change with no
// value, which is what an erase is.
func actionsErased(changes []bess.Change) []bess.Change {
	var out []bess.Change
	for _, ch := range changes {
		if ch.Value == nil && strings.HasSuffix(ch.Resource, "/actions") {
			out = append(out, ch)
		}
	}
	return out
}

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

// teidRule is the change carrying a session's TEID rule, or false: the rule's
// key holds the TEID in one field, values and masks in two lists.
func teidRule(changes []bess.Change, resource string, teid uint32) (bess.Change, bool) {
	want := []byte{byte(teid >> 24), byte(teid >> 16), byte(teid >> 8), byte(teid)}
	for _, c := range changes {
		if c.Resource != resource {
			continue
		}
		values, _ := c.Key["values"].([]map[string]any)
		if len(values) != 1 {
			continue
		}
		if b, _ := values[0]["value_bin"].([]byte); bytes.Equal(b, want) {
			return c, true
		}
	}
	return bess.Change{}, false
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
		// Both tables match the inner IPv4 packet, as deploy/session-live.yaml
		// declares them: one table per direction, because a rule names an
		// ActionId and a table declares one actions resource.
		Up: Direction{
			PDRTable:  "pdr_ul",
			PDRFields: []Field{SrcIP, DstIP, Proto, SrcPort, DstPort},
			Actions:   "at_ul",
			Meters:    "mt_ul",
			NextHop:   1,
		},
		Down: Direction{
			PDRTable:  "pdr_dl",
			PDRFields: []Field{SrcIP, DstIP, Proto, SrcPort, DstPort},
			Actions:   "at_dl",
			Meters:    "mt_dl",
			// The access-side route: the downlink's chain holds an ActionTable
			// too, and a chain whose action names no next hop is a chain the
			// module fails closed on (deploy/session-path.yaml routes it to the
			// encap through this hop).
			NextHop: 2,
			Tunnels: "enc",
		},
		// The F-TEID match, as deploy/smoke-gtpu.yaml wires it: the rule table
		// in front of the decap, one rule per TEID.
		TEIDTable: "teid",
		TEIDGate:  0,
		N3Addr:    netip.MustParseAddr("192.0.2.1"),
		N3MAC:     [6]byte{2, 0, 0, 0, 0, 1},
		PeerMAC:   [6]byte{2, 0, 0, 0, 0, 2},
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
// leaves the choice to the UPF (what a conformant SMF does while FTUP is not
// advertised), and a value pins it.
func establishmentWithFTEID(cpSEID uint64, ueIP string, fteid uint32) *message.SessionEstablishmentRequest {
	return message.NewSessionEstablishmentRequest(0, 0, cpSEID, 1, 0,
		ie.NewNodeID("", "", "smf"),
		ie.NewFSEID(cpSEID, nil, nil),
		ie.NewCreatePDR(
			ie.NewPDRID(1),
			ie.NewPrecedence(100),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, fteid, net.ParseIP("192.0.2.1"), nil, 0),
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
				ie.NewUEIPAddress(0x02, ueIP, "", 0, 0),
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
	del := c.Delete(message.NewSessionDeletionRequest(0, 0, resp.Header.SEID, 2, 0)).(*message.SessionDeletionResponse)
	if got := cause(t, del); got != ie.CauseRequestAccepted {
		t.Fatalf("the deletion answered cause %d", got)
	}
	meters, teidRules := 0, 0
	for _, ch := range rec.last() {
		if strings.HasSuffix(ch.Resource, "/meters") {
			meters++
		}
		if ch.Resource == testConfig().TEIDTable+"/rules" {
			teidRules++
		}
	}
	if meters != 2 {
		t.Errorf("the deletion erases %d meter records, want the QER's two (one per policed direction)", meters)
	}
	if teidRules != 1 {
		t.Errorf("the deletion erases %d TEID rules, want one (two uplink PDRs share the F-TEID)", teidRules)
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
				ie.NewFTEID(0x01, fteid, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, ueIP, "", 0, 0),
				ie.NewSDFFilter("permit out udp from any 1000 to any", "", "", "", 0)),
			ie.NewFARID(1), ie.NewQERID(1)),
		ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(20),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, fteid, net.ParseIP("192.0.2.1"), nil, 0),
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

// A closed gate is not a slow path: the compiler writes the rule's own gate as
// the drop gate and gives it no action, so the packet is dropped where the
// session's state says it must be, without a lookup into the action table.
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
	// session's TEID rule and the uplink meter it is policed by are all its.
	mod := message.NewSessionModificationRequest(0, 0, resp.Header.SEID, 2, 0,
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
	if _, ok := teidRule(onlyErases(erases), testConfig().TEIDTable+"/rules", 0x22222222); !ok {
		t.Error("the removed PDR's TEID rule is still programmed")
	}
	if n := len(actionsErased(erases)); n != 1 {
		t.Errorf("%d action records erased, want the removed PDR's one", n)
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
	// its meter, and any TEID rule no one else used, programmed for good.
	del := c.Delete(message.NewSessionDeletionRequest(0, 0, resp.Header.SEID, 3, 0)).(*message.SessionDeletionResponse)
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
	// them removed. Its own records go; the TEID rule and the meter belong to
	// the PDR that stays, and erasing them would leave that PDR unpoliced and
	// its packets dropped at the decap's default gate.
	rec = &recorder{}
	c = New(testConfig(), rec, quietLogger())
	resp = c.Establish(sharedFTEIDEstablishment(0x7771, "10.45.0.7", 0x33333333)).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	mod = message.NewSessionModificationRequest(0, 0, resp.Header.SEID, 2, 0,
		ie.NewRemovePDR(ie.NewPDRID(2)),
	)
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification answered cause %d", got)
	}
	erases = rec.last()
	if _, ok := teidRule(onlyErases(erases), testConfig().TEIDTable+"/rules", 0x33333333); ok {
		t.Error("the removal erased a TEID rule the surviving PDR still needs")
	}
	if n := len(metersErased(erases)); n != 0 {
		t.Errorf("%d meter records erased, want none: the surviving PDR uses the meter", n)
	}
	if n := len(actionsErased(erases)); n != 1 {
		t.Errorf("%d action records erased, want the removed PDR's one", n)
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
	// A pin released before the walk reaches it is queued, and the value is
	// still ahead of the walk -- so both paths can offer it. The walk must skip
	// an id that is queued, or one id is handed to two sessions: once here, once
	// from the free list.
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
				ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to 10.10.0.0/16 1000", "", "", "", 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw)),
	)
	resp := c.Establish(req).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	old := ruleCarrying(t, rec.last(), fieldDstIP, []byte{10, 10, 0, 0})
	actionID := old.change.Value["action_id"]
	if actionID == nil || actionID == uint32(0) {
		t.Fatalf("the establishment gave the PDR no action (%v)", actionID)
	}

	mod := message.NewSessionModificationRequest(0, 0, resp.Header.SEID, 2, 0,
		ie.NewUpdatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0),
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
	if got := written.change.Value["action_id"]; got != actionID {
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
				ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to 10.10.0.0/16 1000", "", "", "", 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw)),
	)
	resp := c.Establish(req).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}

	rec.fail = &bess.RejectedError{}
	mod := message.NewSessionModificationRequest(0, 0, resp.Header.SEID, 2, 0,
		ie.NewUpdatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to 10.20.0.0/16 1000", "", "", "", 0)),
			ie.NewFARID(1)),
	)
	if got := cause(t, c.Modify(mod)); got == ie.CauseRequestAccepted {
		t.Fatal("a refused modification was answered as accepted")
	}
	rec.fail = nil

	del := c.Delete(message.NewSessionDeletionRequest(0, 0, resp.Header.SEID, 3, 0)).(*message.SessionDeletionResponse)
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
				ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to 10.10.0.0/16 1000", "", "", "", 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw)),
	)
	resp := c.Establish(req).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	actionID := ruleCarrying(t, rec.last(), fieldDstIP, []byte{10, 10, 0, 0}).change.Value["action_id"]

	mod := message.NewSessionModificationRequest(0, 0, resp.Header.SEID, 2, 0,
		ie.NewUpdatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to 10.10.0.0/16 1000", "", "", "", 0)),
			ie.NewFARID(2)),
		ie.NewCreateFAR(ie.NewFARID(2), ie.NewApplyAction(applyForw)),
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
	if got := written.change.Value["action_id"]; got != actionID {
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
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw)),
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
		teid = fields.TEID
	}
	if teid == 0 {
		t.Error("the answer carries no allocated TEID")
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

func TestUplinkPDIsWithOneCHOOSEIDShareOneFTEID(t *testing.T) {
	// TS 29.244 8.2.3: with the CHID flag set, the UP function "shall assign
	// the same F-TEID to the PDRs requested to be created ... with the same
	// CHOOSE ID value". Two uplink PDIs that are two filters on one tunnel are
	// the shape that asks for it, and without the CHOOSE ID each would get a
	// TEID of its own: the answer names one TEID in both Created PDRs, and the
	// transaction writes one TEID rule -- which is also what the engine takes,
	// since it rejects a second operation on one (resource, key).
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
	teids := 0
	for _, ch := range changes {
		if ch.Resource == testConfig().TEIDTable+"/rules" {
			teids++
		}
	}
	if teids != 1 {
		t.Errorf("the transaction writes %d TEID rules, want one for the group", teids)
	}
	if _, ok := teidRule(changes, testConfig().TEIDTable+"/rules", one); !ok {
		t.Errorf("the transaction writes no TEID rule for %#x, the TEID it answered with", one)
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
		if _, ok := teidRule(changes, testConfig().TEIDTable+"/rules", teid); !ok {
			t.Errorf("the transaction writes no TEID rule for %#x", teid)
		}
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

	mod := message.NewSessionModificationRequest(0, 0, resp.Header.SEID, 2, 0,
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

func TestACHOOSEIDsFTEIDIsLetGoWithItsLastPDI(t *testing.T) {
	// The session holds an F-TEID per group while a PDR of that group is live.
	// Once the last one is gone the TEID is back in the pool, and a PDI created
	// later with the same CHOOSE ID must not be handed it from a stale
	// grouping: the pool may have given the value to another session by then,
	// and two sessions naming one TEID rule is two sessions' uplink landing in
	// whichever wrote it last.
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(chidEstablishment(0x9995, "10.45.0.9", 9, 9)).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	gone := createdTEID(t, resp.CreatedPDR, 1)

	mod := message.NewSessionModificationRequest(0, 0, resp.Header.SEID, 2, 0,
		ie.NewRemovePDR(ie.NewPDRID(1)), ie.NewRemovePDR(ie.NewPDRID(2)))
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the removal answered cause %d", got)
	}

	mod = message.NewSessionModificationRequest(0, 0, resp.Header.SEID, 3, 0,
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

func TestACHOOSEForIPv6IsRefused(t *testing.T) {
	// 8.2.3: with the CH bit set, "the UP function shall assign an F-TEID with
	// an IP4 or an IPv6 address if the V4 or V6 bit is set respectively". A
	// request with V6 alone is therefore for an IPv6 F-TEID, and this UP's N3
	// address is IPv4: answering with an IPv4 one would hand the SMF a family
	// it did not ask for. IPv6 has no form anywhere else in this tree either
	// (docs/compliance.md), so it is refused, with a rule failure the SMF can
	// act on -- not an accepted session it cannot use.
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	req := message.NewSessionEstablishmentRequest(0, 0, 0x9996, 1, 0,
		ie.NewFSEID(0x9996, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x06, 0, nil, nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw)),
	)
	if got := cause(t, c.Establish(req)); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("an IPv6 CHOOSE request answered cause %d, want a rule failure", got)
	}
	if len(rec.txns) != 0 {
		t.Error("a refused session wrote to the dataplane")
	}
}

func TestACHOOSEForBothFamiliesGetsTheIPv4FTEID(t *testing.T) {
	// The other shapes 8.2.3 allows, and the one it does not: V4 alone is what
	// an SMF sends, V4|V6 asks for an address of either family ("if the V4 or
	// V6 bit is set"), and a CH bit with no family at all names none -- a shape
	// the section forbids and no SMF sends, kept lenient because nothing about
	// it asks for an address this UP does not have. All three are answered with
	// the IPv4 N3 address the UPF has.
	for _, flags := range []uint8{0x05, 0x07, 0x04} {
		rec := &recorder{}
		c := New(testConfig(), rec, quietLogger())
		req := message.NewSessionEstablishmentRequest(0, 0, 0x9997, 1, 0,
			ie.NewFSEID(0x9997, nil, nil),
			ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
				ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
					ie.NewFTEID(flags, 0, nil, nil, 0),
					ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0)),
				ie.NewFARID(1)),
			ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw)),
		)
		resp := c.Establish(req).(*message.SessionEstablishmentResponse)
		if got := cause(t, resp); got != ie.CauseRequestAccepted {
			t.Errorf("a CHOOSE request with flags %#x answered cause %d", flags, got)
			continue
		}
		if teid := createdTEID(t, resp.CreatedPDR, 1); teid == 0 {
			t.Errorf("a CHOOSE request with flags %#x carries no allocated TEID", flags)
		}
	}
}

func TestTwoUplinkPDRsWithOneFilterAreRefused(t *testing.T) {
	// An SMF with several QoS flows programs several uplink PDRs onto one F-TEID
	// and tells them apart only by QFI. This UP does not read QFI
	// (docs/compliance.md), so those PDRs are one rule key, and the session is
	// refused with a rule failure: the SMF can then fix it, where a PDR that
	// exists and matches nothing would have looked like a working session.
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
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw)),
	)
	if got := cause(t, c.Establish(req)); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("two PDRs with one filter answered cause %d, want a rule failure", got)
	}
	if len(rec.txns) != 0 {
		t.Error("a refused session wrote to the dataplane")
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
	// The action_id the compiler writes for a drop is a uint32 zero; a check
	// against a value of another type would pass whatever the field held.
	if got, ok := r.change.Value["action_id"].(uint32); !ok || got != 0 {
		t.Errorf("a closed gate's rule names action %v (%T), want none", got, r.change.Value["action_id"])
	}
	// The resource is the compiler's own name for the uplink's actions: a
	// literal here would keep passing if the config named the table otherwise.
	actions := actionsRes(c.cfg.Up)
	for _, ch := range rec.last() {
		if ch.Resource == actions {
			t.Errorf("a closed gate wrote an action record in %s", actions)
		}
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

	// The TEID is what makes an uplink G-PDU ours: a rule of the table in
	// front of the decap, holding the TEID itself.
	rule, ok := teidRule(changes, testConfig().TEIDTable+"/rules", fteid.TEID)
	if !ok {
		t.Fatalf("no TEID rule for %#x among %d changes", fteid.TEID, len(changes))
	}
	if got := rule.Value["gate"]; got != uint64(testConfig().TEIDGate) {
		t.Errorf("the TEID rule delivers on gate %v, want the decap's", got)
	}
	masks, _ := rule.Key["masks"].([]map[string]any)
	mask, _ := masks[0]["value_bin"].([]byte)
	if !bytes.Equal(mask, []byte{0xff, 0xff, 0xff, 0xff}) {
		t.Errorf("the TEID rule's mask is %v, want all ones", mask)
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
	ulAction := find(t, changes, testConfig().Up.Actions+"/actions", "id", ul.actionID())
	if got := ulAction.Value["next_hop_id"]; got != uint32(1) {
		t.Errorf("the uplink action's next hop is %v, want the N6 next hop", got)
	}
	if got := ulAction.Value["meter_id"]; got == uint32(0) {
		t.Error("a PDR whose QER has an MBR must name its meter")
	}
	dlAction := find(t, changes, testConfig().Down.Actions+"/actions", "id", dl.actionID())
	if got := dlAction.Value["next_hop_id"]; got != uint32(2) {
		t.Errorf("the downlink action's next hop is %v, want the access side's (2)", got)
	}

	// The downlink FAR's tunnel is keyed by the same ActionId the rule carries.
	tunnel := find(t, changes, testConfig().Down.Tunnels+"/tunnels", "action_id", dl.actionID())
	if got := tunnel.Value["teid"]; got != uint32(0x11223344) {
		t.Errorf("the tunnel's TEID is %v, want the FAR's", got)
	}
	if got := tunnel.Value["gnb_ip"]; got != "10.20.30.2" {
		t.Errorf("the tunnel's peer is %v, want the FAR's", got)
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
	if first.Header.SEID != again.Header.SEID {
		t.Errorf("the retransmission got SEID %d, the first answered %d",
			again.Header.SEID, first.Header.SEID)
	}
	if len(rec.txns) != 1 {
		t.Errorf("%d transactions for one session, want 1", len(rec.txns))
	}
}

func TestDeleteRemovesWhatTheSessionProgrammed(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(establishment(0x3333, "10.45.0.4")).(*message.SessionEstablishmentResponse)

	del := c.Delete(message.NewSessionDeletionRequest(0, 0, resp.Header.SEID, 2, 0)).(*message.SessionDeletionResponse)
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
	// them behind is state the dataplane keeps for a session that is gone.
	est := rec.txns[0]
	for _, resource := range []string{testConfig().Up.Actions + "/actions",
		testConfig().Down.Actions + "/actions"} {
		for _, ch := range est {
			if ch.Resource != resource {
				continue
			}
			if _, ok := find0(rec.last(), resource, "id", ch.Key["id"]); !ok {
				t.Errorf("the deletion leaves %s id %v behind", resource, ch.Key["id"])
			}
		}
	}
	for _, ch := range est {
		if ch.Resource != testConfig().TEIDTable+"/rules" {
			continue
		}
		masks, _ := ch.Key["masks"].([]map[string]any)
		mask, _ := masks[0]["value_bin"].([]byte)
		values, _ := ch.Key["values"].([]map[string]any)
		value, _ := values[0]["value_bin"].([]byte)
		if len(mask) != 4 || len(value) != 4 {
			t.Fatalf("the TEID rule's key is not four bytes: %v / %v", value, mask)
		}
		teid := uint32(value[0])<<24 | uint32(value[1])<<16 | uint32(value[2])<<8 | uint32(value[3])
		if _, ok := teidRule(rec.last(), testConfig().TEIDTable+"/rules", teid); !ok {
			t.Errorf("the deletion leaves the TEID rule for %#x behind", teid)
		}
	}
	if len(rules(rec.last())) != 2 {
		t.Error("the deletion does not remove both rules")
	}

	// A retransmitted deletion is not an error and writes nothing.
	again := c.Delete(message.NewSessionDeletionRequest(0, 0, resp.Header.SEID, 3, 0)).(*message.SessionDeletionResponse)
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
				ie.NewUEIPAddress(0x02, "10.45.0.5", "", 0, 0)),
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
	if _, ok := find0(rec.last(), testConfig().Down.Actions+"/actions", "id", uint32(1)); ok {
		t.Error("a DROP FAR wrote an action record")
	}
}

func TestPortRangeIsRefusedNotMatchedTooWidely(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	req := message.NewSessionEstablishmentRequest(0, 0, 0x5555, 1, 0,
		ie.NewFSEID(0x5555, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to assigned 1000-2000", "", "", "", 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw)),
	)
	if got := cause(t, c.Establish(req)); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a port range answered cause %d, want a rule failure", got)
	}
	if len(rec.txns) != 0 {
		t.Error("a refused session wrote to the dataplane")
	}
}

func TestAnSDFPrefixIsAPrefixNotAnAddress(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	req := message.NewSessionEstablishmentRequest(0, 0, 0x5556, 1, 0,
		ie.NewFSEID(0x5556, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to 10.10.0.0/16", "", "", "", 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw)),
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
	req = message.NewSessionEstablishmentRequest(0, 0, 0x5557, 1, 0,
		ie.NewFSEID(0x5557, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to 10.10.1.5/16", "", "", "", 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw)),
	)
	if got := cause(t, c.Establish(req)); got != ie.CauseRequestAccepted {
		t.Fatalf("a filter with host bits answered cause %d", got)
	}
	sloppy := ruleCarrying(t, rec.last(), fieldDstIP, []byte{10, 10, 0, 0})
	if got := sloppy.value(fieldDstIP); !bytes.Equal(got, []byte{10, 10, 0, 0}) {
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
				ie.NewUEIPAddress(0x02, "10.45.0.7", "", 0, 0)),
			ie.NewFARID(1)),
		ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(20),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewUEIPAddress(0x12, "", "", 0, 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw)),
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
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw)),
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
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw)),
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
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw)),
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
	// session is refused, which is what the IPv6 gap in docs/compliance.md
	// means for a PDI that names one.
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	req := message.NewSessionEstablishmentRequest(0, 0, 0x5558, 1, 0,
		ie.NewFSEID(0x5558, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to 2001:db8::/32 53", "", "", "", 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw)),
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

	// Session 2 leaves the choice to the UPF, and must not be handed the
	// pinned value: two sessions sharing a TEID rule send each other's packets.
	for i := 0; i < 6; i++ {
		resp := c.Establish(establishment(0x9300+uint64(i), "10.45.0.20")).(*message.SessionEstablishmentResponse)
		if got := cause(t, resp); got != ie.CauseRequestAccepted {
			t.Fatalf("establishment %d answered cause %d", i, got)
		}
		if got := reportedTEID(t, resp); got == pinned {
			t.Fatalf("the allocator handed out the pinned F-TEID %#x", pinned)
		}
	}

	// A second session pinning what the first pinioned is refused: the SMF is
	// told the resource is not available, not given a shared rule.
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
				ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0),
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
				ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0),
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

	// PDR 1 is fine and takes the id (its PDI is an access one with an F-TEID
	// of zero: the UPF chooses, which is where the allocator runs); PDR 2's SDF
	// names an IPv6 prefix, which the table cannot carry, so the whole session
	// is refused.
	bad := message.NewSessionEstablishmentRequest(0, 0, 0x5562, 1, 0,
		ie.NewNodeID("", "", "smf"),
		ie.NewFSEID(0x5562, nil, nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, 0, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0)),
			ie.NewFARID(1)),
		ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(20),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x02, "10.45.0.6", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to 2001:db8::/32 53", "", "", "", 0)),
			ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore))),
	)
	if got := cause(t, c.Establish(bad)); got != ie.CauseRuleCreationModificationFailure {
		t.Fatalf("the inexpressible PDI answered cause %d", got)
	}
	// With the id back the space still has one; without it, the answer here is
	// cause 75.
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
	// The id the refused session allocated is back: a new session gets it.
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

// releaseSession frees a session's ids, and the TEID mapping only if it names
// this session -- the property a refused session's rollback rests on. The
// mapping is written in merge, under merge's lock, so the state below cannot be
// reached today; it is built here directly to pin the contract, because the
// release is what a refusal and a deletion share.
func TestReleasingARefusedSessionLeavesAnotherHoldersTEIDAlone(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())

	holder := &Session{LocalSEID: 1, CPSEID: 2, PDRs: map[uint16]*pdr{}}
	holder.PDRs[1] = &pdr{id: 1, srcIfc: ie.SrcInterfaceAccess, teid: 0x77}
	c.mu.Lock()
	c.sessions[holder.LocalSEID] = holder
	c.byTEID[0x77] = holder
	c.mu.Unlock()

	// A request that pinned the same value and was refused: its PDR still
	// carries the value, and its release must not disturb the holder.
	refused := &Session{LocalSEID: 3, CPSEID: 4, PDRs: map[uint16]*pdr{}}
	refused.PDRs[1] = &pdr{id: 1, srcIfc: ie.SrcInterfaceAccess, teid: 0x77}
	c.mu.Lock()
	c.releaseSession(refused)
	still := c.byTEID[0x77]
	c.mu.Unlock()
	if still != holder {
		t.Errorf("the refused request's release erased the holder's TEID mapping (now %p)", still)
	}

	// And its own mapping is freed as usual.
	c.mu.Lock()
	c.releaseSession(holder)
	_, held := c.byTEID[0x77]
	c.mu.Unlock()
	if held {
		t.Error("releasing the holder left its TEID mapping behind")
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
	if err := c.remove(context.Background(), c.sessions[resp.Header.SEID]); err != nil {
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

// The collision check is only as good as when the mapping is written. byTEID is
// filled after a session's Apply, so if the mapping went in there, two
// establishments that pin one value -- the second while the first is in flight
// -- would both pass, and the second Apply would overwrite the first's TEID
// rule. The mapping goes in during merge, under merge's lock; this test holds
// the first Apply open and requires the second establishment to be refused.
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

	rec.fail = errors.New("transport")
	if got := cause(t, c.Establish(establishment(0x7777, "10.45.0.8"))); got != ie.CauseRequestRejected {
		t.Errorf("an unknown outcome answered cause %d, want a plain rejection", got)
	}
}

func TestModifyRewritesTheWholeSession(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(establishment(0x8888, "10.45.0.9")).(*message.SessionEstablishmentResponse)

	mod := message.NewSessionModificationRequest(0, 0, resp.Header.SEID, 2, 0,
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
	u := sessionOf(t, c, resp.Header.SEID).URRs[7]
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
	u := sessionOf(t, c, resp.Header.SEID).URRs[7]
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
		{"a period with no periodic trigger", ie.NewCreateURR(
			ie.NewURRID(7), ie.NewMeasurementMethod(0, 1, 0), ie.NewReportingTriggers(0x02, 0x00),
			ie.NewMeasurementPeriod(30*time.Second))},
		{"no measurement method", ie.NewCreateURR(
			ie.NewURRID(7), ie.NewReportingTriggers(0x02, 0x00))},
		{"a monitoring time", ie.NewCreateURR(
			ie.NewURRID(7), ie.NewMeasurementMethod(0, 1, 0), ie.NewReportingTriggers(0x02, 0x00),
			ie.NewMonitoringTime(time.Now()))},
		{"quota holding time", ie.NewCreateURR(
			ie.NewURRID(7), ie.NewMeasurementMethod(0, 1, 0), ie.NewReportingTriggers(0x02, 0x00),
			ie.NewQuotaHoldingTime(10*time.Second))},
		{"measurement information", ie.NewCreateURR(
			ie.NewURRID(7), ie.NewMeasurementMethod(0, 1, 0), ie.NewReportingTriggers(0x02, 0x00),
			ie.NewMeasurementInformation(0x08))},
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
	s := sessionOf(t, c, resp.Header.SEID)
	s.URRs[7].enforcing = true // as the reporter leaves it after a quota exhaustion

	mod := message.NewSessionModificationRequest(0, 0, resp.Header.SEID, 2, 0,
		ie.NewUpdateURR(
			ie.NewURRID(7),
			ie.NewReportingTriggers(0x01),        // PERIO alone
			ie.NewVolumeQuota(0x02, 0, 1<<40, 0), // a new, larger ULVOL
		),
	)
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification answered cause %d", got)
	}
	u := sessionOf(t, c, resp.Header.SEID).URRs[7]
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

func TestRemoveURRNeedsThePDRsToGoFirst(t *testing.T) {
	// A URR is what measures the traffic of the PDRs that name it: removing it
	// while they still do leaves them counted by a rule the SMF has taken away.
	// The order a modification takes is the PDR first (an Update PDR without the
	// URR ID), then the URR.
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(urrEstablishment(0x3005, 7, fullURR(7))).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}

	mod := message.NewSessionModificationRequest(0, 0, resp.Header.SEID, 2, 0,
		ie.NewRemoveURR(ie.NewURRID(7)))
	if got := cause(t, c.Modify(mod)); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("removing a URR a PDR still names answered cause %d, want a rule failure", got)
	}
	if s := sessionOf(t, c, resp.Header.SEID); s.URRs[7] == nil {
		t.Fatal("the refused removal took the URR out of the model")
	}

	// The Update PDR is the PDR's whole new form: without the URR ID the PDR no
	// longer measures anything.
	mod = message.NewSessionModificationRequest(0, 0, resp.Header.SEID, 3, 0,
		ie.NewUpdatePDR(ie.NewPDRID(1), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, 0x1000, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, "10.45.0.2", "", 0, 0)),
			ie.NewFARID(1)),
	)
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the PDR update answered cause %d", got)
	}
	mod = message.NewSessionModificationRequest(0, 0, resp.Header.SEID, 4, 0,
		ie.NewRemoveURR(ie.NewURRID(7)))
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the removal answered cause %d", got)
	}
	if s := sessionOf(t, c, resp.Header.SEID); s.URRs[7] != nil {
		t.Error("the session still holds the removed URR")
	}
}

func TestAnUpdateURRForAMissingURRIsRefused(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(establishment(0x3006, "10.45.0.2")).(*message.SessionEstablishmentResponse)
	mod := message.NewSessionModificationRequest(0, 0, resp.Header.SEID, 2, 0,
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

	fields := testConfig().Up.PDRFields
	rs := rules(rec.last())
	if len(rs) != 2 {
		t.Fatalf("%d rules, want 2", len(rs))
	}
	for _, r := range rs {
		if len(r.values) != len(fields) {
			t.Fatalf("%d key fields, want %d", len(r.values), len(fields))
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
