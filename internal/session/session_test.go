// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"

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
			Tunnels:   "enc",
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
	return message.NewSessionEstablishmentRequest(0, 0, cpSEID, 1, 0,
		ie.NewNodeID("", "", "smf"),
		ie.NewFSEID(cpSEID, nil, nil),
		ie.NewCreatePDR(
			ie.NewPDRID(1),
			ie.NewPrecedence(100),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x02, 0, net.ParseIP("192.0.2.1"), nil, 0),
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
	if got := dlAction.Value["next_hop_id"]; got != uint32(0) {
		t.Errorf("the downlink action forwards straight to the tunnel, but its next hop is %v", got)
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
	if _, ok := find0(rec.last(), testConfig().Up.Actions+"/actions", "id", uint32(1)); !ok {
		t.Error("the deletion leaves the uplink action behind")
	}
	if _, ok := find0(rec.last(), testConfig().Down.Actions+"/actions", "id", uint32(2)); !ok {
		t.Error("the deletion leaves the downlink action behind")
	}
	if _, ok := teidRule(rec.last(), testConfig().TEIDTable+"/rules", 1); !ok {
		t.Error("the deletion leaves the TEID rule behind")
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

func TestUnknownSessionIsNotFound(t *testing.T) {
	c := New(testConfig(), &recorder{}, quietLogger())
	resp := c.Modify(message.NewSessionModificationRequest(0, 0, 999, 1, 0)).(*message.SessionModificationResponse)
	if got := cause(t, resp); got != ie.CauseSessionContextNotFound {
		t.Errorf("modifying an unknown session answered cause %d", got)
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
