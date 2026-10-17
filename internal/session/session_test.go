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

// A closed gate is not a slow path: the compiler writes the rule's own gate as
// the drop gate and gives it no action, so the packet is dropped where the
// session's state says it must be, without a lookup into the action table.
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
