// SPDX-License-Identifier: BSD-3-Clause
package session

import (
	"net"
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/bess"
)

// marEstablishment is a session whose downlink PDR is steered by MAR 7: the
// 3GPP access is active (FAR 2, a tunnel to the gNB) and the non-3GPP access
// standby (FAR 3, plain IP toward the core).
func marEstablishment(cpSEID uint64, ueIP string) *message.SessionEstablishmentRequest {
	return marEstablishmentTEID(cpSEID, ueIP, 0x11223344)
}

func marEstablishmentTEID(cpSEID uint64, ueIP string, teid uint32) *message.SessionEstablishmentRequest {
	return message.NewSessionEstablishmentRequest(0, 0, cpSEID, 1, 0,
		ie.NewNodeID("", "", "smf"),
		ie.NewFSEID(cpSEID, nil, nil),
		ie.NewCreatePDR(
			ie.NewPDRID(1),
			ie.NewPrecedence(100),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, teid, net.ParseIP("192.0.2.1"), nil, 0),
				ie.NewUEIPAddress(0x02, ueIP, "", 0, 0),
			),
			ie.NewFARID(1),
		),
		ie.NewCreatePDR(
			ie.NewPDRID(2),
			ie.NewPrecedence(100),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(0x02, ueIP, "", 0, 0),
				ie.NewSDFFilter("permit out udp from any to assigned 53", "", "", "", 0),
			),
			ie.NewMARID(7),
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
				ie.NewOuterHeaderCreation(0x0100, 0x55667788, "10.20.30.2", "", 0, 0, 0),
			),
		),
		ie.NewCreateFAR(
			ie.NewFARID(3),
			ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore)),
		),
		ie.NewCreateMAR(
			ie.NewMARID(7),
			ie.NewSteeringFunctionality(ie.SteeringFunctionalityATSSSLL),
			ie.NewSteeringMode(ie.SteeringModeActiveStandby),
			ie.NewTGPPAccessForwardingActionInformation(
				ie.NewFARID(2), ie.NewPriority(ie.PriorityActive)),
			ie.NewNonTGPPAccessForwardingActionInformation(
				ie.NewFARID(3), ie.NewPriority(ie.PriorityStandby)),
		),
	)
}

func marConfig() Config {
	cfg := testConfig()
	cfg.Atsss = "atsss"
	cfg.Down.PdrMatch = "pdr_match_dl"
	// The downlink matcher is keyed by the selector's session id: an N6 packet
	// carries no tunnel to key it by.
	cfg.Down.Selector = "sel_dl"
	cfg.Down.SelectorFields = []Field{DstIP, RouteDomain}
	return cfg
}

func lastChanges(t *testing.T, rec *recorder) []bess.Change {
	t.Helper()
	if len(rec.txns) == 0 {
		t.Fatal("the compiler applied no transaction")
	}
	return rec.txns[len(rec.txns)-1]
}

func changeWithResource(t *testing.T, changes []bess.Change, resource string) bess.Change {
	t.Helper()
	for _, ch := range changes {
		if ch.Resource == resource {
			return ch
		}
	}
	t.Fatalf("no change for %s in %d changes", resource, len(changes))
	return bess.Change{}
}

// TestMARProgramsPolicyAndSteeringRule is the PFCP half of the steering path:
// a MAR's two access actions become one policy, and the PDR's matcher rule
// carries the MAR ID that the packet path writes into the steering attribute.
func TestMARProgramsPolicyAndSteeringRule(t *testing.T) {
	rec := &recorder{}
	c := New(marConfig(), rec, quietLogger())
	resp := c.Establish(marEstablishment(0x7001, "10.45.0.7"))
	if got := answerCause(resp); got != ie.CauseRequestAccepted {
		t.Fatalf("establishment with a MAR was refused with cause %d", got)
	}
	policy := changeWithResource(t, lastChanges(t, rec), "atsss/policies")
	policyID, ok := policy.Key["policy_id"].(uint32)
	if !ok || policyID == 0 {
		t.Fatalf("policy key is %v, want a nonzero global policy id", policy.Key)
	}
	value := policy.Value
	if value["preferred"] != uint32(0) {
		t.Errorf("preferred is %v, want the 3GPP access (0)", value["preferred"])
	}
	access, ok := value["access"].([]map[string]any)
	if !ok || len(access) != 2 {
		t.Fatalf("policy access list is %#v, want two accesses", value["access"])
	}
	if access[0]["next_hop_id"] != uint32(2) || access[0]["health_id"] != uint32(1) {
		t.Errorf("3GPP access is %v, want next hop 2 and health 1", access[0])
	}
	if access[0]["tunnel_id"] == uint32(0) {
		t.Error("the 3GPP access adds an outer header, and names no tunnel record")
	}
	if access[1]["next_hop_id"] != uint32(2) || access[1]["health_id"] != uint32(2) {
		t.Errorf("non-3GPP access is %v, want next hop 2 and health 2", access[1])
	}
	if access[1]["tunnel_id"] != uint32(0) {
		t.Errorf("the non-3GPP access is plain IP, and names tunnel %v", access[1]["tunnel_id"])
	}
	if _, ok := changeWithResource(t, lastChanges(t, rec), "enc/tunnels").Key["action_id"]; !ok {
		t.Error("the tunnelled access has no encap record")
	}

	rules := changeWithResource(t, lastChanges(t, rec), "pdr_match_dl/rules")
	rulesValue := rules.Value["rules"].([]map[string]any)
	if len(rulesValue) != 1 {
		t.Fatalf("downlink matcher has %d rules, want one", len(rulesValue))
	}
	if rulesValue[0]["steering_policy_id"] != policyID {
		t.Errorf("matcher rule steering id is %v, want the policy id %d",
			rulesValue[0]["steering_policy_id"], policyID)
	}
}

// TestUpdateMARMovesThePreferredAccess: an Update MAR names the non-3GPP
// access active, and the policy's preferred index follows it.
func TestUpdateMARMovesThePreferredAccess(t *testing.T) {
	rec := &recorder{}
	c := New(marConfig(), rec, quietLogger())
	if got := answerCause(c.Establish(marEstablishment(0x7002, "10.45.0.8"))); got != ie.CauseRequestAccepted {
		t.Fatalf("establishment was refused with cause %d", got)
	}
	mod := message.NewSessionModificationRequest(0, 0, 1, 2, 0,
		ie.NewFSEID(0x7002, nil, nil),
		ie.NewUpdateMAR(
			ie.NewMARID(7),
			ie.NewUpdateTGPPAccessForwardingActionInformation(
				ie.NewPriority(ie.PriorityStandby)),
			ie.NewUpdateNonTGPPAccessForwardingActionInformation(
				ie.NewPriority(ie.PriorityActive)),
		),
	)
	if got := answerCause(c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("MAR update was refused with cause %d", got)
	}
	policy := changeWithResource(t, lastChanges(t, rec), "atsss/policies")
	if policy.Value["preferred"] != uint32(1) {
		t.Errorf("preferred is %v after the update, want the non-3GPP access (1)",
			policy.Value["preferred"])
	}
}

// TestMARPDRWithoutASteeringModuleIsRefused: the first slice refuses a MAR when
// the deployment names no AtsssSteer, with the rule-failure cause rather than
// compiling a rule the datapath would drop.
func TestMARPDRWithoutASteeringModuleIsRefused(t *testing.T) {
	cfg := marConfig()
	cfg.Atsss = ""
	cfg.Down.PdrMatch = ""
	c := New(cfg, &recorder{}, quietLogger())
	resp := c.Establish(marEstablishment(0x7003, "10.45.0.9"))
	if got := answerCause(resp); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a MAR without -atsss was answered with cause %d, want 73", got)
	}
}

// TestMAROnlySupportsActiveStandby: a steering mode this datapath does not
// apply is refused rather than programmed as something else.
func TestMAROnlySupportsActiveStandby(t *testing.T) {
	req := marEstablishment(0x7004, "10.45.0.10")
	req.CreateMAR[0] = ie.NewCreateMAR(
		ie.NewMARID(7),
		ie.NewSteeringFunctionality(ie.SteeringFunctionalityATSSSLL),
		ie.NewSteeringMode(ie.SteeringModeLoadBalancing),
		ie.NewTGPPAccessForwardingActionInformation(
			ie.NewFARID(2), ie.NewPriority(ie.PriorityActive)),
		ie.NewNonTGPPAccessForwardingActionInformation(
			ie.NewFARID(3), ie.NewPriority(ie.PriorityStandby)),
	)
	c := New(marConfig(), &recorder{}, quietLogger())
	if got := answerCause(c.Establish(req)); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("a load-balancing MAR was answered with cause %d, want 73", got)
	}
}

// TestRemoveMARStillNamedByAPDRIsRefused: the MAR is the PDR's only egress, so
// the SMF must remove the PDR first, as it does for a URR.
func TestRemoveMARStillNamedByAPDRIsRefused(t *testing.T) {
	c := New(marConfig(), &recorder{}, quietLogger())
	if got := answerCause(c.Establish(marEstablishment(0x7005, "10.45.0.11"))); got != ie.CauseRequestAccepted {
		t.Fatalf("establishment was refused with cause %d", got)
	}
	mod := message.NewSessionModificationRequest(0, 0, 1, 2, 0,
		ie.NewFSEID(0x7005, nil, nil),
		ie.NewRemoveMAR(ie.NewMARID(7)),
	)
	if got := answerCause(c.Modify(mod)); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("removing a live PDR's MAR was answered with cause %d, want 73", got)
	}
}

// TestRemoveMARWithItsPDR: the same message may remove both, and the policy and
// the tunnel records go with them.
func TestRemoveMARWithItsPDR(t *testing.T) {
	rec := &recorder{}
	c := New(marConfig(), rec, quietLogger())
	if got := answerCause(c.Establish(marEstablishment(0x7006, "10.45.0.12"))); got != ie.CauseRequestAccepted {
		t.Fatalf("establishment was refused with cause %d", got)
	}
	mod := message.NewSessionModificationRequest(0, 0, 1, 2, 0,
		ie.NewFSEID(0x7006, nil, nil),
		ie.NewRemovePDR(ie.NewPDRID(2)),
		ie.NewRemoveMAR(ie.NewMARID(7)),
	)
	if got := answerCause(c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("removing the MAR and its PDR was refused with cause %d", got)
	}
	changes := lastChanges(t, rec)
	if ch := changeWithResource(t, changes, "atsss/policies"); ch.Value != nil {
		t.Errorf("the removed MAR's policy was written, not erased: %v", ch.Value)
	}
}

// TestMARWithOneAccessAndNoStandby: active/standby allows the SMF to omit the
// access with no standby (TS 29.244 7.5.2.8 NOTE 1). The policy keeps a zero
// entry for the missing access, which the packet path skips.
func TestMARWithOneAccessAndNoStandby(t *testing.T) {
	req := marEstablishment(0x7007, "10.45.0.13")
	req.CreateMAR[0] = ie.NewCreateMAR(
		ie.NewMARID(7),
		ie.NewSteeringFunctionality(ie.SteeringFunctionalityATSSSLL),
		ie.NewSteeringMode(ie.SteeringModeActiveStandby),
		ie.NewTGPPAccessForwardingActionInformation(
			ie.NewFARID(2), ie.NewPriority(ie.PriorityActive)),
	)
	rec := &recorder{}
	c := New(marConfig(), rec, quietLogger())
	if got := answerCause(c.Establish(req)); got != ie.CauseRequestAccepted {
		t.Fatalf("a one-access MAR was refused with cause %d", got)
	}
	value := changeWithResource(t, lastChanges(t, rec), "atsss/policies").Value
	access := value["access"].([]map[string]any)
	if access[0]["health_id"] != uint32(1) {
		t.Errorf("the 3GPP access is %v, want health 1", access[0])
	}
	if access[1]["health_id"] != uint32(0) || access[1]["next_hop_id"] != uint32(0) {
		t.Errorf("the missing non-3GPP access is %v, want zeros", access[1])
	}
}

// TestMARAccessAvailabilityControlIsRefused: this UP has no access
// measurement, so accepting the SMF's control information while ignoring it
// would be a false report. Cause 73 says so.
func TestMARAccessAvailabilityControlIsRefused(t *testing.T) {
	req := marEstablishment(0x7008, "10.45.0.14")
	req.CreateMAR[0] = ie.NewCreateMAR(
		ie.NewMARID(7),
		ie.NewSteeringFunctionality(ie.SteeringFunctionalityATSSSLL),
		ie.NewSteeringMode(ie.SteeringModeActiveStandby),
		ie.NewTGPPAccessForwardingActionInformation(
			ie.NewFARID(2), ie.NewPriority(ie.PriorityActive)),
		ie.NewNonTGPPAccessForwardingActionInformation(
			ie.NewFARID(3), ie.NewPriority(ie.PriorityStandby)),
		ie.NewAccessAvailabilityControlInformation(
			ie.NewRequestedAccessAvailabilityInformation(1)),
	)
	c := New(marConfig(), &recorder{}, quietLogger())
	if got := answerCause(c.Establish(req)); got != ie.CauseRuleCreationModificationFailure {
		t.Errorf("access availability control was answered with cause %d, want 73", got)
	}
}

// TestMARPolicyIDsAreGlobal: MAR IDs are session-local, but the
// AtsssSteer policy table is shared. Two sessions that both use MAR 7 must
// get different policy ids, and their matcher rules must publish those ids.
func TestMARPolicyIDsAreGlobal(t *testing.T) {
	rec := &recorder{}
	c := New(marConfig(), rec, quietLogger())
	if got := answerCause(c.Establish(marEstablishment(0x7010, "10.45.0.20"))); got != ie.CauseRequestAccepted {
		t.Fatalf("first establishment was refused with cause %d", got)
	}
	first := changeWithResource(t, lastChanges(t, rec), "atsss/policies")
	firstID, ok := first.Key["policy_id"].(uint32)
	if !ok || firstID == 0 {
		t.Fatalf("first policy key is %v", first.Key)
	}
	if got := answerCause(c.Establish(marEstablishmentTEID(0x7011, "10.45.0.21", 0x55667788))); got != ie.CauseRequestAccepted {
		t.Fatalf("second establishment was refused with cause %d", got)
	}
	second := changeWithResource(t, lastChanges(t, rec), "atsss/policies")
	secondID, ok := second.Key["policy_id"].(uint32)
	if !ok || secondID == 0 {
		t.Fatalf("second policy key is %v", second.Key)
	}
	if firstID == secondID {
		t.Fatalf("two sessions' MAR 7 share policy id %d", firstID)
	}
}

// TestMARNoStandbyIsIneligible: a present access with Priority "No Standby"
// is still active/standby, but it must never be selected as the standby.
func TestMARNoStandbyIsIneligible(t *testing.T) {
	req := marEstablishment(0x7012, "10.45.0.22")
	req.CreateMAR[0] = ie.NewCreateMAR(
		ie.NewMARID(7),
		ie.NewSteeringFunctionality(ie.SteeringFunctionalityATSSSLL),
		ie.NewSteeringMode(ie.SteeringModeActiveStandby),
		ie.NewTGPPAccessForwardingActionInformation(
			ie.NewFARID(2), ie.NewPriority(ie.PriorityActive)),
		ie.NewNonTGPPAccessForwardingActionInformation(
			ie.NewFARID(3), ie.NewPriority(ie.PriorityNoStandby)),
	)
	rec := &recorder{}
	c := New(marConfig(), rec, quietLogger())
	if got := answerCause(c.Establish(req)); got != ie.CauseRequestAccepted {
		t.Fatalf("a No Standby access was refused with cause %d", got)
	}
	value := changeWithResource(t, lastChanges(t, rec), "atsss/policies").Value
	access := value["access"].([]map[string]any)
	if access[1]["health_id"] != uint32(0) || access[1]["next_hop_id"] != uint32(0) {
		t.Errorf("the No Standby access is %v, want an ineligible zero entry", access[1])
	}
}
