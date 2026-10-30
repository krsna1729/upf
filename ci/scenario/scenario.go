// SPDX-License-Identifier: BSD-3-Clause

// Package scenario builds the PFCP sessions the lanes drive the session
// compiler with, through the UP function's N4 node over UDP (SMF):
// ci/ifacepath against the interface grammar's graph, and ci/vethlayout
// against every veth attachment layout. A session here is one N4 session per
// PDU session, or the 5G VN group's one (docs/compliance.md), and Modes lists
// the Release 16 scenarios this UP serves: 1 to 6, with N19 beside Mode 5.
//
// The identities below (SEIDs, TEIDs, UE addresses) are the lanes' byte
// signatures: ci/iface-path.sh matches the TEIDs and addresses in its Dumps,
// and ci/veth-layouts.sh sends to them, so one value names one session in
// every lane.
package scenario

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// Pass is one phase boundary in a lane's handshake with its shell: it signals
// that the phase's state exists (<name>.done in dir) and waits up to `within`
// for the shell to have read or driven it (<name>.go). An empty dir runs
// straight through.
func Pass(dir, name string, within time.Duration) error {
	if dir == "" {
		return nil
	}
	if err := os.WriteFile(filepath.Join(dir, name+".done"), nil, 0o644); err != nil {
		return fmt.Errorf("signalling %s.done: %w", name, err)
	}
	deadline := time.Now().Add(within)
	for {
		if _, err := os.Stat(filepath.Join(dir, name+".go")); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the caller never wrote %s.go", name)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// ApplyForw is the Apply Action of a FAR that forwards: the only one these
// PDRs name.
const ApplyForw uint8 = 0x02

// The scenario sessions, each with its own SEID, UE address and F-TEIDs.
const (
	SEID1  = 0x4101
	SEID4  = 0x4104
	SEID5  = 0x4105
	SEID8  = 0x4108
	SEID9  = 0x4109
	SEID10 = 0x410a
	SEID11 = 0x410b
	SEID12 = 0x410c
	SEID13 = 0x410d

	UE1  = "10.45.0.2"
	UE4  = "10.45.0.5"
	UE5  = "10.45.0.6"
	UE8  = "10.45.0.8"
	UE9  = "10.45.0.9"
	UE10 = "10.45.0.10"
	UE11 = "10.45.0.11"
	UE13 = "10.45.0.13"
	// RemoteUE is a 5G VN member anchored at the other PSA of the N19 tunnel
	// (S12): S4 reaches it through the group-level session.
	RemoteUE = "10.45.9.2"

	// UpTEID1 is S1's N3 F-TEID and also S9's N9 one: the same TEID on two
	// endpoints is two tunnels, and the admission key's endpoint is all that
	// tells them apart.
	UpTEID1  = 0x11223344
	UpTEID4  = 0x11223347
	UpTEID5  = 0x11223348
	UpTEID8  = 0x1122334b
	UpTEID9  = UpTEID1
	UpTEID10 = 0x1122334d
	// UpTEID11 is S11's uplink F-TEID: on the N9 endpoint, as the upstream
	// I-UPF tunnels to it (Mode 4).
	UpTEID11 = 0x1122334e
	UpTEID13 = 0x11223352
	// The N9 F-TEIDs a PSA's downlink arrives on: S8's from the UL CL's
	// remote PSA, S11's, S10's and S13's from theirs.
	CoreTEID8  = 0x1122334c
	CoreTEID11 = 0x1122334f
	CoreTEID10 = 0x11223351
	CoreTEID13 = 0x11223353
	// N19TEID is the group-level session's N19 F-TEID (S12).
	N19TEID = 0x11223350

	DLTEID1  = 0x55667781
	DLTEID4  = 0x55667784
	DLTEID5  = 0x55667789
	DLTEID8  = 0x55667788
	DLTEID9  = 0x5566778a
	DLTEID10 = 0x5566778b
	DLTEID11 = 0x5566778d
	DLTEID13 = 0x55667791
	// The PSAs' N9 F-TEIDs the I-UPF sessions tunnel uplink to, and the
	// other PSA's N19 F-TEID.
	PSATEID11   = 0x5566778c
	PSATEID10   = 0x5566778f
	PSATEID13   = 0x55667790
	N19PeerTEID = 0x5566778e

	// ULCLBranch is the destination S8's specific uplink PDR selects: the
	// remote PSA's data network, reached through the N9 tunnel.
	ULCLBranch = "10.46.0.2"
)

// Mode 6, indirect data forwarding with the UPF re-allocated (TS 23.502
// 4.9.1.3.3): this UP is the source UPF of S10 and the target UPF of S13. The
// forwarding PDR and FAR each side creates (ForwardingID), the tunnels they
// forward to -- the target UPF's N3 forwarding F-TEID (S10) and the target
// RAN's (S13) -- and the SMF timer after which the resources are released.
const (
	ForwardingID      = 5
	ForwardTEID       = 0x55aa55aa
	TargetForwardTEID = 0x55aa55ab
	ForwardingTimer   = 4 * time.Second
)

// The filters, in the downlink form the CP function provisions on every PDR
// (TS 29.244 5.2.1A.2A), which the UP swaps on an Access PDR. Port53 matches
// the data network's answer to the UE's port 53, Port53Query the UE's query;
// the two port-5000 filters are the 5G VN exchange between two UEs;
// Port53FromBranch is the UL CL branch's specific destination, which the
// general port-53 filter also matches, so the PDR precedences decide.
const (
	Port53           = "permit out udp from any to assigned 53"
	Port53Query      = "permit out udp from any 53 to assigned"
	Port5000From     = "permit out udp from any 5000 to assigned"
	Port5000To       = "permit out udp from any to assigned 5000"
	Port53FromBranch = "permit out udp from " + ULCLBranch + " 53 to assigned"
)

// Local is the UP function's GTP-U endpoint addresses: the F-TEIDs an
// Access-side PDR is pinned to are N3's, unless its Source Interface Type
// names N9 or N19; a Core-side PDR's are N9's.
type Local struct{ N3, N9 string }

// Peers are the far ends the scenarios' tunnels go to. Each side names two,
// so a deployment that attaches one endpoint to several ports sends through
// more than one of them; a deployment with one peer per side names it twice.
type Peers struct {
	// GNB receives S1's, S4's, S5's and S10's downlink; GNB2 receives S8's
	// downlink, and is Mode 6's target side: S13's target RAN and S10's
	// target UPF.
	GNB, GNB2 string
	// UPF is the UL CL's remote PSA (S8's N9 branch), the PSA the I-UPF
	// sessions (S10, S11, S13) tunnel uplink to, and the N19 peer PSA (S12);
	// UPF2 is the I-UPF a Mode 3 PSA (S9) returns downlink to and the one
	// upstream of Mode 4's (S11).
	UPF, UPF2 string
}

// PDR is one PDR of a session: the Source Interface value, the subscriber
// address it names, the filter its traffic carries (as the CP function
// provisions it: see the filters above), the FAR's children, and the local
// F-TEID it admits. An empty UE or SDF omits that IE: a transit rule is
// the F-TEID's alone.
type PDR struct {
	SrcIfc uint8
	UE     string
	SDF    string
	FAR    []*ie.IE
	// TEID pins a local F-TEID on the PDR (0: none). Its address is the
	// endpoint the Source Interface and Type select (Local).
	TEID uint32
	// Type is the Source Interface Type (TS 29.244 8.2.118), 0 for none.
	Type uint8
	// Instance is the PDI's Network Instance when it is not the session's.
	Instance string
	// Precedence 0 is the sessions' default, 100.
	Precedence uint32
}

// Session is one establishment, all on one instance: an uplink PDR (the UE is
// the packet's source) and a subscriber-side PDR (the UE is its destination),
// with an optional second of each.
type Session struct {
	Name     string
	Instance string
	SEID     uint64
	Up, Down PDR
	// Up2 is a second uplink PDR with its own FAR: the UL CL branch.
	Up2 *PDR
	// Down2 is a second subscriber-side PDR: another UE address, or the same
	// UE's traffic arriving on an F-TEID.
	Down2 *PDR
}

// Mode is one Release 16 scenario and the sessions that make it.
type Mode struct {
	Number   int
	Name     string
	Sessions []Session
}

// Forward is a FAR that forwards: the Apply Action, the Destination Interface
// it names, and whatever the case adds inside the forwarding parameters (an
// outer header creation, a forwarding policy).
func Forward(dst uint8, extra ...*ie.IE) []*ie.IE {
	return []*ie.IE{
		ie.NewApplyAction(ApplyForw),
		ie.NewForwardingParameters(append([]*ie.IE{ie.NewDestinationInterface(dst)}, extra...)...),
	}
}

// Tunnel is the Outer Header Creation of a forward that adds one: the far
// end's F-TEID.
func Tunnel(teid uint32, peer string) *ie.IE {
	return ie.NewOuterHeaderCreation(0x0100, teid, peer, "", 0, 0, 0)
}

// EndMarker is a GTP-U End Marker on teid (TS 29.281 7.3.2): version 1, type
// 254, no information element, as the old path's sender ends a tunnel with it.
func EndMarker(teid uint32) []byte {
	return []byte{0x30, 254, 0, 0, byte(teid >> 24), byte(teid >> 16), byte(teid >> 8), byte(teid)}
}

// localFor is the address a PDR's F-TEID is pinned to: a Core-side PDR's, or
// one whose Source Interface Type is N9 or N19, is the N9 endpoint's. Every
// other value keeps N3's, including the values this UP refuses, so a refusal
// is about the Source Interface and nothing else.
func (l Local) localFor(p PDR) string {
	if p.SrcIfc == ie.SrcInterfaceCore || p.Type == ie.TGPPInterfaceTypeN9 || p.Type == ie.TGPPInterfaceTypeN19 {
		return l.N9
	}
	return l.N3
}

// Message is the Session Establishment Request the session sends. PDR ids are
// 1 (Up), 2 (Down), 3 (Down2) and 4 (Up2); each names the FAR of its own id.
func (s Session) Message(l Local) *message.SessionEstablishmentRequest {
	ies := []*ie.IE{ie.NewNodeID("", "", "smf"), ie.NewFSEID(s.SEID, nil, nil)}
	ies = append(ies, s.pdr(l, 1, s.Up, false)...)
	ies = append(ies, s.pdr(l, 2, s.Down, true)...)
	if s.Up2 != nil {
		ies = append(ies, s.pdr(l, 4, *s.Up2, false)...)
	}
	if s.Down2 != nil {
		ies = append(ies, s.pdr(l, 3, *s.Down2, true)...)
	}
	return message.NewSessionEstablishmentRequest(0, 0, s.SEID, 1, 0, ies...)
}

// pdr is one Create PDR and its Create FAR. The UE IP Address IE's S/D flag
// says which side the UE is on, which is what puts the rule in the uplink or
// the downlink chain whatever the Source Interface.
func (s Session) pdr(l Local, id uint16, p PDR, ueIsDestination bool) []*ie.IE {
	prec := p.Precedence
	if prec == 0 {
		prec = 100
	}
	ueFlags := uint8(0x02)
	if ueIsDestination {
		ueFlags = 0x06
	}
	instance := s.Instance
	if p.Instance != "" {
		instance = p.Instance
	}
	pdi := []*ie.IE{ie.NewSourceInterface(p.SrcIfc), ie.NewNetworkInstance(instance)}
	var decap []*ie.IE
	if p.TEID != 0 {
		pdi = append(pdi, ie.NewFTEID(0x01, p.TEID, net.ParseIP(l.localFor(p)), nil, 0))
		decap = append(decap, ie.NewOuterHeaderRemoval(0, 0))
	}
	if p.UE != "" {
		pdi = append(pdi, ie.NewUEIPAddress(ueFlags, p.UE, "", 0, 0))
	}
	if p.SDF != "" {
		pdi = append(pdi, ie.NewSDFFilter(p.SDF, "", "", "", 0))
	}
	if p.Type != 0 {
		pdi = append(pdi, ie.NewTGPPInterfaceType(p.Type))
	}
	pdr := append([]*ie.IE{ie.NewPDRID(id), ie.NewPrecedence(prec), ie.NewPDI(pdi...)}, decap...)
	return []*ie.IE{
		ie.NewCreatePDR(append(pdr, ie.NewFARID(uint32(id)))...),
		ie.NewCreateFAR(append([]*ie.IE{ie.NewFARID(uint32(id))}, p.FAR...)...),
	}
}

// Establish sends one session and requires it to be accepted, answering the
// SEID the UPF named the session by: the modification and the deletion that
// follow are addressed to it (the SMF reads it out of this answer's F-SEID).
func Establish(c N4, s Session, l Local) (uint64, error) {
	resp, ok := c.Establish(s.Message(l)).(*message.SessionEstablishmentResponse)
	if !ok {
		return 0, fmt.Errorf("%s: the establishment answered no session-level response", s.Name)
	}
	if got := Cause(resp.Cause); got != ie.CauseRequestAccepted {
		return 0, fmt.Errorf("%s was refused with cause %d", s.Name, got)
	}
	fseid, err := resp.UPFSEID.FSEID()
	if err != nil {
		return 0, fmt.Errorf("%s: the answer's F-SEID: %w", s.Name, err)
	}
	return fseid.SEID, nil
}

// CreateForwarding is the indirect forwarding tunnel's N4 modification
// (TS 23.502 4.9.1.3.3 step 11b at the target UPF, 11d at the source UPF): a
// PDR on an F-TEID the UP chooses, typed N3 for data forwarding (TS 29.244
// 8.2.118), and a FAR tunnelling what arrives on it to the next forwarding
// hop. The response's Created PDR carries the chosen F-TEID (Forwarding).
func CreateForwarding(seid uint64, instance string, teid uint32, peer string) *message.SessionModificationRequest {
	return message.NewSessionModificationRequest(0, 0, seid, 0, 0,
		ie.NewCreatePDR(ie.NewPDRID(ForwardingID), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess), ie.NewNetworkInstance(instance),
				ie.NewFTEID(0x05, 0, nil, nil, 0),
				ie.NewTGPPInterfaceType(ie.TGPPInterfaceTypeN3ForDataForwarding)),
			ie.NewOuterHeaderRemoval(0, 0), ie.NewFARID(ForwardingID)),
		ie.NewCreateFAR(append([]*ie.IE{ie.NewFARID(ForwardingID)},
			Forward(ie.DstInterfaceAccess, Tunnel(teid, peer))...)...),
	)
}

// SwitchDownlink is step 8a at the target UPF: the downlink FAR (2), which
// dropped until the handover executed, now tunnels to the target RAN.
func SwitchDownlink(seid uint64, teid uint32, peer string) *message.SessionModificationRequest {
	return message.NewSessionModificationRequest(0, 0, seid, 0, 0,
		ie.NewUpdateFAR(ie.NewFARID(2), ie.NewApplyAction(ApplyForw),
			ie.NewUpdateForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess), Tunnel(teid, peer))),
	)
}

// ReleaseForwarding is step 15a at the target UPF once the SMF's timer
// expires: the forwarding PDR and FAR are removed.
func ReleaseForwarding(seid uint64) *message.SessionModificationRequest {
	return message.NewSessionModificationRequest(0, 0, seid, 0, 0,
		ie.NewRemovePDR(ie.NewPDRID(ForwardingID)), ie.NewRemoveFAR(ie.NewFARID(ForwardingID)))
}

// Modify sends one modification and requires it to be accepted, answering
// the response.
func Modify(c N4, req *message.SessionModificationRequest, what string) (*message.SessionModificationResponse, error) {
	resp, ok := c.Modify(req).(*message.SessionModificationResponse)
	if !ok {
		return nil, fmt.Errorf("%s answered no session-level response", what)
	}
	if got := Cause(resp.Cause); got != ie.CauseRequestAccepted {
		return nil, fmt.Errorf("%s was refused with cause %d", what, got)
	}
	return resp, nil
}

// Release is the session's deletion (step 13a at the source UPF once the
// SMF's timer expires) and requires it to be accepted.
func Release(c N4, seid uint64, what string) error {
	resp, ok := c.Delete(message.NewSessionDeletionRequest(0, 0, seid, 0, 0)).(*message.SessionDeletionResponse)
	if !ok {
		return fmt.Errorf("%s answered no session-level response", what)
	}
	if got := Cause(resp.Cause); got != ie.CauseRequestAccepted {
		return fmt.Errorf("%s was refused with cause %d", what, got)
	}
	return nil
}

// Forwarding is the F-TEID a CreateForwarding response's Created PDR names:
// the TEID and the IPv4 address the UP function chose.
func Forwarding(resp *message.SessionModificationResponse) (uint32, string, error) {
	for _, c := range resp.CreatedPDR {
		children, err := c.CreatedPDR()
		if err != nil {
			return 0, "", err
		}
		var id uint16
		var teid uint32
		var addr string
		for _, ch := range children {
			switch ch.Type {
			case ie.PDRID:
				id, _ = ch.PDRID()
			case ie.FTEID:
				if f, err := ch.FTEID(); err == nil {
					teid = f.TEID
					if f.IPv4Address != nil {
						addr = f.IPv4Address.String()
					}
				}
			}
		}
		if id == ForwardingID && teid != 0 && addr != "" {
			return teid, addr, nil
		}
	}
	return 0, "", fmt.Errorf("the response names no Created PDR %d with an IPv4 F-TEID", ForwardingID)
}

// Cause is a response's Cause IE as a PFCP cause value.
func Cause(i *ie.IE) uint8 {
	if i == nil {
		return 0
	}
	c, err := i.Cause()
	if err != nil {
		return 0
	}
	return c
}

// S1 is Mode 1, a PSA: N3 uplink to the data network, and the data network's
// downlink to the gNB.
func S1(p Peers) Session {
	return Session{
		Name:     "S1: Source Interface Access, Destination Interface Core, no outer header",
		Instance: "internet", SEID: SEID1,
		Up: PDR{SrcIfc: ie.SrcInterfaceAccess, UE: UE1, SDF: Port53Query, TEID: UpTEID1,
			FAR: Forward(ie.DstInterfaceCore)},
		Down: PDR{SrcIfc: ie.SrcInterfaceCore, UE: UE1, SDF: Port53,
			FAR: Forward(ie.DstInterfaceAccess, Tunnel(DLTEID1, p.GNB))},
	}
}

// S8 is Mode 2, an UL CL co-located with a PSA: one TEID, two uplink PDRs.
// The general port-53 filter leaves by the data network's hop; the specific
// branch destination has the higher precedence and leaves through an N9
// tunnel to the remote PSA. Downlink returns to the gNB from either PSA: the
// local one's over N6, the remote one's on S8's N9 F-TEID.
func S8(p Peers) Session {
	return Session{
		Name:     "S8: UL CL, one session, two uplink PDRs, two exits, and the remote PSA's N9 downlink",
		Instance: "internet", SEID: SEID8,
		Up: PDR{SrcIfc: ie.SrcInterfaceAccess, UE: UE8, SDF: Port53Query, TEID: UpTEID8, Precedence: 20,
			FAR: Forward(ie.DstInterfaceCore)},
		Up2: &PDR{SrcIfc: ie.SrcInterfaceAccess, UE: UE8, SDF: Port53FromBranch, TEID: UpTEID8, Precedence: 10,
			FAR: Forward(ie.DstInterfaceCore, Tunnel(DLTEID8, p.UPF))},
		Down: PDR{SrcIfc: ie.SrcInterfaceCore, UE: UE8, SDF: Port53,
			FAR: Forward(ie.DstInterfaceAccess, Tunnel(DLTEID8, p.GNB2))},
		Down2: &PDR{SrcIfc: ie.SrcInterfaceCore, UE: UE8, SDF: Port53FromBranch, TEID: CoreTEID8,
			FAR: Forward(ie.DstInterfaceAccess, Tunnel(DLTEID8, p.GNB2))},
	}
}

// S9 is Mode 3, a PSA behind an N3-terminating I-UPF: the uplink arrives on
// S9's N9 F-TEID and leaves by N6 as plain IP; the data network's downlink
// returns over N9 to the I-UPF. The interface values are the direction (TS
// 29.244 Tables 8.2.2-1 and 8.2.24-1 NOTE 1: Access is uplink as a source and
// downlink as a destination), and the 3GPP Interface Type (8.2.118) says the
// tunnel toward the I-UPF is N9 rather than the RAN's N3 (TS 23.501 5.8.2.10:
// N9 between the N3-terminating UPF and the PSA).
func S9(p Peers) Session {
	return Session{
		Name:     "S9: PSA receiving N9, forwarding to N6",
		Instance: "internet", SEID: SEID9,
		Up: PDR{SrcIfc: ie.SrcInterfaceAccess, UE: UE9, SDF: Port53Query, TEID: UpTEID9,
			Type: ie.TGPPInterfaceTypeN9, FAR: Forward(ie.DstInterfaceCore)},
		Down: PDR{SrcIfc: ie.SrcInterfaceCore, UE: UE9, SDF: Port53,
			FAR: Forward(ie.DstInterfaceAccess, Tunnel(DLTEID9, p.UPF2),
				ie.NewTGPPInterfaceType(ie.TGPPInterfaceTypeN9))},
	}
}

// S4 and S5 are Mode 5, two member sessions of one 5G VN on one PSA (no group
// N4 session): S4's uplink PDR forwards to 5G VN Internal, which re-injects
// the packet into the subscriber-side table, where S5's PDR whose PDI names 5G
// VN Internal takes it and tunnels it to S5's gNB.
func S4(p Peers) Session {
	return Session{
		Name:     "S4: an uplink PDR forwarding to 5G VN Internal",
		Instance: "vn", SEID: SEID4,
		Up: PDR{SrcIfc: ie.SrcInterfaceAccess, UE: UE4, SDF: Port5000From, TEID: UpTEID4,
			FAR: Forward(ie.DstInterface5GVNInternal)},
		Down: PDR{SrcIfc: ie.SrcInterfaceCore, UE: UE4, SDF: Port53,
			FAR: Forward(ie.DstInterfaceAccess, Tunnel(DLTEID4, p.GNB))},
	}
}

// S5 is S4's peer member: see S4.
func S5(p Peers) Session {
	return Session{
		Name:     "S5: a PDR whose PDI names 5G VN Internal, forwarding to the access side",
		Instance: "vn", SEID: SEID5,
		Up: PDR{SrcIfc: ie.SrcInterfaceAccess, UE: UE5, SDF: "permit out udp from any 6000 to assigned", TEID: UpTEID5,
			FAR: Forward(ie.DstInterface5GVNInternal)},
		Down: PDR{SrcIfc: ie.SrcInterface5GVNInternal, UE: UE5, SDF: Port5000To,
			FAR: Forward(ie.DstInterfaceAccess, Tunnel(DLTEID5, p.GNB))},
	}
}

// S10 is Mode 6's source UPF, an I-UPF whose N3 uplink tunnels to the PSA
// and whose N9 downlink tunnels to the source RAN. During the handover the
// SMF adds the forwarding tunnel toward the target UPF (CreateForwarding) and
// deletes the session once its timer expires (Release).
func S10(p Peers) Session {
	return Session{
		Name:     "S10: the source I-UPF of an indirect forwarding handover",
		Instance: "internet", SEID: SEID10,
		Up: PDR{SrcIfc: ie.SrcInterfaceAccess, UE: UE10, SDF: Port53Query, TEID: UpTEID10,
			FAR: Forward(ie.DstInterfaceCore, Tunnel(PSATEID10, p.UPF))},
		Down: PDR{SrcIfc: ie.SrcInterfaceCore, UE: UE10, SDF: Port53, TEID: CoreTEID10,
			FAR: Forward(ie.DstInterfaceAccess, Tunnel(DLTEID10, p.GNB))},
	}
}

// S13 is Mode 6's target UPF as step 6c establishes it: N3 uplink to the
// PSA, and the PSA's downlink on its N9 F-TEID dropped until step 8a
// (SwitchDownlink); the forwarding tunnel toward the target RAN comes and
// goes with CreateForwarding and ReleaseForwarding.
func S13(p Peers) Session {
	return Session{
		Name:     "S13: the target I-UPF of an indirect forwarding handover",
		Instance: "internet", SEID: SEID13,
		Up: PDR{SrcIfc: ie.SrcInterfaceAccess, UE: UE13, SDF: Port53Query, TEID: UpTEID13,
			FAR: Forward(ie.DstInterfaceCore, Tunnel(PSATEID13, p.UPF))},
		Down: PDR{SrcIfc: ie.SrcInterfaceCore, UE: UE13, SDF: Port53, TEID: CoreTEID13,
			FAR: []*ie.IE{ie.NewApplyAction(0x01)}},
	}
}

// S11 is Mode 4, an I-UPF between another I-UPF and the PSA (TS 23.502
// 4.3.5.4 step 6, 4.3.5.7 steps 3 and 10): both legs are N9. The uplink
// arrives from the upstream I-UPF -- Source Interface Access, typed N9 (TS
// 29.244 Table 8.2.2-1 NOTE 1, 8.2.118) -- and the downlink leaves toward
// it -- Destination Interface Access, typed N9. Neither rule names the UE:
// a transit rule is its F-TEID.
func S11(p Peers) Session {
	return Session{
		Name:     "S11: I-UPF relaying N9 to N9",
		Instance: "internet", SEID: SEID11,
		Up: PDR{SrcIfc: ie.SrcInterfaceAccess, TEID: UpTEID11, Type: ie.TGPPInterfaceTypeN9,
			FAR: Forward(ie.DstInterfaceCore, Tunnel(PSATEID11, p.UPF))},
		Down: PDR{SrcIfc: ie.SrcInterfaceCore, TEID: CoreTEID11,
			FAR: Forward(ie.DstInterfaceAccess, Tunnel(DLTEID11, p.UPF2),
				ie.NewTGPPInterfaceType(ie.TGPPInterfaceTypeN9))},
	}
}

// S12 is the N19 case: the 5G VN group-level session (TS 23.501 5.8.2.13.1,
// TS 23.502 4.13.8.2.2, TS 29.244 5.23) beside its member sessions S4 and S5.
// Its N19 PDR's PDI names the instance of the N19 F-TEID's address and its
// FAR the 5G VN group, which re-injects into the members' rules; its 5G VN
// Internal PDR takes the traffic for the member the other PSA anchors and
// tunnels it over N19, out of the instance the N19 endpoint serves (the
// FAR's Network Instance, Table 7.5.2.3-2 NOTE 1).
func S12(p Peers) Session {
	return Session{
		Name:     "S12: 5G VN group-level session with an N19 tunnel",
		Instance: "internet", SEID: SEID12,
		Up: PDR{SrcIfc: ie.SrcInterfaceCore, TEID: N19TEID, Type: ie.TGPPInterfaceTypeN19,
			FAR: Forward(ie.DstInterface5GVNInternal, ie.NewNetworkInstance("vn"))},
		Down: PDR{SrcIfc: ie.SrcInterface5GVNInternal, UE: RemoteUE, Instance: "vn",
			FAR: Forward(ie.DstInterfaceCore, Tunnel(N19PeerTEID, p.UPF),
				ie.NewNetworkInstance("internet"), ie.NewTGPPInterfaceType(ie.TGPPInterfaceTypeN19))},
	}
}

// Modes is every scenario docs/compliance.md permits, with its sessions.
// Mode 5 includes the N19 group session (S12) beside its members.
func Modes(p Peers) []Mode {
	return []Mode{
		{Number: 1, Name: "PSA, N3 to N6", Sessions: []Session{S1(p)}},
		{Number: 2, Name: "UL CL steering to local N6 or N9", Sessions: []Session{S8(p)}},
		{Number: 3, Name: "PSA receiving N9, forwarding to N6", Sessions: []Session{S9(p)}},
		{Number: 4, Name: "I-UPF relaying N9 to N9", Sessions: []Session{S11(p)}},
		{Number: 5, Name: "5G VN local switching and N19", Sessions: []Session{S4(p), S5(p), S12(p)}},
		{Number: 6, Name: "indirect data forwarding", Sessions: []Session{S10(p), S13(p)}},
	}
}
