// SPDX-License-Identifier: BSD-3-Clause

// Package scenario builds the PFCP sessions the lanes drive the session
// compiler with directly: ci/ifacepath against the interface grammar's graph,
// and ci/vethlayout against every veth attachment layout. A session here is
// one N4 session per PDU session (docs/compliance.md), and Modes lists the
// Release 16 scenarios this UP serves: 1, 2, 3, 5 and 6. Mode 4 (N9-to-N9
// transit) is not established by any cited procedure, so it has no session
// here and no lane drives it.
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

	"github.com/krsna1729/upf/internal/session"
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

	UE1  = "10.45.0.2"
	UE4  = "10.45.0.5"
	UE5  = "10.45.0.6"
	UE8  = "10.45.0.8"
	UE9  = "10.45.0.9"
	UE10 = "10.45.0.10"

	// UpTEID1 is S1's N3 F-TEID and also S9's N9 one: the same TEID on two
	// endpoints is two tunnels, and the admission key's endpoint is all that
	// tells them apart.
	UpTEID1  = 0x11223344
	UpTEID4  = 0x11223347
	UpTEID5  = 0x11223348
	UpTEID8  = 0x1122334b
	UpTEID9  = UpTEID1
	UpTEID10 = 0x1122334d
	// CoreTEID8 is S8's N9 F-TEID: the remote PSA's downlink arrives on it.
	CoreTEID8 = 0x1122334c

	DLTEID1  = 0x55667781
	DLTEID4  = 0x55667784
	DLTEID5  = 0x55667789
	DLTEID8  = 0x55667788
	DLTEID9  = 0x5566778a
	DLTEID10 = 0x5566778b

	// ULCLBranch is the destination S8's specific uplink PDR selects: the
	// remote PSA's data network, reached through the N9 tunnel.
	ULCLBranch = "10.46.0.2"
)

// Mode 6's temporary forwarding leg: the FAR it creates, the target RAN's
// TEID, and the SMF timer after which the leg is released.
const (
	ForwardFARID    = 9
	ForwardTEID     = 0x55aa55aa
	ForwardingTimer = 4 * time.Second
)

// The filters, in the downlink form the CP function provisions on every PDR
// (TS 29.244 5.2.1A.2A), which the UP swaps on an Access PDR. Port53 matches
// the data network's answer to the UE's port 53, Port53Query the UE's query;
// the two port-5000 filters are the 5G VN exchange between two UEs;
// Port53FromBranch is the UL CL branch's specific destination, which the
// general port-53 filter also matches, so the PDR precedences decide. A
// Core-side PDR's filter is applied as written, so a Core-side uplink PDR
// (Mode 3's N9 arrival) names the UE as the source: Port53QueryN9.
const (
	Port53           = "permit out udp from any to assigned 53"
	Port53Query      = "permit out udp from any 53 to assigned"
	Port53QueryN9    = "permit out udp from assigned to any 53"
	Port5000From     = "permit out udp from any 5000 to assigned"
	Port5000To       = "permit out udp from any to assigned 5000"
	Port53FromBranch = "permit out udp from " + ULCLBranch + " 53 to assigned"
)

// Local is the UP function's GTP-U endpoint addresses: the F-TEIDs an
// Access-side PDR is pinned to are N3's, a Core-side PDR's are N9's.
type Local struct{ N3, N9 string }

// Peers are the far ends the scenarios' tunnels go to. Each side names two,
// so a deployment that attaches one endpoint to several ports sends through
// more than one of them; a deployment with one peer per side names it twice.
type Peers struct {
	// GNB receives S1's, S4's, S5's and S10's downlink; GNB2 receives S8's
	// downlink and is Mode 6's target RAN.
	GNB, GNB2 string
	// UPF is the UL CL's remote PSA (S8's N9 branch); UPF2 is the I-UPF a
	// Mode 3 PSA (S9) returns downlink to.
	UPF, UPF2 string
}

// PDR is one PDR of a session: the Source Interface value, the subscriber
// address it names, the filter its traffic carries (as the CP function
// provisions it: see the filters above), the FAR's children, and the local
// F-TEID it admits.
type PDR struct {
	SrcIfc uint8
	UE     string
	SDF    string
	FAR    []*ie.IE
	// TEID pins a local F-TEID on the PDR (0: none). Its address is the
	// endpoint the Source Interface selects (Local).
	TEID uint32
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

// localFor is the address a PDR's F-TEID is pinned to: a Core-side PDR's is
// the N9 endpoint's. Every other value keeps N3's, including the values this
// UP refuses, so a refusal is about the Source Interface and nothing else.
func (l Local) localFor(srcIfc uint8) string {
	if srcIfc == ie.SrcInterfaceCore {
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
	pdi := []*ie.IE{ie.NewSourceInterface(p.SrcIfc), ie.NewNetworkInstance(s.Instance)}
	if p.TEID != 0 {
		pdi = append(pdi, ie.NewFTEID(0x01, p.TEID, net.ParseIP(l.localFor(p.SrcIfc)), nil, 0))
	}
	pdi = append(pdi, ie.NewUEIPAddress(ueFlags, p.UE, "", 0, 0), ie.NewSDFFilter(p.SDF, "", "", "", 0))
	return []*ie.IE{
		ie.NewCreatePDR(ie.NewPDRID(id), ie.NewPrecedence(prec), ie.NewPDI(pdi...), ie.NewFARID(uint32(id))),
		ie.NewCreateFAR(append([]*ie.IE{ie.NewFARID(uint32(id))}, p.FAR...)...),
	}
}

// Establish sends one session and requires it to be accepted, answering the
// SEID the UPF named the session by: the modification and the deletion that
// follow are addressed to it (the SMF reads it out of this answer's F-SEID).
func Establish(c *session.Compiler, s Session, l Local) (uint64, error) {
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

// StartForward is Mode 6's temporary leg: a separate FAR toward the target
// RAN's tunnel, and the session's uplink PDR (1) rebound to it.
func StartForward(seid uint64, target string) *message.SessionModificationRequest {
	return message.NewSessionModificationRequest(0, 0, seid, 1, 0,
		ie.NewFSEID(seid, nil, nil),
		ie.NewCreateFAR(
			ie.NewFARID(ForwardFARID),
			ie.NewApplyAction(ApplyForw),
			ie.NewForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceAccess),
				Tunnel(ForwardTEID, target),
			),
		),
		ie.NewUpdatePDR(ie.NewPDRID(1), ie.NewFARID(ForwardFARID)),
	)
}

// EndForward is the SMF's cleanup once its timer expires: the uplink PDR goes
// back to its steady FAR (1) and the temporary FAR is removed.
func EndForward(seid uint64) *message.SessionModificationRequest {
	return message.NewSessionModificationRequest(0, 0, seid, 2, 0,
		ie.NewFSEID(seid, nil, nil),
		ie.NewUpdatePDR(ie.NewPDRID(1), ie.NewFARID(1)),
		ie.NewRemoveFAR(ie.NewFARID(ForwardFARID)),
	)
}

// Modify sends one modification and requires it to be accepted.
func Modify(c *session.Compiler, req *message.SessionModificationRequest, what string) error {
	resp, ok := c.Modify(req).(*message.SessionModificationResponse)
	if !ok {
		return fmt.Errorf("%s answered no session-level response", what)
	}
	if got := Cause(resp.Cause); got != ie.CauseRequestAccepted {
		return fmt.Errorf("%s was refused with cause %d", what, got)
	}
	return nil
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
// S9's N9 F-TEID (a Core-side PDR whose UE is the source) and leaves by N6 as
// plain IP; the data network's downlink returns over N9 to the I-UPF.
func S9(p Peers) Session {
	return Session{
		Name:     "S9: PSA receiving N9, forwarding to N6",
		Instance: "internet", SEID: SEID9,
		Up: PDR{SrcIfc: ie.SrcInterfaceCore, UE: UE9, SDF: Port53QueryN9, TEID: UpTEID9,
			FAR: Forward(ie.DstInterfaceCore)},
		Down: PDR{SrcIfc: ie.SrcInterfaceCore, UE: UE9, SDF: Port53,
			FAR: Forward(ie.DstInterfaceCore, Tunnel(DLTEID9, p.UPF2))},
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

// S10 is the session Mode 6 modifies: steady, it is Mode 1's shape, and
// StartForward/EndForward put it in and out of the temporary leg. Its own
// session keeps S1 steady while the leg is live.
func S10(p Peers) Session {
	return Session{
		Name:     "S10: the session indirect forwarding modifies",
		Instance: "internet", SEID: SEID10,
		Up: PDR{SrcIfc: ie.SrcInterfaceAccess, UE: UE10, SDF: Port53Query, TEID: UpTEID10,
			FAR: Forward(ie.DstInterfaceCore)},
		Down: PDR{SrcIfc: ie.SrcInterfaceCore, UE: UE10, SDF: Port53,
			FAR: Forward(ie.DstInterfaceAccess, Tunnel(DLTEID10, p.GNB))},
	}
}

// Modes is every scenario docs/compliance.md permits, with its sessions. Mode
// 4 is absent on purpose: no cited Release 16 procedure establishes it, and a
// valid-mode fixture must not force it.
func Modes(p Peers) []Mode {
	return []Mode{
		{Number: 1, Name: "PSA, N3 to N6", Sessions: []Session{S1(p)}},
		{Number: 2, Name: "UL CL steering to local N6 or N9", Sessions: []Session{S8(p)}},
		{Number: 3, Name: "PSA receiving N9, forwarding to N6", Sessions: []Session{S9(p)}},
		{Number: 5, Name: "5G VN local switching", Sessions: []Session{S4(p), S5(p)}},
		{Number: 6, Name: "indirect data forwarding", Sessions: []Session{S10(p)}},
	}
}
