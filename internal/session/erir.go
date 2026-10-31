// SPDX-License-Identifier: BSD-3-Clause
// The indication arrives on N3/N9 and is logged by the GTP-U responder on
// `GtpuDecap` gate 2 (datapath/gtpu_responder.cc, "drain_errors"). This side
// drains that log once per tick (Config.GTPUErrors) and reports each indication
// as the remote F-TEID the FAR sends with.
package session

import (
	"cmp"
	"net/netip"
	"slices"
)

// ErrorIndication is one tunnel loss as the peer named it: the remote F-TEID
// of an Error Indication the responder recorded (TS 29.281 7.3.1). TEID is the
// one this UPF sends into that tunnel with -- the one the peer could not reach
// -- and Addr is the address it sends to, so the SMF is told which of the
// session's tunnels is gone.
type ErrorIndication struct {
	TEID uint32
	Addr netip.Addr
}

// errorReports is the Error Indication Report one session owes its SMF from
// one tick's drain of the responder's log: the tunnels this session sends into
// -- the F-TEIDs its FARs carry, low TEID first -- that the peer reported since
// the last drain. One report carries them all: several Error Indication Report
// IEs in one message is one report of the Report Type's ERIR bit (7.5.8.4). A
// FAR with no outer header sends into no tunnel, and one whose TEID is zero has
// no record written yet, so neither is matched. A session none of whose tunnels
// was reported costs no allocation.
//
// The guard is judge's: the drain happened outside the lock, and a report
// about a session the SMF no longer has would be worse than none.
func (c *Compiler) errorReports(seid uint64, s *Session, indications map[uint32]bool) []Report {
	if len(indications) == 0 {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sessions[seid] != s {
		return nil
	}
	var owed []ErrorIndication
	for _, f := range s.FARs {
		if f.hasOuter && f.teid != 0 && indications[f.teid] {
			owed = append(owed, ErrorIndication{TEID: f.teid, Addr: f.peer})
		}
	}
	if len(owed) == 0 {
		return nil
	}
	slices.SortFunc(owed, func(a, b ErrorIndication) int { return cmp.Compare(a.TEID, b.TEID) })
	return []Report{{
		SEID:   s.LocalSEID,
		CPSEID: s.CPSEID,
		Errors: owed,
	}}
}
