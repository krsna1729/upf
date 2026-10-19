// SPDX-License-Identifier: BSD-3-Clause
// The Error Indication Report (TS 29.244 5.10): what the SMF is told when the
// peer's GTP-U says it cannot reach a tunnel this UPF sends into. The
// indication arrives on N3 and is counted by the responder behind the TEID
// table's default gate (datapath/gtpu_responder.cc, "get_errors"); this side
// reads that table once per tick (Config.GTPUErrors) and reports every count it
// has not reported before, as the remote F-TEID the FAR sends with.
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

// outboundTEIDs are the tunnels this session sends into, low TEID first: the
// F-TEIDs its FARs carry, which are the TEIDs an Error Indication about this
// session names. A FAR with no outer header sends into no tunnel, and a FAR
// whose TEID is zero is one whose record has not been written yet, so neither
// is in the list.
func outboundTEIDs(s *Session) []ErrorIndication {
	out := make([]ErrorIndication, 0, len(s.FARs))
	for _, f := range s.FARs {
		if f.hasOuter && f.teid != 0 {
			out = append(out, ErrorIndication{TEID: f.teid, Addr: f.peer})
		}
	}
	slices.SortFunc(out, func(a, b ErrorIndication) int { return cmp.Compare(a.TEID, b.TEID) })
	return out
}

// errorReports is the Error Indication Reports one session owes its SMF, from
// one tick's reading of the responder's table: the tunnels the peer reported
// that this session has not been reported about yet. One report carries them
// all -- several Error Indication Report IEs in one message is one report of
// the Report Type's ERIR bit (7.5.8.4) -- and the session's high-water marks
// move with it, so the next tick reports only what arrived since.
//
// The guard is judge's: the reading happened outside the lock, and a report
// about a session the SMF no longer has would be worse than none.
func (c *Compiler) errorReports(seid uint64, s *Session, indications map[uint32]uint64) []Report {
	if len(indications) == 0 {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sessions[seid] != s {
		return nil
	}
	var owed []ErrorIndication
	for _, tunnel := range outboundTEIDs(s) {
		count, seen := indications[tunnel.TEID]
		if !seen || count <= s.erirSent[tunnel.TEID] {
			continue
		}
		if s.erirSent == nil {
			s.erirSent = map[uint32]uint64{}
		}
		s.erirSent[tunnel.TEID] = count
		owed = append(owed, tunnel)
	}
	if len(owed) == 0 {
		return nil
	}
	return []Report{{
		SEID:   s.LocalSEID,
		CPSEID: s.CPSEID,
		Errors: owed,
	}}
}
