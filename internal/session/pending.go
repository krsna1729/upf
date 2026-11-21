// SPDX-License-Identifier: BSD-3-Clause

package session

// sessionChanges retains records replaced or removed by a transaction until
// its outcome is known. Idle sessions need none of these slice headers. The
// PDRs are slab handles the session's model owns (slab.go): settle frees
// them once the dataplane took the transaction.
type sessionChanges struct {
	removed, stale         []uint32
	removedMARs            []*mar
	retiredTunnels, ending []uint32
}

func (s *Session) changes() *sessionChanges {
	if s.pending == nil {
		s.pending = &sessionChanges{}
	}
	return s.pending
}

func (p *sessionChanges) removedPDRs() []uint32 {
	if p == nil {
		return nil
	}
	return p.removed
}

func (p *sessionChanges) stalePDRs() []uint32 {
	if p == nil {
		return nil
	}
	return p.stale
}

func (p *sessionChanges) removedPolicies() []*mar {
	if p == nil {
		return nil
	}
	return p.removedMARs
}

func (p *sessionChanges) retiredIDs() []uint32 {
	if p == nil {
		return nil
	}
	return p.retiredTunnels
}

func (p *sessionChanges) endingFlows() []uint32 {
	if p == nil {
		return nil
	}
	return p.ending
}

// keepStale makes old, a PDR's form before an in-place change, one of the
// replaced forms the next transaction erases, in a slot of its own.
func (c *Compiler) keepStale(s *Session, old pdr) error {
	h, _, err := c.recs.pdrs.alloc(old)
	if err != nil {
		return err
	}
	s.changes().stale = append(s.changes().stale, h)
	return nil
}

// gonePDRs appends the removed and replaced PDRs of s to out.
func (s *Session) gonePDRs(out []*pdr) []*pdr {
	out = s.rs.pdrs.resolve(out, s.pending.removedPDRs())
	return s.rs.pdrs.resolve(out, s.pending.stalePDRs())
}
