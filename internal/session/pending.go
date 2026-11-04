// SPDX-License-Identifier: BSD-3-Clause

package session

import "slices"

// sessionChanges retains records replaced or removed by a transaction until
// its outcome is known. Idle sessions need none of these slice headers.
type sessionChanges struct {
	removed, stale         []*pdr
	removedMARs            []*mar
	retiredTunnels, ending []uint32
}

func (s *Session) changes() *sessionChanges {
	if s.pending == nil {
		s.pending = &sessionChanges{}
	}
	return s.pending
}

func (p *sessionChanges) removedPDRs() []*pdr {
	if p == nil {
		return nil
	}
	return p.removed
}

func (p *sessionChanges) stalePDRs() []*pdr {
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

func (p *sessionChanges) clone() *sessionChanges {
	if p == nil {
		return nil
	}
	return &sessionChanges{
		removed: slices.Clone(p.removed), stale: slices.Clone(p.stale),
		removedMARs:    slices.Clone(p.removedMARs),
		retiredTunnels: slices.Clone(p.retiredTunnels), ending: slices.Clone(p.ending),
	}
}
