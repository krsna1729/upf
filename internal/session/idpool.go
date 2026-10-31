package session

import (
	"errors"
	"math/rand/v2"
	"time"
)

// idPool hands out small ids and takes them back, so a long-lived UPF reuses
// the space the dataplane's fixed-size tables have.
//
// The walk is spread, not in order: the pool starts at a random point and steps
// by a random stride, so it visits the whole space once. Two reasons, both
// about the dataplane's slots. A transaction that removes a record leaves its
// slot retiring for a grace period and refuses a publish into it
// (core/dataplane/slot_table.h: CanPublish), and the engine's cascade of those
// periods is asynchronous: a compiler that reissued the ids it had just
// released got "the meter is still retiring (removed less than a grace period
// ago)", and the session established right after a deletion was refused. And a
// *new* compiler -- after a controller restart, replaying what the SMF sends
// again -- knows nothing of what the daemon still holds retiring, so it must
// not walk its predecessor's order either. A released id is reused only after
// the walk has come round (and then only once it has aged), which is far longer
// than any grace period.
//
// A pool with no grace (F-TEID contexts: internal ids, never on the wire)
// reuses a released id before the walk goes on, oldest released first. Its walk
// can be far longer than the life of the process (contexts span 2^31), and
// queuing every release until it came round grew the free list without bound.
type idPool struct {
	limit  uint32
	start  uint32 // where the walk began, and so where it is done
	next   uint32
	stride uint32
	inv    uint32 // stride's inverse modulo the span: an id's place in the walk
	walked bool   // the walk has visited every id once
	grace  time.Duration
	now    func() time.Time
	// freed is the released ids, oldest first; with a grace, dated by epochs.
	freed []uint32
	// epochs date freed in runs, oldest first: epochs[0] covers the first n
	// ids, and so on. An epoch spans at most a sixteenth of the grace and is
	// dated by its last release, so an id waits out the grace from no earlier
	// than its own release. Runs that have all aged are merged: the list stays
	// a few entries long however long the walk takes to come round.
	epochs []epoch
	// taken holds ids the pool must not hand out even though its own books say
	// nothing about them: an F-TEID an SMF pinned, which another session is
	// using right now. Pool-owned ids need no entry (the walk visits each once,
	// and a released one is aged before it is visited again).
	taken map[uint32]bool
	// released and releasedBits mark the ids waiting in freed: a session
	// releases an id once per PDR that names it, and the pool must not queue it
	// twice. A pool with a grace may hold most of its space until the walk comes
	// round, and its space is a dataplane table's: one bit per id. A pool with
	// none holds only the ids free right now, in a space that may be 2^31: a map.
	released     map[uint32]bool
	releasedBits []uint64
}

type epoch struct {
	n         int
	first, at time.Time
}

// newIDPool returns a pool of ids 1..limit-1 (the dataplane's slots are
// numbered from 1). The starting point and the stride are random; the stride is
// coprime with the space, so the walk visits every id.
func newIDPool(limit uint32, grace time.Duration) *idPool {
	p := &idPool{limit: limit, grace: grace, now: time.Now,
		taken: map[uint32]bool{}, released: map[uint32]bool{}}
	if limit < 2 {
		// No usable id at all (the slots are numbered from 1): the walk is
		// over before it starts, so alloc goes straight to the empty free list
		// and answers no-resources. A misconfigured -capacity must not panic in
		// the walk's arithmetic (limit 0 would underflow span).
		p.walked = true
		return p
	}
	span := limit - 1
	p.start = 1 + rand.Uint32N(span)
	p.next = p.start
	for {
		p.stride = 1 + rand.Uint32N(span)
		if gcd(p.stride, span) == 1 {
			p.inv = inverse(p.stride, span)
			return p
		}
	}
}

func gcd(a, b uint32) uint32 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// inverse is a's inverse modulo m, for a coprime with m.
func inverse(a, m uint32) uint32 {
	t, nt := int64(0), int64(1)
	r, nr := int64(m), int64(a)
	for nr != 0 {
		q := r / nr
		t, nt = nt, t-q*nt
		r, nr = nr, r-q*nr
	}
	if t < 0 {
		t += int64(m)
	}
	return uint32(t)
}

// advance is one step of the walk: ids stay in 1..limit-1.
func (p *idPool) advance(id uint32) uint32 {
	span := p.limit - 1
	if span < 1 {
		span = 1 // a pool with no ids: the walk is one step long
	}
	return 1 + (id-1+p.stride)%span
}

// passed is whether the walk has already visited id: it will not offer it
// again.
func (p *idPool) passed(id uint32) bool {
	if p.walked {
		return true
	}
	span := uint64(p.limit - 1)
	step := func(id uint32) uint64 {
		return (uint64(id) + span - uint64(p.start)) % span * uint64(p.inv) % span
	}
	return step(id) < step(p.next)
}

func (p *idPool) alloc() (uint32, error) {
	if p.grace == 0 {
		if id, ok := p.reuse(); ok {
			return id, nil
		}
	}
	// One walk of the space: an id released behind the walk waits for the
	// round trip, which is what keeps it out of circulation past the grace.
	// An id another session pinned is skipped wherever the walk meets it.
	for !p.walked {
		id := p.next
		p.next = p.advance(p.next)
		if p.next == p.start {
			p.walked = true
		}
		if !p.taken[id] {
			return id, nil
		}
	}
	// The walk is done: a released id, if one has aged.
	if id, ok := p.reuse(); ok {
		return id, nil
	}
	return 0, errors.New("id space exhausted")
}

// reuse takes a released id off the free list, if one has aged.
func (p *idPool) reuse() (uint32, bool) {
	for len(p.freed) != 0 {
		if p.grace != 0 && p.now().Sub(p.epochs[0].at) < p.grace {
			break
		}
		id := p.freed[0]
		p.freed = p.freed[1:]
		if p.grace == 0 {
			delete(p.released, id)
		} else {
			if p.epochs[0].n--; p.epochs[0].n == 0 {
				p.epochs = p.epochs[1:]
			}
			p.releasedBits[id/64] &^= 1 << (id % 64)
		}
		if !p.taken[id] {
			return id, true
		}
	}
	return 0, false
}

// queued is whether id waits in the free list.
func (p *idPool) queued(id uint32) bool {
	if p.grace == 0 {
		return p.released[id]
	}
	return p.releasedBits != nil && p.releasedBits[id/64]&(1<<(id%64)) != 0
}

// reserve keeps an id the pool did not hand out out of the walk: an F-TEID an
// SMF pinned. The walk visits each id once and never returns, so this matters
// twice: a pinned value must not be handed out while the session holds it, and
// once released (releaseSession) the value comes back only because release
// queues it or the walk has yet to reach it -- outside the pool's range neither
// offers it, which is what keeps 0x11223344 (a legal pin, an illegal
// allocation) out of the free list.
func (p *idPool) reserve(id uint32) {
	if id == 0 {
		return
	}
	p.taken[id] = true
}

// release takes back an id the pool handed out, or ends the reservation of one
// an SMF pinned. Either way the id is queued for allocation when it lies in the
// pool's own range and the walk has passed it: the walk visits each id once and
// never comes round again, so a value it passed while it was taken or reserved
// would otherwise be gone for the life of the pool -- the SMF that pinned it
// could not pin it again, and no other session could be given it. A pin the
// walk has yet to reach is the walk's to offer, and queuing it too would offer
// it twice. A value outside the range (0x11223344 is a legal pin and an
// illegal allocation) only ends its reservation: the range is what the
// deployment's peer expects to see in a TEID. A zero grace means an id may be
// reused at once (for an id with no retire period that never reaches the wire:
// an F-TEID context).
func (p *idPool) release(id uint32) {
	if id == 0 {
		return
	}
	delete(p.taken, id)
	if id >= p.limit || !p.passed(id) || p.queued(id) {
		return
	}
	p.freed = append(p.freed, id)
	if p.grace == 0 {
		p.released[id] = true
		return
	}
	if p.releasedBits == nil {
		p.releasedBits = make([]uint64, p.limit/64+1)
	}
	p.releasedBits[id/64] |= 1 << (id % 64)
	now := p.now()
	for len(p.epochs) > 1 && now.Sub(p.epochs[1].at) >= p.grace {
		p.epochs[1].n += p.epochs[0].n
		p.epochs = p.epochs[1:]
	}
	if n := len(p.epochs); n == 0 || now.Sub(p.epochs[n-1].first) >= p.grace/16 {
		p.epochs = append(p.epochs, epoch{first: now})
	}
	e := &p.epochs[len(p.epochs)-1]
	e.n++
	e.at = now
}
