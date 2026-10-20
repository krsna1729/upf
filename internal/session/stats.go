// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"sync/atomic"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// counters is what the compiler counts about its own work: the numbers a
// management endpoint reports. They are the SMF's view of this node -- what it
// asked for and what it was told -- and each is one of the facts this layer
// owns; the dataplane's own counters are the graph's (upfd reports the usage
// ones to the SMF as PFCP Session Reports).
type counters struct {
	established atomic.Uint64
	modified    atomic.Uint64
	deleted     atomic.Uint64
	// refused counts the requests answered with a cause other than accepted.
	// A retransmitted establishment or deletion is not one of them: the answer
	// repeats what the SMF already had.
	refused atomic.Uint64
	// markers counts the End Marker packets this UPF constructed and sent
	// (TS 29.244 5.3.2, on the SNDEM flag); markerFailures counts the ones the
	// graph's port would not take, which is an operator's signal that the
	// marker path -- the graph's unix_port -- is not there.
	markers        atomic.Uint64
	markerFailures atomic.Uint64
	// buffersReleased, buffersDropped and bufferFailures count the store
	// commands a buffering flow's instruction produced (5.2.4.1): the releases
	// and the drops the daemon accepted, and the ones it refused -- the last is
	// an operator's signal that the graph's store would not take the command. An
	// accepted command is not a completed one: the store's own task applies it on
	// a later run, so these count commands, and what the packets did is the
	// store's own readback (`ps/flows`, its drop and release counters).
	buffersReleased atomic.Uint64
	buffersDropped  atomic.Uint64
	bufferFailures  atomic.Uint64
}

// StatsSnapshot is the counters at one instant, copied out so a reader is
// served without holding the compiler's lock.
type StatsSnapshot struct {
	Sessions       int    // the sessions this compiler holds now
	Established    uint64 // establishments that became a session
	Modified       uint64 // modifications applied
	Deleted        uint64 // deletions applied
	Refused        uint64 // requests answered with a cause other than accepted
	Markers        uint64 // End Marker packets sent
	MarkerFailures uint64 // End Marker packets the graph's port refused
	// The buffering half: the release and drop commands the SMF's instruction
	// produced for buffering flows, and the commands the store refused. Counted
	// when the daemon accepted a command, not when the store applied it (the
	// store's own task does that on a later run).
	BuffersReleased uint64
	BuffersDropped  uint64
	BufferFailures  uint64
}

// Holds says whether the session layer still has this session. A report the
// reporting loop holds for one it does not is usage the session's termination
// report already carried (docs/claims.md, finding 20): sending it would
// tell the SMF the same usage twice, and an SMF mid-release may well accept it.
func (c *Compiler) Holds(seid uint64) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.sessions[seid]
	return ok
}

// Stats is what the session layer has done, and what it holds now. A node with
// no session layer at all (no -bess) reports zeros rather than panicking.
func (c *Compiler) Stats() StatsSnapshot {
	if c == nil {
		return StatsSnapshot{}
	}
	c.mu.Lock()
	sessions := len(c.sessions)
	c.mu.Unlock()
	return StatsSnapshot{
		Sessions:        sessions,
		Established:     c.stats.established.Load(),
		Modified:        c.stats.modified.Load(),
		Deleted:         c.stats.deleted.Load(),
		Refused:         c.stats.refused.Load(),
		Markers:         c.stats.markers.Load(),
		BuffersReleased: c.stats.buffersReleased.Load(),
		BuffersDropped:  c.stats.buffersDropped.Load(),
		BufferFailures:  c.stats.bufferFailures.Load(),
		MarkerFailures:  c.stats.markerFailures.Load(),
	}
}

// answerCause is the Cause a session-level response carries, or 0 for a
// response that carries none: a malformed answer is not a refusal, and saying
// it was one would put a number on the endpoint that nothing measured.
func answerCause(resp message.Message) uint8 {
	var i *ie.IE
	switch v := resp.(type) {
	case *message.SessionEstablishmentResponse:
		i = v.Cause
	case *message.SessionModificationResponse:
		i = v.Cause
	case *message.SessionDeletionResponse:
		i = v.Cause
	default:
		return 0
	}
	if i == nil {
		return 0
	}
	cause, err := i.Cause()
	if err != nil {
		return 0
	}
	return cause
}
