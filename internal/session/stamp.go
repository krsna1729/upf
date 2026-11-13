// SPDX-License-Identifier: BSD-3-Clause

package session

import "time"

// stamp is a time held in 8 bytes instead of time.Time's 24: nanoseconds after
// stampBase, a reading with a monotonic clock, and 0 for the zero time. A
// stamp taken from time.Now() keeps the monotonic reading, so the distance
// between two stamps -- a quota's duration -- does not move with the wall
// clock; its wall time is stampBase's plus that distance, which does not follow
// a wall-clock step made after start. A wall-only time (the dataplane's packet
// stamps) comes back with the same wall time it went in with.
type stamp int64

var stampBase = time.Now()

func stampOf(t time.Time) stamp {
	if t.IsZero() {
		return 0
	}
	if s := stamp(t.Sub(stampBase)); s != 0 {
		return s
	}
	return 1 // stampBase itself: 1 ns later rather than the zero time
}

func (s stamp) time() time.Time {
	if s == 0 {
		return time.Time{}
	}
	return stampBase.Add(time.Duration(s))
}

func (s stamp) IsZero() bool { return s == 0 }
