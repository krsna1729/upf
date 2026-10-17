// SPDX-License-Identifier: BSD-3-Clause

package bess

import (
	"testing"
	"time"
)

// TestPacketTimePlacesAStampOnTheWallClock pins the conversion the counting
// module's stamps need: they are nanoseconds of the module's monotonic clock,
// and the reading carries the wall clock it read at, which is what an SMF's
// Time of First/Last Packet (TS 29.244 8.2.44, 8.2.45) is measured against.
// Both zeros and stamps older than the reading are unknown, never an instant.
func TestPacketTimePlacesAStampOnTheWallClock(t *testing.T) {
	wall := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	const mono = 600_000_000_000 // ten minutes into the daemon's monotonic clock
	cases := []struct {
		name  string
		stamp uint64
		want  time.Time
	}{
		{"a packet before the reading", mono - 250_000_000, wall.Add(-250 * time.Millisecond)},
		{"a packet at the reading's own instant", mono, wall},
		{"a packet stamped as the reading ran", mono + 1000, wall.Add(time.Microsecond)},
		{"no packet counted", 0, time.Time{}},
		{"the previous window's last packet (a reissued id)", mono - 60_000_000_000, wall.Add(-time.Minute)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := packetTime(c.stamp, mono, wall.UnixNano()); !got.Equal(c.want) {
				t.Errorf("packetTime(%d) = %v, want %v", c.stamp, got, c.want)
			}
		})
	}
}
