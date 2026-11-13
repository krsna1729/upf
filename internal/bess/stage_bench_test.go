// SPDX-License-Identifier: BSD-3-Clause

package bess

import (
	"context"
	"encoding/binary"
	"fmt"
	"testing"
)

// BenchmarkStageApply feeds the generic stage fixture through upfd's real
// map-to-wire adapter and public SDK transaction path. It excludes PFCP/model
// compilation. Create the idle eight-stage graph with bessbench -stage-graph-only,
// then select -run '^$' -bench '^BenchmarkStageApply$' with UPF_BESS_TARGET set.
// This benchmark must not run against the session-live graph.
func BenchmarkStageApply(b *testing.B) {
	for _, locality := range []string{"hot", "spread"} {
		for _, stages := range []int{1, 2, 3, 4, 8} {
			b.Run(fmt.Sprintf("%s/stages%d", locality, stages), func(b *testing.B) {
				c := liveClient(b)
				ctx := context.Background()
				var key [4]byte
				keyFields := map[string]any{"fields": []any{map[string]any{"value_bin": key[:]}}}
				value := map[string]any{"gate": uint64(1)}
				changes := make([]Change, 8)
				for i := range changes {
					changes[i] = Change{Resource: fmt.Sprintf("stage%d/rules", i), Key: keyFields, Value: value}
				}
				// All eight stages retain 1024 entries, independent of prefix size.
				for slot := 0; slot < 1024; slot++ {
					binary.BigEndian.PutUint32(key[:], 0x0b000001+uint32(slot))
					if err := c.Apply(ctx, changes...); err != nil {
						b.Fatal(err)
					}
				}
				set := func(ordinal int) {
					slot, period := 0, 1
					if locality == "spread" {
						slot, period = ordinal%1024, 1024
					}
					binary.BigEndian.PutUint32(key[:], 0x0b000001+uint32(slot))
					value["gate"] = uint64(2 - (ordinal/period)%2)
				}
				set(0)
				if err := c.Apply(ctx, changes[:stages]...); err != nil {
					b.Fatal(err)
				}
				ordinal := 1
				b.ReportAllocs()
				for b.Loop() {
					set(ordinal)
					if err := c.Apply(ctx, changes[:stages]...); err != nil {
						b.Fatal(err)
					}
					ordinal++
				}
				b.ReportMetric(float64(stages), "stages/transaction")
			})
		}
	}
}
