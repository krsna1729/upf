// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/krsna1729/upf/internal/bess"
	"github.com/krsna1729/upf/internal/n4sim"
	"github.com/wmnsk/go-pfcp/message"
)

// stageCapture isolates compiler work. It records actual output, not native
// application, and supplies zero-traffic readings rather than charging an RPC
// to this boundary. Live/N4 runs use the real client's counter actions instead.
type stageCapture struct{ last []bess.Change }

func (s *stageCapture) Apply(_ context.Context, changes ...bess.Change) error {
	s.last = changes
	return nil
}

func (*stageCapture) AppendRuleCounts(_ context.Context, dst []bess.RuleCount, _ string, ids ...uint32) ([]bess.RuleCount, error) {
	for _, id := range ids {
		dst = append(dst, bess.RuleCount{ActionID: id})
	}
	return dst, nil
}

func (*stageCapture) AppendRuleChanges(_ context.Context, dst []uint32, _ string, _, _, _ uint64) (bess.RuleChangePage, error) {
	return bess.RuleChangePage{Sequence: 1, ActionIDs: dst}, nil
}

// BenchmarkStageCompiler is an establish/delete cycle with prepared PFCP input.
// It is NOT the generic seeded ExactMatch replacement floor. Each establishment
// must emit exactly one upsert in each of the requested distinct graph stages.
// With no native consumer, immediate ID reuse is safe here; native retirement
// and the product's normal one-second reuse margin belong to the live boundary.
func BenchmarkStageCompiler(b *testing.B) {
	for _, stages := range []int{1, 2, 3, 4, 8} {
		b.Run(fmt.Sprintf("stages%d", stages), func(b *testing.B) {
			capture := &stageCapture{}
			cfg := testConfig()
			cfg.IDReuseDelay = time.Nanosecond
			c := New(cfg, capture, slog.New(slog.NewTextHandler(os.Stderr,
				&slog.HandlerOptions{Level: slog.LevelWarn})))
			req, err := n4sim.StageEstablish(1, n4sim.Session{CPSEID: 0x5000,
				UEIP: "10.45.0.1", FTEID: 0x100001, N3IP: "192.0.2.1",
				TEID: 0x200001, GnBIP: "10.20.30.2"}, stages)
			if err != nil {
				b.Fatal(err)
			}
			cycle := func(check bool) {
				resp := c.Establish(req)
				if answerCause(resp) != 1 {
					b.Fatalf("establish cause %d: %#v", answerCause(resp), resp)
				}
				if check {
					resources := map[string]bool{}
					for _, ch := range capture.last {
						if ch.Value == nil || resources[ch.Resource] {
							b.Fatalf("not one upsert per stage: %#v", capture.last)
						}
						resources[ch.Resource] = true
					}
					if len(resources) != stages {
						b.Fatalf("requested %d stages; compiler emitted %v", stages, resources)
					}
					b.Logf("actual graph resources: %v", resources)
				}
				est := resp.(*message.SessionEstablishmentResponse)
				fseid, err := est.UPFSEID.FSEID()
				if err != nil {
					b.Fatal(err)
				}
				if del := c.Delete(n4sim.Delete(2, fseid.SEID)); answerCause(del) != 1 {
					b.Fatalf("delete: %#v", del)
				}
			}
			cycle(true)
			b.ReportAllocs()
			for b.Loop() {
				cycle(false)
			}
			b.ReportMetric(float64(stages), "stages/transaction")
			b.ReportMetric(2, "transactions/cycle")
		})
	}
}
