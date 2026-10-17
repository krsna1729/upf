// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/bess"
	"github.com/krsna1729/upf/internal/n4sim"
)

// liveCompiler dials the daemon ci/session-live.sh started and returns a compiler
// on the graph it applied. The environment names the daemon's control endpoint.
func liveCompiler(tb testing.TB) *Compiler {
	tb.Helper()
	target := os.Getenv("UPF_BESS_TARGET")
	if target == "" {
		tb.Skip("set UPF_BESS_TARGET (ci/session-live.sh does) to run against a live bessd")
	}
	ctx := context.Background()
	client, err := bess.Dial(ctx, target)
	if err != nil {
		tb.Fatalf("dialing %s: %v", target, err)
	}
	tb.Cleanup(func() { client.Close() })
	if err := client.Refresh(ctx); err != nil {
		tb.Fatalf("reading the daemon's schema: %v", err)
	}
	return New(liveConfig(), client, slog.New(slog.NewTextHandler(os.Stderr,
		&slog.HandlerOptions{Level: slog.LevelWarn})))
}

// BenchmarkLiveEstablish is the whole control path with nothing faked: the
// compiler builds the transaction, the SDK sends it to a running bessd, and the
// daemon answers. It is the number the SMF's observed rate is made of, so it is
// the one to compare against an entry's own benchmarks: internal/session's
// BenchmarkEstablish (the compiler alone), internal/n4sim's
// BenchmarkBuildEstablish plus internal/n4's BenchmarkHandleEstablish (the two
// ends of the wire), and internal/bess's BenchmarkLiveMessage (the schema-driven
// message building).
//
// Sessions are numbered from the clock so that a second run does not re-establish
// what the first left behind, and they are deleted again afterwards.
func BenchmarkLiveEstablish(b *testing.B) {
	c := liveCompiler(b)
	base := uint64(time.Now().UnixNano()%1_000_000) * 1000
	ups := make([]uint64, 0, b.N)

	b.ReportAllocs()
	for b.Loop() {
		i := uint64(len(ups)) + 1
		req := establishment(base+i, fmt.Sprintf("10.%d.%d.%d",
			(base+i>>16)&0xff, (base+i>>8)&0xff, (base+i)&0xff))
		resp := c.Establish(req)
		est, ok := resp.(*message.SessionEstablishmentResponse)
		if !ok {
			b.Fatalf("no establishment response: %#v", resp)
		}
		if cause, err := n4sim.Cause(est); err != nil || cause != 1 {
			b.Fatalf("cause %d (err %v)", cause, err)
		}
		ups = append(ups, est.Header.SEID)
	}
	b.StopTimer()

	// Leave the daemon as it was found: these sessions are deleted on the way
	// out, and a failure to delete one is a leftover, not a benchmark failure.
	for _, up := range ups {
		resp := c.Delete(message.NewSessionDeletionRequest(0, 0, up, 3, 0))
		del, ok := resp.(*message.SessionDeletionResponse)
		if !ok {
			b.Logf("session %#x: the deletion answered %#v", up, resp)
			continue
		}
		if cause, err := n4sim.Cause(del); err != nil || cause != 1 {
			b.Logf("session %#x was not deleted: cause %d, err %v", up, cause, err)
		}
	}
}
