// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/bess"
	"github.com/krsna1729/upf/internal/n4sim"
)

// liveCompiler dials the daemon ci/session-live.sh started and returns a compiler
// on the graph it applied, with the client behind it. The environment names the
// daemon's control endpoint.
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

// recordingApplier keeps the last transaction the compiler handed over, so a
// benchmark can work on exactly those changes instead of on types it picked.
type recordingApplier struct {
	inner Applier
	last  []bess.Change
}

func (r *recordingApplier) Apply(ctx context.Context, changes ...bess.Change) error {
	r.last = append(r.last[:0], changes...)
	return r.inner.Apply(ctx, changes...)
}

// BenchmarkLiveChangesToMessages converts the changes one establishment produced:
// every key and every value, by their real field maps -- the work Client.Apply
// does before it commits. It is the session-shaped counterpart of internal/bess's
// per-type BenchmarkLiveMessage, and the number to quote for a session's
// conversion rather than whichever type a graph happened to declare first.
func BenchmarkLiveChangesToMessages(b *testing.B) {
	c := liveCompiler(b)
	client, ok := c.ap.(*bess.Client)
	if !ok {
		b.Fatalf("the compiler's applier is %T, not the live client", c.ap)
	}
	rec := &recordingApplier{inner: c.ap}
	c.ap = rec

	// One real session, through the real client once: what it produced is what
	// this benchmark converts. Numbered from the clock, because a run whose
	// cleanup failed must not collide with the next one.
	base := uint64(time.Now().UnixNano()%1_000_000) * 1000
	first := c.Establish(establishment(base+1, "10.250.0.2"))
	est, ok := first.(*message.SessionEstablishmentResponse)
	if !ok {
		b.Fatalf("no establishment response: %#v", first)
	}
	upSEID := upFSEID(b, est)
	b.Cleanup(func() {
		c.Delete(message.NewSessionDeletionRequest(0, 0, upSEID, 3, 0))
	})

	changes := append([]bess.Change(nil), rec.last...)
	if len(changes) == 0 {
		b.Fatal("the establishment produced no changes")
	}

	// Resolve each change's resource once; the conversion is what is timed.
	// Apply converts a singleton's value alone (it has no key), so the loop does
	// the same: count and convert a key only where one exists.
	type step struct {
		keyType, valueType string
		key, value         map[string]any
	}
	steps := make([]step, 0, len(changes))
	messages := 0
	for _, ch := range changes {
		r, err := client.Resource(ch.Resource)
		if err != nil {
			b.Fatalf("resource %q: %v", ch.Resource, err)
		}
		steps = append(steps, step{keyType: r.KeyType, valueType: r.ValueType,
			key: ch.Key, value: ch.Value})
		if ch.Key != nil {
			messages++
		}
		if ch.Value != nil {
			messages++
		}
	}

	b.ReportAllocs()
	for b.Loop() {
		for _, s := range steps {
			if s.key != nil {
				if _, err := client.Message(s.keyType, s.key); err != nil {
					b.Fatal(err)
				}
			}
			if s.value == nil {
				continue
			}
			if _, err := client.Message(s.valueType, s.value); err != nil {
				b.Fatal(err)
			}
		}
	}
	// After the loop: the first b.Loop resets the timer and clears metrics
	// reported before it.
	b.ReportMetric(float64(messages), "messages/op")
}

// applyTimer wraps the real client to time the transactions it is given, so the
// benchmark can report what the compile costs and what the transaction path --
// our conversion of every change, the RPC and the daemon -- costs. The wrapper
// is the Applier the compiler is built with, so the two are measured by the same
// run.
type applyTimer struct {
	inner Applier
	total time.Duration
	calls int
	durs  []time.Duration
}

func (a *applyTimer) Apply(ctx context.Context, changes ...bess.Change) error {
	start := time.Now()
	err := a.inner.Apply(ctx, changes...)
	d := time.Since(start)
	a.total += d
	a.calls++
	a.durs = append(a.durs, d)
	return err
}

// logApplyHistogram prints where the transactions landed, in buckets of the
// daemon's own first backoff (kBusyFirstBackoff, 200 µs, doubled per retry). A
// total that sits at 1.4 or 3 ms without the sleeps would hide the shape; this
// is what tells a slow RPC apart from a transaction that was answered BUSY and
// slept server-side before it ran.
func logApplyHistogram(b *testing.B, durs []time.Duration) {
	const quantum = 200 * time.Microsecond
	buckets := map[int64]int{}
	for _, d := range durs {
		buckets[int64(d/quantum)]++
	}
	keys := make([]int64, 0, len(buckets))
	for k := range buckets {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		// k counts quanta, so the bucket spans k*quantum to (k+1)*quantum.
		lo, hi := time.Duration(k)*quantum, time.Duration(k+1)*quantum
		b.Logf("apply %6v-%6v: %d of %d", lo, hi, buckets[k], len(durs))
	}
}

// BenchmarkLiveEstablish is the whole control path with nothing faked: the
// compiler builds the transaction, the SDK sends it to a running bessd, and the
// daemon answers. It reports the transaction's share separately ("apply-ns/op"),
// because the compile alone has its own benchmark and the difference is where a
// session's time actually sits.
//
// Sessions are numbered from the clock so that a second run does not re-establish
// what the first left behind, and they are deleted again afterwards.
func BenchmarkLiveEstablish(b *testing.B) {
	c := liveCompiler(b)
	timer := &applyTimer{inner: c.ap}
	c.ap = timer
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
		ups = append(ups, upFSEID(b, est))
	}
	b.StopTimer()

	if timer.calls == 0 {
		b.Fatal("no transaction was applied")
	}
	// The transaction's mean, next to the loop's own ns/op: the difference is
	// the compile, and both are per establishment.
	b.ReportMetric(float64(timer.total.Nanoseconds())/float64(timer.calls), "apply-ns/op")
	logApplyHistogram(b, timer.durs)

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
