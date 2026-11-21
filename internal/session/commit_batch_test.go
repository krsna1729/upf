package session

import (
	"context"
	"errors"
	"reflect"
	"runtime"
	"testing"
	"time"

	sdk "github.com/krsna1729/bess/sdk/go/bess"
	"github.com/krsna1729/upf/internal/bess"
	"google.golang.org/grpc/codes"
)

type batchApplier func(context.Context, ...bess.Change) error

func (a batchApplier) Apply(ctx context.Context, changes ...bess.Change) error {
	return a(ctx, changes...)
}

func TestSessionCommitBatchesAndPreservesOutcomes(t *testing.T) {
	unknown := &bess.TransportError{RequestID: "batch"}
	memory := &bess.InvalidRequestError{Code: codes.ResourceExhausted}
	for _, tc := range []struct {
		name      string
		refusal   error
		wantCalls [][]uint32
	}{
		{"success", nil, [][]uint32{{5, 6, 7}}},
		{"indexed", &bess.RejectedError{Failures: []sdk.OpFailure{{Index: 1, Error: "collision"}}}, [][]uint32{{5, 6, 7}, {5}, {7}}},
		{"memory", memory, [][]uint32{{5, 6, 7}, {5}, {6}, {7}}},
		{"busy", &bess.BusyError{}, [][]uint32{{5, 6, 7}, {5}, {6}, {7}}},
		{"unknown", unknown, [][]uint32{{5, 6, 7}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b sessionCommits
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			started := make(chan uint32, sessionCommitLanes)
			var gates [sessionCommitLanes]chan struct{}
			for i := range gates {
				gates[i] = make(chan struct{})
			}
			calls := make(chan []uint32, sessionCommitWidth+1)
			ap := batchApplier(func(ctx context.Context, changes ...bess.Change) error {
				ids := make([]uint32, 0, len(changes))
				for _, ch := range changes {
					key, _ := bess.Get[SessionKey](ch.Key)
					ids = append(ids, key.SessionID)
				}
				if ids[0] <= sessionCommitLanes {
					started <- ids[0]
					select {
					case <-gates[ids[0]-1]:
						return nil
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				calls <- ids
				if len(ids) > 1 {
					return tc.refusal
				}
				if ids[0] == 6 && tc.name == "memory" {
					return memory
				}
				return nil
			})
			run := func(id uint32) <-chan error {
				done := make(chan error, 1)
				go func() {
					done <- b.apply(ctx, ap, id, []bess.Change{{Key: bess.Fields(SessionKey{SessionID: id})}})
				}()
				return done
			}
			var direct [sessionCommitLanes]<-chan error
			for i := range direct {
				direct[i] = run(uint32(i + 1))
				select {
				case <-started:
				case <-ctx.Done():
					t.Fatal("lone caller waited to fill a batch")
				}
			}
			var grouped [3]<-chan error
			for i := range grouped {
				grouped[i] = run(uint32(i + 5))
				for {
					b.mu.Lock()
					queued := b.n
					b.mu.Unlock()
					if queued == i+1 {
						break
					}
					if ctx.Err() != nil {
						t.Fatal("caller did not queue behind outstanding writes")
					}
					runtime.Gosched()
				}
			}
			close(gates[0])
			for i, done := range grouped {
				select {
				case err := <-done:
					var rejected *bess.RejectedError
					switch {
					case tc.name == "unknown":
						if err != unknown {
							t.Fatalf("member %d lost the common receipt: %v", i, err)
						}
					case tc.name == "indexed" && i == 1:
						if !errors.As(err, &rejected) || len(rejected.Failures) != 1 || rejected.Failures[0].Error != "collision" {
							t.Fatalf("culprit: %v", err)
						}
					case tc.name == "memory" && i == 1:
						if err != memory {
							t.Fatalf("culprit: %v", err)
						}
					default:
						if err != nil {
							t.Fatalf("collateral member %d: %v", i, err)
						}
					}
				case <-ctx.Done():
					t.Fatal("group did not deliver outcomes")
				}
			}
			for i := 1; i < len(gates); i++ {
				close(gates[i])
			}
			for _, done := range direct {
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			}
			var got [][]uint32
			for len(calls) != 0 {
				got = append(got, <-calls)
			}
			if !reflect.DeepEqual(got, tc.wantCalls) {
				t.Fatalf("transactions = %v, want %v", got, tc.wantCalls)
			}
		})
	}
}

func TestSessionCommitOrdersTheSameKeyAndDropsCancelledWaiter(t *testing.T) {
	var b sessionCommits
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first := make(chan struct{})
	release := make(chan struct{})
	second := make(chan int, 2)
	ap := batchApplier(func(ctx context.Context, changes ...bess.Change) error {
		if changes[0].Value == nil {
			close(first)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		second <- len(changes)
		return nil
	})
	run := func(ctx context.Context, upsert bool) <-chan error {
		done := make(chan error, 1)
		ch := bess.Change{Key: bess.Fields(SessionKey{SessionID: 42})}
		if upsert {
			ch.Value = bess.Fields(SessionKey{SessionID: 42})
		}
		go func() { done <- b.apply(ctx, ap, 42, []bess.Change{ch}) }()
		return done
	}
	a := run(ctx, false)
	select {
	case <-first:
	case <-ctx.Done():
		t.Fatal("first write did not start")
	}
	queued := func() {
		t.Helper()
		for ctx.Err() == nil {
			b.mu.Lock()
			n := b.n
			b.mu.Unlock()
			if n == 1 {
				return
			}
			runtime.Gosched()
		}
		t.Fatal("same-key write was not queued")
	}
	waiterCtx, stop := context.WithCancel(ctx)
	defer stop()
	waiter := run(waiterCtx, true)
	queued()
	stop()
	if err := <-waiter; !errors.Is(err, context.Canceled) {
		t.Fatalf("queued cancellation: %v", err)
	}
	next := run(ctx, true)
	queued()
	close(release)
	if err := <-a; err != nil {
		t.Fatal(err)
	}
	if err := <-next; err != nil {
		t.Fatal(err)
	}
	if len(second) != 1 || <-second != 1 {
		t.Fatal("expected one single write after the first completed")
	}
}
