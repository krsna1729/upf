// SPDX-License-Identifier: BSD-3-Clause
package bess

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/protobuf/types/known/anypb"
)

// The plugin answers a snapshot's reads busy until its grace period has
// passed, rather than waiting under the daemon's control lock: the read is
// retried until it answers, a bounded number of times, and never past the
// caller's context. Any other error is not retried.
func TestActivityReadsRetryWhileTheSnapshotIsBusy(t *testing.T) {
	page := &anypb.Any{TypeUrl: "type.googleapis.com/upf.pb.UrrCountCommandGetChangesResponse"}
	answers := func(busy int, last error) (func() (*anypb.Any, error), *int) {
		calls := 0
		return func() (*anypb.Any, error) {
			calls++
			if calls <= busy {
				return nil, &BusyError{Attempts: 1}
			}
			if last != nil {
				return nil, last
			}
			return page, nil
		}, &calls
	}

	invoke, calls := answers(2, nil)
	if got, err := retryBusy(context.Background(), invoke); err != nil || got != page || *calls != 3 {
		t.Fatalf("two busy answers then a page: got %v, %v after %d calls, want the page after 3", got, err, *calls)
	}

	invoke, calls = answers(changesBusyAttempts+5, nil)
	var busy *BusyError
	if _, err := retryBusy(context.Background(), invoke); !errors.As(err, &busy) || *calls != changesBusyAttempts {
		t.Fatalf("a snapshot that stays busy: %v after %d calls, want *BusyError after %d", err, *calls, changesBusyAttempts)
	}

	refused := errors.New("snapshot sequence is not current")
	invoke, calls = answers(0, refused)
	if _, err := retryBusy(context.Background(), invoke); !errors.Is(err, refused) || *calls != 1 {
		t.Fatalf("a refusal: %v after %d calls, want it after 1", err, *calls)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	invoke, calls = answers(changesBusyAttempts, nil)
	if _, err := retryBusy(ctx, invoke); !errors.Is(err, context.Canceled) || *calls != 1 {
		t.Fatalf("a cancelled caller: %v after %d calls, want context.Canceled after 1", err, *calls)
	}
}

func TestMalformedActivityCannotReturnAnAcknowledgableSnapshot(t *testing.T) {
	for name, raw := range map[string][]byte{
		"missing sequence":    {0x12, 0x01, 0x01},
		"truncated sequence":  {0x08, 0x80},
		"truncated packed id": {0x08, 0x01, 0x12, 0x01, 0x80},
		"truncated next page": {0x08, 0x01, 0x12, 0x01, 0x01, 0x18, 0x80},
	} {
		t.Run(name, func(t *testing.T) {
			page, err := appendChanges(nil, raw)
			if err == nil || page.Sequence != 0 || len(page.ActionIDs) != 0 {
				t.Fatalf("malformed activity could be scheduled/acknowledged: %+v, %v", page, err)
			}
		})
	}
}
