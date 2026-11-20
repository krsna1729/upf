// SPDX-License-Identifier: BSD-3-Clause
package bess

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/types/known/anypb"
)

// RuleChangePage is one replayable page of traffic notifications. ActionIDs may
// repeat across worker planes. NextAfter is opaque; zero completes Sequence.
// A caller acknowledges only after it has queued every page's work, including
// work whose subsequent counter reading or enforcement must be retried.
type RuleChangePage struct {
	Sequence, NextAfter uint64
	ActionIDs           []uint32
}

// A snapshot's reads answer busy until every worker has passed a batch boundary
// since the plugin flipped its bank (datapath/counter_changes.h): the plugin
// never waits for the grace period, as it runs under the daemon's control lock.
// A grace period is about 11 µs or one task invocation, so the backoff starts
// where the daemon's own for a BUSY transaction does (kBusyFirstBackoff,
// 200 µs) and doubles. After changesBusyAttempts the error goes to the caller;
// its next tick asks again, and the snapshot stays frozen, so nothing is lost.
const (
	changesBusyFirstBackoff = 200 * time.Microsecond
	changesBusyAttempts     = 8
)

// retryBusy calls invoke until it answers something other than *BusyError,
// at most changesBusyAttempts times, sleeping between attempts.
func retryBusy(ctx context.Context, invoke func() (*anypb.Any, error)) (*anypb.Any, error) {
	backoff := changesBusyFirstBackoff
	for attempt := 1; ; attempt++ {
		result, err := invoke()
		var busy *BusyError
		if !errors.As(err, &busy) || attempt == changesBusyAttempts {
			return result, err
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
		backoff *= 2
	}
}

// AppendRuleChanges appends one page to dst. acknowledge is the last snapshot
// fully queued by this consumer; sequence and after are zero for the first page.
func (c *Client) AppendRuleChanges(ctx context.Context, dst []uint32, counters string,
	acknowledge, sequence, after uint64) (RuleChangePage, error) {
	module, table, _ := strings.Cut(counters, "/")
	fields := map[string]any{"acknowledge": acknowledge, "sequence": sequence, "after": after}
	if table != "" {
		fields["table"] = table
	}
	arg, _, err := c.wire(nil, "upf.pb.UrrCountCommandGetChangesArg", fields)
	if err != nil {
		return RuleChangePage{}, err
	}
	result, err := retryBusy(ctx, func() (*anypb.Any, error) {
		return c.sdk.InvokeAction(ctx, module, "get_changes", arg)
	})
	if err != nil {
		return RuleChangePage{}, fmt.Errorf("bess: %s get_changes: %w", counters, err)
	}
	if result.MessageName() != "upf.pb.UrrCountCommandGetChangesResponse" {
		return RuleChangePage{}, fmt.Errorf("bess: %s get_changes answered %s", counters, result.GetTypeUrl())
	}
	page, err := appendChanges(dst, result.GetValue())
	if err != nil {
		return RuleChangePage{}, fmt.Errorf("bess: %s get_changes: %w", counters, err)
	}
	return page, nil
}

func appendChanges(dst []uint32, raw []byte) (RuleChangePage, error) {
	page := RuleChangePage{ActionIDs: dst}
	for len(raw) != 0 {
		num, typ, value, packed, n := consumeField(raw)
		if n < 0 {
			return RuleChangePage{}, protowire.ParseError(n)
		}
		raw = raw[n:]
		switch {
		case num == 1 && typ == protowire.VarintType:
			page.Sequence = value
		case num == 3 && typ == protowire.VarintType:
			page.NextAfter = value
		case num == 2 && typ == protowire.VarintType:
			page.ActionIDs = append(page.ActionIDs, uint32(value))
		case num == 2 && typ == protowire.BytesType:
			for len(packed) != 0 {
				id, used := protowire.ConsumeVarint(packed)
				if used < 0 {
					return RuleChangePage{}, protowire.ParseError(used)
				}
				page.ActionIDs = append(page.ActionIDs, uint32(id))
				packed = packed[used:]
			}
		}
	}
	if page.Sequence == 0 {
		return RuleChangePage{}, fmt.Errorf("missing counter snapshot sequence")
	}
	return page, nil
}
