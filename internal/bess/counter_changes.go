// SPDX-License-Identifier: BSD-3-Clause
package bess

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
)

// RuleChangePage is one replayable page of traffic notifications. ActionIDs may
// repeat across worker planes. NextAfter is opaque; zero completes Sequence.
// A caller acknowledges only after it has queued every page's work, including
// work whose subsequent counter reading or enforcement must be retried.
type RuleChangePage struct {
	Sequence, NextAfter uint64
	ActionIDs           []uint32
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
	result, err := c.sdk.InvokeAction(ctx, module, "get_changes", arg)
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
