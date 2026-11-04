// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"fmt"
	"net/netip"
	"testing"
)

// identityKeys are the key shapes the compiler writes, with the variants a
// dedupe must treat as one entry (an id typed differently, a list typed
// differently, a map built in another order) and the ones it must not.
func identityKeys() []map[string]any {
	field := func(b ...byte) map[string]any { return map[string]any{"value_bin": b} }
	rule := func(v byte) map[string]any {
		return map[string]any{
			"values": []map[string]any{field(10, 0, 0, v), field(0, 0)},
			"masks":  []map[string]any{field(0xff, 0xff, 0xff, 0xff), field(0, 0)},
		}
	}
	ranged := rule(1)
	ranged["ranges"] = []map[string]any{{"field": uint32(1), "low": uint64(1000), "high": uint64(2000)}}
	return []map[string]any{
		{"action_id": uint32(7)},
		{"action_id": 7},
		{"action_id": uint64(7)},
		{"action_id": uint32(8)},
		{"id": uint32(7)},
		{"teid": uint32(7), "endpoint": uint32(1)},
		{"endpoint": uint32(1), "teid": uint32(7)},
		{"teid": uint32(7), "endpoint": uint32(2)},
		{"id": -1},
		{"id": int64(-1)},
		{"ids": []uint32{1, 2}},
		{"ids": []any{uint32(1), 2}},
		{"ids": []uint32{1}},
		{"ids": []uint32{}},
		{"ids": []any(nil)},
		{"blob": []byte{1, 2}},
		{"blob": []byte{}},
		{"name": "n3"},
		{"name": "n6"},
		{"flag": true},
		{"flag": false},
		{"one": map[string]any{}},
		{"one": map[string]any{"x": uint32(1)}},
		rule(1),
		rule(2),
		ranged,
		{},
	}
}

// changeID keeps the identity the dedupes compared with fmt.Sprint: two keys
// are one entry exactly where fmt printed them alike.
func TestChangeIDKeepsFmtsIdentity(t *testing.T) {
	keys := identityKeys()
	for i, a := range keys {
		for j, b := range keys {
			same := fmt.Sprint(a) == fmt.Sprint(b)
			if got := changeID("r", a) == changeID("r", b); got != same {
				t.Errorf("%v and %v: one identity %v, fmt printed them alike %v", a, b, got, same)
			}
			if i == j && changeID("r", a) == changeID("s", a) {
				t.Errorf("%v is one identity in two resources", a)
			}
		}
	}
}

// Where fmt printed two different entries alike -- a string holding fmt's own
// separators -- changeID keeps them apart: a dedupe on fmt's text would have
// dropped the second as a repeat of the first.
func TestChangeIDSeparatesWhatFmtConflated(t *testing.T) {
	for _, pair := range [][2]map[string]any{
		{{"a": "1 b:2"}, {"a": "1", "b": "2"}},
		{{"ids": []any{"1 2"}}, {"ids": []any{"1", "2"}}},
	} {
		if fmt.Sprint(pair[0]) != fmt.Sprint(pair[1]) {
			t.Fatalf("%v and %v: fmt no longer prints them alike", pair[0], pair[1])
		}
		if changeID("r", pair[0]) == changeID("r", pair[1]) {
			t.Errorf("%v and %v are one identity", pair[0], pair[1])
		}
	}
}

// A rule key's identity costs its one string: a removal names several rule
// keys per PDR, and a modification compiles them for every PDR it keeps.
func TestARuleKeyIdentityAllocatesItsString(t *testing.T) {
	field := func(b ...byte) map[string]any { return map[string]any{"value_bin": b} }
	values := make([]map[string]any, 8)
	masks := make([]map[string]any, 8)
	for i := range values {
		values[i], masks[i] = field(byte(i), 0, 0, 1), field(0xff, 0xff, 0xff, 0xff)
	}
	key := map[string]any{"values": values, "masks": masks}
	if allocs := testing.AllocsPerRun(100, func() { _ = changeID("upf/pdrs_ul", key) }); allocs > 1 {
		t.Errorf("a rule key's identity made %.0f allocations, want 1", allocs)
	}
}

// A rule's identity is one allocation, its own bytes: every compile computes
// it for every variant of every PDR it keeps, to drop repeated keys.
func TestARuleIdentityIsOneAllocation(t *testing.T) {
	p := &pdr{teid: 0x77, fteidContext: 5, ueIP: netip.MustParseAddr("10.45.0.2"),
		endpointFamilies: []uint8{4}, qfis: []uint8{9}, sdfs: []*sdfFilter{{proto: 17, protoOK: true}}}
	key, err := p.variants()[0].ruleKey([]Field{SrcIP, DstIP, Proto, SrcPort, DstPort, RouteDomain, FTEIDContext, QFI})
	if err != nil {
		t.Fatal(err)
	}
	if allocs := testing.AllocsPerRun(100, func() { _ = ruleID(key) }); allocs > 1 {
		t.Errorf("a rule's identity made %.0f allocations, want 1", allocs)
	}
}
