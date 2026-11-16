// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"encoding/binary"
	"fmt"
	"github.com/krsna1729/upf/internal/bess"
	"net/netip"
	"slices"
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
)

// identityKeys pairs every compiler key shape with its pre-cutover canonical form.
func identityKeys() []struct {
	typed  bess.Payload
	legacy map[string]any
} {
	keys := []struct {
		typed  bess.Payload
		legacy map[string]any
	}{}
	add := func(p bess.Payload, m map[string]any) {
		keys = append(keys, struct {
			typed  bess.Payload
			legacy map[string]any
		}{p, m})
	}
	for _, id := range []uint32{0, 7, 7, 8} {
		add(bess.Fields(ActionKey{id}), map[string]any{"action_id": id})
		add(bess.Fields(IDKey{id}), map[string]any{"id": id})
		add(bess.Fields(PolicyKey{id}), map[string]any{"policy_id": id})
		add(bess.Fields(SessionKey{id}), map[string]any{"session_id": id})
	}
	for _, ip := range []string{"", "n3", "n3", "n6", "1 b:2"} {
		add(bess.Fields(ARPKey{ip}), map[string]any{"ip": ip})
	}
	for _, k := range []FTEIDKey{
		{1, 4, []byte{10, 0, 0, 1}, 7}, {1, 4, []byte{10, 0, 0, 1}, 7},
		{2, 4, []byte{10, 0, 0, 1}, 7}, {1, 6, []byte{10, 0, 0, 1}, 7},
		{1, 4, []byte{10, 0, 0, 2}, 7}, {1, 4, []byte{10, 0, 0, 1}, 8},
	} {
		add(bess.Fields(k), map[string]any{"endpoint_id": k.EndpointID, "address_family": k.AddressFamily, "local_address": k.LocalAddress, "teid": k.TEID})
	}
	for _, k := range []RuleKey{
		{Values: [][]byte{{10, 0, 0, 1}, {0, 0}}, Masks: [][]byte{{255, 255, 255, 255}, {0, 0}}},
		{Values: [][]byte{{10, 0, 0, 1}, {0, 0}}, Masks: [][]byte{{255, 255, 255, 255}, {0, 0}}},
		{Values: [][]byte{{10, 0, 0, 2}, {0, 0}}, Masks: [][]byte{{255, 255, 255, 255}, {0, 0}}},
		{Values: [][]byte{{10, 0, 0, 1}, {0, 0}}, Masks: [][]byte{{255, 255, 255, 255}, {0, 0}}, Ranges: []RuleRange{{1, 1000, 2000}}},
		{Values: [][]byte{{1, 2}}}, {Values: [][]byte{{1}, {2}}},
		{Values: [][]byte{{}}}, {Values: [][]byte{nil}}, {Values: [][]byte{}}, {},
	} {
		m := map[string]any{"values": k.Values, "masks": k.Masks}
		if len(k.Ranges) != 0 {
			ranges := make([]map[string]any, len(k.Ranges))
			for i, r := range k.Ranges {
				ranges[i] = map[string]any{"field": r.Field, "low": r.Low, "high": r.High}
			}
			m["ranges"] = ranges
		}
		add(bess.Fields(k), m)
	}
	return keys
}

func TestChangeIDKeepsFmtsIdentity(t *testing.T) {
	keys := identityKeys()
	for i, a := range keys {
		if got, want := changeID("r", a.typed), legacyChangeID("r", a.legacy); got != want {
			t.Errorf("%v: canonical bytes %x, want %x", a.legacy, got, want)
		}
		for j, b := range keys {
			same := fmt.Sprint(a.legacy) == fmt.Sprint(b.legacy)
			if got := changeID("r", a.typed) == changeID("r", b.typed); got != same {
				t.Errorf("%v and %v: one identity %v, fmt printed them alike %v", a.legacy, b.legacy, got, same)
			}
			if i == j && changeID("r", a.typed) == changeID("s", a.typed) {
				t.Errorf("%v is one identity in two resources", a.legacy)
			}
		}
	}
}

// Typed keys can print alike, but differently named fields must never dedupe.
func TestChangeIDSeparatesWhatFmtConflated(t *testing.T) {
	a, b := ActionKey{7}, IDKey{7}
	if fmt.Sprint(a) != fmt.Sprint(b) {
		t.Fatal("fixture keys no longer print alike")
	}
	if changeID("r", bess.Fields(a)) == changeID("r", bess.Fields(b)) {
		t.Fatal("differently named key fields share one identity")
	}
}

// A rule key's identity costs its one string: a removal names several rule
// keys per PDR, and a modification compiles them for every PDR it keeps.
func TestARuleKeyIdentityAllocatesItsString(t *testing.T) {
	p := &pdr{teid: 0x77, fteidContext: 5, ueIP: netip.MustParseAddr("10.45.0.2"),
		wantIPv4: true, pdrExt: &pdrExt{qfis: []uint8{9}}, sdfs: []*sdfFilter{{proto: 17, protoOK: true}}}
	v := ruleVariant{sdf: p.sdfs[0], hasQFI: true, qfi: p.qfis[0]}
	key, err := p.ruleKey([]Field{SrcIP, DstIP, Proto, SrcPort, DstPort, RouteDomain, FTEIDContext, QFI}, v)
	if err != nil {
		t.Fatal(err)
	}
	payload := bess.Fields(key)
	if allocs := testing.AllocsPerRun(100, func() { _ = changeID("upf/pdrs_ul", payload) }); allocs > 1 {
		t.Errorf("a rule key's identity made %.0f allocations, want 1", allocs)
	}
}

// A rule key is a few blocks, not a few per field: every establishment,
// modification and removal compiles one for every variant of every PDR it
// touches. With a map per field and the SDF filter oriented per field, an
// 8-field key was 73 allocations.
func TestARuleKeyIsAFewAllocations(t *testing.T) {
	p := &pdr{teid: 0x77, fteidContext: 5, ueIP: netip.MustParseAddr("10.45.0.2"),
		srcIfc: ie.SrcInterfaceAccess, wantIPv4: true, pdrExt: &pdrExt{qfis: []uint8{9}},
		sdfs: []*sdfFilter{{proto: 17, protoOK: true}}}
	v := ruleVariant{sdf: p.sdfs[0], hasQFI: true, qfi: p.qfis[0]}
	fields := []Field{SrcIP, DstIP, Proto, SrcPort, DstPort, RouteDomain, FTEIDContext, QFI}
	if allocs := testing.AllocsPerRun(100, func() { _, _ = p.ruleKey(fields, v) }); allocs > 17 {
		t.Errorf("an 8-field rule key made %.0f allocations, want <= 17", allocs)
	}
}

// A rule's identity is one allocation, its own bytes: every compile computes
// it for every variant of every PDR it keeps, to drop repeated keys.
func TestARuleIdentityIsOneAllocation(t *testing.T) {
	p := &pdr{teid: 0x77, fteidContext: 5, ueIP: netip.MustParseAddr("10.45.0.2"),
		wantIPv4: true, pdrExt: &pdrExt{qfis: []uint8{9}}, sdfs: []*sdfFilter{{proto: 17, protoOK: true}}}
	v := ruleVariant{sdf: p.sdfs[0], hasQFI: true, qfi: p.qfis[0]}
	key, err := p.ruleKey([]Field{SrcIP, DstIP, Proto, SrcPort, DstPort, RouteDomain, FTEIDContext, QFI}, v)
	if err != nil {
		t.Fatal(err)
	}
	if allocs := testing.AllocsPerRun(100, func() { _ = ruleID(key) }); allocs > 1 {
		t.Errorf("a rule's identity made %.0f allocations, want 1", allocs)
	}
}

func legacyChangeID(resource string, key map[string]any) string {
	return string(appendIdentity(append([]byte(resource), 0), key))
}
func appendIdentity(b []byte, v any) []byte {
	switch x := v.(type) {
	case nil:
		return append(b, 'n')
	case bool:
		if x {
			return append(b, 't')
		}
		return append(b, 'f')
	case string:
		b = binary.AppendUvarint(append(b, 's'), uint64(len(x)))
		return append(b, x...)
	case map[string]any:
		var room [8]string
		names := room[:0]
		for name := range x {
			names = append(names, name)
		}
		slices.Sort(names)
		b = binary.AppendUvarint(append(b, 'm'), uint64(len(names)))
		for _, name := range names {
			b = binary.AppendUvarint(b, uint64(len(name)))
			b = appendIdentity(append(b, name...), x[name])
		}
		return b
	case []byte:
		return legacyAppendByteList(b, x)
	case []uint32:
		b = binary.AppendUvarint(append(b, 'l'), uint64(len(x)))
		for _, e := range x {
			b = appendInt(b, uint64(e), false)
		}
		return b
	case [][]byte:
		b = binary.AppendUvarint(append(b, 'l'), uint64(len(x)))
		for _, e := range x {
			b = legacyAppendByteList(b, e) // not appendIdentity: a []byte in an any is an allocation
		}
		return b
	case []map[string]any:
		b = binary.AppendUvarint(append(b, 'l'), uint64(len(x)))
		for _, e := range x {
			b = appendIdentity(b, e)
		}
		return b
	case []any:
		b = binary.AppendUvarint(append(b, 'l'), uint64(len(x)))
		for _, e := range x {
			b = appendIdentity(b, e)
		}
		return b
	}
	if n, neg, ok := integer(v); ok {
		return appendInt(b, n, neg)
	}
	// Anything else a key never holds today: fmt's own printing, tagged and
	// length-prefixed so it cannot pass for one of the forms above.
	s := fmt.Sprint(v)
	b = binary.AppendUvarint(append(b, '?'), uint64(len(s)))
	return append(b, s...)
}

// appendByteList writes a []byte as the list of integers fmt prints it as.
func legacyAppendByteList(b, x []byte) []byte {
	b = binary.AppendUvarint(append(b, 'l'), uint64(len(x)))
	for _, e := range x {
		b = appendInt(b, uint64(e), false)
	}
	return b
}

func appendInt(b []byte, n uint64, neg bool) []byte {
	if neg {
		return binary.AppendUvarint(append(b, '-'), n)
	}
	return binary.AppendUvarint(append(b, '+'), n)
}

// integer is v's magnitude and sign for every Go integer type.
func integer(v any) (n uint64, neg bool, ok bool) {
	var i int64
	switch x := v.(type) {
	case uint32:
		return uint64(x), false, true
	case uint64:
		return x, false, true
	case uint:
		return uint64(x), false, true
	case uint16:
		return uint64(x), false, true
	case uint8:
		return uint64(x), false, true
	case int:
		i = int64(x)
	case int64:
		i = x
	case int32:
		i = int64(x)
	case int16:
		i = int64(x)
	case int8:
		i = int64(x)
	default:
		return 0, false, false
	}
	if i < 0 {
		return uint64(-(i + 1)) + 1, true, true
	}
	return uint64(i), false, true
}
