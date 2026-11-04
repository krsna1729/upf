// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"encoding/binary"
	"fmt"
	"slices"
)

// changeID is the identity of the entry a change names -- its resource and its
// key -- for the dedupes that keep one transaction from naming an entry twice.
// It keeps fmt.Sprint's equivalence, which is what these dedupes compared
// before: integers by value whatever their Go type, lists by their elements
// (a []byte is a list of integers, as fmt prints it), maps by their entries in
// name order. It is finer only across kinds, where fmt printed a string like
// the number or bool it spells; no key holds one field as both. The difference
// is the cost: fmt sorted each map's names through reflection, which was most
// of what removing a session allocated. This writes into a buffer on the stack
// and allocates the string.
func changeID(resource string, key map[string]any) string {
	var room [512]byte // a rule key of 8 fields is under 300 bytes
	b := append(room[:0], resource...)
	b = append(b, 0)
	return string(appendIdentity(b, key))
}

// appendIdentity writes v so that the writing is injective on the
// equivalence above: every value is tagged, and every string and list carries
// its length.
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
		b = binary.AppendUvarint(append(b, 'l'), uint64(len(x)))
		for _, e := range x {
			b = appendInt(b, uint64(e), false)
		}
		return b
	case []uint32:
		b = binary.AppendUvarint(append(b, 'l'), uint64(len(x)))
		for _, e := range x {
			b = appendInt(b, uint64(e), false)
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
