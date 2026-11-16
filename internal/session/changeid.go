// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"encoding/binary"
	"github.com/krsna1729/upf/internal/bess"
)

// changeID retains the canonical resource/key bytes used by transaction dedupes.
func changeID(resource string, key bess.Payload) string {
	var room [512]byte
	b := append(room[:0], resource...)
	b = append(b, 0)
	if x, ok := bess.Get[ActionKey](key); ok {
		return string(identityUint(identityMap(b, 1), "action_id", uint64(x.ActionID)))
	}
	if x, ok := bess.Get[IDKey](key); ok {
		return string(identityUint(identityMap(b, 1), "id", uint64(x.ID)))
	}
	if x, ok := bess.Get[PolicyKey](key); ok {
		return string(identityUint(identityMap(b, 1), "policy_id", uint64(x.PolicyID)))
	}
	if x, ok := bess.Get[SessionKey](key); ok {
		return string(identityUint(identityMap(b, 1), "session_id", uint64(x.SessionID)))
	}
	if x, ok := bess.Get[ARPKey](key); ok {
		b = identityField(identityMap(b, 1), "ip")
		b = binary.AppendUvarint(append(b, 's'), uint64(len(x.IP)))
		return string(append(b, x.IP...))
	}
	if x, ok := bess.Get[FTEIDKey](key); ok {
		b = identityUint(identityMap(b, 4), "address_family", uint64(x.AddressFamily))
		b = identityUint(b, "endpoint_id", uint64(x.EndpointID))
		b = appendByteList(identityField(b, "local_address"), x.LocalAddress)
		return string(identityUint(b, "teid", uint64(x.TEID)))
	}
	if x, ok := bess.Get[RuleKey](key); ok {
		return string(appendRuleIdentity(b, x))
	}
	panic("unsupported compiler resource key")
}

func identityMap(b []byte, n int) []byte { return binary.AppendUvarint(append(b, 'm'), uint64(n)) }
func identityField(b []byte, name string) []byte {
	return append(binary.AppendUvarint(b, uint64(len(name))), name...)
}
func identityUint(b []byte, name string, n uint64) []byte {
	return binary.AppendUvarint(append(identityField(b, name), '+'), n)
}
func appendRuleIdentity(b []byte, key RuleKey) []byte {
	n := 2
	if len(key.Ranges) != 0 {
		n++
	}
	b = identityMap(b, n)
	b = identityField(b, "masks")
	b = appendIdentityBins(b, key.Masks)
	if len(key.Ranges) != 0 {
		b = identityField(b, "ranges")
		b = binary.AppendUvarint(append(b, 'l'), uint64(len(key.Ranges)))
		for _, r := range key.Ranges {
			b = identityUint(identityMap(b, 3), "field", uint64(r.Field))
			b = identityUint(b, "high", r.High)
			b = identityUint(b, "low", r.Low)
		}
	}
	return appendIdentityBins(identityField(b, "values"), key.Values)
}
func appendIdentityBins(b []byte, bins [][]byte) []byte {
	b = binary.AppendUvarint(append(b, 'l'), uint64(len(bins)))
	for _, x := range bins {
		b = appendByteList(b, x)
	}
	return b
}
func appendByteList(b, x []byte) []byte {
	b = binary.AppendUvarint(append(b, 'l'), uint64(len(x)))
	for _, e := range x {
		b = binary.AppendUvarint(append(b, '+'), uint64(e))
	}
	return b
}
