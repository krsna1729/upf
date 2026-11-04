// SPDX-License-Identifier: BSD-3-Clause

package bess

import (
	"reflect"
	"slices"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// encode appends to b the wire form of the message fill would build from
// fields, and reports false exactly where fill does: the caller then takes
// fill's own path. It writes the bytes itself, where fill sets a dynamic
// message field by field for proto.Marshal to walk again; for a rule key that
// was some 230 allocations, and every session writes several.
//
// Fields go out in descriptor order, so equal maps encode to equal bytes. A
// field with no presence (proto3's plain scalars) is left out at its zero
// value, as a dynamic message leaves it out; a field with presence (a oneof
// member, a nested message, proto2's) goes out whenever fields names it.
func encode(b []byte, md protoreflect.MessageDescriptor, fields map[string]any) ([]byte, bool) {
	if strings.HasPrefix(string(md.FullName()), "google.protobuf.") {
		return b, false
	}
	fds := md.Fields()
	var room [4]protoreflect.OneofDescriptor
	oneofs := room[:0]
	found := 0
	for i := range fds.Len() {
		fd := fds.Get(i)
		v, n := named(fds, fd, fields)
		if n == 0 {
			continue
		}
		if n > 1 {
			return b, false // named twice: fill refuses the second
		}
		found++
		if od := fd.ContainingOneof(); od != nil && !od.IsSynthetic() {
			if slices.Contains(oneofs, od) {
				return b, false
			}
			oneofs = append(oneofs, od)
		}
		var ok bool
		switch {
		case fd.IsMap():
			return b, false
		case fd.IsList():
			b, ok = encodeList(b, fd, v)
		case fd.Message() != nil:
			sub, isMap := v.(map[string]any)
			if !isMap || sub == nil {
				return b, false
			}
			b = protowire.AppendTag(b, fd.Number(), protowire.BytesType)
			start := len(b)
			if b, ok = encode(b, fd.Message(), sub); ok {
				b = insertLen(b, start)
			}
		default:
			var val protoreflect.Value
			if val, ok = scalarValue(fd, v); ok && (fd.HasPresence() || !isZero(fd, val)) {
				b = appendScalar(protowire.AppendTag(b, fd.Number(), wireType(fd)), fd, val)
			}
		}
		if !ok {
			return b, false
		}
	}
	if found != len(fields) {
		return b, false // a name that is no field's
	}
	// fill's message must pass proto.CheckInitialized: every required field
	// named (a nested message checks its own as it is encoded).
	required := md.RequiredNumbers()
	for i := range required.Len() {
		if _, n := named(fds, fds.ByNumber(required.Get(i)), fields); n == 0 {
			return b, false
		}
	}
	return b, true
}

// named is the value fields gives fd under the names fill resolves to it --
// its JSON name, or its proto name when no field has that as its JSON name --
// and how many of those names fields uses.
func named(fds protoreflect.FieldDescriptors, fd protoreflect.FieldDescriptor, fields map[string]any) (any, int) {
	var v any
	n := 0
	if x, ok := fields[fd.JSONName()]; ok {
		v, n = x, 1
	}
	if text := fd.TextName(); text != fd.JSONName() && fds.ByJSONName(text) == nil {
		if x, ok := fields[text]; ok {
			v, n = x, n+1
		}
	}
	return v, n
}

// encodeList appends a repeated field's elements, for the element slices
// fillList takes and on its terms: a scalar list packed where the field is.
func encodeList(b []byte, fd protoreflect.FieldDescriptor, v any) ([]byte, bool) {
	packed := fd.IsPacked()
	start := -1
	elem := func(val protoreflect.Value) {
		if packed {
			if start < 0 {
				b = protowire.AppendTag(b, fd.Number(), protowire.BytesType)
				start = len(b)
			}
			b = appendScalar(b, fd, val)
			return
		}
		b = appendScalar(protowire.AppendTag(b, fd.Number(), wireType(fd)), fd, val)
	}
	message := func(sub map[string]any) bool {
		if sub == nil {
			return false
		}
		b = protowire.AppendTag(b, fd.Number(), protowire.BytesType)
		at := len(b)
		var ok bool
		if b, ok = encode(b, fd.Message(), sub); ok {
			b = insertLen(b, at)
		}
		return ok
	}
	switch s := v.(type) {
	case []uint32:
		if s == nil {
			return b, false
		}
		for _, x := range s {
			val, ok := scalarInt(fd, uint64(x), false)
			if !ok {
				return b, false
			}
			elem(val)
		}
	case []map[string]any:
		if fd.Message() == nil || s == nil {
			return b, false
		}
		for _, x := range s {
			if !message(x) {
				return b, false
			}
		}
	case []byte:
		return b, false // base64 in JSON: a string, not a list
	default:
		rv := reflect.ValueOf(v)
		if rv.Kind() != reflect.Slice || rv.IsNil() {
			return b, false
		}
		for i := range rv.Len() {
			x := rv.Index(i).Interface()
			if fd.Message() != nil {
				sub, ok := x.(map[string]any)
				if !ok || !message(sub) {
					return b, false
				}
				continue
			}
			val, ok := scalarValue(fd, x)
			if !ok {
				return b, false
			}
			elem(val)
		}
	}
	if start >= 0 {
		b = insertLen(b, start)
	}
	return b, true
}

// insertLen puts the length of b[start:] in front of it, as a varint.
func insertLen(b []byte, start int) []byte {
	n := len(b) - start
	k := protowire.SizeVarint(uint64(n))
	b = append(b, make([]byte, k)...)
	copy(b[start+k:], b[start:start+n])
	protowire.AppendVarint(b[start:start], uint64(n))
	return b
}

func wireType(fd protoreflect.FieldDescriptor) protowire.Type {
	switch fd.Kind() {
	case protoreflect.Fixed32Kind, protoreflect.Sfixed32Kind:
		return protowire.Fixed32Type
	case protoreflect.Fixed64Kind, protoreflect.Sfixed64Kind:
		return protowire.Fixed64Type
	case protoreflect.StringKind, protoreflect.BytesKind:
		return protowire.BytesType
	}
	return protowire.VarintType
}

// appendScalar is one value of fd's kind, without its tag. The kinds are
// scalarValue's: no floats.
func appendScalar(b []byte, fd protoreflect.FieldDescriptor, v protoreflect.Value) []byte {
	switch fd.Kind() {
	case protoreflect.BoolKind:
		return protowire.AppendVarint(b, protowire.EncodeBool(v.Bool()))
	case protoreflect.EnumKind:
		return protowire.AppendVarint(b, uint64(int64(v.Enum())))
	case protoreflect.Int32Kind, protoreflect.Int64Kind:
		return protowire.AppendVarint(b, uint64(v.Int()))
	case protoreflect.Sint32Kind, protoreflect.Sint64Kind:
		return protowire.AppendVarint(b, protowire.EncodeZigZag(v.Int()))
	case protoreflect.Fixed32Kind:
		return protowire.AppendFixed32(b, uint32(v.Uint()))
	case protoreflect.Sfixed32Kind:
		return protowire.AppendFixed32(b, uint32(v.Int()))
	case protoreflect.Fixed64Kind:
		return protowire.AppendFixed64(b, v.Uint())
	case protoreflect.Sfixed64Kind:
		return protowire.AppendFixed64(b, uint64(v.Int()))
	case protoreflect.StringKind:
		return protowire.AppendString(b, v.String())
	case protoreflect.BytesKind:
		return protowire.AppendBytes(b, v.Bytes())
	}
	return protowire.AppendVarint(b, v.Uint()) // uint32, uint64
}

// isZero is whether v is its kind's zero, which a field with no presence
// does not carry on the wire.
func isZero(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
	switch fd.Kind() {
	case protoreflect.BoolKind:
		return !v.Bool()
	case protoreflect.EnumKind:
		return v.Enum() == 0
	case protoreflect.StringKind:
		return v.String() == ""
	case protoreflect.BytesKind:
		return len(v.Bytes()) == 0
	case protoreflect.Int32Kind, protoreflect.Int64Kind, protoreflect.Sint32Kind, protoreflect.Sint64Kind,
		protoreflect.Sfixed32Kind, protoreflect.Sfixed64Kind:
		return v.Int() == 0
	}
	return v.Uint() == 0
}
