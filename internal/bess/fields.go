// SPDX-License-Identifier: BSD-3-Clause

package bess

import (
	"bytes"
	"math"
	"reflect"
	"strings"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// fill sets m from field values named the way protojson names them (the
// proto name or the JSON name), for the Go types the session compiler writes:
// integers, bools, strings, []byte, enum names, nested maps and slices of
// those. Every change of every transaction is built here, and the JSON path it
// replaces (json.Marshal, then protojson.Unmarshal) was the control plane's
// largest source of garbage.
//
// It reports false wherever its message could differ from protojson's -- a
// type it does not convert (json.Number, a string for a bytes or number field,
// nil, floats, proto maps, the well-known types), or a value protojson would
// refuse or rewrite (out of range, invalid UTF-8, a field named twice, two
// members of one oneof). m may then be half set; the caller discards it and
// takes the JSON path, so the answer, error or message, is always protojson's.
func fill(m protoreflect.Message, fields map[string]any) bool {
	md := m.Descriptor()
	if strings.HasPrefix(string(md.FullName()), "google.protobuf.") {
		return false
	}
	fds := md.Fields()
	var seen [16]protoreflect.FieldNumber
	set := seen[:0]
	for name, v := range fields {
		// protojson's own order: the JSON name, then the proto name.
		fd := fds.ByJSONName(name)
		if fd == nil {
			fd = fds.ByTextName(name)
		}
		if fd == nil {
			return false
		}
		for _, n := range set {
			if n == fd.Number() {
				return false
			}
		}
		set = append(set, fd.Number())
		if od := fd.ContainingOneof(); od != nil && !od.IsSynthetic() && m.WhichOneof(od) != nil {
			return false
		}
		switch {
		case fd.IsMap():
			return false
		case fd.IsList():
			if !fillList(m.Mutable(fd).List(), fd, v) {
				return false
			}
		case fd.Message() != nil:
			sub, ok := v.(map[string]any)
			if !ok || sub == nil || !fill(m.Mutable(fd).Message(), sub) {
				return false
			}
		default:
			val, ok := scalar(fd, v)
			if !ok {
				return false
			}
			m.Set(fd, val)
		}
	}
	// protojson checks proto2 required fields after it unmarshals.
	return proto.CheckInitialized(m.Interface()) == nil
}

// fillList appends v's elements to l. A nil slice is JSON null, which is not
// an element list this converts.
func fillList(l protoreflect.List, fd protoreflect.FieldDescriptor, v any) bool {
	switch s := v.(type) {
	case []uint32:
		for _, x := range s {
			val, ok := scalar(fd, x)
			if !ok {
				return false
			}
			l.Append(val)
		}
		return s != nil
	case []map[string]any:
		if fd.Message() == nil || s == nil {
			return false
		}
		for _, x := range s {
			e := l.NewElement()
			if x == nil || !fill(e.Message(), x) {
				return false
			}
			l.Append(e)
		}
		return true
	case []byte:
		return false // base64 in JSON: a string, not a list
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Slice || rv.IsNil() {
		return false
	}
	for i := range rv.Len() {
		x := rv.Index(i).Interface()
		if fd.Message() != nil {
			sub, ok := x.(map[string]any)
			e := l.NewElement()
			if !ok || sub == nil || !fill(e.Message(), sub) {
				return false
			}
			l.Append(e)
			continue
		}
		val, ok := scalar(fd, x)
		if !ok {
			return false
		}
		l.Append(val)
	}
	return true
}

// scalar converts v to fd's kind where protojson would read the JSON form of v
// to the same value.
func scalar(fd protoreflect.FieldDescriptor, v any) (protoreflect.Value, bool) {
	switch fd.Kind() {
	case protoreflect.BoolKind:
		b, ok := v.(bool)
		return protoreflect.ValueOfBool(b), ok
	case protoreflect.StringKind:
		s, ok := v.(string)
		// json.Marshal replaces invalid UTF-8; protojson then holds the
		// replacement, which is not s.
		return protoreflect.ValueOfString(s), ok && utf8.ValidString(s)
	case protoreflect.BytesKind:
		b, ok := v.([]byte)
		return protoreflect.ValueOfBytes(bytes.Clone(b)), ok && b != nil
	case protoreflect.EnumKind:
		s, ok := v.(string)
		if !ok {
			return protoreflect.Value{}, false
		}
		ev := fd.Enum().Values().ByName(protoreflect.Name(s))
		if ev == nil {
			return protoreflect.Value{}, false
		}
		return protoreflect.ValueOfEnum(ev.Number()), true
	}
	n, neg, ok := integer(v)
	if !ok {
		return protoreflect.Value{}, false
	}
	switch fd.Kind() {
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return protoreflect.ValueOfUint32(uint32(n)), !neg && n <= math.MaxUint32
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return protoreflect.ValueOfUint64(n), !neg
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		if neg {
			return protoreflect.ValueOfInt32(int32(-int64(n))), n <= -math.MinInt32
		}
		return protoreflect.ValueOfInt32(int32(n)), n <= math.MaxInt32
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		if neg {
			return protoreflect.ValueOfInt64(-int64(n)), n <= 1<<63
		}
		return protoreflect.ValueOfInt64(int64(n)), n <= math.MaxInt64
	}
	return protoreflect.Value{}, false // floats and anything else: the JSON path
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
