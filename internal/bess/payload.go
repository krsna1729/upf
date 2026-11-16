// SPDX-License-Identifier: BSD-3-Clause

package bess

import (
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

// Payload is a resource message, not an action's Message argument. Fields holds
// a typed struct; JSON explicitly supplies the protobuf JSON form when its shape
// is discovered at runtime. Neither representation retains a field-value map.
// A nil Payload means absent, distinct from Fields(struct{}{}) and JSON("{}").
type Payload interface {
	changeFields() reflect.Value
}

type structPayload[T any] struct{ value T }

func (p *structPayload[T]) changeFields() reflect.Value {
	return reflect.ValueOf(&p.value).Elem()
}

// Fields snapshots v's struct fields, without boxing individual field values.
// Exported direct fields use their JSON tags (or Go names); omitempty and
// omitzero omit values just as encoding/json does. Pointers preserve present-zero
// optional fields. Embedded fields, custom JSON marshalers and string-tagged
// fields belong in an explicit JSON payload instead.
//
// This is a shallow copy: slice/byte backing arrays and pointed-to values must
// remain immutable until Apply returns. The transaction receives its own encoded
// bytes, never aliases to these arrays. A small key costs its actual struct size,
// and a rule key holds slice headers, not a boxed generic field graph.
func Fields[T any](v T) Payload { return &structPayload[T]{value: v} }

// Get reads the exact struct type supplied to Fields without copying its backing
// arrays or constructing an intermediate map. It does not decode JSON payloads.
func Get[T any](p Payload) (T, bool) {
	if v, ok := p.(*structPayload[T]); ok && v != nil {
		return v.value, true
	}
	var zero T
	return zero, false
}

// JSON is an explicit protobuf-JSON resource message. Its bytes must remain
// immutable until Apply returns. Parsing uses the daemon's current descriptor,
// including proto2 required fields, protobuf maps and well-known types.
type JSON []byte

func (JSON) changeFields() reflect.Value { return reflect.Value{} }

type payloadField struct {
	name      string
	index     int
	omitEmpty bool
	omitZero  bool
}

type payloadLayout struct {
	fields []payloadField
	err    error
}

var payloadLayouts sync.Map // reflect.Type -> payloadLayout; one per Go struct type
var jsonMarshalerType = reflect.TypeFor[json.Marshaler]()
var textMarshalerType = reflect.TypeFor[encoding.TextMarshaler]()

func customPayloadType(t reflect.Type) bool {
	return t.Implements(jsonMarshalerType) || reflect.PointerTo(t).Implements(jsonMarshalerType) ||
		t.Implements(textMarshalerType) || reflect.PointerTo(t).Implements(textMarshalerType)
}

func layoutOf(t reflect.Type) payloadLayout {
	if cached, ok := payloadLayouts.Load(t); ok {
		return cached.(payloadLayout)
	}
	layout := payloadLayout{}
	if t.Kind() != reflect.Struct {
		layout.err = errors.New("resource fields must be a struct")
	} else if customPayloadType(t) {
		layout.err = errors.New("custom JSON marshaler requires an explicit JSON payload")
	} else {
		for i := range t.NumField() {
			f := t.Field(i)
			if f.PkgPath != "" {
				// An unexported embedded field may promote exported members.
				if f.Anonymous {
					layout.err = errors.New("embedded resource fields require an explicit JSON payload")
					break
				}
				continue
			}
			name, options, _ := strings.Cut(f.Tag.Get("json"), ",")
			if name == "-" {
				continue
			}
			if f.Anonymous {
				layout.err = errors.New("embedded resource fields require an explicit JSON payload")
				break
			}
			if name == "" {
				name = f.Name
			}
			field := payloadField{name: name, index: i}
			for options != "" {
				var option string
				option, options, _ = strings.Cut(options, ",")
				switch option {
				case "omitempty":
					field.omitEmpty = true
				case "omitzero":
					field.omitZero = true
				case "string":
					layout.err = errors.New("string-tagged resource fields require an explicit JSON payload")
				}
			}
			layout.fields = append(layout.fields, field)
		}
	}
	actual, _ := payloadLayouts.LoadOrStore(t, layout)
	return actual.(payloadLayout)
}

func emptyField(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.Interface, reflect.Pointer:
		return v.IsZero()
	}
	return false
}

func zeroField(v reflect.Value) bool {
	// Only a type declaring IsZero leaves the unboxed reflect path.
	type zeroer interface{ IsZero() bool }
	if v.Type().Implements(reflect.TypeFor[zeroer]()) {
		if !indirectField(v).IsValid() {
			return true
		}
		return v.Interface().(zeroer).IsZero()
	}
	if v.CanAddr() && v.Addr().Type().Implements(reflect.TypeFor[zeroer]()) {
		return v.Addr().Interface().(zeroer).IsZero()
	}
	return v.IsZero()
}

func fieldPresent(f payloadField, v reflect.Value) bool {
	return !(f.omitEmpty && emptyField(v) || f.omitZero && zeroField(v))
}

func indirectField(v reflect.Value) reflect.Value {
	for v.IsValid() && (v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface) {
		if v.IsNil() {
			return reflect.Value{}
		}
		v = v.Elem()
	}
	return v
}

// encodePayload appends a validated message to a transaction-owned buffer. The
// typed path never falls back to JSON: JSON is an explicit caller decision.
func encodePayload(buf []byte, md protoreflect.MessageDescriptor, p Payload) ([]byte, []byte, error) {
	if p == nil {
		return nil, buf, errors.New("absent resource payload")
	}
	start := len(buf)
	var b []byte
	var err error
	if raw, ok := p.(JSON); ok {
		m := dynamicpb.NewMessage(md)
		if err = protojson.Unmarshal(raw, m); err == nil {
			b, err = proto.MarshalOptions{Deterministic: true}.MarshalAppend(buf, m)
		}
	} else {
		v := indirectField(p.changeFields())
		if !v.IsValid() {
			return nil, buf, errors.New("nil typed resource payload")
		}
		b, err = encodeStruct(buf, md, v)
	}
	if err != nil {
		return nil, buf, fmt.Errorf("bess: %s fields: %w", md.FullName(), err)
	}
	return b[start:len(b):len(b)], b, nil
}

// PayloadMessage exposes exactly the resource payload validation Apply uses,
// for callers that need a reflective message (including conversion benchmarks).
// Message and wire retain their separate action/query field-map API.
func (c *Client) PayloadMessage(typ string, p Payload) (proto.Message, error) {
	md, err := c.descriptor(typ)
	if err != nil {
		return nil, err
	}
	b, _, err := encodePayload(nil, md, p)
	if err != nil {
		return nil, err
	}
	m := dynamicpb.NewMessage(md)
	if err := proto.Unmarshal(b, m); err != nil {
		return nil, err
	}
	return m, nil
}

func encodeStruct(b []byte, md protoreflect.MessageDescriptor, v reflect.Value) ([]byte, error) {
	if strings.HasPrefix(string(md.FullName()), "google.protobuf.") {
		return b, errors.New("well-known resource types require an explicit JSON payload")
	}
	layout := layoutOf(v.Type())
	if layout.err != nil {
		return b, layout.err
	}
	fds := md.Fields()
	// Validate names before encoding, even when their value is JSON null.
	for _, f := range layout.fields {
		if !fieldPresent(f, v.Field(f.index)) {
			continue
		}
		fd := fds.ByJSONName(f.name)
		if fd == nil {
			fd = fds.ByTextName(f.name)
		}
		if fd == nil {
			return b, fmt.Errorf("unknown field %q", f.name)
		}
	}
	var room [4]protoreflect.OneofDescriptor
	oneofs := room[:0]
	for i := range fds.Len() {
		fd := fds.Get(i)
		value := reflect.Value{}
		found := false
		for _, f := range layout.fields {
			fv := v.Field(f.index)
			if !fieldPresent(f, fv) {
				continue
			}
			if f.name != fd.JSONName() && (f.name != fd.TextName() || fds.ByJSONName(f.name) != nil) {
				continue
			}
			if found {
				return b, fmt.Errorf("field %q named twice", fd.Name())
			}
			found = true
			value = indirectField(fv)
			if value.IsValid() && value.Type().PkgPath() != "" && customPayloadType(value.Type()) {
				return b, fmt.Errorf("field %q custom marshaler requires an explicit JSON payload", fd.FullName())
			}
		}
		// Nil pointers and nil slices are JSON null, which leaves a field unset.
		if !value.IsValid() || value.Kind() == reflect.Slice && value.IsNil() {
			if fd.Cardinality() == protoreflect.Required {
				return b, fmt.Errorf("required field %q not set", fd.FullName())
			}
			continue
		}
		if od := fd.ContainingOneof(); od != nil && !od.IsSynthetic() {
			if slices.Contains(oneofs, od) {
				return b, fmt.Errorf("oneof %q has multiple fields", od.FullName())
			}
			oneofs = append(oneofs, od)
		}
		var err error
		switch {
		case fd.IsMap():
			return b, fmt.Errorf("map field %q requires an explicit JSON payload", fd.FullName())
		case fd.IsList():
			b, err = encodeStructList(b, fd, value)
		case fd.Message() != nil:
			b = protowire.AppendTag(b, fd.Number(), protowire.BytesType)
			start := len(b)
			b, err = encodeStruct(b, fd.Message(), value)
			if err == nil {
				b = insertLen(b, start)
			}
		default:
			var scalar protoreflect.Value
			scalar, err = structScalar(fd, value)
			if err == nil && (fd.HasPresence() || !structZero(fd, scalar)) {
				b = appendStructScalar(protowire.AppendTag(b, fd.Number(), structWireType(fd)), fd, scalar)
			}
		}
		if err != nil {
			return b, fmt.Errorf("field %q: %w", fd.FullName(), err)
		}
	}
	return b, nil
}

func encodeStructList(b []byte, fd protoreflect.FieldDescriptor, v reflect.Value) ([]byte, error) {
	if v.Kind() != reflect.Slice || v.Type().Elem().Kind() == reflect.Uint8 {
		return b, errors.New("expected a repeated-field slice")
	}
	start := -1
	for i := range v.Len() {
		x := indirectField(v.Index(i))
		if !x.IsValid() || x.Kind() == reflect.Slice && x.IsNil() {
			return b, errors.New("null repeated-field element")
		}
		if x.Type().PkgPath() != "" && customPayloadType(x.Type()) {
			return b, errors.New("custom repeated element marshaler requires an explicit JSON payload")
		}
		if fd.Message() != nil {
			b = protowire.AppendTag(b, fd.Number(), protowire.BytesType)
			at := len(b)
			var err error
			if x.Kind() == reflect.Slice && x.Type().Elem().Kind() == reflect.Uint8 {
				if x.Type().Elem().PkgPath() != "" && customPayloadType(x.Type().Elem()) {
					return b, errors.New("custom byte element marshaler requires an explicit JSON payload")
				}
				inner := soleBytes(fd.Message())
				if inner == nil {
					return b, errors.New("byte-list element requires a sole-bytes message")
				}
				if x.Len() != 0 || inner.HasPresence() {
					b = protowire.AppendBytes(protowire.AppendTag(b, inner.Number(), protowire.BytesType), x.Bytes())
				}
			} else {
				b, err = encodeStruct(b, fd.Message(), x)
			}
			if err != nil {
				return b, err
			}
			b = insertLen(b, at)
			continue
		}
		value, err := structScalar(fd, x)
		if err != nil {
			return b, err
		}
		if fd.IsPacked() {
			if start < 0 {
				b = protowire.AppendTag(b, fd.Number(), protowire.BytesType)
				start = len(b)
			}
		} else {
			b = protowire.AppendTag(b, fd.Number(), structWireType(fd))
		}
		b = appendStructScalar(b, fd, value)
	}
	if start >= 0 {
		b = insertLen(b, start)
	}
	return b, nil
}

func structScalar(fd protoreflect.FieldDescriptor, v reflect.Value) (protoreflect.Value, error) {
	if v.Type().PkgPath() != "" && customPayloadType(v.Type()) {
		return protoreflect.Value{}, errors.New("custom marshaler requires an explicit JSON payload")
	}
	var value protoreflect.Value
	var ok bool
	switch v.Kind() {
	case reflect.Bool:
		if fd.Kind() == protoreflect.BoolKind {
			value, ok = protoreflect.ValueOfBool(v.Bool()), true
		}
	case reflect.String:
		s := v.String()
		if fd.Kind() == protoreflect.StringKind {
			if !utf8.ValidString(s) {
				s = string([]rune(s)) // encoding/json replaces each invalid rune
			}
			value, ok = protoreflect.ValueOfString(s), true
		} else if fd.Kind() == protoreflect.EnumKind {
			if ev := fd.Enum().Values().ByName(protoreflect.Name(s)); ev != nil {
				value, ok = protoreflect.ValueOfEnum(ev.Number()), true
			}
		}
	case reflect.Slice:
		if fd.Kind() == protoreflect.BytesKind && v.Type().Elem().Kind() == reflect.Uint8 {
			if v.Type().Elem().PkgPath() != "" && customPayloadType(v.Type().Elem()) {
				return protoreflect.Value{}, errors.New("custom byte element marshaler requires an explicit JSON payload")
			}
			value, ok = protoreflect.ValueOfBytes(v.Bytes()), true
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n := v.Int()
		if fd.Kind() == protoreflect.EnumKind && n >= math.MinInt32 && n <= math.MaxInt32 {
			value, ok = protoreflect.ValueOfEnum(protoreflect.EnumNumber(n)), true
		} else if fd.Kind() == protoreflect.FloatKind || fd.Kind() == protoreflect.DoubleKind {
			value, ok = protoreflect.ValueOfFloat64(float64(n)), true
		} else {
			magnitude := uint64(n)
			if n < 0 {
				magnitude = -magnitude
			}
			value, ok = scalarInt(fd, magnitude, n < 0)
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		n := v.Uint()
		if fd.Kind() == protoreflect.EnumKind && n <= math.MaxInt32 {
			value, ok = protoreflect.ValueOfEnum(protoreflect.EnumNumber(n)), true
		} else if fd.Kind() == protoreflect.FloatKind || fd.Kind() == protoreflect.DoubleKind {
			value, ok = protoreflect.ValueOfFloat64(float64(n)), true
		} else {
			value, ok = scalarInt(fd, n, false)
		}
	case reflect.Float32, reflect.Float64:
		f := v.Float()
		if (fd.Kind() == protoreflect.FloatKind || fd.Kind() == protoreflect.DoubleKind) && !math.IsNaN(f) && !math.IsInf(f, 0) {
			if v.Kind() == reflect.Float32 && fd.Kind() == protoreflect.DoubleKind {
				// JSON formats a float32 at its own precision before the
				// daemon reads that decimal as a double.
				var room [32]byte
				text := strconv.AppendFloat(room[:0], f, 'g', -1, 32)
				f, _ = strconv.ParseFloat(string(text), 64)
			}
			value, ok = protoreflect.ValueOfFloat64(f), true
		}
	}
	if ok && fd.Kind() == protoreflect.FloatKind {
		f := value.Float()
		if f < -math.MaxFloat32 || f > math.MaxFloat32 {
			ok = false
		} else {
			value = protoreflect.ValueOfFloat32(float32(f))
		}
	}
	if !ok {
		return protoreflect.Value{}, fmt.Errorf("cannot convert %s to %s", v.Type(), fd.Kind())
	}
	return value, nil
}

func structWireType(fd protoreflect.FieldDescriptor) protowire.Type {
	switch fd.Kind() {
	case protoreflect.FloatKind:
		return protowire.Fixed32Type
	case protoreflect.DoubleKind:
		return protowire.Fixed64Type
	}
	return wireType(fd)
}

func appendStructScalar(b []byte, fd protoreflect.FieldDescriptor, v protoreflect.Value) []byte {
	switch fd.Kind() {
	case protoreflect.FloatKind:
		return protowire.AppendFixed32(b, math.Float32bits(float32(v.Float())))
	case protoreflect.DoubleKind:
		return protowire.AppendFixed64(b, math.Float64bits(v.Float()))
	}
	return appendScalar(b, fd, v)
}

func structZero(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
	if fd.Kind() == protoreflect.FloatKind || fd.Kind() == protoreflect.DoubleKind {
		return v.Float() == 0
	}
	return isZero(fd, v)
}
