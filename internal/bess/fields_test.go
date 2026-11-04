// SPDX-License-Identifier: BSD-3-Clause

package bess

import (
	"encoding/json"
	"math"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// fieldsSchema is one message with every kind the compiler's changes use and
// the shapes fill must hand to the JSON path: a oneof, a proto map, floats.
func fieldsSchema(t *testing.T) protoreflect.MessageDescriptor {
	t.Helper()
	opt := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum()
	rep := descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum()
	f := func(name string, n int32, typ descriptorpb.FieldDescriptorProto_Type, label *descriptorpb.FieldDescriptorProto_Label, typeName string) *descriptorpb.FieldDescriptorProto {
		fd := &descriptorpb.FieldDescriptorProto{Name: proto.String(name), Number: proto.Int32(n), Type: typ.Enum(), Label: label}
		if typeName != "" {
			fd.TypeName = proto.String(typeName)
		}
		return fd
	}
	oneof := func(fd *descriptorpb.FieldDescriptorProto) *descriptorpb.FieldDescriptorProto {
		fd.OneofIndex = proto.Int32(0)
		return fd
	}
	T := descriptorpb.FieldDescriptorProto_TYPE_UINT32
	file, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name: proto.String("fields.proto"), Package: proto.String("t"), Syntax: proto.String("proto3"),
		EnumType: []*descriptorpb.EnumDescriptorProto{{
			Name: proto.String("Mode"),
			Value: []*descriptorpb.EnumValueDescriptorProto{
				{Name: proto.String("MODE_HOP"), Number: proto.Int32(0)},
				{Name: proto.String("MODE_DESTINATION"), Number: proto.Int32(1)},
			},
		}},
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: proto.String("Field"), Field: []*descriptorpb.FieldDescriptorProto{
				f("value_bin", 1, descriptorpb.FieldDescriptorProto_TYPE_BYTES, opt, ""),
			}},
			// util_msg.proto's FieldData, a WildcardMatch rule key's field.
			{Name: proto.String("Data"), Field: []*descriptorpb.FieldDescriptorProto{
				oneof(f("value_bin", 1, descriptorpb.FieldDescriptorProto_TYPE_BYTES, opt, "")),
				oneof(f("value_int", 2, descriptorpb.FieldDescriptorProto_TYPE_UINT64, opt, "")),
			}, OneofDecl: []*descriptorpb.OneofDescriptorProto{{Name: proto.String("encoding")}}},
			{Name: proto.String("Pair"), Field: []*descriptorpb.FieldDescriptorProto{
				f("a", 1, descriptorpb.FieldDescriptorProto_TYPE_BYTES, opt, ""),
				f("b", 2, descriptorpb.FieldDescriptorProto_TYPE_BYTES, opt, ""),
			}},
			{Name: proto.String("All"), Field: []*descriptorpb.FieldDescriptorProto{
				f("u32", 1, T, opt, ""),
				f("u64", 2, descriptorpb.FieldDescriptorProto_TYPE_UINT64, opt, ""),
				f("i32", 3, descriptorpb.FieldDescriptorProto_TYPE_INT32, opt, ""),
				f("i64", 4, descriptorpb.FieldDescriptorProto_TYPE_INT64, opt, ""),
				f("flag", 5, descriptorpb.FieldDescriptorProto_TYPE_BOOL, opt, ""),
				f("name", 6, descriptorpb.FieldDescriptorProto_TYPE_STRING, opt, ""),
				f("blob", 7, descriptorpb.FieldDescriptorProto_TYPE_BYTES, opt, ""),
				f("mode", 8, descriptorpb.FieldDescriptorProto_TYPE_ENUM, opt, ".t.Mode"),
				f("one", 9, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, opt, ".t.Field"),
				f("many", 10, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, rep, ".t.Field"),
				f("ids", 11, T, rep, ""),
				f("rate", 12, descriptorpb.FieldDescriptorProto_TYPE_DOUBLE, opt, ""),
				f("fixed", 13, descriptorpb.FieldDescriptorProto_TYPE_FIXED64, opt, ""),
				f("s32", 14, descriptorpb.FieldDescriptorProto_TYPE_SINT32, opt, ""),
				oneof(f("by_id", 15, T, opt, "")),
				oneof(f("by_name", 16, descriptorpb.FieldDescriptorProto_TYPE_STRING, opt, "")),
				f("labels", 17, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, rep, ".t.All.LabelsEntry"),
				f("json_named", 18, T, opt, ""),
				f("f32", 19, descriptorpb.FieldDescriptorProto_TYPE_FIXED32, opt, ""),
				f("sf32", 20, descriptorpb.FieldDescriptorProto_TYPE_SFIXED32, opt, ""),
				f("sf64", 21, descriptorpb.FieldDescriptorProto_TYPE_SFIXED64, opt, ""),
				f("s64", 22, descriptorpb.FieldDescriptorProto_TYPE_SINT64, opt, ""),
				f("flags", 23, descriptorpb.FieldDescriptorProto_TYPE_BOOL, rep, ""),
				f("names", 24, descriptorpb.FieldDescriptorProto_TYPE_STRING, rep, ""),
				f("modes", 25, descriptorpb.FieldDescriptorProto_TYPE_ENUM, rep, ".t.Mode"),
				f("blobs", 26, descriptorpb.FieldDescriptorProto_TYPE_BYTES, rep, ""),
				f("data", 27, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, rep, ".t.Data"),
				f("pairs", 28, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, rep, ".t.Pair"),
			},
				OneofDecl: []*descriptorpb.OneofDescriptorProto{{Name: proto.String("target")}},
				NestedType: []*descriptorpb.DescriptorProto{{
					Name:    proto.String("LabelsEntry"),
					Options: &descriptorpb.MessageOptions{MapEntry: proto.Bool(true)},
					Field: []*descriptorpb.FieldDescriptorProto{
						f("key", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING, opt, ""),
						f("value", 2, descriptorpb.FieldDescriptorProto_TYPE_STRING, opt, ""),
					},
				}},
			},
		},
	}, protoregistry.GlobalFiles)
	if err != nil {
		t.Fatal(err)
	}
	return file.Messages().ByName("All")
}

// fieldCases are the inputs fill and encode must agree on with protojson.
// fast marks the compiler's shapes: fill must convert them itself, or it buys
// nothing.
func fieldCases() []fieldCase {
	field := func(b ...byte) map[string]any { return map[string]any{"value_bin": b} }
	return []fieldCase{
		{"scalars", map[string]any{"u32": uint32(7), "u64": uint64(1 << 40), "i32": int32(-3),
			"i64": int64(-1 << 40), "flag": true, "name": "n6", "blob": []byte{1, 2}, "fixed": uint64(9),
			"s32": -5}, true},
		{"untyped ints", map[string]any{"u32": 0, "u64": 5, "i64": -1, "i32": math.MinInt32}, true},
		{"every integer kind", map[string]any{"f32": uint32(math.MaxUint32), "sf32": int32(math.MinInt32),
			"sf64": int64(-7), "s64": int64(math.MinInt64), "s32": math.MaxInt32, "i64": int64(math.MaxInt64)}, true},
		{"zero values", map[string]any{"u32": uint32(0), "flag": false, "name": "", "blob": []byte{},
			"mode": "MODE_HOP", "s64": 0}, true},
		{"rule key", map[string]any{"one": field(0xff), "many": []map[string]any{field(1), field(2, 3)},
			"ids": []uint32{4, 5}}, true},
		{"empty bytes in a nested message", map[string]any{"many": []map[string]any{{"value_bin": []byte{}}, field(0)}}, true},
		{"scalar lists", map[string]any{"flags": []bool{true, false}, "names": []string{"a", ""},
			"modes": []string{"MODE_DESTINATION", "MODE_HOP"}, "blobs": [][]byte{{1}, {}}, "ids": []uint32{0, 1 << 31}}, true},
		{"enum by name", map[string]any{"mode": "MODE_DESTINATION"}, true},
		{"empty", map[string]any{}, true},
		{"empty nested", map[string]any{"one": map[string]any{}}, true},
		{"oneof member", map[string]any{"by_id": uint32(3)}, true},
		{"oneof member at zero", map[string]any{"by_id": uint32(0)}, true},
		{"any slice", map[string]any{"ids": []any{uint32(1), 2}, "many": []any{field(9)}}, true},
		{"json name", map[string]any{"jsonNamed": uint32(4)}, true},
		{"empty list", map[string]any{"ids": []uint32{}}, true},
		{"a long nested message", map[string]any{"one": field(make([]byte, 300)...)}, true},
		{"rule key as byte lists", map[string]any{"data": [][]byte{{1}, {}, {2, 3}},
			"ids": []uint32{4, 5}}, true},
		{"empty bytes in a byte list", map[string]any{"many": [][]byte{{}, {0}}}, true},
		{"empty byte list", map[string]any{"data": [][]byte{}}, true},

		{"uint32 overflow", map[string]any{"u32": uint64(1 << 32)}, false},
		{"negative unsigned", map[string]any{"u64": -1}, false},
		{"int32 overflow", map[string]any{"i32": int64(math.MaxInt32) + 1}, false},
		{"int32 underflow", map[string]any{"i32": int64(math.MinInt32) - 1}, false},
		{"invalid utf8", map[string]any{"name": "\xff"}, false},
		{"unknown field", map[string]any{"nope": 1}, false},
		{"unknown nested field", map[string]any{"one": map[string]any{"nope": 1}}, false},
		{"field named twice", map[string]any{"json_named": uint32(1), "jsonNamed": uint32(2)}, false},
		{"two oneof members", map[string]any{"by_id": uint32(1), "by_name": "x"}, false},
		{"json.Number", map[string]any{"u64": json.Number("18446744073709551615")}, false},
		{"string for bytes", map[string]any{"blob": "AQI="}, false},
		{"nil bytes", map[string]any{"blob": []byte(nil)}, false},
		{"nil list", map[string]any{"ids": []uint32(nil)}, false},
		{"bytes for a list", map[string]any{"ids": []byte{1}}, false},
		{"ints for a message list", map[string]any{"many": []uint32{1}}, false},
		{"ints for a bool list", map[string]any{"flags": []uint32{1}}, false},
		{"maps for a scalar list", map[string]any{"ids": []map[string]any{{}}}, false},
		{"nil message in a list", map[string]any{"many": []map[string]any{nil}}, false},
		{"nil in a byte list", map[string]any{"data": [][]byte{{1}, nil}}, false},
		{"nil byte list", map[string]any{"data": [][]byte(nil)}, false},
		{"byte list for a message of two bytes fields", map[string]any{"pairs": [][]byte{{1}}}, false},
		{"double", map[string]any{"rate": 1.5}, false},
		{"int for double", map[string]any{"rate": 2}, false},
		{"enum number", map[string]any{"mode": 1}, false},
		{"unknown enum name", map[string]any{"mode": "MODE_X"}, false},
		{"proto map", map[string]any{"labels": map[string]any{"a": "b"}}, false},
		{"nil message", map[string]any{"one": nil}, false},
		{"string for int", map[string]any{"u32": "7"}, false},
	}
}

type fieldCase struct {
	name string
	in   map[string]any
	fast bool
}

// jsonForms is, by case name, the input as protojson reads it where the case
// uses a form of fill's own (a [][]byte of sole-bytes messages).
func jsonForms() map[string]map[string]any {
	field := func(b ...byte) map[string]any { return map[string]any{"value_bin": b} }
	return map[string]map[string]any{
		"rule key as byte lists": {"data": []map[string]any{field(1), field([]byte{}...), field(2, 3)},
			"ids": []uint32{4, 5}},
		"empty bytes in a byte list": {"many": []map[string]any{field([]byte{}...), field(0)}},
		"empty byte list":            {"data": []map[string]any{}},
	}
}

// fill must answer exactly what the JSON path answers, or step aside: every
// input either converts on both paths to equal messages, or fill reports false
// and the JSON path's own answer -- message or error -- stands.
func TestFillMatchesProtojson(t *testing.T) {
	md := fieldsSchema(t)
	for _, c := range fieldCases() {
		t.Run(c.name, func(t *testing.T) {
			fast := dynamicpb.NewMessage(md)
			ok := fill(fast, c.in)
			if ok != c.fast {
				t.Fatalf("fill took the fast path: %v, want %v", ok, c.fast)
			}
			jsonIn := c.in
			if alt, ok := jsonForms()[c.name]; ok {
				jsonIn = alt
			}
			raw, err := json.Marshal(jsonIn)
			if err != nil {
				t.Fatal(err)
			}
			slow := dynamicpb.NewMessage(md)
			slowErr := protojson.Unmarshal(raw, slow)
			if !ok {
				return // the JSON path's answer is the answer
			}
			if slowErr != nil {
				t.Fatalf("fill converted what protojson refuses (%v)", slowErr)
			}
			if !proto.Equal(fast, slow) {
				t.Errorf("fill: %v\nprotojson: %v", fast, slow)
			}
		})
	}
}

// Message keeps its contract on the fallback: a field map fill hands back is
// converted by protojson on a fresh message, and its refusal is protojson's.
func TestMessageFallsBackToJSON(t *testing.T) {
	md := fieldsSchema(t)
	registry := new(protoregistry.Files)
	if err := registry.RegisterFile(md.ParentFile()); err != nil {
		t.Fatal(err)
	}
	c := &Client{files: registry}
	m, err := c.Message("t.All", map[string]any{"u32": uint32(1), "blob": "AQI="})
	if err != nil {
		t.Fatal(err)
	}
	got := m.ProtoReflect()
	if got.Get(md.Fields().ByName("u32")).Uint() != 1 || string(got.Get(md.Fields().ByName("blob")).Bytes()) != "\x01\x02" {
		t.Errorf("fallback message %v", m)
	}
	if _, err := c.Message("t.All", map[string]any{"u32": uint64(1 << 32)}); err == nil {
		t.Error("an out-of-range value was accepted")
	}
}
