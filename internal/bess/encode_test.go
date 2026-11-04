// SPDX-License-Identifier: BSD-3-Clause

package bess

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/krsna1729/upf/internal/scaletest"
)

// requiredSchema is a proto2 type whose own field and nested message's field
// are required: fill's message must pass proto.CheckInitialized, so encode
// must refuse wherever either is missing.
func requiredSchema(t *testing.T) protoreflect.MessageDescriptor {
	t.Helper()
	req := descriptorpb.FieldDescriptorProto_LABEL_REQUIRED.Enum()
	opt := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum()
	file, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name: proto.String("required.proto"), Package: proto.String("r"), Syntax: proto.String("proto2"),
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: proto.String("R"),
			Field: []*descriptorpb.FieldDescriptorProto{
				{Name: proto.String("x"), Number: proto.Int32(1), Label: req, Type: descriptorpb.FieldDescriptorProto_TYPE_UINT32.Enum()},
				{Name: proto.String("child"), Number: proto.Int32(2), Label: opt, Type: descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(), TypeName: proto.String(".r.R")},
				{Name: proto.String("note"), Number: proto.Int32(3), Label: opt, Type: descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum()},
			},
		}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return file.Messages().ByName("R")
}

// encode must answer exactly what fill answers: the same verdict for every
// input, and where both convert, the bytes of fill's message -- the bytes a
// deterministic proto.Marshal writes, which the schemas' field order (by
// number) makes comparable byte for byte.
func TestEncodeMatchesFill(t *testing.T) {
	all := fieldsSchema(t)
	cases := fieldCases()
	type schemaCase struct {
		md protoreflect.MessageDescriptor
		fieldCase
	}
	var run []schemaCase
	for _, c := range cases {
		run = append(run, schemaCase{all, c})
	}
	r := requiredSchema(t)
	for _, c := range []fieldCase{
		{"required set", map[string]any{"x": uint32(1)}, true},
		{"proto2 optional at zero", map[string]any{"x": uint32(0), "note": ""}, true},
		{"nested required set", map[string]any{"x": uint32(1), "child": map[string]any{"x": uint32(2)}}, true},
		{"required missing", map[string]any{"note": "n"}, false},
		{"nested required missing", map[string]any{"x": uint32(1), "child": map[string]any{}}, false},
	} {
		run = append(run, schemaCase{r, c})
	}
	for _, c := range run {
		t.Run(c.name, func(t *testing.T) {
			want := dynamicpb.NewMessage(c.md)
			filled := fill(want, c.in)
			got, ok := encode(nil, c.md, c.in)
			if ok != filled {
				t.Fatalf("encode converted: %v; fill converted: %v", ok, filled)
			}
			if !ok {
				return
			}
			raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(want)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, raw) {
				t.Errorf("encode wrote % x\nfill's message marshals to % x", got, raw)
			}
		})
	}
}

// wire's message is what the daemon would read from Message's: the same
// bytes on the wire. A type with required fields of its own takes Message's
// path (the marshal's check cannot see fields carried as unknown), and still
// marshals.
func TestWireMarshalsAsMessageDoes(t *testing.T) {
	registry := new(protoregistry.Files)
	for _, md := range []protoreflect.MessageDescriptor{fieldsSchema(t), requiredSchema(t)} {
		if err := registry.RegisterFile(md.ParentFile()); err != nil {
			t.Fatal(err)
		}
	}
	c := &Client{files: registry}
	for _, in := range []struct {
		typ    string
		fields map[string]any
	}{
		{"t.All", map[string]any{"u32": uint32(7), "many": []map[string]any{{"value_bin": []byte{1}}}, "ids": []uint32{3}}},
		{"t.All", map[string]any{"blob": "AQI="}}, // the JSON path
		{"r.R", map[string]any{"x": uint32(1), "child": map[string]any{"x": uint32(2)}}},
	} {
		want, err := c.Message(in.typ, in.fields)
		if err != nil {
			t.Fatal(err)
		}
		got, _, err := c.wire(nil, in.typ, in.fields)
		if err != nil {
			t.Fatalf("%s %v: %v", in.typ, in.fields, err)
		}
		o := proto.MarshalOptions{Deterministic: true}
		g, err := o.Marshal(got)
		if err != nil {
			t.Fatalf("%s %v: wire's message does not marshal: %v", in.typ, in.fields, err)
		}
		w, err := o.Marshal(want)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(g, w) {
			t.Errorf("%s %v: wire % x, Message % x", in.typ, in.fields, g, w)
		}
	}
}

// A change's key costs the same allocations whatever its field count: the
// encoded bytes go into the transaction's buffer, and the message carrying them
// is one dynamic message. Built field by field, a rule key cost allocations in
// proportion to its fields (a nested message, its value and the list growth
// for each).
func TestAWireKeyDoesNotAllocatePerField(t *testing.T) {
	md := fieldsSchema(t)
	registry := new(protoregistry.Files)
	if err := registry.RegisterFile(md.ParentFile()); err != nil {
		t.Fatal(err)
	}
	c := &Client{files: registry}
	scaletest.AllocsFollowChange(t, func(n int) func() {
		values := make([]map[string]any, n)
		for i := range values {
			values[i] = map[string]any{"value_bin": []byte{byte(i), 1, 2, 3}}
		}
		key := map[string]any{"many": values, "ids": []uint32{1, 2}, "one": map[string]any{"value_bin": []byte{0xff}}}
		buf := make([]byte, 0, 16*n+64)
		return func() {
			if _, _, err := c.wire(buf[:0], "t.All", key); err != nil {
				t.Fatal(err)
			}
		}
	}, [2]int{8, 512}, 0)
}
