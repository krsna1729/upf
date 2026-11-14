// SPDX-License-Identifier: BSD-3-Clause

package bess

import (
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/structpb"
)

type payloadZero uint32

func (v payloadZero) IsZero() bool { return v == 7 }

type payloadCustom uint32

func (payloadCustom) MarshalJSON() ([]byte, error) { return []byte("7"), nil }

// These are representation-boundary cases: the existing map/action encoder's
// tests do not cover typed nil, struct tags, or present-zero pointer payloads.
func TestTypedPayloadPresenceAndValidation(t *testing.T) {
	all, required := fieldsSchema(t), requiredSchema(t)
	zero := uint32(0)
	type child struct {
		X uint32 `json:"x"`
	}
	type requiredValue struct {
		X     uint32  `json:"x"`
		Child *child  `json:"child,omitempty"`
		Note  *string `json:"note,omitempty"`
	}
	note := ""
	cases := []struct {
		name    string
		md      protoreflect.MessageDescriptor
		payload Payload
		want    string
	}{
		{"required zero and optional empty", required, Fields(requiredValue{Child: &child{}, Note: &note}), `{"x":0,"child":{"x":0},"note":""}`},
		{"absent optional pointer", required, Fields(requiredValue{}), `{"x":0}`},
		{"present zero oneof", all, Fields(struct {
			ID *uint32 `json:"by_id,omitempty"`
		}{&zero}), `{"by_id":0}`},
		{"absent oneof pointer", all, Fields(struct {
			ID *uint32 `json:"by_id,omitempty"`
		}{}), `{}`},
		{"omitempty", all, Fields(struct {
			ID uint32 `json:"u32,omitempty"`
		}{}), `{}`},
		{"omitzero method", all, Fields(struct {
			ID payloadZero `json:"u32,omitzero"`
		}{7}), `{}`},
		{"explicit empty message", all, Fields(struct{}{}), `{}`},
		{"byte-list shorthand", all, Fields(struct {
			Data [][]byte `json:"data"`
		}{[][]byte{{1}, {}}}), `{"data":[{"value_bin":"AQ=="},{"value_bin":""}]}`},
		{"float32 decimal as double", all, Fields(struct {
			Rate float32 `json:"rate"`
		}{0.1}), `{"rate":0.1}`},
		{"missing required", required, Fields(struct{}{}), ""},
		{"nested required missing", required, Fields(struct {
			X     uint32   `json:"x"`
			Child struct{} `json:"child"`
		}{}), ""},
		{"nil payload", all, nil, ""},
		{"typed nil payload", all, Fields((*child)(nil)), ""},
		{"map is not a typed payload", all, Fields(map[string]uint32{"u32": 1}), ""},
		{"unknown field", all, Fields(struct {
			Unknown uint32 `json:"unknown"`
		}{}), ""},
		{"duplicate aliases", all, Fields(struct {
			A uint32 `json:"jsonNamed"`
			B uint32 `json:"json_named"`
		}{}), ""},
		{"two oneof fields", all, Fields(struct {
			ID   uint32 `json:"by_id"`
			Name string `json:"by_name"`
		}{}), ""},
		{"no implicit JSON conversion", all, Fields(struct {
			ID string `json:"u32"`
		}{"7"}), ""},
		{"custom scalar requires explicit JSON", all, Fields(struct {
			ID payloadCustom `json:"u32"`
		}{99}), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wire, _, err := encodePayload(nil, tc.md, tc.payload)
			if tc.want == "" {
				if err == nil {
					t.Fatal("invalid typed payload was accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, want := dynamicpb.NewMessage(tc.md), dynamicpb.NewMessage(tc.md)
			if err := proto.Unmarshal(wire, got); err != nil {
				t.Fatal(err)
			}
			if err := protojson.Unmarshal([]byte(tc.want), want); err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(got, want) {
				t.Fatalf("got %v, want %v", got, want)
			}
		})
	}
}

func TestExplicitJSONPayloadUsesRuntimeSchema(t *testing.T) {
	all, required := fieldsSchema(t), requiredSchema(t)
	value := (&structpb.Value{}).ProtoReflect().Descriptor()
	cases := []struct {
		name  string
		md    protoreflect.MessageDescriptor
		raw   JSON
		valid bool
	}{
		{"arbitrary maps and number forms", all, JSON(`{"labels":{"n":"v"},"rate":1.25,"u64":"18446744073709551615"}`), true},
		{"required zero", required, JSON(`{"x":0}`), true},
		{"well-known null", value, JSON(`null`), true},
		{"well-known object", value, JSON(`{"dynamic":[1,true,"x"]}`), true},
		{"missing required", required, JSON(`{}`), false},
		{"unknown field", all, JSON(`{"unknown":1}`), false},
		{"nil JSON is not erasure", all, JSON(nil), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wire, _, err := encodePayload(nil, tc.md, tc.raw)
			if !tc.valid {
				if err == nil {
					t.Fatal("invalid JSON payload was accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, want := dynamicpb.NewMessage(tc.md), dynamicpb.NewMessage(tc.md)
			if err := proto.Unmarshal(wire, got); err != nil {
				t.Fatal(err)
			}
			if err := protojson.Unmarshal(tc.raw, want); err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(got, want) {
				t.Fatalf("got %v, want %v", got, want)
			}
		})
	}
}

func TestPayloadEncodingOwnsTransactionBytes(t *testing.T) {
	md := fieldsSchema(t)
	bytes := []byte{1, 2}
	payload := Fields(struct {
		Blob []byte `json:"blob"`
	}{bytes})
	buffer := make([]byte, 0, 64)
	first, buffer, err := encodePayload(buffer, md, payload)
	if err != nil {
		t.Fatal(err)
	}
	bytes[0] = 9
	_, _, err = encodePayload(buffer, md, payload)
	if err != nil {
		t.Fatal(err)
	}
	got := dynamicpb.NewMessage(md)
	if err := proto.Unmarshal(first, got); err != nil {
		t.Fatal(err)
	}
	if blob := got.Get(md.Fields().ByName("blob")).Bytes(); len(blob) != 2 || blob[0] != 1 {
		t.Fatalf("earlier transaction bytes aliased caller or buffer growth: %v", blob)
	}
}
