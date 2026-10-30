// SPDX-License-Identifier: BSD-3-Clause

package bess

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// TestUintFieldOnASchemaWithoutIt is the fallback a daemon running an older
// plugin needs: its schema has no stamp and clock fields at all, so a reading
// must carry no times and no panic -- a nil descriptor inside the reporting
// loop would take the node's reports down with it.
func TestUintFieldOnASchemaWithoutIt(t *testing.T) {
	fdp := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("old.proto"),
		Package: proto.String("old"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: proto.String("Response"),
			Field: []*descriptorpb.FieldDescriptorProto{{
				Name:   proto.String("packets"),
				Number: proto.Int32(1),
				Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
				Type:   descriptorpb.FieldDescriptorProto_TYPE_UINT64.Enum(),
			}},
		}},
	}
	file, err := protodesc.NewFile(fdp, nil)
	if err != nil {
		t.Fatalf("building the old schema: %v", err)
	}
	md := file.Messages().ByName("Response")
	m := dynamicpb.NewMessage(md)
	if got := uintField(m, "first_packet_ns"); got != 0 {
		t.Errorf("a field the schema does not have read as %d, want 0", got)
	}
	if got := uintField(m, "read_monotonic_ns"); got != 0 {
		t.Errorf("a field the schema does not have read as %d, want 0", got)
	}
	m.Set(md.Fields().ByName("packets"), protoreflect.ValueOfUint64(7))
	if got := uintField(m, "packets"); got != 7 {
		t.Errorf("a field the schema has read as %d, want 7", got)
	}
}

// TestPacketTimePlacesAStampOnTheWallClock pins the conversion the counting
// module's stamps need: they are nanoseconds of the module's monotonic clock,
// and the reading carries the wall clock it read at, which is what an SMF's
// Time of First/Last Packet (TS 29.244 8.2.44, 8.2.45) is measured against.
// Both zeros and stamps older than the reading are unknown, never an instant.
func TestPacketTimePlacesAStampOnTheWallClock(t *testing.T) {
	wall := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	const mono = 600_000_000_000 // ten minutes into the daemon's monotonic clock
	cases := []struct {
		name  string
		stamp uint64
		want  time.Time
	}{
		{"a packet before the reading", mono - 250_000_000, wall.Add(-250 * time.Millisecond)},
		{"a packet at the reading's own instant", mono, wall},
		{"a packet stamped as the reading ran", mono + 1000, wall.Add(time.Microsecond)},
		{"no packet counted", 0, time.Time{}},
		{"the previous window's last packet (a reissued id)", mono - 60_000_000_000, wall.Add(-time.Minute)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := packetTime(c.stamp, mono, wall.UnixNano()); !got.Equal(c.want) {
				t.Errorf("packetTime(%d) = %v, want %v", c.stamp, got, c.want)
			}
		})
	}
}

// A graph's get_counts argument is byte-identical without table and works with
// the old schema. An appliance request selects exactly one of its counter
// tables; a daemon lacking that field must refuse it, never silently read a
// different table.
func TestCounterCommandTableSelection(t *testing.T) {
	for _, withTable := range []bool{false, true} {
		fields := []*descriptorpb.FieldDescriptorProto{
			{Name: proto.String("action_ids"), Number: proto.Int32(1),
				Label: descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum(),
				Type:  descriptorpb.FieldDescriptorProto_TYPE_UINT32.Enum()},
			{Name: proto.String("restart_window"), Number: proto.Int32(2),
				Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
				Type:  descriptorpb.FieldDescriptorProto_TYPE_BOOL.Enum()},
		}
		if withTable {
			fields = append(fields, &descriptorpb.FieldDescriptorProto{
				Name: proto.String("table"), Number: proto.Int32(3),
				Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
				Type:  descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
			})
		}
		file, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
			Name: proto.String("counts.proto"), Package: proto.String("upf.pb"), Syntax: proto.String("proto3"),
			MessageType: []*descriptorpb.DescriptorProto{{
				Name: proto.String("UrrCountCommandGetCountsArg"), Field: fields,
			}},
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		registry := new(protoregistry.Files)
		if err := registry.RegisterFile(file); err != nil {
			t.Fatal(err)
		}
		client := &Client{files: registry}
		for _, restart := range []bool{false, true} {
			module, got, err := client.countRequest("cnt_ul", restart, []uint32{7, 9})
			if err != nil || module != "cnt_ul" {
				t.Fatalf("graph command: module %q, error %v", module, err)
			}
			want, err := client.Message("upf.pb.UrrCountCommandGetCountsArg",
				map[string]any{"action_ids": []uint32{7, 9}, "restart_window": restart})
			if err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(got, want) {
				t.Errorf("graph argument changed: got %v, want %v", got, want)
			}
			for _, table := range []string{"counters_ul", "counters_dl", "buffer_counters"} {
				module, arg, err := client.countRequest("upf/"+table, restart, []uint32{7, 9})
				if !withTable {
					if err == nil {
						t.Error("appliance command accepted by a schema without table")
					}
					continue
				}
				if err != nil || module != "upf" {
					t.Fatalf("appliance command: module %q, error %v", module, err)
				}
				m := arg.ProtoReflect()
				if got := m.Get(m.Descriptor().Fields().ByName("table")).String(); got != table {
					t.Errorf("selected table %q, want %q", got, table)
				}
				m.Clear(m.Descriptor().Fields().ByName("table"))
				if !proto.Equal(arg, want) {
					t.Errorf("appliance changed other arguments: got %v, want %v", arg, want)
				}
			}
		}
	}
}
