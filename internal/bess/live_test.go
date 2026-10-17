// SPDX-License-Identifier: BSD-3-Clause

package bess

import (
	"context"
	"os"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// The client needs a daemon and nothing else: everything this package does --
// reading the schema, naming resources, building messages from the descriptors --
// is asked of a running bessd. ci/session-live.sh starts one and sets
// UPF_BESS_TARGET; without it these tests and benchmarks skip.

// liveClient dials the daemon under test and hands back a refreshed client.
func liveClient(tb testing.TB) *Client {
	tb.Helper()
	target := os.Getenv("UPF_BESS_TARGET")
	if target == "" {
		tb.Skip("set UPF_BESS_TARGET (ci/session-live.sh does) to run against a live bessd")
	}
	ctx := context.Background()
	c, err := Dial(ctx, target)
	if err != nil {
		tb.Fatalf("dialing %s: %v", target, err)
	}
	tb.Cleanup(func() { c.Close() })
	if err := c.Refresh(ctx); err != nil {
		tb.Fatalf("reading the daemon's schema: %v", err)
	}
	return c
}

// TestLiveSchemaAndMessage: what this package promises is that a caller needs no
// generated code -- the daemon's schema is the contract. That is checked here
// against the real schema: every resource has a type, and a message of that type
// can be built and asked for its own descriptor.
func TestLiveSchemaAndMessage(t *testing.T) {
	c := liveClient(t)

	if c.Version() == "" {
		t.Error("the daemon reports no version")
	}
	if c.Epoch() == 0 {
		t.Error("the daemon reports epoch 0, which is what an unread schema has")
	}

	names := c.ResourceNames()
	if len(names) == 0 {
		t.Fatal("the daemon reports no resources: the graph is not applied")
	}

	for _, name := range names {
		r, err := c.Resource(name)
		if err != nil {
			t.Errorf("Resource(%q): %v", name, err)
			continue
		}
		if r.Name != name || r.ValueType == "" {
			t.Errorf("resource %q: name %q, value type %q", name, r.Name, r.ValueType)
			continue
		}
		m, err := c.Message(r.ValueType, nil)
		if err != nil {
			t.Errorf("Message(%q) for resource %q: %v", r.ValueType, name, err)
			continue
		}
		if got := string(m.ProtoReflect().Descriptor().FullName()); got != r.ValueType {
			t.Errorf("resource %q: built %s, wanted %s", name, got, r.ValueType)
		}
	}

	// An unknown resource and an unknown type are refusals, not empty values: a
	// name that is not in the graph is a graph that must be fixed.
	if _, err := c.Resource("no_such_module/rules"); err == nil {
		t.Error("Resource accepted a name the daemon does not have")
	}
	if _, err := c.Message("no.Such.Message", nil); err == nil {
		t.Error("Message accepted a type the schema does not have")
	}
}

// BenchmarkLiveCapabilities is the floor every RPC pays: one round trip that does
// no work on the daemon. A transaction's cost is measured against this, not
// against zero -- when a Commit looks slow, this says how much of it is the
// socket and how much is the daemon's own going.
func BenchmarkLiveCapabilities(b *testing.B) {
	c := liveClient(b)
	sdk := c.SDK()
	ctx := context.Background()

	b.ReportAllocs()
	for b.Loop() {
		if _, err := sdk.Capabilities(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

// scalarFields is the field map a change carries, for the fields of one type: the
// numbers get 1, the strings and bytes their field's own name. It is built from
// the descriptor the daemon reports, and it is what Client.Apply hands to
// Message for every key and every value of a transaction. Nested messages are
// left empty -- the cost this measures is the schema-driven conversion, not the
// semantics of one plugin's table.
func scalarFields(m protoreflect.Message) map[string]any {
	fields := map[string]any{}
	md := m.Descriptor()
	for i := 0; i < md.Fields().Len(); i++ {
		fd := md.Fields().Get(i)
		name := fd.JSONName()
		switch fd.Kind() {
		case protoreflect.StringKind:
			fields[name] = string(fd.Name())
		case protoreflect.BytesKind:
			fields[name] = []byte(fd.Name())
		case protoreflect.BoolKind:
			fields[name] = true
		case protoreflect.EnumKind:
			fields[name] = float64(1)
		case protoreflect.FloatKind, protoreflect.DoubleKind:
			fields[name] = float64(1)
		case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind,
			protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind,
			protoreflect.Uint32Kind, protoreflect.Fixed32Kind,
			protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
			fields[name] = float64(1)
		}
	}
	return fields
}

// BenchmarkLiveMessage is the schema-driven message building against the real
// descriptors, with a real field map: this is the conversion Client.Apply does
// for every key and every value of a session's transaction. Every distinct value
// type the graph declares gets its own case, because they differ by an order of
// magnitude -- a rule with masks is not a settings message with one number -- and
// a single number from whichever table came first would say nothing.
func BenchmarkLiveMessage(b *testing.B) {
	c := liveClient(b)
	seen := map[string]bool{}
	for _, name := range c.ResourceNames() {
		r, err := c.Resource(name)
		if err != nil || r.ValueType == "" || seen[r.ValueType] {
			continue
		}
		seen[r.ValueType] = true
		b.Run(r.ValueType, func(b *testing.B) {
			benchmarkMessage(b, c, r.ValueType)
		})
	}
	if len(seen) == 0 {
		b.Fatal("no resource with a value type")
	}
}

// benchmarkMessage is one type's conversion: build the field map from the
// descriptor once, then build messages from it.
func benchmarkMessage(b *testing.B, c *Client, typ string) {
	empty, err := c.Message(typ, nil)
	if err != nil {
		b.Fatal(err)
	}
	fields := scalarFields(empty.ProtoReflect())
	if len(fields) == 0 {
		b.Skipf("%s has no scalar fields to set", typ)
	}

	b.ReportAllocs()
	for b.Loop() {
		m, err := c.Message(typ, fields)
		if err != nil {
			b.Fatal(err)
		}
		_ = m.ProtoReflect().Descriptor().FullName()
	}
}
