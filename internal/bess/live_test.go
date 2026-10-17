// SPDX-License-Identifier: BSD-3-Clause

package bess

import (
	"context"
	"os"
	"testing"
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

// BenchmarkLiveMessage is the schema-driven message building against the real
// descriptors. It is small -- 258 ns and 3 allocations a message, so the eleven
// a session builds are a few microseconds of its compile -- which is worth
// knowing before anyone blames the dynamic messages for the compiler's cost.
func BenchmarkLiveMessage(b *testing.B) {
	c := liveClient(b)

	// The first resource with a value type: the graph's first table. Its type is
	// what a session's rules are built as.
	var typ string
	for _, name := range c.ResourceNames() {
		r, err := c.Resource(name)
		if err != nil || r.ValueType == "" {
			continue
		}
		typ = r.ValueType
		break
	}
	if typ == "" {
		b.Fatal("no resource with a value type")
	}

	b.ReportAllocs()
	for b.Loop() {
		m, err := c.Message(typ, nil)
		if err != nil {
			b.Fatal(err)
		}
		_ = m.ProtoReflect().Descriptor().FullName()
	}
}
