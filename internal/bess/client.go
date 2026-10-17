// SPDX-License-Identifier: BSD-3-Clause

// Package bess is what the UPF's session layer needs from BESS: the Go SDK
// (github.com/krsna1729/bess/sdk/go), the daemon's own schema, and one
// transaction per session change.
//
// A change is a resource by name ("at/actions", "pdr/rules") with key and value
// fields as plain Go values. The messages are built from the descriptor set the
// daemon reports (control_v2.GetSchema), so the UPF needs no generated code for
// BESS's protobufs or for the datapath plugin's: the daemon's schema is the
// contract, exactly as it is for a manifest or the C++ perf clients.
//
// Nothing here holds session state. A compiler rebuilds a session from the PFCP
// message it is handling, and a restarted controller rebuilds it from the
// sessions the SMF replays (see docs/design.md).
package bess

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/anypb"

	sdk "github.com/krsna1729/bess/sdk/go/bess"
	pb "github.com/krsna1729/bess/sdk/go/controlv2"
)

// kMaxInFlight bounds concurrent transactions to one daemon. The engine has a
// cascade budget: past it every transaction slows and answers `busy`, so a
// client that fires hundreds of applies at once stalls the control plane
// instead of going faster (measured: 256 concurrent applies to one session
// graph answered 8 and then stalled for 30 s at a time).
const kMaxInFlight = 32

// Client is one bessd's control endpoint plus its schema.
type Client struct {
	sdk *sdk.Client

	inFlight chan struct{}

	mu      sync.Mutex
	files   *protoregistry.Files
	types   map[string]sdk.Resource
	epoch   uint64
	version string
}

// Dial connects to bessd's gRPC endpoint and reads its schema.
func Dial(ctx context.Context, target string) (*Client, error) {
	conn, err := sdk.Dial(target)
	if err != nil {
		return nil, fmt.Errorf("bess: dial %s: %w", target, err)
	}
	c := &Client{sdk: conn, inFlight: make(chan struct{}, kMaxInFlight)}
	if err := c.Refresh(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	return c, nil
}

// Close closes the connection.
func (c *Client) Close() error { return c.sdk.Close() }

// SDK is the underlying client, for the calls this package does not wrap
// (metrics, events, the pipeline).
func (c *Client) SDK() *sdk.Client { return c.sdk }

// Refresh re-reads the daemon's schema and resource names. A plugin import, a
// graph change or a daemon restart makes this necessary.
func (c *Client) Refresh(ctx context.Context) error {
	schema, err := c.sdk.Schema(ctx)
	if err != nil {
		return fmt.Errorf("bess: schema: %w", err)
	}
	files, err := protodesc.NewFiles(schema.GetDescriptors())
	if err != nil {
		return fmt.Errorf("bess: schema descriptors: %w", err)
	}
	resources, err := c.sdk.Resources(ctx, true)
	if err != nil {
		return fmt.Errorf("bess: resources: %w", err)
	}
	caps, err := c.sdk.Capabilities(ctx)
	if err != nil {
		return fmt.Errorf("bess: capabilities: %w", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.files, c.types = files, resources
	c.epoch, c.version = caps.GetDaemonEpoch(), caps.GetDaemonVersion()
	return nil
}

// Epoch is the daemon epoch the last Refresh saw (0 before one).
func (c *Client) Epoch() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.epoch
}

// Version is the daemon's version string.
func (c *Client) Version() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.version
}

// Resource is a transactional resource the daemon reports ("<module>/<table>").
func (c *Client) Resource(name string) (sdk.Resource, error) {
	c.mu.Lock()
	r, ok := c.types[name]
	c.mu.Unlock()
	if !ok {
		return sdk.Resource{}, fmt.Errorf(
			"bess: no resource %q: the module registering it is not in the graph", name)
	}
	return r, nil
}

// ResourceNames lists the resources the daemon has, sorted.
func (c *Client) ResourceNames() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	names := make([]string, 0, len(c.types))
	for name := range c.types {
		names = append(names, name)
	}
	return names
}

// Message builds a message of the named protobuf type from field values, which
// are named as the JSON form of the message (the same names a manifest uses).
func (c *Client) Message(typ string, fields map[string]any) (proto.Message, error) {
	c.mu.Lock()
	files := c.files
	c.mu.Unlock()
	if files == nil {
		return nil, errors.New("bess: no schema: call Refresh")
	}
	d, err := files.FindDescriptorByName(protoreflect.FullName(typ))
	if err != nil {
		return nil, fmt.Errorf("bess: no type %s in the schema", typ)
	}
	md, ok := d.(protoreflect.MessageDescriptor)
	if !ok {
		return nil, fmt.Errorf("bess: %s is not a message", typ)
	}
	m := dynamicpb.NewMessage(md)
	if fields == nil {
		return m, nil
	}
	raw, err := json.Marshal(fields)
	if err != nil {
		return nil, fmt.Errorf("bess: %s fields: %w", typ, err)
	}
	if err := protojson.Unmarshal(raw, m); err != nil {
		return nil, fmt.Errorf("bess: %s from %s: %w", typ, raw, err)
	}
	return m, nil
}

// messageFrom unpacks an Any the daemon sent. The type comes from the daemon's
// own schema: the process's global registry knows none of the daemon's
// messages, so anypb.UnmarshalNew would answer "proto: not found" for every
// entry of every resource.
func (c *Client) messageFrom(a *anypb.Any) (proto.Message, error) {
	name := a.MessageName()
	if name == "" {
		return nil, fmt.Errorf("an entry with no type name (%q)", a.GetTypeUrl())
	}
	c.mu.Lock()
	files := c.files
	c.mu.Unlock()
	if files == nil {
		return nil, errors.New("bess: no schema: call Refresh")
	}
	d, err := files.FindDescriptorByName(name)
	if err != nil {
		return nil, fmt.Errorf("bess: no type %s in the schema", name)
	}
	md, ok := d.(protoreflect.MessageDescriptor)
	if !ok {
		return nil, fmt.Errorf("bess: %s is not a message", name)
	}
	m := dynamicpb.NewMessage(md)
	if err := a.UnmarshalTo(m); err != nil {
		return nil, err
	}
	return m, nil
}

// messageMap is the inverse of Message: a message's fields as the JSON form
// names them, ready to hand back to Message. Numbers stay json.Number, because
// a key carrying a 64-bit id must not pass through a float.
func messageMap(m proto.Message) (map[string]any, error) {
	raw, err := protojson.Marshal(m)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	fields := map[string]any{}
	if err := dec.Decode(&fields); err != nil {
		return nil, err
	}
	return fields, nil
}

// RuleCount is what one rule's traffic measured: the ActionId its counter is
// keyed by, and the packets and the IP octets of them that crossed the rule,
// with every worker's plane summed (a reading is exact for each cell -- a
// worker writes only its own -- not one global instant).
//
// First and Last are when the rule's first and last counted packet crossed, as
// absolute time: the module stamps them on its own monotonic clock and the
// reading carries the wall clock it read them at, so this side places them on
// the clock an SMF reads (TS 29.244 8.2.44, 8.2.45). First is the first packet
// since the previous reading -- a reading clears it, so each reporting window
// measures its own start -- and either is zero when no packet was counted.
type RuleCount struct {
	ActionID uint32
	Packets  uint64
	Octets   uint64
	First    time.Time
	Last     time.Time
}

// RuleCounts asks a counting module for the counters of the named rules, or of
// every rule it holds when none are named, through the module's own get_counts
// action, and for the next window: the module clears each rule's first-packet
// stamp when a reading asks it to, so a diagnostic read of the same command
// (an operator's, a test's) finds the window's first packet where the last
// report left it. The message names are the plugin's
// (datapath/upf_datapath.proto), so a graph without that module -- or one built
// against another schema -- is an error here and not an empty reading: a
// reporter that read silence as zero usage would report nothing forever.
func (c *Client) RuleCounts(ctx context.Context, module string, actionIDs ...uint32) ([]RuleCount, error) {
	arg, err := c.Message("upf.pb.UrrCountCommandGetCountsArg",
		map[string]any{"action_ids": actionIDs, "restart_window": true})
	if err != nil {
		return nil, err
	}
	result, err := c.sdk.InvokeAction(ctx, module, "get_counts", arg)
	if err != nil {
		return nil, fmt.Errorf("bess: %s get_counts: %w", module, err)
	}
	response, err := c.Message("upf.pb.UrrCountCommandGetCountsResponse", nil)
	if err != nil {
		return nil, err
	}
	if err := result.UnmarshalTo(response); err != nil {
		return nil, fmt.Errorf("bess: %s get_counts answered %s: %w", module, result.GetTypeUrl(), err)
	}
	fields := response.ProtoReflect().Descriptor().Fields()
	counts := response.ProtoReflect().Get(fields.ByName("counts")).List()
	// The reading's clock: the per-rule stamps are in the module's monotonic
	// domain, and the wall clock it read at the same instant is what places them
	// on the clock a PFCP timestamp carries. A daemon whose plugin predates the
	// stamps has no such field at all -- uintField answers 0 and the times are
	// unknown, rather than the reporting loop panicking on a nil descriptor.
	mono := uintField(response.ProtoReflect(), "read_monotonic_ns")
	wall := int64(uintField(response.ProtoReflect(), "read_wall_unix_ns"))
	out := make([]RuleCount, 0, counts.Len())
	for i := range counts.Len() {
		rule := counts.Get(i).Message()
		out = append(out, RuleCount{
			ActionID: uint32(uintField(rule, "action_id")),
			Packets:  uintField(rule, "packets"),
			Octets:   uintField(rule, "octets"),
			First:    packetTime(uintField(rule, "first_packet_ns"), mono, wall),
			Last:     packetTime(uintField(rule, "last_packet_ns"), mono, wall),
		})
	}
	return out, nil
}

// uintField is a uint field of a message the daemon's own schema defines, or 0
// when that schema has no such field: a plugin built before a field existed
// must read as "no value", never as a panic.
func uintField(m protoreflect.Message, name string) uint64 {
	fd := m.Descriptor().Fields().ByName(protoreflect.Name(name))
	if fd == nil {
		return 0
	}
	return m.Get(fd).Uint()
}

// packetTime places a rule's stamp -- nanoseconds of the module's own monotonic
// clock -- on the wall clock, from the pair the reading carried: the module
// stamped the packet's arrival and then, when the reading ran, stamped the wall
// clock at the same instant, so a packet's absolute time is that wall clock
// less the time between the packet and the reading. A zero stamp ("no packet
// counted") is unknown -- time.Time's zero value, never an invented instant --
// and a stamp older than this reading (a rule whose ActionId was reissued)
// converts to an earlier instant, which the caller gates on: a window in which
// nothing was counted carries no time to report.
func packetTime(stamp, mono uint64, wallNs int64) time.Time {
	if stamp == 0 {
		return time.Time{}
	}
	return time.Unix(0, wallNs+int64(stamp)-int64(mono))
}

// Change is one resource edit of a session's transaction: a map resource's key
// and value, or a singleton's value alone. A nil Value erases the key.
type Change struct {
	Resource string
	Key      map[string]any
	Value    map[string]any
}

// Apply writes every change in one transaction. The daemon validates all of
// them, applies all or nothing, and a change whose own resource is missing is
// refused rather than half-applied (control_v2's D-129 semantics). The error is
// the SDK's typed one, so a caller can tell a refusal from a conflict, a busy
// dataplane or an unknown outcome.
func (c *Client) Apply(ctx context.Context, changes ...Change) error {
	if len(changes) == 0 {
		return errors.New("bess: empty transaction")
	}
	// Bound concurrent transactions. The daemon's engine has a cascade budget,
	// and past it every transaction slows and answers busy; firing hundreds of
	// applies at once therefore stalls the control plane instead of going
	// faster. Holding this slot until the commit returns is the whole fix.
	c.inFlight <- struct{}{}
	defer func() { <-c.inFlight }()

	tx := c.sdk.Transaction()
	for i, ch := range changes {
		r, err := c.Resource(ch.Resource)
		if err != nil {
			return fmt.Errorf("change %d: %w", i, err)
		}
		if r.Kind == pb.TransactionResource_KIND_SINGLETON {
			if ch.Value == nil {
				return fmt.Errorf("change %d: resource %q is a singleton: it has no key to erase",
					i, ch.Resource)
			}
			v, err := c.Message(r.ValueType, ch.Value)
			if err != nil {
				return fmt.Errorf("change %d: %w", i, err)
			}
			if err := tx.Set(r, v); err != nil {
				return fmt.Errorf("change %d (%s): %w", i, ch.Resource, err)
			}
			continue
		}
		if ch.Key == nil {
			return fmt.Errorf("change %d: resource %q is a map: it needs a key", i, ch.Resource)
		}
		k, err := c.Message(r.KeyType, ch.Key)
		if err != nil {
			return fmt.Errorf("change %d: %w", i, err)
		}
		if ch.Value == nil {
			if err := tx.Erase(r, k); err != nil {
				return fmt.Errorf("change %d (%s): %w", i, ch.Resource, err)
			}
			continue
		}
		v, err := c.Message(r.ValueType, ch.Value)
		if err != nil {
			return fmt.Errorf("change %d: %w", i, err)
		}
		if err := tx.Upsert(r, k, v); err != nil {
			return fmt.Errorf("change %d (%s): %w", i, ch.Resource, err)
		}
	}
	if _, err := tx.Commit(ctx); err != nil {
		return err
	}
	return nil
}

// Entry is one entry of a resource as the daemon holds it: the key and value
// it was written with, still packed. A value is nil for a resource whose value
// the daemon keeps to itself.
type Entry struct {
	Key   map[string]any
	Value map[string]any
}

// Contents reads the current entries of the named resources in one round trip
// (Pipeline with include_resources), which is what a restarted controller
// needs before it can take an earlier run's sessions out. The response carries
// every named resource's entries, so a resource the daemon does not have -- a
// module the graph does not load -- comes back with none.
func (c *Client) Contents(ctx context.Context, names ...string) (map[string][]Entry, error) {
	snap, err := c.sdk.Pipeline(ctx, sdk.WithResources(names...))
	if err != nil {
		return nil, fmt.Errorf("bess: pipeline: %w", err)
	}
	got, unique := map[string][]Entry{}, map[string]bool{}
	for _, rc := range snap.Pipeline.GetResources() {
		if unique[rc.GetName()] {
			continue
		}
		unique[rc.GetName()] = true
		entries := got[rc.GetName()]
		for _, e := range rc.GetEntries() {
			var key, value map[string]any
			if e.Key != nil {
				msg, err := c.messageFrom(e.Key)
				if err != nil {
					return nil, fmt.Errorf("bess: %s entry key: %w", rc.GetName(), err)
				}
				key, err = messageMap(msg)
				if err != nil {
					return nil, fmt.Errorf("bess: %s entry key: %w", rc.GetName(), err)
				}
			}
			if e.Value != nil {
				msg, err := c.messageFrom(e.Value)
				if err != nil {
					return nil, fmt.Errorf("bess: %s entry value: %w", rc.GetName(), err)
				}
				value, err = messageMap(msg)
				if err != nil {
					return nil, fmt.Errorf("bess: %s entry value: %w", rc.GetName(), err)
				}
			}
			entries = append(entries, Entry{Key: key, Value: value})
		}
		got[rc.GetName()] = entries
	}
	if len(got) == 0 {
		return nil, fmt.Errorf("bess: the daemon listed no contents for %v: it predates include_resources, or its graph has none of them", names)
	}
	return got, nil
}

// -- typed errors --------------------------------------------------------------
//
// The SDK's error types, so a caller of this package needs no second import to
// tell a refusal from a conflict, a busy dataplane or an unknown outcome.

type (
	InvalidRequestError   = sdk.InvalidRequestError
	ConflictError         = sdk.ConflictError
	RejectedError         = sdk.RejectedError
	BusyError             = sdk.BusyError
	TransportError        = sdk.TransportError
	PipelineConflictError = sdk.PipelineConflictError
	DaemonRestartedError  = sdk.DaemonRestartedError
	StaleResourceError    = sdk.StaleResourceError
)
