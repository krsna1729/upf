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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"

	sdk "github.com/krsna1729/bess/sdk/go/bess"
	pb "github.com/krsna1729/bess/sdk/go/controlv2"
)

// Client is one bessd's control endpoint plus its schema.
type Client struct {
	sdk *sdk.Client

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
	c := &Client{sdk: conn}
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
