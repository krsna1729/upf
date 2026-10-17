// SPDX-License-Identifier: BSD-3-Clause

package bess

import (
	"context"
	"errors"
	"reflect"
	"syscall"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/anypb"

	pb "github.com/krsna1729/bess/sdk/go/controlv2"
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

// TestFlowNotHeldReadsTheErrno covers the store's "I hold nothing for that
// flow": release and drop answer ENOENT for a flow with no entry, and the
// caller must see that as nothing-to-do rather than as a broken command. The
// mapping is by errno in the refusal's detail, so a daemon rewording its
// message cannot change the behaviour, and any other errno stays an error.
func TestFlowNotHeldReadsTheErrno(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"ENOENT is nothing held",
			&InvalidRequestError{Message: "flow id 3 not found in packet store",
				Detail: &pb.ErrorDetail{ErrnoValue: int32(syscall.ENOENT)}}, true},
		{"a different errno is a real failure",
			&InvalidRequestError{Detail: &pb.ErrorDetail{ErrnoValue: int32(syscall.EBUSY)}}, false},
		{"no detail at all", &InvalidRequestError{Message: "refused"}, false},
		{"an error from elsewhere", errors.New("the socket closed"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := errors.Is(flowNotHeld(c.err), ErrFlowNotHeld); got != c.want {
				t.Errorf("flowNotHeld(%v) recognized as nothing-held = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

// recordingStore is a stand-in for the SDK that answers busies on demand and
// remembers the order it was called in.
type recordingStore struct {
	calls     []string
	busies    int   // how many invocations answer EBUSY before anything else
	invokeErr error // what an invocation after the busies returns
	pauseErr  error
	resumeErr error
}

func (r *recordingStore) InvokeAction(ctx context.Context, module, action string, arg proto.Message) (*anypb.Any, error) {
	r.calls = append(r.calls, "invoke "+action)
	if r.busies > 0 {
		r.busies--
		return nil, &BusyError{Attempts: 1}
	}
	return nil, r.invokeErr
}

func (r *recordingStore) PauseWorkers(ctx context.Context) error {
	r.calls = append(r.calls, "pause")
	return r.pauseErr
}

func (r *recordingStore) ResumeWorkers(ctx context.Context) error {
	r.calls = append(r.calls, "resume")
	return r.resumeErr
}

// TestStoreCommandStopsTheWorkersOnlyWhenTheDaemonRefuses is the release
// path's contract with the daemon: the store's commands are thread-unsafe and
// the daemon refuses one while a worker runs the module rather than stopping
// the worker itself (core/module.cc), so the command must be tried first
// (startup's sweep must not start a graph it found stopped), stopped and
// retried when it is refused, and the workers must come back up even when the
// command failed -- otherwise one refusal leaves the datapath down.
func TestStoreCommandStopsTheWorkersOnlyWhenTheDaemonRefuses(t *testing.T) {
	var arg proto.Message // the fake never looks at it
	refused := errors.New("the daemon would not run it")
	cases := []struct {
		name      string
		s         *recordingStore
		wantCalls []string
		wantErr   error // nil means "no error at all"
	}{
		{"the module has no running worker: no pause", &recordingStore{},
			[]string{"invoke release"}, nil},
		{"refused once: stop, retry, start", &recordingStore{busies: 1},
			[]string{"invoke release", "pause", "invoke release", "resume"}, nil},
		{"refused and the retry fails: still started", &recordingStore{busies: 1, invokeErr: refused},
			[]string{"invoke release", "pause", "invoke release", "resume"}, refused},
		{"the pause itself fails: nothing is retried", &recordingStore{busies: 1, pauseErr: refused},
			[]string{"invoke release", "pause"}, refused},
		{"a failure that is not a busy: passed through", &recordingStore{invokeErr: refused},
			[]string{"invoke release"}, refused},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := storeCommandPaused(context.Background(), c.s, "buf", "release", arg)
			if c.wantErr == nil && err != nil {
				t.Fatalf("storeCommandPaused = %v, want no error", err)
			}
			if c.wantErr != nil && !errors.Is(err, c.wantErr) {
				t.Fatalf("storeCommandPaused = %v, want %v", err, c.wantErr)
			}
			if !reflect.DeepEqual(c.s.calls, c.wantCalls) {
				t.Errorf("the daemon was called as %v, want %v", c.s.calls, c.wantCalls)
			}
		})
	}
}
