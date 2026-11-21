// SPDX-License-Identifier: BSD-3-Clause

package bess

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"

	pb "github.com/krsna1729/bess/sdk/go/controlv2"
)

// framePeer is the part of bessd that Dial and Apply talk to: a schema with
// one map resource, and a transaction channel that applies every transaction
// and counts the frames it received and the transactions in them.
type framePeer struct {
	pb.UnimplementedControlServer
	frames       atomic.Uint64
	transactions atomic.Uint64
}

const framePeerEpoch = 7

func framePeerResources() []*pb.TransactionResource {
	return []*pb.TransactionResource{{Name: "m/rules", KeyType: "frames.Key",
		ValueType: "frames.Value", Kind: pb.TransactionResource_KIND_MAP}}
}

func (*framePeer) GetSchema(context.Context, *pb.GetSchemaRequest) (*pb.GetSchemaResponse, error) {
	field := func(name string) *descriptorpb.FieldDescriptorProto {
		return &descriptorpb.FieldDescriptorProto{Name: proto.String(name), Number: proto.Int32(1),
			Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
			Type:  descriptorpb.FieldDescriptorProto_TYPE_UINT32.Enum(), JsonName: proto.String(name)}
	}
	file := &descriptorpb.FileDescriptorProto{
		Name: proto.String("frames.proto"), Package: proto.String("frames"), Syntax: proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: proto.String("Key"), Field: []*descriptorpb.FieldDescriptorProto{field("id")}},
			{Name: proto.String("Value"), Field: []*descriptorpb.FieldDescriptorProto{field("v")}},
		},
	}
	return &pb.GetSchemaResponse{Descriptors: &descriptorpb.FileDescriptorSet{
		File: []*descriptorpb.FileDescriptorProto{file}}, DaemonEpoch: framePeerEpoch}, nil
}

func (*framePeer) ListTransactionResources(context.Context, *pb.ListTransactionResourcesRequest) (*pb.ListTransactionResourcesResponse, error) {
	return &pb.ListTransactionResourcesResponse{Resources: framePeerResources(), DaemonEpoch: framePeerEpoch}, nil
}

func (*framePeer) GetCapabilities(context.Context, *pb.GetCapabilitiesRequest) (*pb.GetCapabilitiesResponse, error) {
	return &pb.GetCapabilitiesResponse{DaemonVersion: "frame-peer", Resources: framePeerResources(),
		DaemonEpoch: framePeerEpoch}, nil
}

func (p *framePeer) TransactionChannel(stream grpc.BidiStreamingServer[pb.TransactionChannelRequest, pb.TransactionChannelResponse]) error {
	for {
		frame, err := stream.Recv()
		if err != nil {
			return err
		}
		p.frames.Add(1)
		p.transactions.Add(uint64(len(frame.GetTransactions())))
		reply := &pb.TransactionChannelResponse{AttemptId: frame.GetAttemptId()}
		for _, tx := range frame.GetTransactions() {
			reply.Results = append(reply.Results, &pb.TransactionChannelResult{
				Result: &pb.TransactionChannelResult_Transaction{Transaction: &pb.ApplyTransactionResponse{
					Record: &pb.TransactionRecord{RequestId: tx.GetRequestId(),
						Outcome: pb.TransactionRecord_OUTCOME_APPLIED},
					DaemonEpoch: framePeerEpoch}}})
		}
		if err := stream.Send(reply); err != nil {
			return err
		}
	}
}

// frameClient dials a framePeer through Dial, so the stream policy under test
// is the one upfd runs.
func frameClient(t *testing.T) (*Client, *framePeer) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	peer := &framePeer{}
	server := grpc.NewServer()
	pb.RegisterControlServer(server, peer)
	go server.Serve(ln)
	t.Cleanup(server.Stop)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := Dial(ctx, ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, peer
}

type frameKey struct {
	ID uint32 `json:"id"`
}

type frameValue struct {
	V uint32 `json:"v"`
}

func frameChange(id uint32) Change {
	return Change{Resource: "m/rules", Key: Fields(frameKey{ID: id}), Value: Fields(frameValue{V: 1})}
}

// TestConcurrentCommitsShareFrames: eight session workers committing at once
// share TransactionChannel frames, so gRPC's per-message cost is paid per
// frame, not per PFCP operation. With one stream per in-flight transaction
// every caller found an idle stream and each frame carried exactly one. Each
// commit is still its own transaction with its own result.
func TestConcurrentCommitsShareFrames(t *testing.T) {
	c, peer := frameClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const callers, rounds = 8, 64
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for w := range callers {
		wg.Go(func() {
			for i := range rounds {
				if err := c.Apply(ctx, frameChange(uint32(w*rounds+i))); err != nil {
					errs <- err
					return
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("a commit failed: %v", err)
	}
	frames, txns := peer.frames.Load(), peer.transactions.Load()
	if txns != callers*rounds {
		t.Fatalf("the peer received %d transactions, want %d (one per commit)", txns, callers*rounds)
	}
	t.Logf("%d callers: %d transactions in %d frames, %.2f per frame", callers, txns, frames, float64(txns)/float64(frames))
	if frames >= txns {
		t.Errorf("%d concurrent callers sent %d transactions in %d frames: one per frame, want them to share frames",
			callers, txns, frames)
	}
	// The client's own counters, which upfd exports, see the same frames.
	if got := c.FrameStats(); got.Frames != frames || got.Transactions != txns {
		t.Errorf("FrameStats = %+v, the peer counted %d frames and %d transactions", got, frames, txns)
	}
}

// TestALoneCallerSendsEachCommitAtOnce: with nobody to share a frame with, a
// commit goes out alone and returns; no timer holds it for company.
func TestALoneCallerSendsEachCommitAtOnce(t *testing.T) {
	c, peer := frameClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const commits = 16
	for i := range commits {
		if err := c.Apply(ctx, frameChange(uint32(i))); err != nil {
			t.Fatalf("commit %d: %v", i, err)
		}
	}
	if frames, txns := peer.frames.Load(), peer.transactions.Load(); frames != commits || txns != commits {
		t.Errorf("%d sequential commits took %d frames carrying %d transactions, want one each", commits, frames, txns)
	}
	if got := c.FrameStats(); got != (FrameStats{Frames: commits, Transactions: commits}) {
		t.Errorf("FrameStats = %+v, want %d frames and %d transactions", got, commits, commits)
	}
}
