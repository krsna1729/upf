// SPDX-License-Identifier: BSD-3-Clause

package bess

import (
	"context"
	"sync/atomic"

	"google.golang.org/grpc"

	pb "github.com/krsna1729/bess/sdk/go/controlv2"
)

// FrameStats is what the transaction channel carried: the acknowledgement
// frames bessd answered and the transaction results in them. Transactions per
// frame is how many commits shared one gRPC message, and so one per-message
// cost on each side. A refused frame counts as a frame with no results; a
// frame that was never answered is not counted.
type FrameStats struct {
	Frames       uint64
	Transactions uint64
}

// frameCounter counts every TransactionChannel acknowledgement the client
// receives. It reads the SDK's exported reply type at the gRPC stream, so it
// needs nothing from the SDK's batching internals.
type frameCounter struct {
	frames       atomic.Uint64
	transactions atomic.Uint64
}

func (f *frameCounter) stats() FrameStats {
	return FrameStats{Frames: f.frames.Load(), Transactions: f.transactions.Load()}
}

// intercept wraps each TransactionChannel stream; every other stream passes
// through untouched.
func (f *frameCounter) intercept(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn,
	method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	s, err := streamer(ctx, desc, cc, method, opts...)
	if err != nil || method != pb.Control_TransactionChannel_FullMethodName {
		return s, err
	}
	return &countedStream{ClientStream: s, f: f}, nil
}

type countedStream struct {
	grpc.ClientStream
	f *frameCounter
}

func (s *countedStream) RecvMsg(m any) error {
	if err := s.ClientStream.RecvMsg(m); err != nil {
		return err
	}
	if r, ok := m.(*pb.TransactionChannelResponse); ok {
		s.f.frames.Add(1)
		s.f.transactions.Add(uint64(len(r.GetResults())))
	}
	return nil
}
