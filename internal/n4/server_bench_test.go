// SPDX-License-Identifier: BSD-3-Clause

package n4

import (
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// cannedHandler answers every session message with a valid response and holds no
// state: these benchmarks measure the server -- the datagram's parse, the
// dispatch, and the reply's marshalling and send -- while the compiler behind the
// handler has its own benchmarks in internal/session.
type cannedHandler struct{}

func (cannedHandler) Establish(req *message.SessionEstablishmentRequest) message.Message {
	return message.NewSessionEstablishmentResponse(0, 0, 0x1122, req.Sequence(), 0,
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewFSEID(0x1122, nil, nil),
		ie.NewCreatedPDR(ie.NewPDRID(1), ie.NewFTEID(0x01, 0x1000, nil, nil, 0)))
}

func (cannedHandler) Modify(req *message.SessionModificationRequest) message.Message {
	return message.NewSessionModificationResponse(0, 0, 0x1122, req.Sequence(), 0,
		ie.NewCause(ie.CauseRequestAccepted))
}

func (cannedHandler) Delete(req *message.SessionDeletionRequest) message.Message {
	return message.NewSessionDeletionResponse(0, 0, 0x1122, req.Sequence(), 0,
		ie.NewCause(ie.CauseRequestAccepted))
}

func (cannedHandler) AssociationEnded(string) {}

// benchPeer is the CP function's address as the server sees it: the association
// has to arrive from the same one before session messages are answered.
// benchStart is the recovery time stamp the peer advertises: any time works, as
// long as it is a time.
var benchStart = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

var benchPeer = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}

// benchServer is a listening server whose replies go to a socket nobody reads:
// the send is what UDP costs here, and the socket is what makes it real.
func benchServer(b *testing.B) *Server {
	b.Helper()
	srv, err := New(Config{
		NodeID:   "192.0.2.9",
		Listen:   "127.0.0.1:0",
		Sessions: cannedHandler{},
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	if err := srv.Listen(); err != nil {
		b.Fatalf("Listen: %v", err)
	}
	b.Cleanup(func() { srv.Close() })

	// The association first: a session message from an unassociated peer is
	// refused before it is parsed, and that is a different path.
	assoc := message.NewAssociationSetupRequest(1,
		ie.NewNodeID("", "", "smf"), ie.NewRecoveryTimeStamp(benchStart))
	datagram := marshal(b, assoc)
	srv.handle(datagram, benchPeer)
	if _, _, associated := srv.Peer(); !associated {
		b.Fatal("the association was not accepted")
	}
	return srv
}

// marshal is the wire form of a message, as a client would send it.
func marshal(b *testing.B, m message.Message) []byte {
	b.Helper()
	buf := make([]byte, m.MarshalLen())
	if err := m.MarshalTo(buf); err != nil {
		b.Fatalf("MarshalTo: %v", err)
	}
	return buf
}

// BenchmarkHandleEstablish measures one datagram's whole way through the server:
// the parse, the association check, the handler, and the response's marshalling
// and send. It is the cost a session establishment adds to the wire, and the
// number the SMF's observed latency has underneath it.
func BenchmarkHandleEstablish(b *testing.B) {
	srv := benchServer(b)
	req := message.NewSessionEstablishmentRequest(0, 0, 0x42, 2, 0,
		ie.NewNodeID("", "", "smf"),
		ie.NewFSEID(0x42, nil, nil),
		ie.NewCreatePDR(
			ie.NewPDRID(1),
			ie.NewPrecedence(100),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, 0, net.IPv4(192, 0, 2, 1), nil, 0),
				ie.NewUEIPAddress(0x02, "10.0.0.1", "", 0, 0),
			),
			ie.NewFARID(1),
		),
		ie.NewCreateFAR(
			ie.NewFARID(1),
			ie.NewApplyAction(0x02),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore)),
		),
	)
	datagram := marshal(b, req)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		srv.handle(datagram, benchPeer)
	}
}

// BenchmarkHandleDelete is the smallest session message: the same path with the
// least to parse and answer.
func BenchmarkHandleDelete(b *testing.B) {
	srv := benchServer(b)
	req := message.NewSessionDeletionRequest(0, 0, 0x1122, 2, 0)
	datagram := marshal(b, req)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		srv.handle(datagram, benchPeer)
	}
}

// BenchmarkHandleHeartbeat is the path that runs when nothing else does: the
// keepalive the association rests on.
func BenchmarkHandleHeartbeat(b *testing.B) {
	srv := benchServer(b)
	req := message.NewHeartbeatRequest(3, ie.NewRecoveryTimeStamp(benchStart), nil)
	datagram := marshal(b, req)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		srv.handle(datagram, benchPeer)
	}
}

// BenchmarkHandleAssociationSetup is the setup itself, which a peer pays once
// per association.
func BenchmarkHandleAssociationSetup(b *testing.B) {
	srv := benchServer(b)
	req := message.NewAssociationSetupRequest(4,
		ie.NewNodeID("", "", "smf"), ie.NewRecoveryTimeStamp(benchStart))
	datagram := marshal(b, req)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		srv.handle(datagram, benchPeer)
	}
}
