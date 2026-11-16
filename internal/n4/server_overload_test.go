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

type congestedHandler struct {
	shutdownHandler
	entered chan struct{}
	release chan struct{}
}

func (h *congestedHandler) Modify(req *message.SessionModificationRequest) message.Message {
	select {
	case <-h.entered:
	default:
		close(h.entered)
	}
	<-h.release
	return message.NewSessionModificationResponse(0, 0, 42, req.Sequence(), 0, ie.NewCause(ie.CauseRequestAccepted))
}

func (*congestedHandler) ResponseSEID(uint64) uint64 { return 42 }

func TestFullSessionQueueRefusesRequestsWithoutBlockingHeartbeat(t *testing.T) {
	h := &congestedHandler{entered: make(chan struct{}), release: make(chan struct{})}
	srv, err := New(Config{NodeID: "127.0.0.1", Listen: "127.0.0.1:0", Sessions: h,
		SessionWorkers: 2, HeartbeatEvery: time.Hour, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve() }()
	defer func() {
		close(h.release)
		srv.Close()
		select {
		case err := <-served:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("Serve did not stop")
		}
	}()
	conn, err := net.DialUDP("udp", nil, srv.Addr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	send := func(req message.Message) {
		t.Helper()
		wire := make([]byte, req.MarshalLen())
		if err := req.MarshalTo(wire); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write(wire); err != nil {
			t.Fatal(err)
		}
	}
	buffer := make([]byte, maxDatagram)
	receive := func() message.Message {
		t.Helper()
		if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		n, err := conn.Read(buffer)
		if err != nil {
			t.Fatal(err)
		}
		response, err := message.Parse(buffer[:n])
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	send(message.NewAssociationSetupRequest(1, ie.NewNodeID("127.0.0.1", "", ""), ie.NewRecoveryTimeStamp(time.Now())))
	if _, ok := receive().(*message.AssociationSetupResponse); !ok {
		t.Fatal("association response missing")
	}
	request := message.NewSessionModificationRequest(0, 0, 2, 2, 0)
	send(request)
	select {
	case <-h.entered:
	case <-time.After(time.Second):
		t.Fatal("session worker did not start")
	}
	queue := srv.work[sessionKey(request)%uint64(len(srv.work))]
	for i := range cap(queue) {
		send(message.NewSessionModificationRequest(0, 0, 2, uint32(i+10), 0))
	}
	cases := []struct {
		request  message.Message
		peerSEID uint64
	}{
		{message.NewSessionModificationRequest(0, 0, 2, 1000, 0), 42},
		{message.NewSessionDeletionRequest(0, 0, 2, 1001, 0), 42},
		{message.NewSessionEstablishmentRequest(0, 0, 0, 1002, 0, ie.NewFSEID(2, nil, nil)), 2},
	}
	for _, test := range cases {
		send(test.request)
		response := receive()
		if response.Sequence() != test.request.Sequence() || response.SEID() != test.peerSEID || response.MessageType() != test.request.MessageType()+1 {
			t.Fatalf("wrong refusal correlation: %s SEID=%d sequence=%d", response.MessageTypeName(), response.SEID(), response.Sequence())
		}
		var cause *ie.IE
		switch response := response.(type) {
		case *message.SessionEstablishmentResponse:
			cause = response.Cause
			if response.NodeID == nil {
				t.Fatal("refused establishment omitted mandatory Node ID")
			}
		case *message.SessionModificationResponse:
			cause = response.Cause
		case *message.SessionDeletionResponse:
			cause = response.Cause
		default:
			t.Fatalf("unexpected response %T", response)
		}
		if got, err := cause.Cause(); err != nil || got != ie.CauseNoResourcesAvailable {
			t.Fatalf("queue-full cause=%d error=%v", got, err)
		}
	}
	send(message.NewHeartbeatRequest(2000, ie.NewRecoveryTimeStamp(time.Now()), nil))
	if response, ok := receive().(*message.HeartbeatResponse); !ok || response.Sequence() != 2000 {
		t.Fatal("full session queue blocked the heartbeat response")
	}
}
