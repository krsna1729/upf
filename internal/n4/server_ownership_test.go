// SPDX-License-Identifier: BSD-3-Clause

package n4

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

func TestQueuedReportAnswersOwnTheirDatagrams(t *testing.T) {
	// handle needs no socket for a report response; Listen only passes New.
	srv, err := New(Config{NodeID: "127.0.0.1", Listen: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8805}
	answers := []*message.SessionReportResponse{
		message.NewSessionReportResponse(0, 0, 0x1111, 27, 0,
			ie.NewCause(ie.CauseRequestAccepted),
			ie.NewUpdateBARWithinSessionReportResponse(ie.NewBARID(1),
				ie.NewDLBufferingDuration(10*time.Second), ie.NewDLBufferingSuggestedPacketCount(64))),
		message.NewSessionReportResponse(0, 0, 0x2222, 28, 0,
			ie.NewCause(ie.CauseSessionContextNotFound),
			ie.NewUpdateBARWithinSessionReportResponse(ie.NewBARID(2),
				ie.NewDLBufferingDuration(20*time.Second), ie.NewDLBufferingSuggestedPacketCount(128))),
	}
	buf := make([]byte, 65535)
	var waiting []*reportWait
	for _, answer := range answers {
		w := &reportWait{got: make(chan ReportAnswer, 1)}
		srv.reports[answer.Sequence()] = w
		waiting = append(waiting, w)
		data, err := answer.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		copy(buf, data)
		// handle queues the answer; reuse Serve's buffer before consuming it.
		srv.handle(buf[:len(data)], peer)
	}
	for i, w := range waiting {
		answer := <-w.got
		wantCause, _ := answers[i].Cause.Cause()
		if answer.Cause != wantCause {
			t.Errorf("answer %d cause = %d, want %d", i, answer.Cause, wantCause)
		}
		if answer.UpdateBAR == nil {
			t.Fatalf("answer %d lost its Update BAR", i)
		}
		actual, err := answer.UpdateBAR.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		want, err := answers[i].UpdateBAR.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(actual, want) {
			t.Errorf("answer %d Update BAR changed after receive-buffer reuse", i)
		}
	}
}

// shutdownHandler records association teardown; these tests deliberately leave
// the worker queues unconsumed, as workers are allowed to do after Close.
type shutdownHandler struct {
	ended chan string
}

func (*shutdownHandler) Establish(*message.SessionEstablishmentRequest) message.Message {
	return nil
}

func (*shutdownHandler) Modify(*message.SessionModificationRequest) message.Message {
	return nil
}

func (*shutdownHandler) Delete(*message.SessionDeletionRequest) message.Message {
	return nil
}

func (h *shutdownHandler) AssociationEnded(reason string) { h.ended <- reason }

func TestCloseUnblocksPendingSessionWork(t *testing.T) {
	for _, operation := range []string{"enqueue", "association drain"} {
		t.Run(operation, func(t *testing.T) {
			h := &shutdownHandler{ended: make(chan string, 1)}
			srv, err := New(Config{
				NodeID: "127.0.0.1", Listen: "127.0.0.1:0",
				Sessions: h, SessionWorkers: 2,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { srv.Close() })
			from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8805}
			srv.peer = &peer{addr: from}
			var run func()
			if operation == "enqueue" {
				q := srv.work[0]
				for range cap(q) {
					q <- sessionWork{}
				}
				srv.queued = cap(q)
				run = func() {
					srv.onSession(message.NewSessionModificationRequest(0, 0, 2, 1, 0), from)
				}
			} else {
				srv.queued = 1
				run = func() { srv.ended("released") }
			}
			returned := make(chan struct{})
			go func() {
				run()
				close(returned)
			}()
			if err := srv.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-returned:
			case <-time.After(time.Second):
				t.Fatal("Close left session work blocked")
			}
			if operation == "enqueue" {
				srv.queuedMu.Lock()
				queued := srv.queued
				srv.queuedMu.Unlock()
				if queued != sessionQueue {
					t.Fatalf("cancelled enqueue left queued = %d, want %d", queued, sessionQueue)
				}
			}
			select {
			case reason := <-h.ended:
				t.Fatalf("association ended before pending sessions answered: %s", reason)
			default:
			}
		})
	}
}
