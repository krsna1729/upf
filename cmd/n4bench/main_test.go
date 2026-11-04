// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// What a real SMF does with a pinned F-TEID: it makes the value unique itself,
// one per session. A bench that pins one value for a whole phase measures the
// UPF refusing all but the first, and reports it as if the path were at fault.
func TestSessionParamsPinOneValuePerSession(t *testing.T) {
	const base = 0x0a2d0000 // 10.45.0.0
	params := sessionParams(4, 0x900000, base, []string{"10.20.30.2"}, "192.0.2.1")
	if len(params) != 4 {
		t.Fatalf("asked for 4 sessions, got %d", len(params))
	}
	seen := map[uint32]bool{}
	for i, p := range params {
		if want := uint32(0x900000 + i); p.FTEID != want {
			t.Errorf("session %d pins %#x, want %#x", i, p.FTEID, want)
		}
		if seen[p.FTEID] {
			t.Errorf("session %d reuses the pinned %#x", i, p.FTEID)
		}
		seen[p.FTEID] = true
		if want := uint32(base + i); p.UEIP != offsetAddr(want, 0) {
			t.Errorf("session %d's UE address is %s, want %s", i, p.UEIP, offsetAddr(want, 0))
		}
		if p.CPSEID != uint64(0x1000+i) || p.TEID != uint32(0x100000+i) {
			t.Errorf("session %d: seids are %#x/%#x, want the per-index pair",
				i, p.CPSEID, p.TEID)
		}
		if p.GnBIP != "10.20.30.2" || p.N3IP != "192.0.2.1" {
			t.Errorf("session %d: addresses are %s/%s", i, p.GnBIP, p.N3IP)
		}
	}

	// Zero pins nothing: every session asks the UPF to choose.
	for i, p := range sessionParams(4, 0, base, []string{"10.20.30.2"}, "192.0.2.1") {
		if p.FTEID != 0 {
			t.Errorf("with -fteid 0, session %d pins %#x", i, p.FTEID)
		}
	}

	// A -gnb list alternates: session i takes the (i mod n)-th address.
	gnbs := []string{"10.20.30.2", "2001:db8:20::2"}
	for i, p := range sessionParams(4, 0, base, gnbs, "192.0.2.1") {
		if p.GnBIP != gnbs[i%2] {
			t.Errorf("session %d's gNB is %s, want %s", i, p.GnBIP, gnbs[i%2])
		}
	}
}

func TestQueuedResponsesOwnTheirDatagrams(t *testing.T) {
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	c, err := dial(peer.LocalAddr().String(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()

	messages := []*message.SessionEstablishmentResponse{
		message.NewSessionEstablishmentResponse(0, 0, 0x1111, 27, 0,
			ie.NewCause(ie.CauseRequestAccepted),
			ie.NewFSEID(0xaaaa, net.IPv4(192, 0, 2, 1), nil)),
		message.NewSessionEstablishmentResponse(0, 0, 0x2222, 28, 0,
			ie.NewCause(ie.CauseSessionContextNotFound),
			ie.NewFSEID(0xbbbb, net.IPv4(192, 0, 2, 2), nil)),
	}
	var got []message.Message
	for _, m := range messages {
		ch := make(chan message.Message, 1)
		c.mu.Lock()
		c.wait[m.Sequence()] = ch
		c.mu.Unlock()
		b, err := wire(m)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := peer.WriteToUDP(b, c.conn.LocalAddr().(*net.UDPAddr)); err != nil {
			t.Fatal(err)
		}
		select {
		case response := <-ch:
			// Do not consume its IEs until the next response has been read
			// into the same receive buffer. The channel orders both reads.
			got = append(got, response)
		case <-time.After(time.Second):
			t.Fatal("response was not queued")
		}
	}
	for i, m := range got {
		response, ok := m.(*message.SessionEstablishmentResponse)
		if !ok {
			t.Fatalf("response %d has type %T", i, m)
		}
		if response.Sequence() != messages[i].Sequence() || response.SEID() != messages[i].SEID() {
			t.Errorf("response %d changed its sequence or header SEID", i)
		}
		fseid, err := response.UPFSEID.FSEID()
		if err != nil {
			t.Fatal(err)
		}
		wantFSEID, _ := messages[i].UPFSEID.FSEID()
		if fseid.SEID != wantFSEID.SEID || !fseid.IPv4Address.Equal(wantFSEID.IPv4Address) {
			t.Errorf("response %d F-SEID = %+v, want %+v", i, fseid, wantFSEID)
		}
		cause, err := response.Cause.Cause()
		if err != nil {
			t.Fatal(err)
		}
		wantCause, _ := messages[i].Cause.Cause()
		if cause != wantCause {
			t.Errorf("response %d cause = %d, want %d", i, cause, wantCause)
		}
		want, err := wire(messages[i])
		if err != nil {
			t.Fatal(err)
		}
		actual, err := wire(response)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(actual, want) {
			t.Errorf("response %d payload changed after receive-buffer reuse", i)
		}
	}
}
