// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"bytes"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// The frame, byte for byte: the OLD tunnel's TEID (0x99887766) and peer
// (10.20.30.2), this UPF's N3 address (10.20.30.1) as the source, the graph's
// two Ethernet addresses (the peer's first), GTP-U type 254 with a zero length
// and no optional field (TS 29.281 5.1, 7.3.2), and padding to the Ethernet
// minimum.
func TestTheEndMarkerFrameIsWhatThePeerReads(t *testing.T) {
	got := endMarkerFrame(0x99887766, netip.MustParseAddr("10.20.30.2"),
		netip.MustParseAddr("10.20.30.1"), [6]byte{2, 0, 0, 0, 0, 1}, [6]byte{2, 0, 0, 0, 0, 2})
	want := []byte{
		0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00,
		0x45, 0x00, 0x00, 0x24, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xea, 0x9e,
		0x0a, 0x14, 0x1e, 0x01, 0x0a, 0x14, 0x1e, 0x02,
		0x08, 0x68, 0x08, 0x68, 0x00, 0x10, 0x00, 0x00,
		0x30, 0xfe, 0x00, 0x00, 0x99, 0x88, 0x77, 0x66,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}
	if !bytes.Equal(got, want) {
		t.Errorf("the end marker frame is\n% x\nwant\n% x", got, want)
	}
	if len(got) != 60 {
		t.Errorf("the frame is %d bytes, want the Ethernet minimum 60", len(got))
	}
}

// The flag is SNDEM's, not DROBU's: TS 29.244 8.2.31 puts SNDEM in the second
// bit, and answering DROBU with an end marker would put a packet on the wire
// for a request that asked for none.
func TestSNDEMIsReadWhereverTheCPFunctionPutsIt(t *testing.T) {
	cases := []struct {
		name string
		ies  []*ie.IE
		want bool
	}{
		{"the flag on the message", []*ie.IE{ie.NewPFCPSMReqFlags(0x02)}, true},
		{"the flag inside an Update FAR's forwarding parameters", []*ie.IE{
			ie.NewUpdateFAR(ie.NewFARID(2),
				ie.NewUpdateForwardingParameters(ie.NewPFCPSMReqFlags(0x02)))}, true},
		{"the flag inside a Create FAR's forwarding parameters", []*ie.IE{
			ie.NewCreateFAR(ie.NewFARID(2),
				ie.NewForwardingParameters(ie.NewPFCPSMReqFlags(0x02)))}, true},
		{"DROBU alone is not SNDEM", []*ie.IE{ie.NewPFCPSMReqFlags(0x01)}, false},
		{"no flag at all", []*ie.IE{ie.NewUpdateFAR(ie.NewFARID(2))}, false},
	}
	for _, tc := range cases {
		if got := sndem(tc.ies); got != tc.want {
			t.Errorf("%s: sndem is %v, want %v", tc.name, got, tc.want)
		}
	}
}

// endMarkerListener is the graph's unix_port as a test sees it: it accepts the
// compiler's connection (BESS's port listens, SOCK_SEQPACKET) and hands every
// message it receives to the caller.
func endMarkerListener(t *testing.T, path string) <-chan []byte {
	t.Helper()
	l, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		t.Fatalf("listening on %s: %v", path, err)
	}
	t.Cleanup(func() { l.Close() })
	frames := make(chan []byte, 8)
	go func() {
		conn, err := l.AcceptUnix()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 2048)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			frames <- append([]byte(nil), buf[:n]...)
		}
	}()
	return frames
}

// TestAModificationWithSNDEMSendsTheOldTunnelsMarker is the whole feature: the
// SMF moves a FAR's downstream F-TEID with the SNDEM flag, and what leaves is
// one End Marker naming the tunnel the session is leaving -- not the new one.
func TestAModificationWithSNDEMSendsTheOldTunnelsMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "end-marker.sock")
	frames := endMarkerListener(t, path)

	cfg := testConfig()
	cfg.EndMarker = path
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())
	resp := c.Establish(establishment(0x6001, "10.45.0.9")).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	seid := upFSEID(t, resp)

	// The handover: a new gNB tunnel (TEID 0xaabbccdd toward 10.20.30.9) and
	// the SNDEM flag, in the same request.
	mod := message.NewSessionModificationRequest(0, 0, seid, 2, 0,
		ie.NewPFCPSMReqFlags(0x02),
		ie.NewUpdateFAR(ie.NewFARID(2),
			ie.NewUpdateForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceAccess),
				ie.NewOuterHeaderCreation(0x0100, 0xaabbccdd, "10.20.30.9", "", 0, 0, 0))))
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification answered cause %d", got)
	}

	select {
	case frame := <-frames:
		want := endMarkerFrame(0x11223344, netip.MustParseAddr("10.20.30.2"), cfg.N3Addr,
			cfg.N3MAC, cfg.PeerMAC)
		if !bytes.Equal(frame, want) {
			t.Errorf("the end marker is\n% x\nwant the OLD tunnel's\n% x", frame, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the modification sent no end marker")
	}
	if stats := c.Stats(); stats.Markers != 1 || stats.MarkerFailures != 0 {
		t.Errorf("markers sent %d, failed %d, want 1 and 0", stats.Markers, stats.MarkerFailures)
	}

	// A second modification with the flag, but no new F-TEID: nothing moves,
	// so no marker is owed (TS 29.244 5.3.2 asks for one when the F-TEID is
	// changed).
	still := message.NewSessionModificationRequest(0, 0, seid, 3, 0,
		ie.NewPFCPSMReqFlags(0x02),
		ie.NewUpdateFAR(ie.NewFARID(2),
			ie.NewUpdateForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess))))
	if got := cause(t, c.Modify(still)); got != ie.CauseRequestAccepted {
		t.Fatalf("the second modification answered cause %d", got)
	}
	select {
	case frame := <-frames:
		t.Errorf("a modification that moved no tunnel sent an end marker: % x", frame)
	case <-time.After(200 * time.Millisecond):
	}
	if stats := c.Stats(); stats.Markers != 1 {
		t.Errorf("markers sent %d, want still 1", stats.Markers)
	}
}

// TestARestoredJournalSendsNoEndMarker: the handovers a replayed journal
// describes happened in an earlier run, and the TEID each named may since have
// been handed to another subscriber -- a marker toward a context that now
// exists would tell that peer a stream it is carrying has ended.
func TestARestoredJournalSendsNoEndMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "end-marker.sock")
	frames := endMarkerListener(t, path)
	j, _ := checkpointJournal(t, filepath.Join(t.TempDir(), "checkpoint"))

	cfg := testConfig()
	cfg.EndMarker = path
	c := New(cfg, &recorder{}, quietLogger())
	c.Checkpoint(j)
	resp := c.Establish(establishment(0x6003, "10.45.0.11")).(*message.SessionEstablishmentResponse)
	seid := upFSEID(t, resp)
	if got := cause(t, c.Modify(message.NewSessionModificationRequest(0, 0, seid, 2, 0,
		ie.NewPFCPSMReqFlags(0x02),
		ie.NewUpdateFAR(ie.NewFARID(2),
			ie.NewUpdateForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceAccess),
				ie.NewOuterHeaderCreation(0x0100, 0xaabbccdd, "10.20.30.9", "", 0, 0, 0)))))); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification answered cause %d", got)
	}
	select {
	case <-frames: // the live run's marker, which is the whole point of the flag
	case <-time.After(2 * time.Second):
		t.Fatal("the live modification sent no end marker")
	}

	// The restart: the same journal, no messages from an SMF.
	restarted := New(cfg, &recorder{}, quietLogger())
	restarted.Checkpoint(j)
	if err := restarted.Restore(j); err != nil {
		t.Fatalf("restoring the journal: %v", err)
	}
	if held := restarted.Stats().Sessions; held != 1 {
		t.Fatalf("the replayed compiler holds %d sessions, want 1", held)
	}
	select {
	case frame := <-frames:
		t.Errorf("a replayed journal put an end marker back on the wire: % x", frame)
	case <-time.After(200 * time.Millisecond):
	}
	if stats := restarted.Stats(); stats.Markers != 0 {
		t.Errorf("the replay sent %d end markers, want none", stats.Markers)
	}
}

// TestAnEndMarkerThatCannotBeSentDoesNotFailTheModification: the switch is
// what the SMF asked for and it has landed, so a graph with no end-marker port
// costs a count and a warning, never a refusal that would make the SMF re-apply
// a change that is in force.
func TestAnEndMarkerThatCannotBeSentDoesNotFailTheModification(t *testing.T) {
	cfg := testConfig()
	cfg.EndMarker = filepath.Join(t.TempDir(), "nothing-listens-here.sock")
	rec := &recorder{}
	c := New(cfg, rec, quietLogger())
	resp := c.Establish(establishment(0x6002, "10.45.0.10")).(*message.SessionEstablishmentResponse)
	seid := upFSEID(t, resp)

	mod := message.NewSessionModificationRequest(0, 0, seid, 2, 0,
		ie.NewPFCPSMReqFlags(0x02),
		ie.NewUpdateFAR(ie.NewFARID(2),
			ie.NewUpdateForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceAccess),
				ie.NewOuterHeaderCreation(0x0100, 0xaabbccdd, "10.20.30.9", "", 0, 0, 0))))
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Errorf("the modification answered cause %d, want accepted", got)
	}
	if stats := c.Stats(); stats.Markers != 0 || stats.MarkerFailures != 1 {
		t.Errorf("markers sent %d, failed %d, want 0 and 1", stats.Markers, stats.MarkerFailures)
	}
}
