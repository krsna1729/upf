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

func TestTunnelTransportUsesTheResolvedHop(t *testing.T) {
	cfg := testConfig()
	cfg.EndMarker = "/tmp/n3-marker.sock"
	n9 := TunnelTransport{
		Gate: 1, Addr: netip.MustParseAddr("10.90.0.1"),
		MAC: [6]byte{2, 9, 0, 0, 0, 1}, PeerMAC: [6]byte{2, 9, 0, 0, 0, 2},
		EndMarker: "/tmp/n9-marker.sock",
	}
	cfg.Transports = map[uint32]TunnelTransport{3: n9, 4: {}}
	c := New(cfg, &recorder{}, quietLogger())
	fallback := TunnelTransport{
		Addr: cfg.N3Addr, MAC: cfg.N3MAC, PeerMAC: cfg.PeerMAC, EndMarker: cfg.EndMarker,
	}
	for _, tc := range []struct {
		hop  uint32
		want TunnelTransport
	}{
		{0, fallback},
		{2, fallback},
		{3, n9},
		{4, TunnelTransport{}},
	} {
		if got := c.tunnelTransport(tc.hop); got != tc.want {
			t.Errorf("hop %d selects %+v, want %+v", tc.hop, got, tc.want)
		}
	}
}

func TestFTEIDAddressFollowsLocalIngressAndInstanceOverride(t *testing.T) {
	cfg := egressConfig(t)
	cfg.N9Addr = netip.MustParseAddr("10.90.0.1")
	override := netip.MustParseAddr("10.91.0.1")
	for _, tc := range []struct {
		name     string
		src      uint8
		instance string
		addrs    map[string]netip.Addr
		want     netip.Addr
	}{
		{"Access defaults to N3", ie.SrcInterfaceAccess, "internet", nil, cfg.N3Addr},
		{"Core defaults to N9", ie.SrcInterfaceCore, "internet", nil, cfg.N9Addr},
		{"Access can advertise N9", ie.SrcInterfaceAccess, "internet", map[string]netip.Addr{"internet": override}, override},
		{"Core instance overrides N9", ie.SrcInterfaceCore, "internet", map[string]netip.Addr{"internet": override}, override},
		{"unnamed PDI uses default instance", ie.SrcInterfaceAccess, "", map[string]netip.Addr{"internet": override}, override},
		{"other instance does not override", ie.SrcInterfaceAccess, "vn", map[string]netip.Addr{"internet": override}, cfg.N3Addr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			local := cfg
			local.FTEIDAddrs = tc.addrs
			c := New(local, &recorder{}, quietLogger())
			if got := c.fteidAddr(&pdr{srcIfc: tc.src, instance: tc.instance}); got != tc.want {
				t.Errorf("advertised address is %s, want %s", got, tc.want)
			}
		})
	}
	cfg.N9Addr = netip.Addr{}
	c := New(cfg, &recorder{}, quietLogger())
	if got := c.fteidAddr(&pdr{srcIfc: ie.SrcInterfaceCore}); got.IsValid() {
		t.Errorf("Core with no N9 address silently advertised %s", got)
	}
}

func TestEndMarkerSocketsAreSelectedAndReusedIndependently(t *testing.T) {
	cfg := testConfig()
	cfg.EndMarker = filepath.Join(t.TempDir(), "n3.sock")
	n9Path := filepath.Join(t.TempDir(), "n9.sock")
	n3Frames := endMarkerListener(t, cfg.EndMarker)
	n9Frames := endMarkerListener(t, n9Path)
	c := New(cfg, &recorder{}, quietLogger())
	t.Cleanup(func() {
		for _, conn := range c.endMarkerConns {
			conn.Close()
		}
	})
	for _, tc := range []struct {
		path   string
		frames <-chan []byte
		value  byte
	}{
		{cfg.EndMarker, n3Frames, 1},
		{n9Path, n9Frames, 2},
		{cfg.EndMarker, n3Frames, 3},
		{n9Path, n9Frames, 4},
	} {
		frame := []byte{tc.value}
		var err error
		if tc.path == cfg.EndMarker {
			err = c.sendEndMarker(frame)
		} else {
			err = c.sendEndMarkerAt(tc.path, frame)
		}
		if err != nil {
			t.Fatalf("sending to %s: %v", tc.path, err)
		}
		select {
		case got := <-tc.frames:
			if !bytes.Equal(got, frame) {
				t.Errorf("socket %s received %x, want %x", tc.path, got, frame)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("socket %s received no marker", tc.path)
		}
	}
	if got := len(c.endMarkerConns); got != 2 {
		t.Errorf("compiler holds %d marker connections, want one per socket", got)
	}
}

func TestSNDEMUsesTheOldTransportForAccessAndCoreTunnels(t *testing.T) {
	for _, tc := range []struct {
		name       string
		oldDest    uint8
		oldHop     uint32
		newDest    uint8
		sameTunnel bool
	}{
		{"Access N9 to Core default", ie.DstInterfaceAccess, 2, ie.DstInterfaceCore, false},
		{"Core N9 to Access default", ie.DstInterfaceCore, 3, ie.DstInterfaceAccess, false},
		{"Access transport-only move", ie.DstInterfaceAccess, 2, ie.DstInterfaceCore, true},
		{"Core transport-only move", ie.DstInterfaceCore, 3, ie.DstInterfaceAccess, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := egressConfig(t)
			cfg.EndMarker = "" // Only N9 has a marker socket.
			n9 := TunnelTransport{
				Gate: 1, Addr: netip.MustParseAddr("10.90.0.1"),
				MAC: [6]byte{2, 9, 0, 0, 0, 1}, PeerMAC: [6]byte{2, 9, 0, 0, 0, 2},
				EndMarker: filepath.Join(t.TempDir(), "n9.sock"),
			}
			cfg.Transports = map[uint32]TunnelTransport{tc.oldHop: n9}
			frames := endMarkerListener(t, n9.EndMarker)
			rec := &recorder{}
			c := New(cfg, rec, quietLogger())
			t.Cleanup(func() {
				for _, conn := range c.endMarkerConns {
					conn.Close()
				}
			})
			resp := c.Establish(egressEstablishment(0x6004, "10.45.0.12", 0x70, "internet",
				farTo(ie.DstInterfaceCore),
				farTo(tc.oldDest, tunnelTo(0x11223344, "10.20.30.2")))).(*message.SessionEstablishmentResponse)
			if got := cause(t, resp); got != ie.CauseRequestAccepted {
				t.Fatalf("establishment answered cause %d", got)
			}
			dl := ruleIn(t, rec.last(), cfg.Down.PDRTable)
			tunnel := find(t, rec.last(), tunnelsRes(cfg.Down), "action_id", dl.actionID())
			if tunnel.Value["gate"] != n9.Gate || tunnel.Value["src_ip"] != n9.Addr.String() {
				t.Errorf("N9 tunnel gate/source is %v/%v, want %d/%s", tunnel.Value["gate"], tunnel.Value["src_ip"], n9.Gate, n9.Addr)
			}
			if !bytes.Equal(tunnel.Value["ether_src"].([]byte), n9.MAC[:]) ||
				!bytes.Equal(tunnel.Value["ether_dst"].([]byte), n9.PeerMAC[:]) {
				t.Errorf("N9 tunnel Ethernet headers are %v/%v, want %v/%v",
					tunnel.Value["ether_src"], tunnel.Value["ether_dst"], n9.MAC, n9.PeerMAC)
			}
			forwarding := []*ie.IE{ie.NewDestinationInterface(tc.newDest)}
			if !tc.sameTunnel {
				forwarding = append(forwarding, tunnelTo(0xaabbccdd, "10.20.30.9"))
			}
			mod := message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 2, 0,
				ie.NewPFCPSMReqFlags(0x02),
				ie.NewUpdateFAR(ie.NewFARID(2),
					ie.NewUpdateForwardingParameters(forwarding...)))
			if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
				t.Fatalf("modification answered cause %d", got)
			}
			dl = ruleIn(t, rec.last(), cfg.Down.PDRTable)
			tunnel = find(t, rec.last(), tunnelsRes(cfg.Down), "action_id", dl.actionID())
			if tunnel.Value["gate"] != uint64(0) || tunnel.Value["src_ip"] != cfg.N3Addr.String() {
				t.Errorf("unmapped new hop did not fall back to N3: %v", tunnel.Value)
			}
			if !bytes.Equal(tunnel.Value["ether_src"].([]byte), cfg.N3MAC[:]) ||
				!bytes.Equal(tunnel.Value["ether_dst"].([]byte), cfg.PeerMAC[:]) {
				t.Errorf("fallback tunnel Ethernet headers are %v/%v, want %v/%v",
					tunnel.Value["ether_src"], tunnel.Value["ether_dst"], cfg.N3MAC, cfg.PeerMAC)
			}
			select {
			case got := <-frames:
				want := endMarkerFrame(0x11223344, netip.MustParseAddr("10.20.30.2"), n9.Addr, n9.MAC, n9.PeerMAC)
				if !bytes.Equal(got, want) {
					t.Errorf("marker is\n% x\nwant old transport and tunnel\n% x", got, want)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("old N9 transport received no marker")
			}
			if stats := c.Stats(); stats.Markers != 1 || stats.MarkerFailures != 0 {
				t.Errorf("markers sent %d, failed %d, want 1 and 0", stats.Markers, stats.MarkerFailures)
			}
		})
	}
}

func TestLeavingTunnelsCapturesSharedPDRAndMARTransports(t *testing.T) {
	cfg := testConfig()
	n9 := TunnelTransport{Gate: 1, Addr: netip.MustParseAddr("10.90.0.1")}
	cfg.Transports = map[uint32]TunnelTransport{3: n9}
	c := New(cfg, &recorder{}, quietLogger())
	old := &far{id: 2, hasOuter: true, teid: 0x11223344, peer: netip.MustParseAddr("10.20.30.2")}
	s := &Session{
		FARs: map[uint32]*far{2: old},
		PDRs: map[uint16]*pdr{
			1: {id: 1, farID: 2, nextHop: 2},
			2: {id: 2, farID: 2, nextHop: 2},
		},
		MARs: map[uint16]*mar{
			1: {
				accesses: [2]marAccess{{hasFarID: true, farID: 2}},
				nextHops: [2]uint32{3}, tunnelIDs: [2]uint32{7},
			},
		},
	}
	markers := c.leavingTunnels(s, []farReq{{id: 2, hasOuter: true, teid: 0xaabbccdd, peer: old.peer}})
	if len(markers) != 2 {
		t.Fatalf("captured %d markers, want two distinct transports, not duplicate PDR markers", len(markers))
	}
	old.teid = 0xaabbccdd
	s.PDRs[1].nextHop = 3
	s.MARs[1].nextHops[0] = 2
	if markers[0].teid != 0x11223344 || markers[1].teid != 0x11223344 {
		t.Error("old TEID changed with the live FAR")
	}
	if markers[0].transport != c.tunnelTransport(2) || markers[1].transport != n9 {
		t.Errorf("old transports changed with live references: %+v", markers)
	}
}

func TestLeavingTunnelsDoesNotEndAnUnchangedTransport(t *testing.T) {
	cfg := egressConfig(t)
	n9 := TunnelTransport{Gate: 1, Addr: netip.MustParseAddr("10.90.0.1")}
	cfg.Transports = map[uint32]TunnelTransport{3: n9}
	c := New(cfg, &recorder{}, quietLogger())
	old := &far{
		id: 2, apply: applyForw, destIfc: ie.DstInterfaceCore, instance: "internet",
		hasOuter: true, teid: 0x11223344, peer: netip.MustParseAddr("10.20.30.2"),
	}
	s := &Session{
		FARs: map[uint32]*far{2: old},
		PDRs: map[uint16]*pdr{
			1: {id: 1, farID: 2, srcIfc: ie.SrcInterfaceCore, instance: "internet", nextHop: 3},
		},
	}
	for _, update := range []farReq{
		{id: 2, hasFwd: true},
		{id: 2, hasDestIfc: true, destIfc: ie.DstInterfaceCore},
		{id: 2, hasInstance: true, instance: "internet"},
		{id: 2, hasOuter: true, teid: old.teid, peer: old.peer},
	} {
		if got := c.leavingTunnels(s, []farReq{update}); len(got) != 0 {
			t.Errorf("unchanged update %+v produced markers %+v", update, got)
		}
	}
	move := farReq{id: 2, hasDestIfc: true, destIfc: ie.DstInterfaceAccess}
	if got := c.leavingTunnels(s, []farReq{move}); len(got) != 1 || got[0].transport != n9 {
		t.Fatalf("transport-only move did not capture old N9 transport: %+v", got)
	}
	cfg.Transports[2] = n9
	if got := c.leavingTunnels(s, []farReq{move}); len(got) != 0 {
		t.Errorf("different hop on identical transport produced markers %+v", got)
	}
}
