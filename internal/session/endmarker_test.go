// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/routing"
)

// The IPv4 frame is byte-for-byte: the old TEID and peer, a zero Ethernet
// header for routed neighbor rewrite, a valid outer IP/UDP header, GTP-U type
// 254 with no optional fields, and Ethernet-minimum padding.
func TestTheEndMarkerFrameIsWhatThePeerReads(t *testing.T) {
	got, err := endMarkerFrame(0x99887766, netip.MustParseAddr("10.20.30.2"),
		netip.MustParseAddr("10.20.30.1"))
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x00,
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

func TestIPv6EndMarkerHasMandatoryUDPChecksum(t *testing.T) {
	src := netip.MustParseAddr("2001:db8:1::1")
	peer := netip.MustParseAddr("2001:db8:1::2")
	frame, err := endMarkerFrame(0x11223344, peer, src)
	if err != nil {
		t.Fatal(err)
	}
	if len(frame) != 70 || !bytes.Equal(frame[:12], make([]byte, 12)) ||
		binary.BigEndian.Uint16(frame[12:14]) != 0x86dd {
		t.Fatalf("IPv6 Ethernet frame has length/type/MAC %d/%04x/%x",
			len(frame), binary.BigEndian.Uint16(frame[12:14]), frame[:12])
	}
	ip := frame[14:54]
	if ip[0]>>4 != 6 || binary.BigEndian.Uint16(ip[4:6]) != 16 ||
		ip[6] != 17 || ip[7] != 64 ||
		!bytes.Equal(ip[8:24], src.AsSlice()) || !bytes.Equal(ip[24:40], peer.AsSlice()) {
		t.Fatalf("unexpected IPv6 outer header: %x", ip)
	}
	udp := frame[54:70]
	if binary.BigEndian.Uint16(udp[0:2]) != gtpuPort ||
		binary.BigEndian.Uint16(udp[2:4]) != gtpuPort ||
		binary.BigEndian.Uint16(udp[4:6]) != 16 ||
		binary.BigEndian.Uint16(udp[6:8]) == 0 {
		t.Fatalf("unexpected IPv6 UDP header: %x", udp[:8])
	}
	checksum := binary.BigEndian.Uint16(udp[6:8])
	datagram := bytes.Clone(udp)
	clear(datagram[6:8])
	if want := ipv6UDPChecksum(src, peer, datagram); checksum != want {
		t.Errorf("UDP checksum is %#04x, want %#04x", checksum, want)
	}
	if udp[8] != 0x30 || udp[9] != endMarkerType ||
		binary.BigEndian.Uint32(udp[12:16]) != 0x11223344 {
		t.Errorf("unexpected GTP-U End Marker: %x", udp[8:])
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

var endMarkerSockets atomic.Uint64

// endMarkerBase is a cfg.EndMarker base in the Linux abstract namespace (the
// leading '@'): a path under t.TempDir() can exceed sun_path's 108 bytes when
// TMPDIR is long, and the compiler dials whatever name it is given.
func endMarkerBase() string {
	return fmt.Sprintf("@upf-end-marker-%d-%d", os.Getpid(), endMarkerSockets.Add(1))
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
	path := endMarkerBase()
	frames := endMarkerListener(t, path+".1")

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
		want, err := endMarkerFrame(0x11223344, netip.MustParseAddr("10.20.30.2"),
			cfg.FTEIDEndpoints[0].IPv4)
		if err != nil {
			t.Fatal(err)
		}
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
	path := endMarkerBase()
	frames := endMarkerListener(t, path+".1")
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

func TestTunnelEndpointUsesReferencePointFamilyAndInstance(t *testing.T) {
	cfg := egressConfig(t)
	cfg.FTEIDEndpoints = []FTEIDEndpoint{
		{ID: 1, ReferencePoint: "n3", TransportRouteDomain: 1,
			SourceInterface: ie.SrcInterfaceAccess, Instance: "internet",
			IPv4: netip.MustParseAddr("10.90.0.1"), IPv6: netip.MustParseAddr("2001:db8:3::1")},
		{ID: 2, ReferencePoint: "n3", TransportRouteDomain: 3,
			SourceInterface: ie.SrcInterfaceAccess,
			IPv4:            netip.MustParseAddr("10.93.0.1")},
		{ID: 3, ReferencePoint: "n9", TransportRouteDomain: 2,
			SourceInterface: ie.SrcInterfaceCore, Instance: "internet",
			IPv4: netip.MustParseAddr("10.91.0.1"), IPv6: netip.MustParseAddr("2001:db8:9::1")},
	}
	c := New(cfg, &recorder{}, quietLogger())
	internet, _ := cfg.Instances.Lookup("internet")
	vn, _ := cfg.Instances.Lookup("vn")
	for _, tc := range []struct {
		name       string
		far        *far
		ifc        routing.Interface
		endpointID uint32
		local      netip.Addr
		domain     uint32
	}{
		{"N3 IPv4 scoped endpoint", &far{destIfc: ie.DstInterfaceAccess, peer: netip.MustParseAddr("10.20.30.2")},
			internet, 1, netip.MustParseAddr("10.90.0.1"), 1},
		{"N9 IPv6 scoped endpoint", &far{destIfc: ie.DstInterfaceCore, peer: netip.MustParseAddr("2001:db8:9::2")},
			internet, 3, netip.MustParseAddr("2001:db8:9::1"), 2},
		{"unscoped endpoint fallback", &far{destIfc: ie.DstInterfaceAccess, peer: netip.MustParseAddr("10.20.30.2")},
			vn, 2, netip.MustParseAddr("10.93.0.1"), 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			endpoint, local, err := c.tunnelEndpoint(tc.far, tc.ifc)
			if err != nil {
				t.Fatal(err)
			}
			if endpoint.ID != tc.endpointID || local != tc.local ||
				endpoint.TransportRouteDomain != tc.domain {
				t.Errorf("selected endpoint %+v with local %s, want endpoint %d, local %s, domain %d",
					endpoint, local, tc.endpointID, tc.local, tc.domain)
			}
		})
	}
	missing := &far{destIfc: ie.DstInterfaceCore, instance: "vn",
		peer: netip.MustParseAddr("2001:db8:9::2")}
	if _, _, err := c.tunnelEndpoint(missing, vn); err == nil {
		t.Fatal("a scoped N9 IPv6 endpoint was selected for a different instance")
	}
}
func TestFTEIDEndpointSelectionUsesSourceAndInstance(t *testing.T) {
	cfg := egressConfig(t)
	cfg.FTEIDEndpoints = []FTEIDEndpoint{
		{ID: 7, ReferencePoint: "n3", SourceInterface: ie.SrcInterfaceAccess, Instance: "internet", IPv4: netip.MustParseAddr("10.90.0.1")},
		{ID: 9, ReferencePoint: "n3", SourceInterface: ie.SrcInterfaceAccess, Instance: "internet", IPv4: netip.MustParseAddr("10.92.0.1"), IPv6: netip.MustParseAddr("2001:4860::9")},
		{ID: 8, ReferencePoint: "n9", SourceInterface: ie.SrcInterfaceCore, Instance: "internet", IPv4: netip.MustParseAddr("10.91.0.1")},
	}
	c := New(cfg, &recorder{}, quietLogger())
	core, err := c.fteidEndpoint(&pdr{srcIfc: ie.SrcInterfaceCore, instance: "internet", wantIPv4: true})
	if err != nil || core.ID != 8 {
		t.Fatalf("Core PDI selected endpoint %+v, error %v", core, err)
	}
	first, err := c.fteidEndpoint(&pdr{srcIfc: ie.SrcInterfaceAccess, instance: "internet", wantIPv4: true})
	if err != nil || first.ID != 7 {
		t.Fatalf("IPv4 CHOOSE selected endpoint %+v, error %v", first, err)
	}
	for _, p := range []*pdr{
		{srcIfc: ie.SrcInterfaceAccess, instance: "internet", wantIPv6: true},
		{srcIfc: ie.SrcInterfaceAccess, instance: "internet", wantIPv4: true, wantIPv6: true},
	} {
		ep, err := c.fteidEndpoint(p)
		if err != nil || ep.ID != 9 {
			t.Fatalf("family-exact CHOOSE selected endpoint %+v, error %v", ep, err)
		}
	}
	pinned := &pdr{srcIfc: ie.SrcInterfaceAccess, instance: "internet", teid: 0x77,
		wantIPv4: true, fteidIPv4: netip.MustParseAddr("10.92.0.1")}
	if ep, err := c.fteidEndpoint(pinned); err != nil || ep.ID != 9 {
		t.Fatalf("pinned F-TEID selected endpoint %+v, error %v", ep, err)
	}
	if _, err := c.fteidEndpoint(&pdr{srcIfc: ie.SrcInterfaceAccess,
		instance: "internet", teid: 0x79, wantIPv4: true,
		fteidIPv4: netip.MustParseAddr("198.51.100.77")}); err == nil {
		t.Fatal("pinned address absent from endpoint configuration was accepted")
	}
	if _, err := c.fteidEndpoint(&pdr{srcIfc: ie.SrcInterfaceAccess, instance: "internet", teid: 0x78, wantIPv4: true}); err == nil {
		t.Fatal("addressless pinned F-TEID was accepted despite multiple matching endpoints")
	}
	if _, err := c.fteidEndpoint(&pdr{srcIfc: ie.SrcInterfaceAccess, instance: "vn", wantIPv4: true}); err == nil {
		t.Fatal("an unmatched instance selected an endpoint")
	}
	onlyV4 := cfg
	onlyV4.FTEIDEndpoints = []FTEIDEndpoint{
		cfg.FTEIDEndpoints[0],
		{ID: 10, ReferencePoint: "n3", SourceInterface: ie.SrcInterfaceAccess,
			Instance: "internet", IPv4: netip.MustParseAddr("10.93.0.1")},
	}
	if _, err := New(onlyV4, &recorder{}, quietLogger()).fteidEndpoint(
		&pdr{srcIfc: ie.SrcInterfaceAccess, instance: "internet", wantIPv4: true, wantIPv6: true}); err == nil {
		t.Fatal("no-partial-fallback family request selected an IPv4-only endpoint")
	}
}

func TestEndMarkerSocketsAreSelectedAndReusedIndependently(t *testing.T) {
	cfg := testConfig()
	base := endMarkerBase()
	cfg.EndMarker = base
	n3Path, n9Path := base+".1", base+".2"
	n3Frames := endMarkerListener(t, n3Path)
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
		{n3Path, n3Frames, 1},
		{n9Path, n9Frames, 2},
		{n3Path, n3Frames, 3},
		{n9Path, n9Frames, 4},
	} {
		frame := []byte{tc.value}
		if err := c.sendEndMarkerAt(tc.path, frame); err != nil {
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

func TestSNDEMUsesTheOldRoutedEndpointForAccessAndCoreTunnels(t *testing.T) {
	for _, tc := range []struct {
		name       string
		oldDest    uint8
		newDest    uint8
		sameTunnel bool
	}{
		{"Access to Core with a new tunnel", ie.DstInterfaceAccess, ie.DstInterfaceCore, false},
		{"Core to Access with a new tunnel", ie.DstInterfaceCore, ie.DstInterfaceAccess, false},
		{"Access to Core transport move", ie.DstInterfaceAccess, ie.DstInterfaceCore, true},
		{"Core to Access transport move", ie.DstInterfaceCore, ie.DstInterfaceAccess, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := egressConfig(t)
			base := endMarkerBase()
			cfg.EndMarker = base
			n3Local := cfg.FTEIDEndpoints[0].IPv4
			n9Local := cfg.FTEIDEndpoints[1].IPv4
			n3Frames := endMarkerListener(t, base+".1")
			n9Frames := endMarkerListener(t, base+".2")
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
			oldLocal, oldDomain, oldFrames := n3Local, uint32(1), n3Frames
			newLocal, newDomain := n9Local, uint32(2)
			if tc.oldDest == ie.DstInterfaceCore {
				oldLocal, oldDomain, oldFrames = n9Local, 2, n9Frames
			}
			if tc.newDest == ie.DstInterfaceAccess {
				newLocal, newDomain = n3Local, 1
			}
			dl := ruleIn(t, rec.last(), cfg.Down.PDRTable)
			tunnel := find(t, rec.last(), tunnelsRes(cfg.Down), "action_id", dl.actionID())
			if !bytes.Equal(tunnel.Value["local_address"].([]byte), oldLocal.AsSlice()) ||
				tunnel.Value["transport_route_domain"] != oldDomain {
				t.Fatalf("old tunnel endpoint is %v/domain %v, want %s/domain %d",
					tunnel.Value["local_address"], tunnel.Value["transport_route_domain"],
					oldLocal, oldDomain)
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
			if !bytes.Equal(tunnel.Value["local_address"].([]byte), newLocal.AsSlice()) ||
				tunnel.Value["transport_route_domain"] != newDomain {
				t.Errorf("new tunnel endpoint is %v/domain %v, want %s/domain %d",
					tunnel.Value["local_address"], tunnel.Value["transport_route_domain"],
					newLocal, newDomain)
			}
			frame, err := endMarkerFrame(0x11223344, netip.MustParseAddr("10.20.30.2"), oldLocal)
			if err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-oldFrames:
				if !bytes.Equal(got, frame) {
					t.Errorf("marker is\n% x\nwant old routed tunnel\n% x", got, frame)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("the old transport route domain received no marker")
			}
			if stats := c.Stats(); stats.Markers != 1 || stats.MarkerFailures != 0 {
				t.Errorf("markers sent %d, failed %d, want 1 and 0", stats.Markers, stats.MarkerFailures)
			}
		})
	}
}

func TestLeavingTunnelsCapturesSharedPDRAndMARRoutedEndpoints(t *testing.T) {
	c := New(testConfig(), &recorder{}, quietLogger())
	localN3 := netip.MustParseAddr("192.0.2.1")
	localN9 := netip.MustParseAddr("192.0.2.9")
	old := &far{id: 2, hasOuter: true, teid: 0x11223344, peer: netip.MustParseAddr("10.20.30.2")}
	s := &Session{
		FARs: map[uint32]*far{2: old},
		PDRs: map[uint16]*pdr{
			1: {id: 1, farID: 2, tunnelLocalAddress: localN3, transportRouteDomain: 1},
			2: {id: 2, farID: 2, tunnelLocalAddress: localN3, transportRouteDomain: 1},
		},
		MARs: map[uint16]*mar{
			1: {
				accesses:              [2]marAccess{{hasFarID: true, farID: 2}},
				tunnelIDs:             [2]uint32{7},
				tunnelLocalAddresses:  [2]netip.Addr{localN9},
				transportRouteDomains: [2]uint32{2},
			},
		},
	}
	markers := c.leavingTunnels(s, []farReq{{id: 2, hasOuter: true, teid: 0xaabbccdd, peer: old.peer}})
	if len(markers) != 2 {
		t.Fatalf("captured %d markers, want one per distinct routed endpoint", len(markers))
	}
	old.teid = 0xaabbccdd
	if markers[0].teid != 0x11223344 || markers[1].teid != 0x11223344 {
		t.Error("old TEID changed with the live FAR")
	}
	if markers[0].localAddress != localN3 || markers[0].transportRouteDomain != 1 ||
		markers[1].localAddress != localN9 || markers[1].transportRouteDomain != 2 {
		t.Errorf("old routed endpoints changed with live references: %+v", markers)
	}
}

func TestLeavingTunnelsDoesNotEndAnUnchangedRoutedEndpoint(t *testing.T) {
	cfg := egressConfig(t)
	local := netip.MustParseAddr("10.90.0.1")
	cfg.FTEIDEndpoints = []FTEIDEndpoint{
		{ID: 1, ReferencePoint: "n3", TransportRouteDomain: 2,
			SourceInterface: ie.SrcInterfaceAccess, Instance: "internet", IPv4: local},
		{ID: 2, ReferencePoint: "n9", TransportRouteDomain: 2,
			SourceInterface: ie.SrcInterfaceCore, Instance: "internet", IPv4: local},
	}
	c := New(cfg, &recorder{}, quietLogger())
	old := &far{
		id: 2, apply: applyForw, destIfc: ie.DstInterfaceCore, instance: "internet",
		hasOuter: true, teid: 0x11223344, peer: netip.MustParseAddr("10.20.30.2"),
	}
	s := &Session{
		FARs: map[uint32]*far{2: old},
		PDRs: map[uint16]*pdr{
			1: {id: 1, farID: 2, srcIfc: ie.SrcInterfaceCore, instance: "internet",
				tunnelLocalAddress: local, transportRouteDomain: 2},
		},
	}
	for _, update := range []farReq{
		{id: 2, hasFwd: true},
		{id: 2, hasDestIfc: true, destIfc: ie.DstInterfaceCore},
		{id: 2, hasInstance: true, instance: "internet"},
		{id: 2, hasOuter: true, teid: old.teid, peer: old.peer},
		{id: 2, hasDestIfc: true, destIfc: ie.DstInterfaceAccess},
	} {
		if got := c.leavingTunnels(s, []farReq{update}); len(got) != 0 {
			t.Errorf("an unchanged routed endpoint produced markers for update %+v: %+v", update, got)
		}
	}
}
