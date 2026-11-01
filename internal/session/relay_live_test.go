// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/bess"
)

// The relay test's tunnel ends: the F-TEID the burst arrives on (endpoint 1,
// N3 at 192.0.2.1), the UE behind it, and the peer its PDRs forward into,
// whose N3 frames the appliance graphs hand to relay_tap.
const (
	relayFTEID     = 0x11223360
	relayUE        = "10.45.0.30"
	relayPeer      = "10.20.30.77"
	relayOldTEID   = 0x77000030 // the tunnel before the modification
	relayTEID      = 0x77000031 // the G-PDUs' tunnel after it
	relaySpareTEID = 0x77000032 // a second PDR's tunnel on the same F-TEID
	relayGPDUs     = 16
)

// TestLiveEndMarkerIsRelayedBehindItsGPDUs drives the appliance targets'
// End Marker relay (TS 29.244 Table 8.2.64-1 NOTE 2; TS 23.502 4.9.1.3.3 step
// 10b) through a live daemon: a session whose F-TEID's PDRs forward into GTP-U
// tunnels is modified to move one tunnel and add another, then one burst of 16
// G-PDUs followed by an End Marker arrives on that F-TEID. What N3 sends
// toward the tunnels' peer, in order, is the 16 G-PDUs in the moved tunnel,
// then one End Marker per tunnel the F-TEID's PDRs forward into after the
// modification -- each with that tunnel's TEID, from N3's address -- and none
// with the tunnel the modification left or the TEID the marker arrived with.
//
// The burst is written while the daemon's workers are paused, so the port
// reads it whole into one batch: the marker shares its burst with the G-PDUs
// it follows. ci/session-path.sh runs it with UPF_TARGET=appliance or
// session-major, where the graph has relay_tap (deploy/session-path-*.yaml).
// Its file sorts after path_live_test.go, so it runs after the control arms
// that require N3 to have sent nothing before their session exists.
func TestLiveEndMarkerIsRelayedBehindItsGPDUs(t *testing.T) {
	target, tap := os.Getenv("UPF_BESS_TARGET"), os.Getenv("UPF_RELAY_SOCK")
	if target == "" || tap == "" {
		t.Skip("set UPF_BESS_TARGET and UPF_RELAY_SOCK (ci/session-path.sh does for the appliance targets) to run against a live bessd")
	}
	ctx := context.Background()
	client, err := bess.Dial(ctx, target)
	if err != nil {
		t.Fatalf("dialing %s: %v", target, err)
	}
	defer client.Close()
	if err := client.Refresh(ctx); err != nil {
		t.Fatalf("reading the daemon's schema: %v", err)
	}
	c := New(liveConfig(), client, quietLogger())

	fteid := ie.NewFTEID(0x01, relayFTEID, net.ParseIP("192.0.2.1"), nil, 0)
	pdr := func(id uint16, precedence uint32, extra ...*ie.IE) *ie.IE {
		pdi := append([]*ie.IE{ie.NewSourceInterface(ie.SrcInterfaceAccess), fteid,
			ie.NewUEIPAddress(0x02, relayUE, "", 0, 0)}, extra...)
		return ie.NewCreatePDR(ie.NewPDRID(id), ie.NewPrecedence(precedence), ie.NewPDI(pdi...),
			ie.NewFARID(uint32(id)))
	}
	tunnel := func(teid uint32) *ie.IE {
		return ie.NewOuterHeaderCreation(0x0100, teid, relayPeer, "", 0, 0, 0)
	}
	// Indirect data forwarding (TS 29.244 8.2.2 NOTE 2): what arrives on the
	// F-TEID leaves N3 again, in a tunnel.
	forward := func(id uint32, teid uint32) *ie.IE {
		return ie.NewCreateFAR(ie.NewFARID(id), ie.NewApplyAction(applyForw),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess), tunnel(teid)))
	}
	resp := c.Establish(message.NewSessionEstablishmentRequest(0, 0, 0x7401, 1, 0,
		ie.NewNodeID("", "", "smf"), ie.NewFSEID(0x7401, nil, nil),
		pdr(1, 100), forward(1, relayOldTEID))).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	seid := upFSEID(t, resp)
	defer func() {
		if got := cause(t, c.Delete(message.NewSessionDeletionRequest(0, 0, seid, 3, 0))); got != ie.CauseRequestAccepted {
			t.Errorf("the deletion answered cause %d", got)
		}
	}()
	// The modification: FAR 1 moves to another tunnel, and a second PDR on
	// the F-TEID (ICMP only, below PDR 1) forwards into a third.
	mod := message.NewSessionModificationRequest(0, 0, seid, 2, 0,
		ie.NewUpdateFAR(ie.NewFARID(1), ie.NewApplyAction(applyForw),
			ie.NewUpdateForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess), tunnel(relayTEID))),
		pdr(2, 200, ie.NewSDFFilter("permit out icmp from any to assigned", "", "", "", 0)),
		forward(2, relaySpareTEID))
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification answered cause %d", got)
	}

	conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: tap, Net: "unixpacket"})
	if err != nil {
		t.Fatalf("connecting to the relay tap %s: %v", tap, err)
	}
	defer conn.Close()
	// Bounds a hung daemon; nothing below waits for time to pass.
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	// confirm_connect: the port sends "yes" once it has the connection, so
	// what it sends from then on reaches this socket.
	if n, err := conn.Read(buf); err != nil || string(buf[:n]) != "yes\x00" {
		t.Fatalf("the relay tap did not confirm the connection: %q, %v", buf[:n], err)
	}

	burst := make([][]byte, 0, relayGPDUs+1)
	for i := range relayGPDUs {
		burst = append(burst, relayGPDU(uint16(i)))
	}
	marker, err := endMarkerFrame(relayFTEID, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("10.20.30.2"))
	if err != nil {
		t.Fatal(err)
	}
	copy(marker[0:6], []byte{0x02, 0, 0, 0, 0, 0x02}) // N3's MAC
	burst = append(burst, marker)
	sdk := client.SDK()
	if err := sdk.PauseWorkers(ctx); err != nil {
		t.Fatalf("pausing the workers: %v", err)
	}
	for _, f := range burst {
		if _, err := conn.Write(f); err != nil {
			_ = sdk.ResumeWorkers(ctx)
			t.Fatalf("writing the burst: %v", err)
		}
	}
	if err := sdk.ResumeWorkers(ctx); err != nil {
		t.Fatalf("resuming the workers: %v", err)
	}

	type sent struct {
		kind     byte
		teid     uint32
		src, dst netip.Addr
	}
	var got []sent
	for len(got) < relayGPDUs+2 {
		n, err := conn.Read(buf)
		if err != nil {
			kinds := map[byte]int{}
			for _, s := range got {
				kinds[s.kind]++
			}
			t.Fatalf("after %d frames toward %s (%d G-PDUs, %d End Markers), want %d: %v",
				len(got), relayPeer, kinds[0xff], kinds[endMarkerType], relayGPDUs+2, err)
		}
		f := buf[:n]
		if n < 14+20+8+8 || binary.BigEndian.Uint16(f[12:14]) != 0x0800 {
			t.Fatalf("frame %d toward %s is not an IPv4 GTP-U frame: % x", len(got), relayPeer, f)
		}
		got = append(got, sent{kind: f[43], teid: binary.BigEndian.Uint32(f[46:50]),
			src: netip.AddrFrom4([4]byte(f[26:30])), dst: netip.AddrFrom4([4]byte(f[30:34]))})
	}
	n3, peer := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr(relayPeer)
	for i, s := range got {
		if s.src != n3 || s.dst != peer {
			t.Errorf("frame %d went %s -> %s, want %s -> %s", i, s.src, s.dst, n3, peer)
		}
	}
	for i, s := range got[:relayGPDUs] {
		if s.kind != 0xff || s.teid != relayTEID {
			t.Errorf("frame %d is type %d TEID %#x, want the burst's G-PDU %d in TEID %#x ahead of any End Marker",
				i, s.kind, s.teid, i, relayTEID)
		}
	}
	var relayed []uint32
	for i, s := range got[relayGPDUs:] {
		if s.kind != endMarkerType {
			t.Errorf("frame %d is type %d after the burst's G-PDUs, want an End Marker", relayGPDUs+i, s.kind)
		}
		relayed = append(relayed, s.teid)
	}
	slices.Sort(relayed)
	if want := []uint32{relayTEID, relaySpareTEID}; !slices.Equal(relayed, want) {
		t.Errorf("the End Markers name TEIDs %s, want one per tunnel the F-TEID forwards into: %s",
			hexes(relayed), hexes(want))
	}
}

// relayGPDU is the burst's i-th G-PDU on the relay F-TEID: from the RAN
// (10.20.30.2) to N3, the UE's UDP packet to 8.8.8.8:53 with its sequence in
// the IP identification.
func relayGPDU(i uint16) []byte {
	inner := make([]byte, 20+8+4)
	inner[0] = 0x45
	binary.BigEndian.PutUint16(inner[2:4], uint16(len(inner)))
	binary.BigEndian.PutUint16(inner[4:6], i)
	inner[8], inner[9] = 64, 17
	copy(inner[12:16], netip.MustParseAddr(relayUE).AsSlice())
	copy(inner[16:20], []byte{8, 8, 8, 8})
	binary.BigEndian.PutUint16(inner[10:12], ipv4Checksum(inner[:20]))
	binary.BigEndian.PutUint16(inner[20:22], 5000)
	binary.BigEndian.PutUint16(inner[22:24], 53)
	binary.BigEndian.PutUint16(inner[24:26], 12)
	copy(inner[28:], "ping")

	frame := make([]byte, 14+20+8+8+len(inner))
	copy(frame[0:6], []byte{0x02, 0, 0, 0, 0, 0x02})  // N3's MAC
	copy(frame[6:12], []byte{0x02, 0, 0, 0, 0, 0x01}) // the RAN's
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	ip := frame[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(frame)-14))
	ip[8], ip[9] = 64, 17
	copy(ip[12:16], []byte{10, 20, 30, 2})
	copy(ip[16:20], []byte{192, 0, 2, 1})
	binary.BigEndian.PutUint16(ip[10:12], ipv4Checksum(ip))
	udp := frame[34:42]
	binary.BigEndian.PutUint16(udp[0:2], gtpuPort)
	binary.BigEndian.PutUint16(udp[2:4], gtpuPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+8+len(inner)))
	gtp := frame[42:50]
	gtp[0], gtp[1] = 0x30, 0xff
	binary.BigEndian.PutUint16(gtp[2:4], uint16(len(inner)))
	binary.BigEndian.PutUint32(gtp[4:8], relayFTEID)
	copy(frame[50:], inner)
	return frame
}

func hexes(teids []uint32) string {
	out := ""
	for i, t := range teids {
		if i > 0 {
			out += " "
		}
		out += fmt.Sprintf("%#x", t)
	}
	return out
}
