// SPDX-License-Identifier: BSD-3-Clause
//
// The UP function's half of End Marker packets (TS 29.244 5.3.2, TS 29.281
// 7.3.2): a Session Modification Request that carries a FAR with a new
// downstream F-TEID and the SNDEM flag asks this node to construct and send an
// End Marker on the tunnel it is leaving, after the last G-PDU on that tunnel.
//
// The frame is built here and written to the graph's unix_port, whose PortInc
// carries it to the N3 output port: a marker is not a packet that arrives, so
// nothing in the datapath can produce it, and a message this node sends is not
// session state a transaction can hold. It leaves through the same outer
// headers the encap would write for that tunnel -- the old TEID and the old
// peer -- so the peer reads it as the end of the stream (7.3.2.1: "a G-PDU that
// arrives after an End Marker message on this tunnel may be silently
// discarded").
package session

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
)

// The GTP-U message type (TS 29.281 table 6.1-1) and the port a marker is sent
// to (4.4.2.0): the message carries no information elements of its own, so its
// length is zero.
const (
	endMarkerType = 254
	gtpuPort      = 2152
)

// endMarkerFrame is one End Marker: the Ethernet minimum, an outer
// Eth/IPv4/UDP/GTP-U header with an empty payload, the header's lengths and
// checksum filled in. The TEID is the OLD F-TEID and the destination the OLD
// peer, while the source is this UPF's N3 address -- 5.3.2's rule for the
// markers the CP function would otherwise construct.
func endMarkerFrame(teid uint32, peer netip.Addr, src netip.Addr, srcMAC, dstMAC [6]byte) []byte {
	frame := make([]byte, 60) // the Ethernet minimum: a 42-byte message is padded to it
	copy(frame[0:6], dstMAC[:])
	copy(frame[6:12], srcMAC[:])
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)

	ip := frame[14:34]
	ip[0] = 0x45 // version 4, 5 words of header
	binary.BigEndian.PutUint16(ip[2:4], 20+8+8)
	ip[6], ip[7] = 0x40, 0x00 // DF: an end marker is never fragmented
	ip[8] = 64                // TTL
	ip[9] = 17                // UDP
	src4, dst4 := src.As4(), peer.As4()
	copy(ip[12:16], src4[:])
	copy(ip[16:20], dst4[:])
	binary.BigEndian.PutUint16(ip[10:12], ipv4Checksum(ip))

	udp := frame[34:42]
	binary.BigEndian.PutUint16(udp[0:2], gtpuPort)
	binary.BigEndian.PutUint16(udp[2:4], gtpuPort)
	binary.BigEndian.PutUint16(udp[4:6], 8+8)
	// The UDP checksum stays 0: legal over IPv4, and what the encap writes too.

	gtp := frame[42:50]
	gtp[0] = 0x30 // version 1, PT 1, S/E/PN clear (5.1: an End Marker carries no optional field)
	gtp[1] = endMarkerType
	binary.BigEndian.PutUint32(gtp[4:8], teid)
	return frame
}

// ipv4Checksum is the header's checksum over a 20-byte IPv4 header whose
// checksum field is still zero.
func ipv4Checksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// dialEndMarker opens the graph's unix_port (SOCK_SEQPACKET, so one write is
// one packet) for this run's markers.
func dialEndMarker(path string) (*net.UnixConn, error) {
	addr := &net.UnixAddr{Name: path, Net: "unixpacket"}
	conn, err := net.DialUnix("unixpacket", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("connecting to the end-marker port %s: %w", path, err)
	}
	return conn, nil
}

// sendEndMarker writes one frame to the graph's unix_port. A failure is the
// caller's to log and count, never a reason to refuse the modification that
// asked for the marker: the switch has already landed, and the packet a peer
// would have read as the end of the stream simply is not sent.
func (c *Compiler) sendEndMarker(frame []byte) error {
	if c.cfg.EndMarker == "" {
		return errors.New("no end-marker port is configured (-end-marker)")
	}
	c.mu.Lock()
	conn := c.endMarkerConn
	if conn == nil {
		c.mu.Unlock()
		opened, err := dialEndMarker(c.cfg.EndMarker)
		if err != nil {
			return err
		}
		c.mu.Lock()
		if c.endMarkerConn == nil {
			c.endMarkerConn = opened
			conn = opened
		} else {
			conn = c.endMarkerConn
			opened.Close()
		}
	}
	c.mu.Unlock()
	if _, err := conn.Write(frame); err != nil {
		// The daemon that held the port is gone or restarted: drop this
		// connection, so the next marker dials again. Only if it is still the
		// run's -- another send may have redialled already, and closing that
		// one would take its connection down with it.
		c.mu.Lock()
		if c.endMarkerConn == conn {
			c.endMarkerConn = nil
			conn.Close()
		}
		c.mu.Unlock()
		return fmt.Errorf("writing to the end-marker port: %w", err)
	}
	return nil
}

// sndem reports whether a Session Modification Request's IEs carry the SNDEM
// flag (TS 29.244 8.2.31): a top-level PFCPSMReq-Flags IE, or one inside a
// Create FAR's or Update FAR's forwarding parameters, which is where some CP
// functions put it.
func sndem(ies []*ie.IE) bool {
	return sndemDepth(ies, 0)
}

func sndemDepth(ies []*ie.IE, depth int) bool {
	if depth > 4 { // FAR -> forwarding parameters -> the flag: no deeper
		return false
	}
	for _, i := range ies {
		if i == nil {
			continue
		}
		if i.Type == ie.PFCPSMReqFlags && i.HasSNDEM() {
			return true
		}
		var children []*ie.IE
		var err error
		switch i.Type {
		case ie.CreateFAR:
			children, err = i.CreateFAR()
		case ie.UpdateFAR:
			children, err = i.UpdateFAR()
		case ie.ForwardingParameters:
			children, err = i.ForwardingParameters()
		case ie.UpdateForwardingParameters:
			children, err = i.UpdateForwardingParameters()
		default:
			continue
		}
		if err == nil && sndemDepth(children, depth+1) {
			return true
		}
	}
	return false
}

// leavingTunnels is the set of tunnels a modification moves away from: for
// every FAR the message updates to a different outer header creation, the
// tunnel the session holds now (TS 29.244 5.3.2: "the destination IP address
// and TEID set according to the old F-TEID value"). It must be read before the
// merge folds the new one in.
func (s *Session) leavingTunnels(fars []farReq) []far {
	var out []far
	for _, f := range fars {
		old := s.FARs[f.id]
		if old == nil || !old.hasOuter || old.teid == 0 {
			continue
		}
		if !f.hasOuter {
			continue // the message did not carry a new tunnel
		}
		if f.teid != old.teid || f.peer != old.peer {
			out = append(out, *old)
		}
	}
	return out
}

// markerRetryInterval is how long a failed dial is remembered before the next
// marker tries again: a daemon restart (or a graph that has no end-marker port
// yet) must not turn into a dial per modification.
const markerRetryInterval = 5 * time.Second
