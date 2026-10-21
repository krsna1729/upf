// SPDX-License-Identifier: BSD-3-Clause
//
// The UP function's half of End Marker packets (TS 29.244 5.3.2, TS 29.281
// 7.3.2): a Session Modification Request that carries a FAR with a new
// downstream F-TEID and the SNDEM flag asks this node to construct and send an
// End Marker on the tunnel it is leaving, after the last G-PDU on that tunnel.
//
// The frame is built here and written to the selected transport's unix_port,
// whose PortInc carries it to that transport's output port. A marker is not a
// packet that arrives, so nothing in the datapath can produce it. A message
// this node sends is not session state a transaction can hold. It leaves through
// the same outer
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

	"github.com/wmnsk/go-pfcp/ie"

	"github.com/krsna1729/upf/internal/routing"
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
// peer, while the source is this UPF's old transport address -- 5.3.2's rule
// for the markers the CP function would otherwise construct.
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

// sendEndMarker uses the default N3 transport's marker port.
func (c *Compiler) sendEndMarker(frame []byte) error {
	return c.sendEndMarkerAt(c.cfg.EndMarker, frame)
}

// sendEndMarkerAt writes one frame to the selected graph unix_port. A failure
// is the caller's to log and count, never a reason to refuse the modification:
// the switch has already landed, and the marker simply is not sent.
func (c *Compiler) sendEndMarkerAt(path string, frame []byte) error {
	if path == "" {
		return errors.New("no end-marker port is configured for the tunnel transport")
	}
	c.mu.Lock()
	conn := c.endMarkerConns[path]
	if conn == nil {
		c.mu.Unlock()
		opened, err := dialEndMarker(path)
		if err != nil {
			return err
		}
		c.mu.Lock()
		if c.endMarkerConns == nil {
			c.endMarkerConns = make(map[string]*net.UnixConn)
		}
		if c.endMarkerConns[path] == nil {
			c.endMarkerConns[path] = opened
			conn = opened
		} else {
			conn = c.endMarkerConns[path]
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
		if c.endMarkerConns[path] == conn {
			delete(c.endMarkerConns, path)
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
	return smReqFlags(ies, (*ie.IE).HasSNDEM)
}

// drobu reports whether a Session Modification Request's IEs carry the DROBU
// flag (TS 29.244 8.2.31): the sibling bit in the same octet as SNDEM -- the
// drop-buffered instruction of 7.5.4.1, which 8.2.31 says the CP function may
// carry on the message or inside a FAR's forwarding parameters.
func drobu(ies []*ie.IE) bool {
	return smReqFlags(ies, (*ie.IE).HasDROBU)
}

// smReqFlags finds a PFCPSMReq-Flags IE wherever a Session Modification Request
// can carry one -- the message's own, or one inside a Create FAR's or Update
// FAR's forwarding parameters -- and asks has whether its bit is set.
func smReqFlags(ies []*ie.IE, has func(*ie.IE) bool) bool {
	return smReqFlagsDepth(ies, 0, has)
}

func smReqFlagsDepth(ies []*ie.IE, depth int, has func(*ie.IE) bool) bool {
	if depth > 4 { // FAR -> forwarding parameters -> the flag: no deeper
		return false
	}
	for _, i := range ies {
		if i == nil {
			continue
		}
		if i.Type == ie.PFCPSMReqFlags && has(i) {
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
		if err == nil && smReqFlagsDepth(children, depth+1, has) {
			return true
		}
	}
	return false
}

// tunnelEndMarker retains the old transport as well as the old F-TEID: a
// modification may change both the FAR's egress and its referring PDRs.
type tunnelEndMarker struct {
	far
	transport TunnelTransport
}

func (c *Compiler) sendTunnelEndMarker(tunnel tunnelEndMarker) error {
	transport := tunnel.transport
	if !transport.Addr.Is4() || !tunnel.peer.Is4() {
		return fmt.Errorf("end-marker transport requires IPv4 source and peer addresses: %s, %s", transport.Addr, tunnel.peer)
	}
	frame := endMarkerFrame(tunnel.teid, tunnel.peer, transport.Addr, transport.MAC, transport.PeerMAC)
	return c.sendEndMarkerAt(transport.EndMarker, frame)
}

// leavingTunnels snapshots the tunnels a modification moves away from before
// merge changes their FARs, PDRs or MARs. A shared FAR can have more than one
// resolved egress; each distinct old transport receives its own marker.
func (c *Compiler) leavingTunnels(s *Session, fars []farReq) []tunnelEndMarker {
	var out []tunnelEndMarker
	for _, f := range fars {
		old := s.FARs[f.id]
		if old == nil || !old.hasOuter || old.teid == 0 {
			continue
		}
		tunnelChanged := f.hasOuter && (f.teid != old.teid || f.peer != old.peer)
		egressChanged := (f.hasDestIfc && f.destIfc != old.destIfc) ||
			(f.hasInstance && f.instance != old.instance)
		if !tunnelChanged && !egressChanged {
			continue
		}
		updated := *old
		if f.hasDestIfc {
			updated.destIfc = f.destIfc
		}
		if f.hasInstance {
			updated.instance = f.instance
		}
		start := len(out)
		add := func(hop uint32, ifc routing.Interface, dir Direction) {
			transport := c.tunnelTransport(hop)
			if !tunnelChanged {
				nextHop, err := c.egressHop(&updated, ifc, dir)
				if err != nil || c.tunnelTransport(nextHop) == transport {
					return
				}
			}
			for _, marker := range out[start:] {
				if marker.transport == transport {
					return
				}
			}
			out = append(out, tunnelEndMarker{far: *old, transport: transport})
		}
		referenced := false
		for _, p := range pdrsInOrder(s) {
			if p.hasMAR || p.farID != old.id {
				continue
			}
			referenced = true
			var ifc routing.Interface
			if !tunnelChanged {
				var err error
				ifc, err = c.interfaceFor(p)
				if err != nil {
					continue
				}
			}
			add(p.nextHop, ifc, c.direction(p.srcIfc))
		}
		for _, m := range s.MARs {
			for which, access := range m.accesses {
				if !access.hasFarID || access.farID != old.id || m.tunnelIDs[which] == 0 {
					continue
				}
				referenced = true
				var ifc routing.Interface
				if !tunnelChanged {
					var err error
					ifc, err = c.marInterface(s, m.id)
					if err != nil {
						continue
					}
				}
				add(m.nextHops[which], ifc, c.cfg.Down)
			}
		}
		if !referenced && tunnelChanged {
			// An unreferenced FAR has no resolved next hop or old
			// packet stream; preserve the default transport behavior.
			add(0, routing.Interface{}, c.cfg.Down)
		}
	}
	return out
}

