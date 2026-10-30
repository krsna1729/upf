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

// endMarkerFrame builds an untagged Ethernet End Marker with zero MAC
// addresses. The routed transport Router selects the neighbor and rewrites
// L2; the outer IP family follows the old tunnel's source and peer.
func endMarkerFrame(teid uint32, peer, src netip.Addr) ([]byte, error) {
	if !peer.IsValid() || !src.IsValid() || peer.Is4In6() || src.Is4In6() ||
		peer.Is4() != src.Is4() {
		return nil, fmt.Errorf("end-marker source and peer must use the same IPv4 or IPv6 family: %s, %s",
			src, peer)
	}
	const (
		ethernetLength = 14
		udpLength      = 8
		gtpuLength     = 8
	)
	ipLength := 40
	etherType := uint16(0x86dd)
	if src.Is4() {
		ipLength = 20
		etherType = 0x0800
	}
	packetLength := ethernetLength + ipLength + udpLength + gtpuLength
	frameLength := max(packetLength, 60)
	frame := make([]byte, frameLength)
	binary.BigEndian.PutUint16(frame[12:14], etherType)
	ip := frame[ethernetLength : ethernetLength+ipLength]
	if src.Is4() {
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:4], uint16(ipLength+udpLength+gtpuLength))
		binary.BigEndian.PutUint16(ip[6:8], 0x4000)
		ip[8], ip[9] = 64, 17
		src4, dst4 := src.As4(), peer.As4()
		copy(ip[12:16], src4[:])
		copy(ip[16:20], dst4[:])
		binary.BigEndian.PutUint16(ip[10:12], ipv4Checksum(ip))
	} else {
		ip[0] = 0x60
		binary.BigEndian.PutUint16(ip[4:6], udpLength+gtpuLength)
		ip[6], ip[7] = 17, 64
		src6, dst6 := src.As16(), peer.As16()
		copy(ip[8:24], src6[:])
		copy(ip[24:40], dst6[:])
	}
	udpOffset := ethernetLength + ipLength
	udp := frame[udpOffset : udpOffset+udpLength]
	binary.BigEndian.PutUint16(udp[0:2], gtpuPort)
	binary.BigEndian.PutUint16(udp[2:4], gtpuPort)
	binary.BigEndian.PutUint16(udp[4:6], udpLength+gtpuLength)
	gtp := frame[udpOffset+udpLength : udpOffset+udpLength+gtpuLength]
	gtp[0], gtp[1] = 0x30, endMarkerType
	binary.BigEndian.PutUint32(gtp[4:8], teid)
	if src.Is6() {
		datagram := frame[udpOffset : udpOffset+udpLength+gtpuLength]
		binary.BigEndian.PutUint16(udp[6:8], ipv6UDPChecksum(src, peer, datagram))
	}
	return frame, nil
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

// ipv6UDPChecksum computes the mandatory IPv6 UDP checksum over the IPv6
// pseudo-header and the complete UDP datagram.
func ipv6UDPChecksum(src, dst netip.Addr, udp []byte) uint16 {
	src6, dst6 := src.As16(), dst.As16()
	var sum uint32
	sum = checksumWords(sum, src6[:])
	sum = checksumWords(sum, dst6[:])
	var pseudo [8]byte
	binary.BigEndian.PutUint32(pseudo[:4], uint32(len(udp)))
	pseudo[7] = 17
	sum = checksumWords(sum, pseudo[:])
	sum = checksumWords(sum, udp)
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	checksum := ^uint16(sum)
	if checksum == 0 {
		return 0xffff
	}
	return checksum
}

func checksumWords(sum uint32, bytes []byte) uint32 {
	for i := 0; i+1 < len(bytes); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(bytes[i : i+2]))
	}
	if len(bytes)%2 != 0 {
		sum += uint32(bytes[len(bytes)-1]) << 8
	}
	return sum
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

// tunnelEndMarker retains the old routed endpoint as well as the old F-TEID:
// a modification may change the FAR's egress or remote tunnel.
type tunnelEndMarker struct {
	far
	localAddress         netip.Addr
	transportRouteDomain uint32
}

func (c *Compiler) sendTunnelEndMarker(tunnel tunnelEndMarker) error {
	if tunnel.transportRouteDomain == 0 {
		return fmt.Errorf("the old tunnel has no transport route domain")
	}
	frame, err := endMarkerFrame(tunnel.teid, tunnel.peer, tunnel.localAddress)
	if err != nil {
		return err
	}
	return c.sendEndMarkerAt(c.target.EndMarkerSocket(tunnel.transportRouteDomain), frame)
}

// leavingTunnels snapshots the tunnels a modification moves away from before
// merge changes their FARs, PDRs or MARs. A shared FAR can have more than one
// resolved routed endpoint; each distinct old endpoint receives a marker.
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
		add := func(local netip.Addr, domain uint32, ifc routing.Interface) {
			if !local.IsValid() || domain == 0 {
				return
			}
			if !tunnelChanged {
				endpoint, nextLocal, err := c.tunnelEndpoint(&updated, ifc)
				if err == nil && nextLocal == local && endpoint.TransportRouteDomain == domain {
					return
				}
			}
			for _, marker := range out[start:] {
				if marker.localAddress == local && marker.transportRouteDomain == domain {
					return
				}
			}
			out = append(out, tunnelEndMarker{
				far: *old, localAddress: local, transportRouteDomain: domain,
			})
		}
		for _, p := range pdrsInOrder(s) {
			if p.hasMAR || p.farID != old.id || !p.tunnelLocalAddress.IsValid() {
				continue
			}
			ifc, err := c.interfaceFor(p)
			if err == nil {
				add(p.tunnelLocalAddress, p.transportRouteDomain, ifc)
			}
		}
		for _, m := range s.MARs {
			ifc, err := c.marInterface(s, m.id)
			if err != nil {
				continue
			}
			for which, access := range m.accesses {
				if !access.hasFarID || access.farID != old.id ||
					m.tunnelIDs[which] == 0 || !m.tunnelLocalAddresses[which].IsValid() {
					continue
				}
				add(m.tunnelLocalAddresses[which], m.transportRouteDomains[which], ifc)
			}
		}
	}
	return out
}
