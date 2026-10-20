// SPDX-License-Identifier: BSD-3-Clause

// Command pfcpdump decodes the PFCP (UDP 8805) messages in a classic pcap file
// -- what tcpdump -w wrote on the interop bridge -- into an indented IE tree.
// It is the repository's tshark substitute for docs/interop.md: every grouped
// IE is walked, the IEs that matter to a UPF (F-TEID, UE IP Address, SDF
// Filter, Apply Action, Outer Header Creation/Removal, ...) are decoded bit by
// bit, and every leaf also carries its raw hex, so a flag this tool does not
// name is still on the page.
//
//	go run ./ci/interop/pfcpdump [-port N] n4.pcap
//
// -port is the UDP port that marks a PFCP packet (default 8805; 0: every UDP
// packet is taken to be PFCP).
package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

var port = flag.Uint("port", 8805, "UDP port of the PFCP endpoint (0: any)")

func main() {
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: pfcpdump [-port N] <file.pcap>")
		os.Exit(2)
	}
	b, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := dump(b); err != nil {
		fmt.Fprintln(os.Stderr, "pfcpdump:", err)
		os.Exit(1)
	}
}

func dump(b []byte) error {
	if len(b) < 24 {
		return fmt.Errorf("short pcap (%d bytes)", len(b))
	}
	var bo binary.ByteOrder
	nano := false
	switch binary.LittleEndian.Uint32(b) {
	case 0xa1b2c3d4:
		bo = binary.LittleEndian
	case 0xa1b23c4d:
		bo, nano = binary.LittleEndian, true
	default:
		switch binary.BigEndian.Uint32(b) {
		case 0xa1b2c3d4:
			bo = binary.BigEndian
		case 0xa1b23c4d:
			bo, nano = binary.BigEndian, true
		default:
			return fmt.Errorf("not a classic pcap file (magic %x)", b[:4])
		}
	}
	link := bo.Uint32(b[20:])
	var t0 time.Time
	n := 0
	for off := 24; off+16 <= len(b); {
		sec, frac, incl := bo.Uint32(b[off:]), bo.Uint32(b[off+4:]), int(bo.Uint32(b[off+8:]))
		off += 16
		if off+incl > len(b) {
			break
		}
		pkt := b[off : off+incl]
		off += incl
		ts := time.Unix(int64(sec), int64(frac)).UTC()
		if !nano {
			ts = time.Unix(int64(sec), int64(frac)*1000).UTC()
		}
		src, dst, sp, dp, payload, ok := udp(link, pkt)
		if !ok || (*port != 0 && uint(sp) != *port && uint(dp) != *port) {
			continue
		}
		if n == 0 {
			t0 = ts
		}
		n++
		fmt.Printf("#%d +%.3fs %s %s:%d -> %s:%d (%d bytes)\n", n, ts.Sub(t0).Seconds(),
			ts.Format("15:04:05.000"), src, sp, dst, dp, len(payload))
		pfcp(payload)
		fmt.Println()
	}
	if n == 0 {
		fmt.Println("no PFCP packets")
	}
	return nil
}

// udp returns the UDP payload of an IPv4 frame, for Ethernet (1) and Linux
// cooked (113) captures.
func udp(link uint32, p []byte) (src, dst net.IP, sp, dp uint16, payload []byte, ok bool) {
	switch link {
	case 1:
		if len(p) < 14 || binary.BigEndian.Uint16(p[12:]) != 0x0800 {
			return
		}
		p = p[14:]
	case 113:
		if len(p) < 16 || binary.BigEndian.Uint16(p[14:]) != 0x0800 {
			return
		}
		p = p[16:]
	default:
		return
	}
	if len(p) < 20 || p[0]>>4 != 4 || p[9] != 17 {
		return
	}
	ihl := int(p[0]&0xf) * 4
	if len(p) < ihl+8 {
		return
	}
	src, dst = net.IP(p[12:16]), net.IP(p[16:20])
	u := p[ihl:]
	sp, dp = binary.BigEndian.Uint16(u), binary.BigEndian.Uint16(u[2:])
	l := int(binary.BigEndian.Uint16(u[4:]))
	if l < 8 || l > len(u) {
		l = len(u)
	}
	return src, dst, sp, dp, u[8:l], true
}

func pfcp(p []byte) {
	if len(p) < 8 {
		fmt.Printf("  short PFCP header\n")
		return
	}
	hdr := 8
	sFlag := p[0]&0x01 != 0
	var seid uint64
	if sFlag {
		hdr = 16
		if len(p) < hdr {
			fmt.Printf("  short PFCP header\n")
			return
		}
		seid = binary.BigEndian.Uint64(p[4:])
	}
	mt := p[1]
	seq := uint32(p[hdr-4])<<16 | uint32(p[hdr-3])<<8 | uint32(p[hdr-2])
	name := fmt.Sprintf("type %d", mt)
	if m, err := message.Parse(p); err == nil {
		name = m.MessageTypeName()
	} else {
		name += " (go-pfcp parse: " + err.Error() + ")"
	}
	if sFlag {
		fmt.Printf("  %s seq=%d seid=0x%x\n", name, seq, seid)
	} else {
		fmt.Printf("  %s seq=%d\n", name, seq)
	}
	ies, err := ie.ParseMultiIEs(p[hdr:])
	if err != nil {
		fmt.Printf("  ie parse: %v\n", err)
		return
	}
	walk(ies, 2)
}

func walk(ies []*ie.IE, depth int) {
	pad := strings.Repeat("  ", depth)
	for _, i := range ies {
		name, ok := ieNames[i.Type]
		if !ok {
			name = fmt.Sprintf("IE%d", i.Type)
		}
		if i.IsGrouped() {
			fmt.Printf("%s%s (%d) len=%d\n", pad, name, i.Type, i.Length)
			if kids, err := i.ValueAsGrouped(); err == nil {
				walk(kids, depth+1)
			} else {
				fmt.Printf("%s  <grouped parse: %v> %s\n", pad, err, hex.EncodeToString(i.Payload))
			}
			continue
		}
		fmt.Printf("%s%s (%d) len=%d %s", pad, name, i.Type, i.Length, hex.EncodeToString(i.Payload))
		if d := decode(i.Type, i.Payload); d != "" {
			fmt.Printf("  = %s", d)
		}
		fmt.Println()
	}
}

func be32(b []byte) uint32 { return binary.BigEndian.Uint32(b) }

func flags(v uint8, names ...string) string {
	var s []string
	for k, n := range names {
		if n != "" && v&(1<<k) != 0 {
			s = append(s, n)
		}
	}
	if len(s) == 0 {
		return "-"
	}
	return strings.Join(s, "|")
}

var causes = map[uint8]string{
	1: "Request accepted", 64: "Request rejected (reason not specified)", 65: "Session context not found",
	66: "Mandatory IE missing", 67: "Conditional IE missing", 68: "Invalid length", 69: "Mandatory IE incorrect",
	70: "Invalid Forwarding Policy", 71: "Invalid F-TEID allocation option", 72: "No established PFCP Association",
	73: "Rule creation/modification Failure", 74: "PFCP entity in congestion", 75: "No resources available",
	76: "Service not supported", 77: "System failure", 78: "Redirection Requested",
}

var ifaces = map[uint8]string{0: "Access", 1: "Core", 2: "SGi-LAN/N6-LAN", 3: "CP-function", 4: "5G VN Internal"}

// decode names a leaf IE's value; "" leaves only the hex.
func decode(t ie.IEType, v []byte) (out string) {
	defer func() {
		if recover() != nil {
			out = "<short>"
		}
	}()
	switch t {
	case 19:
		return causes[v[0]]
	case 20, 42:
		return ifaces[v[0]&0xf]
	case 21: // F-TEID
		f := v[0]
		s := "flags " + flags(f, "V4", "V6", "CH", "CHID")
		o := 1
		if f&4 == 0 {
			s += fmt.Sprintf(" teid=0x%08x", be32(v[o:]))
			o += 4
			if f&1 != 0 {
				s += " v4=" + net.IP(v[o:o+4]).String()
				o += 4
			}
			if f&2 != 0 {
				s += " v6=" + net.IP(v[o:o+16]).String()
				o += 16
			}
		} else if f&8 != 0 {
			s += fmt.Sprintf(" choose-id=%d", v[o])
		}
		return s
	case 93: // UE IP Address
		f := v[0]
		s := "flags " + flags(f, "V6", "V4", "SD", "IPv6D", "CHV4", "CHV6", "IP6PL")
		o := 1
		if f&2 != 0 {
			s += " v4=" + net.IP(v[o:o+4]).String()
			o += 4
		}
		if f&1 != 0 {
			s += " v6=" + net.IP(v[o:o+16]).String()
		}
		if f&4 != 0 {
			s += " (SD set: " + map[bool]string{true: "destination", false: "source"}[f&4 != 0] + ")"
		}
		return s
	case 44:
		s := flags(v[0], "DROP", "FORW", "BUFF", "NOCP", "DUPL", "IPMA", "IPMD", "DFRT")
		if len(v) > 1 {
			s += " / " + flags(v[1], "EDRT", "BDPN", "DDPN", "FSSM", "MBSU")
		}
		return s
	case 84: // Outer Header Creation
		desc := v[0]
		s := "desc " + flags(desc, "GTP-U/UDP/IPv4", "GTP-U/UDP/IPv6", "UDP/IPv4", "UDP/IPv6", "IPv4", "IPv6", "C-TAG", "S-TAG")
		o := 2
		if desc&3 != 0 {
			s += fmt.Sprintf(" teid=0x%08x", be32(v[o:]))
			o += 4
		}
		if desc&(1|4|16) != 0 {
			s += " v4=" + net.IP(v[o:o+4]).String()
			o += 4
		}
		if desc&(2|8|32) != 0 {
			s += " v6=" + net.IP(v[o:o+16]).String()
			o += 16
		}
		if desc&(4|8) != 0 {
			s += fmt.Sprintf(" port=%d", binary.BigEndian.Uint16(v[o:]))
		}
		return s
	case 95: // Outer Header Removal
		names := []string{"GTP-U/UDP/IPv4", "GTP-U/UDP/IPv6", "UDP/IPv4", "UDP/IPv6", "IPv4", "IPv6", "GTP-U/UDP/IP", "VLAN S-TAG", "S-TAG and C-TAG"}
		if int(v[0]) < len(names) {
			return names[v[0]]
		}
	case 23: // SDF Filter
		f := v[0]
		s := "flags " + flags(f, "FD", "TTC", "SPI", "FL", "BID")
		o := 2
		if f&1 != 0 {
			l := int(binary.BigEndian.Uint16(v[o:]))
			s += fmt.Sprintf(" fd=%q", string(v[o+2:o+2+l]))
			o += 2 + l
		}
		if f&2 != 0 {
			s += fmt.Sprintf(" tos=0x%04x", binary.BigEndian.Uint16(v[o:]))
			o += 2
		}
		if f&4 != 0 {
			s += fmt.Sprintf(" spi=0x%08x", be32(v[o:]))
			o += 4
		}
		if f&8 != 0 {
			s += fmt.Sprintf(" flow-label=0x%06x", uint32(v[o])<<16|uint32(v[o+1])<<8|uint32(v[o+2]))
			o += 3
		}
		if f&16 != 0 {
			s += fmt.Sprintf(" sdf-filter-id=%d", be32(v[o:]))
		}
		return s
	case 29, 81, 108, 109:
		return fmt.Sprintf("%d", be32(v))
	case 56:
		return fmt.Sprintf("%d", binary.BigEndian.Uint16(v))
	case 124:
		return fmt.Sprintf("%d", v[0]&0x3f)
	case 25:
		g := map[uint8]string{0: "OPEN", 1: "CLOSED"}
		return "UL " + g[(v[0]>>2)&3] + " DL " + g[v[0]&3]
	case 26, 27: // MBR, GBR: kbps
		u := uint64(v[0])<<32 | uint64(be32(v[1:]))
		d := uint64(v[5])<<32 | uint64(be32(v[6:]))
		return fmt.Sprintf("ul=%d dl=%d kbps", u, d)
	case 57: // F-SEID
		f := v[0]
		s := fmt.Sprintf("flags %s seid=0x%x", flags(f, "V6", "V4"), binary.BigEndian.Uint64(v[1:]))
		o := 9
		if f&2 != 0 {
			s += " v4=" + net.IP(v[o:o+4]).String()
			o += 4
		}
		if f&1 != 0 {
			s += " v6=" + net.IP(v[o:o+16]).String()
		}
		return s
	case 60: // Node ID
		switch v[0] & 0xf {
		case 0:
			return "IPv4 " + net.IP(v[1:5]).String()
		case 1:
			return "IPv6 " + net.IP(v[1:17]).String()
		case 2:
			var parts []string
			for o := 1; o < len(v); {
				l := int(v[o])
				parts = append(parts, string(v[o+1:o+1+l]))
				o += 1 + l
			}
			return "FQDN " + strings.Join(parts, ".")
		}
	case 96:
		return time.Unix(int64(be32(v))-2208988800, 0).UTC().Format(time.RFC3339)
	case 22, 159:
		return fmt.Sprintf("%q", string(v))
	case 113:
		return map[uint8]string{1: "IPv4", 2: "IPv6", 3: "IPv4v6", 4: "Non-IP", 5: "Ethernet"}[v[0]]
	case 62:
		return flags(v[0], "DURAT", "VOLUM", "EVENT")
	case 37:
		return "triggers " + flags(v[0], "PERIO", "VOLTH", "TIMTH", "QUHTI", "START", "STOPT", "DROTH", "LIUSA") +
			" / " + flags(v[1], "VOLQU", "TIMQU", "ENVCL", "MACAR", "EVETH", "EVEQU", "IPMJL", "QUVTI")
	case 31, 73, 121: // volume threshold / quota
		f := v[0]
		s := "flags " + flags(f, "TOVOL", "ULVOL", "DLVOL")
		o := 1
		for k, n := range []string{"total", "ul", "dl"} {
			if f&(1<<k) != 0 {
				s += fmt.Sprintf(" %s=%d", n, binary.BigEndian.Uint64(v[o:]))
				o += 8
			}
		}
		return s
	case 64, 117:
		return fmt.Sprintf("%d s", be32(v))
	case 49:
		return flags(v[0], "DROBU", "SNDEM", "QAURR", "SUMPC", "RUMUC", "DETEID", "")
	case 89:
		return "CP features " + hex.EncodeToString(v)
	case 100:
		return flags(v[0], "MBQE", "INAM", "RADI", "ISTM", "MNOP")
	case 160:
		return fmt.Sprintf("%d", v[0]&0x3f)
	}
	return ""
}
