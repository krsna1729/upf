// SPDX-License-Identifier: BSD-3-Clause

// Command n4shim is a diagnostic UDP relay between the SMF and upfd that
// repairs the two defects of upfd's Session Establishment Response that stop a
// real SMF reading it (docs/interop.md): the missing Node ID, and an UP F-SEID
// that carries no address. It exists only so that a run can go on to the
// stages behind the rejection (the SMF's Session Modification, usage reports,
// Session Deletion) and show what they send. It changes nothing else, logs
// every message it patches, and is NOT part of the UPF: ci/interop/up.sh
// starts it only when SHIM=1, and the evidence it produces is labelled so.
//
//	n4shim -front 10.77.88.1:8805 -upfd 127.0.0.1:50000 -node-id 10.77.88.1
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

func main() {
	front := flag.String("front", "", "address the SMF dials (the bridge gateway, UDP 8805)")
	upfd := flag.String("upfd", "", "upfd's real N4 address")
	nodeID := flag.String("node-id", "", "the IPv4 address the repaired Node ID and UP F-SEID carry")
	flag.Parse()
	if *front == "" || *upfd == "" || *nodeID == "" {
		flag.Usage()
		os.Exit(2)
	}
	ip, err := netip.ParseAddr(*nodeID)
	if err != nil || !ip.Is4() {
		log.Fatalf("n4shim: -node-id %q is not an IPv4 address", *nodeID)
	}

	fa, err := net.ResolveUDPAddr("udp4", *front)
	check(err)
	ua, err := net.ResolveUDPAddr("udp4", *upfd)
	check(err)
	fc, err := net.ListenUDP("udp4", fa)
	check(err)
	bc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	check(err)
	log.Printf("n4shim: SMF side %s, upfd side %s -> %s, node-id %s", fa, bc.LocalAddr(), ua, ip)

	var smf *net.UDPAddr // learned from the first datagram on the front
	done := make(chan struct{})

	go func() { // upfd -> SMF
		buf := make([]byte, 65535)
		for {
			n, _, err := bc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if smf == nil {
				continue
			}
			if _, err := fc.WriteToUDP(patch(buf[:n], ip), smf); err != nil {
				log.Printf("n4shim: to SMF: %v", err)
			}
		}
	}()
	go func() { // SMF -> upfd
		buf := make([]byte, 65535)
		for {
			n, from, err := fc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			smf = from
			if _, err := bc.WriteToUDP(buf[:n], ua); err != nil {
				log.Printf("n4shim: to upfd: %v", err)
			}
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() { <-sig; close(done) }()
	<-done
	fc.Close()
	bc.Close()
}

func check(err error) {
	if err != nil {
		log.Fatalf("n4shim: %v", err)
	}
}

// patch returns b, repaired when it is a Session Establishment Response.
func patch(b []byte, ip netip.Addr) []byte {
	m, err := message.Parse(b)
	if err != nil {
		return b
	}
	r, ok := m.(*message.SessionEstablishmentResponse)
	if !ok {
		return b
	}
	var notes []string
	if r.NodeID == nil {
		r.NodeID = ie.NewNodeID(ip.String(), "", "")
		notes = append(notes, "added Node ID "+ip.String())
	}
	if r.UPFSEID != nil {
		if f, err := r.UPFSEID.FSEID(); err == nil && len(f.IPv4Address) == 0 && len(f.IPv6Address) == 0 {
			r.UPFSEID = ie.NewFSEID(f.SEID, net.IP(ip.AsSlice()), nil)
			notes = append(notes, fmt.Sprintf("gave the UP F-SEID (seid 0x%x) the address %s", f.SEID, ip))
		}
	}
	if len(notes) == 0 {
		return b
	}
	out := make([]byte, r.MarshalLen())
	if err := r.MarshalTo(out); err != nil {
		log.Printf("n4shim: marshal: %v", err)
		return b
	}
	log.Printf("n4shim: Session Establishment Response seq=%d: %v", r.Sequence(), notes)
	return out
}
