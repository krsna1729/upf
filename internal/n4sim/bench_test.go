// SPDX-License-Identifier: BSD-3-Clause

package n4sim

import (
	"fmt"
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// benchSession is a session's worth of parameters without a socket: n4bench and
// the live tests both build requests through these, so their cost is part of any
// client-side measurement.
func benchSession(i uint64) Session {
	return Session{
		CPSEID: i,
		TEID:   uint32(0x1000 + i),
		FTEID:  0,
		UEIP:   fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff),
		GnBIP:  "192.0.2.1",
		N3IP:   "192.0.2.9",
	}
}

// BenchmarkBuildEstablish is the SMF side of one message: the IEs a session
// establishment carries are built and marshalled, which is the work a client
// does before its first byte is on the wire. The server's own costs live in
// internal/n4 and internal/session.
func BenchmarkBuildEstablish(b *testing.B) {
	var i uint64
	b.ReportAllocs()
	for b.Loop() {
		i++
		m := Establish(uint32(i), benchSession(i))
		buf := make([]byte, m.MarshalLen())
		if err := m.MarshalTo(buf); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkBuildModify and BenchmarkBuildDelete are the same for the two other
// session messages, whose IEs are smaller.
func BenchmarkBuildModify(b *testing.B) {
	var i uint64
	b.ReportAllocs()
	for b.Loop() {
		i++
		s := benchSession(i)
		m := Modify(uint32(i), s.CPSEID, 2, s.TEID+1, s.GnBIP)
		buf := make([]byte, m.MarshalLen())
		if err := m.MarshalTo(buf); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBuildDelete(b *testing.B) {
	var i uint64
	b.ReportAllocs()
	for b.Loop() {
		i++
		m := Delete(uint32(i), benchSession(i).CPSEID)
		buf := make([]byte, m.MarshalLen())
		if err := m.MarshalTo(buf); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkParseEstablishmentResponse is the other half of a client's cost: the
// answer it has to read, with the Created PDR and F-SEID a session needs.
func BenchmarkParseEstablishmentResponse(b *testing.B) {
	resp := message.NewSessionEstablishmentResponse(0, 0, 0x1122, 2, 0,
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewFSEID(0x1122, nil, nil),
		ie.NewCreatedPDR(ie.NewPDRID(1), ie.NewFTEID(0x01, 0x1000, nil, nil, 0)),
	)
	buf := make([]byte, resp.MarshalLen())
	if err := resp.MarshalTo(buf); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		m, err := message.Parse(buf)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := Cause(m); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCause measures reading the cause out of an answer, which every
// client-side call does before it looks at anything else.
func BenchmarkCause(b *testing.B) {
	resp := message.NewSessionEstablishmentResponse(0, 0, 0x1122, 2, 0,
		ie.NewCause(ie.CauseRequestAccepted))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Cause(resp); err != nil {
			b.Fatal(err)
		}
	}
}
