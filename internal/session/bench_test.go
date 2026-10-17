// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"

	"github.com/krsna1729/upf/internal/bess"
	"github.com/wmnsk/go-pfcp/message"
)

// discardApplier is the recorder's quiet sibling: it accepts the transaction and
// keeps nothing, so a benchmark measures the compiler rather than the changes it
// hands over.
type discardApplier struct{ changes int }

func (d *discardApplier) Apply(_ context.Context, changes ...bess.Change) error {
	d.changes += len(changes)
	return nil
}

// n4Logger throws the compiler's log lines away.
func n4Logger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// BenchmarkEstablish is the compile path with no socket and no daemon: the
// applier throws the transaction away and what is measured is the controller's
// own work per session -- reading the IEs, building each rule's key and match,
// building the transaction's messages and the response. ci/bench-n4.sh measures
// the whole path this sits under: the datagram, the parse, this, the reply, and
// the transaction's round trip. The request literal is part of the loop because
// every session needs its own; it is what the bench's SMF would have sent.
func BenchmarkEstablish(b *testing.B) {
	var i uint64
	ap := &discardApplier{}
	c := New(testConfig(), ap, n4Logger())
	b.ReportAllocs()
	for b.Loop() {
		i++
		req := establishment(i, fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff))
		if resp := c.Establish(req); resp == nil {
			b.Fatal("Establish answered nothing")
		}
	}
	if ap.changes == 0 {
		b.Fatal("no changes reached the applier")
	}
}

// BenchmarkParseEstablish is the wire's own cost on the way in: the library's
// parse of a session establishment, which every request pays before any of this
// package's work starts.
func BenchmarkParseEstablish(b *testing.B) {
	buf, err := establishment(1, "10.0.0.1").Marshal()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		m, err := message.Parse(buf)
		if err != nil {
			b.Fatal(err)
		}
		if m.MessageType() != message.MsgTypeSessionEstablishmentRequest {
			b.Fatal("parsed the wrong type")
		}
	}
}

// BenchmarkMarshalResponse is the wire's cost on the way out: the response one
// session produces, marshalled as the socket would send it.
func BenchmarkMarshalResponse(b *testing.B) {
	c := New(testConfig(), &discardApplier{}, n4Logger())
	resp := c.Establish(establishment(1, "10.0.0.1"))
	if resp == nil {
		b.Fatal("Establish answered nothing")
	}
	b.ReportAllocs()
	for b.Loop() {
		buf := make([]byte, resp.MarshalLen())
		if err := resp.MarshalTo(buf); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDelete measures the other half of a session's life: the tables are
// read back out and the entries are erased.
func BenchmarkDelete(b *testing.B) {
	var i uint64
	c := New(testConfig(), &discardApplier{}, n4Logger())
	dels := make([]*message.SessionDeletionRequest, 0, b.N)
	for range b.N {
		i++
		est := establishment(i, fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff))
		resp := c.Establish(est)
		if resp == nil {
			b.Fatal("Establish answered nothing")
		}
		upSeid := upSEID(b, resp.(*message.SessionEstablishmentResponse))
		dels = append(dels, message.NewSessionDeletionRequest(0, 0, upSeid, 2, 0))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for _, del := range dels {
		if resp := c.Delete(del); resp == nil {
			b.Fatal("Delete answered nothing")
		}
	}
}
