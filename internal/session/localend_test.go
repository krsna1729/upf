// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"net/netip"
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// A modification that leaves a PDR's tunnel as it was writes no tunnel
// record, even after the local-end table has handed the tunnel's slot to
// other ends: equal ends built at different times may be different copies.
func TestAnUnchangedTunnelIsNotRewrittenAfterItsLocalEndWasEvicted(t *testing.T) {
	rec := &recorder{}
	c := New(testConfig(), rec, quietLogger())
	resp := c.Establish(establishment(0x7101, "10.45.0.71")).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	tunnels := c.tunnelRes(downlinkTunnel)
	written := false
	for _, ch := range rec.last() {
		written = written || ch.Resource == tunnels
	}
	if !written {
		t.Fatal("the establishment wrote no downlink tunnel record")
	}

	for i := range 4 * internSlots {
		newLocalEnd(netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)}), 9)
	}

	mod := message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 2, 0,
		ie.NewUpdateQER(ie.NewQERID(1), ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
			ie.NewMBR(3000, 4000)))
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification answered cause %d", got)
	}
	for _, ch := range rec.last() {
		if ch.Resource == tunnels {
			t.Errorf("a QER rate change rewrote the unchanged tunnel record %v", ch.Key)
		}
	}
}
