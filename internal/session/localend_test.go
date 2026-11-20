// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"net/netip"
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// A modification that leaves a PDR's tunnel as it was writes no tunnel
// record, even after the local-end table has handed out and freed many other
// ends in between: an end's handle is its value's for as long as it is held.
func TestAnUnchangedTunnelIsNotRewrittenAfterOtherLocalEndsChurned(t *testing.T) {
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

	c.mu.Lock()
	for i := range 4096 {
		h := c.st.ends.acquire(localEnd{address: ipOf(netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)})), domain: 9})
		c.st.ends.release(h)
	}
	c.mu.Unlock()

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
