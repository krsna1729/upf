// SPDX-License-Identifier: BSD-3-Clause
package session

import (
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
)

// TestAMalformedSDFFilterIsRefused is the N4 path's half of the fork's
// SDFFilterFields bounds check: an SMF can put any FDLength in the IE, and a
// length past the payload used to panic the daemon while the compiler read
// the filter. The session must be answered with a refusal instead.
func TestAMalformedSDFFilterIsRefused(t *testing.T) {
	req := establishment(0x7014, "10.45.0.24")
	found := false
	for n, pdr := range req.CreatePDR {
		if !hasSDF(pdr) {
			continue
		}
		req.CreatePDR[n] = withMalformedSDF(pdr)
		found = true
	}
	if !found {
		t.Fatal("the fixture carries no SDF filter")
	}
	c := New(testConfig(), &recorder{}, quietLogger())
	resp := c.Establish(req)
	// An unreadable IE is a rejected message (TS 29.244 7.5.2.2), not a
	// dataplane rule failure: the request never reached the compiler's tables.
	if got := cause(t, resp); got != ie.CauseRequestRejected {
		t.Errorf("a malformed SDF filter was answered with cause %d, want 64", got)
	}
}

// withMalformedSDF rebuilds a Create PDR with the SDF filter's FDLength past
// the two payload bytes that follow it: FD flag, 0xfffe, two bytes.
func withMalformedSDF(pdr *ie.IE) *ie.IE {
	bad := ie.NewSDFFilter("permit out ip from any to any", "", "", "", 0)
	bad.Payload = []byte{0x01, 0x00, 0xff, 0xfe, 0x01, 0x02}
	bad.SetLength()
	children := make([]*ie.IE, 0, len(pdr.ChildIEs))
	for _, c := range pdr.ChildIEs {
		if c.Type == ie.PDI {
			pdi := make([]*ie.IE, 0, len(c.ChildIEs))
			for _, pc := range c.ChildIEs {
				if pc.Type == ie.SDFFilter {
					pc = bad
				}
				pdi = append(pdi, pc)
			}
			c = ie.NewPDI(pdi...)
		}
		children = append(children, c)
	}
	return ie.NewCreatePDR(children...)
}

func hasSDF(i *ie.IE) bool {
	if i.Type == ie.SDFFilter {
		return true
	}
	for _, c := range i.ChildIEs {
		if hasSDF(c) {
			return true
		}
	}
	return false
}
