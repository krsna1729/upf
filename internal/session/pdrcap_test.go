// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// An establishment over the cap is refused before the merge allocates the
// model the compile would copy (UG-R10), and no session is left behind.
func TestAnEstablishmentBeyondThePDRCapIsRefused(t *testing.T) {
	cfg := testConfig()
	cfg.MaxPDRs = 1
	c := New(cfg, &recorder{}, quietLogger())
	resp := c.Establish(establishment(0x7a01, "10.45.0.7")).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseNoResourcesAvailable {
		t.Fatalf("a two-PDR establishment under a one-PDR cap answered cause %d, want %d",
			got, ie.CauseNoResourcesAvailable)
	}
	if n := len(c.sessions); n != 0 {
		t.Errorf("the refused establishment left %d sessions", n)
	}
}

// A modification that would grow the session past the cap is refused before
// the snapshot stages the merged model; the model keeps the PDRs it had.
func TestAModificationBeyondThePDRCapIsRefused(t *testing.T) {
	cfg := testConfig()
	cfg.MaxPDRs = 2
	c := New(cfg, &recorder{}, quietLogger())
	resp := c.Establish(establishmentWithFTEID(0x7a02, "10.45.0.8", 0x01020304)).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	mod := message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 2, 0,
		ie.NewCreatePDR(ie.NewPDRID(3), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				testFTEID(0x01020304),
				ie.NewUEIPAddress(0x02, "10.45.0.8", "", 0, 0),
				ie.NewSDFFilter("permit out udp from any 9999 to any", "", "", "", 0)),
			ie.NewFARID(1)),
	)
	if got := cause(t, c.Modify(mod)); got != ie.CauseNoResourcesAvailable {
		t.Fatalf("the growth answered cause %d, want %d", got, ie.CauseNoResourcesAvailable)
	}
	for _, s := range c.sessions {
		if got := s.PDRs().len(); got != 2 {
			t.Errorf("the refused modification left %d PDRs, want the session's 2", got)
		}
	}
}

// Restating the PDRs a session already holds is not growth: a modification
// at the cap that updates them must still be accepted.
func TestAModificationRestatingAPDRAtTheCapIsAllowed(t *testing.T) {
	cfg := testConfig()
	cfg.MaxPDRs = 2
	c := New(cfg, &recorder{}, quietLogger())
	resp := c.Establish(establishmentWithFTEID(0x7a03, "10.45.0.9", 0x05060708)).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	mod := message.NewSessionModificationRequest(0, 0, upFSEID(t, resp), 2, 0,
		ie.NewUpdatePDR(ie.NewPDRID(1), ie.NewPrecedence(100)),
		ie.NewUpdatePDR(ie.NewPDRID(2), ie.NewPrecedence(100)),
	)
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("restating the capped PDRs answered cause %d, want %d",
			got, ie.CauseRequestAccepted)
	}
}
