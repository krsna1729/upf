// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/bess"
)

// TestLiveErrorIndicationBecomesAnERIRReport is finding 15 with nothing faked.
// The lane's graph carries the same error arm as the smoke graph -- a Source
// injecting the peer's GTP-U Error Indication, the rule table's default gate
// delivering it to a responder whose track_errors is on -- and this test drives
// the control plane against that daemon: the tick's live reading of the
// module's error table (get_errors, the same command bessctl answers), and the
// Error Indication Report that comes out of it for the session whose downlink
// FAR sends into the tunnel the frame names.
//
// ci/session-path.sh starts the daemon with the plugin and applies the graph;
// the frame's TEID IE names pathDownTEID, which is the F-TEID the session's
// downlink FAR carries, so the two halves meet on the frame the lane deploys.
func TestLiveErrorIndicationBecomesAnERIRReport(t *testing.T) {
	target := os.Getenv("UPF_BESS_TARGET")
	if target == "" {
		t.Skip("set UPF_BESS_TARGET (ci/session-path.sh does) to run against a live bessd")
	}
	ctx := context.Background()
	client, err := bess.Dial(ctx, target)
	if err != nil {
		t.Fatalf("dialing %s: %v", target, err)
	}
	defer client.Close()
	if err := client.Refresh(ctx); err != nil {
		t.Fatalf("reading the daemon's schema: %v", err)
	}

	cfg := liveConfig()
	// The responder behind the TEID table's default gate, as the graph wires
	// it: the module whose error table the tick reads.
	cfg.GTPUErrors = "echo_err"
	c := New(cfg, client, slog.New(slog.NewTextHandler(os.Stderr,
		&slog.HandlerOptions{Level: slog.LevelWarn})))

	// The UE address the lane's frames do not name: this session must not
	// match the graph's own Sources, whose packets other tests in the lane
	// count as "nothing crossed before a session existed" (10.45.0.2 is the
	// frame's UE, 10.45.0.20 is nobody's).
	resp := c.Establish(pathEstablishment(0x7201, "10.45.0.20")).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	seid := upFSEID(t, resp)

	// The graph's Source has been injecting the Indication since the daemon
	// applied the graph, so the count is already there -- but the graph is
	// applied before this test runs, so the loop tolerates the reading landing
	// between two injections rather than assuming a fixed count.
	deadline := time.Now().Add(10 * time.Second)
	var report Report
	for len(report.Errors) == 0 {
		for _, r := range c.EvaluateAll(ctx, time.Now()) {
			if r.SEID == seid && len(r.Errors) > 0 {
				report = r
			}
		}
		if len(report.Errors) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no Error Indication Report for the session whose FAR sends into the tunnel the graph's frames name")
		}
		time.Sleep(50 * time.Millisecond)
	}

	if len(report.Errors) != 1 || report.Errors[0].TEID != pathDownTEID {
		t.Fatalf("the report carries %v, want the session's own remote F-TEID %#x", report.Errors, pathDownTEID)
	}
	if report.Errors[0].Addr != netip.MustParseAddr("10.20.30.2") {
		t.Errorf("the report names %v, want the peer the FAR sends to", report.Errors[0].Addr)
	}

	ies := report.IEs()
	if len(ies) != 2 || ies[0].Type != ie.ReportType || !ies[0].HasERIR() || ies[0].HasUSAR() {
		t.Fatalf("the report's IEs are %v, want a Report Type with the ERIR bit and one Error Indication Report", ieTypes(ies))
	}
	inner, err := ies[1].ErrorIndicationReport()
	if err != nil || len(inner) != 1 {
		t.Fatalf("the Error Indication Report holds %v (%v), want one F-TEID", ieTypes(inner), err)
	}
	fteid, err := inner[0].FTEID()
	if err != nil {
		t.Fatalf("the F-TEID IE does not parse: %v", err)
	}
	if fteid.TEID != pathDownTEID || !fteid.IPv4Address.Equal(net.ParseIP("10.20.30.2")) {
		t.Errorf("the F-TEID is %#x at %v, want %#x at 10.20.30.2",
			fteid.TEID, fteid.IPv4Address, pathDownTEID)
	}

	// The daemon is shared with the lane's other tests, and each of them
	// allocates its session's ids from its own pool: a session left behind
	// would put two sessions on one action id, and the next test's deletion
	// would be refused for the rule this one still holds (the custom profile's
	// selector is where that shows first).
	if got := cause(t, c.Delete(message.NewSessionDeletionRequest(0, 0, seid, 2, 0))); got != ie.CauseRequestAccepted {
		t.Fatalf("the deletion answered cause %d", got)
	}
}
