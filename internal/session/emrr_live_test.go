// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/bess"
)

// TestLiveEndMarkerBecomesAnEMRRReport runs against the lane's daemon. The
// graph injects the old I-UPF's End Marker on the uplink F-TEID the session
// pins (pathUpTEID at 192.0.2.1, endpoint 1); decap sends it to gate 2, where
// echo_err records it, and the tick's drain_end_markers turns it into a Usage
// Report with EMRRE for the session's REEMR URR.
func TestLiveEndMarkerBecomesAnEMRRReport(t *testing.T) {
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
	cfg.GTPUEndMarkers = "echo_err"
	c := New(cfg, client, slog.New(slog.NewTextHandler(os.Stderr,
		&slog.HandlerOptions{Level: slog.LevelWarn})))

	resp := c.Establish(pathUrrEstablishment(0x7301, "10.45.0.20", ie.NewCreateURR(
		ie.NewURRID(7),
		ie.NewMeasurementMethod(0, 1, 0),          // VOLUM
		ie.NewReportingTriggers(0x00, 0x00, 0x01), // REEMR
	))).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	seid := upFSEID(t, resp)
	defer func() {
		if got := cause(t, c.Delete(message.NewSessionDeletionRequest(0, 0, seid, 2, 0))); got != ie.CauseRequestAccepted {
			t.Errorf("the deletion answered cause %d", got)
		}
	}()

	// The Source sends continuously, so a tick soon drains one that arrived
	// while the session held the F-TEID.
	deadline := time.Now().Add(10 * time.Second)
	var report Report
	for !report.EndMarker {
		for _, r := range c.EvaluateAll(ctx, time.Now()) {
			if r.SEID == seid && r.EndMarker {
				report = r
			}
		}
		if report.EndMarker {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no EMRRE Usage Report for the session whose F-TEID the graph's End Markers name")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if report.URRID != 7 {
		t.Fatalf("the report names URR %d, want the REEMR URR 7", report.URRID)
	}
	ies := report.IEs()
	inner, err := ies[len(ies)-1].UsageReport()
	if err != nil {
		t.Fatalf("the Usage Report does not parse: %v", err)
	}
	for _, i := range inner {
		if i.Type == ie.UsageReportTrigger && !i.HasEMRRE() {
			t.Fatalf("the Usage Report Trigger lacks EMRRE: %v", i.Payload)
		}
	}
}
