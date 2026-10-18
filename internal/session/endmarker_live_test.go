// SPDX-License-Identifier: BSD-3-Clause

package session

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/bess"
)

// endMarkerSocket is the graph's unix_port (deploy/session-path.yaml): the
// socket an End Marker packet is written to, and the same path a deployment
// gives upfd -end-marker. A lane that renders its own path (ci/session-path.sh
// does, so two daemons on one host do not take the socket from each other --
// BESS unlinks a path when it binds) names it in UPF_END_MARKER_SOCK.
func endMarkerSocket() string {
	if p := os.Getenv("UPF_END_MARKER_SOCK"); p != "" {
		return p
	}
	return "/tmp/upf-end-marker.sock"
}

// TestLiveSessionSendsTheEndMarkerOnSNDEM drives a handover against a real
// bessd: the SMF moves the downlink FAR's F-TEID with the SNDEM flag, and the
// marker this UPF constructs leaves through the graph's unix_port, whose
// PortInc ci/session-path.sh's daemon dumps. The frame names the OLD tunnel --
// the TEID and the peer the session was using until the modification landed.
//
// The daemon takes the packet or it does not: a graph without the port, or a
// frame the port refuses, is a counted failure here and a missing dump line in
// the arm.
func TestLiveSessionSendsTheEndMarkerOnSNDEM(t *testing.T) {
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
	cfg.EndMarker = endMarkerSocket()
	c := New(cfg, client, slog.New(slog.NewTextHandler(os.Stderr,
		&slog.HandlerOptions{Level: slog.LevelWarn})))

	resp := c.Establish(establishment(0x7101, "10.45.0.20")).(*message.SessionEstablishmentResponse)
	if got := cause(t, resp); got != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d", got)
	}
	seid := upFSEID(t, resp)

	// The handover: the downlink FAR moves to another gNB tunnel, and the
	// message asks for an End Marker.
	mod := message.NewSessionModificationRequest(0, 0, seid, 2, 0,
		ie.NewPFCPSMReqFlags(0x02),
		ie.NewUpdateFAR(ie.NewFARID(2),
			ie.NewUpdateForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceAccess),
				ie.NewOuterHeaderCreation(0x0100, 0xaabbccdd, "10.20.30.9", "", 0, 0, 0))))
	if got := cause(t, c.Modify(mod)); got != ie.CauseRequestAccepted {
		t.Fatalf("the modification answered cause %d", got)
	}
	if stats := c.Stats(); stats.Markers != 1 || stats.MarkerFailures != 0 {
		t.Fatalf("markers sent %d, failed %d, want 1 and 0", stats.Markers, stats.MarkerFailures)
	}
	// (The frame itself is checked where it lands: ci/session-path.sh greps the
	// daemon's dump of the port for the old TEID and the old peer.)

	if got := cause(t, c.Delete(message.NewSessionDeletionRequest(0, 0, seid, 3, 0))); got != ie.CauseRequestAccepted {
		t.Fatalf("the deletion answered cause %d", got)
	}
}
