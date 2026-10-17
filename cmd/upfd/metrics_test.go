// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/krsna1729/upf/internal/session"
)

// fakePeer is an N4 node's association state, as the endpoint reads it: the
// handler only asks whether a CP function is associated and which.
type fakePeer struct {
	node       string
	addr       net.Addr
	associated bool
}

func (p fakePeer) Peer() (string, net.Addr, bool) { return p.node, p.addr, p.associated }

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestTheMetricsEndpointReportsTheNodesNumbers: the endpoint serves what the
// node measured -- the session layer's own counters, the reporting loop's, and
// whether a CP function is associated -- in the format a scraper reads.
func TestTheMetricsEndpointReportsTheNodesNumbers(t *testing.T) {
	compiler := session.New(reportConfig(), &fakeDataplane{}, discardLogger())
	resp := compiler.Establish(reportLoopEstablishment(1, 0x9101)).(*message.SessionEstablishmentResponse)
	if cause, err := resp.Cause.Cause(); err != nil || cause != ie.CauseRequestAccepted {
		t.Fatalf("the establishment answered cause %d (%v), want accepted", cause, err)
	}

	reports := &reportStats{}
	reports.sent.Add(2)
	reports.refused.Add(1)
	reports.held.Add(3)
	reports.dropped.Add(1)

	peer := fakePeer{node: "smf.example", addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8805}, associated: true}
	rec := httptest.NewRecorder()
	metricsHandler(compiler, peer, reports).ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 200 {
		t.Fatalf("the endpoint answered %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("the endpoint answers %q, want the Prometheus text format", ct)
	}

	body := rec.Body.String()
	for _, want := range []string{
		"upf_sessions 1\n",
		"upf_sessions_established_total 1\n",
		"upf_sessions_modified_total 0\n",
		"upf_sessions_refused_total 0\n",
		`upf_usage_reports_total{outcome="sent"} 2`,
		`upf_usage_reports_total{outcome="refused"} 1`,
		`upf_usage_reports_total{outcome="held"} 3`,
		`upf_usage_reports_total{outcome="dropped"} 1`,
		"upf_pfcp_associated 1\n",
		`upf_pfcp_peer_info{node_id="smf.example",address="127.0.0.1:8805"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the endpoint does not report %q; it reports:\n%s", want, body)
		}
	}

	// Every sample it writes is something it measured: no peer means no peer.
	rec = httptest.NewRecorder()
	metricsHandler(compiler, fakePeer{}, reports).ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body = rec.Body.String()
	if !strings.Contains(body, "upf_pfcp_associated 0\n") {
		t.Errorf("an unassociated node does not report 0; it reports:\n%s", body)
	}
	if strings.Contains(body, "upf_pfcp_peer_info{") {
		t.Errorf("an unassociated node reports a peer identity:\n%s", body)
	}

	// A run with no session layer (no -bess) reports zeros rather than
	// panicking: the endpoint is startable before a dataplane is.
	rec = httptest.NewRecorder()
	metricsHandler(nil, peer, reports).ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(rec.Body.String(), "upf_sessions 0\n") {
		t.Errorf("a node with no session layer reports something other than zero sessions:\n%s", rec.Body.String())
	}
}

// TestTheMetricsAddressIsBoundAtStartup: a -metrics that is not host:port, or
// whose port is taken, is a startup failure rather than a log line printed
// after "listening"; the address the endpoint reports is the listener's own, so
// :0 (any free port) is a real answer.
func TestTheMetricsAddressIsBoundAtStartup(t *testing.T) {
	srv, ln, err := metricsServer("127.0.0.1:0", metricsHandler(nil, fakePeer{}, &reportStats{}))
	if err != nil {
		t.Fatalf("127.0.0.1:0 was refused: %v", err)
	}
	defer ln.Close()
	if ln.Addr().String() == "127.0.0.1:0" {
		t.Error("the endpoint reports the address it was given, not the port it bound")
	}
	// The port is taken now, by that listener: a second one on it must fail
	// here rather than in a goroutine after the node has said it is listening.
	if _, _, err := metricsServer(ln.Addr().String(), metricsHandler(nil, fakePeer{}, &reportStats{})); err == nil {
		t.Error("a port already in use was accepted")
	}
	_ = srv
	// A missing port is not an address, and the empty flag is not reached here
	// (run() only builds a server when the flag is set) -- but an address
	// without one would listen somewhere the operator did not name.
	for _, bad := range []string{"127.0.0.1", ""} {
		if _, _, err := metricsServer(bad, metricsHandler(nil, fakePeer{}, &reportStats{})); err == nil {
			t.Errorf("%q was accepted as an address", bad)
		}
	}
}
