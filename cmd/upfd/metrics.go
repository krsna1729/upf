// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/krsna1729/upf/internal/session"
)

// reportStats is what the reporting loop counts: the reports it sent and what
// became of them. A report the SMF answers is sent; one it refuses is refused
// (a decision, so the loop does not try it again); one it leaves unanswered is
// held for a later attempt; and one the queue has no room for is dropped.
type reportStats struct {
	sent    atomic.Uint64
	refused atomic.Uint64
	held    atomic.Uint64
	dropped atomic.Uint64
}

// peerState is the part of the PFCP node the endpoint reports: whether a CP
// function is associated, and which.
type peerState interface {
	Peer() (nodeID string, addr net.Addr, associated bool)
}

// metricsHandler serves this node's own numbers in the Prometheus text format
// (one sample per line, name and labels then value), so an operator's scraper
// reads them from the node that measured them:
//
//	upf_sessions                       the sessions the session layer holds now
//	upf_sessions_{established,modified,deleted}_total
//	upf_sessions_refused_total         requests answered with a cause but accepted
//	upf_usage_reports_total{outcome}   sent, refused, held (no answer yet), dropped
//	upf_pfcp_associated                a CP function is associated (1) or not (0)
//	upf_pfcp_peer_info{node_id,address}  the associated CP function, if any
//
// A session is a cache of what the SMF asked for, so these are the SMF's own
// view of this node rather than the dataplane's; the usage a report carries is
// the graph's, and `ci/bench-n4.sh` measures the wire.
func metricsHandler(sessions *session.Compiler, pfcp peerState, reports *reportStats) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b strings.Builder
		stats := sessions.Stats()

		fmt.Fprintf(&b, "# HELP upf_sessions The PFCP sessions this node holds now.\n")
		fmt.Fprintf(&b, "# TYPE upf_sessions gauge\n")
		fmt.Fprintf(&b, "upf_sessions %d\n", stats.Sessions)
		fmt.Fprintf(&b, "# HELP upf_sessions_established_total Establishments that became a session.\n")
		fmt.Fprintf(&b, "# TYPE upf_sessions_established_total counter\n")
		fmt.Fprintf(&b, "upf_sessions_established_total %d\n", stats.Established)
		fmt.Fprintf(&b, "# HELP upf_sessions_modified_total Modifications applied.\n")
		fmt.Fprintf(&b, "# TYPE upf_sessions_modified_total counter\n")
		fmt.Fprintf(&b, "upf_sessions_modified_total %d\n", stats.Modified)
		fmt.Fprintf(&b, "# HELP upf_sessions_deleted_total Deletions applied.\n")
		fmt.Fprintf(&b, "# TYPE upf_sessions_deleted_total counter\n")
		fmt.Fprintf(&b, "upf_sessions_deleted_total %d\n", stats.Deleted)
		fmt.Fprintf(&b, "# HELP upf_sessions_refused_total Session requests answered with a cause other than accepted.\n")
		fmt.Fprintf(&b, "# TYPE upf_sessions_refused_total counter\n")
		fmt.Fprintf(&b, "upf_sessions_refused_total %d\n", stats.Refused)

		fmt.Fprintf(&b, "# HELP upf_usage_reports_total PFCP Session Report Requests by outcome.\n")
		fmt.Fprintf(&b, "# TYPE upf_usage_reports_total counter\n")
		fmt.Fprintf(&b, "upf_usage_reports_total{outcome=\"sent\"} %d\n", reports.sent.Load())
		fmt.Fprintf(&b, "upf_usage_reports_total{outcome=\"refused\"} %d\n", reports.refused.Load())
		fmt.Fprintf(&b, "upf_usage_reports_total{outcome=\"held\"} %d\n", reports.held.Load())
		fmt.Fprintf(&b, "upf_usage_reports_total{outcome=\"dropped\"} %d\n", reports.dropped.Load())

		node, addr, associated := pfcp.Peer()
		fmt.Fprintf(&b, "# HELP upf_pfcp_associated A CP function is associated with this node.\n")
		fmt.Fprintf(&b, "# TYPE upf_pfcp_associated gauge\n")
		if associated {
			fmt.Fprintf(&b, "upf_pfcp_associated 1\n")
		} else {
			fmt.Fprintf(&b, "upf_pfcp_associated 0\n")
		}
		// An info metric: the identity is a label, and the value is always 1
		// (a peer that is not associated has none to report).
		fmt.Fprintf(&b, "# HELP upf_pfcp_peer_info The associated CP function.\n")
		fmt.Fprintf(&b, "# TYPE upf_pfcp_peer_info gauge\n")
		if associated {
			fmt.Fprintf(&b, "upf_pfcp_peer_info{node_id=%q,address=%q} 1\n", node, addr.String())
		}

		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		if _, err := w.Write([]byte(b.String())); err != nil {
			// The client went away mid-answer: nothing to do about it here,
			// and nothing the endpoint's own numbers should count.
			_ = err
		}
	})
}

// metricsServer binds the endpoint on addr and returns it with its listener: a
// port that is already in use is a startup failure rather than a log line after
// "listening" has been printed, and the listener's own address is what the log
// reports, so `:0` (any free port) is a real answer.
func metricsServer(addr string, handler http.Handler) (*http.Server, net.Listener, error) {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return nil, nil, fmt.Errorf("-metrics %q: %w", addr, err)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("-metrics: %w", err)
	}
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}, ln, nil
}
