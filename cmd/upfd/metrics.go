// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"net"
	"net/http"
	"runtime/metrics"
	"strings"
	"sync/atomic"
	"time"

	"github.com/krsna1729/upf/internal/bess"
	"github.com/krsna1729/upf/internal/session"
)

// reportStats is what the reporting loop counts: the reports it sent and what
// became of them. A report the SMF answers is sent; one it refuses is refused
// (a decision, so the loop does not try it again); one it leaves unanswered is
// held for a later attempt; one the queue has no room for is dropped; and one
// whose session ended while it waited is cancelled (its usage went in the
// session's termination report instead).
type reportStats struct {
	sent      atomic.Uint64
	refused   atomic.Uint64
	held      atomic.Uint64
	dropped   atomic.Uint64
	cancelled atomic.Uint64
	// The downlink half: the reports that told the SMF about packets being
	// held, and the ones it would not take (offered again on the next tick).
	ddnSent   atomic.Uint64
	ddnFailed atomic.Uint64
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
//	upf_sessions_unadmitted_total      establishments refused before dataplane work (capacity or heap room; also refused)
//	upf_heap_admission_closed          1 while -heap-admission refuses new sessions, else 0
//	upf_heap_admission_refused_total   establishments refused for heap room alone
//	upf_go_heap_live_bytes             the heap the last collection kept live
//	upf_go_memory_limit_bytes          the Go memory limit the heap is held under, when there is one
//	upf_end_markers_total{outcome}     End Markers sent, or failed (the graph's port took none)
//	upf_buffer_flows_total{outcome}    release/drop commands accepted, or refused (accepted, not completed)
//	upf_usage_reports_total{outcome}   sent, refused, held (no answer yet), dropped, cancelled (the session ended first)
//	upf_pfcp_associated                a CP function is associated (1) or not (0)
//	upf_pfcp_peer_info{node_id,address}  the associated CP function, if any
//	upf_bess_channel_frames_total      transaction channel frames bessd acknowledged (with -bess)
//	upf_bess_channel_transactions_total  transaction results those frames carried (with -bess)
//
// A session is a cache of what the SMF asked for, so these are the SMF's own
// view of this node rather than the dataplane's; the usage a report carries is
// the graph's, and `ci/bench-n4.sh` measures the wire.
func metricsHandler(sessions *session.Compiler, pfcp peerState, reports *reportStats, heap *heapGauge,
	admission *heapAdmissionRecovery, bessFrames func() bess.FrameStats) http.Handler {
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
		fmt.Fprintf(&b, "# HELP upf_sessions_unadmitted_total Establishments refused before dataplane work by hard session capacity or -heap-admission; also counted in upf_sessions_refused_total.\n")
		fmt.Fprintf(&b, "# TYPE upf_sessions_unadmitted_total counter\n")
		fmt.Fprintf(&b, "upf_sessions_unadmitted_total %d\n", stats.Unadmitted)
		fmt.Fprintf(&b, "# HELP upf_session_capacity Hard bound on established plus reserved sessions.\n")
		fmt.Fprintf(&b, "# TYPE upf_session_capacity gauge\n")
		fmt.Fprintf(&b, "upf_session_capacity %d\n", stats.SessionCapacity)
		fmt.Fprintf(&b, "# HELP upf_sessions_reserved In-flight or uncertain establishments not included in upf_sessions.\n")
		fmt.Fprintf(&b, "# TYPE upf_sessions_reserved gauge\n")
		fmt.Fprintf(&b, "upf_sessions_reserved %d\n", stats.ReservedSessions)
		if admission != nil {
			closed := 0
			if admission.closedGauge.Load() {
				closed = 1
			}
			fmt.Fprintf(&b, "# HELP upf_heap_admission_closed 1 while -heap-admission refuses new sessions (estimated live heap past its share), else 0.\n")
			fmt.Fprintf(&b, "# TYPE upf_heap_admission_closed gauge\n")
			fmt.Fprintf(&b, "upf_heap_admission_closed %d\n", closed)
			fmt.Fprintf(&b, "# HELP upf_heap_admission_refused_total Establishments refused for heap room alone; also counted in upf_sessions_unadmitted_total.\n")
			fmt.Fprintf(&b, "# TYPE upf_heap_admission_refused_total counter\n")
			fmt.Fprintf(&b, "upf_heap_admission_refused_total %d\n", admission.refusals.Load())
		}
		hr := heap.read()
		live, limit := hr.live, hr.limit
		fmt.Fprintf(&b, "# HELP upf_go_heap_live_bytes The heap the last garbage collection kept live.\n")
		fmt.Fprintf(&b, "# TYPE upf_go_heap_live_bytes gauge\n")
		fmt.Fprintf(&b, "upf_go_heap_live_bytes %d\n", live)
		fmt.Fprintf(&b, "# HELP upf_go_memory_limit_bytes Soft Go runtime memory target; not an RSS or cgroup ceiling.\n")
		fmt.Fprintf(&b, "# TYPE upf_go_memory_limit_bytes gauge\n")
		if limit > 0 {
			fmt.Fprintf(&b, "upf_go_memory_limit_bytes %d\n", limit)
		}
		// Cumulative CPU includes concurrent collection and allocating-goroutine
		// assists; short stop-the-world pauses alone do not measure this cost.
		gc := [...]metrics.Sample{
			{Name: "/cpu/classes/gc/mark/assist:cpu-seconds"},
			{Name: "/cpu/classes/gc/total:cpu-seconds"},
			{Name: "/gc/heap/allocs:bytes"},
		}
		metrics.Read(gc[:])
		fmt.Fprintf(&b, "# HELP upf_go_gc_assist_cpu_seconds_total CPU seconds spent by allocating goroutines assisting GC.\n")
		fmt.Fprintf(&b, "# TYPE upf_go_gc_assist_cpu_seconds_total counter\n")
		fmt.Fprintf(&b, "upf_go_gc_assist_cpu_seconds_total %g\n", gc[0].Value.Float64())
		fmt.Fprintf(&b, "# HELP upf_go_gc_cpu_seconds_total CPU seconds spent on all GC work, not only pauses.\n")
		fmt.Fprintf(&b, "# TYPE upf_go_gc_cpu_seconds_total counter\n")
		fmt.Fprintf(&b, "upf_go_gc_cpu_seconds_total %g\n", gc[1].Value.Float64())
		fmt.Fprintf(&b, "# HELP upf_go_heap_allocated_bytes_total Cumulative Go heap allocation bytes.\n")
		fmt.Fprintf(&b, "# TYPE upf_go_heap_allocated_bytes_total counter\n")
		fmt.Fprintf(&b, "upf_go_heap_allocated_bytes_total %d\n", gc[2].Value.Uint64())
		fmt.Fprintf(&b, "# HELP upf_end_markers_total End Marker packets by outcome: sent, or refused by the graph's port.\n")
		fmt.Fprintf(&b, "# TYPE upf_end_markers_total counter\n")
		fmt.Fprintf(&b, "upf_end_markers_total{outcome=\"sent\"} %d\n", stats.Markers)
		fmt.Fprintf(&b, "upf_end_markers_total{outcome=\"failed\"} %d\n", stats.MarkerFailures)
		fmt.Fprintf(&b, "# HELP upf_buffer_flows_total Release and drop commands for buffering flows: accepted releases, accepted drops, and refusals. A command is counted when the daemon accepted it, not when the store applied it.\n")
		fmt.Fprintf(&b, "# TYPE upf_buffer_flows_total counter\n")
		fmt.Fprintf(&b, "upf_buffer_flows_total{outcome=\"released\"} %d\n", stats.BuffersReleased)
		fmt.Fprintf(&b, "upf_buffer_flows_total{outcome=\"dropped\"} %d\n", stats.BuffersDropped)
		fmt.Fprintf(&b, "upf_buffer_flows_total{outcome=\"failed\"} %d\n", stats.BufferFailures)

		fmt.Fprintf(&b, "# HELP upf_usage_reports_total PFCP Session Report Requests by outcome.\n")
		fmt.Fprintf(&b, "# TYPE upf_usage_reports_total counter\n")
		fmt.Fprintf(&b, "upf_usage_reports_total{outcome=\"sent\"} %d\n", reports.sent.Load())
		fmt.Fprintf(&b, "upf_usage_reports_total{outcome=\"refused\"} %d\n", reports.refused.Load())
		fmt.Fprintf(&b, "upf_usage_reports_total{outcome=\"held\"} %d\n", reports.held.Load())
		fmt.Fprintf(&b, "upf_usage_reports_total{outcome=\"dropped\"} %d\n", reports.dropped.Load())
		fmt.Fprintf(&b, "upf_usage_reports_total{outcome=\"cancelled\"} %d\n", reports.cancelled.Load())
		fmt.Fprintf(&b, "# HELP upf_downlink_reports_total Downlink Data Reports by outcome: delivered, or not taken (retried next tick).\n")
		fmt.Fprintf(&b, "# TYPE upf_downlink_reports_total counter\n")
		fmt.Fprintf(&b, "upf_downlink_reports_total{outcome=\"sent\"} %d\n", reports.ddnSent.Load())
		fmt.Fprintf(&b, "upf_downlink_reports_total{outcome=\"failed\"} %d\n", reports.ddnFailed.Load())
		if bessFrames != nil {
			// Transactions per frame is how many commits shared one gRPC
			// message to bessd, and so one per-message cost.
			frames := bessFrames()
			fmt.Fprintf(&b, "# HELP upf_bess_channel_frames_total Transaction channel frames bessd acknowledged.\n")
			fmt.Fprintf(&b, "# TYPE upf_bess_channel_frames_total counter\n")
			fmt.Fprintf(&b, "upf_bess_channel_frames_total %d\n", frames.Frames)
			fmt.Fprintf(&b, "# HELP upf_bess_channel_transactions_total Transaction results carried by acknowledged transaction channel frames.\n")
			fmt.Fprintf(&b, "# TYPE upf_bess_channel_transactions_total counter\n")
			fmt.Fprintf(&b, "upf_bess_channel_transactions_total %d\n", frames.Transactions)
		}

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
