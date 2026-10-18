#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# The buffering path end to end: a stand-in SMF establishes a session whose
# downlink FAR asks for the packets to be held (Apply Action BUFF without FORW,
# TS 29.244 8.2.26) and provisions the BAR that goes with it; the graph's own
# source keeps sending, so a real daemon holds a real flow's first packet.
# upfd's reporting tick reads the counter in front of the store and owes the SMF
# a Session Report Request with a Downlink Data Report naming the PDR (5.2.4.1),
# and the instruction that moves the path releases what was held, into the action
# path the same request wrote.
#
#   ci/buffer-path.sh
#   STAGE=/some/prefix ci/buffer-path.sh
#
# This arm needs a bessd built with BESS's key_attrs change (packet_store.c,
# commit 128fd237): the store's flow key is what makes one flow one rule, and a
# daemon without it refuses deploy/buffer-path.yaml rather than keying every flow
# at 0. The other arms' graphs are unchanged, so they keep running on a stage
# without it -- this script exists so that upgrade is not a cliff.
#
# It also needs the store's bounded sweep (BESS 0bfd2783, the amendment to
# D-129): `EvictExpiredBounded` frees a flow's packets once they pass its
# per-flow timeout, 256 flows a run. An older daemon checks the timeout only
# when the store reaches its global max_packets, which this graph never does at
# these flow counts, so the held packets would stay where they are and the last
# check below would fail -- not because the SMF's numbers are not in the store,
# but because nothing frees on them.
#
# The plugin must be built first (see README.md); the script uses
# datapath/build/libupf_datapath.so unless PLUG says otherwise. The daemon is
# started with no hugepages (-m 0) and never left running; run it under the
# host's daemon slot if one is in use.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/ci/bess-env.sh"
PLUG=${PLUG:-$ROOT/datapath/build}
GRAPH=${GRAPH:-$ROOT/deploy/buffer-path.yaml}
GO=${GO:-$(MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} mise which go 2>/dev/null || echo go)}

TICK=${TICK:-1s}
BESSD=$STAGE/bin/bessd
BESSCTL=$STAGE/bin/bessctl

WORK=$(mktemp -d /tmp/upf-buffer-XXXXXX)
LOG=$WORK/bessd.log
UPFD_LOG=$WORK/upfd.log
UPFD_PID=
BESSD_PID=

# stop_bessd ends the daemon this script started, and only then is the run
# over: the pid is the daemon's own (it runs in the foreground, -f, so $! is
# it), the pidfile is the fallback when the shell lost it, and the RPC is the
# last resort for a daemon that outlived both. SIGTERM, then a moment, then
# SIGKILL -- a daemon this script leaves behind holds the port and the
# hugepage-free memory node the next run needs.
stop_bessd() {
  [ -n "$BESSD_PID" ] && kill "$BESSD_PID" 2>/dev/null || true
  if [ -n "$BESSD_PID" ]; then
    for _ in $(seq 1 50); do
      kill -0 "$BESSD_PID" 2>/dev/null || break
      sleep 0.1
    done
    kill -9 "$BESSD_PID" 2>/dev/null || true
  fi
  # A daemon whose pid this shell no longer has -- one from an earlier run on
  # this port -- still answers: `shutdown` is bessctl's own stop (there is no
  # `kill` command), and the daemon unlinks its pidfile as it goes.
  if "$BESSCTL" -s "127.0.0.1:$BESS_PORT" status >/dev/null 2>&1; then
    "$BESSCTL" -s "127.0.0.1:$BESS_PORT" shutdown >/dev/null 2>&1 || true
  fi
  if [ -f "$WORK/bessd.pid" ]; then
    # The pid file carries a trailing NUL, so it is stripped rather than read
    # raw: $(cat …) warned "ignored null byte in input" and handed kill a
    # string with the NUL dropped only by luck.
    kill -9 "$(tr -d '\000' <"$WORK/bessd.pid")" 2>/dev/null || true
  fi
}

cleanup() {
  local status=$?
  [ -n "$UPFD_PID" ] && kill "$UPFD_PID" 2>/dev/null || true
  stop_bessd
  if [ "$status" = 0 ]; then
    rm -rf "$WORK"
  else
    # A failed run keeps what it left: the daemon's log is where the refusal
    # is, and the controller's is where its own account of it is.
    echo "buffer-path: exit $status; the daemon's log is $LOG and the controller's is $UPFD_LOG" >&2
  fi
  exit "$status"
}
trap cleanup EXIT

[ -x "$BESSD" ] || { echo "buffer-path: no bessd at $BESSD (set STAGE)" >&2; exit 1; }
[ -x "$BESSCTL" ] || { echo "buffer-path: no bessctl at $BESSCTL (set STAGE)" >&2; exit 1; }
[ -f "$PLUG/libupf_datapath.so" ] || {
  echo "buffer-path: build the plugin first: (cd datapath && ninja -C build)" >&2
  exit 1
}

export LD_LIBRARY_PATH=$STAGE/lib:$DPDK_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}

"$BESSD" -m 0 -skip_root_check -p "$BESS_PORT" -i "$WORK/bessd.pid" \
  -modules="$PLUG" -f >"$LOG" 2>&1 &
BESSD_PID=$!
for _ in $(seq 1 60); do
  "$BESSCTL" -s "127.0.0.1:$BESS_PORT" status >/dev/null 2>&1 && break
  sleep 0.5
done
if ! "$BESSCTL" -s "127.0.0.1:$BESS_PORT" status >/dev/null 2>&1; then
  echo "buffer-path: the daemon did not come up; log follows" >&2
  tail -30 "$LOG" >&2
  exit 1
fi
"$BESSCTL" -s "127.0.0.1:$BESS_PORT" apply "$GRAPH" >/dev/null || {
  echo "buffer-path: the graph did not apply -- a bessd without packet_store key_attrs (commit 128fd237) refuses it; log follows" >&2
  tail -20 "$LOG" >&2
  exit 1
}
"$BESSCTL" -s "127.0.0.1:$BESS_PORT" resume >/dev/null

(cd "$ROOT" && $GO build -o "$WORK/upfd" ./cmd/upfd)
"$WORK/upfd" -n4 "127.0.0.1:$N4_PORT" -node-id 127.0.0.1 -bess "127.0.0.1:$BESS_PORT" \
  -n3-addr 192.0.2.1 -urr-interval "$TICK" \
  -buffer-store buf -buffer-counter cnt_buf -buffer-gate 1 -log-level info >"$UPFD_LOG" 2>&1 &
UPFD_PID=$!
for _ in $(seq 1 20); do
  grep -q -F -- "n4 listening" "$UPFD_LOG" && break
  sleep 0.5
done
kill -0 "$UPFD_PID" 2>/dev/null || {
  echo "buffer-path: upfd exited; log follows" >&2
  cat "$UPFD_LOG" >&2
  exit 1
}

# The SMF's half: the DDN over N4, with this test as the SMF.
MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} UPF_N4_TARGET=127.0.0.1:$N4_PORT \
  $GO test "$ROOT/internal/n4/" -run 'TestLiveDownlinkReportReachesTheSMF' -count=1 -v || {
  echo "buffer-path: the downlink report test failed; upfd's log follows" >&2
  cat "$UPFD_LOG" >&2
  exit 1
}

# The datapath's half, against the same daemon: held, reported once, released --
# and, in the sibling case, freed by the store's own timeout before the SMF's
# instruction arrives, so that instruction releases nothing. Both tests' output
# goes through tee: each case's evidence is the line the checks below match, and
# the numbers in those lines are this arm's own proof, so they are left on this
# script's stdout rather than only in the file. The tests build their own
# controller (New(cfg, client, log)), so upfd is not the one releasing.
MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} UPF_BESS_TARGET=127.0.0.1:$BESS_PORT \
  $GO test "$ROOT/internal/session/" -count=1 -v \
  -run 'TestLiveSession(BuffersAndReleasesTheHeldPackets|HoldsNothingAfterTheBufferingDurationPasses)' \
  2>&1 | tee "$WORK/session-test.log" || {
  echo "buffer-path: the buffering tests failed (their output is above); upfd's log follows" >&2
  cat "$UPFD_LOG" >&2
  exit 1
}

FAIL=0
check() { # check <description> <the line the file must carry> <file>
  # The description is the test; the line is a fixed string, matched as one
  # (-F --): an unquoted bracket in it is a bracket expression to grep, so
  # "pdrs=[2]" would match the "pdrs=2" of every establishment.
  if grep -q -F -- "$2" "$3"; then
    echo "ok: $1"
  else
    echo "FAIL: $1 (no '$2' in $3)" >&2
    FAIL=1
  fi
}
check "the controller reported the buffered downlink" "downlink data reported" "$UPFD_LOG"
check "the report named the buffering PDR" "pdrs=[2]" "$UPFD_LOG"
# Not upfd's counter: upf_buffer_flows_total is served over HTTP and never
# logged, and this arm's upfd never drives a release -- the n4 test above
# deletes its session without one. The evidence is the session tests' own lines:
# the branch's counter held the packets, and the encap's moved only after the
# SMF's instruction. Where upfd itself releases a flow, its counter is what to
# scrape; that belongs to an arm that drives the release through PFCP.
check "the store released the flow on the SMF's instruction" "forwarded after the instruction:" "$WORK/session-test.log"
# The expiry case's own line: the packets were freed by the store's sweep at the
# BAR's short timeout_ns before the instruction arrived, so the release moved
# nothing. The number after the arrow is the same count as before it -- an
# absence, which is all a silent free can leave.
check "the store freed the flow at the BAR's own duration" "forwarded after the wait:" "$WORK/session-test.log"

check_clean_shutdown "$BESSD_PID" || FAIL=1
if [ "$FAIL" = 0 ]; then
  echo "buffer-path: ok (a BUFF FAR's packets were held, reported to the SMF over N4, released when the SMF moved the path, and freed by the store's own timeout when the BAR's duration ran out)"
fi
exit "$FAIL"
