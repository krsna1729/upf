#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# The reporting path end to end: a stand-in SMF establishes a session with a URR
# over PFCP into upfd, upfd's reporting loop reads the graph's usage counters,
# and the Session Report Request it owes the SMF leaves the node -- with the
# SMF's acknowledgement arriving back at upfd, which is what its log then
# records. The quota the session asked for is spent by the lab graph's own
# traffic, so the report is a real one: the packets the frames carried, counted
# by the datapath module, carried over N4.
#
#   ci/session-report.sh
#   STAGE=/some/prefix ci/session-report.sh
#
# The plugin must be built first (see README.md); the script uses
# datapath/build/libupf_datapath.so unless PLUG says otherwise. The daemon is
# started with no hugepages (-m 0) and never left running; run it under the
# host's daemon slot if one is in use.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
STAGE=${STAGE:-/home/krsna1729/Projects/bess/build/stage-fast/usr/local}
DPDK_LIB=${DPDK_LIB:-/home/krsna1729/Projects/bess/deps/dpdk-25.11.3/install/lib}
PLUG=${PLUG:-$ROOT/datapath/build}
GRAPH=${GRAPH:-$ROOT/deploy/session-path.yaml}
GO=${GO:-$(MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} mise which go 2>/dev/null || echo go)}

BESS_PORT=${BESS_PORT:-10517}
N4_PORT=${N4_PORT:-18806}
TICK=${TICK:-1s}
BESSD=$STAGE/bin/bessd
BESSCTL=$STAGE/bin/bessctl

[ -x "$BESSD" ] || { echo "session-report: no bessd at $BESSD (set STAGE)" >&2; exit 1; }
[ -x "$BESSCTL" ] || { echo "session-report: no bessctl at $BESSCTL (set STAGE)" >&2; exit 1; }
[ -f "$PLUG/libupf_datapath.so" ] || {
  echo "session-report: build the plugin first: (cd datapath && ninja -C build)" >&2
  exit 1
}

WORK=$(mktemp -d /tmp/upf-session-report-XXXXXX)
LOG=$WORK/bessd.log
UPFD_LOG=$WORK/upfd.log
DAEMON_PID=""
UPFD_PID=""
cleanup() {
  [ -n "$UPFD_PID" ] && kill "$UPFD_PID" 2>/dev/null || true
  if [ -n "$DAEMON_PID" ]; then
    kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  echo "session-report: logs in $WORK (bessd.log, upfd.log)"
}
trap cleanup EXIT

(cd "$ROOT" && $GO build -o "$WORK/upfd" ./cmd/upfd)

export LD_LIBRARY_PATH=$STAGE/lib:$DPDK_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}

"$BESSD" -m 0 -skip_root_check -p "$BESS_PORT" -i "$WORK/bessd.pid" \
  -modules="$PLUG" -f >"$LOG" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 60); do
  "$BESSCTL" -s "127.0.0.1:$BESS_PORT" status >/dev/null 2>&1 && break
  sleep 0.5
done
if ! "$BESSCTL" -s "127.0.0.1:$BESS_PORT" status >/dev/null 2>&1; then
  echo "session-report: the daemon did not come up; log follows" >&2
  tail -30 "$LOG" >&2
  exit 1
fi
"$BESSCTL" -s "127.0.0.1:$BESS_PORT" apply "$GRAPH" >/dev/null
"$BESSCTL" -s "127.0.0.1:$BESS_PORT" resume >/dev/null

# The controller with its reporting loop on: the graph's chain names its
# defaults, and the tick is short enough that a test's quota is spent inside a
# couple of them.
"$WORK/upfd" -n4 "127.0.0.1:$N4_PORT" -node-id 127.0.0.1 -bess "127.0.0.1:$BESS_PORT" \
  -n3-addr 192.0.2.1 -urr-interval "$TICK" -log-level info >"$UPFD_LOG" 2>&1 &
UPFD_PID=$!
for _ in $(seq 1 20); do
  grep -q "n4 listening" "$UPFD_LOG" && break
  sleep 0.5
done
kill -0 "$UPFD_PID" 2>/dev/null || {
  echo "session-report: upfd exited; log follows" >&2
  cat "$UPFD_LOG" >&2
  exit 1
}

# The SMF's half: it establishes the measured session, receives the report and
# answers it -- the answer is the acknowledgement the controller logs.
MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} UPF_N4_TARGET=127.0.0.1:$N4_PORT \
  $GO test "$ROOT/internal/n4/" -run 'TestLiveUsageReportReachesTheSMF' -count=1 -v || {
  echo "session-report: the reporting test failed; upfd's log follows" >&2
  cat "$UPFD_LOG" >&2
  exit 1
}

FAIL=0
check() { # check <description> <the line the log must carry>
  if grep -q "$2" "$UPFD_LOG"; then
    echo "ok: $1"
  else
    echo "FAIL: $1 (no '$2' in the controller's log)" >&2
    FAIL=1
  fi
}
check "the controller sent a usage report" "usage report acknowledged"
check "the report said the quota is spent" "quota spent: the session's traffic is stopped"
check "the session's report named the URR" "urr=7"

if [ "$FAIL" = 0 ]; then
  echo "session-report: ok (the usage report left the node and the SMF acknowledged it)"
fi
exit "$FAIL"
