#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# The N4 envelope: what our own control plane does under load, measured by our
# own stand-in SMF (cmd/n4bench). Three numbers, each with the target it came
# from, because they answer different questions:
#
#   ci/bench-n4.sh                the whole control path: PFCP -> the session
#                                 compiler -> one control_v2 transaction into
#                                 bessd, per session change
#   MODE=n4 ci/bench-n4.sh        the N4 node alone (upfd with no session
#                                 layer): its ceiling, and its refusal rate
#   (the SDK alone is BESS's own tests/perf/live_transaction_bench, printed
#    here when it is built, since that is the third side of the triangle)
#
# Run it on a quiet machine. The numbers come from the two processes
# themselves, not from a wrapper that isolates CPUs, so anything else running
# (a build, a CI run in a container) is a variable in the result. The script
# records what it can see: the daemon's commit, the machine, and the load.
#
# Nothing here is left running: the daemon and upfd are killed by their own
# PIDs, and the script says so at the end.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BESS=${BESS:-$HOME/Projects/bess}
WT=${WT:-$BESS/.scratch/wt/pkg}
STAGE=${STAGE:-$WT/build/stage-fast/usr/local}
DPDK_LIB=${DPDK_LIB:-$WT/../../wt/codecs/deps/dpdk-25.11.3/install/lib}
PLUG=${PLUG:-$ROOT/datapath/build}
GRAPH=${GRAPH:-$ROOT/deploy/session-live.yaml}
LIVE_BENCH=${LIVE_BENCH:-$WT/../codecs/build/perf-release/tests/perf/live_transaction_bench}

MODE=${MODE:-full}                     # full | n4
SESSIONS=${SESSIONS:-512}
WORKERS=${WORKERS:-16}
MODES=${MODES:-"establish cycle bulk"}  # the n4bench phases to run
N4_PORT=${N4_PORT:-8805}
BESS_PORT=${BESS_PORT:-10514}
N3_ADDR=${N3_ADDR:-192.0.2.1}

BESSD=$STAGE/bin/bessd
BESSCTL=$STAGE/bin/bessctl
[ -x "$BESSD" ] || { echo "bench-n4: no bessd at $BESSD (set STAGE)" >&2; exit 1; }
[ -f "$PLUG/libupf_datapath.so" ] || {
  echo "bench-n4: build the plugin first: (cd datapath && ninja -C build)" >&2; exit 1; }

WORK=$(mktemp -d /tmp/upf-bench-n4-XXXXXX)
DAEMON_PID=""
UPFD_PID=""
cleanup() {
  for pid in "$UPFD_PID" "$DAEMON_PID"; do
    [ -n "$pid" ] || continue
    kill "$pid" 2>/dev/null || true
  done
  sleep 1
  for pid in "$UPFD_PID" "$DAEMON_PID"; do
    [ -n "$pid" ] || continue
    kill -9 "$pid" 2>/dev/null || true
  done
  pgrep -x bessd >/dev/null && echo "bench-n4: WARNING a bessd is still running" >&2
  pgrep -x upfd >/dev/null && echo "bench-n4: WARNING an upfd is still running" >&2
  # After the kills, not before them: the answer here is a fact, not a forecast.
  echo "== nothing left running: bessd $(pgrep -x bessd >/dev/null && echo RUNNING || echo stopped), upfd $(pgrep -x upfd >/dev/null && echo RUNNING || echo stopped)"
}
trap cleanup EXIT

echo "== environment"
echo "upf:    $ROOT ($(env git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo untracked))"
echo "stage:  $STAGE"
[ -x "$BESSD" ] && echo "bessd:  $("$BESSD" --version 2>/dev/null | head -1 || echo unknown) (bess $(env git -C "$WT" rev-parse --short HEAD 2>/dev/null || echo untracked))"
echo "n4:     $MODE, sessions $SESSIONS, workers $WORKERS, mode: $MODES"
echo "uptime: $(uptime | sed 's/.*load average/load average/')"

echo "== build the two tools"
# mise resolves the toolchain from this directory; ask it once for the binary
# and call that, so a shim without a configured version cannot be reached.
GO=$(MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} mise which go 2>/dev/null || echo go)
(cd "$ROOT" && "$GO" build -o "$WORK/n4bench" ./cmd/n4bench && \
  "$GO" build -o "$WORK/upfd" ./cmd/upfd)
echo "n4bench: $WORK/n4bench, upfd: $WORK/upfd"

export LD_LIBRARY_PATH=$STAGE/lib:$DPDK_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}

UPFD_ARGS=(-n4 "127.0.0.1:$N4_PORT" -node-id 127.0.0.1 -log-level warn)
if [ "$MODE" = full ]; then
  echo "== the datapath: bessd with the plugin, then the graph"
  "$BESSD" -m 0 -skip_root_check -p "$BESS_PORT" -i "$WORK/bessd.pid" \
    -modules="$PLUG" -f >"$WORK/bessd.log" 2>&1 &
  DAEMON_PID=$!
  for _ in $(seq 1 60); do "$BESSCTL" -s "127.0.0.1:$BESS_PORT" status >/dev/null 2>&1 && break; sleep 0.5; done
  "$BESSCTL" -s "127.0.0.1:$BESS_PORT" status >/dev/null 2>&1 || {
    echo "bench-n4: the daemon did not come up; log follows" >&2; tail -20 "$WORK/bessd.log" >&2; exit 1; }
  "$BESSCTL" -s "127.0.0.1:$BESS_PORT" apply "$GRAPH" >/dev/null || {
    echo "bench-n4: the graph did not apply" >&2; exit 1; }
  echo "bessd up ($DAEMON_PID), graph $GRAPH applied"
  UPFD_ARGS+=(-bess "127.0.0.1:$BESS_PORT" -n3-addr "$N3_ADDR"
    -pdr-table-ul pdr_ul -pdr-table-dl pdr_dl -teid-table teid -teid-gate 0
    -actions-ul at_ul -meters-ul mt_ul -actions-dl at_dl -meters-dl mt_dl -tunnels enc)
else
  echo "== N4 only: no -bess, so session messages are refused (cause 64): the"
  echo "   numbers below are the node's ceiling on that path"
fi

"$WORK/upfd" "${UPFD_ARGS[@]}" >"$WORK/upfd.log" 2>&1 &
UPFD_PID=$!
sleep 0.5
kill -0 "$UPFD_PID" 2>/dev/null || { echo "bench-n4: upfd exited; log follows" >&2; cat "$WORK/upfd.log" >&2; exit 1; }

# One invocation, one association: PFCP has a single association per peer, so a
# second process gets cause 64 rather than joining the first. The modes are
# alternatives, not a sequence -- cycle is establish+modify+delete in one run.
echo
"$WORK/n4bench" -upf "127.0.0.1:$N4_PORT" -mode "$MODES" -timeout "${N4_TIMEOUT:-5s}" \
  -sessions "$SESSIONS" -workers "$WORKERS" -json "$WORK/n4bench-$MODES.json"
echo

if [ -x "$LIVE_BENCH" ]; then
  echo "== the SDK side of the triangle (BESS's live_transaction_bench)"
  "$LIVE_BENCH" --build current --rounds 3 2>/dev/null | tail -6 || \
    echo "(live_transaction_bench needs a bessd of its own; run it separately)"
fi

echo "== logs: $WORK (bessd.log, upfd.log, n4bench-*.json)"
