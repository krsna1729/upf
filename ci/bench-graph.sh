#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# What the deployed graph carries on one worker core: the lab graph of
# deploy/session-path.yaml with one session programmed over N4 (as
# ci/n4-path.sh programs it), the two Sources offering packets, and the two
# directions' delivery counted over a window.
#
#   ci/bench-graph.sh                  # 3 rounds of 5 s
#   ROUNDS=5 SECONDS_RUN=10 ci/bench-graph.sh
#
# This is a composition number, not a peak: the packets come from BESS's own
# Source modules one per scheduler iteration, so it reports the graph's cost per
# packet on this host -- which is the figure the per-module costs in
# ci/bench-chain.sh compose into. For a NIC-bound number, the same graph on the
# bound ports with TRex is the measurement (docs/design.md's verification plan).
#
# Run it under the host's perf slot if other work matters; a lab run is fine for
# a shape, not for a claim.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
STAGE=${STAGE:-/home/krsna1729/Projects/bess/.scratch/wt/pkg/build/stage-fast/usr/local}
DPDK_LIB=${DPDK_LIB:-/home/krsna1729/Projects/bess/.scratch/wt/codecs/deps/dpdk-25.11.3/install/lib}
PLUG=${PLUG:-$ROOT/datapath/build}
GRAPH=${GRAPH:-$ROOT/deploy/session-path.yaml}
GO=${GO:-$(MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} mise which go 2>/dev/null || echo go)}

BESS_PORT=${BESS_PORT:-10518}
N4_PORT=${N4_PORT:-18807}
ROUNDS=${ROUNDS:-3}
SECONDS_RUN=${SECONDS_RUN:-5}
FTEID=${FTEID:-0x11223344}
UE=${UE:-10.45.0.2}
GNB=${GNB:-10.20.30.2}
N3=${N3:-192.0.2.1}

BESSD=$STAGE/bin/bessd
BESSCTL=$STAGE/bin/bessctl

[ -x "$BESSD" ] || { echo "bench-graph: no bessd at $BESSD (set STAGE)" >&2; exit 1; }
[ -f "$PLUG/libupf_datapath.so" ] || {
  echo "bench-graph: build the plugin first: (cd datapath && ninja -C build)" >&2
  exit 1
}

WORK=$(mktemp -d /tmp/upf-bench-graph-XXXXXX)
LOG=$WORK/bessd.log
DAEMON_PID=""
UPFD_PID=""
cleanup() {
  [ -n "$UPFD_PID" ] && kill "$UPFD_PID" 2>/dev/null || true
  [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null || true
  sleep 1
  [ -n "$UPFD_PID" ] && kill -9 "$UPFD_PID" 2>/dev/null || true
  [ -n "$DAEMON_PID" ] && kill -9 "$DAEMON_PID" 2>/dev/null || true
}
trap cleanup EXIT

(cd "$ROOT" && $GO build -o "$WORK/upfd" ./cmd/upfd && $GO build -o "$WORK/n4bench" ./cmd/n4bench)

export LD_LIBRARY_PATH=$STAGE/lib:$DPDK_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}

echo "upf:    $ROOT ($(cd "$ROOT" && env git rev-parse --short HEAD))"
echo "graph:  $GRAPH"
echo "rounds: $ROUNDS x $SECONDS_RUN s, one worker core"
echo "uptime: $(uptime | sed 's/.*load average/load average/')"

"$BESSD" -m 0 -skip_root_check -p "$BESS_PORT" -i "$WORK/bessd.pid" \
  -modules="$PLUG" -f >"$LOG" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 60); do "$BESSCTL" -s "127.0.0.1:$BESS_PORT" status >/dev/null 2>&1 && break; sleep 0.5; done
"$BESSCTL" -s "127.0.0.1:$BESS_PORT" status >/dev/null 2>&1 || {
  echo "bench-graph: the daemon did not come up; log follows" >&2; tail -20 "$LOG" >&2; exit 1; }
"$BESSCTL" -s "127.0.0.1:$BESS_PORT" apply "$GRAPH" >/dev/null
"$BESSCTL" -s "127.0.0.1:$BESS_PORT" resume >/dev/null

"$WORK/upfd" -n4 "127.0.0.1:$N4_PORT" -node-id 127.0.0.1 -bess "127.0.0.1:$BESS_PORT" \
  -n3-addr "$N3" -log-level warn >"$WORK/upfd.log" 2>&1 &
UPFD_PID=$!
for _ in $(seq 1 20); do
  "$BESSCTL" -s "127.0.0.1:$BESS_PORT" status >/dev/null 2>&1 && sleep 0.25 && break
done
"$WORK/n4bench" -upf "127.0.0.1:$N4_PORT" -mode establish -sessions 1 -workers 1 \
  -fteid "$FTEID" -ue-pool "$UE/32" -gnb "$GNB" -n3 "$N3" -timeout 5s >"$WORK/n4bench.txt" 2>&1 || {
  echo "bench-graph: the establish was refused; logs are $WORK" >&2
  tail -20 "$WORK/n4bench.txt" "$WORK/upfd.log" >&2
  exit 1
}

# pack(): the daemon's output-gate packet count for one module's gate. The
# metric line is name and labels with no space between them
# (bess_gate_packets_total{module="rt",gate="0",direction="out"} 7907), and the
# labels come in map order, so match the pieces rather than a field.
pack() { # pack <module> <gate>
  "$BESSCTL" -s "127.0.0.1:$BESS_PORT" metrics 2>/dev/null | awk -v m="$1" -v g="$2" '
    index($0, "bess_gate_packets_total{") && index($0, "module=\"" m "\"") &&
      index($0, "gate=\"" g "\"") && index($0, "direction=\"out\"") { print $NF }'
}

printf '\n%8s %12s %12s %12s %12s\n' round decapped_to_N6 metered_ul dl_to_N3 input_Mpps
for r in $(seq 1 "$ROUNDS"); do
  a0=$(pack dump_u 0); b0=$(pack rt 0); c0=$(pack dump_d 0)
  sleep "$SECONDS_RUN"
  a1=$(pack dump_u 0); b1=$(pack rt 0); c1=$(pack dump_d 0)
  awk -v r="$r" -v a0="$a0" -v a1="$a1" -v b0="$b0" -v b1="$b1" -v c0="$c0" -v c1="$c1" \
    -v s="$SECONDS_RUN" 'BEGIN { printf "%8s %12.3f %12.3f %12.3f %12.3f\n", r, (a1-a0)/s/1e6, (b1-b0)/s/1e6, (c1-c0)/s/1e6, ((a1-a0)+(c1-c0))/s/1e6 }'
done
echo
echo "columns: decapped_to_N6 = dump_u's output (the uplink after the decap, before the"
echo "         PDR); metered_ul = rt gate 0 (what reached N6 through the SMF's QER, so"
echo "         the session's MBR shapes it); dl_to_N3 = dump_d's output (the downlink"
echo "         through the PDR, action, meter and encap, unmetered in this session);"
echo "         input_Mpps = both chains' input per second, Mpps."
echo "== logs: $WORK (the daemon's log and graph dumps; kept only when this run"
echo "   failed -- the numbers are above)"

# The run's own files, not a result: a failed run keeps everything (the line
# above says where), a green one drops the logs and keeps the directory.
rm -f "$WORK"/*.log
