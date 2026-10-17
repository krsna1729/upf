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
# The plugin must be built first (see README.md); the script uses
# datapath/build/libupf_datapath.so unless PLUG says otherwise. The daemon is
# started with no hugepages (-m 0) and never left running; run it under the
# host's daemon slot if one is in use.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
STAGE=${STAGE:-/home/krsna1729/Projects/bess/build/stage-fast/usr/local}
DPDK_LIB=${DPDK_LIB:-/home/krsna1729/Projects/bess/deps/dpdk-25.11.3/install/lib}
PLUG=${PLUG:-$ROOT/datapath/build}
GRAPH=${GRAPH:-$ROOT/deploy/buffer-path.yaml}
GO=${GO:-$(MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} mise which go 2>/dev/null || echo go)}

BESS_PORT=${BESS_PORT:-10518}
N4_PORT=${N4_PORT:-18807}
TICK=${TICK:-1s}
BESSD=$STAGE/bin/bessd
BESSCTL=$STAGE/bin/bessctl

WORK=$(mktemp -d /tmp/upf-buffer-XXXXXX)
LOG=$WORK/bessd.log
UPFD_LOG=$WORK/upfd.log
UPFD_PID=

cleanup() {
  [ -n "$UPFD_PID" ] && kill "$UPFD_PID" 2>/dev/null || true
  "$BESSCTL" -s "127.0.0.1:$BESS_PORT" kill 2>/dev/null || true
  rm -rf "$WORK"
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
  grep -q "n4 listening" "$UPFD_LOG" && break
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

# The datapath's half, against the same daemon: held, reported once, released.
MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} UPF_BESS_TARGET=127.0.0.1:$BESS_PORT \
  $GO test "$ROOT/internal/session/" -run 'TestLiveSessionBuffersAndReleasesTheHeldPackets' -count=1 -v || {
  echo "buffer-path: the buffering test failed; upfd's log follows" >&2
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
check "the controller reported the buffered downlink" "downlink data reported"
check "the report named the buffering PDR" "pdrs=[2]"
check "the store released the flow on the SMF's instruction" "buffer_flows_total{outcome=\"released\"} 1"

if [ "$FAIL" = 0 ]; then
  echo "buffer-path: ok (a BUFF FAR's packets were held, reported to the SMF over N4, and released when the SMF moved the path)"
fi
exit "$FAIL"
