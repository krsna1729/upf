#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# The two-instance arm: two sessions for one subscriber address, one per network
# instance, each taking its own instance's exit. The Go test programs them and
# reads the router's two output gates (the internet session's traffic leaves by
# gate 0, the ims session's by gate 2, its instance's next hop); this script
# checks that the graph's two G-PDUs carry the two tunnels those sessions'
# uplink rules are keyed on, in the daemon's Dump of them as they arrive.
#
# It is its own manifest (deploy/session-instances.yaml), not an extension of
# deploy/session-path.yaml: that graph's figures are recorded (docs/design.md's
# envelope, `ci/bench-graph.sh`), and adding a Source and a Merge hop to it would
# move a baseline no arm had measured.
#
#   ci/session-instances.sh                    # default stage: the main checkout's installed stage
#   STAGE=/some/prefix ci/session-instances.sh # any installed bess-dev prefix
#
# The plugin must be built first (see README.md); the script uses
# datapath/build/libupf_datapath.so unless PLUG says otherwise. The daemon is
# started with no hugepages (-m 0) and never left running; run it under the
# host's daemon slot if one is in use.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/ci/bess-env.sh"
PLUG=${PLUG:-$ROOT/datapath/build}
GRAPH=${GRAPH:-$ROOT/deploy/session-instances.yaml}
GO=${GO:-$(MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} mise which go 2>/dev/null || echo go)}
SECONDS_RUN=${SECONDS_RUN:-3}

BESSD=$STAGE/bin/bessd
BESSCTL=$STAGE/bin/bessctl
LOG=$(mktemp /tmp/upf-instances-XXXXXX.log)
PIDFILE=$(mktemp /tmp/upf-instances-XXXXXX.pid)

[ -x "$BESSD" ] || { echo "instances: no bessd at $BESSD (set STAGE)" >&2; exit 1; }
[ -x "$BESSCTL" ] || { echo "instances: no bessctl at $BESSCTL (set STAGE)" >&2; exit 1; }
[ -f "$PLUG/libupf_datapath.so" ] || {
  echo "instances: no plugin at $PLUG/libupf_datapath.so (build datapath/; see README.md)" >&2
  exit 1
}

export LD_LIBRARY_PATH=$STAGE/lib:$DPDK_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}

"$BESSD" -m 0 -skip_root_check -p "$BESS_PORT" -i "$PIDFILE" -modules="$PLUG" -f >"$LOG" 2>&1 &
DAEMON=$!
cleanup() {
  kill "$DAEMON" 2>/dev/null || true
  for _ in 1 2 3 4 5; do kill -0 "$DAEMON" 2>/dev/null || break; sleep 1; done
  kill -9 "$DAEMON" 2>/dev/null || true
  wait "$DAEMON" 2>/dev/null || true
  echo "instances: daemon log in $LOG"
}
trap cleanup EXIT

for _ in $(seq 1 30); do "$BESSCTL" -s "127.0.0.1:$BESS_PORT" status >/dev/null 2>&1 && break; sleep 1; done
if ! "$BESSCTL" -s "127.0.0.1:$BESS_PORT" status >/dev/null 2>&1; then
  echo "instances: the daemon never came up; log follows" >&2
  cat "$LOG" >&2
  exit 1
fi

"$BESSCTL" -s "127.0.0.1:$BESS_PORT" validate "$GRAPH" >/dev/null
"$BESSCTL" -s "127.0.0.1:$BESS_PORT" apply "$GRAPH" >/dev/null
"$BESSCTL" -s "127.0.0.1:$BESS_PORT" resume >/dev/null

# The Go half: two sessions for 10.45.0.2, one per instance, and the router's
# two exits counted. Run from the repository root so the module and its
# workspace resolve.
cd "$ROOT"
MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} UPF_BESS_TARGET=$SERVER \
  $GO test ./internal/session/ -run 'TestLiveTwoInstancesRouteIndependently' -count=1 -v

# The packet half: the G-PDUs' own bytes, per dump (the helper is shared with
# ci/session-path.sh; see its header for why a dump is scoped).
sleep "$SECONDS_RUN"
FAIL=0
. "$ROOT/ci/dumphex.sh"
TEID_HEX=$(dump_hex dump_t "$LOG")
check() { # check <description> <the dump's hex> <fixed string it must contain>
  if printf '%s\n' "$2" | grep -Fq -- "$3"; then
    echo "ok: $1"
  else
    echo "FAIL: $1 (no '$3' in that dump)" >&2
    FAIL=1
  fi
}

# Both tunnels are on the wire: the two sessions' F-TEIDs, in the G-PDUs the
# graph's two sources send. The dump is upstream of the TEID table, so this says
# what the sessions' uplink rules are keyed on, not where the packets go -- that
# is the Go half's two gate counts above.
check "the internet stream's G-PDU carries its tunnel" "$TEID_HEX" "11 22 33 44"
check "the ims stream's G-PDU carries its tunnel" "$TEID_HEX" "11 22 33 45"

check_clean_shutdown "$DAEMON" || FAIL=1
if [ "$FAIL" = 0 ]; then
  echo "instances: both tunnels are on the wire (the exits' counters are the Go half's)"
fi
exit "$FAIL"
