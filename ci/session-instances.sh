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
# started with no hugepages (--mem_backing=normal) and never left running; run it under the
# host's daemon slot if one is in use.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/ci/bess-env.sh"
PLUG=${PLUG:-$ROOT/datapath/build}
GRAPH=${GRAPH:-$ROOT/deploy/session-instances.yaml}
GO=${GO:-$(MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} mise which go 2>/dev/null || echo go)}
SECONDS_RUN=${SECONDS_RUN:-3}

BESSCTL=$STAGE/bin/bessctl
LOG=$(mktemp /tmp/upf-instances-XXXXXX.log)
PIDFILE=$(mktemp /tmp/upf-instances-XXXXXX.pid)

bessd_start "$LOG" "$PIDFILE" || exit 1
cleanup() {
  bessd_stop
  echo "instances: daemon log in $LOG"
}
trap cleanup EXIT

if ! bessd_wait 30 1; then
  echo "instances: the daemon never came up; log follows" >&2
  cat "$LOG" >&2
  exit 1
fi

"$BESSCTL" -s "$SERVER" validate "$GRAPH" >/dev/null
bessd_apply "$GRAPH"

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
# graph's two sources send. The dump precedes endpoint tagging and GtpuDecap,
# so it records the input TEIDs; the Go half's separate gate counts above show
# which session's admission and PDR path each stream uses.
check "the internet stream's G-PDU carries its tunnel" "$TEID_HEX" "11 22 33 44"
check "the ims stream's G-PDU carries its tunnel" "$TEID_HEX" "11 22 33 45"

check_clean_shutdown "$BESSD_PID" || FAIL=1
if [ "$FAIL" = 0 ]; then
  echo "instances: both tunnels are on the wire (the exits' counters are the Go half's)"
fi
exit "$FAIL"
