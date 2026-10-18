#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# The keyed per-session matcher's live proof, uplink half: deploy the graph that
# has no WildcardMatch in its uplink chain, program one session into it through
# the compiler's `PdrMatch` opt-in, and show that a packet on N3 is decapsulated,
# matched *by the module*, leaves with the right ActionId and egresses on N6.
#
#   ci/pdrmatch-path.sh                    # default stage: the main checkout's installed stage
#   STAGE=/some/prefix ci/pdrmatch-path.sh # any installed bess-dev prefix
#
# Two halves, deliberately, as ci/session-path.sh has them: the Go driver
# (ci/pdrmatch) programs the session and reads the daemon's own counters --
# zero on the uplink chain before the session, non-zero after, and the map's key
# read back with the ActionId the module will carry -- and this script checks
# the bytes in the daemon's Dump output: the decapsulated inner packet before
# the matcher, and the same packet leaving the router on its N6 gate, which is
# where "the module matched it and the ActionId resolved" stops being a counter
# and becomes a frame.
#
# The plugin must be built first (see README.md); the script uses
# datapath/build/libupf_datapath.so unless PLUG says otherwise. The daemon is
# started with no hugepages (-m 0) and never left running; run it under the
# host's daemon slot if one is in use.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/ci/bess-env.sh"
PLUG=${PLUG:-$ROOT/datapath/build}
GRAPH=${GRAPH:-$ROOT/deploy/pdrmatch-path.yaml}
GO=${GO:-$(MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} mise which go 2>/dev/null || echo go)}
SECONDS_RUN=${SECONDS_RUN:-3}

BESSD=$STAGE/bin/bessd
BESSCTL=$STAGE/bin/bessctl
LOG=$(mktemp /tmp/upf-pdrmatch-XXXXXX.log)
PIDFILE=$(mktemp /tmp/upf-pdrmatch-XXXXXX.pid)

[ -x "$BESSD" ] || { echo "pdrmatch: no bessd at $BESSD (set STAGE)" >&2; exit 1; }
[ -x "$BESSCTL" ] || { echo "pdrmatch: no bessctl at $BESSCTL (set STAGE)" >&2; exit 1; }
[ -f "$PLUG/libupf_datapath.so" ] || {
  echo "pdrmatch: build the plugin first: (cd datapath && ninja -C build)" >&2
  exit 1
}

export LD_LIBRARY_PATH=$STAGE/lib:$DPDK_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}

"$BESSD" -m 0 -skip_root_check -p "$BESS_PORT" -i "$PIDFILE" -modules="$PLUG" -f >"$LOG" 2>&1 &
DAEMON=$!
cleanup() {
  kill "$DAEMON" 2>/dev/null || true
  for _ in 1 2 3 4 5; do kill -0 "$DAEMON" 2>/dev/null || break; sleep 1; done
  kill -9 "$DAEMON" 2>/dev/null || true
}
trap cleanup EXIT

for _ in $(seq 1 30); do "$BESSCTL" -s "127.0.0.1:$BESS_PORT" status >/dev/null 2>&1 && break; sleep 1; done
if ! "$BESSCTL" -s "127.0.0.1:$BESS_PORT" status >/dev/null 2>&1; then
  echo "pdrmatch: the daemon did not come up; log follows" >&2
  cat "$LOG" >&2
  exit 1
fi

"$BESSCTL" -s "127.0.0.1:$BESS_PORT" validate "$GRAPH" >/dev/null
"$BESSCTL" -s "127.0.0.1:$BESS_PORT" apply "$GRAPH" >/dev/null
"$BESSCTL" -s "127.0.0.1:$BESS_PORT" resume >/dev/null

# The Go half: the control arm, the session through the compiler's PdrMatch
# opt-in, the map read back, and the counters. Run from the repository root so
# the module resolves; the workspace is off because the SDK's own module is
# pinned by this module's go.mod (see README.md).
cd "$ROOT"
MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} GOWORK=off \
  $GO run ./ci/pdrmatch -target "$SERVER"

# The packet half: the graph's Dumps in the daemon's log, per dump.
sleep "$SECONDS_RUN"
FAIL=0
. "$ROOT/ci/dumphex.sh"
UP_HEX=$(dump_hex dump_u "$LOG")
N6_HEX=$(dump_hex dump_n6 "$LOG")
check() { # check <description> <the dump's hex> <fixed string it must contain>
  if printf '%s\n' "$2" | grep -Fq -- "$3"; then
    echo "ok: $1"
  else
    echo "FAIL: $1 (no '$3' in that dump)" >&2
    FAIL=1
  fi
}

# The uplink before the matcher: the decap replaced the outer headers with a
# frame around the inner packet, byte for byte the G-PDU's payload
# (10.45.0.2:5000 -> 8.8.8.8:53).
check "decap left the UE's packet in a frame" "$UP_HEX" \
      "02 00 00 00 00 02 02 00 00 00 00 01 08 00 45 00"
check "the inner packet is the UE's" "$UP_HEX" "0a 2d 00 02 08 08 08 08"

# And on the router's N6 gate, which only a match can reach: the TEID table
# drops a G-PDU no session names, and the module drops a packet the session's
# rules do not match, so these bytes are the module's verdict plus the
# ActionTable's, in a frame.
check "the matched packet left the router by its N6 gate" "$N6_HEX" \
      "02 00 00 00 00 02 02 00 00 00 00 01 08 00 45 00"
check "the packet on N6 is the UE's" "$N6_HEX" "0a 2d 00 02 08 08 08 08"

# The module, as the daemon loaded it: the matcher it was built over, and the
# attribute its session key is read from -- the decap's F-TEID.
if grep -Fq "pdr_match_ul/rules over firewall_scan, keyed by 'upf_teid'" "$LOG"; then
  echo "ok: the module's matcher is firewall_scan, keyed by upf_teid"
else
  echo "FAIL: the daemon's log does not name the module's matcher" >&2
  FAIL=1
fi

check_clean_shutdown "$DAEMON" || FAIL=1
if [ "$FAIL" = 0 ]; then
  echo "pdrmatch-path: ok (the session's packet was matched by the module and left by N6)"
  rm -f "$LOG" "$PIDFILE"
else
  echo "pdrmatch-path: failed; log is $LOG" >&2
fi
exit "$FAIL"
