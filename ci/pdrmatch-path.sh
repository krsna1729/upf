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

BESSCTL=$STAGE/bin/bessctl
LOG=$(mktemp /tmp/upf-pdrmatch-XXXXXX.log)
PIDFILE=$(mktemp /tmp/upf-pdrmatch-XXXXXX.pid)

bessd_start "$LOG" "$PIDFILE" || exit 1
cleanup() { bessd_stop; }
trap cleanup EXIT

if ! bessd_wait 30 1; then
  echo "pdrmatch: the daemon did not come up; log follows" >&2
  cat "$LOG" >&2
  exit 1
fi

"$BESSCTL" -s "$SERVER" validate "$GRAPH" >/dev/null
bessd_apply "$GRAPH"

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
# result's next hop, in a frame -- with the deployment's N6 addresses (the Router's
# hop 1, BESS D-153) and the uplink chain's decremented TTL, as in
# ci/session-path.sh.
check "the matched packet left the router by its N6 gate" "$N6_HEX" \
      "02 00 00 00 06 02 02 00 00 00 06 01 08 00 45 00"
check "the packet on N6 is the UE's" "$N6_HEX" "0a 2d 00 02 08 08 08 08"
check "the uplink's TTL was decremented" "$N6_HEX" "45 00 00 25 00 01 40 00 3f 11"

# The QoS flows, by their payloads ("qfi5-upf!", "qfi9-upf!"). Both reached the
# module (they are in the decap's dump); only QFI 5's left it toward N6, so the
# QFI 9 rule dropped its own flow and the QFI 5 rule forwarded the other.
Q5="71 66 69 35 2d 75 70 66 21"
Q9="71 66 69 39 2d 75 70 66 21"
check "the QFI 5 flow reached the module" "$UP_HEX" "$Q5"
check "the QFI 9 flow reached the module" "$UP_HEX" "$Q9"
check "the QFI 5 flow left by N6" "$N6_HEX" "$Q5"
if printf '%s\n' "$N6_HEX" | grep -Fq -- "$Q9"; then
  echo "FAIL: the QFI 9 flow, whose rule drops, left by N6" >&2
  FAIL=1
else
  echo "ok: the QFI 9 flow did not leave by N6"
fi

# The downlink: the graph's source has been sending the data network's reply
# (8.8.8.8:5000 -> the UE:53) since the graph was applied, and the selector in
# front of the matcher names the session by the address it is addressed to --
# which is the only thing that can name it, a packet from N6 carrying no
# tunnel. The encap's dump is where the whole downlink chain's verdict is: the
# packet is inside a G-PDU for the session's TEID, with the outer header the
# FAR's Outer Header Creation named.
D_HEX=$(dump_hex dump_d "$LOG")
check "the downlink packet was selected, matched and encapsulated" "$D_HEX" \
      "08 08 08 08 0a 2d 00 02"
check "the downlink G-PDU carries the session's TEID" "$D_HEX" "55 66 77 88"
check "the downlink's TTL was decremented" "$D_HEX" "45 b8 00 25 00 01 40 00 3f 11"

# The module, as the daemon loaded it: the matcher it was built over, and the
# attribute its session key is read from -- the decap's F-TEID.
if grep -Fq "pdr_match_ul/rules over firewall_scan, keyed by 'upf_teid'" "$LOG"; then
  echo "ok: the module's matcher is firewall_scan, keyed by upf_teid"
else
  echo "FAIL: the daemon's log does not name the module's matcher" >&2
  FAIL=1
fi

check_clean_shutdown "$BESSD_PID" || FAIL=1
if [ "$FAIL" = 0 ]; then
  echo "pdrmatch-path: ok (the session's packet was matched by the module and left by N6)"
  rm -f "$LOG" "$PIDFILE"
else
  echo "pdrmatch-path: failed; log is $LOG" >&2
fi
exit "$FAIL"
