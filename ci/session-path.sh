#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# The packet-path proof: deploy the UPF's whole graph, program a session into it
# over the control plane, and show the packets crossing it both ways -- the
# uplink decapsulated toward N6 and the downlink encapsulated toward N3.
#
#   ci/session-path.sh                    # default stage: the pkg worktree's stage-fast
#   STAGE=/some/prefix ci/session-path.sh # any installed bess-dev prefix
#
# Two halves, deliberately: the Go test programs the session and reads the
# daemon's own counters (zero before the session exists, non-zero after), and
# this script checks the bytes in the daemon's Dump output -- the decapsulated
# inner packet on the uplink, the outer Eth/IPv4/UDP/GTP-U the encap wrote on
# the downlink, with the session's TEID. Between them they cover the claim
# "the session's state is what makes the packets move", which neither half
# shows alone.
#
# The plugin must be built first (see README.md); the script uses
# datapath/build/libupf_datapath.so unless PLUG says otherwise. The daemon is
# started with no hugepages (-m 0) and never left running; run it under the
# host's daemon slot if one is in use.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
STAGE=${STAGE:-/home/krsna1729/Projects/bess/.scratch/wt/pkg/build/stage-fast/usr/local}
DPDK_LIB=${DPDK_LIB:-/home/krsna1729/Projects/bess/.scratch/wt/codecs/deps/dpdk-25.11.3/install/lib}
PLUG=${PLUG:-$ROOT/datapath/build}
GRAPH=${GRAPH:-$ROOT/deploy/session-path.yaml}
SERVER=${SERVER:-127.0.0.1:10514}
GO=${GO:-$(MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} mise which go 2>/dev/null || echo go)}
SECONDS_RUN=${SECONDS_RUN:-3}

BESSD=$STAGE/bin/bessd
BESSCTL=$STAGE/bin/bessctl
LOG=$(mktemp /tmp/upf-path-XXXXXX.log)
PIDFILE=$(mktemp /tmp/upf-path-XXXXXX.pid)

[ -x "$BESSD" ] || { echo "path: no bessd at $BESSD (set STAGE)" >&2; exit 1; }
[ -x "$BESSCTL" ] || { echo "path: no bessctl at $BESSCTL (set STAGE)" >&2; exit 1; }
[ -f "$PLUG/libupf_datapath.so" ] || {
  echo "path: build the plugin first: (cd datapath && ninja -C build)" >&2
  exit 1
}

export LD_LIBRARY_PATH=$STAGE/lib:$DPDK_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}

"$BESSD" -m 0 -skip_root_check -i "$PIDFILE" -modules="$PLUG" -f >"$LOG" 2>&1 &
DAEMON=$!
cleanup() {
  kill "$DAEMON" 2>/dev/null || true
  for _ in 1 2 3 4 5; do kill -0 "$DAEMON" 2>/dev/null || break; sleep 1; done
  kill -9 "$DAEMON" 2>/dev/null || true
}
trap cleanup EXIT

for _ in $(seq 1 30); do "$BESSCTL" status >/dev/null 2>&1 && break; sleep 1; done
if ! "$BESSCTL" status >/dev/null 2>&1; then
  echo "path: the daemon did not come up; log follows" >&2
  cat "$LOG" >&2
  exit 1
fi

"$BESSCTL" validate "$GRAPH" >/dev/null
"$BESSCTL" apply "$GRAPH" >/dev/null
"$BESSCTL" resume >/dev/null

# The Go half: the control arm (counters zero), the session, then the counters
# again. Run from the repository root so the module and its workspace resolve.
cd "$ROOT"
MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} UPF_BESS_TARGET=$SERVER \
  $GO test ./internal/session/ -run 'TestLiveSessionCarriesPackets.*' -count=1 -v

# The packet half: the graph's Dumps in the daemon's log. The Dump module
# wraps sixteen bytes to a line, so a field may straddle two of them: join the
# hex first, then match. (A fixed-string grep over the raw log would miss
# exactly the fields that happen to fall on a boundary.)
sleep "$SECONDS_RUN"
FAIL=0
HEX=$(awk '/^  [0-9a-f]+: / { for (i = 2; i <= NF; i++) printf "%s ", $i }' "$LOG")
check() { # check <description> <fixed string the log's hex must contain>
  if printf '%s\n' "$HEX" | grep -Fq -- "$2"; then
    echo "ok: $1"
  else
    echo "FAIL: $1 (no '$2' in the log)" >&2
    FAIL=1
  fi
}

# Uplink: the decap replaced the outer headers with a frame around the inner
# packet, byte for byte the G-PDU's payload (10.45.0.2:5000 -> 8.8.8.8:53).
check "decap left the UE's packet in a frame" \
      "02 00 00 00 00 02 02 00 00 00 00 01 08 00 45 00"
check "the inner packet is the UE's" "0a 2d 00 02 08 08 08 08"

# Downlink: the encap wrote the outer headers from the tunnel record the FAR's
# outer header creation produced -- Eth, IPv4, UDP toward 2152, GTP-U with the
# gNB's TEID (0x55667788) and the inner packet's length (0x0025 = 37).
check "encap wrote a GTP-U header of the inner packet's length" "30 ff 00 25"
check "encap used the session's downlink TEID" "55 66 77 88"
# The graph's inner frame is marked EF (TOS 0x2e) and the outer header must
# carry it: the RAN's transport is DSCP-marked, so a UPF that dropped the inner
# class would send every downlink packet as best effort.
check "the outer header carries the inner DSCP" "45 2e 00 49 00 00 40 00 40 11"

if [ "$FAIL" = 0 ]; then
  echo "session-path: ok (uplink and downlink both carried the session's packets)"
else
  echo "session-path: failed; log is $LOG" >&2
  cp "$LOG" /tmp/upf-path-failed.log 2>/dev/null || true
fi
exit "$FAIL"
