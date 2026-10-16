#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# The layer above ci/session-path.sh: a stand-in SMF establishes a session over
# PFCP into upfd, upfd compiles it into one control_v2 transaction, and the lab
# graph's packets move because of it -- the same bytes, reached through the node
# a real SMF talks to.
#
#   ci/n4-path.sh
#   STAGE=/some/prefix ci/n4-path.sh
#
# Both halves of the claim are here: before the session nothing leaves the two
# chains (the graph's Sources run from the moment it is applied, so a zero is a
# real absence of state, not an absence of traffic), and after it both ways
# carry packets -- the uplink because the SMF pinned the F-TEID the frames use,
# the downlink because the FAR's outer header creation named the tunnel the
# encap writes.
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
GO=${GO:-$(MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} mise which go 2>/dev/null || echo go)}

BESS_PORT=${BESS_PORT:-10516}
N4_PORT=${N4_PORT:-18805}
BESSD=$STAGE/bin/bessd
BESSCTL=$STAGE/bin/bessctl

# The values the graph's frames carry, and so the values the session must name:
# the F-TEID the SMF pins (the graph's G-PDU header), the UE address and port
# its inner packets use, and the gNB the FAR points the tunnel at.
FTEID=${FTEID:-0x11223344}
UE=${UE:-10.45.0.2}
GNB=${GNB:-10.20.30.2}
N3=${N3:-192.0.2.1}

[ -x "$BESSD" ] || { echo "n4-path: no bessd at $BESSD (set STAGE)" >&2; exit 1; }
[ -x "$BESSCTL" ] || { echo "n4-path: no bessctl at $BESSCTL (set STAGE)" >&2; exit 1; }
[ -f "$PLUG/libupf_datapath.so" ] || {
  echo "n4-path: build the plugin first: (cd datapath && ninja -C build)" >&2
  exit 1
}

WORK=$(mktemp -d /tmp/upf-n4-path-XXXXXX)
LOG=$WORK/bessd.log
UPFD_LOG=$WORK/upfd.log
DAEMON_PID=""
UPFD_PID=""
cleanup() {
  [ -n "$UPFD_PID" ] && kill "$UPFD_PID" 2>/dev/null || true
  [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null || true
  for _ in 1 2 3 4 5; do
    { [ -z "$UPFD_PID" ] || ! kill -0 "$UPFD_PID" 2>/dev/null; } && \
    { [ -z "$DAEMON_PID" ] || ! kill -0 "$DAEMON_PID" 2>/dev/null; } && break
    sleep 1
  done
  [ -n "$UPFD_PID" ] && kill -9 "$UPFD_PID" 2>/dev/null || true
  [ -n "$DAEMON_PID" ] && kill -9 "$DAEMON_PID" 2>/dev/null || true
}
trap cleanup EXIT

(cd "$ROOT" && $GO build -o "$WORK/upfd" ./cmd/upfd && $GO build -o "$WORK/n4bench" ./cmd/n4bench)

export LD_LIBRARY_PATH=$STAGE/lib:$DPDK_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}

"$BESSD" -m 0 -skip_root_check -p "$BESS_PORT" -i "$WORK/bessd.pid" \
  -modules="$PLUG" -f >"$LOG" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 60); do "$BESSCTL" -s "127.0.0.1:$BESS_PORT" status >/dev/null 2>&1 && break; sleep 0.5; done
if ! "$BESSCTL" -s "127.0.0.1:$BESS_PORT" status >/dev/null 2>&1; then
  echo "n4-path: the daemon did not come up; log follows" >&2
  cat "$LOG" >&2
  exit 1
fi
"$BESSCTL" -s "127.0.0.1:$BESS_PORT" apply "$GRAPH" >/dev/null
"$BESSCTL" -s "127.0.0.1:$BESS_PORT" resume >/dev/null

# The control arm: the Sources have been running for seconds, and nothing has
# selected their packets, so the chains' Dumps are silent.
sleep 2
BEFORE=$(grep -c "packet dump" "$LOG" || true)
if [ "$BEFORE" = 0 ]; then
  echo "ok: no session, no packet leaves either chain (control arm)"
else
  echo "n4-path: $BEFORE packets were dumped before any session existed" >&2
  exit 1
fi

# The node a real SMF talks to, with the graph's shape (its flags' defaults are
# deploy/upf.yaml's module names; the N3 address and both next hops match).
"$WORK/upfd" -n4 "127.0.0.1:$N4_PORT" -node-id 127.0.0.1 -bess "127.0.0.1:$BESS_PORT" \
  -n3-addr "$N3" -log-level info >"$UPFD_LOG" 2>&1 &
UPFD_PID=$!
for _ in $(seq 1 20); do
  grep -q "n4 listening" "$UPFD_LOG" 2>/dev/null && break
  sleep 0.25
done
kill -0 "$UPFD_PID" 2>/dev/null || { echo "n4-path: upfd exited; log follows" >&2; cat "$UPFD_LOG" >&2; exit 1; }

# One session, the frames' values pinned: PFCP -> the session layer -> one
# transaction -> the tables the packets cross.
"$WORK/n4bench" -upf "127.0.0.1:$N4_PORT" -mode establish -sessions 1 -workers 1 \
  -fteid "$FTEID" -ue-pool "$UE/32" -gnb "$GNB" -n3 "$N3" -timeout 5s || {
  echo "n4-path: the establish was refused; upfd's log follows" >&2
  cat "$UPFD_LOG" >&2
  exit 1
}

sleep 2
FAIL=0
# The Dump half, per dump: the helper is shared with ci/session-path.sh and its
# header says why a dump is scoped (the graphs' frames share their openings).
. "$ROOT/ci/dumphex.sh"
UP_HEX=$(dump_hex dump_u "$LOG")
DOWN_HEX=$(dump_hex dump_d "$LOG")
check() { # check <description> <the dump's hex> <fixed string it must contain>
  if printf '%s\n' "$2" | grep -Fq -- "$3"; then
    echo "ok: $1"
  else
    echo "FAIL: $1 (no '$3' in that dump)" >&2
    FAIL=1
  fi
}

# Uplink: the F-TEID the SMF pinned is the graph's G-PDU header's, so the TEID
# rule selects it, the decap drops the outer headers, and the inner packet --
# the UE's 10.45.0.2:5000 -> 8.8.8.8:53 -- reaches N6.
check "the F-TEID the SMF pinned decapsulates the graph's G-PDU" "$UP_HEX" \
      "0a 2d 00 02 08 08 08 08"
# Downlink: the FAR's outer header creation (TEID 0x100000 toward 10.20.30.2)
# is what the encap wrote around the data network's answer.
check "the FAR's TEID is on the wire" "$DOWN_HEX" "30 ff 00 25 00 10 00 00"
check "the FAR's gNB is the outer destination" "$DOWN_HEX" "0a 14 1e 02"
check "the downlink PDR matched the UE's address" "$DOWN_HEX" \
      "08 08 08 08 0a 2d 00 02 13 88 00 35"

if [ "$FAIL" = 0 ]; then
  echo "n4-path: ok (PFCP -> session -> packets, both ways)"
  # The work directory is the run's, not a result: a failed run keeps it (the
  # message above says where), a green one leaves nothing behind.
  rm -rf "$WORK"
else
  echo "n4-path: failed; logs are $WORK" >&2
fi
exit "$FAIL"
