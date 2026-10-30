#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# The packet-path proof: deploy the UPF's whole graph, program a session into it
# over the control plane, and show the packets crossing it both ways -- the
# uplink decapsulated toward N6 and the downlink encapsulated toward N3.
#
#   ci/session-path.sh                    # default stage: the main checkout's installed stage
#   STAGE=/some/prefix ci/session-path.sh # any installed bess-dev prefix
#
# Two halves, deliberately: the Go test programs the session and reads the
# daemon's own counters (zero before the session exists, non-zero after), and
# this script checks the bytes in the daemon's Dump output -- the decapsulated
# inner packet on the uplink, the frame that left N6 with the interface's
# addresses and the chain's decremented TTL, the outer Eth/IPv4/UDP/GTP-U the
# encap wrote on the downlink, with the session's TEID. Between them they cover
# the claim "the session's state is what makes the packets move", which neither
# half shows alone.
#
# The plugin must be built first (see README.md); the script uses
# datapath/build/libupf_datapath.so unless PLUG says otherwise. The daemon is
# started with no hugepages (--mem_backing=normal) and never left running; run it under the
# host's daemon slot if one is in use.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/ci/bess-env.sh"
PLUG=${PLUG:-$ROOT/datapath/build}
TARGET=${UPF_TARGET:-graph}
case "$TARGET" in
  graph) DEFAULT_GRAPH=$ROOT/deploy/session-path.yaml ;;
  appliance) DEFAULT_GRAPH=$ROOT/deploy/session-path-appliance.yaml ;;
  *) echo "TARGET must be graph or appliance" >&2; exit 2 ;;
esac
GRAPH=${GRAPH:-$DEFAULT_GRAPH}
export UPF_TARGET=$TARGET
export TMPDIR=${TMPDIR:-$ROOT/build/run}
mkdir -p "$TMPDIR"
export GLOG_log_dir=${GLOG_log_dir:-$TMPDIR/glog}
mkdir -p "$GLOG_log_dir"
GO=${GO:-$(MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} mise which go 2>/dev/null || echo go)}
SECONDS_RUN=${SECONDS_RUN:-3}

BESSCTL=$STAGE/bin/bessctl
LOG=$(mktemp "$TMPDIR/upf-path-XXXXXX.log")
PIDFILE=$(mktemp "$TMPDIR/upf-path-XXXXXX.pid")

bessd_start "$LOG" "$PIDFILE" || exit 1
cleanup() {
  rm -f "${RENDERED:-}" "${MARKER_SOCK:-}"  # rendered per run, not left behind
  bessd_stop
}
trap cleanup EXIT

if ! bessd_wait 30 1; then
  echo "path: the daemon did not come up; log follows" >&2
  cat "$LOG" >&2
  exit 1
fi

# The End Marker's socket is rendered per run: BESS unlinks a path when it
# binds, so a second daemon on the host using the graph's own path would take
# this run's socket.
MARKER_SOCK=$ROOT/build/run/end-marker-$BESS_PORT.sock
mkdir -p "$ROOT/build/run"
RENDERED=$ROOT/build/run/$(basename "$GRAPH" .yaml)-$BESS_PORT.yaml
sed "s|/tmp/upf-end-marker.sock|$MARKER_SOCK|" "$GRAPH" >"$RENDERED"
"$BESSCTL" -s "$SERVER" validate "$RENDERED" >/dev/null
bessd_apply "$RENDERED"

# The Go half: the control arm (counters zero), the session, then the counters
# again. Run from the repository root so the module and its workspace resolve.
cd "$ROOT"
MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} UPF_BESS_TARGET=$SERVER UPF_END_MARKER_SOCK=$MARKER_SOCK UPF_ROUTE_MODE=${ROUTE_MODE:-hop} \
  $GO test ./internal/session/ -run 'TestLiveSessionCarriesPackets.*|TestLiveSessionCarriesNothingOutsideAPortRange|TestLiveSessionCountsTheRulesATURReasures|TestLiveQuotaEvaluationStopsTheTraffic|TestLiveSessionSendsTheEndMarkerOnSNDEM|TestLiveErrorIndicationBecomesAnERIRReport|TestLiveEndMarkerBecomesAnEMRRReport|TestLiveGBRSplitsTheMeter' -count=1 -v

# The packet half: the graph's Dumps in the daemon's log, per dump (the helper
# is shared with ci/n4-path.sh; see its header for why a dump is scoped).
sleep "$SECONDS_RUN"
FAIL=0
. "$ROOT/ci/dumphex.sh"
UP_HEX=$(dump_hex dump_u "$LOG")
N6_HEX=$(dump_hex dump_n6 "$LOG")
DOWN_HEX=$(dump_hex dump_d "$LOG")
MARKER_HEX=$(dump_hex dump_m "$LOG")
check() { # check <description> <the dump's hex> <fixed string it must contain>
  if printf '%s\n' "$2" | grep -Fq -- "$3"; then
    echo "ok: $1"
  else
    echo "FAIL: $1 (no '$3' in that dump)" >&2
    FAIL=1
  fi
}

# Uplink: the decap replaced the outer headers with a frame around the inner
# packet, byte for byte the G-PDU's payload (10.45.0.2:5000 -> 8.8.8.8:53).
if [ "$TARGET" = graph ]; then
  check "decap left the UE's packet in a frame" "$UP_HEX" \
        "02 00 00 00 00 02 02 00 00 00 00 01 08 00 45 00"
else
  # No intermediate tap exists inside the owned module. Its N6 output must
  # preserve the complete inner UDP payload after routing instead.
  UP_HEX=$N6_HEX
  check "decapsulation preserved the external UDP payload" "$UP_HEX" \
        "13 88 00 35 00 11 00 00 68 65 6c 6c 6f 2d 75 70 66"
fi
check "the inner packet is the UE's" "$UP_HEX" "0a 2d 00 02 08 08 08 08"

# Downlink: the encap wrote the outer headers from the tunnel record the FAR's
# outer header creation produced -- Eth, IPv4, UDP toward 2152, GTP-U with the
# gNB's TEID (0x55667788) and the inner packet's length (0x0025 = 37).
check "encap wrote a GTP-U header of the inner packet's length" "$DOWN_HEX" "30 ff 00 25"
check "encap used the session's downlink TEID" "$DOWN_HEX" "55 66 77 88"
# The graph's inner frame is marked EF (TOS 0xb8) and the outer header must
# carry it: the RAN's transport is DSCP-marked, so a UPF that dropped the inner
# class would send every downlink packet as best effort. The inner packet's own
# TOS is b8 as well, and the outer comes first.
check "the outer header carries the inner DSCP" "$DOWN_HEX" "45 b8 00 49 00 00 40 00 3f 11"

# The N6 exit (dump_n6), where the deployment's own shape shows: the Router
# resolved next hop 1 for the frame, and the hop's addresses are the data
# network's next hop as destination and the interface's MAC as source
# (deploy/upf.yaml; BESS D-153). The TTL is the uplink chain's decrement, 64
# (0x40) to 63 (0x3f), on the inner packet the router forwarded -- the outer
# header of a tunneled frame is the encap's own.
check "the forwarded frame carries the N6 next hop's addresses" "$N6_HEX" \
      "02 00 00 00 06 02 02 00 00 00 06 01 08 00 45 00"
check "the uplink's TTL was decremented" "$N6_HEX" "45 00 00 25 00 01 40 00 3f 11"

# Both hop counts decrease: the inner Router forwards the data network's
# packet, then the production outer Router forwards the new tunnel header.
# The exact outer TTL 0x3f is checked with DSCP above.
check "the downlink's TTL was decremented" "$DOWN_HEX" \
      "45 b8 00 25 00 01 40 00 3f 11"

# The control plane's End Marker: the handover modification (SNDEM) made the
# UPF construct a 60-byte frame naming the tunnel the session left -- the OLD
# TEID (0x11223344) toward the old peer (10.20.30.2), from the UPF's N3
# address (192.0.2.1) -- and write it to the graph's unix_port, whose dump this
# is. TS 29.281 7.3.2: type 254, length 0, no optional field.
check "the end marker's IPv4 header is the UPF's N3 address" "$MARKER_HEX" \
      "00 24 00 00 40 00 40 11 50 b2 c0 00 02 01 0a 14"
check "the end marker names the tunnel the session left" "$MARKER_HEX" \
      "1e 02 08 68 08 68 00 10 00 00 30 fe 00 00 11 22"
# Exactly one: the live test's handover is this run's only SNDEM, and a second
# marker would be a stream's end a peer reads twice (or a marker the port
# carried for a tunnel nothing moved).
MARKERS=$(printf '%s\n' "$MARKER_HEX" | grep -c "1e 02 08 68 08 68 00 10 00 00 30 fe 00 00 11 22" || true)
if [ "$MARKERS" = 1 ]; then
  echo "ok: the port carried exactly one end marker"
else
  echo "FAIL: the port carried $MARKERS end markers, want 1" >&2
  FAIL=1
fi

check_clean_shutdown "$BESSD_PID" || FAIL=1
if [ "$FAIL" = 0 ]; then
  echo "session-path: ok (uplink and downlink both carried the session's packets)"
  # The log and the pidfile are the run's, not a result: a failed run keeps both
  # (the message above says where), a green one leaves nothing behind.
  rm -f "$LOG" "$PIDFILE"
else
  echo "session-path: failed; log is $LOG" >&2
fi
exit "$FAIL"
