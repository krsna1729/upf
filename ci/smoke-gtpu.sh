#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# End-to-end smoke test of the datapath plugin: build it against an installed
# bess-dev stage, load it into the staged bessd, apply deploy/smoke-gtpu.yaml,
# and check the two packets the graph dumps -- one decapsulated, one
# encapsulated -- byte for byte.
#
#   ci/smoke-gtpu.sh                    # default stage: the pkg worktree's stage-fast
#   STAGE=/some/prefix ci/smoke-gtpu.sh # any installed bess-dev prefix
#
# The plugin must be built first (see README.md): the script uses
# datapath/build/libupf_datapath.so unless PLUG says otherwise. The daemon is
# started with no hugepages (-m 0) and never left running; run it under the
# host's build/daemon slot if one is in use.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
STAGE=${STAGE:-/home/krsna1729/Projects/bess/.scratch/wt/pkg/build/stage-fast/usr/local}
DPDK_LIB=${DPDK_LIB:-/home/krsna1729/Projects/bess/.scratch/wt/codecs/deps/dpdk-25.11.3/install/lib}
PLUG=${PLUG:-$ROOT/datapath/build}
SECONDS_RUN=${SECONDS_RUN:-5}

BESSD=$STAGE/bin/bessd
BESSCTL=$STAGE/bin/bessctl
LOG=$(mktemp /tmp/upf-smoke-XXXXXX.log)
PIDFILE=$(mktemp /tmp/upf-bessd-XXXXXX.pid)

[ -x "$BESSD" ] || { echo "smoke: no bessd at $BESSD (set STAGE)" >&2; exit 1; }
[ -x "$BESSCTL" ] || { echo "smoke: no bessctl at $BESSCTL (set STAGE)" >&2; exit 1; }
[ -f "$PLUG/libupf_datapath.so" ] || {
  echo "smoke: build the plugin first: (cd datapath && PKG_CONFIG_PATH=<stage>/lib/pkgconfig meson setup build && ninja -C build)" >&2
  exit 1
}

export LD_LIBRARY_PATH=$STAGE/lib:$DPDK_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}

# No hugepages: the smoke runs anywhere, including a workstation with none.
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
  echo "smoke: the daemon did not come up; log follows" >&2
  cat "$LOG" >&2
  exit 1
fi

# validate prints the canonical manifest, apply prints the version it committed.
"$BESSCTL" validate "$ROOT/deploy/smoke-gtpu.yaml" >/dev/null
"$BESSCTL" apply "$ROOT/deploy/smoke-gtpu.yaml" >/dev/null
"$BESSCTL" resume >/dev/null
sleep "$SECONDS_RUN"

FAIL=0
check() { # check <description> <fixed string the log must contain>
  if grep -q -- "$2" "$LOG"; then
    echo "smoke: ok    $1"
  else
    echo "smoke: FAIL  $1 (no '$2' in $LOG)" >&2
    FAIL=1
  fi
}

# Uplink: the plugin stripped Eth/IPv4/UDP/GTP-U, so Dump printed the 37-byte
# inner IPv4 packet (10.0.0.1 -> 8.8.8.8, UDP 1234 -> 53, "hello-upf").
check "decap stripped the tunnel and kept the inner packet" \
      "45 00 00 25 00 01 40 00 40 11 20 b7 0a 00 00 01"
# and wrote the TEID into metadata (the byte after it is upf_gnb_ip, then the
# two Ethernet addresses the downlink setattr wrote).
check "decap wrote upf_teid into metadata" "11 22 33 44 0A 14 1E 02"

# Downlink: the plugin built the outer headers: Eth (setattr's addresses),
# IPv4 src 10.20.30.1 -> dst 10.20.30.2 (the metadata) with a correct header
# checksum (ea 79), UDP -> 2152, GTP-U type 255 (G-PDU), length 37, TEID
# 0x11223344, then the inner packet byte for byte.
# (The Dump hexdump is 16 bytes to a line, so each check stays inside one.)
check "encap built a well-formed outer IPv4 header" \
      "00 49 00 00 40 00 40 11 ea 79 0a 14 1e 01 0a 14"
check "encap wrote UDP/GTP-U toward 2152 with the session TEID" \
      "08 68 00 35 00 00 30 ff 00 25 11 22"
check "the encapsulated frame carries the inner packet" \
      "33 44 45 00 00 25 00 01 40 00 40 11 20 b7"

if [ "$FAIL" = 0 ]; then
  echo "smoke: PASS (log: $LOG)"
else
  echo "smoke: log kept at $LOG" >&2
fi
exit "$FAIL"
