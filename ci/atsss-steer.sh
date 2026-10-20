#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# The AtsssSteer module in isolation: one Source, one policy, two accesses.
# Each window changes health or the policy, sends one packet, and the shell
# checks which Dump saw it. The windows are separated by the driver's
# handshake, so a packet from the next window cannot answer this one's check.
#
#   ci/atsss-steer.sh
#   STAGE=/some/prefix ci/atsss-steer.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/ci/bess-env.sh"
. "$ROOT/ci/dumphex.sh"
PLUG=${PLUG:-$ROOT/datapath/build}
GRAPH=${GRAPH:-$ROOT/deploy/atsss-steer.yaml}
GO=${GO:-$(MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} mise which go 2>/dev/null || echo go)}

WORK=$(mktemp -d /tmp/upf-atsss-steer-XXXXXX)
LOG=$WORK/bessd.log
DRIVER_LOG=$WORK/driver.log
DRIVER=

cleanup() {
  local status=$?
  [ -n "$DRIVER" ] && kill "$DRIVER" 2>/dev/null || true
  bessd_stop
  if [ "$status" = 0 ]; then
    rm -rf "$WORK"
  else
    echo "atsss-steer: exit $status; the daemon's log is $LOG" >&2
  fi
  exit "$status"
}
trap cleanup EXIT

BESSD_STDBUF=1 bessd_start "$LOG" "$WORK/bessd.pid" || exit 1
if ! bessd_wait 30 1; then
  echo "atsss-steer: the daemon did not come up; log follows" >&2
  cat "$LOG" >&2
  exit 1
fi
"$STAGE/bin/bessctl" -s "$SERVER" validate "$GRAPH" >/dev/null
bessd_apply "$GRAPH"

await() {
  for _ in $(seq 1 300); do
    [ -e "$WORK/$1" ] && return 0
    if ! kill -0 "$DRIVER" 2>/dev/null; then
      echo "atsss-steer: the driver stopped before $1; output follows" >&2
      cat "$DRIVER_LOG" >&2
      return 1
    fi
    sleep 0.1
  done
  echo "atsss-steer: the driver never signalled $1" >&2
  return 1
}
slice() { tail -c +$((OFFSET + 1)) "$LOG" >"$1"; OFFSET=$(wc -c <"$LOG"); }
OFFSET=0

(
  cd "$ROOT"
  MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} GOWORK=off \
    "$GO" run ./ci/atssssteer -target "$SERVER" -handshake "$WORK"
) >"$DRIVER_LOG" 2>&1 &
DRIVER=$!

pass=0
fail=0
check() { # check <window> <dump> <want: yes|no>
  local window=$1 dump=$2 want=$3
  local bytes
  bytes=$(dump_hex "$dump" "$WORK/$window.log")
  if { [ "$want" = yes ] && [ -n "$bytes" ]; } || { [ "$want" = no ] && [ -z "$bytes" ]; }; then
    echo "atsss-steer: ok    $window: $dump $want"
    pass=$((pass + 1))
  else
    echo "atsss-steer: FAIL  $window: $dump $want (bytes: ${bytes:-none})" >&2
    fail=$((fail + 1))
  fi
  : >"$WORK/$window.go"
}

for w in both failover none erased preferred2 recovered; do
  await "$w.done"
  sleep 1.2
  slice "$WORK/$w.log"
  case $w in
    both)       check both dump_a yes; check both dump_b no ;;
    failover)   check failover dump_a no; check failover dump_b yes ;;
    none)       check none dump_a no; check none dump_b no ;;
    erased)     check erased dump_a no; check erased dump_b no ;;
    preferred2) check preferred2 dump_a no; check preferred2 dump_b yes ;;
    recovered)  check recovered dump_a yes; check recovered dump_b no ;;
  esac
done

if [ "$fail" -ne 0 ]; then
  echo "atsss-steer: $fail checks failed" >&2
  exit 1
fi
echo "atsss-steer: all $pass checks passed"
