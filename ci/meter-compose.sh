#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# Two QERs on one PDR, enforced through one classifier result and one Meter
# with two levels: the meter stack the compiler uses for every PDR.
#
#   ci/meter-compose.sh                    # default stage: the installed one
#   STAGE=/some/prefix ci/meter-compose.sh # any installed bess-dev prefix
#
# The claim: the classifier's result carries two meter ids, and one Meter with
# `levels: 2` polices them in order. The graph is deploy/meter-compose.yaml;
# what each check means is in its header.
#
# The load-bearing check is the second level's red gate: a run that read only
# the first id would count nothing on gate 2.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/ci/bess-env.sh"
PLUG=${PLUG:-$ROOT/datapath/build}
GRAPH=$ROOT/deploy/meter-compose.yaml
SECONDS_RUN=${SECONDS_RUN:-2}

BESSCTL=$STAGE/bin/bessctl
LOG=$(mktemp /tmp/upf-compose-XXXXXX.log)
PIDFILE=$(mktemp /tmp/upf-compose-XXXXXX.pid)

bessd_start "$LOG" "$PIDFILE" || exit 1
cleanup() { bessd_stop; }
trap cleanup EXIT

if ! bessd_wait 30 1; then
  echo "compose: the daemon did not come up; log follows" >&2
  cat "$LOG" >&2
  exit 1
fi

"$BESSCTL" -s "$SERVER" validate "$GRAPH" >/dev/null
bessd_apply "$GRAPH"
sleep "$SECONDS_RUN"

FAIL=0
# One snapshot for every number below: each `metrics` call is its own instant,
# and counts compared across calls are counts of different things (a later call
# sees more traffic). gate_count reads the snapshot, matching each label where
# it appears -- the label order is the registry's, not a caller's.
METRICS=$("$BESSCTL" -s "127.0.0.1:$BESS_PORT" metrics 2>/dev/null)
gate_count() { # gate_count <module> <direction> <gate>
  printf '%s\n' "$METRICS" |
    awk -v m="module=\"$1\"" -v d="direction=\"$2\"" -v g="gate=\"$3\"" '
      $1 ~ /^bess_gate_packets_total\{/ {
        line = $0
        if (index(line, m) && index(line, d) && index(line, g)) { sum += $NF }
      }
      END { printf "%d", sum }'
}
check() { # check <description> <value> <want>
  if [ "$2" = "$3" ]; then
    echo "ok: $1 ($2)"
  else
    echo "FAIL: $1 (got $2, want $3)" >&2
    FAIL=1
  fi
}
positive() { # positive <description> <value>
  if [ "${2:-0}" -gt 0 ]; then
    echo "ok: $1 ($2 packets)"
  else
    echo "FAIL: $1 (0 packets)" >&2
    FAIL=1
  fi
}

M_GREEN=$(gate_count mt out 0)
M_YELLOW=$(gate_count mt out 1)
M_RED=$(gate_count mt out 2)

check "the second level's red gate is the only exit (mt gate 0)" "$M_GREEN" 0
positive "the first level passed the packets for the second to police (mt gate 2)" "$M_RED"
check "neither level emitted yellow (mt gate 1)" "$M_YELLOW" 0
if grep -E "unreadable" "$LOG" | grep -Eq "Meter"; then
  echo "FAIL: the meter reported an unreadable attribute" >&2
  grep -E "unreadable" "$LOG" | head -3 >&2
  FAIL=1
fi

check_clean_shutdown "$BESSD_PID" || FAIL=1
if [ "$FAIL" = 0 ]; then
  echo "meter-compose: ok (two meter levels, one Meter, two policies)"
else
  echo "meter-compose: log kept at $LOG" >&2
  exit 1
fi
