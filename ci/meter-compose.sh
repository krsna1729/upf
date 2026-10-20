#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# Two QERs on one PDR, enforced, with one meter_id attribute: the composition
# finding 6 needs, proven on this stage with no BESS change.
#
#   ci/meter-compose.sh                    # default stage: the installed one
#   STAGE=/some/prefix ci/meter-compose.sh # any installed bess-dev prefix
#
# The claim: an ActionTable rewrites `meter_id` without consuming the action id,
# so a chain -- classifier -> at1 -> m1 -> at2 -> m2 -- gives each Meter its own
# id and its own rate policy. The graph is deploy/meter-compose.yaml; what each
# check means is in its header.
#
# The load-bearing check is the second meter's red gate: m2's table holds only
# id 2, so a run in which at2's rewrite did not take effect finds no entry for
# the id m1 was given, drops fail-closed, and counts nothing on gate 2.
#
# The plugin must be built first (see README.md): the graph needs this repo's
# BESS build, whose stage carries the Meter/ActionTable resources it declares.

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

M1_GREEN=$(gate_count m1 out 0)
M1_RED=$(gate_count m1 out 2)
AT2_OUT=$(gate_count at2 out 0)
M2_RED=$(gate_count m2 out 2)

positive "the classifier's traffic is metered by the first table's id (m1 gate 0)" "$M1_GREEN"
check "the generous first meter drops nothing (m1 gate 2)" "$M1_RED" 0
positive "the second ActionTable ran on the surviving packets" "$AT2_OUT"
positive "the second meter policed with its own id (m2 gate 2), not the first's" "$M2_RED"
# In-gate counters are not produced (a Track hook is installed on the upstream
# module's ogate), so the second meter's intake is read from the gates it emits
# on, in the one snapshot: red alone is enough, and it cannot exceed what the
# second table passed.
# The counters are read one module after another while workers run, so a few
# packets of skew are expected; a gross disagreement (say a stage dropping
# everything and a later counter not noticing) is what this catches.
SLACK=$(( AT2_OUT / 100 + 4096 ))
if [ "$M2_RED" -gt "$(( AT2_OUT + SLACK ))" ]; then
  echo "FAIL: the second meter emitted more than the second table passed ($M2_RED > $AT2_OUT + $SLACK skew)" >&2
  FAIL=1
fi
if grep -E "unreadable" "$LOG" | grep -Eq "'(at1|at2|m1|m2)'"; then
  echo "FAIL: a stage reported an unreadable attribute (a write with no downstream reader)" >&2
  grep -E "unreadable" "$LOG" | grep -E "'(at1|at2|m1|m2)'" | head -3 >&2
  FAIL=1
fi

check_clean_shutdown "$BESSD_PID" || FAIL=1
if [ "$FAIL" = 0 ]; then
  echo "meter-compose: ok (one meter_id attribute, two meters, two policies)"
else
  echo "meter-compose: log kept at $LOG" >&2
  exit 1
fi
