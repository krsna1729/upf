#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# The A/B bench (datapath/bench/upf_ab.cc): two datapaths on identical seeded
# streams, in alternating rounds (ABBA: the order flips every round), each arm
# in its own daemon. Before any timing both arms must produce byte-identical
# output digests and identical per-rule packet and octet counts; a mismatch
# fails the run.
#
#   ci/bench-ab.sh LOG [upf_ab args...]
#
# Two shapes:
#   graph against appliance (default): the graph modules and UpfAppliance of one
#     plugin build (PLUG).
#   parent against commit: --baseline-plugin DIR [--baseline-layout L] names the
#     parent's plugin build; PLUG is the commit's. Reports call the parent
#     "baseline".
#   graph parent against appliance commit: --graph-plugin DIR runs the graph arm
#     from the parent's build (one that has no appliance yet).
#
# Both plugin builds need -Dbench=true (the traffic and digest modules); the
# client is PLUG's datapath/build/upf_ab. A run holds the machine: on a host
# with a perf slot, wrap it (WRAP="slot perf"). Worker CPU 11 and control CPU 9
# unless --worker-cpu/--control-cpu say otherwise.
#
#   ci/bench-ab.sh ab.log --sessions 1000 --rounds 8 --duration 2 \
#     --mem-backing normal --bessd-arg --mem_limit_mb=4096 \
#     --baseline-plugin ../parent/datapath/build --layout masked
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/ci/bess-env.sh"
PLUG=${PLUG:-$ROOT/datapath/build}
AB=${AB:-$PLUG/upf_ab}
WRAP=${WRAP:-}

(( $# >= 1 )) || { echo "usage: $0 LOG [upf_ab args...]" >&2; exit 2; }
LOG=$1; shift
[ -x "$AB" ] || { echo "no $AB: configure the plugin with -Dbench=true" >&2; exit 1; }
[ -x "$STAGE/bin/bessd" ] || { echo "no bessd at $STAGE/bin/bessd (set STAGE)" >&2; exit 1; }
export LD_LIBRARY_PATH=$STAGE/lib:$DPDK_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}

# The client writes its daemons' pid files and logs to the working directory.
cd "${TMPDIR:-/tmp}"
args=(--bessd "$STAGE/bin/bessd" --plugin "$PLUG")
case " $* " in *" --worker-cpu "*) ;; *) args+=(--worker-cpu 11) ;; esac
case " $* " in *" --control-cpu "*) ;; *) args+=(--control-cpu 9) ;; esac
echo "bench-ab: plugin $PLUG ($(git -C "$ROOT" rev-parse --short HEAD)), bessd $STAGE/bin/bessd" >"$LOG"
rc=0
$WRAP "$AB" "${args[@]}" "$@" >>"$LOG" 2>&1 || rc=$?
grep -E '^SUMMARY|^verify .*: (IDENTICAL|PASS)|FAIL|MISMATCH' "$LOG" || true
echo "bench-ab: rc=$rc log=$LOG"
exit "$rc"
