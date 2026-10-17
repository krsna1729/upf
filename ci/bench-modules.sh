#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# Module costs for the UPF's datapath modules, from BESS's own instrument
# (tests/perf/live_perf.cc). The arms M.gtpu_decap and M.gtpu_encap each carry
# a control arm that keeps the shipping graph's front and tail -- the TEID
# classifier and its rule, the ActionId write, the tunnel record, the reader
# that keeps the decap's attribute real -- with a Bypass in the module's slot,
# so the difference of a pair is that module's cost *in composition*, and the
# frames are deploy/smoke-gtpu.yaml's own bytes.
#
#   ci/bench-modules.sh                 # defaults below
#   BESS=<checkout> ROUNDS=8 ci/bench-modules.sh
#
# A perf run holds the machine: it waits for builds, and nothing else should be
# running. When the host has a perf slot (a lock builds and perf runs share),
# pass it in:  WRAP="slot perf omarchy-benchmark --isolate --diagnose --cpu 2,4 -- taskset -c 2,4"
#
# On this host that wrapper currently loses the run: `omarchy-benchmark` exits 1
# before it starts the command whenever a CPU selection is given (`--cpu 4 --
# /bin/echo` prints nothing, with or without `--isolate`; with no `--cpu` the
# command runs), and it restores governors, turbo and CPU-online on the way out.
# It is not a privilege or tty problem: `sudo -n true` succeeds here. The script
# therefore checks its own report and fails loudly when the wrapper ate the run
# (docs/design.md, "After that measurement").
#
# The numbers and the stage/plugin they came from are printed together: a module
# cost without its stage and plugin build is unreadable.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BESS=${BESS:-$HOME/Projects/bess}
WT=${WT:-$BESS}                             # the checkout whose build holds live_perf
BUILD=${BUILD:-$WT/build/bench}             # release with the benchmarks: the daemon and the tool
DAEMON=${DAEMON:-$BUILD/core/bessd}
LIVE_PERF=${LIVE_PERF:-$BUILD/tests/perf/live_perf}
PLUG=${PLUG:-$ROOT/datapath/build}
STAGE=${STAGE:-$BESS/build/stage-fast/usr/local}
DPDK_LIB=${DPDK_LIB:-$BESS/deps/dpdk-25.11.3/install/lib}
ROUNDS=${ROUNDS:-4}
CPU=${CPU:-4}
CONTROL_CPU=${CONTROL_CPU:-2}
WRAP=${WRAP:-}
OUT=${OUT:-/tmp/upf-bench-modules.log}

for f in "$LIVE_PERF" "$DAEMON" "$PLUG/libupf_datapath.so"; do
  [ -e "$f" ] || { echo "bench: missing $f (set LIVE_PERF/DAEMON/PLUG)" >&2; exit 1; }
done

echo "stage:  $STAGE"
echo "plugin: $PLUG/libupf_datapath.so ($(stat -c %s "$PLUG/libupf_datapath.so") bytes, $(date -r "$PLUG/libupf_datapath.so" +%Y-%m-%d))"
echo "daemon: $DAEMON"
echo "tool:   $LIVE_PERF, $ROUNDS rounds on CPU $CPU (control $CONTROL_CPU)"

export BESS_DPDK_LIB=$DPDK_LIB
export LD_LIBRARY_PATH=$DPDK_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}

status=0
$WRAP "$LIVE_PERF" --cpu "$CPU" --control-cpu "$CONTROL_CPU" \
  --build "name=$DAEMON" --plugin "$PLUG" \
  --tests M.base,M.gtpu_decap.base,M.gtpu_decap,M.gtpu_encap.base,M.gtpu_encap \
  --counters --rounds "$ROUNDS" --save "${OUT%.log}.json" >"$OUT" 2>&1 || status=$?

# A wrapper that fails before the tool starts leaves an empty report, and an
# empty report is indistinguishable from a run with no rows: say which it was and
# keep its output, rather than `sed`-ing nothing and exiting 0. (On this host
# `omarchy-benchmark --cpu <list>` exits 1 before running its command; see
# docs/design.md.)
if ! grep -q '^test ' "$OUT"; then
  echo "bench: no report in $OUT -- ${WRAP:-no wrapper} did not run $LIVE_PERF (exit $status):" >&2
  cat "$OUT" >&2
  exit 1
fi
if [ "$status" != 0 ]; then
  echo "bench: $LIVE_PERF exited $status; its report is $OUT" >&2
  exit "$status"
fi

sed -n '/^test /,/^$/p' "$OUT"

# The pair deltas: the report prints every M row as ns/packet above M.base, so
# an arm minus its control is the module's cost.
awk '/^M\.gtpu_(decap|encap)(\.base)? +[0-9]/{ v[$1]=$2 }
     END {
       if (!("M.gtpu_decap" in v) || !("M.gtpu_encap" in v)) { exit }
       printf "\ndecap: %+.2f ns/pkt over its control (%s - %s)\n",
              v["M.gtpu_decap"] - v["M.gtpu_decap.base"], v["M.gtpu_decap"], v["M.gtpu_decap.base"]
       printf "encap: %+.2f ns/pkt over its control (%s - %s)\n",
              v["M.gtpu_encap"] - v["M.gtpu_encap.base"], v["M.gtpu_encap"], v["M.gtpu_encap.base"]
     }' "$OUT"

echo
echo "full report: $OUT, raw rounds: ${OUT%.log}.json"
echo "counters per packet are in the report; contamination (if any) is in its diagnostics."
