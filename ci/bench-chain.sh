#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# What a module hop costs, and what the datapath's modules cost, measured as the
# throughput of one worker core: one load generator (a Source), the same packet,
# one module more per variant.
#
# Every variant has a *control arm* that differs from it only in the slot of the
# module under test (a Bypass): `decap` is measured against `rewritehop`, not
# against `rewrite`, so the delta is the module in composition -- not a hop, not
# a frame size, not a batching artefact.
#
#   ci/bench-chain.sh              # 3 rounds of 5 s per variant
#   ROUNDS=5 SECONDS_RUN=10 ci/bench-chain.sh
#
# Run it under the host's perf slot: it wants a machine to itself and cores of
# its own (CORES, default 2-3: control + worker, off the build CPUs).
#
# Module names are prefixed with the variant: the daemon refuses an apply that
# changes an existing module's argument ("a module's argument is applied at
# construction"), and two variants that share a name with different arguments
# (decap's G-PDU vs encap's inner packet) would abort the run on the second one.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
STAGE=${STAGE:-/home/krsna1729/Projects/bess/.scratch/wt/pkg/build/stage-fast/usr/local}
DPDK_LIB=${DPDK_LIB:-/home/krsna1729/Projects/bess/.scratch/wt/codecs/deps/dpdk-25.11.3/install/lib}
PLUG=${PLUG:-$ROOT/datapath/build}
CORES=${CORES:-2-3}
ROUNDS=${ROUNDS:-3}
SECONDS_RUN=${SECONDS_RUN:-5}

BESSD=$STAGE/bin/bessd
BESSCTL=$STAGE/bin/bessctl
LOG=$(mktemp /tmp/upf-bench-XXXXXX.log)
PIDFILE=$(mktemp /tmp/upf-bench-XXXXXX.pid)
MANIFEST=$(mktemp /tmp/upf-bench-XXXXXX.yaml)

# The uplink packet: the 87-byte G-PDU deploy/smoke-gtpu.yaml uses
# (TEID 0x11223344, inner 10.0.0.1 -> 8.8.8.8/UDP, "hello-upf").
GPDU="AgAAAAABAgAAAAACCABFAABJAAFAAEAR6ngKFB4BChQeAghoCGgANQAAMP8AJREiM0RFAAAlAAFAAEARILcKAAABCAgICATSADUAEQAAaGVsbG8tdXBm"
# The inner packet alone, for the encap-side variants.
INNER="RQAAJQABQABAESC3CgAAAQgICAgE0gA1ABEAAGhlbGxvLXVwZg=="
# The four session attributes GtpuEncap reads (upf_teid 0x11223344, upf_gnb_ip
# 10.20.30.2, the two MACs), as one SetMetadata argument.
ATTRS='{attrs: [{name: upf_teid, size: 4, value_int: 287454020}, {name: upf_gnb_ip, size: 4, value_int: 169090562}, {name: ether_src, size: 6, value_bin: "AgAAAAAB"}, {name: ether_dst, size: 6, value_bin: "AgAAAAAC"}]}'

export LD_LIBRARY_PATH=$STAGE/lib:$DPDK_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}

write_manifest() { # write_manifest <variant>; a "b1" suffix means Source burst 1
  local v=$1 burst=32
  case "$v" in *b1) burst=1; v=${v%b1};; esac
  local s=${1}_src # every module is <variant>_<role>: see the header
  {
    printf 'modules:\n'
    printf '  - {name: %s, mclass: Source, arg: {pkt_size: 87, burst: %s}}\n' "$s" "$burst"
    case "$v" in
      sink)
        printf '  - {name: %s_sink, mclass: Sink}\n' "$v"
        printf 'connections:\n  - {upstream: %s, downstream: %s_sink}\n' "$s" "$v"
        ;;
      hop1)
        printf '  - {name: %s_bp, mclass: Bypass}\n  - {name: %s_sink, mclass: Sink}\n' "$v" "$v"
        printf 'connections:\n  - {upstream: %s, downstream: %s_bp}\n' "$s" "$v"
        printf '  - {upstream: %s_bp, downstream: %s_sink}\n' "$v" "$v"
        ;;
      hop4)
        printf '  - {name: %s_b0, mclass: Bypass}\n  - {name: %s_b1, mclass: Bypass}\n' "$v" "$v"
        printf '  - {name: %s_b2, mclass: Bypass}\n  - {name: %s_b3, mclass: Bypass}\n' "$v" "$v"
        printf '  - {name: %s_sink, mclass: Sink}\n' "$v"
        printf 'connections:\n  - {upstream: %s, downstream: %s_b0}\n' "$s" "$v"
        printf '  - {upstream: %s_b0, downstream: %s_b1}\n' "$v" "$v"
        printf '  - {upstream: %s_b1, downstream: %s_b2}\n' "$v" "$v"
        printf '  - {upstream: %s_b2, downstream: %s_b3}\n' "$v" "$v"
        printf '  - {upstream: %s_b3, downstream: %s_sink}\n' "$v" "$v"
        ;;
      rewrite) # Rewrite installs the G-PDU
        printf '  - {name: %s_rw, mclass: Rewrite, arg: {templates: ["%s"]}}\n' "$v" "$GPDU"
        printf '  - {name: %s_sink, mclass: Sink}\n' "$v"
        printf 'connections:\n  - {upstream: %s, downstream: %s_rw}\n' "$s" "$v"
        printf '  - {upstream: %s_rw, downstream: %s_sink}\n' "$v" "$v"
        ;;
      rewritehop) # rewrite + one hop: the control for decap and em
        printf '  - {name: %s_rw, mclass: Rewrite, arg: {templates: ["%s"]}}\n' "$v" "$GPDU"
        printf '  - {name: %s_bp, mclass: Bypass}\n  - {name: %s_sink, mclass: Sink}\n' "$v" "$v"
        printf 'connections:\n  - {upstream: %s, downstream: %s_rw}\n' "$s" "$v"
        printf '  - {upstream: %s_rw, downstream: %s_bp}\n' "$v" "$v"
        printf '  - {upstream: %s_bp, downstream: %s_sink}\n' "$v" "$v"
        ;;
      decap) # the G-PDU rewriter + the plugin module
        printf '  - {name: %s_rw, mclass: Rewrite, arg: {templates: ["%s"]}}\n' "$v" "$GPDU"
        printf '  - {name: %s_dec, mclass: GtpuDecap}\n  - {name: %s_sink, mclass: Sink}\n' "$v" "$v"
        printf 'connections:\n  - {upstream: %s, downstream: %s_rw}\n' "$s" "$v"
        printf '  - {upstream: %s_rw, downstream: %s_dec}\n' "$v" "$v"
        printf '  - {upstream: %s_dec, downstream: %s_sink}\n' "$v" "$v"
        ;;
      decapnorewrite) # the Source's own bytes are the G-PDU; control: hop1
        printf '  - {name: %s_dec, mclass: GtpuDecap}\n  - {name: %s_sink, mclass: Sink}\n' "$v" "$v"
        printf 'connections:\n  - {upstream: %s, downstream: %s_dec}\n' "$s" "$v"
        printf '  - {upstream: %s_dec, downstream: %s_sink}\n' "$v" "$v"
        ;;
      em) # the classifier alone, default gate: all packets miss
        printf '  - {name: %s_rw, mclass: Rewrite, arg: {templates: ["%s"]}}\n' "$v" "$GPDU"
        printf '  - {name: %s_em, mclass: ExactMatch, arg: {fields: [{offset: 26, num_bytes: 4}]}}\n' "$v"
        printf '  - {name: %s_sink, mclass: Sink}\n' "$v"
        printf 'connections:\n  - {upstream: %s, downstream: %s_rw}\n' "$s" "$v"
        printf '  - {upstream: %s_rw, downstream: %s_em}\n' "$v" "$v"
        printf '  - {upstream: %s_em, downstream: %s_sink}\n' "$v" "$v"
        ;;
      setmeta) # the encap attributes alone
        printf '  - {name: %s_sm, mclass: SetMetadata, arg: %s}\n' "$v" "$ATTRS"
        printf '  - {name: %s_sink, mclass: Sink}\n' "$v"
        printf 'connections:\n  - {upstream: %s, downstream: %s_sm}\n' "$s" "$v"
        printf '  - {upstream: %s_sm, downstream: %s_sink}\n' "$v" "$v"
        ;;
      encapctl) # the control for encap: same chain, Bypass in the module's slot
        printf '  - {name: %s_rw, mclass: Rewrite, arg: {templates: ["%s"]}}\n' "$v" "$INNER"
        printf '  - {name: %s_sm, mclass: SetMetadata, arg: %s}\n' "$v" "$ATTRS"
        printf '  - {name: %s_bp, mclass: Bypass}\n  - {name: %s_sink, mclass: Sink}\n' "$v" "$v"
        printf 'connections:\n  - {upstream: %s, downstream: %s_rw}\n' "$s" "$v"
        printf '  - {upstream: %s_rw, downstream: %s_sm}\n' "$v" "$v"
        printf '  - {upstream: %s_sm, downstream: %s_bp}\n' "$v" "$v"
        printf '  - {upstream: %s_bp, downstream: %s_sink}\n' "$v" "$v"
        ;;
      encap)
        printf '  - {name: %s_rw, mclass: Rewrite, arg: {templates: ["%s"]}}\n' "$v" "$INNER"
        printf '  - {name: %s_sm, mclass: SetMetadata, arg: %s}\n' "$v" "$ATTRS"
        printf '  - {name: %s_enc, mclass: GtpuEncap, arg: {src_ip: "10.20.30.1"}}\n' "$v"
        printf '  - {name: %s_sink, mclass: Sink}\n' "$v"
        printf 'connections:\n  - {upstream: %s, downstream: %s_rw}\n' "$s" "$v"
        printf '  - {upstream: %s_rw, downstream: %s_sm}\n' "$v" "$v"
        printf '  - {upstream: %s_sm, downstream: %s_enc}\n' "$v" "$v"
        printf '  - {upstream: %s_enc, downstream: %s_sink}\n' "$v" "$v"
        ;;
      *) echo "unknown variant $v" >&2; return 1 ;;
    esac
    printf 'workers:\n  - {wid: 0, core: %s}\n' "${CORES%%-*}"
  } > "$MANIFEST"
}

# The module whose output gate is counted: the one just before the Sink.
counter_module() { # counter_module <variant>
  case "${1%b1}" in
    sink) echo "${1}_src" ;;
    hop1) echo "${1}_bp" ;;
    hop4) echo "${1}_b3" ;;
    rewrite | rewritehop) echo "${1}_rw" ;;
    decap | decapnorewrite) echo "${1}_dec" ;;
    em) echo "${1}_em" ;;
    setmeta) echo "${1}_sm" ;;
    encapctl) echo "${1}_bp" ;;
    encap) echo "${1}_enc" ;;
    *) echo "unknown variant $1" >&2; return 1 ;;
  esac
}

counter() { # counter <module> -- packets on that module's output gate
  "$BESSCTL" metrics 2>/dev/null |
    awk -v m="$1" '$1 ~ ("module=\"" m "\"") && $1 ~ /direction="out"/ {print $2; exit}'
}

declare -A MPPS

measure() { # measure <variant>
  local v=$1 mod best=0
  mod=$(counter_module "$v")
  for _ in $(seq "$ROUNDS"); do
    "$BESSCTL" pause >/dev/null
    write_manifest "$v"
    if ! out=$("$BESSCTL" apply "$MANIFEST" 2>&1); then
      echo "bench: apply failed for variant $v: $out" >&2
      exit 1
    fi
    "$BESSCTL" resume >/dev/null
    local t0 c0 t1 c1
    t0=$(date +%s.%N); c0=$(counter "$mod"); sleep "$SECONDS_RUN"
    c1=$(counter "$mod"); t1=$(date +%s.%N)
    local mpps
    mpps=$(awk -v c0="$c0" -v c1="$c1" -v t0="$t0" -v t1="$t1" \
      'BEGIN { printf "%.3f", (c1 - c0) / (t1 - t0) / 1e6 }')
    best=$(awk -v a="$best" -v b="$mpps" 'BEGIN { print (b > a) ? b : a }')
  done
  MPPS[$v]=$best
  printf 'bench: %-20s %8s Mpps\n' "$v" "$best"
}

[ -x "$BESSD" ] || { echo "bench: no bessd at $BESSD (set STAGE)" >&2; exit 1; }
[ -f "$PLUG/libupf_datapath.so" ] || { echo "bench: build the plugin first" >&2; exit 1; }

trap 'kill "$DAEMON" 2>/dev/null; rm -f "$MANIFEST" "$PIDFILE"' EXIT

echo "bench: cores $CORES, $ROUNDS rounds of ${SECONDS_RUN}s each, worker core ${CORES%%-*}"
taskset -c "$CORES" "$BESSD" -m 0 -skip_root_check -i "$PIDFILE" -modules="$PLUG" -f >"$LOG" 2>&1 &
DAEMON=$!
for _ in $(seq 1 30); do "$BESSCTL" status >/dev/null 2>&1 && break; sleep 1; done

# Every variant follows the same path (pause, apply, resume, count); the order
# below is only the order the numbers are printed in.
VARIANTS=(sink hop1 hop4 rewrite rewritehop decap decapnorewrite setmeta encapctl encap em sinkb1 hop1b1)
for v in "${VARIANTS[@]}"; do
  measure "$v"
done

# Each variant's control: the same chain with Bypass in the tested module's slot.
control_of() {
  case "$1" in
    sink | rewrite | setmeta) echo sink ;;
    hop1 | sinkb1 | hop1b1) echo sink ;;
    hop4) echo hop1 ;;
    rewritehop) echo rewrite ;;
    decap | em) echo rewritehop ;;
    decapnorewrite) echo hop1 ;;
    encap) echo encapctl ;;
    *) echo "" ;;
  esac
}

echo
printf '%-20s %10s %12s %14s %s\n' variant Mpps ns/packet "vs control" control
for v in "${VARIANTS[@]}"; do
  m=${MPPS[$v]}
  ns=$(awk -v m="$m" 'BEGIN { printf "%.2f", 1000.0 / m }')
  ctl=$(control_of "$v")
  if [ -n "$ctl" ] && [ -n "${MPPS[$ctl]:-}" ]; then
    cns=$(awk -v m="${MPPS[$ctl]}" 'BEGIN { printf "%.2f", 1000.0 / m }')
    d=$(awk -v a="$ns" -v b="$cns" 'BEGIN { printf "%+.2f", a - b }')
  else
    d="--" ctl="--"
  fi
  printf '%-20s %10s %12s %14s %s\n' "$v" "$m" "$ns" "$d" "$ctl"
done

kill "$DAEMON" 2>/dev/null || true
echo "bench: daemon log: $LOG"
