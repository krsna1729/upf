# SPDX-License-Identifier: BSD-3-Clause
#
# Sourced by every ci/ lane (`ROOT` must be set): where the BESS build comes
# from, and the ports a run listens on.
#
# The BESS build is this repository's own copy under build/bess (README, "The
# BESS build this repo carries"), never a sibling checkout:
#
#   stage/  the installed bess-dev stage: bessd, bessctl, headers, bess-dev.pc
#   dpdk/   the DPDK runtime bessd loads
#   fast/   the perf tree (core/bessd, tests/perf/*) the bench lanes run
#   sdk/go  the fork's Go SDK, for ci/work.sh
#
# Every variable still overrides: BESS=<tree with this layout>, or STAGE=,
# DPDK_LIB= alone.
#
# Ports are picked free at start, not fixed: another agent or daemon on this
# host may hold bessd's default (10514) or a neighbour's, and a collision would
# make a run talk to someone else's daemon. BESS_PORT, N4_PORT and SERVER
# override.

BESS=${BESS:-$ROOT/build/bess}
STAGE=${STAGE:-$BESS/stage}
DPDK_LIB=${DPDK_LIB:-$BESS/dpdk/install/lib}

# The repo pins the SDK in go.mod; a go.work would substitute another copy.
export GOWORK=off

# A lane's own `go test` runs each test binary under its package's memory row
# (ci/run_capped.py, ci/test-memory.tsv), as the unit pass does.
GO_TEST_EXEC=(-exec "$ROOT/ci/run_capped.py")

free_port() {
  local p
  while :; do
    p=$(shuf -i 30000-60000 -n 1)
    ss -ltnuH "( sport = :$p )" | grep -q . || { echo "$p"; return; }
  done
}
if [ -n "${SERVER:-}" ] && [ -z "${BESS_PORT:-}" ]; then BESS_PORT=${SERVER##*:}; fi
BESS_PORT=${BESS_PORT:-$(free_port)}
N4_PORT=${N4_PORT:-$(free_port)}
SERVER=${SERVER:-127.0.0.1:$BESS_PORT}

# check_clean_shutdown <bessd pid>: stop the daemon the way an operator would
# (SIGTERM) and fail on its own exit status. A daemon that aborts on teardown
# has freed something it should not have, and every other check can pass first.
# bessd writes its crash report to /tmp/bessd_crash.log, one path for every
# daemon on the host: match the pid before crediting it to this run.
check_clean_shutdown() {
  local rc=0 mem=0
  bessd_mem_check "$1" || mem=1
  kill "$1" 2>/dev/null || true
  wait "$1" 2>/dev/null || rc=$?
  if [ "$rc" = 0 ]; then
    echo "ok: bessd shut down cleanly"
    return "$mem"
  fi
  echo "FAIL: bessd exited with status $rc on shutdown (crash report: /tmp/bessd_crash.log, check its pid against $1)" >&2
  return 1
}

# The daemon's memory, per lane (docs/engineering-guide.md, "Test memory").
# Each lane declares the most its bessd may hold resident, in MiB, as a row
# "lane <name> <MiB>" in ci/test-memory.tsv; ci/check-test-memory.py fails a
# lane CI runs that has none. bessd_launcher puts the daemon in a transient
# `systemd-run --user --scope` of its own with MemoryMax at the kill limit
# (1.5x the declaration, at least 32 MiB above, as ci/run_capped.py) and no
# swap; bessd_mem_check reads that scope's memory.peak before the daemon is
# stopped (the scope goes away with it), or, with no user manager, the
# daemon's VmHWM, and fails above the declaration. The lanes run with
# --mem_backing=normal, so the daemon's pools are ordinary pages the cgroup
# charges. UPF_TEST_MEM_MEASURE=1 calibrates: kill limit 3000 MiB, never fail.
# The printed line avoids the daemon's name: ci/verify.sh reads any line naming
# it as a lane that must also print the clean-shutdown line.
LANE=${UPF_LANE:-$(basename "$0" .sh)}

# The lanes' packet pool: 32768 buffers, not bessd's default 262144 (bess
# core/runtime/opts.cc:259). A lane sends a few frames at a time; the default
# pool is most of what its daemon holds. bessd alone with no graph peaks at
# 707 MiB with the default and 129 MiB with --buffers=32768 (memory.peak,
# 2026-11-04); the lanes' rows in ci/test-memory.tsv are measured with it. A
# lane that needs more passes its own --buffers to bessd_start: the last one
# wins.
BESSD_POOL=(--buffers=32768)

mem_declared() {
  awk -v k="$1" -v n="$2" '$1 == k && $2 == n && $3 ~ /^[0-9]+$/ { print $3; exit }' \
    "$ROOT/ci/test-memory.tsv"
}

# bessd_launcher: sets BESSD_LAUNCH to the command prefix that starts the
# daemon in its own scope (empty with no user manager), and BESSD_MEM_LIMIT.
bessd_launcher() {
  local declared
  declared=$(mem_declared lane "$LANE")
  BESSD_LAUNCH=()
  if [ "${UPF_TEST_MEM_MEASURE:-0}" = 1 ]; then
    BESSD_MEM_LIMIT=3000
  elif [ -z "$declared" ]; then
    echo "lane-mem: $LANE: no memory declaration: add \"lane $LANE <MiB>\" to ci/test-memory.tsv" >&2
    return 1
  else
    BESSD_MEM_LIMIT=$(( declared * 3 / 2 > declared + 32 ? declared * 3 / 2 : declared + 32 ))
  fi
  if [ "${UPF_TEST_MEM_NO_SCOPE:-0}" != 1 ] && systemd-run --user --scope -q true 2>/dev/null; then
    # systemd-run --scope execs the command in place: $! is still the daemon.
    BESSD_LAUNCH=(systemd-run --user --scope -q "--unit=upf-lane-$LANE-$$-$RANDOM"
      -p "MemoryMax=${BESSD_MEM_LIMIT}M" -p MemorySwapMax=0 -p OOMPolicy=continue --)
  fi
}

# bessd_mem_check <pid>: the daemon's peak against the lane's declaration, once
# per daemon; call it while the daemon still runs. Returns 1 above it.
bessd_mem_check() {
  local pid=$1 declared cg peak how
  [ -n "$pid" ] && [ "${BESSD_MEM_CHECKED:-}" != "$pid" ] || return 0
  BESSD_MEM_CHECKED=$pid
  declared=$(mem_declared lane "$LANE")
  declared=${declared:-0}
  if [ ! -r "/proc/$pid/cgroup" ]; then
    echo "lane-mem: $LANE: the daemon ($pid) exited before its peak was read (an exit status of 137 would be the kernel's kill at ${BESSD_MEM_LIMIT:-?} MiB)" >&2
    return 1
  fi
  cg=$(cut -d: -f3- "/proc/$pid/cgroup")
  case $cg in
    */upf-lane-"$LANE"-*.scope)
      peak=$(cat "/sys/fs/cgroup$cg/memory.peak" 2>/dev/null) && how="cgroup memory.peak" ;;
  esac
  if [ -z "${how:-}" ]; then
    peak=$(awk '/^VmHWM:/ { print $2 * 1024 }' "/proc/$pid/status" 2>/dev/null)
    how="VmHWM, no cgroup of its own"
  fi
  awk -v lane="$LANE" -v d="$declared" -v p="${peak:-0}" -v how="$how" \
      -v limit="$([ "$how" = "cgroup memory.peak" ] && echo "${BESSD_MEM_LIMIT:-?}" || echo none)" \
      -v measure="${UPF_TEST_MEM_MEASURE:-0}" 'BEGIN {
    printf "lane-mem: %s: declared %d MiB, peak %.1f MiB (%s; kill limit %s)\n", lane, d, p / 1048576, how, limit
    if (measure != 1 && p > d * 1048576) {
      printf "lane-mem: %s: FAILED: declared %d MiB, peak %.1f MiB\n", lane, d, p / 1048576 > "/dev/stderr"
      exit 1
    }
  }'
}

# The daemon lifecycle every lane repeats: one copy. A lane sets PLUG to the
# plugin directory, then calls bessd_start with its log and pid file; the rest
# is here. Extra arguments to bessd_start go to bessd (a lane that needs a
# different queue count or a vdev passes them through).
#
#   bessd_start <log> <pidfile> [bessd args...]   sets BESSD_PID
#   bessd_wait [tries] [delay]                    waits for bessctl status
#   bessd_apply <graph>                           validate/apply/resume
#   bessd_stop                                    kill, wait, escalate
#
# bessd_stop is for cleanup (it says nothing on success); a lane that passes
# calls check_clean_shutdown "$BESSD_PID" before it exits, which is what prints
# the clean-shutdown line the claims runner looks for.
bessd_start() {
  local log=$1 pidfile=$2
  shift 2
  [ -x "$STAGE/bin/bessd" ] || { echo "no bessd at $STAGE/bin/bessd (set STAGE)" >&2; return 1; }
  [ -x "$STAGE/bin/bessctl" ] || { echo "no bessctl at $STAGE/bin/bessctl (set STAGE)" >&2; return 1; }
  [ -n "${PLUG:-}" ] && [ -f "$PLUG/libupf_datapath.so" ] || {
    echo "build the plugin first: ninja -C datapath/build" >&2; return 1; }
  export LD_LIBRARY_PATH=$STAGE/lib:$DPDK_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
  local -a launch=()
  # BESSD_STDBUF=1 for a lane that slices the log: a block-buffered stdout would
  # put a window's dump lines in the next window's slice.
  if [ "${BESSD_STDBUF:-0}" = 1 ]; then
    launch=(stdbuf -oL -eL)
  fi
  bessd_launcher || return 1
  "${BESSD_LAUNCH[@]}" "${launch[@]}" "$STAGE/bin/bessd" --mem_backing=normal -skip_root_check -p "$BESS_PORT" -i "$pidfile" \
    -modules="$PLUG" -f "${BESSD_POOL[@]}" "$@" >"$log" 2>&1 &
  BESSD_PID=$!
}

bessd_wait() {
  local tries=${1:-30} delay=${2:-1}
  for _ in $(seq 1 "$tries"); do
    "$STAGE/bin/bessctl" -s "$SERVER" status >/dev/null 2>&1 && return 0
    sleep "$delay"
  done
  return 1
}

bessd_apply() {
  "$STAGE/bin/bessctl" -s "$SERVER" apply "$1" >/dev/null &&
    "$STAGE/bin/bessctl" -s "$SERVER" resume >/dev/null
}

bessd_stop() {
  [ -n "${BESSD_PID:-}" ] || return 0
  bessd_mem_check "$BESSD_PID" || true
  kill "$BESSD_PID" 2>/dev/null || true
  for _ in 1 2 3 4 5; do
    kill -0 "$BESSD_PID" 2>/dev/null || break
    sleep 1
  done
  kill -9 "$BESSD_PID" 2>/dev/null || true
  wait "$BESSD_PID" 2>/dev/null || true
}
