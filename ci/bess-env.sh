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
  local rc=0
  kill "$1" 2>/dev/null || true
  wait "$1" 2>/dev/null || rc=$?
  if [ "$rc" = 0 ]; then
    echo "ok: bessd shut down cleanly"
    return 0
  fi
  echo "FAIL: bessd exited with status $rc on shutdown (crash report: /tmp/bessd_crash.log, check its pid against $1)" >&2
  return 1
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
  "${launch[@]}" "$STAGE/bin/bessd" --mem_backing=normal -skip_root_check -p "$BESS_PORT" -i "$pidfile" \
    -modules="$PLUG" -f "$@" >"$log" 2>&1 &
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
  kill "$BESSD_PID" 2>/dev/null || true
  for _ in 1 2 3 4 5; do
    kill -0 "$BESSD_PID" 2>/dev/null || break
    sleep 1
  done
  kill -9 "$BESSD_PID" 2>/dev/null || true
  wait "$BESSD_PID" 2>/dev/null || true
}
