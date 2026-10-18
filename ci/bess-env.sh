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
