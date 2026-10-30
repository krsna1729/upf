#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# Live test of the session layer: build the datapath plugin, start the staged
# bessd with it, apply deploy/session-live.yaml, and run the Go test that
# programs a whole session into the running daemon (establish, retransmit,
# modify, delete) through the Go SDK -- every transaction built from the
# daemon's own schema.
#
#   ci/session-live.sh                    # default stage: the main checkout's installed stage
#   STAGE=/some/prefix ci/session-live.sh # any installed bess-dev prefix
#
# The plugin must be built first (see README.md); the script uses
# datapath/build/libupf_datapath.so unless PLUG says otherwise. The daemon is
# started with no hugepages (--mem_backing=normal) and never left running; run it under the
# host's daemon slot if one is in use.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/ci/bess-env.sh"
PLUG=${PLUG:-$ROOT/datapath/build}
GO=${GO:-mise exec -- go}

BESSCTL=$STAGE/bin/bessctl
LOG=$(mktemp /tmp/upf-live-XXXXXX.log)
PIDFILE=$(mktemp /tmp/upf-live-XXXXXX.pid)

bessd_start "$LOG" "$PIDFILE" || exit 1
cleanup() { bessd_stop; }
trap cleanup EXIT

if ! bessd_wait 30 1; then
  echo "live: the daemon did not come up; log follows" >&2
  cat "$LOG" >&2
  exit 1
fi

"$BESSCTL" -s "$SERVER" validate "$ROOT/deploy/session-live.yaml" >/dev/null
bessd_apply "$ROOT/deploy/session-live.yaml"

# The test needs the Go toolchain CI pins; run it from the repository root so
# the module and its workspace resolve.
cd "$ROOT"
MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} UPF_BESS_TARGET=$SERVER \
  $GO test ./internal/session/ -run 'TestLiveSessionProgramsTheDaemon|TestLiveStartupSweepErasesStaleSessions|TestLiveSessionSharedRecords|TestLiveSessionSharesOneFTEIDPerCHOOSEID' -count=1 -v -cover || {
  echo "session-live: failed; the daemon's log is $LOG" >&2
  exit 1
}

# The client's own tests: the schema is the contract, and they check it against
# the daemon that is up. Coverage is asked for here rather than in the unit run,
# because without a daemon these tests skip and the package reports nothing.
MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} UPF_BESS_TARGET=$SERVER \
  $GO test ./internal/bess/ -run 'TestLive' -count=1 -v -cover || {
  echo "session-live: the client's live tests failed; the daemon's log is $LOG" >&2
  exit 1
}

# And the live benchmarks, with the daemon that is already up: the compiler with
# a real transaction behind it, and the schema-driven message building. Their
# numbers are what the role of each fake-free part is judged by (docs/design.md,
# "Where that time goes").
MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} UPF_BESS_TARGET=$SERVER \
  $GO test ./internal/session/ ./internal/bess/ -run '^$' -bench 'BenchmarkLive' \
  -benchtime "${LIVE_BENCHTIME:-200x}" -benchmem || {
  echo "session-live: a live benchmark failed; the daemon's log is $LOG" >&2
  exit 1
}

# The run's own files, not a result: a failed run keeps them (the message above
# says where), a green one leaves nothing behind -- the other CI scripts do the
# same, and this one used to leave a log and a pidfile per run in /tmp.
rm -f "$LOG" "$PIDFILE"
