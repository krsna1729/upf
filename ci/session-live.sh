#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# Live test of the session layer: build the datapath plugin, start the staged
# bessd with it, apply deploy/session-live.yaml, and run the Go test that
# programs a whole session into the running daemon (establish, retransmit,
# modify, delete) through the Go SDK -- every transaction built from the
# daemon's own schema.
#
#   ci/session-live.sh                    # default stage: the pkg worktree's stage-fast
#   STAGE=/some/prefix ci/session-live.sh # any installed bess-dev prefix
#
# The plugin must be built first (see README.md); the script uses
# datapath/build/libupf_datapath.so unless PLUG says otherwise. The daemon is
# started with no hugepages (-m 0) and never left running; run it under the
# host's daemon slot if one is in use.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
STAGE=${STAGE:-/home/krsna1729/Projects/bess/.scratch/wt/pkg/build/stage-fast/usr/local}
DPDK_LIB=${DPDK_LIB:-/home/krsna1729/Projects/bess/.scratch/wt/codecs/deps/dpdk-25.11.3/install/lib}
PLUG=${PLUG:-$ROOT/datapath/build}
SERVER=${SERVER:-127.0.0.1:10514}
GO=${GO:-mise exec -- go}

BESSD=$STAGE/bin/bessd
BESSCTL=$STAGE/bin/bessctl
LOG=$(mktemp /tmp/upf-live-XXXXXX.log)
PIDFILE=$(mktemp /tmp/upf-live-XXXXXX.pid)

[ -x "$BESSD" ] || { echo "live: no bessd at $BESSD (set STAGE)" >&2; exit 1; }
[ -f "$PLUG/libupf_datapath.so" ] || {
  echo "live: build the plugin first: (cd datapath && ninja -C build)" >&2
  exit 1
}

export LD_LIBRARY_PATH=$STAGE/lib:$DPDK_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}

"$BESSD" -m 0 -skip_root_check -i "$PIDFILE" -modules="$PLUG" -f >"$LOG" 2>&1 &
DAEMON=$!
cleanup() {
  kill "$DAEMON" 2>/dev/null || true
  for _ in 1 2 3 4 5; do kill -0 "$DAEMON" 2>/dev/null || break; sleep 1; done
  kill -9 "$DAEMON" 2>/dev/null || true
}
trap cleanup EXIT

for _ in $(seq 1 30); do "$BESSCTL" status >/dev/null 2>&1 && break; sleep 1; done
if ! "$BESSCTL" status >/dev/null 2>&1; then
  echo "live: the daemon did not come up; log follows" >&2
  cat "$LOG" >&2
  exit 1
fi

"$BESSCTL" validate "$ROOT/deploy/session-live.yaml" >/dev/null
"$BESSCTL" apply "$ROOT/deploy/session-live.yaml" >/dev/null

# The test needs the Go toolchain CI pins; run it from the repository root so
# the module and its workspace resolve.
cd "$ROOT"
MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} UPF_BESS_TARGET=$SERVER \
  $GO test ./internal/session/ -run TestLiveSessionProgramsTheDaemon -count=1 -v || {
  echo "session-live: failed; the daemon's log is $LOG" >&2
  exit 1
}

# The run's own files, not a result: a failed run keeps them (the message above
# says where), a green one leaves nothing behind -- the other CI scripts do the
# same, and this one used to leave a log and a pidfile per run in /tmp.
rm -f "$LOG" "$PIDFILE"
