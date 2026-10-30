#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# The layer above ci/session-path.sh: a stand-in SMF establishes a session over
# PFCP into upfd, upfd compiles it into one control_v2 transaction, and the lab
# graph's packets move because of it -- the same bytes, reached through the node
# a real SMF talks to.
#
#   ci/n4-path.sh
#   STAGE=/some/prefix ci/n4-path.sh
#
# Both halves of the claim are here: before the session nothing leaves the two
# chains (the graph's Sources run from the moment it is applied, so a zero is a
# real absence of state, not an absence of traffic), and after it both ways
# carry packets -- the uplink because the SMF pinned the F-TEID the frames use,
# the downlink because the FAR's outer header creation named the tunnel the
# encap writes.
#
# The plugin must be built first (see README.md); the script uses
# datapath/build/libupf_datapath.so unless PLUG says otherwise. The daemon is
# started with no hugepages (--mem_backing=normal) and never left running; run it under the
# host's daemon slot if one is in use.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/ci/bess-env.sh"
PLUG=${PLUG:-$ROOT/datapath/build}
GRAPH=${GRAPH:-$ROOT/deploy/session-path.yaml}
GO=${GO:-$(MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} mise which go 2>/dev/null || echo go)}

BESSCTL=$STAGE/bin/bessctl

# The values the graph's frames carry, and so the values the session must name:
# the F-TEID the SMF pins (the graph's G-PDU header), the UE address and port
# its inner packets use, and the gNB the FAR points the tunnel at.
FTEID=${FTEID:-0x11223344}
UE=${UE:-10.45.0.2}
GNB=${GNB:-10.20.30.2}
N3=${N3:-192.0.2.1}

WORK=$(mktemp -d /tmp/upf-n4-path-XXXXXX)
LOG=$WORK/bessd.log
UPFD_LOG=$WORK/upfd.log
UPFD_PID=""
cleanup() {
  [ -n "$UPFD_PID" ] && kill "$UPFD_PID" 2>/dev/null || true
  bessd_stop
  # Every background job this script started, not only the ones the variables
  # still point at: a phase whose own start failed leaves an earlier process
  # running, and an orphan here holds the daemon slot's lock (its fds are
  # inherited) long after the run.
  for pid in $(jobs -p); do kill "$pid" 2>/dev/null || true; done
  [ -n "$UPFD_PID" ] && kill -9 "$UPFD_PID" 2>/dev/null || true
}
trap cleanup EXIT

(cd "$ROOT" && $GO build -o "$WORK/upfd" ./cmd/upfd && $GO build -o "$WORK/n4bench" ./cmd/n4bench)

bessd_start "$LOG" "$WORK/bessd.pid" || exit 1
if ! bessd_wait 60 0.5; then
  echo "n4-path: the daemon did not come up; log follows" >&2
  cat "$LOG" >&2
  exit 1
fi
bessd_apply "$GRAPH"

# The control arm: the Sources have been running for seconds, and nothing has
# selected their packets, so the chains' Dumps are silent.
sleep 2
BEFORE=$(grep -c "packet dump" "$LOG" || true)
if [ "$BEFORE" = 0 ]; then
  echo "ok: no session, no packet leaves either chain (control arm)"
else
  echo "n4-path: $BEFORE packets were dumped before any session existed" >&2
  exit 1
fi

# The node a real SMF talks to, with the graph's shape (its flags' defaults are
# deploy/upf.yaml's module names; the N3 address and both next hops match).
"$WORK/upfd" -n4 "127.0.0.1:$N4_PORT" -node-id 127.0.0.1 -bess "127.0.0.1:$BESS_PORT" \
  -fteid-address "endpoint=1,reference=n3,transport-domain=1,source=access,ipv4=$N3" -gtpu-decap decap0 -log-level info >"$UPFD_LOG" 2>&1 &
UPFD_PID=$!
for _ in $(seq 1 20); do
  grep -q "n4 listening" "$UPFD_LOG" 2>/dev/null && break
  sleep 0.25
done
kill -0 "$UPFD_PID" 2>/dev/null || { echo "n4-path: upfd exited; log follows" >&2; cat "$UPFD_LOG" >&2; exit 1; }

# One session, the frames' values pinned: PFCP -> the session layer -> one
# transaction -> the tables the packets cross.
"$WORK/n4bench" -upf "127.0.0.1:$N4_PORT" -mode establish -sessions 1 -workers 1 \
  -fteid "$FTEID" -ue-pool "$UE/32" -gnb "$GNB" -n3 "$N3" -timeout 5s || {
  echo "n4-path: the establish was refused; upfd's log follows" >&2
  cat "$UPFD_LOG" >&2
  exit 1
}

sleep 2
FAIL=0
# The Dump half, per dump: the helper is shared with ci/session-path.sh and its
# header says why a dump is scoped (the graphs' frames share their openings).
. "$ROOT/ci/dumphex.sh"
UP_HEX=$(dump_hex dump_u "$LOG")
DOWN_HEX=$(dump_hex dump_d "$LOG")
check() { # check <description> <the dump's hex> <fixed string it must contain>
  if printf '%s\n' "$2" | grep -Fq -- "$3"; then
    echo "ok: $1"
  else
    echo "FAIL: $1 (no '$3' in that dump)" >&2
    FAIL=1
  fi
}

# Uplink: the F-TEID the SMF pinned is the graph's G-PDU header's, so the TEID
# rule selects it, the decap drops the outer headers, and the inner packet --
# the UE's 10.45.0.2:5000 -> 8.8.8.8:53 -- reaches N6.
check "the F-TEID the SMF pinned decapsulates the graph's G-PDU" "$UP_HEX" \
      "0a 2d 00 02 08 08 08 08"
# Downlink: the FAR's outer header creation (TEID 0x100000 toward 10.20.30.2)
# is what the encap wrote around the data network's answer.
check "the FAR's TEID is on the wire" "$DOWN_HEX" "30 ff 00 25 00 10 00 00"
check "the FAR's gNB is the outer destination" "$DOWN_HEX" "0a 14 1e 02"
check "the downlink PDR matched the UE's address" "$DOWN_HEX" \
      "08 08 08 08 0a 2d 00 02 13 88 00 35"

# The restart wall (docs/design.md): kill the controller and start a second one
# against the same daemon. The daemon holds the session the first one
# programmed, and the second knows nothing about it -- it must take it out
# before its PFCP socket opens, so the packets that crossed during the first
# controller's life stop being selected.
if [ "$FAIL" = 0 ]; then
  kill "$UPFD_PID" 2>/dev/null || true
  wait "$UPFD_PID" 2>/dev/null || true
  : >"$UPFD_LOG"
  "$WORK/upfd" -n4 "127.0.0.1:$N4_PORT" -node-id 127.0.0.1 -bess "127.0.0.1:$BESS_PORT" \
    -fteid-address "endpoint=1,reference=n3,transport-domain=1,source=access,ipv4=$N3" -gtpu-decap decap0 -log-level info >>"$UPFD_LOG" 2>&1 &
  UPFD_PID=$!
  for _ in $(seq 1 20); do
    grep -q "n4 listening" "$UPFD_LOG" 2>/dev/null && break
    sleep 0.25
  done
  if grep -q "erased an earlier run's session entries before serving" "$UPFD_LOG"; then
    echo "ok: the restarted controller took the earlier run's session out at startup"
  else
    echo "FAIL: the restarted controller did not sweep; upfd's log follows" >&2
    cat "$UPFD_LOG" >&2
    FAIL=1
  fi
  # And the rules are gone with it: from the moment the sweep was logged on, the
  # Sources keep running and the same G-PDU still arrives, and no rule selects
  # it any more. The count is taken here rather than before the restart: the
  # lines $LOG holds are the first controller's, and packets crossing while the
  # second one was starting up are not what this checks.
  MARK=$(grep -c "packet dump" "$LOG" || true)
  sleep 2
  AFTER=$(grep -c "packet dump" "$LOG" || true)
  if [ "$AFTER" = "$MARK" ]; then
    echo "ok: the stale session's rules are gone; no packet is selected any more"
  else
    echo "FAIL: $((AFTER - MARK)) packets were selected after the sweep" >&2
    FAIL=1
  fi
fi

# The checkpoint (docs/design.md's restart wall, the other half): the same
# restart, with -checkpoint. The second controller is given the first one's
# journal, so it holds the session the SMF established -- the rules stay in the
# graph and the packets keep crossing, which the swept run above does not have --
# and it advertises the *same* Recovery Time Stamp, because that stamp moving is
# how an SMF learns its sessions are gone (TS 29.244 7.4.1). A node that kept
# the sessions and told the SMF otherwise would have it re-establish them into
# rules this node still holds, and every establishment would be refused for the
# key.
if [ "$FAIL" = 0 ]; then
  CP=$WORK/checkpoint
  CP1=$WORK/upfd-cp1.log
  CP2=$WORK/upfd-cp2.log
  # The run above is still serving the port; this phase is its own pair of
  # processes, so it starts from nothing.
  kill "$UPFD_PID" 2>/dev/null || true
  wait "$UPFD_PID" 2>/dev/null || true
  "$WORK/upfd" -n4 "127.0.0.1:$N4_PORT" -node-id 127.0.0.1 -bess "127.0.0.1:$BESS_PORT" \
    -fteid-address "endpoint=1,reference=n3,transport-domain=1,source=access,ipv4=$N3" -gtpu-decap decap0 -log-level info -checkpoint "$CP" >>"$CP1" 2>&1 &
  UPFD_PID=$!
  for _ in $(seq 1 20); do
    grep -q "n4 listening" "$CP1" 2>/dev/null && break
    sleep 0.25
  done
  if ! grep -q "n4 listening" "$CP1"; then
    echo "FAIL: the checkpointed run never listened; log follows" >&2
    cat "$CP1" >&2
    FAIL=1
  fi
  "$WORK/n4bench" -upf "127.0.0.1:$N4_PORT" -mode establish -sessions 1 -workers 1 \
    -fteid "$FTEID" -ue-pool "$UE/32" -gnb "$GNB" -n3 "$N3" -timeout 5s
  MARK=$(grep -c "packet dump" "$LOG" || true)
  sleep 1
  LIVE=$(grep -c "packet dump" "$LOG" || true)
  if [ "$LIVE" -gt "$MARK" ]; then
    echo "ok: the checkpointed run programmed a session the packets cross"
  else
    echo "FAIL: no packet crossed while the checkpointed run held the session" >&2
    FAIL=1
  fi
  STAMP1=$(grep "session checkpoint" "$CP1" | grep -o "recovery_time_stamp=[^ ]*" | head -1 | cut -d= -f2)

  kill "$UPFD_PID" 2>/dev/null || true
  wait "$UPFD_PID" 2>/dev/null || true
  "$WORK/upfd" -n4 "127.0.0.1:$N4_PORT" -node-id 127.0.0.1 -bess "127.0.0.1:$BESS_PORT" \
    -fteid-address "endpoint=1,reference=n3,transport-domain=1,source=access,ipv4=$N3" -gtpu-decap decap0 -log-level info -checkpoint "$CP" >>"$CP2" 2>&1 &
  UPFD_PID=$!
  for _ in $(seq 1 20); do
    grep -q "n4 listening" "$CP2" 2>/dev/null && break
    sleep 0.25
  done
  if ! grep -q "n4 listening" "$CP2"; then
    echo "FAIL: the restarted node never listened; log follows" >&2
    cat "$CP2" >&2
    FAIL=1
  fi
  if grep -q "checkpoint replayed" "$CP2" && grep -q "sessions=1" "$CP2"; then
    echo "ok: the restart replayed the checkpoint instead of sweeping it"
  else
    echo "FAIL: the restart did not replay the checkpoint; log follows" >&2
    cat "$CP2" >&2
    FAIL=1
  fi
  STAMP2=$(grep "session checkpoint" "$CP2" | grep -o "recovery_time_stamp=[^ ]*" | head -1 | cut -d= -f2)
  if [ -n "$STAMP1" ] && [ "$STAMP1" = "$STAMP2" ]; then
    echo "ok: the restarted node advertises the same Recovery Time Stamp ($STAMP1)"
  else
    echo "FAIL: the Recovery Time Stamp moved ($STAMP1 -> $STAMP2) while the sessions were kept" >&2
    FAIL=1
  fi
  # And the rules are the replayed ones: the Sources never stopped, and no SMF
  # message has been sent since the restart, so packets crossing now can only be
  # the journal's session selecting them.
  MARK=$(grep -c "packet dump" "$LOG" || true)
  sleep 2
  STILL=$(grep -c "packet dump" "$LOG" || true)
  if [ "$STILL" -gt "$MARK" ]; then
    echo "ok: the replayed session's rules still select the packets"
  else
    echo "FAIL: the replayed session selects nothing" >&2
    FAIL=1
  fi
  kill "$UPFD_PID" 2>/dev/null || true
  wait "$UPFD_PID" 2>/dev/null || true
fi

check_clean_shutdown "$BESSD_PID" || FAIL=1
if [ "$FAIL" = 0 ]; then
  echo "n4-path: ok (PFCP -> session -> packets, both ways, and across a restart)"
  # The work directory is the run's, not a result: a failed run keeps it (the
  # message above says where), a green one leaves nothing behind.
  rm -rf "$WORK"
else
  echo "n4-path: failed; logs are $WORK" >&2
fi
exit "$FAIL"
