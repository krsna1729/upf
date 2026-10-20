#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# The two-network-instance proof: deploy deploy/pdrmatch-2dn.yaml, drive it one
# window at a time (ci/pdrmatch2dn), and check each window's frames against the
# stream that produced them.
#
# What the claim is: two subscribers with the *same* address, one per data
# network (TS 23.501 5.6.12 NOTE 1's overlapping UE IP addresses assigned by
# multiple Data Networks). Both directions must reach each subscriber's own
# network: the downlink frame, addressed to the UE, is selected by the (route
# domain, UE address) key the graph declares and leaves in a G-PDU for that
# session's TEID; the uplink packet leaves by the exit its instance's next hop
# names -- N6 for the internet instance, the campus network's gate for campus.
#
# The uplink's Ethernet header is evidence too: each exit's hop carries its own
# L2 pair, which the Router writes into the frame it forwards (BESS D-153), so
# the two instances' uplink frames differ in both the exit they left by and
# their addresses. (The pair's own trap: the *downlink* G-PDU's outer header
# carries the N3 hop's addresses, so a byte check must name the Dump it read.)
#
# Why windows rather than one run: with both data networks' streams running at
# once, "both TEIDs appeared" would also pass if the two sessions' rules were
# swapped. Each window injects exactly one instance's streams and the log is
# sliced between windows, so every window says which stream produced which TEID
# and which exit -- and asserts the *absence* of the other instance's TEID, its
# exit, and its L2. The third window runs with *both* sessions live, so the
# internet instance's frame must still leave for the internet session's TEID
# while the campus session's rule holds the same UE address in another domain.
#
# One driver process runs all four arms, because a controller is long-lived and
# its id spaces are the deployment's: two processes would hand out SEID 1,
# action 1 and meter 1 twice, and the second session would take the first one's
# records. The windows are separated by a handshake with the driver (files in
# $WORK), and the daemon runs under stdbuf -oL so the log the shell slices is
# the log the windows wrote.
#
#   ci/pdrmatch-2dn.sh                    # the main checkout's installed stage
#   STAGE=/some/prefix ci/pdrmatch-2dn.sh
#
# The plugin must be built first (see README.md); the script uses
# datapath/build/libupf_datapath.so unless PLUG says otherwise. The daemon runs
# with no hugepages (-m 0) and is never left running.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/ci/bess-env.sh"
PLUG=${PLUG:-$ROOT/datapath/build}
GRAPH=${GRAPH:-$ROOT/deploy/pdrmatch-2dn.yaml}
GO=${GO:-$(MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} mise which go 2>/dev/null || echo go)}

BESSCTL=$STAGE/bin/bessctl
mkdir -p "$ROOT/build/run"
WORK=$(mktemp -d "$ROOT/build/run/pdrmatch-2dn-XXXXXX")
LOG=$WORK/bessd.log
PIDFILE=$WORK/bessd.pid

BESSD_STDBUF=1 bessd_start "$LOG" "$PIDFILE" || exit 1
bc() { "$BESSCTL" -s "$SERVER" "$@"; }
cleanup() {
  local status=$?
  bessd_stop
  if [ "$status" = 0 ]; then rm -rf "$WORK"; else
    echo "pdrmatch-2dn: exit $status; the run's files are in $WORK" >&2
  fi
  exit "$status"
}
trap cleanup EXIT

if ! bessd_wait 30 1; then
  echo "pdrmatch-2dn: the daemon did not come up; log follows" >&2
  cat "$LOG" >&2
  exit 1
fi

bc validate "$GRAPH" >/dev/null
bessd_apply "$GRAPH"

# The driver's handshake: it writes <arm>.done when an arm is over and waits for
# <arm>.go before the next one, so the shell reads a window's dump lines -- which
# the Dumps write once a second -- before the next window's packets exist.
await() { # await <name>: wait for the driver's handshake file
  for _ in $(seq 1 600); do
    [ -e "$WORK/$1" ] && return 0
    if ! kill -0 "$DRIVER" 2>/dev/null; then
      # A driver that refused a message is gone, and its own line says which
      # one: waiting out the deadline would hide it behind a timeout.
      echo "pdrmatch-2dn: the driver stopped before it signalled $1; its output follows" >&2
      cat "$WORK/driver.log" >&2
      return 1
    fi
    sleep 0.1
  done
  echo "pdrmatch-2dn: the driver never signalled $1" >&2
  return 1
}
OFFSET=0
slice() { # slice <file>: the log written since the last slice
  tail -c +$((OFFSET + 1)) "$LOG" >"$1"
  OFFSET=$(wc -c <"$LOG")
}

(
  cd "$ROOT"
  MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} GOWORK=off \
    $GO run ./ci/pdrmatch2dn -target "$SERVER" -handshake "$WORK"
) >"$WORK/driver.log" 2>&1 &
DRIVER=$!

await control.done
sleep 2
slice "$WORK/control.log"
: >"$WORK/control.go"

await a.done
sleep 2
slice "$WORK/a.log"
: >"$WORK/a.go"

await b.done
sleep 2
slice "$WORK/b.log"
: >"$WORK/b.go"

# The fourth arm: the N9 peer. The internet session's uplink is tunneled, the
# G-PDU is dumped before it is decapped, and the peer's campus-instance session
# owns that tunnel's TEID; its own instance's next hop takes the decapped
# packet to the campus exit.
await c.done
sleep 2
slice "$WORK/c.log"
: >"$WORK/c.go"
await peer.done
sleep 2
slice "$WORK/peer.log"

if ! wait "$DRIVER"; then
  echo "pdrmatch-2dn: the driver failed; its output follows" >&2
  cat "$WORK/driver.log" >&2
  exit 1
fi

. "$ROOT/ci/dumphex.sh"
FAIL=0
contains() { # contains <description> <string> <fixed substring it must hold>
  case "$2" in
    *"$3"*) echo "ok: $1" ;;
    *) echo "FAIL: $1 (no '$3')" >&2; FAIL=1 ;;
  esac
}
absent() { # absent <description> <string> <fixed substring it must NOT hold>
  case "$2" in
    *"$3"*) echo "FAIL: $1 ('$3' is present)" >&2; FAIL=1 ;;
    *) echo "ok: $1" ;;
  esac
}
empty() { # empty <description> <string>
  if [ -z "$(printf '%s' "$2" | tr -d ' ')" ]; then
    echo "ok: $1"
  else
    echo "FAIL: $1 (the dump holds '$2')" >&2
    FAIL=1
  fi
}

# Every frame in this graph opens with the same two MACs, so a byte check must
# name the dump it came from (ci/dumphex.sh's warning): each of these is the
# extracted bytes of exactly one Dump in exactly one window.
CTL_D=$(dump_hex dump_d "$WORK/control.log")
A_D=$(dump_hex dump_d "$WORK/a.log")
A_N6=$(dump_hex dump_n6 "$WORK/a.log")
A_N9=$(dump_hex dump_n9 "$WORK/a.log")
B_D=$(dump_hex dump_d "$WORK/b.log")
B_N6=$(dump_hex dump_n6 "$WORK/b.log")
B_N9=$(dump_hex dump_n9 "$WORK/b.log")
C_D=$(dump_hex dump_d "$WORK/c.log")
C_N6=$(dump_hex dump_n6 "$WORK/c.log")
C_N9=$(dump_hex dump_n9 "$WORK/c.log")
PEER_T=$(dump_hex dump_tunnel "$WORK/peer.log")
PEER_N6=$(dump_hex dump_n6 "$WORK/peer.log")
PEER_N9=$(dump_hex dump_n9 "$WORK/peer.log")

# --- the control arm: no session, every stream stopped ----------------------
empty "control: no downlink frame left for either data network" "$CTL_D"

# --- window A: the internet instance only -----------------------------------
# The downlink: the frame the internet interface's MAC was addressed to (src
# 8.8.8.8, dst the UE) leaves in a G-PDU for that session's TEID, and the
# campus TEID is nowhere in the window.
contains "A: the internet frame was selected, matched and encapsulated" \
      "$A_D" "08 08 08 08 0a 2d 00 02"
contains "A: the downlink G-PDU carries the internet session's TEID" "$A_D" "55 66 77 88"
absent "A: the campus session's TEID does not appear (its session does not exist yet)" \
      "$A_D" "55 66 77 89"
# The uplink: the internet session's packet leaves by N6 (the router's gate 0,
# where dump_n6 sits) and not by the campus exit, and the frame that left is
# this window's -- the UE's address to 8.8.8.8, "hello-upf" -- with the next
# hop's addresses written into it (deploy/pdrmatch-2dn.yaml hop 1; BESS D-153).
contains "A: the internet session's uplink left by the internet exit" \
      "$A_N6" "0a 2d 00 02 08 08 08 08"
contains "A: the frame that left is the uplink stream's" "$A_N6" "68 65 6c 6c 6f 2d 75 70 66"
contains "A: the frame carries the internet exit's L2 pair, not the tunnel's" \
      "$A_N6" "02 00 00 00 0a 02 02 00 00 00 0a 01"
empty "A: nothing left by the campus exit" "$A_N9"

# --- window B: the campus instance only, the same subscriber address --------
contains "B: the campus frame was selected, matched and encapsulated" \
      "$B_D" "08 08 08 08 0a 2d 00 02"
contains "B: the downlink G-PDU carries the campus session's TEID" "$B_D" "55 66 77 89"
absent "B: the internet session's TEID does not appear (its stream is stopped)" \
      "$B_D" "55 66 77 88"
contains "B: the campus session's uplink left by the campus exit" \
      "$B_N9" "0a 2d 00 02 08 08 08 08"
contains "B: the frame that left is the uplink stream's" "$B_N9" "68 65 6c 6c 6f 2d 75 70 66"
contains "B: the frame carries the campus exit's L2 pair" \
      "$B_N9" "02 00 00 00 0b 02 02 00 00 00 0b 01"
empty "B: nothing left by the internet exit" "$B_N6"

# --- window C: both sessions live, the internet instance's streams ----------
# The campus session exists now and its rule is keyed by the *same* UE address
# in the other route domain. The internet frame must still leave for the
# internet session's TEID: a graph whose key named only the address would have
# taken this frame for campus (and would have refused the campus establishment
# as a taken key, which window B already rules out).
contains "C: with both sessions live, the internet frame still leaves for the internet TEID" \
      "$C_D" "55 66 77 88"
absent "C: the campus session does not take the internet frame" "$C_D" "55 66 77 89"
contains "C: the internet instance's uplink still leaves by the internet exit" \
      "$C_N6" "0a 2d 00 02 08 08 08 08"
contains "C: with both sessions live it still carries the internet exit's L2 pair" \
      "$C_N6" "02 00 00 00 0a 02 02 00 00 00 0a 01"
empty "C: nothing left by the campus exit" "$C_N9"

# --- the N9 peer ------------------------------------------------------------
# The internet session's uplink FAR adds an outer header, so the frame leaves
# by hop 4 as a G-PDU for the peer's TEID (0x55667790). The peer decapsulates
# it, the TEID table names the peer's campus-instance session, and that
# session's FAR sends it to the campus exit -- the frame that leaves is the same
# inner packet with that exit's L2 pair. It must not also appear at the internet
# exit.
contains "peer: the N9 tunnel carried the peer's TEID" \
      "$PEER_T" "55 66 77 90"
contains "peer: the tunnel's inner packet is the session's" \
      "$PEER_T" "0a 2d 00 03 08 08 08 08"
contains "peer: the decapped packet left by the campus exit" \
      "$PEER_N9" "0a 2d 00 03 08 08 08 08"
contains "peer: it carries the campus exit's L2 pair" \
      "$PEER_N9" "02 00 00 00 0b 02 02 00 00 00 0b 01"
empty "peer: the tunneled packet did not leak to the internet exit" "$PEER_N6"

# The selector's rules, as the driver printed them from sel_dl/rules: one per
# session, keyed by the route domain the graph's Vif writes and the one UE
# address they share. The key is positional (ExactMatch renders each field as
# its bytes in base64), so the evidence is those bytes: 00 00 00 01 and
# 00 00 00 02 are the two domains, 0a 2d 00 02 is 10.45.0.2, the same in both.
contains "the selector holds a rule keyed by route domain 1 (the internet instance)" \
      "$(cat "$WORK/driver.log")" '"valueBin":"AAAAAQ=="'
contains "the selector holds a rule keyed by route domain 2 (the campus instance)" \
      "$(cat "$WORK/driver.log")" '"valueBin":"AAAAAg=="'
contains "both of the selector's keys name the one UE address the two sessions share" \
      "$(cat "$WORK/driver.log")" '"valueBin":"Ci0AAg=="'
contains "the campus session's rule names session 2, not the internet session's 1" \
      "$(cat "$WORK/driver.log")" '"actionId":2'

# The daemon stops the way an operator would (SIGTERM), and a daemon that aborts
# on teardown has freed something it should not have.
check_clean_shutdown "$BESSD_PID" || FAIL=1

if [ "$FAIL" = 0 ]; then
  echo "pdrmatch-2dn: both data networks' subscribers, both directions, one address, and the N9 peer"
  rm -rf "$WORK"
fi
exit "$FAIL"
