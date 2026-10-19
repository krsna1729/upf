#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# The interface grammar's proof: deploy deploy/iface-path.yaml, drive it one
# window at a time (ci/ifacepath), and check every PFCP Source Interface and
# Destination Interface value this UPF serves against the exit its packet left
# by -- and every value it refuses against the cause the SMF reads.
#
# What the claim is: the value a PDI's Source Interface names puts the rule in
# the right chain (Access is the access side, and Core, the service LAN's
# interface and the 5G VN's internal interface are the side toward the
# subscriber, TS 29.244 8.2.2 Table 8.2.2-1), and the value a FAR's Destination
# Interface names chooses the egress (8.2.24 Table 8.2.24-1) from the
# deployment's own table: the data network's plain hop, the access side's
# (through the encap -- an uplink forward toward Access is indirect data
# forwarding, 8.2.2 NOTE 2), a tunnel out of the instance (N9), the service
# LAN's, or the 5G VN re-injection. Where the deployment declares no such
# egress, and for the values this UP does not serve at all, the establishment is
# refused with a cause that names the fault (73, or 66 for the IE Tables
# 7.5.2.3-1/7.5.2.3-2 make mandatory). A session's UE address is answered over
# ARP while the session lives, and not after it is deleted.
#
# Why windows rather than one run: every frame in this graph opens with the same
# MACs, so each window injects exactly the streams its case is about and the
# log is sliced between windows -- every check is the extracted bytes of exactly
# one Dump in exactly one window (ci/dumphex.sh's warning). The refusals are
# control-plane only, and the driver's own lines carry their causes.
#
# One driver process runs every arm, because a controller is long-lived and its
# id spaces are the deployment's: two processes would hand out SEID 1, action 1
# and meter 1 twice, and the second session would take the first one's records.
# The windows are separated by a handshake with the driver (files in $WORK), and
# the daemon runs under stdbuf -oL so the log the shell slices is the log the
# windows wrote. The driver's own output is one file: its lines name what each
# arm established, refused and holds.
#
#   ci/iface-path.sh                      # the main checkout's installed stage
#   STAGE=/some/prefix ci/iface-path.sh
#
# The plugin must be built first (see README.md); the script uses
# datapath/build/libupf_datapath.so unless PLUG says otherwise. The daemon runs
# with no hugepages (-m 0) and is never left running.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/ci/bess-env.sh"
PLUG=${PLUG:-$ROOT/datapath/build}
GRAPH=${GRAPH:-$ROOT/deploy/iface-path.yaml}
GO=${GO:-$(MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} mise which go 2>/dev/null || echo go)}

BESSD=$STAGE/bin/bessd
BESSCTL=$STAGE/bin/bessctl
mkdir -p "$ROOT/build/run"
WORK=$(mktemp -d "$ROOT/build/run/iface-path-XXXXXX")
LOG=$WORK/bessd.log
PIDFILE=$WORK/bessd.pid

[ -x "$BESSD" ] || { echo "iface-path: no bessd at $BESSD (set STAGE)" >&2; exit 1; }
[ -x "$BESSCTL" ] || { echo "iface-path: no bessctl at $BESSCTL (set STAGE)" >&2; exit 1; }
[ -f "$PLUG/libupf_datapath.so" ] || {
  echo "iface-path: build the plugin first: (cd datapath && ninja -C build)" >&2
  exit 1
}

export LD_LIBRARY_PATH=$STAGE/lib:$DPDK_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}

# stdbuf -oL: the daemon's stdout is a file here, and a block-buffered log
# would put a window's dump lines in the next window's slice.
stdbuf -oL -eL "$BESSD" -m 0 -skip_root_check -p "$BESS_PORT" -i "$PIDFILE" -modules="$PLUG" -f >"$LOG" 2>&1 &
DAEMON=$!
bc() { "$BESSCTL" -s "127.0.0.1:$BESS_PORT" "$@"; }
cleanup() {
  local status=$?
  if bc status >/dev/null 2>&1; then bc shutdown >/dev/null 2>&1 || true; fi
  kill "$DAEMON" 2>/dev/null || true
  wait "$DAEMON" 2>/dev/null || true
  if [ "$status" = 0 ]; then rm -rf "$WORK"; else
    echo "iface-path: exit $status; the run's files are in $WORK" >&2
  fi
  exit "$status"
}
trap cleanup EXIT

for _ in $(seq 1 30); do bc status >/dev/null 2>&1 && break; sleep 1; done
if ! bc status >/dev/null 2>&1; then
  echo "iface-path: the daemon did not come up; log follows" >&2
  cat "$LOG" >&2
  exit 1
fi

bc validate "$GRAPH" >/dev/null
bc apply "$GRAPH" >/dev/null
bc resume >/dev/null

# The driver's handshake: it writes <arm>.done when an arm is over and waits for
# <arm>.go before the next one, so the shell reads a window's dump lines -- which
# the Dumps write once a second -- before the next window's packets exist.
await() { # await <name>: wait for the driver's handshake file
  for _ in $(seq 1 600); do
    [ -e "$WORK/$1" ] && return 0
    if ! kill -0 "$DRIVER" 2>/dev/null; then
      # A driver that refused a message is gone, and its own line says which
      # one: waiting out the deadline would hide it behind a timeout.
      echo "iface-path: the driver stopped before it signalled $1; its output follows" >&2
      cat "$WORK/driver.log" >&2
      return 1
    fi
    sleep 0.1
  done
  echo "iface-path: the driver never signalled $1" >&2
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
    $GO run ./ci/ifacepath -target "$SERVER" -handshake "$WORK"
) >"$WORK/driver.log" 2>&1 &
DRIVER=$!

# window <name>: wait for the arm, read the daemon's log, let the next arm start.
window() {
  await "$1.done"
  sleep 2
  slice "$WORK/$1.log"
  : >"$WORK/$1.go"
}

window control
window egress
window down
window forward
window vn
window refuse
window arp
window gone

if ! wait "$DRIVER"; then
  echo "iface-path: the driver failed; its output follows" >&2
  tail -40 "$WORK/driver.log" >&2
  exit 1
fi

. "$ROOT/ci/dumphex.sh"
FAIL=0

contains() { # contains <description> <string> <fixed substring it must hold>
  if [ "${2#*"$3"}" != "$2" ]; then
    echo "ok: $1"
  else
    echo "FAIL: $1 (want $3)" >&2
    FAIL=1
  fi
}
absent() { # absent <description> <string> <fixed substring it must NOT hold>
  if [ "${2#*"$3"}" = "$2" ]; then
    echo "ok: $1"
  else
    echo "FAIL: $1 (found $3)" >&2
    FAIL=1
  fi
}
empty() { # empty <description> <string>
  if [ -z "$2" ]; then
    echo "ok: $1"
  else
    echo "FAIL: $1 (found bytes)" >&2
    FAIL=1
  fi
}

CTL_N6=$(dump_hex dump_n6 "$WORK/control.log")
CTL_N3=$(dump_hex dump_n3 "$WORK/control.log")
CTL_LAN=$(dump_hex dump_lan "$WORK/control.log")
CTL_ARP=$(dump_hex dump_arp "$WORK/control.log")
EG_N6=$(dump_hex dump_n6 "$WORK/egress.log")
EG_N3=$(dump_hex dump_n3 "$WORK/egress.log")
EG_LAN=$(dump_hex dump_lan "$WORK/egress.log")
DN_N6=$(dump_hex dump_n6 "$WORK/down.log")
DN_N3=$(dump_hex dump_n3 "$WORK/down.log")
FW_N6=$(dump_hex dump_n6 "$WORK/forward.log")
FW_N3=$(dump_hex dump_n3 "$WORK/forward.log")
VN_N6=$(dump_hex dump_n6 "$WORK/vn.log")
VN_N3=$(dump_hex dump_n3 "$WORK/vn.log")
REF_N6=$(dump_hex dump_n6 "$WORK/refuse.log")
ARP_N6=$(dump_hex dump_n6 "$WORK/arp.log")
ARP_ARP=$(dump_hex dump_arp "$WORK/arp.log")
GONE_N6=$(dump_hex dump_n6 "$WORK/gone.log")
GONE_ARP=$(dump_hex dump_arp "$WORK/gone.log")
DRIVER=$(cat "$WORK/driver.log")

# --- the control arm: no session, every stream stopped ----------------------
empty "control: nothing left by any exit" "$CTL_N6$CTL_N3$CTL_LAN$CTL_ARP"
contains "control: the deployment declares five next hops" \
      "$DRIVER" "rt/next_hops"
contains "control: the interface's own ARP entry is the deployment's" \
      "$DRIVER" '{"192.0.2.2":"02:00:00:00:06:01"}'

# --- Source Interface Access, Destination Interface Core, no outer header ---
# S1's uplink packet leaves by hop 1, the instance's plain egress, and the
# Router has written that hop's L2 pair into the frame (BESS D-153).
contains "egress: the uplink packet left by the data network's exit" \
      "$EG_N6" "0a 2d 00 02 08 08 08 08"
contains "egress: it carries that exit's L2 pair" \
      "$EG_N6" "02 00 00 00 06 02 02 00 00 00 06 01"
# Destination Interface Core with an outer header: a tunnel out of the instance
# (N9), through the encap, carrying the FAR's own TEID.
contains "egress: a tunnel out of the instance left through the encap" \
      "$EG_N3" "55 66 77 82"
contains "egress: the tunneled frame holds that session's packet" \
      "$EG_N3" "0a 2d 00 03 08 08 08 08"
# Destination Interface SGi-LAN/N6-LAN, with its Forwarding Policy: the service
# LAN's own exit and L2 pair.
contains "egress: the service-LAN forward left by the service LAN's exit" \
      "$EG_LAN" "0a 2d 00 04 08 08 08 08"
contains "egress: it carries the service LAN's L2 pair" \
      "$EG_LAN" "02 00 00 00 0c 02 02 00 00 00 0c 01"
contains "egress: the session's UE address is answered over ARP" \
      "$DRIVER" "the responder holds 10.45.0.2 -> 02:00:00:00:06:01"

# --- a subscriber-side PDR forwarding to Core -------------------------------
# The data network's frame is matched on the Core side and leaves by the
# instance's plain hop: the frame the interface received, rewritten with hop 1's
# L2 pair, and nothing through the encap.
contains "down: the data network's frame left by the data network's exit" \
      "$DN_N6" "08 08 08 08 0a 2d 00 07"
contains "down: it carries that exit's L2 pair" \
      "$DN_N6" "02 00 00 00 06 02 02 00 00 00 06 01"
empty "down: a plain forward added no outer header" "$DN_N3"

# --- an uplink forward toward the access side (indirect forwarding) ---------
contains "forward: the indirect forward left through the encap" \
      "$FW_N3" "55 aa 55 aa"
contains "forward: it carries the session's own packet" \
      "$FW_N3" "0a 2d 00 02 08 08 08 08"
empty "forward: it did not leave by the data network's exit" "$FW_N6"

# --- 5G VN Internal, both steps ---------------------------------------------
# S4's uplink packet is re-injected into the subscriber-side table, where S5
# takes it and tunnels it to the target UE's gNB: the TEID is S5's own.
contains "vn: the re-injected packet left toward the target UE's gNB" \
      "$VN_N3" "55 66 77 89"
contains "vn: the frame is the one S4's UE sent to S5's UE" \
      "$VN_N3" "0a 2d 00 05 0a 2d 00 06"
empty "vn: the re-injection did not leave by the data network's exit" "$VN_N6"

# --- the refusals -----------------------------------------------------------
# Each is the cause the SMF reads, named by the driver; the controller's own
# line (the driver's log) names the value or the IE.
empty "refuse: no refused establishment wrote a frame" "$REF_N6"
# The plan's four probes for this lane: with -access-next-hop ignored, the
# indirect forward takes the uplink direction's hop and the 'forward' window
# fails above; with direction() back to its old mapping, Src 2 flows into the
# uplink chain and the downlink-key checks above fail; with the Forwarding
# Policy requirement dropped, the refusal below disappears; with the ARP entries
# not written, the 'arp' window's reply and the entry line above disappear.
contains "refused: Source Interface 3 (CP-function), cause 73" \
      "$DRIVER" "refused: Source Interface 3 (CP-function): cause 73"
contains "refused: Source Interface 5 (Spare), cause 73" \
      "$DRIVER" "refused: Source Interface 5 (a Spare value): cause 73"
contains "refused: Destination Interface 3 (CP-function), cause 73" \
      "$DRIVER" "refused: Destination Interface 3 (CP-function): cause 73"
contains "refused: Destination Interface 4 (LI Function), cause 73" \
      "$DRIVER" "refused: Destination Interface 4 (LI Function): cause 73"
contains "refused: Destination Interface 5 with no egress declared, cause 73" \
      "$DRIVER" "refused: Destination Interface 5 on an instance with no 5G VN egress: cause 73"
contains "refused: a forwarding FAR with no Forwarding Parameters, cause 66" \
      "$DRIVER" "refused: a forwarding FAR with no Forwarding Parameters: cause 66"
contains "refused: Forwarding Parameters with no Destination Interface, cause 66" \
      "$DRIVER" "refused: Forwarding Parameters with no Destination Interface: cause 66"
contains "refused: SGi-LAN/N6-LAN with no Forwarding Policy, cause 66" \
      "$DRIVER" "refused: SGi-LAN/N6-LAN with no Forwarding Policy: cause 66"
# And the controller's own lines, which name what the cause cannot.
contains "the CP-function Source Interface refusal names the value" \
      "$DRIVER" "the PDI's Source Interface value 3 is not one this UP serves"
contains "the LI Function refusal names the value" \
      "$DRIVER" "Destination Interface 4 (LI Function) is not one this UP serves"
contains "the missing Forwarding Parameters refusal names the IE and the table" \
      "$DRIVER" "the Forwarding Parameters IE is mandatory then (Table 7.5.2.3-1)"
contains "the missing Destination Interface refusal names the IE and the table" \
      "$DRIVER" "name no Destination Interface, which is mandatory (Table 7.5.2.3-2)"
contains "the missing Forwarding Policy refusal names the IE and the table" \
      "$DRIVER" "the Forwarding Policy IE is mandatory then (Table 7.5.2.3-2)"
contains "the undeclared-egress refusal names the destination interface" \
      "$DRIVER" "Destination Interface 5 (5G VN Internal)"

# --- the subscriber's ARP identity ------------------------------------------
# The reply's bytes: an ARP frame (0x0806), opcode 2 (a reply), sender MAC the
# interface's and sender address the session's UE.
contains "arp: the responder answered the request for the session's address" \
      "$ARP_ARP" "08 06 00 01 08 00 06 04 00 02"
contains "arp: the reply's sender is the interface's own MAC" \
      "$ARP_ARP" "02 00 00 00 06 01"
contains "arp: the reply's sender address is the session's UE address" \
      "$ARP_ARP" "0a 2d 00 02"
contains "arp: the reply left by the port's exit" \
      "$ARP_N6" "08 06 00 01 08 00 06 04 00 02"
contains "arp: the driver read the entry back from the daemon" \
      "$DRIVER" "the responder holds 10.45.0.2 -> 02:00:00:00:06:01"

# --- the entry goes with the session ----------------------------------------
empty "gone: the deleted session's address is not answered" "$GONE_ARP$GONE_N6"
GONE_HOLD=$(grep -o '^ifacepath: after the deletion .*' "$WORK/driver.log" || true)
absent "gone: the responder no longer holds the deleted session's address" \
       "$GONE_HOLD" "10.45.0.2"
contains "gone: the other sessions' entries survive" "$GONE_HOLD" "10.45.0.3"

# The daemon stops the way an operator would (SIGTERM), and a daemon that aborts
# on teardown has freed something it should not have.
check_clean_shutdown "$DAEMON" || FAIL=1

if [ "$FAIL" = 0 ]; then
  echo "iface-path: every Source and Destination Interface value served (or refused) with its own egress"
  rm -rf "$WORK"
fi
exit "$FAIL"
