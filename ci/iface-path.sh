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
# ARP while the session lives, and not after it is deleted. One session's two
# uplink PDRs -- a general port-53 filter and a specific destination -- send
# their frames out of two different exits (ULCL: the data network's hop and an
# N9 tunnel) on the session's one TEID, and the remote PSA's downlink arrives on
# that session's N9 F-TEID and leaves toward the gNB.
# Mode 4 (S11, an I-UPF between an I-UPF and the PSA: TS 23.502 4.3.5.4 step
# 6) is one transit window per direction: each arrives on an N9 F-TEID and
# leaves through a tunnel sourced from the N9 endpoint, which the 3GPP
# Interface Type selects (TS 29.244 8.2.118). The N19 windows run the 5G VN
# group-level session (S12, TS 23.502 4.13.8.2.2) beside its members: the
# other PSA's member reaches S5's UE over N19, and S4's UE reaches it back.
# The m6_* windows run Mode 6, an N2 handover with the intermediate UPF
# re-allocated and indirect forwarding (TS 23.502 4.9.1.3), with this UP as
# the source I-UPF of S10 and the target I-UPF of S13: the steady legs, S13's
# downlink dropped until step 8a, the forwarding tunnels of steps 11b and 11d
# on the F-TEIDs the UP chose (the driver rewrites the two streams' frames to
# them), the switch, the old path's End Markers (step 10b: each one sent to
# S10's N9 or forwarding F-TEID, S13's forwarding F-TEID or S11's N9 downlink
# F-TEID leaves relayed through that rule's tunnel, with its TEID), and --
# after the SMF's timer -- 13a and 15a, after which nothing S10 or a
# forwarding F-TEID admitted leaves and S13 still does. The stand-in SMF
# sends every message over PFCP; there is no RAN or N2 here.
# The `concurrent` window adds Mode 3 (a PSA receiving N9: the uplink arrives on
# an N9 F-TEID carrying the same TEID S1 holds on N3, and leaves by N6) and then
# holds every Release 16 scenario this UP serves -- Modes 1 to 5, N19, and
# Mode 6 between the switch and the timer -- with every stream running at
# once: each session's own bytes must leave by its own exit and by no other.
#
# Why windows rather than one run: every frame in this graph opens with the same
# MACs, so each window injects exactly the streams its case is about and the
# log is sliced between windows -- every check is the extracted bytes of exactly
# one Dump in exactly one window (ci/dumphex.sh's warning). The concurrent window
# is the exception by design: its streams share the Dumps, each Dump prints one
# packet a second, and so the window stays open until every session's bytes
# have been printed. The refusals are control-plane only, and the driver's own
# lines carry their causes.
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
# with no hugepages (--mem_backing=normal) and is never left running.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/ci/bess-env.sh"
PLUG=${PLUG:-$ROOT/datapath/build}
GRAPH=${GRAPH:-$ROOT/deploy/iface-path.yaml}
GO=${GO:-$(MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} mise which go 2>/dev/null || echo go)}

BESSCTL=$STAGE/bin/bessctl
mkdir -p "$ROOT/build/run"
WORK=$(mktemp -d "$ROOT/build/run/iface-path-XXXXXX")
LOG=$WORK/bessd.log
PIDFILE=$WORK/bessd.pid

BESSD_STDBUF=1 bessd_start "$LOG" "$PIDFILE" || exit 1
bc() { "$BESSCTL" -s "$SERVER" "$@"; }
cleanup() {
  local status=$?
  bessd_stop
  if [ "$status" = 0 ]; then rm -rf "$WORK"; else
    echo "iface-path: exit $status; the run's files are in $WORK" >&2
  fi
  exit "$status"
}
trap cleanup EXIT

if ! bessd_wait 30 1; then
  echo "iface-path: the daemon did not come up; log follows" >&2
  cat "$LOG" >&2
  exit 1
fi

# The graph's unix sockets live in this run's directory: BESS unlinks a path
# when it binds, so a fixed one would be taken by another run's daemon.
RENDERED=$WORK/iface-path.yaml
sed "s|/tmp/upf-iface-path-|$WORK/|" "$GRAPH" >"$RENDERED"
bc validate "$RENDERED" >/dev/null
bessd_apply "$RENDERED"

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
slice_more() { # slice_more <file>: append the log written since the last slice
  # The concurrent window slices while the Dumps write: the size is read first,
  # so a line written after it is the next slice's rather than nobody's.
  local size
  size=$(wc -c <"$LOG")
  head -c "$size" "$LOG" | tail -c +$((OFFSET + 1)) >>"$1"
  OFFSET=$size
}

(
  cd "$ROOT"
  MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} GOWORK=off \
    $GO run ./ci/ifacepath -target "$SERVER" -handshake "$WORK" -sockets "$WORK/"
) >"$WORK/driver.log" 2>&1 &
DRIVER=$!

# window <name>: wait for the arm, read the daemon's log, let the next arm start.
window() {
  await "$1.done"
  sleep 2
  slice "$WORK/$1.log"
  : >"$WORK/$1.go"
}

. "$ROOT/ci/dumphex.sh"

# Each concurrent session's own bytes, by the Dump its exit feeds: the data
# network's (dump_n6) for Mode 1's uplink, Mode 2's local branch, Mode 3's N9
# arrival and S6's subscriber-side forward; the encap's (dump_n3) for Mode 1's
# downlink, Mode 2's N9 branch and its remote PSA's downlink, Mode 4's two
# directions, Mode 5's re-injected packet, N19's two, and Mode 6's: S13's
# uplink, and the downlink to S13's and S10's UEs (S13's switched leg and both
# forwarding tunnels). Each holds the inner source and destination; the TEIDs
# tell the legs that carry one inner packet apart.
CONCURRENT_N6=(
  "0a 2d 00 02 08 08 08 08" # Mode 1 uplink (S1)
  "0a 2d 00 08 08 08 08 08" # Mode 2 local PSA branch (S8)
  "0a 2d 00 09 08 08 08 08" # Mode 3 N9 arrival (S9)
  "08 08 08 08 0a 2d 00 07" # S6, the service LAN's interface to Core
)
CONCURRENT_N3=(
  "08 08 08 08 0a 2d 00 02" # Mode 1 downlink (S1)
  "0a 2d 00 08 0a 2e 00 02" # Mode 2 N9 branch (S8)
  "0a 2e 00 02 0a 2d 00 08" # Mode 2 remote PSA's downlink (S8)
  "0a 2d 00 0b 08 08 08 08" # Mode 4 uplink, to the PSA (S11)
  "08 08 08 08 0a 2d 00 0b" # Mode 4 downlink, to the upstream I-UPF (S11)
  "0a 2d 00 05 0a 2d 00 06" # Mode 5, S4's UE to S5's (S5's tunnel)
  "0a 2d 09 02 0a 2d 00 06" # N19 in: the other PSA's member to S5's UE
  "0a 2d 00 05 0a 2d 09 02" # N19 out: S4's UE to the other PSA's member
  "0a 2d 00 0d 08 08 08 08" # Mode 6 target I-UPF uplink (S13)
  "08 08 08 08 0a 2d 00 0d" # Mode 6 downlink to S13's UE
  "08 08 08 08 0a 2d 00 0a" # Mode 6 downlink to S10's UE, forwarded
)
# The TEIDs the encap wrote: Mode 1's, Mode 2's, Mode 4's both ways, Mode 5's
# (S5's: the re-injection and the N19 arrival), N19's, and Mode 6's S13 uplink,
# switched downlink and the two forwarding tunnels.
CONCURRENT_TEIDS=(
  "55 66 77 81" "55 66 77 88" "55 66 77 8c" "55 66 77 8d" "55 66 77 89"
  "55 66 77 8e" "55 66 77 90" "55 66 77 91" "55 aa 55 aa" "55 aa 55 ab"
)
concurrent_seen() { # every concurrent signature is in the window's slice so far
  local n6 n3 sig
  n6=$(dump_hex dump_n6 "$WORK/concurrent.log")
  n3=$(dump_hex dump_n3 "$WORK/concurrent.log")
  for sig in "${CONCURRENT_N6[@]}"; do [ "${n6#*"$sig"}" != "$n6" ] || return 1; done
  for sig in "${CONCURRENT_N3[@]}" "${CONCURRENT_TEIDS[@]}"; do
    [ "${n3#*"$sig"}" != "$n3" ] || return 1
  done
}
# The concurrent window: the streams run until each session's bytes have been
# printed, bounded below the driver's own 60-second wait for the go file. Then
# the driver stops them and the Dumps' last lines join the same slice, so the
# next window starts quiet.
concurrent_window() {
  await concurrent.done
  : >"$WORK/concurrent.log"
  for _ in $(seq 1 45); do
    sleep 1
    slice_more "$WORK/concurrent.log"
    concurrent_seen && break
  done
  : >"$WORK/concurrent.go"
  await concurrent_stop.done
  sleep 2
  slice_more "$WORK/concurrent.log"
  : >"$WORK/concurrent_stop.go"
}

window control
window egress
window ulcl
window ulcl_n9_down
window down
window mode1_down
window vn
window transit_up
window transit_down
window n19_in
window n19_out
window m6_source_up
window m6_source_down
window m6_target_up
window m6_held
window m6_forward_source
window m6_forward_target
window m6_switched
window m6_end_markers
concurrent_window
window m6_released
window m6_target_kept
window refuse
window arp
window gone

if ! wait "$DRIVER"; then
  echo "iface-path: the driver failed; its output follows" >&2
  tail -40 "$WORK/driver.log" >&2
  exit 1
fi

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
UL_N6=$(dump_hex dump_n6 "$WORK/ulcl.log")
UL_N3=$(dump_hex dump_n3 "$WORK/ulcl.log")
UD9_N6=$(dump_hex dump_n6 "$WORK/ulcl_n9_down.log")
UD9_N3=$(dump_hex dump_n3 "$WORK/ulcl_n9_down.log")
DN_N6=$(dump_hex dump_n6 "$WORK/down.log")
DN_N3=$(dump_hex dump_n3 "$WORK/down.log")
M1D_N6=$(dump_hex dump_n6 "$WORK/mode1_down.log")
M1D_N3=$(dump_hex dump_n3 "$WORK/mode1_down.log")
# The Mode 4, N19 and Mode 6 windows' Dumps, read by window name.
n3_of() { dump_hex dump_n3 "$WORK/$1.log"; }
n6_of() { dump_hex dump_n6 "$WORK/$1.log"; }
VN_N6=$(dump_hex dump_n6 "$WORK/vn.log")
VN_N3=$(dump_hex dump_n3 "$WORK/vn.log")
CC_N6=$(dump_hex dump_n6 "$WORK/concurrent.log")
CC_N3=$(dump_hex dump_n3 "$WORK/concurrent.log")
CC_LAN=$(dump_hex dump_lan "$WORK/concurrent.log")
CC_ARP=$(dump_hex dump_arp "$WORK/concurrent.log")
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
# ULCL: one session, one TEID, two uplink PDRs. The general port-53 filter
# matches both destinations; the specific 10.46.0.2 filter has the higher
# precedence, so that frame takes the N9 branch while 8.8.8.8 takes the data
# network's plain hop.
contains "ulcl: the general destination left by the data network's exit" \
      "$UL_N6" "0a 2d 00 08 08 08 08 08"
contains "ulcl: the specific destination left by the N9 tunnel" \
      "$UL_N3" "0a 2d 00 08 0a 2e 00 02"
contains "ulcl: the N9 tunnel carries the branch's own TEID" \
      "$UL_N3" "55 66 77 88"
# Mode 2's other direction: the remote PSA's downlink arrives on S8's N9 F-TEID
# (endpoint 2) and leaves through the encap toward the gNB, with S8's own
# downlink TEID, and nothing of it leaves by the data network's exit.
contains "ulcl_n9_down: the remote PSA's downlink left toward the gNB" \
      "$UD9_N3" "0a 2e 00 02 0a 2d 00 08"
contains "ulcl_n9_down: it carries S8's downlink TEID" \
      "$UD9_N3" "55 66 77 88"
empty "ulcl_n9_down: nothing left by the data network's exit" "$UD9_N6"
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
# S6's PDI names Source Interface 2 (the service LAN's interface), so the rule
# that matches this frame is the proof that the value lands on the subscriber
# side: before that, a rule with this PDI went to the uplink chain and matched
# nothing.
contains "down: the data network's frame left by the data network's exit" \
      "$DN_N6" "08 08 08 08 0a 2d 00 07"
contains "down: it carries that exit's L2 pair" \
      "$DN_N6" "02 00 00 00 06 02 02 00 00 00 06 01"
empty "down: a plain forward added no outer header" "$DN_N3"
# Mode 1's downlink: the data network's answer to S1's UE leaves through the
# encap with S1's own downlink TEID.
contains "mode1_down: the answer to S1's UE left toward its gNB" \
      "$M1D_N3" "08 08 08 08 0a 2d 00 02"
contains "mode1_down: it carries S1's downlink TEID" \
      "$M1D_N3" "55 66 77 81"
empty "mode1_down: nothing left by the data network's exit" "$M1D_N6"

# --- 5G VN Internal, both steps ---------------------------------------------
# S4's uplink packet is re-injected into the subscriber-side table, where S5
# takes it and tunnels it to the target UE's gNB: the TEID is S5's own.
contains "vn: the re-injected packet left toward the target UE's gNB" \
      "$VN_N3" "55 66 77 89"
contains "vn: the frame is the one S4's UE sent to S5's UE" \
      "$VN_N3" "0a 2d 00 05 0a 2d 00 06"
empty "vn: the re-injection did not leave by the data network's exit" "$VN_N6"

# --- Mode 4: an I-UPF between an I-UPF and the PSA ---------------------------
# Both legs are N9 (TS 23.502 4.3.5.4 step 6): the uplink arrives on S11's N9
# F-TEID (Source Interface Access, typed N9) and leaves through a tunnel to the
# PSA; the PSA's downlink arrives on its other N9 F-TEID and leaves toward the
# upstream I-UPF (Destination Interface Access, typed N9). Each tunnel is
# sourced from the N9 endpoint (192.0.2.9) to the peer 10.20.30.9: the
# downlink one without the type would be the RAN's N3 (192.0.2.1).
T_UP=$(n3_of transit_up)
T_DN=$(n3_of transit_down)
contains "transit_up: the uplink left through the tunnel to the PSA" "$T_UP" "55 66 77 8c"
contains "transit_up: it is the upstream I-UPF's packet" "$T_UP" "0a 2d 00 0b 08 08 08 08"
contains "transit_up: the tunnel is sourced from the N9 endpoint" "$T_UP" "c0 00 02 09 0a 14 1e 09"
empty "transit_up: nothing left by the data network's exit" "$(n6_of transit_up)"
contains "transit_down: the downlink left through the tunnel to the upstream I-UPF" "$T_DN" "55 66 77 8d"
contains "transit_down: it is the PSA's packet" "$T_DN" "08 08 08 08 0a 2d 00 0b"
contains "transit_down: the tunnel is sourced from the N9 endpoint" "$T_DN" "c0 00 02 09 0a 14 1e 09"
absent "transit_down: not from the N3 endpoint" "$T_DN" "c0 00 02 01 0a 14 1e 09"
empty "transit_down: nothing left by the data network's exit" "$(n6_of transit_down)"

# --- N19: the 5G VN group-level session -------------------------------------
# S12's N19 PDR takes the other PSA's packet on its N19 F-TEID and re-injects
# it into the 5G VN's classification, where S5's 5G VN Internal PDR tunnels it
# to S5's gNB; S4's packet to the member the other PSA anchors is re-injected
# the same way and S12's 5G VN Internal PDR tunnels it over N19, from the N9
# endpoint.
N19_IN=$(n3_of n19_in)
N19_OUT=$(n3_of n19_out)
contains "n19_in: the other PSA's member reached S5's gNB" "$N19_IN" "55 66 77 89"
contains "n19_in: it is the member's packet to S5's UE" "$N19_IN" "0a 2d 09 02 0a 2d 00 06"
empty "n19_in: nothing left by the data network's exit" "$(n6_of n19_in)"
contains "n19_out: S4's packet left over N19" "$N19_OUT" "55 66 77 8e"
contains "n19_out: it is S4's UE to the other PSA's member" "$N19_OUT" "0a 2d 00 05 0a 2d 09 02"
contains "n19_out: the N19 tunnel is sourced from the N9 endpoint" "$N19_OUT" "c0 00 02 09 0a 14 1e 09"
empty "n19_out: nothing left by the data network's exit" "$(n6_of n19_out)"

# --- Mode 6: indirect data forwarding, UPF re-allocated ---------------------
contains "m6_source_up: S10's uplink left through its tunnel to the PSA" \
      "$(n3_of m6_source_up)" "55 66 77 8f"
contains "m6_source_down: the PSA's downlink to S10 left toward the source RAN" \
      "$(n3_of m6_source_down)" "55 66 77 8b"
contains "m6_target_up: S13's uplink left through its tunnel to the PSA" \
      "$(n3_of m6_target_up)" "55 66 77 90"
empty "m6_held: S13's downlink is dropped until step 8a" "$(n3_of m6_held)$(n6_of m6_held)"
# Steps 11b and 11d: each forwarding PDR's F-TEID is one the UP chose, on the
# N3 endpoint (typed N3 for data forwarding); the stream's frame was rewritten
# to it, and what it admitted left through the forwarding tunnel.
M6_11B=$(grep -o 'Mode 6 11b: .*' "$WORK/driver.log" || true)
M6_11D=$(grep -o 'Mode 6 11d: .*' "$WORK/driver.log" || true)
contains "m6: the target UPF chose its forwarding F-TEID on the N3 endpoint" "$M6_11B" "the UP chose F-TEID 0x"
contains "m6: ... on 192.0.2.1" "$M6_11B" "on 192.0.2.1"
contains "m6: the source UPF chose its forwarding F-TEID on the N3 endpoint" "$M6_11D" "the UP chose F-TEID 0x"
contains "m6: ... on 192.0.2.1" "$M6_11D" "on 192.0.2.1"
FWD_S=$(n3_of m6_forward_source)
FWD_T=$(n3_of m6_forward_target)
contains "m6_forward_source: the forwarded downlink left toward the target UPF" "$FWD_S" "55 aa 55 aa"
contains "m6_forward_source: it is the downlink to S10's UE" "$FWD_S" "08 08 08 08 0a 2d 00 0a"
empty "m6_forward_source: nothing left by the data network's exit" "$(n6_of m6_forward_source)"
contains "m6_forward_target: the forwarded downlink left toward the target RAN" "$FWD_T" "55 aa 55 ab"
contains "m6_forward_target: it is the downlink to S13's UE" "$FWD_T" "08 08 08 08 0a 2d 00 0d"
empty "m6_forward_target: nothing left by the data network's exit" "$(n6_of m6_forward_target)"
contains "m6_switched: after step 8a S13's downlink left toward the target RAN" \
      "$(n3_of m6_switched)" "55 66 77 91"
# After the timer: 13a released S10 and 15a S13's forwarding PDR and FAR.
contains "m6: the driver released S10 (13a) and S13's forwarding resources (15a)" \
      "$DRIVER" "Mode 6: timer expired; S10 released (13a), S13's forwarding PDR and FAR removed (15a)"
empty "m6_released: nothing S10 or a forwarding F-TEID admitted left" \
      "$(n3_of m6_released)$(n6_of m6_released)"
contains "m6_target_kept: S13's downlink still left toward the target RAN" \
      "$(n3_of m6_target_kept)" "55 66 77 91"

# --- Mode 6 and transit: the old path's End Markers, relayed ---------------
# TS 23.502 4.9.1.3.3 step 10b: the PSA's End Marker reaches S10 (the source
# I-UPF) on its N9 F-TEID and leaves toward the source RAN; the source RAN's
# reaches S10's forwarding F-TEID and leaves toward the target UPF, whose
# forwarding F-TEID (S13's) sends it on to the target RAN; and S11 (Mode 4)
# relays the PSA's over N9 toward the upstream I-UPF (TS 29.244 Table
# 8.2.64-1 NOTE 2). Each leaves with the outgoing tunnel's TEID, from that
# tunnel's local endpoint, to its peer: 30 fe is version 1 and type 254, the
# length is 0. S1's uplink ends at N6, so the one on its F-TEID is recorded and
# relayed nowhere. The driver required exact counts: every marker reached the
# responder, the four relays left decap0's gate 3 through the relay queue, and
# none a Router exit.
EM=$(dump_hex dump_em "$WORK/m6_end_markers.log")
contains "m6_end_markers: the driver counted every marker and every relay" \
      "$DRIVER" "m6_end_markers: 5 End Markers received, 4 relayed through their tunnels, 0 by a Router exit"
contains "m6_end_markers: the PSA's marker left S10 toward the source RAN" \
      "$EM" "c0 00 02 01 0a 14 1e 09 08 68 08 68 00 10 00 00 30 fe 00 00 55 66 77 8b"
contains "m6_end_markers: the source RAN's marker left S10's forwarding tunnel toward the target UPF" \
      "$EM" "c0 00 02 01 0a 14 1e 09 08 68 08 68 00 10 00 00 30 fe 00 00 55 aa 55 aa"
contains "m6_end_markers: the source UPF's marker left S13's forwarding tunnel toward the target RAN" \
      "$EM" "c0 00 02 01 0a 14 1e 09 08 68 08 68 00 10 00 00 30 fe 00 00 55 aa 55 ab"
contains "m6_end_markers: Mode 4 relayed the PSA's marker over N9 toward the upstream I-UPF" \
      "$EM" "c0 00 02 09 0a 14 1e 09 08 68 08 68 00 10 00 00 30 fe 00 00 55 66 77 8d"
absent "m6_end_markers: S1's marker, which ends at N6, was not relayed" "$EM" "30 fe 00 00 11 22 33 44"
absent "m6_end_markers: no marker left with the TEID it arrived on" "$EM" "30 fe 00 00 11 22 33 51"
empty "m6_end_markers: nothing left by a session exit" \
      "$(n3_of m6_end_markers)$(n6_of m6_end_markers)"

# --- every scenario at once -------------------------------------------------
# Modes 1 to 5, the N19 group session, S6 and Mode 6 between the switch and
# the timer are established together and every stream runs at once. The
# driver required each scenario exit's Router gate to move and the service
# LAN's and the responder's not to; here each session's own bytes must be in
# the Dump its exit feeds and in no other.
contains "concurrent: every scenario's Router exit moved with all sessions live" \
      "$DRIVER" "concurrent: every scenario's exit moved with all sessions live"
for sig in "${CONCURRENT_N6[@]}"; do
  contains "concurrent: $sig left by the data network's exit" "$CC_N6" "$sig"
  absent "concurrent: $sig did not leave through the encap" "$CC_N3" "$sig"
done
for sig in "${CONCURRENT_N3[@]}"; do
  contains "concurrent: $sig left through the encap" "$CC_N3" "$sig"
  absent "concurrent: $sig did not leave by the data network's exit" "$CC_N6" "$sig"
done
# Mode 3's arrival rode S1's TEID on the other endpoint: S9 took it, and so
# did S1 on N3 (its uplink bytes above), each by its own admission key.
contains "concurrent: Mode 3's N9 F-TEID is S1's TEID on endpoint 2" \
      "$DRIVER" "established: S9: PSA receiving N9, forwarding to N6"
for teid in "${CONCURRENT_TEIDS[@]}"; do
  contains "concurrent: the encap carried TEID $teid" "$CC_N3" "$teid"
done
empty "concurrent: nothing left by the service LAN's exit or the responder" "$CC_LAN$CC_ARP"

# --- the refusals -----------------------------------------------------------
# Each is the cause the SMF reads, named by the driver; the controller's own
# line (the driver's log) names the value or the IE.
empty "refuse: no refused establishment wrote a frame" "$REF_N6"
# The plan's four probes for this lane: with -access-next-hop ignored, the
# forwarding tunnels (an uplink-chain PDR whose FAR names Access) take the
# uplink direction's hop and the m6_forward_* windows fail above; with
# direction() back to its old mapping, Src 2 flows into the
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
# One session's two addresses ride one transaction, and their hashes collide in
# the responder's table: the readback must hold both, the second must be
# answered over ARP too (its reply carries 10.44.0.2 as the sender address, a
# byte string no request in this window produces), and both must go with the
# session.
contains "arp: both addresses of one transaction are held" \
      "$DRIVER" "one transaction published both entries: 10.44.0.2 and 10.46.0.2"
contains "arp: the pair's second address was answered too" \
      "$ARP_ARP" "0a 2c 00 02"
contains "arp: both addresses went with the session" \
      "$DRIVER" "one transaction erased both entries: 10.44.0.2 and 10.46.0.2"

# --- the entry goes with the session ----------------------------------------
empty "gone: the deleted session's address is not answered" "$GONE_ARP$GONE_N6"
GONE_HOLD=$(grep -o '^ifacepath: after the deletion .*' "$WORK/driver.log" || true)
absent "gone: the responder no longer holds the deleted session's address" \
       "$GONE_HOLD" "10.45.0.2"
contains "gone: the other sessions' entries survive" "$GONE_HOLD" "10.45.0.3"

# The daemon stops the way an operator would (SIGTERM), and a daemon that aborts
# on teardown has freed something it should not have.
check_clean_shutdown "$BESSD_PID" || FAIL=1

if [ "$FAIL" = 0 ]; then
  echo "iface-path: every Source and Destination Interface value served (or refused) with its own egress"
  rm -rf "$WORK"
fi
exit "$FAIL"
