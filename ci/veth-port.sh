#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# The N3/N6/N9 port, on a veth: one PMD port with four queues, split by a `Vif`
# into the three reference points, each with its own address and its own route
# domain -- what docs/design.md's port section describes and what a NIC would
# otherwise be needed to show. The graph is deploy/veth-port.yaml; this script
# puts it on a kernel veth (the af_packet PMD), sends traffic at each interface
# and at the port, and checks what came back:
#
#   - the port's queue count, from two independent views: bessctl's (the
#     runtime PortInfo and the active pipeline) and DPDK's own (the ethdev
#     telemetry, which is the device talking, not BESS);
#   - each interface's gate: three frames, three destination MACs, three gates,
#     and the three gates' counts are exactly the frames sent;
#   - the per-queue spread: many flows, all four QueueIncs moving;
#   - the compiler's rule selected per domain: upfd establishes a session
#     against this daemon with the instance the manifest serves, the compiler
#     writes its downlink rule into the graph's pdr_dl -- whose key carries the
#     route domain the Vif writes -- and the session's own frame, sent from the
#     N6 interface, is selected by it. Before the rule exists the same frame is
#     dropped; the compiler's own test for two instances -- two rules for one
#     filter, one per domain -- runs too.
#
#   ci/veth-port.sh
#   STAGE=/some/prefix ci/veth-port.sh
#
# bessd binds the port through the af_packet PMD, which opens a raw socket, so
# this script starts it under sudo (passwordless on this host). It creates the
# veth if it is not there and DELETES IT AT THE END -- including a pair it found
# already present, which is the same furniture and this script's only user -- so
# nothing of the port is left behind; the daemon is stopped the way
# ci/buffer-path.sh stops its own, and its log is kept when the run fails.
#
# The plugin must be built first (see README.md); the script uses
# datapath/build/libupf_datapath.so unless PLUG says otherwise.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/ci/bess-env.sh"
# DPDK's own telemetry client, which talks to the daemon's device, not to BESS.
DPDK_TELEMETRY=${DPDK_TELEMETRY:-$(dirname "$(dirname "$DPDK_LIB")")/usertools/dpdk-telemetry.py}
PLUG=${PLUG:-$ROOT/datapath/build}
GRAPH=${GRAPH:-$ROOT/deploy/veth-port.yaml}
GO=${GO:-$(MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} mise which go 2>/dev/null || echo go)}

VETH=${VETH:-upfv0}
VETH_PEER=${VETH_PEER:-upfv1}
QUEUES=${QUEUES:-4}
# What the manifest says, so this script knows where to send and what to look
# for. A graph is data and a script is code; every arm repeats the values its
# graph carries (ci/n4-path.sh's FTEID/UE/GNB do the same). The veth's peer
# holds an address in the interfaces' subnet, and the frames go out from it.
NET=${NET:-192.0.2}
HOST_ADDR=${HOST_ADDR:-192.0.2.2/24}
N3_IP=${NET}.101; N3_MAC=02:00:00:00:01:01
N9_IP=${NET}.102; N9_MAC=02:00:00:00:02:02
N6_IP=${NET}.103; N6_MAC=02:00:00:00:03:03
N6_DOMAIN=${N6_DOMAIN:-3}
# The session the compiler is given, and the frame its downlink rule selects:
# one instance, the N6 interface's, and a UDP datagram to the UE's DNS port --
# the filter n4sim's establishment carries ("permit out udp from any to
# assigned 53"). ci/n4-path.sh's values are the same, because it is the same
# compiler writing the same shape.
UE=${UE:-10.45.0.2}
N3_ADDR=${N3_ADDR:-192.0.2.1}
FTEID=${FTEID:-0x11223344}
GNB=${GNB:-10.20.30.2}
# The per-queue spread's flows: this many distinct destinations.
SPREAD_FIRST=${SPREAD_FIRST:-200}
SPREAD_COUNT=${SPREAD_COUNT:-40}
PINGS=${PINGS:-3}

BESSD=$STAGE/bin/bessd
BESSCTL=$STAGE/bin/bessctl

WORK=$(mktemp -d /tmp/upf-veth-port-XXXXXX)
LOG=$WORK/bessd.log
UPFD_LOG=$WORK/upfd.log
BESSD_PID=
UPFD_PID=

bc() { "$BESSCTL" -s "127.0.0.1:$BESS_PORT" "$@"; }

# stop_bessd ends the daemon this script started, and only then is the run
# over: the RPC is what stops it (it runs as root under this script, so the pid
# this shell holds is sudo's, not the daemon's), the pidfile is the fallback for
# a daemon that outlived that, and SIGKILL is the last resort. A daemon left
# behind holds the port and the veth the next run wants.
stop_bessd() {
  if bc status >/dev/null 2>&1; then
    bc shutdown >/dev/null 2>&1 || true
  fi
  if [ -n "$BESSD_PID" ]; then
    for _ in $(seq 1 50); do
      kill -0 "$BESSD_PID" 2>/dev/null || break
      sleep 0.1
    done
    kill -9 "$BESSD_PID" 2>/dev/null || true
  fi
  if [ -f "$WORK/bessd.pid" ]; then
    # The pid file carries a trailing NUL, so it is stripped rather than read
    # raw (the same warning ci/buffer-path.sh fixes).
    sudo kill -9 "$(tr -d '\000' <"$WORK/bessd.pid")" 2>/dev/null || true
  fi
}

cleanup() {
  local status=$?
  [ -n "$UPFD_PID" ] && kill "$UPFD_PID" 2>/dev/null || true
  stop_bessd
  # The veth pair goes with the run: the port's side is what bessd binds, the
  # peer is where this script sends from, and the addresses, routes and
  # neighbours this script put on them leave with the interfaces. A pair that
  # was already here is deleted too -- leaving either half would be the state
  # this arm exists to avoid.
  sudo ip link del "$VETH" 2>/dev/null || true
  if [ "$status" = 0 ]; then
    rm -rf "$WORK"
  else
    echo "veth-port: exit $status; the daemon's log is $LOG and the controller's is $UPFD_LOG" >&2
  fi
  exit "$status"
}
trap cleanup EXIT

[ -x "$BESSD" ] || { echo "veth-port: no bessd at $BESSD (set STAGE)" >&2; exit 1; }
[ -x "$BESSCTL" ] || { echo "veth-port: no bessctl at $BESSCTL (set STAGE)" >&2; exit 1; }
[ -f "$PLUG/libupf_datapath.so" ] || {
  echo "veth-port: build the plugin first: (cd datapath && ninja -C build)" >&2
  exit 1
}
[ -f "$DPDK_TELEMETRY" ] || {
  echo "veth-port: no DPDK telemetry client at $DPDK_TELEMETRY (set DPDK_TELEMETRY)" >&2
  exit 1
}

# The veth, before the daemon: the PMD probes iface=upfv0 at apply time, so the
# interface must exist and be up. Its queues are the kernel's; the PMD's are
# `qpairs=` in the manifest, which is why the two are checked separately below.
if ip link show "$VETH" >/dev/null 2>&1; then
  echo "veth-port: using the $VETH/$VETH_PEER pair already here"
else
  echo "veth-port: creating the $VETH/$VETH_PEER pair ($QUEUES queues each)"
  sudo ip link add "$VETH" type veth peer name "$VETH_PEER" \
    numrxqueues "$QUEUES" numtxqueues "$QUEUES"
fi
# The host's own IPv6 chatter on the pair -- duplicate address detection and
# router solicitations for the two ends' link-local addresses -- is not this
# arm's traffic, and being multicast it lands on the Vif's default gate, where
# the check below reads a zero. The arm is IPv4: the interfaces' IPv6 is turned
# off before they come up, so none of it is ever generated. A host with no IPv6
# has nothing to turn off, and the setting lives on the interfaces, which this
# script deletes.
sudo sysctl -qw "net.ipv6.conf.$VETH.disable_ipv6=1" "net.ipv6.conf.$VETH_PEER.disable_ipv6=1" || true
sudo ip link set "$VETH" up
sudo ip link set "$VETH_PEER" up
if ! ip -o -4 addr show dev "$VETH_PEER" | grep -q -w "${HOST_ADDR%/*}"; then
  sudo ip addr add "$HOST_ADDR" dev "$VETH_PEER"
fi
# The session's UE is nowhere on-link, so the frame that carries the session's
# downlink tuple needs a route to it through the peer and a permanent neighbour
# pointing at the interface whose domain is the rule's key.
sudo ip route replace "$UE" dev "$VETH_PEER"
sudo ip neigh replace "$UE" lladdr "$N6_MAC" dev "$VETH_PEER" nud permanent

export LD_LIBRARY_PATH=$STAGE/lib:$DPDK_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}

sudo -E env LD_LIBRARY_PATH="$LD_LIBRARY_PATH" \
  "$BESSD" -m 0 -p "$BESS_PORT" -i "$WORK/bessd.pid" -modules="$PLUG" -f >"$LOG" 2>&1 &
BESSD_PID=$!

for _ in $(seq 1 60); do bc status >/dev/null 2>&1 && break; sleep 0.5; done
if ! bc status >/dev/null 2>&1; then
  echo "veth-port: the daemon did not come up; log follows" >&2
  cat "$LOG" >&2
  exit 1
fi

bc validate "$GRAPH" >/dev/null
bc apply "$GRAPH" >/dev/null
# A pipeline's workers start paused, and a paused worker counts nothing: until
# this runs, the port's rx stays 0 while the veth's own counters climb.
bc resume >/dev/null
# What the kernel queued before the PMD started is read now, not when it
# arrived; the counters below are this script's traffic, so they are read after
# the port has drained.
sleep 1

bc status >"$WORK/status.txt"
bc get -o json >"$WORK/pipeline.json" 2>/dev/null
printf '/ethdev/info,0\n' |
  sudo -E env PYTHONDONTWRITEBYTECODE=1 python3 "$DPDK_TELEMETRY" >"$WORK/telemetry.json" 2>/dev/null

FAIL=0
check() { # check <description> <fixed string it must contain> <file>
  # The string is matched as one (-F): an unquoted bracket in it is a bracket
  # expression to grep otherwise, and JSON is full of brackets.
  if grep -q -F -- "$2" "$3"; then
    echo "ok: $1"
  else
    echo "FAIL: $1 (no '$2' in $3)" >&2
    FAIL=1
  fi
}

gate_packets() { # gate_packets <module> <gate>: the packets that output gate counted
  bc metrics 2>/dev/null | grep '^bess_gate_packets_total{' |
    grep -F "module=\"$1\"" | grep -F "gate=\"$2\"" | awk '{print $2; exit}' || true
}

wait_gate() { # wait_gate <module> <gate> <at least>: that gate's count, once it is there
  local v=0
  for _ in $(seq 1 60); do
    v=$(gate_packets "$1" "$2")
    [ "${v:-0}" -ge "$3" ] && break
    sleep 0.05
  done
  echo "${v:-0}"
}

nonzero() { # nonzero <description> <count>
  if [ "${2:-0}" -gt 0 ] 2>/dev/null; then
    echo "ok: $1 ($2)"
  else
    echo "FAIL: $1 (counted ${2:-0})" >&2
    FAIL=1
  fi
}

# --- the port and its queue count -------------------------------------------
# Two views, and they are independent: bessctl reads the pipeline and the
# runtime PortInfo BESS built from the driver; the telemetry reads the device's
# own ethdev. The PMD takes its queue count from the vdev string's `qpairs=`,
# not from the veth's numrxqueues, so the kernel's numbers are not the claim.
check "the port and its queues (bessctl status)" "upf_port driver PMDPort rx 4 tx 4" "$WORK/status.txt"
check "the pipeline's port declares four receive queues" '"num_rx_queues": 4' "$WORK/pipeline.json"
check "the pipeline's port declares four transmit queues" '"num_tx_queues": 4' "$WORK/pipeline.json"
check "the device has four receive queues (DPDK telemetry)" '"nb_rx_queues": 4' "$WORK/telemetry.json"
check "the device's four receive queues are started" '"rxq_state": [1, 1, 1, 1]' "$WORK/telemetry.json"
check "the device's four transmit queues are started" '"txq_state": [1, 1, 1, 1]' "$WORK/telemetry.json"
# Not a claim about this port: the af_packet PMD advertises no RSS capability
# and there is no key or RETA to program, so ethdev_rss_hf is 0. That is what
# docs/design.md's placement measurement needs a NIC for; it is checked here so
# the arm says which of the two it is running on.
check "the device advertises no RSS hash to configure" '"ethdev_rss_hf": "0x0"' "$WORK/telemetry.json"
# The three interfaces are the manifest's, and the traffic below depends on
# their MACs: read back what the daemon accepted.
check "the Vif declares the N3 interface" "$N3_MAC" "$WORK/pipeline.json"
check "the Vif declares the N9 interface" "$N9_MAC" "$WORK/pipeline.json"
check "the Vif declares the N6 interface" "$N6_MAC" "$WORK/pipeline.json"
# The downlink PDR's key carries the route domain: this is the field the Vif
# fills in, and the field the compiler below keys a rule on.
check "the downlink PDR key declares the route domain" '"attr_name": "route_domain"' "$WORK/pipeline.json"

# --- traffic: three interfaces, then the spread ------------------------------
# Each interface's address is sent to with a permanent neighbour pointing at its
# MAC, so the frame's destination MAC is what names the interface (that is how
# the Vif classifies). Nothing replies -- the graph has no rules yet, so the
# frames die at the PDR table's default gate -- and that is the point: what
# moves is the Vif's own gate.
send_to() { # send_to <address> <mac> <pings>
  sudo ip neigh replace "$1" lladdr "$2" dev "$VETH_PEER" nud permanent
  ping -c "$3" -W 0.2 -I "$VETH_PEER" "$1" >/dev/null 2>&1 || true
}
send_to "$N3_IP" "$N3_MAC" "$PINGS"
send_to "$N9_IP" "$N9_MAC" "$PINGS"
send_to "$N6_IP" "$N6_MAC" "$PINGS"

# The counts are exact, not positive: every frame this script addressed to an
# interface went to that interface's gate, and no frame went to two gates. The
# default gate is not compared: the host's own multicast on the address the
# peer holds (mDNS from 192.0.2.2:5353 to 224.0.0.251, seen in this graph)
# names no interface's MAC and belongs there.
check_count() { # check_count <description> <count> <want>
  if [ "${2:-0}" = "$3" ]; then
    echo "ok: $1 ($2)"
  else
    echo "FAIL: $1 (counted ${2:-0}, want $3)" >&2
    FAIL=1
  fi
}
check_count "N3's interface took the frames addressed to it (Vif gate 1)" "$(wait_gate vif 1 "$PINGS")" "$PINGS"
check_count "N9's interface took the frames addressed to it (Vif gate 2)" "$(wait_gate vif 2 "$PINGS")" "$PINGS"
check_count "N6's interface took the frames addressed to it (Vif gate 3)" "$(wait_gate vif 3 "$PINGS")" "$PINGS"

# The spread: many distinct flows, one destination each, addressed to the port
# itself (so the Vif sends them to its default gate and the QueueIncs are what
# is being read). af_packet's fanout_mode=hash puts one flow on one queue, so
# four queues that all move is the per-queue spread the port offers here.
PORT_MAC=$(cat "/sys/class/net/$VETH/address")
before0=$(gate_packets inc0 0); before1=$(gate_packets inc1 0)
before2=$(gate_packets inc2 0); before3=$(gate_packets inc3 0)
before0=${before0:-0}; before1=${before1:-0}; before2=${before2:-0}; before3=${before3:-0}
for i in $(seq "$SPREAD_FIRST" $((SPREAD_FIRST + SPREAD_COUNT - 1))); do
  sudo ip neigh replace "$NET.$i" lladdr "$PORT_MAC" dev "$VETH_PEER" nud permanent
done
for i in $(seq "$SPREAD_FIRST" $((SPREAD_FIRST + SPREAD_COUNT - 1))); do
  ping -c 1 -W 0.2 -I "$VETH_PEER" "$NET.$i" >/dev/null 2>&1 || true
done
wait_gate inc0 0 "$(( before0 + 1 ))" >/dev/null
spread0=$(( $(gate_packets inc0 0) - before0 )); spread1=$(( $(gate_packets inc1 0) - before1 ))
spread2=$(( $(gate_packets inc2 0) - before2 )); spread3=$(( $(gate_packets inc3 0) - before3 ))
nonzero "the spread reached queue 0 (QueueInc inc0)" "$spread0"
nonzero "the spread reached queue 1 (QueueInc inc1)" "$spread1"
nonzero "the spread reached queue 2 (QueueInc inc2)" "$spread2"
nonzero "the spread reached queue 3 (QueueInc inc3)" "$spread3"

# --- the compiler's rule, selected per domain --------------------------------
# The frame the session's downlink PDR filters on: a UDP datagram to the UE's
# DNS port, from the host through the peer, so it arrives on the N6 interface
# and the Vif writes that interface's route domain into it.
send_downlink() { (exec 3<>"/dev/udp/$UE/53" && echo hi >&3) 2>/dev/null || true; }

# The control: the same frame, with no rule written yet. pdr_dl's default gate
# drops it, so the downlink chain's counter must not move -- which is what
# makes the same counter moving below mean the rule selected it.
send_downlink
if [ "$(wait_gate cnt_dl 0 1)" = "0" ]; then
  echo "ok: with no rule the session's downlink frame reached no chain (cnt_dl stayed 0)"
else
  echo "FAIL: the session's downlink frame crossed with no rule written (cnt_dl $(gate_packets cnt_dl 0))" >&2
  FAIL=1
fi

# upfd is the compiler's own driver on N4: the instance it is given is the N6
# interface's (the domain the manifest puts on that port), and the field lists
# mirror the manifest's tables. It and n4bench are built here the way
# ci/n4-path.sh builds them.
(cd "$ROOT" && $GO build -o "$WORK/upfd" ./cmd/upfd && $GO build -o "$WORK/n4bench" ./cmd/n4bench)
"$WORK/upfd" -n4 "127.0.0.1:$N4_PORT" -node-id 127.0.0.1 -bess "127.0.0.1:$BESS_PORT" \
  -n3-addr "$N3_ADDR" -max-domains 4 \
  -instances "name=n6,domain=$N6_DOMAIN,next-hop=1,pool=$UE/32" \
  -pdr-fields-ul src,dst,proto,sport,dport,teid,qfi \
  -pdr-fields-dl src,dst,proto,sport,dport,domain \
  -log-level info >"$UPFD_LOG" 2>&1 &
UPFD_PID=$!
for _ in $(seq 1 40); do
  grep -q 'n4 listening' "$UPFD_LOG" 2>/dev/null && break
  sleep 0.25
done
kill -0 "$UPFD_PID" 2>/dev/null || {
  echo "veth-port: upfd exited; log follows" >&2
  cat "$UPFD_LOG" >&2
  exit 1
}
"$WORK/n4bench" -upf "127.0.0.1:$N4_PORT" -mode establish -sessions 1 -workers 1 \
  -fteid "$FTEID" -ue-pool "$UE/32" -gnb "$GNB" -n3 "$N3_ADDR" -timeout 5s || {
  echo "veth-port: the establishment failed; upfd's log follows" >&2
  cat "$UPFD_LOG" >&2
  exit 1
}
bc get -o json >"$WORK/after.json" 2>/dev/null

# The rule the compiler wrote into the port's own downlink table, keyed on the
# route domain it resolved: the key's last value is the domain, big-endian, in
# the resource's base64 (3 is 00 00 00 03, "AAAAAw=="), and its mask is all
# ones. The block is cut out of the pipeline so a value from another resource
# cannot answer for it.
awk '/^    "pdr_dl\/rules":/{f=1} f&&/^    "/&&$0!~/pdr_dl\/rules/{exit} f{print}' \
  "$WORK/after.json" >"$WORK/pdr_dl_rule.json"
DOMAIN_B64=$(printf '\x00\x00\x00'"$(printf '\\%03o' "$N6_DOMAIN")" | base64)
check "the compiler wrote its downlink rule into the port graph" '"value_bin"' "$WORK/pdr_dl_rule.json"
check "the rule's key carries the N6 interface's route domain ($N6_DOMAIN)" \
  "\"value_bin\": \"$DOMAIN_B64\"" "$WORK/pdr_dl_rule.json"

# And the frame is selected: the same datagram that was dropped a moment ago
# now matches by the domain the Vif wrote, and crosses the downlink chain to
# the encap.
before_dl=$(gate_packets cnt_dl 0); before_dl=${before_dl:-0}
send_downlink
crossed=$(( $(wait_gate cnt_dl 0 "$(( before_dl + 1 ))") - before_dl ))
nonzero "the Vif's route domain selected the compiler's rule (cnt_dl moved)" "$crossed"
nonzero "the selected frame crossed the chain to the encap" "$(gate_packets enc 0)"

# The compiler's own test for what "per domain" means here: two instances that
# serve one prefix are two rules for one filter, each keyed on its own domain.
MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} \
  $GO test "$ROOT/internal/session/" -run '^TestTwoInstancesRouteIndependently$' -count=1 -v \
  >"$WORK/compiler.log" 2>&1 || {
  echo "veth-port: the compiler's per-domain test failed; output follows" >&2
  cat "$WORK/compiler.log" >&2
  exit 1
}
check "the compiler writes one rule per domain for one filter" \
  "--- PASS: TestTwoInstancesRouteIndependently" "$WORK/compiler.log"

# The evidence itself, so a run's output is the proof and not only the verdict:
# the port's own line, the device's own telemetry, and the rule the compiler
# wrote into the port's downlink table.
echo "veth-port: port    $(grep -F 'upf_port driver' "$WORK/status.txt")"
echo "veth-port: device  $(tr -d '\n' <"$WORK/telemetry.json")"
echo "veth-port: rule    $(tr -d '\n' <"$WORK/pdr_dl_rule.json")"

if [ "$FAIL" = 0 ]; then
  echo "veth-port: ok (one port, four queues, three interfaces with their own route domains, and the compiler's rule selected by one of them)"
fi
exit "$FAIL"
