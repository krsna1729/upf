#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# Carry every Release 16 scenario this UP serves through every veth attachment
# layout: nine layouts of N3, N6 and N9 onto one to four promiscuous PMD ports
# (asserted once the PMDs run), each deployed as the production-shaped graph
# ci/vethlayout generates -- decap0, the PDR tables and chains, rt, enc and
# rt_transport behind the layout's ports -- and programmed by one compiler
# (vethlayout -drive) to which a stand-in SMF sends, over N4, the sessions of
# Modes 1 to 6 and the N19 group session (ci/scenario) before any packet is
# sent.
#
# Per layout, once both Routers have resolved their neighbors, every
# scenario's packets are sent on every attachment of the endpoint they arrive
# on -- G-PDUs to the endpoint's one local address over N3 or N9, plain UDP
# over N6 -- and each phase's counters must move by exactly the packets sent:
# route_check / route_check_n6 (the Vif's route domain picks decap0 or pdr_dl), decap0's
# uplink, downlink and unknown gates, endpoint_check (admission on the
# endpoint the attachment tags), rt's gates and enc. rt_transport's gate and
# the port's PortOut for the attachment each scenario egresses by must move
# by at least as many: the resolvers' ARP shares them. Mode 6's indirect
# forwarding procedure (the forwarding tunnels on F-TEIDs the UP chooses, the
# target's downlink switch, the old path's End Markers, the releases after the
# timer) runs between the phases, and every earlier phase is replayed after
# it, all remaining sessions still live: no later session or modification may
# have overwritten an earlier one. The End Markers -- sent to S10's N9 and
# forwarding F-TEIDs, S13's forwarding F-TEID, S11's N9 downlink F-TEID and
# S1's uplink F-TEID -- reach decap0's unknown/control gate and no chain;
# decap0's gate 3 relays them, and the host's sink must see each relayed
# exactly once per marker sent, with the outgoing tunnel's TEID from its local
# endpoint to its peer, and none for S1's, which ends at N6. A burst of
# G-PDUs and then an End Marker on S11's N9 downlink F-TEID must reach the
# host in that order, the relay last. A TEID no session admits reaches the
# unknown path and nothing else. The one-VLAN case gives N3 and N9 the same
# local address, and Mode 3's F-TEID is Mode 1's TEID: only the endpoint id
# tells the two admissions apart.
#
# The cases cover all five PMD partitions for one to three ports, alternate
# one-port L2 encodings, direct per-port endpoint tagging, and a four-port
# fan-in layout that attaches every logical endpoint to two ports (no port or
# attachment count is fixed in the lane or the driver):
#   one-mac, one-vlan, one-hybrid,
#   two-n3n9-n6, two-n3n6-n9, two-n6n9-n3,
#   three-vif, three-direct, four-fanin.
#
# The host side of every attachment is a veth peer (or a VLAN on one) holding
# the attachment's peer address. It reaches each local endpoint address and
# each subscriber address it sends to by a per-device /32 route and a
# permanent neighbor, so a send bound to one device leaves by that attachment
# whatever the others hold; it does not forward what the graph sends it, and a
# UDP socket on 2152 absorbs the tunnels the graph returns to it.
#
# ci/iface-path.sh exercises the PFCP Source/Destination Interface grammar and
# the scenarios concurrently on one synthetic graph; ci/veth-port.sh exercises
# upfd on one veth.
#
#   sudo -E ci/veth-layouts.sh
#   PINGS=5 sudo -E ci/veth-layouts.sh   # packets per attachment per phase

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/ci/bess-env.sh"
PLUG=${PLUG:-$ROOT/datapath/build}
GO=${GO:-$(MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} mise which go 2>/dev/null || echo go)}
BESSD=$STAGE/bin/bessd
BESSCTL=$STAGE/bin/bessctl
PINGS=${PINGS:-3}
[[ "$PINGS" =~ ^[1-9][0-9]*$ ]] || { echo "veth-layouts: PINGS must be a positive integer" >&2; exit 2; }
BURST=16 # the G-PDUs ahead of the End Marker in mode4_end_marker_order's burst

WORK=$(mktemp -d "${TMPDIR:-/tmp}/upf-veth-layouts-XXXXXX")
LOG=$WORK/bessd.log
BESSD_PID=
BESSD_STARTED=0
CURRENT_VETHS=()
VETHS=()
PEERS=()
PORTS=0

# One row per attachment of a logical endpoint (n3/n6/n9) to a PMD port; a
# layout may attach one endpoint to several ports. A_ROUTER/A_GATE are the
# Router gate that sends out of the attachment.
A_NAME=() A_PORT=() A_VLAN=() A_MAC=() A_IP=() A_SRC=() A_DEV=() A_ROUTER=() A_GATE=()
# The contract's other rows: each logical endpoint's local address, the
# attachment each scenario egress takes (by endpoint and peer host), and each
# phase's packets.
declare -A LOCAL EGRESS_EP EGRESS_HOST
P_PHASE=() P_EP=() P_KIND=() P_TEID=() P_SRC=() P_DST=() P_SPORT=() P_DPORT=()
R_IN=() R_TEID=() R_LOCAL=() R_LABEL=()
DRIVER_PID=
SINK_PID=
HS=

bc() { "$BESSCTL" -s "$SERVER" "$@"; }

stop_bessd() {
  [ "$BESSD_STARTED" = 1 ] || return 0
  if bc status >/dev/null 2>&1; then
    bc shutdown >/dev/null 2>&1 || true
  fi
  local rc=0 daemon_pid
  for _ in $(seq 1 50); do
    kill -0 "$BESSD_PID" 2>/dev/null || break
    sleep 0.1
  done
  if kill -0 "$BESSD_PID" 2>/dev/null; then
    if [ -f "$WORK/bessd.pid" ]; then
      daemon_pid=$(tr -d '\000' <"$WORK/bessd.pid")
      sudo kill -9 "$daemon_pid" 2>/dev/null || true
    fi
    kill -9 "$BESSD_PID" 2>/dev/null || true
  fi
  wait "$BESSD_PID" 2>/dev/null || rc=$?
  BESSD_STARTED=0
  BESSD_PID=
  rm -f "$WORK/bessd.pid"
  if [ "$rc" != 0 ]; then
    echo "veth-layouts: bessd exited with status $rc" >&2
    return 1
  fi
  echo "bessd shut down cleanly"
}

remove_veths() {
  local name
  for name in "${CURRENT_VETHS[@]}"; do
    sudo ip link del "$name" 2>/dev/null || true
  done
  CURRENT_VETHS=()
}

stop_helpers() { # the driver and the UDP sink, if they still run
  local pid
  for pid in "$DRIVER_PID" "$SINK_PID"; do
    [ -n "$pid" ] || continue
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  DRIVER_PID= SINK_PID=
}

cleanup() {
  local status=$?
  stop_helpers
  stop_bessd || true
  remove_veths
  if [ "$status" = 0 ]; then
    rm -rf "$WORK"
  else
    echo "veth-layouts: exit $status; graph and daemon log are in $WORK" >&2
  fi
  exit "$status"
}
trap cleanup EXIT

[ -x "$BESSD" ] || { echo "veth-layouts: no bessd at $BESSD (set STAGE)" >&2; exit 1; }
[ -x "$BESSCTL" ] || { echo "veth-layouts: no bessctl at $BESSCTL (set STAGE)" >&2; exit 1; }
[ -f "$PLUG/libupf_datapath.so" ] || {
  echo "veth-layouts: build the plugin first: ninja -C datapath/build" >&2
  exit 1
}
(cd "$ROOT" && GOWORK=off MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} \
  "$GO" build -o "$WORK/vethlayout" ./ci/vethlayout)

fail() {
  echo "FAIL: $*" >&2
  return 1
}

new_names() { # new_names <port count>
  local suffix i
  printf -v suffix '%05d' "$((BASHPID % 100000))"
  VETHS=() PEERS=()
  for ((i = 0; i < $1; i++)); do
    VETHS+=("upfl${suffix}$i")
    PEERS+=("upfp${suffix}$i")
  done
}

read_contract() {
  local kind f1 f2 f3 f4 f5 f6 f7 f8 f9 f10
  PORTS=0
  A_NAME=() A_PORT=() A_VLAN=() A_MAC=() A_IP=() A_SRC=() A_DEV=() A_ROUTER=() A_GATE=()
  LOCAL=() EGRESS_EP=() EGRESS_HOST=()
  P_PHASE=() P_EP=() P_KIND=() P_TEID=() P_SRC=() P_DST=() P_SPORT=() P_DPORT=()
  R_IN=() R_TEID=() R_LOCAL=() R_LABEL=()
  while IFS=$'\t' read -r kind f1 f2 f3 f4 f5 f6 f7 f8 f9 f10; do
    case "$kind" in
      ports) PORTS=$f1 ;;
      # endpoint <name> <port> <vlan> <mac> <ip> <domain> <id> <host> <router> <gate>
      endpoint)
        A_NAME+=("$f1") A_PORT+=("$f2") A_VLAN+=("$f3")
        A_MAC+=("$f4") A_IP+=("$f5") A_SRC+=("$f8") A_ROUTER+=("$f9") A_GATE+=("$f10")
        ;;
      local) LOCAL[$f1]=$f2 ;;
      egress) EGRESS_EP[$f1]=$f2 EGRESS_HOST[$f1]=$f3 ;;
      packet)
        P_PHASE+=("$f1") P_EP+=("$f2") P_KIND+=("$f3") P_TEID+=("$f4")
        P_SRC+=("$f5") P_DST+=("$f6") P_SPORT+=("$f7") P_DPORT+=("$f8")
        ;;
      # relay <arrival endpoint> <teid> <local endpoint> <egress label>
      relay) R_IN+=("$f1") R_TEID+=("$f2") R_LOCAL+=("$f3") R_LABEL+=("$f4") ;;
      # upfd rows are the same deployment as `upfd -config` flags: the driver
      # is the compiler here, and the rows are for a daemon run against the
      # same graph.
    esac
  done <"$WORK/contract.tsv"
  [ "$PORTS" = "${#VETHS[@]}" ] || fail "contract names $PORTS PMD ports, ${#VETHS[@]} were created"
}

# attachments <name>: how many ports the logical endpoint is attached to.
attachments() {
  local n=0 k
  for k in "${!A_NAME[@]}"; do [ "${A_NAME[$k]}" = "$1" ] && n=$((n + 1)); done
  echo "$n"
}

create_veths() {
  local i k dev vlan port base addr_key port_mac
  for ((i = 0; i < PORTS; i++)); do
    if ip link show "${VETHS[$i]}" >/dev/null 2>&1 || ip link show "${PEERS[$i]}" >/dev/null 2>&1; then
      fail "refusing to reuse existing interfaces ${VETHS[$i]}/${PEERS[$i]}"
    fi
    sudo ip link add "${VETHS[$i]}" type veth peer name "${PEERS[$i]}" numrxqueues 1 numtxqueues 1
    CURRENT_VETHS+=("${VETHS[$i]}")
    sudo sysctl -qw "net.ipv6.conf.${VETHS[$i]}.disable_ipv6=1" "net.ipv6.conf.${PEERS[$i]}.disable_ipv6=1" || true
    # The BESS-facing end receives frames addressed to the endpoints' MACs,
    # never its own: it must be promiscuous (asserted after the graph starts).
    sudo ip link set "${VETHS[$i]}" promisc on
    sudo ip link set "${VETHS[$i]}" up
    sudo ip link set "${PEERS[$i]}" up
  done

  declare -A created_devs configured_addrs
  for k in "${!A_NAME[@]}"; do
    port=${A_PORT[$k]}
    base=${PEERS[$port]}
    vlan=${A_VLAN[$k]}
    dev=$base
    if [ "$vlan" != 0 ]; then
      dev="$base.$vlan"
      if [ -z "${created_devs["$dev"]:-}" ]; then
        sudo ip link add link "$base" name "$dev" type vlan id "$vlan"
        # Slash-separated keys: a VLAN device's name has a dot in it.
        sudo sysctl -qw "net/ipv6/conf/$dev/disable_ipv6=1" || true
        sudo ip link set "$dev" up
        created_devs["$dev"]=1
      fi
    fi
    addr_key="${dev}:${A_SRC[$k]}"
    if [ -z "${configured_addrs["$addr_key"]:-}" ]; then
      sudo ip addr add "${A_SRC[$k]}/24" dev "$dev"
      configured_addrs["$addr_key"]=1
    fi
    A_DEV[$k]=$dev
    sudo ip neigh replace "${A_IP[$k]}" lladdr "${A_MAC[$k]}" dev "$dev" nud permanent
    # The host is a peer, not a router: what the graph sends it toward the
    # data network stops here.
    sudo sysctl -qw "net/ipv4/conf/$dev/forwarding=0"

    port_mac=$(cat "/sys/class/net/${VETHS[$port]}/address" | tr '[:upper:]' '[:lower:]')
    if [ "$port_mac" = "${A_MAC[$k]}" ]; then
      fail "${A_NAME[$k]}'s destination MAC equals PMD $port's MAC; promiscuous receive is not tested"
    fi
  done

  # The destinations the host sends to: each endpoint's one local address from
  # each of its N3/N9 attachments, and the subscribers the N6 phases address
  # from each N6 attachment. A /32 per device (distinct metrics, so they
  # coexist) and a permanent neighbor at the attachment's MAC make a send
  # bound to that device leave by that attachment.
  local r
  for k in "${!A_NAME[@]}"; do
    case "${A_NAME[$k]}" in
      n3 | n9) route_to "${LOCAL[${A_NAME[$k]}]}" "$k" ;;
      n6)
        for r in "${!P_PHASE[@]}"; do
          [ "${P_KIND[$r]}" = udp ] && route_to "${P_DST[$r]}" "$k"
        done
        ;;
    esac
  done
  return 0
}

route_to() { # route_to <address> <attachment>
  sudo ip route replace "$1/32" dev "${A_DEV[$2]}" metric "$((100 + $2))"
  sudo ip neigh replace "$1" lladdr "${A_MAC[$2]}" dev "${A_DEV[$2]}" nud permanent
}

# assert_promisc: every BESS-facing veth still carries PROMISC once the PMDs
# have started (a driver that cleared it would leave the endpoints' frames to
# the MAC filter).
assert_promisc() {
  local dev
  for dev in "${VETHS[@]}"; do
    if ip -o link show "$dev" | grep -q '[<,]PROMISC[,>]'; then
      echo "ok: $dev is promiscuous"
    else
      fail "$dev lost PROMISC: $(ip -o link show "$dev")"
    fi
  done
}

start_bessd() {
  if bc status >/dev/null 2>&1; then
    fail "another BESS daemon already answers at $SERVER"
  fi
  export LD_LIBRARY_PATH=$STAGE/lib:$DPDK_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
  sudo -E env LD_LIBRARY_PATH="$LD_LIBRARY_PATH" \
    "$BESSD" -m 0 -p "$BESS_PORT" -i "$WORK/bessd.pid" -modules="$PLUG" -f >"$LOG" 2>&1 &
  BESSD_PID=$!
  BESSD_STARTED=1
  for _ in $(seq 1 60); do
    bc status >/dev/null 2>&1 && return 0
    if ! kill -0 "$BESSD_PID" 2>/dev/null; then
      cat "$LOG" >&2
      fail "bessd exited before becoming ready"
    fi
    sleep 0.25
  done
  cat "$LOG" >&2
  fail "bessd did not become ready"
}

# snap <file>: every gate counter of the daemon at one moment, and each port's
# frames on the wire as module "wire": its peer veth's rx_packets, which counts
# every frame the port sent whatever its MAC. A PortOut has no output gate and
# its input gate no counter, so the wire is where a port's egress shows.
snap() {
  local i
  bc metrics 2>/dev/null | grep '^bess_gate_packets_total{' >"$1" || true
  for i in "${!PEERS[@]}"; do
    echo "wire{direction=\"in\",gate=\"$i\",module=\"wire\"} $(cat "/sys/class/net/${PEERS[$i]}/statistics/rx_packets")" >>"$1"
  done
}

# count_of <snapshot> <module> <gate> <in|out>
count_of() {
  local v
  v=$(awk -v m="module=\"$2\"" -v g="gate=\"$3\"" -v d="direction=\"$4\"" \
    'index($0, m) && index($0, g) && index($0, d) { print $2; exit }' "$1")
  printf '%.0f\n' "${v:-0}"
}

# send_phase <phase>: every packet row of the phase, on every attachment of its
# endpoint. The unknown TEID is one packet on the first N3 attachment. A TEID
# of @<name> is one the UP chose, which the driver wrote to teid-<name>.
send_phase() {
  local r k teid count=$PINGS
  [ "$1" = unknown ] && count=1
  for r in "${!P_PHASE[@]}"; do
    [ "${P_PHASE[$r]}" = "$1" ] || continue
    teid=${P_TEID[$r]}
    if [[ "$teid" == @* ]]; then
      teid=$(cat "$HS/teid-${teid#@}") || fail "the driver wrote no chosen TEID ${teid#@}"
    fi
    for k in "${!A_NAME[@]}"; do
      [ "${A_NAME[$k]}" = "${P_EP[$r]}" ] || continue
      if [ "${P_KIND[$r]}" = gpdu ]; then
        sudo "$WORK/vethlayout" -send-gpdu -device "${A_DEV[$k]}" -local "${A_SRC[$k]}" \
          -remote "${LOCAL[${P_EP[$r]}]}" -teid "$teid" -ue "${P_SRC[$r]}" \
          -dst "${P_DST[$r]}" -sport "${P_SPORT[$r]}" -dport "${P_DPORT[$r]}" -count "$count"
      elif [ "${P_KIND[$r]}" = em ]; then
        sudo "$WORK/vethlayout" -send-end-marker -device "${A_DEV[$k]}" -local "${A_SRC[$k]}" \
          -remote "${LOCAL[${P_EP[$r]}]}" -teid "$teid" -count "$count"
      elif [ "${P_KIND[$r]}" = burst ]; then
        sudo "$WORK/vethlayout" -send-burst -device "${A_DEV[$k]}" -local "${A_SRC[$k]}" \
          -remote "${LOCAL[${P_EP[$r]}]}" -teid "$teid" -ue "${P_SRC[$r]}" \
          -dst "${P_DST[$r]}" -sport "${P_SPORT[$r]}" -dport "${P_DPORT[$r]}" -count "$BURST"
      else
        sudo "$WORK/vethlayout" -send-udp -device "${A_DEV[$k]}" -local "${A_SRC[$k]}" \
          -dst "${P_DST[$r]}" -sport "${P_SPORT[$r]}" -dport "${P_DPORT[$r]}" -count "$count"
      fi
      [ "$1" = unknown ] && return 0
    done
  done
  return 0
}

# egress <label> <want>: the expectations on the attachment a scenario's egress
# takes: its Router gate and its port's PortOut, at least `want` (the
# resolvers' ARP shares both).
egress() {
  local k
  for k in "${!A_NAME[@]}"; do
    if [ "${A_NAME[$k]}" = "${EGRESS_EP[$1]}" ] && [ "${A_SRC[$k]}" = "${EGRESS_HOST[$1]}" ]; then
      echo "${A_ROUTER[$k]}/${A_GATE[$k]}/out>=$2 wire/${A_PORT[$k]}/in>=$2"
      return 0
    fi
  done
  # An expectation no gate can meet, so the phase that asked fails by name.
  echo "no_attachment_for_$1/0/out>=1"
  fail "the contract's $1 egress (${EGRESS_EP[$1]} to ${EGRESS_HOST[$1]}) names no attachment"
}

# delta <expectation>: parse module/gate/dir(=|>=)N and set E_NAME, E_OP,
# E_WANT and E_GOT, the gate's movement between before.prom and after.prom.
delta() {
  [[ "$1" =~ ^(([a-z0-9_]+)/([0-9]+)/(in|out))(=|>=)([0-9]+)$ ]] || fail "bad expectation $1"
  E_NAME=${BASH_REMATCH[1]} E_OP=${BASH_REMATCH[5]} E_WANT=${BASH_REMATCH[6]}
  E_GOT=$(($(count_of "$WORK/after.prom" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]}") -
    $(count_of "$WORK/before.prom" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]}")))
}

# phase <description> <packet phase> <expectation>...: send the phase's
# packets, wait until every expectation can hold, then require each one of
# the deltas: module/gate/dir=N exactly, module/gate/dir>=N at least.
phase() {
  local what=$1 sends=$2 e ready held
  shift 2
  snap "$WORK/before.prom"
  send_phase "$sends"
  for _ in $(seq 1 50); do
    snap "$WORK/after.prom"
    ready=1
    for e in "$@"; do
      delta "$e"
      [ "$E_GOT" -ge "$E_WANT" ] || { ready=0; break; }
    done
    [ "$ready" = 1 ] && break
    sleep 0.1
  done
  # A little longer, so a packet counted twice -- or by a gate that must not
  # move -- has had its time to show.
  sleep 0.3
  snap "$WORK/after.prom"
  for e in "$@"; do
    delta "$e"
    case "$E_OP" in
      "=") held=$((E_GOT == E_WANT)) ;;
      *) held=$((E_GOT >= E_WANT)) ;;
    esac
    if [ "$held" = 1 ]; then
      echo "ok: $LAYOUT $what: $E_NAME +$E_GOT (want $E_OP$E_WANT)"
    else
      fail "$LAYOUT $what: $E_NAME moved by $E_GOT, want $E_OP$E_WANT"
    fi
  done
}

# The scenario phases. A, B and C are the packets one phase sends over every
# N3, N9 and N6 attachment (attachments x PINGS). decap0 gates are 0 uplink, 1
# downlink, 2 unknown; rt gates are 0 N6, 1 access (enc), 2 N9 tunnel (enc), 4
# the 5G VN re-injection.
mode1_uplink() {
  phase "Mode 1 uplink (S1, every N3 attachment)" m1ul \
    route_check/1/out=$A decap0/0/out=$A decap0/1/out=0 decap0/2/out=0 \
    endpoint_check/1/out=$A endpoint_check/2/out=0 \
    rt/0/out=$A rt/1/out=0 rt/2/out=0 rt/4/out=0 enc/0/out=0 $(egress n6hop "$A")
}
mode1_downlink() {
  phase "Mode 1 downlink (S1's UE, every N6 attachment)" m1dl \
    route_check_n6/3/out=$C decap0/0/out=0 decap0/1/out=0 decap0/2/out=0 \
    rt/0/out=0 rt/1/out=$C rt/2/out=0 rt/4/out=0 enc/0/out=$C $(egress s1dl "$C")
}
mode2_uplink() {
  phase "Mode 2 UL CL (S8's two branches, every N3 attachment)" m2ul \
    route_check/1/out=$((2 * A)) decap0/0/out=$((2 * A)) decap0/1/out=0 decap0/2/out=0 \
    endpoint_check/1/out=$((2 * A)) \
    rt/0/out=$A rt/1/out=0 rt/2/out=$A rt/4/out=0 enc/0/out=$A \
    $(egress n6hop "$A") $(egress s8n9 "$A")
}
mode2_downlink() {
  phase "Mode 2 remote PSA downlink (S8's N9 F-TEID, every N9 attachment)" m2dl \
    route_check/2/out=$B decap0/0/out=0 decap0/1/out=$B decap0/2/out=0 \
    endpoint_check_dl/2/out=$B endpoint_check_dl/1/out=0 \
    rt/0/out=0 rt/1/out=$B rt/2/out=0 rt/4/out=0 enc/0/out=$B $(egress s8dl "$B")
}
mode3_uplink() {
  phase "Mode 3 N9 arrival (S9, S1's TEID on endpoint 2, every N9 attachment)" m3ul \
    route_check/2/out=$B decap0/0/out=$B decap0/1/out=0 decap0/2/out=0 \
    endpoint_check/2/out=$B endpoint_check/1/out=0 \
    rt/0/out=$B rt/1/out=0 rt/2/out=0 rt/4/out=0 enc/0/out=0 $(egress n6hop "$B")
}
mode3_downlink() {
  # Destination Interface Access typed N9: the access side's hop, through the
  # encap, sourced from the N9 endpoint toward the I-UPF.
  phase "Mode 3 downlink back over N9 (S9's UE, every N6 attachment)" m3dl \
    route_check_n6/3/out=$C decap0/0/out=0 decap0/1/out=0 decap0/2/out=0 \
    rt/0/out=0 rt/1/out=$C rt/2/out=0 rt/4/out=0 enc/0/out=$C $(egress s9dl "$C")
}
mode5() {
  phase "Mode 5 local switch (S4 to S5, every N3 attachment)" m5 \
    route_check/1/out=$A decap0/0/out=$A decap0/1/out=0 decap0/2/out=0 endpoint_check/1/out=$A \
    rt/0/out=0 rt/1/out=$A rt/2/out=0 rt/4/out=$A enc/0/out=$A $(egress s5dl "$A")
}
mode4_uplink() {
  phase "Mode 4 N9 transit uplink (S11 from the upstream I-UPF, every N9 attachment)" m4ul \
    route_check/2/out=$B decap0/0/out=$B decap0/1/out=0 decap0/2/out=0 \
    endpoint_check/2/out=$B endpoint_check/1/out=0 \
    rt/0/out=0 rt/1/out=0 rt/2/out=$B rt/4/out=0 enc/0/out=$B $(egress s11n9 "$B")
}
mode4_downlink() {
  phase "Mode 4 N9 transit downlink (S11 from the PSA, every N9 attachment)" m4dl \
    route_check/2/out=$B decap0/0/out=0 decap0/1/out=$B decap0/2/out=0 \
    endpoint_check_dl/2/out=$B endpoint_check_dl/1/out=0 \
    rt/0/out=0 rt/1/out=$B rt/2/out=0 rt/4/out=0 enc/0/out=$B $(egress s11dl "$B")
}
n19_in() {
  phase "N19 arrival (S12's N19 F-TEID to S5's UE, re-injected, every N9 attachment)" n19in \
    route_check/2/out=$B decap0/0/out=0 decap0/1/out=$B decap0/2/out=0 \
    endpoint_check_dl/2/out=$B endpoint_check_dl/1/out=0 \
    rt/0/out=0 rt/1/out=$B rt/2/out=0 rt/4/out=$B enc/0/out=$B $(egress s5dl "$B")
}
n19_out() {
  phase "N19 egress (S4's UE to the other PSA's member through S12, every N3 attachment)" n19out \
    route_check/1/out=$A decap0/0/out=$A decap0/1/out=0 decap0/2/out=0 endpoint_check/1/out=$A \
    rt/0/out=0 rt/1/out=0 rt/2/out=$A rt/4/out=$A enc/0/out=$A $(egress s12n19 "$A")
}
mode6_uplink() {
  phase "Mode 6 I-UPF uplinks (S10 and S13 to the PSA, every N3 attachment)" m6ul \
    route_check/1/out=$((2 * A)) decap0/0/out=$((2 * A)) decap0/1/out=0 decap0/2/out=0 \
    endpoint_check/1/out=$((2 * A)) \
    rt/0/out=0 rt/1/out=0 rt/2/out=$((2 * A)) rt/4/out=0 enc/0/out=$((2 * A)) $(egress s10n9 "$((2 * A))")
}
mode6_downlink() {
  phase "Mode 6 source downlink (S10's N9 F-TEID to the source RAN, every N9 attachment)" m6dl \
    route_check/2/out=$B decap0/1/out=$B decap0/2/out=0 endpoint_check_dl/2/out=$B \
    rt/0/out=0 rt/1/out=$B rt/2/out=0 rt/4/out=0 enc/0/out=$B $(egress s10dl "$B")
}
mode6_held() {
  phase "Mode 6 target downlink before 8a (S13's N9 F-TEID, dropped)" m6t \
    route_check/2/out=$B decap0/1/out=$B decap0/2/out=0 endpoint_check_dl/2/out=$B \
    rt/0/out=0 rt/1/out=0 rt/2/out=0 rt/4/out=0 enc/0/out=0
}
mode6_forward() {
  phase "Mode 6 indirect forwarding (S10's and S13's chosen F-TEIDs, every N3 attachment)" m6fwd \
    route_check/1/out=$((2 * A)) decap0/0/out=$((2 * A)) decap0/1/out=0 decap0/2/out=0 \
    endpoint_check/1/out=$((2 * A)) \
    rt/0/out=0 rt/1/out=$((2 * A)) rt/2/out=0 rt/4/out=0 enc/0/out=$((2 * A)) $(egress m6fwd "$((2 * A))")
}
mode6_switched() {
  phase "Mode 6 target downlink after 8a (S13's N9 F-TEID to the target RAN)" m6t \
    route_check/2/out=$B decap0/1/out=$B decap0/2/out=0 endpoint_check_dl/2/out=$B \
    rt/0/out=0 rt/1/out=$B rt/2/out=0 rt/4/out=0 enc/0/out=$B $(egress s13dl "$B")
}
mode6_released() {
  phase "Mode 6 after 13a and 15a (S10's and the forwarding F-TEIDs are unknown)" m6gone \
    decap0/2/out=$((3 * A + B)) decap0/0/out=0 decap0/1/out=0 \
    rt/0/out=0 rt/1/out=0 rt/2/out=0 rt/4/out=0 enc/0/out=0
}

# The old path's End Markers between the switch and the timer (TS 23.502
# 4.9.1.3.3 step 10b; TS 29.244 Table 8.2.64-1 NOTE 2): the PSA's on S10's N9
# F-TEID, the source RAN's and the source UPF's on the two forwarding
# F-TEIDs, the PSA's on S11's N9 downlink F-TEID, and one on S1's uplink
# F-TEID, whose FAR ends at N6. Each reaches the responder on decap0 gate 2
# and no session chain; decap0 relays every one but S1's out its gate 3,
# through em_relay and rt_transport onto the attachment its tunnel's peer is
# on.
mode6_end_markers() {
  local r ex=()
  for r in "${!R_IN[@]}"; do
    # shellcheck disable=SC2207 # egress prints two expectations
    ex+=($(egress "${R_LABEL[$r]}" "$(($(attachments "${R_IN[$r]}") * PINGS))"))
  done
  phase "Mode 6 and Mode 4 End Markers (every N3 and N9 attachment)" m6em \
    route_check/1/out=$((3 * A)) route_check/2/out=$((2 * B)) \
    decap0/0/out=0 decap0/1/out=0 decap0/2/out=$((3 * A + 2 * B)) \
    decap0/3/out=$((2 * A + 2 * B)) em_relay/0/out=$((2 * A + 2 * B)) \
    endpoint_check/1/out=0 endpoint_check/2/out=0 endpoint_check_dl/1/out=0 endpoint_check_dl/2/out=0 \
    rt/0/out=0 rt/1/out=0 rt/2/out=0 rt/4/out=0 enc/0/out=0 "${ex[@]}"
  relayed
}

# relayed: the host's sink saw each contract relay exactly once per End Marker
# sent -- the outgoing tunnel's TEID, from that tunnel's local endpoint, to
# its egress's peer -- and no End Marker from a local endpoint besides.
relayed() {
  local r line want got total expect=0
  for r in "${!R_IN[@]}"; do expect=$((expect + $(attachments "${R_IN[$r]}") * PINGS)); done
  from_local() {
    grep -F ' type 254 ' "$WORK/sink.log" | grep -cF -e " from ${LOCAL[n3]} to " -e " from ${LOCAL[n9]} to " || true
  }
  for _ in $(seq 1 50); do
    total=$(from_local)
    [ "$total" -ge "$expect" ] && break
    sleep 0.1
  done
  sleep 0.3
  for r in "${!R_IN[@]}"; do
    want=$(($(attachments "${R_IN[$r]}") * PINGS))
    line="vethlayout: sink: GTP-U type 254 TEID ${R_TEID[$r]} from ${LOCAL[${R_LOCAL[$r]}]} to ${EGRESS_HOST[${R_LABEL[$r]}]}"
    got=$(grep -cxF "$line" "$WORK/sink.log" || true)
    if [ "$got" = "$want" ]; then
      echo "ok: $LAYOUT End Marker relayed on TEID ${R_TEID[$r]} from ${LOCAL[${R_LOCAL[$r]}]} to ${EGRESS_HOST[${R_LABEL[$r]}]}: $got (want $want)"
    else
      fail "$LAYOUT: the host saw '$line' $got times, want $want"
    fi
  done
  total=$(from_local)
  if [ "$total" = "$expect" ]; then
    echo "ok: $LAYOUT End Markers on the wire: $total (want $expect, none for S1's)"
  else
    fail "$LAYOUT: $total End Markers reached the host, want $expect"
  fi
}

# The relay keeps the tunnel's order: the End Marker (TS 29.281 7.3.2) follows
# the old path's last G-PDU. From each N9 attachment, BURST G-PDUs on S11's N9
# downlink F-TEID and then an End Marker on it, in one sendmmsg: out of
# rt_transport, the host sees every G-PDU of a burst before that burst's
# relayed End Marker, and exactly one relay per burst.
mode4_end_marker_order() {
  local r n mark tunnel lines want_g
  n=$(attachments n9)
  want_g=$((n * BURST))
  for r in "${!R_IN[@]}"; do [ "${R_LABEL[$r]}" = s11dl ] && break; done
  tunnel="TEID ${R_TEID[$r]} from ${LOCAL[n9]} to ${EGRESS_HOST[s11dl]}"
  mark=$(wc -l <"$WORK/sink.log")
  phase "Mode 4 G-PDUs then an End Marker in one burst (every N9 attachment)" m4order \
    route_check/2/out=$((want_g + n)) decap0/1/out=$want_g decap0/2/out=$n \
    decap0/3/out=$n em_relay/0/out=$n enc/0/out=$want_g $(egress s11dl $((want_g + n)))
  for _ in $(seq 1 50); do
    lines=$(tail -n +"$((mark + 1))" "$WORK/sink.log" | grep -F " $tunnel" | grep -cE ' type (254|255) ' || true)
    [ "$lines" -ge $((want_g + n)) ] && break
    sleep 0.1
  done
  sleep 0.3
  # The k-th relay must follow at least k bursts' G-PDUs; the sends are
  # sequential, so a relay that overtook its burst's G-PDUs breaks this.
  if tail -n +"$((mark + 1))" "$WORK/sink.log" | grep -F " $tunnel" |
    awk -v burst="$BURST" -v n="$n" '
      / type 255 / { g++ }
      / type 254 / { e++; if (g < e * burst) { printf "relay %d after %d G-PDUs\n", e, g; bad = 1 } }
      END { if (g != n * burst || e != n) { printf "%d G-PDUs, %d relays\n", g, e; bad = 1 }; exit bad }' >"$WORK/order.log"; then
    echo "ok: $LAYOUT End Marker relay in tunnel order: $n relays, each behind its burst's $BURST G-PDUs ($want_g G-PDUs)"
  else
    fail "$LAYOUT: the relay left out of tunnel order on $tunnel: $(cat "$WORK/order.log")"
  fi
}

# await <file>: the driver's handshake, failing at once if the driver has gone.
await() {
  for _ in $(seq 1 600); do
    [ -e "$HS/$1" ] && return 0
    if ! kill -0 "$DRIVER_PID" 2>/dev/null; then
      cat "$WORK/driver.log" >&2
      fail "the driver stopped before it signalled $1"
    fi
    sleep 0.1
  done
  cat "$WORK/driver.log" >&2
  fail "the driver never signalled $1"
}

run_layout() {
  local iface_csv m
  LAYOUT=$1
  new_names "$("$WORK/vethlayout" -layout "$LAYOUT" -port-count)"
  iface_csv=$(IFS=,; echo "${VETHS[*]}")
  "$WORK/vethlayout" -layout "$LAYOUT" -ifaces "$iface_csv" \
    -contract "$WORK/contract.tsv" >"$WORK/graph.json"
  read_contract
  create_veths
  A=$(($(attachments n3) * PINGS)) B=$(($(attachments n9) * PINGS)) C=$(($(attachments n6) * PINGS))

  start_bessd
  bc validate "$WORK/graph.json" >/dev/null
  bc apply "$WORK/graph.json" >/dev/null
  bc resume >/dev/null
  sleep 0.5
  assert_promisc

  "$WORK/vethlayout" -sink-udp 2152 >"$WORK/sink.log" 2>&1 &
  SINK_PID=$!
  HS=$WORK/handshake-$LAYOUT
  mkdir -p "$HS"
  # One compiler holds every session, each sent to it over N4 by the driver's
  # stand-in SMF: it establishes all of them, waits for both Routers'
  # neighbors, and only then signals.
  "$WORK/vethlayout" -drive -layout "$LAYOUT" -target "$SERVER" -handshake "$HS" \
    >"$WORK/driver.log" 2>&1 &
  DRIVER_PID=$!
  await established.done
  for m in 1 2 3 4 5 6; do
    grep -q "^vethlayout: established: Mode $m " "$WORK/driver.log" ||
      fail "$LAYOUT: the driver established no Mode $m session"
  done
  grep -q "^vethlayout: established: Mode 5 .*S12: " "$WORK/driver.log" ||
    fail "$LAYOUT: the driver established no N19 group session"
  echo "ok: $LAYOUT: Modes 1 to 6 and the N19 group session established over N4 in one compiler"

  # A TEID no session admits reaches the unknown path, still endpoint-tagged,
  # and enters neither admission.
  snap "$WORK/before.prom"
  [ "$(count_of "$WORK/before.prom" decap0 2 out)" = 0 ] || fail "$LAYOUT: the unknown path is not empty before the unknown TEID"
  phase "unknown TEID" unknown \
    decap0/2/out=1 route_check/1/out=1 decap0/0/out=0 decap0/1/out=0 endpoint_check/1/out=0

  mode1_uplink
  mode1_downlink
  mode2_uplink
  mode2_downlink
  mode3_uplink
  mode3_downlink
  mode4_uplink
  mode4_downlink
  mode4_end_marker_order
  mode5
  n19_in
  n19_out
  mode6_uplink
  mode6_downlink
  mode6_held

  # Mode 6's procedure: the forwarding tunnels (11b, 11d), forwarding (3b),
  # the target's downlink switch (8a), the old path's End Markers relayed
  # (10b), and the releases after the timer (13a, 15a), each checked while
  # every other session stays live.
  : >"$HS/established.go"
  await forward.done
  mode6_forward
  mode6_held
  : >"$HS/forward.go"
  await switched.done
  mode6_switched
  mode6_forward
  mode6_end_markers
  : >"$HS/switched.go"
  await released.done
  mode6_released
  # Every earlier phase again, in reverse, every remaining session still live.
  mode6_switched
  n19_out
  n19_in
  mode5
  mode4_downlink
  mode4_uplink
  mode3_downlink
  mode3_uplink
  mode2_downlink
  mode2_uplink
  mode1_downlink
  mode1_uplink
  : >"$HS/released.go"
  wait "$DRIVER_PID" || { cat "$WORK/driver.log" >&2; DRIVER_PID=; fail "$LAYOUT: the driver failed"; }
  DRIVER_PID=

  echo "veth-layouts: ok ($LAYOUT, $PORTS PMD ports)"
  stop_helpers
  stop_bessd
  remove_veths
}

for layout in one-mac one-vlan one-hybrid two-n3n9-n6 two-n3n6-n9 two-n6n9-n3 three-vif three-direct four-fanin; do
  echo "veth-layouts: testing $layout"
  run_layout "$layout"
done

echo "veth-layouts: ok (9 attachment layouts, up to 4 promiscuous PMD ports; Modes 1 to 6 and N19 over N4 through the compiled pipeline on every attachment, End Markers relayed by the datapath through transit and forwarding tunnels behind their G-PDUs, endpoint-scoped GTP-U admission, unknown-TEID separation)"
