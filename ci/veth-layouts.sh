#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# Exercise N3, N6 and N9 ingress attachment across eight veth layouts. Every
# layout sends real G-PDUs through AF_PACKET and checks route-domain selection,
# endpoint-scoped F-TEID admission and the unknown-TEID path. The one-VLAN case
# deliberately gives N3 and N9 the same local IPv4 address and TEID; VLAN and
# endpoint_id must still keep their admissions distinct.
#
# The cases cover all five PMD partitions for one to three ports, plus alternate
# one-port L2 encodings and direct per-port endpoint tagging:
#   one-mac, one-vlan, one-hybrid,
#   two-n3n9-n6, two-n3n6-n9, two-n6n9-n3,
#   three-vif, three-direct.
#
# ci/iface-path.sh exercises the PFCP Source/Destination Interface scenarios;
# ci/veth-port.sh exercises a compiler-programmed session and routed egress.
# This lane isolates the physical ingress discriminator and admission contract.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/ci/bess-env.sh"
PLUG=${PLUG:-$ROOT/datapath/build}
GO=${GO:-$(MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} mise which go 2>/dev/null || echo go)}
BESSD=$STAGE/bin/bessd
BESSCTL=$STAGE/bin/bessctl
PINGS=${PINGS:-3}
[[ "$PINGS" =~ ^[1-9][0-9]*$ ]] || { echo "veth-layouts: PINGS must be a positive integer" >&2; exit 2; }
TEID=287454020 # 0x11223344
UNKNOWN_TEID=3735928559 # 0xdeadbeef

WORK=$(mktemp -d /tmp/upf-veth-layouts-XXXXXX)
LOG=$WORK/bessd.log
BESSD_PID=
BESSD_STARTED=0
CURRENT_VETHS=()
VETHS=()
PEERS=()
PORTS=0

declare -A EP_PORT EP_VLAN EP_MAC EP_IP EP_SRC EP_DEV

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

cleanup() {
  local status=$?
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

new_names() {
  local suffix
  printf -v suffix '%05d' "$((BASHPID % 100000))"
  VETHS=("upfl${suffix}0" "upfl${suffix}1" "upfl${suffix}2")
  PEERS=("upfp${suffix}0" "upfp${suffix}1" "upfp${suffix}2")
}

read_contract() {
  local kind name port vlan mac ip ignored_domain ignored_id src
  PORTS=0
  unset EP_PORT EP_VLAN EP_MAC EP_IP EP_SRC EP_DEV
  declare -gA EP_PORT EP_VLAN EP_MAC EP_IP EP_SRC EP_DEV
  while IFS=$'\t' read -r kind name port vlan mac ip ignored_domain ignored_id src; do
    case "$kind" in
      ports) PORTS=$name ;;
      endpoint)
        EP_PORT[$name]=$port
        EP_VLAN[$name]=$vlan
        EP_MAC[$name]=$mac
        EP_IP[$name]=$ip
        EP_SRC[$name]=$src
        ;;
    esac
  done <"$WORK/contract.tsv"
  [ "$PORTS" -ge 1 ] && [ "$PORTS" -le 3 ] || fail "invalid PMD count $PORTS"
}

create_veths() {
  local i dev vlan name port base addr_key port_mac
  for ((i = 0; i < PORTS; i++)); do
    if ip link show "${VETHS[$i]}" >/dev/null 2>&1 || ip link show "${PEERS[$i]}" >/dev/null 2>&1; then
      fail "refusing to reuse existing interfaces ${VETHS[$i]}/${PEERS[$i]}"
    fi
    sudo ip link add "${VETHS[$i]}" type veth peer name "${PEERS[$i]}" numrxqueues 1 numtxqueues 1
    CURRENT_VETHS+=("${VETHS[$i]}")
    sudo sysctl -qw "net.ipv6.conf.${VETHS[$i]}.disable_ipv6=1" "net.ipv6.conf.${PEERS[$i]}.disable_ipv6=1" || true
    sudo ip link set "${VETHS[$i]}" up
    sudo ip link set "${PEERS[$i]}" up
  done

  declare -A created_devs configured_addrs
  for name in n3 n6 n9; do
    port=${EP_PORT[$name]}
    base=${PEERS[$port]}
    vlan=${EP_VLAN[$name]}
    dev=$base
    if [ "$vlan" != 0 ]; then
      dev="$base.$vlan"
      if [ -z "${created_devs["$dev"]:-}" ]; then
        sudo ip link add link "$base" name "$dev" type vlan id "$vlan"
        sudo sysctl -qw "net.ipv6.conf.$dev.disable_ipv6=1" || true
        sudo ip link set "$dev" up
        created_devs["$dev"]=1
      fi
    fi
    addr_key="${dev}:${EP_SRC[$name]}"
    if [ -z "${configured_addrs["$addr_key"]:-}" ]; then
      sudo ip addr add "${EP_SRC[$name]}/24" dev "$dev"
      configured_addrs["$addr_key"]=1
    fi
    EP_DEV[$name]=$dev
    sudo ip neigh replace "${EP_IP[$name]}" lladdr "${EP_MAC[$name]}" dev "$dev" nud permanent

    port_mac=$(cat "/sys/class/net/${VETHS[$port]}/address" | tr '[:upper:]' '[:lower:]')
    if [ "$port_mac" = "${EP_MAC[$name]}" ]; then
      fail "$name's destination MAC equals PMD $port's MAC; promiscuous receive is not tested"
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

gate_packets() {
  bc metrics 2>/dev/null | grep '^bess_gate_packets_total{' | \
    grep -F "module=\"$1\"" | grep -F "gate=\"$2\"" | awk '{print $2; exit}' || true
}

wait_gate() {
  local got=0
  for _ in $(seq 1 100); do
    got=$(gate_packets "$1" "$2")
    [ "${got:-0}" -ge "$3" ] && break
    sleep 0.05
  done
  echo "${got:-0}"
}

check_count() {
  if [ "${2:-0}" = "$3" ]; then
    echo "ok: $1 ($2)"
  else
    fail "$1 counted ${2:-0}, want $3"
  fi
}

run_layout() {
  local layout=$1 iface_csv name unknown_before
  new_names
  iface_csv=$(IFS=,; echo "${VETHS[*]}")
  "$WORK/vethlayout" -layout "$layout" -ifaces "$iface_csv" \
    -contract "$WORK/contract.tsv" >"$WORK/graph.json"
  read_contract
  create_veths

  start_bessd
  bc validate "$WORK/graph.json" >/dev/null
  bc apply "$WORK/graph.json" >/dev/null
  bc resume >/dev/null
  sleep 0.5

  for name in n3 n9; do
    sudo "$WORK/vethlayout" -send-gpdu -device "${EP_DEV[$name]}" \
      -local "${EP_SRC[$name]}" -remote "${EP_IP[$name]}" -teid "$TEID" -count "$PINGS"
  done
  ping -c "$PINGS" -W 0.2 -I "${EP_DEV[n6]}" "${EP_IP[n6]}" >/dev/null 2>&1 || true

  check_count "$layout N3 route-domain gate" "$(wait_gate route_check 1 "$PINGS")" "$PINGS"
  check_count "$layout N9 route-domain gate" "$(wait_gate route_check 2 "$PINGS")" "$PINGS"
  check_count "$layout N6 route-domain gate" "$(wait_gate route_check 3 "$PINGS")" "$PINGS"
  check_count "$layout N3 endpoint/F-TEID admission" "$(wait_gate endpoint_check 1 "$PINGS")" "$PINGS"
  check_count "$layout N9 endpoint/F-TEID admission" "$(wait_gate endpoint_check 2 "$PINGS")" "$PINGS"
  check_count "$layout known G-PDUs" "$(wait_gate decap 0 "$((2 * PINGS))")" "$((2 * PINGS))"

  # One valid G-PDU with an unknown TEID must reach the unknown path, not either
  # endpoint's admitted PDR chain.
  unknown_before=$(gate_packets decap 2); unknown_before=${unknown_before:-0}
  check_count "$layout unknown path starts empty" "$unknown_before" 0
  sudo "$WORK/vethlayout" -send-gpdu -device "${EP_DEV[n3]}" \
    -local "${EP_SRC[n3]}" -remote "${EP_IP[n3]}" -teid "$UNKNOWN_TEID" -count 1
  check_count "$layout unknown TEID gate" "$(wait_gate decap 2 1)" 1
  check_count "$layout unknown TEID stays endpoint-tagged" "$(wait_gate route_check 1 "$((PINGS + 1))")" "$((PINGS + 1))"
  check_count "$layout unknown TEID did not enter N3 admission" "$(gate_packets endpoint_check 1)" "$PINGS"

  echo "veth-layouts: ok ($layout, $PORTS PMD ports)"
  stop_bessd
  remove_veths
}

for layout in one-mac one-vlan one-hybrid two-n3n9-n6 two-n3n6-n9 two-n6n9-n3 three-vif three-direct; do
  echo "veth-layouts: testing $layout"
  run_layout "$layout"
done

echo "veth-layouts: ok (8 attachment layouts; N3/N9 endpoint-scoped GTP-U admission and N6 route-domain split)"
