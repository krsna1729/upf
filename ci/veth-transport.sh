#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# The post-encap transport path on a real veth, with the real resolver: what
# rt_transport (deploy/upf.yaml's outer Router) does to a tunnel's frames once
# GtpuEncap has written them. The graph is deploy/veth-transport.yaml; this
# script puts it on a kernel veth whose peer lives in its own network namespace
# -- a Linux host that answers ARP and Neighbor Discovery and captures what
# arrives -- programs two sessions over N4 with upfd and n4bench, and checks
# every claim byte by byte on the peer's own capture:
#
#   1. End Markers (SNDEM handover): the marker upfd writes to the End Marker
#      port reaches the wire through rt_transport, IPv4 and IPv6, with the old
#      TEID, type 254, the resolved peer MAC and the outer hop count
#      decremented once (upfd builds 64; 63 leaves).
#   2. IPv4 outer: a G-PDU's outer TTL leaves 63 (GtpuEncap writes 64,
#      rt_transport decrements once) with a valid header checksum, and the
#      inner TTL is what the inner hop left (sent N, leaves N-1: rt's one
#      decrement), untouched by the transport Router.
#   3. IPv6 outer: the same for a session whose gNB is IPv6 (Outer Header
#      Creation 0x0200, a dual-stack N3 endpoint): outer hop limit 63, inner
#      TTL N-1, the gateway resolved by Neighbor Discovery.
#   4. Neighbor change: the peer's MAC changes; once the resolver has
#      re-resolved (aging -> broadcast ARP / multicast NS -> reply), both
#      families' frames carry the new MAC.
#   5. Unreachable: the IPv4 gateway's address is removed from the peer; once
#      the resolver gives up, an IPv4 tunnel frame never reaches the wire (the
#      capture holds none, with any MAC) and lands on rt_transport's unresolved
#      punt gate, while the IPv6 tunnel on the same capture still leaves.
#
#   ci/veth-transport.sh
#   STAGE=/some/prefix ci/veth-transport.sh
# Needs root (sudo) for the af_packet PMD, the namespace and tcpdump; it creates
# a fresh veth pair and namespace and deletes only those. Existing names are a
# hard error. The logs and captures are kept when the run fails.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/ci/bess-env.sh"
PLUG=${PLUG:-$ROOT/datapath/build}
GRAPH=${GRAPH:-$ROOT/deploy/veth-transport.yaml}
GO=${GO:-$(MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} mise which go 2>/dev/null || echo go)}

VETH=${VETH:-upft$BASHPID}
PEER=${PEER:-upfq$BASHPID}
NS=${NS:-upf-transport-$BASHPID}
# The manifest's values, repeated (a graph is data, a script is code).
N3_MAC=02:00:00:00:51:01
N3_IP=198.51.100.1
N3_IP6=2001:db8:51::1
N6_MAC=02:00:00:00:51:06
N6_DOMAIN=3
PEER_IP=198.51.100.2
GW4=198.51.100.4    # rt_transport/neighbors id 1: removed in arm 5
GW6=2001:db8:51::2  # rt_transport/neighbors id 2
# Two sessions: n4bench gives session i UE .2+i, downlink TEID 0x100000+i,
# and the i-th -gnb; its handover moves the TEID to 0x110000+i.
UE0=10.46.0.2
UE1=10.46.0.3
UE_POOL=$UE0/31
FTEID=0x11223344
GNB4=10.20.30.2       # off-link: reached by the domain-1 IPv4 default route
GNB6=2001:db8:20::2   # off-link: reached by the domain-1 IPv6 default route
# The peer sends its inner datagrams with this TTL (its namespace's
# ip_default_ttl), distinct from the outer 64 so the two cannot be confused.
INNER_TTL=100
# The peer's MAC for arm 4: the only MAC this lane sets, because changing it
# is the arm.
NEW_MAC=02:00:00:00:51:aa
# Abstract socket (no file, no permissions): upfd appends .<transport domain>.
EM_SOCK=@upf-veth-transport-$BASHPID-em

BESSD=$STAGE/bin/bessd
BESSCTL=$STAGE/bin/bessctl

WORK=$(mktemp -d /tmp/upf-veth-transport-XXXXXX)
LOG=$WORK/bessd.log
UPFD_LOG=$WORK/upfd.log
N4_LOG=$WORK/n4bench.log
GRAPH_RUN=$WORK/veth-transport.yaml
BESSD_PID=
UPFD_PID=
N4BENCH_PID=
CAPTURE_PID=
BESSD_STARTED=0
NS_CREATED=0
VETH_CREATED=0

bc() { "$BESSCTL" -s "127.0.0.1:$BESS_PORT" "$@"; }
nsx() { sudo ip netns exec "$NS" "$@"; }

# As ci/veth-port.sh: the RPC stops the root daemon, the pidfile and SIGKILL
# are the fallbacks.
stop_bessd() {
  [ "$BESSD_STARTED" = 1 ] || return
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
    sudo kill -9 "$(tr -d '\000' <"$WORK/bessd.pid")" 2>/dev/null || true
  fi
}

cleanup() {
  local status=$?
  [ -n "$N4BENCH_PID" ] && kill "$N4BENCH_PID" 2>/dev/null || true
  [ -n "$UPFD_PID" ] && kill "$UPFD_PID" 2>/dev/null || true
  [ -n "$CAPTURE_PID" ] && sudo kill -INT "$CAPTURE_PID" 2>/dev/null || true
  stop_bessd
  # Deleting the host end deletes the pair; the namespace goes after it.
  if [ "$VETH_CREATED" = 1 ]; then
    sudo ip link del "$VETH" 2>/dev/null || true
  fi
  if [ "$NS_CREATED" = 1 ]; then
    sudo ip netns del "$NS" 2>/dev/null || true
  fi
  if [ "$status" = 0 ]; then
    rm -rf "$WORK"
  else
    echo "veth-transport: exit $status; logs and captures are in $WORK" >&2
  fi
  exit "$status"
}
trap cleanup EXIT

[ -x "$BESSD" ] || { echo "veth-transport: no bessd at $BESSD (set STAGE)" >&2; exit 1; }
[ -x "$BESSCTL" ] || { echo "veth-transport: no bessctl at $BESSCTL (set STAGE)" >&2; exit 1; }
[ -f "$PLUG/libupf_datapath.so" ] || {
  echo "veth-transport: build the plugin first: (cd datapath && ninja -C build)" >&2
  exit 1
}
[ -f "$GRAPH" ] || { echo "veth-transport: no graph at $GRAPH" >&2; exit 1; }
for tool in tcpdump python3; do
  command -v "$tool" >/dev/null || { echo "veth-transport: $tool is required" >&2; exit 1; }
done

# --- the link and its peer host ----------------------------------------------
# The peer is a namespace, not the host: it can have its MAC changed and its
# address removed without touching the host's own stack, its forwarding is off
# (a tunnel frame addressed to the off-link gNB dies there instead of leaving
# for a real network), and IPv6 is on only there -- the arm that needs ND.
if ip link show "$VETH" >/dev/null 2>&1 || ip netns list | grep -q -w -- "$NS"; then
  echo "veth-transport: refusing to reuse existing $VETH or namespace $NS" >&2
  exit 1
fi
echo "veth-transport: creating $VETH and its peer $PEER in namespace $NS"
sudo ip netns add "$NS"
NS_CREATED=1
sudo ip link add "$VETH" type veth peer name "$PEER" netns "$NS"
VETH_CREATED=1
# The host end is BESS's: the kernel holds no address there and sends nothing.
sudo sysctl -qw "net.ipv6.conf.$VETH.disable_ipv6=1" || true
sudo ip link set "$VETH" up
nsx sysctl -qw net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0 \
  "net.ipv4.ip_default_ttl=$INNER_TTL"
nsx ip link set "$PEER" up
nsx ip addr add "$PEER_IP/24" dev "$PEER"
nsx ip addr add "$GW4/24" dev "$PEER"
# nodad: the address answers Neighbor Solicitations at once, not after DAD.
nsx ip -6 addr add "$GW6/64" dev "$PEER" nodad
# The UEs are nowhere on-link: their datagrams leave the peer for the N6 MAC,
# so the Vif classifies them onto N6 and the downlink PDRs select them.
nsx ip route add "$UE_POOL" dev "$PEER"
nsx ip neigh replace "$UE0" lladdr "$N6_MAC" dev "$PEER" nud permanent
nsx ip neigh replace "$UE1" lladdr "$N6_MAC" dev "$PEER" nud permanent
PEER_MAC=$(nsx cat "/sys/class/net/$PEER/address" | tr '[:upper:]' '[:lower:]')

# --- the daemon and the graph ------------------------------------------------
export LD_LIBRARY_PATH=$STAGE/lib:$DPDK_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
sudo -E env LD_LIBRARY_PATH="$LD_LIBRARY_PATH" \
  "$BESSD" -m 0 -p "$BESS_PORT" -i "$WORK/bessd.pid" -modules="$PLUG" -f >"$LOG" 2>&1 &
BESSD_PID=$!
BESSD_STARTED=1
for _ in $(seq 1 60); do bc status >/dev/null 2>&1 && break; sleep 0.5; done
bc status >/dev/null 2>&1 || {
  echo "veth-transport: the daemon did not come up; log follows" >&2
  cat "$LOG" >&2
  exit 1
}
while IFS= read -r line || [ -n "$line" ]; do
  line=${line//__VETH_IFACE__/$VETH}
  printf '%s\n' "${line//__END_MARKER_PATH__/$EM_SOCK.1}"
done <"$GRAPH" >"$GRAPH_RUN"
bc validate "$GRAPH_RUN" >/dev/null
bc apply "$GRAPH_RUN" >/dev/null
bc resume >/dev/null

# --- checks ------------------------------------------------------------------
FAIL=0
pass() { echo "ok: $1"; }
fail() { echo "FAIL: $1" >&2; FAIL=1; }

gate_packets() { # gate_packets <module> <gate>
  bc metrics 2>/dev/null | grep '^bess_gate_packets_total{' |
    grep -F "module=\"$1\"" | grep -F "gate=\"$2\"" | awk '{print $2; exit}' || true
}

# neighbor <address>: "<state> <mac>" for that binding, as rt_transport's
# get_neighbors reports it (state without its enum prefix; "-" for no MAC).
neighbor() {
  bc action rt_transport get_neighbors 2>/dev/null | python3 -c '
import json, sys
for n in json.load(sys.stdin).get("neighbors", []):
    if sys.argv[1] in (n.get("ipv4"), n.get("ipv6")):
        print(n.get("state", "").replace("ROUTER_NEIGHBOR_STATE_", ""),
              n.get("mac_addr") or "-")
' "$1" 2>/dev/null || true
}

# wait_neighbor <address> <state regex> <mac or "-" or "*">: polls for 10 s.
wait_neighbor() {
  local got=
  for _ in $(seq 1 100); do
    got=$(neighbor "$1")
    if [[ "${got% *}" =~ ^($2)$ ]] && { [ "$3" = "*" ] || [ "${got#* }" = "$3" ]; }; then
      echo "$got"
      return 0
    fi
    sleep 0.1
  done
  echo "$got"
  return 1
}

hexmac() { tr ':' ' ' <<<"$1" | tr '[:upper:]' '[:lower:]'; }
hex4() { local IFS=.; set -- $1; printf '%02x %02x %02x %02x' "$1" "$2" "$3" "$4"; }
hex6() {
  python3 -c 'import ipaddress, sys; print(" ".join("%02x" % b for b in ipaddress.IPv6Address(sys.argv[1]).packed))' "$1"
}
hex32() { printf '%02x %02x %02x %02x' $(($1 >> 24 & 255)) $(($1 >> 16 & 255)) $(($1 >> 8 & 255)) $(($1 & 255)); }

# The peer's capture: tcpdump in the namespace, promiscuous (so a frame for any
# MAC, an invented one included, is seen), stopped after <count> frames or
# <seconds>.
capture_start() { # capture_start <name> <count> <seconds> <filter>
  : >"$WORK/$1.tcpdump.log"
  sudo timeout -s INT "$3" ip netns exec "$NS" \
    tcpdump -i "$PEER" -nn -U -Z root -c "$2" -w "$WORK/$1.pcap" "$4" \
    2>"$WORK/$1.tcpdump.log" &
  CAPTURE_PID=$!
  for _ in $(seq 1 50); do
    grep -q 'listening on' "$WORK/$1.tcpdump.log" && return 0
    sleep 0.1
  done
  echo "veth-transport: tcpdump did not start; its log follows" >&2
  cat "$WORK/$1.tcpdump.log" >&2
  exit 1
}
# capture_end <name>: waits for the capture and writes <name>.frames, one
# frame per line, its bytes as lowercase hex pairs.
capture_end() {
  wait "$CAPTURE_PID" 2>/dev/null || true
  CAPTURE_PID=
  tcpdump -r "$WORK/$1.pcap" -nn -xx 2>/dev/null | awk '
    /^[^ \t]/ { if (b != "") print b; b = ""; next }
    /^[ \t]+0x[0-9a-f]+:/ {
      for (i = 2; i <= NF; i++)
        for (j = 1; j < length($i); j += 2)
          b = b (b == "" ? "" : " ") substr($i, j, 2)
    }
    END { if (b != "") print b }' >"$WORK/$1.frames"
}

bytes() { # bytes <frame> <offset> <count>
  local -a b
  read -ra b <<<"$1"
  echo "${b[*]:$2:$3}"
}
# pick <frames file> <offset:bytes>...: the first frame with all those bytes.
pick() {
  local file=$1 line spec want
  shift
  while IFS= read -r line; do
    for spec in "$@"; do
      want=${spec#*:}
      [ "$(bytes "$line" "${spec%%:*}" "$(wc -w <<<"$want")")" = "$want" ] || continue 2
    done
    printf '%s\n' "$line"
    return 0
  done <"$file"
  return 1
}
expect() { # expect <description> <frame> <offset> <bytes>
  local got
  got=$(bytes "$2" "$3" "$(wc -w <<<"$4")")
  if [ "$got" = "$4" ]; then pass "$1 ($got)"; else fail "$1 (got '$got', want '$4')"; fi
}
# ipv4_sum_ok <frame> <offset>: the 20-byte header at offset sums to 0xffff.
ipv4_sum_ok() {
  local -a b
  read -ra b <<<"$1"
  local o=$2 s=0 i
  for ((i = o; i < o + 20; i += 2)); do s=$((s + 0x${b[i]}${b[i + 1]})); done
  while ((s >> 16)); do s=$(((s & 0xffff) + (s >> 16))); done
  [ "$s" = 65535 ]
}

# check_tunnel <label> <frame> <4|6> <gtp type> <teid> <dst mac> <gnb> [inner ttl]
# The outer stack as rt_transport leaves it: the resolved MACs, the outer hop
# count 0x3f (built 64 by GtpuEncap's WriteGtpOuterHeaders and by upfd's
# endMarkerFrame, decremented once by route::WriteForwarded), UDP to 2152, and
# the GTP-U type and TEID. With an inner TTL, the inner IPv4 header's TTL and
# checksum too.
check_tunnel() {
  local label=$1 f=$2 fam=$3 l4 flags inner
  if [ -z "$f" ]; then fail "$label: no such frame on the peer's capture"; return; fi
  expect "$label: destination MAC is the resolved peer" "$f" 0 "$(hexmac "$6")"
  expect "$label: source MAC is the N3 interface's" "$f" 6 "$(hexmac "$N3_MAC")"
  if [ "$fam" = 4 ]; then
    expect "$label: outer IPv4, no options" "$f" 12 "08 00 45"
    expect "$label: outer id 0, DF" "$f" 18 "00 00 40 00"
    expect "$label: outer TTL 64 decremented once, UDP" "$f" 22 "3f 11"
    expect "$label: outer source is the N3 address" "$f" 26 "$(hex4 "$N3_IP")"
    expect "$label: outer destination is the gNB" "$f" 30 "$(hex4 "$7")"
    if ipv4_sum_ok "$f" 14; then pass "$label: outer IPv4 checksum valid after the decrement"
    else fail "$label: outer IPv4 checksum invalid"; fi
    l4=34
  else
    expect "$label: outer IPv6" "$f" 12 "86 dd"
    [ "$(bytes "$f" 14 1 | cut -c1)" = 6 ] && pass "$label: IP version 6" || fail "$label: not IPv6"
    expect "$label: next header UDP, hop limit 64 decremented once" "$f" 20 "11 3f"
    expect "$label: outer source is the N3 IPv6 address" "$f" 22 "$(hex6 "$N3_IP6")"
    expect "$label: outer destination is the gNB" "$f" 38 "$(hex6 "$7")"
    l4=54
  fi
  expect "$label: UDP to 2152" "$f" $((l4 + 2)) "08 68"
  expect "$label: GTP-U message type" "$f" $((l4 + 9)) "$4"
  expect "$label: TEID" "$f" $((l4 + 12)) "$(hex32 "$5")"
  if [ -n "${8:-}" ]; then
    flags=0x$(bytes "$f" $((l4 + 8)) 1)
    inner=$((l4 + 16 + ((flags & 0x04) ? 8 : 0)))
    expect "$label: inner TTL is the inner hop's, untouched by the transport Router" \
      "$f" $((inner + 8)) "$(printf '%02x' "$8")"
    if ipv4_sum_ok "$f" "$inner"; then pass "$label: inner IPv4 checksum valid"
    else fail "$label: inner IPv4 checksum invalid"; fi
  fi
}

# The downlink datagram for a session: from the peer, to the UE's DNS port
# (the filter n4sim's establishment carries).
send_downlink() { nsx bash -c "exec 3<>/dev/udp/$1/53 && echo hi >&3" 2>/dev/null || true; }

# --- dynamic resolution, both families -----------------------------------------
# No MAC is configured for either gateway: the graph binds addresses, and the
# resolver must learn the peer's real MAC by ARP and by Neighbor Discovery.
got=$(wait_neighbor "$GW4" RESOLVED "$PEER_MAC") &&
  pass "the IPv4 gateway resolved by ARP to the peer's MAC ($got)" ||
  fail "the IPv4 gateway did not resolve to $PEER_MAC ($got)"
got=$(wait_neighbor "$GW6" RESOLVED "$PEER_MAC") &&
  pass "the IPv6 gateway resolved by ND to the peer's MAC ($got)" ||
  fail "the IPv6 gateway did not resolve to $PEER_MAC ($got)"

# --- sessions and End Markers ------------------------------------------------
# upfd with a dual-stack N3 endpoint (transport domain 1) and the End Marker
# port; n4bench establishes session 0 toward the IPv4 gNB and session 1 toward
# the IPv6 one, then hands both over with SNDEM and holds the association
# (answering heartbeats) so the sessions stand for the arms below.
(cd "$ROOT" && $GO build -o "$WORK/upfd" ./cmd/upfd && $GO build -o "$WORK/n4bench" ./cmd/n4bench)
"$WORK/upfd" -n4 "127.0.0.1:$N4_PORT" -node-id 127.0.0.1 -bess "127.0.0.1:$BESS_PORT" \
  -fteid-address "endpoint=1,reference=n3,transport-domain=1,source=access,instance=n6,ipv4=$N3_IP,ipv6=$N3_IP6" \
  -gtpu-decap decap0 -max-domains 4 \
  -instances "name=n6,domain=$N6_DOMAIN,next-hop=1,pool=$UE_POOL" \
  -pdr-fields-ul src,dst,proto,sport,dport,fteid,qfi \
  -pdr-fields-dl src,dst,proto,sport,dport,domain,fteid,qfi \
  -end-marker "$EM_SOCK" -log-level info >"$UPFD_LOG" 2>&1 &
UPFD_PID=$!
for _ in $(seq 1 40); do
  grep -q 'n4 listening' "$UPFD_LOG" 2>/dev/null && break
  sleep 0.25
done
kill -0 "$UPFD_PID" 2>/dev/null || {
  echo "veth-transport: upfd exited; log follows" >&2
  cat "$UPFD_LOG" >&2
  exit 1
}

capture_start markers 2 30 'udp port 2152'
"$WORK/n4bench" -upf "127.0.0.1:$N4_PORT" -mode handover -sessions 2 -workers 1 \
  -fteid "$FTEID" -ue-pool "$UE_POOL" -gnb "$GNB4,$GNB6" -n3 "$N3_IP" \
  -timeout 5s -hold 1h >"$N4_LOG" 2>&1 &
N4BENCH_PID=$!
for _ in $(seq 1 80); do
  grep -q '^holding the association' "$N4_LOG" && break
  kill -0 "$N4BENCH_PID" 2>/dev/null || break
  sleep 0.25
done
grep -q '^holding the association' "$N4_LOG" || {
  echo "veth-transport: the establishment or handover failed; n4bench's and upfd's logs follow" >&2
  cat "$N4_LOG" "$UPFD_LOG" >&2
  exit 1
}
capture_end markers
if grep -q 'an end marker was not sent' "$UPFD_LOG"; then
  fail "upfd failed to send an End Marker ($(grep 'an end marker was not sent' "$UPFD_LOG" | head -1))"
fi
check_tunnel "IPv4 End Marker" "$(pick "$WORK/markers.frames" "12:08 00" "43:fe" || true)" \
  4 fe 0x100000 "$PEER_MAC" "$GNB4"
check_tunnel "IPv6 End Marker" "$(pick "$WORK/markers.frames" "12:86 dd" "63:fe" || true)" \
  6 fe 0x100001 "$PEER_MAC" "$GNB6"

# --- TTL once, both outer families -------------------------------------------
# One datagram per session, captured as it leaves the peer (UDP 53, TTL as
# sent) and as it comes back encapsulated (UDP 2152, the new TEIDs).
capture_start ttl 4 15 'udp port 2152 or udp port 53'
send_downlink "$UE0"
send_downlink "$UE1"
capture_end ttl
sent=$(pick "$WORK/ttl.frames" "12:08 00" "36:00 35" "30:$(hex4 "$UE0")" || true)
expect "the inner datagram leaves the peer with TTL $INNER_TTL" "$sent" 22 "$(printf '%02x' "$INNER_TTL")"
check_tunnel "IPv4 G-PDU" "$(pick "$WORK/ttl.frames" "12:08 00" "36:08 68" "43:ff" || true)" \
  4 ff 0x110000 "$PEER_MAC" "$GNB4" $((INNER_TTL - 1))
check_tunnel "IPv6 G-PDU" "$(pick "$WORK/ttl.frames" "12:86 dd" "56:08 68" "63:ff" || true)" \
  6 ff 0x110001 "$PEER_MAC" "$GNB6" $((INNER_TTL - 1))

# --- the neighbor changes its MAC --------------------------------------------
# Nothing tells the resolver: it reconfirms each gateway when its reachable
# lifetime (1 s) runs out, with a broadcast ARP request / multicast NS, and the
# reply from the new MAC re-resolves it (route/neighbor_resolver.h).
nsx ip link set dev "$PEER" address "$NEW_MAC"
# A device's address change flushes its neighbor table, permanent entries
# included (the kernel's neigh_changeaddr): the peer's own route to the UEs
# through BESS's N6 side is put back, or nothing would reach BESS to encapsulate.
nsx ip neigh replace "$UE0" lladdr "$N6_MAC" dev "$PEER" nud permanent
nsx ip neigh replace "$UE1" lladdr "$N6_MAC" dev "$PEER" nud permanent
got=$(wait_neighbor "$GW4" RESOLVED "$NEW_MAC") &&
  pass "the IPv4 gateway re-resolved to the new MAC ($got)" ||
  fail "the IPv4 gateway did not follow the MAC change ($got)"
got=$(wait_neighbor "$GW6" RESOLVED "$NEW_MAC") &&
  pass "the IPv6 gateway re-resolved to the new MAC ($got)" ||
  fail "the IPv6 gateway did not follow the MAC change ($got)"
capture_start moved 2 15 'udp port 2152'
send_downlink "$UE0"
send_downlink "$UE1"
capture_end moved
check_tunnel "IPv4 G-PDU after the MAC change" "$(pick "$WORK/moved.frames" "12:08 00" || true)" \
  4 ff 0x110000 "$NEW_MAC" "$GNB4" $((INNER_TTL - 1))
check_tunnel "IPv6 G-PDU after the MAC change" "$(pick "$WORK/moved.frames" "12:86 dd" || true)" \
  6 ff 0x110001 "$NEW_MAC" "$GNB6" $((INNER_TTL - 1))

# --- the IPv4 gateway becomes unreachable ------------------------------------
# Its address leaves the peer, so nothing answers ARP for it: the next
# reconfirmation sends its 3 probes unanswered and fails the neighbor, which
# clears its MAC; retries every 500 ms keep failing.
nsx ip addr del "$GW4/24" dev "$PEER"
got=$(wait_neighbor "$GW4" 'UNREACHABLE|INCOMPLETE' -) &&
  pass "the IPv4 gateway is unresolved with no MAC ($got)" ||
  fail "the IPv4 gateway stayed resolved ($got)"
sleep 0.2 # the resolver's change is published on the next maintenance tick
punted_before=$(gate_packets rt_transport 2)
punted_before=${punted_before:-0}
# Up to 4 frames, but only the IPv6 one may come: the capture runs out its time
# rather than its count when the IPv4 frames are held back.
capture_start dead 4 3 'udp port 2152'
for _ in 1 2 3; do send_downlink "$UE0"; done
send_downlink "$UE1"
capture_end dead
v4=$(grep -c '^\([0-9a-f][0-9a-f] \)\{12\}08 00' "$WORK/dead.frames" || true)
if [ "$v4" = 0 ]; then
  pass "no IPv4 tunnel frame reached the wire, with any MAC"
else
  fail "$v4 IPv4 tunnel frame(s) left toward an unresolved gateway"
fi
check_tunnel "IPv6 G-PDU while IPv4 is unresolved" "$(pick "$WORK/dead.frames" "12:86 dd" || true)" \
  6 ff 0x110001 "$NEW_MAC" "$GNB6" $((INNER_TTL - 1))
punted=0
for _ in $(seq 1 40); do
  punted=$(($(gate_packets rt_transport 2) - punted_before))
  [ "$punted" -ge 3 ] && break
  sleep 0.05
done
if [ "$punted" = 3 ]; then
  pass "rt_transport counted the 3 frames on its unresolved punt gate (gate 2, to a Sink)"
else
  fail "rt_transport's unresolved punt gate counted $punted, want 3"
fi

echo "veth-transport: neighbors $(bc action rt_transport get_neighbors 2>/dev/null | tr -d '\n ')"
if [ "$FAIL" = 0 ]; then
  echo "veth-transport: ok (ARP and ND resolution, IPv4 and IPv6 outer hop count once with the inner untouched, End Markers through the transport Router, a MAC change followed, an unreachable gateway failed closed)"
fi
exit "$FAIL"
