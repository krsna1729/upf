#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# The radio side of the real-SMF environment: a UERANSIM gNB and UE
# (free5gc/ueransim) in two containers sharing one network namespace -- the
# UE finds the gNB over a loopback "radio link", as in the free5gc-compose
# setup. Needs ci/interop/up.sh. With SECOND_UE=1 (the default) a second UE
# (IMSI2, uecfg2.yaml) shares the gNB's namespace and establishes its own PDU
# session; SECOND_UE=0 starts the original one-UE environment.
#
#   ci/interop/ue.sh start     gNB (NG Setup with the AMF), then the UE(s): registration, and the
#                              one PDU session each config asks for
#   ci/interop/ue.sh release   each UE releases PDU session 1 (nr-cli ps-release)
#   ci/interop/ue.sh status    each UE's view (nr-cli info/ps-list)
#   ci/interop/ue.sh traffic [count] [1|2]   echo through the selected UE's tunnel
#   ci/interop/ue.sh stop      remove the gNB and UE containers

set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

GNB=$PREFIX-ueransim
UE=$PREFIX-ue
UE2C=$PREFIX-ue2
cli() { dk exec "$UE" ./nr-cli "$IMSI" -e "$1"; }   # one nr-cli command per call
cli2() { dk exec "$UE2C" ./nr-cli "$IMSI2" -e "$1"; }

case "${1:-}" in
start)
  dk inspect "$PREFIX-smf" >/dev/null 2>&1 || die "the core is not up (ci/interop/up.sh)"
  GNB_ARGS=()
  # With real packets the gNB's address and MAC are fixed. The UPF's transport
  # Router learns this peer's MAC from ARP; the gNB has a permanent neighbor for
  # the UPF's N3 address because no host kernel owns that address.
  [ -n "$DATAPLANE" ] && GNB_ARGS=(--ip "$GNB_IP" --mac-address "$GNB_MAC")
  nf ueransim --network-alias gnb.free5gc.org --cap-add NET_ADMIN --device /dev/net/tun \
    "${GNB_ARGS[@]}" \
    -v "$CONF/gnbcfg.yaml:/ueransim/config/gnbcfg.yaml:ro" \
    "free5gc/ueransim:$TAG" ./nr-gnb -c ./config/gnbcfg.yaml
  if [ -n "$DATAPLANE" ]; then
    # The UPF's N3 address is answered by no kernel: a permanent neighbour entry
    # names the N3 port's MAC.
    dk exec "$GNB" ip neigh replace "$N3_IP" lladdr "$N3_MAC" dev eth0 nud permanent
  fi
  wait_clog ueransim "NG Setup procedure is successful" 30 || { dk logs "$GNB" 2>&1 | tail -20 >&2; die "the gNB's NG Setup did not complete"; }
  log "gNB: NG Setup successful"
  # The UE shares the gNB's namespace: its radio link is loopback.
  NF_NETWORK="container:$GNB" nf ue --cap-add NET_ADMIN --device /dev/net/tun \
    -v "$CONF/uecfg.yaml:/ueransim/config/uecfg.yaml:ro" \
    "free5gc/ueransim:$TAG" ./nr-ue -c ./config/uecfg.yaml
  # The second UE is a second nr-ue in its own namespace: its own IMSI,
  # subscription and PDU session, and its own routing tables -- two UEs in one
  # namespace collide on UERANSIM's per-session table (both sessions are PSI 1).
  # It reaches the gNB's radio link over the interop network.
  if [ "$SECOND_UE" = 1 ]; then
    nf ue2 --cap-add NET_ADMIN --device /dev/net/tun \
      -v "$CONF/uecfg2.yaml:/ueransim/config/uecfg2.yaml:ro" \
      "free5gc/ueransim:$TAG" ./nr-ue -c ./config/uecfg2.yaml
  fi
  ;;
release)
  cli ps-list
  cli "ps-release 1" || cli ps-release-all
  if [ "$SECOND_UE" = 1 ]; then
    cli2 ps-list
    cli2 "ps-release 1" || cli2 ps-release-all
  fi
  ;;
status)
  cli info || true
  cli ps-list || true
  if [ "$SECOND_UE" = 1 ]; then
    cli2 info || true
    cli2 ps-list || true
  fi
  ;;
traffic)
  # ICMP echo from a UE's tunnel interface to the data network, through the
  # whole chain (UERANSIM -> GTP-U -> bessd N3 -> N6 -> the namespace, and back).
  # 228-byte frames: 20 of them cross the 1000-byte volume threshold the SMF's
  # URRs carry, each way. `traffic [count] [1|2]` selects the UE; both share the
  # gNB's namespace, so the second UE's tun is found by its session address.
  [ -n "$DATAPLANE" ] || die "traffic needs DATAPLANE=1 (there is no data network without it)"
  count=${2:-20}
  which=${3:-1}
  if [ "$which" = 2 ]; then
    [ "$SECOND_UE" = 1 ] || die "no second UE (SECOND_UE=0)"
    uc=$UE2C
    addr=$(cli2 ps-list | sed -n 's/^[[:space:]]*address: //p' | head -1 | tr -d '[:space:]')
    [ -n "$addr" ] || die "the second UE has no session address"
    tun=$(dk exec "$uc" ip -o -4 addr show |
      awk -v a="$addr" '{split($4, x, "/"); if (x[1] == a) {print $2; exit}}')
    [ -n "$tun" ] || die "no tunnel carries $addr"
  else
    uc=$UE
    tun=uesimtun0
  fi
  # The UE's own route to the data network: UERANSIM installs the session's
  # prefix on the tunnel and nothing else, so without this the echo would leave
  # by the container's default route -- the bridge -- and never see the UPF.
  dk exec "$uc" ip route replace "$DN_NET" dev "$tun"
  dk exec "$uc" ping -I "$tun" -c "$count" -i 0.2 -s 200 -W 2 "$DN_IP"
  ;;
stop)
  for c in $UE2C $UE $GNB; do
    if dk inspect "$c" >/dev/null 2>&1; then
      dk logs "$c" >"$LOGS/${c#"$PREFIX"-}.docker.log" 2>&1 || true
      dk rm -f "$c" >/dev/null && log "removed $c"
    fi
  done
  ;;
*) die "usage: ue.sh start|release|status|traffic [count] [1|2]|stop" ;;
esac
