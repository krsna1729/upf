#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# The radio side of the real-SMF environment: a UERANSIM gNB and UE
# (free5gc/ueransim) in two containers sharing one network namespace -- the
# UE finds the gNB over a loopback "radio link", as in the free5gc-compose
# setup. Needs ci/interop/up.sh.
#
#   ci/interop/ue.sh start     gNB (NG Setup with the AMF), then the UE: registration, and the one
#                              PDU session its config asks for
#   ci/interop/ue.sh release   the UE releases PDU session 1 (nr-cli ps-release)
#   ci/interop/ue.sh status    the UE's view (nr-cli info/ps-list)
#   ci/interop/ue.sh stop      remove the gNB and UE containers

set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

GNB=$PREFIX-ueransim
UE=$PREFIX-ue
cli() { dk exec "$UE" ./nr-cli "$IMSI" -e "$1"; }   # one nr-cli command per call

case "${1:-}" in
start)
  dk inspect "$PREFIX-smf" >/dev/null 2>&1 || die "the core is not up (ci/interop/up.sh)"
  GNB_ARGS=()
  # With real packets the gNB container's address and MAC are fixed: upfd's one
  # downlink next hop (-peer-mac) is that MAC.
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
  ;;
release)
  cli ps-list
  cli "ps-release 1" || cli ps-release-all
  ;;
status)
  cli info || true
  cli ps-list || true
  ;;
traffic)
  # ICMP echo from the UE's tunnel interface to the data network, through the
  # whole chain (UERANSIM -> GTP-U -> bessd N3 -> N6 -> the namespace, and back).
  # 228-byte frames: 20 of them cross the 1000-byte volume threshold the SMF's
  # URRs carry, each way.
  [ -n "$DATAPLANE" ] || die "traffic needs DATAPLANE=1 (there is no data network without it)"
  # The UE's own route to the data network: UERANSIM installs the session's
  # prefix on the tunnel and nothing else, so without this the echo would leave
  # by the container's default route -- the bridge -- and never see the UPF.
  dk exec "$UE" ip route replace "$DN_NET" dev uesimtun0
  dk exec "$UE" ping -I uesimtun0 -c "${2:-20}" -i 0.2 -s 200 -W 2 "$DN_IP"
  ;;
stop)
  for c in $UE $GNB; do
    if dk inspect "$c" >/dev/null 2>&1; then
      dk logs "$c" >"$LOGS/${c#"$PREFIX"-}.docker.log" 2>&1 || true
      dk rm -f "$c" >/dev/null && log "removed $c"
    fi
  done
  ;;
*) die "usage: ue.sh start|release|status|traffic [count]|stop" ;;
esac
