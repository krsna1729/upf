#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# The packet plumbing of the real-SMF environment with DATAPLANE=1
# (docs/interop.md): bessd's two ports as veths, the N3 one a port of the docker
# bridge (so the gNB container reaches it at layer 2) and the N6 one the other
# end of a veth whose far side is eth0 of a network namespace -- the data
# network. Names, MACs and addresses are lib.sh's constants; running it twice
# gives the same state, and `down` removes exactly these.
#
#   ci/interop/net.sh up      needs the docker network (up.sh creates it first)
#   ci/interop/net.sh down

set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

dn() { sudo -n ip netns exec "$DN_NS" "$@"; }

down() {
  sudo -n ip netns del "$DN_NS" 2>/dev/null || true
  sudo -n ip link del "$IF_N6" 2>/dev/null || true
  sudo -n ip link del "$IF_N3" 2>/dev/null || true
}

case "${1:-}" in
up)
  ip link show "$BRIDGE" >/dev/null 2>&1 || die "$BRIDGE does not exist (up.sh creates the docker network)"
  down

  # N3: bessd's port <-> a bridge port. IPv6 off before the links come up: DAD
  # and router solicitations are multicast, and would land in the graph.
  sudo -n ip link add "$IF_N3" type veth peer name "$IF_N3B"
  sudo -n ip link set "$IF_N3" address "$N3_MAC"
  sudo -n sysctl -qw "net.ipv6.conf.$IF_N3.disable_ipv6=1" "net.ipv6.conf.$IF_N3B.disable_ipv6=1"
  sudo -n ip link set "$IF_N3B" master "$BRIDGE"
  sudo -n ip link set "$IF_N3" up
  sudo -n ip link set "$IF_N3B" up
  # No transmit offloads on the ends that hand frames to bessd: a checksum the
  # kernel left partial, or a super-frame, would be forwarded as it stands --
  # ICMP survives that, TCP and UDP do not.
  sudo -n ethtool -K "$IF_N3" tx off tso off gso off gro off 2>/dev/null || true
  sudo -n ethtool -K "$IF_N3B" tx off tso off gso off gro off 2>/dev/null || true

  # N6: bessd's port <-> eth0 in the data network's namespace.
  sudo -n ip netns add "$DN_NS"
  sudo -n ip link add "$IF_N6" type veth peer name eth0 netns "$DN_NS"
  sudo -n ip link set "$IF_N6" address "$N6_MAC"
  sudo -n sysctl -qw "net.ipv6.conf.$IF_N6.disable_ipv6=1"
  sudo -n ip link set "$IF_N6" up
  sudo -n ethtool -K "$IF_N6" tx off tso off gso off gro off 2>/dev/null || true
  dn sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
  dn ip link set lo up
  dn ip link set eth0 address "$DN_MAC"
  dn ip addr add "$DN_IP/24" dev eth0
  dn ip link set eth0 up
  dn ethtool -K eth0 tx off tso off gso off gro off 2>/dev/null || true
  # The UE pool is behind a gateway that is the UPF's N6 port: one neighbour
  # entry instead of one per UE address.
  dn ip neigh replace "$DN_GW" lladdr "$N6_MAC" dev eth0 nud permanent
  dn ip route replace "$UE_POOL" via "$DN_GW" dev eth0
  log "net: $IF_N3 (bridge port $IF_N3B on $BRIDGE, MAC $N3_MAC), $IF_N6 <-> $DN_NS eth0 $DN_IP (MAC $DN_MAC)"
  ;;
down)
  down
  ;;
*) die "usage: net.sh up|down" ;;
esac
