#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
#
# The deployed graph (deploy/upf.yaml) with this environment's wiring:
#
#   * its two PMD ports become af_packet vdevs over the veths ci/interop/net.sh
#     makes;
#   * the encap's outer source is the N3 address, and the end-marker socket
#     moves out of /tmp;
#   * the addresses the graph writes into frames are this rig's. The N6 next
#     hop (`rt/next_hops`, id 1) carries the deployment's own MAC pair in the
#     file, and here it is the veths': the Router writes a resolved hop's
#     addresses into the frame it forwards, so what the graph names is what the
#     data network sees (BESS D-153). Where the graph has an N6 interface
#     (deploy/upf.yaml: the Vif; the keyed graph has none), its MAC is this
#     rig's too -- so a frame the data network sends is the interface's -- and
#     its address is the gateway the rig's data network routes the pool
#     through. ci/interop/net.sh sets that neighbour permanently, so the
#     interface answers no ARP in this rig (the deployment's own frames are
#     what the MAC substitution is for).
#
#   graph.py <deployed.yaml> <out.yaml> <if_n3> <if_n6> <n3_ip> <n6_mac> <dn_mac> <dn_gw> <marker_path>
import base64
import re
import sys

src, out, if_n3, if_n6, n3_ip, n6_mac, dn_mac, dn_gw, marker = sys.argv[1:10]

# The marker is a socket path, and bessd binds it as given: a relative path (or
# a value that is not a path at all, which is what an argument list that slipped
# one position produces) would have the daemon bind a socket named after that
# value wherever it happens to run -- once a MAC address in the checkout's root.
# Every path this script writes must be absolute.
for name, value in (("marker", marker), ("out", out)):
    if not value.startswith("/"):
        sys.exit(f"graph.py: {name} must be an absolute path, got {value!r} "
                 f"(check the argument order: <if_n3> <if_n6> <n3_ip> <n6_mac> "
                 f"<dn_mac> <dn_gw> <marker_path>)")


def mac(s):
    return base64.b64encode(bytes(int(x, 16) for x in s.split(':'))).decode()


text = open(src).read()

ports = f'''ports:
  - name: n3
    driver: PMDPort
    arg: {{vdev: "net_af_packet0,iface={if_n3},qpairs=1"}}
    num_rx_queues: 1
    num_tx_queues: 1
  - name: n6
    driver: PMDPort
    arg: {{vdev: "net_af_packet1,iface={if_n6},qpairs=1"}}
    num_rx_queues: 1
    num_tx_queues: 1
  - name: cp_marker
    driver: UnixSocketPort
    arg: {{path: {marker}}}

'''
new, n = re.subn(r'^ports:\n.*?(?=^modules:)', lambda m: ports, text, count=1, flags=re.S | re.M)
assert n == 1, 'no ports: block before modules:'

new, n = re.subn(r'src_ip: "[0-9.]+"', f'src_ip: "{n3_ip}"', new, count=1)
assert n == 1, 'no GtpuEncap src_ip'

# The N6 next hop's MACs: this rig's pair in place of the file's (or of an
# The N6 next hop's MACs: this rig's pair in place of the file's (or of an
# absent pair, whose gateway then answers or not as the rig decides).
new, n = re.subn(r'^      value: \{egress_gate: 0(?:, dst_mac: "[^"]*", src_mac: "[^"]*")?\}$',
                 f'      value: {{egress_gate: 0, dst_mac: "{mac(dn_mac)}", src_mac: "{mac(n6_mac)}"}}',
                 new, count=1, flags=re.M)
assert n == 1, 'no rt/next_hops hop 1'

# The N6 interface, where the graph has one.
new, n = re.subn(r'^        - \{id: 1, vlan: 0, mac_addr: "[^"]*", ip_addr: "[^"]*", route_domain: [0-9]+, gate: 1\}$',
                 f'        - {{id: 1, vlan: 0, mac_addr: "{n6_mac}", ip_addr: "{dn_gw}", route_domain: 1, gate: 1}}',
                 new, count=1, flags=re.M)

open(out, 'w').write(new)
