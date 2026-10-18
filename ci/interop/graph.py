#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
#
# The deployed graph (deploy/upf.yaml, or deploy/custom-pdrmatch.yaml with the
# keyed matcher) with this environment's wiring:
#
#   * its two PMD ports become af_packet vdevs over the veths ci/interop/net.sh
#     makes;
#   * the encap's outer source is the N3 address, and the end-marker socket
#     moves out of /tmp;
#   * the uplink's egress gets a layer-2 rewrite the deployed graph does not
#     have: after the decap the frame still carries the N3 frame's addresses
#     (the gNB's as source, the N3 port's as destination -- docs/design.md,
#     "Framing"), and the Router picks only the gate, so a frame leaving N6
#     would name the wrong destination MAC on the data network. Two stock
#     modules do the rewrite: GenericDecap (14 bytes) and GenericEncap (the
#     data network's MACs). This is a gap in the deployed graph, recorded in
#     docs/interop.md, not a property of this environment.
#
#   graph.py <deployed.yaml> <out.yaml> <if_n3> <if_n6> <n3_ip> <n6_mac> <dn_mac> <marker_path>
import base64
import re
import sys

src, out, if_n3, if_n6, n3_ip, n6_mac, dn_mac, marker = sys.argv[1:9]


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

# The layer-2 rewrite of the uplink's egress, in front of the N6 port.
l2 = f'''  # The N6 egress's layer 2: strip the frame's Ethernet header and write the
  # data network's (this environment's gap-filler, see the header comment).
  - name: n6_l2
    mclass: GenericDecap
    arg: {{bytes: 14}}
  - name: n6_eth
    mclass: GenericEncap
    arg:
      fields:
        - {{size: 6, value: {{value_bin: "{mac(dn_mac)}"}}}}
        - {{size: 6, value: {{value_bin: "{mac(n6_mac)}"}}}}
        - {{size: 2, value: {{value_int: 2048}}}}  # 0x0800, IPv4

'''
new, n = re.subn(r'^connections:\n', lambda m: l2 + 'connections:\n', new, count=1, flags=re.M)
assert n == 1, 'no connections: block'

new, n = re.subn(r'^  - \{upstream: rt, downstream: n6_out\}\n',
                 '  - {upstream: rt, downstream: n6_l2}\n'
                 '  - {upstream: n6_l2, downstream: n6_eth}\n'
                 '  - {upstream: n6_eth, downstream: n6_out}\n', new, count=1, flags=re.M)
assert n == 1, 'no rt -> n6_out connection'

open(out, 'w').write(new)
