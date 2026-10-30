#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
#
# Render deploy/upf.yaml or deploy/appliance.yaml for the interop veths. Each
# target's own resolver learns the gNB and data-network neighbors; the rendered
# interfaces supply local identities, not static tunnel MAC addresses.
#
#   graph.py <deployed.yaml> <out.yaml> <if_n3> <if_n6> <n3_ip> <n3_mac>
#            <gnb_ip> <n6_mac> <dn_ip> <dn_gw> <marker_path>
import base64
import re
import socket
import sys

if len(sys.argv) != 12:
    sys.exit("graph.py: expected deployed graph, output, two interfaces, "
             "N3 IP/MAC, gNB IP, N6 MAC, DN IP/gateway, and marker path")

src, out, if_n3, if_n6, n3_ip, n3_mac, gnb_ip, n6_mac, dn_ip, dn_gw, marker = sys.argv[1:]

# The daemon binds UnixSocketPort paths as given. Every path this script writes
# must be absolute, or a misplaced argument would create a socket in its cwd.
for name, value in (("marker", marker), ("out", out)):
    if not value.startswith("/"):
        sys.exit(f"graph.py: {name} must be an absolute path, got {value!r}")


def ipv4(value):
    return base64.b64encode(socket.inet_aton(value)).decode()


def replace_once(text, pattern, replacement, label, flags=re.MULTILINE):
    updated, count = re.subn(pattern, replacement, text, count=1, flags=flags)
    if count != 1:
        sys.exit(f"graph.py: could not replace {label}")
    return updated


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
  - name: cp_marker_n3
    driver: UnixSocketPort
    arg: {{path: "{marker}.1"}}
  - name: cp_marker_n9
    driver: UnixSocketPort
    arg: {{path: "{marker}.2"}}

'''
new = replace_once(text, r"^ports:\n.*?(?=^modules:)", ports,
                   "ports block", re.MULTILINE | re.DOTALL)

if "mclass: UpfAppliance" in text:
    # Keep the production port -> owned appliance -> port deployment. Only the
    # lab's live interface identities and resolver bindings differ.
    for old, replacement, label in (
        ("mac_addr: '02:00:00:00:03:01', ip_addr: '192.0.2.1'",
         f"mac_addr: '{n3_mac}', ip_addr: '{n3_ip}'", "N3 identity"),
        ("addresses: ['192.0.2.1/24',",
         f"addresses: ['{n3_ip}/24',", "N3 prefix"),
        ("mac_addr: '02:00:00:00:06:01', ip_addr: '192.0.2.2', addresses: ['192.0.2.2/24']",
         f"mac_addr: '{n6_mac}', ip_addr: '{dn_gw}', addresses: ['{dn_gw}/24']", "N6 identity"),
        ("  upf/neighbors:\n    - {key: {id: 1}, value: {interface_id: 1, ipv4: '192.0.2.1'}}",
         f"  upf/neighbors:\n    - {{key: {{id: 1}}, value: {{interface_id: 1, ipv4: '{dn_ip}'}}}}", "N6 resolver"),
        ("  upf/transport_neighbors:\n    - {key: {id: 1}, value: {interface_id: 1, ipv4: '192.0.2.2'}}",
         f"  upf/transport_neighbors:\n    - {{key: {{id: 1}}, value: {{interface_id: 1, ipv4: '{gnb_ip}'}}}}", "N3 resolver"),
        ("  upf/entries:\n    - {key: {ip: '192.0.2.2'}, value: {mac_addr: '02:00:00:00:06:01'}}",
         f"  upf/entries:\n    - {{key: {{ip: '{dn_gw}'}}, value: {{mac_addr: '{n6_mac}'}}}}", "N6 ARP identity"),
    ):
        new = replace_once(new, re.escape(old), lambda _: replacement, label)
    open(out, "w").write(new)
    sys.exit(0)

# The Vifs and Router interfaces name the local address/MAC. Neighbor MACs
# are learned by the Router from ARP, not injected into tunnel entries.
new = replace_once(
    new,
    r'^        - \{id: 1, vlan: 0, mac_addr: "02:00:00:00:03:01", ip_addr: "192\.0\.2\.1", ipv6_addr: "[^"]*", route_domain: 0, gate: 1\}$',
    f'        - {{id: 1, vlan: 0, mac_addr: "{n3_mac}", ip_addr: "{n3_ip}", ipv6_addr: "2001:db8:1::1", route_domain: 0, gate: 1}}',
    "N3 Vif identity")
new = replace_once(
    new,
    r'^        - \{id: 1, vlan: 0, mac_addr: "02:00:00:00:06:01", ip_addr: "192\.0\.2\.2", ipv6_addr: "[^"]*", route_domain: 0, gate: 1\}$',
    f'        - {{id: 1, vlan: 0, mac_addr: "{n6_mac}", ip_addr: "{dn_gw}", ipv6_addr: "2001:db8:6::1", route_domain: 0, gate: 1}}',
    "N6 Vif identity")
new = replace_once(
    new,
    r'^        - \{id: 1, egress_gate: 0, mac_addr: "02:00:00:00:06:01", addresses: \["192\.0\.2\.2(/\d+)"\]\}$',
    rf'        - {{id: 1, egress_gate: 0, mac_addr: "{n6_mac}", addresses: ["{dn_gw}\1"]}}',
    "N6 Router interface")
new = replace_once(
    new,
    r'^  rt/neighbors:\n    - key: \{id: 1\}\n      value: \{interface_id: 1, ipv4: "[^"]*"\}$',
    f'  rt/neighbors:\n    - key: {{id: 1}}\n      value: {{interface_id: 1, ipv4: "{dn_ip}"}}',
    "N6 Router neighbor binding")
new = replace_once(
    new,
    r'^        - \{id: 1, egress_gate: 0, mac_addr: "02:00:00:00:03:01", addresses: \["192\.0\.2\.1(/\d+)", ("[^"]*")\]\}$',
    rf'        - {{id: 1, egress_gate: 0, mac_addr: "{n3_mac}", addresses: ["{n3_ip}\1", \2]}}',
    "N3 transport Router interface")
new = replace_once(
    new,
    r'^  rt_transport/neighbors:\n    - key: \{id: 1\}\n      value: \{interface_id: 1, ipv4: "192\.0\.2\.2"\}$',
    f'  rt_transport/neighbors:\n    - key: {{id: 1}}\n      value: {{interface_id: 1, ipv4: "{gnb_ip}"}}',
    "N3 transport neighbor binding")
new = replace_once(
    new,
    r'^  arp_n6/entries:\n    - key: \{ip: "[^"]*"\}\n      value: \{mac_addr: "[^"]*"\}$',
    f'  arp_n6/entries:\n    - key: {{ip: "{dn_gw}"}}\n      value: {{mac_addr: "{n6_mac}"}}',
    "N6 ARP identity")

# ARP requests emitted by the N3 resolver use the local N3 address as sender.
# Route those requests to the N3 port; peer replies go to the Router.
old_n3 = ipv4("192.0.2.1")
new_n3 = ipv4(n3_ip)
if old_n3 not in new:
    sys.exit("graph.py: no N3 ARP sender rule")
new = new.replace(f'value_bin: "{old_n3}"', f'value_bin: "{new_n3}"', 1)

open(out, "w").write(new)
