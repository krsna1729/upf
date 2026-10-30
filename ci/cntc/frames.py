#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
#
# The N3 frames of TOSSI CNTC's robustness suite (upfbench/suites/n3neg/_pktgen.py:
# a valid G-PDU, an unknown TEID, control and reserved message types, a wrong
# version, three truncations, a valid and a malformed PDU Session Container),
# built byte by byte -- no scapy -- and written into the selected real
# session-path deployment. UPF_TARGET=graph|appliance selects the same target
# as upfd; GRAPH may override its deployment. Only external fixtures change.
#
#   frames.py <out.yaml> <variant> [<variant> ...]
#   frames.py <out.yaml> --control-plane    # paused, no fixture traffic
import argparse
import base64
import os
import struct

import yaml  # CNTC's existing PyYAML dependency

TEID = 210001   # pfcpsim's uplink TEID for --baseID 210001, as CNTC's NT tests use it
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def csum(b):
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    s = (s & 0xffff) + (s >> 16)
    s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip(src, dst, proto, payload):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0x4000, 64, proto, 0,
                    bytes(map(int, src.split('.'))), bytes(map(int, dst.split('.'))))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload


def udp(sport, dport, payload):
    return struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload


ETH = bytes.fromhex('020000000002020000000001') + b'\x08\x00'
INNER = ip('10.250.0.1', '8.8.8.8', 17, udp(1234, 80, b'\x00' * 40))


def frame(flags=0x30, typ=0xff, length=None, teid=TEID, opt=b'', payload=INNER, trunc=None):
    if length is None:
        length = len(opt) + len(payload)
    g = struct.pack('!BBHI', flags, typ, length, teid) + opt + payload
    if trunc is not None:
        g = g[:trunc]
    return ETH + ip('192.0.2.10', '192.0.2.1', 17, udp(2152, 2152, g))


VARIANTS = {
    'valid': frame(),
    'unknown_teid': frame(teid=TEID + 999999),
    'echo_request': frame(typ=1),
    'reserved_type': frame(typ=7),
    'bad_version': frame(flags=0x10),
    'truncated_hdr': frame(trunc=4),
    'gpdu_no_inner': frame(length=0, payload=b''),
    'len_overflow': frame(length=0xFFFF, payload=b'\x45\x00\x00\x14'),
    # E flag, next extension 0x85 (PDU Session Container): one 4-octet container
    # (UL PDU session information, QFI 5) and then the inner packet.
    'psc_valid': frame(flags=0x34, opt=struct.pack('!HBB', 0, 0, 0x85) + bytes([1, 0x10, 0x05, 0])),
    # The same flags, then an extension header whose length byte (0xff) runs far
    # past the packet.
    'psc_malformed': frame(flags=0x34, opt=struct.pack('!HBB', 0, 0, 0x85), payload=b'\xff\x85\x00'),
}

def render(out, names, control_plane=False):
    target = os.environ.get('UPF_TARGET', 'graph')
    if target not in ('graph', 'appliance'):
        raise ValueError('UPF_TARGET must be graph or appliance')
    default = 'session-path-appliance.yaml' if target == 'appliance' else 'session-path.yaml'
    path = os.environ.get('GRAPH') or os.path.join(ROOT, 'deploy', default)
    with open(path) as f:
        deployment = yaml.safe_load(f)
    modules = {m['name']: m for m in deployment['modules']}
    if target == 'appliance':
        assert modules['upf']['mclass'] == 'UpfAppliance', 'appliance fixture must own a real UpfAppliance'
    else:
        assert modules['decap0']['mclass'] == 'GtpuDecap', 'graph fixture must own GtpuDecap'
        # Observe the real responder's output, not an internal test tap.
        deployment['modules'].append({'name': 'sink_control', 'mclass': 'Sink'})
        deployment['connections'].append({'upstream': 'echo_err', 'downstream': 'sink_control'})
    # Isolate one N3 stream: no downlink, Error Indication or End Marker
    # background traffic may contribute PDR failures, URR usage or replies.
    for name in ('src_err', 'src_em', 'src_dn', 'src_up'):
        modules[name]['arg']['burst'] = 0
    if not control_plane:
        frames = [VARIANTS[name] for name in names]
        # This is a disposition/conservation test, not a QER overload test.
        # Source has no packet/rate limit of its own. A one-packet burst at
        # 100 pps stays below the unchanged n4bench 1-Mbit/s UL QER (and
        # pfcpsim's higher MBRs), so every valid input must still be counted
        # and forwarded. Bound scheduler credit too, to avoid a resume burst.
        modules['src_up']['arg'].update(pkt_size=max(map(len, frames)), burst=1)
        deployment.setdefault('traffic_classes', []).append({
            'name': 'cntc_n3_rate', 'policy': 'rate_limit', 'resource': 'packet',
            'wid': 0, 'limit': {'packet': 100}, 'max_burst': {'packet': 1}})
        deployment['tasks'] = [
            task for task in deployment.get('tasks', [])
            if task['module'] != 'src_up' or task.get('task', 0) != 0]
        deployment['tasks'].append({'module': 'src_up', 'parent': 'cntc_n3_rate'})
        modules['rewrite_up']['arg']['templates'] = [
            base64.b64encode(frame).decode() for frame in frames]
    # No daemon shares another run's marker socket (including CF-only runs).
    marker = os.path.join(os.path.abspath(os.environ.get('TMPDIR', os.path.dirname(out))),
                          'cntc-marker-%s.sock.1' % os.environ.get('BESS_PORT', os.getpid()))
    for port in deployment.get('ports', []):
        if port['name'] == 'cp_marker':
            port['arg']['path'] = marker
    with open(out, 'w') as f:
        yaml.safe_dump(deployment, f, sort_keys=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('out')
    parser.add_argument('variants', nargs='*', metavar='variant')
    parser.add_argument('--control-plane', action='store_true')
    args = parser.parse_args()
    render(args.out, args.variants or list(VARIANTS), args.control_plane)
