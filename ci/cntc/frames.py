#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
#
# The N3 frames of TOSSI CNTC's robustness suite (upfbench/suites/n3neg/_pktgen.py:
# a valid G-PDU, an unknown TEID, control and reserved message types, a wrong
# version, three truncations, a valid and a malformed PDU Session Container),
# built byte by byte -- no scapy -- and written into a copy of
# deploy/session-path.yaml whose uplink Rewrite carries them.
#
#   frames.py <out.yaml> <variant> [<variant> ...]
import base64
import os
import re
import struct
import sys

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

if __name__ == '__main__':
    out, names = sys.argv[1], sys.argv[2:] or list(VARIANTS)
    tpl = '\n'.join('        - "%s"' % base64.b64encode(VARIANTS[n]).decode() for n in names)
    src = open(os.path.join(ROOT, 'deploy/session-path.yaml')).read()
    new = re.sub(r'(  - name: rewrite_up\n    mclass: Rewrite\n    arg:\n      templates:\n)        - "[^"]*"\n',
                 lambda m: m.group(1) + tpl + '\n', src)
    assert new != src, 'deploy/session-path.yaml no longer has the rewrite_up block this script replaces'
    new = new.replace('arg: {pkt_size: 87, burst: 32}', 'arg: {pkt_size: 100, burst: 32}', 1)
    open(out, 'w').write(new)
