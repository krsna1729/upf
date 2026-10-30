#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Snapshot and check one CNTC N3 stream after pausing its worker.

Graph: decap0/0 is admission, decap0/2 is control/unknown, rt/0 is
user forwarding. Appliance has no internal gates: get_counts reads its
real UL/DL/buffer URR banks, get_drops identifies the terminal parser or
control verdict, and physical outputs 0/1 are N6/N3. Exact accounting of
EVERY sent frame to an early drop (and zero other reasons, URR usage and
outputs) proves malformed traffic never reached a PDR, not merely that a
later stage discarded it. Unknown TEID and Echo must each produce an N3
reply per input; reserved type must be consumed as control_type. The graph
checks those responder outcomes too. Background sources are disabled by
frames.py, so no unrelated traffic can satisfy or pollute this accounting.

The four printed numbers retain the historical semantic observation names
sent/admitted/gate2/routed for comparable normalized verdicts. Appliance
admitted is measured user traffic, gate2 is the actual control disposition
(reply or unsupported-type consumption), NOT invented internal tap gates.
Raw observations are saved beside each variant's log, including zeroes.
Not every installed PDR is measured by a PFCP URR. --arm registers each
forwarding PDR's real ActionId in its counting bank before traffic starts,
so a zero reading is a real negative control. Drop/default and buffer
rules are not forwarding rules and get no fabricated ActionIds. This
changes no PDR/FAR/admission rule or PFCP message; these are the same
counter entries a measured session uses.
"""
import base64
import json
import re
import subprocess
import sys


def arm(bessctl, server, target, path):
    def ctl(*args):
        return subprocess.check_output([bessctl, '-s', server, *args], text=True)

    ctl('pause')
    deployment = json.loads(ctl('get', '-o', 'json'))
    resources = deployment['resources']
    for direction in ('ul', 'dl'):
        pdr = f'upf/pdr_{direction}' if target == 'appliance' else f'pdr_{direction}/rules'
        counter = f'upf/counters_{direction}' if target == 'appliance' else f'cnt_{direction}/counters'
        ids = set()
        for entry in resources[pdr]:
            gate = int(entry['value'].get('gate', 0))
            if gate in (1, 8192):  # buffer or DROP_GATE: not a forwarding action
                continue
            if gate != 0:
                raise ValueError(f'{pdr}: unexpected PDR gate {gate}')
            result = base64.b64decode(entry['value']['result'], validate=True)
            action_id = int.from_bytes(result[:4], 'big')
            if len(result) < 4 or not action_id:
                raise ValueError(f'{pdr}: expected a forwarding PDR with a real ActionId')
            ids.add(action_id)
        if direction == 'ul' and not ids:
            raise ValueError(f'{pdr}: no PFCP-programmed uplink forwarding rule')
        existing = {int(entry['key']['action_id']) for entry in resources.get(counter, [])}
        resources.setdefault(counter, []).extend(
            {'key': {'action_id': action_id}, 'value': {}}
            for action_id in sorted(ids - existing))
    with open(path, 'w') as f:
        json.dump(deployment, f, indent=2)
        f.write('\n')
    ctl('apply', path)


def observe(bessctl, server, target, variant, path):
    def ctl(*args):
        return subprocess.check_output([bessctl, '-s', server, *args], text=True)

    def action(module, name, arg=None):
        return json.loads(ctl('action', module, name, json.dumps(arg or {}), '-o', 'json'))

    ctl('pause')
    metrics = {}
    for line in ctl('metrics').splitlines():
        match = re.fullmatch(r'bess_gate_packets_total\{([^}]*)\}\s+(\S+)', line)
        if not match:
            continue
        labels = dict(re.findall(r'(\w+)="([^"]*)"', match[1]))
        if labels.get('direction') == 'out':
            metrics[(labels['module'], int(labels['gate']))] = int(float(match[2]))

    def packets(module, gate=0):
        return metrics.get((module, gate), 0)

    banks = [('upf', name) for name in ('counters_ul', 'counters_dl', 'buffer_counters')] if target == 'appliance' else [('cnt_ul', ''), ('cnt_dl', '')]
    counts = {table or module: action(module, 'get_counts', {'table': table} if table else {}) for module, table in banks}
    usage = sum(int(count.get('packets', 0)) for bank in counts.values() for count in bank.get('counts', []))
    drops = {entry['reason']: int(entry.get('count', 0)) for entry in action('upf', 'get_drops').get('drops', [])} if target == 'appliance' else {}
    sent = packets('src_up')
    routed = packets('upf', 0) if target == 'appliance' else packets('rt')
    reply = packets('upf', 1) if target == 'appliance' else packets('echo_err')
    admitted = usage if target == 'appliance' else packets('decap0')
    gate2 = reply + drops.get('control_type', 0) if target == 'appliance' else packets('decap0', 2)
    snapshot = dict(target=target, variant=variant, sent=sent, admitted=admitted,
                    gate2=gate2, routed=routed, reply=reply, usage=usage,
                    drops=drops, counts=counts,
                    gates={f'{module}/{gate}': value for (module, gate), value in metrics.items()})
    with open(path, 'w') as f:
        json.dump(snapshot, f, indent=2, sort_keys=True)
        f.write('\n')

    def require(condition, message):
        if not condition:
            raise ValueError(f'{variant}: {message}; observations: {path}')

    require(sent > 0, 'nothing was sent')
    require(bool(counts['counters_ul' if target == 'appliance' else 'cnt_ul'].get('counts')), 'no programmed uplink counter exists')
    if target == 'appliance':
        require('malformed_gtpu' in drops and 'control_type' in drops, 'get_drops did not return admission/control reasons')
    if variant in ('valid', 'psc_valid'):
        require(admitted == sent and usage == sent and routed == sent and gate2 == 0 and reply == 0,
                'valid frames must all be admitted, counted and forwarded only to N6')
        require(not any(drops.values()), 'valid frames hit an appliance drop reason')
    else:
        require(admitted == 0 and usage == 0 and routed == 0,
                'non-user traffic reached admission, URR accounting or N6')
        if variant in ('unknown_teid', 'echo_request', 'reserved_type'):
            require(gate2 == sent, 'control/unknown traffic did not all use the control path')
            if variant == 'reserved_type':
                require(reply == 0, 'reserved message type produced a reply')
                expected = {'control_type'} if target == 'appliance' else set()
            else:
                require(reply == sent, 'unknown TEID/Echo did not produce exactly one N3 reply per input')
                expected = set()
        else:
            require(gate2 == 0 and reply == 0, 'malformed traffic left parser/admission')
            expected = {'malformed_gtpu'} if target == 'appliance' else set()
        if target == 'appliance':
            require(sum(drops.get(reason, 0) for reason in expected) == (sent if expected else 0),
                    'not every input is accounted for by its early/control disposition')
            require(not any(value for reason, value in drops.items() if reason not in expected),
                    'traffic reached an unexpected or later drop stage (including PDR)')
    print(sent, admitted, gate2, routed)


if __name__ == '__main__':
    try:
        if sys.argv[1] == '--arm':
            arm(*sys.argv[2:])
        else:
            observe(*sys.argv[1:])
    except (ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
