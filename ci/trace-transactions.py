#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Turn bench-churn transaction traces into HTML and Perfetto JSON."""
import argparse
from bisect import bisect_right
from collections import Counter, defaultdict
from contextlib import contextmanager
import json
from pathlib import Path
import re
import subprocess

PERF_LINE = re.compile(r'^\s*(.*?)\s+(\d+)/(\d+)\s+\[\d+\]\s+(\d+)\.(\d+):\s+(\S+):\s*(.*)$')
GO_LINE = re.compile(r'^M=(-?\d+) P=(-?\d+) G=(-?\d+) (\w+) Time=(\d+) (.*)$')
GO_STATE = re.compile(r'^GoID=(\d+) (\w+)->(\w+) Reason="([^"]*)"')
GO_LOG = re.compile(r'^Task=\d+ Category="(bess\.\w+)" Message="([0-9a-f ]*)"')
ID = re.compile(r'[0-9a-f]{32}\Z')


@contextmanager
def output(command):
    with subprocess.Popen(command, stdout=subprocess.PIPE, text=True) as p:
        yield p.stdout
        if p.wait():
            raise RuntimeError(f'{command[0]} exited with status {p.returncode}')


def read_go(lines):
    marks, states, anchors, bounds = [], [], [], []
    receive_wakes = defaultdict(list)
    wake = None
    for line in lines:
        m = GO_LINE.match(line)
        if not m:
            if wake is not None and 'google.golang.org/grpc/internal/transport.(*http2Client).handleData @' in line:
                t, waiter = wake
                receive_wakes[waiter].append(t)
                wake = None
            continue
        wake = None
        thread, _, g, kind, ns, fields = m.groups()
        t = int(ns)
        if kind == 'Sync':
            bounds.append(t)  # the final Sync can omit a clock anchor
            a = re.search(r'\bTrace=(\d+) Mono=(\d+)', fields)
            if a:
                anchors.append((t, int(a[2]) - int(a[1])))
        elif kind == 'Log':
            log = GO_LOG.match(fields)
            if log:
                marks.append((t, int(thread), int(g), log[1][5:], log[2]))
        elif kind == 'StateTransition':
            state = GO_STATE.match(fields)
            if state:
                states.append((t, int(thread), int(g), int(state[1]), state[2], state[3], state[4]))
                if state[2] == 'Waiting' and state[3] == 'Runnable':
                    wake = (t, int(state[1]))
    if not anchors:
        raise ValueError('Go trace lacks a monotonic clock anchor; use the pinned Go version')
    offset = anchors[0][1]
    drift = max(abs(o - offset) for _, o in anchors)
    if drift > 50_000:
        raise ValueError(f'Go and perf clocks disagree by {drift} ns')
    return offset, drift, len(anchors), marks, states, bounds, receive_wakes


def read_perf(lines, meta):
    marks, switches, wakes = [], [], []
    losses = Counter()
    names = {}
    stack = None
    for line in lines:
        if re.search(r'\bPERF_RECORD_LOST(?:_SAMPLES)?\b', line):
            lost = re.search(r'\blost\s+(\d+)', line)
            if lost and int(lost[1]) > 0:
                losses['samples'] += int(lost[1])
            else:
                losses['records_without_count'] += 1
        if line.startswith('\t'):
            if stack is not None:
                stack.append(line.strip())
            continue
        stack = None
        m = PERF_LINE.match(line)
        if not m:
            continue
        comm, pid, tid, sec, frac, event, fields = m.groups()
        pid, tid = int(pid), int(tid)
        t = int(sec) * 10**9 + int(frac.ljust(9, '0'))
        if pid in (meta['upfd'], meta['bessd']):
            names[tid] = ('upfd' if pid == meta['upfd'] else 'bessd', comm)
        if event.startswith(meta['group'] + ':') and pid == meta['bessd']:
            a = dict(re.findall(r'arg([1-4])=(0x[0-9a-fA-F]+|[0-9]+)', fields))
            stage = event.split(':')[1]
            required = {'1', '2', '3'}
            if stage in ('frame_read', 'apply_enter', 'apply_leave', 'write_leave'):
                required.add('4')
            if not required <= a.keys():
                raise ValueError(f'USDT event has missing arguments: {line.strip()}')
            hi, lo, attempt, val = (int(a.get(str(i), '0'), 0) for i in range(1, 5))
            marks.append((t, tid, stage, f'{hi:016x}{lo:016x}', attempt, val))
        elif event == 'sched:sched_switch':
            x = re.search(r'prev_pid=(\d+).*?prev_state=(\S+).*?next_pid=(\d+)', fields)
            if x:
                stack = []
                switches.append((t, int(x[1]), int(x[3]), x[2], stack))
        elif event in ('sched:sched_waking', 'sched:sched_wakeup', 'sched:sched_wakeup_new'):
            a = re.search(r'\bpid=(\d+)', fields)
            if a:
                wakes.append((t, tid, int(a[1]), event.rsplit(':', 1)[1]))
    return marks, switches, wakes, names, losses


def intervals(transitions):
    result = defaultdict(list)
    last = {}
    for t, ident, state, why in sorted(transitions):
        if ident in last:
            start, old, reason = last[ident]
            if t > start:
                result[ident].append((start, t, old, reason))
        last[ident] = t, state, why
    return result


def kernel_intervals(switches, wakes, names, loss):
    # A loss record does not identify the missing transitions or when the
    # gap started. A thread can also migrate across CPUs. Leave the OS state
    # lanes blank rather than extending a state through a possible gap.
    if loss:
        return {}
    events = []
    for t, prev, nxt, state, stack in switches:
        if prev in names:
            why = next((s for s in ('futex', 'ep_poll', 'nanosleep', 'tcp_recvmsg')
                        if any(s in f for f in stack)), '')
            events.append((t, prev, 'runnable' if state.startswith('R') else 'blocked', why or state))
        if nxt in names:
            events.append((t, nxt, 'running', ''))
    events.extend((t, dst, 'runnable', 'scheduler wake') for t, _, dst, k in wakes
                  if dst in names and k != 'sched_waking')
    return intervals(events)


def join(go, bess, begin, end):
    client, server = defaultdict(list), defaultdict(list)
    commits = defaultdict(list)
    pfcp = defaultdict(list)
    for t, tid, g, stage, value in go:
        if stage.startswith(('commit_', 'encode_')) and ID.fullmatch(value):
            commits[value].append((stage, t, tid, g))
        elif stage in ('send', 'reply'):
            lead, attempt, slot, req = value.split()
            if ID.fullmatch(lead) and ID.fullmatch(req):
                client[lead, int(attempt), int(slot)].append((stage, t, tid, g, req))
        elif stage.startswith('pfcp_'):
            pfcp[g].append((t, stage))
    for t, tid, stage, lead, attempt, value in bess:
        server[lead, attempt].append((stage, t, tid, value))
    skipped = Counter()
    rows = []
    for (lead, attempt, slot), c in client.items():
        sides = {k: [x for x in c if x[0] == k] for k in ('send', 'reply')}
        if len(sides['send']) != 1 or len(sides['reply']) != 1:
            skipped['duplicate or incomplete client attempt'] += 1
            continue
        _, send, send_tid, grpc_g, req = sides['send'][0]
        _, reply, reply_tid, reply_g, returned = sides['reply'][0]
        s = server.get((lead, attempt), ())
        points = {}
        for key in ('frame_read', 'lock_request', 'lock_acquired', 'apply_enter',
                    'apply_leave', 'lock_release', 'write_enter', 'write_leave'):
            matches = [(t, tid) for k, t, tid, value in s if k == key and
                       (k not in ('apply_enter', 'apply_leave') or value == slot)]
            if len(matches) == 1:
                points[key] = matches[0]
        order = ('frame_read', 'lock_request', 'lock_acquired', 'apply_enter', 'apply_leave', 'lock_release', 'write_enter')
        if not all(k in points for k in order) or len({tid for _, tid in points.values()}) != 1:
            skipped['duplicate or incomplete server attempt'] += 1
            continue
        if 'write_leave' in points and not points['write_enter'][0] <= points['write_leave'][0] <= end:
            del points['write_leave']
        clocks = [send, *(points[k][0] for k in order), reply]
        if req != returned or grpc_g != reply_g or not begin <= send <= reply <= end or clocks != sorted(clocks):
            skipped['identity, clock, or window mismatch'] += 1
            continue
        commit = [k for k in commits[req] if k[0] == 'commit_enter' and k[1] <= send]
        leave = [k for k in commits[req] if k[0] == 'commit_leave' and k[1] >= reply]
        row = dict(request=req, lead=lead, attempt=attempt, slot=slot, send=send, reply=reply,
                   grpc_g=grpc_g, send_tid=send_tid, reply_tid=reply_tid, server_tid=points['frame_read'][1],
                   points={k: t for k, (t, _) in points.items()})
        if len(commit) == len(leave) == 1 and commit[0][3] == leave[0][3]:
            row.update(commit=commit[0][1], leave=leave[0][1], caller_g=commit[0][3])
            enc = {k: [p for p in commits[req] if p[0] == k and p[3] == row['caller_g']
                       and p[1] <= row['commit']] for k in ('encode_enter', 'encode_leave')}
            if all(len(v) == 1 for v in enc.values()):
                row.update(encode_enter=enc['encode_enter'][0][1], encode_leave=enc['encode_leave'][0][1])
                dispatch = pfcp[row['caller_g']]
                at = bisect_right(dispatch, (row['encode_enter'], '\uffff'))
                if 0 < at < len(dispatch) and dispatch[at-1][1] == 'pfcp_enter' and dispatch[at][1] == 'pfcp_leave':
                    row.update(pfcp_enter=dispatch[at-1][0], pfcp_leave=dispatch[at][0])
        rows.append(row)
    frame_count = len({k[:2] for k in client})
    server_count = sum(any(s == 'frame_read' and begin <= t <= end for s, t, _, _ in frames)
                       for frames in server.values())
    return sorted(rows, key=lambda r: r['send']), skipped, frame_count, server_count


def clip(seq, lo, hi):
    return [(max(a, lo), min(b, hi), k, why) for a, b, k, why in seq if a < hi and b > lo]


def mark_receive_dispatch(rows, wakes, offset):
    for r in rows:
        times = wakes.get(r['grpc_g'], ())
        start = bisect_right(times, r['points']['write_enter'] - offset - 1)
        end = bisect_right(times, r['reply'] - offset)
        if end == start + 1:
            r['receive_dispatch'] = times[start] + offset


def render(evidence, go_binary, template):
    directory = evidence / 'transactions'
    meta = json.loads((directory / 'capture.json').read_text())
    with output([go_binary, 'tool', 'trace', '-d=parsed', str(evidence / 'transactions.go.trace')]) as lines:
        offset, drift, anchor_count, go, states, bounds, receive_wakes = read_go(lines)
    with output(['perf', 'script', '--ns', '--show-lost-events', '-i', str(directory / 'perf.data'),
                 '-F', 'trace:comm,pid,tid,cpu,time,event,trace,ip,sym']) as lines:
        bess, switches, wakes, names, loss = read_perf(lines, meta)
    if not go or not bess or not switches:
        raise ValueError('capture has no Go markers, BESS markers, or scheduler switches')
    lo = max(min(x[0] for x in switches), bounds[0] + offset)
    hi = min(max(x[0] for x in switches), bounds[-1] + offset)
    if hi <= lo:
        raise ValueError('Go and perf capture windows do not overlap')
    go = [(t + offset, *rest) for t, *rest in go]
    states = [(t + offset, *rest) for t, *rest in states]
    rows, skipped, frame_count, server_count = join(go, bess, lo, hi)
    if not rows:
        raise ValueError(f'no complete attempts joined: {dict(skipped)}')
    mark_receive_dispatch(rows, receive_wakes, offset)
    ks = kernel_intervals(switches, wakes, names, loss)
    gs = intervals((t, g, state.lower().replace('waiting', 'blocked'), why)
                   for t, _, _, g, _, state, why in states
                   if state in ('Running', 'Waiting', 'Runnable', 'Syscall', 'NotExist'))
    trace, tracks = [], {}

    def track(name, seq):
        ident = len(tracks) + 1
        tracks[str(ident)] = (name, seq)
        trace.append(dict(ph='M', name='thread_name', pid=1, tid=ident, args={'name': name}))
        for a, b, label, why in seq:
            trace.append(dict(ph='X', name=label, pid=1, tid=ident, ts=(a-lo)/1000,
                              dur=(b-a)/1000, args={'detail': why}))
        return ident

    tids = {t: track(f'{p} {comm} T{t}', clip(ks.get(t, ()), lo, hi)) for t, (p, comm) in sorted(names.items())}
    gids = {g: track(f'upfd G{g}', clip(seq, lo, hi)) for g, seq in sorted(gs.items())}
    marks = [(t, tids.get(tid), 'BESS ' + stage, f'{lead}/{attempt}:{value}')
             for t, tid, stage, lead, attempt, value in bess]
    marks.extend((t, gids.get(g), 'Go ' + stage, value) for t, _, g, stage, value in go)
    for t, tid, stage, detail in marks:
        if tid is not None and lo <= t <= hi:
            trace.append(dict(ph='i', s='t', name=stage, pid=1, tid=tid, ts=(t-lo)/1000,
                              args={'identity': detail}))
    kernel_wakes = [(t, tids[src], tids[dst]) for t, src, dst, k in wakes
                    if k == 'sched_waking' and src in tids and dst in tids and lo <= t <= hi]
    go_wakes = [(t, gids[src], gids[dst]) for t, _, src, dst, old, new, _ in states
                if lo <= t <= hi and old == 'Waiting' and new == 'Runnable' and src in gids and dst in gids]
    edges = kernel_wakes + go_wakes
    for i, (t, src, dst) in enumerate(edges):
        for ph, tid in (('s', src), ('f', dst)):
            trace.append(dict(ph=ph, bp='e', id=i, name='wake', pid=1, tid=tid, ts=(t-lo)/1000))
    for r in rows:
        r['tracks'] = [gids.get(r.get('caller_g')), gids.get(r['grpc_g']),
                       tids.get(r['send_tid']), tids.get(r['reply_tid']), tids.get(r['server_tid'])]
    # Application flows link exact requests; scheduler wakes are a separate
    # category and do not claim to identify a socket operation.
    edge_id = len(edges)
    for r in rows:
        client, server = gids.get(r['grpc_g']), tids.get(r['server_tid'])
        if client is not None and 'receive_dispatch' in r:
            trace.append(dict(ph='i', s='t', name='Go HTTP/2 receive-queue wake', pid=1, tid=client,
                              ts=(r['receive_dispatch']-lo)/1000, args={'request_id': r['request']}))
        if client is None or server is None:
            continue
        for name, start, src, end, dst in (
            ('request', r['send'], client, r['points']['frame_read'], server),
            ('reply', r['points']['write_enter'], server, r['reply'], client),
        ):
            for ph, tid, t in (('s', src, start), ('f', dst, end)):
                trace.append(dict(ph=ph, bp='e', id=edge_id, name=name, cat='transaction',
                                  pid=1, tid=tid, ts=(t-lo)/1000, args={'request_id': r['request']}))
            edge_id += 1
    returned = sum(lo <= t <= hi and stage == 'commit_leave' for t, _, _, stage, _ in go)
    counts = sum(lo <= t <= hi and stage == 'counts_leave' for t, _, _, stage, _ in go)
    encoding = [r['encode_leave'] - r['encode_enter'] for r in rows if 'encode_leave' in r]

    def p50_us(values):
        ns = sorted(values)
        return round(ns[len(ns)//2]/1000, 2) if ns else None

    phases = {
        'pfcp_before_encode': p50_us(r['encode_enter'] - r['pfcp_enter'] for r in rows if 'pfcp_enter' in r),
        'encode': p50_us(encoding),
        'send_to_bess_read': p50_us(r['points']['frame_read'] - r['send'] for r in rows),
        'wait_for_control_lock': p50_us(r['points']['lock_acquired'] - r['points']['lock_request'] for r in rows),
        'apply': p50_us(r['points']['apply_leave'] - r['points']['apply_enter'] for r in rows),
        'bess_write_to_reply': p50_us(r['reply'] - r['points']['write_enter'] for r in rows),
        'bess_write': p50_us(r['points']['write_leave'] - r['points']['write_enter']
                             for r in rows if 'write_leave' in r['points']),
        'write_to_receive_dispatch': p50_us(r['receive_dispatch'] - r['points']['write_enter']
                                           for r in rows if 'receive_dispatch' in r),
        'receive_dispatch_to_reply': p50_us(r['reply'] - r['receive_dispatch']
                                           for r in rows if 'receive_dispatch' in r),
    }
    frame_sizes = Counter(value for t, _, stage, _, _, value in bess if stage == 'frame_read' and lo <= t <= hi)
    log = (directory / 'perf.log').read_text()
    reordered = re.search(r'(\d+) out of order', log)
    info = dict(overlap_ms=(hi-lo)/1e6, sender_frames=frame_count, server_frames=server_count,
                joined_requests=len(rows), skipped=dict(skipped), clock_drift_ns=drift,
                client_attempt_slots=len(rows) + sum(skipped.values()), clock_anchors=anchor_count,
                perf_loss=dict(loss), perf_out_of_order=int(reordered[1]) if reordered else 0,
                kernel_intervals_omitted=bool(loss),
                commit_returns_per_s=round(returned * 1e9/(hi-lo)),
                counts_rpc_returns=counts, encode_samples=len(encoding),
                pfcp_samples=sum('pfcp_enter' in r for r in rows),
                receive_dispatch_samples=sum('receive_dispatch' in r for r in rows),
                frame_sizes=dict(frame_sizes), median_us=phases)
    (directory / 'perfetto.json').write_text(json.dumps({'traceEvents': trace}))
    payload = json.dumps(dict(info=info, rows=rows, tracks=tracks, edges=edges)).replace('<', '\\u003c')
    (directory / 'timeline.html').write_text(template.read_text().replace('/* TRACE_PAYLOAD */ null', payload))
    (directory / 'quality.json').write_text(json.dumps(info, indent=2) + '\n')
    print(json.dumps(info, indent=2))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('evidence', type=Path, help='bench-churn evidence directory')
    p.add_argument('--go', default='go', help='Go executable used for the trace')
    a = p.parse_args()
    render(a.evidence, a.go, Path(__file__).with_name('txtrace.html'))
