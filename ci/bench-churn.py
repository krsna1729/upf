#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Bounded PFCP churn with real packets and acknowledged usage reports.

Build upfd and cmd/churnbench first. No builds run during measurements.
All daemons have no-swap scopes inside an aggregate memory-limited slice.
--instrumented enables the measurement-only CHURN_PROFILE_ADDR overlay; normal
product binaries instead provide their production Prometheus metrics.
"""
import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent.parent


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + "\n")


def cgroup():
    entry = Path('/proc/self/cgroup').read_text().strip()
    return Path('/sys/fs/cgroup') / entry.split('0::', 1)[1].lstrip('/')


def group_state(path):
    return {name: (path / name).read_text().strip()
            for name in ('memory.current', 'memory.peak', 'memory.events',
                         'memory.stat', 'cpu.stat') if (path / name).exists()}


def child(prefix, command):
    """Keep the scope alive long enough to read its final memory counters."""
    prefix = Path(prefix)
    group = cgroup()
    p = subprocess.Popen(command)
    save(str(prefix) + '.process.json', {'pid': p.pid, 'cgroup': str(group),
         'launch_cpu_affinity': sorted(os.sched_getaffinity(0))})
    def stop(_sig, _frame):
        if p.poll() is None:
            p.terminate()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    rc = p.wait()
    save(str(prefix) + '.final.json', {'returncode': rc, 'cgroup': group_state(group)})
    return rc if rc >= 0 else 128 - rc


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def request(url, payload=None, timeout=60, text=False):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            data = response.read()
    except urllib.error.HTTPError as error:
        detail = error.read().decode(errors='replace').strip()
        raise RuntimeError(f'{url}: HTTP {error.code}: {detail}') from error
    return data.decode() if text else json.loads(data)


def metrics(text):
    out = {}
    for line in text.splitlines():
        if not line or line.startswith('#'):
            continue
        key, value = line.rsplit(' ', 1)
        if '{' in key:
            name, labels = key.split('{', 1)
            pairs = sorted(re.findall(r'(\w+)="([^"]*)"', labels))
            key = name + '{' + ','.join(k + '="' + v + '"' for k, v in pairs) + '}'
        out[key] = float(value)
    return out

def udp_state(driver_address, upf_port):
    """Separate client/server socket drops from aggregate namespace losses."""
    lines = Path('/proc/net/snmp').read_text().splitlines()
    namespace = {}
    for header, values in zip(lines, lines[1:]):
        if header.startswith('Udp:') and values.startswith('Udp:'):
            namespace = dict(zip(header.split()[1:], map(int, values.split()[1:])))
            break
    ports = {'driver': int(driver_address.rsplit(':', 1)[1]), 'upfd': upf_port}
    sockets = {}
    for line in Path('/proc/net/udp').read_text().splitlines()[1:]:
        fields = line.split()
        local_port = int(fields[1].split(':')[1], 16)
        for name, number in ports.items():
            if local_port == number:
                tx, rx = fields[4].split(':')
                sockets[name] = {'receive_drops': int(fields[-1]),
                    'send_queue_bytes': int(tx, 16), 'receive_queue_bytes': int(rx, 16)}
    if sockets.keys() != ports.keys():
        raise RuntimeError(f'UDP socket evidence missing: {sockets}, expected {ports}')
    return {'namespace': namespace, 'sockets': sockets}



def checksum(data):
    if len(data) % 2:
        data += b'\0'
    value = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def ipv4(src, dst, payload, tos=0):
    header = struct.pack('!BBHHHBBH4s4s', 0x45, tos, 20 + len(payload), 0,
                         0x4000, 64, 17, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return header[:10] + struct.pack('!H', checksum(header)) + header[12:] + payload


def packet(index, uplink):
    ue = str(ipaddress.IPv4Address(0x0a000000 + index))
    data = b'hello-upf'
    udp = struct.pack('!HHHH', 5000, 53, 8 + len(data), 0) + data
    if uplink:
        inner = ipv4(ue, '8.8.8.8', udp)
        gtpu = struct.pack('!BBHI', 0x30, 255, len(inner), 0x100000 + index) + inner
        outer = struct.pack('!HHHH', 2152, 2152, 8 + len(gtpu), 0) + gtpu
        frame = bytes.fromhex('0200000000020200000000010800') + ipv4('10.20.30.2', '192.0.2.1', outer)
    else:
        frame = bytes.fromhex('0200000006010200000006020800') + ipv4('8.8.8.8', ue, udp, 0xb8)
    return base64.b64encode(frame).decode()


def graph(args, capacity, counters, fteids):
    """Use the proven session-path appliance's interfaces and routing contract."""
    upf = {'name': 'upf', 'mclass': 'UpfSessionAppliance', 'arg': {
        'session': {'capacity': capacity, 'max_actions': 2, 'max_qers': 2},
        'decap': {'max_fteids': fteids},
        'counters': {'capacity': counters, 'worker_planes': 1},
        'interfaces': [
            {'ingress_gate': 0, 'output_gate': 1, 'id': 1, 'endpoint_id': 1,
             'mac_addr': '02:00:00:00:00:02', 'ip_addr': '192.0.2.1',
             'addresses': ['192.0.2.1/24'], 'transport_route_domain': 1},
            {'ingress_gate': 4, 'output_gate': 0, 'id': 1, 'n6': True,
             'mac_addr': '02:00:00:00:06:01', 'ip_addr': '192.0.2.2',
             'addresses': ['192.0.2.2/24']}],
        'next_hop_classes': [
            {'egress_gate': 0, 'action': 'OUTPUT', 'output_gate': 0},
            {'egress_gate': 1, 'action': 'ENCAP'}]}}
    modules = [upf, {'name': 'sink_n6', 'mclass': 'Sink'},
               {'name': 'sink_n3', 'mclass': 'Sink'},
               {'name': 'sink_control', 'mclass': 'Sink'},
               {'name': 'n3_data', 'mclass': 'ExactMatch', 'arg': {
                   'fields': [{'offset': 43, 'num_bytes': 1}], 'default_gate': 1}}]
    links = [{'upstream': 'upf', 'downstream': 'sink_n6', 'ogate': 0},
             {'upstream': 'upf', 'downstream': 'n3_data', 'ogate': 1},
             {'upstream': 'n3_data', 'downstream': 'sink_n3', 'ogate': 0},
             {'upstream': 'n3_data', 'downstream': 'sink_control', 'ogate': 1}]
    for name, uplink, gate in [('ul', True, 0), ('dl', False, 4)]:
        modules += [
            {'name': 'src_' + name, 'mclass': 'Source', 'arg': {
                'pkt_size': 87 if uplink else 51, 'burst': 32}},
            {'name': 'rewrite_' + name, 'mclass': 'Rewrite', 'arg': {
                'templates': [packet(i, uplink) for i in range(args.probes)]}}]
        links += [{'upstream': 'src_' + name, 'downstream': 'rewrite_' + name},
                  {'upstream': 'rewrite_' + name, 'downstream': 'upf', 'igate': gate}]
    return {'modules': modules, 'connections': links,
            'workers': [{'wid': 0, 'core': args.worker_cpu}],
            'resources': {
                'upf/next_hops': [
                    {'key': {'id': 1}, 'value': {'egress_gate': 0,
                        'dst_mac': 'AgAAAAYC', 'src_mac': 'AgAAAAYB'}},
                    {'key': {'id': 2}, 'value': {'egress_gate': 1}}],
                'upf/transport_next_hops': [{'key': {'id': 1}, 'value': {'egress_gate': 0}}],
                'upf/transport_routes': [{'key': {'ipv4': '0.0.0.0', 'prefix_length': 0,
                    'domain': 1}, 'value': {'next_hop_id': 1}}],
                'n3_data/rules': [{'key': {'fields': [{'value_int': 255}]},
                                   'value': {'gate': 0}}]}}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--stage', type=Path, required=True)
    p.add_argument('--bessd', type=Path)
    p.add_argument('--upfd', type=Path, required=True)
    p.add_argument('--driver', type=Path, required=True)
    p.add_argument('--plugin', type=Path, default=ROOT / 'datapath/build')
    p.add_argument('--evidence', type=Path, required=True)
    p.add_argument('--sessions', type=int, default=1000000)
    p.add_argument('--cohort', type=int, default=65536)
    p.add_argument('--probes', type=int, default=16)
    p.add_argument('--seconds', type=int, default=30)
    p.add_argument('--rates', default='1000,10000,100000')
    p.add_argument('--modes', default='far,pdr,qer,urr,replace,establish,delete')
    p.add_argument('--transport', choices=['tcp', 'uds'], default='tcp')
    p.add_argument('--bess-control-cpu', type=int, required=True)
    p.add_argument('--upfd-cpu', type=int, required=True)
    p.add_argument('--upfd-gomaxprocs', type=int, default=1,
                   help='UPFD Go execution slots; default matches its single-CPU affinity')
    p.add_argument('--worker-cpu', type=int, required=True)
    p.add_argument('--client-cpus', required=True)
    p.add_argument('--bess-mib', type=int, default=3000)
    p.add_argument('--upfd-mib', type=int, default=5300)
    p.add_argument('--lane-mib', type=int, default=7872)
    p.add_argument('--instrumented', action='store_true', help='Measurement-overlay runtime/heap snapshots; not an uninstrumented product run')
    p.add_argument('--perf', action='store_true', help='Child-inherited user-mode sampling of BESS and UPF; corroborate with a plain product run')
    p.add_argument('--perf-event', default='cycles:u')
    args = p.parse_args()
    if args.sessions <= 0 or args.cohort <= 0 or not 1 <= args.probes <= min(32, args.sessions):
        p.error('positive populations and 1..32 traffic probes are required')
    if args.upfd_gomaxprocs <= 0:
        p.error('UPFD Go execution slots must be positive')
    rates = [int(x) for x in args.rates.split(',')]
    modes = args.modes.split(',')
    if any(x <= 0 or x > 1000000 for x in rates) or not 1 <= args.seconds <= 300:
        p.error('rates must be 1..1000000 and duration 1..300 seconds')
    if not set(modes) <= {'establish', 'delete', 'replace', 'far', 'pdr', 'qer', 'urr'}:
        p.error('unknown churn mode')
    args.evidence.mkdir(parents=True, exist_ok=False)
    out = args.evidence.resolve()
    runner_source = Path(__file__).read_bytes()
    (out / 'runner.py').write_bytes(runner_source)
    stage = args.stage.resolve()
    bp, np, mp, hp, dp = [port() for _ in range(5)]
    endpoint = f'127.0.0.1:{bp}' if args.transport == 'tcp' else 'unix:' + str(out / 'control.sock')
    env = dict(os.environ, GOMAXPROCS='2', TMPDIR=str(out), GLOG_log_dir=str(out))
    env['LD_LIBRARY_PATH'] = str(stage / 'lib') + ':' + env.get('LD_LIBRARY_PATH', '')
    lane = f'app-upfchurn{os.getpid()}.slice'
    roles = []
    stop = threading.Event()
    phase = 'setup'
    summary = {'arguments': vars(args) | {'stage': str(stage)}, 'endpoint': endpoint,
               'start': time.time(), 'kernel': os.uname().release, 'rows': [],
               'active_traffic_sessions': args.probes,
               'finite_cohort_note': 'establish/delete offer min(rate*seconds,cohort) distinct sessions; report actual duration'}
    summary['arguments'] = {k: str(v) if isinstance(v, Path) else v for k, v in summary['arguments'].items()}
    summary['observers'] = {'runtime_heap_overlay': args.instrumented, 'perf': args.perf,
                            'go_cpu_sampling': False}
    summary['sha256'] = {'runner': hashlib.sha256(runner_source).hexdigest()}
    lane_group = None
    thread = None
    upf_pidfd = None

    def healthy():
        for name, proc, _unit in roles:
            if proc.poll() is not None:
                raise RuntimeError(f'{name} exited early: {proc.returncode}')

    def wait_for(fn, seconds=120):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            healthy()
            try:
                value = fn()
                if value is not None:
                    return value
            except (OSError, ValueError):
                pass
            time.sleep(.2)
        raise TimeoutError('endpoint did not become ready')

    def scope(name, command, limit, cpus, extra=None):
        unit = f'upfchurn-{os.getpid()}-{name}'
        log = open(out / (name + '.log'), 'w')
        cmd = ['systemd-run', '--user', '--scope', '-q', f'--slice={lane}',
               f'--unit={unit}', '-p', f'MemoryMax={limit}M', '-p', 'MemorySwapMax=0',
               'taskset', '-c', cpus, sys.executable, str(Path(__file__).resolve()),
               '--child', str(out / name), *map(str, command)]
        proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT,
                                env=env | (extra or {}))
        log.close()
        roles.append((name, proc, unit + '.scope'))
        return proc

    def cgstates():
        result = {}
        for name, _proc, _unit in roles:
            meta = out / (name + '.process.json')
            if meta.exists():
                group = Path(json.loads(meta.read_text())['cgroup'])
                if group.exists():
                    result[name] = group_state(group)
        return result

    ctl = [str(stage / 'bin/bessctl'), '-s', endpoint]
    def bess_metrics():
        return metrics(subprocess.check_output(ctl + ['metrics'], env=env, text=True))

    def upf_metrics():
        return metrics(request(f'http://127.0.0.1:{mp}/metrics', text=True))

    def snapshot(label):
        after = label.endswith('-after')
        # Exclude the observer's forced GC from measured CPU deltas.
        groups = cgstates() if after else None
        value = {'time': time.time(), 'monotonic': time.monotonic(),
                 'load_average': os.getloadavg(),
                 'upf': upf_metrics(), 'bess': bess_metrics(),
                 'driver': request(f'http://127.0.0.1:{dp}/state')}
        value['udp'] = udp_state(value['driver']['local_udp_address'], np)
        if args.instrumented:
            value['runtime'] = request(f'http://127.0.0.1:{hp}/snapshot?gc=1&label={label}')
        value['cgroups'] = groups if after else cgstates()
        save(out / (label + '.json'), value)
        return value

    def monitor():
        with open(out / 'samples.jsonl', 'w') as f:
            while not stop.is_set():
                f.write(json.dumps({'time': time.time(), 'phase': phase, 'load_average': os.getloadavg(), 'cgroups': cgstates(),
                    'lane': group_state(lane_group) if lane_group and lane_group.exists() else {}}) + '\n')
                f.flush()
                stop.wait(2)

    def wrap_perf(role, command):
        if 'native_profiler' not in summary:
            summary['native_profiler'] = {
                'version': subprocess.check_output(['perf', '--version'], text=True).strip(),
                'mode': 'always-on child-inherited user-mode; no attach, privileged CPU-wide sampling or Go profiling timers',
                'scope': 'sampler shares each workload scope; BESS has 192 MiB extra; UPF retains its original limit',
                'call_graphs': {'bessd': 'dwarf,8192', 'upfd': 'fp'},
                'interpretation': 'separate sampled arm, including startup/fill/reconciliation; attribute only explicit measured-cell windows'}
        # A separate always-on arm preserves MMAP/COMM/FORK records too.
        # Turning the recorder off loses library/worker identity metadata.
        # DWARF unwinds the unmodified release native binary; Go retains FPs.
        graph = 'dwarf,8192' if role == 'bessd' else 'fp'
        return ['perf', 'record', '--no-buildid-cache', '--all-user', '--user-callchains',
                '--sample-cpu', '-F', '99', '-m', '64',
                '--call-graph', graph, '-e', args.perf_event, '-k', 'CLOCK_MONOTONIC',
                '-o', out / (role + '.perf.data'), '--', *command]



    try:
        subprocess.run(['systemctl', '--user', 'set-property', '--runtime', lane,
                        f'MemoryMax={args.lane_mib}M', 'MemorySwapMax=0'], check=True)
        subprocess.run(['systemctl', '--user', 'start', lane], check=True)
        group = subprocess.check_output(['systemctl', '--user', 'show', lane, '-p',
                                         'ControlGroup', '--value'], text=True).strip()
        lane_group = Path('/sys/fs/cgroup') / group.lstrip('/')
        maximum = max(rates)
        capacity = args.sessions + args.cohort + max(65536, maximum)
        counters = 1 << (max(65536, 2 * capacity) - 1).bit_length()
        fteids = 1 << (max(65536, args.sessions + args.cohort + 5 * maximum) - 1).bit_length()
        summary.update(session_capacity=capacity, counters=counters, fteids=fteids)
        save(out / 'graph.json', graph(args, capacity, counters, fteids))
        daemon = (args.bessd or stage / 'bin/bessd').resolve()
        for name, binary in [('bessd', daemon), ('upfd', args.upfd), ('driver', args.driver)]:
            summary.setdefault('sha256', {})[name] = hashlib.sha256(binary.read_bytes()).hexdigest()
        for binary in args.plugin.resolve().glob('*.so'):
            summary['sha256']['plugin/' + binary.name] = hashlib.sha256(binary.read_bytes()).hexdigest()
        daemon_command = [daemon, '--mem_backing=normal', f'--mem_limit_mb={args.bess_mib}',
             '--buffers=131072', '-skip_root_check', f'--grpc_url={endpoint}',
             f'--control_cpus={args.bess_control_cpu}',
             '-modules=' + str(args.plugin.resolve()), '-f', '-logtostderr']
        if args.perf:
            daemon_command = wrap_perf('bessd', daemon_command)
        scope('bessd', daemon_command, args.bess_mib + (192 if args.perf else 0),
              f'{args.bess_control_cpu},{args.worker_cpu}')
        wait_for(lambda: True if subprocess.run(ctl + ['status'], env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0 else None)
        subprocess.run(ctl + ['apply', str(out / 'graph.json')], env=env, check=True)
        subprocess.run(ctl + ['resume'], env=env, check=True)
        # Record runtime parallelism separately from the process CPU affinity.
        extra = {'GOMAXPROCS': str(args.upfd_gomaxprocs)}
        if args.instrumented:
            extra.update(CHURN_PROFILE_ADDR=f'127.0.0.1:{hp}', CHURN_PROFILE_OUT=str(out))
        upf_command = [args.upfd.resolve(), '-n4', f'127.0.0.1:{np}', '-node-id', '127.0.0.1',
             '-bess', endpoint, '-log-level', 'warn', '-capacity', counters, '-session-workers', 8,
             '-urr-interval', '1s', '-target', 'session-major', '-max-sessions', capacity,
             '-session-actions', 2, '-session-qers', 2, '-gtpu-decap', 'decap0',
             '-fteid-address', 'endpoint=1,reference=n3,transport-domain=1,source=access,ipv4=192.0.2.1',
             '-metrics', f'127.0.0.1:{mp}']
        if args.perf:
            upf_command = wrap_perf('upfd', upf_command)
        scope('upfd', upf_command, args.upfd_mib, str(args.upfd_cpu), extra)
        wait_for(upf_metrics)
        if args.perf:
            # Stop the workload, not its recorder, so perf can report its real
            # exit status and finish the data file before the scope disappears.
            perf_pid = json.loads((out / 'upfd.process.json').read_text())['pid']
            children = Path(f'/proc/{perf_pid}/task/{perf_pid}/children').read_text().split()
            for pid in map(int, children):
                if os.readlink(f'/proc/{pid}/exe') == str(args.upfd.resolve()):
                    upf_pidfd = os.pidfd_open(pid)
                    save(out / 'upfd.workload.json', {'pid': pid, 'perf_pid': perf_pid})
                    break
            else:
                raise RuntimeError('cannot identify the UPF workload child of perf')
        scope('driver', [args.driver.resolve(), '-upf', f'127.0.0.1:{np}', '-http', f'127.0.0.1:{dp}',
             '-sessions', args.sessions, '-cohort', args.cohort, '-probes', args.probes,
             '-workers', 64, '-out', out], 512, args.client_cpus,
             {'GOMAXPROCS': '4', 'GOMEMLIMIT': '448MiB'})
        wait_for(lambda: request(f'http://127.0.0.1:{dp}/state'))
        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()
        phase = 'fill'
        deadline = time.monotonic() + 14400
        while time.monotonic() < deadline:
            healthy()
            state = request(f'http://127.0.0.1:{dp}/state')
            if state['fill_error']:
                raise RuntimeError(state['fill_error'])
            if state['ready']:
                break
            print('fill', state['held'], '/', args.sessions, flush=True)
            time.sleep(5)
        else:
            raise TimeoutError('population fill exceeded deadline')
        time.sleep(3)
        loaded = snapshot('loaded')
        if loaded['upf']['upf_sessions'] != args.sessions:
            raise RuntimeError('loaded population mismatch')
        if not loaded['driver']['report_acknowledgements_sent'] or not loaded['driver']['report_wire_packets']:
            raise RuntimeError('no acknowledged nonzero traffic usage before measurement')
        if not loaded['upf']['upf_usage_reports_total{outcome="sent"}']:
            raise RuntimeError('UPF has not confirmed any report acknowledgement')
        for module, gate in [('upf', 0), ('n3_data', 0)]:
            key = f'bess_gate_packets_total{{direction="out",gate="{gate}",module="{module}"}}'
            if loaded['bess'].get(key, 0) <= 0:
                raise RuntimeError(f'no forwarded traffic on {module}:{gate}')
        for mode in modes:
            for rate in rates:
                profiled = args.perf
                healthy()
                prepared = None
                if mode in ('establish', 'delete'):
                    prepared = request(f'http://127.0.0.1:{dp}/prepare?mode={mode}', {}, timeout=1800)
                label = f'{mode}-{rate}-' + ('profile' if profiled else 'baseline')
                phase = label
                before = snapshot(label + '-before')
                start = time.monotonic()
                result = request(f'http://127.0.0.1:{dp}/run',
                    {'Mode': mode, 'Rate': rate, 'Seconds': args.seconds},
                    timeout=args.seconds + 90)
                end = time.monotonic()
                if result['state']['pending']:
                    raise RuntimeError('measured cell returned with pending requests')
                after = snapshot(label + '-after')
                if profiled:
                    summary.setdefault('perf_windows', {})[label] = [start, end]
                row = {'phase': label, 'profiled': profiled, 'start': start, 'end': end,
                       'result': result, 'before': before, 'after': after, 'prepare': prepared}
                summary['rows'].append(row)
                save(out / 'campaign.json', summary)
                print(label, json.dumps(result), flush=True)
                phase = 'reconcile-' + label
                request(f'http://127.0.0.1:{dp}/reconcile', {}, timeout=1800)
                state = request(f'http://127.0.0.1:{dp}/state')
                actual = upf_metrics()['upf_sessions']
                if state['held'] != args.sessions or state['uncertain'] or state['pending'] or actual != args.sessions:
                    raise RuntimeError(f'population reconciliation failed: {state}, upfd={actual}')
                time.sleep(2)
        summary['complete'] = True
    except (Exception, KeyboardInterrupt) as error:
        summary['error'] = repr(error)
        print('ERROR', repr(error), flush=True)
        try:
            summary['failure_snapshot'] = snapshot('failure')
        except Exception as snapshot_error:
            summary['failure_snapshot_error'] = repr(snapshot_error)
    finally:
        stop.set()
        summary['cleanup'] = {}
        if thread is not None:
            thread.join(timeout=5)
        for name, proc, unit in reversed(roles):
            if name == 'upfd' and upf_pidfd is not None and proc.poll() is None:
                try:
                    signal.pidfd_send_signal(upf_pidfd, signal.SIGTERM)
                    proc.wait(timeout=20)
                except (OSError, subprocess.TimeoutExpired) as error:
                    summary['cleanup']['upfd_workload_stop'] = repr(error)
            if name == 'bessd' and proc.poll() is None:
                try:
                    shutdown = subprocess.run(ctl + ['shutdown'], env=env,
                        capture_output=True, text=True, timeout=10)
                    summary['cleanup']['shutdown_rpc'] = {
                        'returncode': shutdown.returncode, 'stderr': shutdown.stderr}
                    if shutdown.returncode == 0:
                        proc.wait(timeout=20)
                except (OSError, subprocess.TimeoutExpired) as error:
                    summary['cleanup']['shutdown_rpc_error'] = repr(error)
            if proc.poll() is None:
                subprocess.run(['systemctl', '--user', 'kill', '--signal=TERM', unit],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    proc.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    subprocess.run(['systemctl', '--user', 'kill', '--signal=KILL', unit],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    try:
                        proc.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        summary['cleanup'][name + '_wait'] = 'timed out after kill'
        if upf_pidfd is not None:
            os.close(upf_pidfd)
        if lane_group and lane_group.exists():
            summary['lane_final'] = group_state(lane_group)
        for action in ('stop', 'revert'):
            rc = subprocess.run(['systemctl', '--user', action, lane], capture_output=True, text=True)
            summary['cleanup'][action] = {'returncode': rc.returncode, 'stderr': rc.stderr}
        summary['end'] = time.time()
        summary['returns'] = {name: proc.returncode for name, proc, _unit in roles}
        for name, expected in [('bessd', 0), ('upfd', 0), ('driver', 143)]:
            if name in summary['returns'] and summary['returns'][name] != expected:
                summary.setdefault('error', f'{name} exit {summary["returns"][name]}, expected {expected}')
        if 'error' in summary:
            summary['complete'] = False
        save(out / 'campaign.json', summary)
    return 1 if 'error' in summary else 0


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--child':
        raise SystemExit(child(sys.argv[2], sys.argv[3:]))
    raise SystemExit(main())
