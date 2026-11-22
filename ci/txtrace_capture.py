# SPDX-License-Identifier: BSD-3-Clause
"""Linux recorder for bench-churn's optional cross-process transaction trace."""
import json
import os
import re
import select
import signal
import subprocess
import time

POINTS = ('frame_read', 'lock_request', 'lock_acquired', 'apply_enter', 'apply_leave',
          'lock_release', 'write_enter', 'write_leave')


def offsets(binary):
    # Kernel uprobes take file offsets. Derive them from the ELF notes and
    # executable segments: perf's cache can return virtual addresses for PIEs.
    notes = subprocess.check_output(['readelf', '-n', str(binary)], text=True)
    headers = subprocess.check_output(['readelf', '-lW', str(binary)], text=True)
    loads = [tuple(int(x, 16) for x in m) for m in re.findall(
        r'^\s*LOAD\s+(0x\w+)\s+(0x\w+)\s+0x\w+\s+(0x\w+)\s+0x\w+\s+R\s+E\s',
        headers, re.M)]
    result = {}
    for point, raw in re.findall(r'Provider: bess_tx\s+Name: (\w+)\s+Location: (0x\w+),', notes):
        address = int(raw, 16)
        candidates = [offset + address - vaddr for offset, vaddr, size in loads
                      if vaddr <= address < vaddr + size]
        if point in result or len(candidates) != 1:
            raise ValueError(f'ambiguous ELF offset for SDT point {point}')
        result[point] = candidates[0]
    return result


def capture(out, upfd, bessd, binary, cpus, *, upfd_binary=None):
    """Record one Go window inside a wider perf window; exact pids belong to the lane."""
    out.mkdir(mode=0o700)
    cache = ['perf', '--buildid-dir', str(out / 'buildids')]
    subprocess.run(cache + ['buildid-cache', '-a', str(binary)], check=True)
    addresses = offsets(binary)
    # Resolve the argument locations from the binary's SDT notes, never from
    # an ABI guess. Use a private probe group and remove only installed events.
    group = f'upf_tx_{os.getpid()}'
    sudo = ['sudo', '-n']
    installed = []
    tracefs = '/sys/kernel/tracing/dynamic_events'
    def install(definition):
        subprocess.run(sudo + ['tee', '-a', tracefs], input=definition + '\n',
                       text=True, stdout=subprocess.DEVNULL, check=True)

    try:
        for point in POINTS:
            definition = subprocess.check_output(cache + [
                'probe', '-x', str(binary), '--definition', f'%sdt_bess_tx:{point}',
            ], text=True).strip()
            old = f'p:sdt_bess_tx/{point} '
            if not definition.startswith(old) or '\n' in definition:
                raise RuntimeError(f'expected one SDT definition for {point}: {definition!r}')
            if point not in addresses:
                raise RuntimeError(f'missing {point} SDT note; build bessd with -Dtransaction_trace=true')
            rest = definition[len(old):].split()
            definition = ' '.join([f'{binary}:0x{addresses[point]:x}', *rest[1:]])
            install(f'p:{group}/{point} ' + definition)
            installed.append(point)

        for name in ('control', 'ack'):
            os.mkfifo(out / name, 0o600)
        ctl = os.open(out / 'control', os.O_RDWR)
        ack = os.open(out / 'ack', os.O_RDWR)
        data = out / 'perf.data'
        try:
            with (out / 'perf.log').open('w') as log, subprocess.Popen(sudo + [
                'perf', 'record', '-a', '-C', ','.join(map(str, sorted(cpus))),
                '-k', 'CLOCK_MONOTONIC', '-D', '-1',
                '--control', f'fifo:{out / "control"},{out / "ack"}', '-o', str(data),
                '-e', 'sched:sched_switch/call-graph=fp/', '-e', 'sched:sched_waking',
                '-e', 'sched:sched_wakeup', '-e', 'sched:sched_wakeup_new',
                '-e', f'{group}:*', '--', 'sleep', '4',
            ], stdout=log, stderr=log) as perf:
                os.write(ctl, b'enable\n')
                if not select.select([ack], [], [], 3)[0] or os.read(ack, 128).strip(b'\x00\n') != b'ack':
                    raise RuntimeError(f'perf never armed; see {out / "perf.log"}')
                start = time.monotonic_ns()
                pidfd = os.pidfd_open(upfd)
                try:
                    if upfd_binary and os.readlink(f'/proc/{upfd}/exe') != str(upfd_binary):
                        raise RuntimeError('upfd process does not match the benchmark binary')
                    signal.pidfd_send_signal(pidfd, signal.SIGUSR2)
                    time.sleep(1.25)
                    os.write(ctl, b'disable\n')
                finally:
                    os.close(pidfd)
                if perf.wait() != 0:
                    raise RuntimeError(f'perf failed; see {out / "perf.log"}')
        finally:
            os.close(ctl)
            os.close(ack)
            (out / 'control').unlink()
            (out / 'ack').unlink()
            if data.exists():
                subprocess.run(sudo + ['chown', f'{os.getuid()}:{os.getgid()}', str(data)], check=True)
        (out / 'capture.json').write_text(json.dumps({
            'upfd': upfd, 'bessd': bessd, 'group': group, 'start_ns': start,
            'cpus': sorted(cpus),
        }) + '\n')
        return start
    finally:
        for point in installed:
            install(f'-:{group}/{point}')