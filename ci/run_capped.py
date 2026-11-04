#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Run one test under its declared memory bound and fail it above that.

Every Go test package and every datapath meson test declares the most memory
it may use, in MiB, in ci/test-memory.tsv (docs/engineering-guide.md, "Test
memory"). This script is how the declaration is held:

  * `go test -exec ci/run_capped.py` (ci/verify.sh, the lanes' live tests,
    the weekly -race run): the go command compiles and links outside, and this
    script runs only the test binary. The package is the binary's working
    directory (the go command runs it in the package's source directory); its
    row is `go <dir>`, or `go-race <dir>` for a binary built with -race (read
    from the binary's build info). A run of one test alone (-test.run=^Name$)
    that has a row of its own, `go <dir>:<Name>`, is held to that row:
    ci/go-test.sh runs such a test by itself and skips it in the package's run.
  * meson's default test setup (datapath/meson.build, add_test_setup): each
    test() passes its row as UPF_TEST_MEM_MB.

It runs the test in a cgroup of its own where it can: a transient
`systemd-run --user --scope` with MemoryMax at the kill limit (KILL_FACTOR
times the declaration, at least KILL_MIN_HEADROOM_MB above it) and no swap, so
a runaway test is stopped by the kernel in its own cgroup, not the session's.
It records the peak of the whole process tree: the scope's memory.peak, read
inside the scope before the scope goes away with its last process, or, with no
user manager to make a scope, wait4()'s ru_maxrss (the largest single process
of the tree: a lower bound when several run at once). It fails the test when
that peak is above the declaration: "declared X MiB, peak Y MiB".

Not RLIMIT_AS: an address-space limit bounds what a process reserves, not what
it touches, and Go's runtime reserves address space for its heap arenas and
goroutine stacks ahead of use. Measured 2026-11-04 (VmSize and VmHWM from
/proc, 1.5 s into the run): internal/session's test binary at 2955 MiB of
address space and 1237 MiB resident in its 2.1M-rule test; built with -race,
2083 MiB of address space and 267 MiB resident. An address-space limit at its
1736 MiB row would fail the first on a reservation, not on memory it uses.
The cgroup limit and memory.peak are resident (charged) memory, which is what
fills a machine.

Usage:
  go test -exec "$PWD/ci/run_capped.py" ./...          (the row from the table)
  UPF_TEST_MEM_MB=64 ci/run_capped.py [--no-scope] CMD [ARGS...]
  ci/run_capped.py --self-test

Environment:
  UPF_TEST_MEM_MB       the declaration, MiB (meson sets it; for a Go binary
                        it overrides the table's row)
  UPF_TEST_MEM_MEASURE  1: calibration; report the peak, never fail on it, kill
                        limit MEASURE_LIMIT_MB, a missing row allowed
  UPF_TEST_MEM_NO_SCOPE 1: as --no-scope (measure with wait4 only)
"""

import mmap
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import uuid

MIB = 1 << 20
ROOT = Path(__file__).resolve().parent.parent
TABLE = ROOT / 'ci' / 'test-memory.tsv'
# The kernel's limit is above the declaration, so a test that overshoots it by
# less than half runs to the end and fails with its measured peak; one that
# runs away is stopped at the limit. At least 32 MiB above: a small test's
# declaration is mostly its binary's pages.
KILL_FACTOR = 1.5
KILL_MIN_HEADROOM_MB = 32
# The kill limit in measure mode: the per-binary cap this host's test rule sets.
MEASURE_LIMIT_MB = 3000

# Runs inside the scope: notes that the scope exists (so the wrapper can tell
# "systemd-run could not make it" from "the test failed"), runs the test as a
# child, then reads the scope's counters while it still exists (a scope goes
# away with its last process) and exits with the test's status.
INNER = r'''
out=$1; shift
cg=$(cat /proc/self/cgroup); cg=/sys/fs/cgroup${cg#0::}
echo started > "$out"
"$@"
rc=$?
{
  echo "peak $(cat "$cg/memory.peak" 2>/dev/null || echo -1)"
  echo "oom_kill $(sed -n 's/^oom_kill //p' "$cg/memory.events" 2>/dev/null)"
} >> "$out"
exit $rc
'''


def table(path=TABLE):
    """{(kind, name): MiB} from ci/test-memory.tsv."""
    out = {}
    for line in path.read_text(encoding='utf-8').splitlines():
        fields = line.split()
        if len(fields) >= 3 and not fields[0].startswith('#') and fields[2].isdigit():
            out[(fields[0], fields[1])] = int(fields[2])
    return out


def race_built(binary):
    """A -race binary's build info carries the line "build\\t-race=true" (as
    `go version -m` prints it, indented there)."""
    try:
        with open(binary, 'rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
            return m.find(b'\nbuild\t-race=true\n') >= 0
    except (OSError, ValueError):
        return False


def go_row(binary, cwd, args=(), rows=None):
    """The table row a Go test binary is held to: its package directory, or
    <dir>:<Test> when it runs that one test alone and the table has its row."""
    try:
        pkg = Path(cwd).resolve().relative_to(ROOT).as_posix()
    except ValueError:
        pkg = str(cwd)
    kind = 'go-race' if race_built(binary) else 'go'
    for a in args:
        m = re.fullmatch(r'-test\.run=\^(Test\w+)\$', a)
        if m and (kind, f'{pkg}:{m.group(1)}') in (rows or {}):
            return kind, f'{pkg}:{m.group(1)}'
    return kind, pkg


def kill_limit_mb(declared_mb, measure):
    if measure:
        return MEASURE_LIMIT_MB
    return max(int(declared_mb * KILL_FACTOR + 0.5), declared_mb + KILL_MIN_HEADROOM_MB)


def read_lines(path):
    try:
        with open(path, encoding='utf-8') as f:
            return f.read().splitlines()
    except FileNotFoundError:
        return []


def spawn(cmd, env):
    """(status, ru_maxrss bytes): the child's wait4, which takes in every
    descendant it reaped; a signal N comes back as 128+N, as a shell says it.
    posix_spawn, not fork: a forked child's high-water mark would start at
    this interpreter's resident size."""
    pid = os.posix_spawnp(cmd[0], cmd, env)
    _, raw, usage = os.wait4(pid, 0)
    code = os.waitstatus_to_exitcode(raw)
    return (code if code >= 0 else 128 - code), usage.ru_maxrss * 1024


def run_in_scope(cmd, env, limit_mb):
    """(status, peak bytes, oom kills, how), or None when no scope could be made."""
    if not shutil.which('systemd-run'):
        return None
    unit = f'upf-test-{os.getpid()}-{uuid.uuid4().hex[:8]}'
    with tempfile.TemporaryDirectory(prefix='run_capped.') as tmp:
        out = os.path.join(tmp, 'scope')  # the inner script creates it: the proof
        # systemd-run --scope execs the shell in place: wait4 sees the test.
        # OOMPolicy=continue: the kernel kills the process that ran over, and
        # the shell lives to read the counters (the default stops the scope).
        status, maxrss = spawn(
            ['systemd-run', '--user', '--scope', '-q', f'--unit={unit}',
             '-p', f'MemoryMax={limit_mb}M', '-p', 'MemorySwapMax=0',
             '-p', 'OOMPolicy=continue',
             '--', 'sh', '-c', INNER, 'sh', out, *cmd], env)
        lines = read_lines(out)
    if not lines or lines[0] != 'started':
        return None
    fields = dict(line.split(' ', 1) for line in lines[1:] if ' ' in line)
    if 'peak' not in fields:
        # The shell was killed with the test: only the kernel's limit does that.
        return status, maxrss, 1, 'wait4 ru_maxrss, scope killed'
    peak = int(fields['peak'] or -1)
    oom = int(fields.get('oom_kill') or 0)
    if peak < 0:  # a kernel before 5.19 has no memory.peak
        return status, maxrss, oom, 'wait4 ru_maxrss, cgroup without memory.peak'
    return status, peak, oom, 'cgroup memory.peak'


def exit_like(status):
    """Exit as the test did: a signal again as a signal, so the runner names it."""
    sys.stdout.flush()
    sys.stderr.flush()
    if status > 128 and status - 128 < signal.NSIG:
        sig = status - 128
        signal.signal(sig, signal.SIG_DFL)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))  # the test dumped, if anyone
        os.kill(os.getpid(), sig)
    sys.exit(status)


def run(cmd, no_scope=False):
    measure = os.environ.get('UPF_TEST_MEM_MEASURE') == '1'
    no_scope = no_scope or os.environ.get('UPF_TEST_MEM_NO_SCOPE') == '1'
    declared = os.environ.get('UPF_TEST_MEM_MB', '')
    if cmd[0].endswith('.test'):  # a Go test binary: go test -exec
        rows = table()
        kind, name = go_row(cmd[0], os.getcwd(), cmd[1:], rows)
        if not declared:
            declared = str(rows.get((kind, name), ''))
        where = f'"{kind} {name}" in ci/test-memory.tsv'
    else:
        name = os.path.basename(cmd[0])
        where = 'its UPF_TEST_MEM_MB from ci/test-memory.tsv (datapath/meson.build)'
    if not declared.isdigit() or int(declared) <= 0:
        if not measure:
            print(f'run_capped: {name}: no memory declaration: add {where}', file=sys.stderr)
            return 1
        declared = '0'
    declared_mb = int(declared)

    limit_mb = kill_limit_mb(declared_mb, measure)
    env = dict(os.environ)
    scoped = None if no_scope else run_in_scope(cmd, env, limit_mb)
    if scoped is not None:
        status, peak, oom, how = scoped
    else:
        status, peak = spawn(cmd, env)
        oom = 0
        how = 'wait4 ru_maxrss, no cgroup'
    print(f'run_capped: {name}: declared {declared_mb} MiB, peak {max(peak, 0) / MIB:.1f} MiB '
          f'({how}; kill limit {limit_mb if scoped is not None else "none"})',
          file=sys.stderr)
    if oom:
        print(f'run_capped: {name}: FAILED: killed by the kernel at its cgroup limit '
              f'({limit_mb} MiB; declared {declared_mb} MiB)', file=sys.stderr)
        return status or 1
    if not measure and peak > declared_mb * MIB:
        print(f'run_capped: {name}: FAILED: declared {declared_mb} MiB, '
              f'peak {peak / MIB:.1f} MiB', file=sys.stderr)
        return status or 1
    return status


# The self-test's hog: allocates argv[1] bytes, writes one byte in every page so
# each is resident, and exits 0.
HOG = r'''
import mmap, sys
n = int(sys.argv[1])
m = mmap.mmap(-1, n)
for i in range(0, n, mmap.PAGESIZE):
    m[i] = 1
print(f'touched {n} bytes')
'''


def self_test():
    """The mechanism, by bytes: a process that touches more than its
    declaration fails with "declared X MiB, peak Y MiB", the same process under
    its bound passes, and the peak reported is at least what it touched; in a
    scope and with wait4 alone."""
    peak_re = re.compile(r'declared (\d+) MiB, peak ([0-9.]+) MiB')
    failures = []

    def case(touch_mb, declared_mb, no_scope, want):
        env = dict(os.environ, UPF_TEST_MEM_MB=str(declared_mb))
        for name in ('UPF_TEST_MEM_MEASURE', 'UPF_TEST_MEM_NO_SCOPE'):
            env.pop(name, None)
        cmd = [sys.executable, os.path.abspath(__file__)]
        cmd += ['--no-scope'] if no_scope else []
        cmd += [sys.executable, '-c', HOG, str(touch_mb * MIB)]
        r = subprocess.run(cmd, env=env, capture_output=True, text=True)
        mode = 'wait4' if no_scope else 'scope'
        got = 'pass' if r.returncode == 0 else ('oom' if 'killed by the kernel' in r.stderr
                                                else 'over')
        m = peak_re.search(r.stderr)
        peak = float(m.group(2)) if m else -1.0
        print(f'{mode}: touch {touch_mb} MiB, declared {declared_mb} MiB: {got}, '
              f'peak {peak:.1f} MiB')
        if got != want:
            failures.append(f'{mode} {touch_mb}/{declared_mb}: want {want}, got {got}: '
                            f'{r.stderr.strip()}')
        elif not m or int(m.group(1)) != declared_mb:
            failures.append(f'{mode} {touch_mb}/{declared_mb}: no "declared X MiB, peak Y MiB"')
        elif want != 'oom' and peak < touch_mb:
            failures.append(f'{mode} {touch_mb}/{declared_mb}: peak {peak} MiB is below the '
                            f'{touch_mb} MiB touched')

    scope_ok = bool(shutil.which('systemd-run')) and subprocess.run(
        ['systemd-run', '--user', '--scope', '-q', 'true'], capture_output=True).returncode == 0
    # Declared 48 MiB: the kernel's limit is max(48 * 1.5, 48 + 32) = 80 MiB. The
    # interpreter itself is about 10 MiB of the 32 MiB case's peak.
    for no_scope in ([False, True] if scope_ok else [True]):
        case(32, 64, no_scope, 'pass')   # under its bound
        case(64, 48, no_scope, 'over')   # above it, below the kernel's limit: measured, failed
        if not no_scope:
            case(160, 48, no_scope, 'oom')  # far above: the kernel stops it at the limit
        else:
            case(160, 48, no_scope, 'over')  # no cgroup: runs to the end, then failed
    # A Go binary's row: its package directory, go-race when its build info
    # says -race (the build-info bytes as the linker writes them), and a test's
    # own row when it runs alone (-test.run=^Name$) and the table has one.
    rows = {('go', 'internal/session:TestBig'): 1}
    with tempfile.TemporaryDirectory(prefix='run_capped.') as tmp:
        for kind, info, args, want in (
                ('go', b'\nbuild\tCGO_ENABLED=1\n', [], 'internal/session'),
                ('go-race', b'\nbuild\t-race=true\nbuild\tCGO_ENABLED=1\n', [], 'internal/session'),
                ('go', b'\n', ['-test.run=^TestBig$'], 'internal/session:TestBig'),
                ('go', b'\n', ['-test.run=TestBig'], 'internal/session'),
                ('go', b'\n', ['-test.run=^TestOther$'], 'internal/session')):
            binary = os.path.join(tmp, f'{kind}.test')
            with open(binary, 'wb') as f:
                f.write(b'\0' * 4096 + b'path\tx.test' + info)
            got = go_row(binary, ROOT / 'internal' / 'session', args, rows)
            print(f'row: {kind} binary in internal/session {" ".join(args)}: {got[0]} {got[1]}')
            if got != (kind, want):
                failures.append(f'go_row: a {kind} binary with {args} got {got}, want {want}')
    if not scope_ok:
        print('no user manager: the scope cases did not run')
        if os.environ.get('UPF_TEST_MEM_REQUIRE_SCOPE') == '1':
            failures.append('UPF_TEST_MEM_REQUIRE_SCOPE=1 and systemd-run --user --scope failed')
    for f in failures:
        print('FAIL', f)
    print('self-test: ' + ('FAILED' if failures else 'ok'))
    return 1 if failures else 0


def main():
    args = sys.argv[1:]
    if args == ['--self-test']:
        return self_test()
    no_scope = args[:1] == ['--no-scope']
    if no_scope:
        args = args[1:]
    if args[:1] == ['--']:
        args = args[1:]
    if not args:
        sys.exit(__doc__)
    exit_like(run(args, no_scope))


if __name__ == '__main__':
    sys.exit(main())
