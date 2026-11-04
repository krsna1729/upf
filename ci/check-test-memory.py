#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Every test declares its memory, and the Go suite fits 2048 MiB at -p 2.

Reads ci/test-memory.tsv and fails when:

  * a Go package with tests (a directory of *_test.go in this module) has no
    `go <dir>` or no `go-race <dir>` row;
  * a datapath meson test (a test() call in datapath/meson.build) has no
    `meson <name>` row, or does not pass test_memory_mb.get('<name>', 0) as
    UPF_TEST_MEM_MB; with --build-dir, a built test whose UPF_TEST_MEM_MB is
    missing or zero (meson-info/intro-tests.json);
  * a lane CI runs -- the GATING_LANES and CORE_LANES of
    .github/workflows/ci.yml, and the lanes docs/claims.json cites that
    ci/verify.sh does not skip -- has no `lane <name>` row, or starts its
    daemon without ci/bess-env.sh's bessd_launcher, or never checks it
    (check_clean_shutdown or bessd_mem_check);
  * a row is above CEILING_MB without a `# above the ceiling: <reason>` line
    just above it;
  * the GO_JOBS largest package rows of a Go kind add up to more than
    SUITE_LIMIT_MB (`go test -p 2` runs two test binaries at once). A test
    with a row of its own, `go <dir>:<Test>`, is skipped in its package's run
    and runs by itself (ci/go-test.sh): it is left out of that sum, must fit
    SUITE_LIMIT_MB, and must name a test in that package;
  * ci/verify.sh or .github/workflows/ci.yml runs the Go unit pass with a
    bare `go test`, not ci/go-test.sh (which runs each binary under its row);
  * docs/engineering-guide.md's table does not list a row with its MiB, or
    lists one the table does not have.

Usage:
  ci/check-test-memory.py [--build-dir datapath/build]
  ci/check-test-memory.py --calibrate LOG...   peaks in logs -> rows
  ci/check-test-memory.py --self-test
"""

import argparse
import fnmatch
import json
import math
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
CEILING_MB = 1024
SUITE_LIMIT_MB = 2048
GO_JOBS = 2
KINDS = ('go', 'go-race', 'meson', 'lane')
JUSTIFIED = '# above the ceiling:'
DOC_ROW = re.compile(r'^\|\s*`(go|go-race|meson|lane) ([^`]+)`\s*\|\s*(\d+)\s*\|')
PEAK = re.compile(r'(?:run_capped|lane-mem): ([^:]+): declared \d+ MiB, peak ([0-9.]+) MiB')


def rows(text):
    """({(kind, name): (MiB, justified)}, problems)."""
    out, problems, comment = {}, [], []
    for n, line in enumerate(text.splitlines(), 1):
        f = line.split()
        if f and not f[0].startswith('#'):
            f = line.split('#', 1)[0].split()  # a row's own trailing comment: its peak
        if not f:
            comment = []
            continue
        if f[0].startswith('#'):
            comment.append(line.strip())
            continue
        if len(f) != 3 or f[0] not in KINDS or not f[2].isdigit() or int(f[2]) <= 0:
            problems.append(f'ci/test-memory.tsv:{n}: not "<{"|".join(KINDS)}> <name> <MiB>": {line!r}')
        elif (f[0], f[1]) in out:
            problems.append(f'ci/test-memory.tsv:{n}: a second row for {f[0]} {f[1]}')
        else:
            justified = any(c.startswith(JUSTIFIED) and len(c) > len(JUSTIFIED) + 10
                            for c in comment)
            out[(f[0], f[1])] = (int(f[2]), justified)
        comment = []
    return out, problems


def go_packages(root):
    """{directory: its Test functions} for each directory of this module that
    holds *_test.go (nested modules and scratch trees pruned)."""
    skip = {'.git', '.scratch', '.ci', 'build', 'testdata', 'vendor', 'node_modules'}
    out = {}
    for d, dirs, files in os.walk(root):
        here = Path(d)
        dirs[:] = [x for x in dirs if x not in skip and not (here / x / 'go.mod').exists()]
        tests = set()
        for f in files:
            if f.endswith('_test.go'):
                tests |= set(re.findall(r'(?m)^func (Test\w+)\(', (here / f).read_text()))
        if any(f.endswith('_test.go') for f in files):
            out[here.relative_to(root).as_posix()] = tests
    return dict(sorted(out.items()))


def meson_tests(text):
    """(name, call text) of each test(...) call, parentheses balanced."""
    for m in re.finditer(r'(?m)^\s*test\(', text):
        depth = 0
        for i in range(m.end() - 1, len(text)):
            depth += {'(': 1, ')': -1}.get(text[i], 0)
            if depth == 0:
                break
        call = text[m.end():i]
        yield call.split(',', 1)[0].strip().strip("'"), call


def ci_lanes(workflow, claims, verify):
    """The lanes CI runs: the workflow's lists and the cited lanes verify.sh runs."""
    lanes = set()
    for key in ('GATING_LANES', 'CORE_LANES'):
        m = re.search(rf'(?m)^\s*{key}:\s*>-\n((?:\s{{4,}}\S.*\n)+)', workflow)
        if m:
            lanes |= set(re.findall(r'ci/[\w./-]+\.sh', m.group(1)))
    skipped = []
    m = re.search(r"(?m)^\s*([^\n()]+)\)\n\s*printf 'skip\\t%s\\tneeds containers", verify)
    if m:
        skipped = m.group(1).strip().split('|')
    cited = {tok for c in claims.get('claims', []) for tok in c.get('evidence', [])
             if tok.endswith('.sh')}
    lanes |= {lane for lane in cited if not any(fnmatch.fnmatch(lane, s) for s in skipped)}
    return sorted(lanes)


def lane_name(path, text):
    m = re.search(r'\bUPF_LANE=([\w-]+)', text)
    return m.group(1) if m else Path(path).name.removesuffix('.sh')


def check(table_text, packages, meson_text, intro, lanes, doc_text, runners=()):
    """lanes: [(path, script text, exec'd script text or '')];
    runners: [(path, text)] of the files that start the Go unit pass."""
    table, problems = rows(table_text)
    for kind, name in table:
        mb, justified = table[(kind, name)]
        if mb > CEILING_MB and not justified:
            problems.append(f'{kind} {name}: {mb} MiB is above the {CEILING_MB} MiB ceiling with no '
                            f'"{JUSTIFIED} <what a smaller one could not prove>" line above it')
    for pkg in packages:
        for kind in ('go', 'go-race'):
            if (kind, pkg) not in table:
                problems.append(f'{pkg}: no "{kind} {pkg} <MiB>" row in ci/test-memory.tsv')
    for name, call in meson_tests(meson_text):
        if ('meson', name) not in table:
            problems.append(f'meson test {name}: no "meson {name} <MiB>" row in ci/test-memory.tsv')
        if not re.search(r"'UPF_TEST_MEM_MB'\s*:\s*test_memory_mb\.get\('%s',\s*0\)"
                         % re.escape(name), call):
            problems.append(f"datapath/meson.build: test('{name}') does not pass "
                            f"test_memory_mb.get('{name}', 0) as UPF_TEST_MEM_MB")
    for t in intro:
        value = t.get('env', {}).get('UPF_TEST_MEM_MB', '')
        if not value.isdigit() or int(value) <= 0:
            problems.append(f'meson test {t["name"]}: built with UPF_TEST_MEM_MB={value!r}')
    for path, text, execd in lanes:
        name = lane_name(path, text)
        if ('lane', name) not in table:
            problems.append(f'{path}: no "lane {name} <MiB>" row in ci/test-memory.tsv')
        body = text + execd
        if not re.search(r'\bbessd_(start|launcher)\b', body):
            problems.append(f'{path}: starts no daemon through bessd_start or bessd_launcher '
                            '(ci/bess-env.sh), so nothing holds it to its row')
        if not re.search(r'\b(check_clean_shutdown|bessd_mem_check)\b', body):
            problems.append(f'{path}: never checks its daemon\'s peak (check_clean_shutdown '
                            'or bessd_mem_check)')
    for kind in ('go', 'go-race'):
        for name in sorted(n for k, n in table if k == kind and ':' in n):
            pkg, test = name.split(':', 1)
            if test not in packages.get(pkg, ()):
                problems.append(f'{kind} {name}: {pkg} has no func {test}')
            if table[(kind, name)][0] > SUITE_LIMIT_MB:
                problems.append(f'{kind} {name}: {table[(kind, name)][0]} MiB is above '
                                f'{SUITE_LIMIT_MB} MiB even alone')
        top = sorted(((mb, name) for (k, name), (mb, _) in table.items()
                      if k == kind and ':' not in name), reverse=True)[:GO_JOBS]
        if sum(mb for mb, _ in top) > SUITE_LIMIT_MB:
            problems.append(f'{kind}: go test -p {GO_JOBS} can hold {sum(mb for mb, _ in top)} MiB '
                            f'at once ({", ".join(n for _, n in top)}), above {SUITE_LIMIT_MB} MiB')
    for path, text in runners:
        for n, line in enumerate(text.splitlines(), 1):
            if re.search(r'\btest\b.*\./internal/\.\.\.', line) and 'go-test.sh' not in line \
                    and not line.lstrip().startswith('#'):
                problems.append(f'{path}:{n}: runs the Go unit pass without ci/go-test.sh, '
                                'so no binary is held to its row')
    docs = {(m.group(1), m.group(2)): int(m.group(3))
            for m in map(DOC_ROW.match, doc_text.splitlines()) if m}
    for key, (mb, *_) in sorted(table.items()):
        if docs.get(key) != mb:
            problems.append(f'docs/engineering-guide.md: no row "| `{key[0]} {key[1]}` | {mb} |"'
                            + (f' (it says {docs[key]})' if key in docs else ''))
    for key in sorted(set(docs) - set(table)):
        problems.append(f'docs/engineering-guide.md: `{key[0]} {key[1]}` has a row but no declaration')
    return problems, table


def run(root, build_dir):
    lanes = []
    for path in ci_lanes((root / '.github/workflows/ci.yml').read_text(),
                         json.loads((root / 'docs/claims.json').read_text()),
                         (root / 'ci/verify.sh').read_text()):
        text = (root / path).read_text()
        m = re.search(r'exec "\$ROOT/(ci/[\w-]+\.sh)"', text)
        lanes.append((path, text, (root / m.group(1)).read_text() if m else ''))
    intro = []
    if build_dir:
        intro = json.loads((build_dir / 'meson-info' / 'intro-tests.json').read_text())
    runners = [(p, (root / p).read_text()) for p in ('ci/verify.sh', '.github/workflows/ci.yml')]
    problems, table = check((root / 'ci/test-memory.tsv').read_text(), go_packages(root),
                            (root / 'datapath/meson.build').read_text(), intro, lanes,
                            (root / 'docs/engineering-guide.md').read_text(), runners)
    print(f'{len(table)} rows: {len(go_packages(root))} Go packages (plain and -race), '
          f'{sum(1 for k, _ in table if k == "meson")} meson tests, {len(lanes)} lanes')
    for p in problems:
        print(p)
    return 1 if problems else 0


def declaration(peak_mb):
    """The calibration rule: the peak times 1.25, rounded up to 8 MiB."""
    return max(8, math.ceil(peak_mb * 1.25 / 8) * 8)


def calibrate(logs):
    """The largest peak each name logged, and the row it calibrates to."""
    peaks = {}
    for log in logs:
        for name, peak in PEAK.findall(Path(log).read_text(errors='replace')):
            peaks[name] = max(peaks.get(name, 0.0), float(peak))
    for name, peak in sorted(peaks.items(), key=lambda kv: -kv[1]):
        print(f'{name:<28} peak {peak:8.1f} MiB  row {declaration(peak):5d}')
    return 0


def self_test():
    table = '\n'.join([
        'go pkg/a 600', 'go-race pkg/a 64', 'go pkg/b 900',
        '# above the ceiling: it needs 2M rules to cross the reply bound',
        'go pkg/big 1500', 'go-race pkg/big 64', 'go-race pkg/b 1100',
        'meson t1 32', 'lane good 128', 'lane bare 64', 'bogus x 1'])
    meson = ("test('t1', exe, env: {'UPF_TEST_MEM_MB': test_memory_mb.get('t1', 0).to_string()})\n"
             "test('t2', exe)\n")
    lanes = [('ci/good.sh', 'bessd_start x; check_clean_shutdown "$P"', ''),
             ('ci/route.sh', 'UPF_LANE=route exec "$ROOT/ci/good.sh"', 'bessd_start; bessd_mem_check'),
             ('ci/bare.sh', '"$BESSD" -f &', '')]
    doc = '| `go pkg/a` | 600 |\n| `meson t1` | 9 |\n| `go gone` | 1 |\n'
    intro = [{'name': 't1', 'env': {'UPF_TEST_MEM_MB': '32'}},
             {'name': 't2', 'env': {'UPF_TEST_MEM_MB': '0'}}]
    problems, _ = check(table, {'pkg/a': set(), 'pkg/b': set(), 'pkg/c': set()}, meson, intro,
                        lanes, doc)
    want = {
        'ci/test-memory.tsv:11: not': True,                       # unknown kind
        'go-race pkg/b: 1100 MiB is above the 1024 MiB ceiling': True,
        'go pkg/big': False,                                      # justified
        'pkg/b: no "go-race': False,
        'pkg/b: no "go pkg/b': False,
        'pkg/c: no "go pkg/c <MiB>"': True,
        'pkg/c: no "go-race pkg/c <MiB>"': True,
        'meson test t2: no "meson t2': True,
        "datapath/meson.build: test('t2') does not pass": True,
        "datapath/meson.build: test('t1')": False,
        'meson test t2: built with': True,
        'meson test t1: built': False,
        'ci/route.sh: no "lane route': True,
        'ci/route.sh: starts no': False,
        'ci/good.sh': False,
        'ci/bare.sh: no "lane': False,
        'ci/bare.sh: starts no daemon': True,
        'ci/bare.sh: never checks': True,
        'go: go test -p 2 can hold 2400 MiB at once (pkg/big, pkg/b)': True,
        'go-race: go test -p 2': False,                           # 1100 + 64
        'docs/engineering-guide.md: no row "| `meson t1` | 32 |" (it says 9)': True,
        'docs/engineering-guide.md: no row "| `go pkg/b` | 900 |"': True,
        'docs/engineering-guide.md: no row "| `go pkg/a`': False,
        'docs/engineering-guide.md: `go gone` has a row but no declaration': True,
    }
    failures = [f'{"missing" if expected else "unexpected"}: {needle}'
                for needle, expected in want.items()
                if any(p.startswith(needle) for p in problems) != expected]
    workflow = 'env:\n  GATING_LANES: >-\n    ci/a.sh ci/b.sh\n  CORE_LANES: >-\n    ci/c.sh\njobs:\n'
    verify = "    case \"$l\" in\n      ci/interop/*|ci/x.sh)\n        printf 'skip\\t%s\\tneeds containers'\n"
    claims = {'claims': [{'evidence': ['ci/d.sh', 'ci/x.sh', 'ci/interop/run.sh', 'TestX']}]}
    alone = '\n'.join([
        '# above the ceiling: one test holds 2.1M rules to cross the bound',
        'go pkg/a:TestHuge 1900', 'go pkg/a 600', 'go pkg/b 900',
        '# above the ceiling: as TestHuge, but larger than the machine',
        'go pkg/a:TestVast 2100', 'go pkg/b:TestGone 8'])
    runners = [('ci/verify.sh', '  go test ./cmd/... ./internal/... -json'),
               ('ci.yml', '  GO_BIN=go ci/go-test.sh -race ./internal/...\n  # go test ./internal/...')]
    packages = {'pkg/a': {'TestHuge', 'TestVast'}, 'pkg/b': {'TestSmall'}}
    problems, _ = check(alone, packages, '', [], [], '', runners)
    for needle, expected in {
            'go: go test -p 2': False,              # pkg/a + pkg/b; TestHuge runs by itself
            'go pkg/a:TestHuge': False,
            'go pkg/a:TestVast: 2100 MiB is above 2048 MiB even alone': True,
            'go pkg/b:TestGone: pkg/b has no func TestGone': True,
            'ci/verify.sh:1: runs the Go unit pass without ci/go-test.sh': True,
            'ci.yml': False}.items():
        if any(p.startswith(needle) for p in problems) != expected:
            failures.append(f'{"missing" if expected else "unexpected"}: {needle}: {problems}')
    got = ci_lanes(workflow, claims, verify)
    if got != ['ci/a.sh', 'ci/b.sh', 'ci/c.sh', 'ci/d.sh']:
        failures.append(f'ci_lanes: {got}')
    if [declaration(p) for p in (1.0, 36.2, 1200.0)] != [8, 48, 1504]:
        failures.append('declaration: not peak x 1.25 rounded up to 8 MiB')
    for f in failures:
        print('FAIL', f)
    print('self-test: ' + ('FAILED' if failures else 'ok'))
    return 1 if failures else 0


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--root', type=Path, default=ROOT)
    p.add_argument('--build-dir', type=Path)
    p.add_argument('--calibrate', nargs='+', metavar='LOG')
    p.add_argument('--self-test', action='store_true')
    args = p.parse_args()
    if args.self_test:
        return self_test()
    if args.calibrate:
        return calibrate(args.calibrate)
    return run(args.root, args.build_dir)


if __name__ == '__main__':
    sys.exit(main())
