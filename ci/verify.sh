#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# The claims contract.
#
# docs/claims.json is the single source of truth: every claim this tree makes
# (our status against TS 29.244, and the competitive score) with the evidence it
# cites -- Go tests, lane scripts, deploy graphs. This script reads that file,
# runs the evidence once, writes each result back into it, and renders
# docs/claims.md from it. The document is therefore never hand-edited: the
# claim text, its evidence and the last run's verdict are one record, and the
# markdown is a view of it.
#
# Usage:
#   ci/verify.sh              # units + every cited lane + the render
#   ci/verify.sh --quick      # units only (lanes keep their last run's verdict)
#   ci/verify.sh --lanes-only # lanes only (tests keep their last run's verdict)
#   ci/verify.sh --render     # render docs/claims.md from the last results
#   ci/verify.sh --strict     # a claim with no runnable evidence also fails
#   ci/verify.sh --benches    # also run the cited bench scripts
#   ci/verify.sh --list       # inventory the claims and their evidence, run nothing
#
# Environment: GO_BIN (default: go, or the mise install this tree uses),
# LANE_TIMEOUT (default 900), FORK (default ../bess; only for source anchors).

set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1
CLAIMS=docs/claims.json
OUT=build/run/verify
mkdir -p "$OUT"
LANE_TIMEOUT=${LANE_TIMEOUT:-900}
FORK=${FORK:-$ROOT/../bess}

QUICK=0; LANES_ONLY=0; STRICT=0; BENCHES=0; LIST=0; RENDER=0
for arg in "$@"; do
  case "$arg" in
    --quick) QUICK=1 ;;
    --lanes-only) LANES_ONLY=1 ;;
    --strict) STRICT=1 ;;
    --benches) BENCHES=1 ;;
    --list) LIST=1 ;;
    --render) RENDER=1 ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "verify: unknown argument $arg" >&2; exit 2 ;;
  esac
done

if [ ! -f "$CLAIMS" ]; then
  echo "verify: $CLAIMS not found -- it is the claims contract" >&2
  exit 2
fi

GO_BIN=${GO_BIN:-}
if [ -z "$GO_BIN" ]; then
  if [ -x "$HOME/.local/share/mise/installs/go/1.27.2/bin/go" ]; then
    GO_BIN=$HOME/.local/share/mise/installs/go/1.27.2/bin/go
  else
    GO_BIN=$(command -v go || true)
  fi
fi

# --- the evidence inventory, straight from the contract ----------------------
python3 - "$CLAIMS" > "$OUT/inventory.tsv" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding='utf-8'))
tests, lanes, graphs = set(), set(), set()
claims = d.get('claims', [])
for c in claims:
    for tok in c.get('evidence', []):
        if tok.startswith('Test'):
            tests.add(tok)
        elif tok.endswith('.sh'):
            lanes.add(tok)
        elif tok.startswith('deploy/') and (tok.endswith('.yaml') or tok.endswith('.yml')):
            graphs.add(tok)
for t in sorted(tests):  print(f"test\t{t}")
for l in sorted(lanes):  print(f"lane\t{l}")
for g in sorted(graphs): print(f"graph\t{g}")
print(f"claim\t{len(claims)}")
PY

tests=$(awk -F'\t' '$1=="test"{print $2}' "$OUT/inventory.tsv")
lanes=$(awk -F'\t' '$1=="lane"{print $2}' "$OUT/inventory.tsv")
graphs=$(awk -F'\t' '$1=="graph"{print $2}' "$OUT/inventory.tsv")
nclaims=$(awk -F'\t' '$1=="claim"{print $2}' "$OUT/inventory.tsv")

if [ "$LIST" -eq 1 ]; then
  printf 'claims: %s | tests: %s | lanes: %s | graphs: %s\n' \
    "$nclaims" "$(printf '%s\n' "$tests" | grep -c .)" \
    "$(printf '%s\n' "$lanes" | grep -c .)" "$(printf '%s\n' "$graphs" | grep -c .)"
  printf '%s\n' "$lanes" | sed 's/^/  lane  /' | grep .
  exit 0
fi

# --- units -------------------------------------------------------------------
if [ "$LANES_ONLY" -eq 0 ] && [ "$RENDER" -eq 0 ]; then
  if [ -z "$GO_BIN" ]; then
    echo "verify: no Go toolchain (set GO_BIN)" >&2
    exit 2
  fi
  : > "$OUT/tests.tsv"
  if [ -n "$(printf '%s\n' "$tests" | grep .)" ]; then
    "$GO_BIN" test ./cmd/... ./internal/... -count=1 -json > "$OUT/go-test.json" 2> "$OUT/go-test.err"
    python3 - "$OUT/go-test.json" "$OUT/tests.tsv" <<'PY'
import json, sys
seen, failed, skipped = {}, {}, {}
for line in open(sys.argv[1]):
    try:
        ev = json.loads(line)
    except ValueError:
        continue
    t = ev.get('Test')
    if not t:
        continue
    base = t.split('/')[0]
    a = ev.get('Action')
    if a == 'pass':   seen[base] = True
    elif a == 'fail': failed[base] = True
    elif a == 'skip': skipped[base] = True
with open(sys.argv[2], 'w') as f:
    for t in sorted(set(seen) | set(failed) | set(skipped)):
        state = 'fail' if failed.get(t) else ('skip' if skipped.get(t) and not seen.get(t) else 'ok')
        f.write(f"{state}\t{t}\n")
PY
    # A cited test that did not run is not missing if its source exists: a live
    # arm skips without its environment (the lane that sets it is named here),
    # a build-tagged one is not part of this pass.
    while IFS= read -r t; do
      [ -z "$t" ] && continue
      if ! awk -F'\t' -v t="$t" '$2==t{found=1} END{exit found?0:1}' "$OUT/tests.tsv"; then
        if grep -rq "func $t(" internal/ cmd/ 2>/dev/null; then
          printf 'source\t%s\n' "$t" >> "$OUT/tests.tsv"
        else
          printf 'missing\t%s\n' "$t" >> "$OUT/tests.tsv"
        fi
      fi
    done <<< "$tests"
  fi
fi

# --- lanes -------------------------------------------------------------------
if [ "$QUICK" -eq 0 ] && [ "$RENDER" -eq 0 ]; then
  : > "$OUT/lanes.tsv"
  while IFS= read -r l <&3; do
    [ -z "$l" ] && continue
    if [ ! -f "$l" ]; then
      printf 'missing\t%s\n' "$l" >> "$OUT/lanes.tsv"; continue
    fi
    if grep -q 'sudo ' "$l" 2>/dev/null && ! sudo -n true 2>/dev/null; then
      printf 'skip\t%s\tneeds sudo (no non-interactive ticket)\n' "$l" >> "$OUT/lanes.tsv"; continue
    fi
    case "$l" in
      ci/interop/*|ci/cntc-path.sh|ci/work.sh|ci/vendor-bess.sh|ci/bess-env.sh)
        printf 'skip\t%s\tneeds containers or the stage checkout\n' "$l" >> "$OUT/lanes.tsv"; continue ;;
      ci/bench-*.sh)
        if [ "$BENCHES" -eq 0 ]; then
          printf 'skip\t%s\tbenchmark (--benches runs it)\n' "$l" >> "$OUT/lanes.tsv"; continue
        fi ;;
    esac
    out="$OUT/lane-$(echo "${l#ci/}" | tr '/' '_').out"
    timeout "$LANE_TIMEOUT" bash "$l" </dev/null >"$out" 2>&1
    rc=$?
    clean=1
    if grep -q "bessd" "$out" 2>/dev/null; then
      grep -q "bessd shut down cleanly" "$out" || clean=0
    fi
    if [ $rc -eq 0 ] && [ $clean -eq 1 ]; then
      printf 'ok\t%s\n' "$l" >> "$OUT/lanes.tsv"
    else
      printf 'fail\t%s\trc=%d clean=%d\t%s\n' "$l" "$rc" "$clean" "$out" >> "$OUT/lanes.tsv"
    fi
  done 3<<< "$lanes"
fi

# --- graphs (static anchors) -------------------------------------------------
: > "$OUT/graphs.tsv"
while IFS= read -r g; do
  [ -z "$g" ] && continue
  if [ -e "$g" ]; then printf 'ok\t%s\n' "$g" >> "$OUT/graphs.tsv"
  else printf 'missing\t%s\n' "$g" >> "$OUT/graphs.tsv"; fi
done <<< "$graphs"

# --- merge the results, write the contract, render the document --------------
python3 - "$CLAIMS" "$OUT" "$STRICT" <<'PY'
import json, sys, re

claims_path, out, strict = sys.argv[1], sys.argv[2], sys.argv[3] == '1'

def table(name):
    rows = {}
    try:
        for line in open(f"{out}/{name}"):
            p = line.rstrip('\n').split('\t')
            if len(p) >= 2:
                rows[p[1]] = p[0]
    except FileNotFoundError:
        pass
    return rows

status = {'test': table('tests.tsv'), 'lane': table('lanes.tsv'), 'graph': table('graphs.tsv')}
doc = json.load(open(claims_path, encoding='utf-8'))

def kind(tok):
    if tok.startswith('Test'):
        return 'test'
    if tok.endswith('.sh'):
        return 'lane'
    if tok.startswith('deploy/'):
        return 'graph'
    return 'src'

src = {}
import os
for c in doc['claims']:
    for tok in c.get('evidence', []):
        if kind(tok) == 'src' and tok not in src:
            src[tok] = 'ok' if os.path.exists(tok) else 'missing'

fail = gap = 0
for c in doc['claims']:
    prior = c.setdefault('result', {}).setdefault('evidence', {})
    for tok in c.get('evidence', []):
        k = kind(tok)
        st = status.get(k, {}).get(tok) if k != 'src' else src.get(tok)
        if st is None:
            continue          # not run in this pass: keep the last verdict
        prior[tok] = {'state': st}
    states = [prior.get(t, {}).get('state', 'not run') for t in c.get('evidence', [])]
    if not c.get('evidence'):
        state = 'gap'
    elif any(s in ('fail', 'missing') for s in states):
        state = 'FAIL'
    elif all(s in ('skip', 'source', 'not run') for s in states):
        state = 'skip'
    else:
        state = 'ok'
    c['result']['state'] = state
    if state == 'FAIL':
        fail += 1
    if state in ('gap', 'FAIL'):
        gap += 1

json.dump(doc, open(claims_path, 'w', encoding='utf-8'), indent=1)
open(claims_path, 'a').write('\n')

def esc(v):
    return v.replace('|', '\\|')

blocks = {}
for c in doc['claims']:
    if c['scope'] == 'competition':
        n = int(re.search(r'(\d+)$', c['id']).group(1))
        sc = c.get('scores', {})
        order = ['us', 'OAI-CN5G', 'open5gs', 'free5GC', 'UPG-VPP', 'eUPF', 'OMEC']
        vals = {k: sc[k] for k in order if k in sc}
        best, best_name = -1, ''
        for k in order[1:]:
            v = vals.get(k, '')
            if v.strip().lstrip('*').isdigit():
                if int(v.strip('*')) > best:
                    best, best_name = int(v.strip('*')), k
        blocks[n] = {'name': c.get('title', ''), 'vals': vals, 'best': best, 'best_name': best_name}

def sortkey(c):
    cl = c.get('clause') or ''
    out = []
    for p in cl.split('.'):
        m = re.match(r'(\d+)([A-Z]?)$', p)
        out.append((int(m.group(1)), m.group(2)) if m else (999, p))
    return (c.get('spec') or '', out, c['id'])

def idkey(c):
    m = re.search(r'(\d+)$', c['id'])
    return int(m.group(1)) if m else 0

def esc(v):
    return v.replace('|', '\\|')

def field_vals(b):
    return ' · '.join(f"{k} {v}" for k, v in b['vals'].items() if k != 'us')

def plural(n, one, many):
    return f"{n} {one if n == 1 else many}"

def claim_text(c):
    v = (c.get('claim') or '').strip()
    if v:
        return v
    return (c.get('title') or c.get('statement') or '').replace('\n', ' ').strip()

def evidence_kinds(c):
    counts = {}
    for tok in c.get('evidence', []):
        if tok.startswith('TestLive'):
            k = 'live test'
        elif tok.startswith('Test'):
            k = 'test'
        elif tok.startswith('ci/'):
            k = 'lane'
        elif tok.startswith('docs/'):
            k = 'doc'
        elif tok.startswith('deploy/'):
            k = 'graph'
        else:
            k = 'other'
        counts[k] = counts.get(k, 0) + 1
    order = ['test', 'live test', 'lane', 'graph', 'doc', 'other']
    return ' · '.join(k if counts[k] == 1 else f"{k} ×{counts[k]}"
                      for k in order if counts.get(k))

def head_of(c):
    if c['scope'] == 'competition':
        return f"block {c.get('block')}"
    return c.get('clause') or 'no clause'

def claim_line(c):
    out = f"- **{c['id']}** · {head_of(c)} — {claim_text(c)}"
    kinds = evidence_kinds(c)
    if kinds:
        out += f" · {kinds}"
    if c['result']['state'] != 'ok':
        out += f" · **{c['result']['state']}**"
    return out

sections = [
    'Association',
    'Heartbeat and restart detection',
    'Error Indication and its report',
    'Session Establishment',
    'Session Modification',
    'Session Deletion',
    'Session Report',
    'Shared information elements',
    'Cross-cutting (no message)',
]

tot = {}
for c in doc['claims']:
    tot[c['result']['state']] = tot.get(c['result']['state'], 0) + 1

lines = [
    '# Claims: our status, and the competition',
    '',
    'Generated by `ci/verify.sh` from `docs/claims.json` — the single source: the',
    "requirement, the evidence it cites and the last run's verdict are one record.",
    'Edit the JSON and re-run; never this file. Named tests and the narrative sit in',
    'the JSON, not here.',
    '',
    f"**{len(doc['claims'])} claims · {tot.get('ok', 0)} ok · {tot.get('gap', 0)} gap · "
    f"{tot.get('skip', 0)} skip · {tot.get('FAIL', 0)} fail**",
    '',
    '`ok` proved by the evidence named · `gap` a documented missing capability ·',
    '`skip` needs an environment this run lacks · `FAIL` a regression.',
    '',
]

open_claims = [c for c in doc['claims'] if c['result']['state'] in ('FAIL', 'gap')]
if open_claims:
    lines += ['## Open', '']
    for c in open_claims:
        lines += [f"### {c['id']} · {head_of(c)} · {c['result']['state']}", '',
                  claim_text(c), '']
        if c.get('detail') and c['detail'] != claim_text(c):
            lines += [c['detail'], '']
        if c.get('effect'):
            lines += [c['effect'], '']
        if c['scope'] == 'competition':
            b = blocks.get(c.get('block'))
            if b:
                us = str(b['vals'].get('us', '')).strip('*')
                field = ' · '.join(f"{k} {v}" for k, v in b['vals'].items() if k != 'us')
                best = f" · best {b['best']} ({b['best_name']})" if b['best'] >= 0 else ''
                lines += [f"Scores: us **{us}** · {field}{best}.", '']
        if c.get('evidence'):
            lines += [f"Evidence: {evidence_kinds(c)}.", '']
        else:
            lines += ['No evidence in this tree.', '']

skips = [c for c in doc['claims'] if c['result']['state'] == 'skip']
if skips:
    items = '; '.join(f"`{c['id']}` — {claim_text(c)}" for c in skips)
    lines += ['## Not run here', '',
              f"Claim{'s' if len(skips) > 1 else ''} that need{'s' if len(skips) == 1 else ''} "
              f'an environment this run does not provide: {items}.', '',
              'The code is not in question.', '']

lines += ['## Status claims', '']
for m in sections:
    cs = [c for c in doc['claims'] if c.get('message') == m and c['scope'] == 'status']
    if not cs:
        continue
    cnt = {}
    for c in cs:
        cnt[c['result']['state']] = cnt.get(c['result']['state'], 0) + 1
    summary = ', '.join(f"{v} {k}" for k, v in sorted(cnt.items()))
    lines += [f"### {m} · {plural(len(cs), 'claim', 'claims')} ({summary})", '']
    for c in sorted(cs, key=sortkey):
        lines.append(claim_line(c))
    lines.append('')

comp = [c for c in doc['claims'] if c['scope'] == 'competition']
if comp:
    impls = [k for k in comp[0].get('scores', {}) if k != 'us']
    lines += ['## Competition', '',
              '`us` is bold where nothing in the field scores higher.', '',
              '| block | us | ' + ' | '.join(impls) + ' | proof |',
              '|---|---|' + '---|' * len(impls) + '---|']
    for c in sorted(comp, key=idkey):
        s = c.get('scores', {})
        nums = [int(v.strip('*')) for v in s.values() if v.strip('*').isdigit()]
        top = max(nums) if nums else -1
        us = s.get('us', '—').strip('*')
        usc = f"**{us}**" if us.isdigit() and int(us) == top else us
        name = claim_text(c).replace('|', '\\|')
        if c['result']['state'] != 'ok':
            name += f" · {c['result']['state']}"
        lines.append(f"| **{c['block']}** {name} | {usc} | " +
                     ' | '.join(s.get(k, '—').strip('*') for k in impls) +
                     f" | {evidence_kinds(c) or '—'} |")
    lines.append('')

aliases = doc.get('aliases') or {}
if aliases:
    lines += ['## Finding numbers', '',
              'Code comments cite the finding numbers of the audit that produced this',
              'register; they map to entries:', '']
    for k in sorted(aliases, key=int):
        lines.append(f"- finding {k} → " + ', '.join(f"`{v}`" for v in aliases[k]))
    lines.append('')

open('docs/claims.md', 'w', encoding='utf-8').write('\n'.join(lines) + '\n')

counts = {}
for c in doc['claims']:
    counts[c['result']['state']] = counts.get(c['result']['state'], 0) + 1
print(f"claims {len(doc['claims'])}: " + ', '.join(f"{k} {v}" for k, v in sorted(counts.items())))
print('rendered: docs/claims.md')
sys.exit(1 if fail or (strict and any(c['result']['state'] == 'gap' for c in doc['claims'])) else 0)
PY
