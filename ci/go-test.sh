#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# The Go unit pass under the test-memory rows (ci/test-memory.tsv;
# docs/engineering-guide.md, "Test memory"). Every test binary runs under
# ci/run_capped.py (go test -exec), two packages at a time (-p 2: the
# parallelism ci/check-test-memory.py sums the package rows at). A test with a
# row of its own, `go <dir>:<Test>` (`go-race` under -race), is skipped there
# and run after, by itself, held to that row. Extra arguments go to each go
# test (-race, -json, -count=1); the outputs are concatenated on stdout.
#
#   GO_BIN=go ci/go-test.sh -count=1 -json > go-test.json

set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1
GO_BIN=${GO_BIN:-go}
EXEC=(-exec "$ROOT/ci/run_capped.py")

kind=go
for a in "$@"; do [ "$a" = -race ] && kind=go-race; done
alone=$(awk -v k="$kind" '$1 == k && index($2, ":") { print $2 }' ci/test-memory.tsv)
skip=()
if [ -n "$alone" ]; then
  skip=(-skip "^($(printf '%s\n' "$alone" | cut -d: -f2 | paste -sd'|'))\$")
fi

rc=0
"$GO_BIN" test -p 2 "${EXEC[@]}" "${skip[@]}" "$@" ./cmd/... ./internal/... || rc=$?
for t in $alone; do
  "$GO_BIN" test -p 1 "${EXEC[@]}" "$@" -run "^${t#*:}\$" "./${t%%:*}" || rc=$?
done
exit "$rc"
