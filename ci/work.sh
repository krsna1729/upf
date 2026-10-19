#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
#
# Points this workspace at a BESS checkout's Go SDK (see go.work). The SDK is a
# nested module of the fork (github.com/krsna1729/bess/sdk/go); until the fork's
# commits are published, that module exists only on a local checkout, and a
# workspace file is how the Go toolchain is told where it is.
#
#   ci/work.sh                              # the copy under build/bess
#   BESS_SRC=<tree with sdk/go> ci/work.sh  # another tree's SDK
#
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BESS_SRC=${BESS_SRC:-$ROOT/build/bess}

if [ ! -f "$BESS_SRC/sdk/go/go.mod" ]; then
    echo "no Go SDK at $BESS_SRC/sdk/go" >&2
    exit 1
fi

cd "$(dirname "$0")/.."
# The workspace's go directive must be at least every module's it uses: the
# SDK's own go.mod moves with the fork, and a workspace naming a lower one makes
# every command fail with a version error ("... requires go >= 1.27.2, but
# go.work lists go 1.26.0") instead of building. So the higher of the two is
# written.
root_go=$(awk '$1 == "go" { print $2; exit }' go.mod)
sdk_go=$(awk '$1 == "go" { print $2; exit }' "$BESS_SRC/sdk/go/go.mod")
go_line=$(printf '%s\n%s\n' "$root_go" "$sdk_go" | sort -V | tail -1)
cat > go.work <<EOF
go $go_line

use (
	.
	$BESS_SRC/sdk/go
)
EOF

echo "go.work now points at $BESS_SRC/sdk/go (go $go_line)"
