#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# Refreshes build/bess, this repository's own copy of the BESS build, from a
# BESS checkout, and makes the copy independent of it:
#
#   ci/vendor-bess.sh [<bess checkout>]       # default: $BESS_SRC or ~/Projects/bess
#
# The layout it produces is the one ci/bess-env.sh reads (README, "The BESS
# build this repo carries"). What it copies, from the checkout's own outputs:
#
#   build/stage-fast/usr/local -> build/bess/stage    installed bess-dev stage
#   deps/dpdk-*/install        -> build/bess/dpdk/install
#   deps/dpdk-*/usertools      -> build/bess/dpdk/usertools
#   build/fast                 -> build/bess/fast     perf tree (bench lanes)
#   sdk/go                     -> build/bess/sdk/go
#
# And what it rewrites, because three places carry the checkout's absolute
# path and would silently keep the copy reading the original:
#
#   - the DPDK paths in every .pc file under stage/ and dpdk/install (bess-dev.pc
#     and DPDK's own; meson puts them in lib/pkgconfig or lib/<triplet>/pkgconfig
#     depending on the host) and in rte_build_config.h (the plugin build and its
#     flags read them);
#   - the PMD driver directory compiled into librte_eal (RTE_EAL_PMD_PATH): bessd
#     has no flag for it, so without this every NIC driver loads from the
#     checkout. The string is patched in place, NUL-padded, which is why the new
#     path must not be longer than the old one (checked);
#   - nothing in fast/: its RUNPATH names the checkout, but the lanes put
#     build/bess/dpdk first on LD_LIBRARY_PATH, which the loader searches before
#     RUNPATH. Rebuilding fast/ in place is not supported -- rebuild in the
#     checkout and refresh.
#
# It ends by checking that nothing under stage/ or dpdk/ names the checkout.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SRC=${1:-${BESS_SRC:-$HOME/Projects/bess}}
STAGE_SRC=${STAGE_SRC:-$SRC/build/stage-fast/usr/local}
FAST_SRC=${FAST_SRC:-$SRC/build/fast}
DPDK_SRC=${DPDK_SRC:-$(ls -d "$SRC"/deps/dpdk-*/ | head -1)}
DPDK_SRC=${DPDK_SRC%/}
DEST=$ROOT/build/bess

for p in "$STAGE_SRC/bin/bessd" "$DPDK_SRC/install/lib" "$FAST_SRC/core/bessd" "$SRC/sdk/go/go.mod"; do
  [ -e "$p" ] || { echo "vendor-bess: missing $p (is $SRC a built BESS checkout?)" >&2; exit 1; }
done

echo "vendor-bess: $SRC -> $DEST"
rm -rf "$DEST/stage" "$DEST/dpdk" "$DEST/fast" "$DEST/sdk"
mkdir -p "$DEST/dpdk" "$DEST/sdk"
cp -a "$STAGE_SRC" "$DEST/stage"
cp -a "$DPDK_SRC/install" "$DEST/dpdk/install"
cp -a "$DPDK_SRC/usertools" "$DEST/dpdk/usertools"
cp -a "$FAST_SRC" "$DEST/fast"
cp -a "$SRC/sdk/go" "$DEST/sdk/go"

OLD=$DPDK_SRC
NEW=$DEST/dpdk
# Where meson installs pkg-config files depends on the host's libdir: a plain
# lib/pkgconfig here, lib/<triplet>/pkgconfig on Debian/Ubuntu. Rewrite every
# one the install produced rather than assuming the first layout -- a missed
# bess-dev.pc keeps naming the checkout, and the final check below catches it.
while IFS= read -r -d '' f; do
  sed -i "s|$OLD|$NEW|g" "$f"
done < <(find "$DEST/stage" "$DEST/dpdk/install" -type f \
           \( -name '*.pc' -o -name rte_build_config.h \) -print0)

PMD_OLD=$(ls -d "$OLD"/install/lib/dpdk/pmds-* | head -1)
PMD_NEW=$NEW/install/lib/dpdk/$(basename "$PMD_OLD")
python3 - "$PMD_OLD" "$PMD_NEW" "$DEST"/dpdk/install/lib/librte_eal.* <<'PY'
import sys
old, new = sys.argv[1].encode(), sys.argv[2].encode()
assert len(new) <= len(old), f"new PMD path is {len(new) - len(old)} bytes too long: {new.decode()}"
for path in sys.argv[3:]:
    with open(path, "rb") as f:
        data = f.read()
    needle = old + b"\0"
    n = data.count(needle)
    if n == 0:
        continue
    data = data.replace(needle, new + b"\0" * (len(old) - len(new) + 1))
    with open(path, "wb") as f:
        f.write(data)
    print(f"vendor-bess: {path}: PMD path patched at {n} place(s)")
PY

if grep -rIlF "$SRC" "$DEST/stage" "$DEST/dpdk" 2>/dev/null | grep .; then
  echo "vendor-bess: the files above still name $SRC" >&2
  exit 1
fi
if grep -rlaF "$SRC" "$DEST/stage/bin" "$DEST/dpdk/install/lib" 2>/dev/null | grep .; then
  echo "vendor-bess: the binaries above still name $SRC" >&2
  exit 1
fi
echo "vendor-bess: ok (stage/ and dpdk/ name nothing outside build/bess)"
