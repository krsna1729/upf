#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
#
# What the Dump module printed, per dump, for the CI scripts to match against.
# Sourced (ci/session-path.sh, ci/n4-path.sh), never run.
#
# Two properties of that output are easy to get wrong. The module wraps sixteen
# bytes to a line, so a field can straddle two of them -- the hex is joined. And
# every frame in these graphs opens with the same two MACs, so a match must be
# scoped to the dump it came from: joining the whole log lets the uplink's check
# pass on the downlink's dump, which is how a broken uplink stayed green.

# dump_hex <module> <log file>: that module's dumped packet bytes, joined.
dump_hex() {
	awk -v want="$1" '
	  /^[a-z0-9_]+: packet dump/ { inside = ($1 == want ":") ; next }
	  /^  [0-9a-f]+: / {
	    if (!inside) next
	    for (i = 2; i <= NF; i++) {
	      if ($i == "Metadata") break
	      printf "%s ", $i
	    }
	  }' "$2"
}
