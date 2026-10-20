#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# The routed variant of ci/session-path.sh: the same session, the same bytes,
# with the Router in destination mode and the compiler writing no next hop.
# What it proves beyond the policy lane is that one egress can reach more than
# one destination: the graph's two routes send the uplink's 8.8.8.8 to the data
# network's hop and the downlink's subscriber pool to the encap, both chosen by
# the packet's own address in its route domain.
#
# The lane is session-path's, run with its two overrides; the graph's own
# comments (deploy/route-path.yaml) say what changed and why the UpdateTTL
# modules are absent.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
GRAPH=$ROOT/deploy/route-path.yaml ROUTE_MODE=destination exec "$ROOT/ci/session-path.sh"
