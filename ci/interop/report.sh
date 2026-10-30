#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# Collect the evidence of the run in progress into $IX/runs/<label>/ without
# stopping anything: the N4 capture (pcap and its decoded IE tree, via
# ci/interop/pfcpdump), upfd's and bessd's logs, and every container's log.
#
#   ci/interop/report.sh <label>

set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

LABEL=${1:?usage: report.sh <label>}
OUT=$IX/runs/$LABEL
mkdir -p "$OUT"

cp "$IX/n4.pcap" "$OUT/n4.pcap" 2>/dev/null || log "no capture yet"
[ -s "$OUT/n4.pcap" ] && (cd "$ROOT" && $GO run ./ci/interop/pfcpdump "$OUT/n4.pcap" >"$OUT/n4.txt")
cp "$LOGS/upfd.log" "$OUT/upfd.log" 2>/dev/null || true
cp "$LOGS/bessd.log" "$OUT/bessd.log" 2>/dev/null || true
cp "$STATE/target" "$OUT/target.txt" 2>/dev/null || true
cp "$STATE/graph.yaml" "$OUT/dataplane.yaml" 2>/dev/null || true
cp "$LOGS/traffic-counters.out" "$OUT/traffic-counters.out" 2>/dev/null || true
for c in $(dk ps -a --filter "name=^$PREFIX-" --format '{{.Names}}'); do
  dk logs "$c" >"$OUT/${c#"$PREFIX"-}.docker.log" 2>&1 || true
done
if [ -s "$IX/n4-upfd.pcap" ]; then   # SHIM=1: upfd's own side, before the repair
  cp "$IX/n4-upfd.pcap" "$OUT/n4-upfd.pcap"
  (cd "$ROOT" && $GO run ./ci/interop/pfcpdump -port 0 "$OUT/n4-upfd.pcap" >"$OUT/n4-upfd.txt")
fi
cp "$LOGS/n4shim.log" "$OUT/n4shim.log" 2>/dev/null || true
# The dataplane arm's own evidence: every module's gate counters as they stand
# (the counting modules are what a URR report is built from), the active
# pipeline, and the UE's echo output.
if [ -s "$STATE/bess_port" ]; then
  "$BESSCTL" -s "127.0.0.1:$(cat "$STATE/bess_port")" metrics 2>/dev/null >"$OUT/bessd.metrics" || true
  "$BESSCTL" -s "127.0.0.1:$(cat "$STATE/bess_port")" get 2>/dev/null >"$OUT/bessd.pipeline" || true
  if [ "$UPF_TARGET" = appliance ]; then
    for direction in ul dl; do
      "$BESSCTL" -s "127.0.0.1:$(cat "$STATE/bess_port")" \
        action upf get_counts "{\"table\":\"counters_$direction\"}" \
        >"$OUT/counters_$direction.json"
    done
  fi
fi
cp "$LOGS/ping.out" "$OUT/ping.out" 2>/dev/null || true
if ip netns list 2>/dev/null | grep -q "^$DN_NS\b"; then
  sudo -n ip netns exec "$DN_NS" ip -s link show eth0 >"$OUT/dn-eth0.txt" 2>/dev/null || true
fi
# The one-line-per-message view of the PFCP exchange, in order.
[ -s "$OUT/n4.txt" ] && grep -E '^#[0-9]+ |^  [A-Z][A-Za-z ]+ seq=|^    Cause' "$OUT/n4.txt" >"$OUT/n4.summary" || true
log "evidence in $OUT"
