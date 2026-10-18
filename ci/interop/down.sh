#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# Take the real-SMF environment down (docs/interop.md), idempotently, touching
# only what up.sh/ue.sh made: the containers named upf-interop-*, the network
# upf-interop-net, the capture, and the upfd and bessd this directory started.
# Each container's log is saved to $LOGS/<name>.docker.log first. Like
# ci/n4-path.sh, the two daemons are stopped with SIGTERM and judged by their
# exit status: a daemon that aborts on teardown has freed something it should
# not have.
#
#   ci/interop/down.sh

set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

FAIL=0

for cap in n4 n4-upfd; do
  if [ -s "$STATE/$cap.pid" ]; then
    sudo -n kill -INT "$(cat "$STATE/$cap.pid")" 2>/dev/null || true
    sleep 0.5
    rm -f "$STATE/$cap.pid"
    log "capture stopped ($IX/$cap.pcap)"
  fi
done

if dk info >/dev/null 2>&1; then
  for c in $(dk ps -a --filter "name=^$PREFIX-" --format '{{.Names}}'); do
    dk logs "$c" >"$LOGS/${c#"$PREFIX"-}.docker.log" 2>&1 || true
    dk rm -f "$c" >/dev/null && log "removed $c"
  done
  if dk network inspect "$NET" >/dev/null 2>&1; then
    dk network rm "$NET" >/dev/null && log "removed network $NET"
  fi
else
  echo "FAIL: docker is not reachable; containers and network left as they are" >&2
  FAIL=1
fi

FW_RULE=(INPUT -i "$BRIDGE" -p udp --dport 8805 -m comment --comment "$PREFIX-n4" -j ACCEPT)
while sudo -n iptables -w -C "${FW_RULE[@]}" 2>/dev/null; do
  sudo -n iptables -w -D "${FW_RULE[@]}" && log "firewall: removed the INPUT rule for $BRIDGE udp/8805"
done

if [ -s "$STATE/n4shim.pid" ]; then
  rc=$(stop_detached n4shim)
  [ "$rc" = 0 ] && log "n4shim stopped" || { echo "FAIL: n4shim exited with status $rc" >&2; FAIL=1; }
fi

if [ -s "$STATE/upfd.pid" ]; then
  rc=$(stop_detached upfd)
  if [ "$rc" = 0 ]; then log "ok: upfd shut down cleanly"; else echo "FAIL: upfd exited with status $rc on shutdown (see $LOGS/upfd.log)" >&2; FAIL=1; fi
fi

if [ -s "$STATE/bessd.pid" ]; then
  pid=$(cat "$STATE/bessd.pid")
  rc=$(stop_detached bessd)
  if [ "$rc" = 0 ]; then
    log "ok: bessd shut down cleanly"
  else
    echo "FAIL: bessd exited with status $rc on shutdown (crash report: /tmp/bessd_crash.log -- one path for every daemon on the host, check its pid against $pid)" >&2
    FAIL=1
  fi
  rm -f "$STATE/bess_port" "$STATE/bessd-own.pid"
fi
rm -f "$STATE/n4_backend_port"

[ "$FAIL" = 0 ] && log "down"
exit "$FAIL"
