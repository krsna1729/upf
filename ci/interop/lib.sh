# SPDX-License-Identifier: BSD-3-Clause
#
# Sourced by ci/interop/{up,ue,down,report,run}.sh: the names, addresses and
# helpers of the real-SMF environment (docs/interop.md).
#
# Everything this environment owns carries the prefix "upf-interop-" (docker
# containers, the docker network) and lives under one directory, $IX
# (build/run/interop, gitignored). Nothing here touches another container, a
# shared port or /tmp: up.sh/down.sh act on those names only.

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
. "$ROOT/ci/bess-env.sh"      # BESS/STAGE/DPDK_LIB, GOWORK=off, free_port

IX=${IX:-$ROOT/build/run/interop}
STATE=$IX/state               # pid files, exit statuses, the picked ports
LOGS=$IX/logs                 # one log per process / container
CONF=$IX/conf                 # rendered NF configs (deploy/interop/free5gc/*.yaml with the @..@ filled in)
CERT=$IX/cert                 # the free5gc-compose sample certs, fetched once
BIN=$IX/bin

PREFIX=upf-interop
NET=$PREFIX-net
BRIDGE=${BRIDGE:-upfinterop0}
# A /24 of its own: not docker's default 172.17/16, not podman's 10.88/16, not
# the host LAN. The gateway (.1) is the bridge address upfd binds: a real SMF
# dials UDP 8805 and the node this address names. Containers without a fixed
# address (everything but the SMF) are numbered from .128 up.
SUBNET_PREFIX=${SUBNET_PREFIX:-10.77.88}
SUBNET=$SUBNET_PREFIX.0/24
UPF_IP=$SUBNET_PREFIX.1
SMF_IP=$SUBNET_PREFIX.10
N4=$UPF_IP:8805

TAG=${F5GC_TAG:-v4.3.0}       # free5gc/<nf>:$TAG, one release for every NF and the simulator
MONGO_IMAGE=${MONGO_IMAGE:-mongo:4.4}
GRAPH=${GRAPH:-$ROOT/deploy/session-path.yaml}
PLUG=${PLUG:-$ROOT/datapath/build}
CERT_URL=https://raw.githubusercontent.com/free5gc/free5gc-compose/master/cert

IMSI=${IMSI:-imsi-208930000000001}
PLMN=${PLMN:-20893}

# Go: the mise toolchain the repo is built with, unless GO says otherwise.
for d in "$HOME"/.local/share/mise/installs/go/1.27.2/bin; do [ -d "$d" ] && PATH=$d:$PATH; done
GO=${GO:-go}

OWNER=${SUDO_USER:-$(id -un)}
# dk: docker, through the docker group when this shell has not got it yet.
dk() {
  if [ -z "${_DK:-}" ]; then
    if docker info >/dev/null 2>&1; then _DK=plain; else _DK=sudo; fi
  fi
  if [ "$_DK" = plain ]; then docker "$@"; else sudo -n -u "$OWNER" -g docker docker "$@"; fi
}

log() { echo "[interop $(date +%H:%M:%S)] $*"; }
die() { echo "interop: $*" >&2; exit 1; }

alive() { # alive <pidfile>: the recorded process still runs
  [ -s "$1" ] && kill -0 "$(cat "$1")" 2>/dev/null
}

# detach <name> <cmd...>: run cmd in its own session, record its pid in
# $STATE/<name>.pid and, when it ends, its exit status in $STATE/<name>.exit
# (down.sh reads it: a daemon that aborts on teardown has freed something it
# should not have). The stdout/stderr are $LOGS/<name>.log.
detach() {
  local name=$1; shift
  rm -f "$STATE/$name.exit"
  setsid bash -c '
    "$@" >>"'"$LOGS/$name.log"'" 2>&1 &
    echo $! >"'"$STATE/$name.pid"'"
    wait $!
    echo $? >"'"$STATE/$name.exit"'"
  ' _ "$@" </dev/null >/dev/null 2>&1 &
  for _ in $(seq 1 40); do [ -s "$STATE/$name.pid" ] && return 0; sleep 0.05; done
  die "$name did not start"
}

# stop_detached <name>: SIGTERM, wait up to 15 s for the exit status file, print
# the status (137: it had to be killed; unknown: it was not running).
stop_detached() {
  local name=$1 pid rc=""
  pid=$(cat "$STATE/$name.pid" 2>/dev/null || true)
  [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  for _ in $(seq 1 150); do
    [ -s "$STATE/$name.exit" ] && { rc=$(cat "$STATE/$name.exit"); break; }
    if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then   # gone; its wrapper may still be writing the status
      sleep 0.3
      [ -s "$STATE/$name.exit" ] && rc=$(cat "$STATE/$name.exit")
      break
    fi
    sleep 0.1
  done
  if [ -z "$rc" ] && [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    kill -9 "$pid" 2>/dev/null || true
    rc=137
  fi
  rm -f "$STATE/$name.pid"
  echo "${rc:-unknown}"
}

cip() { # cip <container>: its address on the interop network
  dk inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$PREFIX-$1" 2>/dev/null
}

# wait_tcp <host> <port> <secs>
wait_tcp() {
  local i
  for ((i = 0; i < $3 * 5; i++)); do
    (exec 3<>"/dev/tcp/$1/$2") 2>/dev/null && return 0
    sleep 0.2
  done
  return 1
}

# wait_log <logfile> <regex> <secs>
wait_log() {
  local i
  for ((i = 0; i < $3 * 5; i++)); do
    grep -Eq "$2" "$1" 2>/dev/null && return 0
    sleep 0.2
  done
  return 1
}

# wait_clog <container> <regex> <secs>: the container's log, not a file
wait_clog() {
  local i out
  for ((i = 0; i < $3 * 5; i++)); do
    out=$(dk logs "$PREFIX-$1" 2>&1 || true)   # not a pipe into grep -q: SIGPIPE would fail it under pipefail
    grep -Eq "$2" <<<"$out" && return 0
    sleep 0.2
  done
  return 1
}

# nf <name> <docker run args...>: start container upf-interop-<name> on $NET (or NF_NETWORK)
# unless it already runs.
nf() {
  local name=$1; shift
  local c=$PREFIX-$name
  if [ "$(dk inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" = true ]; then
    log "$c already running"; return 0
  fi
  dk rm -f "$c" >/dev/null 2>&1 || true
  dk run -d --name "$c" --network "${NF_NETWORK:-$NET}" --label upf-interop=1 "$@" >/dev/null
  log "started $c"
}
mkdir -p "$STATE" "$LOGS" "$CONF" "$BIN"
