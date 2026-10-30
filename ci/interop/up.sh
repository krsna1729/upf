#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# Bring up the real-SMF environment (docs/interop.md), idempotently:
#
#   host    bessd (this repo's build, own gRPC port) + the lab graph + upfd,
#           N4 bound to the bridge gateway $UPF_IP:8805 only, and a tcpdump of
#           UDP 8805 on the bridge
#   docker  network upf-interop-net (own /24 and own bridge) and the free5GC
#           v4.3.0 core -- MongoDB, NRF, UDR, UDM, AUSF, NSSF, PCF, CHF, WebUI,
#           AMF, SMF -- with the SMF's UPF address pointed at upfd, and the
#           subscriber provisioned
#
# The gNB/UE are not started here: ci/interop/ue.sh does that, so the PFCP
# association can be watched alone first. A second run changes nothing that is
# already running. down.sh undoes exactly this.
#
#   ci/interop/up.sh
#   SMF_NODE_ID_FQDN=1 ci/interop/up.sh   # the SMF's Node ID as its FQDN, as the stock config has it
#   SHIM=1 ci/interop/up.sh                   # diagnostic: repair upfd's establishment response (n4shim)
#   SUBSCRIBER=subscriber-flows.json ci/interop/up.sh   # two PCC flow rules: SDF filters and QER/QFI per rule
#   URR_PERIOD=0 URR_THRESHOLD=0 ci/interop/up.sh   # the SMF creates no default URRs
#   UPFD_BIN=/path/to/upfd ci/interop/up.sh   # skip building upfd

set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

BESSD=$STAGE/bin/bessd
BESSCTL=$STAGE/bin/bessctl
[ -x "$BESSD" ] || die "no bessd at $BESSD (set STAGE)"
[ -x "$BESSCTL" ] || die "no bessctl at $BESSCTL (set STAGE)"
[ -f "$PLUG/libupf_datapath.so" ] || die "build the plugin first: (cd datapath && ninja -C build)"
dk info >/dev/null 2>&1 || die "docker is not reachable (neither directly nor through 'sudo -n -u $OWNER -g docker')"

# --- the network ----------------------------------------------------------
if dk network inspect "$NET" >/dev/null 2>&1; then
  log "network $NET exists"
else
  if ip -4 route show | grep -q "^$SUBNET_PREFIX\."; then
    die "$SUBNET overlaps a host route; set SUBNET_PREFIX"
  fi
  dk network create --driver bridge --subnet "$SUBNET" --gateway "$UPF_IP" --ip-range "$SUBNET_PREFIX.128/25" \
    -o com.docker.network.bridge.name="$BRIDGE" "$NET" >/dev/null
  log "network $NET created: $SUBNET, bridge $BRIDGE, gateway $UPF_IP"
fi
ip -4 addr show dev "$BRIDGE" 2>/dev/null | grep -q "inet $UPF_IP/" || die "$BRIDGE does not carry $UPF_IP"

# --- certificates, configs ------------------------------------------------
# The free5gc-compose sample certificates: public test material, fetched once.
mkdir -p "$CERT"
if [ ! -s "$CERT/root.pem" ]; then
  for f in root nrf amf ausf nssf pcf smf udm udr chf; do
    for e in pem key; do curl -fsS --max-time 30 "$CERT_URL/$f.$e" -o "$CERT/$f.$e" || die "fetching cert $f.$e"; done
  done
  log "fetched the sample certificates into $CERT"
fi
SMF_NODE_ID=$SMF_IP
[ -n "${SMF_NODE_ID_FQDN:-}" ] && SMF_NODE_ID=smf.free5gc.org
# The stock SMF reports usage every 10 s / 1000 bytes through URRs that carry
# Measurement Information; URR_PERIOD=0 URR_THRESHOLD=0 makes it create none.
URR_PERIOD=${URR_PERIOD:-10}
URR_THRESHOLD=${URR_THRESHOLD:-1000}
# The N3 address the SMF hands the gNB: the UPF's own, which with real packets
# is the N3 port's address (.2), not the bridge's (.1, the host's, and N4's).
UPF_N3=$UPF_IP
[ -n "$DATAPLANE" ] && UPF_N3=$N3_IP
for f in "$ROOT"/deploy/interop/free5gc/*.yaml; do
  sed -e "s|@SMF_IP@|$SMF_IP|g" -e "s|@UPF_IP@|$UPF_IP|g" -e "s|@UPF_N3_IP@|$UPF_N3|g" -e "s|@SMF_NODE_ID@|$SMF_NODE_ID|g" \
    -e "s|@URR_PERIOD@|$URR_PERIOD|g" -e "s|@URR_THRESHOLD@|$URR_THRESHOLD|g" "$f" >"$CONF/$(basename "$f")"
done

# --- the host firewall ----------------------------------------------------
# The host's INPUT chain is policy DROP (ufw): a packet a container sends to the
# bridge gateway never reaches a process listening there. One rule, scoped to
# this bridge and to UDP 8805 (the SMF's requests, and the answers to the UPF's
# own), lets N4 through; down.sh deletes it. It is a runtime rule, not saved.
FW_RULE=(INPUT -i "$BRIDGE" -p udp --dport 8805 -m comment --comment "$PREFIX-n4" -j ACCEPT)
if sudo -n iptables -w -C "${FW_RULE[@]}" 2>/dev/null; then
  log "firewall: INPUT accept for $BRIDGE udp/8805 already present"
else
  sudo -n iptables -w -I "${FW_RULE[@]}" || die "could not insert the INPUT rule for $BRIDGE udp/8805"
  log "firewall: inserted INPUT accept -i $BRIDGE -p udp --dport 8805 (comment $PREFIX-n4)"
fi

# --- the node under test: bessd, the graph, upfd --------------------------
export LD_LIBRARY_PATH=$STAGE/lib:$DPDK_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
if alive "$STATE/bessd.pid"; then
  BESS_PORT=$(cat "$STATE/bess_port")
  log "bessd already running (pid $(cat "$STATE/bessd.pid"), port $BESS_PORT)"
else
  : >"$LOGS/bessd.log"
  echo "$BESS_PORT" >"$STATE/bess_port"
  if [ -n "$DATAPLANE" ]; then
    # Real ports: the veths, the graph wired to them, and bessd as root (an
    # AF_PACKET socket needs it; the packets and the N4 side stay the same).
    "$(dirname "${BASH_SOURCE[0]}")/net.sh" up
    DEPLOYED=$ROOT/deploy/upf.yaml
    python3 "$(dirname "${BASH_SOURCE[0]}")/graph.py" "$DEPLOYED" "$STATE/graph.yaml" "$IF_N3" "$IF_N6" \
      "$N3_IP" "$N3_MAC" "$GNB_IP" "$N6_MAC" "$DN_IP" "$DN_GW" "$STATE/end-marker.sock" || die "building the dataplane graph failed"
    GRAPH=$STATE/graph.yaml
    detach bessd sudo -n -E env "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" \
      "$BESSD" -m 0 -skip_root_check -p "$BESS_PORT" -i "$STATE/bessd-own.pid" -modules="$PLUG" -f
  else
    detach bessd "$BESSD" -m 0 -skip_root_check -p "$BESS_PORT" -i "$STATE/bessd-own.pid" -modules="$PLUG" -f
  fi
  for _ in $(seq 1 60); do "$BESSCTL" -s "127.0.0.1:$BESS_PORT" status >/dev/null 2>&1 && break; sleep 0.5; done
  "$BESSCTL" -s "127.0.0.1:$BESS_PORT" status >/dev/null 2>&1 || { cat "$LOGS/bessd.log" >&2; die "bessd did not come up"; }
  "$BESSCTL" -s "127.0.0.1:$BESS_PORT" apply "$GRAPH" >/dev/null
  "$BESSCTL" -s "127.0.0.1:$BESS_PORT" resume >/dev/null
  log "bessd up on 127.0.0.1:$BESS_PORT, graph $(basename "$GRAPH") applied"
fi

# SHIM=1: upfd listens on loopback and ci/interop/n4shim, a diagnostic relay,
# owns $N4 and repairs the Session Establishment Response's Node ID and UP
# F-SEID (docs/interop.md): the evidence of such a run is labelled as shimmed.
N4_UPFD=$N4
[ -n "${SHIM:-}" ] && N4_UPFD=127.0.0.1:$(cat "$STATE/n4_backend_port" 2>/dev/null || free_port)
if alive "$STATE/upfd.pid"; then
  log "upfd already running (pid $(cat "$STATE/upfd.pid"))"
else
  # Nothing may hold 8805 on a wildcard address or on the gateway.
  if ss -lnuH "( sport = :8805 )" | awk '{print $4}' | grep -Eq "^(0\.0\.0\.0|\*|\[::\]|$UPF_IP):8805$"; then
    die "UDP 8805 is already bound on $UPF_IP or a wildcard address (not by this environment)"
  fi
  if [ -n "${UPFD_BIN:-}" ]; then
    cp "$UPFD_BIN" "$BIN/upfd"
  else
    (cd "$ROOT" && $GO build -o "$BIN/upfd" ./cmd/upfd) || die "building upfd failed"
  fi
  : >"$LOGS/upfd.log"
  echo "${N4_UPFD##*:}" >"$STATE/n4_backend_port"
  # The deployed uplink key includes the 5-tuple, F-TEID endpoint identity and
  # QFI. The default field order matches deploy/upf.yaml.
  UPFD_ARGS=(-n4 "$N4_UPFD" -node-id "$UPF_IP" -bess "127.0.0.1:$BESS_PORT"
    -fteid-address "endpoint=1,reference=n3,transport-domain=1,source=access,ipv4=$UPF_N3"
    -gtpu-decap decap0
    -log-level "${UPFD_LOG_LEVEL:-debug}")
  # The evaluation loop: without it no URR is ever read, so a real SMF's URRs
  # (the stock config's period 10 s and volume threshold 1000 bytes) are never
  # reported on, and even the Session Deletion Response's termination reports
  # carry zero -- the first reading of a URR is its baseline, not its usage
  # (report.go). One second is well inside the SMF's own 10 s period.
  UPFD_ARGS+=(-urr-interval "${URR_INTERVAL:-1s}")
  # The base path selects a tunnel's domain-specific marker socket: the old
  # tunnel's on SNDEM, and the outgoing tunnel's when a received End Marker
  # (drained from echo0, deploy/upf.yaml) is relayed through it.
  [ -n "$DATAPLANE" ] && UPFD_ARGS+=(-end-marker "$STATE/end-marker.sock" -gtpu-end-markers echo0)
  detach upfd "$BIN/upfd" "${UPFD_ARGS[@]}"
  wait_log "$LOGS/upfd.log" "n4 listening" 10 || { cat "$LOGS/upfd.log" >&2; die "upfd did not start"; }
  log "upfd up: N4 $N4_UPFD, node-id $UPF_IP, bess 127.0.0.1:$BESS_PORT"
fi
if [ -n "${SHIM:-}" ] && ! alive "$STATE/n4shim.pid"; then
  (cd "$ROOT" && $GO build -o "$BIN/n4shim" ./ci/interop/n4shim) || die "building n4shim failed"
  : >"$LOGS/n4shim.log"
  detach n4shim "$BIN/n4shim" -front "$N4" -upfd "$N4_UPFD" -node-id "$UPF_IP"
  wait_log "$LOGS/n4shim.log" "n4shim: SMF side" 10 || die "n4shim did not start"
  log "n4shim up: $N4 -> $N4_UPFD (DIAGNOSTIC: repairs the Session Establishment Response)"
fi

# --- the capture ----------------------------------------------------------
# capture <name> <interface> <bpf>: tcpdump (as root through sudo, dropping to
# this user for the file) into $IX/<name>.pcap, one pid file for down.sh.
capture() {
  if [ -s "$STATE/$1.pid" ] && sudo -n kill -0 "$(cat "$STATE/$1.pid")" 2>/dev/null; then
    log "capture $1 already running"; return 0
  fi
  rm -f "$STATE/$1.pid"
  sudo -n sh -c 'echo $$ >"$1"; exec tcpdump -i "$2" -U -n -Z "$3" -w "$4" $5' _ \
    "$STATE/$1.pid" "$2" "$OWNER" "$IX/$1.pcap" "$3" >"$LOGS/$1-tcpdump.log" 2>&1 &
  for _ in $(seq 1 50); do grep -q "listening on" "$LOGS/$1-tcpdump.log" 2>/dev/null && break; sleep 0.1; done
  log "capturing '$3' on $2 -> $IX/$1.pcap"
}
capture n4 "$BRIDGE" "udp port 8805"
# With the shim, what upfd itself said, before the repair.
[ -n "${SHIM:-}" ] && capture n4-upfd lo "udp port ${N4_UPFD##*:}"

# --- the core -------------------------------------------------------------
# core <nf> [extra docker args]: a free5gc NF with its config and the certs mounted
core() {
  local n=$1; shift
  nf "$n" --user "$(id -u):$(id -g)" --network-alias "$n.free5gc.org" -e GIN_MODE=release -e DB_URI=mongodb://db/free5gc \
    -v "$CONF/${n}cfg.yaml:/free5gc/config/${n}cfg.yaml:ro" -v "$CERT:/free5gc/cert" "$@" \
    "free5gc/$n:$TAG" ./"$n" -c ./config/"${n}cfg.yaml"
}

nf db --network-alias db --tmpfs /data/db "$MONGO_IMAGE" mongod --port 27017
wait_clog db "Waiting for connections" 60 || die "mongodb did not come up"

core nrf
wait_tcp "$(cip nrf)" 8000 30 || die "nrf did not listen"
core udr
core udm
core ausf
core nssf
core pcf
nf webui --user "$(id -u):$(id -g)" --network-alias webui -e GIN_MODE=release -v "$CONF/webuicfg.yaml:/free5gc/config/webuicfg.yaml:ro" \
  -v "$CERT:/free5gc/cert" "free5gc/webui:$TAG" ./webui -c ./config/webuicfg.yaml
wait_tcp "$(cip webui)" 5000 30 || die "webui did not listen"
core chf
core amf
nf smf --user "$(id -u):$(id -g)" --network-alias smf.free5gc.org --ip "$SMF_IP" -e GIN_MODE=release \
  -v "$CONF/smfcfg.yaml:/free5gc/config/smfcfg.yaml:ro" -v "$CONF/uerouting.yaml:/free5gc/config/uerouting.yaml:ro" \
  -v "$CERT:/free5gc/cert" "free5gc/smf:$TAG" ./smf -c ./config/smfcfg.yaml -u ./config/uerouting.yaml

# --- the subscriber -------------------------------------------------------
# Through the WebUI's REST API (login, then POST /api/subscriber/<supi>/<plmn>);
# the database starts empty on every fresh mongodb container.
WEB=http://$(cip webui):5000
TOKEN=""
for _ in $(seq 1 30); do
  TOKEN=$(curl -fsS --max-time 3 -H 'Content-Type: application/json' -d '{"username":"admin","password":"free5gc"}' \
    "$WEB/api/login" 2>/dev/null | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p') || true
  [ -n "$TOKEN" ] && break
  sleep 1
done
[ -n "$TOKEN" ] || die "webui login failed ($WEB/api/login)"
if curl -fsS --max-time 5 -H "Token: $TOKEN" "$WEB/api/subscriber" 2>/dev/null | grep -q "$IMSI"; then
  log "subscriber $IMSI already provisioned"
else
  code=$(curl -sS --max-time 10 -o "$LOGS/subscriber.out" -w '%{http_code}' -H "Token: $TOKEN" -H 'Content-Type: application/json' \
    --data-binary @"$ROOT/deploy/interop/${SUBSCRIBER:-subscriber.json}" "$WEB/api/subscriber/$IMSI/$PLMN")
  case "$code" in 200|201) log "subscriber $IMSI provisioned" ;; *) cat "$LOGS/subscriber.out" >&2; die "provisioning the subscriber: HTTP $code" ;; esac
fi

# The SMF is ready when its N4 side has dialed the UPF: it starts the
# association itself, once it knows the UPF from its config.
if wait_log "$LOGS/upfd.log" "association|Association" 40; then
  log "the SMF has reached upfd (see $LOGS/upfd.log)"
else
  log "no association line in upfd's log yet; see docs/interop.md"
fi
log "up. Next: ci/interop/ue.sh start"
