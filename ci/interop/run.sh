#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# The real-SMF run, start to finish, in the stages docs/interop.md records. It
# starts from nothing (down.sh, then up.sh), so every run sees a fresh
# database, a fresh upfd and a fresh capture, and ends by taking everything
# down, upfd's and bessd's clean shutdown being part of the result.
#
#   a  PFCP association: the SMF dials upfd, heartbeats follow
#   b  registration and PDU session establishment: the UE registers, asks for
#      a session, and the SMF's Session Establishment Request meets upfd
#   c  PDU session release: the UE releases it, the SMF's Session Deletion
#
# A stage that does not complete stops the run there, with the evidence
# collected up to it. Environment: LABEL (name of the evidence directory,
# $IX/runs/<LABEL>), KEEP=1 (leave the environment up), and up.sh's variables
# (SMF_NODE_ID_FQDN, URR_PERIOD/URR_THRESHOLD, SHIM, ...).
#
#   ci/interop/run.sh
#   LABEL=no-urr URR_PERIOD=0 URR_THRESHOLD=0 ci/interop/run.sh

set -uo pipefail
D=$(dirname "${BASH_SOURCE[0]}")
. "$D/lib.sh"

LABEL=${LABEL:-run-$(date +%Y%m%d-%H%M%S)}
STAGE_REACHED=none
RC=0

finish() {
  "$D/report.sh" "$LABEL" || true
  "$D/ue.sh" stop >/dev/null 2>&1 || true
  if [ -z "${KEEP:-}" ]; then "$D/down.sh" || RC=1; fi
  log "stage reached: $STAGE_REACHED (evidence: $IX/runs/$LABEL)"
  exit "$RC"
}

"$D/down.sh" >/dev/null 2>&1 || true
rm -f "$IX/n4.pcap" "$IX/n4-upfd.pcap" "$LOGS"/*.log "$LOGS"/*.out
"$D/up.sh" || { RC=1; finish; }

# --- a: association -------------------------------------------------------
log "stage a: association"
if ! wait_log "$LOGS/upfd.log" "association established" 30; then
  log "stage a FAILED: upfd logged no association"; RC=1; finish
fi
STAGE_REACHED=a
log "the association is up; waiting 25 s for heartbeats"
sleep 25

# --- b: registration and PDU session --------------------------------------
log "stage b: registration and PDU session establishment"
"$D/ue.sh" start || { RC=1; finish; }
UEC=$PREFIX-ue
for _ in $(seq 1 60); do
  out=$(dk logs "$UEC" 2>&1)
  grep -q "PDU Session establishment is successful" <<<"$out" && break
  [ "$(grep -c "PDU Session Establishment Reject" <<<"$out")" -ge 3 ] && break
  sleep 1
done
if ! grep -q "PDU Session establishment is successful" <<<"$out"; then
  log "stage b FAILED: the UE has no PDU session ($(grep -c 'PDU Session Establishment Reject' <<<"$out") rejects)"
  RC=1; finish
fi
STAGE_REACHED=b
log "the PDU session is established; waiting 15 s (SMF follow-up, usage reports)"
sleep 15

# --- b2: packets through the dataplane (DATAPLANE=1) -----------------------
# The session is up and the SMF's URRs are live (period 10 s, threshold 1000
# bytes by default): ICMP echo from the UE's tunnel interface to the data
# network crosses N3 (GTP-U, decap), the uplink rule, the counters and N6, and
# the reply crosses the same chain the other way. What is checked: the echo
# comes back, and the UPF's own counting modules saw the packets -- the counters
# a URR report is built from.
if [ -n "$DATAPLANE" ]; then
  log "stage b2: packets through bessd (UE -> data network)"
  ul0=$(dp_pkts cnt_ul); dl0=$(dp_pkts cnt_dl)
  "$D/ue.sh" traffic 20 >"$LOGS/ping.out" 2>&1 || true
  ul1=$(dp_pkts cnt_ul); dl1=$(dp_pkts cnt_dl)
  loss=$(grep -o '[0-9]*% packet loss' "$LOGS/ping.out" | tail -1 | tr -dc '0-9')
  log "ping: loss=${loss:-?}%, cnt_ul +$((ul1 - ul0)) packets, cnt_dl +$((dl1 - dl0)) packets"
  if [ "${loss:-100}" != 0 ]; then
    log "stage b2 FAILED: the echo did not come back ($(tail -3 "$LOGS/ping.out" | tr '\n' ' '))"
    RC=1; finish
  fi
  if [ $((ul1 - ul0)) -le 0 ] || [ $((dl1 - dl0)) -le 0 ]; then
    log "stage b2 FAILED: the UPF's counters did not move (uplink $((ul1 - ul0)), downlink $((dl1 - dl0)))"
    RC=1; finish
  fi
  STAGE_REACHED=b2
fi

# --- c: release -----------------------------------------------------------
log "stage c: PDU session release"
"$D/ue.sh" release || true
sleep 10
smflog=$(dk logs "$PREFIX-smf" 2>&1)
grep -q "Received PFCP Session Deletion Accepted Response" <<<"$smflog" && STAGE_REACHED=c
finish
