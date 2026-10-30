#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# TOSSI CNTC's UPF conformance profile (https://tossi.org, TOSSI-Foundation/CNTC,
# `conformance`: CF-01..05 over N4, NT-01..03 over N3), as far as it can be driven
# without CNTC's own Python harness:
#
#   N4  OMEC's pfcpsim -- the PFCP simulator CNTC's suites drive, so the messages
#       are CNTC's, but for one bit corrected below -- against a live upfd:
#       association, a session's establishment, modification and deletion
#       (CF-01..04), and three sessions with a QFI.
#       CF-05 is NOT exercised here: pfcpsim refuses an unknown session on its own
#       side ("Not enough active sessions") and sends nothing, so CNTC's CF-05
#       passes without the UPF being asked; the unknown-SEID answer is tested in
#       internal/session and internal/n4.
#   N3  CNTC's NT-01..03 frames (ci/cntc/frames.py), one variant at a time, at line
#       rate through endpoint-scoped F-TEID admission and GtpuDecap, with a
#       pfcpsim session installed: the daemon must stay up, malformed packets
#       must drop, control/unknown traffic must use gate 2, and valid frames
#       must reach the Router.
#
# This is not CNTC's verdict and earns no certificate: CNTC's own N3 tests send
# through a NIC and read port counters (its adapters are per UPF), and upfd has
# no adapter. What this proves is the part a UPF can fail: the PFCP messages and
# the frames are CNTC's, and the answers are checked here.
#
#   ci/cntc-path.sh
#   CNTC_DIR=/path/to/CNTC ci/cntc-path.sh     # a checkout with pfcpsim built
#
# CNTC is fetched into .scratch/CNTC (gitignored) and pfcpsim built there on the
# first run; that needs the network, git and the go toolchain.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/ci/bess-env.sh"
PLUG=${PLUG:-$ROOT/datapath/build}
GO=${GO:-$(MISE_GO_VERSION=${MISE_GO_VERSION:-1.27.1} mise which go 2>/dev/null || echo go)}
export GOWORK=off
CNTC_DIR=${CNTC_DIR:-$ROOT/.scratch/CNTC}
PS=$CNTC_DIR/third_party/pfcpsim
N3=192.0.2.1
GNB=192.0.2.10
N4_ADDR=127.0.0.77   # a loopback address of its own: the PFCP port stays the standard one

BESSD=$STAGE/bin/bessd
BESSCTL=$STAGE/bin/bessctl
[ -x "$BESSD" ] || { echo "cntc-path: no bessd at $BESSD (set STAGE)" >&2; exit 1; }
[ -f "$PLUG/libupf_datapath.so" ] || { echo "cntc-path: build the plugin first: (cd datapath && ninja -C build)" >&2; exit 1; }

WORK=$ROOT/build/run/cntc-path
rm -rf "$WORK"; mkdir -p "$WORK"

if [ ! -d "$CNTC_DIR/.git" ]; then
  mkdir -p "$(dirname "$CNTC_DIR")"
  git clone -q --depth 1 https://github.com/TOSSI-Foundation/CNTC.git "$CNTC_DIR"
fi
[ -x "$PS/pfcpctl" ] || (cd "$PS" && $GO build -o pfcpctl ./cmd/pfcpctl)
# pfcpsim codes the downlink PDR's UE IP Address with S/D=0, a source address
# (TS 29.244 8.2.62), while that PDR's own SDF filter ("to assigned") makes the
# UE the destination; upfd refuses the contradiction (Cause 69), and CF-02 with
# it. pfcpsim is built here with S/D set (0x6: V4 and S/D), the coding an SMF
# gives a downlink PDR, by a build overlay that leaves the CNTC checkout as is.
# Reported: https://github.com/omec-project/pfcpsim/issues/363 and, for CNTC's
# vendored copy, https://github.com/TOSSI-Foundation/CNTC/issues/1.
PDRB=$PS/pkg/pfcpsim/session/pdr_builder.go
OVERLAY=()
if grep -q 'NewUEIPAddress(0x2, b.ueAddress' "$PDRB"; then
  sed 's/NewUEIPAddress(0x2, b\.ueAddress/NewUEIPAddress(0x6, b.ueAddress/' "$PDRB" >"$WORK/pdr_builder.go"
  printf '{"Replace":{"%s":"%s"}}\n' "$PDRB" "$WORK/pdr_builder.go" >"$WORK/overlay.json"
  OVERLAY=(-overlay "$WORK/overlay.json")
fi
(cd "$PS" && $GO build "${OVERLAY[@]}" -o "$WORK/pfcpsim" ./cmd/pfcpsim)
echo "cntc-path: CNTC $(git -C "$CNTC_DIR" rev-parse --short HEAD)"

(cd "$ROOT" && $GO build -o "$WORK/upfd" ./cmd/upfd)
export LD_LIBRARY_PATH=$STAGE/lib:$DPDK_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}

BESS_PID="" UPFD_PID="" SIM_PID=""
stop() {
  [ -n "$SIM_PID" ] && kill "$SIM_PID" 2>/dev/null || true
  [ -n "$UPFD_PID" ] && kill "$UPFD_PID" 2>/dev/null || true
  if [ -n "$BESS_PID" ] && kill -0 "$BESS_PID" 2>/dev/null; then
    "$BESSCTL" -s "127.0.0.1:$BESS_PORT" shutdown >/dev/null 2>&1 || true
    wait "$BESS_PID" 2>/dev/null || true
  fi
  BESS_PID="" UPFD_PID="" SIM_PID=""
}
trap stop EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

# start <graph.yaml>: bessd with the graph applied (paused), upfd, pfcpsim.
start() {
  "$BESSD" --mem_backing=normal -skip_root_check -p "$BESS_PORT" -i "$WORK/bessd.pid" -modules="$PLUG" -f >"$WORK/bessd.log" 2>&1 &
  BESS_PID=$!
  for _ in $(seq 1 60); do "$BESSCTL" -s "127.0.0.1:$BESS_PORT" status >/dev/null 2>&1 && break; sleep 0.5; done
  "$BESSCTL" -s "127.0.0.1:$BESS_PORT" status >/dev/null 2>&1 || { cat "$WORK/bessd.log" >&2; fail "bessd did not come up"; }
  "$BESSCTL" -s "127.0.0.1:$BESS_PORT" apply "$1" >/dev/null
  "$WORK/upfd" -n4 "$N4_ADDR:8805" -node-id "$N4_ADDR" -bess "127.0.0.1:$BESS_PORT" -fteid-address "endpoint=1,reference=n3,transport-domain=1,source=access,ipv4=$N3" -gtpu-decap decap0 \
    -log-level info >"$WORK/upfd.log" 2>&1 &
  UPFD_PID=$!
  for _ in $(seq 1 40); do grep -q 'n4 listening' "$WORK/upfd.log" 2>/dev/null && break; sleep 0.25; done
  kill -0 "$UPFD_PID" 2>/dev/null || { cat "$WORK/upfd.log" >&2; fail "upfd exited"; }
  GRPC=$(free_port)
  "$WORK/pfcpsim" -p "$GRPC" -i lo >"$WORK/pfcpsim.log" 2>&1 &
  SIM_PID=$!
  sleep 1
  CTL=("$PS/pfcpctl" -s "localhost:$GRPC")
  "${CTL[@]}" service configure -r "$N4_ADDR" -n "$N3" >/dev/null 2>&1
  "${CTL[@]}" service associate >"$WORK/associate.out" 2>&1 || { cat "$WORK/associate.out" >&2; fail "CF-01: the association was refused"; }
}

# metric <module> <gate>: packets out of a module's gate, from the daemon's metrics.
metric() {
  "$BESSCTL" -s "127.0.0.1:$BESS_PORT" metrics 2>/dev/null >"$WORK/metrics.out" || true
  grep bess_gate_packets_total "$WORK/metrics.out" | grep "module=\"$1\"" | grep "gate=\"$2\"" |
    grep 'direction="out"' | awk '{print $NF}' | head -1 || true
}

# ---------------------------------------------------------------------------
echo "== N4: pfcpsim, CNTC's messages (CF-01..04)"
start "$ROOT/deploy/session-path.yaml"
step() { # step <what> <pfcpctl args...>
  local what=$1; shift
  "${CTL[@]}" "$@" >"$WORK/step.out" 2>&1 || { cat "$WORK/step.out" >&2; cat "$WORK/upfd.log" >&2; fail "$what"; }
  echo "ok: $what"
}
step "CF-02: a session is established" session create -c 1 -i 20 -u 10.250.0.0/24 -g "$GNB"
step "CF-03: it is modified" session modify -c 1 -i 20 -u 10.250.0.0/24 -g "$GNB"
step "CF-04: it is deleted" session delete -c 1 -i 20
step "three sessions with a QFI are established" session create -c 3 -i 100 -u 10.250.0.0/24 -g "$GNB" -q 9
step "and deleted" session delete -c 3 -i 100
"${CTL[@]}" service disassociate >/dev/null 2>&1 || fail "CF-01: the release was not answered"
echo "ok: CF-01: the association is set up and released"
if grep -q 'level=WARN\|level=ERROR' "$WORK/upfd.log"; then
  cat "$WORK/upfd.log" >&2; fail "upfd logged a warning or an error"
fi
stop

# ---------------------------------------------------------------------------
echo "== N3: CNTC's NT-01..03 frames, one variant at a time"
# route = admitted and forwarded; miss/control = decap gate 2; drop = no decap
# output. The unknown TEID and non-G-PDU control messages intentionally share
# gate 2, while malformed frames stop before either output gate.
VARIANT_LIST="valid:route psc_valid:route unknown_teid:miss echo_request:control reserved_type:control truncated_hdr:drop bad_version:drop gpdu_no_inner:drop len_overflow:drop psc_malformed:drop"
CRASH_LOG=/tmp/bessd_crash.log
for entry in $VARIANT_LIST; do
  v=${entry%%:*} stage=${entry##*:}
  python3 "$ROOT/ci/cntc/frames.py" "$WORK/n3.yaml" "$v"
  BEFORE=$(stat -c %Y "$CRASH_LOG" 2>/dev/null || echo 0)
  start "$WORK/n3.yaml"
  "${CTL[@]}" session create -c 1 -i 210001 -u 10.250.0.0/24 -g "$GNB" >"$WORK/step.out" 2>&1 ||
    { cat "$WORK/step.out" >&2; fail "$v: the session was not established"; }
  "$BESSCTL" -s "127.0.0.1:$BESS_PORT" resume >/dev/null
  sleep 3
  sent=$(metric src_up 0); admitted=$(metric decap0 0); gate2=$(metric decap0 2); routed=$(metric rt 0)
  kill -0 "$BESS_PID" 2>/dev/null || fail "$v: bessd died"
  [ "$(stat -c %Y "$CRASH_LOG" 2>/dev/null || echo 0)" = "$BEFORE" ] || fail "$v: bessd wrote a crash report"
  "$BESSCTL" -s "127.0.0.1:$BESS_PORT" status >/dev/null 2>&1 || fail "$v: bessd stopped answering"
  [ "${sent:-0}" -gt 0 ] || fail "$v: nothing was sent"
  case $stage in
    route)
      [ "${admitted:-0}" -gt 0 ] && [ "${routed:-0}" -gt 0 ] ||
        fail "$v: an admitted valid frame did not reach the Router (sent=$sent admitted=$admitted routed=$routed)"
      ;;
    miss)
      [ "${admitted:-0}" -eq 0 ] && [ "${gate2:-0}" -gt 0 ] && [ "${routed:-0}" -eq 0 ] ||
        fail "$v: unknown TEID did not use gate 2 (admitted=$admitted gate2=$gate2 routed=$routed)"
      ;;
    control)
      [ "${admitted:-0}" -eq 0 ] && [ "${gate2:-0}" -gt 0 ] && [ "${routed:-0}" -eq 0 ] ||
        fail "$v: control traffic did not use gate 2 (admitted=$admitted gate2=$gate2 routed=$routed)"
      ;;
    drop)
      [ "${admitted:-0}" -eq 0 ] && [ "${gate2:-0}" -eq 0 ] && [ "${routed:-0}" -eq 0 ] ||
        fail "$v: malformed traffic left decap (admitted=$admitted gate2=$gate2 routed=$routed)"
      ;;
  esac
  echo "ok: $v: sent=$sent admitted=${admitted:-0} gate2=${gate2:-0} routed=${routed:-0}, must stop at: $stage"
  stop
done
echo "ok: bessd stayed up through every variant and wrote no crash report"
rm -rf "$WORK"
