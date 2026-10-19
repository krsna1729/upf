#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# End-to-end smoke test of the datapath plugin: build it against an installed
# bess-dev stage, load it into the staged bessd, apply deploy/smoke-gtpu.yaml,
# and check the two packets the graph dumps -- one decapsulated, one
# encapsulated -- byte for byte.
#
#   ci/smoke-gtpu.sh                    # default stage: the main checkout's installed stage
#   STAGE=/some/prefix ci/smoke-gtpu.sh # any installed bess-dev prefix
#
# The plugin must be built first (see README.md): the script uses
# datapath/build/libupf_datapath.so unless PLUG says otherwise. The daemon is
# started with no hugepages (-m 0) and never left running; run it under the
# host's build/daemon slot if one is in use.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/ci/bess-env.sh"
PLUG=${PLUG:-$ROOT/datapath/build}
SECONDS_RUN=${SECONDS_RUN:-5}

BESSD=$STAGE/bin/bessd
BESSCTL=$STAGE/bin/bessctl
LOG=$(mktemp /tmp/upf-smoke-XXXXXX.log)
PIDFILE=$(mktemp /tmp/upf-bessd-XXXXXX.pid)

[ -x "$BESSD" ] || { echo "smoke: no bessd at $BESSD (set STAGE)" >&2; exit 1; }
[ -x "$BESSCTL" ] || { echo "smoke: no bessctl at $BESSCTL (set STAGE)" >&2; exit 1; }
[ -f "$PLUG/libupf_datapath.so" ] || {
  echo "smoke: build the plugin first: (cd datapath && PKG_CONFIG_PATH=<stage>/lib/pkgconfig meson setup build && ninja -C build)" >&2
  exit 1
}

export LD_LIBRARY_PATH=$STAGE/lib:$DPDK_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}

# No hugepages: the smoke runs anywhere, including a workstation with none.
"$BESSD" -m 0 -skip_root_check -p "$BESS_PORT" -i "$PIDFILE" -modules="$PLUG" -f >"$LOG" 2>&1 &
DAEMON=$!
cleanup() {
  kill "$DAEMON" 2>/dev/null || true
  for _ in 1 2 3 4 5; do kill -0 "$DAEMON" 2>/dev/null || break; sleep 1; done
  kill -9 "$DAEMON" 2>/dev/null || true
}
trap cleanup EXIT

for _ in $(seq 1 30); do "$BESSCTL" -s "127.0.0.1:$BESS_PORT" status >/dev/null 2>&1 && break; sleep 1; done
if ! "$BESSCTL" -s "127.0.0.1:$BESS_PORT" status >/dev/null 2>&1; then
  echo "smoke: the daemon did not come up; log follows" >&2
  cat "$LOG" >&2
  exit 1
fi

# validate prints the canonical manifest, apply prints the version it committed.
"$BESSCTL" -s "127.0.0.1:$BESS_PORT" validate "$ROOT/deploy/smoke-gtpu.yaml" >/dev/null
"$BESSCTL" -s "127.0.0.1:$BESS_PORT" apply "$ROOT/deploy/smoke-gtpu.yaml" >/dev/null
"$BESSCTL" -s "127.0.0.1:$BESS_PORT" resume >/dev/null
sleep "$SECONDS_RUN"

FAIL=0
check() { # check <description> <fixed string the log must contain>
  if grep -q -- "$2" "$LOG"; then
    echo "smoke: ok    $1"
  else
    echo "smoke: FAIL  $1 (no '$2' in $LOG)" >&2
    FAIL=1
  fi
}
# check_metadata greps the metadata blocks Dump prints (four lines of hexdump
# per packet) rather than the packet hexdump: the two share byte strings.
check_metadata() { # check_metadata <description> <fixed string>
  if grep -A 5 "Metadata buffer" "$LOG" | grep -q -- "$2"; then
    echo "smoke: ok    $1"
  else
    echo "smoke: FAIL  $1 (no '$2' in a metadata block of $LOG)" >&2
    FAIL=1
  fi
}

# check_next greps for a line and then for a string in the line after it: a
# packet's Ethernet and IPv4 headers together span two 16-byte dump lines.
check_next() { # check_next <description> <fixed string> <fixed string in the next line>
  if grep -A 1 -- "$2" "$LOG" | grep -q -- "$3"; then
    echo "smoke: ok    $1"
  else
    echo "smoke: FAIL  $1 (no '$2' followed by '$3' in $LOG)" >&2
    FAIL=1
  fi
}

# refute_metadata is refute within the metadata blocks only: a packet's own
# hexdump can carry the same bytes (the QFI frame's packet does), so a
# whole-log refute would fail for the wrong reason.
refute_metadata() { # refute_metadata <description> <fixed string>
  if grep -A 5 "Metadata buffer" "$LOG" | grep -q -- "$2"; then
    echo "smoke: FAIL  $1 ('$2' is in a metadata block of $LOG)" >&2
    FAIL=1
  else
    echo "smoke: ok    $1"
  fi
}

refute() { # refute <description> <fixed string the log must not contain>
  if grep -q -- "$2" "$LOG"; then
    echo "smoke: FAIL  $1 ('$2' is in $LOG)" >&2
    FAIL=1
  else
    echo "smoke: ok    $1"
  fi
}

# Uplink: the plugin stripped IP/UDP/GTP-U and left the inner packet in a
# frame (the outer frame's own Ethernet header + the 37-byte inner IPv4 packet
# 10.0.0.1 -> 8.8.8.8, UDP 1234 -> 53, "hello-upf").
check "decap left the inner packet in a frame" \
      "02 00 00 00 00 01 02 00 00 00 00 02 08 00 45 00"
# and wrote the TEID into metadata (the mt_md reader makes that attribute a
# real one; the padding after it is another attribute's, so only the TEID is
# checked here).
check_metadata "decap wrote upf_teid into metadata" "11 22 33 44"
# The uplink frame carries a PDU Session Container (TS 38.415, extension header
# 0x85) with QFI 5, so the decap must have read it: the metadata dump's first
# line is the TEID it wrote followed by the QFI, in the layout mt_md declares
# (upf_teid 4 bytes, then qfi 1). A graph that stopped reading `qfi` would make
# the write inert (core/metadata.cc) and this line would be `11 22 33 44 00`.
check "decap read the PDU Session Container's QFI into metadata" \
      "00000000: 11 22 33 44 05"

# The same TEID with no PDU Session Container at all (src_nocont's frame, E
# flag clear) must leave 255 in the QFI byte: 0 is a real QFI (TS 38.415
# 5.5.3.3's range is 0..63, and TS 29.244 8.2.89's IE takes it), so a rule a
# PDI keys on QFI 0 has to be able to tell that packet from this one. A writer
# that wrote 0 for "no container" would make the two the same packet to the
# rule table.
check_metadata "a G-PDU with no container leaves qfi at 255, not 0" \
      "11 22 33 44 FF"
refute_metadata "no packet leaves 0 in the QFI byte of a container-less G-PDU" \
      "11 22 33 44 00"

# The session table is what makes a TEID ours: the second uplink chain's frame
# carries TEID 0x55667788, which no entry names, so the decap dropped it -- its
# inner source address (10.0.0.2) must not appear anywhere in the log.
refute "decap dropped a G-PDU whose TEID is not a session" "0a 00 00 02"

# Downlink: the plugin resolved the ActionId the packet carried against
# encap0/tunnels and built the outer headers: Eth (the record's addresses),
# IPv4 src 10.20.30.1 -> dst 10.20.30.2 (the record's peer) with a correct
# header checksum (ea 79), UDP -> 2152, GTP-U type 255 (G-PDU), length 37, TEID
# 0x11223344, then the inner packet byte for byte.
# (The Dump hexdump is 16 bytes to a line, so each check stays inside one.)
check "encap built a well-formed outer IPv4 header" \
      "00 49 00 00 40 00 40 11 ea 79 0a 14 1e 01 0a 14"
check "encap wrote UDP/GTP-U toward 2152 with the session TEID" \
      "08 68 00 35 00 00 30 ff 00 25 11 22"
check "the encapsulated frame carries the inner packet" \
      "33 44 45 00 00 25 00 01 40 00 40 11 20 b7"

# Downlink with a QFI: the second chain's tunnel record names QFI 5, so the
# outer header grows by the four-octet optional tail and a PDU Session
# Container (TS 38.415, extension header 0x85): IPv4 total 0x51 and UDP length
# 0x3d (eight more than the plain chain), then flags 0x34 (E set), GTP-U length
# 0x2d, the tail `00 00 00 85` and the container `01 00 05 00` -- length 1
# unit, PDU type 0 (downlink), QFI 5, next type 0. Each check stays inside one
# 16-byte dump line.
check "the QFI's outer header grew by the container" \
      "00 51 00 00 40 00 40 11 ea 71 0a 14"
check "the container carries the QFI and the downlink PDU type" \
      "33 44 00 00 00 85 01 00 05 00"

# Downlink with a Transport Level Marking: the third chain's session FAR names
# the marking 0xb8fc (TS 29.244 8.2.42: the DSCP EF in the ToS octet and the
# spec's 0xfc mask), while the inner frame's own TOS is 0x02. An outer header
# still reading "45 02" would be the encap copying the inner class; the outer
# TOS 0xba is the marking's EF 0xb8 over the inner packet's ECN bits 0x02,
# which the mask keeps (the NOTE under 8.2.42), and e9 bf is the IPv4 checksum
# that header recomputes to -- a marking applied to the ToS alone would leave
# the copy's ea 79 here and be a header no receiver accepts. Each check stays
# inside one 16-byte dump line.
check "the session's marking won over the inner DSCP" \
      "08 00 45 ba"
check "the marked outer header's checksum is over the marking" \
      "40 11 e9 bf 0a 14 1e 01"

# Echo: TEID 0 is no session's rule, so the request took the table's default
# gate -- the plugin's echo module -- which answered it in place. The request
# was a conformant one (flags 0x32: S set, as 5.1 requires of an echo; sequence
# 0x1234; a Recovery Time Stamp IE of its own), and the reply is that message
# with its Ethernet and IPv4 addresses swapped, its type set to 2 and its
# payload replaced: 36 bytes of outer IPv4 (0x24 -> 0x35: 20 + UDP 33) with the
# checksum that header recomputes to, UDP 2152 -> 2152 with length 33 and
# checksum 0, and a GTP-U message whose length is 17 -- the S-flag field with
# the request's sequence number, the Recovery IE (14 00: the restart counter is
# zero, 8.2) and a Recovery Time Stamp of this node's own (231, 8 octets).
check_next "echo swapped the addresses and rewrote the IPv4 header in place" \
      "02 00 00 00 00 02 02 00 00 00 00 01 08 00 45 00" \
      "00 35 00 00 40 00 40 11 ea 8d 0a 14 1e 01 0a 14"
check "echo answered with S set, its length 17, and TEID 0" \
      "1e 02 08 68 08 68 00 21 00 00 32 02 00 11 00 00"
check "echo carried the request's sequence, the Recovery IE, and its own stamp" \
      "00 00 12 34 00 00 0e 00 e7 00 08"
# The request carried a Recovery Time Stamp of its own (de ad be ef 00 00 00
# 00). The reply must carry this node's, not that one: a peer reads the stamp
# to tell when the entity it is talking to started. Any occurrence of those
# bytes would come from the reply, because the request itself is never dumped.
refute "echo replaced the request's stamp instead of echoing it" "de ad be ef"

check_clean_shutdown "$DAEMON" || FAIL=1
if [ "$FAIL" = 0 ]; then
  echo "smoke: PASS (log: $LOG)"
else
  echo "smoke: log kept at $LOG" >&2
fi
exit "$FAIL"
