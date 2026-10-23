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

BESSCTL=$STAGE/bin/bessctl
LOG=$(mktemp /tmp/upf-smoke-XXXXXX.log)
PIDFILE=$(mktemp /tmp/upf-bessd-XXXXXX.pid)

bessd_start "$LOG" "$PIDFILE" || exit 1
cleanup() { bessd_stop; }
trap cleanup EXIT

if ! bessd_wait 30 1; then
  echo "smoke: the daemon did not come up; log follows" >&2
  cat "$LOG" >&2
  exit 1
fi
if ! bessd_apply "$ROOT/deploy/smoke-gtpu.yaml"; then
  echo "smoke: the graph did not apply; log follows" >&2
  cat "$LOG" >&2
  exit 1
fi

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
# check_file greps a file that is not the log (a command's answer).
check_file() { # check_file <description> <file> <fixed string>
  if grep -q -- "$3" "$2" 2>/dev/null; then
    echo "smoke: ok    $1"
  else
    echo "smoke: FAIL  $1 (no '$3' in $2)" >&2
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

# check_block greps the metadata blocks one Dump printed. The allocator picks
# attribute offsets per graph, so the checks name byte values that only one
# attribute of that chain can hold rather than positions.
dump_block() { # dump_block <dump module>
  awk -v d="$1: packet dump" '$0 == d { p = 1; next } /: packet dump$/ { p = 0 }
    p && /^000000[0-9a-f]0: /' "$LOG"
}
check_block() { # check_block <description> <dump module> <fixed string>
  if dump_block "$2" | grep -q -- "$3"; then
    echo "smoke: ok    $1"
  else
    echo "smoke: FAIL  $1 (no '$3' in a metadata block of $2 in $LOG)" >&2
    FAIL=1
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
# frame (the outer frame's Ethernet header + the 37-byte inner IPv4 packet
# 10.0.0.1 -> 8.8.8.8, UDP 1234 -> 53, "hello-upf").
check "decap left the inner packet in a frame" \
      "02 00 00 00 00 01 02 00 00 00 00 02 08 00 45 00"
# dump_up's metadata holds endpoint_id 1, the fteid_context 0x0C0FFEE1 that
# decap0's fteids row carries, and qfi 5. No other attribute of the chain can
# hold 0C 0F FE E1 or 05.
check_block "decap wrote the admission entry's fteid_context" dump_up "0C 0F FE E1"
check_block "decap read the container's QFI into metadata" dump_up " 05 "

# The second admitted F-TEID has no PDU Session Container. Its one qfi byte is
# 255, not 0 (QFI 0 is valid); no other attribute of the chain holds FF.
check_block "the container-less F-TEID was admitted" dump_nocont "0C 0F FE E2"
check_block "a G-PDU with no container leaves qfi at 255, not 0" dump_nocont " FF "

# The F-TEID table is what makes a TEID ours: TEID 0x55667788 has no admission
# entry, so GtpuDecap sends it to gate 2 and the responder returns an Error
# Indication. The inner source address (10.0.0.2) must not appear in the log.
refute "an unknown TEID's payload goes nowhere" "0a 00 00 02"

# Downlink: the plugin resolved the ActionId against encap0/tunnels and built
# routed outer headers. Ethernet resolution remains the Router's job, so the
# output MAC addresses are zero. The outer IPv4 source is 10.20.30.1, peer is
# 10.20.30.2, and the header checksum is ea79.
check "encap defers Ethernet resolution to Router" \
      "00 00 00 00 00 00 00 00 00 00 00 00 08 00"
# UDP -> 2152, GTP-U type 255 (G-PDU), length 37, TEID 0x11223344, then the
# inner packet byte for byte. Each check stays inside one 16-byte dump line.
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

# Echo: control messages bypass F-TEID lookup and leave decap gate 2 for the
# responder. The request is conformant (flags 0x32: S set, as 5.1 requires of
# an echo; sequence 0x1234; a Recovery Time Stamp IE of its own), and the reply
# is that message with Ethernet and IPv4 addresses swapped, type set to 2, and
# payload replaced. The outer IPv4 packet is 20 + UDP 33 bytes with its checksum
# recomputed; GTP-U length is 17 with the sequence, Recovery IE and this node's
# Recovery Time Stamp.
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

# The G-PDU with unknown TEID 0x55667788 misses F-TEID admission and reaches
# gate 2. The responder answers with an Error Indication (TS 29.281 7.3.1):
# type 26, S clear, length 5 (the TEID IE alone), TEID 0 in the header, and the
# peer's TEID in the IE.
check "an unnamed TEID is answered with an Error Indication" "30 1a 00 05 00 00"
check "the Error Indication names the TEID the peer used" "10 55 66 77 88"

# The IPv6 unknown G-PDU has no admission row. The Error Indication must swap
# the outer endpoints and carry a valid, nonzero IPv6 UDP checksum (0x6391).
check "IPv6 unknown G-PDU receives a checksummed Error Indication" \
      "08 68 08 68 00 15 63 91 30 1a"
check "the IPv6 Error Indication names the peer's TEID" "10 55 66 77 89"

# The IPv6 Echo response keeps its IPv6 outer header and rewrites the payload
# length for the longer reply tail; the first GTP-U octets name Echo Response.
check_next "IPv6 Echo response has the rebuilt IPv6 payload length" \
      "86 dd 60 00" "00 00 00 21 11 40"
check_next "IPv6 Echo request receives a type-2 response" \
      "32 02" "00 11 00 00"

# The peer's own Error Indication is control traffic on gate 2. The responder
# records it without a reply; the count is what the controller's ERIR report
# reads. 0x55667788 is 1432778632.
ERRORS=$(mktemp /tmp/upf-smoke-errors-XXXXXX.txt)
"$BESSCTL" -s "127.0.0.1:$BESS_PORT" action resp_err get_errors '{}' >"$ERRORS" 2>&1 || true
check_file "the responder counted the peer's Error Indication" "$ERRORS" "1432778632"

check_clean_shutdown "$BESSD_PID" || FAIL=1
if [ "$FAIL" = 0 ]; then
  echo "smoke: PASS (log: $LOG)"
else
  echo "smoke: log kept at $LOG" >&2
fi
exit "$FAIL"
