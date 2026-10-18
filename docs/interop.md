# Real-SMF interop: free5GC v4.3.0 against `upfd`

No test of this repository had a real 5GC SMF on the other end of N4. This
environment puts one there (free5GC's SMF, with the rest of the core and a
UERANSIM gNB/UE to make it create sessions) and records what it sends and what
`upfd` answers. Everything here is **measured** unless marked **[INFERRED]**.
Measured on 2026-10-18 against the working tree of that day (`upfd` built from
it, `internal/session/compile.go` modified and uncommitted by another agent).

**Result, current (2026-10-18, `upfd` built from `40daf7b`, which contains the
fixes; evidence `runs/fixes-ccf667c`): the stock free5GC configuration reaches
stage (c) unshimmed.** Association, Session Establishment, Session
Modification, Heartbeats and Session Deletion are all answered `Cause 1`, with
no warning in `upfd`'s log. Scope, stated plainly: **N4 only.** The gNB and UE
ran, but no packet crossed `bessd` (no N3/N6 ports in this environment), so the
usage reports of the deletion carry zero volume, and no periodic or threshold
Session Report Request was seen in the 15 s hold.

| # | message | what the capture shows |
|---|---|---|
| 1 | Association Setup | accepted, heartbeats every 10 s answered |
| 7-8 | Session Establishment (478 B) | accepted; response carries Node ID, UP F-SEID with V4 address, Created PDR |
| 9-10 | Session Modification (173 B: Update PDR 2, Update FAR 2 with the gNB's tunnel) | accepted; the response carried a Created PDR on the first run, and since `4f40f59` it is `Cause 1` alone (re-run `runs/final`, capture checked: the only Created PDR is in the establishment response) |
| 13-14 | Session Deletion | accepted; the 197 B response carries one TERMR Usage Report per URR (trigger `000800`, URSEQN 0); the SMF completed the release |

The earlier result, kept below as the record of what failed first, is that
against an unmodified `upfd` of that day the furthest stage was (a): the first
PDU session was refused for three independent reasons (section "Findings"),
and stage (c) was reached only with a diagnostic relay (`SHIM=1`); that
evidence is labelled *shimmed*.

## Images

Open5GS publishes no usable image: `ghcr.io/open5gs/open5gs`, `…/open5gs-smf`
and `docker.io/open5gs/open5gs` all answer *denied* to `docker manifest
inspect` (they do not exist). Only third-party builds exist (`gradiant/open5gs:2.8.0`,
`openverso/open5gs:2.7.0`, manifests resolve); not used. free5GC publishes one
image per NF on Docker Hub, all pulled:

| image (pulled, `docker pull`) | digest |
|---|---|
| `free5gc/smf:v4.3.0` | `sha256:8b005eeb6af02fa9f3c5a65b5017ecfc057a53392db1be9fbd3b3fa2ac8ef473` |
| `free5gc/amf:v4.3.0` | `sha256:5035b443fb2d780ba75e576cde6cb7264ba143462945fd84c6b1bb10c0f4eeb2` |
| `free5gc/nrf:v4.3.0` | `sha256:e0c7bf50ca27d2af01ad4bad3f4772f9d07a564b9b280786f9bec9ec0d023751` |
| `free5gc/udr:v4.3.0` | `sha256:47d9f8be58b32d6284eff42efe68e868e31c21e0f5372744ddbcab87d46c49b8` |
| `free5gc/udm:v4.3.0` | `sha256:7bff71f639e1666f315a6059fe99812ff7bfdfceea4cd3b021aa7145cbbe3197` |
| `free5gc/ausf:v4.3.0` | `sha256:0692a2583bc10700bd4f7e6d02c8a97acaa58acf5a1c707e16a741cfc014f6bd` |
| `free5gc/nssf:v4.3.0` | `sha256:b073ed0b2f918a0d54338a8cedf03b53304d51ad3778f6b5aa739397df37515f` |
| `free5gc/pcf:v4.3.0` | `sha256:035d238081e393294a8c880b1582aab497d75e9a2169a4b65673403c9a27a19c` |
| `free5gc/chf:v4.3.0` | `sha256:844d775d2a29eb99101e543514a23a0c0e343564dfdc3dbd37a9d188573944f6` |
| `free5gc/webui:v4.3.0` | `sha256:425e8d609ce9f34644b4382170ba5f29dbbbb252c7504004688358608c93aadb` |
| `free5gc/ueransim:v4.3.0` (UERANSIM v3.3.0) | `sha256:93bcf5277024f204d355a2f1a902f02a2c78015f73289f2eb597bc1c8f91126a` |
| `mongo:4.4` | `sha256:4be76f674fc4b27859816811b8baa3c51830eb1dbf4ca81a51e26b79edd662ef` |

The SMF's PFCP stack is `github.com/wmnsk/go-pfcp` (v0.0.25 pre-release per its
`go.mod`), the same library `upfd` uses, so a parse difference is not a library
difference. Its source (`internal/pfcp/session.go`) is what the "missing
mandatory IE(s)" line below was traced to.

## The environment

Minimum chain that makes the SMF create a PFCP session: NRF, UDR, UDM, AUSF,
NSSF, PCF, CHF, WebUI (subscriber provisioning, and CHF's CGF peer), AMF, SMF,
MongoDB, one gNB, one UE. (free5GC's SMF starts charging toward CHF on every
session, so the CHF is part of the minimum.) Configs are the free5gc-compose
ones, in `deploy/interop/free5gc/`; changes from stock are the SMF's UPF
address and Node ID (`@UPF_IP@`, `@SMF_IP@`, `@SMF_NODE_ID@`), one slice and
one PDU session for the UE, and `urrPeriod/urrThreshold` made switchable.

```
host                                          docker network upf-interop-net 10.77.88.0/24
  bessd (own gRPC port, build/bess)             bridge upfinterop0 = 10.77.88.1  <- upfd N4 binds here only
  upfd  -n4 10.77.88.1:8805 -node-id 10.77.88.1   10.77.88.10  upf-interop-smf (fixed)
  tcpdump on upfinterop0 (udp 8805)               10.77.88.128+ every other container
```

| file | role |
|---|---|
| `ci/interop/lib.sh` | names, addresses, helpers; everything is prefixed `upf-interop-` |
| `ci/interop/up.sh` | network, firewall rule, bessd + graph, upfd, capture, core, subscriber; idempotent |
| `ci/interop/ue.sh start\|release\|status\|stop` | gNB + UE containers; `release` = `nr-cli … ps-release 1` |
| `ci/interop/down.sh` | removes exactly those, saves container logs, stops upfd/bessd with SIGTERM and fails on a non-zero exit status (as `ci/n4-path.sh` does); idempotent |
| `ci/interop/report.sh <label>` | evidence into `build/run/interop/runs/<label>/`: pcap, decoded IE tree (`n4.txt`), one-line view (`n4.summary`), every log |
| `ci/interop/run.sh` | down, up, stage a, b, c, report, down; prints `stage reached: x` |
| `ci/interop/pfcpdump/` | pcap -> PFCP IE tree (tshark is not installed; `go-pfcp` decodes, the common UPF IEs are decoded bit by bit, every leaf also in hex) |
| `ci/interop/n4shim/` | **diagnostic** relay used only with `SHIM=1` (below) |
| `deploy/interop/free5gc/*.yaml`, `subscriber*.json` | NF configs, the subscriber |

```
ci/interop/run.sh                                         # stock SMF
LABEL=no-urr URR_PERIOD=0 URR_THRESHOLD=0 ci/interop/run.sh
LABEL=x SHIM=1 URR_PERIOD=0 URR_THRESHOLD=0 ci/interop/run.sh        # diagnostic, reaches (c)
SUBSCRIBER=subscriber-flows.json ...                      # two PCC rules: SDF filters, per-rule QER/URR
SMF_NODE_ID_FQDN=1 ...                                    # the SMF's Node ID as its FQDN (stock config)
```

A full `run.sh` takes 40 s (100 s with `subscriber-flows.json`: the UE waits out T3580).

Isolation: ports are bessd's picked-free gRPC port (`build/run/interop/state/bess_port`)
and UDP 8805 on the bridge gateway only (`up.sh` refuses if 8805 is held on a
wildcard or on that address); nothing in `/tmp`; docker is reached through
`sudo -n -u $USER -g docker docker` when the shell lacks the group;
`down.sh` removes only containers named `upf-interop-*` and the network
`upf-interop-net`.

**One change to host state outside the project: an iptables rule.** The host's
`INPUT` chain is policy DROP (ufw), so a container's datagram to the gateway
never reaches `upfd`. `up.sh` inserts, and `down.sh` deletes, exactly
`iptables -I INPUT -i upfinterop0 -p udp --dport 8805 -m comment --comment upf-interop-n4 -j ACCEPT`
(runtime only, not saved). Without it the SMF's association fails as:

```
[WARN][SMF][Main] Failed to setup an association with UPF[[10.77.88.1]], error:PFCP Association Setup Request to 10.77.88.1:8805: PFCP request to 10.77.88.1:8805 timed out
```

## Stage (a): association and heartbeats — PASSED, unmodified `upfd`

The SMF dials the UPF the moment it starts. Request and answer
(`runs/stock-urr/n4.txt`, decoded from the capture; Node IDs are IPs):

```
#1  10.77.88.10:8805 -> 10.77.88.1:8805   Association Setup Request seq=0
      NodeID (60)            000a4d580a  = IPv4 10.77.88.10
      RecoveryTimeStamp (96) ee7f3c9d    = 2026-10-18T12:39:57Z
      CPFunctionFeatures (89) 00
#2  10.77.88.1:8805 -> 10.77.88.10:8805   Association Setup Response seq=0
      NodeID (60)            000a4d5801  = IPv4 10.77.88.1
      Cause (19)             01          = Request accepted
      RecoveryTimeStamp (96)
      UPFunctionFeatures (43) 10000000
```

```
[INFO][SMF][Main] Sending PFCP Association Request to UPF[10.77.88.1]
[INFO][SMF][Main] Received PFCP Association Setup Accepted Response from UPF[10.77.88.1]
[INFO][SMF][Main] UPF(10.77.88.1) setup association
upfd: level=INFO msg="n4: association established" node_id=10.77.88.10 from=10.77.88.10:8805 has_recovery_time_stamp=true
```

* The SMF advertises CP Function Features `00` (nothing). `upfd`'s UP Function
  Features is `10000000`; the SMF logged nothing about it.
* The SMF's Node ID as an FQDN (`SMF_NODE_ID_FQDN=1`, the stock config's
  `nodeID: smf.free5gc.org`) works too: request `NodeID (60) 0203736d66… = FQDN
  smf.free5gc.org`, response accepted, `upfd` logs
  `msg="n4: association established" node_id=smf.free5gc.org` (`runs/fqdn-node-id`).
* **Heartbeats are one-directional.** In every run (observed up to 98 s) the
  only Heartbeat Requests are `upfd`'s, every 10.0 s, at `upfd`'s default
  interval; the SMF answers each in under 1 ms with its Recovery Time Stamp
  `ee7f3c9d` (unchanged) and sends none of its own. `upfd` logs, at debug:

```
level=DEBUG msg="n4: heartbeat request" to=10.77.88.10:8805 seq=1 try=1
level=DEBUG msg="n4: unmatched heartbeat response" from=10.77.88.10:8805 seq=1
```

  The second line is logged for a response that is in fact the answer (same
  sequence number in the capture, seq 1..N). **[INFERRED from `internal/n4/server.go`]**
  cosmetic: `noteActivity` clears `s.pending` on any datagram from the peer
  before `onHeartbeatResponse` compares it, so the response always looks
  unmatched; liveness itself is not affected.

## Stage (b): registration and PDU session — registration PASSED, session REFUSED

gNB and UE (UERANSIM, one container pair sharing a network namespace):

```
[ngap] [info] NG Setup procedure is successful
[nas] [debug] Sending Initial Registration
[nas] [debug] Registration accept received
[nas] [info] Initial Registration is successful
[nas] [debug] Sending PDU Session Establishment Request
```

Registration touches only the core; `upfd` sees nothing until the PDU session.

### What the SMF sends (stock config) — `runs/stock-urr/n4.txt`

One Session Establishment Request, 478 bytes, header `seid=0` (decoded; hex in the file):

```
NodeID           IPv4 10.77.88.10
FSEID            flags V4 seid=0x1 v4=10.77.88.10                       (CP F-SEID)
CreatePDR 1  Precedence 255
  PDI: SourceInterface Access
       FTEID           flags V4 teid=0x00000002 v4=10.77.88.1           (CHOOSE not set)
       NetworkInstance "internet"
       UEIPAddress     flags V4 v4=10.60.0.1                            (SD clear: source)
  OuterHeaderRemoval   GTP-U/UDP/IPv4
  FARID 1   URRID 1, URRID 2   QERID 2, QERID 1
CreatePDR 2  Precedence 255
  PDI: SourceInterface Core, NetworkInstance "internet"
       UEIPAddress     flags V4|SD v4=10.60.0.1                         (SD set: destination)
  FARID 2   URRID 1, URRID 2   QERID 2, QERID 1
CreateFAR 1  ApplyAction FORW  ForwardingParameters: DestinationInterface Core, NetworkInstance "internet"
CreateFAR 2  ApplyAction FORW  ForwardingParameters: DestinationInterface Access     (no Outer Header Creation yet)
CreateURR 1  MeasurementMethod VOLUM  ReportingTriggers PERIO|VOLTH  MeasurementPeriod 10 s
             VolumeThreshold ULVOL|DLVOL ul=1000 dl=1000   MeasurementInformation 0x11 = MBQE|MNOP
CreateURR 2  (same, MeasurementInformation 0x10 = MNOP)
CreateQER 1  GateStatus UL/DL OPEN  MBR ul=1000000 dl=1000000 kbps  QFI 1
CreateQER 2  GateStatus UL/DL OPEN  QFI 1
PDNType IPv4
```

What is **not** there: no SDF Filter (no PCC rules), no F-TEID CHOOSE (the SMF
allocates the TEID itself, `0x00000002`, and takes the N3 address from its
`interfaces.endpoints`, here `upfd`'s own `-n3-addr`), no Outer Header Creation in
the downlink FAR (the gNB is not known yet: it is plain `FORW` to Access, not
`BUFF`/`NOCP`, until the Modification), no BAR, no Traffic Endpoint.

With `URR_PERIOD=0 URR_THRESHOLD=0` the SMF creates no default URRs
(`[WARN][SMF][PduSess] No Create URR`): the request is 332 bytes, the same minus
the 2 CreateURR and the URRIDs (`runs/no-urr/n4.txt`).

With `SUBSCRIBER=subscriber-flows.json` (two PCC rules, `runs/shim-no-urr-flows/n4.txt`)
the request is 1276 bytes and carries **six PDRs** (default rule pair 1/2 at
precedence 255, rule `8.8.8.8/32 53-53` pair 3/4 at 127, rule `1.1.1.1/32` pair
5/6 at 128), six FARs, **four QERs** (QER 1 QFI 1 MBR 1000000 kbps, QER 2 QFI 1 no MBR, QER 3 QFI 2 MBR 100000, QER 4 QFI 3 MBR 208000) and
three URRs (one per rule: `ReportingTriggers VOLTH`, `MeasurementInformation 0x00`).
Every PDR, uplink and downlink, carries one SDF Filter, flag FD only (no BID, no
Filter ID), the same text for both directions:

```
PDR 1 (Access) SDFFilter fd="permit out ip from any to assigned"
PDR 2 (Core)   SDFFilter fd="permit out ip from any to assigned"
PDR 3 (Access) SDFFilter fd="permit out ip from 8.8.8.8/32 53 to assigned"
PDR 4 (Core)   SDFFilter fd="permit out ip from 8.8.8.8/32 53 to assigned"
PDR 5 (Access) SDFFilter fd="permit out ip from 1.1.1.1/32 to assigned"
PDR 6 (Core)   SDFFilter fd="permit out ip from 1.1.1.1/32 to assigned"
```

That is the "uplink SDF filters are not swapped for ACCESS PDRs" case seen
from the sender: the SMF writes every filter in the downlink orientation
(`from <server> to assigned`) and relies on the UP to read it per
Source Interface. A PDI holds exactly one SDF Filter here, so the
"several SDF Filter IEs per PDI" case does not occur with free5GC's PCF, and
no bidirectional (BID + Filter ID) filter was sent. Not reached by `upfd`: see below.

### Network Instance in the free5GC request

From the captured Session Establishment Requests `runs/stock-urr/n4.txt`
(stock config, 2 PDRs) and `runs/shim-no-urr-flows/n4.txt` (PCC rules, 6 PDRs).
Every Network Instance IE (type 22) is the same 8 bytes, `696e7465726e6574` =
`"internet"` (the DNN, no APN-style length prefix); the two captures agree
PDR for PDR.

| IE | Source / Destination Interface | Network Instance | where it sits |
|---|---|---|---|
| Create PDR 1 (stock), 1/3/5 (PCC) | Source Interface `00` ACCESS | `"internet"` | **inside the PDI**, directly after the F-TEID (`01000000020a4d5801`), before the UE IP Address |
| Create PDR 2 (stock), 2/4/6 (PCC) | Source Interface `01` CORE | `"internet"` | inside the PDI, no F-TEID |
| Create FAR 1 (stock), 1/3/5 (PCC), the uplink FAR | Destination Interface `01` CORE | `"internet"` | inside Forwarding Parameters |
| Create FAR 2 (stock), 2/4/6 (PCC), the downlink FAR | Destination Interface `00` ACCESS | **absent** | Forwarding Parameters is 5 bytes: Destination Interface only |

No Create PDR carries a Network Instance as its own child (outside the PDI); the
only place it appears next to the F-TEID is the ACCESS PDR's PDI, as above.
In the Session Modification Request the SMF sends later (`runs/shim-no-urr`),
Update FAR 2's Update Forwarding Parameters carries Destination Interface
ACCESS, Network Instance `"internet"` and the Outer Header Creation, and the
re-sent Update PDR 2's PDI carries `"internet"` again: the access-side FAR
gains a Network Instance only there.

### What `upfd` answers — three independent failures

**1. A URR naming Measurement Information is refused, even when it names nothing.**
Stock config (`runs/stock-urr`), and again with PCC rules whose URRs carry
`MeasurementInformation 0x00` (`runs/shim-no-urr-flows`):

```
upfd:  level=WARN msg="session: cannot read the establishment request" error="the rule cannot be expressed by a mask: the URR names Measurement Information, and this UP does not implement it"
```

`#8  10.77.88.1:8805 -> 10.77.88.10:8805  Session Establishment Response seq=1 seid=0x1`
`      Cause (19) 49 = Rule creation/modification Failure` — and nothing else (21 bytes:
header + Cause; no Offending IE, no Failed Rule ID).
free5GC sends Measurement Information on both default URRs (`0x11` MBQE|MNOP and
`0x10` MNOP) and, with PCC rules, on every per-rule URR as `0x00`. Both are
refused, so the IE's presence, not its value, is what is tested **[INFERRED from
the log text and the `0x00` case]**.

**2. The response carries no Node ID (mandatory, TS 29.244 7.5.3.1).** Quoted
from the SMF, stock config:

```
[WARN][SMF][PduSess] PFCP Session Establishment failed: PFCP Session Establishment Response from 10.77.88.1:8805 is missing mandatory IE(s)
```

The SMF (`internal/pfcp/session.go`) tests `response.NodeID == nil || response.Cause == nil`.
The 21-byte response above has no Node ID, so even the rejection is
unreadable to the SMF; it answers the UE with a 5GSM
`PDU Session Establishment Reject [NETWORK_FAILURE]` at once and the UE retries
every ~1 s (`UE: Sending PDU Session Establishment Request` ... `Reject received [NETWORK_FAILURE]`).
With the Node ID repaired (`runs/shim-stock-urr`) the SMF logs the cause:
`PFCP Session Establishment failed: PFCP Session Establishment rejected with Cause 73`.

**3. An accepted response has an UP F-SEID with no address.** With URRs avoided
(`runs/no-urr`, unmodified `upfd`) `upfd` accepts and programs the session
(`level=INFO msg="session: established" cp_seid=1 seid=1 ue_ip=10.60.0.1 pdrs=2 changes=7`)
but answers (57 bytes):

```
Session Establishment Response seq=1 seid=0x1
    Cause (19)   01 = Request accepted
    FSEID (57)   000000000000000001 = flags - seid=0x1          <- neither V4 nor V6 bit, no address
    CreatedPDR (8): PDRID 1, FTEID flags V4 teid=0x00000002 v4=10.77.88.1
```

and no Node ID. The SMF rejects it on failure 2 before it could use the F-SEID;
**[INFERRED]** the empty address would be its next failure (`accepted PFCP Session
Establishment Response ... missing UP F-SEID` / address use, `session.go`).
`upfd` echoes the SMF-chosen F-TEID back in Created PDR (the SMF sent no CHOOSE).

The SMF then releases its side at once (`Release IP[10.60.0.1]`, `smContext ... is
deleted from pool`), sends no Session Deletion (it never learnt the UP SEID),
and does not retry the PFCP request; the UE does, and every retry is a fresh
establishment (new SEID, `seid=0x2`, `0x3`, ... and a fresh UE IP 10.60.0.2, .3).
On `upfd` those accepted-but-unreadable sessions stay programmed
(`session: established` for cp_seid 1, 2, 3 in `runs/no-urr/upfd.log`; no Deletion
arrives) **[measured: no deletion in the capture]**.

### The diagnostic shim: how far it goes once 2 and 3 are repaired

`SHIM=1` starts `ci/interop/n4shim` on `10.77.88.1:8805` and moves `upfd` to a
loopback port. It relays UDP both ways and changes one thing: it adds the Node
ID `10.77.88.1` to a Session Establishment Response that lacks it, and gives an
address-less UP F-SEID the address `10.77.88.1`. It logs each patch
(`n4shim: Session Establishment Response seq=1: [added Node ID 10.77.88.1 gave the UP F-SEID (seid 0x1) the address 10.77.88.1]`)
and `n4-upfd.pcap` keeps what `upfd` really said. **Everything below this line
(`shim-*` runs) is not an unmodified `upfd`'s behaviour.** The URR cause (failure 1)
is not shimmed: it needs `URR_PERIOD=0 URR_THRESHOLD=0`.

Shimmed + no URRs (`runs/shim-no-urr`): the session establishes.

```
[INFO][SMF][PduSess] Received PFCP Session Establishment Accepted Response
[INFO][SMF][PduSess] Received PFCP Session Modification Accepted Response from AN UPF
[nas] [info] PDU Session establishment is successful PSI[1]
[app] [info] Connection setup for PDU session[1] is successful, TUN interface[uesimtun0, 10.60.0.1] is up.
```

The SMF's next message, 47 ms after the Establishment Request (the UE's `PDU
Session Establishment Accept` is logged 2 ms before it), is a **Session
Modification Request**, `seid=0x1`, 157 bytes:

```
FSEID  flags V4 seid=0x1 v4=10.77.88.10
UpdatePDR 2 (the downlink PDR, sent whole again): Precedence 255; PDI SourceInterface Core,
          NetworkInstance "internet", UEIPAddress V4|SD 10.60.0.1; FARID 2; QERID 2, QERID 1
UpdateFAR 2  ApplyAction FORW
  UpdateForwardingParameters: DestinationInterface Access, NetworkInstance "internet",
     OuterHeaderCreation desc GTP-U/UDP/IPv4 teid=0x00000001 v4=10.77.88.138      (the gNB)
```

`upfd` logs `session: modified seid=1 pdrs=2 changes=8` and answers `Cause 01`
**plus a `CreatedPDR` (PDR 1, the uplink F-TEID again)**: a Created PDR in a
Modification Response, which the Modification never asked for (no CHOOSE). The
SMF accepted it. Nothing in the SMF's request was refused.

## Stage (c): PDU session release — REACHED, shimmed only

`ci/interop/ue.sh release` (`nr-cli imsi-208930000000001 -e "ps-release 1"`):

```
#13 10.77.88.10:8805 -> 10.77.88.1:8805  Session Deletion Request  seq=3 seid=0x1     (16 bytes: header only, no IEs)
#14 10.77.88.1:8805  -> 10.77.88.10:8805 Session Deletion Response seq=3 seid=0x1
      Cause (19) 01 = Request accepted                                                (21 bytes: no Usage Report)
upfd:  level=INFO msg="session: deleted" seid=1
SMF:   [INFO][SMF][PduSess] Sending PFCP Session Deletion Request
       [INFO][SMF][PduSess] Received PFCP Session Deletion Accepted Response
       [INFO][SMF][Charging] build MultiUnitUsageFromUsageReport
       [INFO][SMF][Charging] Send Charging Data Request[Termination] successfully
UE:    [nas] [debug] PDU Session Release Command received
```

The response carries no Usage Report (known); free5GC's Termination charging
request is built from usage reports, so it has none to send (that run had no
URRs). The SMF then sees the N2 resource release answer in the wrong state
(`[WARN] ... Unexpected state, expect: [InActive], actual:[InActivePending]`,
a free5GC/UERANSIM matter, not N4). UERANSIM re-requests a session 141 ms
after the release (its config asks for one session, so it re-establishes),
which the SMF answers as a duplicate (`Cause_REL_DUE_TO_DUPLICATE_SESSION_ID`);
no PFCP follows it in that run.

## Findings for `upfd`, in order of what blocks first

Status after the re-run above: findings 1, 2 and 3 are **fixed** (`ccf667c`,
confirmed by the run); finding 4 is **fixed** in `4f40f59` (test-proven, not
re-run against the SMF); 5 is a sender fact, not a defect.

1. **The Session Establishment Response carries no Node ID** (mandatory,
   7.5.3.1), accepted or rejected; fatal for free5GC's SMF ("is missing
   mandatory IE(s)"). The Association Setup Response has one. *Blocks every session.*
2. **Any `Measurement Information` IE in a URR is refused**, value 0 included,
   with Cause 73 and no Offending IE / Failed Rule ID. free5GC's default
   config sends it on both default URRs (`urrPeriod: 10`, `urrThreshold: 1000`)
   and on every per-rule URR. *Blocks every session of the stock SMF config.*
3. **Accepted Establishment Response has an UP F-SEID with flags 0** (no V4/V6
   address). Mandatory to carry the UP's address (8.2.37).
4. **A Created PDR rides on a Session Modification Response** that asked for no
   F-TEID allocation.
5. Known and now seen on the wire from the sender's side: free5GC writes every
   SDF filter in downlink orientation in both directions (section above); it
   never sends BID/Filter-ID or several SDF Filters in one PDI.

What the SMF sends that `upfd`'s own logs never mention (**[INFERRED]** from an
accepted run's log: one `session: established … pdrs=2 changes=7` line, no
per-IE message): the QER MBR/QFI/Gate Status, PDN Type, Precedence, Network
Instance on the PDI and FAR, the CP F-SEID's address, the CP Function
Features, the Recovery Time Stamp value after association. Whether any of
those is programmed is not visible in the log; the only notice `upfd` gives of
an IE it does not support is the URR refusal.

Open: Open5GS (no official image), free5GC's own UPF (not relevant), a second
UE/session, N9, the SMF-initiated release/modify paths (T3591/T3592 timers),
and finding 20's narrow residue (a report already in flight when the deletion
arrives can be counted twice -- 5 packets, once, on `runs/dp-fix`).
`ci/interop/run.sh` is the regression entry point: it ends with
`stage reached: c` and `upfd` and `bessd` shutting down cleanly.

## The dataplane arm (`DATAPLANE=1`): real packets through `bessd`

Everything above is N4 only: the gNB and UE run, but no packet reaches the
graph, so every volume is zero. With `DATAPLANE=1` the same environment carries
the UE's own traffic, and nothing about the N4 side changes.

```
gNB container 10.77.88.20 (MAC fixed)  --docker bridge-->  veth upfi-n3b | upfi-n3  = bessd's N3 port (10.77.88.2)
bessd, upfd on the host                bessd's N6 port upfi-n6  <--veth-->  eth0 of netns upf-interop-dn (10.99.0.1)
```

| piece | who makes it | why |
|---|---|---|
| the two veths, the data network's namespace, the bridge port | `ci/interop/net.sh` (fixed names, MACs, addresses; removed by `down.sh`) | the gNB's GTP-U must reach a port bessd owns, and the UPF's N3 address must be answered by nobody's kernel |
| the graph | `ci/interop/graph.py`, from `deploy/upf.yaml` (or `deploy/custom-pdrmatch.yaml` with `PROFILE=custom`) | the deployed graph with this rig's ports, addresses and MACs |
| the gNB's fixed address and MAC, and a permanent neighbour for the N3 address | `ci/interop/ue.sh` | `upfd -peer-mac` is one next hop: the downlink's outer Ethernet header names the gNB |
| the UE's route to the data network, then the echo | `ci/interop/ue.sh traffic` | UERANSIM installs the session's prefix on the tunnel and nothing else, so without it the echo leaves by the container's default route |
| `-urr-interval 1s` | `ci/interop/up.sh` | without it no URR is ever read: no periodic or threshold report reaches the SMF, and even the termination reports are zero (the first reading of a URR is its baseline) |

Measured (`runs/dp4`, `runs/dp5`, generic; `runs/dp-custom`, custom):

| what | result |
|---|---|
| the echo | 20 packets, **0% loss**, each way: `cnt_ul +20`, `cnt_dl +20` packets (the graph's own counting modules) |
| the URRs at a real SMF | PERIO reports before the traffic, then VOLTH reports with real volume: 2052 octets / 9 packets each way, accepted (`Session Report Response`, cause 1) |
| the whole traffic accounted | both URRs' windows plus the deletion's termination report sum to 20 packets / 4560 octets each way, exactly what crossed (`runs/dp-fix`; before the fix `runs/dp5` delivered 20 for URR 1 and 11 for URR 2 -- finding 20) |
| a report the session's end overtook | the queued report is cancelled, not sent (`upf_usage_reports_total{outcome="cancelled"}`), and its usage goes in the termination report instead |

Two gaps this arm exposed; the first is closed:

1. **The deployed graph cannot put a destination MAC on an N6 egress frame --
   closed.** The decap leaves the inner packet behind the *outer* frame's
   addresses (`docs/design.md`, "Framing"), and the fork's `Router` used to
   pick the gate from a resolved next hop without writing its addresses;
   **BESS D-153** landed (`route::RewriteL2`: a resolved hop's
   `dst_mac`/`src_mac` go into the frame the Router forwards), and
   `deploy/upf.yaml`'s hop 1 now carries the data network's pair. The rig's
   `GenericDecap`+`GenericEncap` gap-filler is deleted from `ci/interop/graph.py`;
   what the renderer still does is translate the graph's addresses to this rig's
   veths -- the hop's MACs, and the N6 interface's own (the `vif_n6`
   `deploy/upf.yaml` now has, which matches the rig's data network and answers
   for its gateway address; the rig's permanent neighbour means no ARP is
   exchanged). The deployed behaviour has a lane of its own: `ci/session-path.sh`
   byte-checks the addresses in the frame that left `dump_n6`.
2. **Finding 20** (above): the URR windows, not the packets.

## Reproduce

```
cd datapath && ninja -C build                    # the plugin, once
ci/interop/run.sh                                # stage a/b/c with the stock SMF
LABEL=flows SUBSCRIBER=subscriber-flows.json URR_PERIOD=0 URR_THRESHOLD=0 ci/interop/run.sh
build/run/interop/runs/<label>/n4.summary        # one line per PFCP message; n4.txt: full IE tree
```

Evidence of the runs quoted here is in `build/run/interop/runs/`:
`fixes-ccf667c` (the current result), `stock-urr`, `no-urr`, `fqdn-node-id`,
`shim-no-urr`, `shim-stock-urr`, `shim-no-urr-flows` (gitignored, regenerated
by `run.sh`).
