# Compliance and performance target: the field, and what we must beat

Status: research note, 2026-10-16. Reproduce with the commands in [Method](#method).
Purpose: name the most compliant open-source UPF with evidence, take its feature set
as the target, and keep our own feature list Pareto (no ATSSS/TSCU/LI theatre).

## Method

Three kinds of evidence, in this order:

1. **Code evidence** — the UP Function Features the project actually sets in its PFCP
   Association Setup Response, and the code paths that implement each rule type.
   A project's README is a claim; the association response and the datapath functions
   are facts. Where a README claim is contradicted by the code, the code wins.
2. **Third-party measurement** — s5uishida's TRex + Simple PFCP Client runs
   (2026.10 series) are the only same-harness, same-version comparison of open-source
   UPFs found. They are 2-vCPU Proxmox VMs over VirtIO, so the absolute numbers are
   VM-bound; the spread between designs (~1.4 to ~9.4 Gbps) is the signal.
3. **Project health** — last push date and star/issue count from the GitHub API.

Candidates were cloned shallow (no submodules, no vendored trees) and grepped for
`FTUP/UEIP/BUNDL/MPAS/SSET/UDBC/EMPU` (declared features) and
`URR/BAR/QER/MBR/MAR/DLDR/DDN` (implemented rule types).

## The field

| Project | Datapath | Last push | Features (code-verified) | Not implemented |
|---|---|---|---|---|
| **OAI-CN5G-UPF** v2.2.1 | eBPF/XDP (+ "Simple Switch") | 2026-10-15 | PDR/FAR, QER (TC-BPF), **URR**, **BAR buffering + DDN**, **MAR**, DLDR, IPv4 + Ethernet PDU sessions; one XDP kernel per stage (`xdp_{pdr_match,session_lookup_ip,qer_apply,urr_apply,bar_apply,mar_apply,far_apply}_kern.c`, 3.5 kloc); `upf_n4.cpp:202+` sets `ftup=1`; startup banner prints the enabled feature set | young project (5 stars), interop maturity unproven |
| **open5gs** v2.8.0 | userspace TUN/TAP | 2026-10-15 | PDR/FAR, QER, URR **with real accounting** (`upf_sess_urr_acc_add` starts measurement on first packet and arms timers, `src/upf/context.c:781+`), BAR (`ogs_pfcp_handle_create_bar/remove_bar`, `src/upf/n4-handler.c:172,472`), end marker, DDN; declares FTUP + EMPU + MNOP + **VTIME** + FRRT (`src/upf/context.c:44-49`) | no MAR, no Ethernet PDU sessions; slowest datapath |
| **free5GC go-upf** v1.3.0 | gtp5g kernel module | 2026-09-30 | PDR/FAR, QER (via gtp5g), URR volume+time thresholds pushed into the module (`newVolumeThreshold`, `internal/forwarder/gtp5g.go:481`), BAR validation, DLDR report types (`internal/report/report.go:15`) | no QER/BAR *semantics* in userspace — delegates to the kernel module |
| **UPG-VPP** v1.13.0 | VPP/DPDK | 2026-04-28 | deepest URR (quota holding time, quota validity time, linked usage reports; `upf-plugin/upf/pfcp/upf_session.c:640-680`), MAR message support, IPv4/IPv6 inner+outer | README: **BAR and QER "not yet working"**; QER MBR/gate drop reasons exist in code but are not wired as a working feature |
| **eUPF** v0.7.1 | eBPF/XDP | 2026-10-13 | FAR + QER, **one each per PDR** (README), URR in the datapath (`cmd/ebpf/xdp/urr.h`, 2 URR/session) | URR not wired to the session handler (parse block commented out, `cmd/core/pfcp_session_handlers.go:656`), no BAR, no MAR |
| **OMEC** (what we replace) | BESS | 2026-10-15 | PDR/FAR, QER (app + session), SDF filters, end marker, DDN **notification only**, UE IP assignment, ULCL/N9, DSCP copy, GTP-U path monitoring, NAT, frag/reassembly | **no URR anywhere in pfcpiface** (case-insensitive grep: zero rule paths), no buffering, no MAR/DLDR |
| **5GOpenUPF** v0.1 | DPDK | **2021-05-21** | broadest *declared* set (19 UP features Y incl. QUOAC/UDBC/DPDRA/SSET/UEIP) and PFCP parsing for URR/BAR/QER/MAR/DLDR | dead since the single v0.1 commit; a claim, not a reference |

### Measured performance (s5uishida, TRex, 2-vCPU VMs, ~1 Mpps offered)

| UPF | UpLink Rx | DownLink Rx |
|---|---|---|
| open5gs (TAP) | 1.39 Gbps / 120 Kpps | 1.49 Gbps / 126 Kpps |
| free5GC go-upf (gtp5g) | 4.93 Gbps / 426 Kpps | 4.34 Gbps / 365 Kpps |
| OAI-CN5G (Simple Switch) | 2.21 Gbps / 191 Kpps | 3.55 Gbps / 298 Kpps |
| UPG-VPP (DPDK) | 8.51 Gbps / 735 Kpps | 9.04 Gbps / 762 Kpps |
| **eUPF (XDP)** | 9.12 Gbps / 788 Kpps | 9.38 Gbps / 787 Kpps |
| **OAI-CN5G (XDP)** | 9.13 Gbps / 789 Kpps | 9.24 Gbps / 775 Kpps |

XDP and VPP saturate this test's generator; the userspace TUN/TAP designs are 5-7x
behind. These numbers are VM-bound and are a *shape*, not a ceiling.

## Verdict

* **Broadest feature set: OAI-CN5G-UPF.** It is the only candidate with URR, BAR
  buffering, QER, MAR and Ethernet PDU sessions in the datapath at once, and it
  splits the pipeline into one XDP stage per rule type. Caveat: young, small, no
  independent interop record.
* **Most compliant *and proven*: open5gs UPF.** URR with honest accounting and
  timers, BAR, QER, DDN, in a 2.7k-star project that runs in production labs.
* **Nobody has everything.** upg-vpp's URR semantics are the deepest but it has no
  QER/BAR; eUPF is fast but its URR is unwired; OMEC has no URR at all.
* Therefore: the target is not "copy one project". The target is the spec's Pareto set
  implemented as fused MVPs (see *Target feature set* above), with a per-packet budget
  that beats the field's throughput -- the list below is *input* evidence, not the goal.
* **The order is part of the claim.** 1) the classifier result model `{gate, ActionId}`
  and the pre-resolved action record; 2) `ExactMatch`/`WildcardMatch` returning that
  record on per-worker tables (the 400G scale rule); 3) the URR counters folded into the
  same record (the differentiator, and the cheapest one to get right); 4) the FAR/QER
  patches on the same record; 5) N4 session lifecycle on top. The PFCP side (1 and 5's
  control plane) has no datapath dependency and proceeds in parallel; the data path
  order above is what the throughput claim rests on.
* **The five-minute test of the central claim.** Run the `live_perf` GTP-U
  decap-and-forward chain twice on an isolated core: once bare, once with a URR and a
  QER provisioned. The two numbers must agree to within the action-record cost printed
  by the same run. If they diverge, the dual objective has failed and no feature count
  saves the claim -- so this is the first thing to run before any feature is called
  done.

## Target feature set (spec Pareto, not field parity)

Three jobs, scored separately. What the field happens to have is an input, never the
target:

1. **Implement the spec.** A standard exists, so the MVP per feature is unambiguous;
   only feature interaction and lifecycle are not (see the coverage table above).
2. **Beat the field where it is broken.** A correct MVP already beats both leaders on
   URR and BAR (their URR is unwired or absent, their BAR buffers nothing), so this
   class is won by implementing the spec, not by catching up with the field.
3. **Sequence by frequency x weight.** A small set of features covers most
   deployments; that dense set is MUST. What remains is **whitespace**: features the
   field does not have at all (URR, downlink buffering, IPv6, Ethernet PDU sessions).
   Leadership there is cheap -- but only with a bar per feature that can be run,
   otherwise it is a claim without evidence.

**Dual objective.** Feature coverage *and* no throughput loss from what is provisioned
but not in use: the base path must not move when a QER, URR or BAR is added. The field
dies exactly there (OMEC's graph walks pdrLookup -> appQER -> sessionQER -> farLookup
per packet, and its classifier returns a gate rather than an action). The throughput
floor is the field's throughput with the field's bugs; the per-packet budget below is
what buys the headroom above it.

**Scale target: a path to 400G.** 400G in one direction at an average frame of 350 B is
~140 Mpps (both directions double it), which at the budget below (<= 120 cycles/packet,
~25 Mpps/core at 3 GHz) is ~6 data-plane cores. Reaching it must not require shared
state: multi-queue RSS with one worker per queue, per-worker tables, no locks, no
allocations and no control-plane work in the packet path, batched bursts, and the
per-worker cost measured in cycles rather than argued -- datapath MUST item 9 below is
that requirement, stated as a build rule.

MUST — PFCP (TS 29.244) and N4 procedures:
1. Association Setup/Update/Release, heartbeat, restart detection via Recovery Time
   Stamp; honest UP Function Features (declare only what is implemented: FTUP, UEIP,
   EMPU, MNOP, VTIME at minimum — `QUOAC`, `UDBC`, `DPDRA`, `SSET` only once true).
2. Session Establishment/Modification/Deletion, one transaction per change, and the
   UP-initiated report path (Session Report Request): usage report (USAR) and
   downlink data report (DLDR).
3. PDR: precedence, PDI (source interface, F-TEID, UE IP, SDF filter, Network
   Instance, QFI), rule correlation (FAR-ID, QER-IDs, URR-IDs).
4. FAR: apply action FORW / DROP / BUFF, forwarding parameters (destination
   interface, network instance, outer header creation GTP-U/UDP/IPv4, TEID),
   PFCPSMReqFlags (SNDEM -> end marker; DROBU -> drop buffered).
5. QER: MBR/GBR (UL/DL), gate closed/open, QFI, per-session and per-flow.
6. URR: volume + time, UL/DL/total, thresholds, quota, reporting triggers
   (periodic, threshold, quota exhausted, session termination), linked URR.
   *This is the feature OMEC lacks and both current leaders have.*
7. BAR: downlink buffering, DDN delay, DL buffering duration, suggested packet
   count. *OMEC's explicit gap ("notification only, no buffering"); open5gs has it.*

MUST — datapath:
8. GTP-U v1 decap/encap (G-PDU + echo + end marker), IPv4 inner/outer, DSCP copy
   inner -> outer, UE IP NAT, per-flow counters, ULCL/Branching on N9.
9. Multi-queue RSS, per-worker tables, RCU rule updates, no locks or allocations in
   the packet path.

Differentiators already inside the MUST lists, each with a bar and an arm -- "done" means
the bar passes, not that the clause is wired:

| feature | bar for "done" | arm |
|---|---|---|
| URR | volume and time per UR-SEQN; thresholds, quota and termination reported so a controller accepts the report | live URR test; `live_perf` cost delta with URR provisioned |
| BAR / DL buffering | buffer DL packets on downlink data notification, deliver on DDN, drop when the duration expires | live buffering test; burst arm |
| IPv6 | PFCP UE IP and inner/outer IPv6 for UL/DL and N9, inside the same per-packet budget | dual-stack conformance graph; budget arm |

Phased, each an MVP when its phase opens (own phase; the release plan carries the
schedule): Ethernet PDU sessions, TSCU/URLLC, lawful intercept (needs a third-party
LI gateway), MAR/ATSSS-LL.

Excluded (documented, not silently dropped): advanced DDDS reporting,
PFDM/HEEU/TREU/framed routing, NAT beyond IPv4. Promotion rule for the last two lists:
an item re-enters the roadmap only with a deployment that needs it or a spec release
that makes it mandatory -- and then it enters as an MVP with a bar, like everything
above. Nothing leaves this section silently; a feature either has a bar or it is on one
of these lists.

## Per-packet budget (the "minimal instructions" rule)

The field's costs come from repeated lookups: OMEC's BESS graph walks
pdrLookup -> appQER -> sessionQER -> farLookup, and its classifier returns a gate, not
an action. Our path pre-resolves all of that at rule-install time:

```
ingress Eth+IPv4+UDP+GTP-U parse  (~10-15 cyc, fixed offsets, no branches on well-formed)
        |
   TEID -> ExactMatch (one hash lookup, 16-byte key)  (~10-15 cyc)
        |
   ActionId -> action record (pre-compiled at install time)
        |-- QER: token-bucket check                  (~5-10 cyc)
        |-- URR: two counter adds (bytes, packets)   (~5 cyc)
        |-- FAR: outer-header template patch
        |        (TEID, inner DSCP, IP tot_len, UDP len - no checksum recompute)
        |                                            (~10-20 cyc)
        |
   egress route lookup (LPM) or N9 tunnel            (~15-25 cyc)
```

Design target: **<= 120 cycles/packet for the UL decap-and-forward path** (about
25 Mpps/core at 3 GHz), with the DROP path far below that. The number is a budget to
hold the design honest, not a promise; it is measured, not argued
(`tests/perf/live_perf.cc` graph tests + TRex GTP-U 1-pkt end to end).

This is why the PDR classifier must return `{gate, ActionId}` — the ActionId *is* the
pre-resolved QER+URR+FAR record — and why the classifier-result work item
(`Classifier result model {gate, ActionId}`) is on the critical path for this UPF.

## Verification plan (what makes the claim real)

1. Packet path: a `live_perf` UPF graph test (parse -> TEID exact-match -> action ->
   encap) reporting cycles/packet, comparable to the existing `F.hop` numbers.
2. End to end: TRex GTP-U profiles + PacketRusher against bessd on this host, same
   profiles as the field's test; and eUPF run on the *same host* as the A/B peer, so
   the comparison is a same-hardware ratio rather than two VM snapshots.
3. Compliance: interop against open5gs SMF and free5GC SMF (session est/mod/del,
   URR threshold report, DDN + BAR buffering, end marker), plus the refusal Causes
   the SMF actually sees.
4. Spec receipts: every implemented feature carries its TS 29.244 clause next to the
   test that exercises it, in this repository's documentation.

## Reproducing the survey

```bash
for r in omec-project/upf free5gc/go-upf edgecomllc/eupf travelping/upg-vpp \
         5GOpenUPF/openupf open5gs/open5gs openairinterface/oai-cn5g-upf; do
  git clone --depth 1 --no-tags --quiet "https://github.com/$r" "/tmp/upfcmp/${r##*/}"
done
grep -rn -E "FTUP|UEIP|UDBC|EMPU" /tmp/upfcmp/*/ --include=*.c --include=*.go | grep -v _test | head
grep -rni "\bURR\b" /tmp/upfcmp/*/ --include=*.go --include=*.c | head
```

## The score

This file is the survey. The score it supports -- one percentage per compliance
block, per project, with the sub-features and the evidence behind each -- is
[`scorecard.md`](scorecard.md).


