# Scorecard: our compliance blocks against the field

Status: 2026-10-18. Purpose: one number per compliance block, for us and for the
open-source UPFs this project measures itself against, so the roadmap's order can
be argued from a score rather than from impressions.

**Evidence.** [`compliance-landscape.md`](compliance-landscape.md) is the survey:
per project, the features its code sets and the code path that implements each.
[`compliance.md`](compliance.md) is our own row-by-row state, each row carrying
its TS 29.244 clause and the test that exercises it. This file scores those two
and introduces no claims of its own.

---

## How to read the numbers

| rule | why |
|---|---|
| A block's percentage is the sub-features of that block a project shows, over the sub-features the block scores. They are listed under [The blocks, audited](#the-blocks-audited). | a percentage is only worth reading if you can see what it counts |
| **We are credited only where a test exists** — not where a clause is read, not where the code "supports" it. | this repository's own rule: a feature without a bar is a claim |
| **Competitors are credited only where the survey found code**, so every competitor number is a **lower bound**. Silence counts as absent for scoring. | an unexamined feature is not a missing feature; the audit table says where this bites |
| No sub-feature is counted in two blocks, and **nothing a project only documents is scored at all** (see [Not scored](#not-scored)). | a score that rewards writing things down measures the writing |
| `—` in a cell: the survey did not examine that block per project; the block is left out of the means. | no number is better than a wrong one |
| A mean is the arithmetic mean of the cells above it, rounded, over the blocks every project scores. | the number has to divide its own row, or it is decoration |

## Not scored

| left out | why |
|---|---|
| one atomic transaction per change, idempotent retries, refusal with a Cause | ours, and tested, but the survey does not examine any other project's atomicity: scoring it would score the survey's silence, not the field |
| a clause number and a test per feature; published per-packet numbers | this repository's documentation habit. It is why the numbers in this file can be checked; it is not a capability |
| declared UP Function Features (association response bits) | a declaration is a claim until a code path implements it, which is the survey's own starting rule |

---

## The score

| # | block (sub-features scored) | us | OAI-CN5G | open5gs | free5GC | UPG-VPP | eUPF | OMEC |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| 1 | association, heartbeat, restart detection (3) | 100 | 100 | 100 | 100 | 100 | 100 | 100 |
| 2 | session establishment, modification, deletion (3) | 100 | 100 | 100 | 100 | 100 | 100 | 100 |
| 3 | Session Report Request: USAR, DLDR (2) | **100** | 100 | 100 | 100 | 50 | 0 | 0 |
| 4 | PDI sub-features: precedence, F-TEID + CHID, UE IP, SDF + ranges, NI + QFI (5) | **80** | — | — | — | — | — | — |
| 5 | QER: gate, MBR, per-flow or GBR (3) | **100** | 67 | 67 | 33 | 0 | 67 | 67 |
| 6 | URR: volume, time, thresholds, quota + enforcement, linked (5) | **80** | 60 | 60 | 60 | 100 | 0 | 0 |
| 7 | BAR + DDN: buffering, DDN, duration, drop-buffered (4) | **75** | 75 | 75 | 25 | 0 | 0 | 25 |
| 8 | GTP-U: decap, encap, echo, end marker, DSCP copy (5) | **100** | 40 | 80 | 40 | 40 | 40 | 80 |
| 9 | IPv6: PFCP UE IP, inner + outer, N9 (3) | **0** | 0 | 0 | 0 | 33 | 0 | 0 |
| 10 | MAR / ATSSS-LL (2) | **0** | 50 | 0 | 0 | 50 | 0 | 0 |
| 11 | ULCL / N9 route domains (2) | **50** | 0 | 0 | 0 | 0 | 0 | 50 |
| 12 | real-SMF interop (1) | **0** | 0 | **100** | 0 | 0 | 0 | 0 |
| | **mean of the eleven blocks every project scores (1-3, 5-12)** | **64** | **54** | **62** | **42** | **43** | **28** | **38** |

Block 4 is left out of every mean because no competitor cell exists for it (`—`),
so no project is credited or debited for it. **Corrected 2026-10-18:** block 3's
competitor cells had been written one place over — OAI-CN5G held free5GC's 50,
free5GC held UPG-VPP's 100, eUPF held OAI's 50 — which contradicted the block's
own Field text ("OAI…, open5gs…, free5GC… send both; UPG-VPP sends usage reports,
DLDR not evidenced; eUPF's URR is unwired, OMEC has none") and made the means
look as if they had stopped following their cells. They had not: with the cells
as the Field text gives them, every mean below divides its own row again, and
the four that appeared to have drifted (OAI-CN5G 54, free5GC 42, UPG-VPP 43,
eUPF 28) come back unchanged. Each cell in this table was then checked against
its block's Field text or the survey; block 3 was the only one out of step.

## What each number is made of

| project | its mean rests on | weakest blocks |
|---|---|---|
| **us** | URR wired end to end, both GTP-U path messages, the report path in both halves and now live, and the PDI sub-features no one else is scored on; nothing in the box an idle UE sits in | 9, 10, 12 (0) |
| **open5gs** | the roundest project in the field: reports, buffering, markers, and production interop — four blocks at 75-100 | 9, 10, 11 (0) |
| **OAI-CN5G** | feature breadth in one XDP pipeline: BAR 75, MAR 50, URR 60 | 9, 11, 12 (0) |
| **free5GC** | delegating to the `gtp5g` kernel module: fast, but semantics it does not own | 5 (33), 7 (25), 9/10/11/12 (0) |
| **UPG-VPP** | the deepest URR in the field (100) and nothing in the box below it: no working QER or BAR | 5, 7, 11, 12 (0) |
| **eUPF** | speed; its URR is in the datapath but not wired to the session handler | 5, 6, 7, 9, 10, 11, 12 (0) |
| **OMEC** | the UPF this project replaces: QER, DDN notification, ULCL/N9, DSCP copy — and no URR at all | 3, 6, 9, 10, 12 (0) |

---

## The blocks, audited

One section per block: what it scores, where our credit comes from, and what the
survey found for everyone else. Competitor citations are the survey's (file and
symbol, in [`compliance-landscape.md`](compliance-landscape.md)); ours are test
names in [`compliance.md`](compliance.md).

### 1. Association — us 100

**Sub-features.** association setup/update/release; heartbeat; restart detection
by Recovery Time Stamp.

**Ours.** `internal/n4`: `TestAssociationAndHeartbeat`,
`TestCPRestartVoidsAssociation`, `TestSecondCPFunctionIsRejected`.

**Field.** every project must interoperate with an SMF to be used at all; the
survey found no absence.

### 2. Session lifecycle — us 100

**Sub-features.** establishment; modification; deletion.

**Ours.** `ci/session-live.sh`; `TestEstablishCompilesTheSessionIntoOneTransaction`.

**Field.** in every project.

### 3. Session Report Request — us 100

**Sub-features.** USAR (a report sent when a URR says so); DLDR (one sent when
downlink data arrives with no tunnel).

**Ours.** `TestAReportIsAUsageReportTheSMFCanRead`,
`TestTheDownlinkReportIsOwedOncePerBufferingEpisode`.

**Live.** both halves are proven against a daemon. USAR:
`internal/n4/live_report_test.go`, run by `ci/session-report.sh`, reports URR 7,
VOLQU, 6071040 packets and 224628480 octets, and the SMF acknowledges it. DLDR:
`internal/n4/live_ddn_test.go`, run by `ci/buffer-path.sh`, whose checks pass
(`ok: the report named the buffering PDR`, `ok: the store released the flow on
the SMF's instruction`).

**Field.** OAI (`xdp_urr_apply_kern.c` and its DLDR path), open5gs
(`upf_sess_urr_acc_add`, DDN), free5GC (`report.go` types) send both; UPG-VPP
sends usage reports, DLDR not evidenced; eUPF's URR is unwired, OMEC has none, so
neither can report.

### 4. PDI sub-features — us 80

**Sub-features.** precedence; F-TEID with CH/CHID (FTUP); UE IP; SDF filter incl.
port ranges; Network Instance and QFI.

**Ours.** `TestUplinkPDIsWithOneCHOOSEIDShareOneFTEID`,
`TestThePrecedenceIsInvertedIntoTheClassifiersPriority`,
`TestAPDINamingAQFIKeysTheRuleOnIt`, `TestAQERsQFIReachesTheTunnelRecord`,
`TestPortRangeIsRefusedNotMatchedTooWidely`, `TestANonIPv4PDIIsRefusedNotWidened`,
`ci/smoke-gtpu.sh` (a G-PDU carrying a PDU Session Container, decap reading QFI 5
into metadata).

**Field.** not examined per project: the survey scores rule types
(PDR/FAR/QER/URR/BAR), not PDI sub-features. Only OAI's `ftup=1` is on record,
and it is not enough to score the block.

### 5. QER — us 100

**Sub-features.** gate; MBR; per-flow or GBR semantics.

**Ours.** `TestAClosedGateDropsWithoutAnAction`; `TestAQERsQFIReachesTheTunnelRecord`
(a QER's QFI reaching the flow's tunnel record); `TestTwoQFIKeyedPDRsGetTheirOwnMeters`
(two PDRs of one session differing only by QFI, each naming its own QER,
compiling to two actions and two meter ids — the flows are policed apart);
`ci/smoke-gtpu.sh` (the encap writing the container from the record's QFI);
`ci/session-path.sh`.

**Field.** OAI TC-BPF, open5gs `appQER`/`sessionQER`, eUPF one QER per PDR, OMEC
app + session QER; free5GC has no QER semantics in userspace (33); UPG-VPP's
README says QER is "not yet working" (0).

### 6. URR — us 80

**Sub-features.** volume; time; thresholds; quota and its enforcement; linked
UR-SEQN.

**Ours.** `TestEvaluateReportsAUsedUpQuotaAndStopsTheTraffic`,
`TestEvaluateReportsTheWindowItMeasured`.

**Field.** UPG-VPP `upf_session.c:640-680` (100); OAI, open5gs and free5GC
measure volume and time with thresholds but the survey shows no quota-enforcement
or linked half; eUPF unwired; OMEC none.

### 7. BAR + DDN — us 75

**Sub-features.** downlink buffering; DDN; buffering duration; drop-buffered.

**Ours.** `TestABuffFARIsGatedToTheStoreAndCounted`,
`TestTheDownlinkReportIsOwedOncePerBufferingEpisode`,
`TestAModificationThatStopsBufferingReleasesTheFlow`, and the live arm
`ci/buffer-path.sh`, which passes end to end against the 3f3716df stage:
`ok: the controller reported the buffered downlink`, `ok: the report named the
buffering PDR`, `ok: the store released the flow on the SMF's instruction`, and
`buffer-path: ok (a BUFF FAR's packets were held, reported to the SMF over N4,
and released when the SMF moved the path)`, with `held: 1536 packets counted on
the branch; forwarded after the instruction: 0 -> 11136`.

**Why 75 and not 100.** The arm proves buffering, DDN and the release. The DL
Buffering Duration is read and unit-tested — `compile.go` parses it with the
stopped-timer (all-zero) and infinite cases, `buffer_test.go` pins all three —
but its expiry is not what the arm measures, and `TestABuffOnlyFARIsADrop` is the
drop-buffered half.

**History.** The arm's first run against a daemon carrying both contracts failed
at its own first test: the daemon refused the session transaction, `#3 references
missing at_dl/actions/10b10000`, and the cause was ours. A **buffering** rule
names an ActionId the compiler allocates as the flow's store key and, until
`2c1acc2`, deliberately wrote no action record for (`compile.go`'s comment said
so in as many words), while the engine's reference check — as old as the engine,
D-021 — validates a rule's `action_id` as a reference whatever gate the rule
takes. `2c1acc2` writes the record, after the id is allocated, with the flow's
own meter and next hop, and the release path reads it.

The next failure was not test isolation: the deletion really did not erase the
buffering counter's entry. `remove()` — the path a deletion takes — erased the
direction's counter, the actions, the tunnels, the TEIDs and the meters, but
never the BUFF branch's entry, so it outlived the session and the next test in
the daemon read a table that was not empty (`ec9946d`;
`TestDeletingABufferingSessionErasesItsBufferCounter` was written first and
failed against the unfixed tree). The arm's third check was then found to be
reading the wrong place: it grepped upfd's log for a metric upfd serves over
HTTP and never logs, for a release this arm's upfd never drove.

**Field.** OAI and open5gs buffer; free5GC validates BAR and does not buffer (25);
OMEC notifies and does not buffer (25); UPG-VPP's README says BAR is "not yet
working".

### 8. GTP-U — us 100

**Sub-features.** decap; encap; echo request/reply; end marker; inner-to-outer
DSCP copy.

**Ours.** `ci/smoke-gtpu.sh` (decap, encap, DSCP, and the echo reply byte for
byte: `gtpu_echo`, TS 29.281 7.2.2); `ci/session-path.sh` (the End Marker a
handover sends, byte for byte: `internal/session/endmarker.go`, TS 29.244 5.3.2).

**Field.** open5gs and OMEC have both markers (80); everyone decapsulates and
encapsulates; echo is not examined per project by the survey.

### 9. IPv6 — us 0

**Sub-features.** PFCP UE IP and prefixes; IPv6 inner and outer; IPv6 on N9.

**Ours.** refusal with cause 73: `TestANonIPv4PDIIsRefusedNotWidened`,
`TestACHOOSEForIPv6IsRefused`.

**Field.** UPG-VPP states IPv4/IPv6 inner + outer (33, one sub-feature of three);
no other project claims any.

### 10. MAR / ATSSS-LL — us 0

**Sub-features.** MAR; ATSSS-LL.

**Ours.** nothing; phased in `compliance.md`.

**Field.** OAI (MAR) and UPG-VPP (MAR message support) at 50; ATSSS-LL nowhere.

### 11. ULCL / N9 route domains — us 50

**Sub-features.** Network Instance to route domain; branching on N9.

**Ours.** `internal/routing`; `TestParseInstancesReadsTheDeployment`.

**Field.** OMEC has ULCL/N9 (50); nothing else claims it.

### 12. Real-SMF interop — us 0

**Sub-features.** a real SMF driving this UPF end to end.

**Ours.** none yet: `ci/n4-path.sh` drives our own stand-in.

**Field.** open5gs is the field's proven one (production labs) and scores 100.

---

## What moves our number

The two closes that were on this list have landed and are counted above: BAR +
DDN (block 7, 0 → 75) and the DLDR half of the report path (block 3, 50 → 100),
both proven by `ci/buffer-path.sh`. Each row below is one remaining close, on its
own, against the current mean of 64:

| close | block | block from → to | mean | cost |
|---|---|---|---|---|
| linked UR-SEQN | 6 | 80 → 100 | 64 → 66 | one field read and one counter link |
| the vif that writes the route domain (gap 5's tail) | 11 | 50 → 100 | 64 → 69 | the port work in `design.md`; needs the placement measurement first |
| IPv6 | 9 | 0 → 100 | 64 → 73 | the dataplane's tables and the F-TEID key: a second form, not a patch |
| a real SMF (open5gs or free5GC) at the door | 12 | 0 → 100 | 64 → 73 | no code: an afternoon with a NIC and someone else's SMF |
| all four | 6, 9, 11, 12 | | **64 → 96** | |

None of them is a rewrite. (GBR *as such* is not on the list because block 5's
sub-feature is "per-flow **or** GBR", and the per-flow half is what the QFI work
earns; a guaranteed bit rate with its own rate pair remains absent and would be
its own close if the survey ever scored the two halves apart.)

## Three readings

1. **We lead on the mean, and the lead is one block wide.** 64 against open5gs's
   62 is not a verdict: it is the two closes that landed this week (BAR + DDN and
   the DLDR half) against open5gs's production interop, which we score 0 on. What
   we lead is real but narrow — markers 100 against 80, URR 80 against 60, QER
   100 against 67, the report path 100 against free5GC's 50 and OMEC's 0 — and
   none of it is what a handover or a stalled UE notices. Two closes still on
   the list (linked UR-SEQN, the vif that writes the route domain) would take the
   mean to 69 without touching the dataplane's shape.
2. **The mean is not a verdict on the dataplane.** No row here is a throughput
   claim: the same-harness measurement that would settle that (verification plan
   section 2) has not been run. The floors that do exist are per packet and
   per module, in `design.md`'s arms.
3. **No project has everything, and the two leaders trade places per block.**
   UPG-VPP owns URR and nothing in the box under it; eUPF is fast and unwired;
   OMEC is what this project replaces — it has the box and no measurement.
