# Scorecard: our compliance blocks against the field

Status: 2026-10-17. Purpose: one number per compliance block, for us and for the
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
| 3 | Session Report Request: USAR, DLDR (2) | **50** | 50 | 100 | 50 | 100 | 50 | 0 |
| 4 | PDI sub-features: precedence, F-TEID + CHID, UE IP, SDF + ranges, NI + QFI (5) | **80** | — | — | — | — | — | — |
| 5 | QER: gate, MBR, per-flow or GBR (3) | **100** | 67 | 67 | 33 | 0 | 67 | 67 |
| 6 | URR: volume, time, thresholds, quota + enforcement, linked (5) | **80** | 60 | 60 | 60 | 100 | 0 | 0 |
| 7 | BAR + DDN: buffering, DDN, duration, drop-buffered (4) | **0** | 75 | 75 | 25 | 0 | 0 | 25 |
| 8 | GTP-U: decap, encap, echo, end marker, DSCP copy (5) | **100** | 40 | 80 | 40 | 40 | 40 | 80 |
| 9 | IPv6: PFCP UE IP, inner + outer, N9 (3) | **0** | 0 | 0 | 0 | 33 | 0 | 0 |
| 10 | MAR / ATSSS-LL (2) | **0** | 50 | 0 | 0 | 50 | 0 | 0 |
| 11 | ULCL / N9 route domains (2) | **50** | 0 | 0 | 0 | 0 | 0 | 50 |
| 12 | real-SMF interop (1) | **0** | 0 | **100** | 0 | 0 | 0 | 0 |
| | **mean of the eleven blocks every project scores (1-3, 5-12)** | **53** | **54** | **62** | **42** | **43** | **28** | **38** |

## What each number is made of

| project | its mean rests on | weakest blocks |
|---|---|---|
| **us** | URR wired end to end, both GTP-U path messages, and the PDI sub-features no one else is scored on; nothing in the box an idle UE sits in | 7, 9, 10, 12 (0) |
| **open5gs** | the roundest project in the field: reports, buffering, markers, and production interop — four blocks at 75-100 | 9, 10, 11 (0) |
| **OAI-CN5G** | feature breadth in one XDP pipeline: BAR 75, MAR 50, URR 60 | 9, 11, 12 (0) |
| **free5GC** | delegating to the `gtp5g` kernel module: fast, but semantics it does not own | 7 (25), 5 (33), 9/10/11/12 (0) |
| **UPG-VPP** | the deepest URR in the field (100) and nothing in the box below it: no working QER or BAR | 5, 7, 10, 11, 12 (0) |
| **eUPF** | speed; its URR is in the datapath but not wired to the session handler | 3, 6, 7, 9, 10, 11, 12 (0) |
| **OMEC** | the UPF this project replaces: QER, DDN notification, ULCL/N9, DSCP copy — and no URR at all | 3, 6, 9, 10, 12 (0) |

---

## The blocks, audited

Each block's sub-features and where the credit comes from. Competitor citations
are the survey's (file and symbol, in
[`compliance-landscape.md`](compliance-landscape.md)); ours are test names in
[`compliance.md`](compliance.md).

| # | sub-features | us | field |
|---|---|---|---|
| 1 | association setup/update/release; heartbeat; restart detection by Recovery Time Stamp | `internal/n4`: `TestAssociationAndHeartbeat`, `TestCPRestartVoidsAssociation`, `TestSecondCPFunctionIsRejected` | every project must interoperate with an SMF to be used at all; the survey found no absence |
| 2 | establishment; modification; deletion | `ci/session-live.sh`; `TestEstablishCompilesTheSessionIntoOneTransaction` | in every project |
| 3 | USAR (a report sent when a URR says so); DLDR (one sent when downlink data arrives with no tunnel) | `TestAReportIsAUsageReportTheSMFCanRead`, `TestTheDownlinkReportIsOwedOncePerBufferingEpisode`; live: `internal/n4/live_report_test.go` (USAR, run by `ci/session-report.sh`); the DLDR live arm (`internal/n4/live_ddn_test.go`, `ci/buffer-path.sh`) is written and needs a daemon carrying BESS's `packet_store` key_attrs (128fd237) *and* the store's new contract (release/drop/clear thread-safe, accepted-not-completed, `3f3716df` on develop), so the DLDR half is **in, unverified live** and is not scored until that arm passes | OAI (`xdp_urr_apply_kern.c` and its DLDR path), open5gs (`upf_sess_urr_acc_add`, DDN), free5GC (`report.go` types) send both; UPG-VPP sends usage reports, DLDR not evidenced; eUPF's URR is unwired, OMEC has none, so neither can report |
| 4 | precedence; F-TEID with CH/CHID (FTUP); UE IP; SDF filter incl. port ranges; Network Instance and QFI | `TestUplinkPDIsWithOneCHOOSEIDShareOneFTEID`, `TestThePrecedenceIsInvertedIntoTheClassifiersPriority`, `TestAPDINamingAQFIKeysTheRuleOnIt`, `TestAQERsQFIReachesTheTunnelRecord`, `TestPortRangeIsRefusedNotMatchedTooWidely`, `TestANonIPv4PDIIsRefusedNotWidened`, `ci/smoke-gtpu.sh` (a G-PDU carrying a PDU Session Container, decap reading QFI 5 into metadata) | not examined per project: the survey scores rule types (PDR/FAR/QER/URR/BAR), not PDI sub-features. Only OAI's `ftup=1` is on record, and it is not enough to score the block |
| 5 | QER gate; MBR; per-flow or GBR semantics | `TestAClosedGateDropsWithoutAnAction`; `TestAQERsQFIReachesTheTunnelRecord` (a QER's QFI reaching the flow's tunnel record); `TestTwoQFIKeyedPDRsGetTheirOwnMeters` (two PDRs of one session differing only by QFI, each naming its own QER, compiling to two actions and two meter ids -- the flows are policed apart); `ci/smoke-gtpu.sh` (the encap writing the container from the record's QFI); `ci/session-path.sh` | OAI TC-BPF, open5gs `appQER`/`sessionQER`, eUPF one QER per PDR, OMEC app + session QER; free5GC has no QER semantics in userspace (33); UPG-VPP's README says QER is "not yet working" (0) |
| 6 | volume; time; thresholds; quota and its enforcement; linked UR-SEQN | `TestEvaluateReportsAUsedUpQuotaAndStopsTheTraffic`, `TestEvaluateReportsTheWindowItMeasured` | UPG-VPP `upf_session.c:640-680` (100); OAI, open5gs and free5GC measure volume and time with thresholds but the survey shows no quota-enforcement or linked half; eUPF unwired; OMEC none |
| 7 | downlink buffering; DDN; buffering duration; drop-buffered | buffering and DDN: `TestABuffFARIsGatedToTheStoreAndCounted`, `TestTheDownlinkReportIsOwedOncePerBufferingEpisode`, `TestAModificationThatStopsBufferingReleasesTheFlow`, with the live arm `ci/buffer-path.sh` (written; needs the same daemon rebuild — key_attrs *and* the `3f3716df` store contract — so buffering and DDN are **in, unverified live** and are not scored until that arm passes); a graph with no store still drops (`TestABuffOnlyFARIsADrop`) | OAI and open5gs buffer; free5GC validates BAR and does not buffer (25); OMEC notifies and does not buffer (25); UPG-VPP's README says BAR is "not yet working" |
| 8 | GTP-U decap; encap; echo request/reply; end marker; inner-to-outer DSCP copy | `ci/smoke-gtpu.sh` (decap, encap, DSCP, and the echo reply byte for byte: `gtpu_echo`, TS 29.281 7.2.2); `ci/session-path.sh` (the End Marker a handover sends, byte for byte: `internal/session/endmarker.go`, TS 29.244 5.3.2) | open5gs and OMEC have both markers (80); everyone decapsulates and encapsulates; echo is not examined per project by the survey |
| 9 | PFCP UE IP and prefixes; IPv6 inner and outer; IPv6 on N9 | refusal with cause 73: `TestANonIPv4PDIIsRefusedNotWidened`, `TestACHOOSEForIPv6IsRefused` | UPG-VPP states IPv4/IPv6 inner + outer (33, one sub-feature of three); no other project claims any |
| 10 | MAR; ATSSS-LL | nothing; phased in `compliance.md` | OAI (MAR) and UPG-VPP (MAR message support) at 50; ATSSS-LL nowhere |
| 11 | Network Instance to route domain; branching on N9 | `internal/routing`; `TestParseInstancesReadsTheDeployment` | OMEC has ULCL/N9 (50); nothing else claims it |
| 12 | a real SMF driving this UPF end to end | none yet: `ci/n4-path.sh` drives our own stand-in | open5gs is the field's proven one (production labs) and scores 100 |

---

## What moves our number

Each row is one close, on its own, against the mean of 53 — the QFI row has closed (`e3822d8`, per-flow QER and the PDI's QFI with tests and a wire smoke) and is counted in it:

| close | block | block from → to | mean | cost |
|---|---|---|---|---|
| BAR + DDN (gap 4) | 7 | 0 → 75 | 53 → 60 | the largest item: a buffer, a DDN report, and the duration semantics; the code is in (`a10e9e5`) and its live arm waits on a daemon carrying BESS's `packet_store` key_attrs |
| the DLDR half of the report path | 3 | 50 → 100 | 53 → 58 | the code is in the same commit, waiting on the same arm |
| linked UR-SEQN | 6 | 80 → 100 | 53 → 55 | one field read and one counter link |
| the vif that writes the route domain (gap 5's tail) | 11 | 50 → 100 | 53 → 58 | the port work in `design.md`; needs the placement measurement first |
| IPv6 | 9 | 0 → 100 | 53 → 62 | the dataplane's tables and the F-TEID key: a second form, not a patch |
| a real SMF (open5gs or free5GC) at the door | 12 | 0 → 100 | 53 → 62 | no code: an afternoon with a NIC and someone else's SMF |

Taken together, the closes left on that list — BAR + DDN and the DLDR half (both
written, both waiting on the live arm), linked UR-SEQN, the vif that puts a
downlink rule's domain in its key, IPv6 and a real SMF — are the ones that put
the mean past open5gs's 62, and none of them is a rewrite. (GBR *as such* is not
on the list because block 5's sub-feature is "per-flow **or** GBR", and the
per-flow half is what the QFI work earns; a guaranteed bit rate with its own
rate pair remains absent and would be its own close if the survey ever scored
the two halves apart.)

## Three readings

1. **We are behind, and by a specific list.** open5gs 62 and OAI 54 against our
 53 is not noise: it is BAR + DDN (0 against 75) and interop (0 against 100),
 with the tunnel-marker block now *ahead* (100 against 80), URR ahead too
 (80 against 60 for three of them) and the QER block level with the best of the
 field (100 against 67) — and none of what we lead is what a
 handover or a stalled UE notices. Two of those numbers are about to move and are
 deliberately still unscored: the buffering and DLDR code is in, and both blocks
 wait on one live arm (`ci/buffer-path.sh`) that needs a daemon carrying BESS's
 packet_store key_attrs *and* the store's new contract.
2. **The mean is not a verdict on the dataplane.** No row here is a throughput
   claim: the same-harness measurement that would settle that (verification plan
   section 2) has not been run. The floors that do exist are per packet and
   per module, in `design.md`'s arms.
3. **No project has everything, and the two leaders trade places per block.**
   UPG-VPP owns URR and nothing in the box under it; eUPF is fast and unwired;
   OMEC is what this project replaces — it has the box and no measurement.
