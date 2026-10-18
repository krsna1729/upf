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
| 6 | URR: volume, time, thresholds, quota + enforcement, linked (5) | **100** | 60 | 60 | 60 | 100 | 0 | 0 |
| 7 | BAR + DDN: buffering, DDN, duration, drop-buffered (4) | **100** | 75 | 75 | 25 | 0 | 0 | 25 |
| 8 | GTP-U: decap, encap, echo, end marker, DSCP copy (5) | **100** | 40 | 80 | 40 | 40 | 40 | 80 |
| 9 | IPv6: PFCP UE IP, inner + outer, N9 (3) | **0** | 0 | 0 | 0 | 33 | 0 | 0 |
| 10 | MAR / ATSSS-LL (2) | **0** | 50 | 0 | 0 | 50 | 0 | 0 |
| 11 | ULCL / N9 route domains (2) | **50** | 0 | 0 | 0 | 0 | 0 | 50 |
| 12 | real-SMF interop (1) | **0** | 0 | **100** | 0 | 0 | 0 | 0 |
| | **mean of the eleven blocks every project scores (1-3, 5-12)** | **68** | **54** | **62** | **42** | **43** | **28** | **38** |

Block 4 is left out of every mean because no competitor cell exists for it (`—`),
so no project is credited or debited for it. **Updated 2026-10-18 (block 6):**
the linked UR-SEQN half landed, so block 6 is 100 and the us mean is
recomputed from the cells: the eleven blocks every project scores
(1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12) are 100+100+100+100+100+75+100+0+0+50+0 =
**725**, and 725 / 11 = 65.9 → **66** (it was 705 / 11 = 64.1 → 64 with block 6
at 80). **Corrected 2026-10-18:** block 3's
competitor cells had been written one place over — OAI-CN5G held free5GC's 50,
free5GC held UPG-VPP's 100, eUPF held OAI's 50 — which contradicted the block's
own Field text ("OAI…, open5gs…, free5GC… send both; UPG-VPP sends usage reports,
DLDR not evidenced; eUPF's URR is unwired, OMEC has none") and made the means
look as if they had stopped following their cells. They had not: with the cells
as the Field text gives them, every mean below divides its own row again, and
the four that appeared to have drifted (OAI-CN5G 54, free5GC 42, UPG-VPP 43,
eUPF 28) come back unchanged. Each cell in this table was then checked against
its block's Field text or the survey; block 3 was the only one out of step.
**2026-10-18 (block 7): the duration's expiry is proven live, so block 7 is
100.** `ci/buffer-path.sh` now carries a second live case: a BAR whose DL
Buffering Duration is 2 s, a store filled under it, a wait past the duration, and
then the very instruction the first case uses to release — which moves nothing,
because the store's own sweep freed the flow first. The cell moves and the mean
is recomputed from the cells: the eleven blocks every project scores
(1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12) are
100+100+100+100+100+100+100+0+0+50+0 = **750**, and 750 / 11 = 68.18 → **68**
(it was 725 / 11 = 65.9 → 66 with block 7 at 75). The row still divides as
written, and block 7's section below says what the arm now proves — including
that the free is *silent*, so what the arm observes is the absence of the
release's effect rather than a count of anything.
**2026-10-18 (the firewall path, blocks 4 and 9): no cell moves.** The compiler
now has an opt-in path on which a port *range* and an IPv6 SDF prefix compile
instead of being refused (`internal/session`, `upfd -firewall-ul`/`-firewall-dl`),
which is what block 4's "SDF + ranges" and block 9's "PFCP UE IP and prefixes"
are about — but the module it writes to is not in the stage the arms run
against, no `deploy/*.yaml` graph names it (a graph naming a module the daemon
does not have fails to load), and nothing has matched a packet through such a
rule. Unit tests justify the *compile*, not the capability, and this file's own
precedent is block 7's history: numbers written and read back were not credited —
its cell sat at 75 with the effect unshown — until the arm observed the effect
live (block 7's section below). So block 4 stays **80** and
block 9 **0**, the mean is unchanged, and its arithmetic is the same row as
above: 100+100+100+100+100+100+100+0+0+50+0 = **750**, 750 / 11 = 68.18 →
**68**. What would move them is a graph in the installed stage and an arm like
`ci/buffer-path.sh` that carries such a rule end to end — the work is named in
each block below.

## What each number is made of

| project | its mean rests on | weakest blocks |
|---|---|---|
| **us** | URR wired end to end (volume, time, quota enforcement and the linked group reporting), both GTP-U path messages, the report path in both halves and now live, and the PDI sub-features no one else is scored on; nothing in the box an idle UE sits in | 9, 10, 12 (0) |
| **open5gs** | the roundest project in the field: reports, buffering, markers, and production interop — four blocks at 75-100 | 9, 10, 11 (0) |
| **OAI-CN5G** | feature breadth in one XDP pipeline: BAR 75, MAR 50, URR 60 | 9, 11, 12 (0) |
| **free5GC** | delegating to the `gtp5g` kernel module: fast, but semantics it does not own | 5 (33), 7 (25), 9/10/11/12 (0) |
| **UPG-VPP** | the deepest URR in the field (100) and nothing in the box below it: no working QER or BAR | 5, 7, 11, 12 (0) |
| **eUPF** | speed; its URR is in the datapath but not wired to the session handler | 5, 6, 7, 9, 10, 11, 12 (0) |
| **OMEC** | the UPF this project replaces: QER, DDN notification, ULCL/N9, DSCP copy — and no URR at all | 3, 6, 9, 10, 12 (0) |

---

## The custom profile, row by row

The keyed per-session matcher (`PdrMatch`) is a second dataplane strategy, and
the score above is the *generic* profile's. This is the same ground walked
against the custom path, so "the full feature list on the custom profile" has a
definition instead of an impression. Three states: **works** (the control plane
writes it and the dataplane carries it), **refused** (the compiler refuses the
rule, deliberately), **untested** (the code path exists and nothing has run a
packet through it).

| block | on the custom path | why |
|---|---|---|
| 1 association, heartbeat, restart | works | the N4 layer is profile-independent |
| 2 establishment, modification, deletion | **works, tested** | one key per session, keyed by the F-TEID, in SMF precedence order — committed with its seven tests (`3508638`) |
| 3 Session Report: USAR / DLDR | USAR works / DLDR refused | the report path is control-side; DLDR needs a buffering flow, and a BUFF PDR is refused on this path |
| 4 PDI: precedence / F-TEID+CHID / UE IP / SDF+ranges / NI+QFI | precedence, F-TEID, UE IP, ranges work; QFI refused; domain untested | the key *is* the F-TEID, so a PDR is chosen by its tunnel and the UE address is not needed; the rule shape is the firewall's, so inclusive port ranges and both families compile; a QFI-naming PDI is refused (the rules are the 5-tuple) |
| 5 QER: gate, MBR, GBR | untested | the meter and the action are per-PDR and the keyed path writes the same action ids |
| 6 URR: volume, time, thresholds, quota, linked | untested | counters are per rule (per ActionId), which the keyed path writes |
| 7 BAR + DDN: buffering, DDN, duration, drop | **refused** | a BUFF PDR is refused on this path — the largest gap between the two profiles |
| 8 GTP-U: decap, encap, echo, end marker, DSCP | untested | the tunnel modules are unchanged by the profile |
| 9 IPv6 | SDF prefixes **compile, untested**; UE address and F-TEID refused | the module's rules carry both families (the firewall rule shape), which is *better* than the generic wildcard path; the F-TEID key is IPv4-only, so an IPv6 session is still refused |
| 10 MAR / ATSSS-LL | not implemented | phased in both profiles; needs a dual-3GPP deployment |
| 11 ULCL / N9 route domains | partly | the routing model is control-side; the module is uplink-only, so N9 and the downlink need the selector below |
| 12 real-SMF interop | not run | in both profiles |

**The checklist that closes the goal**, in order, each item with its own proof:

1. **The uplink arm** — a packet on N3, decapped, matched *by the module*, the
   right `action_id`, egress on N6. In flight (`Upf.PdrMatchArm`), and it is
   what commits the module.
2. **The profile mechanism** — `-profile generic|custom`, resolved at startup,
   with the default's no-regression shown by the existing arms. In flight
   (`Upf.ProfileMechanism`).
3. **Buffering on the custom path** — the module must carry a verdict for a BUFF
   PDR (a gate or a store key), so the largest gap above closes. Module change.
4. **QFI on the custom path** — the rule's key must carry the QFI, or the map
   must be keyed per QFI. Module change.
5. **The downlink selector** — `LpmRouteTable` keyed on (route domain, UE
   prefix), so a session is named on N6. Module change, and the reason the
   module is uplink-only today.
6. **A custom arm carrying QER + meters + URR counters** — the per-PDR action
   ids and counters are already written; nothing has measured them through this
   path.
7. **A custom arm carrying the tunnel path messages** — echo, end marker, DSCP
   marking — unchanged modules, unproven in this graph.
8. **An IPv6 SDF prefix through the module** — the capability the custom path
   has and the generic wildcard path does not; needs a v6 key form or a second
   map.
9. **Route domains on the custom path** — one module per domain, or the domain
   in the key; unproven either way.

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

**Why 80 and not 100.** The uncredited sub-feature is the "SDF + ranges" pair:
the SDF half is in (prefixes and single ports, with the live arm), the **range**
half is refused rather than widened, because a WildcardMatch mask can only hold
one port value. As of 2026-10-18 the compiler has an opt-in path that carries it
— `upfd -firewall-ul`/`-firewall-dl` put a direction's PDRs into BESS's
`firewall` table, whose rules carry inclusive port ranges and both address
families (`TestAPortRangeCompilesToAFirewallRuleWithItsRange`,
`TestAnIPv6SDFPrefixCompilesOnTheFirewallPathOnly`) — but that table is not in
the installed stage, no graph in `deploy/` declares the module, and no packet
has crossed such a rule, so the sub-feature stays uncredited on the same rule
block 7 uses below: a number written and read back is not the effect shown. The
cell moves when an arm can carry a range through the module, not when the
compiler can write one.

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

### 6. URR — us 100

**Sub-features.** volume; time; thresholds; quota and its enforcement; linked
UR-SEQN.

**Ours.** `TestEvaluateReportsAUsedUpQuotaAndStopsTheTraffic`,
`TestEvaluateReportsTheWindowItMeasured`, and for the linked half
`TestALinkedURRReportsItsGroupUnderOneURSEQN` (a URR linked to another, 8.2.55,
is read and the group reports whole under one UR-SEQN, 8.2.71, both members'
usage in one Session Report Request), `TestALinkedURRNamingAnUnknownURRIsRefused`
(a link the session cannot resolve is refused with cause 73, naming it) and
`TestARemoveURROfALinkedToURRIsRefused` (a linked-to URR is not removed out from
under the link).

**Field.** UPG-VPP `upf_session.c:640-680` (100); OAI, open5gs and free5GC
measure volume and time with thresholds but the survey shows no quota-enforcement
or linked half; eUPF unwired; OMEC none.

### 7. BAR + DDN — us 100

**Sub-features.** downlink buffering; DDN; buffering duration; drop-buffered.

**Ours.** `TestABuffFARIsGatedToTheStoreAndCounted`,
`TestTheDownlinkReportIsOwedOncePerBufferingEpisode`,
`TestAModificationThatStopsBufferingReleasesTheFlow`, and the live arm
`ci/buffer-path.sh`, which passes end to end against a stage carrying BESS's
`key_attrs` change (128fd237) and the bounded sweep below (0bfd2783):
`ok: the controller reported the buffered downlink`, `ok: the report named the
buffering PDR`, `ok: the store released the flow on the SMF's instruction`,
`ok: the store freed the flow at the BAR's own duration`, and
`buffer-path: ok (a BUFF FAR's packets were held, reported to the SMF over N4,
released when the SMF moved the path, and freed by the store's own timeout when
the BAR's duration ran out)`. The two live cases' own lines are
`held: 9248 packets counted on the branch; forwarded after the instruction:
0 -> 5712` (the sibling's release, flooding the encap because the graph's
source is still running) and `held: 6560 packets counted on the branch under the
BAR's timeout_ns 2s, freed by the store's own sweep; forwarded after the wait:
5712 -> 5712` (the expiry case's absence; both counts are packets a run's own
timing decides, and what the case asserts is that the two are equal). **Which
daemon:** the fourth check needs BESS `0bfd2783` — before that amendment the
store freed an aged flow only at its global `max_packets`, so the held packets
outlive the 3 s wait, the instruction releases the sixteen they cap at, and the
case fails (`the encap carried 16 packets after the instruction (was 6480)`)
while the three checks before it pass — and the stage this repo carries
(`build/bess/stage`, BESS `54fbf982`) has it, so the arm runs on its own
default; the lines above were recorded against BESS `a464f230`, whose
stage is not carried. Re-run 2026-10-18 against
`build/bess/stage`, the four checks pass (`held: 864 packets counted on the
branch; forwarded after the instruction: 0 -> 5456` and `held: 1216 packets
counted on the branch under the BAR's timeout_ns 2s … forwarded after the wait:
5936 -> 5936`).

**Why 100.** All four sub-features are shown live. Buffering, the DDN and the
release are the arm's first three checks; the **duration** is the fourth, and it
is the half that sat uncredited until the store's own sweep could be waited out.
The compiler half is unchanged: `compile.go` writes the flow's own `flows` entry
— `timeout_ns` from 8.2.29 (the infinite unit as a present zero) and
`max_packets_per_flow` from 8.2.30, each left out where the SMF named none —
`buffer_test.go` pins the three duration codes and the entry's rewrite and erase
(`TestABufferingFlowsOwnNumbersAreWrittenToTheStore`,
`TestAnUpdateBARInAReportResponseRewritesTheStoreEntry`), and the live arm reads
`buf/flows` back with the SMF's number.

What the entry *does* is the store's own aging, and BESS's amendment to D-129
(0bfd2783) is what makes it observable: the owner's run sweeps 256 flows from
where the last run stopped (`EvictExpiredBounded`) and frees what is older than
its `timeout_ns` whatever the store holds, where an older daemon checked the
timeout only under global `max_packets` pressure — a store this small never
reaches it. With one flow the rotation is one run, so the bound after the
deadline is the store's next run (a blocked task is rescheduled within its own
backoff, ~0.3 ms at most on this host), not a timer either side controls:
`TestLiveSessionHoldsNothingAfterTheBufferingDurationPasses` states that bound
and waits a second over the 2 s duration rather than racing it.

**Why the proof is an absence.** The free is *silent*: the sweep calls
`bess::PacketFree`, emits nothing on a gate and no metric, and the module's
`GetDesc` is not reachable from this controller's control surface — so there is
no count that could be read, and the observable is the absence of the effect the
timeout would otherwise leave. That effect is the SMF's instruction (5.2.4.1's
Update FAR that forwards the buffered downlink): the sibling case shows it
releasing the flow and moving the encap (`0 -> 5712`), and the expiry case shows
the same instruction moving nothing (`5712 -> 5712`) because the store freed
the flow before it arrived. The expiry case stops the graph's generator after the
fill — the Source's live `settings` singleton, `src_dn/settings` — because with
the source running the instruction's own forwarding floods the encap with the
graph's frames and a released flow's sixteen packets could not be seen at all.
The differential is the per-flow entry itself, and it is what the arm proves on
the *unfixed* side: with `timeout_ns` absent the module-wide `timeout_ms` (5000
in `deploy/buffer-path.yaml`) is what holds the flow, so the same 3 s wait leaves
the packets in the store and the instruction releases them — the run with the
write suppressed fails with `the encap carried 16 packets after the instruction
(was 0)` (one flow's cap, the packets that were still held). The 3 s wait is
deliberately under that 5 s so that only the per-flow number can have freed them.
`TestABuffOnlyFARIsADrop` is the drop-buffered half.

**History.** The arm's first run against a daemon carrying both contracts failed
at its own first test: the daemon refused the session transaction, `#3 references
missing at_dl/actions/10b10000`, and the cause was ours. A **buffering** rule
names an ActionId the compiler allocates as the flow's store key and, until
`4dcd338`, deliberately wrote no action record for (`compile.go`'s comment said
so in as many words), while the engine's reference check — as old as the engine,
D-021 — validates a rule's `action_id` as a reference whatever gate the rule
takes. `4dcd338` writes the record, after the id is allocated, with the flow's
own meter and next hop, and the release path reads it.

The next failure was not test isolation: the deletion really did not erase the
buffering counter's entry. `remove()` — the path a deletion takes — erased the
direction's counter, the actions, the tunnels, the TEIDs and the meters, but
never the BUFF branch's entry, so it outlived the session and the next test in
the daemon read a table that was not empty (`b9e6941`;
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

**Why 0 and not 33.** Since 2026-10-18 an SDF filter's IPv6 prefix compiles on
the opt-in firewall path, whose table holds IPv4 and IPv6 rules in one policy
(`TestAnIPv6SDFPrefixCompilesOnTheFirewallPathOnly`) — but only the *prefix*
half of the first sub-feature, only in the compiler: a PDI's IPv6 UE address is
still refused (the F-TEID key, the tunnel record and the WildcardMatch key's
address fields are IPv4-only), so this is not an IPv6 session; IPv6 inner and
outer headers and IPv6 on N9 are untouched; and the path cannot be run at all
(the module is not in the installed stage, no graph declares it, no packet has
crossed one of its rules — `docs/compliance.md`, gap 6). Half of one sub-feature
in the compiler, with nothing demonstrated, is not a third of the block.

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

The closes that were on this list have landed and are counted above: BAR + DDN
(block 7, 0 → 100), the DLDR half of the report path (block 3, 50 → 100), both
proven by `ci/buffer-path.sh`, and linked UR-SEQN (block 6, 80 → 100, proven by
`TestALinkedURRReportsItsGroupUnderOneURSEQN` and
`TestALinkedURRNamingAnUnknownURRIsRefused`). Each row below is one remaining
close, on its own, against the current mean of 68:

| close | block | block from → to | mean | cost |
|---|---|---|---|---|
| the port work's placement measurement (the vif's write itself landed on 2026-10-18: `deploy/veth-port.yaml` splits one port into the three interfaces and `ci/veth-port.sh` shows the compiler's rule selected by the domain the port wrote) | 11 | 50 → 100 | 68 → 73 | `docs/design.md`'s port section and `docs/ports.md`; needs a NIC -- a veth advertises no RSS offload (`ethdev_rss_hf=0x0`) |
| IPv6 | 9 | 0 → 100 | 68 → 77 | the dataplane's tables and the F-TEID key: a second form, not a patch. An SDF filter's IPv6 *prefix* is compiled on the opt-in firewall path since 2026-10-18, which is not a close: the module is not in the installed stage and no packet has crossed one of its rules (block 9's note) |
| a real SMF (open5gs or free5GC) at the door | 12 | 0 → 100 | 68 → 77 | no code: an afternoon with a NIC and someone else's SMF |
| all three | 9, 11, 12 | | **68 → 91** | |

The single-close means are the arithmetic from the cells: adding a block's gain
to the 750/11 = 68 base (block 11's 50, or IPv6's 100, or the SMF's 100, each
over 11), and the three together are (750 + 50 + 100 + 100) / 11 = 1000 / 11 =
90.9 → 91.

None of them is a rewrite. (GBR *as such* is not on the list because block 5's
sub-feature is "per-flow **or** GBR", and the per-flow half is what the QFI work
earns; a guaranteed bit rate with its own rate pair remains absent and would be
its own close if the survey ever scored the two halves apart.)

## Three readings

1. **We lead on the mean, and the lead is six points wide.** 68 against
   open5gs's 62 is not a verdict: it is the closes that landed this week (BAR +
   DDN, the DLDR half, and linked UR-SEQN) against open5gs's production interop,
   which we score 0 on. What we lead is real but narrow — markers 100 against 80,
   URR 100 against 60, QER 100 against 67, the report path 100 against free5GC's
   50 and OMEC's 0, BAR + DDN 100 against their 75 — and none of it is what a
   handover or a stalled UE notices. One close still on the list, block 11's port
   work, would take the mean to 73 without touching the dataplane's shape.
2. **The mean is not a verdict on the dataplane.** No row here is a throughput
   claim: the same-harness measurement that would settle that (verification plan
   section 2) has not been run. The floors that do exist are per packet and
   per module, in `design.md`'s arms.
3. **No project has everything, and the two leaders trade places per block.**
   UPG-VPP owns URR and nothing in the box under it; eUPF is fast and unwired;
   OMEC is what this project replaces — it has the box and no measurement.
