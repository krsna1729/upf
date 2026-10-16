# Compliance: what is implemented, and what proves it

Status: 2026-10-17. `compliance-landscape.md` is about the field (who else
implements what, and with what evidence); this file is about us: one row per
capability, its clause, its state, and the test or script that shows it.
"Interop: none" means only our own stand-ins have driven it — no open-source SMF
has yet, so no row claims it.

Every clause number here was read off **ETSI TS 129 244 V17.9.0 (2023-07)**, the
PDF ETSI publishes, on 2026-10-17: the grouped IEs (PDR, PDI, FAR, QER, URR,
BAR, MAR) are specified inside the procedure clauses (§7.5.2.x for establishment,
§7.5.4.x for modification), and §8.2 holds the IEs they are built from. An
earlier revision of this file cited clause numbers from memory; most were wrong,
which is why the version is named.

## Declared capabilities (TS 29.244 8.2.25)

The Association Setup Response advertises **no optional UP Function Features**:
`internal/n4`'s four octets are a config and `cmd/upfd` leaves them zero, so the
answer says "mandatory behaviour only". That is the honest thing to say while
every optional feature is a milestone of its own, and it is the conservative
thing to say while the optional behaviour below is only partly exercised.

Two optional behaviours *are* implemented without being declared:

| bit | implemented where | why the bit is still off |
|---|---|---|
| FTUP | the compiler allocates an F-TEID when the SMF sends TEID 0 and reports it in the Created PDR (`internal/session/compile.go`) | the milestone turns the bit on; until then a conformant SMF simply never asks, and the path is exercised by the live tests instead |
| UEIP | the UE IP IE is a rule key and the session's UE address (`internal/session/compile.go`) | same: the behaviour is what the tests assert, the bit is a promise about the rest of the feature |

A milestone that implements a feature turns its bit on in `cmd/upfd`; a feature
whose bit is on with nothing behind it is the kind of claim
`compliance-landscape.md` collected from other projects.

## N4 procedures (TS 29.244)

| § | capability | state | evidence |
|---|---|---|---|
| 7.4.4.1-7.4.4.2 | Association Setup (Node ID, Recovery Time Stamp, UP Function Features); a second CP function refused | in | `internal/n4`: TestAssociationAndHeartbeat, TestSecondCPFunctionIsRejected |
| 7.4.4.3-7.4.4.6 | Association Update / Release, sessions end with the association | in | TestAssociationReleaseEndsSessions |
| 7.4.2 | Heartbeat, both directions, timeout ends the association | in | TestHeartbeatInitiatorKeepsAssociationAlive, TestHeartbeatTimeoutEndsAssociation |
| 7.4.4.1 | CP restart detection (a new Recovery Time Stamp, 8.2.65) voids the association | in | TestCPRestartVoidsAssociation |
| 7.4.4.7 | Version not supported answered | in | TestVersionNotSupported |
| 7.6.1-7.6.4 | a malformed datagram, or a message type we do not implement, is ignored rather than answered wrongly | in | TestMalformedDatagramIgnored, TestUnimplementedMessageTypesAreIgnored |
| — | a session request with no session layer configured is refused with a Cause | in | TestSessionRequestsWithoutSessionLayer |
| 7.5.2-7.5.3 | Session Establishment, one transaction per change | in | `ci/session-live.sh`; `internal/session`: TestEstablishCompilesTheSessionIntoOneTransaction |
| 7.5.4-7.5.5 | Session Modification (a handover rewrites the whole session) | in | TestModifyRewritesTheWholeSession; `ci/bench-n4.sh` |
| 7.5.6-7.5.7 | Session Deletion removes what it programmed | in | TestDeleteRemovesWhatTheSessionProgrammed |
| 7.5.2 | a repeated establishment for the same keys answers with the same session (idempotent by choice: the SMF that re-sent after a lost answer gets its session, not a second one) | in | TestRepeatedEstablishmentAnswersWithTheSameSession |
| 7.5.8 | Session Report Request (USAR, DLDR) — the UP-initiated path | **not implemented** | — |
| 7.5.9 | Session Report Response | not implemented (same row) | — |
| — | a datapath refusal becomes a Cause, not a half-programmed session | in | TestDataplaneRefusalBecomesACause |
| 8.2.1 | an unknown CP F-SEID is answered "session context not found" rather than programmed | in | TestUnknownSessionIsNotFound |

## Rules

| § | capability | state | evidence |
|---|---|---|---|
| 7.5.2.2 (Create PDR); 8.2.36 PDR ID, 8.2.11 precedence, 8.2.2 source interface, 8.2.3 F-TEID, 8.2.62 UE IP address, 8.2.5 SDF filter, 8.2.74 FAR ID, 8.2.75 QER ID | PDR and its PDI, correlated with the FAR and QER | in | `internal/session`: TestEstablishCompilesTheSessionIntoOneTransaction |
| 8.2.5 | SDF filter: source and destination addresses **and prefixes**, protocol, single ports | in: the key is canonical, the mask says which fields the filter constrains, and a prefix's mask is its length | TestRuleKeysAreCanonical, TestAnSDFPrefixIsAPrefixNotAnAddress (and the live arm with it); `ci/session-path.sh` |
| — | a port **range** in an SDF filter | refused, deliberately: a rule that cannot express the range must not match more widely than the filter | TestPortRangeIsRefusedNotMatchedTooWidely |
| 8.2.89 QFI, 8.2.4 network instance | not read: one QFI per session, one network instance (N6) | — | — |
| 7.5.2.3 (Create FAR); 8.2.26 apply action, 8.2.24 destination interface | FAR: apply action FORW; destination interface | in | the live tests, and `ci/n4-path.sh` for the downlink's |
| 8.2.56 | FAR: outer header creation GTP-U/UDP/IPv4 with a TEID toward the gNB | in | `ci/n4-path.sh` (the FAR's TEID is on the wire) |
| 7.5.2.6 (Create BAR); 8.2.26 BUFF, 8.2.29-8.2.30 buffering, 7.5.8.2 DDN | FAR: BUFF (and the DDN that makes it useful) | not implemented | — |
| 8.2.31 PFCPSMReq-Flags, 7.5.4.1 | SNDEM (end marker), DROBU (drop buffered) | not read | — |
| 7.5.2.5 (Create QER); 8.2.7 gate status, 8.2.8 MBR, 8.2.9 GBR | QER: MBR (UL/DL), gate status, one QER per session | in: the compiler writes a meter per policed direction and the gate's state; a closed gate compiles to the drop gate with no action | TestAClosedGateDropsWithoutAnAction; `ci/session-path.sh` counts the packets through the meter |
| 7.5.2.4 (Create URR); 8.2.54 URR ID, 8.2.40 measurement method, 8.2.19 reporting triggers, 8.2.13-8.2.14 thresholds, 8.2.50-8.2.51 quota, 8.2.44-8.2.45 measurements | URR: volume and time, thresholds, quota, reporting triggers | **not implemented** — the design doc's next milestone after the routing domains | — |
| — | session churn: an id released by a deletion is not reused until the dataplane's retire period has passed, and a restarted controller does not walk its predecessor's order | in | TestTheIDPoolWalksTheSpaceAndWaitsOutTheGrace; both live arms of `ci/session-path.sh` (the second one is what found it) |
| 7.5.2.8 (Create MAR); 8.2.123 MAR ID, 8.2.124-8.2.126 steering, 8.2.154 MPTCP, 8.2.155 ATSSS-LL | MAR/ATSSS | not implemented (phased, needs a dual-3GPP-access deployment) | — |

## Datapath

| capability | state | evidence |
|---|---|---|
| GTP-U v1 decapsulation: TEID match, outer headers removed, `upf_teid` reported | in | `datapath/`; `ci/smoke-gtpu.sh` (six checks, including that a TEID no session names is dropped) |
| GTP-U v1 encapsulation: outer Eth/IPv4/UDP 2152/GTP-U from the FAR's parameters | in | `ci/session-path.sh`, `ci/n4-path.sh` (byte-level, from the daemon's Dumps) |
| the whole path under one session: UL N3 (TEID table -> decap) -> PDR -> action -> meter -> the next hop's gate (N6), DL N6 -> PDR -> action -> meter -> GTP-U -> N3 | in | `ci/session-path.sh` (counters zero before the session, both directions after) |
| GTP-U echo request/response | not implemented — and an echo request is a G-PDU with TEID 0 targeting no tunnel, so it is dropped rather than answered: a peer running path management reads that as a dead path, which is the honest symptom until the milestone lands | — |
| GTP-U end marker (type 254) | not implemented | — |
| DSCP copy inner -> outer | in: the encap writes the inner packet's TOS on the outer IPv4 header | `ci/session-path.sh` (the outer header carries the graph's EF mark, and fails without the copy) |
| per-rule counters (packets and bytes per PDR, so a URR can report them) | gate counters are in; per-rule counters arrive with URR | `ci/session-path.sh` reads the gate counters |
| multi-queue RSS, per-worker tables, RCU rule updates, no locks or allocations in the packet path | in (BESS: D-097's layout, the classifier's per-worker tables, RCU publishing) | BESS `docs/decisions.md`, `docs/performance-contract.md`; `docs/ports.md` |
| UE IP NAT, ULCL/branching on N9 | not implemented (N9 comes with the route domains) | — |

## Interop

| peer | state |
|---|---|
| our own stand-in SMF (`cmd/n4bench` + `internal/n4sim`) | in: `ci/n4-path.sh` (a session carries packets), `ci/bench-n4.sh` (the envelope) |
| open5gs SMF | not run |
| free5GC SMF | not run |
| open5gs/free5GC gNB + UE (PacketRusher) | not run (needs the bound N3/N6 ports and a NIC) |

Every row above that says "not implemented" or "not read" is a *deployment*
statement, not a silent failure: the UPF ignores what it does not read, and the
Association Setup Response declares no optional feature it cannot honour.

## Gaps, in the order they close

1. **URR** (7.5.2.4 + the Session Report path): volume and time per URR,
   thresholds and quota, reported so a real SMF accepts it. The counters are the
   design's differentiator and the one place the field is weakest.
2. **End marker and echo** (GTP-U v1, 7.4.2 and TS 29.281): both are three-line
   packets the SMF's handover path depends on.
3. **DSCP copy**: in as of 2026-10-17 (the encap copies the inner TOS); the
   remaining part is the per-QER override the SMF can ask for with the QoS rules.
4. **BAR + DDN** (7.5.2.6 + 7.5.8.2): the downlink buffering OMEC never had.
5. **QFI and Network Instance** (8.2.89, 8.2.4): one per session today; reading
   them is what N9 (ULCL) needs, along with `internal/routing`'s domains.
