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

The Association Setup Response advertises **one optional UP Function Feature**:
FTUP, and only in the run that has a session layer (`upfd -bess`), because that
is where the F-TEID allocation lives. With no session layer this node refuses
every session request, so an answer promising an F-TEID it could not allocate
would be a claim with nothing behind it. Everything else the four octets could
say stays clear: every other optional feature is still a milestone of its own,
and the answer otherwise declares mandatory behaviour alone.

What the FTUP bit covers (TS 29.244 8.2.3), and what proves it:

| part of the feature | state | evidence |
|---|---|---|
| a PDI whose F-TEID IE carries the CH flag (no TEID field) is given an F-TEID | in: the compiler allocates the TEID, reports it in the Created PDR, and writes the TEID rule in front of the decap from it | `internal/session`: TestACHRequestIsAllocatedWhateverItsFamilyFlag, TestACHOOSEForBothFamiliesGetsTheIPv4FTEID; `internal/n4`: TestAConfiguredFeatureIsAdvertised; `ci/session-live.sh` |
| the PDIs of one PFCP session that carry the same CHOOSE ID share one F-TEID | in: the session keeps one F-TEID per CHOOSE ID and hands it to every PDI that names it; a refused modification keeps the F-TEID it allocated rather than returning it to the pool, and the SMF's retry is answered with that value (the model's mutation is not undone by a refusal, and the reservation is what keeps the value off another session until this one ends) | TestUplinkPDIsWithOneCHOOSEIDShareOneFTEID, TestTwoCHOOSEIDsGetTwoFTEIDs, TestACHOOSEIDIsTheSessionsFTEIDForThatGroup, TestACHOOSEIDsFTEIDIsLetGoWithItsLastPDI, TestARefusedModificationKeepsTheCHIDItAllocated; `ci/session-live.sh`: TestLiveSessionSharesOneFTEIDPerCHOOSEID |
| a CHOOSE request for an address family this UP has no address for (V6 set, V4 not) | refused with cause 73, deliberately: the Created PDR would otherwise name a family the SMF did not ask for | TestACHOOSEForIPv6IsRefused |

Two design choices 8.2.3 does not settle, recorded here because the section
leaves them to the implementation:

- **The group is the session's, not the message's.** The section requires the
  sharing of "the PDRs requested to be created in a PFCP Session Establishment
  Request or PFCP Session Modification Request with the same CHOOSE ID value",
  i.e. within one message. This UPF carries the CHOOSE ID for the session's
  life, so a PDI a later modification creates with an ID the session has
  already used is given the same F-TEID: that is what makes the ID a handle an
  SMF can program against across requests, and a group whose value changed per
  message would be no group at all. An entry is dropped, and its TEID released,
  as soon as no PDR of the session names it.
- **Two CHOOSE IDs are two F-TEIDs.** Nothing in the section makes two values
  one tunnel, and an SMF that used two IDs to ask for two tunnel endpoints
  would be given one by an implementation that answered every CHOOSE request
  with its single F-TEID.

One optional behaviour is implemented without being declared:

| bit | implemented where | why the bit is still off |
|---|---|---|
| UEIP | the UE IP IE is a rule key and the session's UE address (`internal/session/compile.go`) | the bit covers the CHV4/CHV6 half too -- the SMF asking the **UP** to choose the address -- and this UP does not allocate one: such a request is refused with a rule failure (`TestAUEIPAllocationRequestIsRefused`), so the feature is half there and the bit stays off until allocation exists |

A milestone that implements a feature turns its bit on in `cmd/upfd`; a feature
whose bit is on with nothing behind it is the kind of claim
`compliance-landscape.md` collected from other projects.

## N4 procedures (TS 29.244)

| § | capability | state | evidence |
|---|---|---|---|
| 7.4.4.1-7.4.4.2 | Association Setup (Node ID, Recovery Time Stamp, UP Function Features); a second CP function refused | in | `internal/n4`: TestAssociationAndHeartbeat, TestSecondCPFunctionIsRejected, TestAConfiguredFeatureIsAdvertised |
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
| 7.2.2.4 (the header's SEID; 8.2.51 F-SEID) | the SEID a PFCP message is addressed by | in: the header's SEID is the identity of the *receiving* node's session, so every message to the SMF carries the CP F-SEID — the Establishment, Modification and Deletion Responses (`establishResponse`/`modifyResponse`/`deleteResponse` in `internal/session/compile.go`) and the Session Report Request (`session.Report.CPSEID`). Our own F-SEID travels in the establishment answer's F-SEID IE, which is what the SMF addresses later requests with (open5gs's `n4_build_session_establishment_response` does exactly this, and its SMF finds a session by the SEID it allocated). A request naming no CP F-SEID at all is answered with the header's SEID unset (S flag clear) rather than under a value that is not the peer's | TestLiveUsageReportReachesTheSMF, TestReportLoopSendsAReportTheSMFAcknowledges (the report's CP SEID, asserted on the wire); `ci/session-live.sh` (modify/delete addressing the UP F-SEID from the answer's IE) |
| 7.5.2.2 (Create PDR); 8.2.36 PDR ID, 8.2.11 precedence, 8.2.2 source interface, 8.2.3 F-TEID, 8.2.62 UE IP address, 8.2.5 SDF filter, 8.2.74 FAR ID, 8.2.75 QER ID | PDR and its PDI, correlated with the FAR and QER | in | `internal/session`: TestEstablishCompilesTheSessionIntoOneTransaction |
| 8.2.5 | SDF filter: source and destination addresses **and prefixes**, protocol, single ports | in: the key is canonical, the mask says which fields the filter constrains, and a prefix's mask is its length | TestRuleKeysAreCanonical, TestAnSDFPrefixIsAPrefixNotAnAddress (and the live arm with it); `ci/session-path.sh` |
| 8.2.3 | F-TEID: a PDI whose IE asks the UP function to choose one (CH) is given one, and every PDI of the session that carries the same CHOOSE ID (CHID) is given the same one; a request for an IPv6 F-TEID is refused | in: the F-TEID the answer reports in the Created PDR is the TEID the uplink's rule is written from | TestACHRequestIsAllocatedWhateverItsFamilyFlag, TestUplinkPDIsWithOneCHOOSEIDShareOneFTEID, TestTwoCHOOSEIDsGetTwoFTEIDs, TestACHOOSEIDIsTheSessionsFTEIDForThatGroup, TestACHOOSEIDsFTEIDIsLetGoWithItsLastPDI, TestACHOOSEForIPv6IsRefused; `ci/session-live.sh`: TestLiveSessionSharesOneFTEIDPerCHOOSEID |
| — | a port **range** in an SDF filter | refused, deliberately: a rule that cannot express the range must not match more widely than the filter | TestPortRangeIsRefusedNotMatchedTooWidely |
| 8.2.62 | a UE IP address IE whose CHV4/CHV6 bit asks the UP function to choose an address -- including a dual-stack IE that carries the IPv4 address and asks for the IPv6 one -- an IE that parses as 0.0.0.0, or one present with no address in it | refused, deliberately: the CH bits are the only sign a request was made (the other family's address is present in the dual-stack case), so reading the IE by its addresses compiles the rule from the other direction's address and answers a success the SMF reads as an allocation it would never learn | TestAUEIPAllocationRequestIsRefused |
| — | a PDI naming an address or prefix that is not IPv4, and an SDF prefix whose address carries host bits | refused with cause 73 (an IPv6 address cannot be masked into four bytes, and widening it would match another session's packets); a sloppy prefix means its network (`10.10.1.5/16` compiles to `10.10.0.0/16`) | TestANonIPv4PDIIsRefusedNotWidened, TestAnSDFPrefixIsAPrefixNotAnAddress |
| — | a PDI with no UE IP IE (an uplink PDR chosen by its F-TEID, or an SMF that sent the address on one direction only) | in: the field is left unconstrained rather than refused | TestAPDRWithoutAUEAddressIsUnconstrained |
| 8.2.4 network instance; 8.2.89 QFI | Network Instance: read and resolved per PDR and per FAR; QFI still not read (one QFI per session) | **partly in**: the deployment's interfaces are `internal/routing`'s model (`upfd -instances`, `-max-domains`), a PDI's and a FAR's forwarding-parameters Network Instance are both resolved against them, a name no interface serves is refused with cause 73 (the refusal names what the deployment does serve) instead of being served by the default interface, a PDI naming none takes the first interface, a subscriber address outside that interface's pool is refused too, the interface's route domain goes into the PDR rule's key wherever the graph declares it (`domain` in `-pdr-fields-*`) and its next hop sends the forward out (the FAR's own instance overrides the PDI's for the egress). QFI is not one of a rule's fields, so a PDI told apart only by QFI compiles to one key with another's: refused with cause 73, which the SMF can act on. The vif that writes `route_domain` into the packet is not wired yet, so the domain field is declared only by a graph with a writer -- today an uplink rule keys on the tunnel it arrived on instead (docs/design.md, "N3, N6, N9: one port, three interfaces") | TestTwoInstancesRouteIndependently, TestAPDINamingAnUnknownInstanceIsRefused, TestAPDIWithoutAnInstanceTakesTheDefault, TestAnAddressOutsideTheInstancesPoolIsRefused, TestTheForwardsNetworkInstanceChoosesTheEgress, TestTheTunnelFieldNeedsATunnel, TestAOneInstanceDeploymentIsUnchanged, TestAnUpdateThatRenamesTheInstanceMovesTheRule; `internal/routing`: TestTwoInstancesMayServeTheSamePool, TestAnInterfaceServesAPrefixOnce, TestADeploymentTheRouterCannotHaveIsRefused; `cmd/upfd`: TestParseInstancesReadsTheDeployment, TestParseInstancesRefuses, TestParsePDRFieldsNamesTheGraphsKey; `ci/session-path.sh`: TestLiveTwoInstancesRouteIndependently |
| 7.5.2.3 (Create FAR); 8.2.26 apply action, 8.2.24 destination interface | FAR: apply action FORW; destination interface | in | the live tests, and `ci/n4-path.sh` for the downlink's |
| 8.2.56 | FAR: outer header creation GTP-U/UDP/IPv4 with a TEID toward the gNB | in | `ci/n4-path.sh` (the FAR's TEID is on the wire) |
| 7.5.2.6 (Create BAR); 8.2.26 BUFF, 8.2.29-8.2.30 buffering, 7.5.8.2 DDN | FAR: BUFF (and the DDN that makes it useful) | not implemented | — |
| 8.2.31 PFCPSMReq-Flags, 7.5.4.1 | SNDEM (end marker), DROBU (drop buffered) | not read | — |
| 7.5.2.5 (Create QER); 8.2.7 gate status, 8.2.8 MBR, 8.2.9 GBR | QER: MBR (UL/DL), gate status, one QER per session | in: the compiler writes a meter per policed direction and the gate's state; a closed gate compiles to the drop gate with no action | TestAClosedGateDropsWithoutAnAction; `ci/session-path.sh` counts the packets through the meter |
| 7.5.2.4 (Create URR); 8.2.54 URR ID, 8.2.40 measurement method, 8.2.19 reporting triggers, 8.2.13-8.2.14 thresholds, 8.2.50-8.2.51 quota, 8.2.44-8.2.45 measurements | URR: volume and time, thresholds, quota, reporting triggers | **partly in** — the URR IEs are read and validated (a field this UP cannot honour is refused with cause 73, `urrUnsupported`), the per-rule counters are in (see the Datapath table), the decision is in (`session.Evaluate` reads the counters, reports the period, a volume/time threshold or a volume/time quota, and stops the traffic of a spent quota until the SMF provisions a new one), and the report is sent: `upfd -urr-interval` evaluates every session on each tick and sends what is due as a PFCP Session Report Request over N4 (`internal/n4`'s `Report`, with retries and the Session Report Response routed back to the caller). What is not in: `Measurement Information` (its flags are refused by name rather than acted on: the clause text is not in hand, and a flag carried out by guess is worse than a refusal the SMF can act on). A report the SMF does not answer is no longer dropped: `upfd`'s reporting loop holds it (a bounded per-session queue, oldest report first, 4 per session and 256 sessions) and sends it before that session's newer ones, so the UR-SEQNs the SMF reads stay in order; a *refusal* is an answer and is not retried, a held report is retried with a doubling backoff capped at 30 s, a tick makes at most one attempt and stops its drain at the first unanswered send (so a silent CP function cannot turn the tick that enforces every session's quota into minutes of retries), and the log follows the doublings rather than the attempts. The time half is the dataplane's own measurement now: the counting module stamps each rule's first packet since the previous reading and its last one, the reading carries the wall clock it took them at, and the controller reports Time of First Packet and Time of Last Packet (8.2.44, 8.2.45) and measures a time threshold and a time quota against the window's running time | `internal/session`: TestATimeQuotaIsSpentByTheTimeTheTrafficRan, TestEvaluateReportsAUsedUpQuotaAndStopsTheTraffic, TestEvaluateReportsTheWindowItMeasured, TestEvaluateReportsThePeriodEvenWithNoTraffic, TestEvaluateTakesTheFirstReadingAsItsBaseline, TestEvaluateAllWalksEverySession, TestAQuotaExhaustedURRDropsItsPDRs, TestAMeasuredPDRThatDropsKeepsItsCounterEntry, TestAReportIsAUsageReportTheSMFCanRead; `cmd/upfd`: TestAnUnansweredReportIsSentAgainBeforeTheNextOne, TestARefusedReportIsNotRetried, TestTheReportQueueIsBoundedPerSession; `internal/bess`: TestPacketTimePlacesAStampOnTheWallClock; `internal/n4`: TestReportCarriesTheUsageAndTakesTheAnswer, TestAnUnansweredReportIsRetriedAndFails, TestAReportWithoutAnAssociationIsRefused; `ci/session-path.sh`: TestLiveSessionCountsTheRulesATURReasures (the rule's stamps are this run's), TestLiveQuotaEvaluationStopsTheTraffic; `ci/session-report.sh`: TestLiveUsageReportReachesTheSMF (a real upfd, a real SMF, the acknowledgement in upfd's log) |
| — | a restarted controller does not inherit its predecessor's dataplane state: `upfd` empties the session tables in one transaction before its PFCP socket opens | in (docs/design.md's restart wall, no PFCP clause): the sweep reads the session resources back, erases exactly the entries it found, key by key, and leaves every resource the graph itself declares; a dataplane it cannot read back is a warning at startup, not an outage | TestSweepNamesTheGraphsResources, TestSweepErasesEveryReadEntryInOneTransaction, TestSweepWithNothingToEraseWritesNothing, TestSweepReportsAnUnreadableDataplane, TestLiveStartupSweepErasesStaleSessions; `ci/n4-path.sh`'s restart step (a second controller against a daemon still holding the first one's session: the rules go, and the packets that crossed stop being selected) |
| — | session churn: an id released by a deletion is not reused until the dataplane's retire period has passed, and a restarted controller does not walk its predecessor's order | in | TestTheIDPoolWalksTheSpaceAndWaitsOutTheGrace; both live arms of `ci/session-path.sh` (the second one is what found it) |
| 7.5.2.8 (Create MAR); 8.2.123 MAR ID, 8.2.124-8.2.126 steering, 8.2.154 MPTCP, 8.2.155 ATSSS-LL | MAR/ATSSS | not implemented (phased, needs a dual-3GPP-access deployment) | — |

## Datapath

| capability | state | evidence |
|---|---|---|
| GTP-U v1 decapsulation: TEID match, outer headers removed, `upf_teid` reported | in | `datapath/`; `ci/smoke-gtpu.sh` (six checks, including that a TEID no session names is dropped) |
| GTP-U v1 encapsulation: outer Eth/IPv4/UDP 2152/GTP-U from the FAR's parameters | in | `ci/session-path.sh`, `ci/n4-path.sh` (byte-level, from the daemon's Dumps) |
| the whole path under one session: UL N3 (TEID table -> decap) -> PDR -> action -> meter -> the next hop's gate (N6), DL N6 -> PDR -> action -> meter -> GTP-U -> N3 | in | `ci/session-path.sh` (counters zero before the session, both directions after) |
| GTP-U echo request/response | not implemented, and no test drives one: an Echo Request (GTP-U type 1, TEID 0) names no session's F-TEID, so the TEID table drops it like any G-PDU whose TEID no rule matches (the drop `ci/smoke-gtpu.sh` checks). A peer running path management reads that as a dead path — the honest symptom until the milestone lands | `ci/smoke-gtpu.sh` for the drop, by inference for the message type |
| GTP-U end marker (type 254) | not implemented | — |
| DSCP copy inner -> outer | in: the encap writes the inner packet's TOS on the outer IPv4 header | `ci/session-path.sh` (the outer header carries the graph's EF mark, and fails without the copy) |
| per-rule counters (packets and bytes per PDR, so a URR can report them) | in: the `UrrCount` module counts the rules a URR's PDRs name, in the direction's chain behind the meter, and its `get_counts` action is the control-side read — the reporting side (`session.Evaluate` and upfd's `-urr-interval`) is in too. What is counted is the **IP packet's** octets (the inner IPv4 header's Total Length), not the frame's. The same reading carries each rule's first packet since the previous reading and its last one, with the wall clock read at that instant: that is what the duration half of a URR and Time of First/Last Packet (8.2.44, 8.2.45) are made of | `ci/session-path.sh`: TestLiveSessionCountsTheRulesATURReasures (37 octets per 51-byte frame, counted through the module's own command, and the rule's stamps asserted to be this run's); `ci/session-report.sh`: TestLiveUsageReportReachesTheSMF; `internal/bess`: TestPacketTimePlacesAStampOnTheWallClock; `internal/session`: TestAPDRATURReasuresIsCounted, TestAURRWithoutACountingModuleIsRefused, TestATimeQuotaIsSpentByTheTimeTheTrafficRan |
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
5. **QFI and Network Instance** (8.2.89, 8.2.4): the Network Instance is read
   and resolved now (row 8.2.4 above, `internal/routing`, `upfd -instances`);
   what remains of this gap is QFI (still one per session, and a PDI told apart
   only by QFI is refused rather than mis-programmed) and the vif that writes
   the route domain into an arriving packet, which is what puts a downlink
   rule's domain in its key on a real port (docs/design.md's port section, and
   the placement measurement the roadmap's hardware list holds).
6. **IPv6** — an explicit refusal, not a silent gap: a PDI naming an IPv6 UE
   address or SDF prefix is answered cause 73, because the classifier's four
   bytes cannot carry it and widening it would match other sessions' packets
   (TestANonIPv4PDIIsRefusedNotWidened), and an F-TEID IE asking for an IPv6
   address (CH with V6 and no V4) is refused for the same reason
   (TestACHOOSEForIPv6IsRefused), which is also why the FTUP bit above cannot
   promise an IPv6 F-TEID. The dataplane's tables, the two
   address fields and the TEID rule key would all need a second form; until
   then refusing is the honest behaviour, and this is what "IPv6 not
   implemented" means here.

(Gap 7 — FTUP's CHID — closed on 2026-10-17: the compiler reads the F-TEID's
CH and CHID flags, the session keeps one F-TEID per CHOOSE ID, and `upfd`
advertises FTUP where the session layer runs. See "Declared capabilities"
above for what proves it.)
