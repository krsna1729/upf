# Interface conformance

This page records Release 16 role evidence and the UPF's PFCP interface
behavior. `docs/spec/` holds official R16 excerpts; `docs/claims.json` is the
machine-checked contract and names the evidence.

Causes are PFCP causes: **66** is "mandatory IE missing", **73** is "rule
creation/modification failure", **75** is "no resources available".

## Project scenarios and Release 16 role scope

The six labels below are project-defined traffic scenarios, not a 3GPP
taxonomy. “Allowed” and “Conditional” describe the specified topology or
procedure. “Not established” means the pinned text does not establish that
topology; it is not a claim that 3GPP prohibits it. This status is separate
from whether the current graph implements it.

TS 23.501 §6.2.3 states that some or all UPF functions may be supported by one
UPF instance. This permits instance-level role co-residence. It does not put
all six scenarios into one PDU session: each PDU session keeps its own N4
session and topology, while 5G-VN group and handover state has the scope stated
below. The specifications define logical reference points and packet/session
behavior, not PMD, queue, Vif, or physical-port counts.

| Project scenario | Session and role scope | Reference points and PFCP shape | Pinned R16 status |
|---|---|---|---|
| 1 — PSA, N3 ↔ N6 | One ordinary PDU-session N4 context at a PSA. | N3 Access-side tunnel admission by F-TEID; N6 plain-IP path; downlink FAR toward Access carries the RAN Outer Header Creation. | **Allowed.** Ordinary PSA connectivity and N3 tunnel behavior (TS 23.501 §§6.2.3, 5.8.2.3.1, 5.8.2.10). |
| 2 — UL CL steering to local N6 or N9 | One PDU session with an UL CL and multiple PSAs; an UL CL may also host a PSA. Co-location is conditional on SMF/operator placement. | N3 ingress; UL CL rules steer uplink traffic to a local N6 PSA or an N9 tunnel to another PSA; downlink traffic returns toward the access tunnel. | **Conditional.** The SMF inserts and controls the UL CL; there is one UPF supporting the UL CL connected to the RAN over N3 except during relocation. Co-location with a PSA is explicitly permitted (TS 23.501 §5.6.4.2; TS 23.502 §4.3.5.4). |
| 3 — PSA receiving N9, forwarding to N6 | A PDU session traverses an N3-terminating I-UPF and a PSA; this UPF is the PSA role. These are distinct UPF roles, even when function capabilities share a process. | N9 terminates at the PSA as per-session CN Tunnel Info; N6 connects the PSA to the data network. The N9 arrival is the uplink, so its PDR names Source Interface Access (TS 29.244 Table 8.2.2-1 NOTE 1) with Source Interface Type N9 (8.2.118), which puts its F-TEID on the N9 endpoint; the downlink FAR back to the I-UPF names Destination Interface Access (Table 8.2.24-1 NOTE 1) typed N9. N6 egress is plain IP. | **Allowed** as the ordinary multi-UPF PSA path. TS 23.501 §5.8.2.10 names the N9 tunnel between an N3-terminating UPF and the PSA. |
| 4 — Cascaded N9-to-N9 transit | One PDU session's N4 context at an intermediate UPF whose upstream and downstream are both UPFs: an UL CL or Branching Point inserted behind an existing I-UPF, or a Source UL CL holding the N9 forwarding tunnel to a Target UL CL during UL CL relocation. | Uplink PDR: Source Interface Access typed N9, its F-TEID on the N9 endpoint, Outer Header Removal; FAR Core with Outer Header Creation toward the PSA. Downlink PDR: Source Interface Core on its own N9 F-TEID; FAR Access with Outer Header Creation toward the upstream UPF, typed N9 so the tunnel is sourced from the N9 endpoint. Neither PDR needs the UE address: the F-TEID identifies the session (TS 29.244 §5.2.1). | **Conditional.** The SMF updates "the existing UPF between the (R)AN and new inserted UL CL" via N4 (TS 23.502 §4.3.5.4 step 6), so the UL CL receives and sends on N9; with session continuity upon UL CL relocation, uplink traffic to PSA2 goes Target (R)AN → Target UL CL → Source UL CL and downlink the reverse (§4.3.5.7 step 3, NOTEs 2 and 4) until the N9 forwarding tunnel is released (steps 10–12). |
| 5 — 5G-VN local switching and N19 | At least two distinct member PDU-session/N4 contexts; the source and target sessions share one common PSA UPF, one 5G-VN group, and one controlling SMF. No group-level N4 session is required for local switching. N19 forwarding to members anchored at another PSA adds one group-level N4 session at each involved UPF. | Source member PDR uses Access-side CN Tunnel Info (N3 or N9) and FAR Destination Interface 5G-VN internal. Internal-interface classification matches the target member by destination address; its FAR carries OHC to that member's N3/N9 tunnel. The group-level session's N19 PDR (Source Interface Core, its F-TEID on the N9 endpoint) forwards to 5G VN Internal, and its 5G VN Internal PDR for a remote member's address tunnels over N19 (TS 29.244 §5.23). | **Conditional.** The same-PSA, different-PDU-session local-switch procedure is explicit. If N19 forwarding between different PSA UPFs is used instead, a group-level N4 session is required at each involved UPF (TS 23.501 §§5.8.2.13, 5.8.2.13.1, 5.29.4; TS 23.502 §4.13.8.2.2). |
| 6 — Indirect data forwarding during handover | An existing PDU session is temporarily modified at the selected S-UPF and/or T-UPF; this is handover state, not a second permanent user-plane topology. | Applies to N2-based inter-NG-RAN handover when direct forwarding is unavailable and the SMF chooses indirect forwarding. The S/T-UPF allocates or receives temporary N3 forwarding tunnel information through N4; the UPF forwards only along that procedure's endpoints. The SMF starts a timer and releases the temporary resources. | **Conditional.** This is the procedure in TS 23.502 §4.9.1.3: preparation steps 11a–11f, execution and cleanup steps 3, 10b (the old path's End Markers), 11, 13a–13b, and 15a–15b. It is not a generic FAR-routing mode. |

**Fixture scope.** `ci/scenario` holds one session per scenario role and a
stand-in SMF that sends each step as PFCP over UDP to `internal/n4`, the
same N4 node `upfd` runs. Mode 3 is S9; Mode 4 is S11, whose two PDRs carry
no UE address; N19 is S12, a group-level session beside its members S4 and
S5. Mode 6 is S10 (the S-UPF, an I-UPF) and S13 (the T-UPF, whose downlink
FAR drops until step 8a), driven through
the TS 23.502 §4.9.1.3 N4 steps: 11b and 11d each add a forwarding PDR with a
CHOOSE F-TEID on N3 and a FAR toward the next forwarding hop, and the UP
function's chosen F-TEID (11c, 11e) is what the lane then sends to (step
3b); 8a switches S13's downlink to the target RAN; the old path's End
Markers (10b) are sent to S10's and S13's F-TEIDs and relayed (below); the
SMF's timer (four seconds) starts after step 11; 13a releases S10 and 15a
removes S13's forwarding rules, after which S13 still carries its own traffic.
`ci/iface-path.sh` checks each step's packets at the exits by byte, and
`ci/veth-layouts.sh` runs every step on every attachment layout with exact
gate counts, every other scenario's session live.
`TestIndirectForwardingTunnelsFollowTheHandoverProcedure`,
`TestCascadedN9TransitUsesTheN9EndpointBothWays`,
`TestPSABehindAnIUPFTakesItsN9UplinkAsAccess` and
`TestN19GroupLevelSessionBesideItsMembers` check the compiled rules. N2
signalling and RAN behaviour are outside the UP function and not modelled;
the target UPF and RAN are scripted peers.

**End Markers through transit and forwarding tunnels.** A received GTP-U End
Marker is relayed through the GTP-U tunnel its F-TEID's PDR forwards into. TS
29.244 Table 8.2.64-1 NOTE 2 has the I-UPF keep the message type of a GTP-U
signalling message it forwards, and TS 23.502 §4.9.1.3.3 step 10b has the
PSA's End Markers forwarded toward the target RAN. Decap relays a received
End Marker in the packet path: the compiler writes, with each F-TEID's
admission entry (`<decap>/fteids`), one relay per distinct tunnel of a PDR on
that endpoint-scoped F-TEID whose FAR forwards with an Outer Header Creation
(TEID, local and peer address, transport route domain), and decap emits one
End Marker per relay with the FAR's TEID toward its peer, from the tunnel's
local address, on its gate 3. Through a `Queue` (`em_relay`) it reaches
`rt_transport`, which routes it like the encap's tunnels. A PDR whose FAR
ends the tunnel (N6, 5G VN Internal), drops, buffers or names a MAR relays
nothing. Decap still sends the marker to the GTP-U responder, which records it
for REEMR (`-gtpu-end-markers`). The relay leaves on the worker's next
scheduler round, never ahead of the G-PDUs that preceded it on its tunnel
(`ci/veth-layouts.sh` sends a burst of G-PDUs then the marker and checks the
order on the wire). `ci/iface-path.sh` (`m6_end_markers`) and
`ci/veth-layouts.sh` (every attachment of every layout) send the PSA's marker
to S10's N9 F-TEID, the source RAN's and the source UPF's to the two
forwarding F-TEIDs, and the PSA's to S11's N9 F-TEID (Mode 4): each leaves
once per marker sent, with the outgoing tunnel's TEID, from its local endpoint
to its peer, and no session chain counts it. The one sent to S1's uplink
F-TEID, whose FAR ends at N6, is relayed nowhere.
`TestEndMarkerRelaysAreWrittenWithTheirFTEIDsAdmission` checks the relays the compiler writes. The
appliance and session-major targets relay from the same entries in their own
packet path, emitting the relays after the burst the marker arrived in
(`TestLiveEndMarkerIsRelayedBehindItsGPDUs`: 16 G-PDUs and the marker in one
burst leave as the 16 G-PDUs, then one End Marker per tunnel). The
End Marker the UP function builds itself when the SMF asks (SNDEM) is
unchanged.

**Not supported.** Indirect forwarding without UPF re-allocation, where the
retained S-UPF forwards to T-RAN SM N3 forwarding information, is not driven.
The pinned text names no N4 message that releases the S-UPF's forwarding
resources in that case (13a applies to a source intermediate UPF that is
released, 15a to a re-allocated UPF).

**Co-residence boundary.** The UPF function statement permits a process to host
the function capabilities used by multiple specified scenarios. It does not
override a procedure's PDU-session, group, N4-session, peer-UPF, or temporary
tunnel requirements. The six-scenario claim is therefore limited to the
procedure-backed cases above, each under the condition its row names.

**Runtime coexistence boundary.** One `upfd` process owns one `bessd` graph and
is its only controller writer. That process can hold many independent
PDU-session contexts at once. The Mode 5 fixture establishes S4 and S5 as
separate CP F-SEIDs in the same compiler and common SMF/PSA (`ci/scenario`,
driven by `ci/ifacepath` and `ci/vethlayout`); the N19 fixture adds S12, the
group-level PFCP session, as a third F-SEID beside them. `internal/n4` accepts one CP-function
association at a time and rejects a second (`TestSecondCPFunctionIsRejected`).
Do not run a second `upfd` against the same `bessd`: each startup sweep erases
shared session-owned resources, and each compiler's ID and ownership state is
process-local. `TestCHOOSEIDStateIsScopedToPFCPSession` checks that the same
numeric CHOOSE ID in separate CP F-SEIDs gets distinct local F-TEIDs, and that
deleting one session releases only its own allocation. These are implementation
constraints, not 3GPP requirements.

## Topology and coexistence: evidence comparison (inspected 2026-10-23)

This compares one combined property: the project scenarios co-resident in one
process, endpoints and attachments set by deployment configuration rather
than fixed ports, and routed dual-stack outer transport. It is separate from
the scored competition blocks in `docs/claims.md` and does not change their
scores. Each row cites what the
project's own documentation or configuration shows. "Not shown" means the
inspected source does not establish the property; it is not proof that the
property is absent.

| Project | What the inspected source shows | Not shown by that source |
|---|---|---|
| This UPF | Endpoint-tagged ingress feeds one decap that admits by complete F-TEID key (`ci/veth-layouts.sh`: nine real-veth layouts on up to four promiscuous PMD ports, including the same TEID on two endpoints and every endpoint attached twice). Outer IPv4/IPv6 is routed per transport domain after encap with ARP/ND resolution: `ci/veth-transport.sh` shows both families resolved, the outer hop count decremented once with the inner untouched, End Markers through the same Router, a neighbor's MAC change followed, and an unreachable gateway failing closed. One compiler holds the sessions of scenarios 1, 2 (ULCL to N6 and to an N9 tunnel, and the remote PSA's N9 downlink), 3 (N9 arrival at a PSA, plain N6 egress), 4 (N9-to-N9 transit), 5 (local switch, and N19 through a group-level session) and 6 (indirect forwarding through S-UPF and T-UPF tunnels, the downlink switch, the timer and the release) at once, each set up by PFCP over N4: `ci/iface-path.sh` runs the streams of 1–6 and N19 together on one daemon, and `ci/veth-layouts.sh` drives every scenario through the compiled pipeline on every attachment of each layout. | Received End Markers are recorded and dropped, not relayed through a transit or forwarding tunnel (TS 29.244 Table 8.2.64-1 NOTE 2). Inner IPv6 UE PDRs are not supported. |
| [OAI UPF](https://github.com/openairinterface/oai-cn5g-upf/blob/develop/docs/FEATURE_SET.md) | N3, N4 and N6 implemented; uplink classifier listed as implemented. | N9 and N19 marked not implemented; branching point and I-UPF/PSA/ULCL marked not implemented. |
| [Open5GS](https://github.com/open5gs/open5gs/discussions/3090) | Several GTP-U server addresses, IPv4 and IPv6, each with a `network_instance` and `source_interface` ([`upf.yaml.in`](https://github.com/open5gs/open5gs/blob/main/configs/open5gs/upf.yaml.in)). | The maintainer's accepted answer says its UPF "lacks the N9 interface", which rules out the N9-dependent scenarios. |
| [free5GC](https://github.com/free5gc/free5gc.github.io/blob/main/docs/guide/5-install-ueransim.md) | `gtpu.ifList` entries typed N3 or N9 with listed addresses. N6 goes through host forwarding and NAT. | Not shown: all scenarios co-resident in one instance, or deployment-defined attachments beyond the address list. |
| [OMEC BESS UPF](https://github.com/omec-project/upf/blob/main/conf/upf.jsonc) | An `access` (N3) interface and a `core` interface that is "N6 or N9 (depending on the UPF's deployment [PSA-UPF or I-UPF])". | Not shown: N3, N6 and N9 at once, or more than two attachments. |
| [eUPF](https://github.com/edgecomllc/eupf) | Roadmap checks "Single & Multi-port support" and "I-UPF/A-UPF ULCL/Branching (N9 interface)". It configures IPv4 N3 and N9 addresses and relies on kernel routing. | Not shown: outer IPv6, deployment-defined endpoint-to-attachment mapping, or all scenarios co-resident. |
| [UPG-VPP](https://github.com/travelping/upg-vpp) | "IPv4 -- inner and outer" and "IPv6 -- inner and outer"; PDR/FAR support is "some parts"; Release 15. | N9 role combinations and attachment topology are not described: unknown, not unsupported. |

## Source Interface (TS 29.244 8.2.2, Table 8.2.2-1)

Source Interface identifies the logical side or internal interface on which a
PDR applies. It is not a universal UL/DL selector and it is not a physical
port. Access commonly names access-side traffic, Core commonly names N9 or
other core-side traffic, SGi-LAN/N6-LAN names the data-network side, and
5G-VN-internal names the second-stage local-switch path. Direction must come
from the matched PDR and its procedure, not from “non-Access”.

| Value | Name | What this UPF does |
|---|---|---|
| 0 | Access | Access-side ingress, commonly the RAN-facing N3 path. Many ordinary Access PDRs are uplink, but Source Interface alone is not a direction selector. A tunnel PDR carries the applicable F-TEID. |
| 1 | Core | Core-side ingress, including an N9 GTP-U path. The PDI carries CN Tunnel Info when the procedure uses a tunnel; plain N6 ingress has no F-TEID. |
| 2 | SGi-LAN/N6-LAN | Data-network-side ingress. The FAR's Destination Interface, not this value, determines the forwarding egress. |
| 3 | CP-function | Refused, cause 73. No user-plane packet is sent on the CP function's path. |
| 4 | LI function | Refused, cause 73. Interception is not implemented. |
| 5 | 5G VN internal | Internal second-stage classification for 5G-VN forwarding. It is not an external port or a synonym for downlink. |
| 6..15 | Spare | Refused, cause 73. |

An absent Source Interface IE is read as 0 (Access). Table 8.2.2-1 makes the IE
mandatory; this is a lenient default, not a claim of conformance. A deployment
that needs the strict reading should refuse the PDI instead of defaulting it.

An Access PDR claims resources for the packet direction and procedure its
matched PDR represents. A non-Access Source Interface does not, by itself,
make a PDR downlink. Resource selection must follow the matched PDR's
procedure, not a `srcIfc != Access` test.

## Destination Interface (TS 29.244 8.2.24, Table 8.2.24-1)

The FAR's Destination Interface, together with whether the FAR carries an Outer
Header Creation, is the key of the deployment's egress table
(`internal/routing.Interface.Hops`). With `-instances`, a deployment declares
`next-hop=`, `tunnel-next-hop=`, `sgi-lan-next-hop=`, `vn-next-hop=` and
`-access-next-hop`; without `-instances`, the single-instance deployment falls
back to the direction's own hop for the values it has always served.

| Value | Name | What this UPF does | Refusal |
|---|---|---|---|
| 0 | Access | Access-side forwarding endpoint. A FAR with Outer Header Creation uses its configured tunnel record; Source Interface and packet direction do not follow from this value. For handover Mode 6, the temporary endpoints and lifecycle in TS 23.502 §4.9.1.3 are also required. | Cause 73 if the tunnel module is unset. |
| 1 | Core | Core-side forward. Without Outer Header Creation, plain IP uses the instance's `next-hop`; with it, the configured tunnel record carries the packet toward a core peer. The FAR alone does not establish an N9 procedure. | Cause 73 if the instance declares no such egress, or the tunnel module is unset. |
| 2 | SGi-LAN/N6-LAN | The instance's `sgi-lan-next-hop=` (plain or tunneled by the same key's `Tunnel` bit). The Forwarding Policy IE is mandatory toward this value (Table 7.5.2.3-2). | Cause 66 if the Forwarding Policy is absent; cause 73 if the deployment declares no service-LAN egress. |
| 3 | CP-function | Not served. | Cause 73. |
| 4 | LI function | Not served; an X3 copy is a duplication action, not this forward. | Cause 73. |
| 5 | 5G VN internal | Re-injection into the subscriber side; the instance's `vn-next-hop=`. An outer header is refused: this is the UPF's own chain, not a tunnel. | Cause 73 for a missing egress or an outer header. |
| 6..15 | Spare | Not served. | Cause 73. |

A FAR whose Apply Action forwards must carry Forwarding Parameters (Table
7.5.2.3-1) and a Destination Interface (Table 7.5.2.3-2); either omission is
cause 66. An Update FAR carries only what changes, so the check is made on the
merged FAR, not on the message's own IEs.

The Outer Header Creation and Destination Interface identify a tunnel-forwarding
shape, not a complete traffic scenario. Mode 6 is specifically conditional
handover indirect data forwarding: TS 23.502 §4.9.1.3 requires the handover
decision, temporary N3 forwarding tunnel information allocated or supplied
through N4, and timer-based resource release. A generic FAR with an outer
header does not prove that lifecycle or make arbitrary tunnelling an indirect
forwarding procedure.

## Update PDR (TS 29.244 Table 7.5.4.2-1)

An Update PDR carries only the IEs that change, and the UPF keeps the stored
value of every IE it leaves out (NOTE 1):

| IE | Row | Absent | Present |
|---|---|---|---|
| Precedence | present "if there is a change in the PDR's precedence" | kept | replaces |
| PDI | present "if there is a change within the PDI" | kept | replaces the whole stored PDI; an F-TEID it leaves out is kept |
| FAR ID | present "if it needs to be changed" | kept (with a MAR the PDR names) | replaces; a MAR ID in its place replaces it the same way |
| URR ID, QER ID | present "if ... applied or no longer applied"; the list of all IDs | kept | the list replaces the stored list |
| Outer Header Removal | present "if it needs to be changed" | not read from any PDR | not read |

An Update PDR for a PDR the session does not hold is cause 73. An empty URR or
QER list has no encoding, so a PDR's last URR or QER is not dissociated by an
Update PDR. Remove URR / Remove QER does it: the rule goes and its ID leaves
the URR or QER list of every PDR that named it (TS 29.244 5.2.2.3.1, 5.4.5).
A removed URR's final usage is reported (TERMR) in the Modification Response,
and the PDR forwards on without the counter or meter. A URR another URR still
links to (8.2.55) stays refused (cause 73).

## The subscriber's ARP answer

An N6 segment is Ethernet: before a downlink packet addressed to a UE can be
sent, the next hop asks ARP who holds the UE's address. The SMF provisions that
address, and this UPF is what it is reachable through, so the answer must be
this UPF's.

| Item | Behaviour |
|---|---|
| Configuration | Per network instance: `arp=<module>` and `arp-mac=<MAC>` in `-instances`. The MAC is the interface's own, not the UE's. |
| Resources | One `<module>/entries` entry per session per subscriber IPv4 address (`{"ip": ..., "mac_addr": ...}`). |
| Claims | The entry is a compiler claim, like a rule key: two sessions cannot answer for the same address on one interface; the second is refused with cause 73. |
| Lifecycle | The entry is written when a subscriber-side PDR names the address and erased when that PDR or the session goes. A session with downlink PDRs on two instances answers on both. |
| IPv6 | No entry is written for an IPv6 address; no ND responder is implemented. |
| Placement | `UpfArpResponder` answers ARP on gate 0 and passes IPv4 on `ip_gate`; it must sit on N6 ingress before the Vif (`deploy/upf.yaml`, `ci/iface-path.sh`). Other packet types are dropped. |

TS 23.501 6.2.3 makes the ARP/ND responder a UPF function for Ethernet PDU
sessions. For IP PDU sessions this is not an SMF-visible function at all: it is
the deployment's N6 reachability duty. A segment that never learns the UE's MAC
drops the downlink before the packet reaches this UPF, whatever the PFCP rules
say.

## Related documents

- `docs/router.md` — the Router's inventory, and the routing gaps (route
  programming, connected routes, neighbour resolution).
- `docs/datapath.md` — the modules, the graphs and the lanes.
- `docs/claims.json` — the cited evidence for each row above.
