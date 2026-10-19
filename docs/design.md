# Design

The architecture, the walls and the costs. The datapath's own engineering
reference -- module by module, resources and keys, what it takes from BESS,
placement and state locality -- is `docs/datapath.md`.

## Deployment shape (fixed by the deployment decision)

- **One `upfd` process.** It terminates PFCP/N4 (UDP 8805 server), owns the
  session store, and is the *only* writer of BESS state. No second controller,
  no per-session workers, no sidecar.
- **One `bessd` process**, with the UPF datapath loaded as a plugin
  (`datapath/`, built against the installed `bess-dev` stage, loaded with
  `--modules=`). One graph, one set of workers, one packet path. Bess has no
  supported hook for compiling extra sources into the daemon (no meson option
  does it; D-008 puts UPF-specific code in a plugin), and a
  plugin may use only the installed headers, of which the GTP-U codec and the
  conntrack parse types are experimental.
- The controller is stateless with respect to the dataplane: it can restart and
  rebuild everything from BESS's own state (pipeline + resources) plus the
  PFCP sessions the SMF replays.

## The control path in one sentence

A PFCP session change becomes **one control_v2 transaction**: the session's
PDR rules, its action, its meters, its next hop and its route go in together or
not at all, with a request id that survives retries, and no other writer exists
to race.

## Mapping PFCP → BESS

| PFCP | BESS |
|---|---|
| PDR (Precedence, PDI: Source Interface, F-TEID, Network Instance, UE IP, SDF filters, QFI) | one rule in the PDR table (WildcardMatch over masked keys) whose result is `{gate, ActionId}`; the rule's priority is the Precedence inverted (8.2.11's lower value is the higher precedence, the classifier applies the higher priority), and the QFI is the last key field where the graph declares it, so one session's several QoS flows are several rules; a port *range* is refused on this path — the opt-in firewall path below carries it, and see the OMEC table below |
| F-TEID the CP function asks the UP function to choose (8.2.3: the CH flag, and CHID for a group the CP function names) | one TEID rule in front of the decap per F-TEID we allocate; the PDIs of a session that carry one CHOOSE ID share the F-TEID the session gave that group, so an SMF's several filters on one tunnel are one rule and one Created PDR value |
| FAR (Apply Action, Forwarding Parameters: Destination Interface, Network Instance, Outer Header Creation) | a *treatment* resource the action references (forward / drop / buffer / notify) plus the next hop and GTP-U encap parameters |
| QER (Gate Status, MBR, QFI) | a meter resource per QER, referenced from the action; its QFI goes into the tunnel record, where the encap writes the downlink packet's PDU Session Container from |
| URR (Measurement Method, Reporting Triggers, thresholds, period) | per-rule counters in the `UrrCount` module, one entry per rule a URR's PDRs name, keyed by the rule's ActionId, plus the decision in `session.EvaluateAll` -- one bulk reading per counter module per tick, every session judged in memory against it -- and `session.Evaluate`, the single-session reading that names its own rules: it reads the module's counters, reports the period, a threshold or a quota, and stops the traffic of a spent quota. Every limit and the period are measured over the usage since the URR's last report (a report opens the next window), which is the window the report itself carries; the alternative -- accumulate from provisioning and compare the running total -- needs a second base per URR, and the SMF's lever (an Update URR that provisions a new quota, which clears the flag) is the same either way. Time is the dataplane's own fact: the counting module stamps a rule's first packet of a reading and the last one it counted (one stamp pair per rule, shared and stored once per counted batch -- a timestamp is the rule's, not a worker's), the reading carries the wall clock it took them at, and the controller places them on the clock an SMF reads; a reading the reporting side makes closes the window and the next packet opens the next one, while a diagnostic read of the same command leaves it alone. A time threshold and a time quota are then measured against the time the *window's* traffic ran -- the window's own first packet to the reading's last -- which is the base the volume limits use too, with the idle gaps taken out of it. A graph whose counters carry no stamps falls back to the window's length, the same number while the traffic is continuous. Sending the report as a PFCP Session Report Request is `internal/n4`'s `Report` (the one exchange this node initiates, with retries and the Session Report Response routed back to the caller), driven by `upfd -urr-interval`; a report the SMF does not answer is held by the loop (a bounded per-session queue, the oldest report first, so the UR-SEQNs the SMF reads stay in order, retried with a doubling backoff and at most one attempt per tick, since each attempt costs the n4 layer's whole retry budget) rather than dropped, because an unanswered send leaves the outcome unknown while a refusal is an answer. Two facts hold the counters together: a rule's entry exists exactly while a URR measures it (a rule that drops keeps it, so an erase always finds it), and the first reading of a URR is the window's baseline (the cells outlive an erased entry and the id pool reissues ActionIds, so a fresh rule's first reading may hold the previous holder's totals) |
| Session (CP F-SEID, UP F-SEID) | one transaction's worth of resources, all named `<session-id>/…` |
| Network Instance (N3/N6/N9) | a route domain; overlapping subscriber prefixes never collide because each domain has its own table |
| Outer Header Creation (TEID, peer address) | the tunnel encap parameters of the treatment |
| BAR (DL Buffering Duration, DL Buffering Suggested Packet Count) and the BUFF Apply Action | the deployment's own packet store (BESS's `packet_store`) on a branch the BUFF rule delivers to, keyed by the rule's ActionId; the first buffered packet is reported to the SMF as a Downlink Data Report, and the SMF's next instruction releases what is held. Two facts to know: the store's caps and timeout are the SMF's own per-flow numbers where its BAR gives them -- the compiler writes a `flows` entry per buffering rule, `timeout_ns` from 8.2.29 and `max_packets_per_flow` from 8.2.30, each left out where the SMF named none, so a flow without an instruction of its own falls back to the module's arguments (`requires_paused_workers: false`; the store enforces the cap on every arrival and frees a flow's packets past its timeout on the owner's own sweep — `EvictExpiredBounded`, 256 flows a run, since BESS 0bfd2783; an older daemon freed only at its global `max_packets`), and the DDN trigger is a *poll* -- the branch's counters read once per `-urr-interval` tick, so the report's latency is up to that tick and a deployment that wants DDN must set the interval; BESS's bounded dataplane->control event channel (G1.4) is what replaces the counter hop |
| Path management: an Echo Request (TS 29.281 7.2.1) and an End Marker on a FAR that moves (5.3.2's SNDEM, 7.3.2) | the echo is the datapath's -- the TEID table's default gate is the `gtpu_echo` module behind it, so a message no session names is answered or dropped there, not in the packet path; the end marker is the controller's -- `upfd` builds the 60-byte frame (old TEID, old peer, N3 source) and writes it to the graph's `unix_port` after the transaction that switched the tunnel has landed, because a marker is a message this node *sends*, not state a transaction can hold |

The datapath therefore never chases relations: the PFCP side resolves
`PDR → QER/FAR` once, at programming time, and the packet carries an
`ActionId` that names the resolved object graph.

## The packet path, and how its cost is proven

The mapping above is a claim about *structure*. This section is the claim about
*cost*, and it is the one that has to be measured.

**Work per packet, in order:** parse up to the key (fixed offsets, no branches on
well-formed input) → one classifier lookup → one action-record read → the treatment
the record names → egress (route lookup, or the tunnel header the record carries).
One lookup and one record read, whatever the session contains: a session with a QER,
a URR and a BAR costs the same steps as one with none. The compiler resolves
PDR → QER/FAR/URR at install time; the packet path never chases a relation.

**The key** is what a BESS classifier can read: *packet* bytes at an offset. A
classifier's fields are `{offset, num_bytes}` (`bess::pb::Field`, `module_msg.proto`;
`bessctl/conf/samples/session_pipeline.yaml` uses offset 26 for the IPv4 source), and
metadata attributes are not matchable. The TEID of an uplink G-PDU sits in the outer
header the decap module strips, so after decap it exists only as metadata -- but
*before* decap it is packet bytes at a fixed offset (Eth 14 + IPv4 20 + UDP 8 + the
GTP-U header's flags, type and length 4). The F-TEID is therefore a **rule** of the
table in front of the decap, one per session:

- `teid/rules` holds one rule per session: the four bytes of the TEID, masked all
  ones, whose gate is the decap's output. A G-PDU whose TEID no rule names never
  reaches the decap (the table's default gate drops it), so the decap needs no
  session table at all: it strips headers, writes `upf_teid` and passes the inner
  packet on (TS 29.281 answers an Error Indication to the peer -- the responder
  behind the table's default gate does, 7.3.1; the notification path to the SMF
  is a later item, finding 15). This is also the *whole* cost of the F-TEID
  match, and it
  is one hash lookup, the same table machinery every other rule uses.
- A *session table* in the plugin was the first design, and it does not work: the
  fork's `SlotResource` keys are dense ids in `1..capacity` (`slot_table.h`), and a
  TEID is an arbitrary 32-bit id (0x11223344 is a plausible one). The rule table has
  no such constraint, and it inherits the classifier's transactional model (D-141)
  and its reference checking.
- the decap writes `upf_teid` for the modules downstream that read it. A
  write-only metadata attribute no module reads is not allocated at all -- the
  pipeline gives it `kMetadataOffsetNoWrite` (`core/metadata.cc`,
  `FillOffsetArrays`: "attr not read downstream") -- so a graph that wants the TEID
  in metadata must contain a reader, and `deploy/smoke-gtpu.yaml` has one.
- the PDR rules match what the PDI names after the F-TEID: the UE IPv4 address and the
  SDF tuple (protocol, ports, at their fixed offsets). `WildcardMatch` masks make
  "UE IP only" and "UE IP plus 5-tuple" the same table.
- a PDR whose PDI names *only* an F-TEID (no UE IP, no SDF) cannot be selected by a
  packet classifier. The compiler refuses it with a PFCP cause instead of installing a
  catch-all rule, which would hand one session's traffic to another's action. Real
  SMFs put the UE IP in the PDI; the interop milestone checks that against open5gs
  rather than assuming it.

**Framing.** The graph carries Ethernet frames: BESS's core modules read IPv4 behind
an Ethernet header (`core/modules/ip_lookup.cc` reads `eth + 1`), so the decap leaves
the inner packet behind a header it writes from the headroom the outer headers
occupied (the outer frame's addresses, the inner packet's version), and the encap
takes that header off before it writes the outer one -- a G-PDU's payload is the inner
IP packet, not a frame (TS 29.281). Neither direction copies a payload byte, and
each egress names its peer in that header itself: the encap builds the outer
frame's addresses from the tunnel record, and the `Router` writes the resolved
next hop's `dst_mac`/`src_mac` into the frame it forwards (BESS D-153) -- so a
frame leaving N6 names the data network's next hop and the interface it left by
(`deploy/upf.yaml`'s hop 1, byte-checked by `ci/session-path.sh` at `dump_n6`).

**Two chains, one per direction.** A module has one output gate per path, and a rule
names an `ActionId` that resolves against the actions resource its table declares
(D-141). One classifier table and one action table therefore cannot serve both
directions: the uplink's meter feeds the router toward N6 and the downlink's feeds the
tunnel toward N3, and a downlink rule's action lives in the downlink table. The graph
has `pdr_ul → at_ul → mt_ul → rt` and `pdr_dl → at_dl → mt_dl → enc`, each table
declaring its own chain's actions resource, so every rule's reference is exact.
`deploy/session-live.yaml` is that graph (module names: the session layer's `Config`).

Both results — the gate and the ActionId — come from one lookup
(`{gate, ActionId}`, the BESS-side item *Classifier result model*).

**The firewall path (opt-in).** A direction may name a BESS `firewall` module
instead of its WildcardMatch table (`session.Direction.Firewall`, `upfd
-firewall-ul`/`-firewall-dl`). Its table is tuple space over the *masked fields
alone* — one group per (family, protocol, source prefix length, destination
prefix length) — and a rule's ports are checked after its group's key hits, so
a port **range** costs it no group, no mask and no entry (BESS D-147); IPv4 and
IPv6 rules live in one policy. Those are the two shapes a 4-byte mask cannot
carry, and they are what the WildcardMatch path refuses rather than widening
(`internal/session`: the SDF's port range, and a prefix that is not IPv4).

Three things follow from the module's own shape, and they are what a deployment
has to know before naming one:

- **The policy is written whole.** `<module>/rules` is a *singleton* holding the
  ordered policy, and the module builds the table whole and swaps it. So the
  compiler writes every live session's rules of that module, not one session's:
  a write of its own would erase the rules of the sessions already programmed,
  and a packet no rule matches is *dropped*, not passed. The order is the
  spec's own — TS 29.244 8.2.11 has the lower Precedence value win and a
  firewall list applies its first matching rule, so the list is sorted by
  Precedence ascending, with no inversion (unlike `rulePriority`, where the
  classifier applies the *higher* priority).
- **A rule is a match, not an action.** `FirewallArg.Rule` carries
  `src_ip`/`dst_ip` (CIDR strings whose length is mandatory), `proto`, the four
  port-range fields and `drop`; the module's only words are drop and pass, it
  passes a matching packet on the gate it arrived on and writes no packet
  metadata. So a firewall rule cannot name the ActionId or the next hop the
  WildcardMatch path's rule names, nor the PDI's QFI, the route domain or the
  tunnel: those stay fields of the WildcardMatch key, and a deployment that
  wants meters, tunnels or per-rule counters behind the classifier needs BESS
  to carry an action word in the rule first. A PDR that buffers is refused on
  this path for the same reason (its packets are delivered on the store's gate,
  and a firewall rule has only the one it arrived on). What the two paths do
  share is the choice of sides: the uplink's rule is its UE address (or the
  SDF's source), the downlink's is the SDF's destination or the UE's.
- **No deployed graph names the module.** It is BESS's D-147 work and is not in
  the stage the `ci/` arms run against, and a graph that names a module the
  daemon does not have fails to load — so no `deploy/*.yaml` graph carries it,
  and the flag is the only way to ask for the path. Nothing about this changes
  a deployment that does not pass it: with no module named, both directions are
  the WildcardMatch table with its refusals
  (`TestTheFirewallPathIsOptIn`).

**The action record** (one cache line, read once, never written by a worker):

| offset | contents | written by |
|---|---|---|
| 0 | treatment (forward / drop / buffer / notify) and the next-hop id | FAR |
| 8 | route domain and the outer-header template (TEID, peer address, ports) | FAR, Network Instance |
| 24 | meter id, the QER's gate state, QFI | QER |
| 32 | counter ids (bytes UL/DL, packets UL/DL) | URR |
| 48 | buffer class, the BAR's duration, suggested packet count | BAR |
| 60 | flags: which of the above are present, so an absent feature is a branch not taken | compiler |

**Per feature, per packet** — the "the base path does not move" obligation, as the
costs the arms below are expected to confirm:

| provisioned | extra work on a packet that uses it | on one that does not |
|---|---|---|
| FAR forward | none beyond the record read; the next hop is in the record | — |
| outer header creation (GTP-U) | header write and the tunnel-table lookup: measured +63 cycles/pkt (below); outer UDP checksum 0, so no recompute | — |
| QER MBR | token-bucket update | 0 |
| QER gate closed | drop | 0 |
| URR volume and time | two additions into worker-local counters (relaxed), plus the rule's stamp pair written once per batch that counted it (shared) | 0 |
| BAR | a slot write, only on a buffered packet | 0 |
| ULCL / branching | one route-domain select from the record | 0 |
| echo (TS 29.281 path management) | one parse and a 67-byte reply, on a message no session's rule matched | 0 |

**State policy (the path to 400G).** What the *controller* writes is shared and read,
never written, by the packet path: one classifier table and one `ActionTable` per
direction (`classifier::ConcurrentMaskedTable`, `dataplane::SlotTable` -- a rule or a
record exists once for every worker, and a configuration change is published as a new
generation), so a session's rules cost memory once rather than once per worker. What
the *packet path* writes is per-worker: URR counters are worker-local and summed by the
reporting task (no atomics in the path). Policing is the one state that has to be shared
at the point of decision, because it cannot be summed after the fact: a counter's read
is order-free and can be taken later, but a rate's decision -- the colour *this* packet
gets -- is this packet's. MBR policing goes through the `Meter` module, which creates
every controller-written meter as `kShared` (`core/modules/meter.cc:158`;
`Reconfigure` keeps the mode, so it is `kShared` for the meter's life): one token
bucket, each check under the meter's own spinlock. The rate is therefore enforced
*once* regardless of how many workers a session's flow reaches; the cost is
serialization on one cache line, not N times the rate. `kWorkerExclusive` would remove
the lock but requires the flow to be pinned to one worker, and no control-plane path
selects it today (`datapath/` and `internal/` name no sharing mode, and the graph's
`Meter` takes none).

The counterpoint is NAT, where a shared table is the multi-worker mode by *decision*
rather than by default: a binding cannot be partitioned at all -- the rewrite changes
the tuple, so the two directions hash differently, and endpoint-independent mapping
needs every flow of an internal endpoint on one worker -- so a shared multi-writer
table is the only mode above one worker (BESS's design scratch,
`.scratch/design/table_policy.md`, §5.1; its decision 6: NAT never uses rte_flow
steering, `SHARED` is the multi-worker mode). The URR counter plane is priced by that
plan's own table rather than by a new one: `table_policy.md`'s benchmark plan, its
Usage counters (G5) row in §7a -- per-packet cost of NoUsage vs InlineUsage vs
AtomicUsage vs PerWorkerUsage at 1-8 workers, NoUsage's disassembly identical and the
costs reported.

**Install order, one transaction.** Resources first (meters, counters, next hops,
routes), then the action record, then the rule that names it. A worker that wins the
lookup can then never read a record whose resources are missing — publication is the
classifier hit. Removal is the reverse, and the record goes after a grace period
longer than a worker's longest batch.

**Modification.** A QER or FAR parameter change rewrites the record in place (one
cache line under RCU): no rule change, no classifier touch, no worker pause. A PDR key
change adds the new rule before removing the old one. Only a graph change (modules,
ports, workers) goes through `ApplyPipeline`.

**How it is measured** (`tests/perf/live_perf.cc`, the instrument CI runs):

- Every `M.*` test is a chain with a control arm: `M.base/<frame>` is the same chain
  with `Bypass` in the module's slot, so a test's number is that module's cost *in
  composition*, not in isolation. A module that needs a different frame (a tunnel)
  must bring its own control arm, or the frame's size leaks into the delta.
- `--counters` adds instructions and cycles per packet for the window (`perf stat`).
  The table above is filled from those arms, same burst size, isolated core.
- The obligation in one line: the base-path arm and the arm with the feature
  provisioned must agree to within the feature's own arm. A run where they do not is a
  design bug, not a number to explain away.
- The plugin's own arms (`GtpuDecap`, `GtpuEncap`) run the same tool with
  `--plugin <plugin dir>`, which appends `--modules=` to the daemon command: that is
  the UPF's perf run, not BESS's, because those modules are not in BESS's tree.
  `M.urr_count.base`/`M.urr_count`/`M.urr_count.empty` are the counting module's
  three arms -- its control, a counted rule, and the module with no entry (the
  one-lookup path a graph that charges nothing pays). Their numbers are in the
  run recorded below: the arms exist so the stamps' per-batch cost is measured
  rather than claimed.
- `ci/bench-modules.sh` is the thin wrapper: it records the stage and plugin build the
  numbers came from and prints each arm against its control.

**Taken 2026-10-16** on this host (P-cores, performance governor), release daemon and
release plugin, four rounds on one isolated CPU with the control thread on another:

| arm | ns/pkt (above `M.base`) | instructions/pkt | cycles/pkt | over its control |
|---|---|---|---|---|
| `M.base` (the front end) | 8.09 | 119.8 | 25.5 | -- |
| `M.gtpu_decap.base` | 15.52 | 368.6 | 75.1 | -- |
| `M.gtpu_decap` | 28.89 | 612.4 | 119.3 | **+13.4 ns, +244 instructions, +44 cycles** |
| `M.gtpu_encap.base` | 1.19 | 133.8 | 31.9 | -- |
| `M.gtpu_encap` | 19.32 | 414.5 | 94.9 | **+18.1 ns, +281 instructions, +63 cycles** |

Both instruments agree (44 cycles at ~3.3 GHz is 13.3 ns, 63 is 19.1 ns), which is what
makes a pair reading trustworthy. The frames are the smoke test's, byte for byte: the
decap's number is the uplink's F-TEID path, the encap's is the downlink's outer header.

Reproduced the same night by a second `ci/bench-modules.sh` run: delta +13.54 ns and
+244.1 instructions for the decap, +18.21 ns and +280.9 instructions for the encap
(+46.1 and +64.4 cycles). The instruction counts reproduce to 0.2, which is what a
publishable module cost looks like.

**The counting arms, and the owed re-run (2026-10-17).** The three `M.urr_count`
arms were taken by `ci/bench-modules.sh` inside the host's perf slot --
`WRAP="taskset -c 2,4" ROUNDS=4 slot perf ci/bench-modules.sh`, so no build ran
while the window was open -- pinned to CPUs 2,4, the governor as found (`powersave`
on the measured CPU, `no_turbo=0`, i.e. turbo on: `slot perf` changes neither, and
`perf stat` needs `perf_event_paranoid <= 0`, which this host sets to 2), plugin
519584 bytes of 2026-10-17 (the DSCP copy is in), the daemon and the tool from
`build/fast`:

| arm | ns/pkt (above `M.base`) | over its control |
|---|---|---|
| `M.urr_count.base` | 1.21 | -- |
| `M.urr_count` | 5.40 | **+4.19 ns for a counted rule** |
| `M.urr_count.empty` | 2.55 | **+1.34 ns with no entry** |

The four rounds' paired deltas: a counted rule 3.69-4.46 ns, no entry 1.09-1.64 ns.
From the same run, the module arms: decap +12.45 ns (paired rounds 12.20, 12.35,
15.09, 12.30 -- round 3 sampled 39.7 ns against its own 24.7 ns control) and encap
+17.77 ns (17.49-18.03 paired) -- the encap's cost *with* the DSCP copy, which is the
re-run the section owed. An earlier run of the same arms with `taskset` alone gave
+3.88 and +1.56 ns, within 0.3 ns of these: the shape was right, and these are the
figures. There is no instruction column, so the 2026-10-16 run's instructions/pkt
remain the only ones on record, and the two runs' conditions differ (that one on an
isolated CPU at the performance governor).

**After that measurement** the encap learned to copy the inner packet's TOS to the
outer header (the DSCP copy; `ci/session-path.sh` checks the outer header carries the
inner class). Its re-run is the 2026-10-17 run above (+17.77 ns over its control; an
unisolated cross-check had put it at +16.88 ns against the +18.1 here, which is the
between-run spread an unpaired run can see). What the re-run had to work around is the
wrapper's child: it writes nothing and exits 1 —
measured today, and it is **`--cpu` rather than `--isolate`**: `omarchy-benchmark
--cpu 4 -- /bin/echo` exits 1 without running the command (its launcher's status is
1, and it restores the machine on the way out), `--cpu 4 --isolate` the same, while
the same command with no CPU selection runs — so `ci/bench-modules.sh` now fails
loudly when its report is empty instead of `sed`-ing nothing and exiting 0. It is
not a privilege problem: `sudo -n true` succeeds on this host, and the wrapper
does restore the CPU, turbo and governor state it touched.

**Fusion decision from these numbers.** The decap is 44 cycles, the encap 63, and the
classifier in front of the decap is ~49 (its control above `M.base`, including its rule,
the attribute reader and two hops). Fusing parse-and-classify would save the hop between
them (2-4 cycles) and the metadata write (one store): under 10% of what the pair costs,
in exchange for a forked classifier that would have to carry every future WildcardMatch
change. They stay two modules.

**The composition's rate**, for the shape the lab can offer -- this is
`deploy/session-path.yaml`, the bench graph, not a claim about a deployment
graph (whose module count, ports and NIC decide its own number): the whole
graph (both chains, the plugin's decap and encap, one session programmed over
N4) carries 7.25 Mpps per direction and 14.5 Mpps together on one worker core
-- three rounds of `ci/bench-graph.sh`, 7.254/7.273/7.254 Mpps. That is
the ceiling of the graph's own generator, whose `Source` bursts at most 32 packets
(about 227K scheduler iterations a second), so it is a floor for the chains rather
than their limit; the per-packet numbers above are what bound them. The same run
shows the meter working: the session's QER MBR (1000 kbit/s, from `cmd/n4bench`'s
message) lets 0.003 Mpps of the uplink's 7.25 through to N6, which is the 0.0025 Mpps
that MBR allows for 51-byte packets plus a token bucket's slack.

## What is deliberately not copied from OMEC

| OMEC pattern | Why it is unnecessary here | What this repo does instead |
|---|---|---|
| A goroutine and a `ModuleCommand` per PDR/FAR/QER, unordered; `SendMsgToUPFWithCompletion` per session | BESS's transaction engine orders, validates and rolls back server-side; a client that orders internals has to reimplement all of it | one `Transaction` per session change, `WithExpectedGeneration` when the caller has a generation in hand |
| Cartesian expansion of port ranges into many rules | a range is a set of masked values **per field** (an n-bit field decomposes into at most 2n-2 masked entries), and a rule whose masks cover several fields matches the *product* of those per-field sets: a two-port range is up to 30x30 entries, a smaller product than OMEC's naive expansion but still a product. `max_tuples` is the budget that bounds it, and a rule whose masks cannot carry the constraint is refused rather than widened (docs/compliance.md) | one rule per PDR with a masked key, and the opt-in firewall path (above) for the ranges that key cannot carry: a range there costs no group, no mask and no entry |
| Client-side establishment, then a second pass to modify | desired state is the model: `ApplyPipeline` diffs and plans, and resource contents ride along in the same call | `Pipeline` + `PlanPipeline` before a change, `ApplyPipeline` for topology |
| Retries, idempotency and "did it apply?" reinvented in the client | the SDK owns it: one request id per logical transaction, `GetTransaction` after an unanswered send, `DaemonRestartedError` when the epoch moved | `internal/bess` wraps exactly that and nothing else |
| State in the controller that the dataplane also holds (and they drift) | the dataplane is the state of record; sessions are reconstructible | the controller keeps only what PFCP needs (session ids, SEIDs, the last reported counters) |

## PFCP on the wire

The codec is [`github.com/wmnsk/go-pfcp`](https://github.com/wmnsk/go-pfcp),
pinned at v0.0.24, its newest release tag. It is pure Go, MIT, and the
implementation the surrounding ecosystem builds on: OMEC's UPF and its many
forks depend on it, while free5GC's SMF uses its own `free5gc/pfcp` +
`free5gc/tlv` stack. We carry one codec, not two — a second one would be a
second thing to get wrong on the interface that faces another vendor's SMF.
What the library deliberately leaves out is what `internal/n4` adds:
association and session management, sequence numbers, restart detection, and
the state machine.

Facts about the pinned version, read in its source rather than assumed:

- The header's flag bits are S = bit 0, MP = bit 1, FO = bit 2, and the version
  is bits 7-5 (`message/header.go`), as in TS 29.244 figure 7.2.2-1.
- `Header.SetMP` sets bit 2, which is FO, while `HasMP` reads bit 1: do not
  call it. Messages are built with the `message.NewXRequest`/`NewXResponse`
  constructors, which set the bits correctly.
- `message.Parse` falls back to `Generic` for a message type it does not know,
  so a type a later release adds arrives without an error and is ignored here,
  as TS 29.244 7.2 requires.
- `IE.ReportingTriggers()` requires **two** octets (`len(Payload) < 2` is an
  error) while the IE's own octets 6 and 7 are present only when the SMF sets a
  bit in them (8.2.19): a periodic-only URR is a one-octet IE, and the accessor
  reads it as malformed. The compiler reads the IE's payload itself
  (`internal/session/compile.go`, `parseURR`), which is also what lets it name
  the trigger bit it refuses.
- `message.NewSessionEstablishmentRequest` (and its siblings) sorts each IE into
  the field it belongs to (`CreatePDRs`, `CreateURR`, …), so `IEs` then holds only
  the ones it does not recognize. A test that wants a different URR must replace
  `req.CreateURR`, not append to `req.IEs`: an IE appended there is never read.
- The `Message` interface has no `Marshal`: sending means `MarshalLen` plus
  `MarshalTo` into a buffer the caller owns.

Moving the pin is a decision, not a `go get`: read the diff of `message/` and
`ie/`, and re-check these facts.

## Restart and failure semantics

- The compiler's id spaces (actions, meters, TEIDs) are bounded by
  `upfd -capacity`, and the graph's tables must be at least that wide: the
  ActionTable and the Meter take `capacity`, the GtpuEncap takes `max_tunnels`
  (and the decap's session table its own default), and a module refuses an id
  beyond its limit as invalid -- a mismatch is a session the SMF sees refused,
  not a slow path.
- Two sessions cannot hold one rule. The PDR tables are shared by every
  session and one key is one rule, so a graph whose key is the tuple alone makes
  two sessions whose keys agree -- one UE address, or one SDF prefix -- compile
  to the same key: the second would take the first's packets, and its own
  deletion would erase the rule the first still holds. `compile` keeps the owner
  of every key a live session holds and refuses the second claimant with a rule
  failure; the check and the claim are one critical section under `compile`'s
  lock, so two sessions cannot both find a key free. A claim goes at exactly two
  points, both after a transaction has landed -- `settle` releases the keys a
  transaction erased, `releaseSession` the keys of a session that has been
  deleted -- because a refused transaction leaves the old rules programmed: a
  claim dropped while a transaction is in the air would let another session
  write a rule this one's retry then erases. A compile that fails gives up only
  the keys it was the first to claim; the keys the session already held stay,
  their rules being in the dataplane, and an Apply whose answer never came keeps
  them too (its transaction may have committed). The keys are listed on the
  session itself, so a release frees its own rules rather than walking every live
  key under the lock -- at the million-session target that walk is the difference
  between a release and a stall. What makes the key's contents a statement
  is the same fact from the other side: the tunnel on the uplink (`upf_teid`)
  and the route domain where a graph writes one are why two instances serving
  one subscriber prefix are two rules rather than a collision.
- A released id is not handed out again until the pool's walk of its space has
  come round (and then only once it has aged): a transaction that removes a
  record leaves its slot retiring for a grace period, and publishing into a
  retiring slot is refused (`slot_table.h`: `CanPublish`). The walk starts at a
  random point with a random stride, so a controller that restarts and replays
  what the SMF sends does not walk its predecessor's order -- which is the case
  that found this: a session established right after a deletion was answered
  `73` with "the meter is still retiring (removed less than a grace period
  ago)".
- A refused modification is not undone: `merge` has already taken the ids and
  registered the objects the request named, and only a *definite* refusal of an
  establishment (`compile.go`, the Establish path) or a deletion frees a
  session's ids. That is the safe direction -- a live session's records may
  already name them, and the SMF's retry is what reconciles the model with the
  dataplane -- but it has a bound worth stating: every refused modification that
  introduces a *new* CHOOSE ID reserves one more TEID for that session, and each
  such reservation lasts until a transaction settles (which drops a CHOOSE ID no
  PDR names) or the session ends. A session therefore cannot run the pool dry
  through refusals alone: what it can do is hold as many TEIDs as it has PDRs
  with distinct CHOOSE IDs, plus the ones a refused request reserved that no PDR
  names yet. Releasing those exactly (provenance for what a failed transaction
  allocated) is the design's own future item, not a property of today's code.
- `bessd` restarts: every handle goes stale (`StaleResourceError`), the
  controller re-reads `Capabilities`/`Pipeline`/`Resources`, reapplies the
  graph, and re-programs sessions from its own PFCP state; PFCP peers see
  `Association Release`/`Heartbeat` timeouts meanwhile.
- `upfd` restarts: its PFCP state (CP F-SEIDs, session identity, URR
  configuration) is in memory only, and its id pools start empty while BESS
  still holds the previous incarnation's records -- the pools hand out the
  same ids, and an action's object is changed id by id
  (`core/modules/action_table.h`: immutable, one id at a time), so a write to
  an occupied id replaces it: a rule that outlives its controller can come to
  name another session's action, and on the downlink another session's tunnel.
  There is no checkpoint and no replay path yet, so a restart is followed by
  emptying the session tables — the controller does it itself, **in chunks**,
  before its PFCP socket opens (`session.Compiler.Sweep`: it reads the session
  resources back with `bess.Client.Contents`, erases exactly the entries it
  found, and leaves the graph's own resources alone -- both directions' tunnel
  records among them, and the subscriber entries of every interface's ARP
  responder, which is the one table that has two writers: the graph writes the
  interface's own entry there, so the sweep takes back only the addresses inside
  the interface's declared pools, which is exactly what the compiler writes) — or by a `bessd` restart,
  and by the SMF re-establishing, which its own path management forces once the
  Recovery Time Stamp changes. The chunking is implemented on both halves:
  `Sweep` erases in transactions of at most 1000 changes each (`sweepBatch`),
  in sequence, and stops at the first the daemon refuses -- a partial sweep
  leaves the tables half-empty, so `upfd` treats any sweep error as fatal rather
  than serving PFCP beside one (a few hundred entries are still one
  transaction) -- and it reads the tables back **one `Contents` call per
  resource**, never one call naming them all, because every resource a call
  names is packed into one response and the daemon refuses a response above its
  64 MiB message limit (`RESOURCE_EXHAUSTED`, "name fewer resources"; its
  `GetPipelineRequest` carries a resource list and no cursor, offset or chunk
  size). **The ceiling is therefore a table, not a session count:** a resource
  read is bounded by that message limit, so a table is readable to roughly 510K
  entries at 131 B each, and one resource per call is what puts the limit on the
  largest single table rather than the sum of all of them. That is the interim's
  limit, and past that table's capacity the operator's escape is a `bessd`
  restart, which discards the warm dataplane -- which is why "the erase is
  chunked" must not be read as "the sweep scales to 1M" on its own. **The target
  is a bounded clear, which removes the readback entirely:** the readback exists
  only so the sweep can name the keys it erases, a client-side enumeration of a
  table the daemon already owns, so the operation to expose is *clear this
  resource*, batched inside the daemon -- a handful of control calls, no read.
  That is the direction recorded here and it is a BESS item; until it exists,
  the per-resource read above is what makes a sweep work to roughly 510K entries
  per table ("Session scale" below, item 1 of the control plane's O(total
  sessions) operations). What is still missing is the replay path that
  would keep the sessions across a restart instead of emptying them: Wall 4
  below is that work.
- Either restart must be a *reapply*, never a trust fall: the controller
  verifies by reading back what it wrote (the SDK's readback and
  `ReadBackDiffers`-style comparison exist for this).

## Milestones

1. **N4 node** — the PFCP socket, the association with one CP function, its
   liveness in both directions, and the dispatch to the session layer.
   *Proof:* an SMF associates, heartbeats, and is detected restarting; a
   session request it sends is answered with a Cause, never dropped.
2. **Graph** — the UPF pipeline as manifests plus the datapath modules:
   `deploy/smoke-gtpu.yaml` (the two datapath halves, byte-checked) and
   `deploy/session-live.yaml` (the two chains the compiler writes into), with
   `upfd`'s `-bess` wiring the session layer to a running daemon. The graph
   with real N3/N6 ports is the deployment's, and its proof needs the NIC the
   hardware items in the roadmap are waiting for.
   *Proof:* a packet on N3 decapsulates, matches a PDR, takes its action and
   leaves on N6 -- `ci/smoke-gtpu.sh` for the two halves, `ci/session-live.sh`
   for what the compiler wrote.
3. **Session transaction** — PDR/action/meter/route in one transaction;
   establishment, modification, deletion. *Proof:* a session is programmed and
   erased atomically; killing `upfd` mid-change leaves no half-session.
4. **Routing** — N3/N6/N9 domains, next hops, UE IP pools, SDF filters with
   port ranges. *Proof:* two subscribers with overlapping private prefixes in
   different network instances route independently.
   *In:* `internal/routing` holds the deployment's interfaces -- each a network
   instance name (8.2.4), a route domain, the next hop a forward out of it takes,
   and the subscriber prefixes it serves -- with two instances allowed to serve
   one prefix and one interface not; `upfd -instances`/`-max-domains` configure
   them; the compiler reads the Network Instance of a PDI *and* of a FAR's
   forwarding parameters, resolves each against them, refuses a name the
   deployment does not serve (cause 73, naming what it does) and an address
   outside the interface's pool, puts the interface's domain in the rule's key
   wherever the graph declares it (`domain` in `-pdr-fields-*`), and sends a
   forward out by the FAR's instance (or the PDI's) rather than by the
   direction's. Port ranges stay refused rather than widened (see the
   classifier work below).
   *Out:* the vif wiring's hardware half (the section above: a real port's
   interface writes `route_domain`, and the software half of that is proven on
   a veth by `ci/veth-port.sh` -- what is left is the packet-placement
   measurement a NIC's RSS engine is needed for, and a graph whose key leaves
   the domain out still keys the uplink on the tunnel it arrived on, which is
   what tells two instances' sessions with one UE address apart), and N9's
   real peer UPF, which needs a deployment with a second UPF to name.
   *Proof:* `internal/session`'s TestTwoInstancesRouteIndependently (two
   sessions, one address, two instances, two rule keys and two next hops) and
   `ci/session-instances.sh`'s TestLiveTwoInstancesRouteIndependently -- its own
   manifest, `deploy/session-instances.yaml`, because the shared one's figures
   are recorded and an arm may not move a baseline it never measured. The live
   arm ran on 2026-10-17: both sessions for 10.45.0.2 established, and in a 2 s
   window taken once both exits were moving, gate 0 carried 16,524,544 packets
   against gate 2's 2,065,620 -- ratio 8.00, the streams' own burst ratio (32
   against 4; the same 8.00 in three runs), with both tunnels visible in the
   G-PDU dump. A snapshot at the instant the second stream starts says nothing:
   an earlier look caught 1600 against 728 and the window is what settled it.
5. **Usage** — URR counters, reporting triggers, session reports. *Proof:* a
   report matches the packets a source produced, within a known bound.

Each milestone lands with its tests and a run that shows it, not with a
scaffold for the next one.

## N3, N6, N9: one port, three interfaces

The UPF faces three reference points, and they are **IP-level** interfaces:
3GPP does not define their L2, so the deployment decides whether they are one
NIC, one NIC with tagged sub-interfaces, or three.

BESS's `vif` module (`core/modules/vif.{h,cc}`) is built for this and is more
than a lookup: it matches and strips 802.1Q, finds an interface by `(VLAN,
destination MAC)` -- and by IP when it answers ARP on that interface's behalf --
writes `vif_id` and `route_domain` into the packet's metadata, and sends the
frame out of the vif's own output gate. It is configured through `VifArg` -- a list of `interface`s with `id`, `vlan`,
`mac_addr`, `ip_addr`, `route_domain` and `gate`, plus a `default_gate` for
unclassified traffic -- and through `VifCommandAddArg` with the same
per-interface fields (`protobuf/module_msg.proto`), which is the shape `upfd`
drives. So N3, N6 and N9 can be
three interfaces on one PMD port, each with its own address, its own ARP answers
and its own routing domain; nothing in 3GPP requires a distinct MAC per reference
point, and a shared MAC is fine where the segments are tagged apart.

`route_domain` is written, and now read: `core/route/route_domain.h` and
`Router` (`core/route/router.h`) are domain-aware (`kMaxRouteDomains`, a
`max_domains` per router, routes taken per domain) and `vif` writes the domain
into packet metadata; a match table that declares the attribute among its
fields (`attr_name: route_domain`, as `deploy/veth-port.yaml`'s downlink table
does) consumes it, so the domain a packet arrived with is what its PDR rule is
keyed on. The Router's own per-domain *routes* are a separate path, and no graph
here uses it: a session's action names its next hop by id, not by domain. What a
*PDR* selects is not a vif but a **network instance** (TS 29.244 8.2.4), beside
the **source interface** (8.2.2), which this repo does read
(`internal/session/compile.go`). That link is in now:
`internal/routing` is the deployment's interfaces (name, route domain, next hop,
subscriber pool), the compiler resolves the Network Instance of a PDI and of a
FAR's forwarding parameters against them -- refusing a name the deployment does
not serve, and an address outside the interface's pool -- puts the interface's
domain in the rule's key wherever the graph declares it (`domain` in
`-pdr-fields-*`) and sends a forward out by the FAR's instance. An interface carries one hop
*per egress* since 2026-10-19: the FAR's **Destination Interface** (8.2.24)
chooses between the instance's plain hop, a tunnel out of it (an Outer Header
Creation: N9 and indirect data forwarding), the service LAN's and the 5G VN
re-injection, the `-instances` keys and `-access-next-hop` name them, and an
egress the instance does not declare is refused with cause 73 rather than
served by whatever hop the direction had -- an interface whose forwards all
tunnel, or that only re-injects, needs no plain hop, and a forward that needs
one is then the thing refused. A forward that **adds an outer header** needs
more than a hop: the tunnel's own parameters are a per-session record in the
direction's encap module (`upfd -tunnels` for the downlink, `-tunnels-ul` for
an uplink forward that carries one -- indirect data forwarding and the uplink
of an N9 tunnel), and a direction with no module refuses the forward rather
than compiling a rule the encap drops for want of a record. The interface's ARP identity (the
module and the MAC) is where a session's UE address is answered from. The packet-side
half is the vif's `route_domain` -- a rule's key can carry the domain only where
something writes it into the packet -- and it is in: `deploy/veth-port.yaml`
declares the three interfaces on one port and the tables that read what they
write. The deployed graph wires the same module for its one N6 port: `vif_n6`
matches the data network's frames by `(VLAN, MAC)`, and `l2_sort` sorts by
EtherType ahead of it -- an ARP request names the broadcast MAC that no `Vif`
matches, so it is diverted to `arp_n6` (`upf_arp_responder`, this repo's own
module, `docs/datapath.md`), which answers for the interface's own address *and*
for every live session's UE address, while the IP frames continue to the
interface and its downlink chain. The `Vif`'s own ARP answer is inert in that
graph (the graphs that put a `Vif` first still use it), and nothing there reads
the domain it writes (`deploy/upf.yaml`; `ci/session-path.sh` and
`ci/iface-path.sh` send the frames through it). A deployment that has no vif still tells two instances apart by what the
ingress writes on its own: on the uplink the tunnel the G-PDU arrived on
(`upf_teid`, the decap's own attribute), which is
what `deploy/session-instances.yaml` declares and `ci/session-instances.sh`
drives -- its own manifest, so the shared graph's recorded figures stay the
figures of the arm that produced them. That is a fact about the key, not luck:
two instances serving one subscriber prefix are two rules because the tunnel
they arrived on is part of what selects them, and a graph whose key leaves it
out is refused the second claim (see "Restart and failure semantics").

**A plain NIC cannot put both halves of a session on one worker, and the port
count is not the reason.** The uplink arrives as GTP-U and the downlink as the
UE's own flow; outer-header hashing sees two unrelated tuples, because the inner
one is not in the outer header. Three ports hash the same way. N3/N6 (and N9)
sessions therefore take the shared tables of the placement policy, with
per-worker cells for what the packet path writes, while per-flow sharding stays
for what does have one worker across both directions.

That is a statement about outer-header hashing, not about the protocol, and the
difference matters enough to measure rather than assume. The knobs are in our
DPDK (`lib/ethdev/rte_ethdev.h`): `RTE_ETH_RSS_LEVEL_INNERMOST` with
`RTE_ETH_RSS_L3_SRC_ONLY` for the uplink -- the inner source is the UE address --
and `RTE_ETH_RSS_L3_DST_ONLY` for the downlink, where the inner destination is.
`RTE_ETH_RSS_GTPU` (bit 23) is not that: it hashes at the tunnel level, and the
two halves a session really has are a GTP-U packet carrying a per-direction TEID
and a plain-IP packet carrying no GTP-U header at all. The two L3 bits are also
mutually exclusive inside one `rss_hf` (the header clears both when both are
set), so a single port carrying both directions needs per-pattern RSS -- an
`rte_flow` RSS action -- rather than one port-level setting. Driver support for
GTP-U exists in both engines we build (mlx5's flow steering, and ice's
`drivers/net/intel/ice/base/ice_flow.c`), which is what makes this worth
measuring. Whether this box's NIC and DPDK can do it belongs on the hardware
list, not in the basis of the placement policy.

**What a veth proves, and what it cannot.** The port half of this section is
measured on a software port, so that it does not wait for a NIC:
`deploy/veth-port.yaml` declares one PMD port (the af_packet PMD over a kernel
veth, `qpairs=4`) with four `QueueInc`s into a `Vif` whose three interfaces are
N3, N6 and N9 -- each with its own MAC, its own address and its own route
domain -- and the PDR tables whose keys carry what the Vif writes;
`ci/veth-port.sh` deploys it and checks the result, and `docs/ports.md` holds
the recipe. That is four things the port has to get right, proven here:

- **the queue count**, from two independent views: BESS's (the runtime PortInfo
  and the active pipeline, four receive and four transmit queues) and DPDK's own
  device telemetry (four rx/tx queues, all of them started) -- and the PMD's
  count comes from the vdev's `qpairs=`, not from the veth's `numrxqueues`, so
  it is a real declaration that took effect rather than an echo;
- **real L2**, in that a frame addressed to an interface's MAC crosses the veth,
  is read by the port and lands on that interface's gate -- the three gates'
  counts are exactly the frames sent, no more and no fewer;
- **the vif split with its route domains**, end to end: the domain the port
  wrote for a frame is what the compiler's downlink rule (`upfd`, over N4) is
  keyed on, and that frame is selected by the rule and crosses the chain to the
  encap, while the same frame before that rule existed is dropped;
- **the per-queue spread**: the af_packet PMD's `fanout_mode=hash` places a flow
  on a queue, and all four queues move under many flows.

What the veth cannot do is the measurement this section is about. The af_packet
PMD advertises no RSS offload at all -- the telemetry's `ethdev_rss_hf` is `0x0`,
and there is no hash key, no RETA and no per-queue hash function to program -- so
the Innermost/L3-only RSS pattern above cannot be configured on it, let alone
measured at line rate: what spreads flows over the four queues above is the
kernel's AF_PACKET fanout hash, not a NIC's. The knobs the measurement needs
(`RTE_ETH_RSS_LEVEL_INNERMOST` with `L3_SRC_ONLY`/`L3_DST_ONLY` as a per-pattern
`rte_flow` RSS action, on a driver with GTP-U flow steering) and the rate it is
measured at therefore stay on the hardware list. Nothing above weakens that: the
veth arm is why the *software* half of the port work is not blocked on hardware,
and it is checked as a NIC-independent claim (`docs/ports.md` says which).

What `upfd` owns, then: the ports and their vifs, the graph, the routes per
instance (the UE pool's next hop out of N6, the peer UPF for N9, the data
network's default), and the management surface OMEC scattered across flags and
scripts -- metrics, echo and end-marker handling, DDN/BAR, and the checkpoint a
restart replays from. `internal/routing` holds the interfaces the route domains
above are made of. Of the management surface, the numbers are in: `upfd
-metrics host:port` serves the session layer's own counters (sessions held,
establishments, modifications, deletions, refusals), the reporting loop's
(reports sent, refused, held, dropped) and whether a CP function is associated,
in the Prometheus text format -- the facts this node measured, at the node that
measured them, with no screen between. Echo and the end marker are the
dataplane's (a G-PDU's peer-speaks-GTP-U half, and the TS 29.281 packet that
tells a gNB to switch paths), DDN/BAR is the buffering OMEC never had, and the
checkpoint is the restart wall below.

### Which session a packet belongs to, and which of its rules matches it

Every packet forces two questions, and they are answered differently in each
direction.

1. **Which session does this packet belong to?** On N3 the packet is inside a
   GTP-U tunnel and the **TEID names the session exactly** — the SMF gave that
   TEID to the gNB for that one session — so this lookup is exact, and no prefix
   structure is involved on the uplink, ever. On N6 the packet is bare: no
   tunnel, no TEID, and the only thing in it that names a session is the **UE's
   own IP address**, which the SMF assigned to the session and sent in the PDI's
   UE IP Address IE (TS 29.244 8.2.62). Because the SMF may name a *prefix*
   rather than a single address — a framed route, or a /64 for prefix delegation
   — that lookup is a longest-prefix match, which is what the LPM is for, and it
   is **downlink-only for exactly this reason**.
2. **Which of that session's rules matches it, and what does that rule say to
   do?** That is the PDR stage, in both directions.

**The chain has a session selector now, and the shared table still needs none.**
The shared PDR table's own key carries the masked UE address (or prefix), so the
prefix matching happens where the SMF's PDI puts it: inside the PDR table, in
both directions (`deploy/upf.yaml`, `deploy/session-path.yaml`). A dedicated
downlink selector exists only so that a session can be named *before* a 2–4 rule
scan — i.e. so each session can own its rules — so it is **not needed, it is
enabled**, and it is written only for the profile whose downlink is the keyed
per-session map. What was built is the spec's own look-up rather than the LPM
this section first expected: **an exact match on (route domain, UE IPv4
address)**, which is what 5.2.1 with 8.2.62's exact address asks for, as stock
modules — `ExactMatch` (`sel_dl`) writing the session id into the packet's
`action_id` metadata, then the keyed matcher reading that id
(`internal/session/selector.go`, live in `ci/pdrmatch-path.sh`). An LPM is the
structure for an IPv6 UE *prefix* or a framed route, and it is owed when those
are served (IPv6 is refused today: docs/compliance.md). Under that design the
shared table does **not** disappear either: a profile whose downlink is the
shared table keeps it, and the compiler chooses per direction which structure a
rule goes in.

**The break-even line below is what a deployment below the target decides on.**
It is not a threshold the selector waits for: the selector is written, and the
line says where a *shared* downlink table is still the better choice.

**The decision is a break-even line, not a threshold:**

```
churn_break_even (sessions/s) = (per-packet LPM+scan cost × downlink packets/s)
                                ÷ shard rebuild cost
```

with its two halves labelled by whose measurement they are. The per-packet cost
is an LPM lookup plus a 2–4 rule scan **in our graph** — ours to measure. The
table end — `LookupBatch` at 2, 3 and 4 rules, the fixed overhead, and the
per-rule and per-group memory that is also the per-session footprint budget —
is **BESS's published rows** (Main's), and the denominator is BESS's own
rebuild row, "about 50 µs at 1K rules and about 1 ms at 10,000"
(`bess/docs/dataplane-tables.md`, `benchmarking.md`; Main's later sample reads
44 µs). What the line means in words: the rebuild is a **spike** (one session
change) against a **steady tax** (per downlink packet), so a deployment that
churns rarely and forwards heavily sits far below the line and keeps the shared
table, while a lab or a small network sits below it by orders of magnitude —
which is why the expected outcome below that line is that the LPM is never
written. The x-axis ceiling comes from our own measured establishment envelope
(`ci/bench-n4.sh`), so it is a measured bound rather than an assumed one. **The
number is still owed**: this is the decision *rule*, and no decision is taken.

**The capacity target is what makes the selector required rather than
optional.** At O(10^6) sessions the shared table's rebuild stops being a spike a
deployment can absorb: 1M sessions at 2–4 PDRs is 100k–1M rules per shard, which
extrapolates BESS's rebuild row above to tens of milliseconds per session
change, so even 0.1 %/min of churn — about 17 establishments a second — is 17 ×
tens of milliseconds, i.e. a core spent on rebuilds. Per-session programming is
therefore required at the target, and with it the downlink longest-prefix
selector — **v4 and v6**, because a 1M-session deployment has v6 UEs and prefix
delegation is exactly the case an exact lookup cannot serve. The break-even line
then says *where the crossover sits for deployments below the target*, not
whether the LPM is written at all.

**What 10^6 multiplies is not only rule sets.** The target multiplies **1M LPM
entries, 1M TEID entries and 1M meters** too — four structures that all grow
with the session count — so the per-session footprint budget is what holds
*every* one of them to account, not just the rules. It is a measured budget we
owe, with BESS's per-rule, per-group and LPM-per-entry rows as its inputs, and
nothing about it is assumed; the target size and the arithmetic are in "Session
scale" below. The control plane's unit is the per-session transaction for the
same reason: 1M small transactions, each O(that session's rules), never 1M
rebuilds of a shared structure — which is also why any resource whose value is
"every session's rules" is the shape to look for in a new table (the three
O(total sessions) operations in "Session scale" are what that shape costs).

**One downlink LPM, not one per session — and how many is bounded by the domain
count.** `rte_lpm`'s `tbl24` is `RTE_LPM_TBL24_NUM_ENTRIES` = `1 << 24` entries
of a 4-byte `struct rte_lpm_tbl_entry` (a union over a `uint32_t`), i.e. **64
MiB fixed per table, whatever it holds**, plus `tbl8` groups of
`RTE_LPM_TBL8_GROUP_NUM_ENTRIES` = 256 entries × 4 B = **1 KiB each**, allocated
per table (`number_tbl8s`, 256 groups by default) and used for the prefixes
longer than /24 that fall in a /24's entry. A per-session LPM is therefore
impossible at 1M sessions (64 MiB each); a single table holding every session's
prefixes is not, which is what this design already assumes. But the fixed cost
means our *per-domain* tables multiply it, and **both families pay it**: a
dual-stack domain is two tables — `rte_lpm` and `rte_lpm6` each costing 64 MiB
fixed per table — so three such domains are ~384 MiB before a single group, i.e.
**~128 MiB per dual-stack domain**. That is a count times a fixed number, so the
whole cost is predictable before anything is deployed (`domains × 128 MiB`),
which is what makes "few, long-lived domains" a constraint rather than a
preference: it decides whether a per-tenant domain is affordable at all. The
group memory depends on *clustering* rather than on the entry count: 1M /32s
spread over 1M distinct /24s is ~1M groups (~1 GB by the same 1 KiB-per-group
arithmetic), while the same 1M inside a few shared /24s is a handful of groups
— so the deployment's address plan matters as much as the session count. v6 is
the same shape, not a cheaper one: `rte_lpm6`'s `tbl24` is also `1 << 24`
entries of a 4-byte `struct rte_lpm6_tbl_entry` (`lib/lpm/rte_lpm6.c`), its
`tbl8` groups are the same 1 KiB each, and it adds a `rules_tbl` hash over the
rules. None of these numbers is settled: Main is measuring **both families'
fixed parts and both group behaviours** (and a realistic v4 distribution), and
will not publish the row until both exist — the shape and the arithmetic here
come from the headers, the numbers are owed.

**The three pieces have one owner each.** The keyed write is ours to write —
the map-resource module above, `PdrMatch`-shaped, one key per session,
`ExactMatch`'s shape rather than the firewall module's whole-policy singleton.
The matcher side is BESS's, and it is two pieces, not one: the `firewall`
module extracts a rule's key from the packet and applies its verdict (the
D-147 work, which the compiler can opt into today with `upfd -firewall-ul` and
`-firewall-dl`, and no deployment configures), and **`FirewallScan` is the
small-policy matcher we hold one of per session**, in
`core/classifier/firewall_table.h` beside `FirewallTable`. On BESS's side of
that line — neither of these is ours, and we have not run them —
`FirewallScan`'s `Lookup`/`LookupBatch` return the same `Match` shape and call
the same `FirewallTable::Matches` predicate the index calls per group, so the
two structures cannot disagree about what a rule means; its `Create` makes the
same refusals the index's `Build` makes, rule for rule; and their test walks a
random corpus of both families through the scan, the index and a scalar
reference for agreement. Both pieces land in Main's next push. And the selector
that *names the session* on the downlink is the LPM: a different structure,
with a different cost (a lookup per packet, inside the break-even line above)
and a different limit (the domain count, and the deployment's address plan).
Keeping the three apart is what lets each be measured and replaced on its own —
and conflating them is how a whole-policy write came to look like the right
shape for per-session state in the first place.

### Profiles: one compiler, three dataplane strategies

The three pieces above are chosen per deployment, and that choice is what the
comparison is about — so it is carried as a **profile** rather than as flags
that accumulate. A profile is five things and nothing more:

- **the graph** (or the per-direction fragments): which matcher module sits in
  the chain, and how its output is wired;
- **the compiler strategy per direction**: what a session's PDRs are written
  into — the shared `WildcardMatch` table, the firewall policy, or the keyed
  map;
- **the module list** the daemon must load (`-m upf_datapath`, `-m firewall`),
  which is also where the plugin's build-and-load cost lives;
- **the capability envelope**: what the profile expresses and what it refuses —
  the wildcard table refuses port ranges and IPv6 (cause 75), the firewall
  policy carries both but rewrites the whole policy per session change, the
  keyed module carries both and writes one key;
- **the measured rows**, generated by the bench with the profile's name and the
  deployment shape attached, never typed by hand.

Three to start: `generic-wildcard` (the shipped default), `generic-firewall`
(the opt-in that carries ranges and IPv6), and `custom-pdrmatch` (the keyed
module). `upfd -profile <name>` selects one and the individual flags stay as
overrides; the arms in `ci/` take a profile name so one workload can be run
against each, with `ci/profile-compare.sh` printing the vector and the
crossover for every profile and being re-run whenever either side changes.
That is what makes the tradeoff live rather than argued once from a snapshot.

**A profile costs nothing at runtime, by construction.** It is a start-time
choice: the flag resolves to a graph and a per-direction strategy before the
controller serves PFCP and before the daemon loads its modules, so the packet
path holds no profile check and the session path holds no profile branch — the
profile *is* the graph and the strategy, not a layer consulted per packet or
per PDR. What it must never become: a table of function pointers dispatched
per packet, a "which profile am I" lookup inside the module, or a strategy
object allocated per session. And the shipped default must not regress:
`generic-wildcard` produces the same graph, the same rules and the same packet
path as today, which the existing arms prove by producing the same numbers
before and after — a differential on the default rather than a promise.

Four guardrails, because a profile is a strategy selection and not a fork:

- **A profile never forks the compiler.** Parsing, validation and the PFCP
  semantics stay in one place; a profile chooses *where* the rules live. A
  profile that needs its own copy of a predicate has failed the way the shared
  `Matches` predicate exists to prevent.
- **The equivalence gate applies to every profile.** A profile is admitted when
  the random-corpus test shows it answers like the reference, not when it is
  faster.
- **No new profile without a deployment that needs one.**
- **Measured rows are generated**, with the profile's name and its deployment
  shape in the output, because the crossover moves with the address plan and
  the churn.

**One gap the profiles make visible**, and it belongs in `generic-firewall`'s
envelope rather than in a footnote: **our compiler does not emit a firewall
rule's `action_id` yet.** The stock module writes a per-rule `action_id` into
packet metadata and an `ActionTable` downstream resolves it (D-141), so stock
BESS *can* carry a range or IPv6 PDR that forwards to its own FAR's next hop —
but `firewallRule` emits only the verdict and the match, so that path cannot
serve such a PDR until the compiler emits the id and the graph points the
firewall's output at the ActionTable it already has. Stated as a limitation
with its consequence, and as the next item after the keyed module. Any comment
claiming a firewall rule cannot carry an id usefully is wrong: each rule
carries its own.

## Where a table lives: shared, per-worker, or behind a ring

The default is **shared**: a table a controller writes and workers read (the
classifier's rules, the action table, the tunnel records, the TEID table, the
next hops) has no reason to be copied per worker. Every write in a session's
life arrives out of band, one PFCP message at a time, and the BESS contract
prices the shared read path. Partitioning a controller-written table multiplies
its memory by the worker count and buys nothing: the writer is not the packet
path.

**Per-worker state is for writes the packet path makes.** A table whose entries
change because packets flow -- a NAT binding learned on the wire, a flow's usage
counters, a forwarding entry learned from traffic -- cannot take a shared write
per packet. It gets one of two shapes:

- *per-worker tables*, when the flow's owner is knowable: every packet of the
  session reaches one worker. D-097 and `update_scale_bench` E2 measure 3.4x for
  sharding by flow owner over one shared table at 3% new flows.
- *per-worker cells inside a shared table* (the `CounterSet` usage-plane shape),
  when the owner is not knowable or the reads are control-side: the packet path
  writes its own slot with no atomic, and a control read sums the planes.

The first shape has an assumption that is easy to miss, and it is a property of
the *port*, not of the module: **symmetric RSS**. When the two directions of a
flow hash to different workers -- asymmetric RSS, or a rewrite in the path (NAT
does this by construction) -- no worker owns a session, so per-worker tables
cannot hold its state and shared (or the ring below) is the only option. The
UPF must therefore know the RSS behaviour of its ports instead of assuming it;
the deployment decides which shape the N3 and N6 sides get.

**A ring to an owner is the third shape**, for when the state must live with a
specific worker but the packets do not arrive there: a bounded SPSC/MPSC ring
hands the work, or the record, to the owner core -- the same mechanism as BESS's
handoff/punt channel. It costs a queue operation per handoff and needs
back-pressure, so it is for per-flow events and control-side records, not for
the per-packet path.

**What it costs is measured, not argued.** Each placement above is priced by the
performance contract (the shared read/write under transactions, per-worker
tables under `update_scale_bench` E2, counter planes under the G5 row of
`table_policy.md`'s benchmark plan -- the plan wall 2 names), and a placement that
only "feels" right does not move the design.
The one case with no measurement yet is a session's state under asymmetric RSS,
which the G5 plan wall 2 names is to settle.

## Session scale: 10^6 sessions, dimensioned by PDR/FAR/QER/URR/MAR

The target is a million sessions on one box, with the packet path unchanged
while they are programmed. The BESS performance contract already measures every
structure this design uses, so the arithmetic below is that table at this shape
(4 PDR, 4 FAR, 2 QER, 2 URR, 1 MAR per session).

| per session | state in BESS | measured bytes | at 10^6 sessions |
|---|---|---|---|
| 4 PDR | WildcardMatch rule (one masked table, shared by the workers) | not measured: 16-byte key, mask, value, priority, result, cuckoo body | about 360 MB (2.9 GB only if the table were copied per worker, which it is not) |
| 4 FAR | ActionTable record (`dataplane::SlotTable<ActionId, Action>`, one cache line per record) | 64 B/object | 256 MB |
| 2 QER | `MeterSet` | 64 B state + 8 B pointer | 144 MB (1,048,576 meters measure 64 MiB) |
| 2 URR | `CounterSet` block | 4 KiB for three counters (each slot per worker: 64 slots) | the wall: 8 GB if each URR owns a full per-worker block |
| 1 MAR (ATSSS, P1) | per-session record | not measured, small | about 64 MB |
| 1 F-TEID | the decap's tunnel table | 64 B/object | 64 MB |

The table is not the whole footprint, and the per-session budget is what holds
all of it: 10^6 sessions multiply **1M LPM entries, 1M TEID entries and 1M
meters** as well as the rules, and each of those is a structure of its own. The
target for all four is the low hundreds of bytes per session -- a kilobyte per
session is a gigabyte, which is the difference between deployable and not -- and
it is a *measured* budget we owe, with BESS's per-rule, per-group and
LPM-per-entry rows as its inputs. Nothing about it is assumed, and the LPM side
of it is not a per-session table: there is **one downlink LPM, not one per
session**, because `rte_lpm`'s `tbl24` costs 64 MiB fixed per table (the
arithmetic is in "N3, N6, N9"), so the LPM instances are bounded by the domain
count and the domains have to stay few. That fixed cost and a realistic prefix
distribution are Main's measurements to make; what is settled is the shape.

**The control plane has three O(total sessions) operations**, and they fail
before the dataplane footprint above becomes the limit. They are all ours, and
the 1M target is a claim about the whole system, so all three have to be
addressed:

1. **`Compiler.Sweep`.** It reads the session tables back and erases what it
   read **key by key**. Both halves are now bounded, and neither is unbounded
   any more: the erase goes out in transactions of `sweepBatch` (1000) changes
   rather than one -- the daemon refuses one transaction per sweep twice over,
   at 64 MiB of changes and at its engine's retirement budget ("transaction
   retires up to N objects, more than one batch allows (2048); split it") -- and
   the readback is **one `Contents` call per resource**, never one call naming
   them all, because every resource a call names is packed into one response and
   a response above the daemon's 64 MiB message limit is refused with "name
   fewer resources" (`api_v2.cc`).
   **What is left is the ceiling, and it is per table:** the daemon has no paged
   or cursored read (`GetPipelineRequest` carries a resource list and no offset,
   chunk size or cursor), so one resource read is one message, and a table is
   readable to roughly 510K entries at 131 B each. That is the interim's limit:
   at 1M sessions a single table that holds a session each way is past it, past
   a table's capacity the operator's escape is a `bessd` restart, which discards
   the warm dataplane, and nothing in the session layer lifts it (the SDK's
   `Pipeline`/`WithResources` is the same call).
   **The target is a bounded clear, which removes the readback entirely.** The
   readback exists only so the sweep can name the keys it erases -- a
   client-side enumeration of a table the daemon already owns, which at 1M
   sessions is both the 64 MiB wall and a million entries' worth of work. The
   operation to expose is *clear this resource*, batched inside the daemon,
   which makes the sweep a handful of control calls and no read at all. The
   shape exists already: a desired-state pipeline that *lists* a resource with
   no entries clears it (`ResourceContents`' own comment), but it builds one
   server-side transaction with one op per entry it finds (`Converge` →
   `engine.Apply(ops)` under the control-plane lock), so it is unbounded exactly
   where the sweep is now bounded -- the batching inside the daemon is what is
   missing, not the operation. That is the direction recorded here, a BESS item;
   until it exists, the per-resource read above is what makes a sweep work to
   roughly 510K entries per table.
   The design sentence that *prescribed* the defect is corrected
   above ("emptying the session tables" now says chunked on both halves and why).
2. **The firewall policy is a whole-policy singleton, so every session change
   rewrites every session's rules.** `compile.go`'s `firewallChanges` builds
   "the whole policy of every configured firewall module ... every live
   session's rules", because BESS's `Firewall` exposes `rules` as a singleton
   (`ResourceTable::Singleton<FirewallArg>("rules", false)`, D-147) that takes
   the policy, not a rule. That is O(all rules) per change -- the shared-table
   scaling problem, in the control plane -- and it would bite precisely the
   deployment that needs that path (ranges and IPv6 at scale). It is a
   *deliberate* property of that module (one table, replaced whole, published by
   RCU, workers never paused: right for a firewall, wrong for per-session
   programming), and it is opt-in today (a no-op for a deployment that
   configures no firewall module, which is every deployment today), so it is a
   trap for the future rather than a present defect. **The keyed write is
   already a resource kind, so the fix is ours to write rather than an ask:**
   `ResourceTable::Map<Key, Value>` is how `ExactMatch` exposes its `rules`
   (with `settings` as the singleton beside it, `exact_match.cc`), and the
   transaction engine applies map operations per key. A module that exposes
   **one session's rule lists as one key's value** -- a `PdrMatch`-shaped
   module, keyed by session or by (domain, session), singleton for its own
   settings -- makes a session change one upsert, O(that session's rules), which
   is the transaction unit the rest of this design assumes. Until it exists the
   firewall path stays a lab-scale path. The general lesson is worth keeping:
   a whole-policy write is O(all rules) whatever the structure behind it, so any
   resource whose value is "every session's rules" has this problem -- the
   firewall path is just the one that got written first, and it is why to check
   every new resource for the shape.
3. **The URR report loop's read path.** `upfd` calls `Compiler.EvaluateAll` once
   per `-urr-interval` tick (`cmd/upfd/main.go`), which walks every session, and
   each session's `Evaluate` makes its **own** `reader.RuleCounts` RPC per
   counter module (`internal/session/report.go`) -- at 1M sessions that is one to
   two million gRPC round trips per tick, one after another, so a tick lasts
   minutes, longer than any sensible interval. The cost was the read path, not
   the loop, and the fix is **one bulk read per counter module per tick**
   covering all sessions, evaluated in memory afterwards: one or two round trips
   instead of one to two million. **This tree does that now** (`EvaluateAll`
   reads each counter module once, with no rules named, and judges every session
   against what was read; `Evaluate` stays as the single-session reading, which
   names its own rules. `internal/session/report_test.go`'s
   `TestATickReadsEachCounterModuleOnce` pins the call count: one read per
   module, never one per session, and the reports it decides are compared
   element by element against the per-session path's). The reading itself is the
   module's `get_counts`, one call per counter module. **That is not a
   preference, it is the only read that carries counts:** the counter *resource*
   (`<module>/counters`) is the existence of an entry, keyed by ActionId, with
   an **empty value** -- `datapath/upf_datapath.proto` says why ("the counts are
   not here: they are the module's per-worker planes, because a resource value
   is copied on every publish and the controller rewrites a session's records on
   every modification -- a number kept in the value would be zeroed by a
   handover") -- so an entry is 90 B (two `Any` envelopes, the key and the empty
   value, each with its own type URL; measured the same way, at the daemon's own
   encoding) *without* a single count. A tick built on the pipeline's resource
   readback would therefore read 90 B per counted rule and decide **every
   report from zeros**; the numbers are the module's per-worker planes, and the
   module's own command (`datapath/urr_count.cc`) is what enumerates them -- the
   whole module's, when the argument names no rule. At the interval an operator
   sets (`-urr-interval` has no default; the flag is what turns reporting on at
   all) the cost of one tick is **one call per counter module, and 27 B per
   counted rule** -- measured by marshalling the module's own response with its
   descriptor (`datapath/upf_datapath.desc`): an ActionId up to 1M, a
   thousand-odd packets, a megabyte-odd of octets and two ~10^12 ns stamps
   encode to 27.0 B per rule, 34.0 B with a 4M-wide ActionId space, 4 GiB counts
   and day-old stamps. So 1M sessions at one counted PDR per module is 1M rules,
   25.7 MiB in one response (32.4 MiB at the widest encoding), and two of them
   -- uplink and downlink -- are ~52 MiB per tick,
   some 1.8 MB/s at a 30 s interval and 0.9 MB/s at 60 s. The daemon refuses
   any response over 64 MiB (`kMaxMessageBytes`), which at the measured 27 B
   lands on **~2.5M rules in one module** (1.97M at the widest encoding): 1M
   sessions at one counted PDR per module fit, and a deployment that measures
   2-4 PDRs per session crosses it at ~620K-1.2M sessions (earlier with the
   widest encoding). Past that the read has to be split, and the split is by
   **ActionId**: the module's `get_counts` takes an explicit id list, so a shard
   is a slice of the rules, not a resource name (naming fewer *resources* splits
   between tables and cannot split the one table that holds a rule each way:
   `Sweep`'s item 1 above) -- names cannot split one table, ids can, so past the
   ceiling the answer is **fewer rules per read and not a bigger message**, and
   the ceiling is per module in rules, not a session count (1M sessions at one
   counted PDR per module is half of it). At the 1M target the whole-module read
   is therefore the answer as it stands: ~52 MiB a tick and the 1.8 MB/s at a
   30 s interval above, reached without any paging, and nothing about the loop
   is O(sessions) in round trips any more. The remaining
   O(all sessions) is the bytes: every tick still reads every counted rule (the
   restart wall's sweep has the same read, once). Beside it, as the
   design-level improvement that removes the per-tick O(all sessions) read
   entirely -- and that is where this ends up -- the counter module could report
   threshold crossings itself (a dataplane that flags "this rule crossed X"),
   and the tick would read only what was flagged. **That mechanism is mostly
   already built, so the target is an event type and a
   consumer, not a transport:** `core/stats/event_hub.h` has the shape (a module
   registers an event type in `Init`, a worker posts with
   `Post(ctx->wid, WorkerEvent{...})` and never blocks -- a full per-worker ring
   refuses the event and counts it, and the maintenance loop's `DrainWorkers`
   moves what was posted into the log the `WatchEvents` stream reads: bounded,
   per worker, drop-and-count), and `core/stats/event_throttle.h` is the piece
   for this use case -- at most one event per second per worker, **carrying the
   count**, called on the failure path only, so what the control plane reads is
   "this worker crossed this threshold, N times" and never one event per
   crossing. What is left to design is the **composition**, not the channel:
   which crossings are worth a report, and how the pushed crossings and the
   pulled counts compose so that a session is **never double-reported** -- a
   crossing that already produced a report must not be reported again by the
   next tick's read of the same window -- with the pull staying the fallback for
   whatever the channel drops (a full ring, a ring lost across a restart),
   which is the path the bulk read above already carries to 1M on its own. One
   constraint follows from the traps above: a pushed crossing and a pulled count
   have to come from the **same per-worker planes**, or the two disagree -- the
   empty-value trap seen from the other end, a report whose trigger came from
   the channel and whose window came from a resource-shaped read. The reason
   this is the target is *latency*, not volume: a pulled quota or threshold is
   enforced no sooner than the tick, so a 60 s interval lets a quota overrun for
   up to 60 s before anything notices, while a pushed crossing is enforced when
   it happens. "Incremental evaluation" is not
   that fix and does not fit the code: a session cannot be skipped for a volume
   threshold or a quota without reading its counters first, so the information
   that would justify skipping arrives only after the read.

Time is measured at scale where memory is not: the masked table looks up 32
keys in 556 ns at 10^6 rules with one mask tuple, 1,716 ns with four and
2,463 ns with eight (17 / 54 / 77 ns per key), and an add+delete costs about
1 µs up to 100K rules (performance contract row 75). The tuple count is the
graph's `max_tuples`, so it is a UPF decision, not a default.

Rates, measured (performance contract rows 66-67): one transaction per session
sustains 695K sessions/s (519K in the other profile), and with the writer flat
out at 194K sessions/s four readers still do 44.8 Mpps each, from 49.3 at rest.
A million establishments at the N4 rate measured below (1,184 a second, one
client in flight) is 845 seconds -- 14 minutes -- of control traffic; at the
transaction engine's ceiling it is 1.4 s. (The envelope table further down
reports 2,274.8/s for another run of the same script: the p50s differ, 324 vs
786 µs, so those are two runs of a quiet machine, not two paths.) Either way a
million sessions is a campaign, not a migration. And the rate is the *server's*,
not the client's: upfd's PFCP loop reads one datagram and handles it before
reading the next, so what the SMF gets is that serial path -- 522/s at one client
in flight and 534/s at eight on this machine, the same number twice, with the
eight-worker latency being the queue (13 ms p50 against 1.7 ms). Making the loop
parallel is what would raise it, and then the in-flight count and the engine's
cascade budget (`kMaxInFlight` in `internal/bess`) become the limits.

The deployment's own numbers, through the whole N4 path (a PFCP message, the
session compiler, one transaction, the daemon's answer) with one client in
flight, 64 sessions, `ci/bench-n4.sh` MODE=establish: establish 2.832 ms p50
(351/s), p95 3.977 ms, p99 4.321 ms, max 7.211 ms, on 2026-10-17 at load average
1.3 (`cbd9f53`). Earlier runs of the same script give 786 µs p50 (1,184/s) and
439 µs (2,274.8/s, the envelope below). Three samples of one path, 3.4x apart,
one of them taken on a quiet machine. Which of the two the spread belongs to is
not settled, and the load is not evidence on its own: the compile path has gained
work since the fastest sample (the key maps built for the transaction's own
duplicate checks, the removal and replacement walks). That is now checked rather
than assumed: paired against the commit before those changes (`c8814a6`), two
rounds each on this machine at load ~0.2, the old tree gave 2.439 and 1.757 ms
p50 and this one 2.552 and 2.552 -- a difference inside the old tree's own
run-to-run spread, so the compile path has not regressed and the distance from
the 786 µs sample is the machine's state, not these changes. Which machine state
is a question of its own (governor and frequency, and pinning, are open items),
so each number here is still one sample, and none of them is a ceiling.

That is the rate an SMF sees today, per session in flight rather than per core,
and the answer is in how many a client keeps in flight. The eight-in-flight
figure here used to be a stall -- 7 of 256 establishments answered inside 5 s,
with "answer to no request" -- and that line was the *bench's*, not the
daemon's: n4bench numbered its requests by session index while it registered
each waiter under a call counter, so with several workers the two orders diverge
and replies matched nothing (the daemon held all 256 sessions in its action
tables, programmed correctly). With `send` putting its own number on the
message, the same run answers all 256: 8 workers, 256 sessions, establish
13.09 ms p50 (534/s aggregate) against one worker's 1.685 ms p50 (522/s) on the
same machine -- the aggregate is flat, and the latency is the queue, which is
what one serialized control path should look like.

Where that time goes, measured by part (`go test -bench`, 2000-3000 iterations
each; `ci/session-live.sh` runs the live ones against the daemon it starts):

- The PFCP library is not what costs: parsing an establishment request is 5.9 µs
  and marshalling the response 1.5 µs, with the client's own building and
  marshalling 13.1 µs (`internal/n4sim/bench_test.go`) and the server's whole way
  through one datagram -- parse, association check, handler, reply, send --
  10.6 µs (`internal/n4/bench_test.go`).
- The compiler is 121 µs (792 allocations) per establishment and 39 µs per
  deletion (`internal/session/bench_test.go`).
- The transaction is the rest, and it is most of it. Against a running daemon an
  establishment measures about 2.1 ms, of which `Client.Apply` is 1.99 ms; the
  parts inside it are bounded from both sides: converting exactly the changes one
  real establishment produced -- eleven records, so twenty-two keys and values,
  by their own field maps -- costs 144 µs (`BenchmarkLiveChangesToMessages`), a
  single message of any type the graph declares costs 3-7 µs
  (`BenchmarkLiveMessage`, per type), and one no-op RPC to the same daemon costs
  120 µs (`BenchmarkLiveCapabilities`). What remains is about 1.7 ms per session,
  and it is the daemon.

So the lever is the daemon's transaction path, not go-pfcp and not the compiler.
The transactions themselves land between 1.0 and 2.0 ms with a tail to 3 ms (the
histogram `BenchmarkLiveEstablish` logs, bucketed by the daemon's first backoff),
and the daemon answers BUSY by sleeping 200 µs, then doubling, up to five retries
(`kBusyFirstBackoff`, `kBusyRetries`, `core/control/api_v2.*`): a retried
transaction is slow, not failed, so some of that time can be the engine waiting
for reclamation rather than working. Which part is which is not measured. The
engine's own benchmark records 695K sessions a second, but that is in-process,
with no gRPC, no lock and no plugin graph, so it bounds nothing here -- it makes
"the session's tables are what cost" a hypothesis worth testing, and the test is
the same transaction against a minimal graph.

The next measurements, in order: publish the engine's retry counter
(`busy_retried()` is counted and not in `ListMetrics`) so a run reads retries
instead of inferring them from a histogram; the minimal-graph comparison; and
`perf` on bessd under the isolate wrapper this box's paranoid setting requires --
Go's own `-cpuprofile` is killed here, and that does not say anything about
`perf`.

The walls, in order:

1. **Per-worker tables.** The tables a controller *writes* are not the subject of
   this wall: they are shared -- one copy, read by every worker, published as a
   generation -- so the state at issue is what the *packet path* writes (a usage
   count, a learned binding). Sharding that by flow owner -- the worker whose
   queue sees the session -- measures 3.4x better than one shared table at 3% new
   flows (`update_scale_bench` E2), so packet-path state is sharded by flow owner
   rather than shared. That holds only while one worker sees the whole session:
   with asymmetric RSS, or the N6 side of a rewritten flow, the two directions
   land on different workers and the sharded form cannot hold a session's state.
   Which shape this deployment gets is a property of its ports, not of the module
   (see "Where a table lives"), and that case is not measured yet.
2. **URR counters.** A counter block is priced per worker slot (`CounterSet`:
   4 KiB for three counters): right for a hot counter, wrong for a million
   mostly-idle sessions. A URR must allocate its block on the worker where the
   session is live, and a control read must sum the live copies -- which needs
   either one worker per session (symmetric RSS, wall 1) or a plane per worker
   per direction summed at the report. A hard byte quota is a budget under the
   second shape, not a gate: each worker counts the bytes it sees, and only the
   control side can add them up, so enforcing a quota exactly across workers
   means the control side pushes allowances down (a ring, per "Where a table
   lives") rather than the packet path writing a shared total. This is the one
   structure whose cost model is not in the contract, so it takes a plan from
   the table policy rather than a new one: `table_policy.md`'s benchmark plan,
   its Usage counters (G5) row in §7a -- per-packet cost of NoUsage vs
   InlineUsage vs AtomicUsage vs PerWorkerUsage at 1-8 workers, NoUsage's
   disassembly identical and the costs reported -- read back the way this one
   has to be, from the control plane, over live sessions under symmetric and
   asymmetric RSS.
3. **The transaction wire.** A typed rule is 131 B and a message is capped at
   64 MiB, about 510K rules, so bulk programming is chunked. This layer already
   programs one session per transaction, below the cap by design.
4. **Restart.** PFCP has no "give me your sessions", and BESS holds the
   *dataplane's* state (rules, actions, tunnels, counters), not the control
   plane's: a session's SEIDs, its URR configuration and its identity are
   `upfd`'s, in memory. So a restart needs a checkpoint and a replay path --
   and, until then, the controller empties the session tables itself at
   startup (`session.Compiler.Sweep`, in bounded transactions, before the PFCP
   socket opens, and fatal to the run if it cannot finish), because the previous
   incarnation's records are indistinguishable from this one's.
   The replay path is `upfd -checkpoint <path>`: an append-only journal of the
   *applied* PFCP session messages, not a serialisation of the model, because
   the messages are already the complete description of what a session is, any
   second format would be a second thing to keep in step with the first, and
   replaying messages is what an SMF does. A record is written before the SMF is
   answered, so a change it was told about is in the file and a torn last line
   belongs to a message nobody was answered for -- which its own retransmission
   puts back. A restart sweeps first -- the dataplane's records are the graph's,
   and dropping them wholesale is what makes the replay an installation rather
   than a trust fall -- and then replays the journal in order, pinning each
   session's local SEID to the value the journal recorded, so a retransmission
   of an establishment the previous incarnation accepted is answered with the
   same SEID.
   The stamp is what makes the replay coherent with the SMF rather than a trap:
   a restart that restored the journal re-advertises the *recorded* Recovery
   Time Stamp, so the SMF does not consider its sessions lost and does not
   re-establish them -- it would be re-establishing into rules the restored
   sessions still hold, and `compile` would refuse every one of them for the
   key. A restart with no usable journal mints a new stamp (and clears the file
   to begin with it), so the SMF's re-establishment is exactly what the sweep
   made room for. That is also why the association's end clears the journal: the
   CP function restarted, so the sessions it describes are void (7.4.1) and a
   later restart of ours must not hand them back.
   *Proof:* `internal/session`'s TestTheCheckpointReplaysSessions (a second
   compiler holds the same session under the SEID the SMF addresses -- a
   modification at that SEID is accepted -- with the deleted session still gone
   and the journal unchanged by the replay),
   TestTheCheckpointIgnoresATornRecord, TestTheCheckpointRefusesCorruption,
   TestTheCheckpointStampSurvivesARestart,
   TestTheAssociationEndingClearsTheCheckpoint, and
   TestTheAssociationAnswerCarriesTheConfiguredRecoveryTimeStamp in
   `internal/n4`; `ci/n4-path.sh`'s checkpoint phase does it live: a session
   established into a checkpointed `upfd`, the process killed, its successor
   logging `checkpoint replayed ... sessions=1` with the same Recovery Time
   Stamp, and the replayed rules selecting packets with no SMF message since the
   restart. The file is appended to and never rewritten by a replay, so folding
   a long session's chain into one record is compaction, and it is not a
   prerequisite for the replay being correct: a replay reads the records in the
   order they were written.
5. **Id and priority space.** uint32 throughout (PDR priority, ActionId, meter
   id): a million sessions at four PDRs is 4M rules, which fits.

What proves it, on a quiet machine: `BM_ClassifyUnderTransactions` and
`BM_LookupsUnderTransactions` at this session count, `table_scale_bench`'s
wildcard row at 10^6 rules for the per-packet cost, `update_scale_bench` E2 for
the sharding decision at 10^7 keys, a WildcardMatch bytes-per-rule measurement
to replace the one unmeasured cell above, the URR counter benchmark wall 2 names
(that plan's G5 row), and `ci/bench-n4.sh` for the N4 rate that drives all of it.

### The envelope, measured (2026-10-16)

Three regimes, three tools, one host (`bessd 612cbff1`, no hugepages). Each
number is the rate of the thing named, and they are not interchangeable:

| path | tool | result |
|---|---|---|
| the transaction engine, in process | BESS's `BM_ClassifyUnderTransactions` | 695K sessions/s (the control) |
| the live API: client, gRPC, daemon | BESS's `live_transaction_bench` | 6.0-6.4K transactions/s; p50 110 us |
| N4 end to end: PFCP, compile, one transaction, ack | `ci/bench-n4.sh` + `cmd/n4bench`, serial | establish 2,274.8/s (p50 324 us), modify 2,585.6/s, delete 5,379.0/s |

A session is one transaction of eight changes plus an N4 round trip, so 2.3K
sessions/s against 6K transactions/s is the expected cost of those two hops,
not a defect. The live rate is wire-bound before it is anything else: a
transaction's p50 is about 110 us, so one synchronous client cannot ask for much
more than 9,000/s. The 695K is the same machinery with no wire in the path --
the two numbers differ by the API, not by a hundredfold regression.

The defect is on the other side of the graph. At 6,000 transactions per second
the packet path loses 47% of its rate, and the law is linear: 1,000/s costs 8%.
The cost is about 80 us of datapath time per transaction. That is BESS's to
carry, it is written down in its performance contract's live-API section, and it
is the number a session has to be programmed against a million times over.
Finding which part of a change's publication to the workers costs those 80 us --
the generation handoff, or the reader's next-iteration check -- is the next
experiment.

Two operational findings from the same runs. `upfd` must bound how many
transactions it has in flight: 256 concurrent applies made the node answer eight
and then stall for thirty seconds at a time (reproduced twice, with the client's
own SEID bug ruled out), while one worker doing the same 16 sessions never
missed a reply. And the run that measures this must fail when answers are
missing, or a starved box and a slow UPF look alike.

## What proves it

- `ci/smoke-gtpu.sh` — the datapath, byte for byte: it builds the plugin against
  the staged `bess-dev`, loads it into the staged `bessd`, applies
  `deploy/smoke-gtpu.yaml`, and checks the decapsulated frame, the TEID in
  metadata, the drop of a TEID no rule names, and the encapsulated outer headers
  against the log's packet dumps.
- `ci/session-live.sh` — the control path against a real daemon:
  `deploy/session-live.yaml` is the graph, and the Go test it runs programs a
  whole session into the running `bessd` through the SDK (establish, retransmit,
  modify, delete, retransmit the delete). Every message is built from the
  daemon's own schema, so a key or value it does not accept fails the test with
  what it said -- the class of mistake no recorder catches, and the one this
  layer made (an F-TEID keyed as a dense id).
- `ci/bench-chain.sh` — the plugin's arms for the perf tool: a GTP-U decap or
  encap arm is not BESS's number to take.
- `ci/iface-path.sh` + `ci/ifacepath` (`deploy/iface-path.yaml`) — the interface
  grammar, one arm per case and each window sliced out of the daemon's own log:
  every Source Interface value a PDI can name and every Destination Interface
  value a FAR can name, checked against the exit its packet left by, byte for
  byte (the plain hop with its L2 pair, a tunnel out of the instance, the
  service LAN, the access side through the encap, the 5G VN re-injection into
  the subscriber-side table), and every value this UP refuses against the cause
  the SMF reads -- 73 for a value it does not serve or an egress the instance
  does not declare, 66 for the IEs Tables 7.5.2.3-1/-2 make mandatory. The same
  lane holds the subscriber ARP answer: a request for a live session's UE
  address is answered with the interface's MAC and the session's address, one
  session's two colliding addresses ride one transaction and both survive, and a
  deleted session's address stops being answered.
