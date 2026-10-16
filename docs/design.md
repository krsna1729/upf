# Design

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
| PDR (Precedence, PDI: Source Interface, F-TEID, Network Instance, UE IP, SDF filters) | one rule in the PDR table (WildcardMatch for masked keys, a range classifier for port ranges) whose result is `{gate, ActionId}` |
| FAR (Apply Action, Forwarding Parameters: Destination Interface, Network Instance, Outer Header Creation) | a *treatment* resource the action references (forward / drop / buffer / notify) plus the next hop and GTP-U encap parameters |
| QER (Gate Status, MBR, QFI) | a meter resource per QER, referenced from the action |
| URR (Measurement Method, Reporting Triggers, thresholds, period) | a counter resource per URR plus a reporting task; reports become PFCP Session Reports |
| Session (CP F-SEID, UP F-SEID) | one transaction's worth of resources, all named `<session-id>/…` |
| Network Instance (N3/N6/N9) | a route domain; overlapping subscriber prefixes never collide because each domain has its own table |
| Outer Header Creation (TEID, peer address) | the tunnel encap parameters of the treatment |

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
  packet on (TS 29.281 answers an Error Indication to the peer; the notification
  path is a later item). This is also the *whole* cost of the F-TEID match, and it
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
IP packet, not a frame (TS 29.281). Neither direction copies a payload byte.

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
| URR volume and time | two additions into worker-local counters (relaxed) | 0 |
| BAR | a slot write, only on a buffered packet | 0 |
| ULCL / branching | one route-domain select from the record | 0 |

**State policy (the path to 400G).** No shared mutable state in the packet path:
classifiers and records are per-worker copies published by RCU; URR counters are
worker-local and summed by the reporting task (no atomics in the path); token buckets
are per flow, and under RSS a flow maps to one worker, so a flow-level QER is enforced
exactly by that worker. A *session*-level QER spans flows on several workers, which is
the one place where exactness and scale conflict: the default is a per-worker share of
the session's MBR (an approximation, bounded by the worker count), with a
shared-counter mode for deployments that need a hard session limit. The choice is a
QER property, not a global switch.

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

**Fusion decision from these numbers.** The decap is 44 cycles, the encap 63, and the
classifier in front of the decap is ~49 (its control above `M.base`, including its rule,
the attribute reader and two hops). Fusing parse-and-classify would save the hop between
them (2-4 cycles) and the metadata write (one store): under 10% of what the pair costs,
in exchange for a forked classifier that would have to carry every future WildcardMatch
change. They stay two modules.

**The composition's rate**, for the shape the lab can offer: the whole graph
(`deploy/session-path.yaml`: both chains, the plugin's decap and encap, one session
programmed over N4) carries 7.25 Mpps per direction and 14.5 Mpps together on one
worker core -- three rounds of `ci/bench-graph.sh`, 7.254/7.273/7.254 Mpps. That is
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
| Cartesian expansion of port ranges into many rules | range keys and masked rules are a classifier concern, and the mask limit is now configurable (`max_tuples`) | one rule per PDR with a range/mask key |
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
- The `Message` interface has no `Marshal`: sending means `MarshalLen` plus
  `MarshalTo` into a buffer the caller owns.

Moving the pin is a decision, not a `go get`: read the diff of `message/` and
`ie/`, and re-check these facts.

## Restart and failure semantics

- `bessd` restarts: every handle goes stale (`StaleResourceError`), the
  controller re-reads `Capabilities`/`Pipeline`/`Resources`, reapplies the
  graph, and re-programs sessions from its own PFCP state; PFCP peers see
  `Association Release`/`Heartbeat` timeouts meanwhile.
- `upfd` restarts: it re-reads BESS state and rebuilds sessions from it; a
  session the SMF still holds is re-established through a PFCP Session Report
  or a Modification from the SMF, and a session only BESS knows about is
  erased (it has no CP F-SEID to answer to).
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
5. **Usage** — URR counters, reporting triggers, session reports. *Proof:* a
   report matches the packets a source produced, within a known bound.

Each milestone lands with its tests and a run that shows it, not with a
scaffold for the next one.

## Session scale: 10^6 sessions, dimensioned by PDR/FAR/QER/URR/MAR

The target is a million sessions on one box, with the packet path unchanged
while they are programmed. The BESS performance contract already measures every
structure this design uses, so the arithmetic below is that table at this shape
(4 PDR, 4 FAR, 2 QER, 2 URR, 1 MAR per session).

| per session | state in BESS | measured bytes | at 10^6 sessions |
|---|---|---|---|
| 4 PDR | WildcardMatch rule (masked table, per worker) | not measured: 16-byte key, mask, value, priority, result, cuckoo body | about 360 MB partitioned, about 2.9 GB if every worker holds every rule |
| 4 FAR | ActionTable record (`ObjectTable`) | 64 B/object | 256 MB |
| 2 QER | `MeterSet` | 64 B state + 8 B pointer | 144 MB (1,048,576 meters measure 64 MiB) |
| 2 URR | `CounterSet` block | 4 KiB for three counters (each slot per worker: 64 slots) | the wall: 8 GB if each URR owns a full per-worker block |
| 1 MAR (ATSSS, P1) | per-session record | not measured, small | about 64 MB |
| 1 F-TEID | the decap's tunnel table | 64 B/object | 64 MB |

Time is measured at scale where memory is not: the masked table looks up 32
keys in 556 ns at 10^6 rules with one mask tuple, 1,716 ns with four and
2,463 ns with eight (17 / 54 / 77 ns per key), and an add+delete costs about
1 µs up to 100K rules (performance contract row 75). The tuple count is the
graph's `max_tuples`, so it is a UPF decision, not a default.

Rates, measured (performance contract rows 66-67): one transaction per session
sustains 695K sessions/s (519K in the other profile), and with the writer flat
out at 194K sessions/s four readers still do 44.8 Mpps each, from 49.3 at rest.
A million sessions is therefore seconds of control traffic, not a migration.

The deployment's own numbers, through the whole N4 path (a PFCP message, the
session compiler, one transaction, the daemon's answer) with one client in
flight, 64 sessions, `ci/bench-n4.sh` MODE=full: establish 786 µs p50 (1,184/s),
modify 353 µs p50 (2,595/s), delete 213 µs p50 (4,256/s); p99 1.54 ms, 636 µs
and 471 µs. That is the rate an SMF sees today, and it is per session in flight,
not per core: with eight in flight the same run answers 7 of 256 establishments
within 5 s and the rest minutes later (the daemon logs those as "answer to no
request"), so the runway to the transaction numbers above is a client-side
stall, not the compiler -- the next thing to fix, and the reason the bench's
default is one worker.

The walls, in order:

1. **Per-worker tables.** Classifier rules and action records are per-worker
   (D-097). Sharding by flow owner -- the worker whose queue sees the session
   -- measures 3.4x better than one shared table at 3% new flows
   (`update_scale_bench` E2), so sessions are sharded, not shared.
2. **URR counters.** A counter block is priced per worker slot (`CounterSet`:
   4 KiB for three counters): right for a hot counter, wrong for a million
   mostly-idle sessions. A URR must allocate its block on the worker where the
   session is live, and a control read must sum the live copies. This is the
   one structure whose cost model is not in the contract, so it needs its own
   benchmark (live sessions, counter blocks, read from the control plane).
3. **The transaction wire.** A typed rule is 131 B and a message is capped at
   64 MiB, about 510K rules, so bulk programming is chunked. This layer already
   programs one session per transaction, below the cap by design.
4. **Restart.** PFCP has no "give me your sessions": if `upfd` restarts the SMF
   does not re-establish, so the session store needs a checkpoint and a replay
   path. BESS holds no session state to recover.
5. **Id and priority space.** uint32 throughout (PDR priority, ActionId, meter
   id): a million sessions at four PDRs is 4M rules, which fits.

What proves it, on a quiet machine: `BM_ClassifyUnderTransactions` and
`BM_LookupsUnderTransactions` at this session count, `table_scale_bench`'s
wildcard row at 10^6 rules for the per-packet cost, `update_scale_bench` E2 for
the sharding decision at 10^7 keys, a WildcardMatch bytes-per-rule measurement
to replace the one unmeasured cell above, the URR counter benchmark from wall 2,
and `ci/bench-n4.sh` for the N4 rate that drives all of it.

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
the generation handoff, the per-worker table swap, or the reader's
next-iteration check -- is the next experiment.

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
