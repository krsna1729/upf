# The datapath: modules, resources and placement

Engineering reference for `datapath/` (the UPF's BESS plugin) and the graphs it
plugs into. It is deliberately narrower than the other files:

| file | what it owns |
|---|---|
| `docs/design.md` | why the deployment is shaped this way, the walls, the costs, the milestones |
| **`docs/datapath.md`** (this) | what each module is, which resource it owns and under which key, what it takes from BESS, how packets and workers are placed |
| `docs/compliance.md` | clause-by-clause status and the test or script that proves each row |
| `docs/scorecard.md` | how the field scores, and what each of our numbers rests on |
| `README.md` | how to build, run and prove |

## The graph

One `bessd`, one graph, one set of workers. `[0]` on an arrow is the gate the
packet leaves by; a gate no connection wires is a drop. `WCM` is
`WildcardMatch`, and every `WCM` rule's value is `{priority, gate, action_id}`
(BESS D-141): the action id the classifier writes is the id everything
downstream is keyed by.

### Uplink

```
   N3  PMDPort (n3), num_rx_queues: 1
    |
    v
 +-----------------+          +--------------------+          +---------------------+
 | n3_in  PortInc  |--- 0 --->| teid   WCM         |--- 0 --->| decap0  GtpuDecap   |
 +-----------------+          |  key: GTP-U TEID   |          |  strips Eth/IP/UDP/ |
                              |  one rule/session  |          |  GTP-U; writes      |
                              +---------+----------+          |  upf_teid, qfi (u8) |
                                        |                     +----------+----------+
                          ogate 1: default gate                         | 0
                          (TEID 0, no rule)                              v
                                        |                     +---------------------+
                                        v                     | mt_ul_read          |
                              +-------------------+           |  MetadataTest       |  (a write-only attribute
                              | echo0  GtpuEcho   |           |  reads upf_teid     |   gets no offset unless
                              |  type 1 -> type 2 |           +----------+----------+   something reads it)
                              +---------+---------+                      | 0
                                        |                                v
                                        |                     +---------------------+
                                        |                     | pdr_ul  WCM         |
                                        |                     |  key: inner 5-tuple |
                                        |                     +----------+----------+
                                        |                                | 0
                                        |                                v
                                        |                     +---------------------+
                                        |                     | at_ul  ActionTable  |  its own resource is
                                        |                     |  {meter, next hop}  |  at_ul/actions; meters
                                        |                     +----------+----------+  and next hops are
                                        |                                | 0           resources it reads
                                        |                                v
                                        |                     +---------------------+
                                        |                     | mt_ul  Meter        |
                                        |                     +----------+----------+
                                        |                                | 0
                                        |                                v
                                        |                     +---------------------+
                                        |                     | cnt_ul  UrrCount    |
                                        |                     +----------+----------+
                                        |                                | 0
                                        |                                v
                                        |                     +---------------------+
                                        |                     | rt  Router          |
                                        |                     +----------+----------+
                                        |                                | ogate 0
                                        v                                v
                              +-------------------+          +---------------------+
                              | n3_out  PortOut   |---> N3   | n6_out  PortOut     |---> N6
                              +-------------------+          +---------------------+
                                 ^                                        ^
                                 |                                        |
                          echo0's reply, the                    rt's ogate 0 (next hop 1):
                          End Marker's frame                    the deployment's N6 port
```

### Downlink

```
   N6  PMDPort (n6), num_rx_queues: 1
    |
    v
 +-----------------+          +--------------------+
 | n6_in  PortInc  |--- 0 --->| pdr_dl  WCM        |
 +-----------------+          |  key: inner 5-tuple|
                              +----+---------------+
                                   | 0
                                   v
                        +------------------+
                        | at_dl ActionTable|<--------------------+
                        +--------+---------+                     |
                                 | 0                             |
                                 v                               |
                        +------------------+                     |
                        | mt_dl  Meter     |                     |
                        +--------+---------+                     |
                                 | 0                             |
                                 v                               |
                        +------------------+                     |
                        | cnt_dl  UrrCount |                     |
                        +--------+---------+                     |
                                 | 0                             |
                                 v                               |
                        +------------------+                     |
                        | rt  Router       |                     |
                        +--------+---------+                     |
                                 | ogate 1                       |
                                 v                               |
                        +------------------+                     |
                        | enc  GtpuEncap   |                     |
                        |  outer headers,  |                     |
                        |  DSCP copy/mark  |                     |
                        +--------+---------+                     |
                                 | 0                             |
                                 v                               |
                        +------------------+                     |
                        | n3_out  PortOut  |---> N3              |
                        +------------------+                     |
                                                                 |
   pdr_dl, ogate 1 (deploy/buffer-path.yaml only)                |
                                                                 |
                        +------------------+                     |
                        | cnt_buf  UrrCount|--- 0 --->+          |
                        +------------------+           |          |
                                                       v          |
                                             +-------------------+--+
                                             | buf  PacketStore     |  BESS's own module,
                                             |  key_attrs:          |  one queue per rule
                                             |  ["action_id"]       |
                                             +----+-----------------+
                                                  | gate 0: release, into the action path
                                                  +-----> at_dl (above), which applies the
                                                          SMF's new instruction
                                                  | gate 1: unwired -> dropped
                                                  +-----> eviction and overflow; the daemon's
                                                          gate counters see them
```

### The control plane's own port

```
   cp_in  PortInc -----> dump_m  Dump -----> sink_m  Sink      (deploy/session-path.yaml)
      ^
      |  one write of a whole frame, SOCK_SEQPACKET
   upfd (-end-marker): constructs the 60-byte End Marker itself
```

| graph | used by | what differs |
|---|---|---|
| `deploy/upf.yaml` | the deployment | PMD ports `n3`/`n6` (one rx queue each), `MetadataTest` after the decap, the marker port; **no buffering branch** |
| `deploy/session-path.yaml` | `ci/session-path.sh`, `ci/n4-path.sh`, `ci/session-report.sh` | Sources `src_up`/`src_dn`, `Rewrite`, `Dump`, `Sink`; frames fixed so a test can byte-check them; no buffering branch |
| `deploy/buffer-path.yaml` | `ci/buffer-path.sh` | `session-path.yaml` **plus** `cnt_buf`/`buf` and the `pdr_dl` ogate-1 connection; needs a daemon with BESS's packet store key attribute |
| `deploy/session-live.yaml` | `ci/session-live.sh` | no packet path: the control path's tables only |
| `deploy/smoke-gtpu.yaml` | `ci/smoke-gtpu.sh` | the two datapath halves alone |

Gate numbers, in full: `0` is the chain's next module; `8192` is `DROP_GATE`
(`core/gate.h`), what a rule carries when its FAR drops or a QER's gate is
closed; `1` on `pdr_dl` is the buffering branch; `1` on the uplink's `teid`
table is the echo module; and any gate no connection wires drops the packet,
which is why the store's evictions need no module of their own — the store
*evicts* a flow's oldest packet on gate 1 when its per-flow cap is reached, and
*frees* an expired one outright (`EvictExpired`'s `bess::PacketFree`, no gate,
no metric) when the store is at its global `max_packets` and its flow's own
timeout has passed.

A buffering flow's numbers are the SMF's, not the graph's: the compiler writes
the store's `flows` entry for every buffering rule, keyed by the rule's
ActionId — `timeout_ns` from the BAR's DL Buffering Duration (8.2.29, the
infinite unit as a present zero) and `max_packets_per_flow` from its Suggested
Packet Count (8.2.30) — and leaves a field out where the SMF named none, which
is when the module's own arguments above are the flow's numbers. The store's
`StoreBatch` enforces the cap on every arrival; its timeout is honoured only in
`EvictExpired`, which runs when `total_packets_` reaches `max_packets`, so a
flow's duration bites under global memory pressure rather than on a timer of its
own.

## Modules we own

Four modules, one `.so` (`BESS_PLUGIN` + `ADD_MODULE`, `datapath/meson.build`),
built only against the installed `bess-dev` stage.

| module | mclass | resource it owns (key) | state it holds | workers |
|---|---|---|---|---|
| `gtpu_decap.{h,cc}` | `gtpu_decap` | none | `port_`, two attribute ids | all |
| `gtpu_encap.{h,cc}` | `gtpu_encap` | `<module>/tunnels` (`TunnelKey{action_id}`) | `src_ip_`, `max_tunnels_` | all |
| `gtpu_echo.{h,cc}` | `gtpu_echo` | none | `port_`, a Recovery Time Stamp | all |
| `urr_count.{h,cc}` | `urr_count` | `<module>/counters` (`CounterKey{action_id}`) | per-worker cell planes, per-rule stamp pairs | all |

Two resources, then: the encap's tunnels and the counters — one instance of the
latter per direction, plus one on the buffering branch.

### `gtpu_decap` — the N3 entry

Strips Ethernet, IPv4, UDP and GTP-U (the header itself is parsed with the
installed `tunnel/tunnel.h` codec) and writes the tunnel's TEID into the
packet's `upf_teid` metadata (`be32`). It owns **no resource**: whether a TEID
belongs to a session is the `teid` `WildcardMatch`'s decision, so an unknown
TEID never reaches the module (`teid/rules` is the table the controller writes,
the sweep reads and the TEID-0 echo rule lives in). The attribute is a *write*,
so something downstream must read it or it gets no offset at all
(`core/metadata.cc`) — `MetadataTest mt_ul_read` in `upf.yaml` and the lab
graphs, and the encap further along the same chain. Attributes are laid out in
module registration order, which is why the decap is listed early everywhere.

It also writes the QFI the incoming G-PDU's PDU Session Container carried into
the one-byte `qfi` attribute — the GTP-U extension header of type 0x85
(TS 29.281 5.2.2.7), whose QFI is the low six bits of the container's second
content octet (TS 38.415 5.5.2.1). That is the QoS flow the gNB put the uplink
packet on, and it is what tells two uplink PDRs that share one F-TEID apart.
The module walks the extension header chain for it (the tunnel library reports
the chain's first type and skips the rest) and writes `0` for a G-PDU with no
container; the zero is written rather than skipped because a packet's metadata
is reused buffer space that nothing clears, so a skipped write would let one
packet's QFI reach the next packet's rule lookup. The reader is the uplink rule
table: `pdr_ul`'s match `fields` name the attribute, and a rule's mask is
`0xff` when its PDR named a QFI and `0x00` when it did not.

### `gtpu_encap` — the N3 exit

Writes the outer Eth/IPv4/UDP/GTP-U around a downlink packet from the tunnel
record the packet's ActionId names — `{teid, gnb_ip, ether_src, ether_dst,
qfi, marking}` — copying the inner TOS onto the outer header (the RAN's
transport is DSCP-marked; dropping it would send every downlink packet as best
effort) and recomputing lengths and checksums. One record per downlink rule: the
controller resolves the FAR once, at programming time, so the packet path does
one indexed load and chases no control-plane relation.

When the record names a Transport Level Marking (TS 29.244 8.2.42, from the
FAR's forwarding parameters), the SMF's DSCP wins over the inner packet's: the
marking's high octet is the ToS/Traffic Class the outer header carries and its
low octet is the mask naming which of the inner header's own class bits survive
— the ECN bits, with the spec's 0xFC, which applying the marking must not change
(the NOTE under 8.2.42). `marking == 0` means the SMF asked for none and the
inner TOS is copied byte for byte, which is what a record written before the
field existed reads as.

A record naming a QFI also gets a PDU Session Container after the GTP-U header
(TS 29.281 5.2.2.7; the content is TS 38.415's): the E flag set, the 4-octet
optional tail whose last octet names the extension header, and one 4-octet
unit of container — length 1, the DL PDU session information content (PDU type
0 in the high nibble of its first octet, the QFI in the low six bits of its
second), and no further extension header. That is 8 bytes of the packet's
headroom, sized before the prepend; a record with `qfi == 0` writes none of it,
so the wire is byte for byte what it was before the field existed.

### `gtpu_echo` — path management

Answers a GTP-U Echo Request (type 1, TEID 0 — the only message a UPF sees on
TEID 0 that names no session) with the reply TS 29.281 7.2.2 prescribes, and
drops everything else it is handed. It is reached through the TEID table's
*default* gate and sits outside the session path entirely; it reads no session
state and allocates nothing.

### `urr_count` — usage, and the buffering signal

Counts packets and octets per rule (the *IP packet's* octets, not the frame's)
and stamps each rule's first and last counted packet. The `<module>/counters`
entry's existence is the whole test — a rule with no entry is counted by nobody,
which keeps a session without a URR off the module's cost (one lookup) — and one
instance serves two purposes in two places: a direction's counters for URRs, and
the arrival signal the Downlink Data Report is decided from on the BUFF branch.

* **Locality.** Cells are worker-local: one plane per worker, whole cache lines
  apart, written with a relaxed load-add-store and never a locked instruction
  (`stats/worker_slots.h`'s rule). A reading sums the planes, so it is exact per
  cell, not one global instant; the memory is `capacity × 2 × 8 B × workers`.
* **The one shared write.** A rule's stamp pair is the rule's own fact, not a
  worker's, so it is shared and written once per batch that counted a packet —
  never once per packet, and by design a store lost to a concurrent reader costs
  one packet's stamp rather than a count (`urr_count.h`).
* **Reads** are the `get_counts` command
  (`upf.pb.UrrCountCommandGetCountsArg` → `…Response`), which is also how the
  control side asks for a *window*: with `restart_window` the module clears each
  rule's first stamp, so the next reading's stamp means "a packet arrived since".
  The URR path uses that to open its next window; the DDN path reads with
  `restart_window: false` and clears only once the SMF has taken the report
  (`bess.Client.{RuleCounts,PeekRuleCounts}`).

## Modules and drivers we take from BESS

Used as they are; the configuration is ours and is what the compiler assumes.

| module | where | the configuration that matters |
|---|---|---|
| `WildcardMatch` | both PDR tables, the TEID table | `action_resource: <at_*/actions>` (D-141: the rule's action id goes to the packet's `action_id`), `fields` = the graph's key in the order the compiler's `PDRFields` names, `max_tuples` |
| `ActionTable` | one per direction | its own resource is `<module>/actions` (a rule's `{meter_id, next_hop_id}`); it *reads* `mt_*/meters` and `rt/next_hops` and fails closed when the id it writes has no reader |
| `Meter` | one per direction | `<module>/meters`, the QER's committed and peak rate; a closed gate compiles to the drop gate instead |
| `Router` | one, both directions | `<module>/next_hops`, the egress gate an action names |
| `PMDPort` | `n3`, `n6` | `num_rx_queues: 1` each in the deployment's graph; RSS and one worker per queue are the scale path, and the one-port split (per-pattern RSS, `L3_SRC_ONLY` uplink / `L3_DST_ONLY` downlink) is designed in `docs/design.md`, "N3, N6, N9" — no graph wires it yet |
| `UnixSocketPort` | `cp_marker` | `SOCK_SEQPACKET`: one write from `upfd` is one End Marker frame |
| `PortInc`/`PortOut`, `Sink`, `Source`, `Rewrite`, `Dump`, `MetadataTest` | graphs | plumbing and lab only; a `Sink` has no output gate, so it appears in no metric — the counters that prove behaviour sit on modules' *output* gates |
| `PacketStore` | the buffering branch (`buffer-path.yaml`) | `key_attrs: ["action_id"]`, `max_packets`, `max_packets_per_flow`, `timeout_ms`; one owner task, any number of workers. `release`/`drop`/`clear` are commands that enqueue into the store's own request ring (`Command::THREAD_SAFE` since BESS `cdeb4e77`), and its `flows` table is live configuration (`requires_paused_workers: false`), so neither a command nor a flow write is refused with EBUSY or RESOURCE_BUSY and nothing stops the datapath; a command is **accepted, not completed** -- the store's owner task applies it on a later run -- so a caller that needs the effect reads it back (`ps/flows`, the drop and release counters, `GetDesc`). A flow the store holds nothing for is a no-op (ENOENT is gone; the only refusal left is ENOSPC, a full request ring), an upsert or an erase moves no packet, and an erase removes configuration only -- `drop` is what frees what a flow holds (BESS's note: `packet_store: the flow key is a configured attribute, not a fixed pair`, 96d22a8f). The `flows` entries are the SMF's own numbers: `internal/session` writes one per buffering rule (`writeFlowEntry`), keyed by the rule's ActionId, with `timeout_ns` from 8.2.29's DL Buffering Duration and `max_packets_per_flow` from 8.2.30's Suggested Packet Count, each left out where the SMF named none; a modification's Update BAR rewrites it, a deletion erases it, and the startup sweep names the table. BESS's `LimitsFor` resolves it per flow; the store then enforces the cap on every arrival (`StoreBatch`) and, when `total_packets_` reaches `max_packets`, ages each flow's packets past its `timeout_ns` out with `bess::PacketFree` in `EvictExpired` -- a silent discard (no gate, no metric; only `GetDesc`'s stored count falls), distinct from the `drop` command's counted free and from the gate-1 eviction the cap uses |
| `Vif` | not wired yet | the module that would write a packet's `vif_id`/`route_domain` from the PDI's Network Instance (`docs/design.md`, "N3, N6, N9") |

## Framework and library surface we use

| surface | where we use it |
|---|---|
| control_v2, one transaction per session change | `internal/session` writes a session's rules, actions, meters, counters and tunnels together or not at all, with a request id that survives retries |
| resources and codecs (D-129) | the tables above: configuration written in a transaction, a codec that validates the key, and a readback the startup sweep uses. The store's `flows` is one of them (one entry per flow id, each field optional, absent meaning the module-wide argument), written by the session compiler with the SMF's own numbers (8.2.29's duration as `timeout_ns`, 8.2.30's count as `max_packets_per_flow`) in the same transaction as the rule: an upsert or an erase moves no packet and stops no worker, and an erase is configuration only — `drop` is what frees what a flow holds |
| module commands | `get_counts` (counters), `release`/`drop`/`clear` (the store's *held packets* — commands act on state, resources on configuration) |
| metadata attributes | `action_id` (written by `WildcardMatch`, read by counters, the encap and the store), `upf_teid` (written by the decap), `qfi` (written by the decap, one byte: the uplink PDU Session Container's QoS flow, read by `pdr_ul`'s match fields), `route_domain`/`vif_id` (the `vif` work) |
| slot tables (`dataplane/slot_table.h`) | every per-rule table: ids are 1..capacity, an erased key retires for a grace period, and publishing into a retiring slot is refused — which is why released ids wait their walk (`docs/design.md`, the id pool) |
| packet ownership | `bess::PacketRef` and the store's explicit free/release path; our modules copy no packet and allocate none |
| tasks (`RegisterTask`/`RunTask`) | BESS's store drains released packets from a task; **none of our modules has one** — nothing in our packet path runs between packets |
| `GetSchema`/descriptor set | the controller builds every message from the daemon's own schema, so a field this plugin does not have fails loudly instead of silently |
| `ListMetrics` (D-116) | per-gate counters: how an unwired gate's drops (store eviction, overflow) and a chain's throughput are read. What it does *not* show is a command's effect on the packets a module holds: `packet_store`'s `drop` frees them with `bess::PacketFree` and only decrements `total_packets_` (visible in `GetDesc`, not in metrics), `EvictExpired` frees an aged flow's packets the same way (its own timeout, no counter at all), while `release` moves them to the release queue, which does reach a gate — and only once the store's owner task has applied the request, since the command is *accepted* when the call returns. That is why the session layer counts the *accepted* commands it issued (`Stats.BuffersReleased`/`BuffersDropped`/`BufferFailures`) rather than reading drops back out of the daemon |
| `tunnel/tunnel.h`, `conntrack/packet_parse.h` | header-only, experimental: the GTP-U codec and the parse types, installed by `bess-dev` |
| `utils/{ip,ether,checksum,endian,time,logging}.h`, `dataplane/action_id.h`, `framework/{resource_codec,resource_registry,resource_bindings}.h`, `commands.h`, `pb/module_msg.pb.h` | the rest of the plugin's includes; no module reaches past these into BESS internals |

## Placement, queues and state locality

* **One daemon, one graph, one writer.** `upfd` is the only writer of session
  state; the graph's own resources (next hops, module arguments) are the
  deployment's.
* **Workers: who may run where, and what stops.** Each module declares both how
  many workers it tolerates and whether writing its resources needs the workers
  stopped. Ours declare *all* workers (`max_allowed_workers_ =
  Worker::kMaxWorkers`) and no pause: `urr_count`'s cells are one plane per
  worker, so two workers never touch a line, and its two resources behave like
  the daemon's own concurrent ones.
* **Which part of this graph needs paused workers: none of it — and no caller
  stops anything for the store.** A resource whose codec declares
  `requires_paused_workers` is **refused** with `RESOURCE_BUSY` while a worker
  runs its module ("nothing was tried", the SDK's `Resource` comment), and a
  command declared `THREAD_UNSAFE` is **refused** with `EBUSY` ("There is a
  running worker and command '%s' is not MT safe", `core/module.cc`); in both
  cases the daemon leaves the stopping to whoever is writing. The modules that
  declare the flag are `arp_responder` (`entries`), `bridge` (`statics`),
  `flowgen` and `vif` (`interfaces`) — none of them in any graph here; every
  resource the session path writes is a concurrent slot-table resource applied
  live (`WildcardMatch`'s rules, `ActionTable`'s actions, `Meter`'s meters,
  `Router`'s next hops, `enc/tunnels`, `cnt_*/counters`).

  The store was the one exception, and BESS `cdeb4e77` removed it: the module
  has one owner task, `release`/`drop`/`clear` are `Command::THREAD_SAFE` and
  enqueue a request into the store's SPSC request ring (the owner applies it on
  a later task run), and its `flows` table is live -- an upsert or an erase does
  not stop the datapath -- so `requires_paused_workers` is false. So
  there is nothing to pause around and nothing that answers `EBUSY`:
  `internal/bess` calls `InvokeAction` directly from `ReleaseFlow`/`DropFlow`/
  `ClearStore`, and the `storeCommand` wrapper that used to try, stop the
  workers on a refusal, retry and start them again — with
  `TestStoreCommandStopsTheWorkersOnlyWhenTheDaemonRefuses` pinning its
  orderings — is gone with the refusal it handled. A command there is
  *accepted*, not completed: the caller that needs the effect reads it back
  (`ps/flows`, the drop and release counters, `GetDesc`), which is also why a
  successful call is not evidence that packets moved.

  ```
  what stops, and who stops it

  (A) session state -- rules, actions, meters, next hops, tunnels, counters,
      and the store's live `flows` table
      upfd --commit--> daemon --publish--> concurrent resource
      workers ............................ running throughout: nothing stops

  (B) the store's own commands -- release, drop, clear
      upfd --invoke--> daemon: enqueue into the store's request ring
      workers ............................ running throughout: nothing stops
      the store's owner task applies the request on its next run
  ```

  A stop is still the shape for a `THREAD_UNSAFE` command or a paused-worker
  resource, and BESS's own modules are where either could appear again:
  `upfd --PauseWorkers--> invoke/commit --> ResumeWorkers`, bounded by one
  command or one commit and at signalling rate — a BAR arriving, a DDN answer
  releasing packets — never per packet. The SDK stays explicit (`InvokeAction`,
  `PauseWorkers`, `ResumeWorkers`) and D-146 keeps the three SDKs' surfaces
  alike, so such a loop would be this layer's policy rather than the SDK's
  method. The in-process tests cover a refusal's consequences as well
  (`TestAReleaseTheStoreRefusesIsCountedNotFatal` and the sweep's tests).
* **Where state lives.** Per-worker: the counters' planes. Shared, atomic,
  written once per batch: the counters' stamps. Per-rule, indexed by the
  ActionId the classifier wrote: the tunnel records and the counter entries.
  Per-packet: metadata. Behind a lock, control-plane only: the session model,
  the rule-ownership table, the id pools.
* **What the packet path never does**: allocate (except inside the store's own
  queue), take a lock, read a control-plane structure, or look a rule up twice —
  the classifier's result is the id everything downstream is keyed by.

## What we would fuse, and what decides it

The chain is split into the modules above because each one has a single job and its
state is owned at one layer. Fusion is available to us — our modules can hold a
table, and BESS's own primitives (the wildcard matcher, the meter's token bucket)
are ordinary C++ we can call — but a fusion *costs* a lookup's worth of state
ownership and gains a dispatch and a table lookup per packet. The measured arms are
what decide it (`docs/design.md`'s table, taken with `ci/bench-modules.sh`): the
front end is 8.09 ns/pkt, `gtpu_decap` +13.4 ns and 612 instructions over its
control, `gtpu_encap` +18.1 ns and 414 instructions, `urr_count` +4.19 ns for a
counted rule and +1.34 ns for a miss.

| fusion | what it removes per packet | what it costs |
|---|---|---|
| `teid` ⊕ `gtpu_decap` | one wildcard lookup and one batch dispatch — the decap already parses the header the lookup keys on | the decap would own a rule table and its TEID id space; today it owns none (its header comment says so) |
| `pdr_ul` ⊕ `at_ul` | one ActionTable lookup | the ActionId stops being the single id the meter, counter, tunnel and store flow all key on — the saving is one lookup, the cost is the whole downstream contract, so this is the fusion *not* to make |
| `mt_ul` ⊕ `cnt_ul` | one lookup and one dispatch | one module holding both the policer's bucket and the counter cells; both primitives are available to us (BESS's meter, our counters), and the cells' per-worker planes are the thing that must survive |
| `rt` ⊕ `enc` | the router's lookup on the downlink | the encap gains the route table; on a single-port N3/N6/N9 deployment (docs/design.md's port section) the next hop is a queue rather than a port, which is exactly the case where this fusion starts to look right |

None of these is done. Two things decide it, and neither is taste.

**The measurement.** `docs/design.md`'s "measure before any placement change" and
its "per feature, per packet" obligation mean an arm in `ci/bench-modules.sh` that
measures the fused module against the same work split, on the frames
`smoke-gtpu.sh` uses. The first such obligation is already owed by a feature in
this tree: the decap now parses the 0x85 PDU Session Container and writes `qfi`
unconditionally, and `pdr_ul`'s key grows by a field with its own mask, so the
decap arm must be re-taken against the 2026-10-16 baseline (+13.4 ns/pkt, 612
instructions over its control) on **both** frame kinds -- a G-PDU with a container
and one without -- and the rule table's tuple budget reported with it. That same
pair of numbers is what decides `teid` ⊕ `gtpu_decap`: a fusion has to beat the
lookup and dispatch it removes, and the decap's own arm is the upper bound on what
there is to win.

**The taps.** A split is also the place where the transformation is *observed*:
`smoke-gtpu.yaml` dumps the frame after the decap and after the encap, and
`ci/smoke-gtpu.sh` byte-checks both against the log, which is how a wrong header
length or a dropped option is caught at the stage that wrote it. Fusing two
modules removes that boundary: a tcpdump between them is no longer possible, and
"did the decap strip it or did the encap write it wrong" stops being answerable
from the wire. The tap that does not cost anything to have *off* is the daemon's
own: `core/gate_hooks/tcpdump.cc` and `pcapng.cc` are gate hooks switched at
runtime through control_v2's `SetCapture` (`core/control/admin_v2.cc:138`, a
direction of INPUT or OUTPUT, `FORMAT_PCAP` or `FORMAT_PCAPNG` to a fifo, one
gate or every gate of a module). No module is in the graph and the base path pays
nothing while the capture is off, which is what makes it usable as the evidence
for a stage -- and `pcapng` writes the metadata block, so a capture on `decap0`'s
output gate shows each packet's `qfi` and `action_id` next to its bytes, which is
how the QFI slice's own live check is taken (the Go SDK exposes it:
`sdk/go/bess/client.go:866`). So a fusion is acceptable only if the fused stage
stays observable through that surface or a per-gate tap of its own; the `Dump`
modules in `smoke-gtpu.yaml` are the same idea at fixed points, with a per-packet
copy that a measured graph should not carry. That is the ergonomic half of the
evidence, and it is a criterion, not a preference: what we would lose is exactly
the class of mistake the smoke test exists to catch.

**The fused module's table, decided before it is written.** `teid` ⊕
`gtpu_decap` needs a table keyed by TEID, and the primitive decides the cost the
fusion exists to win. It is not the one our other resources use: the tunnels and
the counters are `SlotTable<ActionId, …>` behind `SlotResource`, and that header
describes itself as "ObjectTable (K2) **without the rebuild**" — a change is one
pointer store and the object it replaced is retired through RCU. That fits dense
ids, and a TEID is a sparse `uint32` the *SMF* usually chooses (it sends the
F-TEID; we allocate only when it asks with CHOOSE/CHID, FTUP). So the dense
encoding — pool index plus a generation prefix — would serve only the TEIDs we
allocate and die on the case that matters, and a translation table for the SMF's
own TEIDs is a second lookup, i.e. no win.

The table is the daemon's own concurrent exact table, the one its match modules
use: `bess::classifier::ConcurrentExactTable`
(`core/classifier/concurrent_exact.h`), keyed on the four bytes of the TEID and
held behind `bess::rcu::RcuPtr<Generation>`, published through the runtime's
`RcuDomain` exactly as `ExactMatch` holds its table
(`core/modules/exact_match.h:259-269`: one acquire load per batch on the data
path, serialized rebuilds off it, the retired generation destroyed by a control
thread). It is rte_hash underneath — CRC32C over the key, a fixed capacity
(`CapacityFor(rules)`: three quarters of a power of two), per-key upsert and
remove with headroom for the deletes still waiting out a grace period, and a
deliberate rebuild only when it runs out of room. A session change is therefore
one upsert, not a rebuild of the whole table: O(1) per establish is what
`docs/design.md`'s `update_scale_bench` exists to hold at 10^5–10^6 sessions, and
a map rebuilt per transaction is precisely what it would catch. Per packet the
cost is one hash probe and one key compare — no masks, no key construction —
against `WildcardMatch`'s tuple-plus-masks path in the split chain.

**Status: deferred behind the feature list.** The fusion is a performance
experiment, not a capability — nothing in `docs/compliance.md`'s gaps or the
roadmap waits on it, and `docs/design.md`'s "measure before any placement change"
makes the module and its arm the price of an *answer*, not of a feature. The
design work above is the part that was expensive to derive, and it is recorded
here so the deferral costs nothing later. The module and the arm pair stay
unwritten until something needs the number — the single-port N3/N6/N9 placement
work is the first thing that will.

When it resumes, the first step is not the module but a control that needs no new
code: stock `ExactMatch` uses the same `ConcurrentExactTable`, so `teid` as an
`ExactMatch` (`fields: [{offset: 46, num_bytes: 4}]`, `default_gate: 1`) followed
by `decap0` is *unfused but already exact-table*. Three points then read cleanly
— split `WildcardMatch` (today), split `ExactMatch`, fused — and the middle one
separates the two wins: how much is the lookup kind (available with no module at
all) and how much is the dispatch the fusion removes. If `ExactMatch` closes most
of the gap, the fusion is not worth losing the tap and the module is never
written. That arm belongs in the same request as the fused pair.

## Building and loading it

```sh
PKG_CONFIG="pkg-config --define-prefix" \
  PKG_CONFIG_PATH=<stage>/lib/pkgconfig meson setup datapath/build
ninja -C datapath/build
bessd -modules=<dir with libupf_datapath.so> -f        # plus a graph
```

The plugin's wire types are `datapath/upf_datapath.proto`: `protoc` emits the
C++ and `.desc` during the build, and the descriptor set is installed next to
the `.so` so a controller can build the messages without generated Go code.
BESS's own `packet_store` needs no plugin; its flow key became configurable in
96d22a8f (`packet_store: the flow key is a configured attribute, not a fixed
pair`), which the buffering branch needs and no other graph does.
