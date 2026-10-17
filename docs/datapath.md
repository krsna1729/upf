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
                              +---------+----------+          |  upf_teid (be32)    |
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
                        |  DSCP copy       |                     |
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
which is why the store's evictions need no module of their own.

## Modules we own

Four modules, one `.so` (`BESS_PLUGIN` + `ADD_MODULE`, `datapath/meson.build`),
built only against the installed `bess-dev` stage.

| module | mclass | resource it owns (key) | state it holds | workers |
|---|---|---|---|---|
| `gtpu_decap.{h,cc}` | `gtpu_decap` | none | `port_`, one attribute id | all |
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

### `gtpu_encap` — the N3 exit

Writes the outer Eth/IPv4/UDP/GTP-U around a downlink packet from the tunnel
record the packet's ActionId names — `{teid, gnb_ip, ether_src, ether_dst}` —
copying the inner TOS onto the outer header (the RAN's transport is
DSCP-marked; dropping it would send every downlink packet as best effort) and
recomputing lengths and checksums. One record per downlink rule: the controller
resolves the FAR once, at programming time, so the packet path does one indexed
load and chases no control-plane relation.

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
| `PacketStore` | the buffering branch (`buffer-path.yaml`) | `key_attrs: ["action_id"]`, `max_packets`, `max_packets_per_flow`, `timeout_ms`; single worker; `release`/`drop`/`clear` are commands, and both they and (when it lands) a write to its `flows` resource are **refused** while a worker runs the module, so the caller stops the workers around them; a flow it holds nothing for comes back as ENOENT, which `internal/bess` maps to `ErrFlowNotHeld` and the session layer treats as nothing to do -- a BUFF FAR is in force long before any packet arrives (BESS's note: `packet_store: the flow key is a configured attribute, not a fixed pair`, 96d22a8f) |
| `Vif` | not wired yet | the module that would write a packet's `vif_id`/`route_domain` from the PDI's Network Instance (`docs/design.md`, "N3, N6, N9") |

## Framework and library surface we use

| surface | where we use it |
|---|---|
| control_v2, one transaction per session change | `internal/session` writes a session's rules, actions, meters, counters and tunnels together or not at all, with a request id that survives retries |
| resources and codecs (D-129) | the four tables above: configuration written in a transaction, a codec that validates the key, and a readback the startup sweep uses. The store's `flows` is BESS's to add; until it lands, a transaction naming it is refused, which is why the compiler writes no flow entry yet |
| module commands | `get_counts` (counters), `release`/`drop`/`clear` (the store's *held packets* — commands act on state, resources on configuration) |
| metadata attributes | `action_id` (written by `WildcardMatch`, read by counters, the encap and the store), `upf_teid` (written by the decap), `route_domain`/`vif_id` (the `vif` work) |
| slot tables (`dataplane/slot_table.h`) | every per-rule table: ids are 1..capacity, an erased key retires for a grace period, and publishing into a retiring slot is refused — which is why released ids wait their walk (`docs/design.md`, the id pool) |
| packet ownership | `bess::PacketRef` and the store's explicit free/release path; our modules copy no packet and allocate none |
| tasks (`RegisterTask`/`RunTask`) | BESS's store drains released packets from a task; **none of our modules has one** — nothing in our packet path runs between packets |
| `GetSchema`/descriptor set | the controller builds every message from the daemon's own schema, so a field this plugin does not have fails loudly instead of silently |
| `ListMetrics` (D-116) | per-gate counters: how an unwired gate's drops (store eviction, overflow) and a chain's throughput are read. What it does *not* show is a command's effect on the packets a module holds: `packet_store`'s `drop` frees them with `bess::PacketFree` and only decrements `total_packets_` (visible in `GetDesc`, not in metrics), while `release` and an erase move them to the release queue, which does reach a gate. That is why the session layer counts the *commands* it issued (`Stats.BuffersReleased`/`BuffersDropped`/`BufferFailures`) rather than reading drops back out of the daemon |
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
* **Which part of this graph needs paused workers: none of it today, and one
  resource of it later — and the *caller* is the one that stops.** Two facts
  decide it, and neither is a quiesce: a resource whose codec declares
  `requires_paused_workers` is **refused** with `RESOURCE_BUSY` while a worker
  runs its module ("nothing was tried", the SDK's `Resource` comment), and a
  command declared `THREAD_UNSAFE` — the store's `release`, `drop`, `clear` —
  is **refused** with `EBUSY` ("There is a running worker and command '%s' is
  not MT safe", `core/module.cc`). In both cases the daemon leaves the stopping
  to whoever is writing. The modules that declare the flag are `arp_responder`
  (`entries`), `bridge` (`statics`), `flowgen` and `vif` (`interfaces`) — none of
  them in any graph here; every resource the session path writes is a concurrent
  slot-table resource applied live (`WildcardMatch`'s rules, `ActionTable`'s
  actions, `Meter`'s meters, `Router`'s next hops, `enc/tunnels`,
  `cnt_*/counters`). The store's `flows`, when BESS adds it, will be the first
  paused-worker resource any graph here has.

  ```
  what stops, and who stops it

  (A) session state -- rules, actions, meters, next hops, tunnels, counters
      upfd --commit--> daemon --publish--> concurrent resource
      workers ............................ running throughout: nothing stops

  (B) a thread-unsafe command, or a resource that requires paused workers
      upfd --invoke/commit--> daemon: is a worker running the module?
                                 |
                                 +-- no  --> runs; no pause at all
                                 |
                                 +-- yes --> EBUSY / RESOURCE_BUSY, nothing tried
                                                |
      upfd --PauseWorkers--> invoke/commit --> ResumeWorkers
              the only stop in this tree, and it is the caller's to make
  ```

  Both stops are bounded by one command or one commit and happen at signalling
  rate — a BAR arriving, a DDN answer releasing packets — never per packet.
  `internal/bess` wraps the three commands in exactly that loop
  (`storeCommand`), and its five orderings are pinned by
  `TestStoreCommandStopsTheWorkersOnlyWhenTheDaemonRefuses`: try, and on a
  refusal stop the workers, retry, start them again -- tried first so a startup
  clearance cannot start a graph it found stopped, and resumed even when the
  retry failed so one refusal cannot leave the datapath stopped. The SDK stays
  explicit (`InvokeAction`, `PauseWorkers`, `ResumeWorkers`) and D-146 keeps the
  three SDKs' surfaces alike, which makes this shape this layer's policy rather
  than the SDK's method. The store's `flows` write will need the same wrapper
  around the one commit that carries it, since the engine does not pause for it.
  The in-process tests cover the refusal's consequences as well
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

None of these is done. The rule is `docs/design.md`'s "measure before any placement
change" and its "per feature, per packet" obligation: an arm in
`ci/bench-modules.sh` that measures the fused module against the same work split,
on the frames `smoke-gtpu.sh` uses, is the evidence, not the argument.

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
