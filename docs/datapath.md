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

One `bessd`, one graph, one set of workers. Both graphs below are the same
composition; the lab one swaps the two PMD ports for Sources, Rewrites and Dumps
so a run needs no NIC.

```
                    +----------------------- uplink (UL) -----------------------+
 N3 -> n3_in -> teid -> decap0 -> mt_ul_read -> pdr_ul -> at_ul -> mt_ul -> cnt_ul -> rt -> n6_out -> N6
        (PortInc) WCM   GtpuDecap   MetadataTest  WCM       ActionTable Meter   UrrCount  Router PortOut
                    |                                  ^                    |
                    +-- default gate -> echo0 -> n3_out (TEID 0: path management)

                    +---------------------- downlink (DL) ----------------------+
 N6 -> n6_in -> pdr_dl -> at_dl -> mt_dl -> cnt_dl -> rt --ogate1--> enc -> n3_out -> N3
      (PortInc)  WCM      ActionTable Meter  UrrCount  Router          GtpuEncap PortOut
                    |
                    +-- buffering gate -> cnt_buf -> buf(ogate0) -> at_dl
                                        UrrCount   PacketStore
 cp_in -> dump/sink            (the End Marker port: `upfd` writes a frame, the port carries it to N3)
```

| graph | used by | what differs |
|---|---|---|
| `deploy/upf.yaml` | the deployment | PMD ports (`n3`, `n6`), the deployment's next hops and instances |
| `deploy/session-path.yaml` | `ci/session-path.sh`, `ci/n4-path.sh`, `ci/session-report.sh` | Sources `src_up`/`src_dn`, Rewrite, Dump, Sink; frames fixed so a test can byte-check them |
| `deploy/session-live.yaml` | `ci/session-live.sh` | no packet path at all: the control path's tables only |
| `deploy/buffer-path.yaml` | `ci/buffer-path.sh` | `session-path.yaml` plus the buffering branch, and needs a daemon with BESS's `packet_store` `key_attrs` |
| `deploy/smoke-gtpu.yaml` | `ci/smoke-gtpu.sh` | the two datapath halves alone |

Gate numbers are the rule's. A rule's value is `{priority, gate, action_id}`
(BESS D-141): gate 0 is the chain's next module, `8192` is `DROP_GATE`
(core/gate.h), 1 on `pdr_dl` is the buffering branch, and any unwired gate drops
— which is why evictions from the store need no module of their own.

## Modules we own

All four are in `datapath/`, exported by one `.so` (`BESS_PLUGIN` +
`ADD_MODULE`, `datapath/meson.build`), and built only against the installed
`bess-dev` stage.

| module | mclass | resource (key) | state it holds | workers |
|---|---|---|---|---|
| `gtpu_decap.{h,cc}` | `gtpu_decap` | none | `port_`, one attribute id | all |
| `gtpu_encap.{h,cc}` | `gtpu_encap` | `<module>/tunnels` (`TunnelKey{action_id}`) | `src_ip_`, `max_tunnels_` | all |
| `gtpu_echo.{h,cc}` | `gtpu_echo` | none | `port_`, a Recovery Time Stamp | all |
| `urr_count.{h,cc}` | `urr_count` | `<module>/counters` (`CounterKey{action_id}`) | per-worker cell planes, per-rule stamp pairs | all |

### `gtpu_decap` — the N3 entry

Strips Ethernet, IPv4, UDP and GTP-U (the header itself is parsed with the
installed `tunnel/tunnel.h` codec) and writes the tunnel's TEID into the
packet's `upf_teid` metadata (be32). It owns **no resource**: whether a TEID
belongs to a session is the decision of the `WildcardMatch` in front of it, so
an unknown TEID never reaches the module (`teid/rules` is the table the
controller writes and the sweep reads). The attribute is a *write*, so a reader
must declare it downstream (`MetadataTest` in the lab graphs, the encap's own
chain in a deployment): a write-only attribute gets no offset at all
(`core/metadata.cc`), and attributes are laid out in module registration order,
which is why the decap is listed early in every graph.

### `gtpu_encap` — the N3 exit

Writes the outer Eth/IPv4/UDP/GTP-U around a downlink packet from the tunnel
record the packet's ActionId names: `{teid, gnb_ip, ether_src, ether_dst}`,
with the inner TOS copied onto the outer header (the RAN's transport is
DSCP-marked; dropping it would send every downlink packet as best effort) and
the lengths/checksums recomputed. One record per downlink rule: the controller
resolves the FAR once, at programming time, so the packet path does one indexed
load and chases no control-plane relation.

### `gtpu_echo` — path management

Answers a GTP-U Echo Request (type 1, TEID 0 — the only message a UPF sees on
TEID 0 that names no session) with the reply TS 29.281 7.2.2 prescribes, and
drops everything else it is handed. It is reached through the TEID table's
*default* gate, so it sits outside the session path entirely. It reads no
session state and allocates nothing.

### `urr_count` — usage, and the buffering signal

Counts packets and octets per rule (the *IP packet's* octets, not the frame's)
and stamps each rule's first and last counted packet. The `<module>/counters`
entry's existence is the whole test — a rule with no entry is counted by nobody,
which keeps a session without a URR off the module's cost (one lookup) — and the
same module instance serves two purposes in two places: the direction's counters
for URRs, and, on the BUFF branch, the arrival signal the Downlink Data Report
is decided from.

* **Locality.** Cells are worker-local: one plane per worker, laid out whole
  cache lines apart, written with a relaxed load-add-store and never a locked
  instruction (`stats/worker_slots.h`'s rule). A reading sums the planes, so it
  is exact per cell, not one global instant; the memory is `capacity × 2 × 8 B ×
  workers`.
* **The one shared write.** A rule's stamp pair is a fact about the rule, not
  about a worker, so it is shared and written once per batch that counted a
  packet — never once per packet. A store lost to a concurrent reader costs one
  packet's stamp, never a count.
* **Reads** are the `get_counts` command (`upf.pb.UrrCountCommandGetCountsArg`
  → `…Response`), which is also how the control side asks for a *window*: with
  `restart_window` the module clears each rule's first stamp, so the next
  reading's stamp means "a packet arrived since". The URR path uses that to open
  its next window; the DDN path reads with `restart_window: false` and clears
  only once the SMF has taken the report (`bess.Client.{RuleCounts,PeekRuleCounts}`).

## Modules and drivers we take from BESS

Used as they are, but the configuration is ours and is what the compiler assumes:

| module | where | the configuration that matters |
|---|---|---|
| `WildcardMatch` | both PDR tables, the TEID table | `action_resource: <at_*/actions>` (D-141: the rule's action id goes to the packet's `action_id` attribute), `fields` = the graph's key in the order the compiler's `PDRFields` names, `max_tuples` |
| `ActionTable` | one per direction | `meters` and `next_hops` resources; fails closed when the id it writes has no reader |
| `Meter` | one per direction | the QER's committed/peak rate; a closed gate compiles to the drop gate instead |
| `Router` | one, both directions | the deployment's `next_hops`; the egress gate the action names |
| `PMDPort` | `n3`, `n6` | one rx queue each; RSS and one worker per queue are the scale path (D-097's layout) |
| `UnixSocketPort` | `cp_marker` | `SOCK_SEQPACKET`: one write from `upfd` is one End Marker frame |
| `PortInc`/`PortOut`, `Sink`, `Source`, `Rewrite`, `Dump`, `MetadataTest` | graphs | lab/plumbing only; a `Sink` has no output gate, so it appears in no metric — the counters that prove behaviour are on the modules' *output* gates |
| `PacketStore` | the buffering branch | `key_attrs: ["action_id"]` (BESS `packet_store`: the flow key is whichever attribute the graph provides), `max_packets`, `max_packets_per_flow`, `timeout_ms`; single worker; `release`/`drop`/`clear` are commands, and a transaction that writes its `flows` resource pauses the workers |
| `Vif` | not wired yet | the module that would write a packet's `vif_id`/`route_domain` from the PDR's Network Instance (`docs/design.md`, "N3, N6, N9") |

## Framework and library surface we use

| surface | where we use it |
|---|---|
| control_v2, one transaction per session change | `internal/session` writes a session's rules, actions, meters, counters, tunnels and (once it exists) the store's flow entry together or not at all, with a request id that survives retries |
| resources and codecs (D-129) | our four tables + the store's `flows`: configuration written in a transaction, with a codec that validates the key and a readback the sweep uses |
| module commands | `get_counts` (counters), `release`/`drop`/`clear` (the store's *held packets* — commands act on state, resources on configuration) |
| metadata attributes | `action_id` (written by `WildcardMatch`, read by counters, encap and store), `upf_teid` (written by the decap), `route_domain`/`vif_id` (the `vif` work) |
| slot tables (`dataplane/slot_table.h`) | every per-rule table: ids are 1..capacity, an erased key retires for a grace period, and publishing into a retiring slot is refused — which is why released ids wait (`docs/design.md`, the id pool) |
| packet ownership | `bess::PacketRef` and the store's explicit free/release path; our modules copy no packet and allocate none |
| tasks (`RegisterTask`/`RunTask`) | BESS's store drains released packets from a task; **none of our modules has one** — nothing in our packet path runs between packets |
| `GetSchema`/descriptor set | the controller builds every message from the daemon's own schema, so a field this plugin does not have fails loudly instead of silently |
| `ListMetrics` (D-116) | per-gate counters: how an unwired gate's drops (store evictions, overflow) and a chain's throughput are read |
| `tunnel/tunnel.h`, `conntrack/packet_parse.h` | header-only, experimental: the GTP-U codec and the parse types, installed by `bess-dev` |
| `utils/{ip,ether,checksum,endian,time,logging}.h`, `dataplane/action_id.h`, `framework/{resource_codec,resource_registry,resource_bindings}.h`, `commands.h`, `pb/module_msg.pb.h` | the rest of what the plugin includes; no module reaches past these into BESS internals |

## Placement, queues and state locality

* **One daemon, one graph, one writer.** `upfd` is the only writer of session
  state; the graph's own resources (next hops, module arguments) are the
  deployment's.
* **Workers.** The lab graphs run one worker (`workers: [{wid: 0, core: 0}]`) so
  a measurement is not a scheduling artefact. The deployment graph gives each
  PMD port one rx queue; RSS (and, once the one-port split lands, per-pattern
  RSS with `L3_SRC_ONLY` uplink / `L3_DST_ONLY` downlink) is the scale path. Our
  modules allow every worker; BESS's store allows one, and its `flows` resource
  pauses the workers when written — a per-session event, not per packet.
* **Where state lives.** Per-worker: the counters' planes. Shared, atomic,
  written once per batch: the counters' stamps. Per-rule, indexed by the
  ActionId the classifier wrote: the tunnel records, the counter entries.
  Per-packet: metadata. Behind a lock, control-plane only: the session model,
  the rule-ownership table, the id pools.
* **What the packet path never does**: allocate (except the store's own
  buffer queue), take a lock, read a control-plane structure, or look a rule up
  twice — the classifier's result is the id everything downstream is keyed by.

## Building and loading it

```sh
PKG_CONFIG="pkg-config --define-prefix" \
  PKG_CONFIG_PATH=<stage>/lib/pkgconfig meson setup datapath/build
ninja -C datapath/build
bessd -modules=<dir with libupf_datapath.so> -f        # plus the graph
```

The plugin's wire types are `datapath/upf_datapath.proto`: `protoc` emits the
C++ and `.desc` during the build, and the descriptor set is installed next to
the `.so` so a controller can build the messages without generated Go code.
BESS's own `packet_store` needs no plugin; its `key_attrs` field arrived in
`packet_store: the flow key is a configured attribute, not a fixed pair`.
