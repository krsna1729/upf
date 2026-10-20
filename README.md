# upf — a 5G UPF on BESS

One controller process, one `bessd` process, with the UPF datapath loaded into
`bessd` as a plugin. The controller speaks PFCP (N4) to the SMF and drives BESS
through control_v2 with the Go SDK — desired state plus one transaction per
session change. It holds no dataplane state of its own.

```
                 PFCP/N4 (UDP 8805)
   SMF  <───────────────────────────────>  upfd (Go)
                                             │  control_v2 over gRPC
                                             │  desired state: Pipeline
                                             │  per session: one transaction
                                             ▼
                                    bessd (C++ + upf datapath)
                                    ├── classifier → {gate, ActionId}
                                    ├── ActionTable → meters / next hops
                                    ├── tunnel: GTP-U decap / encap
                                    └── Router (N3 / N6 / N9 domains)
   N3 (gNB) ──▶ bessd ──▶ N6 (data network) ──▶ bessd ──▶ N3
```

- `cmd/upfd` — the controller: PFCP server, session store, and the compiler
  from PFCP objects (PDR/FAR/QER/URR) to BESS resources.
- `internal/n4` — the N4 node: the PFCP socket, the association with one CP
  function, and its liveness (Heartbeat both ways, restart detection through
  recovery time stamps). The wire format is
  [`github.com/wmnsk/go-pfcp`](https://github.com/wmnsk/go-pfcp), pinned as
  `go.mod` says — one PFCP implementation in the tree. This package adds the
  node-level state machine and the dispatch to the session layer, which is
  exactly where that library stops by design.
- `internal/bess` — the client wrapper: resource names, the session
  transaction, pipeline bootstrap, restart handling.
- `internal/session` — the session state machine: one PFCP session is one
  BESS transaction.
- `internal/routing` — the deployment's network instances: their route domains,
  their subscriber pools, one next hop per egress (a FAR's Destination Interface
  decides which) and the interface's ARP identity.
- `datapath/` — the UPF datapath as a Bess **plugin** (D-008: UPF-specific
  code stays in a plugin) — GTP-U decapsulation and encapsulation, on the
  installed header-only codec (`core/tunnel/tunnel.h`, experimental). It is
  built against the installed `bess-dev` stage and loaded by `bessd`
  (`--modules=`), because Bess offers no supported way to compile extra sources
  into the daemon (no meson hook) and a plugin must not link Bess's static
  archives. The rest of the graph — classification, `ActionTable`, `Meter`,
  `Router` — is Bess's own modules, composed by `deploy/upf.yaml`.

## Why it is shaped this way

BESS is the dataplane; the UPF owns its own semantics. `docs/datapath.md`
is the datapath's engineering reference (modules, resources, placement) and
`docs/design.md`
records the boundary and, in particular, the controller patterns that are
deliberately *not* copied from OMEC's `pfcpiface` (a goroutine and a
`ModuleCommand` per PDR/FAR/QER, Cartesian port-range expansion, client-side
ordering and rollback), because BESS now offers the transactional machinery
that makes them unnecessary.

What the tree *claims* -- each clause it serves, each value it refuses, the
competitive score -- lives in one place, `docs/claims.md`, rendered from
`docs/claims.json` by `ci/verify.sh`. That script runs every piece of evidence
the claims cite (Go tests, lane scripts, deploy graphs), writes each verdict
back into the JSON, and re-renders the document, so a claim and its proof
cannot drift apart.

## Build

```sh
go build ./cmd/upfd        # the controller

# the datapath plugin, against an installed bess-dev stage
cd datapath
# a stage installed with --destdir keeps /usr/local as the prefix inside
# bess-dev.pc (pkg-config's ordinary, correct behaviour -- the file is not
# relocatable), so --define-prefix is what derives the stage's own include
# paths from where the .pc file lives. PKG_CONFIG passes that through to meson.
PKG_CONFIG="pkg-config --define-prefix" \
PKG_CONFIG_PATH=../build/bess/stage/lib/pkgconfig \
  meson setup build && ninja -C build

# the proof it works: bessd loads the plugin, applies the smoke graph, and the
# script checks one decapsulated and one encapsulated packet byte for byte
../ci/smoke-gtpu.sh
```

The stage must be a BESS install whose `bess-dev.pc` carries the stage's own
paths — i.e. BESS configured with `-Dprefix=<stage>`. An install made with
`meson install --destdir=...` keeps `/usr/local` inside the `.pc`, which is why
the build above puts `pkg-config --define-prefix` in `PKG_CONFIG`; a stage
configured with `-Dprefix=<stage>` needs neither.

### The BESS build this repo carries

Every build and run lane uses `build/bess/` (untracked, like every other build
output), never a sibling BESS checkout. `ci/bess-env.sh` is the one place the
lanes read it from, and `ci/vendor-bess.sh [<bess checkout>]` is how it is
made and refreshed:

| path | what | used by |
|---|---|---|
| `build/bess/stage/` | the installed `bess-dev` stage: `bessd`, `bessctl`, headers, `bess-dev.pc` | the plugin build, every arm |
| `build/bess/dpdk/` | the DPDK `bessd` loads at run time | every arm (`LD_LIBRARY_PATH`) |
| `build/bess/fast/` | the perf tree: `core/bessd`, `tests/perf/live_perf` | `ci/bench-modules.sh`, `ci/bench-n4.sh` |
| `build/bess/sdk/go` | the fork's Go SDK | `ci/work.sh` only |

`BESS=`, `STAGE=` and `DPDK_LIB=` override each default. Things to know:

- The copy names nothing outside itself where it matters. The script rewrites
  the DPDK paths in `bess-dev.pc` and DPDK's own `.pc` files, and patches the
  PMD driver directory compiled into `librte_eal` (`RTE_EAL_PMD_PATH`; `bessd`
  has no flag for it, and without the patch every NIC driver loads from the
  checkout). `LD_DEBUG=libs ci/smoke-gtpu.sh` loads no library from the
  checkout.
- `fast/core/bessd` still carries an absolute RUNPATH into the checkout it was
  built in; the lanes put `build/bess/dpdk` first on `LD_LIBRARY_PATH`, which
  the loader searches before RUNPATH. Rebuilding BESS happens in a BESS
  checkout, then refresh; `fast/` is not rebuilt in place.
- Go builds use the SDK `go.mod` pins (`GOWORK=off`, which the env file
  exports). `build/bess/sdk/go` is a *newer* SDK than that pin; `ci/work.sh`
  makes a workspace of it for developing against it, and the arms do not use it.
- The lanes pick free ports for `bessd` and N4 at start (`BESS_PORT`,
  `N4_PORT`, `SERVER` override), because another daemon on the host may hold
  the defaults. `bessd` itself always writes its crash report to
  `/tmp/bessd_crash.log`, shared by every daemon on the host: read it with its
  pid in hand.

## Run

```sh
# the N4 node, today
./upfd -n4 0.0.0.0:8805 -node-id 10.0.0.1

# the datapath: bessd with the plugin, then apply the graph (the daemon starts
# empty; -f is foreground mode, and the manifest is applied over control_v2)
export LD_LIBRARY_PATH=$PWD/build/bess/stage/lib:$PWD/build/bess/dpdk/install/lib
build/bess/stage/bin/bessd -m 4096 -modules=<plugin dir> -f &
build/bess/stage/bin/bessctl apply deploy/upf.yaml
./upfd -bess localhost:10514 -n4 0.0.0.0:8805 -node-id 10.0.0.1
```

## Status

- The datapath plugin is in and proven: `datapath/` (GTP-U decapsulation,
  encapsulation and the echo responder) builds against the installed `bess-dev`
  stage, and `ci/smoke-gtpu.sh` loads it into `bessd`, applies
  `deploy/smoke-gtpu.yaml`, and checks fourteen things: the decapsulated frame,
  the `upf_teid` attribute, that a G-PDU whose TEID no session names is
  dropped, the outer header, the UDP/GTP-U header with the session's TEID, the
  inner packet, the PDU Session Container a record's QFI adds, the outer TOS
  and checksum a record's Transport Level Marking (TS 29.244 8.2.12, the
  transport header's DSCP) produces,
  and the four fields of an Echo Response (`gtpu_responder`: the swapped
  addresses, the lengths and checksum, the sequence number and the Recovery
  IE). Its first run found a real bug (an uninitialized UDP source port), which
  is the point of the check.
- The deployment graph is in: `deploy/upf.yaml` (N3 and N6 on `PMDPort`s, the
  TEID table, the two PDR tables with their action resources, both chains, and
  the next hop each direction's action names) validates against a daemon with
  the plugin loaded.
  `deploy/session-live.yaml` is the same composition without ports, for a host
  with no bound NIC.
- The N4 node is in (`internal/n4`, `cmd/upfd`): an SMF can associate, heartbeat,
  and be seen restarting; association, heartbeat, restart handling and the
  refusal Causes are covered by tests over a real UDP socket.
- The session layer is in and live: `internal/session` compiles a PFCP session
  into resources and one transaction per change, and `ci/session-live.sh`
  programs a whole session into a running bessd through the Go SDK — establish
  (two PDRs, eight changes, one transaction), a repeated establishment (a
  no-op), a modify, and a delete — with every message built from the daemon's
  own schema.
- The packet path is proven end to end: `ci/session-path.sh` applies the lab
  graph, programs one session, and shows both halves — the daemon's counters
  move from zero (the graph's Sources run from the moment it is applied, so a
  zero is absent state, not absent traffic) and the Dumps carry the bytes: the
  decapsulated inner packet toward N6, and toward N3 the outer Eth/IPv4/UDP
  2152/GTP-U the encap built around the UE's packet, with the session's TEID.
  Its first run found two bugs, which is the point: a downlink rule that
  demanded the UE's address on both sides, and a downlink action that named no
  next hop — which a chain holding an ActionTable fails closed on, so
  `deploy/upf.yaml` had the same blackhole.
- N4 reaches the datapath: `ci/n4-path.sh` starts `upfd` against the same graph
  and establishes a session over PFCP (`cmd/n4bench` as the stand-in SMF); the
  packets that then cross are keyed by the SMF's own values — the F-TEID it
  pinned, the FAR's TEID and gNB address. Its restart steps show both halves of
  the restart wall: a controller started without a checkpoint takes the previous
  run's records out and the packets stop being selected, and one started with
  `-checkpoint` replays the sessions the journal holds — same Recovery Time
  Stamp, so the SMF keeps them — and the packets cross again. `ci/bench-n4.sh`
  measures the same path's envelope.
- The node declares FTUP, and only where the session layer runs: a PDI whose
  F-TEID IE carries the CH flag (8.2.3) is given an F-TEID by the compiler and
  reads it back in the Created PDR, and the PDIs of a session that carry one
  CHOOSE ID share it — one TEID rule for the group, and one value in each of
  their Created PDRs.
- Downlink buffering and DDN are in, with two recorded deviations: a FAR whose
  Apply Action is BUFF and not FORW delivers its rule on the graph's buffering
  gate (`upfd -buffer-store`, `-buffer-counter`, `-buffer-gate`), BESS's own
  packet store holds the packets keyed by the rule's ActionId, the first one is
  reported to the SMF as a Downlink Data Report on the reporting tick when the
  same FAR also carries NOCP (8.2.26: BUFF alone is an instruction to hold the
  packets and say nothing), and the instruction that moves the path releases
  what was held into the action path.
  The SMF's own numbers are the flow's, not the graph's: 8.2.29's duration and
  8.2.30's count reach the store's live per-flow `flows` entry, so a buffering
  flow's cap and its expiry are per-BAR; both are measured — `docs/claims.md`'s
  competition-7 and status-27 carry the evidence, including the arm's
  default-stage negative. The DDN trigger is a poll of the branch's counters at
  `-urr-interval`, so its latency is up to one tick and a deployment that wants
  DDN must set that interval. `ci/buffer-path.sh` proves the whole path against
  a live daemon (it needs a `bessd` built with BESS's `packet_store` key_attrs
  change and, for the expiry check, the store's bounded sweep (`0bfd2783`),
  which is why its graph is `deploy/buffer-path.yaml` rather than the shared
  one).
- The two GTP-U path messages are in. `gtpu_responder` answers an Echo Request
  (type 1, TEID 0) with the reply TS 29.281 7.2.2 prescribes — the S flag, the
  request's sequence number, the mandatory Recovery IE and this node's Recovery
  Time Stamp — and `ci/smoke-gtpu.sh` checks the reply byte for byte. An End
  Marker goes the other way: a Session Modification whose SNDEM flag moves a
  FAR's F-TEID makes `upfd` construct the 60-byte frame itself — the OLD TEID
  and peer, this UPF's N3 address as the source — and write it to the graph's
  `unix_port` (`-end-marker`), whose `PortInc` carries it to the N3 output after
  the switch has landed; `ci/session-path.sh` checks the frame and that the port
  carried exactly one. Both bits a peer reads are only advertised where they
  work: FTUP with `-bess`, EMPU with `-end-marker`.
- Per-rule usage counters are in: `datapath/urr_count.*` counts the packets and
  octets of every rule a URR's PDRs name (the entry in `<module>/counters` is
  what says a rule is measured), and its `get_counts` action is how a controller
  reads them — `ci/session-path.sh` drives real packets through it and checks
  that the octets are the inner IP packet's, not the frame's.
- The decision half of URR reporting is in as well: `session.Evaluate` reads
  those counters through the module's own command, decides which URR owes a
  report (the period, the volume and time thresholds, the volume and time
  quotas), and stops the traffic when a quota is spent -- the PDRs that name the
  URR compile to a drop until the SMF provisions a new quota.
- The report is sent: `upfd -urr-interval` evaluates every session on each tick
  and sends what a URR owes as a PFCP Session Report Request, waiting for the
  SMF's answer (`internal/n4`: the one exchange this node initiates, retried
  while nothing arrives) -- `ci/session-report.sh` runs bessd, the graph and
  upfd, and the test in `internal/n4` is the SMF that receives the report and
  answers it.
- The numbers are served: `upfd -metrics host:port` answers a scrape with this
  node's own counters -- sessions held, establishments, modifications,
  deletions, refusals, usage reports sent/refused/held/dropped, and whether a CP
  function is associated -- in the Prometheus text format.
- Two outside checks run as lanes. `ci/interop/run.sh` brings up free5GC v4.3.0
  from its published images on a private bridge and runs a real SMF's
  association, PDU session and release against `upfd` (N4 only: no packet
  crosses the dataplane; `docs/interop.md`). `ci/cntc-path.sh` drives TOSSI
  CNTC's PFCP simulator and its N3 robustness frames against `upfd` and `bessd`
  and checks the answers; it is not CNTC's verdict and earns no certificate
  (`docs/claims.md`, status-32).
- The port split is in, on a veth: `deploy/veth-port.yaml` is one PMD port with
  four queues split by a `Vif` into N3/N6/N9, each with its own address and
  route domain, and `ci/veth-port.sh` proves the queues, the split and the
  compiler's downlink rule selected by the domain the port wrote. What waits for
  hardware is the placement measurement (per-pattern RSS and the line rate); a
  veth advertises no RSS offload at all (`docs/datapath.md`).
- Next, in this order: a real SMF (open5gs or free5GC) against `upfd` for
  interop and Causes, packets over the bound N3/N6 ports (the placement
  measurement is the hardware item), then the classifier's explicit tuple budget
  (`max_tuples`). `docs/design.md` holds the milestones and what each one must
  prove.
