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
- `internal/routing` — route domains (N3/N6/N9) and next-hop programming.
- `datapath/` — the UPF datapath as a Bess **plugin** (D-008: UPF-specific
  code stays in a plugin) — GTP-U decapsulation and encapsulation, on the
  installed header-only codec (`core/tunnel/tunnel.h`, experimental). It is
  built against the installed `bess-dev` stage and loaded by `bessd`
  (`--modules=`), because Bess offers no supported way to compile extra sources
  into the daemon (no meson hook) and a plugin must not link Bess's static
  archives. The rest of the graph — classification, `ActionTable`, `Meter`,
  `Router` — is Bess's own modules, composed by `deploy/upf.yaml`.

## Why it is shaped this way

BESS is the dataplane; the UPF owns its own semantics. `docs/design.md`
records the boundary and, in particular, the controller patterns that are
deliberately *not* copied from OMEC's `pfcpiface` (a goroutine and a
`ModuleCommand` per PDR/FAR/QER, Cartesian port-range expansion, client-side
ordering and rollback), because BESS now offers the transactional machinery
that makes them unnecessary.

## Build

```sh
go build ./cmd/upfd        # the controller

# the datapath plugin, against an installed bess-dev stage
cd datapath
PKG_CONFIG_PATH=<stage>/lib/pkgconfig meson setup build && ninja -C build

# the proof it works: bessd loads the plugin, applies the smoke graph, and the
# script checks one decapsulated and one encapsulated packet byte for byte
STAGE=<stage> ../ci/smoke-gtpu.sh
```

The stage must be a BESS install whose `bess-dev.pc` carries the stage's own
paths — i.e. BESS configured with `-Dprefix=<stage>`. An install made with
`meson install --destdir=...` keeps `/usr/local` inside the `.pc`, and a build
against it fails on headers that are not there; with such a stage, put a copy of
`bess-dev.pc` whose `prefix` line names the stage in a directory of its own and
point `PKG_CONFIG_PATH` at that directory instead. The smoke's `STAGE` default
is the pkg worktree's `stage-fast`, which is such a destdir install.

Driving BESS needs the fork's Go SDK, the nested module `sdk/go`; until those
commits are published, `go.mod` documents the local `replace` to use.

## Run

```sh
# the N4 node, today
./upfd -n4 0.0.0.0:8805 -node-id 10.0.0.1

# the datapath: bessd with the plugin, then apply the graph (the daemon starts
# empty; -f is foreground mode, and the manifest is applied over control_v2)
build/stage/bin/bessd -m 4096 -modules=<plugin dir> -f &
build/stage/bin/bessctl apply deploy/upf.yaml
./upfd -bess localhost:10514 -n4 0.0.0.0:8805 -node-id 10.0.0.1
```

## Status

- The datapath plugin is in and proven: `datapath/` (GTP-U decapsulation and
  encapsulation) builds against the installed `bess-dev` stage, and
  `ci/smoke-gtpu.sh` loads it into `bessd`, applies `deploy/smoke-gtpu.yaml`,
  and checks six things: the decapsulated frame, the `upf_teid` attribute, that
  a G-PDU whose TEID no session names is dropped (`decap0/sessions`), the outer
  header, the UDP/GTP-U header with the session's TEID, and the inner packet.
  Its first run found a real bug (an uninitialized UDP source port), which is the
  point of the check.
- The deployment graph is in: `deploy/upf.yaml` (N3 and N6 on `PMDPort`s, the
  TEID table, the two PDR tables with their action resources, both chains, the
  N6 route) validates against a daemon with the plugin loaded.
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
- Next, in this order: a real SMF (open5gs or free5GC) against `upfd` for
  interop and Causes, packets over the bound N3/N6 ports, route domains in
  `internal/routing` for N9, the classifier's explicit tuple budget
  (`max_tuples`), then usage reporting. `docs/design.md` holds the milestones
  and what each one must prove.
