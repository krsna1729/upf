# upf — a 5G UPF on BESS

One controller process, one `bessd` process, with the UPF datapath compiled into
`bessd`. The controller speaks PFCP (N4) to the SMF and drives BESS through
control_v2 with the Go SDK — desired state plus one transaction per session
change. It holds no dataplane state of its own.

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
- `datapath/` — the C++ UPF datapath (modules on BESS's public/experimental
  API). Built into `bessd`, not loaded from a `.so`: `ci/build-bess.sh`
  compiles these sources into the daemon, so one process runs the graph and
  one controller programs it.

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
```

The BESS side arrives with the datapath: `BESS_SRC=~/Projects/bess
./ci/build-bess.sh` compiles the UPF datapath into `bessd` and installs a stage
under `build/stage`. Driving BESS needs the fork's Go SDK, the nested module
`sdk/go`; until those commits are published, `go.mod` documents the local
`replace` to use.

## Run

```sh
# the N4 node, today
./upfd -n4 0.0.0.0:8805 -node-id 10.0.0.1

# once the datapath and the session layer are in
build/stage/bin/bessd -m 4096 -c 0 -- -f deploy/upf.yaml
./upfd -bess localhost:10514 -n4 0.0.0.0:8805 -node-id 10.0.0.1
```

## Status

- The N4 node is in (`internal/n4`, `cmd/upfd`): an SMF can associate, heartbeat,
  and be seen restarting. Session requests are answered with Cause "Request
  rejected" until the session layer exists — nothing is silently dropped.
- Next, in this order: the datapath graph (`datapath/`, `deploy/upf.yaml`,
  `ci/build-bess.sh`), the session transaction (`internal/session` plus
  `internal/bess`), routing, then usage reporting. `docs/design.md` holds the
  milestones and what each one must prove.
