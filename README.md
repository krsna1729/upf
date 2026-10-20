# upf — a 5G UPF on BESS

One Go controller (`upfd`) speaks PFCP/N4 to the SMF and drives one `bessd`
through control_v2: the graph is applied once, and every PFCP session change
becomes one transaction. The UPF-specific datapath is a BESS plugin in
`datapath/`; the rest of the pipeline is BESS's own classifier, action table,
meter and router.

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

## Onboarding

**You need:** Linux, Go 1.26+, meson, ninja, pkg-config, python3. For the
datapath, a `bess-dev` stage: this tree reads its own copy under `build/bess/`
(untracked), vendored from a built checkout of the BESS fork
(`github.com/krsna1729/bess`) with `ci/vendor-bess.sh`; the layout and the
`BESS`/`STAGE`/`DPDK_LIB` overrides are in the header of `ci/bess-env.sh`.
No NIC is needed for anything below. Only `ci/veth-port.sh` needs root — it
creates a veth pair; every other lane runs unprivileged and starts its own
daemon on free ports.

### The Go side — no BESS needed

```sh
go build ./cmd/upfd
go test ./cmd/... ./internal/...
```

`./upfd` alone serves N4 and refuses sessions; a session needs the session
layer, which is `-bess <addr>` against a running daemon.

### The datapath

```sh
# one-time, if build/bess is absent: import the fork's built tree
ci/vendor-bess.sh ~/Projects/bess

PKG_CONFIG="pkg-config --define-prefix" \
PKG_CONFIG_PATH=build/bess/stage/lib/pkgconfig \
  meson setup datapath/build
ninja -C datapath/build

# first proof: bessd loads the plugin, a G-PDU is decapsulated, an outer
# header is built, and both frames are byte-checked
ci/smoke-gtpu.sh
```

### Run it

```sh
# controller only: N4 is served, session requests are refused (no session layer)
./upfd -n4 0.0.0.0:8805 -node-id 10.0.0.1

# against a daemon that has deploy/upf.yaml applied
./upfd -bess 127.0.0.1:10514 -n4 0.0.0.0:8805 -node-id 10.0.0.1
```

The shortest way to see the whole thing — `bessd`, the graph, `upfd` and one
session carrying packets both ways — is `ci/session-path.sh`.

## The inner loop

```sh
go test ./cmd/... ./internal/...                 # after a Go change
ninja -C datapath/build && ci/smoke-gtpu.sh      # after a datapath change
ci/verify.sh --quick                             # every claim's unit evidence
ci/verify.sh --lanes-only                        # every cited lane
ci/verify.sh                                     # both, then render the register
ci/verify.sh --render                            # markdown only, last results
```

`./...` also walks the untracked lane scratch under `build/run`, so build and
test the two source trees explicitly, as above. `ci/verify.sh --benches` adds
the benchmark lanes.

Run the lane that proves the path you touched:

| lane | what it proves |
|---|---|
| `ci/smoke-gtpu.sh` | decap, encap, echo reply, Error Indication; QFI and DSCP bytes |
| `ci/session-path.sh` | one session programmed over the SDK; both chains and the End Marker byte-checked |
| `ci/n4-path.sh` | PFCP message → compiler → one transaction → packets; restart and checkpoint replay |
| `ci/session-report.sh` | URR reports — period, threshold, quota — over PFCP |
| `ci/buffer-path.sh` | BAR buffering, DDN, and the duration's expiry |
| `ci/iface-path.sh` | every Source/Destination Interface value and the exit it names |
| `ci/veth-port.sh` | one PMD port split into N3/N6/N9 on a veth, with route domains (needs root) |
| `ci/pdrmatch-2dn.sh` | two network instances, one UE address, two exits |
| `ci/bench-n4.sh` | the N4 envelope: establish / modify / delete rates |

Every lane starts its own `bessd` on free ports, writes under `build/run/`, and
fails unless the daemon shuts down cleanly. A datapath change that no lane
observes is not proven.

### The rules that keep it honest

- **A claim carries evidence.** `docs/claims.json` is the source; `ci/verify.sh`
  runs every cited test and lane and renders `docs/claims.md`. Never edit the
  markdown by hand.
- **Fail first where practical.** Write the test that fails on the old code,
  then fix it; the commit that closes a gap says so.
- **A lane that records a number uses its own graph**, so the number does not
  move under unrelated changes. `deploy/*.yaml` is the deployment's
  configuration.
- **Generated files carry no timestamps**, so a rerun with the same verdicts is
  byte-identical.

## Where things are

| path | what |
|---|---|
| `cmd/upfd/` | the controller: PFCP server, session store, flags |
| `internal/n4/` | association, heartbeats, restart detection, reports, the PFCP state machine |
| `internal/session/` | the compiler and model: PFCP objects → one BESS transaction |
| `internal/routing/` | network instances, route domains, per-egress hops, ARP identity |
| `internal/bess/` | the SDK wrapper: resources, transactions, bootstrap, restart handling |
| `datapath/` | the plugin: decap, encap, responder, counters, ARP, the keyed PDR matcher |
| `deploy/` | the deployment graph and the lanes' graphs |
| `ci/` | the lanes, the claims contract, the interop rig |
| `docs/` | design, datapath reference, claims register, interop record |

## Status

The last full evidence run: **49 claims — 45 ok, 2 gap, 2 skip, 0 fail**.

- Open: Packet Rate (QER packet caps and their query) and MAR/ATSSS-LL.
- Skipped here: two claims whose lanes need environments this host lacks.
- Real-SMF interop: stock free5GC v4.3.0, unshimmed, through session deletion
  (`docs/interop.md`).
- Competitive mean over twelve compliance blocks: **78**.

`docs/claims.md` is the detail: one line per claim, its proof, and the field
matrix with the per-cell audit.

## Read next

- `docs/design.md` — why the deployment is shaped this way: walls, costs,
  milestones.
- `docs/datapath.md` — modules, resources and keys, placement, and the
  processing graphs for both directions.
- `docs/claims.md` — clause-by-clause status, the evidence, and the competitive
  score.
- `docs/interop.md` — a real SMF against this UPF, including the failure record
  that got it there.
