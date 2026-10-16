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
2. **Graph** — the UPF pipeline as a manifest (`deploy/upf.yaml`) plus the
   datapath modules; `upfd` boots bessd's graph and verifies it applied.
   *Proof:* a packet on N3 decapsulates, matches a PDR, takes its action and
   leaves on N6.
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
