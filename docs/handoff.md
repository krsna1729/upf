# Handoff: the two-profile UPF

Status: 2026-10-18, updated after the module and its arm landed and ran. This
file is the state of the work, what is verified and what is not, and what is
left.

## The goal

An end-to-end working **two-profile UPF** — `generic` (stock BESS modules) and
`custom` (this tree's keyed per-session matcher) — with the decided feature list
working in at least the custom profile. The definition of that list is
`docs/scorecard.md`'s "The custom profile, row by row" and its nine-item
checklist; `docs/compliance.md`'s "Profiles: what each row means in each
profile" is the same ground over the compliance rows.

## Landed and verified

| commit | what it lands | what proves it |
|---|---|---|
| `3508638` | the compiler's keyed write: one map key per session, keyed by the F-TEID, value in SMF precedence order | seven tests in `internal/session/pdr_match_test.go`, read through the compiler's own encoder |
| `e1672ff` | `-profile generic\|custom`, resolved once at startup | `profile_test.go`: the strategies, the refusal of an unknown name, an unset direction still reading as the wildcard table |
| `266fc30` | the two graphs, and a test that each profile's graph exists on disk | `TestAProfilesGraphIsInTheTree` — an **existence check, not a tracking check**: `os.Stat` passes on an untracked file, so it would not have caught the graph's untracked state. The fresh-checkout guarantee comes from verifying the suite on a `git archive` export (`git archive HEAD \| tar -x -C /tmp/verify && go test ./...`), which is the practice this repo already uses |
| `768d353` | the startup sweep: chunked erase (bound derived from the engine's retire budget), one `Contents` call per resource, fatal on a partial sweep | `sweep_test.go`, failing-first against the single-transaction shape |
| `645488a` | the usage tick reads each counter module **once** per tick, not once per session | `report_test.go`; 27.0 B per counted rule measured |
| `43b4971`, `00244b7`, `a685069`, `140a704` | the design's profiles section, the scorecard matrix and checklist, the per-profile compliance and performance tables, and their accuracy fixes | docs only |

Full suite green at every one of those commits, with **`GOWORK=off`**.

## Landed since, and what proves it

Commits are named by subject; hashes moved when `n4.test` (a 7 MB test binary
that was the only binary ever tracked) was removed from history.

| what | what proves it |
|---|---|
| every `ci/` lane on this repo's own BESS copy (`build/bess/`, built by `ci/vendor-bess.sh`; never `~/Projects/bess`), on free ports (`ci/bess-env.sh`), with a clean-shutdown verdict | `LD_DEBUG=libs ci/smoke-gtpu.sh`: no library initialised from outside the copy; every lane exits 0 only if `bessd` exits 0 on SIGTERM |
| the `PdrMatch` module, its proto and the arm `ci/pdrmatch-path.sh` | a packet on N3, decapped, matched by the module, its ActionId resolved, out on N6; the module's key read back from the daemon |
| a **use-after-free the arm found**: `UpsertOp::Publish` kept ownership of the `Rules` it published, so the op's destructor freed what the packet path read and a later erase retired it twice | fail-first: the pre-fix plugin fails the lane (`bessd exited with status 1 on shutdown`), the fixed one passes; the old arm had exited 0 on freed memory |
| QFI on the custom path | `ci/pdrmatch-path.sh` (QFI 9 dropped by its rule, QFI 5 forwarded on its own ActionId, one stream at a time) and `TestAPdrMatchPDINamingAQFIIsCarriedOnItsRule` |
| `deploy/custom-pdrmatch.yaml` ported: `upf.yaml` with the matcher swapped | a structural diff shows only that; it validates, and a copy with the NIC ports as unix sockets applies. A real apply needs a NIC |
| the PFCP lane on the custom profile | `PROFILE=custom ci/n4-path.sh`, restart sweep and checkpoint replay included |
| QER meter, URR counters, quota, DSCP, end marker through the module | `PROFILE=custom ci/session-path.sh` (the End Marker socket is rendered per run) |

`GOWORK=off go test ./...` passes. One `PROFILE=custom ci/session-path.sh` run
failed once and its output was lost; 21 later runs (both profiles) passed, so
it is **unexplained, not fixed**.

## Left, in order

1. **The firewall's `action_id`** — the stock module writes a per-rule id and an
   `ActionTable` resolves it (D-141); `firewallRule` in `compile.go` does not
   emit it, so our opt-in firewall path cannot carry a range or IPv6 PDR to its
   own next hop. The stage **does** load `Firewall` (a graph naming it applied),
   so this is armable.
2. **BUFF on the custom path** — the action names a **Router next hop**, not a
   gate: `PdrMatch (rule, action_id) → ActionTable (next_hop_id metadata) →
   Router → gate`, so the store's input gate must be reachable as a next hop of
   the Router declared in its `next_hops` resource, with a config field for the
   id. **Check the placement first**: in `deploy/buffer-path.yaml` the store sits
   *before* `at_dl`, so via the action route it would sit after the Router and
   the release path would re-enter the meter and encap rather than the
   ActionTable. Needs the owner's call.
3. **The downlink selector** — `route::LpmRouteTable` keyed on (route domain, UE
   prefix), which is why the module is uplink-only today. Needs a design call.
4. **IPv6 through the module** and **route domains on the custom path** — the
   key is IPv4-only; one module per domain or the domain in the key.
5. **Not done anywhere**: gate/GBR, time and threshold URRs on the custom path
   (live), the echo responder in the custom lab graph, an ASan build of the
   plugin, a benchmark of the custom path, a real SMF, a NIC.
6. **The force-push**: the rewritten history is local; the GitHub remote still
   has `n4.test` until the owner force-pushes.

## Traps worth not rediscovering

- **`GOWORK=off` for every `go` command.** The workspace now includes
  `../bess/sdk/go`, which wants a newer Go directive than `go.work` lists, so a
  workspace-aware build dies before running. The repo's `go.mod` pins the SDK by
  pseudo-version precisely so no workspace is needed.
- **The retire budget**: the transaction engine refuses a transaction retiring
  more than `retire_high_water()/2` = 2048 objects and aborts its reservations,
  so nothing becomes visible. The sweep's batch bound (1000 changes) comes from
  it.
- **64 MiB per message**: ~510K entries at 131 B. One `Contents` call per
  resource puts the ceiling on the largest single table; past it the operator
  restarts `bessd`. The target is a bounded clear in the daemon.
- **`next_hop_id` is a Router next-hop id**, not a gate (`action_table.cc`), and
  the Router turns it into a gate.
- **The counter resource's value is empty by design** — the counts are the
  module's per-worker planes, read through `get_counts`; a `Contents`-based tick
  would decide every report from zeros. 90 B an entry, no count in it.
- **The LPM's fixed cost is per table, per family**: `rte_lpm` and `rte_lpm6`
  each carry a `tbl24` of `1<<24` 4-byte entries (~64 MiB), so a dual-stack
  domain is two tables and three domains ~384 MiB before any group. Groups
  depend on the address plan, not the entry count.
- **A whole-policy write is O(all rules) whatever the structure** — the check to
  run on any new resource is "is its value every session's state?".

## How this work went, for whoever picks it up

**Six agents died on the module and the arm** (hard-aborted, cancelled, or
gone) — and a seventh, the read-only diagnosis agent, was killed deliberately
and does not belong in the count. Every one of the six left uncommitted edits
behind. Two rules follow, both learned the hard way:

- **Judge an agent's leftovers; do not trust them and do not discard them.** The
  module compiled and the keyed write was complete and thoughtful; the custom
  graph was the wrong shape; the profile mechanism was sound and needed only its
  test.
- **Slice size is the signal, not luck.** Every small slice finished; the
  module, its graphs and the compiler in one brief did not. Read-mostly work
  survives; a C++ build plus a live arm plus a compiler change does not.

And the repository's own rules, which have caught more errors than any test:
**credited only where a test exists**; **derived and measured are different
labels** and both must be written down as what they are; and when a document and
the code disagree, read the code — that is how the counter entry's size, the
firewall's `action_id`, and the Transport Level Marking's clause number were all
corrected this session.
