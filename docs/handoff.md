# Handoff: the two-profile UPF

Status: 2026-10-18, end of the session that built the profile mechanism and the
keyed per-session matcher's compiler half. This file is the state of the work,
what is verified and what is not, and the order the rest should be taken in.

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

## Uncommitted, and why

- **The module** — `datapath/pdr_match.{h,cc}`, `pdr_match_matcher.h` (the
  seam), `pdr_match_resource.h`, `pdr_match_scan.cc`, plus `meson.build` and
  `upf_datapath.proto`. **It compiles against the installed stage** (the objects
  are in `datapath/build`, the `.so` links, the temporary indexed matcher is
  deleted) and **no packet has ever crossed it**. It is not landable until it has
  a test that fails without it — an encoding test, or the arm.
- **The arm** — `ci/pdrmatch-path.sh`, `ci/pdrmatch/`, and the graph
  `deploy/pdrmatch-path.yaml`. Never run. This is the slice that has killed
  every agent that touched it.
- **The custom graph's shape is wrong** — `deploy/custom-pdrmatch.yaml` is the
  no-NIC shape (no ports, egress to a `sink`, no echo, no marker), so it differs
  from `deploy/upf.yaml` by five things rather than by the matcher alone. Make
  it `upf.yaml` with `pdr_ul` replaced by `pdr_match_ul` and `mt_ul_read`
  dropped (the module reads `upf_teid` itself through `key_attr`), keeping the
  ports, the echo and the marker.

## Next, in order

1. **The custom graph, ported** (above), then **load-check both graphs**: a
   `bessd` from the installed stage loads them or it does not — the cheapest
   real proof available, and the only thing that shows the module's `key_attr`
   read is enough to give `upf_teid` an offset where `mt_ul_read` used to.
2. **The module's encoding test**, which is what makes it landable.
3. **The arm**: a session established with the opt-in, a packet on N3,
   decapsulated, matched **by the module**, the right `action_id`, out on N6.
4. **QFI on the custom path** — a `qfi` field on the rule, matched against the
   metadata the decap writes from the PDU Session Container; the compiler's
   refusal then comes off (`pdrMatchChanges`).
5. **BUFF on the custom path** — the action names a **Router next hop**, not a
   gate: `PdrMatch (rule, action_id) → ActionTable (next_hop_id metadata) →
   Router → gate`, so the store's input gate must be reachable as a next hop of
   the Router declared in its `next_hops` resource, with a config field for the
   id. **Check the placement first**: in `deploy/buffer-path.yaml` the store sits
   *before* `at_dl`, so via the action route it would sit after the Router and
   the release path would re-enter the meter and encap rather than the
   ActionTable.
6. **The downlink selector** — `route::LpmRouteTable` keyed on (route domain, UE
   prefix), which is why the module is uplink-only today.
7. **The firewall's `action_id`** — the stock module writes a per-rule id and an
   `ActionTable` resolves it (D-141); `firewallRule` in `compile.go` does not
   emit it, so our opt-in firewall path cannot carry a range or IPv6 PDR to its
   own next hop. Small, and it makes the generic profile's other structure
   honest.

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
