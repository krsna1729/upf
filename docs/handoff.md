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
| QFI on the custom path | `ci/pdrmatch-path.sh` (QFI 9 dropped by its own rule, QFI 5 forwarded -- which rule matched it is not shown --, one stream at a time) and `TestAPdrMatchPDINamingAQFIIsCarriedOnItsRule` |
| `deploy/custom-pdrmatch.yaml` ported: `upf.yaml` with the matcher swapped | a structural diff shows only that; it validates, and a copy with the NIC ports as unix sockets applies. A real apply needs a NIC |
| the PFCP lane on the custom profile | `PROFILE=custom ci/n4-path.sh`, restart sweep and checkpoint replay included |
| QER meter, URR counters, quota, DSCP, end marker through the module | `PROFILE=custom ci/session-path.sh` (the End Marker socket is rendered per run) |

`GOWORK=off go test ./...` passes. One `PROFILE=custom ci/session-path.sh` run
failed once and its output was lost; 21 later runs (both profiles) passed, so
it is **unexplained, not fixed** (the log was not kept; keep logs with `tee` next time).

## Left, in order

1. **Firewall arm for ranges and IPv6** -- `firewallRule` now emits the PDR's
   `action_id` (unit test `TestAForwardingFirewallRuleNamesItsAction`;
   `FIREWALL=1 ci/session-path.sh` on `deploy/firewall-path.yaml`, failing with
   the old compiler and passing with the new). What is not yet sent through it:
   a port-range PDR and an IPv6 packet.
2. **BUFF on the custom path** — decided, and shown for what runs today. The
   placement is the spec's, so it is one placement for both profiles: TS 29.244
   5.2.4.2 has the buffered packets forwarded or dropped "following the packet
   forwarding model specified in clause 5.2.1" under the new instruction, so the
   store sits **before** the ActionTable, on the matcher's buffer gate, and
   releases into the ActionTable's input (`deploy/buffer-path.yaml`:
   `pdr_dl` gate 1 → `cnt_buf` → `buf` → `at_dl`). The custom profile's downlink
   matcher is the stock WildcardMatch, so it is already that placement:
   `PROFILE=custom ci/buffer-path.sh` (graph `deploy/pdrmatch-buffer-path.yaml`)
   holds, reports and releases exactly as the generic lane does. Not done: when
   `PdrMatch` serves a downlink (item 3) it needs a second output gate for a
   BUFF verdict (a rule field, a configurable gate, default 1), because routing
   BUFF through an action's next hop would put the store *after* the Router and
   the release would re-enter the meter and encap. `pdrMatchChanges` refuses
   BUFF on a PdrMatch direction until then.
3. **The downlink selector** — `PdrMatch` is keyed by session, and the session of
   a downlink packet is found by its destination address, so a selector in front
   of it must map (route domain, destination address) → session. For IPv4 that
   is an **exact-match** table (every project whose source was read does the
   same: Open5GS `upf_sess_find_by_ue_ip_address`, eUPF's
   `pdr_map_downlink_ip4`); for IPv6 it is an LPM on the prefix (TS 29.244
   8.2.62: an IPv6 UE address is a /64 prefix). Either emits the session
   attribute `PdrMatch`'s `key_attr` already names, so the module does not
   change. **No custom selector module is needed**: stock `ExactMatch` keyed on
   (`route_domain` attribute, destination address at offset 30), with
   `action_resource: at_dl/actions`, writes the rule's `action_id` into the
   packet, and `PdrMatch` with `key_attr: action_id` (declared once, as an
   update, since 2026-10-18) reads it as the session key and overwrites it with
   the matched PDR's own ActionId. The session's id is one id from the
   compiler's action pool with a record in `at_dl/actions` (the engine checks a
   rule's `action_id` as a reference). Probed live: 19.2M packets through
   `ExactMatch -> PdrMatch` on a throwaway graph, both stages' gate 0 counters
   equal. Not yet in a lane or the compiler. The generic profile needs neither table: its `pdr_dl` is keyed on the
   destination address and is the lookup. This is the spec's two-step model
   (5.2.1: session look-up, then the PDR look-up within the session). Needs the
   selector module(s); a design call on whether one module serves both
   families.
4. **IPv6 through the module** and **route domains on the custom path** — the
   key is IPv4-only; one module per domain or the domain in the key.
5. **Known limits of the QFI arm**: the QFI 5 phase proves the flow is
   forwarded and the QFI 9 phase proves it is dropped, but QFI 5's rule and the
   plain rule share a FAR, so a lookup that wrongly fell through to the
   QFI-less rules would still pass; a per-ActionId counter (a URR per PDR)
   would tell them apart. A session whose rules *all* name a QFI (an empty
   QFI-less list) is accepted by the daemon (probed once, not an arm).
6. **Not done anywhere**: gate/GBR, time and threshold URRs on the custom path
   (live), the echo responder in the custom lab graph, an ASan build of the
   plugin, a benchmark of the custom path, a real SMF, a NIC.
7. **The force-push**: the rewritten history is local; the GitHub remote still
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
