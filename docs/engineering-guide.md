# Engineering guide

This page gives the rules that review and the lanes found broken again and
again in this tree, so that a change is right the first time. Each rule
names the commit, pull request, decision or audit finding behind it; the
full contracts are in the linked documents.

**Sources.** A 7-character hex is a commit in this repository. `bess:xxxxxxxx`
is a commit in the BESS fork (`krsna1729/bess`). `#nn` is a pull request here;
`bess#nn` is one in the fork. `D-nnn` is a decision in the fork's
`docs/decisions.md`. IDs such as `UG-B3` (Go control plane), `UD-R3`
(datapath plugin) and `U-6` (BESS) name findings of the 2026-10-31
data-structure audit at 379165c (UPF) and bess:2561ff36 (BESS). Some cited
commits are on open branches; the pull request is named where it matters.

**The datapath plugin is BESS code.** For packet-path, memory, lock, RCU and
toolchain rules, read the BESS
[engineering guide](https://github.com/krsna1729/bess/blob/develop/docs/engineering-guide.md);
this page does not repeat it.

## 1. Read first

| You change | Read |
|---|---|
| Anything | README.md (lanes, the inner loop), [design.md](design.md) (deployment, costs) |
| The compiler or the session model (`internal/session`) | §2, §3, §4 of this page; design.md "Mapping PFCP → BESS", "Session scale" |
| A tick, a sweep, or anything that loops over sessions | §2 and §8 of this page |
| A PFCP behaviour or a claim | §3 of this page; [spec/README.md](spec/README.md); `docs/claims.json` |
| The plugin (`datapath/`) | [datapath.md](datapath.md); the BESS engineering guide |
| The BESS pin, a transaction shape, a refusal | §4 of this page |
| A lane or a test | §5 of this page |
| A number in a doc | §6 of this page |

## 2. Go control plane at scale

The target is 10⁶ sessions with 2-8 PDRs each (design.md "Session scale").
Each miss below passed every unit test and lane, and showed only at
100K-1M sessions.

1. **A message costs what it changes, not what is installed.** A lookup is
   an index, never a walk: `findByCP` walked every session under the lock on
   each establishment, O(N²) over a load (b7a02ae, UG-F1).
2. **Build each derived value once, in its compact form.** Rule keys built
   twice per PDR were 29% of bytes allocated (190d996). A JSON → protojson
   round trip per change was 30% (744837d). `fmt.Sprint` ownership keys held
   37% of the live heap at 100K sessions (b7a02ae). `fmt.Sprint` dedupe keys
   and a deep clone per modify remain (UG-R6).
3. **A tick reads in bulk, and a bulk read is paged.** One RPC per session
   per tick was 1-2M round trips (645488a). One read per module is the fix,
   but one `get_counts` reply passes the 64 MiB message limit at about 2M
   rules, and then no URR is reported at all (UG-B1). The downlink tick
   still sends one RPC per idle session (UG-B3).
4. **No per-tick O(N) under the session lock.** The usage and downlink
   ticks walk every session under `c.mu`, which stalls every establishment
   (UG-R1); per-session allocations per tick add about 10M per tick (UG-R2).
   Keep the set that needs work (the measured sessions) up to date in
   compile, and walk only that, in pages, outside the lock.
5. **Work over many sessions is bounded batches.** The startup sweep and
   the association end apply `sweepBatch` (1000) changes per transaction
   and stop at the first refused batch (9bee0ab, b7a02ae); one transaction
   of every entry breaks the 2048 retire budget and the 64 MiB limit
   (D-148). Empty a table on the daemon side; never read it back to erase it
   (a2d16c1, D-171). Quota enforcement inside a tick is still one
   transaction per session (UG-R9).
6. **Bound concurrency where the engine is serial.** 256 concurrent applies
   stalled for 30 s at a time; the client holds 32 tokens (31cb745). The
   N4 rate is set by the server's serial loop: 522/s at one in flight, 534/s
   at eight (7dc7e1f). Shard by SEID to overlap sessions and keep each
   session's order (f28b7ac).
7. **Everything that grows has a reclaim path that runs.** The F-TEID
   context pool's freed list grows forever, because the walk never wraps
   (UG-B4). The journal grows with message history, not live sessions
   (UG-B5). Go maps do not shrink after a mass teardown (UG-R5). One fsync
   per message serialises every worker (UG-R7).
8. **Cap what the peer controls.** An uncapped PDR count per session gives
   O(P²) work under the shared lock (UG-R10).
9. **Garbage is memory.** upfd sets GOMEMLIMIT to the smallest cgroup
   `memory.max` on its path, less max(32 MiB, 10%), unless GOMEMLIMIT is set
   (f28b7ac). Watch allocations per operation: `BenchmarkEstablish` reports
   allocs/op (e3d84f0: 1,110 → 1,094).
10. **Check a runtime claim before you act on it.** A timer change built on
    "time.After leaks until GC" was reverted: Go 1.24 frees it (6e5beca).
11. **Prove scale with a count, not a time.** Assert RPCs, transactions,
    allocations (`testing.AllocsPerRun`) or entries visited at two session
    counts. Each audit finding above names such a test.
12. **Justify each remaining O(N) step with `// scale: <bound>`** on the
    line or the line above: what bounds N (config, a constant, a module
    count) and the test. A planned gate (BESS `tools/check_scaling.py`) will
    enforce it in this repository; it does not run here yet.

## 3. 3GPP compliance

The pinned release is Release 16 ([spec/README.md](spec/README.md)).

1. **Read the clause; never cite from memory.** Most of the compliance
   matrix's clause column was memory, and wrong (01ae00a); the Report Type
   is 8.2.21, not 8.2.18 (7aee611).
2. **Quote it.** A change that relies on a clause adds the clause text to
   `docs/spec/<spec>-<version>.txt`, updates the excerpt SHA-256 in
   spec/README.md (1506e86), names the spec, version and clause in
   `docs/claims.json`, and quotes the clause in the commit message (76f7461,
   9a642dd).
3. **The spec beats the ticket.** The ticket's byte layout put the QFI in
   the wrong octet; TS 38.415 puts it in octet 2's low six bits (3688e9b).
4. **An update keeps what it omits.** TS 29.244 Table 7.5.4.2-1 NOTE 1: an
   Update PDR without Precedence reset it to 0 and outranked the session's
   other PDRs (9a642dd, #24). A removal unlinks its references, it does not
   refuse them (5.2.2.3.1, 5.4.5; 76f7461, #27).
5. **Implement the documented contract.** The docs said malformed frames
   drop at decap; they left on gate 2 (7882263, #32).
6. **upfd stays strict; peer bugs go upstream.** pfcpsim sends a downlink
   PDR whose S/D=0 contradicts its own SDF filter. upfd refuses it (TS 29.244
   8.2.62), the lane builds pfcpsim with an overlay, and the bug is reported
   upstream (01876ee; omec-project/pfcpsim#363, TOSSI-Foundation/CNTC#1).
   Accept a quirk only when the spec allows it: QER ID 0 (e5cddf2), a
   zero-TEID Outer Header Creation (40a552c).

## 4. The BESS interface

One PFCP message is one BESS transaction (design.md "The control path in
one sentence").

1. **Follow the engine's rules, not the fake's.** The engine refuses a
   second operation on one (resource, key) in a transaction (0ac7d0c). It
   checks a reference whatever gate the rule takes (3f9b929). It answers
   BUSY; it does not pause the workers for you (8710574).
2. **A released id waits out the grace period.** Reuse it at once and the
   engine refuses "the meter is still retiring" (3b7c657).
3. **Release ids on the right refusals.** A refused establishment frees
   every id it took; a refused modification does not, because live records
   still name them (2c844ae). A shared pin is released once, and the
   collision check is atomic with the merge (482dd5b). Rollback keeps each
   id pool separate (11bd436).
4. **A memory refusal is a cause, not a crash.** Every plugin table comes
   from `init_context().memory()`; RESOURCE_EXHAUSTED becomes cause 75 and
   the session's claims are released (aee9546, #29; D-198).
5. **Size admitted memory to what is written.** Counter planes default to 64
   workers for a one-worker module: 3 KiB per ActionId (U-6). The
   session-major stride keeps a spare version per session (UD-R3).
6. **Pin BESS by full SHA** in `.github/bess.sha`; CI reverse-checks the pin
   against the staged build (63d4fec). A short pin cannot be fetched
   (af1514e). Lanes use this repo's `build/bess`, never a sibling checkout
   (8020234, e178555).

## 5. Lanes and tests

**Environment.**

| Rule | Source |
|---|---|
| A Unix socket path fits `sun_path` (108 bytes). Tests bind abstract names; a long TMPDIR broke `bind`. | 733ead7 (#26) |
| No fixed `/tmp` socket: BESS unlinks on bind, so a second daemon steals the first one's endpoint. Render a per-run path. | 9fc162f |
| Scratch goes under TMPDIR (default `build/run`), never `/tmp`. Clean up on green; keep and print the path on red. | a8c7410, c8814a6 (67 leftovers in `/tmp`) |
| `sudo` strips TMPDIR, so pass it with `sudo -E` or explicitly. A root lane's work dir must sit outside a private (0700) home: `bessctl` drops its capabilities even as root and cannot enter it. | feat/end-marker-relay lane run (#28) |
| The host firewall (ufw, INPUT policy drop) drops GTP-U arriving on a veth and N4 from a container. Read lane traffic from a packet socket, or add one scoped runtime rule and remove it at teardown. | 2c20c91 (#28), cc705ce |
| Refuse relative paths in a lane's arguments; a slipped argument made a root daemon bind a socket in the repo root. | 37eecde |
| Root-written files need care: a pidfile carried a NUL. | b3ed037 |
| Each lane starts its own daemon on free ports from this repo's BESS build. | 8020234 |

**Oracles.**

- Match a dump's bytes in that dump: hex joined from every Dump let an
  uplink check pass on downlink bytes (4ba1242).
- Silence background sources in a shared graph: an Error Indication source
  put 971,430 frames on the gate a drop check read (c674eb5).
- Count from the event you claim, not from before a restart (926a6d5).
- A run that did not run fails: an empty report exited 0 (2d79d9a), and so
  did an interop stage that never ran (f80123d, #33).

**Fakes enforce the engine's rules.** The recorder in `internal/session`
tests accepted anything, and three commits passed that the daemon refuses
(0ac7d0c). A fake refuses what the engine refuses, or the claim is proven on
a live lane (`TestLiveSessionSharedRecords`).

**Claims name their check.** Every claim in `docs/claims.json` names its
test or lane, and `ci/verify.sh` renders `docs/claims.md` (README.md).
Prose follows the same rule: a doc claimed the daemon quiesces workers
(8710574); another called buffering unverified after a lane had proven it
(3e70d72). The commit that falsifies a claim corrects it. A deployment names
only tracked files (266fc30). Write `[INFERENCE]` for what no check shows.

## 6. Measurement

1. **Pair the runs (ABBA) in one session.** A paired A/B settled that an N4
   spread was the machine, not the compile path (6854b03). Module costs are
   arms against a control arm (design.md, `ci/bench-modules.sh`).
2. **Pin and know every thread.** Run on an isolated CPU with the control
   thread on another (design.md "Taken 2026-10-16"). Confirm the wrapper ran
   the command: `omarchy-benchmark --cpu` exits 1 without running it
   (2d79d9a, ec50b99).
3. **Record contention.** One N4 sample was 3.4× slower at load average 1.3
   and read like a ceiling (1cfcb8c). Print the load average with every rate
   (`ci/bench-graph.sh`).
4. **Report counts, not only time.** Instructions per packet reproduce to
   0.2 between runs; ns do not (design.md). Scale and garbage claims are
   allocation and byte shares (744837d, 190d996), not latency.

## 7. Pull requests

1. **A fix is its own PR, off main.** Bugs found while building a feature
   land separately and first: #24, #26, #31, #32 and #33 against the
   features #23 and #28. A fix that needs another fix stacks on it (#27 on
   #24).
2. **A stacked PR names what blocks it and pins it.** #29 and #30 stack on
   the pin bump #25 and are titled "[blocked on krsna1729/bess#109-#114]".
   A pin of an unmerged BESS branch is its own commit, says what replaces
   it, and blocks the merge (aac6ea9).
3. **One concern per commit.** The message says what was wrong, the clause
   or evidence, and which tests fail on the parent (README.md "Fail first").
4. **Review a fix as new code.** A fix's own new tests found a non-atomic
   check and a double release (482dd5b); the second review of a fix found
   two regressions in it (11bd436). List the state a fix adds and its
   rollback and release paths.

## 8. Scale review checklist

Run it on every change that touches a table, queue, loop over sessions or
entries, tick, or packet path:

- [ ] Each message, tick or sweep costs O(changed); lookups are indexes.
- [ ] No message, RPC reply or transaction grows with the session count; work is batched (`sweepBatch`) and paged.
- [ ] No per-session RPC or allocation per tick; ticks walk only the sessions with work.
- [ ] No O(N) walk under `c.mu` or a plugin `mu_` (UG-R1, UD-B3).
- [ ] Every map, list, pool and file has a reclaim path that runs in the workload that grows it, teardown included.
- [ ] Peer-controlled counts (PDRs, URRs, flows) are capped.
- [ ] Derived keys are built once, compact, without `fmt.Sprint` or JSON.
- [ ] Plugin memory is admitted and written; nothing is sized for 64 workers by default.
- [ ] Each remaining O(N) step has a `// scale:` bound and a count-based test.
- [ ] Count-based tests use `internal/scaletest`: `Ops` and `RPCsAtMost` for a fake's calls, `AllocsFollowChange` at n = 64 and 8000, `HeapPerItem`, `MessageBytesAtMost` for the 64 MiB reply bound.
