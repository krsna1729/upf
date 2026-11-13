# Performance: baseline, attribution and improvement

Use this page to choose and assess performance changes. Preserve dated baselines;
append measured outcomes instead of replacing old evidence with a new claim.
The deployment and capacity record remains in
[design.md](design.md#final-1m-session-churn-measurement-2026-11-05).
Follow the [measurement rules](engineering-guide.md#6-measurement).

## Power qualification correction — 2026-11-06

The laptop's power source changed during earlier work. The journal does not
identify a reliable disconnect/reconnect interval. Treat **all earlier timing
results as unqualified**, including partial release measurements; retain them
only as diagnostics. Functional pass/fail results are not capacity measurements.

Repeat the release baseline, candidate TCP/Unix comparisons and observer-overhead
arms after confirmed AC reconnection. Keep the power evidence with each local
campaign. Power checks belong in a disposable laptop-only runner, not the product
or the repository's measurement harness. The user's subsequent target is
**AC-powered with turbo disabled**, after CPU/fan cooldown; repeat the complete
matched sequence in that state. Keep the earlier AC-only runs separate.
No governor, EPP or RAPL change is part of this work.

## Build qualification correction — 2026-11-06

The earlier BESS tree named `fast` was configured with Meson `buildtype=plain`,
`optimization=plain` and no optimization flag in its actual C++ compiler
commands. `-DNDEBUG` was present; that does not enable optimization. The UPF
plugin was compiled with `-O3` and libstdc++ assertions. Preserve those
mixed-build runs as diagnostics, **not production capacity ratings**, including
the dated one-million-session profiles below and the first typed-churn passes.

The matched release builds use the project's production defaults:
`buildtype=release`, `-O3 -DNDEBUG`, x86-64-v3 and no LTO for both original and
candidate BESS. Keep their build-info JSON and actual compiler commands with
the binary hashes. A directory named `fast`, a release label, or assertion
settings alone are not build evidence. Do not attribute a compiler-setting
change to a source optimization.


## First-principles N4/compiler representation budget

This is **design arithmetic, not an implemented layout, a formal entropy
minimum, or a throughput claim**. Resident state is set by session/rule
cardinality; churn rate sets the work and the number of outstanding versions.
A fixed benchmark template could be compressed much further, but that would
not be a general N4 compiler.

Scope: the current workload has two PDRs, two FARs, one QER, one volume-quota
URR, one IPv4 SDF predicate and one uplink F-TEID per session. It has no BAR or
MAR. Rule IDs remain arbitrary protocol IDs; do not replace them with assumed
constants. Keep shared deployment/association data once and reference it by
integer handle. Variable-length and less common features need explicit side
storage, not silent omission.

### Resident canonical state

A concrete pointer-free Go layout was checked with `unsafe.Sizeof`:

| Record | Count | Bytes each | Bytes/session | Required contents |
|---|---:|---:|---:|---|
| Session header | 1 | 64 | 64 | Both SEIDs; association/native-slot handles; model/publication versions; slot generation; UE address; flags, counts and extension/timer handles |
| PDR | 2 | 96 | 192 | Protocol IDs and references; precedence/presence; endpoint/F-TEID; compiled handles; one 32-byte IPv4 predicate |
| FAR | 2 | 48 | 96 | ID, TEID, peer-address union, policy/instance/endpoint/next-hop handles, marking and flags |
| QER | 1 | 64 | 64 | Four 64-bit UL/DL MBR/GBR rates, window, ID/meter handles, gates/QFI/presence |
| URR | 1 | 224 | 224 | ID/UR-SEQN, triggers/period, six volume limits, two time limits, measured/queued/confirmed counter baselines, four wall/monotonic time pairs and pending/link handles |
| **Canonical core** | | | **640** | No per-record pointers, maps, strings or `time.Time` objects |

The URR budget retains the distinction between sampled, queued and confirmed
usage. Removing that distinction to save bytes risks lost or duplicate billing.
The PDR budget covers this fixture's single predicate/reference set; multiple
SDFs, QFIs, QERs/URRs, IPv6 selectors, BAR/MAR and linked-rule lists add storage.
Do not retain a second decoded PFCP IE tree merely to preserve optional fields:
retain the normalized values and explicit presence bits required by supported
semantics. Keep unknown-extension bytes only where the contract requires them.

Budget another 224 B/session for indexes and allocation/queue bookkeeping:
40 B for CP-F-SEID lookup, 80 B for two classifier-ownership entries, 40 B for
F-TEID ownership and 64 B for allocation/timer/queue bookkeeping. The hash
budgets assume 32-byte slots at 80% occupancy. Ownership fingerprints are only
shortlists: compare the complete predicate in the canonical record on a match;
a hash collision must not become a false ownership conflict or alias.

For one million sessions, the packed budget is 864 MB. At 80% canonical-slab
utilization it is 1.024 GB. Rounding the three indexes to power-of-two capacities
raises the example to 1,132,435,456 B, about 1.055 GiB. A reasonable engineering
target is therefore **1–1.25 KiB of retained control state per fixture session**,
not 3 KiB as an inherent language floor. This excludes BESS dataplane tables,
packet buffers, runtime overhead, extra rule features and bounded request/report
payload retention. The observed 3.09 GB UPF live heap includes other objects;
it is not a like-for-like proof of recoverable encoding overhead.

Use pointer-free slabs and flat handle indexes if implementing this layout.
Go can keep their contents outside its pointer scan; a million heap objects
and a million pointers are not required merely because the control plane is Go.

### Per-change staging and CPU budget

A 32-byte delta header can identify the session, expected version, request and
operation. Stage only changed fields plus their before-images; do not clone
every PDR/FAR/QER/URR on an eight-byte quota update. These are rounded logical
staging budgets, not measured allocations or gRPC wire sizes:

| Completed operation/cycle | Staged bytes | 1K/s, MB/s | 10K/s, MB/s | 100K/s, MB/s |
|---|---:|---:|---:|---:|
| FAR change: header + old/new FAR | 128 | 0.128 | 1.28 | 12.8 |
| PDR change: header + old/new PDR, rounded | 256 | 0.256 | 2.56 | 25.6 |
| QER change: header + old/new QER, rounded | 192 | 0.192 | 1.92 | 19.2 |
| URR quota-only change: header + old/new limit/presence | 64 | 0.064 | 0.64 | 6.4 |
| Establish: header + canonical core | 672 | 0.672 | 6.72 | 67.2 |
| Delete: identity/version and tombstone/undo metadata | 96 | 0.096 | 0.96 | 9.6 |
| Replace: delete plus establish | 768 | 0.768 | 7.68 | 76.8 |

These bytes can pass through reusable worker scratch; bytes touched are not
necessarily bytes allocated. Retain an old/candidate version until its outcome
is known, serialize same-session publication or check its version, and keep
uncertain outcomes quarantined. Reporting must not race a rollback.

The current session-major BESS API still replaces a complete native entry for
forwarding changes. A compact compiler delta does **not** imply a partial-field
RPC. Budget canonical reads, lowering and actual protobuf encoding separately.
Even a 1 KiB application payload per acknowledgement is 102.4 MB/s at 100K/s;
that alone is not a reason to introduce shared memory.

| Accepted cycles/s | CPU time available per separate control core | Cycles at nominal 2.6 GHz | 70%-utilization work budget |
|---:|---:|---:|---:|
| 1,000 | 1,000 µs | 2,600,000 | 700 µs |
| 10,000 | 100 µs | 260,000 | 70 µs |
| 100,000 | 10 µs | 26,000 | 7 µs |

These are budgets, not measured execution times; effective frequency can be
lower. UPFD control, BESS control and BESS dataplane need distinct physical
cores for the appliance comparison. Each control stage must meet its own
budget. Native RPC below already costs approximately 51–53 µs of BESS control
CPU/ack at concurrency eight for its small two-change payload: 100K such
acknowledgements/s would consume approximately 5.1–5.3 control cores at that
cost. That is not a prediction for larger UPF transactions. Replacement uses
two acknowledged operations per cycle; a model-only quota change can use no
BESS transaction while enforcement/forwarding remains unchanged.

### Outstanding work, retries and reporting

Little's law is `in_flight = accepted_rate × mean_ack_latency`. With 1 KiB per
outstanding context, a 1 ms mean acknowledgement needs 1, 10 or 100 KiB at the
three target rates. A five-second failure window instead exposes 5.12, 51.2 or
512 MB if that layer admits the full rate. A separate 256-byte dedup/reply-cache
entry retained for five seconds costs 1.28, 12.8 or 128 MB. Actual response
lengths, cache windows and admission bounds must be measured and recorded.

At 100K/s and 1 ms, 100 requests must be in flight on average. With only eight,
mean acknowledgement latency must be at most 80 µs to reach that rate; enough
memory is not enough concurrency or CPU. Bounded queues and explicit overload
handling remain required. Individual acknowledgements and safe retransmission
must not be removed to make the throughput number larger.

URR reporting adds its own rate and outstanding payloads. The current packet
witness activates 16 sessions, not one million one-second reporting sessions.
One million active one-second reports would add one million reports/s and
must be dimensioned separately. General state is
`sessions × core/index bytes + extra-rule bytes + rate × latency × in-flight bytes
+ rate × retention × dedup bytes + reporting + runtime`.

Arithmetic evidence: local `state-budget-layout.go` and
`state-budget-arithmetic.json`; the former verifies the proposed Go sizes,
not semantic completeness or product behavior.

## Appliance alternative before shared memory: embedded N4

**Candidate, not implemented or selected as the deployment contract.** An
embedded C++ PFCP frontend, canonical model and compiler could live in the UPF
plugin/control component and install typed native transactions without an RPC
boundary. Keep generic BESS free of PFCP/UPF policy. The existing separate
`upfd` deployment remains the implemented contract in `design.md`.

The framework already exposes the relevant owner capability:
`ModuleInitContext::resources().ApplyOwned(owned, ops)` in
`core/dataplane/resource_registry.h`. It is installed for plugins and gated by
`BESS_CAP_OWNED_APPLY`. Its contract preserves transaction-engine all-or-nothing
publication, referential consistency, ownership restrictions, retirement
budgets, BUSY/refusal handling and common outcome metrics. The UPF plugin
already uses it in `datapath/upf_appliance_selftest.cc` and its neighbor slow
path. It is not a direct mutable-table escape hatch.

The intended path would be PFCP → normalized session delta → native typed
operations → owned transaction → packet-visible publication. This can remove
the Go/C++ boundary, RPC serialization and some duplicate representations.
It removes Go GC for session state only if that state actually moves; retaining
Go and C++ copies would defeat much of the benefit.

Constraints that remain:

- Call on the control side with the control-plane lock held, never from packet
  workers or inside resource Reserve/Prepare/Publish callbacks.
- `ApplyOwned` applies only resources the caller registered. An appliance
  owner can use it for its session resources; a new sidecar module does not
  acquire ownership of another module's tables by knowing their names.
- It does not supply PFCP association identity, request deduplication, durable
  restart, report acknowledgement/accounting or application model versioning.
  These remain N4/compiler responsibilities. Owned apply also does not mean
  every gRPC receipt/event adapter behavior happens automatically.
- Socket receive, heartbeat/report timers and BUSY deferral must not block the
  control lock. Existing `TickEndpoint` callbacks have bounded maintenance
  slices; do not assume their polling cadence is a 100K/s N4 event loop.
- One model/writer owns a session. Admin reset, resource inspection and events
  must stay coherent; Go and embedded N4 must not both write the same sessions.
- An embedded C++ parser shares the dataplane's failure domain. Bounds checks,
  malformed-message handling, parser fuzzing and restart/HA parity are
  equipment-level acceptance criteria, not optional performance overhead.

For attribution, compare the same transaction workload at three boundaries:
remote gRPC; local `DataplaneTransactions::Apply` with the same request/receipt
semantics; then typed `ApplyOwned`. The second isolates RPC transport/dispatch
and wire decoding from the receipt/codec path. The third also removes adapter
work and is an engine-side floor, not a complete N4 measurement; account for
the embedded frontend's own PFCP deduplication and acknowledgement work.
Keep individual outcomes, bounded concurrency, packets and reporting.

The recommendation is to assess this architecture **before** introducing
shared-memory RPC, not to start a C++ protocol rewrite from the native RPC
throughput number. The compact representation budget applies in either
language. If selected, migrate the protocol/model/compiler with semantic
parity and avoid maintaining unrelated graph/appliance implementations.

## 2026-11-06: qualified release RPC comparison, turbo disabled

**Worker reuse gives a larger gain than switching TCP to Unix gRPC. Shared
memory remains deferred.** This is native RPC evidence, not an N4 capacity
rating or a forwarding/NIC qualification.

`rpc-release-nt-abba` completed all 16 cases: baseline/candidate/candidate/baseline
for each transport and concurrency. Each case ran 0, 1K, 10K, 100K and maximum
offered transactions/s for ten seconds each. A transaction contains one typed
`ExactMatch` upsert plus one erase, with an individual acknowledgement.
Persistent C++ SDK clients have one outstanding transaction each; eight clients
therefore bound aggregate pipelining at eight. Every arm uses the same client
binary, payload shape, 512 sessions per client and packet workload.

Both servers use matched release flags. One control P-core, one packet P-core
and three separate client P-cores are pinned on the non-exclusive i9-13900H
laptop. AC was online and turbo disabled in start/end and two-second local
policy samples; cooldown preceded the comparison. No sampler or product overlay.
Control CPU below is process-wide daemon CPU minus persistent packet-worker
CPU, divided by acknowledged transactions. It includes exited handler threads.

The table gives the range of the two **maximum-offer** repetitions, not a
confidence interval. Latencies are per-transaction, including busy retries.

| Clients | Transport | Server | Acknowledged transactions/s | p99, µs | Control CPU, µs/ack |
|---:|---|---|---:|---:|---:|
| 1 | TCP | Baseline | 5,780–5,889 | 215–219 | 109.7–110.4 |
| 1 | TCP | Candidate | 8,014–8,183 | 153–156 | 62.5–63.1 |
| 1 | Unix | Baseline | 6,361–6,442 | 207–209 | 114.1–115.9 |
| 1 | Unix | Candidate | 8,559–8,715 | 142–144 | 73.1–74.2 |
| 8 | TCP | Baseline | 8,503–8,572 | 1,294–1,316 | 109.2–110.0 |
| 8 | TCP | Candidate | 15,913–16,576 | 638–659 | 50.7–53.2 |
| 8 | Unix | Baseline | 9,561–9,614 | 1,166–1,175 | 100.0–100.5 |
| 8 | Unix | Candidate | 17,521–17,775 | 644–655 | 51.2–52.2 |

All cases preserved the expected half-matched packet witness and completed
administrative shutdown and scope cleanup. The `busy` output column counts
refused/busy transaction answers; it is **not CPU utilization**. Client process
CPU includes its gRPC threads; committer-thread CPU alone is not the client
cost. Raw logs and `cpu-attribution.json` preserve both.

Reproduce the comparison with `tests/perf/live_transaction_bench`, `--clients`
1/8, `--sessions 512`, `--duration 10`, `--rates 0,1000,10000,100000,max`,
`--daemon-pid` and the matching TCP/Unix endpoint. Keep the before/after worker
accounting and binary hashes. Evidence is under the local root named below.

### N4 remeasurement qualification limits

The first complete no-turbo N4 baseline is `nt2-base-tcp-1`, all 21 cells.
The corresponding candidate reached 17 cells before a **host-wide OOM**
killed UPF below its own scope cap. The kernel explicitly reports
`global_oom`; this is not a local memory-limit pass or a completed matrix.
Three unused 1 GiB hugepages remain reserved on the laptop; they are not
available to the normal-page run.

The explicit `GOMEMLIMIT=4GiB` attempt also stopped after 17 cells during
untimed reconciliation. A later preserved failure snapshot identified the
product's unchanged 70%-of-Go-limit heap admission boundary: live heap
3,018,422,936 bytes exceeded the approximately 3,006,477,107-byte threshold,
with `upf_sessions_unadmitted_total=33738` and zero rejected BESS transactions.
The original HTTP 500 body was not retained; the runner now preserves error bodies
and a failure snapshot before cleanup. Do not attribute every earlier kill
or unobserved HTTP failure to this later diagnosed cause.

The completed NT5 campaign instead retained the product's cgroup-derived
Go limit, **5,001,707,520 bytes**, and used **`GOGC=25` for every arm**.
This contains transient garbage without bypassing admission or increasing
hard budgets; it also increases GC work and is not a claim of optimal tuning.
Shared-control-core and incomplete matrices remain separate diagnostics.

## 2026-11-06–07: complete N4 comparison on independent control cores

**The candidate reduces common mutation work, but it does not sustain the
10K/100K offered rates across all churn types. Unix gRPC is not a universal
improvement. Shared memory remains deferred.**

### NT5 configuration and acceptance boundary

Nine arms completed: `nt5-base-tcp-1`, `nt5-cand-tcp-1`,
`nt5-cand-uds-1`, `nt5-cand-uds-2r`, `nt5-cand-tcp-2`,
`nt5-base-tcp-2`, `nt5-cand-perf`, `nt5-cand-overlay`,
`nt5-cand-tcp-3`. Exclude the interrupted `nt5-cand-uds-2`.
Each arm has all seven modes at 1K, 10K and 100K offered cycles/s.

- One million resident sessions; mutation/replacement selects that population.
  Establish/delete use an extra 65,536-session finite cohort. Sixteen resident
  sessions are synthetic UL/DL/reporting witnesses. Mutation/replacement offers
  have a nominal 30-second schedule; record actual offer/drain duration because
  driver catch-up can extend an overloaded offer. Finite establishment/deletion
  is not a 30-second high-rate steady-state qualification.
- Separate physical P-cores: UPFD CPU 4, BESS control CPU 6, packet worker CPU 8;
  driver CPU 10–11. Monitoring avoids these cores and their siblings.
- AC online and turbo disabled in every recorded two-second policy sample.
  The initial thermal gate requires package ≤55°C and fan ≤3,000 RPM for
  60 seconds. CPUs remain shared with ordinary host tasks.
- Native baseline/candidate use matched GCC 16.2.1 `-O3 -DNDEBUG
  -march=x86-64-v3`, no LTO/sanitizers; ordinary Go 1.27.2 product binaries
  use no profiling overlay or local SDK replacement.
- NT5 explicitly uses `GOMAXPROCS=2` despite UPFD affinity to one logical CPU.
  This is a recorded runtime configuration, not the default-affinity runtime
  floor. The corrected runner uses one Go P; keep its follow-up separate.
- Hard limits: BESS 3,000 MiB, UPFD 5,300 MiB, driver 512 MiB,
  aggregate 7,872 MiB, no swap. The perf arm reserves 192 MiB extra only
  inside the BESS role; its daemon limit and aggregate budget are unchanged.
- The first three arms ran November 6; resumed arms ran November 7. Observed
  PL1/PL2 changed from 58/82 W to 82/82 W between days without a write by this
  campaign. Preserve same-day comparisons and do not infer causation.

All **189 cells** reconcile to one million sessions, zero pending/uncertain
or busy sessions, with clean BESS/UPFD exits. Every cell has positive UL/DL
packet and report-acknowledgement deltas. No role/lane hard-limit or OOM event
was recorded. Aggregate peaks span 6,644.0–7,004.9 MiB; some
`sock_throttled` counters are nonzero. The perf BESS role peaks at 3,008.9 MiB,
above the plain role cap but within its explicit 3,192 MiB recorder reserve.

This is **not loss-free qualification**: overloaded cells have substantial
UPFD socket receive drops and PFCP timeouts. Reconciliation repairs uncertain
population outside the measured window. Report acknowledgements are traffic
witnesses, not a measurement of all-million-session reporting capacity.

### Plain-product completed cycles/s

Ranges retain both baseline TCP passes, all three candidate TCP passes and
both candidate Unix passes. Rate denominator includes drain; replacement
requires two successful PFCP messages per complete cycle. Latency quantiles
cover successful survivors only, excluding timeouts/refusals.

| Mode | Offered cycles/s | Baseline TCP | Candidate TCP | Candidate Unix |
|---|---:|---:|---:|---:|
| FAR | 1,000 | 699–999 | 999 | 999 |
| FAR | 10,000 | 1,055–2,213 | 2,966–4,123 | 3,169–3,269 |
| FAR | 100,000 | 2,440–2,457 | 2,907–4,173 | 2,981–3,322 |
| PDR | 1,000 | 999 | 999 | 999 |
| PDR | 10,000 | 1,915–2,383 | 2,805–3,557 | 750–1,961 |
| PDR | 100,000 | 1,300–2,477 | 2,740–3,632 | 1,092–2,834 |
| QER | 1,000 | 999 | 999 | 969–999 |
| QER | 10,000 | 2,201–2,775 | 3,209–4,000 | 1,107–3,102 |
| QER | 100,000 | 2,235–2,621 | 2,898–3,989 | 2,952–3,538 |
| URR | 1,000 | 999 | 999 | 999 |
| URR | 10,000 | 2,221–2,760 | 9,286–9,993 | 9,831–9,889 |
| URR | 100,000 | 2,375–2,605 | 18,401–24,129 | 16,467–17,748 |
| Replace | 1,000 | 765–976 | 466–999 | 811–818 |
| Replace | 10,000 | 390–505 | 135–1,085 | 759–830 |
| Replace | 100,000 | 211–251 | 259–446 | 393–424 |
| Establish | 1,000 | 996–999 | 775–999 | 999 |
| Establish | 10,000 | 927–1,559 | 743–2,159 | 1,160–2,069 |
| Establish | 100,000 | 937–995 | 908–1,118 | 898–1,465 |
| Delete | 1,000 | 999 | 999 | 999 |
| Delete | 10,000 | 868–908 | 1,922–2,315 | 1,928–2,097 |
| Delete | 100,000 | 396–449 | 285–923 | 251–760 |

Quota-only URR emits **zero native applied transactions in all 21 candidate
URR cells**, versus one per completed cycle in both baseline passes. That
gain removes unnecessary work; it is not a faster-RPC result.

Do not claim blanket non-regression. In the same-day second TCP pair,
replacement 1K/10K falls 52.2%/73.3%; establishment 100K falls 8.7% and
deletion 100K falls 28.2%. The later bare candidate recovers replacement but
establishment 1K/10K falls to 775/743 cycles/s, with survivor p99
1,409/1,268 ms. The second Unix PDR 10K cell reaches only 750 cycles/s
with survivor p99 about 2,940 ms. Run order, heap state and overload sensitivity
remain material; neither an all-mode 1K SLA nor a universal Unix speedup follows.

### Observer corroboration, not an overhead correction factor

Same candidate release, same placement/payloads/budgets; only the indicated
observer differs. Perf uses 99 Hz user cycles, native DWARF 8,192-byte stacks
and Go frame-pointer stacks, active from child startup. The heap/runtime
overlay uses forced-GC snapshots but **no Go CPU profiler**. Plain before/after
arms have neither overlay nor sampler. Values are completed cycles/s.

| Mode | Offered/s | Plain TCP 2 | Perf | Heap/runtime | Plain TCP 3 |
|---|---:|---:|---:|---:|---:|
| FAR | 1,000 | 999 | 999 | 999 | 999 |
| FAR | 10,000 | 2,966 | 3,866 | 4,142 | 4,123 |
| FAR | 100,000 | 2,907 | 4,050 | 4,099 | 4,173 |
| PDR | 1,000 | 999 | 999 | 999 | 999 |
| PDR | 10,000 | 2,805 | 3,505 | 2,155 | 3,557 |
| PDR | 100,000 | 2,740 | 3,556 | 2,643 | 3,632 |
| QER | 1,000 | 999 | 999 | 999 | 999 |
| QER | 10,000 | 3,243 | 3,892 | 4,150 | 4,000 |
| QER | 100,000 | 2,898 | 3,909 | 3,905 | 3,989 |
| URR | 1,000 | 999 | 999 | 999 | 999 |
| URR | 10,000 | 9,702 | 8,602 | 9,992 | 9,993 |
| URR | 100,000 | 18,401 | 24,007 | 24,425 | 24,129 |
| Replace | 1,000 | 466 | 993 | 996 | 999 |
| Replace | 10,000 | 135 | 438 | 1,162 | 1,085 |
| Replace | 100,000 | 446 | 449 | 488 | 416 |
| Establish | 1,000 | 999 | 999 | 999 | 775 |
| Establish | 10,000 | 2,159 | 2,230 | 2,238 | 743 |
| Establish | 100,000 | 908 | 945 | 1,492 | 1,036 |
| Delete | 1,000 | 999 | 999 | 999 | 999 |
| Delete | 10,000 | 1,922 | 2,195 | 2,354 | 2,159 |
| Delete | 100,000 | 285 | 367 | 983 | 923 |

For example, perf FAR 10K differs +30.4% from the preceding plain but −6.2%
from the following plain. Perf replacement 10K differs +225.2%/−59.6%.
Overlay PDR 10K differs −23.2%/−39.4%; perf URR 10K differs −11.3%/−13.9%.
These quantify **observed differences**, not isolated observer cost.
Plain-to-plain variability is too large to support one correction factor or
to interpret an apparent observer speedup as negative sampling overhead.

### Where the remaining work goes

Go attribution clips normal-release perf samples to explicit
`CLOCK_MONOTONIC` measured windows and weights by cycle period.
Exclusive precedence is GC/scavenging, BESS encoding/SDK/gRPC, compile/fold,
remaining model/lifecycle, other session/reporting, remaining N4/codec,
then other runtime. The table shows 10K-offer cells, not wall latency,
all-process CPU or a general PFCP cost distribution.

| Mode | GC/scavenging % | BESS encode/SDK/gRPC % | Compile/fold % | Remaining model % | Remaining N4/codec % |
|---|---:|---:|---:|---:|---:|
| FAR | 66.98 | 16.17 | 8.79 | 4.54 | 1.11 |
| PDR | 66.08 | 14.61 | 10.25 | 5.56 | 1.25 |
| QER | 67.97 | 15.21 | 9.67 | 3.77 | 1.37 |
| URR | 59.29 | 0.22 | 10.85 | 13.58 | 7.44 |
| Replace | 61.91 | 18.91 | 3.17 | 12.23 | 1.81 |
| Establish | 63.87 | 13.90 | 9.30 | 8.73 | 2.15 |
| Delete | 67.58 | 19.45 | 0.35 | 10.54 | 0.70 |

Unlisted other-session/runtime buckets complete the denominator. Inclusive
PFCP-library, allocation and map shares overlap these buckets; do not add them.
The profile contains no reported LOST record. Native unwinding has a separate
limitation described below.

The independent heap/runtime arm measures the following allocation ranges.
Numerator includes failed/partial work, reporting and observer allocation;
denominator is completed cycles, not all received messages or native writes.

| Mode | Allocated bytes/completed cycle | Mallocs/completed cycle |
|---|---:|---:|
| FAR | 22,734–23,107 | 285–293 |
| PDR | 24,886–25,294 | 313–321 |
| QER | 21,822–22,245 | 276–285 |
| URR | 3,357–3,743 | 38–43 |
| Replace | 49,253–106,559 | 675–1,514 |
| Establish | 30,194–30,438 | 389–396 |
| Delete | 22,107–22,397 | 322–333 |

Post-forced-GC live heap is 2.403–2.644 GiB and scan heap 1.676–1.839 GiB.
Each before→after runtime interval includes exactly one forced GC, while the
cgroup CPU window excludes those snapshots. Runtime GC CPU-class estimates
are not physical CPU counters and can exceed cgroup CPU under this two-P,
one-CPU configuration. Do not divide those mismatched numerators/denominators
to derive a GC percentage.

Allocation differentials identify concrete remaining work: URR 10K repeatedly
clones ID maps/records and parses PFCP; FAR 10K allocates meter changes,
compiled values, rule keys, snapshots and protobuf/gRPC objects. Eliminating
full snapshots requires preserving mutation/resolve/rollback/report ownership;
reusing mutable records without that proof would corrupt recovery.

For a first-principles scale check, holding FAR 10K's measured 22,784 B/cycle
constant at 100K accepted cycles/s implies 2.278 GB/s of allocation. With
roughly 2.49 GiB live state, `GOGC=25` allows about 0.62 GiB of growth before
the nominal heap goal; repeatedly scanning 1.74 GiB then implies roughly
6 GB/s of scan work. This is idealized arithmetic, excluding roots, pacing
and changed workload behavior, **not a measured 100K run**. Reducing retained
pointers and per-change garbage addresses that amplification; shared-memory
RPC alone does not.

Native perf excludes the packet-worker TID and retains 18,015 non-packet
samples across all 21 cells. Complete task metadata shows **one thread birth
and one exit across 1,280,079 applied native transactions**. Additional idle
poller tuning is not the supported next cut.

Independent sampled-IP buckets put 25.24% of native non-packet user cycles in
gRPC/gpr libraries and 38.34% in libc. These are instruction locations, not
complete transport costs. Native DWARF ancestry is incomplete and
decode-range sensitive; do not subtract observed engine/codec ancestry from
100% and label the remainder transport.

The periodic `mallinfo2` free-list walk alone has 21.57% observed inclusive
native non-packet cycles, 19.55% across the 14 high-offer cells. It belongs to
maintenance, not admission or metrics. Existing admission already uses a
conservative 1 MiB cache and refreshes/trims before refusal.

Do **not** remove or merely slow that allocator check: it reclaims unadmitted
garbage under a reserve/4 retention bound. RSS-growth-only gating misses
live-to-free transitions at unchanged RSS. A work-triggered or bounded-cost
replacement must preserve that bound, admitted-release reclamation, fresh
admission checks and strict-budget tests before acceptance.

### Evidence and equipment-rating limits

Local root: `.scratch/evidence/nonshm-control/`. Retain each named
`campaign.json`, 21 reconciliation files, `samples.jsonl`, role process/final
metadata, saved runner, `release-provenance.json`, compile commands and raw
perf/heap files. Summaries: `nt5-completion-audit.json` and
`nt5-go-cycle-attribution.json`; analysis also preserves every cell's latency,
counts, socket drops, resource peaks and observer comparison.

One million resident sessions is a demonstrated workload population, **not a
maximum session rating**. This is session-major appliance control qualification,
not graph forwarding equivalence, a NIC/Gbit/s rating, all-session charging
capacity, HA/failover performance, or formal 3GPP conformance certification.
The existing functional lanes separately cover graph/appliance enforcement,
quota reporting and restart/replay. Any equipment spec must state those limits,
rule mix, active-session/report load, memory/core allocation, accepted goodput,
loss and tail latency instead of presenting offered rate as capacity.

## 2026-11-07: one Go P is not an oversubscription cure

NT6 changes only UPFD `GOMAXPROCS=2` to 1 on the same CPU 4, retaining
binary hashes, payloads, `GOGC=25`, admission and budgets. **Five arms complete
all 21 cells:** two baseline TCP plains, two candidate TCP plains and one
separate candidate perf arm. The heap/runtime arm remains partial with 15 cells.
Both pair orders and all 105 complete plus 15 partial rows are retained.

**Do not infer a universal one-P improvement or blanket non-regression.**
Initial establishment 100K goodput falls 61.23%, with survivor p99 increasing
from 155.67 to 1,146.37 ms. The closing plain recovers to 1,218.83 versus
baseline 1,020.72 cycles/s, but p99 still worsens 37.20% and UPFD CPU/completion
18.14%. Closing deletion 100K improves goodput 5.26% while UPFD
CPU/completion worsens 579.33%. Short cohorts and differing GC/host state limit
causal attribution; unfavorable results are not averaged away.

### Finished one-P plain-product goodput

Completed cycles/s including drain; each range spans two passes, not a
confidence interval. Replacement requires both PFCP operations. Latencies
and CPU numerators remain in the companion JSON/CSV, including failed work.

| Mode | Target cycles/s | Baseline TCP | Candidate TCP |
|---|---:|---:|---:|
| FAR | 1,000 | 549–999 | 999 |
| FAR | 10,000 | 713–2,839 | 3,392–3,828 |
| FAR | 100,000 | 1,777–2,668 | 2,998–4,097 |
| PDR | 1,000 | 999 | 999 |
| PDR | 10,000 | 2,348–2,431 | 3,511–3,557 |
| PDR | 100,000 | 957–2,218 | 3,205–3,501 |
| QER | 1,000 | 999 | 999 |
| QER | 10,000 | 2,606–2,788 | 3,887–3,915 |
| QER | 100,000 | 2,378–2,690 | 3,550–3,895 |
| URR | 1,000 | 999 | 999 |
| URR | 10,000 | 2,668–2,731 | 8,092–8,699 |
| URR | 100,000 | 2,409–2,705 | 10,067–23,550 |
| Replace | 1,000 | 945–955 | 964–999 |
| Replace | 10,000 | 516–541 | 812–1,118 |
| Replace | 100,000 | 218–221 | 264–475 |
| Establish | 1,000 | 999 | 999 |
| Establish | 10,000 | 1,663–1,692 | 1,977–2,296 |
| Establish | 100,000 | 1,021–1,097 | 425–1,219 |
| Delete | 1,000 | 999 | 999 |
| Delete | 10,000 | 326–1,333 | 1,838–2,543 |
| Delete | 100,000 | 413–475 | 435–837 |

All completed arms reconcile after every cell, retain positive packet/report
witnesses, match frozen binary hashes and preserve sampled AC/no-turbo,
separate-core placement and hard budgets without OOM/max events. Overload
still causes substantial UPFD receive drops/timeouts. The final plains follow
a fresh thermal gate and fsync/`POSIX_FADV_DONTNEED` on four owned completed
perf files, not a global cache flush. Host/cache state is therefore not held
identical; neither runtime nor observer differences are isolated causal costs.

### Actual offers and observer corroboration

The frozen driver catches up nominal attempts: baseline PDR 100K offers for
80.584 seconds rather than 30; closing candidate URR 100K offers for 66.948
seconds. These are **not sustained 100K/s offered or accepted capacities**.
Across completed arms, the 100K-target cells actually send:

| Mode | Initial logical requests / actual offer second |
|---|---:|
| FAR | 58,081–81,732 |
| PDR | 37,228–72,967 |
| QER | 54,658–91,076 |
| URR | 44,811–99,781 |
| Replace | 33,479–33,651 |
| Establish, finite cohort | 24,413–54,324 |
| Delete, finite cohort | 99,838–99,886 |

Use `Sent / offer_seconds`, not replacement `WireSent`, which also includes
follow-up establishments during drain. Historical `BusySkips` combines busy
and uncertain slots; replacement shortfall is not purely a slow pacer.

Both final plain repeats corroborate the sampled arm. For example, perf
PDR 10K goodput differs −19.9%/−21.0% from the before/after plains; perf URR 100K
differs −47.7%/+22.4%. Full 21-cell comparisons retain goodput, latency and CPU
differences; the partial heap arm has six missing E/D cells, never zeros.
There is still no defensible scalar instrumentation correction.

### One-P profiles

The normal-product perf arm retains 39,611 UPFD samples in the exact 21
measured windows. Exclusive period-weighted **GC/scavenging is 66.88%**,
largest in 19 cells, versus 63.64% in the separate NT5 two-P profile.
Those mixed-workload fractions are not matched CPU-cost ratios.
All nine FAR/PDR/QER cells have 1.111–1.316× the prior profile's sampled
cycles/completion, including failed/background work. No large eliminated
oversubscription tax is demonstrated. Runtime/other falls 1.66%→1.00%,
but that residual is not a complete scheduling-cost counter.

Native profiling independently retains 21,959 non-packet samples. It observes
three births/three exits across 1,151,790 applied transactions; worker reuse
remains effective. `mallinfo2` maintenance has 26.07% observed inclusive
non-packet user cycles, 24.84% in high-offer cells. Native DWARF still has
range-sensitive missing ancestors; these fractions cannot establish a
transport share or predict a speedup from deleting maintenance.

The heap/runtime overlay is **partial and unqualified**: 15 timed cells,
then HTTP 500 timeout in the initial untimed resolve/re-establish batch after
replacement 100K. Server population is 1M; driver holds 999,990 with 128 uncertain
and zero pending. No admission rejection, native rejection, role/lane
hard-limit or OOM event explains it; daemons later exit cleanly. Significant
page reclaim/major faults and elevated load are observed, but cause is
unestablished. Do not treat cleanup as successful reconciliation or retry
until obtaining a favorable result and discard this failure.

Partial-overlay endpoints confirm one Go P and still scan about 1.81–1.88 GB
after forced GC. Per-cell runtime intervals again include one forced GC;
their CPU estimates are not divided by physical cgroup CPU.
Local evidence includes `nt6-final-analysis.{md,json}`, `nt6-final-rows.csv`,
`nt6-final-pairs.csv`, the preserved initial `nt6-campaign-analysis.{md,json}`,
`nt6-go-profile.{md,json}`, `nt6-native-profile.{md,json}` and reproducible
`nt6-go-profile-analyzer.py`, beside raw campaign/profile files.

## 2026-11-05: one-million-session control-plane baseline

**Conclusion:** PFCP wire parsing is not the main measured cost. The session
representation and GC, rebuilding BESS state, and the RPC machinery are larger
candidates. CPU consumption is not a partition of request elapsed time.

### Provenance and workload

- Host: Intel Core i9-13900H; one NUMA node. Control-plane campaign, not a
  server-class NIC or forwarding-capacity qualification.
- Layout: session-major appliance; 1,000,000 installed sessions, capacity
  1,165,536; two action slots and two meter slots per session; one counter plane;
  counter capacity 4,194,304; F-TEID capacity 2,097,152; 131,072 packet buffers.
- Each session: two PDRs, two FARs, one QER and one volume-quota URR. Only the
  UL PDR names the QER and URR; no BAR or MAR. Two configured meter slots do
  not mean two PFCP QER objects.
- Modification: change the DL FAR's tunnel endpoint. Replacement: delete plus
  establishment. Offered rates are not achieved rates or PFCP message rates.
- Each profiled window lasts 30 seconds. The normal-page profiles below contain
  12.16 CPU seconds (modify-10K), 12.22 (modify-100K), and 8.89 (replace-10K).
- Campaign metadata records UPF `96c69885` plus
  `paired-final-worktree.diff` and `harness-overlay.json`. The product changes
  were subsequently integrated through PR #66, merged as `bc92bf50`; do not
  describe the instrumented binary as a bit-identical build of that merge.
  BESS is `f5d947311601cb66e914b9adfeb7ea766ddac5bd`.
- Local evidence root, relative to the outer UPF checkout:
  `.scratch/evidence/urr-events/`. Preserve `binaries.sha256`,
  `bessd-paired-final.sha256`, the patch/overlay, campaign metadata, raw
  profiles, analysis and reconciliation records with any published result.
  These local artifacts are not part of this document or guaranteed to be in
  a fresh checkout.

### Non-overlapping upfd CPU attribution

Each raw CPU sample is assigned once, using the precedence below. Percentages
are of all sampled **upfd CPU**, not of a core, all process CPU, successful
handler CPU, or wall latency. These are normal-page, overloaded windows.

| Work | Modify, 10K/s offered | Modify, 100K/s offered | Replace, 10K/s offered |
|---|---:|---:|---:|
| N4 receive/decode/queue/reply | 5.7% | 6.5% | 5.4% |
| Remaining session-model/lifecycle work | 9.0% | 8.9% | 15.7% |
| Compile/fold/encode BESS state | 12.8% | 13.6% | 1.9% |
| BESS client/SDK/gRPC, including transport goroutines | 28.5% | 27.1% | 51.1% |
| GC and scavenging | 31.3% | 31.0% | 0.4% |
| Other session/usage work | 1.2% | 1.6% | 0.1% |
| Runtime/scheduler/other | 11.4% | 11.2% | 25.3% |

Rounding can prevent exact totals. A replacement window with little GC is not
proof that replacement is intrinsically GC-free. Background work and unsuccessful
requests remain in these denominators.

**Bucket precedence, highest first:**

1. GC/scavenging: a frame beginning with `runtime.gcBgMarkWorker`,
   `runtime.gcAssistAlloc`, `runtime.bgsweep`, `runtime.bgscavenge`,
   `runtime.gcStart`, `runtime.gcMarkDone`, or `runtime.sweepone`.
2. BESS client/SDK/gRPC: any frame in `upf/internal/bess`, `bess/sdk`, or
   `google.golang.org/grpc`. Includes counter reads and asynchronous transport
   work, not only transaction commits.
3. Lowering: any `session.(*Compiler).compile`, `.foldSession` or
   `.sessionValue` frame, including their generated/inlined variants.
4. Remaining model/lifecycle: any `session.(*Compiler).Modify`, `.Establish`
   or `.Delete` frame. Includes snapshots, merge, semantic validation, IDs,
   ownership and bookkeeping, excluding buckets already assigned.
5. Other session/usage: remaining frames in `upf/internal/session`.
6. N4: remaining frames in `upf/internal/n4` or `github.com/wmnsk/go-pfcp`.
7. Everything else remains runtime/scheduler/other; do not distribute it by
   guesswork. Allocator work inherits its caller's bucket unless rule 1 applies.

To reproduce, decode each `*-profile.cpu.pprof` with `go tool pprof -raw`,
expand every sampled location's inline frames, and sum `cpu/nanoseconds` using
this precedence. Check that assigned time equals the raw profile's total.
Use the recorded Go toolchain; the original profiles were decoded with Go 1.27.2.

For ordinary inspection:

```sh
go tool pprof -top -cum RUN/modify-100000-profile.cpu.pprof
go tool pprof -top -sample_index=inuse_space RUN/modify-100000-profile-after.heap.pprof
go tool pprof -top -sample_index=alloc_space \
  -base RUN/modify-100000-profile-before.heap.pprof \
  RUN/modify-100000-profile-after.heap.pprof
```

`RUN` is the preserved campaign directory. Cumulative rows overlap: for example,
`Compiler.modify` includes compilation and the foreground BESS client call.
Do not add cumulative percentages. The simple `message.Parse` entry accounts
for 0.3% of modify-100K CPU; PFCP-library frames anywhere account for 1.8%.
Those two figures overlap and are not extra rows in the table.

### Native BESS cost is additional

The matching `modify-100000-profile.bess-perf-callers.txt` reports these
inclusive **BESS cycle-sample** shares:

| Boundary | Inclusive share |
|---|---:|
| gRPC `ThreadManager::MainWorkLoop` | 53.8% |
| `ControlV2Service::ApplyTransaction` | 30.4% |
| `TransactionEngine::Apply` | 13.0% |
| Session-major `SessionResource::Reserve` | 6.2% |

These boundaries are nested, not additive. They do not form a disjoint BESS
breakdown. `MallocFreeCheck` also accounts for about 5.9% inclusive. The saved
native report records zero lost samples. Do not add native percentages to Go
percentages: the process denominators and sampling events differ.

Transacting includes client encoding, HTTP/2, server dispatch, request
conversion, validation, resource preparation, publication and the response.
The native transaction engine is only one part. CPU profiles do not measure
queueing, blocked RPC time or grace-period waits as elapsed latency.

### Memory and allocation pressure

At one million loaded sessions, normal backing:

- Go live heap after GC: 2,560.7 MiB; about 23 million heap objects.
- Scannable heap: 1,996.9 MiB, 78% of live heap.
- Peak upfd cgroup memory: 4,659.8 MiB; not the same as retained heap.
- Modification allocates about 30 KB per accepted PFCP request, amortized over
  the window; this includes background work, not just the accepted handler.

In the modify-100K allocation delta, three distinct flat sites are `pdr.ruleKey`
(16.3%), `pdr.variants` (7.0%) and `meterChange` (6.9%). These quantify repeated
construction, not irreducible protocol state. Retained `Compiler.merge`
allocation sites account for about half the retained profile; that does not
prove half the live objects can be deleted. GC serves both retained state and
transient construction and cannot be charged entirely to one stage.

### What this baseline does not establish

Neither 10K/s nor 100K/s was sustained. Completed modification cycles, including
drain, were about 1.7-1.8K/s. Replacement was about 69-159 cycles/s across the
final cells, with substantial timeouts/drops. These are overload observations,
not an SLA. There was no packet generator in the million-session campaign.
Do not transfer these figures to the graph or action-major appliance, arbitrary
QoS-flow density, all-active URRs, or a NIC forwarding rate.

## 2026-11-08: transaction-stage floors and cross-layer blockers

Start at the native in-process boundary, then add each layer. A stage is a
distinct resource-bearing pipeline module, not another operation in one table.
The generic fixture keeps all eight `ExactMatch` modules and 1,024 existing
entries per module at every point. One transaction replaces one entry in each
of the first 1, 2, 3, 4 or 8 resources. Gates change on every revisit to a key;
hot-key and 1,024-key spread runs are separate. There are no reference edges
between these resources, no active packet reader and no N4 session model.

The [portable record](performance-stage-floors.json) retains all native samples,
source/binary hashes, adverse results and the compiler/lifecycle evidence. Local
raw logs are under `.scratch/evidence/nonshm-control/layered-20261108/`, relative
to the outer UPF checkout. The source bases are merged BESS `43582ca8` and UPF
`709bc7b`, plus the recorded benchmark and directional-meter changes. Do not
label an edited benchmark binary a clean release build.

### Native in-process floor

Each value is the median of three one-second block means, in microseconds per
accepted transaction. Native control/caller affinity is CPU 6. The normal-page
policy is 512 MiB inside the unchanged 600 MiB benchmark guard. AC and turbo-off
hold throughout 271 host observations; package temperature is 49–62 C and CPU 6's
throttle count does not increase. The governor remains powersave, EPP remains
balance_performance and the frequency ceiling is 2.6 GHz; frequency is not fixed.
Affinity is not an exclusive cpuset. No sampler or concurrent build runs here.

| Boundary, hot key | 1 stage | 2 | 3 | 4 | 8 |
|---|---:|---:|---:|---:|---:|
| Typed `TransactionEngine::ApplyOwned` plus outer control lock | 0.550 | 0.753 | 0.995 | 1.196 | 2.000 |
| `DataplaneTransactions::Apply`: codec, digest and receipts | 2.881 | 4.076 | 5.361 | 6.518 | 11.465 |
| Direct public `ControlV2Service::ApplyTransaction` | 3.566 | 4.841 | 6.181 | 7.357 | 12.508 |
| Request/receipt protobuf round trip around that service | 4.375 | 6.040 | 7.806 | 9.487 | 16.105 |

All 180 measured native rows complete without transaction errors:
68,004,237 acknowledged transactions. The typed row deliberately excludes
public epochs, deduplication, receipts and events. The adapter and public rows
restore those contracts in steps; they are not direct mutable-table writes.
Only cold/last client examples are retained, while the normal bounded server
receipt ledger remains enabled.

The eight-stage public path already exceeds a single core's 10 us work budget
at 100K transactions/s, **before IPC or Go**. The adapter is the first measured
boundary that misses it. This does not price a complete UPF transaction: its
resource types, dependencies and payloads differ. It does not qualify packet
forwarding, a million residents, concurrent reports or a 100K N4 rate.

The native TCP/Unix cases run the real gRPC service in the benchmark process,
on the same core as their caller, and omit daemon maintenance. Their process
CPU includes both RPC ends. Do not subtract them from a separate-core Go client
against a real daemon and call the difference language overhead. TCP's
three-stage hot means are 151.465, 336.860 and 293.057 us; all remain in the
record. No fixed-plus-per-stage fit or transport conclusion discards them.
The separate real-daemon C++ SDK mode supplies the topology-matched comparison.

### Real-daemon SDK and UPFD adapter ladder

These are median block-mean wall times in us per acknowledged transaction,
three repeats, one outstanding transaction, 5,000 transactions per SDK block.
All eight stages and 8,192 resident entries remain present; these rows use the
1,024-key spread, the same key/value bytes and individually validated receipts.
Clients run on CPU 4 and BESS control on CPU 6, different physical P-cores.
There is no packet worker. TCP and Unix use fresh real daemons, not bufconn.
Go uses 1.27.2, GOAMD64=v3, GOMAXPROCS=1, GOGC=100 and a 448-MiB soft limit
inside its 512-MiB no-swap scope. This small fixture is not the GOGC=25,
automatically cgroup-limited one-million-session workload.

| Build through receipt, spread keys | 1 stage | 2 | 3 | 4 | 8 |
|---|---:|---:|---:|---:|---:|
| Go SDK, encoded, TCP | 84.266 | 88.752 | 94.050 | 96.360 | 111.782 |
| Go SDK, messages, TCP | 86.173 | 90.261 | 96.369 | 99.346 | 116.868 |
| C++ SDK, messages, TCP | 110.526 | 119.907 | 123.950 | 132.025 | 158.409 |
| UPFD `bess.Client.Apply`, TCP | 108.869 | 118.108 | 129.386 | 137.668 | 156.910 |
| Go SDK, encoded, Unix | 80.678 | 85.817 | 88.441 | 92.333 | 103.725 |
| Go SDK, messages, Unix | 82.107 | 89.969 | 91.887 | 94.517 | 116.447 |
| C++ SDK, messages, Unix | 100.699 | 105.697 | 114.927 | 122.827 | 145.540 |
| UPFD `bess.Client.Apply`, Unix | 100.360 | 108.807 | 112.695 | 114.292 | 142.130 |

The Go SDK validates 1,200,000 warm acknowledgements across separate prebuilt
Commit and combined Build+Commit arms; C++ validates 300,000. The UPFD adapter
uses three one-second Go benchmark blocks per shape/locality/transport, not a
fixed 5,000-call block. Its complete eight-stage TCP call allocates 9,660 B and
132 objects per transaction. These are this adapter's live allocations, not
the compiler's allocations or a million-session retained-state estimate.

For eight stages, Go's separate Build-only TCP blocks measure 12.291 us with
messages versus 3.352 us with encoded values. Values/messages are prepared
before these blocks; this does not price PFCP-to-map encoding. The SDK's
combined encoded TCP client process CPU is about 39.9 us/transaction. C++'s
message client process CPU is 88.0 us, while its daemon process CPU is 80.0 us,
with coarse 10-ms `/proc` accounting over each 5,000-call block. Unix reduces
wall latency but does not automatically reduce CPU: C++'s corresponding client
and daemon figures are 95.3 and 88.0 us.

This is not a Go-versus-C++ language limit: SDK implementations and API
construction differ. It does rule out assuming that replacing the Go caller
with this C++ SDK makes this workload faster. Single-outstanding latency is
not a bounded-concurrency saturation rate. Likewise, differences between
separate adapter and SDK benchmark loops are not exclusive per-layer costs.
No batching, shared memory, receipt suppression or weakened consistency is used.

Review found that the original prebuilt Go Commit arm retained each
transaction's cached Applied result. The final code clears each consumed
transaction reference and explicitly rejects replay; the full SDK campaign was
rerun, not corrected arithmetically. It also bounds iterations at 65,536 and
checks exact attached key/value populations plus absence of workers/tasks
outside timing. Live guards reject extra keys and oversized iterations without
purging caller contents. GraphOnly reports observed zero entries separately
from its intended target; C++ failure output is complete, parseable JSON.

The adapter's full final sweep is slower than its earlier 120.069-us TCP and
111.306-us Unix eight-stage spread results, despite the same production SDK and
9,660 B/132 allocation counts. Preserve that adverse result. An isolated
four-pair old/final-binary ABBA experiment, with the same reviewed provisioner,
finds median paired eight-stage spread ratios 0.9990 TCP and 0.9959 Unix.
Thus the benchmark rename does not reproduce a 30% regression in that
isolation; the full-sweep/isolated-condition gap remains unattributed.
Do not call the gap an exclusive UPFD layer tax or discard the slower sweep.


### Actual N4 and compiler shapes

PFCP fixtures produce 1/2/3/4/8 distinct graph resources, verified from actual
compiler output: downlink dropping classifier; uplink classifier plus F-TEID;
add an uplink meter; add an uplink counter; then both directions with meters,
counters, F-TEID and tunnel. These are mixed UPF resource payloads, **not** the
generic ExactMatch payload above. They establish and then delete sessions,
not replacements of existing generic entries.

Compiler-only blocks execute the real establishment+deletion model cycle
without a native consumer, with a zero-traffic CounterReader. Requests are
prepared before timing. Each iteration is **two transactions**, not one:

| Fixed compiler, per establish+delete cycle | 1 stage | 2 | 3 | 4 | 8 |
|---|---:|---:|---:|---:|---:|
| Median wall time, us | 7.710 | 11.765 | 14.279 | 19.493 | 30.300 |
| Allocated bytes | 5,463 | 7,577 | 9,651 | 13,443 | 22,216 |
| Allocated objects | 69 | 108 | 132 | 188 | 278 |

The real UDP N4 sweep uses 4,096 residents per cell, one outstanding PFCP
message, UPFD on CPU 4, BESS control on CPU 6 and the N4 driver on CPU 10.
Thirty cells (three repeats, two transports, five shapes) accept all 245,760
establishment/deletion responses and cleanly stop their daemons. There are no
active packets or usage-report witnesses in this floor campaign.

| Real N4 median of per-cell p50s, us | 1 stage | 2 | 3 | 4 | 8 |
|---|---:|---:|---:|---:|---:|
| Establish, TCP BESS | 117.27 | 134.68 | 162.86 | 172.03 | 242.26 |
| Delete, TCP BESS | 106.05 | 115.12 | 141.72 | 236.24 | 431.19 |
| Establish, Unix BESS | 112.91 | 125.92 | 156.76 | 165.10 | 255.90 |
| Delete, Unix BESS | 104.32 | 108.06 | 131.81 | 223.35 | 418.21 |

Delete becomes more expensive with measured URRs; final counter/report work
must be separated before calling that delta compiler, GC or transport cost.
Do not subtract compiler-cycle means from PFCP p50s or add either to the
generic RPC means. The later normal-policy loaded run reaches one million
sessions but fails its campaign reconciliation; its separate results follow.

### Sampling corroboration and blocker order

Separate 99-Hz user-cycle observations are bracketed by plain runs of the same
eight-stage case. Values below are medians of three block means:

| Case | Plain before, us | Sampled, us | Plain after, us |
|---|---:|---:|---:|
| Native public service, spread | 12.598 | 12.727 | 12.693 |
| Fixed compiler establish+delete | 29.732 | 29.849 | 29.745 |

Sampling changes these means by +0.27–1.03% and +0.35–0.39%, respectively,
relative to the two plain references. Keep both references; do not apply a
scalar correction to profiles. Native has 437 samples, compiler 350, neither
reports lost samples. Profiles include setup, calibration and teardown; their
symbol weights are diagnostic whole-process observations, not an exact warm
transaction partition. The plain campaign remains the performance evidence.

| Layer/blocker | Current evidence | Next isolation and acceptance gate |
|---|---|---|
| Native codec/receipt path | Eight-stage public service 12.812 us versus typed engine 2.052 us for spread keys. This crosses the 10-us/core budget before IPC; the difference also buys required semantics. Native samples include adapter, malloc/free, codec, hashing and mutex work. | Attribute decode, resource lookup, receipt reservation/digest and event work on the same requests. Reduce allocations/copies with bounded scratch; preserve admission, rollback, epochs, replay, individual receipts and ordered events. Do not remove semantics to match the typed row. |
| Real RPC and SDK | Encoded Go is faster here than message Go or the measured C++ SDK. Unix helps wall latency but does not erase client/server CPU. | Repeat at explicitly bounded concurrency with the same payloads and individual outcomes; measure client CPU, daemon CPU, queue wait and all-offered tails. Exhaust persistent/pipelined gRPC and Unix before shared memory. |
| UPFD materialization | Live eight-stage adapter uses 9,660 B and 132 allocations per call; separate SDK Build blocks expose a message-versus-encoded construction gap. | Separate map-to-wire, op construction, request encoding and response resolution on one compiled corpus. Preserve required/unknown fields, numeric bounds, caller ownership, refresh/epoch invalidation and error resolution. Do not credit already-fixed warm resource lookup twice. |
| N4/model compiler | Eight-stage lifecycle uses 22,216 B, 278 allocations and 30.300 us per two-transaction cycle without native apply. Whole-program compiler samples prominently include allocator/GC and map/byte-list work. | Compact transient representation and then retained state; measure bytes/scan/GC CPU per accepted operation at one million residents. A 100K lifecycle/s target implies 2.22 GB/s allocation at this fixture's present rate, not a universal N4 estimate. No language rewrite is justified by unlike workloads. |
| Lifecycle correctness | One-direction QER fixture exposed a real invalid erase. The ownership fix passes real deletion, rate transitions, compiler-refusal rollback and no-residual-resource checks. | Keep the behavioral regression in the live lane. Unknown completion retains possibly live IDs; no ignored erase, fake meter, premature ID reuse or widened memory budget. |
| Queueing, RCU and maintenance | Current small floor has no active reader. Session-major re-update can synchronize while control/resource/engine locks are held; prior allocator/GC percentages are historical, not current cost shares. | Requalify corrected-driver churn with packets/reports; isolate hot versus spread, queue/lock/grace-period wait and allocator maintenance. Preserve packet/control/report tails, no-fail publication and strict memory/refusal behavior. |

At 100K acknowledged transactions/s each dedicated serial core has 10 us of
CPU work available per transaction. Separate UPFD and BESS cores pipeline;
their CPU demands are separate bottlenecks, not one shared-core sum. A
replacement/lifecycle may require multiple PFCP messages and native applies:
state the denominator before converting any floor into a spec-sheet rate.

### A real N4 lifecycle blocker found by the stage sweep

The three-stage PFCP fixture uses one uplink meter and no downlink rate cap.
Clean merged UPFD accepted all 16 establishments, then refused all 16 deletions
with cause 73: native operation 3 erased a meter key that never existed.
`merge` allocated both directional meter IDs, `compileModel` wrote only the
non-zero-rate direction, and `removal` erased every allocated meter ID.

The fix allocates a direction's ID only at its first non-zero rate. An existing
ID remains owned when the rate later becomes zero; its native record must still
be removed, and an uncertain write must not release a possibly live ID. Existing
definite-refusal rollback, unknown-outcome retention and ID reuse delay remain.
This is an ownership fix, not an ignored native error or a padded fixture.

`TestLiveQERDirectionalMetersRemainDeletable` passes against real BESS for
uplink-only, downlink-only, unpoliced, rate-transition and compiler-refused
activation paths, on graph, appliance and session-major backends. It checks
successful deletion and absence of residual session-owned entries. The graph
and alternate-backend live selectors include it. Full N4 smokes then accept
all 16 establishments and all 16 deletions at each of 1/2/3/4/8 graph stages.
The compiler-only check also verifies one upsert per distinct stage.

This defect does **not** explain the historical 1K replacement timeouts: that
campaign's QER capped both directions. Preserve that separate investigation.
Likewise, the historical NT6 `mallinfo2` and Go GC fractions retain their old
revision/workload labels; the new small stage floor does not requalify them.

The refused activation is model validation before native apply, not an injected
native rejection or lost reply. Those outcomes are distinct coverage boundaries;
successful later changes and empty native resources alone do not prove allocator
rollback returned an ID to its pool.

### Qualification exclusions and remaining blocker

The first large campaign accidentally exported `GOMEMLIMIT=off` from a
laptop-only launcher. It completed 16 cells before an orderly interruption;
all partial results remain diagnostic, not normal-policy qualification.
No product policy or machine power setting was changed.

With `GOMEMLIMIT` unset, the first automatic cgroup-derived policy attempt exits
137 during fill; its last progress record is 81,047 sessions. UPFD's retained
cgroup peak is 371,113,984 bytes against an unchanged 5,300-MiB cap; its own
and aggregate cgroup OOM counters are zero. There is no core or kill-time OOM
journal entry. These facts do not establish an OOM cause, Go limit or compiler
regression. Native BESS exits cleanly. The later plain attempt reaches a million
sessions without this kill, so 81,047 is not a demonstrated population ceiling.
The unexplained failed attempt still remains a stability observation. Do not
bypass it by disabling heap admission or raising any budget.

A separately labeled, bounded strace diagnostic with the same automatic policy
passes 363,200 sessions before its requested 90-second stop; BESS and UPFD exit
zero. The observed Go limit is 5,001,707,520 bytes, last-GC live heap is
1,019,671,184 bytes, and all observed threads use SCHED_OTHER. No unexpected
kill occurs under tracing. This is neither a fix nor throughput evidence and
does not identify the plain run's signal sender. Privileged kernel signal
tracing is unavailable through noninteractive sudo.

### Current loaded churn: ingress loss, not a blanket 10K rating

The plain corroboration uses the corrected driver, fixed UPFD, session-major
backend, 1,000,000 residents and 16 active packet/acknowledged-report witnesses.
UPFD/control/packet/driver physical cores remain separate (4/6/8/10–11).
Normal pages, GOGC=25, GOMAXPROCS=1 and automatic Go heap limit remain in use;
hard no-swap scopes remain 3,000 MiB native, 5,300 MiB UPFD and 7,872 MiB
aggregate. Across 586 host observations AC/turbo-off hold, temperature is 45–65 C
and CPU 6 throttle count remains 21,098. Native/UPFD/driver peaks are
2,835,783,680 / 4,347,392,000 / 196,513,792 bytes, with no cgroup OOM events.

Twenty cells complete before a reconciliation timeout correctly aborts the
campaign. The table is completed logical cycles/s **including bounded drain**,
not offered rate or a loss-free capacity rating:

| Churn | Target 1K/s | Target 10K/s | Target 100K/s |
|---|---:|---:|---:|
| FAR | 999.3 | 3,722.9 | 4,077.5 |
| PDR | 999.3 | 3,527.5 | 3,643.1 |
| QER | 999.3 | 3,982.0 | 4,075.3 |
| Quota-only URR | 999.9 | 8,685.9 | 27,565.0 |
| Replacement, delete+establish | 990.8 | 1,133.3 | 365.2 |
| Establish | 999.3 | 2,116.7 | 928.2 |
| Delete | 999.9 | 835.3 | Not reached in this campaign |

Establish/delete are finite 65,536-session cohorts, not steady 30-second
10K/100K operation. The portable record retains actual durations, scheduled,
sent, skipped, accepted and timed-out partitions. At 1K FAR/PDR/QER and
establish accept all 30,000 submitted operations; URR/delete each miss one
producer pacing deadline but accept every submitted request.

**The replacement exception is reproduced and located at ingress.** At 1K,
29,744 of 30,000 logical replacements complete; 256 requests time out.
UPFD's UDP receive-drop delta is exactly 256; the driver's is zero.
59,565 native applies match 59,565 accepted PFCP wire requests, with zero
native BUSY/rejection/retry deltas. This is not the fixed missing-meter erase.
It directly identifies socket receive loss; it does not yet divide the
receiver stall into GC, compiler locks, native waits or shard queueing.

`Server.Serve` calls `handle` synchronously, and `onSession` blocks sending to
one of eight 64-entry shard queues (`internal/n4/server.go:338–362,634–648`).
One full shard can therefore stop reading UDP, including heartbeat/report
answers for otherwise unrelated work. This is a concrete head-of-line boundary,
not proof of its exclusive CPU share. Isolate receive/parse, shard wait,
compiler lock and native completion before changing it; preserve per-session
ordering and bounded memory. Increasing buffers or queue depth alone is not
a demonstrated processing optimization.

The ingress review found a semantic prerequisite, not a safe queue-only fix.
The session-handler contract promises that every session message read before
association end is answered before teardown. Nonblocking enqueue plus counted
or logged drops would narrow that promise and could merely move the measured
loss out of the socket counter. No such patch was retained.

Before sending overload refusals, N4 needs bounded association-scoped
transaction ownership/replay: distinguish new requests from queued, executing
and completed duplicates before admission. In-flight duplicates must retain
their owned outcome; completed duplicates need the original response, including
usage reports, through an agreed retransmission horizon. Registry exhaustion
also needs explicit bounded admission rules; early eviction is not a solution.
Correct refusal addressing differs: establishment gets CP-SEID from CP F-SEID
and needs Node ID, whereas modification/deletion headers carry the UP's SEID.
Their CP-SEID lives in compiler-owned session state; successful deletion removes
it, so replay needs a retained response/tombstone. Redispatching a duplicate
deletion returns context-not-found, not its original termination usage reports;
modification can also reopen usage/reporting paths.

This is local design work, not an external blocker. Preserve FIFO, response-byte
ownership and the existing shutdown drain fix. First qualify the persistent
gRPC path through UPFD at the original all-offered 1K load; retain timeouts,
uncertain sessions, reconciliation failures and both RX/admission losses.
Faster native transactions may relieve that load but do not remove the ingress
contract prerequisite or establish 10K/100K capacity.

**Outcome (UPF `perf/n4-receive-buffer`, 7f11e0a).** A flight-recorder trace
of 1K replacement over 1M residents (`evidence/upfd-mem-20261113/
1m-lane5000-trace`) located the receiver stall: the read loop blocked on a
full shard queue 433 times for 1.8 s in a 20 s window, the longest 49.9 ms.
The workers it waited behind were waiting on bessd (commit p99 9.9 ms, max
52.9 ms; deletion's rule-count read p99 15.0 ms, max 49.9 ms) and on GC mark
assists (1.18 s). No single stall was long; the 208 KiB default socket buffer
could not hold the requests arriving during them. `-n4-receive-buffer`
(default 4 MiB) keeps FIFO, response ownership and the answer-everything
contract, and needs no refusal path. Same lane, 1M, replace 1K for 10 s:
239/307 timeouts (= UPFD receive drops), p99 350/371 ms before; 0/0, p99
115/230 ms after. The stalls remain; the overload-refusal design above is
still the prerequisite for loss-free operation above capacity.

**Complete 21-cell 1M campaign** (`evidence/upfd-mem-20261113/
1m-matrix-rcvbuf4m-u2900`; UPF session-memory series + N4 receive buffer;
lane 5,000 MiB with bessd 2,600 / UPFD 2,900 MiB scopes, 16,384 packet
buffers, UDS, GOGC=25, GOMAXPROCS=1; uninstrumented). It runs to the end with
every reconciliation passing and no cgroup OOM event; per-process peaks
bessd/UPFD/driver 2,285/2,658/172 MiB. Completed cycles/s including drain
(timeouts in brackets):

| Churn | Target 1K/s | Target 10K/s | Target 100K/s |
|---|---:|---:|---:|
| FAR | 997 (0) | 3,323 (50,123) | 3,499 (947,447) |
| PDR | 997 (0) | 3,274 (50,643) | 3,256 (950,832) |
| QER | 997 (0) | 3,584 (46,023) | 3,732 (943,976) |
| Quota-only URR | 997 (0) | 9,879 (0) | 15,477 (767,276) |
| Replacement | 997 (0) | 1,155 (82,579) | 522 (991,637) |
| Establish (65,536 cohort) | 997 (0) | 2,808 (32,941) | 2,025 (39,739) |
| Delete (65,536 cohort) | 997 (0) | 3,438 (25,567) | 2,256 (52,667) |

Every 1K cell accepts all 10,000 operations (p99 31-43 ms; replacement 381
ms), and URR at 10K now accepts all 100,000. Above 1K the native-transaction
modes are over capacity (~3.3-3.7K/s single-transaction changes, ~1.2K/s
replacement), and the excess times out at the socket: loss-free operation
there still needs the overload-refusal design. Not ABBA against the earlier
campaign, whose lane and scopes differ.

With a 2,700 MiB UPFD scope the same campaign stopped at replacement-1K: after
the 100K cells admission's live-heap reading stood at 1,708 MiB against its
1,701 MiB threshold, and refused establishments allocate too little to start
the collection that would refresh it, so all 10,000 were refused (cause 75)
while deletions proceeded (`1m-matrix-rcvbuf4m`). The guard refuses on a
stale reading until something else allocates.

**Loaded UPFD at 1M: unary vs persistent transaction streams.** Same lane and
binaries except `sdk.Dial` → `sdk.DialTransactionStreams(target, 32)` in UPF's
`internal/bess` via a measurement overlay (`binaries.sha256`). Eight runs in
adjacent pairs (B A, A B, A B, B A), each run gated on no_turbo=1, AC online and
package temperature (54–66 °C, all logged in `gates.txt`); every run exits 0.
Means of the four runs per arm; the pair range is each stream run against its
neighbouring unary run (`evidence/upfd-mem-20261113/abba2/`):

| Cell | Unary | Stream | Change | Pair range | Stream better |
|---|---:|---:|---:|---:|---:|
| FAR 10K, completed/s | 2,885 | 3,051 | +5.7% | +1 … +10% | 4/4 |
| Replacement 10K, completed/s | 822 | 1,008 | +22.7% | +9 … +31% | 4/4 |
| FAR 1K p99 | 42.5 ms | 36.0 ms | −15% | −10 … −29% | 4/4 |
| Replacement 1K p99 | 923 ms | 588 ms | −36% | −24 … −57% | 4/4 |
| Replacement 1K p50 | 34.8 ms | 14.4 ms | −59% | −12 … −84% | 4/4 |

Both arms complete every 1K operation (one stream run sent 9,999 of 10,000:
a client pacer skip, UPFD counted 9,999 modifications). The 10K cells are over
capacity in both arms (48–89% timeouts). Runs 1–4 are much slower than runs 5–8
in both arms (FAR 10K 2.3–2.8K versus 3.2–3.4K completed/s; replacement 1K p99
0.86–1.3 s versus 0.28–0.73 s); adjacent pairing cancels the drift, but its
cause is not assigned (package temperature fell 66 → 57 °C; light read-only git
commands ran during runs 4–5). Absolute 1K replacement tails are therefore not
rated from this campaign.

An earlier ungated four-run ABBA (`abba-{A1-unary,B1-stream,B2-stream,A2-unary}`,
turbo state uncertain) reported +22% for FAR 10K; the gated campaign does not
reproduce that, and replaces it. Streams raise capacity but do not reach 10K:
loss-free operation above capacity still needs the overload-refusal design.
Adopting streams in UPF needs the SDK from BESS PR #151, which is not merged.

Quota-only URR changes issue **zero native transactions**, yet target 10K has
147 timeouts and target 100K completes 965,751 of 3,000,000 scheduled cycles.
Thus transport removal alone cannot establish a 100K N4 rating. Current
large-state allocation/GC and dispatch costs must be assigned, rather than
relabeling historical GC percentages or assuming a language limit.
UPFD consumes 30.683 CPU-seconds in that 35.035-second URR window: 31.77 us per
completed cycle, inclusive of unsuccessful work, reports and background/GC work.
This is not an exclusive parser, compiler or GC cost.

After delete-at-10K, population reconciliation returns HTTP 500 timeout:
the driver has 64 uncertain sessions and 1,055,871 held instead of the intended
1,000,000. Native and UPFD still exit zero. The campaign does **not** continue
to delete-at-100K on an unreconciled population, and is not a completed
21-cell qualification.

The missing delete-at-100K cell is measured **separately on fresh daemons**,
with the same frozen binaries, automatic heap policy, caps and one million
residents. A finite 65,536-delete cohort offers for 0.656 s: 5,328 succeed,
60,208 time out, exactly 60,208 UPFD UDP receives drop, and the driver drops
none. Native records 5,328 applies and no BUSY/rejected transactions.
Drain-inclusive completion is 932.8 cycles/s over 5.712 s; this is not sustained
100K service or an all-offered latency measurement. All 48 observed usage
reports receive acknowledgements. Bounded post-cell reconciliation succeeds
and returns to 1,000,000 held, zero uncertain and zero pending sessions.
All 141 power observations are valid, temperature is 43–62 C, throttle count
stays 21,098 and cgroup OOM counters stay zero. This completes measurement
coverage, **not** the aborted 21-cell campaign or its loss-free qualification.

The final C++ CLI (including optional counter-window support) passes actual
one-transaction smoke runs for all five stage counts. The full selected
packet/report/meter live-test pattern passes 12 top-level tests in each of
appliance and session-major modes, including all four directional-meter cases.
Earlier graph-mode live tests and focused race/full ordinary tests remain
separate evidence; these functional runs are not performance measurements.

### Persistent-client idle regression checks

The initial 40-arm external-CLI diagnostic had 263–328 ms of endpoint timing
uncertainty per ten-second window. Its midpoints do not establish small
regressions or parity. The existing C++ live benchmark now optionally brackets
its **existing persistent Metrics calls** with `--counter-window`, adding no
RPC or per-packet clock, and records raw packet deltas, both elapsed bounds,
the old denominator and idle process/worker CPU deltas.

The precision-corrected experiment uses one identical new C++ client and
libraries for both frozen native revisions, fresh daemons, four adjacent ABBA
pairs per retained shape, and ten-second idle windows. Forty native comparison
arms plus eight plain/off-on observer-reference arms all exit cleanly. Total
RPC endpoint bounds are about 1.1–2.2 ms, not hundreds of milliseconds.
The observer's median paired legacy-rate shift is -0.258%, range
-1.075% to +0.172%; no scalar correction is applied.

| Retained idle shape | Original 1-s paired delta | Persistent 10-s paired delta | Negative pairs | Existing 3% gate |
|---|---:|---:|---:|---|
| TCP/P, 1 client, later 2 ops | -3.175% | -4.112% | 4/4 | Fails |
| TCP/E, 8 clients, later 2 ops | -1.328% | -3.664% | 3/4 | Fails |
| Unix/P, 1 client, later 2 ops | -1.427% | -1.652% | 4/4 | Below threshold, sign retained |
| Unix/P, 1 client, later 8 ops | -1.619% | -0.839% | 3/4 | Below threshold |
| Unix/P, 8 clients, later 2 ops | -2.231% | -1.443% | 3/4 | Below threshold |

The two TCP regressions remain open, not waived by the control-rate gains.
Packet workers use almost a full core in both arms and sampled CPU 8 frequency
is generally near the same 2.6-GHz ceiling; these observations do not attribute
instruction, cache/TLB, allocation-layout or frequency-residency effects.
Source inspection of the treatment finds control-poller retention changes, not
a packet algorithm change. Next isolate worker cycles/instructions/cache
behavior and poller 1/2/16 diagnostic ablations on the same payload/setup,
with separate plain corroboration. Do not conclude idle spinning, scheduler
steal, timing bias or a causal packet-path fix without that evidence.

### Same-binary poller diagnostic: controls do not qualify attribution

A temporary startup-only interposer changes MAX_POLLERS to 1/2/16 in the
identical frozen daemon; MIN_POLLERS remains 1. Actual daemon dynamic-binding
logs prove calls pass through the interposer to libgrpc++, with the requested
effective values. No BESS production default or host power policy changes.
The same client/library and fresh-daemon method measures 56 ten-second arms:
four adjacent ABBA pairs per comparison, including counter off/on, plain versus
pass-through shim, and pass-through versus explicit 16 (the same policy).

| Comparison, B/A | Shape | Median paired shift | Negative pairs |
|---|---|---:|---:|
| Counter on / off, same legacy denominator | TCP/P c1 | +3.958% | 0/4 |
| Pass-through shim / plain | TCP/P c1 | +0.644% | 2/4 |
| Forced 16 / pass-through 16 | TCP/P c1 | -9.073% | 2/4 |
| Max 16 / max 1 | TCP/P c1 | -2.647% | 3/4 |
| Max 16 / max 2 | TCP/P c1 | -0.753% | 3/4 |
| Max 16 / max 1 | TCP/E c8 | -0.819% | 3/4 |
| Max 16 / max 2 | TCP/E c8 | +1.061% | 1/4 |

All 719 power observations are valid, package temperature is 47–67 C and CPU 6
throttle count stays 21,098. However, **the controls fail to establish a clean
causal effect**: counter off/on shifts in all four pairs, and identical-policy
arms include two approximately 20% losses followed by two near-flat/positive
pairs. Preserve these adverse data; do not apply a scalar observer correction,
waive the earlier native regression gates, or claim poller count is/no longer
is the cause. Worker task time stays near a full core, while sampled frequency
varies; effective PMU cycles/ref-cycles and IPC isolation remain unperformed.
The user prioritizes gRPC overhead decomposition before further idle experiments.

### Locality-aware cross-language API shortlist

This is source review, **not measured performance of replacement libraries**.
Keep schema/encoding, RPC semantics and transport selection separate:
protobuf does not require gRPC/HTTP/2, and zero-copy decoding does not imply
a cross-process shared-memory transport.

| Candidate | Locality-aware transport | Schema and Go/C++ fit | Qualification / limitation |
|---|---|---|---|
| Zenoh | Negotiated SHM domain, transparent normal-payload conversion beyond it | Existing protobuf bytes; query/reply plus pub/sub; Go binding uses CGo/Zenoh-C | Explicit SHM API list omits Go. Prove actual Go-to-C++ SHM and fallback. Implicit optimization is thresholded/opportunistic. |
| UCX/UCP + protobuf | Selects local SHM and network transports, including TCP | Existing protobuf schemas; C/C++ and official CGo active-message bindings | Transport library, not generated RPC. Dispatch, deadlines, admission and commit receipts remain application work. |
| Fast DDS | Same-host detection and default SHM alongside network transports | DDS IDL/generated types, not protobuf wire compatibility | Go integration and RPC/API packaging require qualification; not a drop-in control API. |
| eCAL | Automatic SHM/local and network/remote for pub/sub | Protobuf support | Documented service RPC uses TCP. Pub/sub SHM is not evidence of SHM commit RPC. |
| Cap'n Proto RPC | Standard socket-based RPC; automatic SHM remains upstream work | Typed Go/C++, asynchronous RPC and promise pipelining | Go bindings identify themselves as beta. Useful non-HTTP/2 comparison without SHM, not a turnkey adaptive SHM transport. |
| FlatBuffers + gRPC | Retains gRPC transport and HTTP/2 | Typed Go/C++, direct serialized-buffer access | Codec experiment, not an automatic local SHM/network RPC solution. |
| Flow-IPC + Cap'n Proto | Implemented local SHM-backed Cap'n Proto RPC, sessions and cleanup | C++ | Current documentation puts Go and networked sessions in future work. Useful implementation precedent, not a Go/C++ drop-in. |

Sources checked:
[Zenoh SHM](https://raw.githubusercontent.com/eclipse-zenoh/roadmap/main/rfcs/ALL/SHM.md),
[Zenoh Go](https://github.com/eclipse-zenoh/zenoh-go),
[UCX transport selection](https://openucx.readthedocs.io/en/master/faq.html),
[UCX Go active messages](https://github.com/openucx/ucx/blob/master/bindings/go/src/ucx/endpoint.go),
[Fast DDS SHM](https://fast-dds.docs.eprosima.com/en/3.x/fastdds/transport/shared_memory/shared_memory.html),
[eCAL transport layers](https://eclipse-ecal.github.io/ecal/stable/advanced/transport_layers.html),
[eCAL services](https://eclipse-ecal.github.io/ecal/stable/getting_started/services.html),
[Cap'n Proto SHM status](https://github.com/capnproto/capnproto/issues/2174),
[Go Cap'n Proto status](https://github.com/capnproto/go-capnp),
[FlatBuffers/gRPC](https://grpc.io/blog/grpc-flatbuffers/),
[Flow-IPC scope](https://flow-ipc.github.io/doc/flow-ipc/versions/main/generated/html_public/about.html).

The generic request is 177 bytes at one stage and 1,094 bytes at eight.
UDS phases below are separately timed block medians, **not additive stages**:

| Encoded-value Go path, us | One stage | Eight stages |
|---|---:|---:|
| Build only | 0.935 | 3.268 |
| Complete build + RPC | 80.678 | 103.725 |

The fixed RPC/dispatch/wakeup path is a candidate, not an assigned exclusive
cost. A large-message SHM optimization need not improve this small-message
workload. No cross-library latency winner follows from serialization benchmarks.

Before changing protocols, exercise asynchronous/pipelined gRPC dispatch:
[gRPC's own guidance](https://grpc.io/docs/guides/performance/) explicitly
discourages the synchronous C++ server API for performance-sensitive servers.
The frozen baseline uses it; the callback candidate below is not yet latency
qualified. Then compare Cap'n Proto and FlatBuffers in their intended efficient
Go/C++ modes, on the same native transactions, before considering SHM.
Keep one BESS control implementation and preserve epochs, exact replay,
individual APPLIED/REJECTED/UNKNOWN outcomes, snapshots, events, admin calls
and bounded memory. Transport send completion is not commit acknowledgement.
Actual local SHM use, forced network mode, incompatible/isolated SHM domains,
client/server restart, cancellation, backpressure and Go buffer lifetimes must
be proved before a cutover. This shortlist is not a product dependency change
or a waiver of the existing packet/N4 gates.
Automatic discovery/fallback is not required: an explicitly configured SHM
transport is acceptable when both endpoints can access the same SHM domain.
Cap'n Proto is not excluded for lacking automatic selection; its Go/C++ SHM
integration remains the qualification gap. An explicitly required SHM mode
must fail clearly if unavailable, rather than silently benchmark a socket path.

### gRPC decomposition and first cuts — 2026-11-09/10

The [gRPC qualification record](performance-grpc-cuts.json) keeps the paired
SDK results, recovered diagnostic windows, hashes and current candidate gates.
Raw evidence stays under `layered-20261108/grpc-*` in the local evidence root
named above. These are generic idle transaction floors, not PFCP capacity.

The warm eight-stage profiles used 65,536 transactions, client CPU 4 and native
control CPU 6. Plain-before / sampled / plain-after build+RPC means were
118.587 / 143.247 / 116.462 us for encoded Go and
163.056 / 188.099 / 164.270 us for message C++. The observer adds approximately
15–23% latency here: use profiles to locate work, never as acceptance timings.
C++ protobuf packing accounts for 18.78% inclusive client cycles; request-ID
`random_device` initialization accounts for 2.50% leaf cycles. Native public
ApplyTransaction accounts for 11–12% inclusive server cycles. The remainder
is **not** an exclusive RPC bucket; inclusive stacks overlap.

The two sampled arms retain their original failed wrapper verdicts. The guard
misclassified the intentionally requested sampler SIGINT (`returncode=-2`).
Client outputs contain all accepted transactions, perf output finalized, and
the retained warm-window reports parsed successfully. The derived record
annotates this recovery instead of rewriting the adverse raw verdict.

First SDK cuts: keep the C++ request-ID entropy source thread-local and add
`Transaction::UpsertEncoded` plus C++ `--stage-mode message|encoded`. Prepared
bytes are copied by the C++ SDK, not borrowed. Native schema validation,
atomic rejection, epochs, retries and individual receipts remain in force.
Three fresh-daemon ABBA pairs per comparison, with reversed stage sweeps,
accepted all 600,000 measured transactions without profiling:

| Modified stages | Request-ID cut: paired median wall reduction | Prepared bytes: paired median wall reduction |
|---|---:|---:|
| 1 | -0.78% | 0.77% |
| 2 | -0.65% | 5.74% |
| 3 | 3.09% | 5.94% |
| 4 | 2.04% | 8.64% |
| 8 | 1.01% | 10.22% |

At eight stages, the request-ID comparison's median paired-arm means are
169.779 → 166.632 us; client CPU is 102.151 → 99.709 us/transaction.
The separate packing comparison is 164.897 → 148.694 us, with client CPU
100.150 → 82.693 us/transaction. Each eight-stage wall reduction has the same
sign in all three pairs. Small-prefix wall gains are not established: the
request-ID comparison is adverse in two of three one/two-stage pairs.
Do not chain these separate comparisons or compare absolute times across boots.

The callback-server and reusable C++ completion-queue experiments built and
passed functional checks before timing:

- Experimental Native ApplyTransaction used callback dispatch. The ordinary call
  used the default reactor; reclamation BUSY retries used timers. The direct
  in-process handler shared the same attempt implementation. Epoch trailers,
  bounded BUSY retry policy, replay and events were retained.
- Experimental C++ SDK unaries reused one completion queue per caller thread,
  across methods and channels, preserving the blocking SDK contract, deadlines
  and typed error trailers. WatchEvents was unchanged; no private UPFD-only API
  was introduced.
- UDS and TCP smoke runs complete all five stage prefixes for Go and C++,
  comparing the frozen sync server, callback server and C++ queue-reuse path.
  The native transaction/retry suite passes 16 tests; four API boundary tests
  and the server shutdown test also pass.
- A separate actual-daemon C++ proof accepts 67 transactions per transport,
  including two concurrent callers. It verifies malformed-second-op atomic
  rejection, owned input lifetime, an empty/default encoded value, typed epoch
  trailers and an expired unary deadline. Both daemons shut down cleanly.

After passwordless sudo became available, turbo-off was restored and cooldown
completed. The within-boot plain campaign finished all 36 fresh-daemon arms:
three ABBA pairs per comparison, all five prefixes, one outstanding transaction,
client CPU 4 and native control CPU 6. All 1.2 million measured transaction
receipts passed; all daemons exited cleanly; power guards reported no failures.
Functional turbo-enabled smoke timings remain excluded.

| Modified stages | Callback server, encoded Go: wall reduction | Callback server, encoded C++: wall reduction | Reused C++ CQ on callback server: wall reduction |
|---|---:|---:|---:|
| 1 | -2.59% | 9.36% | -0.35% |
| 2 | 1.81% | 4.06% | -0.81% |
| 3 | 0.36% | 5.19% | 0.12% |
| 4 | -1.74% | 4.22% | 0.44% |
| 8 | -4.28% | 2.05% | 0.85% |

These are medians of three paired ABBA reductions, not ratios of independently
pooled medians. Positive means faster. Go callback latency is adverse in all
three one-stage pairs; neither callback dispatch nor queue reuse closes the
Go/UPFD gap. Queue reuse has no consistent material win in the measured case.
The original synchronous server and C++ unary transport are therefore restored,
not made configurable production alternatives. Frozen candidate source/binaries
and adverse raw results remain available. Restored defaults pass real Go/C++
UDS/TCP smoke at all five prefixes. The measured request-ID/prepared-byte SDK
cuts remain.

Bounded unary qualification then completed 24 fresh-daemon arms: TCP/UDS,
caller windows 1/2/4/8, all five prefixes, three reversed-order repetitions.
All 1.2 million warm transactions received checked individual receipts.
The Go scheduler uses disjoint strided key lanes and preserves each key's
alternating replacements; its boundary/order/cancellation tests pass under
the race detector. Encoded and message paths also pass actual-program smoke.

| Modified stages | UDS, window 1, K transactions/s | UDS, window 8 | TCP, window 1 | TCP, window 8 |
|---|---:|---:|---:|---:|
| 1 | 12.112 | 20.454 | 11.740 | 20.672 |
| 2 | 11.473 | 18.848 | 11.129 | 19.207 |
| 3 | 11.101 | 17.823 | 10.728 | 17.738 |
| 4 | 10.888 | 16.194 | 10.354 | 16.234 |
| 8 | 9.769 | 14.045 | 9.011 | 13.852 |

These are medians of three complete build+Commit blocks. At parallel windows,
wall time divided by accepted transactions is inverse throughput, not request
latency. Client CPU, all window sizes and raw blocks remain in the portable
record. The 118 host observations retain AC/turbo guards, 42–49 C package
temperature and zero core-throttle counts. No sampling ran in these arms.
Four rebuilt native service/UDS cases also pass a one-iteration functional
smoke; those smoke times are not performance results.

Saturated eight-stage/window-eight profiling uses 65,536 transactions per block,
with explicit warm `CLOCK_MONOTONIC` bounds:

| Arm | Wall/accepted operation, us (inverse throughput) | Go process CPU/accepted operation, us |
|---|---:|---:|
| Plain before | 72.864 | 30.250 |
| Sampled | 87.133 | 32.381 |
| Plain after | 72.775 | 31.211 |

The observer adds 19.66% wall/op relative to the mean plain controls. Treat
the 99 Hz profiles as diagnostic: only 216 Go and 565 native warm samples,
zero lost samples. Inclusive Go ancestry includes gRPC Invoke (46.46%) and
background GC marking (19.03%); native ancestry includes EventEngine work
stealing (36.56%), ExecCtx flush (34.33%) and public ApplyTransaction (18.50%).
These overlap; never sum them or call the complement exclusive RPC cost.
Several native libc frames remain unresolved. Named native leaf samples include
malloc, adapter/engine work, Abseil locking, hashing and typed key decoding.
This profiler campaign has boundary AC/turbo checks, not the continuous host
trace used by the plain throughput campaign.

Persistent public gRPC transaction leases are now implemented, opt-in in both
SDKs; ordinary Dial remains unary. Each lease has one outstanding attempt;
parallel callers use separate persistent streams, not multiple requests queued
on one stream. The protobuf transaction body and native admission, epoch, replay,
rollback and event paths are unchanged. Correlated per-attempt replies preserve
full transaction records or typed status/details. The ordinary complete
management/action/snapshot/reporting API remains available.

The matched plain comparison completed **72 fresh-daemon arms and 3,000,000
checked warm transaction receipts** across TCP/UDS, Go windows 1/8 and C++
window 1. Each cell has three unary/stream/stream/unary pairs, reversed prefix
sweeps and identical binaries/payloads within its campaign. All eight tables and
8,192 entries remain resident. Separate physical P-cores: client 4, native 6;
affinity, not exclusive cpusets. AC connected, turbo off, throttle counters zero;
continuous read-only host trace. No profiler or per-call clocks.

Median paired wall/op reduction; every cell improved in all three pairs:

| Stages | Go W1 UDS | Go W1 TCP | Go W8 UDS | Go W8 TCP | C++ W1 UDS | C++ W1 TCP |
|---|---:|---:|---:|---:|---:|---:|
| 1 | 35.99% | 31.80% | 43.85% | 41.10% | 24.92% | 30.99% |
| 2 | 33.98% | 30.23% | 43.99% | 39.33% | 22.01% | 27.82% |
| 3 | 33.39% | 31.10% | 40.58% | 38.39% | 21.65% | 32.40% |
| 4 | 31.95% | 29.87% | 39.75% | 39.18% | 22.88% | 29.24% |
| 8 | 25.80% | 25.01% | 30.64% | 28.13% | 30.59% | 27.49% |

At Go W8 UDS, stream wall/op is 28.385 us at one stage and 51.109 us at eight
(about 35.2K/19.6K accepted transactions/s). These are inverse-throughput
figures, not acknowledgement latencies or PFCP session rates. Corresponding
client CPU/op is 11.666/19.497 us versus unary 20.994/30.137 us. Do not chain
these pairs with earlier campaigns or infer that TCP/UDS differences are causal.

Native-backed Go tests over both transports prove that a lost real APPLIED
acknowledgement resolves through the native replay record and table, and closing
the stream client preserves its borrowed connection. C++ native-state proof
checks 67 individual applied receipts per transport, explicit same-ID replay,
atomic rejection of malformed second operations, encoded input ownership,
empty defaults, two concurrent callers, typed epoch refusal and expired
attempts. A separate ASAN/UBSAN-instrumented C++ driver exercises an unresponsive
network peer, active/waiting/expired deadlines and completion-queue drain.
The Go cancellation regression initially failed: lease cancellation changed an
active caller's DeadlineExceeded into Canceled. The SDK now preserves the caller
context cause; the SDK/bench race suites and actual native tests pass.

Budgets start when the native service reads the frame; client cancellation
retires only its leased stream. Neither implies rollback. EOF, missing/mismatched
acknowledgement or transport loss remains UNKNOWN, with unchanged GetTransaction
resolution and exact request-ID/payload retry rules. Pool size and existing
message limits bound outstanding wire payloads; this is not a decoded-memory
reservation. Raw evidence: `grpc-persistent-{uds,tcp}-abba-20261110`,
`grpc-stream-live-recovery-20261110`, `grpc-stream-cpp-native-20261110-r2`,
and `grpc-stream-cpp-deadline-20261110`. The retained initial C++ proof failure
was a harness mistake: reusing a completed Transaction returns its cached
result; wire replay requires a second transaction with the original request ID.
TCP uses the Go binary with the error-only deadline-cause fix; UDS retains its
original frozen binary. No shared memory or alternate codec was introduced.

The opt-in acknowledgement observer then completed all five prefixes over
TCP/UDS at windows 1/8: 12 fresh-daemon plain/observed/plain arms, each with
5,000 transactions per block. All receipts and observer sample counts pass.
Representative combined-phase **SDK Commit** latency, not inverse throughput:

| Transport | Window | Stages | p50, us | p99, us |
|---|---:|---:|---:|---:|
| UDS | 1 | 1 | 74.704 | 242.745 |
| UDS | 1 | 8 | 90.647 | 284.968 |
| UDS | 8 | 1 | 351.098 | 899.534 |
| UDS | 8 | 8 | 533.649 | 1119.079 |
| TCP | 1 | 1 | 77.177 | 256.476 |
| TCP | 1 | 8 | 99.595 | 342.742 |
| TCP | 8 | 1 | 349.961 | 1354.381 |
| TCP | 8 | 8 | 540.117 | 1055.353 |

Per-call clocks are absent in the surrounding plain arms. Observed wall/op
deviations span -11.22% to +3.59% across the 20 cells: one bracket per cell
does not isolate clock cost from run/phase variability, and negative values
are not a clock-induced speedup. Keep these p99s diagnostic. They include
SDK retries and individual receipt validation, exclude combined-phase build,
and do not measure an offered-arrival N4 queue. The larger window improves
throughput while increasing individual request latency.

#### Follow-up cuts and acceptance gates — 2026-11-11

Bounded-load stream profiles also have plain-before/plain-after controls.
C++ W1 observer wall/op increases 19.98%; Go W8 increases 21.87%. Warm samples
are small (C++ client/native 397/427, Go 159/392; lost zero), with unresolved
libc/native frames. Diagnostic C++ ancestry includes EventEngine work stealing
31.95%, CQ wait 9.06%, operation destruction 8.49%; mutex lock is 12.47% leaf.
Go background marking is 21.50% inclusive. These overlap and are not exclusive
costs or proof that W8 saturates either CPU. Raw:
`grpc-persistent-profile-20261110`.

The measured native key decoder now writes directly into the owned dense key
(maximum 64 bytes), removing intermediate field vectors, protobuf field copies
and packed-buffer copying. No thread-local cache or retained scratch. Native
module/control tests pass, including input ownership, integer truncation/byte
order, unset fields and atomic rejection of short/long binary fields.
Three old/new/new/old plain pairs cover every 1/2/3/4/8 prefix:

| Eight-stage boundary | Before, us | After, us | Median paired reduction |
|---|---:|---:|---:|
| Typed owned control (unchanged path) | 2.043 | 2.037 | 0.29% |
| Framework adapter | 11.603 | 10.862 | 6.39% |
| Public transaction service | 12.982 | 12.032 | 7.32% |
| Protobuf encode/decode | 16.428 | 15.806 | 3.88% |

All paired signs improve, but small-prefix typed controls also move 1.86–3.47%;
do not attribute all cross-binary change to decoding. Eight-stage service and
protobuf floors still exceed the 10 us/core budget for 100K transactions/s,
before N4 or separate-process RPC. Raw: `native-direct-keypack-abba-20261111`.

Further C++ SDK candidates are **not accepted**. Transient operation borrowing
plus receipt moves improves eight-stage TCP streams 7.03%, but worsens UDS
5.71% (3/3 adverse pairs). Direct-owned requests plus overlapped CQ and receipt
moves again improve TCP 5.93%, but worsen UDS 8.42% (3/3 adverse).
An isolated receipt-copy/move comparison (24 arms, 480K checked receipts)
does not explain it: copy effect is +0.93% UDS, +0.024% TCP, mixed signs.
Restore the original transaction representation and serial write/read strategy,
not a protocol- or stage-specific workaround. Keep bounded CQ draining and
borrowed-envelope lifetimes correct. Candidate client/library ABIs were matched;
do not load a layout-changing candidate library into an older C++ client.
Raw: `grpc-cpp-{owned,direct-overlap}-abba-20261111`,
`grpc-cpp-receipt-isolate-20261111`. Do not chain independent percentages.

The actual native daemon also passes 64 idle transaction streams over TCP/UDS:
ordinary capability RPCs still progress, Admin.Shutdown closes all 64 while
the caller context remains live, and native exit is zero. This is lifecycle/
administrative progress proof, not a loaded transaction rate. Raw:
`grpc-idle-stream-admin-shutdown-20261111`.

The plain stream caller ladder then completes all five prefixes at windows
1/2/4/8/16/32/64, three repeats over TCP/UDS: 42 fresh daemons and 2,100,000
checked warm receipts, reversed transport/window/prefix orders, valid AC/turbo
guards. Representative combined-phase median accepted transactions/s:

| Callers/leases | UDS, 1 stage | UDS, 8 stages | TCP, 1 stage | TCP, 8 stages |
|---|---:|---:|---:|---:|
| 1 | 18,550 | 13,368 | 17,066 | 12,608 |
| 2 | 24,898 | 15,761 | 22,683 | 15,530 |
| 4 | 30,579 | 19,208 | 30,428 | 18,187 |
| 8 | 36,312 | 21,142 | 35,104 | 19,861 |
| 16 | 38,955 | 21,536 | 37,811 | 20,440 |
| 32 | 41,054 | 21,474 | 39,604 | 20,675 |
| 64 | 40,172 | 21,656 | 41,585 | 21,263 |

Eight-stage UDS has little useful throughput gain beyond eight callers; the
single-stage boundary benefits more. A larger window is not a latency win;
measure its acknowledgement/queue cost separately. These are distinct native
table transactions, not N4 session transactions. Raw:
`grpc-stream-window-sweep-20261111`.

Go gRPC buffer tuning is now measured: 144 fresh-daemon ABBA arms, 7,200,000
checked warm receipts, three repeats for TCP/UDS x W1/W8 x write0/read0/both0.
No profiler or per-call clocks. Default buffering is retained. Eight-stage
median paired wall/op reduction (negative means slower):

| Transport/window | Write buffer off | Read buffer off | Both off |
|---|---:|---:|---:|
| UDS W1 | -4.32% | -2.83% | -9.56% |
| UDS W8 | -5.83% | +2.05% | -5.78% |
| TCP W1 | -20.91% | -4.99% | -26.52% |
| TCP W8 | -9.73% | -0.97% | -10.26% |

The isolated UDS W8/read0 eight-stage gain does not justify a default: its other
prefixes regress. Across all 60 cells, 59 median effects are adverse; both-off
reaches 36.95% slowdown. No application/SDK special case or new buffer setting
was added. Raw: `grpc-go-buffers-abba-20261111`.

The bounded native request-arena candidate completed 96 ABBA arms and
4,200,000 checked warm receipts, with the same memory caps and passing
epoch/replay/error/lifetime/large-seed/64-idle-shutdown proof. It is **not
accepted**: eight-stage Go W8 improves 7.82% UDS/9.08% TCP, but unchanged
TCP unary controls regress 3.26–7.05%, and several C++ TCP cells regress.
Those controls do not qualify a portable causal gain. Restore ordinary heap
frames; retain the candidate and adverse results rather than applying an
observer correction or a stage-specific workaround. Raw:
`grpc-native-frame-arena-abba-20261111`.

Independent code review then found and fixed three correctness defects:

- Initial Go stream creation used only the client-wide context until after
  NewStream returned. A context-blocked real dialer reproduced cancellation
  hanging for the five-second watchdog. Register attempt cancellation before
  creation and preserve its cause; the race regression now passes.
- A matching frame ID did not validate its nested record. Faults on actual
  native APPLIED replies reproduced an ordinary missing-record error and
  cached success for a foreign request ID. Both SDKs now classify those as
  UNKNOWN, retire the lease and resolve the original request ID.
- A locally oversized ACK was misclassified as native refusal. A real native
  60-byte ACK with a 16-byte stream receive limit reproduced InvalidRequestError
  after APPLIED. Untyped RESOURCE_EXHAUSTED now remains ambiguous in both
  shared SDK classifiers; a valid typed transient-status refusal stays known.

Full Go SDK/bench race tests and C++ SDK/protocol-model tests pass. Native
TCP/UDS fault tests resolve dropped, missing-record, foreign-record and oversized
ACKs through the real record and table; borrowed-channel Close remains correct.
C++ actual-network malformed-record tests also pass. Raw before/after:
`grpc-stream-{record-guard-before,recv-limit-before,review-fixed}-20261111`.
The specialist review requests stalled; independent working agents performed
the scoped audits. No review/merge or CodeQL approval is implied by these tests.

Pipelining alone does not remove the per-frame cost. A throwaway probe with K
frames in flight on one real UDS stream stops at 26.6 us (1 stage) and 48.6 us
(8 stages) per transaction at K=16, from 54.1/75.6 us at K=1 (median of 3; TCP
30.9/48.7 us). The native service is 3.6/13.0 us, so about 23-35 us per frame
is gRPC per-message cost. BESS PR #151 commit 5 therefore lets one frame carry
1..64 **independent** transactions, each applied atomically on its own with
its own result in order; a refusal does not stop later transactions, and a
refused frame applies nothing. No independent session transactions merge into
one atomic transaction. The Go client sends whatever commits are already
queued behind a busy stream, without a timer; a lone caller sends at once.

Matched ABBA plain runs, parent versus commit 5 (each arm its own bessd and
bessbench, 4,096 commits per stage count, client CPU 4 GOMAXPROCS=1, native
CPU 6, AC, turbo off, valid power), median commit wall per transaction:

| Callers/streams | UDS 1 stage | UDS 8 stages | TCP 1 stage | TCP 8 stages | Pairs better |
|---|---|---|---|---|---|
| 32/8 | 31.4 -> 19.3 | 52.3 -> 41.7 | 39.1 -> 21.4 | 56.5 -> 44.0 | 3/3 each |
| 64/8 | 31.7 -> 17.9 | 53.5 -> 40.4 | 33.2 -> 17.5 | 53.4 -> 42.2 | 3/3 each |
| 64/2 | 44.2 -> 17.9 | 65.6 -> 38.9 | 55.3 -> 16.9 | 70.4 -> 38.9 | 3/3 each |

Client CPU falls too (UDS 64/2: 19.2 -> 8.3 and 26.8 -> 14.7 us). At 1/1 and 8/8
nothing combines: 15/32 pairs better, no consistent wall effect, client CPU
+0-6%. A first per-stream worker-goroutine version cost a lone caller 2-24% and
was replaced before commit. The 8-stage floor stays near 27 us even at 64 per
frame, about 1.7x the in-process protobuf service; that server-side remainder
is the next gRPC target. Raw: `.scratch/evidence/pipe-probe-20261111/`
(`{uds,tcp}-r*`, `batch-smoke-uds`, `ab-combining2-{low,high}-callers-plain`).

UPFD functional smoke on commit 5 (unary versus 32 stream leases, all seven
modes, offered 1K cycles/s): UDS completes every offered cycle in both arms.
TCP needed four runs; three stopped on a single `PacerSkip` (driver shortfall at
the offer deadline, Sent = Completed, no timeout/refusal/error), once in the
unary arm and twice in the stream arm, and the fourth completed every offered
cycle in both arms. Raw: `.scratch/evidence/upfd-grpc-20261111/{uds,tcp}-smoke-c5`
and `tcp-smoke-c5-pacerskip-r{1,2,3}`.

#### Cap'n Proto and FlatBuffers on the same native transactions — 2026-11-11

A benchmark-only C++ server (not in BESS) builds the same eight-table stage
fixture and answers each RPC system through the same
`ControlV2Service::ApplyTransaction`: gRPC + protobuf (the real service and
commit-5 `TransactionChannel`), gRPC + FlatBuffers (bidi stream of batched
frames: only the codec differs), and Cap'n Proto RPC v1.5.0 (one call per
batch, D calls outstanding on one connection, its intended mode). Every arm
fills a reused protobuf request from its own message and returns the same
receipt content (request ID, outcome, generation, replayed, epoch, visibility,
per-op status, per-op error when set). One Go client (go-capnp v3.1.0-alpha.2,
flatbuffers v25.12.19, raw generated stubs) sends B transactions per frame/call
with D outstanding and checks every receipt. UDS; client CPU 4 GOMAXPROCS=1;
server CPU 6; AC, turbo off, valid power; fresh server per system run, rotated
order, 3 repeats. Server CPU is the server scope's cgroup usage around each
single-cell client run. Median us per transaction, wall (client CPU / server CPU):

| Stages | B/D | gRPC + protobuf | gRPC + FlatBuffers | Cap'n Proto | Native Service |
|---|---|---|---|---|---|
| 1 | 1/1 | 57.0 (24.5 / 55.0) | 53.8 (21.9 / 51.9) | 39.2 (27.9 / 20.2) | 3.6 |
| 1 | 1/4 | 33.0 (17.9 / 32.0) | 31.2 (16.9 / 30.3) | 23.9 (19.6 / 12.5) | |
| 1 | 16/4 | 11.0 (4.5 / 10.6) | 8.1 (2.7 / 8.3) | 7.9 (3.4 / 6.4) | |
| 1 | 64/4 | 8.1 (3.0 / 7.8) | 5.5 (1.6 / 6.0) | 6.3 (2.4 / 5.4) | |
| 8 | 1/1 | 79.3 (33.5 / 74.2) | 63.1 (25.6 / 60.5) | 52.3 (31.8 / 29.4) | 13.0 |
| 8 | 1/4 | 56.7 (27.3 / 54.6) | 44.9 (21.6 / 44.0) | 36.6 (23.6 / 22.4) | |
| 8 | 16/4 | 27.6 (10.5 / 26.2) | 16.8 (5.0 / 17.1) | 18.2 (7.2 / 14.6) | |
| 8 | 64/4 | 25.4 (9.0 / 24.1) | 14.7 (3.9 / 14.8) | 16.6 (5.5 / 13.9) | |

Findings:

- One transaction per message: the gRPC server spends about 50 us of CPU per
  message whatever the codec; Cap'n Proto's transport costs 20-29 us, so its
  wall is 28-35% lower, at slightly higher client CPU.
- Batched: transport cost amortizes and the codec dominates. On the same gRPC
  transport FlatBuffers is 26-42% faster than protobuf; server CPU at 8 stages
  is 14.8 versus 24.1 us. The ~10 us/transaction difference is the remote
  protobuf request/response codec (two `Any` per op, per-message allocation),
  much more than the in-process round trip suggested (16.4 - 13.0 us).
- Batched FlatBuffers/Cap'n Proto server CPU is 1.1-1.7x the native service.
  Neither alternative is a drop-in: Cap'n Proto Go is alpha, and both would
  need the full control surface (discovery, events, snapshots, admin), SDK
  recovery and a second schema.

Allocation counts, rerun on AC with the same binaries, cooldown and power
checks (the first pass ran on battery; counts agree within 1.1 per
transaction). Go client allocations per transaction from `runtime.MemStats`
(harness transaction building, identical for all arms, included; median of 3);
server libc `malloc` calls per transaction from a temporary uprobe over each
whole client invocation:

| Cell | Client allocs: protobuf / FlatBuffers / Cap'n Proto | Server mallocs: protobuf / FlatBuffers / Cap'n Proto |
|---|---|---|
| 1 stage, B1/D1 | 42.4 / 34.0 / 48.0 | 57.7 / 45.7 / 67.1 |
| 1 stage, B64/D4 | 19.7 / 8.3 / 8.7 | 37.5 / 23.4 / 22.4 |
| 8 stages, B1/D1 | 78.5 / 39.1 / 55.0 | 176.6 / 91.1 / 114.0 |
| 8 stages, B64/D4 | 57.7 / 15.3 / 15.8 | 156.8 / 69.5 / 68.5 |

The AC timing rerun (`three-way-uds-alloc-plain`) keeps every ordering of the
table above; some batched gRPC cells read 10-20% higher (1 stage B16/D1 16.5
versus 13.5 us), so treat that much as run-to-run spread.

About 69 server mallocs per 8-op transaction are the shared native path (both
alternative handlers add almost nothing). The protobuf transport adds about 88
more: the batched request parses into heap messages (op, two `Any`, strings per
op).

Arena parse of each `TransactionChannel` frame (BESS commit "Parse each
transaction channel frame into an arena"): server mallocs 156.8 -> 87.7 per
8-op batched transaction (176.6 -> 112.5 unbatched). Real bessd + bessbench
persistent streams, matched ABBA versus `afa7963c`, two campaigns of 3 pairs:
8 stages 43/48 pairs better, median -2% to -13% in 15 of 16 run-cells (UDS
64/8: 41.0 -> 35.7 us; TCP 64/8: 40.5 -> 36.4 us); 1 stage 28/48 pairs, no
consistent effect. The earlier rejected arena trial used one-transaction frames.
Raw: `pipe-probe-20261111/ab-arena-vs-heap-plain{,-r2}`,
`rpcalt-20261111/server-malloc-counts-ac`.

Go client allocations (BESS commit "Cut Go SDK allocations on the transaction
stream path"): an alloc profile of the SDK path (8 stages, 64 callers on 8
streams) showed ~37 allocations per transaction in acknowledgement decoding
(a fresh message per result, response, record and op result) and ~25 in op
building (one `packedOp` per op plus list growth); the per-attempt deadline
and per-member cancellation hooks (~20) are contract semantics and stay. Op
blocks plus a stream codec that keeps the protobuf wire format but decodes
all-records acknowledgements in a few allocations per frame (falling back to
`proto.Unmarshal` for anything else): 102.4 -> 56.8 allocations per
transaction, bytes +2.9%. Same arena bessd in both arms, two campaigns of 3
ABBA pairs: client CPU 81/96 pairs better (-2% to -12% at 8 stages); wall
66/96, mostly 0% to -7%. The decoder alone against the op blocks alone:
client CPU 38/48. Raw: `pipe-probe-20261111/ab-gocodec-plain{,-r2}`,
`ab-gocodec-decoder-only-plain`, `go-client-allocs-20261112`.

gRPC transport knobs, screened against the current guidance (grpc.io
performance guide: callback/async server over sync, raw `ByteBuffer` when
serialization dominates; grpc-go v1.83.2: shared write buffer already
default, read/write buffers measured adverse earlier). Same rpcalt server
binary, env-set channel args; UDS; 3 ABBA pairs. Wall change versus defaults:

| Arm | Unbatched cells (B1) | Batched cells (B64) |
|---|---|---|
| Go client static 1 MiB windows (BDP off) | -5% to -8%, 3/3 in 4 of 4 | -0% to -4% |
| Server `minimal_stack=1`, `bdp_probe=0`, `enable_channelz=0` | -2% to -6% | -3% to +2% |
| Both | -3% to -15% | -5% to +1% |

Isolated on top of client static windows: server `bdp_probe=0` alone has no
effect; adding `enable_channelz=0` is noise (+7% to +13% in 8-stage batched
cells); the server gain is `minimal_stack`, -5% to -8% unbatched at D4, mixed
batched. `minimal_stack` turns optional filters off and may drop the
message-size limit BESS relies on, so none is adopted: each is under 8% and
only for unbatched traffic, which frames already remove. Raw:
`rpcalt-20261111/grpc-knobs-plain`, `grpc-knobs-isolate-plain`.

The next gRPC lever after the arena is the remaining protobuf codec cost
(an encoded-op form without `Any`; FlatBuffers on the same transport is the
floor: 69.5 server mallocs and 14.8 us at 8 stages batched). Raw:
`.scratch/evidence/rpcalt-20261111/three-way-uds-servercpu-plain` (and the
earlier client-CPU-only `three-way-uds-plain`, consistent);
`sources.sha256` lists the schema, server, client and build-script hashes.

Still required: persistent-stream acknowledgement tails and current profiles
with plain controls, offered-arrival queue tails, loaded packets/reporting,
cancellation/lock contention, UPFD integration and native idle regression gates.
No loss-free 1K/10K/100K N4 rating or universal asynchronous-gRPC win follows.

### Next changes, in order

1. Finish the reviewed gRPC build's matched unary/stream ABBA qualification and
   bracketed acknowledgement tails. The TCP/UDS W1/2/4/8/16/32/64 sweep and buffer
   trials above are complete; default buffers stay. Qualify UPFD's bounded stream
   constructor against the identical local SDK's unary constructor, retaining
   full resident state, all offered arrivals, packets, reports and reconciliation.
   Callback/CQ, C++ ownership/overlap and native arena candidates are not defaults.
2. Close native idle regression gates before claiming regression-free control
   gains. Keep original short windows and adverse long windows.
3. Resume N4 receive/shard/compile/native-wait and failed-reconciliation work.
   Preserve bounded memory, per-session ordering and heartbeat/report-answer
   progress; expanding a socket/queue alone is not a fix. The tested N4 Close
   fix releases enqueue/drain/report waiters on shutdown; it is not an overload
   fix or a capacity measurement.
4. Compact Go transient/retained representation in `compile.go`,
   `sessionmajor.go` and `internal/bess/client.go`; assign current allocation,
   scan and GC CPU per accepted operation using separately corroborated profiles.
   Do not optimize the already-fixed warm resource-cache clone again.
5. Cut measured native codec/materialization work in
   `core/framework/resource_codec.h` and
   `core/control/dataplane_transactions.cc` with bounded scratch/ownership.
   Preserve admitted receipts, exact replay, epochs, rollback, reference ordering
   and allocation-free publication; the typed-only floor omits some of them.
6. Rerun N4 with packets/reports and strict reconciliation at 1K/10K/100K offers;
   publish the updated blocker ledger. RPC microbenchmarks do not replace these
   equipment-level gates.
7. Only after exhausting gRPC and its acceptance gates, compare Cap'n Proto and
   FlatBuffers in their intended efficient modes on the same complete native
   transaction semantics. Shared memory and a language rewrite remain deferred.




## Improvement loop

For every performance change:

1. Pick one observed cost and state the expected affected bucket. Separate a
   transport change from compiler/model changes so attribution remains useful.
2. Pin UPF/BESS revisions and dirty patches, binary hashes, build options,
   hardware/topology, affinity, layout, capacity, session template, active
   fraction, traffic mix, URR interval, checkpoint policy and memory limits.
3. Establish a loss-free accepted-rate point, with latency, as well as the
   saturation curve. Report scheduled, sent, accepted, refused, timed-out and
   completed counts separately. A replace cycle is two PFCP operations.
4. Pair baseline/candidate runs in ABBA order on the same isolated resources.
   No concurrent build or analysis. Repeat enough to expose run-to-run spread;
   a single short smoke is not a performance acceptance result.
5. Measure unprofiled goodput and p50/p99 first; profile a separate matching
   window. Capture both processes, per-role CPU, alloc bytes/objects, post-GC
   live/scan heap, cgroup peaks/events, queue pressure, retries, retire backlog
   and lost samples. Add stage elapsed timing when deciding a latency claim.
6. Exercise real packets with meters/counters and concurrent updates. Reconcile
   installed state between cells. Preserve refusal, shutdown, accounting and
   uncertain-completion correctness; a faster wrong result fails.
7. Append an outcome here: date, hypothesis, exact change, baseline/candidate
   evidence, distributions, correctness result, decision and remaining bottleneck.
   Keep inconclusive and negative results. Do not repin an old baseline as if
   it measured the new implementation.

### Candidate status at this cutover

| Work | Status | Remaining gate |
|---|---|---|
| Skip unchanged graph/appliance publications | Implemented; known-baseline checks retain full replacement semantics | Preserve rollback, enforcement and unknown-outcome coverage |
| Reuse RPC workers and avoid SDK catalog copies | Implemented; matched TCP/Unix release results recorded above | Keep complete control/admin/event behavior |
| Compact retained model and changed-field staging | Duplicate identity state reduced; whole snapshots and pointer-rich retained state remain | Lower allocation and scanning without losing supported N4 state |
| Native allocator maintenance | Expensive free-list traversal measured; reclamation policy unchanged | Preserve admitted and unadmitted memory bounds |
| Unix gRPC | Supported; not a universal end-to-end winner | Select on matched complete-workload evidence |
| Shared-memory RPC | Deferred | Demonstrate a remaining IPC bottleneck after the steps below |

### Next optimization design

**Design only, not an implemented store, allocator policy or N4 frontend.**
Keep the separate Go N4 process and complete gRPC API as the current contract.
Implement one measured change per branch; do not combine a representation
change and a transport change into one speedup claim.

#### 0. Establish the post-merge, corrected-driver reference

Pin merged BESS/native SDK revisions and rebuild both products with the recorded
release options. The corrected producer, its deadline/uncertainty counters and
its binary hash become the new reference; NT5/NT6 are historical observations,
not timings of that producer.

- Exercise all seven churn types at the 1K/10K/100K targets, one million
  resident sessions, the declared rule mix and explicit active/reporting load.
  Keep finite establishment/deletion bursts separate from steady-state churn.
- Establish a loss-free accepted-rate curve as well as overload points. Ramp
  offered rate, bracket the first failure, then refine the bracket. A capacity
  point requires the producer to achieve its offer without producer/window/
  busy/uncertain skips, timeouts or unexpected refusals. A skipped offer is
  producer/state-limited evidence, not UPF capacity.
- Report latency tiers rather than inventing an equipment SLA: successful
  response/cycle p50/p99, the failed fraction and timeout censoring separately.
  Expected packet drops from QER/URR policy are not forwarding failures.
- Use separate physical UPFD-control, BESS-control and packet cores. Treat
  Go parallelism and GC policy as explicit independent variables, not assumed
  wins. Keep laptop power/thermal helpers outside the repository.
- Use ABBA plain-product pairs; profile separate matching runs with plain
  corroboration before and after. No concurrent build or heavy analysis.
  Preserve actual offers, CPU numerators, socket drops, memory events,
  reconciliation, reporting and restart evidence.

**Exit:** repeatable accepted-rate/latency distributions for every mode, a
producer that is not the limiting stage at those points, and no unexplained
population or accounting divergence. Keep failed/inconclusive cells.

#### 1. Stage changed configuration, not whole-session snapshots

Primary files: `internal/session/session.go`, `compile.go`, `idmap.go` and
`report.go`. Replace whole-record cloning with a per-change before-image of
touched normalized configuration and an immutable candidate publication.
This is not safe as a shallow-copy substitution: resolving one FAR/QER/URR
can change derived PDR fields.

The private write contract must carry session identity, expected local
model/write-history version, touched rule IDs, before-images and retained
references. Build derived values in candidate scratch, not by mutating the
committed baseline. Preserve the current full native entry replacement when
forwarding changes, and zero native transactions for a proven model-only change.

One session writer owns configuration publication. A known refusal releases the
candidate and restores only its uncommitted configuration; accepted usage,
queued/confirmed reports and acknowledgement progress must not roll back.
An unknown outcome retains/quarantines its candidate and references until
resolved and invalidates incremental lowering. A late completion cannot
publish over a newer write.

**Exit:** existing graph/appliance enforcement, handover, overlap, refusal,
reporting and restart cases pass; add deterministic report-ack-during-refused-
write and delayed-completion cases where the new ownership boundary requires
them. Measure allocation per accepted operation, including failed work in the
separate numerator. A provisional full-path quota-update target is at most
2 KiB allocated per accepted operation for this fixture, not merely a
64-byte logical delta. Accept measured improvement beyond paired-run spread,
not allocation moved into an unmeasured pool.

#### 2. Move canonical session state to pointer-free segmented storage

Keep one model/compiler shared by graph and appliance lowering. The private
storage boundary is a session/rule handle plus generation and model version,
not a retained Go IE tree or a pointer into a mutable session object.

- Use segmented pointer-free record arrays and flat handle indexes. The
  640-byte canonical core and 1–1.25 KiB/session indexed budget above are
  engineering targets for the stated fixture, not universal feature limits.
- Retain arbitrary protocol IDs, association identity and explicit presence.
  Put variable IPv6/SDF/BAR/MAR/linked-rule data in bounded side storage;
  do not omit less common supported semantics to meet the compact budget.
- Ownership indexes resolve collisions by comparing complete canonical keys.
  A fingerprint alone must never establish classifier/F-TEID ownership.
- Separate configuration versions from measurement/queued/confirmed accounting
  state. Reporting and native publication consume stable views under the
  existing synchronization contract.
- Reuse a slot or release an empty segment only after pending writes, reports
  and borrowed views release it. Generation/version checks prevent late
  callbacks from accessing a replacement session. Specify generation-wrap
  handling rather than assuming it cannot occur.
- Preserve checkpoint/restart semantics. Migrate compiler, reporting,
  ownership and checkpoint callers together; remove the obsolete object model
  rather than retaining parallel canonical copies.

**Exit:** account for core, index capacity/slack, side storage, pending versions
and runtime memory separately at one million sessions and after mass
delete/re-establish. Canonical backing must be non-scannable; report descriptor/
side-object scanning explicitly. Demonstrate the indexed fixture budget or
explain its measured excess. Paired plain runs must improve GC CPU/service cost
without lifecycle, accounting, refusal or hard-budget regressions.

#### 3. Reduce native allocation and reclamation cost without hiding memory

Primary files: BESS `core/runtime/malloc_policy.*`,
`core/control/maintenance_loop.cc`, and UPF native session decoding/reservation.
This work can be developed independently of the Go store, but measure the
changes separately.

First prototype budgeted, bounded reusable codec/reservation scratch using
existing framework allocation/ownership patterns. Cap both per-request capacity
and aggregate retained idle capacity; an oversized request must not permanently
inflate every worker. Reduce fragmented transient glibc objects before replacing
the free-list observation policy.

Admitted-release trimming, fresh measurement/trim before admission refusal and
the reserve/4 unadmitted-garbage retention contract remain mandatory. Any
work-triggered reclamation design must identify all covered allocation/release
lifetimes. Keep a conservative fallback for untracked gRPC/protobuf garbage.
RSS-growth-only gating misses live-to-free transitions at unchanged RSS;
simply slowing or deleting `mallinfo2` is not an accepted design.

**Exit:** strict-budget and unadmitted-garbage cases, unchanged-RSS frees,
fragmented-heap churn, idle retention and packet/control tail latency all pass.
Show lower allocator-maintenance CPU under the same budget. If the proposed
policy cannot preserve the bound, retain the old policy and record the result.

#### 4. Isolate lowering, encoding and RPC before changing architecture

After re-profiling the compact paths, compare identical transaction payloads
from Go and C++ at the same bounded concurrency with individual outcomes.
Record encode/decode, queue/lock wait, transaction service and acknowledgement
time separately; sampled user cycles alone cannot partition wall latency.

Compare remote persistent TCP/Unix gRPC against local
`DataplaneTransactions::Apply` with equivalent codec/receipt semantics, then
typed owned apply as an engine-side floor. The last comparison also removes
adapter work and is not a pure transport speedup. Reuse existing framework
benchmark paths; do not add an unrelated flow-only protocol.

Preserve validation, deduplication/receipts, epochs, ownership, admission,
backpressure, atomic publication, events, inspection and administration.
Then repeat through full N4 with packets, reporting and restart.

**Exit:** identify the stage that misses its own per-core service budget:
100 µs at 10K/s or 10 µs at 100K/s, before utilization margin. Do not turn the
historical native microbenchmark or VPP routes/s into a session-rate prediction.

#### 5. Architecture decision, only if a measured stage still misses budget

Evaluate the embedded UPF-owned C++ frontend described above before shared
memory. Require the same PFCP/model/report/restart cases and supported-feature
matrix as the separate frontend, parser bounds/fuzzing, one writer per session
and explicit shared failure-domain treatment. Use owned typed transactions,
never direct mutable-table writes. Do not keep unrelated graph/appliance
semantics or duplicate Go/native canonical models.

Shared memory remains last: require evidence that residual IPC, rather than
retained state, allocation, compilation, transaction-engine work or the
producer, prevents the target after these cuts. Compare with the complete
existing API and identical acknowledgement/backpressure/restart semantics.
Without that evidence, keep gRPC and stop the transport work.

## 2026-11-05: VPP-inspired local transport investigation

**Decision:** shared-memory RPC is technically viable for co-located upfd and
BESS, and the profiles justify a controlled transport experiment. It is not yet
an implemented product transport or a demonstrated end-to-end speedup. Compare
worker reuse and persistent pipelined RPC before choosing the more complex IPC
implementation. Keep the model/compiler optimizations independent.

### What the VPP evidence actually says

The historical [programmability text](https://my-vpp-docs.readthedocs.io/en/what-is-vpp/overview/whatisvpp/programmability.html)
says it is "reasonable to expect performance yields of 500k routes/second" using
shared memory/message queues. The fetched source belongs to the
`javierfernandezvalles/vpp-docs` documentation fork, not a current official
performance result. This verifies the remembered wording, not a reproducible
500K/s benchmark, hardware configuration, atomic multi-resource transaction
rate, or PFCP session rate.

Official [VPP API-handler documentation](https://s3-docs.fd.io/vpp/26.02/_sources/interfacing/binapi/writing_api_handlers.rst.txt)
describes global/private shared memory and sockets, transport-independent
handlers, ring allocation, request/reply context, and barriers around
thread-unsafe handlers. This is not a claim that every handler can run
concurrently or without affecting packet workers.

Source checked at VPP `01448359f2c19a2502a3aa7776e84649235f721e`:

- [memory_client.c](https://github.com/FDio/vpp/blob/01448359f2c19a2502a3aa7776e84649235f721e/src/vlibmemory/memory_client.c):
  client registration creates a reply queue, sends its address, and exchanges
  message pointers through shared-memory queues.
- [socket_api.c](https://github.com/FDio/vpp/blob/01448359f2c19a2502a3aa7776e84649235f721e/src/vlibmemory/socket_api.c):
  `sock_init_shm` creates a private memfd-backed segment and sends the FD over
  the Unix socket with `SCM_RIGHTS`; the segment contains shared heap/queue
  structures. Do not copy the pointer-bearing representation into a Go/C++
  protocol that assumes independent virtual addresses.
- [client/test.c](https://github.com/FDio/vpp/blob/01448359f2c19a2502a3aa7776e84649235f721e/src/vpp-api/client/test.c):
  the message performance test asynchronously sends 10,000 `show_version`
  requests, then waits for a final control-ping reply. It is not a route
  transaction or UPF-state benchmark.
- [GoVPP perf-bench](https://github.com/FDio/govpp/blob/master/examples/perf-bench/perf-bench.go):
  uses the Unix `socketclient`, with synchronous/asynchronous `ControlPing`
  requests. A high GoVPP API rate is not, by itself, shared-memory evidence.

Transfer the bounded queues, reusable message storage, correlation and pipelining
ideas. Do not transfer a throughput number or VPP's worker-barrier policy.

### Existing BESS work, not a new prototype requirement

In BESS, `core/dataplane/ingress_bench.cc` already compares unary protobuf,
unary packed records, client-streaming packed records, and a forked two-process
`MAP_SHARED` SPSC ring. Records are 16 bytes; shared-memory publication uses
acquire/release atomics. It can decode only or update an `rte_hash`.

BESS D-005 records historical results of about 20M raw operations/s for packed
streaming batches of 256 and 78-275M/s for shared-memory decode. Its wording
about a production streaming API must not be treated as implementation evidence:
the checked `protobuf/control_v2.proto` still declares **unary**
`ApplyTransaction`; the ingress benchmark uses a separate test service.

The benchmark skips real transaction validation, request receipts, reference
checks, admission and RCU publication. Its streaming case acknowledges the
whole stream, not each transaction. It is a useful transport comparison, not a
replacement for the production transaction contract.

### Runtime smoke performed

No implementation was changed. Existing benchmark executables were built at
BESS `aade599a089838378a6cb169e23264db951341a9` (clean, plain build,
x86-64-v3, no LTO). The daemon in the live transaction smoke was `f5d94731`.

1. `live_transaction_bench`: 512 exact-match sessions, one upsert plus one
   erase per transaction, generated packets, one client; two seconds at each
   of 0, 1000 and maximum transactions/s. Daemon control CPU 9, packet worker
   11, client mask 2,3; normal pages, 16,384 buffers, 512 MiB memory policy.
   Both TCP and Unix gRPC achieved 1000 transactions/s, about 0.50 classifier
   hit fraction and zero BUSY answers. Both daemons exited zero after SIGTERM.
2. `ingress_bench --benchmark_min_time=0.001s`: normal pages,
   `BESSD_MEM_LIMIT_MB=512`, launch mask 9,11. This selects 0.05-second gRPC
   cases, batch 16, and 100,000 operations per shared-memory case. It exited
   zero and removed its Unix socket.

Selected outputs from these **short, unpaired smokes**, not acceptance ratings:

| Live transaction transport | Maximum observed tx/s | p50 | p99 |
|---|---:|---:|---:|
| TCP gRPC | 4,583 | 184 us | 253 us |
| Unix gRPC | 5,027 | 166 us | 240 us |

| Raw ingress variant | Publish/batch size | Observed hash-apply operations/s |
|---|---:|---:|
| Unary packed, Unix gRPC | 16 | 0.206M |
| Streaming packed, Unix gRPC | 16 | 2.257M |
| Shared-memory ring | 1 | 8.344M |
| Shared-memory ring | 64 | 21.002M |

The shared-memory cases busy-spin on two CPUs and have no per-transaction
receipt path. The comparison changes framing, encoding and acknowledgement
behavior, not only transport. Do not derive an UPF speedup or an advantage for
Unix sockets from these samples. The checks establish that existing mechanisms
run on this host and that we can reuse this benchmark for isolation experiments.

### Conditional future design — not implemented

Use an authenticated Unix-domain bootstrap to pass a BESS-owned memfd, then
bounded request/completion queues and a byte arena. Use offsets and lengths,
not Go objects, C++ pointers or a fixed shared virtual address. Keep the current
protobuf request/response payload initially: remove per-RPC HTTP/2/dispatch
overhead without changing serialization and transaction semantics at once.
Prefer batched drain with idle notification over a mandatory spinning core.

The BESS Go SDK has a package-private `transport` interface, but public `Dial`
and `NewClient` are gRPC-specific. UPF also uses the generated `Control()` client
for streamed resource reads and reset. This is an SDK/server integration, not
an interchangeable socket address. Hot `InvokeAction` calls include URR reads;
moving only `ApplyTransaction` would leave those costs on gRPC. Cold metadata,
administration and remote management can keep the existing gRPC transport.

The native seam is `ControlV2Service::ApplyTransaction` ->
`DataplaneTransactions::Apply` -> `TransactionEngine::Apply`. Extract and reuse
the transport-neutral service behavior, not a direct ring-to-engine shortcut:

- Check daemon epoch before side effects; preserve expected-generation and
  requested consistency semantics.
- Preserve request ID plus content-digest deduplication and receipt lookup.
  Timeout/disconnect after submission means uncertain completion, not failure
  or permission to replay under a new ID.
- Preserve the common control-plane lock and single-writer ordering against
  module actions, maintenance and administrative changes. Do not add another
  writer or execute control changes on packet workers.
- Preserve deadline-aware BUSY handling outside the control lock, typed errors,
  events, resource validation, reference checks, memory admission and retirement.
- Reserve outcome-record memory before applying a transaction, as the current
  `DataplaneTransactions` implementation does.
- Bound descriptors, in-flight bytes and large replies; account the IPC mapping
  and prefault ownership in the memory budget. A full queue must exert bounded
  backpressure, never cause unbounded buffering or silent loss.
- Validate descriptor bounds and the stable request snapshot; seal the memfd
  against resizing. Define alignment and cross-language publication ordering.
- Define producer/client death, restart, segment ownership and teardown without
  waiting forever on a dead process. Reconnect is a new connection/epoch check,
  not reuse of stale queue contents.

The existing handoff channels are in-process objects with their own lifetime
contract; they are not a cross-process, crash-safe transport to reuse unchanged.

### Experiment and adoption gate

Compare unchanged unary RPC, worker/poller reuse, persistent pipelined RPC, and
shared memory with the **same encoded ApplyTransaction payload, native service,
individual acknowledgements and bounded concurrency**. Network batching must
not merge independent session transactions into one larger atomic transaction.

First isolate transport with the existing ingress benchmark, then use real
session transactions at the intended population, then N4 with packets and
reporting. Record both processes' CPU, thread births, allocation, p50/p99,
accepted goodput, queue pressure, memory and packet interference. Run duplicate
IDs, queue-full, deadlines, disconnect-after-submit, stalled readers and daemon
restart through the same semantics.

Adopt shared memory only if that matched end-to-end comparison improves the
chosen operating point over the simpler alternatives without losing safety or
spending an unacceptable extra core/memory budget. There is no measured 500K/s
UPF or production BESS-transaction claim from this investigation.

## 2026-11-05: non-shared-memory first, typed churn

**Decision:** keep the complete gRPC control plane. First remove worker lifecycle
overhead, unnecessary representation/compilation work and client allocations;
qualify Unix-domain gRPC alongside TCP. `upfd` already reuses its gRPC client
and permits bounded concurrent unary calls; individual transaction receipts
remain intact. Shared memory is not implemented and is not the next default
step. It needs a matched end-to-end result that simpler paths cannot provide,
with the same transaction and failure semantics.

### Implemented cuts and safety boundaries

- BESS configures one minimum and sixteen maximum **idle** synchronous pollers
  per completion queue for TCP and Unix listeners. Threads start on demand;
  this bounds idle retention, not active handlers or streams. The first
  two-idle-poller candidate still created about 0.22–0.24 threads per
  acknowledged modification in overloaded FAR/URR windows.
- Go, C++ and Python single-resource cache hits no longer copy the complete
  resource map. Public resource listings remain caller-owned copies. C++
  lookup also avoids constructing a temporary string for its cached lookup.
- UPF compilation resolves a PDR once and caches its canonical selector IDs
  in one immutable length-prefixed string. General graph/appliance updates
  skip unchanged classifiers, meters, usage counters, tunnels and F-TEID
  records. Session-major publishes a complete entry when its resolved state
  changes, but preserves a known unchanged entry for model-only updates.
  That decision travels with the compiled plan, so a later enforcement write
  cannot turn an earlier no-op into an empty or stale replacement.
- Delta baselines are invalidated after unknown/refused writes, overlapping
  writes and interleaved enforcement. This is not permission to skip
  reconciliation or to replay an uncertain transaction under a new ID.
- A dropping/buffering model is not proof that its resolved tunnel was
  published. Reopening forwarding restates the tunnel; the quota-spend,
  handover-while-dropping, then quota-grant regression fails before this guard
  and passes afterward for graph and masked-appliance targets.
- Small rollback snapshots use bounded contiguous value backing. Collections
  above 16 entries keep independent value allocations, so one surviving rule
  cannot retain a formerly large, mostly removed collection after rollback.
- Model field packing recovered allocator size classes without removing
  safety state. The initial candidate failed the existing retained-memory
  guard at 2,631 B/session versus 2,550 B allowed. The corrected model passes
  that guard unchanged; derive exact campaign memory from runtime/cgroup
  snapshots, not from nominal struct-size arithmetic.

The transaction schema, all Control/Admin methods, receipt/digest semantics,
generation/epoch checks, admission, reference checks and retirement remain
unchanged. Unix gRPC is an endpoint selection, not an UPF-only command channel.
`upfd` exercises discovery, transactions, actions, streamed reads and reset;
native live qualification covers the wider management surface.

### Reusable typed workload

`cmd/churnbench` is an open-loop PFCP driver. `ci/bench-churn.py` starts a real
BESS appliance, `upfd` and the driver under bounded no-swap scopes, supplies
generated UL/DL packets, records metrics/cgroups, and reconciles populations.
Build before measuring; do not run builds or other benchmarks during a paired
performance campaign.

Choose each CPU role explicitly. `--bess-control-cpu` controls native BESS RPC
threads; `--upfd-cpu` controls the N4/compiler process; `--worker-cpu` controls
the BESS packet worker. The former combined `--control-cpu` interface is
removed. For an appliance comparison these are distinct physical P-cores,
not SMT siblings. Shared-control-core campaigns are separate constrained
experiments, not appliance capacity ratings.

On this laptop, the corrected layout is UPFD 4 (physical core 2), BESS control
6 (core 3), BESS dataplane 8 (core 4), and driver 10–11 (core 5).
Monitoring uses 0–3,12–19, avoiding all four workload cores and their siblings.
This pins the campaign; it does not isolate those CPUs from other host tasks.

The runner defaults UPFD to `GOMAXPROCS=1` for its one-logical-CPU affinity.
Use `--upfd-gomaxprocs` to record a different runtime policy explicitly; one P
is not a demonstrated universal speedup. N4 worker concurrency remains eight,
not the number of available CPUs. Keep the one-P and two-P experiments separate.

After building, set `BESS_STAGE`, `UPFD`, `CHURNBENCH` and a fresh `OUT` to the
chosen artifacts/evidence directory:

```sh
taskset -c 0-3,12-19 python ci/bench-churn.py \
  --stage "$BESS_STAGE" --upfd "$UPFD" --driver "$CHURNBENCH" \
  --evidence "$OUT" --bess-control-cpu 6 --upfd-cpu 4 \
  --worker-cpu 8 --client-cpus 10-11
```

Record any local GC policy, power/thermal conditions and sampler reserves
with the run. Child metadata includes the actual launch affinity. Power and
turbo checks remain outside this repository.

| Mode | Actual change | Rate unit |
|---|---|---|
| `establish` | New distinct CP F-SEIDs in an extra finite cohort | establishments/s offered |
| `delete` | Delete the prepared extra cohort | deletions/s offered |
| `replace` | Delete then establish each selected resident session | complete replacement cycles/s offered; two PFCP requests per successful cycle |
| `far` | Change the DL FAR's GTP-U TEID | modifications/s offered |
| `pdr` | Change the DL PDR's exact UDP destination port | modifications/s offered |
| `qer` | Alternate the UL gate and change its MBR | modifications/s offered |
| `urr` | Change the UL volume quota | modifications/s offered |

Defaults: 1,000,000 resident sessions, an extra 65,536-session cohort, targets
1K/10K/100K cycles/s and nominal 30-second modification/replacement schedules.
The current driver stops new attempts at the offer deadline, allowing one
pacing tick, and records producer shortfall in `PacerSkips` rather than
extending the offer indefinitely. Frozen NT5/NT6 driver `1d9132e4…` used the
older catch-up policy; do not apply the new semantics retroactively.
Each session has two PDRs, two FARs, one UL QER and one UL volume-quota URR. Only 16 resident
sessions are active traffic/reporting witnesses: this does **not** qualify
one million simultaneously active UEs or forwarding capacity. Witnesses have
one-second periodic reports; the driver acknowledges them, and the server's
`upf_usage_reports_total{outcome="sent"}` confirms accepted acknowledgements.
Reported wire volume is not a deduplicated charging total.

Establishment/deletion are bounded bursts of
`min(rate × seconds, cohort)` distinct sessions. At high offered rates, their
offer is shorter than 30 seconds and can be shorter than one reporting period.
Keep their actual offer/drain duration and report deltas visible; do not call
them sustained 30-second churn. Preparation, restoring witness PDR/QER policy
and reconciling missing/uncertain sessions happen outside measured cells.

Results distinguish scheduled opportunities, initial requests sent, complete
cycles, accepted PFCP messages, refusals, timeouts, busy/uncertain/state/window
skips and producer-deadline skips. The current scheduling partition is
`Scheduled = Sent + BusySkips + UncertainSkips + StateSkips + WindowSkips + PacerSkips`.
`sent_cycles_per_offer_second` reports achieved initial-request load; replacement
follow-up requests are not counted again in that rate. Latency includes
successful-response and whole-cycle p50/p99; goodput includes drain. A cell
with outstanding requests after its bounded drain is invalid.

### Post-NT6 driver correction and verification

The frozen driver scans every pending request each 100 ms. At 500K future
outstanding requests, a disposable, plain algorithm fixture measures the old
idle scan against the new ordered queue:

| Future pending requests | Old idle scan/tick | Ordered queue/tick |
|---:|---:|---:|
| 1 | 59.02–59.15 ns | 20.17 ns |
| 500,000 | 23.06–24.50 ms | 20.16 ns |

Three repeats, zero allocation per idle tick, same future records, one physical
client core/SMT pair, `GOMAXPROCS=4`, `GOGC=25`. This is algorithm cost, **not an
end-to-end UPF speedup**. Source/output provenance is retained in
`driver-expiry-cost-smoke.{go,json}`; the temporary benchmark is removed.

Requests share a fixed timeout and are timestamped under the insertion lock,
so an intrusive deadline-ordered queue avoids scanning future requests.
Acknowledgements/send failures unlink in constant time; expiry detaches only
the due prefix and completes it outside the lock. Boundary/ownership tests
cover head/middle/tail acknowledgement, modify/delete timeout accounting and
uncertainty. No request timeout, payload or reconciliation retry policy changes.
Reconciliation still fails visibly if uncertainty remains; the earlier failed
overlay is not erased by new retries.

Actual-program verification completes all 21 cells with the final plain driver
over TCP, then all 21 with its race build over Unix gRPC and explicit UPFD
`--upfd-gomaxprocs 2`. The runtime endpoint confirms two Ps in that second run.
Both use 256 resident sessions/cohort 128 and nominal two-second schedules,
preserve exact scheduling partitions, reconcile populations and exit daemons
cleanly. Producer skips and overload timeouts are recorded, not hidden.
These small functional smokes are not new million-session ratings.
Evidence: `smoke-fifo-final-plain`, `smoke-fifo-final-race-p2` and
`driver-fifo-final-smoke-audit.json`.

Snapshots include actual driver socket buffer sizes, client/server socket
receive drops, aggregate UDP loss counters, packet-gate metrics, acknowledged
reports, CPU and memory. Client socket drops must not be attributed to UPF
processing. With the measurement-only profiler overlay, snapshots also include
Go allocation/live/scan counters and heap profiles. The `-baseline` suffix
means no CPU sampler in that arm, not necessarily the old product or a plain
binary: a heap-overlay arm is still instrumented. Historical selective-perf
arms also used that suffix for sampling-disabled cells.

Current `--perf` runs are **separate always-on sampled arms**, including startup,
fill and reconciliation. Attribute samples only within the recorded per-cell
`CLOCK_MONOTONIC` windows. Keeping the recorder on preserves library mappings,
worker names and thread-lifecycle records; the earlier initially-disabled
recorder missed loaded shared libraries. Native BESS uses DWARF CFI with an
8,192-byte user-stack capture, while Go uses its normal frame pointers. This
does not require profiling compiler flags in either product binary, attach
to a live process, or arm Go profiling timers. Samplers share their workload's
scope; CPU, buffering, stack-copy and tracking costs remain in that arm.
Interpret user-cycle samples as on-CPU attribution, not latency or syscall
time. Exclude packet-worker threads before attributing BESS control costs.
Short-lived handlers can exit before their first sample, so thread-lifecycle
records and process-wide CPU deltas must corroborate a thread-reuse claim.
In the 2,000-modification baseline sampler smoke, the measured interval
contained 2,010 BESS thread births/exits but only five control-side cycle
samples after packet-worker exclusion. That smoke validates the observer and
exposes its blind spot; it is not a representative CPU-cost distribution.

### Mandatory observer-overhead corroboration

Use a **plain product binary** as the throughput/latency reference. No
measurement overlay, pprof endpoint, forced-GC snapshot, sampling process or
extra profiling flags. Production metrics and the same external load/state
checks remain enabled. Merely omitting CPU sampling from an overlay build does
not meet this requirement.

Run matching instrumentation-only and sampled arms separately. Preserve the
same source, workload, resident population, graph capacities, packet/report
load, transport, concurrency, CPU placement and resource limits. Record any
sampler-specific reserve separately. Compare accepted goodput, p50/p99,
refusal/timeouts, packets/reports, CPU and memory against the plain arm; report
the measured overhead rather than assuming it is negligible. Historical
sampling-disabled cells are not substitutes for plain product runs.
Repeat paired runs with reversed order before attributing small differences.

The first matched-source reference passes demonstrate why a scalar observer
correction is unsafe. `base-matrix` used the heap/runtime overlay and
forced-GC snapshots; `base-plain` used the plain product, without either.
Both offered 10K modifications/s with the same million-session population:

| Mode | Plain accepted cycles/s, including drain | Overlay accepted cycles/s, including drain |
|---|---:|---:|
| FAR | 1,812.0 | 1,879.3 |
| QER | 868.1 | 1,890.7 |

These are single passes, not causal overhead estimates or capacity ratings.
Forced-GC state and run history are confounders; an observer can appear to
improve results. Do not correct a sampled result by an assumed fixed
percentage. Retain the plain result and repeat in reversed order.

On this host, attempts to start Go's runtime CPU profiler ended the baseline
with SIGKILL, including a 256-session case whose scope peaked near 40 MiB with
zero OOM events. `profile-signal-trace.*` records successful `setitimer` and
per-thread SIGPROF timer setup immediately before termination; the kill's
origin is unconfirmed. The aborted `base-tcp` campaign contains only two
completed FAR cells, not a full matrix. Keep it as partial evidence, not a
capacity or performance rating. Do not invoke that observer during the
corroborating product campaign.

### Qualification evidence

Local evidence: `.scratch/evidence/nonshm-control/`, relative to the outer UPF
checkout. Baseline binaries are frozen separately from the candidate; campaign
JSON records binary SHA-256 values, capacities, endpoints, results, before/after
snapshots, role exits and aggregate-slice cleanup.

- `base-matrix`: complete 1M-resident, 21-cell instrumentation-only reference;
  not an uninstrumented product baseline.
- `base-plain` and `cand-tcp`: complete 1M-resident, 21-cell plain-product TCP
  passes, with no measurement overlay, forced-GC snapshot or sampler.
  Both reconciled after each cell, recorded zero lane OOM events and exited
  BESS/UPF normally. The first candidate pass is not yet reversed-order
  speedup evidence; its URR overload cells require follow-up profiling.
- `smoke-baseline`: all 21 typed rate/mode cells completed through baseline TCP.
- `smoke-uds`: all 21 cells completed through candidate Unix gRPC.
- Both used 256 resident sessions, cohort 128 and two-second steady offers.
  They proved forwarding, nonzero reported usage, accepted report responses,
  empty pending/uncertain sets after reconciliation and clean daemon exits.
  These small, short functional smokes are not performance ratings or paired
  speedup evidence.
- Matched candidate release: **250/250 functional native tests passed** with
  `BESS_TEST_RPC=unix`, including all 14 live suites, C++/Go conformance,
  administration/SDK lifecycle, transactions, events and HTTP.
- The separate unrestricted 304-case release attempt reached its outer deadline.
  Two benchmark memory guards failed: `classifier_shared_writer_bench` peaked
  at 129.4 MiB against 120 MiB; `l2_fdb_bench` at 174.9 MiB against 160 MiB.
  No budgets were raised. Do not describe that partial run as an all-green suite.
- All nine existing UPF `session-path`, `session-report` and `n4-path` lanes
  passed across graph, masked appliance and session-major against release BESS.
  These cover packet enforcement, reporting, quota handling and restart/replay.
- Full ordinary `GOWORK=off` UPF tests passed after pinning the published Go SDK;
  targeted session delta/enforcement/unknown-completion cases also passed under
  the race detector. The dropping-PDR tunnel-handover regression failed before
  the fix and passed after it for graph and appliance.
- After the final driver changes, the complete capped Go pass and focused
  churn-driver race tests pass. The synchronized budget gate has 35 rows:
  nine Go packages plain/race, two meson tests and fourteen lanes. The new
  driver-test rows are calibrated 32 MiB each; no existing budget is raised.
- Compiler/model changes are committed as `32ffaa3`; the measured product
  binaries remain the frozen pre-commit builds recorded by SHA256, not
  relabeled as new bit-identical builds.
- [BESS PR #149](https://github.com/krsna1729/bess/pull/149) merged as
  `529e53742273036417d9e2d584c6d3c0fb834ccd`. The final native pin and public Go
  SDK `v0.0.0-20261107173432-529e53742273` replace the provisional branch pins
  from `c2541fd`; the dependency merge blocker is cleared.
- Independent merge review found no compiler/model blockers. Harness review
  identified request-controlled evidence names, overwritten prepare records
  and incomplete resident selection for populations sharing the old stride.
  Result paths are now server-owned unique `driver-*.json` files returned as
  `record_file`; HTTP `Name` is removed. Prepare mode and its returned record
  stay with the cell. A coprime stride visits every resident. Historical file
  names and measurements above remain unchanged.

### Final merged-pin verification — 2026-11-07 UTC

These are functional checks, not a new capacity or timing qualification.
Release BESS was rebuilt from clean merged `529e5374` into a separate installed
stage; the frozen NT5/NT6 stage was not overwritten. Ordinary UPFD and plain/
race churn drivers were built from clean `486748d` with the public merged SDK,
without a local module replacement or profiling overlay.

- All nine capped ordinary Go packages, the isolated message-bound case,
  churn-driver race tests and targeted session compiler/enforcement race cases
  passed. Both native UPF tests and the 35-row budget declaration gate passed.
- The merged BESS non-benchmark run passed 249 of 250 selected Meson cases.
  Its remaining Go conformance case first lacked the Go executable, then
  inherited the outer UPF workspace. It passed with explicit `BESS_GO` and
  `GOWORK=off`; no product fix or `BESS_SKIP_GO` was used. The earlier native
  benchmark memory overruns remain recorded above, not waived or relabeled.
- All nine `session-path`, `session-report` and `n4-path` lanes passed across
  graph, masked appliance and session-major, including packet bytes, usage
  acknowledgement, quota enforcement and checkpoint/restart.
- `final-pin-tcp-smoke` and `final-pin-uds-race-smoke` each completed 21 cells
  with 256 residents, cohort 128 and two-second nominal offers. Each retained
  49 distinct driver records; all 27 run/prepare response records matched their
  own files. All six prepare records retained the correct mode and cell link.
  Both original `loaded.json` snapshots remained intact.
- TCP's URR 100K-offer cell recorded 35 request timeouts; the Unix/race arm
  recorded none. Neither arm recorded refusals. Both reconciled after every
  cell and shut down cleanly. The timeout cause was not attributed in this
  smoke. These small-population offers, run during functional verification,
  are not loss-free capacity points or a TCP-versus-Unix performance comparison.

