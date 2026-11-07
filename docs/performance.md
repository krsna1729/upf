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

### Current candidates, not measured gains

| Candidate | Measured reason | Evidence needed before accepting |
|---|---|---|
| Incremental FAR-only compilation | Rebuild/fold/key allocations for a tunnel-endpoint change | Lower CPU and allocation per accepted modify; preserve update, counter and rollback semantics |
| Compact retained model | Many pointer-bearing objects and high scan/GC share | Lower live/scan heap and GC CPU at the same population and semantics, including delete/re-establish |
| Reuse gRPC server workers / adjust pollers | Thread churn; current BESS uses `MAX_POLLERS=1` | Matched RPC workload, control CPU/thread births, packet interference and tail latency |
| Local transport, including shared-memory RPC | Client/transport and server machinery are material | Same transaction engine and payload, bounded memory/backpressure, restart correctness, matched end-to-end improvement |

A shared-memory message rate from another system is not a UPF session rate.
Do not remove validation, receipts, epoch checks, admission or reclamation to
make a transport benchmark faster.

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
- BESS changes are published in [draft PR #149](https://github.com/krsna1729/bess/pull/149),
  commit `98fe43d2e8ec06e7ba7c5d3c30e05e4c281447e2`. UPF pin commit `c2541fd`
  explicitly blocks merging until that framework PR lands and both pins are
  replaced with the final merged revision.

