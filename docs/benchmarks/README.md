# Cache baseline (#1)

The [stdlib SoA comparison](#stdlib-soa-comparison-1) and [packet pool comparison](#packet-pool-comparison-1) follow the original baseline below.

[Raw trials, counters, profile, and disassembly](2026-09-06-cache-baseline.txt) use production source `822e3aa5424b8aaa034af7688104ba51697d07d2`.
The host is launchpad: aarch64 Neoverse-V3, Linux 7.2.3, Zig 0.16.0, and ReleaseSafe.
The flake supplies the tools. Dependency pins and production algorithms remain unchanged.
This historical baseline predates production packaging. Current packages use ReleaseSafe and the baseline CPU target.
Debug results are not comparison baselines.

## Run

Inside `nix develop`, run these commands:

```sh
zig build bench -Doptimize=ReleaseSafe -- baseline
zig build bench-build -Doptimize=ReleaseSafe
./zig-out/bin/dns-benchmark layout
perf stat -e cycles,instructions -- ./zig-out/bin/dns-benchmark profile
zig build test-resolver -Doptimize=ReleaseSafe
zig build test-runtime -Doptimize=ReleaseSafe -Druntime-filter='cache stress native'
```

## Timed boundaries

All modes use the pinned zig-benchmark helper. Its first `B.loop` resets the timer after setup.
Inputs pass through `blackBox`. Outputs pass through `keepAlive`, with DNS or index checks after each trial.
Each ordinary case has three trials. `smoke` has one eight-iteration trial per case.
Wire, routing, and first-slot cases use 100000 iterations. Other scaling cases use `max(128, 10000000 / capacity)` iterations.
`profile` uses 50000 full-pipeline hits at capacity 10000. No mode permits unbounded counts or durations.

| Case | Includes | Excludes |
|---|---|---|
| `WireDecodeAResponse` | Parse one compressed, single-A response | Encode, resolver, logs, I/O |
| `LongestSuffix64` | Route alternating names through 64 suffixes | Query decode, cache, logs, I/O |
| `index_*` | Production `Bank.find`, prebuilt keys | Key construction, LRU touch, packet decode/rewrite, allocation |
| `lookup_*` | `Cache.lookup`, key construction, bank scans, TTL aging, client rewrite, LRU touch | Query decode, final pipeline rewrite, allocation |
| `pipeline_*`, `CacheHitPipeline1` | Real `Pipeline.answer`, query decode, routing, RFC6761 check, cache delivery, final UDP rewrite | Logging, sockets, kernel I/O, TLS, allocation |
| `insert_evict` | Production `Cache.forward`, response decode, client/stored rewrites, allocation, scans, eviction, publication | Mock response construction, final runtime rewrite, logs, I/O |

Scaling fixtures use capacities 128, 1024, 10000, and 100000 per bank.
Empty occupancy is zero. Sparse occupancy is 12.5%, in the first physical slots. Full occupancy fills every slot.
Denial hits scan a full positive bank before a full denial bank. Sparse lookup misses scan a sparse positive bank and empty denial bank.
Numbered names share a prefix and length. Random index hits use 256 deterministic prebuilt keys with PRNG seed 822.
First and last refer to physical slots, not LRU positions. The last-slot cases remain last-slot cases after repeated LRU touches.

Large fixtures directly seed valid keys, independently owned packets, and LRU links outside the timer.
This avoids quadratic production population at 100000 entries. These runs do not measure cold population time.
`CacheHitPipeline1` and native stress populate through production forwarding and cache publication.
Churn starts with a directly seeded full bank. Prebuilt replacement inputs ensure that every timed production insertion evicts an entry.

## Results

Values below are medians of three trials, in microseconds per operation.
These are in-process measurements, not end-to-end QPS, latency percentiles, or maximum sustainable capacity.

| Capacity per bank | Empty index miss | Last-slot index hit | Pipeline positive hit | Denial lookup hit | Insert and evict |
|---:|---:|---:|---:|---:|---:|
| 128 | 0.046 | 0.944 | 20.314 | 11.172 | 16.745 |
| 1024 | 0.379 | 6.786 | 26.144 | 22.714 | 24.385 |
| 10000 | 5.315 | 67.125 | 85.714 | 135.133 | 91.593 |
| 100000 | 121.651 | 635.033 | 640.138 | 1228.865 | 882.619 |

Wire decode takes 1.636 microseconds. Routing takes 1.443 microseconds. The one-entry pipeline takes 19.371 microseconds.
First-slot index hits remain about 0.024 microseconds at every capacity. They hide the physical scan cost.
At capacity 10000, random index hits take 35.270 microseconds. Full index misses take 59.252 microseconds.
The default-capacity pipeline profile attributes 78.47% of sampled cycles to `Cache.lookup` and 19.45% to `memset`.
Disassembly retains the scan and its 312-byte stride. These measurements support an index/layout investigation, not an optimization claim.

The separate 50000-hit profile run records 14.242 billion cycles and 82.385 billion instructions over 4.393 seconds.
Perf reports user-space counters, with multiplexed hardware events. Its process totals include setup and teardown, unlike the benchmark timer.
No CPU affinity, frequency control, or isolation applies. Short trials do not establish tail behavior under contention.

## Memory and resilience

`Entry` occupies 312 bytes. Its key occupies 262 bytes. Two default-capacity metadata arrays occupy 6240000 bytes, even when empty.
At maximum capacity, those arrays occupy 62400000 bytes. This is allocated metadata size, not total RSS.
Seeded positive packets contain 58 bytes. Seeded denial packets contain 78 bytes. Each entry owns its packet separately.
Sizes exclude allocator overhead and other runtime storage. Cache packets can reach 65535 bytes under the separate SPEC bounds.
Every measured lookup and pipeline hit reports zero Zig allocations. Production churn reports one allocation and 58 packet bytes per operation.

Two cache tests exercise capacity 128 with mixed name/type/class/DO keys and an independent LRU model.
They cover 640 allocation-guarded or final positive hits, 16 evictions, and complete positive/denial replacement cycles.
The native case fills 128 entries through one reused TCP upstream connection, then checks 512 hits across eight concurrent UDP/TCP clients.
It checks IDs, question identity, TTLs, payloads, cache source logs, and client addresses. An allocator guard rejects new runtime allocations after population.
The fixture owns every loopback socket. A ten-second work budget and fixed helper bounds limit the native case.
The memory log sink retains normal formatting but replaces the stderr syscall. No whole-runtime performance claim follows from its test duration.

The restored resolver suite passes 49 tests. The forward selection passes 54 tests, including existing local UDP and verified DoT cases.
The two new cache tests take about 18 and 23 milliseconds. The native cache case takes about 68 milliseconds within the forward selection.
The LRU mutation removes `bank.touch(index)` from `Cache.lookup`. The new mixed-key test rejects the wrong surviving eviction victim with `TestExpectedEqual`.
The source returns byte-for-byte to its original state. All 49 resolver tests then pass.
The first native fixture attempt incorrectly treated a response as `resolver.Request`. The query-only assertion rejected it before the fixture correction.

Native macOS execution, overnight soak, production load, and cold population timing remain unproved.
Health probes, listener bootstrap, final packaging, and historical restart issues remain separate work.

## Stdlib SoA comparison (#1)

[Raw comparison, profile, and disassembly](2026-09-06-cache-soa.txt) compare `ff72269` with candidate `8c8204b` on the same host.
The baseline production source remains `822e3aa`. Its binary was copied before edits.
The tested candidate was committed before measurement. Both binaries use ReleaseSafe and three trials per case.
The baseline ran first, then the candidate. No CPU affinity, frequency control, or isolation applies.

The retained change uses preallocated `std.MultiArrayList(Entry)` columns and stdlib scalar-search functions.
A dense fingerprint column selects candidates. Complete DNS key equality rejects collisions.
Packet ownership, configured capacities, stable slots, and LRU policy remain unchanged.
This is not the separate packet slab experiment.

### Boundaries

The original workload counts, occupancy, physical hit positions, and timer boundaries remain unchanged.
`index_*` still times production `Bank.find` with prebuilt keys. It now includes fingerprint construction inside that call.
`Cache.lookup` and `Pipeline.answer` also retain all fingerprint work inside their timers.
Direct setup uses production `Bank.put` for fingerprints and LRU links. It does not measure production cache population.

### Results

Values are medians of three trials, in microseconds per operation. Each cell shows baseline → candidate.

| Capacity per bank | Random index hit | Last-slot index hit | Pipeline last-slot hit | Insert and evict |
|---:|---:|---:|---:|---:|
| 128 | 0.539 → 0.058 | 0.938 → 0.061 | 20.299 → 19.394 | 16.696 → 15.763 |
| 1024 | 3.900 → 0.130 | 6.726 → 0.198 | 26.200 → 19.570 | 23.933 → 16.198 |
| 10000 | 34.921 → 0.8812 | 66.493 → 1.574 | 86.114 → 21.241 | 88.717 → 20.952 |
| 100000 | 338.271 → 8.611 | 628.598 → 15.646 | 641.939 → 36.275 | 838.962 → 65.742 |

The primary random-index metric falls 97.48% at default capacity, well beyond the 5% retention threshold.
The paired pipeline guardrail falls 75.33%. No measured pipeline case materially regresses.
The earlier reference medians were 35.270 microseconds for random index hits and 85.714 microseconds for the default pipeline.
The paired baseline stays within 1% of both reference values.

At default capacity, empty index misses fall from 5.285 to 1.621 microseconds.
Full index misses fall from 58.660 to 1.550 microseconds.
Sparse two-bank lookup misses fall from 18.737 to 3.113 microseconds.
Denial hits fall from 132.833 to 12.834 microseconds. The raw capture includes every smaller and larger case.

First-slot index hits regress from 23.64 to 50.58 nanoseconds at default capacity, approximately 114% slower.
Fingerprint construction adds work even when the first slot matches. The disassembly retains that work inside `Bank.find`.
The one-entry pipeline changes from 19.351 to 19.368 microseconds, below 0.1%.
Unchanged routing changes from 1.458 to 1.508 microseconds. These short runs do not isolate code-layout effects from host noise.

The 100000-entry churn trials vary from 64.511 to 132.412 microseconds in the candidate.
The median remains lower than the baseline, but three trials do not characterize this variation or tail latency.
All measured hits and misses report zero allocations. Churn still allocates one 58-byte packet per operation.

### Layout and profile

The reconstructed `Entry` occupies 320 bytes. Actual stdlib columns allocate 315 bytes per configured slot.
Two default-capacity banks allocate 6300000 metadata bytes, versus 6240000 before this change: a 0.96% increase.
At maximum capacity, metadata occupies 63000000 bytes. The fingerprint column occupies eight bytes per slot within those totals.
These values exclude packet allocations and allocator overhead. They are not RSS measurements.

The 50000-hit profile records 3.723 billion cycles and 13.934 billion instructions over 1.137 seconds.
Process counters include setup and teardown. The separate sample run contains 1170 samples with none lost.
Sampled cycles attribute 85.54% to `memset`, 7.28% to `std.mem.findScalarPos`, and 3.29% to `memcpy`.
No wire initialization change accompanies this result.

The retained disassembly shows stdlib vector loads and `cmeq v*.2d` comparisons over dense 64-bit values.
It also shows the scalar tail and complete key comparisons after fingerprint matches.
No handwritten `@Vector` scanner exists in the cache.

### Correctness evidence

The candidate passes 52 resolver tests and 54 forward-selected tests, including the native cache stress case.
A separate native stress run, benchmark smoke, and native ReleaseSafe build pass.
Formatting and both lint invocations pass. Runtime and resolver tests pass macOS and x86_64 Linux semantic compilation.
These compilation checks do not establish native execution on either target.

Three new tests cover fingerprint equivalence, collision continuation, exact capacities, slot reuse, and allocated metadata bytes.
Existing tests retain cross-bank replacement, stale, LRU, allocation guards, and transactional startup rollback coverage.
The collision mutation accepts fingerprints without complete key equality. The new index test rejects it with `expected null, found 0`.
The restored resolver run passes all 52 tests. The raw capture records commands and the failure.

The change meets the local performance retention gate. Parent review and full resolver acceptance remain separate.
Native foreign-target execution, production load, soak, and packet slab storage remain outside this slice.

## Packet pool comparison (#1)

[Raw trials and validation](2026-09-06-cache-packets.txt) compare lookup-only source `d1eb1d9` with packet storage source `58dff94`.
The final benchmark configuration is committed as `23b5580` before measurement.
Both binaries use ReleaseSafe on the same launchpad host. The lookup-only binary was copied before source edits.
The original baseline and SoA captures remain unchanged.

### Boundaries and configuration

The 47 cases retain three trials each, with the original iteration counts, occupancy, keys, and timed production boundaries.
All setup and memory-report operations remain outside the timer. Direct seeds use the production pool ownership helper and `Bank.put`.
The scaling fixture explicitly reserves 64 MiB of packet backing at every capacity.
The one-entry pipeline keeps the production 8 MiB default. Neither setup policy establishes a latency improvement.

The first committed fixture reserved 32 MiB. Its 100000-positive plus 100000-denial seed failed with `OutOfMemory` before denial timing.
The capture retains that failure and its earlier completed trials. Those partial results do not supply the comparison below.
The corrected 64 MiB fixture fills both banks completely and completes all 141 trials.
The initial lookup-only run supplies the baseline. No CPU affinity, frequency control, or isolation applies.

### Allocation and latency

Production insertion with eviction falls from one general-purpose allocation to zero at every capacity.
Requested general-purpose bytes per operation fall from 58 to zero. Pool allocation and bookkeeping remain inside the preallocated backing.
Tests also reject backing allocation during initial insertion, refresh, lookup, and packet reuse after removal.
This is not a whole-process zero-allocation claim. Existing libcrypto setup and key-update exceptions remain unchanged.

Values below are medians of three trials, in microseconds per operation. Each cell shows lookup-only → packet pools.

| Capacity per bank | Insert and evict | Pipeline last-slot hit | Denial lookup hit |
|---:|---:|---:|---:|
| 128 | 15.760 → 15.752 | 19.415 → 19.423 | 9.332 → 9.348 |
| 1024 | 16.188 → 16.170 | 19.546 → 19.574 | 9.611 → 9.638 |
| 10000 | 20.890 → 20.617 | 21.205 → 21.091 | 12.811 → 12.756 |
| 100000 | 65.307 → 65.997 | 36.591 → 35.838 | 43.180 → 42.559 |

Default-capacity churn falls 1.31%. Maximum-capacity churn rises 1.06%, with candidate trials from 65.930 through 66.750 microseconds.
The one-entry pipeline changes from 19.365 to 19.380 microseconds, a 0.08% increase.
Sparse lookup miss medians rise between 0.28% and 0.96% across the four capacities.
These short trials support the allocation result without a material latency regression. They do not establish a latency win or tail behavior.

### Reserved and used memory

`Entry` remains 320 bytes. Actual metadata columns rise from 315 to 316 bytes per slot for explicit packet class ownership.
Two default-capacity banks therefore rise from 6300000 to 6320000 bytes, a 0.32% increase.
Pool control occupies 296 bytes per zone, within the tested 512-byte cap and the existing fixed runtime zone budget.
The configured backing includes every stdlib arena header, alignment gap, free block, and unused arena byte.

The positive seed is 58 bytes in the 64-byte class. The denial seed is 78 bytes in the 128-byte class.
The table shows completely full positive and denial banks. Values are bytes, not RSS.

| Capacity per bank | Live DNS bytes | Live class bytes | Consumed backing | Reserved benchmark backing |
|---:|---:|---:|---:|---:|
| 128 | 17408 | 24576 | 48944 | 67108864 |
| 1024 | 139264 | 196608 | 393008 | 67108864 |
| 10000 | 1360000 | 1920000 | 3839792 | 67108864 |
| 100000 | 13600000 | 19200000 | 38399792 | 67108864 |

For these seeds, class rounding adds 41.18% to live bytes. Stdlib arena consumption then approaches twice the class bytes.
The largest fixture therefore consumes about 38.4 MB, not the 19.2 MB that class sizes alone predict.

The pinned `std/heap/ArenaAllocator.zig:351–389` advances `node.end_index` before the fit check.
Its in-place resize path uses that advanced index and reserves another allocation length.
With these FBA-backed pools, each such growth leaves approximately one block unused. This explains the observed cost beyond header metadata.
The toolchain source hash accompanies the capture. No stdlib or dependency source changes accompany this slice.
The production default reserves 8388608 backing bytes, independently of occupancy. It fits the default-capacity seed but not the largest fixture.
The old implementation requests only live packet bytes from its general allocator. Its allocator rounding and metadata are not measured here.
Fixed reservations increase empty-cache memory commitments. These results make no total-memory or RSS improvement claim.

The bounded layout report from committed source `3011d18` exhausts each class with an independent, empty 8 MiB backing allocation.
Every run reaches 4 MiB of live class storage before exhaustion. These are separate single-class maxima, not simultaneous quotas.

| Packet class bytes | Blocks at the default budget |
|---:|---:|
| 64 | 65536 |
| 128 | 32768 |
| 512 | 8192 |
| 4096 | 1024 |
| 65536 | 64 |

The raw capture includes all eleven classes. Full-size DNS messages use 65535 bytes within the final class.
Classes never rebalance. A free block in one class cannot satisfy another class, and arena growth can fail with unused backing space.
A changed packet-size mix can strand free blocks while another class rejects insertion. Repeated same-class refresh still succeeds under complete backing exhaustion.
The minimum 64 KiB budget cannot hold a full-size class block plus its arena headers.
Same-class refresh and eviction transfer existing blocks after all fallible rewrites. Other exhaustion preserves old data and returns the uncached upstream answer.

### Correctness and limits

The final candidate passes 59 resolver tests, 16 config tests, all 54 forward-selected tests, and the separate native cache stress selection.
Native ReleaseSafe build, benchmark smoke, formatting, and both lint invocations pass.
Runtime and resolver test roots pass macOS and x86_64 Linux semantic compilation. These checks do not establish native foreign-target execution.

New tests cover every packet class boundary, including production storage and delivery of a 65535-byte message.
They cover pool reuse, class pressure, transactional failure, both-bank isolation, same-class transfer, disabled storage, and startup rollback.
A mutation disables same-class reuse. The full-arena refresh test fails with `expected .stored, found .exhausted`.
The restored source hash matches its pre-mutation hash, and all resolver tests pass afterward.

The forward selection initially rejects its old teardown trace count: nine events versus eleven after the additional packet allocation.
The fixture now requires the exact new allocation and release pair after the same retirement barrier. Runtime teardown behavior remains unchanged.
No full runtime or restart suite runs for this slice. Existing listeners remain untouched.
Parent review owns retention and final acceptance. Production load, soak, and full SPEC acceptance remain separate work.

## CoreDNS and build-mode comparison (#1)

The [raw capture](2026-09-08-coredns.txt) compares the deployed package with ReleaseFast and CoreDNS 1.14.6 on launchpad.
Production source is `9a7c2c4`. Harness source is `6cd62a7`.
The Nix derivations have identical inputs and source. Only the optimization flag and output path differ.
Production remains on ReleaseSafe with the baseline CPU target.

### Workload

`scripts/compare-coredns.py` uses dnsperf 2.16.0 and owned loopback services.
Each resolver receives one CPU. CoreDNS uses `GOMAXPROCS=1` and `GOGC=100`.
The generator uses two other CPUs for its sender and receiver.
The host retains normal workloads. No CPU isolation or frequency control applies.

The workload uses shuffled A queries and a single-address answer with TTL 3600.
Both resolvers use their default cache capacities. The cache also contains one readiness name outside the workload.
An owned CoreDNS template supplies all initial answers. The upstream log stays unchanged during every timed trial.
A disabled-cache control fails at that check.

Query logs remain enabled on both resolvers, with output to `/dev/null`.
The timings include formatting and writes, but exclude journald persistence and disk backpressure.
These configurations omit hosts and TLS. They do not measure the complete deployment configuration.

### Results

Values are medians of three three-second trials. Resolver order rotates between trials.
Throughput uses 32 clients and at most 32 outstanding queries.
The latency column uses UDP with one outstanding query and reports the mean within each trial.

| Workload names | Resolver | UDP queries/s | TCP queries/s | Low-load UDP latency, µs |
|---:|---|---:|---:|---:|
| 1 | z53 ReleaseSafe | 17954 | 16511 | 58 |
| 1 | z53 ReleaseFast | 18407 | 16666 | 58 |
| 1 | CoreDNS | 94905 | 112144 | 16 |
| 4096 | z53 ReleaseSafe | 17945 | 16164 | 60 |
| 4096 | z53 ReleaseFast | 18431 | 16569 | 59 |
| 4096 | CoreDNS | 92433 | 109996 | 16 |

At 4096 names, CoreDNS delivers 5.15 times the UDP throughput and 6.81 times the TCP throughput of ReleaseSafe.
ReleaseFast improves the medians by 2.7% and 2.5%, respectively.
The UDP trial ranges overlap. Three short trials do not establish a reliable small throughput gain.
Single-outstanding throughput contains generator gaps and varies substantially. It does not establish a capacity limit.

All 54 timed trials complete 5988170 queries with zero losses and only NOERROR responses.
This is an observed throughput comparison, not a search for maximum sustainable load or a tail-latency result.

After the TCP trials at 4096 names, median sampled RSS is:

| Resolver | RSS, MiB |
|---|---:|
| z53 ReleaseSafe | 59.04 |
| z53 ReleaseFast | 12.47 |
| CoreDNS | 58.84 |

These are resident process measurements for this fixture, not reserved storage sizes or deployment memory budgets.
The ReleaseFast RSS reduction does not establish a reduction in the configured allocation bounds.

### Profile

Separate profiles sample userspace cycles at 199 Hz during the 4096-name UDP workload.
ReleaseSafe attributes 87.01% to `compiler_rt.memset`. ReleaseFast attributes 85.46% to the same function.
The profiles contain 588 and 602 samples, respectively, with zero lost samples.
Both binaries contain the same byte-at-a-time loop:

```asm
subs x2, x2, #1
strb w1, [x8], #1
b.ne <loop>
```

The capture includes both disassemblies and the profile commands.
The next performance investigation targets this memory-fill path, not removal of runtime safety checks.
No production optimization or build-mode change accompanies these measurements.

### Checks and limits

The ReleaseFast resolver and wire suites pass 60 and 35 tests, respectively.
The generator smoke and disabled-cache control pass their expected checks.
All-system flake evaluation and source formatting/lints pass.
The production resolver retains PID 782149 and zero automatic restarts after measurement.
No benchmark query reaches the production listener or a public upstream.

## Scratch reuse and CPU targets — 2026-09-08

[Raw capture](2026-09-08-scratch.txt). Issue #1.

The package comparison uses source `9a7c2c4` before optimization and `be029b3` after optimization.
All z53 variants use ReleaseSafe. The package defaults remain `-Dcpu=baseline`.
A second package pair uses explicit `-Dcpu=neoverse_v3`, not a change to the production target.
AArch64 baseline includes NEON. The comparison does not equate baseline with scalar-only code.

### Retained work

`ScratchSet` resets word-validity metadata instead of its complete backing array.
The first write initializes one dirty word. Membership reads consult validity first.
`Packet.name` reads immutable provenance. Encoder occupancy gates every retained dictionary offset.
The compression dictionary retains exact suffix checks and bounded probing.

Selected-word access removes the remaining by-value `ArrayBitSet` copies.
The captured `Packet.name` function uses a 384-byte stack frame, without the earlier 2048-byte and 8192-byte copies.
Small copies that construct decoded names remain. This is evidence for the captured build, not every target.

The later `ef97a67` refactor adds `ArrayBuffer` for RDATA parts and rewrite order.
Its clear operation resets only the active length. Overflow checks precede writes and narrow casts.
The refactor follows the full package comparison. Its microbenchmark results remain within one percent of the measured source.
A final package smoke exercises the refactor separately.

### Microbenchmarks

Each figure is the median of three trials on CPU 2, with ReleaseSafe and the baseline target.
The pipeline uses a last-slot positive hit at 10000 entries. The wire case decodes one A response.

| Source | Change | Pipeline, ns | Wire, ns |
|---|---|---:|---:|
| `a08b14b` | Before | 40624 | 3207 |
| `028f64c` | Dirty storage with validity maps | 5145 | 103.8 |
| `44ad350` | Immutable name inspection | 4380 | 90.80 |
| `2f52957` | Retained permutation scratch | 3892 | 91.76 |
| `05ece77` | Selected bitmap words | 3315 | 49.03 |
| `ef97a67` | Shared append-only buffers | 3322 | 49.38 |

The final pipeline latency falls by 91.8 percent. The shared-buffer refactor is a structural improvement, not a separate speed claim.
All timed cases report zero allocator calls per operation. This does not remove the documented OpenSSL allocation exceptions.

### Socket throughput

The owned-loopback fixture uses 4096 warm names and 32 outstanding queries.
Each figure is the median of three three-second trials. The capture also contains the one-name population.
The generator and resolver use the same CPU assignments as the preceding CoreDNS comparison.
Completion logs go to `/dev/null`. The fixture excludes hosts and TLS.

| Resolver | CPU target | UDP QPS | TCP QPS |
|---|---|---:|---:|
| Before | baseline | 17697 | 16022 |
| Before | neoverse_v3 | 29524 | 27425 |
| After | baseline | 96000 | 72627 |
| After | neoverse_v3 | 99879 | 74240 |
| CoreDNS | packaged Go build | 89774 | 105587 |

The baseline source change improves UDP throughput by 5.42 times and TCP throughput by 4.53 times.
CoreDNS still delivers more TCP throughput. The optimized UDP results are close to CoreDNS in this fixture.
The small target-specific TCP gain has overlapping trial ranges. Three short trials do not establish a reliable gain of that size.
Single-outstanding throughput still contains generator gaps and does not establish capacity.

The 90 timed trials complete 12628129 queries with zero losses and only NOERROR responses.
No timed trial increases the owned upstream log. No query reaches a production listener or public upstream.
All z53 variants show approximately 59 MiB sampled RSS after the 4096-name TCP trials.
The change reduces work, not the configured storage bounds.

### Profile and checks

Userspace-cycle profiles contain 576 baseline samples and 551 V3 samples, with zero lost samples.
The baseline `memset` share falls from the earlier 87.01 percent to 13.81 percent.
The V3 profile attributes 7.08 percent to `memset`. No compiler-runtime replacement accompanies these results.
`Driver.drive` accounts for 48.62 percent and 59.64 percent, respectively, including its inlined helpers.
Some samples remain unresolved. These shares do not measure request-latency attribution.

The final source passes these checks:

- 42 wire tests and 60 resolver tests on baseline and V3 targets.
- 60 native forwarding tests and 12 completion-log tests on Linux.
- 20008 decoder fuzz executions and 20247 structured-relocation fuzz executions.
- Wire semantic compilation for aarch64 macOS and x86_64 Linux.
- A Nix package build and nine owned-loopback smoke trials.
- Formatting, both ziglint commands, and whitespace checks.

The earlier scratch candidate also passes all 18 native health tests.
Negative controls detect stale words and shared-provenance writes.
Other controls detect missing occupancy resets and incorrect collision matches.
Buffer controls detect whole-value clear and success instead of `NoSpaceLeft`. The controls are restored before the final green runs.
Independent code reviews report no remaining correctness blockers.

The transport scheduler and repeated pipeline stages remain unchanged.
Production remains at source `9a7c2c4`. The Linux service retains PID 782149 and zero automatic restarts after these checks.
These measurements do not establish a saturation limit or tail latency.
They do not establish native Mac execution or deployment acceptance.

## Runtime work elimination — 2026-09-08

[Raw trials, controls, profiles, and helpers](2026-09-08-runtime.txt). Issue #1.

The baseline is the final scratch package from the preceding section.
Retained production code ends at `a4871df`. Reverts through `135b510` restore that source exactly.
Both z53 packages use ReleaseSafe and the baseline CPU target. Dependency pins remain unchanged.

### Retained changes

| Change | Source | Paired primary gain |
|---|---|---:|
| Enumerate configured health candidates instead of all 1024 slots | `9e37d3a` | 56.52% |
| Retain the synchronous logger buffer | `9ff8b6c` | 17.00% |
| Index stable cache slots and bound tombstone debt | `42a760f` + `a4871df` | 10.55% |

These percentages come from separate paired runs. The final comparison below measures their combined effect.
The health list preserves sparse endpoint identities and probe policy.
The logger exposes only the current line. Its synchronous sink can still block the event thread.
The cache keeps full-key collision checks, stable slots, and its existing packet ownership rules.

### Final paired comparison

The fixture uses 4096 warm names. It has 32 clients and permits at most 32 outstanding queries.
Each median covers three three-second trials. Resolver order rotates between trials.
Resolver CPU 2, generator CPUs 0/3, and upstream CPU 1 remain unchanged.
The host retains normal workloads. No CPU isolation or frequency control applies.

The primary case enables health and configures one owned upstream.
Completion logs remain enabled, with output to `/dev/null`.
The fixture excludes hosts and TLS. It does not persist service logs.

| Resolver | UDP QPS | TCP QPS | UDP CPU µs/query | TCP CPU µs/query |
|---|---:|---:|---:|---:|
| Final scratch package | 93018 | 71873 | 9.262 | 11.926 |
| Retained runtime package | 191142 | 143936 | 4.253 | 5.244 |
| CoreDNS 1.14.6 | 89361 | 108664 | 9.776 | 7.177 |

The runtime package delivers 2.03 times the scratch package's primary geometric mean.
UDP throughput reaches 2.05 times the baseline. TCP throughput reaches 2.00 times the baseline.
z53 delivers 2.14 times CoreDNS UDP throughput and 1.32 times CoreDNS TCP throughput.
These are observed fixture results, not maximum sustainable capacity or production latency.

| Secondary case | Scratch UDP/TCP QPS | Runtime UDP/TCP QPS |
|---|---:|---:|
| Health disabled, one upstream | 96639 / 72781 | 194280 / 143665 |
| Health enabled, sixteen upstream members | 94930 / 71786 | 187872 / 139235 |

All 42 final timed trials complete 15358431 queries, with zero losses and only NOERROR responses.
No timed trial increases the owned upstream log. No query reaches production or a public upstream.
Median sampled RSS rises from 60436 KiB to 60600 KiB between the z53 packages. CoreDNS records 60216 KiB.
These resident measurements do not replace allocated storage bounds.

### Cache maintenance and memory

The first index improved warm hits but accumulated tombstones until no free bucket remained.
The longer aged fixture performs 320000 replacements before 10000 timed operations.
Each result below is the median of three trials. All report zero bytes and allocations per operation.

| Index | Miss, ns/op | Insert/evict, ns/op |
|---|---:|---:|
| Previous linear scan | 2659 | 5359 |
| Index without maintenance | 33905 | 71832 |
| Index with bounded removal debt | 36.09 | 164.1 |

The timed churn interval includes periodic rehashes. These index-only results exclude DNS and packet-pool work.
Separate clock-instrumented trials record p99 values of 240–243 ns and three rehashes per 10000 operations.
Rehash maxima range from 116906 to 119126 ns. The occasional 119 µs stall is a real tail cost.
Collision-dependent probes prevent a strict linear worst-case claim. These measurements do not establish DNS response percentiles.

An enabled cache now makes five startup allocations instead of three.
Default metadata rises from 6320000 to 6483888 bytes across both banks.
The allocated metadata bound rises from 320 to 384 bytes per configured entry, with index headers included.
The `Entry` size limit remains 320 bytes. Packet budgets and fixed runtime caps remain unchanged.

### Rejected candidates and warmup

Three later candidates miss the five-percent throughput gate:

- Question-name output reuse: 0.54%.
- UTC prefix cache: 5.13% initially, then 3.11% in an independent confirmation.
- Compile-time RFC 6761 names: 2.24%.

Targeted reverts remove all three changes. The campaign stops at this measured plateau.

Three earlier comparisons stop during untimed dnsperf warmup. Their partial captures remain in the evidence.
One CoreDNS-only trial takes 4.344 seconds for 4096 replies, with 28 µs average DNS latency and zero loss.
The exact timeout mechanism remains unknown.

Final warmup uses a sequential UDP client with the same names and one outstanding request.
It permits no retry and applies a one-second deadline to each exchange.
Eight controls reject incorrect responses or a timeout. A disabled flag check makes the control suite fail.
Timed dnsperf commands remain unchanged. Every timed trial still requires zero loss and only NOERROR replies.
The owned upstream log must remain unchanged during each timed trial.
The raw capture embeds both warmup implementations and their controls.

### Checks and limits

The final source passes these native ReleaseSafe checks:

- 42 wire tests and 62 resolver tests.
- 60 forwarding tests.
- 21 health tests.
- 13 logger tests.
- 16 configuration tests and four foundation tests.
- The benchmark smoke.
- Source style and whitespace checks.

The executable and all test roots pass semantic compilation for x86_64 Linux and aarch64 macOS.
Those checks do not establish native execution on either target.
Negative controls cover sparse endpoint IDs and retained logger bytes.
Cache controls reject fingerprint-only matches and missing index retirement.
A reserve test fails before tombstone maintenance, then passes with the fix.
Read-only reviews approve the retained source changes. The parent executes the tests and measurements.

The final userspace profile contains 582 samples, with none lost.
Name decode accounts for 8.49% of samples. Timestamp formatting accounts for 6.84%, and packet parsing accounts for 4.46%.
The remaining costs span several functions. Unresolved samples account for 14.57%.
Sample shares do not measure request-latency attribution.

Production remains at source `9a7c2c4`. This campaign performs no push or deployment.

## Per-dispatch scheduler clock (#1)

[The capture](2026-09-08-clock.txt) compares `1609241` with `9f85150` under ReleaseSafe and the baseline CPU target.
An owned trace records nine → three monotonic calls across three idle wakes.
Twenty local UDP queries issue 140 → 80 calls. Query-duration endpoints remain fresh.
Each receive or send dispatch retains its own scheduler sample.

The table pools six trials per cell from two complete matrices, with no discarded rows.
The primary fixture uses 4096 warm names with 32 outstanding requests. Health is enabled with one upstream.

| Transport | Before QPS | Shared tick QPS | Change |
|---|---:|---:|---:|
| UDP | 186090.1 | 199027.8 | +6.95% |
| TCP | 138427.0 | 148118.0 | +7.00% |

All 72 trials complete 32446201 queries with zero loss. All replies are NOERROR, and no timed trial grows the upstream log.

The initial matrix contains severe slowdowns in both binaries. Its health-disabled TCP median regresses 30.76%.
That median improves 6.20% in the repeat. All six pooled medians improve, but the initial slowdown remains undiagnosed.
These are shared-host fixture results, not a fixed production gain.

Native Linux checks pass. macOS receives semantic compilation, not native execution.
The implementation and evidence are pushed. This slice performs no production restart or deployment.
