# Cache baseline (#1)

The [retained stdlib SoA comparison](#stdlib-soa-comparison-1) follows the original baseline below.

[Raw trials, counters, profile, and disassembly](2026-09-06-cache-baseline.txt) use production source `822e3aa5424b8aaa034af7688104ba51697d07d2`.
The host is launchpad: aarch64 Neoverse-V3, Linux 7.2.3, Zig 0.16.0, and ReleaseSafe.
The flake supplies the tools. Dependency pins and production algorithms remain unchanged.
Production packaging does not yet specify a release profile. Debug results are not comparison baselines.

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
