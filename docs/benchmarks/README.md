# Cache baseline (#1)

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
