# Benchmarks

The benchmarks separate in-process DNS work from end-to-end resolver throughput.
Captures identify their source revisions and build settings. Historical results do not describe every later revision.

## Run

Enter `nix develop` at the repository root.

Run the in-process baseline:

```sh
zig build bench -Doptimize=ReleaseSafe -- baseline
```

Build the benchmark executable:

```sh
zig build bench-build -Doptimize=ReleaseSafe
```

Inspect its storage layout:

```sh
./zig-out/bin/dns-benchmark layout
```

On Linux, collect profile counters:

```sh
perf stat -e cycles,instructions -- ./zig-out/bin/dns-benchmark profile
```

Run the benchmark smoke and native cache stress test:

```sh
zig build bench-smoke
zig build test-runtime -Doptimize=ReleaseSafe -Druntime-filter='cache stress native'
```

Available modes:

- `smoke`: eight iterations per case, for build and execution checks.
- `baseline`: the complete in-process matrix.
- `wire` and `route`: packet decoding and suffix routing.
- `index`: cache index lookup without packet delivery.
- `cache`: cache and pipeline response delivery.
- `churn`: insertion and eviction.
- `profile`: repeated full-pipeline cache hits.
- `layout`: storage sizes.

The benchmark uses zig-benchmark and ReleaseSafe. Counts and capacities are bounded.
Setup occurs before the timer. Directly seeded cases do not measure production cache population.

## Measurement boundaries

| Case | Timed work | Excluded work |
|---|---|---|
| Wire | Parse a compressed single-A response | Encoding, resolver policy, logs, sockets |
| Route | Longest-suffix selection | Query decoding, cache, logs, sockets |
| Index | `Bank.find`, including fingerprint work | Key construction, LRU updates, packets |
| Cache lookup | Key construction, LRU updates, TTL aging, rewrite | Admission, logs, sockets |
| Pipeline | Decode, route, local-name checks, cache delivery, final rewrite | Logs and sockets |
| Churn | Response parsing, preparation, insertion, eviction | Mock-response construction, logs, sockets |

The baseline covers capacities from 128 through 100000 entries per bank.
Captures distinguish full and sparse caches, along with hit position.
The smoke produces no stable timing result. In-process timings are not DNS throughput or response percentiles.

End-to-end captures use dnsperf against isolated loopback listeners and a local upstream.
They record CPU affinity and concurrency, along with log destinations.
Production listeners and public upstreams receive no benchmark traffic.

## Warm-cache comparison

The [2026-09-08 runtime capture](2026-09-08-runtime.txt) compares the scratch-refactor baseline with `a4871df` and CoreDNS 1.14.6.
Both z53 binaries use ReleaseSafe and the baseline CPU target.
This comparison predates the scheduler clock change below.

Fixture settings:

- Aarch64 Neoverse-V3, Linux 7.2.3, Zig 0.16.
- 4096 warm names with one A record each and TTL 3600.
- 32 clients and at most 32 outstanding requests.
- Health enabled with one upstream.
- Completion logs sent to `/dev/null`.
- Resolver on CPU 2, generator on CPUs 0/3, upstream on CPU 1.
- Three rotating three-second trials per cell.

| Resolver | UDP QPS | TCP QPS | UDP CPU µs/query | TCP CPU µs/query |
|---|---:|---:|---:|---:|
| Scratch-refactor baseline | 93018 | 71873 | 9.262 | 11.926 |
| z53 `a4871df` | 191142 | 143936 | 4.253 | 5.244 |
| CoreDNS 1.14.6 | 89361 | 108664 | 9.776 | 7.177 |

Values are medians. The capture includes health-disabled and sixteen-upstream cases.
All 42 timed trials completed 15358431 queries with zero loss and only NOERROR responses.
No timed trial grew the upstream log.
Median RSS was 60436 KiB for the baseline and 60600 KiB for `a4871df`. CoreDNS used 60216 KiB.

The host retained normal workloads without CPU isolation or frequency control.
The fixture excludes TLS and hosts. Logs are formatted but not persisted.
These results do not establish maximum capacity or production latency.

## Scheduler clock reuse

The [clock capture](2026-09-08-clock.txt) compares `1609241` with `9f85150` under the same build settings.
The change shares one scheduler timestamp per dispatch, while query-duration measurements remain fresh.

| Traced workload | Monotonic calls before | Monotonic calls after |
|---|---:|---:|
| Three idle wakes | 9 | 3 |
| Twenty local UDP queries | 140 | 80 |

Two complete throughput matrices retain all 72 trials, with six trials per cell and no discarded rows.
The primary fixture uses 4096 warm names with 32 outstanding requests. Health is enabled with one upstream.

| Transport | Before QPS | Shared tick QPS | Change |
|---|---:|---:|---:|
| UDP | 186090.1 | 199027.8 | +6.95% |
| TCP | 138427.0 | 148118.0 | +7.00% |

All 32446201 comparison queries completed with zero loss and only NOERROR responses.
The initial matrix contains severe slowdowns in both binaries. Its health-disabled TCP median regresses 30.76%.
That median improves 6.20% in the repeat. The initial slowdown remains undiagnosed.
The table pools both matrices rather than omit the slow trials.

## Cache maintenance costs

The fixed hash index needs periodic rehashes to remove tombstones.
The [aged-index capture](2026-09-08-runtime.txt) performs 320000 replacements before 10000 timed operations at capacity 10000.

| Index | Miss, ns/op | Insert/evict, ns/op |
|---|---:|---:|
| Linear scan | 2659 | 5359 |
| Hash index without maintenance | 33905 | 71832 |
| Hash index with bounded removal debt | 36.09 | 164.1 |

Values are medians of three trials, with zero general allocations per operation.
The timed interval includes rehashes but excludes DNS packet work.
Separate clock-instrumented trials record rehash maxima from 116906 to 119126 ns.
That occasional 119 µs stall is not a DNS latency percentile or a worst-case guarantee.

Default metadata rises from 6320000 to 6483888 bytes across both banks, including the indexes.
The allocated metadata limit is 384 bytes per configured entry. Packet backing has a separate budget.
[Design notes](../decisions.md#cache-storage) explain the ownership and memory tradeoffs.

## Capture archive

The captures retain measured regressions and failed trials as well as improvements.
Raw logs preserve their original commands and environment paths.
Personal planning notes are omitted. Benchmark data and retained artifact hashes are unchanged.

| Capture | Contents |
|---|---|
| [Cache baseline, 2026-09-06](2026-09-06-cache-baseline.txt) | Linear index scaling, packet work, initial profiles |
| [Dense columns, 2026-09-06](2026-09-06-cache-soa.txt) | Structure-of-arrays lookup and metadata costs |
| [Packet pools, 2026-09-06](2026-09-06-cache-packets.txt) | Fixed backing, allocation counts, class pressure |
| [Initial CoreDNS comparison, 2026-09-08](2026-09-08-coredns.txt) | ReleaseSafe, ReleaseFast, and CoreDNS before scratch reuse |
| [Scratch reuse, 2026-09-08](2026-09-08-scratch.txt) | Retained buffers, generated-code fixes, CPU-target comparison |
| [Runtime changes, 2026-09-08](2026-09-08-runtime.txt) | Health enumeration, logger reuse, hash index, aged churn |
| [Scheduler clock, 2026-09-08](2026-09-08-clock.txt) | Syscall counts, fresh query durations, paired throughput |
