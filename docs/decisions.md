# Design notes

[SPEC.md](../SPEC.md) defines observable behavior and resource limits.
This document explains the implementation choices behind that contract.

## Dependencies and build

The runtime uses Zig 0.16 and ztls with OpenSSL through pkg-config.
Dependency revisions are pinned in `build.zig.zon` and `flake.lock`.
The libcrypto declaration forces pkg-config rather than a system-library fallback.

ztls provides a Sans-I/O TLS engine. The runtime owns socket operations and retains the engine's buffers between completions.
ztest and zig-benchmark are lazy, test-only dependencies.
Their pins include an [elapsed-time correction for ztest](https://github.com/mattrobenolt/ztest/pull/2) and [Zig 0.16 I/O support for zig-benchmark](https://github.com/mattrobenolt/zig-benchmark/pull/2).

Preserve these fixes in updates to the helper pins.

Nix fetches dependency archives separately, then builds with Zig's `--system` mode without network access.
Packages use ReleaseSafe and an explicit baseline CPU target, independent of the build host.

## Configuration and routing

`src/config.zig` parses typed ZON within a fixed startup workspace.
A tokenizer pass bounds source size, token count, and delimiter depth before the standard parser runs.
Unknown fields are errors at every level. Diagnostics use AST locations rather than searches for field names in source text.

Parsed strings and configuration views remain valid until the workspace is released.
The loader performs no socket operations or hostname resolution.
Listener hostnames currently fail at startup with `UnresolvedListener`.
An unsupported upstream hostname returns uncached local SERVFAIL when selected, without a silent skip to another member.
TLS `server_name` supplies certificate verification and SNI, not address resolution.

The router compares length-prefixed labels and folds ASCII case.
A dot within a label cannot become a suffix separator.
It scans at most 64 zones without heap allocation.

## Wire codec

The codec borrows immutable input. Record views retain offsets rather than packet copies.
A parse failure invalidates the target and its partial views.
Output cannot overlap input or borrowed EDNS options.
The event thread owns a reusable parser and rewrite workspace. Borrowed views cannot survive asynchronous work.

Fixed bounds limit parser work:

- A message contains at most 65535 bytes.
- Record metadata has 5956 slots.
- Compression pointers have 16384 possible targets.
- An opaque-RDATA mask covers 65536 byte positions.
- A name walk takes at most 16512 steps, without recursion.

### Compression and opaque RDATA

Pointers normally reference previously decoded label boundaries.
RFC 3597 section 4 also permits a record owner to reference an uncompressed name inside unknown RDATA.
An SVCB target is one example, under RFC 9460 section 2.2.

An otherwise unregistered target must form a complete name inside one earlier opaque RDATA region.
Every byte, including the root terminator, must precede the pointer.
The fallback accepts no embedded pointers and cannot cross record headers.
Only complete validation publishes new label boundaries.

Known scalar or string fields do not supply fallback targets.
This excludes OPT and known address layouts, even when their bytes resemble a name.
Unknown type/class layouts supply opaque regions because their internal semantics are unavailable.
A referencing owner is encoded afresh after relocation. The opaque bytes remain unchanged.

The encoder registers only output offsets below 16384, within the RFC 1035 pointer range.
Copied opaque RDATA never enters the output dictionary.

Output compression follows RFC 3597 section 4:

| Layout | Types | Output compression |
|---|---|---|
| One name | NS, MD, MF, CNAME, MB, MG, MR, PTR | Allowed |
| Two names and five integers | SOA | Allowed |
| Two names | MINFO | Allowed |
| Preference and name | MX | Allowed |
| Two names | RP | Forbidden |
| Preference and name | AFSDB, RT | Forbidden |
| Header, signer, signature | SIG | Forbidden |
| Preference and two names | PX | Forbidden |
| Name and bitmap | NXT | Forbidden |
| Three integers and name | SRV | Forbidden |
| Two integers, three strings, name | NAPTR | Forbidden |

NSAP-PTR decodes a name and emits it without compression, under RFC 1348 section 2.
KX, DNAME, RRSIG, and NSEC reject compressed names.
Other types retain opaque RDATA. The codec does not validate DNSSEC signatures.

### Rewrites and truncation

Rewrites relocate names rather than shuffle raw record spans.
UDP truncation reserves OPT space and retains a prefix with no partial RRsets.
The prefix-closure algorithm takes at most 5956 squared comparisons.
This finite bound is not a latency guarantee.

Uncompressed output can exceed the DNS message limit even when the input fits.
For example, a 6271-byte SRV response expands to 82171 bytes after removal of prohibited target compression.
The codec returns `RewriteTooLarge` rather than copy an invalid wire representation.
The resolver returns uncached local SERVFAIL without failover or a health penalty.
Ordinary UDP payload truncation remains a separate path.

### Retained scratch storage

`ScratchSet` clears a small map of initialized words between requests.
The first write clears a backing word before publication. Reads consult the map before access to that word.
The compression dictionary uses the same validity rule, with exact suffix comparisons.
`Packet.name` inspects existing provenance without a private bitmap copy.

`ArrayBuffer` holds fixed append-only storage and its active length.
`clear()` resets the length, not the backing array.
Checked append methods reject external lengths before writes or narrow casts.
Unchecked appends require a capacity proof. Stream cursors and kernel-owned buffers retain separate lifetime models.
The [scratch measurements](benchmarks/2026-09-08-scratch.txt) record the effect of these changes.

## Hosts and synthetic answers

RFC 6761 and NODATA rules match every query class. Synthetic records use class IN while the question retains its original class.
Hosts serves IN queries only. These policies intentionally differ from CoreDNS in the cases listed in [SPEC §7.2](../SPEC.md#72-deliberate-deviations).

Hosts uses two disjoint tables with at most 16384 address/name pairs each.
Reload parses the inactive table and publishes it only after a successful read.
The event-thread swap requires no cross-thread synchronization. Readers cannot retain views across replacement.
Errors preserve the active table and its mtime.

The loader checks that the source is a regular file and rechecks metadata after the bounded read.
This detects ordinary mid-read changes, not writers that deliberately restore metadata.
Duplicate pairs collapse. Aliases receive PTR records, and invalid lines are skipped as a whole.
Lookup and load deduplication use bounded linear scans.

Answer rotation partitions record indices into this order:

1. CNAME records.
2. Other records.
3. Address records.
4. MX records.

Only the address and MX groups shuffle. Authority and additional records retain their order.
Each cache delivery rotates afresh. RFC 6761 and NODATA answers never rotate.

## Cache storage

Each enabled cache allocates two fixed `std.MultiArrayList` banks at startup.
Positive and denial banks have separate intrusive LRU lists. SERVFAIL entries consume denial capacity.
Stable slot numbers identify packets independently of index bucket positions.
A successful replacement removes a matching key from the other bank.

Keys include framed labels, class, type, and the DO bit.
Names compare case-insensitively. Framed labels prevent binary dots or zero bytes from aliasing separators.
Fingerprints use only initialized key bytes. Exact equality resolves collisions.

Each bank has a preallocated `std.HashMapUnmanaged(u32, void, IndexContext, 80)` index of slot numbers.
The context reads fingerprints from the columns without copies of full keys.
The columns and indexes never resize after initialization.

Each occupied slot owns one index key. Removal deletes the key before the slot changes.
Insertion publishes the fingerprint before index insertion.
Zero marks vacant slots. A zero hash maps to one, so live entries never use zero.

### Tombstone maintenance

A fixed-size hash map still needs maintenance under churn.
Without maintenance, repeated replacements consumed every free bucket and made misses slower than a linear scan.
The [aged-index measurements](benchmarks/2026-09-08-runtime.txt) include that regression.

A removal counter triggers allocation-free rehashes at half the difference between bucket count and configured entry capacity.
The threshold uses configured capacity rather than current population, so later growth retains free buckets.
A rehash changes only bucket positions. It leaves packets and LRU links untouched.
The measured maintenance stall reaches approximately 119 microseconds at 10000 entries.
Collision-dependent work prevents a strict linear worst-case claim.

### Packet pools and memory pressure

One fixed allocation backs eleven `std.heap.MemoryPool` classes, from 64 through 65536 bytes in powers of two.
Both banks share this backing. Each entry records its class, and freed blocks return to that class.
Pool arenas never fall back to the general allocator.

The backing budget includes arena metadata and unused capacity.
Classes do not rebalance, so free blocks in one class cannot satisfy another class.
Rounding can almost double packet storage. Arena growth can fail before live packet bytes reach the configured budget.
A 64 KiB backing allocation cannot guarantee a maximum-sized packet plus arena overhead.
The [pool measurements](benchmarks/2026-09-06-cache-packets.txt) include the pinned allocator's growth overhead.

All fallible rewrites finish before packet ownership changes.
A same-class refresh or eviction can reuse its block. A matching entry in the other bank can transfer its block.
Other replacements obtain storage before removal.
Exhaustion preserves existing entries and returns the valid upstream answer without insertion.
It never triggers an eviction loop across unrelated entries.

Each enabled cache makes five startup allocations. Later cache operations make no general allocator calls.
Columns and indexes have a combined bound of 384 bytes per configured slot.
Packet backing has its own configured budget. General allocator bookkeeping remains outside these totals.
The runtime's libcrypto allocation exceptions remain separate.

### Publication and client fields

Only admitted upstream responses and terminal forward-stage SERVFAIL can enter the cache.
The runtime completes final client encoding and rotation before cache publication.
This prevents a failed client rewrite from replacing a usable stale entry.

Stored packets use ID zero and the admitted question, without OPT.
Delivery restores the current client's ID and question.
It also rebuilds EDNS fields, so another client's COOKIE or payload size cannot leak through a cache hit.
Fresh responses age TTLs. Stale responses use TTL 30 only after eligible transport exhaustion.
SERVFAIL entries expire after five seconds and are never stale candidates.

A nonzero extended RCODE requires client EDNS, under RFC 6891 section 6.1.3.
A client without EDNS receives local SERVFAIL without OPT. The low four bits cannot substitute for the full error code.
This local failure leaves the cache unchanged and causes no stale fallback or health penalty.

## Event loops and operation ownership

`src/runtime.zig` selects the backend at compile time.
Both backends run one event thread. [SPEC §1](../SPEC.md#1-non-negotiable-constraints) lists their buffer and operation limits.
Transactions copy the original query before a listener returns or reuses its input buffer.
A client destination retains a generation until response publication.

Only idle upstream sessions permit eviction. Each session carries one exchange at a time.
A disconnected client can retain its slot until that bounded exchange completes.
Partial reads and writes retain offsets in fixed buffers. Coalesced TCP queries remain in the socket until their turn.

### Linux

The minimum supported kernel is Linux 7.0.0.
Both Linux architectures passed the native socket suite on `7.0.0-1012-azure` ([CI run](https://github.com/mattrobenolt/z53/actions/runs/34411427340)).

The ring uses `SINGLE_ISSUER` and `DEFER_TASKRUN`, without a fallback backend.
Unconnected UDP listeners use multishot RECVMSG with a non-incremental provided buffer ring.
Response slots retain their output and destination until send completion.
The input buffer returns after synchronous processing or transfer into a forward transaction.
ENOBUFS terminates a receive operation. The listener rearms with a new generation.

TCP listeners use multishot direct accept into registered client slots.
A full range pauses admission until a close completes.
Close completion and a replacement accept can arrive in either order. Client state retains the replacement until the older close completes.
Every operation generation is non-wrapping. Cancellation requires both the target completion and its acknowledgement before slot reuse.

The pinned `register_file_alloc_range` wrapper supplies the wrong `nr_args` value.
The proctor calls `io_uring_register` directly with zero, as Linux and liburing require.
Accepted clients retrieve their peer through socket `URING_CMD`, with per-client sockaddr storage retained until completion.
`SOCKET_URING_OP_GETSOCKNAME=5` and `optlen=1` request the peer rather than the local socket address.

An interrupted submission or completion wait returns no event.
The next step uses existing ring state without a synthetic CQE or deadline renewal.
Other syscall errors remain fatal.
TCP listeners use `SO_REUSEADDR` for restarts. UDP address reuse and port reuse remain disabled.

### Linux teardown

Cancellation completion alone does not establish that all request objects released their resources.
Teardown completely submits older work, then cancels it and submits a separate `NOP` with `IOSQE_IO_DRAIN`.
No later SQE follows this marker.
The marker must complete before checked file and provided-ring unregistration, followed by storage release.

The allocation-based drain waits until `nr_req_allocated == nr_drained`.
Request cleanup releases resource-node references before a request enters the cache.
Worker-held references also delay the marker, even when their final cleanup produces no CQE.
The kernel mechanisms are documented in Linux 7.2.3:

- [`io_queue_deferred`](https://github.com/gregkh/linux/blob/v7.2.3/io_uring/io_uring.c#L457-L478).
- [`io_free_batch_list`](https://github.com/gregkh/linux/blob/v7.2.3/io_uring/io_uring.c#L1094-L1168).
- [`io_wq_free_work`](https://github.com/gregkh/linux/blob/v7.2.3/io_uring/io_uring.c#L1457-L1471).

One five-second absolute MONOTONIC deadline covers the entire teardown.
Raw waits use `GETEVENTS | EXT_ARG | ABS_TIMER` with the 24-byte `io_uring_getevents_arg`.
The marker token is `0xffffffffffffffff`, outside normal operation indices.
Deadline exhaustion or a failed barrier exits the process without release of kernel-visible storage.

Teardown consumes at most 2048 CQEs without dispatch or buffer recycling.
The conservative producer count is 1925:

- 1024 already published CQEs.
- 290 terminal target CQEs.
- 290 explicit cancellation acknowledgements.
- 64 provided-buffer UDP shots.
- 256 direct accepts, including replacements after queued closes.
- One marker CQE.

Final file release depends on the sole-submitter context and the current ordinary socket operations.
See [`file_table.c`](https://github.com/gregkh/linux/blob/v7.2.3/fs/file_table.c#L484-L590) and [`resume_user_mode.h`](https://github.com/gregkh/linux/blob/v7.2.3/include/linux/resume_user_mode.h#L40-L50).
SOCKET operations, zero-copy sends, forced asynchronous closes, or another issuer require a new lifetime analysis.
The teardown tests do not establish a cause for the intermittent restart `BindFailed` failures tracked in [#1](https://github.com/mattrobenolt/z53/issues/1).

### macOS

The kqueue backend fetches one readiness event per step.
No userspace event batch retains a descriptor across close or reuse.
One-shot interests use the same non-wrapping generations as Linux.
EV_EOF still invokes recv so buffered TCP frames drain before the connection closes.

Sockets are nonblocking and close-on-exec. TCP uses `SO_NOSIGPIPE`.
UDP responses retain output after EAGAIN or EINTR. Each listener shares one write filter across its pending responses.
The one-second timer retries admission after descriptor exhaustion.

`EV_DELETE` cancels readiness synchronously. Kernel registrations do not borrow query buffers.

Connect completion checks `SO_ERROR`. A dedicated nanosecond timer tracks the nearest upstream deadline.
A fresh clock sample converts absolute deadlines into relative kernel timers, without extension for time spent inside a dispatch.
The pinned Darwin bindings lack `IPV6_V6ONLY`. The address helper uses value 27 from the toolchain's bundled system headers.

## Forwarding, TLS, and health

Connect, TLS handshake, and request transmission share one absolute timeout.
Complete request transmission starts a separate response deadline.
Partial records and rejected frames do not renew that deadline.
Linux uses absolute linked timeouts, so queued SQEs cannot extend the budget.

A separately seeded CSPRNG supplies upstream query IDs. Answer rotation has its own generator.
Secure entropy failure aborts startup without a weak fallback.
Response admission checks connection identity and generation, then the DNS header and question.
Any admitted DNS response ends failover, including SERVFAIL and REFUSED.
Local resource failures return uncached SERVFAIL rather than penalize an upstream.

TLS uses actual wall-clock certificate time and the system trust bundle.
A bounded 1.5 MiB trust scan completes before listeners start. Empty or unreadable bundles fail startup.
Custom Apple trust overrides are unsupported.
TLS takes precedence over `force_tcp` and client transport. Certificate rejection never permits plaintext fallback to the same member.

TLS output is acknowledged only after complete socket transmission, including Finished and KeyUpdate responses.
Post-handshake tickets are discarded. KeyUpdate uses the established engine.
Session storage remains alive through completion retirement on Linux or `EV_DELETE` on macOS.
Bounded libcrypto allocations for setup and infrequent key updates are the exceptions to the steady-state allocation rule.

Health state is separate for each configured endpoint and zone, even when addresses match.
Counters saturate at the maximum `u32`. An admitted DNS response restores health before client encoding.
Typed transport results determine penalties, not diagnostic strings.
Local resource failures and cancellation do not count as upstream failures.

Clients have priority over probes within the shared pools.
At most two probes run concurrently, with at most one per endpoint.
A compact list of supported, health-enabled endpoints supplies round-robin selection without a scan of all unused slots.
Resource pressure defers probes with a ten-millisecond retry floor.
Probes use the configured transport and normal admission rules, but bypass the client cache and query-completion logs.

## Time and logs

Each active dispatch samples monotonic time after event retrieval.
The cache and scheduler share this timestamp until the next dispatch.
Time inside the dispatch consumes absolute timeout budgets. Linux teardown retains its independent clock and deadline.

Query-duration endpoints use fresh samples rather than the scheduler timestamp.
The duration ends at response publication, before log formatting or kernel delivery.
The logger reparses the original query and final response through a synchronous workspace.
Its retained 3072-byte buffer exposes only the current formatted prefix to the sink.
Callbacks must not reenter the same logger.

Stderr writes are synchronous. Backpressure can delay every query and timeout dispatch.
A short or failed write loses log bytes without a DNS error or retry queue.
[Clock measurements](benchmarks/2026-09-08-clock.txt) include syscall counts and duration checks.

## Fuzz runner compatibility

The pinned Zig default fuzz runner uses a stack-trace API that changed in Zig 0.16.
Returned-error tracing is disabled only for fuzz roots. Runtime safety and panic traces remain enabled.
Raw and structured targets run in separate binaries so each receives its full iteration budget.
Fuzz builds select LLVM because the default x86 backend emits no coverage instrumentation in Zig 0.16.
`scripts/fuzz.sh` creates `tmp/libfuzzer.log` and `f/in0` inside its isolated cache before either process starts.
These shared files avoid the [Darwin first-creation race in `openat(O_CREAT)`](https://github.com/golang/go/issues/81246).
The bounded runner uses one process per target. Only `in0` faces simultaneous first creation.

`scripts/fuzz.sh` checks reports and crash artifacts because the build runner can return zero after a fuzz panic.
It rejects incomplete reports and empty crash samples as well as nonzero exits.
Each run uses an isolated cache under `.tmp/fuzz/`.
Successful runs remove their captures. Failed runs retain the log, exit status, and a crash sample when available.
`tests/fuzz-gate.sh` checks this cleanup and failure detection.
