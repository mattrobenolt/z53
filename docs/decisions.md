# Foundation decisions

Approval: [z53#1](https://github.com/mattrobenolt/z53/issues/1#issuecomment-5547844594).

## Dependencies

ztls is pinned at `1d72c5331c6a9079279a27eede680534b74f596d`.
The build selects OpenSSL and requires libcrypto through pkg-config.
Zig 0.16 keeps the first system-library entry (`Build/Step/Compile.zig:1089`).
We set `.force` on that entry. A duplicate permits fallback.

No dependency source changes are needed.
No other runtime module is added. The executable does not serve DNS yet.

ztls exposes a Sans-I/O handshake. Connections will own record, output, and
reassembly storage. Tests exercise ClientHello, write completion, partial
records, and oversized record rejection. They do not prove a full handshake.

Trust uses `Bundle.empty`, then `rescan(allocator, io, timestamp)`.
The test scans actual system roots. Production will load once before listen.
Zig reads Apple keychains directly. Custom Apple trust overrides are unsupported.
The trust memory cap and scratch allowance remain unproven.

## Test helpers

ztest uses reviewed revision `ab7a2ed05547340261dd8f12a564aefc2950df91`.
Normal tests use its simple runner, with one line per test.
The upstream timer fix includes second-boundary regression tests.
See [ztest#2](https://github.com/mattrobenolt/ztest/pull/2).
Future fuzz tests must use Zig's default runner.

Both helper dependencies are lazy and test-only in our package manifest.
The pinned ztls build eagerly fetches its benchmark dependency. Its build
script also requests lazy test helpers. These fetches add no runtime module.

zig-benchmark uses reviewed revision `bc978caebd4424c99a84e9329a9ea847cc7a22e4`.
See [zig-benchmark#2](https://github.com/mattrobenolt/zig-benchmark/pull/2).
Both helper PRs are published but unmerged. Neither repository has CI.

Our Zig 0.16 smoke passes `init.io` through `Options.io`.
Custom callers must supply Io. Measurement without it returns `error.MissingIo`.
Generated build helpers supply Io. `Options.parse` accepts either argument iterator.

There are no local dependency patches. The package cache and adjacent
worktrees remain untouched. The smoke runs eight iterations through the real
helper. It makes no resolver performance claim.

## Contract corrections

Reference listeners use ZON tuples. Terminal forward-stage SERVFAIL caches for
five seconds, but never replaces a stale candidate. Denial TTL caps use the
smaller positive and denial maximum. Invalid clamp intervals fail config load.

Unconnected UDP listeners need multishot RECVMSG to retain source addresses.
Connected UDP upstreams can use RECV. Established exchanges allocate nothing.
Bounded libcrypto setup and infrequent key-update allocations are exceptions.

## Wire codec (#1)

The codec borrows an immutable packet. Record views store offsets, not copies.
Names use length-prefixed labels and a root terminator. Binary dots and zero
bytes cannot alias label separators. Case changes are never needed for encoding.

Parse failure invalidates the target and its partial views.
The output cannot overlap the input or borrowed EDNS options.
One event-thread workspace owns the encoder and record order.
The workspace survives no asynchronous work. TTL changes use `Record.ttl_s`.
The original packet stays unchanged.

The message bound is 65535 bytes. Record metadata has 5956 slots.
The decoder tracks 16384 possible pointer targets in a bit set.
A fixed 65536-bit mask tracks genuinely unknown RDATA bytes.
Each name walk has at most 16512 steps.
The parser has no recursion or allocator parameter.

Pointers reference earlier decoded label boundaries or validated uncompressed names in prior opaque RDATA.
The amendment below defines that validation.
The encoder stores only output offsets below 16384. Its dictionary is fixed.

UDP truncation retains a prefix containing no partial RRsets.
It reserves OPT space before records.
Prefix closure takes at most 5956 squared comparisons.
No benchmark or worst-case latency claim is made here.

The compression table follows RFC 3597 section 4:

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

Legacy NSAP-PTR follows RFC 1348 section 2. It decodes a name and emits it
without compression. KX, DNAME, RRSIG and NSEC names reject compression.
Other types retain opaque RDATA under RFC 3597. Pointer-like bytes stay bytes.
The codec does not validate DNSSEC signatures or opaque type-specific payloads.

### Owner references into unknown RDATA

Approval: [#1](https://github.com/mattrobenolt/z53/issues/1#issuecomment-5548539798).

RFC 3597 section 4 permits owner compression even when a new RDATA name must remain uncompressed.
A later owner can reference an SVCB target (RFC 9460 section 2.2).
Requiring only previously decoded boundaries rejected the valid 65-byte regression packet.
Its additional A owner points to target offset 33.

An unregistered target requires every name byte to stay inside one prior opaque RDATA region.
This includes label lengths and the root terminator.
Every byte must precede the referring pointer.
Record headers separate regions. The byte mask cannot bridge them.

The fallback accepts no embedded compression pointers.
Label and total-name bounds remain 63 and 255 bytes, including any prefix before the pointer.
Only complete validation publishes decoded label boundaries.
Existing header, known-label-interior, forward, self and cycle rejection remains in place.

`Part.bytes` alone does not make data opaque.
IN A/AAAA/WKS, NULL, HINFO, TXT, SPF and OPT bytes do not supply fallback targets.
Known layout scalar, string, signature and bitmap parts are also excluded.

Unknown type/class layouts supply regions, not only SVCB.
For example, a non-IN A layout is not assumed to be an IPv4 address.
The semantic identity of an unknown field is unavailable.
Structural validity and region provenance are the explicit policy limits.

Unknown RDATA is copied byte-for-byte during rewriting.
A referencing owner is expanded and encoded afresh.
Relocation does not preserve an input offset or introduce forbidden RDATA compression.
The encoder does not register copied opaque bytes in its output dictionary.

### Expansion failure

Approval: [#1](https://github.com/mattrobenolt/z53/issues/1#issuecomment-5548287059).

The deterministic SRV test has a 255-byte name and 300 answers. Each input
SRV target points to the question. The input is 6271 bytes. RFC 3597 permits
legacy receive support, but RFC 2782 forbids compressed outbound SRV targets.
The compliant result needs 82171 bytes. The codec returns `RewriteTooLarge`.
It never uses a raw copy to evade an outbound compression restriction.

Section 3.9 fixes the later resolver policy: local SERVFAIL, no health penalty,
no failover, and no cache insertion. The resolver is not implemented here.
Representable responses remain lossless. Normal UDP truncation is separate.

### Fuzz compiler compatibility

The pinned Zig 0.16 default fuzz runner fails compilation at line 566.
It passes `builtin.StackTrace` to `debug.writeStackTrace`, which now needs
`debug.StackTrace`. A callback returning `error{}!void` did not fix this:
`std.testing.fuzz` coerces callbacks to `anyerror!void`.

The parent approved disabling returned-error tracing on the fuzz root only.
Normal unit tests keep error tracing. Runtime safety, assertions, instrumentation,
panic traces, the default runner and toolchain pins remain unchanged.
Unexpected fuzz outcomes panic. Malformed input and `RewriteTooLarge` remain
expected outcomes. Raw and structured targets run in separate test binaries.
This ensures each target receives the requested fuzz iteration budget.

### Canonical fuzz gate

From the repository root, inside `nix develop`, run:

```sh
bash scripts/fuzz.sh 20000
```

Outside the development shell, run:

```sh
nix develop -c bash scripts/fuzz.sh 20000
```

#### Coverage and result checks

The optional argument is iterations per target, not milliseconds. It defaults to 20000.
The pinned runner can overshoot a budget by a batch.
The raw target exercises malformed packets and safe rewrites.
The structured target also exercises record movement and owner references into opaque SVCB RDATA.
This is bounded coverage, not proof that all inputs are safe.

The raw Zig build exit status alone is not an acceptance signal.
The build runner can print a panic, retain a crash input and still exit zero.
The script requires a successful process status, no crash artifact and no failure diagnostics.
An empty crash input also counts as a failure.
Each target requires exactly one completed report, starting from zero and reaching the requested iteration count.

#### Retained evidence

Every invocation uses a fresh isolated cache under the ignored project-local `.tmp/fuzz/run.*` directory.
The EXIT handler prints the build log and removes the cache.
Successful runs also remove the capture directory.

Failed runs retain only these files:

- `build.log`
- `status`
- One `crash` sample, if present

An empty crash file is retained.
For a crash directory, the first regular file supplies the sample.
Empty crash directories leave no sample.
The script prints the failed evidence path.
Failure evidence remains until explicitly removed.

`status` records the build exit code.
Signal exits use these values:

- HUP: 129
- INT: 130
- TERM: 143

The build runs in a dedicated process group.
Cleanup sends TERM to that group and allows 0.1 seconds for shutdown.
It then sends KILL to any members that remain.
It waits for the build leader to exit before it removes the cache.
SIGKILL and machine failure bypass shell cleanup.

#### Manual cache cleanup

1. Preserve useful fuzz inputs and compact failure evidence first.
2. Remove compiled metadata and objects together, not only `.zig-cache/o`.
3. Leave shared toolchain and dependency caches untouched.

Partial object removal leaves stale build-runner references.
Toolchain and dependency caches are not patched.
The script assumes the pinned runner's report format.
It rejects missing or changed report formats.

#### Gate validation

`tests/fuzz-gate.sh` runs in `test-wire` and `test`.
It checks these results and artifacts:

- Successful reports
- Nonzero process status
- Failure diagnostics
- Empty-file and directory crash artifacts
- Cache removal after each supported exit path
- Capture removal after success
- Exact retained failure files and crash sample contents
- Report format
- Report completeness
- Report uniqueness
- Reused-cache reports
- Insufficient budgets
- Invalid arguments

The interruption mock includes a build leader and descendant that both ignore TERM.
Neither remains live after cleanup.
Each mock owns an isolated fixture directory.
Its EXIT handler removes all mock evidence.

An actual temporary fuzz invariant panic was rejected while the build runner reported success.
The invariant was removed before the restored bounded run.

## Configuration and suffix routing (#1)

`src/config.zig` loads typed `std.zon` structs.
Unknown fields are errors at every level.
SPEC §5.1 defines the schema and startup bounds.

Both example files remain unchanged. Tests read the actual files.
The package manifest includes `examples` so packaged tests retain both fixtures.

`cache = null` and `hosts = null` encode absence.
The reference `rotate` and `force_tcp` booleans remain schema switches, not redundant runtime state.
Numeric NODATA types use `.{ .number = N }`.
Common names retain `.AAAA` syntax.

The caller provides a source buffer and at most 4 MiB of parser storage.
The binary makes one bounded startup allocation for that workspace.
The load fails if its data does not fit. There is no allocation fallback.
The workspace holds these values:

- AST
- Zoir
- Typed values
- Strings
- Canonical suffixes

Config views live until the workspace is reused or freed.
A successful parse retains no source bytes.
Diagnostics own a fixed reason buffer and borrow only the path.
No query operation takes an allocator.

A tokenizer pass checks these bounds before the standard AST parser runs:

- Source size
- Token count
- Delimiter depth

It excludes Zig-only recursive prefix syntax and repeated negation.
These checks bound the parser's recursive grammar. The standard library remains unchanged.

Semantic validation maps Zoir field and array nodes to their actual AST locations.
It does not search for field names in source text.
Textual lookup can select the wrong source location in these cases:

- Comments
- Escaped identifiers
- Repeated nested fields

The router uses the length-prefixed Name representation.
It compares only at wire label boundaries and folds ASCII case.
It scans at most 64 zones and constructs a bounded suffix name on the stack.
It makes no heap allocation.
This is a correctness implementation, not a measured optimization.

The endpoint parser retains hostnames. It does not resolve them.
Later slices still own these features:

- Sockets
- DNS bootstrap
- Upstream transport selection
- The query pipeline

The startup CLI loads `/etc/z53/z53.zon` or exactly one `-c path` override.
Failures exit 1 and report these fields to stderr:

- Path
- One-based line and byte column
- Reason

A valid file still produces the service-not-implemented message and exit status 1.
A successful configuration load does not mean the binary serves DNS.

## Synthetic answers, hosts, and rotation (#1)

Class policy approval: [#1](https://github.com/mattrobenolt/z53/issues/1#issuecomment-5549680247).
RFC 6761 intercepts every class and emits IN records. The question retains its class.
NODATA matches every class. Hosts serves only IN and otherwise falls through.
CH follows the ordinary pipeline.

CoreDNS 1.14.6 local has no class guard and emits IN records.
CoreDNS hosts also has no class guard.
IN-only hosts is therefore an explicit approved deviation, not a parity claim.

`src/resolver.zig` exposes two synchronous seams after zone routing:

- `beforeCache`: RFC 6761 hit, or proceed to cache lookup.
- `afterCache`: called only on a cache miss. The remaining stages run in this order:
  1. NODATA
  2. Hosts
  3. Forward

Synthetic encoders echo the question.
They also echo the client's EDNS payload size and COOKIE.
They apply these flag rules:

- Set AA.
- Clear RA/AD.
- Preserve RD/CD.

Source policies prohibit synthetic cache insertion and prohibit RFC 6761/NODATA rotation.
These seams do not implement the cache or forward stage.
The runtime must obey the documented order and end a hit immediately.

Hosts storage uses two caller-owned disjoint entry arrays.
Each array holds at most 4096 address/name pairs.
The source buffer holds at most 1 MiB plus one overflow byte.
No query operation allocates.

Loads parse the inactive table and publish only on success.
Publication is a synchronous event-thread swap, not a cross-thread atomic pointer.
Readers cannot retain table views across replacements. Old data and mtime survive errors.
The load API performs these steps:

1. Open a regular file.
2. Compare mtime.
3. Read within the bound.
4. Recheck these fields before publication:
   - Size
   - Mtime
   - Ctime

Detected mid-read changes are retryable errors.
This is not a filesystem snapshot or a guarantee against writers who deliberately restore metadata.
Real-file tests use isolated temporary directories and deterministic mtime changes.
Io fault injection tests cover a torn read and read failure. They do not modify std.

Entries retain these fields:

- Canonical name
- Reverse name
- Address bytes

Aliases get PTRs. Identical pairs collapse. Malformed lines are skipped as a whole.
Lookup and load deduplication use bounded linear scans. There is no performance claim.

Rotation partitions only answer-record indices into these groups, in order:

1. CNAME
2. Other records
3. A/AAAA
4. MX

Only the last two groups shuffle. The caller supplies the random source.
Authority and additional records retain order. Extended EDNS error codes also inhibit rotation.
The wire rewriter relocates compressed names and retains opaque bytes.
Raw record byte spans are never shuffled.

Forward responses gain RA and retain AA. Cache responses retain stored flags.
The runtime must apply `Source.forward.responseBits` before cache insertion, so cached forwarded data already carries RA.
Final delivery uses the same normalization. Each cache delivery shuffles afresh.
The input header is restored even on rewrite failure.

Full-size hosts encoding failure is `RewriteTooLarge`, not truncation.
Smaller caller buffers use `NoSpace`.

Later runtime work still owns these responsibilities:

- Startup table allocation and initial file-load error policy
- Configured periodic checks (default five seconds, zero disabled)
- Listener/transport I/O
- Cache integration
- Final client UDP limits and COOKIE policy on forwarded/cache answers
- Random seeds
- Logs

No event loop or service endpoint is introduced in this slice.
Existing wire fuzz targets remain unchanged and continue to exercise safe record movement and malformed packets.

## Per-zone cache (#1)

`src/cache.zig` supplies synchronous cache seams, not a DNS service.
The runtime creates one instance per validated zone and supplies monotonic whole seconds.
An expired lookup returns a miss.
Only `terminalFailure`, after transport exhaustion, serves stale data.
An upstream SERVFAIL uses `forward`, without stale fallback.

SERVFAIL entries expire after five seconds and are not stale candidates.
The grace interval includes expiry and excludes expiry plus grace.
Subtraction avoids overflow.

Each enabled cache allocates two fixed entry arrays at startup.
Positive and denial entries have independent capacities and intrusive LRU lists.
SERVFAIL consumes denial capacity.
A successful replacement removes the same key from the other bank.
Lookup scans bounded arrays.
Eviction and recency updates use links.

This is a correctness implementation, not a measured lookup optimization.
Each entry owns one rewritten packet, at most 65535 bytes.
Entry metadata has a tested upper budget of 320 bytes.
Live storage is bounded by `2 * capacity * (sizeof(Entry) + 65535)`, exclusive of allocator overhead.
Transactional insertion briefly owns at most one additional packet of 65535 bytes.

Insertion allocates before eviction.
Exhaustion returns the already-encoded answer with `insertion=exhausted`.
Startup failure rolls back its earlier allocation.
The event thread supplies a fixed packet/rewrite workspace and disjoint output storage.
These operations make no heap allocations:

- Fresh lookup
- Miss
- Stale delivery

The key retains these fields:

- Framed name labels
- Class
- Type
- Named DO state

Name comparison folds ASCII case.
Dots inside labels do not alias separators.
Positive expiry is the smallest clamped non-OPT record TTL.
Every non-OPT TTL is clamped and aged.
OPT flags are not TTLs.

NXDOMAIN and empty NOERROR use authority SOA TTL/MINIMUM, with a fixed five-second floor.
CNAME and DNAME redirection chains with authority SOA also use denial policy when they lack terminal query data.
Actual answers to these query types remain positive:

- CNAME
- DNAME
- ANY

The positive maximum also caps the denial maximum.
These responses bypass insertion:

- Denials without an SOA
- Truncated responses
- Error RCODEs other than NXDOMAIN and SERVFAIL

`forward` accepts only responses already admitted by the future forward stage.
It normalizes RA and clamps TTLs.
It proves full-size client rewrite before cache insertion.
The stored packet uses ID zero and the admitted query question, with no OPT.
Each delivery reconstructs these client fields:

- ID
- Question
- EDNS payload size
- DO
- COOKIE

Delivery cannot reuse another client's COOKIE or upstream payload size.
Stored header flags otherwise survive hits.
Fresh deliveries age TTLs.
Stale deliveries use TTL 30.
Local parse/encoding errors return without publication or terminal-failure handling.
A failed stale rewrite also leaves the stale candidate unchanged.

### Extended RCODE delivery

Approval: [#1](https://github.com/mattrobenolt/z53/issues/1#issuecomment-5550142068).

RFC 6891 section 6.1.3 places the upper RCODE bits in OPT.
A client without EDNS cannot receive a nonzero extended RCODE.
The cache forward seam returns local SERVFAIL with no OPT and source `servfail` in this case.
It never substitutes the low four RCODE bits for the complete error.
Clients with EDNS retain the complete RCODE.

This local failure bypasses cache insertion and stale fallback.
Existing fresh and stale entries remain unchanged.
The later runtime applies no failover or upstream health penalty.
Deterministic regressions cover these cases:

- BADVERS and nonzero low RCODE bits
- Enabled and disabled caches
- Fresh and stale positive and denial candidates
- Client EDNS and COOKIE preservation

Only the forward and terminal-transport seams can insert.
The synthetic seams remain unchanged.
`Source.stale` and `Source.servfail` identify later log sources.
The runtime still owns these tasks:

- Complete pipeline integration
- Upstream attempts before stale fallback
- Final answer rotation
- Client UDP limits
- Logs
- Listener and transport I/O
- Upstream health accounting

No service endpoint is added here.

## Linux local client runtime (#1)

`src/runtime.zig` owns one event thread and one io_uring instance.
Setup uses `SINGLE_ISSUER` and `DEFER_TASKRUN` unconditionally.
Setup failure aborts startup without probes or fallback.
SPEC §1.1 lists fixed resource bounds.
The query path has no allocator calls.
Cache instances and disjoint hosts tables allocate only at startup in this slice.

Unconnected UDP listeners use multishot RECVMSG and a non-incremental provided buffer ring.
Each completion retains the source address and the original listener identity.
The decoder validates recvmsg metadata before the wire codec sees the payload.
A response slot owns its output and destination until send completion.
The provided input buffer returns immediately after synchronous response construction.
Response-slot exhaustion drops the datagram without an overflow queue.

The provided-ring helper receives `inc=false` unconditionally.
Its incremental compatibility retry branch is unreachable with that argument.
ENOBUFS ends the receive operation and triggers rearm with a new completion generation.
Zero-copy send remains absent because no measurement justifies it.

TCP listeners use multishot direct accept into 128 registered client slots.
The registered allocation range bounds undispatched accepts without unbounded process-descriptor use.
A full range pauses admission until a client close completes.
Each connection reads one framed query and writes its complete response before the next query.
Partial frame reads and response writes retain offsets in fixed buffers.
Coalesced queries remain in the socket until their turn.

Direct-close completion and a subsequent accept can reach userspace in either order.
The client lifecycle records a replacement until the preceding close completion arrives.
Operation generations advance only after terminal completion.
Cancellation requires both the target completion and the cancel acknowledgement before slot reuse.
A generation never wraps into an earlier token.

The runtime stop API drains cancellation acknowledgements and target completions.
Daemon signals still rely on process teardown rather than the stop API.
Fatal teardown uses synchronous io_uring cancellation before storage release.
After synchronous cancellation, teardown explicitly unregisters the file table before ring destruction.
This releases listener and direct-accept references, even for unread accept completions.
Ring close alone defers file release and prevented immediate UDP rebind in the native regression.

Teardown accepts an absent file table when startup failed before registration.
A failed cancellation or file-release barrier exits the process without release of kernel-visible memory.
Startup rollback releases earlier tables and listener descriptors.

TCP listeners set `SO_REUSEADDR` before bind so server-side close and TIME_WAIT do not block configuration restarts.
UDP does not enable address reuse, and neither transport enables port reuse.
Concurrent UDP and TCP listeners on the same endpoint remain rejected.

Native regressions perform 16 same-port service cycles with server-side TCP close.
Each restart is immediate, with alternate cycles for drained shutdown and direct teardown.
Another 16-cycle regression fails a later listener's TCP bind.
It immediately rebinds the registered earlier listener and the unregistered UDP socket.
Neither restart regression sleeps or retries a failed bind.

Both restart regressions failed before explicit file unregistration.
With only that fix, the active-close regression still failed at TCP bind.
TCP address reuse made both pass.

### Pinned standard wrapper discrepancy

The pinned `IoUring.register_file_alloc_range` passes `sizeof(io_uring_file_index_range)` as `nr_args`.
Linux and liburing require zero for this opcode.
The native transport tests initially failed with EINVAL through that wrapper.
The proctor calls `std.os.linux.io_uring_register` directly with zero and initialized reserved fields.
The same native direct-accept tests then passed.

Installed source and dependency caches remain unchanged.
Toolchain pins remain unchanged, and no compatibility fallback was added.

### Local response pipeline and remaining scope

The runtime routes first and returns REFUSED without a matching zone.
A matching zone runs these stages in order:

1. RFC 6761
2. Cache lookup
3. NODATA
4. Hosts

Local hits finish synchronously before buffer reuse or hosts replacement.
Rotation precedes final UDP payload limits.
Final UDP limits also cap IPv4 at 65507 DNS bytes and ordinary IPv6 at 65527 bytes.
The socket uses fixed IP headers without extra options or jumbograms.
The existing codec truncates whole RRsets and retains the client's OPT payload size.
TCP retains the full representable answer.

An unresolved forward stage returns uncached SERVFAIL without stale fallback or upstream health effects.

Enabled hosts sources load before socket setup.
Initial file failures abort startup even with zero reload interval.
A monotonic io_uring timer schedules configured periodic checks.
Failed checks preserve the active table and mtime.
Zero disables periodic checks but not the initial load.

Listener hostnames remain valid configuration.
This slice rejects them with `UnresolvedListener` at startup.
The rejection is temporary, not a schema restriction.
Later bootstrap work must resolve both listener and upstream hostnames.
No blocking socket I/O exists beneath the proctor.
The accepted synchronous hosts file API remains on the event thread.

Later slices retain these obligations:

- Listener and upstream hostname bootstrap.
- Forward transports and linked upstream read timeouts.
- Upstream health and connection reuse.
- Forward-cache publication and stale integration.
- Per-query logs and upstream transition logs.
- macOS kqueue runtime.
- Remaining end-to-end SPEC acceptance.

Native tests cover these behaviors:

- Linux transport events
- Timer reloads
- Pool exhaustion
- Malformed input
- Cancellation

Temporary mutations rejected defects in these areas:

- Generations
- Cancellation barriers
- Framing bounds
- Metadata bounds
- Startup errors
- Rollback
- Reload disablement
- UDP limits
- Receive rearm

A burst alone did not reliably exhaust provided buffers because completion handling recycled them.
The deterministic depletion regression withholds the initial buffer batch before the first submission.
It observes ENOBUFS, rearm, buffer publication, and a successful response.
No resolver performance claim accompanies these checks.
