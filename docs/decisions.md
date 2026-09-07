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
- Listener DNS bootstrap
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

Each enabled cache allocates two fixed `std.MultiArrayList` banks at startup.
Positive and denial entries have independent capacities and intrusive LRU lists.
SERVFAIL consumes denial capacity.
A successful replacement removes the same key from the other bank.
Lookup scans dense fingerprint columns through `std.mem.findScalarPos` and checks complete keys at matching slots.
Eviction and recency updates use stable slot links.

Each entry still owns one rewritten packet, at most 65535 bytes.
Allocated metadata has a tested upper budget of 320 bytes per configured slot.
Live storage is bounded by `2 * capacity * (320 + 65535)`, exclusive of allocator overhead.
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
Fatal teardown originally treated synchronous cancellation and file unregistration as sufficient barriers before storage release.
The submitted-receive regression disproves the expected immediate CQE publication, not an observed access after free.
The Linux teardown correction below adds request retirement before file unregistration.
Unread direct accepts retain their file-table references until that unregistration.
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
Later bootstrap work must resolve listener hostnames. Upstream addresses remain literal IPs under the cache-baseline decision below.
No blocking socket I/O exists beneath the proctor.
The accepted synchronous hosts file API remains on the event thread.

Later slices retain these obligations:

- Listener hostname bootstrap.
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


## macOS local client runtime candidate (#1)

The platform facade selects `runtime_linux.zig` or `runtime_darwin.zig` at compile time.
The Linux runtime was moved byte-for-byte from `src/runtime.zig`.
Its address helper, proctor, framing, ownership, and native transport tests remain unchanged.
This includes explicit registered-file teardown and TCP address reuse for restarts.

macOS uses one kqueue through Zig 0.16 `std.c`, with no event-loop dependency.
Socket calls are nonblocking. Readiness is one-shot and each rearm advances the shared
non-wrapping operation generation. One event is fetched per step, so no userspace batch
retains a descriptor reference across close/reuse. EV_EOF still runs recv so buffered
TCP frames drain before zero-length receive closes the connection.

SPEC §1.2 documents its fixed operation, descriptor, and buffer budgets.
UDP reads use one event-thread scratch buffer; response slots own the destination,
listener identity and output until send succeeds or fails. EAGAIN/EINTR retain output.
One write filter per listener drains its bounded response slots without replacing udata.
TCP shares the existing length framing and partial-write state machine.
Full admission pauses without accepting an extra process descriptor.
The relative one-second timer also retries resource-limited admission without busy looping.

Darwin socket creation and accept require explicit fcntl for nonblocking and close-on-exec.
SO_NOSIGPIPE prevents peer close from terminating the event thread.
The pinned std.c.IPV6 is void on Darwin. `address_darwin.zig` names IPV6_V6ONLY=27,
verified against the pinned toolchain's bundled
`libc/include/any-darwin-any/netinet6/in6.h`. No installed source or pin changed.

EV_DELETE is the synchronous readiness cancellation barrier.
Neither kevent nor a pending registration borrows query buffers.
Fatal and startup teardown closes kqueue and every owned socket before releasing storage.
Runtime.stop remains an explicit API; daemon signals still rely on process teardown.
The local pipeline, hosts startup/reload policy and unresolved-forward SERVFAIL are shared.
Listener hostname bootstrap, upstream I/O/health, forward-cache/stale integration and logs remain later work.

### Candidate evidence and blockers

Darwin runtime and test roots pass `-target aarch64-macos -fno-emit-bin` semantic compilation
on aarch64 Linux. This is neither Darwin linking nor native execution.
The native-CI regressions cover timer deletion, registration/setup failure, socket flags,
pool exhaustion/recovery, repeated restart/rollback, UDP/TCP framing, malformed input,
hosts reload, IPv6 half-close and original-listener reply identity.
The initial candidate lacked native execution and Darwin-specific negative controls.
The native acceptance record below supplies that later evidence.

Two added platform-independent tests ran on Linux and rejected five temporary mutations:
stale generation admission, duplicate terminal release, short frame admission,
partial receive overrun and partial send overrun. Shared source was restored byte-for-byte.
No wire fuzz target, malformed-input test, assertion or runtime safety mode was removed.

The candidate full Linux suite failed its two unchanged immediate-restart regressions
at UDP bind. Other runtime tests passed (20/22), as did other suites.
Three bounded comparison runs then passed: candidate focused restarts, exact accepted
baseline focused restarts, and exact baseline full suite with matching `-j2`.
These passes do not explain or withdraw the observed failure.
No endpoint/errno/cycle diagnosis was captured by the original tests.
Socket/load snapshots and source hashes accompany the run artifact.
This remains an unresolved Linux release blocker, separate from the later Darwin acceptance.
No bind retries, sleeps, UDP address reuse or weakened regressions were added.
There is no resolver performance claim.


### Native ARM macOS CI preparation (#1)

The `test/darwin-runtime` branch supplies a focused `macos-15` workflow.
GitHub documents this label as ARM64 and lists `macos-15-intel` separately.
The job requires `uname -m` to return `arm64` and records the exact Git head and source hashes.
Action references use verified repository commit hashes.
The workflow uses read-only repository permissions, no retained credentials, and no private cache or deployment access.

The retained-send regression submits four UDP queries through the real Runtime, across two listeners and two client sources.
A test-only errno field injects EAGAIN before `sendto` and disappears from production storage.
This is injected errno evidence, not kernel backpressure evidence.
Real kqueue write events retry retained responses before native `sendto` delivers their original bytes and destinations.
The test checks one write filter per listener and release of every response slot.

The deletion regression arms an already-ready socket and calls `remove`.
A zero-time kernel poll must return no event before any close or replacement registration.
A distinct timer supplies the sentinel event.
A later `dup2` operation reuses the descriptor, and a new registration reuses the operation slot with its next generation.
Separate native events exercise stale identity and generation rejection.

The accept-quota regression lowers the real descriptor limit after the client connects.
Admission must remain unarmed after quota failure.
The next real timer restores admission after the limit returns to its previous value.
A fresh connection then serves a framed query after the timer restores admission.
The fixture also records and checks the original client's terminal receive result.

Each native command has a 180-second execution deadline and a separate process group.
Bounded teardown follows that deadline.
The runner rejects zero-exit crash diagnostics, incomplete suite reports, and unexpected Darwin skips.
Each command retains at most 2 MiB of output.
Compiler objects do not survive a completed batch, and generated storage has a 1 GiB limit.
Artifacts contain only compact logs, statuses, source hashes, and bounded crash samples.

Harness teardown first allows 25 seconds for cooperative cleanup of its detached fixtures.
A separate SIGUSR1 latch avoids the harness's intentional signal tests.
Safe checkpoints propagate cancellation outside cleanup blocks.
Ordinary teardown allows 0.5 seconds for TERM and five seconds for the final reap.
Real Linux cancellation tests cover active fixtures, cleanup, and intentional signal-handler overrides.
The native acceptance record below includes Darwin cancellation evidence.

Controls run one at a time in an owned detached worktree at the exact published head.
Each control requires one exact source match and the named test's intended assertion failure.
Only exit 1 with the intended assertion report satisfies a control.
A signal, crash, leak, compile failure, or deadline does not satisfy a control.
Each `finally` block restores the original bytes and checks source hashes and the index.
After ordinary control completion or failure, the restored full suite and both lint invocations follow.
Cancellation restores the source and completes cleanup without new validation.

The finite controls cover these paths:

- Retained UDP release, listener selection, and write-filter ownership
- Kernel deletion, stale identity, and stale generation
- Nonblocking, close-on-exec, and SIGPIPE flags
- Startup rollback and reload disablement
- External and embedded datagram metadata lengths
- Buffered EOF delivery
- Accept-quota pause and timer recovery
- Nonzero `SO_ERROR` rejection after a controlled TCP reset
- Preservation of a second queued frame by the test reader

The installed ast-grep Zig parser rejected the relevant control patterns or produced ERROR nodes.
The controls therefore use exact byte replacements with unique-match checks, not approximate syntax rewrites.
Local semantic compilation can reject invalid mutations but cannot prove their native assertion failures.

Publication initially permitted native evidence collection without implementation acceptance.
The acceptance record below supersedes that restriction for the local-runtime slice only.
The unexplained Linux UDP `BindFailed` results remain release blockers.
The passing instrumented D1 run supplied no failed-endpoint ownership capture and remains inconclusive.
No Linux runtime behavior, dependency pin, deployment module, or example changes accompany this preparation.

### Native fixture semantics (#1)

Run 33966889564 records 27 runtime passes, two failures, and four approved skips.
The original TCP `NOTCONN` and retained UDP delivery cases pass in that run.
Quota recovery still fails after four post-rearm steps, despite an armed accept filter and advanced timer generations.
The new bound-port test reports `ConnectDeadline`, not its original expected `ConnectFailed`.
Neither failure is classified as intermittent noise.

Apple's public [XNU accept implementation](https://github.com/apple-oss-distributions/xnu/blob/xnu-11417.140.69/bsd/kern/uipc_syscalls.c#L551-L635)
removes the connection from the queue before `falloc`.
Allocation failure calls `soclose` instead of queue restoration.
SPEC §1.2 requires timer-restored admission, not survival of that discarded client.
The quota fixture preserves exact pause and generation assertions before a fresh recovery connection.
A bounded receive on the original client requires EOF or `ECONNRESET` and records the actual result.
The accepted descriptor flags and framed response remain required.

The [TCP input path](https://github.com/apple-oss-distributions/xnu/blob/xnu-11417.140.69/bsd/netinet/tcp_input.c#L2465-L2469)
drops packets for `TCPS_CLOSED` without a reset.
TCP attachment starts in that state, and bind does not enter `LISTEN`.
The reserved, non-listening endpoint therefore tests the helper's exact deadline result, not refusal or `SO_ERROR`.
This is not a general contract for all unavailable endpoints.

A separate fixture establishes TCP, accepts the connection, and closes the accepted peer with enabled zero linger.
[XNU `tcp_disconnect`](https://github.com/apple-oss-distributions/xnu/blob/xnu-11417.140.69/bsd/netinet/tcp_usrreq.c#L3150-L3164)
uses `tcp_drop` for this case.
The fixture waits for read readiness without a receive, then requires rejection through the shared `finishConnect` check.
[`SO_ERROR`](https://github.com/apple-oss-distributions/xnu/blob/xnu-11417.140.69/bsd/kern/uipc_socket.c#L6051-L6054)
returns and clears the pending error.
This tests a real asynchronous socket error, not necessarily a failed `EINPROGRESS` handshake.
The seventeenth finite control ignores positive socket errors and requires the named assertion failure.
The original 16 controls and their strict gate remain unchanged.

The cited public tag is `xnu-11417.140.69`.
The native runner reports `xnu-11417.140.69.711.44~1/RELEASE_ARM64_VMAPPLE`.
Source inspection explains the fixture corrections but does not establish exact patch-level equivalence.
The native acceptance record below includes these corrections and the additional frame-reader control.
No production runtime change accompanies these fixture corrections.

### Native local-runtime acceptance (#1, #2)

Matt approved the Darwin local-runtime slice and its merge after native CI and physical MacBook validation.
The unexplained Linux restart failure remains a release blocker.
The approval permits work on upstream transport without further diagnostic calibration.
It does not grant deployment or full SPEC acceptance.

[ARM CI run 33989708897](https://github.com/mattrobenolt/z53/actions/runs/33989708897)
tested commit `953447d0fa00120e76d255815fc66f1c9d7fbf22`.
The physical MacBook tested the same commit.
Both hosts ran the full suite before and after the finite controls.
Each full run passed 133 tests, with 23 Darwin cases and four approved Linux-only skips.
All 18 controls failed at their designated assertions without a crash or deadline.
Every restoration matched all 82 published source hashes.

The physical MacBook archive has SHA-256 `251e0d4e3276d11422698321bfedec13efdbb935c475741847249b242c2b3edc`.
Its full runs completed in 102.228 and 97.901 seconds under the unchanged 180-second deadline.
The audit reconciled individual test reports with suite totals and inspected each control's first project frame.
Native builds and the harness cleanup checks also passed.

An earlier MacBook run failed while the client awaited two TCP responses.
The test reader consumed extra frames and discarded bytes after the first frame.
The corrected reader receives only one prefix and declared payload.
A deterministic regression queues two complete frames before its first read.
The eighteenth control restores the old reader and fails at the remaining-frame assertion.
The original log lacks byte counts, so its exact failure mechanism remains unconfirmed.

Injected EAGAIN does not prove actual kernel backpressure.
The reset fixture proves nonzero `SO_ERROR`, not a failed handshake.
The helper benchmark and fuzz-gate smoke tests do not establish resolver performance or decoder fuzz coverage.
The earlier Linux failure and inconclusive D1 result remain preserved.
No additional Linux diagnostic follows from this acceptance.


## Literal forced-TCP forwarding candidate (#1)

This candidate supports a zone only when every configured upstream uses a literal address, forced TCP, and no TLS.
It preserves configured order and attempts each member at most once per transaction.
An unsupported zone miss remains uncached local SERVFAIL without stale fallback or health effects.
Local responses and cache hits retain their existing pipeline order.
Health exclusion and probes remain incomplete even for supported zones.
Ordinary UDP upstreams, DoT, listener hostname bootstrap, and logs remain later work.

### Ownership and bounds

SPEC sections 1.1 through 1.3 replace the earlier local-only resource limits.
Both backends own 32 transactions and 32 reusable sessions without an overflow queue.
A transaction copies the original query before the listener returns or reuses its input buffer.
UDP response slots reserve their destination and generation before asynchronous admission.
TCP clients retain a connection generation and wait for response delivery before the next query.
A disconnected client can retain its slot until its bounded exchange completes.

Each session owns its framed input and output buffers.
Only an idle session permits eviction, and an accepted response retains its session until client publication.
Endpoint identity includes the configured zone and upstream position, not only the address text.
The startup endpoint table uses 1024 entries of 32 bytes each.
The forwarding object occupies 6326480 bytes on aarch64 Linux.
The Linux Runtime occupies 33144744 bytes before external zone metadata and ring mappings.

Compile-time assertions include the backend metadata in the 8 MiB forwarding cap.
The 40 MiB combined cap includes 14336 bytes of maximum zone metadata and a 256 KiB allowance for Linux mappings.
The native ring requests 18496 shared bytes, 32768 SQE bytes, and 1024 provided-ring bytes before page rounding.

Configuration storage, the entire cache, and hosts tables retain separate bounds.
The cache exclusion covers allocated entry arrays and packets.
SPEC §1.3 states the separate cache limits, including the transient insertion packet.
Kernel socket memory is outside these userspace caps.
These sizes are storage evidence, not performance measurements.

### Completion and deadline rules

Linux retains provided-buffer multishot UDP and the direct-accept file range at 32 through 159.
Upstream files occupy 160 through 191.
Operation slots 225 through 288 form 32 I/O and timeout pairs, with the idle timer at 289.
Both linked completions retire before rearm, close, failover, or file reassignment.
Each explicit cancellation also retains its target completion and acknowledgement through the existing ownership state machine.
Stop batches cancellations against the remaining SQ capacity, including queued work.

Connect and request transmission share one absolute configured budget.
Complete transmission starts a separate response deadline across prefix, body, and rejected frames.
Linux uses `IORING_TIMEOUT_ABS` for linked operations and idle expiry.
Relative timeouts can gain time while their SQEs wait for submission, so the kernel receives the absolute monotonic deadline.
The native exchange assertion rejected the missing ABS flag before the correction.
Fatal and startup teardown now require the additional request-retirement barrier described below.

Darwin uses one-shot socket interests and SO_ERROR for connect completion.
Its separate upstream timer selects the nearest nanosecond deadline.
EV_DELETE precedes replacement of a deadline timer or socket identity.
The original one-second hosts and admission timer remains separate.
No new socket operation blocks or allocates on the established path.

### Admission and publication

A startup-seeded CSPRNG supplies each upstream ID independently of answer rotation.
`Io.randomSecure` supplies the entire seed without a weak fallback.
Entropy failure or cancellation aborts startup before event queue or listener creation.
A deferred secure erase covers the seed lifetime on success and failure.

Tests compare the encoded ID with transaction ownership, not with an assumption that random IDs always differ from client IDs.
Admission requires the connected endpoint and generation, ID, QR, opcode, and exactly one matching question.
Question comparison preserves DNS case-insensitive name equality and exact type and class.
Malformed and mismatched frames never reach cache publication or renew the deadline.

Each admitted DNS response ends failover, including upstream SERVFAIL.
Only actual supported transport exhaustion enters the stale or terminal SERVFAIL policy.
Pool exhaustion, socket resource failures, and local encoding failures remain uncached without stale fallback.
Upstream queries retain all validated client options and DO, with payload size 1232.
Final responses restore the original client ID, question, payload size, and COOKIE.

Cache preparation now separates full-size response construction from publication.
The runtime completes rotation and client encoding before it commits the prepared cache packet.
The rotation regression moves opaque padding before repeated address owners, beyond the encoder dictionary range.
The full client rewrite then fails without replacement of its stale candidate.
The publication-order mutation fails at that candidate's pointer identity assertion.
Extended-RCODE exclusions retain their earlier policy and native coverage.

### Candidate evidence and limits

The native Linux fixtures use owned loopback peers and actual Runtime sockets.
They cover both client transports, concurrent identities, partial frames, queued client queries, reuse, expiry, failure-only sequence, and cache policy.
They also cover EDNS envelopes, large UDP truncation, full TCP delivery, pool exhaustion, descriptor quotas, and cancellation in each upstream phase.
The cache-disabled exchange and cache-hit tests reject allocator use after startup.
Partial transmit bounds have deterministic state-machine tests, but the fixtures do not force kernel-induced short upstream sends.
Native macOS execution remains pending and belongs to parent CI.

The additional IPv6 fixture first failed at its owned `[::1]:0` bind on Linux.
A separate owned bind returned EADDRNOTAVAIL, errno 99.
Both Linux IPv6 disable flags equal one, and the interface table is empty.
The supervisor approved explicit Darwin-only native scope for that fixture without host changes or general feature probes.
Native Linux IPv6 exchange coverage remains unproved. Semantic compilation does not replace it.
The failed run and its diagnosis remain preserved.

That failure also exposed a fixture cleanup leak before Runtime startup.
The fixture now owns cleanup immediately after preparation and distinguishes `prepared`, `running`, and `released` states.
A Linux error-path regression checks allocation balance and descriptor release after startup rejection.
Its storage-release mutation fails at the allocation counter assertion, without a leak as the acceptance signal.
An independent deferred release cleans the omitted allocation after that assertion.

The original 18 Darwin controls retain their exact source spans and assertion intent.
No workflow, watchdog, native gate, example, or dependency lock changes accompany this candidate.
One new control initially searched a multiline argument absent from the stack excerpt.
Its existing first project frame proved the intended deadline assertion without a rerun.
A broad ordinary-timeout mutation exceeded the control deadline before its intended assertion and supplies no red proof.
The revised read-phase mutation reaches and fails the opcode assertion. Both logs remain preserved.

The unresolved historical Linux restart failure remains a release blocker.
An earlier candidate full suite passed 146 tests. That pass does not explain or withdraw the historical failure.
No diagnostic calibration, production deployment, or primary-checkout changes accompany this slice.

### Fresh candidate blocker

The final restored Linux suite passed 147 tests and failed two tests, including 46 runtime passes out of 48.
Both failures occur at the UDP bind in `runtime_linux.zig`, through `address.zig`.
The server-close restart case fails at `tests/runtime_transport.zig:157` after 26.26 milliseconds.
The partial-initialization restart case fails at `tests/runtime_transport.zig:206` after 34.80 milliseconds.
The tests do not report the endpoint, errno, or cycle. Those values remain unavailable.

This is a fresh unclassified failure after the forwarding changes.
Matching historical test names do not establish a shared cause.
All forwarding cases pass within that failed full run, but the candidate does not pass implementation acceptance.
The supervisor directed a blocked handoff without another native test or new instrumentation.
Only static checks, semantic compilation, preservation, and evidence finalization follow that direction.
The failed run remains preserved and blocks publication.


### Linux teardown retirement correction (#1)

Overall candidate acceptance remains **BLOCKED**.
The original submitted-receive run unexpectedly failed its regression assertion. It was not a mutation control.
It recorded cancellation result 1, no published target CQEs, upstream EAGAIN, and client EOF.
That observation establishes neither access after free nor a cause for either earlier bind failure.

The reviewed sources use upstream Linux `v7.2.3`, not an attested copy of the host kernel.
The same allocation-based drain mechanism exists at the `v7.2` floor.
[`io_queue_deferred`](https://github.com/gregkh/linux/blob/v7.2.3/io_uring/io_uring.c#L457-L478)
flushes cached requests and requires `nr_req_allocated == nr_drained` before dispatch.
One final standalone `NOP` with `IOSQE_IO_DRAIN` therefore waits for all older request objects, not just their CQEs.

[`io_free_batch_list`](https://github.com/gregkh/linux/blob/v7.2.3/io_uring/io_uring.c#L1094-L1168)
releases operation resources and resource-node references before request caching.
A worker-held reference also blocks the marker, through its CQE-less last-put cleanup.
See [`io_wq_free_work`](https://github.com/gregkh/linux/blob/v7.2.3/io_uring/io_uring.c#L1457-L1471).

Teardown completely consumes older SQEs before cancellation and marker preparation.
Each of at most 512 submission attempts must consume at least one SQE.
A separate submission prevents linkage to older work, even after a partial submission.

The marker uses token `0xffffffffffffffff`, outside all normal and cancellation owner indices.
Its opcode-specific flags are zero. It borrows no payload, file, or buffer resource.
No later SQE follows it. Reserved-only and synthetic owners require no fabricated completion.

One five-second absolute MONOTONIC deadline starts before teardown work.
Cancellation receives the remaining relative duration, not the DNS response timeout.
See [`io_sync_cancel`](https://github.com/gregkh/linux/blob/v7.2.3/io_uring/cancel.c#L272-L369).
Kernel waits use `GETEVENTS | EXT_ARG | ABS_TIMER` with that same absolute deadline.

The ring defaults to MONOTONIC, and [`io_cqring_wait`](https://github.com/gregkh/linux/blob/v7.2.3/io_uring/wait.c#L189-L235)
converts absolute time through the time namespace.
Pinned Zig lacks `ABS_TIMER` and fixes its enter wrapper argument size to `NSIG/8`.
The raw six-argument syscall uses UAPI bit 5 and the 24-byte `io_uring_getevents_arg`.
Its zero `pad` field matches the newer UAPI `min_wait_usec` field.

Teardown copies CQEs in 32-entry stack batches without Runtime dispatch or buffer recycling.
The 2048-CQE ceiling exceeds this conservative producer sum of 1925:

- 1024 already published CQEs
- 290 terminal target CQEs
- 290 explicit cancellation acknowledgements
- 64 provided-buffer UDP shots
- 256 successful direct accepts
- One marker CQE

The 128 client file slots permit 128 accepts, plus at most 128 replacements after already queued direct closes.
No teardown dispatch submits another close or returns a UDP buffer.
Terminal accept errors and linked timeouts use the existing 290 target allowance.
The CQ reader permits at most 4097 iterations, with at most one wait per nonempty batch.
A wait requests one completion only when the published CQ is empty. It does not busy-poll or add arbitrary enters.
Overflow-list entries also count against the ceiling. Excess entries fail closed rather than extend the proof bound.
This ceiling is a termination bound, not native evidence for full-capacity teardown.

Marker result zero and flags zero precede checked file unregistration.
The absent-file-table startup case remains valid.
Checked provided-ring unregistration precedes metadata unmapping, unlike the unchecked Zig helper.
Every payload and mapping remains alive through both barriers.
Runtime then retains its existing listener-close and Pipeline-release order.
Errors or deadline exhaustion exit without storage-release unwinding.

The final-file guarantee depends on the actual sole-submitter context with `SINGLE_ISSUER | DEFER_TASKRUN`.
Ordinary `fput` queues final release on the live submitter before return to userspace.
See [`file_table.c`](https://github.com/gregkh/linux/blob/v7.2.3/fs/file_table.c#L484-L590)
and [`resume_user_mode.h`](https://github.com/gregkh/linux/blob/v7.2.3/include/linux/resume_user_mode.h#L40-L50).
Current opcodes are:

- RECVMSG and ACCEPT
- RECV, SEND, and SENDMSG
- CONNECT and direct CLOSE
- TIMEOUT and LINK_TIMEOUT
- ASYNC_CANCEL

Production creates sockets through `socket()` and registration, without `IOSQE_ASYNC` or zero-copy operations.
Future SOCKET, zero-copy, forced asynchronous closes, or another issuer requires a separate context proof.

The existing submitted-receive fixture retains real SEND, RECV, and LINK_TIMEOUT operations on listenerless socketpairs.
A bounded external transcript captures the actual marker and retired CQEs.
Its snapshot freezes that transcript after file unregistration, before metadata release.
The snapshot performs one nonblocking read per silent, drained peer.
Assertions follow unconditional direct Runtime teardown and destruction.

Observation-order controls move only the snapshot. Every real barrier and cleanup still executes.

This one-pair proof does not establish native full-capacity or delayed-worker behavior.
Error branches, synthetic-owner regressions, unread accepts, startup, native Darwin, and full gates remain separate proof slices.
Earlier frame, entropy, driver-order, and failed-run evidence remains unchanged.

## UDP forwarding POC (#1)

The POC adds plain literal UDP upstreams through the existing session pool and event drivers.
Connected datagram sockets retain kernel source filtering. Response admission still checks the ID and question.
Each datagram contains one DNS message, without the TCP length prefix.
Malformed datagrams do not restart the response deadline.

TCP clients use TCP upstream sockets, even when `force_tcp` is false.
Session reuse requires both the configured endpoint and the transport to match.
A truncated UDP answer returns to the client without automatic TCP fallback or cache insertion.
Its client TCP retry can then obtain the full answer.

This stage replaces the earlier whole-zone support restriction.
A later TLS or hostname member no longer disables an earlier supported member.
Selection of an unsupported member returns uncached local SERVFAIL and stops the sequence.
The POC never skips that member or counts its absence as transport exhaustion.
DoT, health checks, listener bootstrap, and query logs remain incomplete.

The Linux loopback tests cover replies, cache hits, rejected datagrams, TCP retries, and timeout dispositions.
Manual queries through `examples/poc.zon` returned public DNS answers over UDP and TCP.
The macOS test roots compile. Native macOS feedback remains separate.
No change here explains the historical Linux restart bind failures.

## DNS-over-TLS POC (#1)

The forwarding cap increases from 8 MiB to 12 MiB under the
[#1 budget decision](https://github.com/mattrobenolt/z53/issues/1#issuecomment-5563391075).
The combined fixed Runtime cap remains 40 MiB.
Each session owns separate TLS reassembly, encrypted input, and encrypted output arrays.
The DNS buffers retain their existing layout. No buffer overlap or dependency change accompanies this slice.

The system trust scan uses a fixed 1.5 MiB allocator before listener creation.
The initial 1 MiB bound failed on the 472033-byte NixOS certificate file because Zig reserves decode space and grows capacity.
The 1.5 MiB bound passes that scan and includes all scan allocations and retained certificate storage.
Empty bundles and scan failures abort startup. Custom Apple trust overrides remain unsupported.

On aarch64 Linux, `Forward` occupies 11708688 bytes and its backend occupies 5920 bytes.
`Runtime` occupies 38526960 bytes. Zone metadata and ring allowances bring the combined fixed total to 38803440 bytes.
The TLS byte arrays occupy 3695072 bytes across 32 sessions, apart from handshake engine metadata.
Bounded libcrypto setup and key-update allocations retain their SPEC section 1 exception outside the fixed storage total.
These values describe storage, not performance.

The TLS adapter uses ztls TLS 1.3 with secure ephemeral seeds and actual wall-clock certificate time.
`server_name` supplies both SNI and hostname verification. No verification bypass exists in the runtime.
TLS takes precedence over client transport and `force_tcp`.
Certificate failures advance the configured sequence as transport failures, without plaintext fallback to that member.
Distinguishable local crypto, entropy, and buffer failures remain uncached local failures.

Connect, handshake, and request transmission share the original absolute deadline.
Complete request transmission starts the response deadline. Partial records and control events do not renew it.
The adapter acknowledges Finished and other pending output only after complete socket transmission.
It discards tickets and processes KeyUpdate events through ztls.
Linux retains all TLS storage through both linked completions and existing teardown barriers.
Darwin removes socket interests before session destruction.

Native Linux tests exercise encrypted DNS, session reuse across both client transports, fragmented DNS records, and KeyUpdate responses.
Wrong-hostname and untrusted-CA tests reject application traffic and enter terminal transport failure policy.
A wrong-hostname member also fails over to a second authenticated TLS member.
Focused tests cover partial write acknowledgement, completion overruns, and TLS transport precedence.
The precedence mutation restored the old selection expression and failed with `expected .tls, found .tcp`.
The restored test passes. The older unsupported-member tests now use unresolved hostnames rather than supported TLS.

The fixture key and self-signed certificate serve tests only. They never enter the production trust bundle.
A real query check used the new binary with `examples/dot.zon` on port 8853 and the system trust bundle.
Cloudflare returned NOERROR and two A records for `example.com` over a UDP client and `example.net` over a TCP client.
A repeat query also succeeded. The owned resolver process exited afterward; the existing port 5353 listener remained untouched.
The macOS runtime and test roots pass semantic compilation on Linux. Native macOS execution remains pending.
Health checks, listener bootstrap, query logs, and historical Linux restart diagnosis remain outside this slice.


## Query completion logs (#1)

Both runtimes log at their existing UDP and TCP publication points.
The resolver supplies the source tag. The final client packet supplies the full response code.
The formatter reparses the original query and final response through the existing event-thread workspace.
Malformed questions use placeholders. No borrowed packet view survives the synchronous log call.

Each client or reserved UDP response owns its peer address and monotonic start time.
Forward transactions retain the original query through publication, as before.
The selected session supplies the actual endpoint, transport, and TLS name before session release.
Cache and local answers omit all upstream fields, even when an idle TLS session exists.

Linux retains multishot direct accept and its fixed-file allocation range.
Each accepted connection submits one socket `URING_CMD` on its existing client operation slot before its first receive.
`SOCKET_URING_OP_GETSOCKNAME=5` with `optlen=1` requests the peer address.
The SQE follows liburing's `io_uring_prep_cmd_getsockname` layout.
Each client owns its sockaddr and length until completion. Coalesced accepts cannot overwrite another client's identity.
The existing ownership generation and teardown barriers retain this storage.
Darwin obtains the peer directly from `accept`.

The formatter has a 3072-byte stack buffer and no allocator.
The default sink submits one bounded stderr write through the existing `Io`.
Zig's process `Io` handles SIGPIPE. A failed or short write loses log bytes without a DNS error.
The sink has no background queue. Synchronous stderr backpressure can delay the entire event thread.
This tradeoff is intentional. No throughput or latency improvement is claimed.

Attempt diagnostics describe transport failures, not health transitions.
TLS retains static causal error names, including certificate rejection, without certificate bytes or connection secrets.
Retry, stale, cache, and health semantics remain unchanged.
Health counters, probes, and transition logs remain future work.

Native capture tests cover both client protocols, distinct concurrent TCP peers, and actual DoT selection.
They also cover cache omission, failure-driven fallback, fragmented frames, coalesced frames, and sink failure.
The peer-lookup mutation changes `optlen` from one to zero, so the kernel returns the listener address instead.
The concurrent-peer test fails at its client-address assertion while DNS replies still succeed.
The restored peer lookup passes the same test.
The synthetic driver fixture bypasses normal admission with Unix socket pairs and needed explicit log metadata initialization.
A new capture assertion failed before that fixture correction. All six driver-pair tests pass afterward.
A live Cloudflare check on port 8853 produced three completion lines for three successful queries.
The first UDP query reported `src=forward upstream=1.1.1.1:853 upstream_proto=dot` and the verified TLS name.
Its repeat reported `src=cache` with no upstream fields. An uncached TCP query reported DoT and its actual client port.
The owned resolver exited afterward. The existing port 5353 listener remained untouched.
Native macOS execution remains separate from semantic compilation on Linux.


## Cache scaling baseline (#1)

Matt selected cache scaling measurements before further feature work or optimization.
The [baseline](benchmarks/README.md) separates physical index scans from DNS response work and packet allocation.
Directly seeded large caches avoid quadratic setup. Separate churn cases use production insertion and eviction.
ReleaseSafe is the reference candidate mode. Packaging still has no specified release profile.
No cache index, entry layout, runtime policy, or dependency pin changes accompany this baseline.

Upstream addresses always use literal IPs. Upstream hostname bootstrap is not required.
The parser still accepts upstream hostname syntax, but selection returns uncached local SERVFAIL without further attempts.
TLS `server_name` remains necessary for certificate verification and SNI, not DNS bootstrap.
Listener hostname support remains required. Health probes and final packaging requirements remain unchanged.

## Dense cache columns (#1)

Approval: [#1](https://github.com/mattrobenolt/z53/issues/1#issuecomment-5564692321).
Matt selected stdlib SoA lookup before a separate packet slab experiment.
This slice changes metadata only. Packet allocation and transactional publication remain unchanged.

`std.MultiArrayList(Entry)` owns one exact-capacity allocation per bank.
All columns retain the configured slot count, including empty slots. No query grows or compacts storage.
`std.mem.findScalarPos` scans the fingerprint column. `std.mem.findScalar` finds an empty slot for insertion.
The standard library selects vectorization. No custom SIMD scanner or hash table exists.

The fingerprint uses Wyhash over initialized, ASCII-folded wire names and explicit type, class, and DO bytes.
Framed labels retain binary dots and zero bytes. Padding and unused name tails never enter the hash.
The low bit is set, so zero always means empty. Complete key equality rejects fingerprint collisions.
`Bank.put` establishes the fingerprint and LRU links for production insertion and direct benchmark fixtures.

Tests cover collision continuation, exact capacities, slot reuse, and allocated metadata bytes.
Existing tests retain stale, cross-bank replacement, LRU, and allocation-failure rollback checks.
A mutation accepted fingerprints without complete key equality.
The dense-index regression failed with `expected null, found 0`. The source was restored before the passing resolver run.
Performance evidence follows the tested candidate commit. The earlier baseline capture remains unchanged.
