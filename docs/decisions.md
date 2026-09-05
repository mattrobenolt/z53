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
