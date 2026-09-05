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
