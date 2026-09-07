# z53

A DNS caching forwarder in Zig. io_uring on Linux, kqueue on macOS,
configuration in ZON. A small, personal replacement for CoreDNS under development.

**Status: UDP, TCP, and DNS-over-TLS forwarding POC (#1).** The contract is [`SPEC.md`](SPEC.md).
Literal upstreams support UDP, TCP, verified TLS 1.3, sequential transport failover, and caching.
TLS connections use the system trust bundle and retain sessions across queries.
Hosts, synthetic answers, NODATA rules, and answer rotation also work.
Query logs show the actual selected upstream transport, including DoT.
Health exclusion and bounded probes restore failed endpoints without client traffic.
Listener hostname bootstrap remains incomplete.
Upstreams use literal IPs. Hostname syntax remains accepted but unsupported at runtime.
TLS `server_name` supplies certificate verification and SNI, not DNS bootstrap.
Earlier Linux restart bind failures remain unexplained. Native macOS forwarding feedback remains pending.

## Targets

aarch64-linux · x86_64-linux · aarch64-darwin. Zig 0.16. Zero Zig
dependencies beyond ztls; one libcrypto backend (OpenSSL) linked through
pkg-config.

## Try the POC

`examples/poc.zon` uses Cloudflare over plain UDP, with TCP for TCP clients.
It listens on `127.0.0.1:5354` and leaves the system resolver unchanged.

Enter `nix develop`.
Start the resolver:

```sh
zig build run -- -c examples/poc.zon
```

In another terminal, query the resolver:

```sh
dig @127.0.0.1 -p 5354 example.com A
dig @127.0.0.1 -p 5354 example.net A +tcp
```

`examples/dot.zon` uses Cloudflare DoT and listens on `127.0.0.1:8853`.
Both UDP and TCP client queries use authenticated TLS upstream.
The trust scan has a 1.5 MiB bound. Trust load failures abort startup before listener creation.

## Query logs

Every answered query emits one completion line on stderr.
`proto` describes the client. `upstream_proto=dot` identifies authenticated TLS to the selected upstream.
`tls_name` identifies its certificate hostname. Reused TLS connections retain these fields.
Cache hits show `src=cache` without upstream fields or a new TLS exchange.
Failed attempts report their endpoint and reason, including certificate errors.
Health transitions report `event=upstream_health`, the endpoint, transport, state, and failure count.
DoT transitions include the configured TLS name.

```sh
dig @127.0.0.1 -p 8853 example.com A
dig @127.0.0.1 -p 8853 example.net A +tcp
```

The log uses numeric DNS types and full response codes.
`duration_ms` covers resolver admission through response publication, not kernel delivery.
Hostile name bytes use hexadecimal escapes. Malformed questions use explicit placeholders.
The bounded stderr sink is synchronous. A slow consumer can delay the event thread.
Sink failures lose logs without a DNS failure. [SPEC §4](SPEC.md#4-observability) defines the fields and timing.

## Upstream health

Each configured endpoint and zone retains its own consecutive failure count. The default threshold is two.
An admitted DNS response resets that count, including SERVFAIL and REFUSED. RCODEs never trigger failover.
Transport failures and timeouts penalize health. Local resource failures and cancellation do not.
A zero `max_fails` disables exclusion and probes. An all-down sequence uses the existing stale or SERVFAIL policy.

Root NS probes set RD and use the configured UDP, forced TCP, or verified DoT transport.
They bypass the client cache and query-completion logs. Clients receive priority within the shared fixed pools.
At most two concurrent probes rotate across due endpoints. Resource pressure defers probes, without simultaneous service guarantees for every endpoint.
Native Linux fixtures cover health recovery. macOS and x86 Linux semantic checks do not establish native execution.

## Development

Enter `nix develop`, then run:

```sh
zig build
zig build test
zig build bench-smoke
zig fmt --check build.zig build.zig.zon src tests
ziglint
nixfmt --check flake.nix
```

`zig build check` checks binary compilation without linking.
`zig build test-compile` checks unit test compilation without linking.
`zig build test-unit` runs the dependency API and startup tests.
Tests cover dependency APIs, resolver policy, and local socket exchanges.
The benchmark smoke exercises real DNS paths with eight iterations per case.
It supplies no stable timing result.
See [dependency decisions](docs/decisions.md) for known limits.


## Cache baselines and bounded stress

Inside `nix develop`, run these commands:

```sh
zig build bench -Doptimize=ReleaseSafe -- baseline
zig build bench-build -Doptimize=ReleaseSafe
perf stat -e cycles,instructions -- ./zig-out/bin/dns-benchmark profile
zig build test-resolver -Doptimize=ReleaseSafe
zig build test-runtime -Doptimize=ReleaseSafe -Druntime-filter='cache stress native'
```

The benchmark always uses ReleaseSafe. Modes are `smoke`, `baseline`, `wire`, `route`, `index`, `cache`, `churn`, `profile`, and `layout`.
Counts are fixed and bounded. The [capture and boundaries](docs/benchmarks/README.md) include capacities through 100000 entries per bank.
Microbenchmarks exclude logging and kernel I/O. They do not establish end-to-end QPS or maximum capacity.
Native stress uses owned loopback peers and a test-only memory sink for normal log formatting.
These checks do not supply overnight or production soak evidence. They exclude the historical restart cases.

## License

Apache-2.0. See [LICENSE](LICENSE).
