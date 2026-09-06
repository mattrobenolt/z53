# z53

A DNS caching forwarder in Zig. io_uring on Linux, kqueue on macOS,
configuration in ZON. A small, personal replacement for CoreDNS under development.

**Status: UDP and TCP forwarding POC (#1).** The contract is [`SPEC.md`](SPEC.md).
Plain literal upstreams support UDP, TCP, sequential transport failover, and caching.
Hosts, synthetic answers, NODATA rules, and answer rotation also work.
DoT, health checks, hostname bootstrap, and query logs remain incomplete.
An unused DoT fallback does not disable a plain primary. If selection reaches DoT, the POC returns uncached SERVFAIL.
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
The benchmark smoke checks the helper only. It is not a DNS performance result.
See [dependency decisions](docs/decisions.md) for known limits.

## License

Apache-2.0. See [LICENSE](LICENSE).
