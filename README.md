# z53

A DNS caching forwarder in Zig. io_uring on Linux, kqueue on macOS,
configuration in ZON. A small, personal replacement for CoreDNS under development.

**Status: UDP, TCP, and DNS-over-TLS forwarding POC (#1).** The contract is [`SPEC.md`](SPEC.md).
Literal upstreams support UDP, TCP, verified TLS 1.3, sequential transport failover, and caching.
TLS connections use the system trust bundle and retain sessions across queries.
Hosts, synthetic answers, NODATA rules, and answer rotation also work.
Health checks, hostname bootstrap, and query logs remain incomplete.
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
