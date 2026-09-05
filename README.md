# z53

A DNS caching forwarder in Zig. io_uring on Linux, kqueue on macOS, DoT
through [ztls](https://github.com/mattrobenolt/ztls), configuration in ZON.
A small, personal replacement for CoreDNS: hosts overrides, per-zone NODATA
rules, health-checked sequential failover, caching with RFC 8767
serve-stale, answer rotation.

**Status: build foundation only.** The contract is [`SPEC.md`](SPEC.md).
The binary prints a diagnostic to stderr and exits with status 1.
It does not listen or serve DNS.

## Targets

aarch64-linux · x86_64-linux · aarch64-darwin. Zig 0.16. Zero Zig
dependencies beyond ztls; one libcrypto backend (OpenSSL) linked through
pkg-config.

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
Tests exercise dependency APIs, not resolver behavior. The benchmark smoke
checks the helper only. It is not a DNS performance result.
See [dependency decisions](docs/decisions.md) for known limits.

## License

Apache-2.0. See [LICENSE](LICENSE).
