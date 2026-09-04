# z53

A DNS caching forwarder in Zig. io_uring on Linux, kqueue on macOS, DoT
through [ztls](https://github.com/mattrobenolt/ztls), configuration in ZON.
A small, personal replacement for CoreDNS: hosts overrides, per-zone NODATA
rules, health-checked sequential failover, caching with RFC 8767
serve-stale, answer rotation.

**Status: specification stage.** The contract is [`SPEC.md`](SPEC.md). No
implementation exists yet.

## Targets

aarch64-linux · x86_64-linux · aarch64-darwin. Zig 0.16. Zero Zig
dependencies beyond ztls; one libcrypto backend (OpenSSL) linked through
pkg-config.

## License

Apache-2.0. See [LICENSE](LICENSE).
