# z53

z53 is a DNS caching forwarder. It answers from its cache and a hosts file
when it can, and forwards everything else to the resolvers you configure,
over UDP, TCP, or verified DNS-over-TLS.

The design goal is a resolver whose memory you can reason about. It is a
single binary running one event thread, with storage pre-sized at startup
instead of growing under load. io_uring on Linux and kqueue on macOS. The
steady-state query path performs no allocations. It does not resolve
recursively or validate DNSSEC.

z53 is experimental. Two things are known-incomplete: listener and upstream
hostnames are not resolved (use literal IP addresses), and intermittent Linux
restart bind failures are still under investigation in
[#1](https://github.com/mattrobenolt/z53/issues/1).

## Requirements

- aarch64-linux and x86_64-linux, on Linux 7.0.0 or newer. io_uring is
  required; there is no epoll fallback.
- aarch64-darwin.

The build uses Zig 0.16, ztls, and OpenSSL through pkg-config. The Nix flake
pins the toolchain and every dependency.

## Quick start

```sh
nix build .#z53
./result/bin/z53 -c examples/poc.zon
```

The example listens on `127.0.0.1:5354` and forwards to Cloudflare over UDP.
It does not touch the system resolver. Query it:

```sh
dig @127.0.0.1 -p 5354 example.com A
dig @127.0.0.1 -p 5354 example.net A +tcp
```

For DNS-over-TLS, `examples/dot.zon` listens on `127.0.0.1:8853` and forwards
to Cloudflare over verified TLS, using the system trust store and the
configured `server_name` for certificate checks and SNI.

The default configuration path is `/etc/z53/z53.zon`; `-c` selects another
file. Configuration changes take effect on restart. Hosts files reload
separately, at their configured interval, without a restart.

Bind only to interfaces you trust. z53 does not authenticate DNS clients.

## Configuration

Configuration is a [ZON](SPEC.md#5-configuration-zon) document. A minimal
split-DNS setup, forwarding most names over TLS but a private zone to an
internal resolver:

```zig
.{
    .listen = .{"127.0.0.1:53"},
    .zones = .{
        .{
            .suffix = ".",
            .upstreams = .{
                .{ .address = "1.1.1.1:853", .tls = .{ .server_name = "one.one.one.one" } },
            },
        },
        .{
            .suffix = "internal.example.",
            .upstreams = .{ .{ .address = "10.0.0.1:53" } },
        },
    },
}
```

A query matches the zone with the longest suffix, then runs through local
RFC 6761 names, the cache, NODATA rules, and the hosts table before any
upstream sees it. Each zone carries its own upstream list, cache, hosts file,
and NODATA rules.

Failover is sequential. Only transport errors and timeouts advance it. A DNS
response, including SERVFAIL, ends the attempt sequence. Endpoints
that keep failing are probed on their configured interval and held out of
rotation until they answer again; `max_fails = 0` disables health checking
entirely. When every upstream for a zone is down, cached answers are served
past expiry, per RFC 8767.

Defaults, limits, and the full field list are in
[the configuration reference](SPEC.md#5-configuration-zon). The
[reference configurations](SPEC.md#6-reference-configs) show more of the
surface.

## Logs

Every answered query logs one line on stderr: client address and protocol,
query name and type, response code, duration, and the answer source: cache,
stale, hosts, or a named upstream with its transport. Failures and health
transitions get their own events.

Writes are synchronous, so a slow stderr consumer delays the resolver.
Field definitions and escaping rules are in [SPEC §4](SPEC.md#4-observability).

## NixOS and nix-darwin

Add the flake and import the module for your platform:

```nix
inputs.z53.url = "github:mattrobenolt/z53";
inputs.z53.inputs.nixpkgs.follows = "nixpkgs";
```

```nix
{ inputs, ... }:
{
  imports = [ inputs.z53.nixosModules.default ];
  services.z53 = {
    enable = true;
    config = builtins.readFile ./z53.zon;
  };
}
```

For nix-darwin, import `inputs.z53.darwinModules.default` instead. Both
modules install `/etc/z53/z53.zon` and restart the service when it changes.
Config text lands in the Nix store, so it must not contain secrets. The
modules do not disable other resolvers or change host DNS settings — before
binding port 53, stop whatever already owns it and keep the previous system
generation for rollback.

On NixOS the service runs as a dynamic user with the bind capability and
logs to journald. On macOS it runs as a root launchd daemon writing
`/var/log/z53.log`, with an hourly logrotate job using copytruncate so the
inherited descriptors keep working without a restart.

Module details are in [SPEC §8](SPEC.md#8-packaging-and-deployment).

## CI and binary cache

CI runs the flake checks, the native socket suites, and both fuzz targets
(20,000 iterations each) on all three supported systems. Workflow auditing
uses actionlint, pinact, and zizmor.

Pushes to `main` publish the package and its runtime closure to
[mattrobenolt.cachix.org](https://mattrobenolt.cachix.org). Pull requests
build but cannot publish.

## Development

```sh
nix develop
zig build                 # installs zig-out/bin/z53
zig build run -- -c examples/poc.zon
zig build test
nix fmt
ziglint && ziglint build.zig src tests
nix flake check
bash scripts/fuzz.sh 20000
```

`zig build test` runs every suite, including the native socket tests and a
benchmark smoke run. Intermittent Linux restart tests can fail with
`BindFailed`; the cause remains under investigation in
[#1](https://github.com/mattrobenolt/z53/issues/1).

[Design notes](docs/decisions.md) explain the implementation and its
constraints. [Benchmarks](docs/benchmarks/README.md) record commands,
methodology, and results, including comparisons against CoreDNS.

## License

Apache-2.0. See [LICENSE](LICENSE).
