# z53

z53 is an experimental DNS caching forwarder in Zig, with io_uring on Linux and kqueue on macOS.
Configuration uses [ZON](SPEC.md#5-configuration-zon).

- UDP and TCP clients, with UDP, TCP, or verified DNS-over-TLS upstreams.
- Sequential failover on transport errors, with health checks and connection reuse.
- Per-zone positive and negative caches, bounded memory, and optional stale answers.
- Hosts files, NODATA rules, and answer rotation.
- Nix packages and modules for NixOS and nix-darwin.

z53 forwards queries to configured resolvers. It does not perform recursive resolution or DNSSEC validation.
The [specification](SPEC.md) defines its behavior and differences from CoreDNS.

## Requirements

Supported targets:

- aarch64-linux and x86_64-linux, with Linux 7.2.0 or newer.
- aarch64-darwin.

Linux requires io_uring. There is no epoll fallback.
The build uses Zig 0.16, ztls, and OpenSSL through pkg-config.
The Nix flake pins the toolchain and dependencies.

## Quick start

Build the package:

```sh
nix build .#z53
```

Start it with the example configuration:

```sh
./result/bin/z53 -c examples/poc.zon
```

The example listens on `127.0.0.1:5354` and forwards to Cloudflare.
It does not change the system resolver.

In another terminal, enter the development shell:

```sh
nix develop
```

Query the resolver:

```sh
dig @127.0.0.1 -p 5354 example.com A
dig @127.0.0.1 -p 5354 example.net A +tcp
```

The default config path is `/etc/z53/z53.zon`. The `-c` flag selects another file.
Configuration changes require a restart. Hosts files reload separately at their configured interval.

For DNS-over-TLS, use `examples/dot.zon`, which listens on `127.0.0.1:8853`.
Both client transports then use verified TLS upstream.
TLS uses the system trust store and the configured `server_name` for certificate checks and SNI.

Use literal IP addresses for listeners and upstreams. Hostname resolution is not implemented.
Bind only to trusted interfaces. z53 does not authenticate DNS clients.

## Configuration

Each zone selects the longest matching DNS suffix and has its own upstream list.
The query pipeline is:

1. RFC 6761 local answers.
2. Cache lookup.
3. NODATA rules.
4. Hosts lookup.
5. Forward to an upstream.

Only transport errors and timeouts trigger failover. DNS responses such as SERVFAIL and REFUSED end the attempt sequence.
Down endpoints receive health probes. `max_fails = 0` disables health checks.

See [the configuration reference](SPEC.md#5-configuration-zon) for defaults and limits.
The [reference configurations](SPEC.md#6-reference-configs) demonstrate split DNS and transport selection.

## Logs

Answered queries produce one completion line on stderr.
It contains the query, response code, duration, and answer source.
Forwarded responses also identify the selected upstream and its transport.
Cache hits omit upstream fields. Attempt failures and health transitions use separate events.

`duration_ms` measures query admission through response publication, not socket delivery.
Log writes are synchronous, so a slow stderr consumer can delay queries.
See [the log format](SPEC.md#4-observability) for field definitions and escaping.

## NixOS and nix-darwin

Add the flake input:

```nix
inputs.z53.url = "github:mattrobenolt/z53";
inputs.z53.inputs.nixpkgs.follows = "nixpkgs";
```

Pass `inputs` through `specialArgs` to the host modules.
Import the module in the NixOS host configuration:

```nix
{ inputs, ... }:
{
  imports = [ inputs.z53.nixosModules.default ];
  services.z53 = {
    enable = true;
    config = builtins.readFile ./z53.zon;
    # Optional: package = inputs.z53.packages.aarch64-linux.z53;
  };
}
```

For nix-darwin, import `inputs.z53.darwinModules.default` instead.
Both modules install `/etc/z53/z53.zon` and restart the service after config changes.
Config text enters the Nix store and must not contain secrets.
The modules do not disable other resolvers or change host DNS settings.

NixOS uses a dynamic user with the bind capability and sends logs to journald.
nix-darwin uses a root launchd daemon and `/var/log/z53.log`.
An hourly logrotate job retains seven compressed archives, with daily rotation and a 10 MiB threshold.
Copytruncate avoids a resolver restart, but can lose concurrent writes. The active log can exceed the threshold between checks.

Before use on port 53, stop any resolver that already binds the address.
Retain its configuration and the previous system generation for rollback.
See [packaging and deployment](SPEC.md#8-packaging-and-deployment) for module details.

## CI and binary cache

CI runs on pull requests and `main`. Manual dispatch is also available.
Each supported target runs `nix flake check`, the host trust tests, and compilation of the integration tests.
Both wire fuzz targets receive at least 20000 iterations.
The macOS job also runs the native kqueue suite.

Linux socket tests require kernel 7.2 or newer.
They remain a separate acceptance gate until CI has a compatible Linux runner.
Hosted Linux checks do not substitute for that coverage.

Successful pushes to `main` publish the package output and its runtime closure to [mattrobenolt.cachix.org](https://mattrobenolt.cachix.org).
Pull requests cannot publish packages.
The upload excludes development shells and test derivations.
Publication fails if the repository lacks `CACHIX_AUTH_TOKEN`.

Workflow checks use actionlint, pinact, and zizmor.
pinact verifies SHA pins against their version comments and enforces a three-day release age.
zizmor reports failures without GitHub Advanced Security.

### Cache credentials

Add a cache-scoped write token as the repository secret `CACHIX_AUTH_TOKEN`.
Use the repository's [Actions secrets settings](https://github.com/mattrobenolt/z53/settings/secrets/actions).

## Development

Enter `nix develop`, then run the build and tests:

```sh
zig build
zig build test
zig fmt --check build.zig build.zig.zon src tests
ziglint
ziglint build.zig src tests
nixfmt --check flake.nix nix/*.nix nix/modules/*.nix nix/tests/*.nix
```

`zig build` installs `zig-out/bin/z53`.

Run from source with the example configuration:

```sh
zig build run -- -c examples/poc.zon
```

Run the fuzz targets with 20000 iterations per target:

```sh
bash scripts/fuzz.sh 20000
```

Run the package and module checks:

```sh
nix flake check
```

The sandbox selects TLS API tests that do not require host trust files.
`zig build test` also exercises the host trust store and native socket paths.
Intermittent Linux restart tests can fail with `BindFailed`; the cause remains under investigation in [#1](https://github.com/mattrobenolt/z53/issues/1).

[Design notes](docs/decisions.md) describe the implementation and its constraints.
[Benchmarks](docs/benchmarks/README.md) include commands, methodology, and recorded results.

## License

Apache-2.0. See [LICENSE](LICENSE).
