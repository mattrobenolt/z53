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

## Nix package and modules (#1)

Build the native package with local builders:

```sh
nix build .#z53 --builders ''
```

`packages.default` aliases `packages.z53` on all three targets.
The ReleaseSafe package contains only `bin/z53`, with OpenSSL in its runtime closure.
Nix fetches the pinned dependency archives separately. Normal sandbox builds require neither network access nor a local Zig package cache.

Add the input to the deployment flake:

```nix
inputs.z53.url = "github:mattrobenolt/z53";
inputs.z53.inputs.nixpkgs.follows = "nixpkgs";
```

Import the NixOS module in the host configuration:

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

For nix-darwin, use `inputs.z53.darwinModules.default` instead.
Set an unused loopback port in `z53.zon` before any trial activation.
Keep secrets out of `services.z53.config`, because its text enters the Nix store.

Both modules require config text when enabled and install it at `/etc/z53/z53.zon`.
A config change restarts the service during a system switch.
NixOS uses a dynamic user, the bind capability, and existing journald retention.
Darwin uses a root launchd daemon and `/var/log/z53.log` for both output streams.

Darwin runs a one-shot logrotate job hourly, with daily rotation, a 10 MiB threshold, and seven compressed archives.
Copytruncate preserves launchd's open descriptors without a resolver restart.
It requires append-mode descriptors; the pending native Mac check must verify continued logging without a sparse-file gap after rotation.
Writes between the copy and truncation can disappear. The active file can exceed the threshold between checks.
No persistent log daemon or global retention override accompanies either module.

### Checks and deployment boundary

Run the native sandbox checks:

```sh
nix flake check --builders ''
```

Inside `nix develop`, run the separate host trust check:

```sh
zig build -j2 test-unit
```

Sandbox checks cover three TLS APIs, both reference configs, resolver policy, wire behavior, and benchmark smoke.
The sandbox requires all three selected TLS tests to run; an empty or changed selection fails the check.
The host-root scan remains in the default, unfiltered Zig test commands.
Module checks cover service flags, config changes, package overrides, disablement, and retention.
The full runtime/restart suite remains separate. These checks do not establish deployment readiness or foreign native execution.

Modules never disable CoreDNS or change host DNS policy. Distinct configured ports permit coexistence.
Deployment configuration and the eventual port-53 cutover belong in `mattrobenolt/nix-darwin`, not this repository.

Retain the previous system generation and resolver configuration before cutover.
If rollback is necessary, stop the replacement resolver before the previous service reclaims its port.
Restore the previous host configuration through its normal system switch.

## Development

Enter `nix develop`, then run:

```sh
zig build
zig build test
zig build bench-smoke
zig fmt --check build.zig build.zig.zon src tests
ziglint
ziglint build.zig src tests
nixfmt --check flake.nix nix/*.nix nix/modules/*.nix nix/tests/*.nix
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
