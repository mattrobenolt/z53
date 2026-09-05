# z53 — Feature Specification

**Stage: build foundation only. The binary does not serve DNS yet.
This document is the contract for the first implementation.**

z53 is a DNS caching forwarder in Zig. It replaces CoreDNS on two machines.
This document fixes behavior. The implementer owns every internal decision
that this document does not fix. Section 9 lists the open decisions.

Two reference deployments define the complete feature set:

- **launchpad** — AWS Graviton, NixOS, aarch64-linux. The root zone forwards
  to the EC2 VPC resolver. Cloudflare DoT is the fallback. A `ts.net.` zone
  forwards to Tailscale MagicDNS.
- **Matts-MacBook-Pro** — macOS, aarch64-darwin. The root zone forwards to a
  home LAN resolver first. Cloudflare DoT is the fallback. The `ts.net.` zone
  forwards to MagicDNS. A `svc.cluster.local.` zone forwards to a kubernetes
  resolver over TCP.

Section 6 contains both reference configs as ZON.

---

## 1. Non-negotiable constraints

1. Language: Zig 0.16.x. The flake pins the exact toolchain revision.
2. Targets: aarch64-linux, x86_64-linux, aarch64-darwin. No other target.
3. Runtime dependencies: ztls and one libcrypto backend. Pin ztls at commit
   `1d72c5331c6a9079279a27eede680534b74f596d`.
   The default backend is OpenSSL from nixpkgs, linked through
   pkg-config. No other runtime dependency is allowed.
4. Use ztest and zig-benchmark as the test and benchmark helpers. Keep them
   lazy and test-only in `build.zig.zon`, following the ztls pattern.
5. I/O model: Linux builds require kernel 7.2.0 or newer and use io_uring
   for socket events. There is no epoll fallback and no feature probing.
   Every io_uring feature named in this document exists on that kernel.
   Use provided buffer rings, multishot `RECVMSG` on unconnected UDP
   listeners, multishot accept, registered files, and linked timeouts.
   Connected UDP upstreams can use `RECV`. An `io_uring_setup` failure is a startup
   error, not a fallback trigger. Where the std wrapper lacks a feature,
   use the raw io_uring syscalls through `std.os.linux`. macOS builds use
   kqueue. Do not add an event-loop dependency.
6. One binary, named `z53`.
7. Configuration is a ZON document. Parse it with `std.zon`. Default path:
   `/etc/z53/z53.zon`. The `-c` flag overrides the path.
8. No in-process reload. The service manager restarts the process after a
   config change.
9. ztls is pre-alpha. Bump the pin deliberately. Never bump it silently.
10. Performance is a design goal. The steady-state query path performs zero
    heap allocations. Static buffers, pools, or an arena per query.
    Bounded libcrypto allocations for connection setup and infrequent key
    updates are exceptions. Established exchanges allocate nothing.
11. Every long-lived structure is bounded and pre-sized. Nothing grows
    without a configured bound.

## 2. Non-goals

- Recursive resolution from the root servers.
- DNSSEC validation.
- DoH, DoQ, DTLS.
- AXFR, IXFR, dynamic update, TSIG.
- Prometheus metrics, or HTTP endpoints of any kind.
- Query rewriting, views, per-client routing.
- Authoritative zone serving from zone files.
- Config reload without restart.
- epoll or select fallbacks on Linux. Kernel 7.2.0 or newer is a hard
  requirement.

## 3. Behavior

### 3.1 Listener and zone routing

- One process. For each entry in `listen`, bind UDP and TCP on that address.
  Default: `127.0.0.1:53`.
- A zone is a suffix rule plus feature settings. Route each query to the zone
  with the longest matching suffix. The match is case-insensitive. `"."`
  matches every name.
- If no zone matches, answer REFUSED.
- All zones share the listener. Zone blocks do not bind their own sockets.
  This mirrors CoreDNS, which multiplexes server blocks on one port.

### 3.2 Query pipeline

For every query, the stages run in this order:

1. RFC 6761 check (3.3). A hit answers the query. No later stage runs.
2. Cache lookup (3.7). A hit answers the query.
3. NODATA rules (3.4). A hit answers the query.
4. hosts (3.5). A hit answers the query.
5. Forward (3.6). The upstream answer returns to the client.

On the response path, the cache stores forwarded answers. Answer rotation
(3.8) runs last, before the client sees the response.

Flags on answers:

- Synthetic answers (RFC 6761, NODATA, hosts) set AA and clear RA.
- Forwarded answers set RA. They preserve the upstream AA bit.
- Cache hits preserve the stored flags.

### 3.3 RFC 6761 answering (always on, no config)

Covered names, per RFC 6761 and the CoreDNS `local` plugin:

- `localhost.`
- Every name under `.localhost.`
- Every name under `0.in-addr.arpa.`, `127.in-addr.arpa.`, and
  `255.in-addr.arpa.`

Answers:

- `localhost.` or `<x>.localhost.` type A returns `127.0.0.1`. Type AAAA
  returns `::1`. TTL 30 seconds. This TTL is a spec choice, not parity.
- `1.0.0.127.in-addr.arpa.` type PTR returns `localhost.`
- Every other covered name returns an empty NOERROR.
- These answers set AA and clear RA.
- No covered query reaches the cache, the hosts file, or any upstream.

The legacy `localhost.<domain>` prefix form is out. RFC 6761 names only.

### 3.4 NODATA rules (per zone)

- A zone lists query types that get an empty NOERROR answer. The reference
  configs use AAAA on the root zones, because launchpad has no IPv6.
- The rule matches any query class. This mirrors `template ANY AAAA`.
- The answer echoes the question, carries zero answer records, sets AA, and
  clears RA.
- If the client sent EDNS, the answer carries an OPT record. Echo the client
  payload size. Echo COOKIE when the client sent one.
- NODATA answers are not cached and not rotated. Deviation, see 7.2.

### 3.5 hosts (per zone)

- Source: `/etc/hosts` by default. A zone can name another file.
- Serve A, AAAA, and PTR. Synthesize PTR records from the reverse entries.
- TTL: 30 seconds default. Configurable per zone.
- A query with no matching record falls through to forward. A name that
  exists under a different record type also falls through. There is no
  NXDOMAIN mode. This is a deliberate simplification.
- The file reloads on change. Check mtime every 5 seconds by default. The
  interval is configurable. Zero disables the check. Swap the table
  atomically. Skip unparsable lines.
- Answers set AA and clear RA. Answers are not cached. Deviation, see 7.2.

### 3.6 Forwarding (per zone)

Upstream list, in configured order. Each upstream has an address, an optional
TLS block, and an optional `force_tcp` flag.

- Plain upstreams speak UDP first. `force_tcp` forces TCP for a plain
  upstream. TLS upstreams always speak TLS over TCP (DoT). Default TLS port:
  853.
- A TLS upstream requires `server_name`. Config load fails without it.
- Policy: sequential. Try upstreams in order. This is the only policy. A
  zone with one upstream needs nothing else.
- Failover happens on transport failure or timeout only. Any upstream
  response, including SERVFAIL, goes to the client. No rcode triggers
  failover.
- A truncated UDP upstream response goes to the client with TC set. The
  client retries over TCP against z53.
- Read timeout: 2 seconds per exchange. Configurable per zone.

Health:

- After `max_fails` consecutive failed exchanges, mark the upstream down.
  Default 2.
- Skip down upstreams in the sequence.
- Probe each down upstream every `health_check_interval`. Default 500 ms.
- The probe is a DNS query for `.` with RD set, sent over that upstream's
  transport. Any response restores the upstream. The query type belongs to
  the implementer.
- DoT probes ride the TLS connection.

Connections:

- Reuse TCP and TLS connections. Close idle connections after 10 seconds.
  Configurable per zone.
- One in-flight query per upstream connection. No pipelining toward the
  upstream.
- TLS: ztls client handshake, SNI from `server_name`, chain and hostname
  verification against the system trust store. Trust follows Zig's system
  bundle scan. Custom Apple trust overrides are unsupported.
  A handshake failure is a transport failure.
- Upstream queries use a fresh random query ID.
- Upstream queries carry EDNS0 with payload size 1232. Copy the client DO
  bit and all unknown EDNS options.
- Accept an upstream response only when the query ID and the source address
  match the outstanding query.

### 3.7 Cache (per zone, on by default)

- Key: qclass, qtype, qname, and the client DO bit.
- Positive answers: clamp each response TTL into [min_ttl, max_ttl].
  Defaults: 5 s and 3600 s.
- Negative answers (NXDOMAIN, NODATA): derive the TTL from
  `min(SOA TTL, SOA.MINIMUM)`. Clamp into
  [5 s, min(max_ttl_s, neg_max_ttl_s)]. Defaults: [5 s, 1800 s].
- SERVFAIL answers cache for 5 seconds. This includes terminal forward-stage
  transport failure. An eligible stale answer takes precedence.
  A terminal failure never replaces its stale candidate.
- Capacity: 10000 positive and 10000 negative entries. Evict the
  least-recently-used entry when full.
- Rewrite the served TTL to the clamped value.
- Only forwarded answers and terminal forward-stage SERVFAIL enter the
  cache. hosts, NODATA, and RFC 6761 answers bypass it.
- Serve stale (RFC 8767), opt-in per zone, default off: a grace window in
  seconds. On an expired entry, z53 tries the upstreams first. If every
  upstream fails, return the expired entry with TTL 30, inside the grace
  window. Log the source as `stale`.

### 3.8 Answer rotation (per zone)

- Applies to NOERROR responses from hosts and from forward. Cache hits rotate
  again on each response.
- Split the answer section: CNAME records first, then other records, then
  address records, then MX records. Shuffle the address records. Shuffle the
  MX records separately. This mirrors the CoreDNS composition order.
- RFC 6761 answers never rotate.

### 3.9 Wire behavior

- UDP: answer on the socket that received the query. Send the answer to the
  query source.
- A UDP response that does not fit the client payload limit gets TC set and
  is cut to the limit. Limit without EDNS: 512 bytes.
- TCP: standard two-byte length framing. A connection accepts queries until
  the client closes it.
- Responses echo the client EDNS payload size and COOKIE when present.
- Opcode other than QUERY: answer NOTIMP. This is a spec choice.
- CH class queries forward like any other query.
- Malformed input: answer FORMERR when the header parses, else drop. Input
  must never crash the process.
- The codec must decode compressed names. Responses can compress names.
- Rewrites preserve all records when the compliant result fits 65535 bytes.
  If expansion cannot fit, the codec returns `RewriteTooLarge`. TCP is never
  silently truncated. The resolver answers SERVFAIL and logs `src=servfail`.
  This local encoding error causes no failover or upstream health penalty.
  Neither the unservable answer nor this generated failure enters the cache.
  This differs from terminal transport failure in section 3.7. Ordinary UDP
  payload-limit truncation remains unchanged.

## 4. Observability

All output goes to stderr. The service manager captures it.

One line per query. Required fields: timestamp, proto, client address, qtype,
qname, rcode, duration, source tag, upstream address when forwarded. Source
tags: `rfc6761`, `nodata`, `hosts`, `cache`, `stale`, `forward`, `servfail`.

```
2026-09-05T01:12:33.512Z udp 127.0.0.1:44123 A api.fireworks.ai. NOERROR 0.6ms src=cache
```

The exact layout belongs to the implementer. The fields do not.

Upstream state transitions print one line each: address, new state, failure
count. Config errors print the file, the position, and the reason, then exit
with status 1.

Nothing else. No HTTP, no metrics, no health port.

## 5. Configuration (ZON)

Parse with `std.zon` into typed structs. Unknown fields fail the load.

Validation rules:

- A zone without upstreams fails the load.
- A TLS upstream without `server_name` fails the load.
- Duplicate zone suffixes fail the load.
- Reject inconsistent TTL clamp intervals. `min_ttl_s` must not exceed
  `max_ttl_s`. The effective denial maximum must be at least 5 seconds.
- Normalize suffixes: accept `ts.net` and `ts.net.`. Store the canonical
  form with the trailing dot.

The schema below fixes the required expressiveness. The implementer finalizes
exact field names, types, and ergonomics.

| Setting | Scope | Default | Notes |
|---|---|---|---|
| `listen` | global | `["127.0.0.1:53"]` | UDP and TCP on each address |
| `suffix` | zone | required | Longest match wins |
| `hosts` | zone | off | `.path`, `.ttl`, `.reload_s` |
| `nodata` | zone | `[]` | Query types that get empty NOERROR |
| `upstreams` | zone | required | Ordered list |
| upstream `.address` | upstream | required | `host:port` |
| upstream `.tls.server_name` | upstream | — | Required for TLS |
| upstream `.force_tcp` | upstream | false | Plain upstreams over TCP |
| `max_fails` | zone | 2 | Consecutive failures before down |
| `health_check_interval_s` | zone | 0.5 | Probe period while down |
| `read_timeout_s` | zone | 2 | Per exchange |
| `conn_expire_s` | zone | 10 | Idle upstream connection close |
| `cache` | zone | on | `.max_ttl_s` 3600, `.min_ttl_s` 5, `.neg_max_ttl_s` 1800, `.capacity` 10000 |
| `serve_stale_s` | zone | 0 (off) | RFC 8767 grace window |
| `rotate` | zone | false | Answer rotation |

## 6. Reference configs

These two configs are the acceptance fixtures. Ship them as
`examples/launchpad.zon` and `examples/darwin.zon`. A test must parse and
validate both.

### 6.1 launchpad (EC2, NixOS, aarch64-linux)

Replaces `hosts/nixos/launchpad/files/Corefile` in mattrobenolt/nix-darwin.

```zon
.{
    .listen = .{ "127.0.0.1:53" },
    .zones = .{
        .{
            .suffix = ".",
            .hosts = .{ .ttl = 30 },
            .nodata = .{ .AAAA },
            .upstreams = .{
                .{ .address = "169.254.169.253:53" },
                .{ .address = "1.1.1.1:853", .tls = .{ .server_name = "one.one.one.one" } },
                .{ .address = "1.0.0.1:853", .tls = .{ .server_name = "one.one.one.one" } },
            },
            .max_fails = 1,
            .health_check_interval_s = 5,
            .rotate = true,
        },
        .{
            .suffix = "ts.net.",
            .hosts = .{ .ttl = 30 },
            .upstreams = .{
                .{ .address = "100.100.100.100:53" },
            },
            .max_fails = 1,
            .cache = .{ .max_ttl_s = 30 },
        },
    },
}
```

### 6.2 Matts-MacBook-Pro (macOS, aarch64-darwin)

Replaces `hosts/darwin/files/Corefile` in mattrobenolt/nix-darwin. The root
zone blocks AAAA. The `ts.net.` zone does not: the Mac has IPv6. The
`svc.cluster.local.` zone forces TCP toward the kubernetes resolver.

```zon
.{
    .listen = .{ "127.0.0.1:53" },
    .zones = .{
        .{
            .suffix = ".",
            .hosts = .{ .ttl = 30 },
            .nodata = .{ .AAAA },
            .upstreams = .{
                .{ .address = "192.168.2.100:53" },
                .{ .address = "1.1.1.1:853", .tls = .{ .server_name = "one.one.one.one" } },
                .{ .address = "1.0.0.1:853", .tls = .{ .server_name = "one.one.one.one" } },
            },
            .max_fails = 1,
            .health_check_interval_s = 5,
            .rotate = true,
        },
        .{
            .suffix = "ts.net.",
            .hosts = .{ .ttl = 30 },
            .upstreams = .{
                .{ .address = "100.100.100.100:53" },
            },
            .cache = .{ .max_ttl_s = 30 },
        },
        .{
            .suffix = "svc.cluster.local.",
            .upstreams = .{
                .{ .address = "192.168.194.138:53", .force_tcp = true },
            },
            .health_check_interval_s = 60,
            .rotate = true,
        },
    },
}
```

## 7. Parity reference — CoreDNS 1.14.6

The numbers below come from the CoreDNS 1.14.6 source tree, not from memory.

| Value | Number | Source |
|---|---|---|
| Upstream read timeout | 2 s | `plugin/forward/forward.go:33` |
| Idle connection expire | 10 s | `plugin/forward/forward.go:32` |
| `max_fails` default | 2 | `plugin/forward/forward.go:83` |
| Health check interval default | 500 ms | `plugin/forward/forward.go:34` |
| Health check query | `.` with RD set | `plugin/forward/forward.go:83` |
| Cache capacity | 10000 positive, 10000 denial | `plugin/cache/cache.go:363` |
| Positive TTL clamp | [5 s, 3600 s] | `plugin/cache/cache.go:358` + `plugin/pkg/dnsutil/ttl.go:55,57` |
| Denial TTL clamp | [5 s, 1800 s] | `plugin/cache/cache.go:360` |
| SERVFAIL cache TTL | 5 s | `plugin/cache/cache.go:73` |
| `cache 30` semantics | caps positive and denial at 30 s | `plugin/cache/setup.go:60-61` |
| hosts reload interval | 5 s | `plugin/hosts/hostsfile.go:48` |
| hosts record types | A, AAAA, PTR | `plugin/hosts/hosts.go:40-52` |
| hosts sets AA | yes | `plugin/hosts/hosts.go:72` |
| NODATA template sets AA | yes | `plugin/template/template.go:103` |
| Rotation composition | CNAME, rest, address, MX; address and MX shuffled | `plugin/loadbalance/loadbalance.go` |
| Pipeline order | local → loadbalance → cache → template → hosts → forward | `plugin.cfg` |

### 7.2 Deliberate deviations

| Deviation | Reason |
|---|---|
| NODATA and hosts answers bypass the cache | Regeneration is free. The cache adds nothing. |
| hosts always falls through | The NXDOMAIN mode is unused in both Corefiles. |
| Sequential policy only | Both Corefiles use one upstream or sequential. |
| NOTIMP for non-QUERY opcodes | RFC-conservative. Unused by real clients here. |
| serve_stale added, default off | Requested feature. RFC 8767. |
| Legacy `localhost.<domain>` dropped | Deprecated upstream. Matt's decision. |
| hosts TTL default 30, not 3600 | Both Corefiles set 30. |
| Log line adds source and upstream fields | Free observability. |

## 8. Packaging and deployment

### 8.1 Flake

- Inputs: nixpkgs (`nixos-unstable`). Build the binary with the Zig 0.16
  toolchain and OpenSSL, following the ztls flake pattern for a Zig package
  that links libcrypto through pkg-config.
- Outputs: `packages.default` for all three systems, `nixosModules.default`,
  `darwinModules.default`, a devshell (Zig 0.16, just, dig, ziglint, OpenSSL
  pkg-config), and `checks` that build and test on all three systems.
- Formatter: nixfmt. Match the mattrobenolt/nix-darwin repo.

### 8.2 NixOS module

Options: `services.z53.enable`, `services.z53.config` (text, required),
`services.z53.package`. The unit mirrors nixpkgs `services.coredns`:

- `DynamicUser = true`
- `AmbientCapabilities = cap_net_bind_service` with a matching bounding set
- `Restart = on-failure`
- `LimitNOFILE = 1048576`
- Config file at `/etc/z53/z53.zon` through `environment.etc`
- `restartTriggers` on the config file, so a switch restarts after changes

### 8.3 nix-darwin module

Options: `services.z53.enable`, `services.z53.config`, `services.z53.package`.
Define a root launchd daemon. Mirror the existing coredns daemon block in
mattrobenolt/nix-darwin:

- `RunAtLoad = true`, `KeepAlive = true`
- `StandardOutPath` and `StandardErrorPath` at `/var/log/z53.log`
- Config file at `/etc/z53/z53.zon` through `environment.etc`

### 8.4 Integration

Deployment config lives in github.com/mattrobenolt/nix-darwin. That repo adds
z53 as a flake input, imports the modules on launchpad and
Matts-MacBook-Pro, and swaps `services.coredns` for `services.z53` with the
translated configs. The `enforce-dns` daemon on the Mac needs no change: it
points at `127.0.0.1`, not at coredns by name.

## 9. Acceptance criteria

### 9.1 Unit tests (`zig build test`)

- Wire codec: header, question, and record round trips. Compressed name
  decode. Label bounds: 63 bytes per label, 255 bytes per name.
- Malformed message handling: FORMERR or drop, never a crash.
- Suffix matcher: longest match, case-insensitivity, canonical form.
- Cache TTL clamp math, positive and denial.
- Rotation composition order.
- RFC 6761 zone set and answers.
- hosts parser: valid lines, skip invalid lines, PTR synthesis.
- Config loader: defaults, both example configs, and every validation error
  in section 5.

### 9.2 Integration tests

Bind z53 on a loopback port with a test config. Drive it with dig and with
in-process queries:

- hosts hit: A answer, TTL 30, AA set.
- NODATA: AAAA query returns empty NOERROR, AA set, COOKIE echoed.
- Zone routing: the `ts.net.`-style zone hits its own upstream.
- Failover: stop the first upstream. The second answers. The log shows the
  down transition and the restore.
- DoT: run an in-process DoT upstream with the ztls server role and a
  self-signed CA. z53 must resolve through it. A wrong CA must fail the
  handshake and count toward `max_fails`.
- Cache: a repeated query answers from cache. The log shows `src=cache`.
  The served TTL respects the clamp.
- Truncation: a large answer over UDP sets TC. The same query over TCP
  returns the full answer.
- Serve stale: with the grace window on and all upstreams dead, an expired
  entry serves with TTL 30.
- Every upstream dead: SERVFAIL, cached 5 seconds.

### 9.3 Fuzzing

The wire decoder must have a fuzz target. The ztls fuzz pattern applies.

### 9.4 Benchmarks

Benchmarks cover the wire codec, the suffix matcher, and the cache lookup.
zig-benchmark is the harness. Commit a capture for any performance claim.
CI runs a short benchmark smoke run.

### 9.5 Nix and CI

- `nix build .#z53` succeeds on all three systems.
- Both modules eval on their platforms.
- Both example configs parse and validate in a test.
- CI runs on all three targets: `zig build test`, `zig fmt --check`, lint,
  and the nix build.

## 10. What the implementer owns

- Proctor design over io_uring and kqueue, thread model, and buffer
  layout, inside the constraints of section 1.
- Exact ZON field names, types, and defaults syntax. The expressiveness in
  section 5 is fixed.
- Internal module layout and file organization.
- Log line layout. The field list in section 4 is fixed.
- Cache data structure and eviction internals.
- Test harness details.
- Any decision this document does not fix.

When an implementation choice conflicts with a parity value in section 7,
file an issue. Do not deviate silently.
