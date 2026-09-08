# z53 — Feature Specification

**Stage: UDP, TCP, and DNS-over-TLS forwarding POC (#1).**
Linux and macOS select io_uring and kqueue respectively for UDP and TCP clients.
Literal upstreams support UDP, TCP, and authenticated TLS 1.3, including session reuse.
A later unsupported hostname member does not disable an earlier supported upstream.
Selection of that unsupported member returns uncached local SERVFAIL without a silent skip.
Native Linux and macOS tests exercise UDP, TCP, verified TLS, health recovery, and caching.
Manual Linux queries also exercise the packaged binary.
Linux IPv6 execution and live macOS deployment checks remain pending.
The earlier Linux restart bind failures remain unexplained. Full SPEC acceptance remains incomplete.
These features remain incomplete:

- Listener hostname bootstrap

This document is the contract for the first implementation.

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

### 1.1 Linux client runtime bounds

The Linux event thread owns these fixed resources:

- 512 submission entries and 1024 completion entries.
- 290 operation slots with completion generations.
- 64 provided UDP buffers and 64 response slots, shared across listeners.
- 128 TCP client slots, each with one request and one response buffer.
- 192 registered files: 32 listener slots, 128 direct-accept slots, and 32 upstream slots.

Direct accept retains files 32 through 159. Upstreams use files 160 through 191.
Each direct-accepted TCP connection retrieves its peer through socket `URING_CMD GETSOCKNAME` before its first receive.
Per-client sockaddr storage survives lookup completion under the existing operation ownership barriers.
Upstream I/O and linked timeout pairs use operation slots 225 through 288.
Slot 289 supplies the idle timer. Both linked completions retire before a session can rearm.
Explicit cancellation also retains each slot until its target completion and cancellation acknowledgement arrive.
Stop batches cancellation submissions against the remaining submission capacity.

Linux teardown retains storage through cancellation, request retirement, and checked resource unregistration (#1).
One five-second absolute MONOTONIC deadline covers teardown, independently of DNS timeouts.
After complete submission of older work, teardown cancels it and submits one standalone `NOP` with `IOSQE_IO_DRAIN`.
No later operation follows that marker.

Its successful completion precedes file unregistration and checked provided-ring unregistration.
Only then can teardown release mappings and return to Runtime storage cleanup.
Teardown consumes at most 2048 CQEs without dispatch, rearm, admission, or buffer recycling.
These failures exit the process without storage-release unwinding:

- Deadline or CQE ceiling exhaustion
- Submission or cancellation failure
- Invalid marker completion or dropped CQEs
- Resource unregistration failure

Reserved-only owners require no fabricated completion.
This contract covers the current ordinary socket operations and sole submitter, not future SOCKET or zero-copy operations.
The submitted-receive regression and its observation controls remain a separate proof from full-capacity and delayed-worker behavior.
Overall candidate acceptance remains BLOCKED.

UDP response-slot exhaustion drops the datagram and returns its provided buffer.
An empty provided ring terminates multishot receive with ENOBUFS.
The listener rearms on terminal completion.
TCP admission pauses after registered client slots fill and resumes after a close.
No overflow queue or allocation fallback exists.

An enabled hosts source loads before listeners start.
An initial load failure aborts startup even when `reload_s` is zero.
A monotonic io_uring timer schedules subsequent checks at whole-second intervals.
Periodic failures preserve the active table and mtime for the next configured check.

### 1.2 macOS client runtime bounds

The macOS event thread owns one kqueue with 210 one-shot operation slots:

- 16 UDP reads and 16 TCP accepts
- One hosts/admission timer and 128 TCP clients
- 16 UDP writes and 32 upstream socket interests
- One precise upstream deadline timer
It receives one readiness event per step, so no userspace event batch survives descriptor reuse.
Each rearm advances a non-wrapping completion generation.

Sockets and accepted clients are nonblocking and close-on-exec.
TCP sockets suppress SIGPIPE and enable address reuse for immediate restarts, not port reuse.
There are at most 32 listener descriptors, 128 accepted client descriptors, and 32 upstream descriptors.
TCP admission pauses when the client pool fills and resumes after close.
Descriptor/resource quota failures retry admission on the next timer, without a hot loop.

One 65535-byte scratch buffer receives datagrams synchronously.
64 response slots retain output, source address, and listener identity across EAGAIN.
Each UDP listener has one write filter shared by its pending responses.
Response-slot exhaustion drops a datagram without an overflow queue.
The 128 TCP clients use the same bounded framing buffers as Linux.
No steady-state socket operation allocates or blocks.

A relative one-second kqueue timer schedules the same hosts reload policy as Linux.
EV_DELETE synchronously cancels readiness; the kernel never borrows query buffers.
Closing kqueue and sockets releases all interests and descriptors on teardown or startup failure.
Runtime.stop is an explicit API; daemon signals still rely on process teardown.
PR #2 records native local-runtime tests and assertion-specific mutation evidence.
The forwarding candidate adds nonblocking connect completion through SO_ERROR and nanosecond deadlines.
The nearest upstream deadline replaces the dedicated timer through an EV_DELETE barrier.
The separate one-second timer retains the existing hosts and admission policy.
Full upstream transport and deployment acceptance remain incomplete.

### 1.3 Candidate forwarding bounds

Both backends retain these fixed limits:

- 32 shared transactions and 32 reusable UDP/TCP/TLS sessions
- At most two concurrent probes, within those shared pools
- No overflow queue
- 1024 endpoint entries, at most 64 bytes each
- One original query of at most 65535 bytes per transaction
- Two framed buffers of 65537 bytes per session
- Separate TLS storage per session: 65536 reassembly bytes, 33290 record bytes, and 16645 output bytes
- 1.5 MiB for the system trust scan, including its retained bundle and allocator workspace
- 12 MiB for forwarding storage, including TLS engines, trust storage, and backend metadata
- 40 MiB for combined fixed runtime storage, excluding the cache, hosts tables, and configuration

The DNS packet arrays occupy 6291488 bytes. The separate TLS byte arrays occupy 3695072 bytes.
Compile-time assertions enforce the complete storage caps.
The combined cap includes zone metadata and a separate 256 KiB allowance for Linux ring mappings.
The mapping allowance includes page rounding for the submission, completion, and provided-buffer mappings.
Configuration retains its separate section 5.1 bounds. Kernel socket memory is outside these userspace storage caps.

The cache exclusion covers allocated metadata columns and the fixed packet backing allocation.
The cache retains these separate bounds, exclusive of general allocator bookkeeping for its three startup allocations:

- 1000000 aggregate positive and denial entries across all zones
- At most 320 bytes of allocated metadata per configured entry slot
- At most 65535 live packet bytes per entry
- Configured packet backing, including pool arena headers, alignment, free blocks, and unused arena capacity
- At most 512 bytes of pool control per zone, also counted in the fixed runtime zone metadata

Each enabled cache allocates all backing storage at startup. Cache operations never call the general allocator afterward.
The existing fixed rewrite workspace supplies transactional packet preparation. Insertion requires no additional backing allocation.

A transaction owns its original query before the listener returns or reuses its input buffer.
A UDP response slot reserves its destination before admission and retains a non-wrapping generation.
A TCP client retains a separate connection generation and waits for delivery before it reads another frame.
A disconnected client can retain its slot until the bounded exchange completes.

Only idle sessions permit eviction. Each session carries at most one exchange.
Pool and local socket resource exhaustion return uncached local SERVFAIL without stale fallback or failover.
Supported transport exhaustion invokes the existing stale or five-second SERVFAIL policy.
An admitted DNS response, including SERVFAIL, ends the configured sequence.
An unsupported selected member returns uncached local SERVFAIL, without stale fallback or transport exhaustion policy.

Connect, TLS handshake, and request transmission share one absolute configured timeout.
Complete transmission starts a separate response deadline across prefix, body, and rejected frames.
Partial I/O and rejected frames never renew that response deadline.
Linux links each operation to its absolute monotonic deadline with `IORING_TIMEOUT_ABS`.
Queued submissions cannot renew the remaining budget.
Idle expiry uses the configured interval after an accepted response.

A separately seeded CSPRNG supplies upstream IDs. Answer rotation retains its separate generator.
Secure entropy failure or cancellation aborts startup before event queue or listener creation.
The upstream seed has no weak fallback.

Response admission requires the connected endpoint, connection generation, ID, QR, opcode, and exactly one matching question.
Final client encoding and rotation succeed before cache publication.

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
- Coverage applies to every query class. Synthetic answer records use class IN.
  The echoed question retains the original class.
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
- Serve these record types for IN queries only:
  - A
  - AAAA
  - PTR

  Non-IN queries fall through.
  Synthesize PTR records for every hostname and alias associated with an address.
  The IN-only restriction is a deliberate deviation from CoreDNS, see 7.2.
- TTL: 30 seconds default. Configurable per zone.
- A query with no matching record falls through to forward. A name that
  exists under a different record type also falls through. There is no
  NXDOMAIN mode. This is a deliberate simplification.
- The file reloads on change. Check mtime every 5 seconds by default. The
  interval is configurable. Zero disables the check. Swap the table
  atomically. Skip unparsable lines.
- Answers set AA and clear RA. Answers are not cached. Deviation, see 7.2.
- Load only regular files, at most 1 MiB per source.
  Each table holds at most 16384 unique address/name pairs. Aliases count toward this bound.
  The caller pre-sizes two disjoint table buffers for replacement.
  Duplicate pairs collapse. One name at multiple addresses retains every address.
- Skip an entire line if an address or hostname is invalid.
  Hostnames obey DNS label bounds and accept these ASCII characters:
  - Letters
  - Digits
  - Hyphens
  - Underscores
  - Label separators

  Scoped IPv6 addresses cannot be represented in AAAA and are skipped.
- These failures leave the active table and its mtime unchanged, so the next check can retry:
  - Failed read
  - Oversized source
  - Exhausted table
  - Detected mid-read change

  A successful empty file clears the table. Checks compare mtime.
  Edits that deliberately retain the same mtime are not detected.

### 3.6 Forwarding (per zone)

Upstream list, in configured order. Each upstream has an address, an optional
TLS block, and an optional `force_tcp` flag.

Deployments use literal IPv4 or IPv6 upstream addresses. Upstream hostname bootstrap is outside this contract.
TLS `server_name` supplies certificate verification and SNI, not address resolution.

- Plain upstreams use UDP for UDP clients and TCP for TCP clients.
  `force_tcp` forces TCP regardless of client transport.
  TLS upstreams always speak TLS over TCP (DoT). Default TLS port: 853.
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

- Count consecutive transport failures separately for each configured endpoint and zone, even when addresses match.
- After `max_fails` consecutive failed exchanges, mark the endpoint down. The default is 2. Counters saturate at the maximum `u32`.
- A zero `max_fails` disables exclusion and probes.
- Skip down endpoints in the sequence. If all members are down, use the existing exhausted, stale, or SERVFAIL policy.
- Only transport errors, timeouts, and TLS certificate rejection penalize health. Local resource and crypto failures do not penalize health.
- Encoding errors and unsupported hostnames do not penalize health. Idle close, shutdown, and client cancellation do not penalize health.
- An admitted DNS response resets the failure count and restores health, including SERVFAIL and REFUSED. No RCODE triggers failover.
- A retired failed probe contributes one failure. Linux retains both linked completions and close retirement before failure accounting.
- Schedule down endpoints at `health_check_interval_s`, with a default of 500 ms. Failed probes schedule their next interval after retirement.
- Probes query `.` for NS with RD set and a fresh secure ID. They use the existing response admission rules and deadlines.
- Probes use UDP unless `force_tcp` or TLS selects TCP or verified DoT. They reuse normal connections, including TLS connections.
- Probes bypass the client cache, answer rotation, client delivery, and query-completion logs.

The scheduler admits clients first and rotates fairly across due endpoints.
At most two probes share the existing transaction and session pools. Each endpoint permits at most one in-flight probe.
Resource pressure defers probes without a health penalty. A ten-millisecond retry floor prevents overdue timer loops under pressure.
The scheduler does not guarantee simultaneous probes for all 1024 endpoint slots.
Probe storage survives the existing Linux cancellation and drain barriers, or Darwin EV_DELETE, before reuse or release.

Connections:

- Reuse TCP and TLS connections. Close idle connections after 10 seconds.
  Configurable per zone.
- One in-flight query per upstream connection. No pipelining toward the
  upstream.
- TLS: ztls client handshake, SNI from `server_name`, chain and hostname
  verification against the system trust store. Trust follows Zig's system
  bundle scan. Custom Apple trust overrides are unsupported.
  A handshake failure is a transport failure.
  TLS always takes precedence over client transport and `force_tcp`.
  Certificate rejection never permits plaintext fallback to the same member.
  A TLS configuration triggers one system trust scan before listeners start.
  An empty or unreadable bundle aborts startup with `TrustStoreLoadFailed`.
  Scan allocation exhaustion aborts startup with `TrustStoreTooLarge`.
  TLS retains partial records and partial writes across socket operations.
  Only complete socket transmission acknowledges pending TLS output, including Finished and KeyUpdate responses.
  Post-handshake tickets are discarded. KeyUpdate responses use the established TLS engine.
  Distinguishable local crypto and buffer failures return uncached local SERVFAIL.
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
  Each bank preallocates fixed `std.MultiArrayList` columns at its configured capacity.
  A dense 64-bit fingerprint scan selects candidates. Exact key equality resolves collisions.
  Slots and LRU links remain stable. Queries never resize these columns.
- Packet storage: `packet_bytes_max` defaults to 8 MiB per zone, shared across both banks.
  One fixed allocation backs eleven `std.heap.MemoryPool` classes, from 64 through 65536 bytes in powers of two.
  Each entry records its class. Freed blocks return to that class, without a general allocator fallback.
  Pool arena headers and spare capacity consume the configured budget. Rounding can almost double packet storage.
  Classes never rebalance. A free block in one class cannot satisfy another class.
  Arena growth can fail before live packet bytes reach the budget. The minimum budget does not guarantee a full-size packet slot.
  Exhaustion skips insertion and returns the valid upstream answer. It preserves existing and stale entries.
  All fallible rewrites finish before replacement. A same-class destination victim or matching other-bank entry can transfer its block transactionally.
  Other replacements obtain a block before removal. Byte pressure never evicts unrelated entries from the other bank.
  Disabled caches allocate no packet storage.
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
  The transport also caps DNS payloads at 65507 bytes for IPv4 and 65527 bytes for IPv6.
  These caps assume fixed IP headers without extra options or IPv6 jumbograms.
  The smaller client or transport limit controls complete-RRset truncation.
  The echoed OPT payload size remains unchanged.
- TCP: standard two-byte length framing. A connection accepts queries until
  the client closes it.
- Responses echo the client EDNS payload size and COOKIE when present.
- Opcode other than QUERY: answer NOTIMP. This is a spec choice.
- CH class queries follow the ordinary pipeline. RFC 6761 and NODATA can
  answer them before the forward stage. Hosts falls through for non-IN classes.
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
- An upstream response with a nonzero extended RCODE requires client EDNS.
  Without client EDNS, z53 returns local SERVFAIL with no OPT and logs `src=servfail`.
  The local answer does not substitute the low four bits for the complete error.
  Clients with EDNS receive the complete upstream RCODE.

  This local failure causes no failover or upstream health penalty.
  Neither the upstream response nor the local failure enters the cache.
  Existing cache entries remain unchanged. This path never serves stale data.

## 4. Observability

All output goes to stderr. The service manager captures it.

Each answered query emits one `event=query` completion line.
Dropped queries emit no completion line.
The line includes these fields:

- UTC timestamp with milliseconds
- `proto=udp|tcp` for the client transport
- Actual client IP address and port
- Numeric `qtype`, including unknown type numbers
- Quoted, escaped `qname`
- Full numeric `rcode`, including the upper EDNS bits
- Monotonic `duration_ms` with three fractional digits
- `src=rfc6761|nodata|hosts|cache|stale|forward|servfail`

Forwarded answers also include the selected upstream address and `upstream_proto=udp|tcp|dot`.
DoT answers include `tls_name` from that selected member.
These fields describe the actual exchange, not the first configured member or the client transport.
A reused DoT connection still has `upstream_proto=dot`. This field does not imply a new handshake.
Cache, stale, and local answers omit upstream fields. They never imply a new TLS exchange.

```text
2026-09-05T01:12:33.512Z event=query proto=udp client=127.0.0.1:44123 qtype=1 qname="example.com." rcode=0 duration_ms=0.600 src=forward upstream=1.1.1.1:853 upstream_proto=dot tls_name="one.one.one.one"
2026-09-05T01:12:34.100Z event=query proto=tcp client=127.0.0.1:44124 qtype=1 qname="example.com." rcode=0 duration_ms=0.050 src=cache
```

Duration starts when the runtime admits a complete query to the resolver.
It ends at final response publication. TCP publication precedes socket writes. UDP publication queues or attempts the send.
The interval excludes completion-log formatting, its stderr write, and kernel delivery.
Fragmented reads and partial writes do not produce extra completion lines.

DNS label bytes outside ASCII letters, digits, hyphens, and underscores use `\xHH` escapes.
Literal label dots also use escapes. Only real label separators appear as dots.
Control bytes, quotes, backslashes, and non-ASCII bytes cannot forge lines or terminal commands.
Malformed questions use `qtype=unknown qname=unknown`. An unparsable response uses `rcode=unknown`.
The source tag identifies the pipeline path, not the numeric response code.
A malformed query can therefore produce `src=servfail rcode=1`.

Failed upstream attempts emit bounded `event=upstream_failure` lines with the endpoint, upstream transport, and reason.
DoT failures include the TLS name and the causal certificate error when the TLS engine supplies it.
The completion line identifies the successful fallback, if one answers.
These diagnostics do not alter retry or cache policy.
Each health transition emits one `event=upstream_health` line with the endpoint, upstream transport, state, and failure count.
DoT transitions include `tls_name`. States are `down` and `restored`. Restored transitions report a zero failure count.
Attempt failures never claim a health state or a failure count.

The formatter uses a fixed 3072-byte buffer and the existing parser workspace.
No query log requires heap allocation or a background queue.
The sink writes synchronously on the event thread. A slow stderr consumer can delay every query and upstream timeout dispatch.
A failed or short write loses all or part of the line, without a DNS error or retry queue.

Config errors print the file, position, and reason, then exit with status 1.

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
| upstream `.address` | upstream | required | Literal IP, optional port. See section 5.1 for parser compatibility. |
| upstream `.tls.server_name` | upstream | — | Required for TLS |
| upstream `.force_tcp` | upstream | false | Plain upstreams over TCP |
| `max_fails` | zone | 2 | Consecutive failures before down |
| `health_check_interval_s` | zone | 0.5 | Probe period while down |
| `read_timeout_s` | zone | 2 | Per exchange |
| `conn_expire_s` | zone | 10 | Idle upstream connection close |
| `cache` | zone | on | `.max_ttl_s` 3600, `.min_ttl_s` 5, `.neg_max_ttl_s` 1800, `.capacity` 10000, `.packet_bytes_max` 8388608 |
| `serve_stale_s` | zone | 0 (off) | RFC 8767 grace window |
| `rotate` | zone | false | Answer rotation |

### 5.1 Finalized schema and bounds

`zones` is required. An empty tuple is valid and matches no queries.

`hosts = null` disables hosts (the default).
`.hosts = .{}` enables its defaults.
Hosts reload zero disables the periodic file check.

`cache = null` disables the cache.
Omitted `cache` or `.cache = .{}` enables defaults.
Capacity applies separately to positive and denial entries.
`cache.packet_bytes_max` applies to both banks together and uses `u32` bytes.
Its default is 8388608 bytes. Valid values range from 65536 through 268435456 bytes, inclusive.
Enabled zones together reserve at most 536870912 packet bytes.
These product budgets do not establish a performance result.

`nodata` accepts symbolic types, such as `.AAAA` and `.HTTPS`.
It also accepts `.{ .number = 65280 }` for any numeric `u16` query type.

These values use `u32`:

- TTL values
- Hosts reload seconds
- Stale grace seconds
- `max_fails`

These durations use finite `f64` seconds in [0.001, 86400]:

- Exchange timeout
- Health check interval
- Idle connection expiry

Endpoint syntax accepts a hostname or IPv4 address, with an optional decimal port.
IPv6 uses brackets, for example `[::1]:53`.
Omitted ports are 53 for listeners and plain upstreams, or 853 for TLS upstreams.
Explicit ports are in [1, 65535].
Upstream hostnames remain syntactically accepted but unsupported at runtime. No upstream bootstrap implementation is required.
Listener hostname support remains a requirement.

The loader performs no hostname resolution or socket operations.
It rejects an empty or invalid DNS hostname in `server_name`.
TLS takes precedence over `force_tcp`.

The load fails if any resource exceeds these bounds:

| Resource | Maximum |
|---|---|
| Source file | 65536 bytes |
| Parser workspace, including parsed storage | 4 MiB |
| Tokens / delimiter nesting | 8192 / 16 |
| Listeners (at least one) / zones | 16 / 64 |
| Upstreams per zone (at least one) / NODATA types | 16 / 256 |
| Cache capacity per class per zone | 100000 entries, minimum 1 when enabled |
| Total positive plus denial capacity across zones | 1000000 entries |
| Packet backing per enabled zone | 256 MiB, minimum 64 KiB, default 8 MiB |
| Aggregate packet backing across enabled zones | 512 MiB |
| Hosts path | 4096 bytes, nonempty, no NUL |
| Endpoint text / DNS hostname text | 320 / 253 bytes |

Suffixes obey the DNS 63-byte label and 255-byte wire-name limits.
Their stored text folds ASCII case and ends with a dot.
The router consumes length-prefixed wire labels.
A literal dot inside a query label does not create a suffix match.

Diagnostics use one-based source lines and byte columns.
A missing or defaulted field uses the position of its parent object.
File I/O and workspace failures without a source token use position 1:1.
Only the first error is reported, with a bounded 512-byte reason.

Process reload remains unsupported.
The runtime serves local responses on literal listener addresses.
Listener hostnames remain valid configuration, but startup returns `UnresolvedListener` until bootstrap exists.
The POC supports literal upstreams over UDP, TCP, or authenticated TLS 1.3.
It tries configured members in order. A later unsupported member does not prevent an earlier supported member from a successful exchange.
Selection of an unsupported hostname member returns uncached SERVFAIL, without stale fallback, health effects, or further attempts.
Supported endpoints implement health exclusion, bounded probes, and transition logs.
The POC does not change the final transport, health, or logging requirements.

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
| hosts serves IN queries only | DNS address data is IN. Non-IN hosts queries fall through. CoreDNS hosts has no class guard. |
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
- Outputs: `packages.z53` and `packages.default` for all three systems, plus `nixosModules.default` and `darwinModules.default`.
- The devshell supplies Zig 0.16, just, dig, ziglint, and OpenSSL through pkg-config.
- Packages use ReleaseSafe and the baseline CPU target. Each installed output contains only `bin/z53`.
- A fixed-output Nix fetch supplies all six manifest-pinned dependencies, including transitive lazy helpers.
  Normal sandbox builds use Zig's `--system` mode without network access or a local package cache.
- Native install checks require the OpenSSL runtime path and execute CLI validation without library-path environment overrides.
  Test private keys and verification bypasses never enter the installed package.
- `checks` include the package, portable tests, module assertions, and source formatting/lints on each target.
  Portable tests cover TLS APIs, configuration, resolver policy, wire behavior, and the benchmark smoke.
  The sandbox selects the three TLS foundation tests with `-Dunit-filter=TLS` because the system-root test requires host trust files.
  It requires the runner to report all three tests; an empty or changed selection fails the check.
  Check and devshell inputs provide the platform's `ps` for fuzz-gate process checks.
  Default `test-unit` and `test` remain unfiltered. Host checks must separately run the system-root test.
  The full native runtime/restart suite remains a separate acceptance gate. No check suppresses its failures.
- The pinned Nix-only nix-darwin input supplies module evaluation and follows the root nixpkgs input.
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
- Existing journald policy supplies retention, without global policy overrides

### 8.3 nix-darwin module

Options: `services.z53.enable`, `services.z53.config`, `services.z53.package`.
Define a root launchd daemon. Mirror the existing coredns daemon block in
mattrobenolt/nix-darwin:

- `RunAtLoad = true`, `KeepAlive = true`
- `StandardOutPath` and `StandardErrorPath` at `/var/log/z53.log`
- Config file at `/etc/z53/z53.zon` through `environment.etc`
- The plist includes the content-addressed config source as `Z53_CONFIG_SOURCE`.
  A config change changes the plist, so nix-darwin reloads the daemon during activation.
  The daemon still reads `/etc/z53/z53.zon`. It does not consume this environment variable.
- An hourly one-shot logrotate job retains seven compressed archives, with daily rotation and a 10 MiB size threshold.
  Its config resides at `/etc/z53/logrotate.conf`. Its state resides at `/var/log/z53-logrotate.status`.
  `copytruncate` preserves launchd's inherited file descriptors without a resolver restart.
  Correct post-truncation logging requires append-mode descriptors. Native Mac acceptance must verify continued output without a sparse-file gap across rotation.
  Writes between the copy and truncation can disappear. Retention is best-effort, not lossless or a hard byte cap between checks.

### 8.4 Integration

Deployment config lives in github.com/mattrobenolt/nix-darwin. That repo adds
z53 as a flake input, imports the modules on launchpad and
Matts-MacBook-Pro, and swaps `services.coredns` for `services.z53` with the
translated configs. The `enforce-dns` daemon on the Mac needs no change: it
points at `127.0.0.1`, not at coredns by name.

Modules do not disable CoreDNS or change host DNS configuration.
Both resolvers can coexist on distinct configured ports. Config text enters the Nix store and must not contain secrets.
Package and module acceptance does not authorize a port-53 cutover or establish native execution on another platform.
The deployment owner controls cutover and retains the previous service configuration and system generation for rollback.
A rollback must release the replacement listener before the previous resolver reclaims its port.

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
- Failover: stop the first upstream. The second answers. The log shows the failed attempt and the selected fallback.
  New uncached queries skip the down primary. Down and restored transitions each produce one log line.
- Health: owned UDP, TCP, and verified DoT fixtures prove recovery without client traffic.
  Root probes retain RD, transport selection, identity admission, and the original deadline after rejection.
  Fake-clock tests cover thresholds 1, 2, 0, and maximum `u32`, with endpoint and zone isolation.
  Pressure defers probes fairly without client-buffer reuse. Stop retains pending probes without a health penalty.
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

Benchmarks cover the wire codec, the suffix matcher, and the real resolver/cache path.
Cache baselines distinguish index scans, response delivery, and insertion with eviction.
Captures record capacity, occupancy, hit position, build mode, and timed boundaries.
Directly seeded fixtures must identify their setup policy. They do not measure production cache population.
zig-benchmark supplies the in-process harness. Commit a capture for any performance claim.
End-to-end comparisons use dnsperf against owned loopback resolvers and an owned upstream.
These comparisons record build flags, CPU affinity, cache occupancy, query concurrency, and log destinations.
The production resolver and public upstreams receive no benchmark traffic.
CI runs a short benchmark smoke run. In-process timings do not establish end-to-end throughput or production soak acceptance.

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
