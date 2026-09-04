# AGENTS.md

This is z53: a DNS caching forwarder in Zig, on io_uring and kqueue, with ztls
for DoT. Read `SPEC.md` before writing any code. `SPEC.md` is the contract.

---

## What This Is

A loopback caching resolver that replaces CoreDNS on two machines. Targets:
aarch64-linux, x86_64-linux, aarch64-darwin. Zig 0.16. Runtime dependencies:
ztls (pinned commit) and one libcrypto backend (OpenSSL default, via
pkg-config). Everything else comes from Zig std. No event-loop dependency:
io_uring and kqueue through std, hand-rolled proctor.

Not a general-purpose resolver. Not a library. One binary, one config file,
two deployments. If a feature is not in `SPEC.md`, it does not exist here.

## Spec Discipline

- `SPEC.md` fixes behavior. Section 7 pins parity numbers from the CoreDNS
  1.14.6 source tree. Treat those numbers as requirements, not suggestions.
- A conflict between an implementation choice and a parity value is an issue,
  never a silent deviation. File it, then decide.
- When your work changes what the spec promises, update `SPEC.md` in the same
  commit. A spec that lags the code is a lie.

## Dev Environment

The Nix flake is the source of truth for tooling. If a check needs a command,
add it to the flake devshell. Do not suggest global installs. Inside the
devshell, run commands directly.

## Operating Loop

1. Pick one slice. Verify the current state against the spec before editing.
2. Implement the smallest honest change.
3. Run the relevant checks.
4. Commit the slice.
5. Comment on the GitHub issue with evidence and residual scope.

Do not broaden a slice because nearby work looks tempting. "Closed" means
proven against the acceptance criteria in `SPEC.md` §9, not "a slice landed."
Search open issues before filing. Extend the existing issue; do not fork a
parallel one. Committed files cite GitHub issues (`#NN`), never pi todos.

## The Wire Codec Is Hostile Input

Every length field on the DNS wire is attacker-controlled: labels, names,
RDLENGTH, the header counts. Rules:

- Widen narrow-type arithmetic in bounds checks. `if (remaining < len + N)`
  in `u8`/`u16` arithmetic overflows before the comparison rejects. Write
  `if (remaining < @as(usize, len) + N)`. This bit ztls in 14 places
  (ztls #72) and it is a remote DoS class here too.
- Hard limits: 63 bytes per label, 255 bytes per name, 65535 bytes per
  message. Reject early.
- A malformed message is FORMERR or a drop. It is never a crash, and never an
  unbounded allocation.
- Fuzz the decoder. `zig build test` green is not fuzz coverage.

## Code Style — Tiger Style

Safety > performance > developer experience, in that order. The full guide:
https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/TIGER_STYLE.md.
The rules that carry the most weight here:

- No recursion. Hard limit: 70 lines per function. Keep control flow in the
  parent; push pure logic into helpers.
- Upper bounds on everything: loops, queues, buffers, allocations.
- `std.debug.assert` for preconditions, invariants, and postconditions that
  catch real bugs. Never for input validation — wire input is validation
  territory. Split compound asserts; ziglint Z016 enforces this.
- Explicitly-sized types (`u32`, `u16`), not `usize`, unless the value is
  genuinely pointer-sized.
- Split compound conditions into nested `if/else`. State invariants
  positively: `if (index < length)`.
- Names carry units last, sorted by descending significance
  (`latency_ms_max`). Paired names get equal character length (`source` and
  `target`). No abbreviations.
- Comments are sentences. They say why, not what.
- Construct large structs in place: `fn init(target: *T) !void`. Pass
  arguments larger than 16 bytes as `*const`. Never alias state; compute
  values close to their use.
- Error sets are explicit. No `anyerror` in public functions.
- Less code is better code. A 10-line function that is obviously correct
  beats a 30-line one that might be.

`zig fmt` and ziglint run in the devshell and in CI. Both must pass before
 every commit. ziglint is the minimum bar, not the ceiling.

### Booleans are a code smell

Every `bool` must survive scrutiny. Before writing one, check in order:

1. Does it encode anything? If every call site passes the same literal,
   delete it and comment the invariant.
2. Do two bools describe one thing with a meaningless combination? Use one
   `enum` so the illegal state is unrepresentable.
3. Several independent flags on a struct? Use `std.EnumSet`.
   `flags.contains(.rotate)` reads, and the whole group packs into one byte.
4. Presence of a thing? `?T`, not `has_thing: bool`.
5. A two-valued parameter? A named `enum`, so call sites read `.udp`
   instead of `false`.

A function that takes two bools is a design error.

## Performance Is a First-Class Goal

This is a loopback resolver and the load is trivial. The systems work is
still the point of the project. Correctness first — then speed, with
evidence.

- Allocation budget: zero heap allocations on the steady-state query path.
  Static buffers, pools, or an arena per query. The cache and the hosts
  table may allocate, on insert and on load. Both are bounded. No ad-hoc
  heap use anywhere else.
- io_uring: use what the kernel gives, or say why not in the design notes:
  provided buffer rings (`io_uring_register_buf_ring`) with multishot
  `RECV` on the UDP socket; multishot `ACCEPT` on the TCP listeners;
  registered files where they pay; linked SQEs with `LINK_TIMEOUT` for
  upstream read deadlines; `SINGLE_ISSUER` + `DEFER_TASKRUN` over
  thread-pool shapes; zero-copy send for UDP responses when a measurement
  says it pays. Where the std wrapper lacks a feature, use the raw
  io_uring syscalls through `std.os.linux`. A plain submit/complete loop
  that ignores provided buffers and multishot is a design failure, not a
  simplification. macOS has no equivalent: plain `kevent`, no penalty.
- Memory: every long-lived structure is bounded and pre-sized. Struct
  layout is a deliberate choice — packing, padding, cache lines. The cache
  entry is the hottest structure in the program; treat its size as a
  budget.
- Measurement: profile with `perf` or Instruments, disassemble with
  `objdump -d` or `llvm-objdump`, benchmark with zig-benchmark. No
  performance claim without a capture. Gut feelings are wrong until
  measured.
- SIMD: probably nowhere. std already vectorizes memcpy and memchr. The
  honest candidates are case-insensitive name matching and label scanning.
  Only with measured evidence — a forced `@Vector` is worse than none.
- Tracy zones are optional. If they appear, vendor the zero-cost wrapper
  that TigerBeetle uses. perf and disassembly are the required floor.

## Tests

Every test cites the RFC section or the `SPEC.md` section it validates:

```zig
// RFC 1035 §4.1.4 — name compression points backwards only
test "compression pointer decode" { ... }
```

Error path tests are not optional. A test is evidence only after you have
seen it fail for the right reason: reproduce before fixing, or run a mutation
check (revert the fix, confirm red, restore). Record the result in the commit
or issue comment.

Use the project helpers: ztest for readable test output (one line per test in
CI logs), zig-benchmark for benchmarks. Both are lazy test-only dependencies
in `build.zig.zon`.

## Nix

Format with nixfmt. Module changes must eval on all three systems. Deployment
config lives in github.com/mattrobenolt/nix-darwin — this repo ships the
package and the modules, not host configs.
