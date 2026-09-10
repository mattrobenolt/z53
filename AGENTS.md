# Contributor instructions

z53 is a loopback DNS caching forwarder in Zig 0.16.
It uses io_uring on Linux, kqueue on macOS, and ztls for DNS-over-TLS.
Runtime dependencies are ztls and one libcrypto backend, with OpenSSL as the default.
The supported targets are aarch64-linux, x86_64-linux, and aarch64-darwin.

## Scope and specification

Read `SPEC.md` before code changes.
Use `docs/decisions.md` for implementation rationale.
Keep changes within the feature scope of the specification.
Update `SPEC.md` in the same commit as any change to its promised behavior.

Treat the CoreDNS 1.14.6 parity values in section 7 as requirements.
If an implementation choice conflicts with a parity value, file an issue before a deviation.
Search existing issues before a new issue.
Keep issue closure tied to the acceptance criteria in `SPEC.md` section 9.

## Development workflow

Use the Nix development shell.
Add required tools to the flake rather than rely on global installations.
Run commands directly inside the shell.

1. Check the current behavior against the specification.
2. Implement one focused change.
3. Run the relevant checks.
4. Commit the change.
5. Record results and remaining work on the GitHub issue.

Reference GitHub issues in commit messages, not routine source comments.
Keep private work notes out of the repository.
Run the formatting and lint gates before every commit:

```sh
just fmt-check
just lint
```

## Hostile wire input

Treat every DNS length and count as untrusted input.
Widen narrow integer arithmetic before bounds comparisons:

```zig
if (remaining < @as(usize, len) + N) return error.Truncated;
```

Enforce these limits before access or allocation:

- 63 bytes per label.
- 255 bytes per name.
- 65535 bytes per message.

Return FORMERR or drop malformed messages.
Never use assertions for input validation.
Fuzz the decoder as well as ordinary unit tests.

## Code style

Follow [Tiger Style](https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/TIGER_STYLE.md).
Prioritize safety, then performance, then developer convenience.

- Avoid recursion.
- Keep functions within 70 lines.
- Bound every loop and allocation.
- Bound every queue and buffer.
- Keep control flow in the caller and move pure logic into helpers.
- Assert preconditions, invariants, and postconditions that detect programming errors.
- Split compound assertions. ziglint Z016 enforces this rule.
- Use explicitly sized integers unless a value is pointer-sized.
- Split compound conditions into nested branches.
- State invariants positively, such as `if (index < length)`.
- Put units last in names, such as `latency_ms_max`.
- Use equal-length paired names, such as `source` and `target`.
- Avoid abbreviations.
- Write comments as sentences that explain the reason for the code.
- Construct large structs in place, such as `fn init(target: *T) !void`.
- Pass arguments larger than 16 bytes as `*const`.
- Avoid aliases for mutable state.
- Compute values close to their use.
- Use explicit error sets in public functions, not `anyerror`.
- Prefer direct code over additional abstractions.

### Reusable buffers

Use `ArrayBuffer(T, N)` from `src/array_buffer.zig` for fixed append-only collections.
Derive capacity and index types from the buffer type.
Use `clear()` to reset retained storage, not assignment of `.empty`.
Use checked append methods for input-derived lengths.
Use `appendAssumeCapacity` only after a capacity proof.

Keep specialized lifetime models for these structures:

- Stream cursors.
- Sparse maps.
- Kernel-owned buffers.

### State representation

Review each `bool` before addition.

1. Remove parameters that receive the same literal at every call site.
2. Replace related booleans with an enum when some combinations are invalid.
3. Use `std.EnumSet` for independent flags on a struct.
4. Represent presence with `?T`, not a separate boolean.
5. Use a named enum for two-valued parameters, so call sites express their meaning.

Do not add functions with two boolean parameters.

## Performance and memory

Keep the steady-state query path free of heap allocations.
Use preallocated storage for query work:

- Static buffers.
- Fixed pools.
- Bounded per-query arenas.

Preallocate cache storage at startup.
Keep hosts-load allocations bounded.
Allow libcrypto allocations only for connection setup and infrequent key updates.
Keep established exchanges allocation-free.

Account for layout, padding, and alignment in long-lived structures.
Keep cache entry size within the specification's budget.
Measure performance changes before retention.
Record a capture for every performance claim.

Use the project tools:

- zig-benchmark for benchmarks.
- `perf` or Instruments for profiles.
- `objdump -d` or `llvm-objdump` for disassembly.

Prefer removal of unnecessary work over faster primitives.
Add explicit SIMD only with measured evidence.
Use the existing standard-library copy and search operations by default.
If Tracy instrumentation is added, use the zero-cost wrapper from TigerBeetle.
Keep perf and disassembly as the baseline measurement tools.

### Linux I/O

Require Linux 7.0.0 or newer.
Treat `io_uring_setup` failure as a startup error.
Do not add feature probes or an epoll fallback.
Use raw `std.os.linux` syscalls where standard wrappers lack required features.

Use the kernel features specified in `SPEC.md`:

- Provided buffer rings with multishot RECVMSG for unconnected UDP listeners.
- RECV for connected UDP upstreams where appropriate.
- Multishot ACCEPT for TCP listeners.
- Registered files where they reduce work.
- Linked SQEs with LINK_TIMEOUT for upstream deadlines.
- SINGLE_ISSUER and DEFER_TASKRUN rather than a thread pool.

Retain source addresses from unconnected UDP receives.
Add zero-copy sends only when measurements justify them.
Record the reason for any deviation from these I/O choices in the design notes.
Use ordinary kevent operations on macOS.

## Tests

Keep unit tests beside their implementation.
Keep socket integration fixtures separate.

Cite the relevant RFC or specification section for every test:

```zig
// RFC 1035 §4.1.4 — name compression points backwards only
test "compression pointer decode" { ... }
```

Cover error paths.
Reproduce a defect before the fix, or use a mutation that makes the regression fail at its intended assertion.
Restore the source and rerun the test after a mutation.
Record the result in the commit or issue comment.
Use ztest for unit-test output and zig-benchmark for benchmarks.
Keep both dependencies lazy and test-only in `build.zig.zon`.

## Nix

Format Nix files with nixfmt.
Evaluate module changes on all three supported systems.
Keep host configurations outside this repository.
This repository supplies the package and reusable modules.
