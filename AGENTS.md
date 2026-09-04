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

## Code Style

- `zig fmt` is necessary but not sufficient. Run the full lint before you
  commit.
- `std.debug.assert` for invariants, never for input validation. Wire input
  is validation, not assertion territory.
- Error sets are explicit. No `anyerror` in public functions.
- Keep per-query memory bounded. An arena per query, or pools. Steady-state
  memory must not grow with query count.
- Less code is better code. A 10-line function that is obviously correct
  beats a 30-line one that might be.

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

## Nix

Format with nixfmt. Module changes must eval on all three systems. Deployment
config lives in github.com/mattrobenolt/nix-darwin — this repo ships the
package and the modules, not host configs.
