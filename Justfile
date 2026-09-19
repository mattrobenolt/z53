set minimum-version := "1.55.0"
set default-list
set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

# Build the resolver and install zig-out/bin/z53.
[group('build')]
build:
    zig build

# Run the resolver from source against a configuration file.
[group('build')]
run config="examples/poc.zon":
    zig build run -- -c "{{ config }}"

# Run every test suite: portable tests, the native socket suite, and the
# benchmark smoke run. Uses the reference ReleaseSafe and baseline CPU flags.
[group('test')]
test: test-portable test-runtime

# Run the portable suites: dependency APIs, startup, host trust, and
# integration-test compilation. This is the subset the Nix sandbox checks.
[group('test')]
test-portable:
    zig build test-unit check test-compile -Doptimize=ReleaseSafe -Dcpu=baseline

# Run the native socket suite for this platform.
[group('test')]
test-runtime:
    zig build test-runtime -Doptimize=ReleaseSafe -Dcpu=baseline

# Fuzz both wire targets. The script validates the iteration count and
# retains crash evidence under .tmp/fuzz/ on failure.
[group('test')]
fuzz iterations="20000":
    bash scripts/fuzz.sh "{{ iterations }}"

# Run one benchmark mode: baseline, wire, route, index, cache, churn,
# profile, or layout. Benchmarks always build ReleaseSafe.
[group('bench')]
bench mode="baseline":
    zig build bench -- {{ mode }}

# Install the ReleaseSafe benchmark binary for perf and disassembly work.
[group('bench')]
bench-build:
    zig build bench-build

# Format Zig and Nix sources in place.
[group('check')]
fmt:
    zig fmt build.zig build.zig.zon src tests
    nix fmt

# Verify formatting without writing.
[group('check')]
fmt-check:
    zig fmt --check build.zig build.zig.zon src tests
    nixfmt --check flake.nix nix/*.nix nix/modules/*.nix nix/tests/*.nix

# Run both ziglint entry points.
[group('check')]
lint:
    ziglint
    ziglint build.zig src tests

# Run the full Nix gate: package, portable tests, modules, and style checks.
[group('check')]
check:
    nix flake check --no-write-lock-file

# Refresh every ztls pin from main: the build.zig.zon revision, the SPEC.md
# section 3 commit, and the sandbox closure hash in nix/package.nix. Safe to
# rerun. If the archive-count check fails, update the count and rerun.
[doc('Refresh every ztls pin from main across build.zig.zon, SPEC.md, and nix/package.nix.')]
[group('deps')]
bump-ztls:
    #!/usr/bin/env bash
    set -euo pipefail

    # zig resolves main to a commit and rewrites the build.zig.zon pin.
    zig fetch --save git+https://github.com/mattrobenolt/ztls#main

    commit=$(sed -n 's|.*github.com/mattrobenolt/ztls[^"#]*#\([0-9a-f]\{40\}\).*|\1|p' build.zig.zon)
    if test "${#commit}" -ne 40; then
        echo "no ztls commit found in build.zig.zon" >&2
        exit 1
    fi
    echo "ztls commit $commit"

    # SPEC.md section 3 pins the same commit and owns the only 40-hex hash.
    pins=$(grep -oE '[0-9a-f]{40}' SPEC.md | wc -l)
    if test "$((pins))" -ne 1; then
        echo "SPEC.md must hold exactly one commit hash" >&2
        exit 1
    fi
    sed "s/[0-9a-f]\{40\}/$commit/" SPEC.md > SPEC.md.tmp
    mv SPEC.md.tmp SPEC.md

    # A deliberately wrong closure hash makes nix print the real one.
    sed 's|outputHash = "sha256-[^"]*";|outputHash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";|' \
        nix/package.nix > nix/package.nix.tmp
    mv nix/package.nix.tmp nix/package.nix
    log=$(nix build .#z53 2>&1 | tee /dev/stderr) || true
    closure=$(printf '%s\n' "$log" | sed -n 's/.*got: *\(sha256-[A-Za-z0-9+/=]\{44\}\).*/\1/p')
    if test -z "$closure"; then
        echo "nix did not report a closure hash" >&2
        exit 1
    fi
    echo "closure hash $closure"

    sed "s|outputHash = \"[^\"]*\";|outputHash = \"$closure\";|" \
        nix/package.nix > nix/package.nix.tmp
    mv nix/package.nix.tmp nix/package.nix

    # AGENTS.md: verify dependency changes with nix build .#z53.
    nix build .#z53
