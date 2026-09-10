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
