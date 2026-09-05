#!/usr/bin/env bash
# SPEC §9.3: the fuzz gate rejects absent evidence and zero-exit crashes (#1).
set -euo pipefail
cd "$(dirname "$0")/.."
fixture=$(mktemp -d "${TMPDIR:-/tmp}/z53-fuzz-gate-test.XXXXXXXX")
trap 'rm -rf "$fixture"' EXIT
cat >"$fixture/zig" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
while (( $# > 0 )); do
    if [[ $1 == --cache-dir ]]; then cache=$2; break; fi
    shift
done
mkdir -p "$cache/f"
case "$Z53_GATE_CASE" in
    empty-crash) : >"$cache/f/crash" ;;
    crash-directory) mkdir "$cache/f/crash" ;;
    diagnostic) echo 'error: returned error.TestUnexpectedResult' ;;
    panic) echo 'thread 123 panic: injected failing invariant' ;;
esac
if [[ $Z53_GATE_CASE == no-report ]]; then exit 0; fi
echo 'Fuzz test: "fuzz.test.fuzz DNS decoder and safe rewrites" (abc)'
echo 'Runs: 0 -> 20'
case "$Z53_GATE_CASE" in
    missing-target) exit 0 ;;
    duplicate-target)
        echo 'Fuzz test: "fuzz.test.fuzz DNS decoder and safe rewrites" (abc)'
        echo 'Runs: 0 -> 20'
        ;;
    unknown-target)
        echo 'Fuzz test: "unrecognized target" (abc)'
        echo 'Runs: 0 -> 20'
        ;;
esac
echo 'Fuzz test: "fuzz.test.fuzz structured DNS record relocation" (def)'
case "$Z53_GATE_CASE" in
    no-runs) ;;
    too-few) echo 'Runs: 0 -> 9' ;;
    reused-cache) echo 'Runs: 1 -> 20' ;;
    malformed-runs) echo 'Runs: 0 -> unknown' ;;
    *) echo 'Runs: 0 -> 20' ;;
esac
if [[ $Z53_GATE_CASE == status ]]; then exit 9; fi
MOCK
chmod +x "$fixture/zig"
for mode in success status empty-crash crash-directory diagnostic panic no-report \
    missing-target duplicate-target unknown-target no-runs too-few reused-cache malformed-runs; do
    status=0
    PATH="$fixture:$PATH" Z53_GATE_CASE="$mode" bash scripts/fuzz.sh 10 >"$fixture/$mode.log" 2>&1 || status=$?
    expected=1
    if [[ $mode == success ]]; then expected=0; fi
    if [[ $status != "$expected" ]]; then
        cat "$fixture/$mode.log"
        echo "fuzz gate $mode: expected exit $expected, got $status" >&2
        exit 1
    fi
    echo "fuzz gate $mode: exit $status (expected)"
done
# SPEC §9.3: reject invalid budgets before starting a build.
for iterations in 0 -1 1ms 1000000000; do
    status=0
    bash scripts/fuzz.sh "$iterations" >"$fixture/budget.log" 2>&1 || status=$?
    if [[ $status != 2 ]]; then
        echo "fuzz gate invalid budget $iterations: expected exit 2, got $status" >&2
        exit 1
    fi
    echo "fuzz gate invalid budget $iterations: exit $status (expected)"
done
