#!/usr/bin/env bash
# SPEC §9.3: the fuzz gate rejects absent evidence and zero-exit crashes (#1).
set -euo pipefail
cd "$(dirname "$0")/.."
gate="$PWD/scripts/fuzz.sh"
fixture=$(mktemp -d "${TMPDIR:-/tmp}/z53-fuzz-gate-test.XXXXXXXX")
cleanup() {
    local result=$?
    trap - EXIT
    trap '' HUP INT TERM
    if [[ -f $fixture/build-pid ]]; then
        kill -KILL -- "-$(cat "$fixture/build-pid")" 2>/dev/null || true
    fi
    rm -rf "$fixture"
    exit "$result"
}
trap cleanup EXIT
trap 'echo "fuzz gate ${mode:-setup}: assertion failed at line $LINENO" >&2' ERR
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
# Each mock owns a project-local evidence root inside this disposable fixture.
cd "$fixture"
cat >"$fixture/zig" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
while (( $# > 0 )); do
    if [[ $1 == --cache-dir ]]; then cache=$2; break; fi
    shift
done
printf '%s\n' "$cache" >cache-path
printf '%s\n' "$$" >build-pid
mkdir -p "$cache/f" "$cache/o"
printf 'disposable compiler object\n' >"$cache/o/object"
case "$Z53_GATE_CASE" in
    empty-crash) : >"$cache/f/crash" ;;
    crash-directory) mkdir "$cache/f/crash" ;;
    crash-sample)
        mkdir "$cache/f/crash"
        printf 'crash input\n' >"$cache/f/crash/sample"
        ;;
    interrupt)
        # Both generations ignore TERM, so cleanup reaches KILL before waiting.
        trap '' TERM
        bash -c '
            trap "" TERM
            echo "$$" >descendant-pid
            echo "interrupted mock build with TERM-resistant descendant"
            kill -TERM "$1"
            for ((spin = 0; spin < 1000000; spin++)); do :; done
            exit 99
        ' mock-descendant "$PPID" &
        wait "$!"
        exit 99
        ;;
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
for mode in success status empty-crash crash-directory crash-sample interrupt diagnostic panic no-report \
    missing-target duplicate-target unknown-target no-runs too-few reused-cache malformed-runs; do
    status=0
    PATH="$fixture:$PATH" Z53_GATE_CASE="$mode" bash "$gate" 10 >"$fixture/$mode.log" 2>&1 || status=$?
    expected=1
    case "$mode" in
        success) expected=0 ;;
        interrupt) expected=143 ;;
    esac
    if [[ $status != "$expected" ]]; then
        cat "$fixture/$mode.log"
        echo "fuzz gate $mode: expected exit $expected, got $status" >&2
        exit 1
    fi
    # SPEC §9.3: no object cache survives any gate outcome, including interruption.
    cache=$(cat cache-path)
    capture=${cache%/cache}
    [[ ! -e $cache ]]
    if [[ $mode == success ]]; then
        [[ ! -e $capture ]]
        grep -q '^Runs: 0 -> 20$' "$fixture/$mode.log"
    else
        [[ -f $capture/build.log ]]
        build_status=0
        case "$mode" in
            status) build_status=9 ;;
            interrupt)
                build_status=143
                for process in build-pid descendant-pid; do
                    process_status=$(ps -o stat= -p "$(cat "$process")" || true)
                    # An orphaned zombie has exited. Only its OS parent reaps it.
                    case "$process_status" in
                        ''|Z*) ;;
                        *) echo "mock process survived: $process ($process_status)" >&2; exit 1 ;;
                    esac
                done
                ;;
        esac
        [[ $(cat "$capture/status") == "$build_status" ]]
        expected_files=$'build.log\nstatus'
        case "$mode" in
            empty-crash)
                [[ -f $capture/crash ]]
                [[ ! -s $capture/crash ]]
                expected_files=$'build.log\ncrash\nstatus'
                ;;
            crash-sample)
                [[ $(cat "$capture/crash") == 'crash input' ]]
                expected_files=$'build.log\ncrash\nstatus'
                ;;
        esac
        [[ $(cd "$capture" && printf '%s\n' * | sort) == "$expected_files" ]]
        grep -Fq "Fuzz evidence: $capture" "$fixture/$mode.log"
        rm -rf "$capture"
    fi
    rm -f build-pid descendant-pid
    echo "fuzz gate $mode: exit $status, cleanup and evidence checked"
done
# SPEC §9.3: reject invalid budgets before starting a build.
for iterations in 0 -1 1ms 1000000000; do
    status=0
    bash "$gate" "$iterations" >"$fixture/budget.log" 2>&1 || status=$?
    if [[ $status != 2 ]]; then
        echo "fuzz gate invalid budget $iterations: expected exit 2, got $status" >&2
        exit 1
    fi
    echo "fuzz gate invalid budget $iterations: exit $status (expected)"
done
