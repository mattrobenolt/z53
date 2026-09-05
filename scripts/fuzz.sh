#!/usr/bin/env bash
# SPEC §9.3, #1: Zig 0.16 can report fuzz crashes while exiting zero.
set -euo pipefail
iterations=${1:-20000}
if [[ ! $iterations =~ ^[1-9][0-9]{0,8}$ ]]; then
    echo 'usage: scripts/fuzz.sh [iterations: 1..999999999]' >&2
    exit 2
fi
# Keep failed evidence project-local, outside Nix's temporary development shell.
mkdir -p .tmp/fuzz
capture=$(mktemp -d "$PWD/.tmp/fuzz/run.XXXXXXXX")
cache="$capture/cache"
log="$capture/build.log"
status=125
build_pid=
cleanup() {
    local result=$? sample
    trap - EXIT
    trap '' HUP INT TERM
    set +e
    if [[ -n $build_pid ]]; then
        # The build owns a separate group, including compiler and fuzzer descendants.
        kill -TERM -- "-$build_pid" 2>/dev/null || true
        if kill -0 -- "-$build_pid" 2>/dev/null; then
            sleep 0.1
            kill -KILL -- "-$build_pid" 2>/dev/null || true
        fi
        wait "$build_pid" 2>/dev/null || true
    fi
    cat "$log" || result=1
    if (( result != 0 )); then
        printf '%s\n' "$status" >"$capture/status" || result=1
        if [[ -f "$cache/f/crash" ]]; then
            cp "$cache/f/crash" "$capture/crash" || result=1
        elif [[ -d "$cache/f/crash" ]]; then
            sample=$(find "$cache/f/crash" -type f -print -quit) || result=1
            if [[ -n $sample ]]; then cp "$sample" "$capture/crash" || result=1; fi
        fi
        rm -rf "$cache" || result=1
        echo "Fuzz evidence: $capture" >&2
    else
        rm -rf "$capture" || result=1
    fi
    exit "$result"
}
trap cleanup EXIT
trap 'status=129; exit 129' HUP
trap 'status=130; exit 130' INT
trap 'status=143; exit 143' TERM
: >"$log"
# Bash job control gives this asynchronous build its own process group on both targets.
set -m
zig build fuzz --fuzz="$iterations" --cache-dir "$cache" --summary all >"$log" 2>&1 &
build_pid=$!
set +m
status=0
wait "$build_pid" || status=$?
if (( status != 0 )); then
    echo "Fuzz build exited $status" >&2
    exit 1
fi
if [[ -e "$cache/f/crash" ]]; then
    echo 'Fuzz crash input exists (an empty input also counts)' >&2
    exit 1
fi
if grep -Eiq 'error:|failed|failure|panic|crash' "$log"; then
    echo 'Fuzz failure diagnostic found' >&2
    exit 1
fi
# Require one fresh, completed report for each named target. No report is failure.
if ! awk -v minimum="$iterations" '
    /^Fuzz test: / {
        current = ""
        if ($0 ~ /"fuzz.test.fuzz DNS decoder and safe rewrites"/) current = "raw"
        if ($0 ~ /"fuzz.test.fuzz structured DNS record relocation"/) current = "structured"
        if (current == "") exit 1
        seen[current]++
    }
    /^Runs: / {
        if (current == "") exit 1
        if ($2 != "0" || $3 != "->" || $4 !~ /^[0-9]+$/ || $4 < minimum) exit 1
        runs[current]++
        current = ""
    }
    END {
        if (seen["raw"] != 1 || seen["structured"] != 1) exit 1
        if (runs["raw"] != 1 || runs["structured"] != 1) exit 1
    }
' "$log"; then
    echo 'Missing, incomplete, or ambiguous fuzz reports' >&2
    exit 1
fi
