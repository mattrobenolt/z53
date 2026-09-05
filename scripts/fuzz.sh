#!/usr/bin/env bash
# SPEC §9.3, #1: Zig 0.16 can report fuzz crashes while exiting zero.
set -euo pipefail
iterations=${1:-20000}
if [[ ! $iterations =~ ^[1-9][0-9]{0,8}$ ]]; then
    echo 'usage: scripts/fuzz.sh [iterations: 1..999999999]' >&2
    exit 2
fi
# Nix owns TMPDIR; use /tmp so evidence survives the development shell.
capture=$(mktemp -d /tmp/z53-fuzz.XXXXXXXX)
cache="$capture/cache"
log="$capture/build.log"
status=0
zig build fuzz --fuzz="$iterations" --cache-dir "$cache" --summary all >"$log" 2>&1 || status=$?
printf '%s\n' "$status" >"$capture/status"
cat "$log"
echo "Fuzz evidence: $capture" >&2
# Keep evidence on success too. The cache is never reused by this gate.
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
