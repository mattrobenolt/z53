   set -eu

   export GITHUB_SHA=953447d0fa00120e76d255815fc66f1c9d7fbf22

   git fetch origin test/darwin-runtime
   test_root=$(mktemp -d "${TMPDIR:-/tmp}/z53-macbook.XXXXXX")
   git worktree add --detach "$test_root/source" "$GITHUB_SHA"

   export RUNNER_TEMP="$test_root/tmp"
   mkdir -p "$RUNNER_TEMP"
   cd "$test_root/source"

   mkdir darwin-evidence
   {
     uname -a
     sw_vers
     git rev-parse HEAD
   } > darwin-evidence/host.txt

   printf 'Evidence directory: %s\n' "$test_root"

   if nix develop --no-write-lock-file path:. \
       -c python3 scripts/darwin-ci.py \
       > "$test_root/runner.log" 2>&1
   then
     status=0
   else
     status=$?
   fi

   printf '%s\n' "$status" > darwin-evidence/devshell.status
   cp "$test_root/runner.log" darwin-evidence/runner.log
   tar -czf "$test_root/evidence.tar.gz" darwin-evidence

   printf '\nExit status: %s\nEvidence archive: %s/evidence.tar.gz\n' \
     "$status" "$test_root"
