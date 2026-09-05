"""Collect native ARM macOS candidate evidence without publication or acceptance (#1)."""

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import shutil
import signal
import subprocess
import tempfile

from darwin_controls import CONTROLS, assertion_lines, preflight, unique
import darwin_watchdog as watchdog
from darwin_watchdog import check_cancelled, run

# Normal assertion failures include exit-one diagnostics from the pinned build runner.
CRASH = re.compile(r"panic(?::| in test\b)|Segmentation fault|Bus error|"
                   r"memory address .* leaked|LEAK:|compilation (?:errors?|failed)|"
                   r"^.*:\d+:\d+: error:|"
                   r"^error: (?!(?:process exited with error code 1|the following "
                   r"(?:command exited with error code 1:|(?:build|test) command failed "
                   r"with exit code 1:))$)", re.M | re.I)
BAD = re.compile(r"^error:|^TESTS FAILED$|^\[\d+/\d+\] FAIL:", re.M | re.I)
SKIPS = {
    "native ring setup registered files and cancellation",
    "native proctor teardown without registered files",
    "native setup failure under descriptor quota",
    "UDP recvmsg metadata bounds",
}


def git(root, *args):
    return subprocess.check_output(["git", *args], cwd=root, timeout=30).decode()


def hashes(root):
    paths = git(root, "ls-files", "-z").rstrip("\0").split("\0")
    return {path: hashlib.sha256((root / path).read_bytes()).hexdigest() for path in paths}


def green(result, text):
    if result["exit"] != 0 or result["reason"] or BAD.search(text) or CRASH.search(text):
        raise RuntimeError("The command failed its status or diagnostic gate.")


def full_green(result, text, root):
    green(result, text)
    summaries = re.findall(r"^ztest: (\d+) passed, (\d+) failed, (\d+) skipped "
                           r"\(of (\d+) total\)", text, re.M)
    if len(summaries) != 5 or text.count("ALL TESTS PASSED") != 5:
        raise RuntimeError("The full test run lacks five complete suite reports.")
    for passed, failed, skipped, total in summaries:
        if int(failed) or int(passed) + int(skipped) != int(total):
            raise RuntimeError("A suite report is incomplete or failed.")
    skipped = re.findall(r"^\[\d+/\d+\] SKIP: (.*?) \(", text, re.M)
    if len(skipped) != 4 or set(skipped) != SKIPS:
        raise RuntimeError("The native run contains unexpected or absent skips.")
    expected = re.findall(r'^test "([^"]+)"',
                          (root / "tests/runtime_darwin.zig").read_text(), re.M)
    for name in expected:
        pattern = r"^\[\d+/\d+\] PASS: " + re.escape(name) + r" \("
        if len(re.findall(pattern, text, re.M)) != 1:
            raise RuntimeError(f"The Darwin test lacks one PASS report: {name}")


def intended_red(result, text, control, tests):
    pattern = (r"^\[\d+/\d+\] FAIL: " + re.escape(control.test)
               + r" — error\." + re.escape(control.error) + r" \([^\n()]+\)$")
    if result["exit"] != 1 or result["reason"] or len(re.findall(pattern, text, re.M)) != 1:
        raise RuntimeError(f"The control lacks its intended assertion failure: {control.name}")
    lines = assertion_lines(tests, control)
    if not any(re.search(r"tests/runtime_darwin\.zig:" + str(line) + r":\d+", text)
               for line in lines):
        raise RuntimeError(f"The control failed outside its intended assertion: {control.name}")
    summaries = re.findall(r"^ztest: (\d+) passed, (\d+) failed, (\d+) skipped "
                           r"\(of (\d+) total\)", text, re.M)
    if len(summaries) != 1 or len(re.findall(r"^\[\d+/\d+\] FAIL:", text, re.M)) != 1:
        raise RuntimeError("The control requires exactly one failed test and one complete report.")
    passed, failed, skipped, total = map(int, summaries[0])
    if failed != 1 or skipped != 0 or passed + failed != total:
        raise RuntimeError("The control report is incomplete or contains another failure.")
    if CRASH.search(text):
        raise RuntimeError("A crash, compile error, or leak does not prove the assertion.")


def crash_inputs(scratch, evidence, name):
    found = []
    for path in scratch.rglob("crash"):
        found.append(str(path.relative_to(scratch)))
        samples = [path] if path.is_file() else sorted(p for p in path.rglob("*") if p.is_file())
        for sample in samples[:1]:
            target = evidence / f"{name}.crash"
            with sample.open("rb") as source:
                target.write_bytes(source.read(65535))
    if found:
        raise RuntimeError(f"Unexpected crash inputs: {found}")


def batch(root, scratch, evidence, name, command):
    check_cancelled()
    cache = scratch / "cache"
    global_cache = scratch / "global"
    env = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(global_cache),
               ZIG_LOCAL_CACHE_DIR=str(cache), ZTEST_PLAIN="1", ZTEST_VERBOSE="1")
    try:
        cleanup = watchdog.cleanup_harness if name == "harness" else watchdog.cleanup_group
        result, text = run(command, root, evidence, name, env=env, storage=scratch, cleanup=cleanup)
        crash_inputs(scratch, evidence, name)
        return result, text
    finally:
        shutil.rmtree(cache, ignore_errors=True)
        # Dependencies stay local. Compiler objects do not survive a completed batch.
        if global_cache.exists():
            for path in global_cache.iterdir():
                if path.name != "p":
                    if path.is_dir():
                        shutil.rmtree(path)
                    else:
                        path.unlink()
        shutil.rmtree(root / ".zig-cache", ignore_errors=True)


def controls(root, scratch, evidence):
    original = hashes(root)
    tests = (root / "tests/runtime_darwin.zig").read_text()
    preflight(root)
    for control in CONTROLS:
        check_cancelled()
        path = root / control.path
        source = path.read_bytes()
        text = source.decode()
        unique(text, control.old)
        try:
            path.write_text(text.replace(control.old, control.new, 1))
            result, output = batch(root, scratch, evidence, control.name,
                                   ["zig", "build", "test-runtime", "-j2", "--summary", "all",
                                    f"-Druntime-filter={control.test}"])
            intended_red(result, output, control, tests)
        finally:
            path.write_bytes(source)
            if hashes(root) != original:
                raise RuntimeError("Source hashes differ after control restoration.")
            if git(root, "diff", "--cached", "--name-only"):
                raise RuntimeError("A control staged source changes.")
            (evidence / f"{control.name}.restored.json").write_text(
                json.dumps(hashes(root), indent=2) + "\n")


def native(root, scratch, evidence):
    for name, command in [
        ("environment", ["bash", "-c", "set -euo pipefail; uname -a; sw_vers; zig version; zig env; "
                         "nix --version; python3 --version; pkg-config --modversion libcrypto"]),
        ("format", ["zig", "fmt", "--check", "build.zig", "src", "tests"]),
        ("lint-default", ["ziglint"]),
        ("lint-explicit", ["ziglint", "build.zig", "src", "tests"]),
        ("nix-format", ["nixfmt", "--check", "flake.nix"]),
        ("workflow", ["actionlint"]),
        ("harness", ["python3", "tests/darwin-ci-test.py"]),
        ("build", ["zig", "build", "-j2", "--summary", "all", "--prefix", str(scratch / "out")]),
    ]:
        check_cancelled()
        result, text = batch(root, scratch, evidence, name, command)
        green(result, text)
    check_cancelled()
    binary = scratch / "out/bin/z53"
    if not binary.is_file():
        raise RuntimeError("The native executable is absent.")
    (evidence / "binary.sha256").write_text(hashlib.sha256(binary.read_bytes()).hexdigest() + "\n")
    result, text = batch(root, scratch, evidence, "native-full",
                         ["zig", "build", "test", "-j2", "--summary", "all"])
    full_green(result, text, root)
    try:
        controls(root, scratch, evidence)
    finally:
        # Ordinary control failures still require restored validation. Cancellation does not.
        check_cancelled()
        result, text = batch(root, scratch, evidence, "restored-full",
                             ["zig", "build", "test", "-j2", "--summary", "all"])
        full_green(result, text, root)
        for name, command in [("restored-lint", ["ziglint"]),
                              ("restored-lint-explicit", ["ziglint", "build.zig", "src", "tests"]),
                              ("restored-format", ["zig", "fmt", "--check", "build.zig", "src", "tests"])]:
            check_cancelled()
            result, text = batch(root, scratch, evidence, name, command)
            green(result, text)


def interrupted(number, _frame):
    watchdog.cancel(number)


def main():
    root = Path.cwd()
    evidence = root / "darwin-evidence"
    evidence.mkdir(exist_ok=True)
    outcome = {"native_candidate": "failed", "full_spec_acceptance": "not claimed"}
    scratch = None
    worktree = None
    before = hashes(root)
    try:
        if platform.system() != "Darwin" or platform.machine() != "arm64":
            raise RuntimeError("The runner requires native ARM macOS.")
        if git(root, "rev-parse", "HEAD").strip() != os.environ["GITHUB_SHA"]:
            raise RuntimeError("The checkout differs from the workflow head.")
        if git(root, "status", "--porcelain", "--untracked-files=no"):
            raise RuntimeError("The published checkout contains source changes.")
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            signal.signal(sig, interrupted)
        scratch = Path(tempfile.mkdtemp(prefix="z53-darwin-", dir=os.environ["RUNNER_TEMP"]))
        worktree = scratch / "source"
        git(root, "worktree", "add", "--detach", str(worktree), "HEAD")
        if hashes(worktree) != before:
            raise RuntimeError("The isolated worktree differs from the published source.")
        (evidence / "source-before.json").write_text(json.dumps(before, indent=2) + "\n")
        native(worktree, scratch, evidence)
        if hashes(worktree) != before or git(worktree, "status", "--porcelain", "--untracked-files=no"):
            raise RuntimeError("The isolated source differs after native checks.")
        if hashes(root) != before or git(root, "diff", "--cached", "--name-only"):
            raise RuntimeError("The published source or index changed during native checks.")
        check_cancelled()
        outcome["native_candidate"] = "passed"
    except Exception as error:
        outcome["error"] = str(error)
        raise
    finally:
        (evidence / "source-after.json").write_text(json.dumps(hashes(root), indent=2) + "\n")
        outcome["published_source_unchanged"] = hashes(root) == before
        outcome["no_staged_files"] = not git(root, "diff", "--cached", "--name-only")
        if worktree is not None and worktree.exists():
            (evidence / "isolated-after.json").write_text(json.dumps(hashes(worktree), indent=2) + "\n")
            git(root, "worktree", "remove", "--force", str(worktree))
        if scratch is not None:
            shutil.rmtree(scratch, ignore_errors=True)
        if watchdog.cancellation_signal is not None:
            outcome["native_candidate"] = "cancelled"
            outcome["signal"] = watchdog.cancellation_signal
        (evidence / "outcome.json").write_text(json.dumps(outcome, indent=2) + "\n")
    check_cancelled()


if __name__ == "__main__":
    main()
