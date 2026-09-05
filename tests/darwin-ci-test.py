"""SPEC §1.2 and §9.5: native CI rejects false evidence and restores controls (#1)."""

import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, call, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import darwin_controls as controls
import darwin_watchdog as watchdog

spec = importlib.util.spec_from_file_location("darwin_ci", ROOT / "scripts/darwin-ci.py")
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)


def valid_red():
    control = controls.CONTROLS[0]
    tests = (ROOT / "tests/runtime_darwin.zig").read_text()
    line = controls.assertion_lines(tests, control).start
    return control, tests, (
        f"[1/1] FAIL: {control.test} — error.{control.error} (1ms)\n"
        f"tests/runtime_darwin.zig:{line}:5\n"
        "ztest: 0 passed, 1 failed, 0 skipped (of 1 total)\nTESTS FAILED\n"
        "error: the following command exited with error code 1:\n/path/to/test\n"
        "error: the following build command failed with exit code 1:\n/path/to/build\n"
        "error: process exited with error code 1\n"
        "error: the following test command failed with exit code 1:\n/path/to/test\n")


class EvidenceTests(unittest.TestCase):
    def test_controls_match_exact_source(self):
        controls.preflight(ROOT)
        with self.assertRaises(RuntimeError):
            controls.unique("twice twice", "twice")
        with self.assertRaises(RuntimeError):
            controls.unique("absent", "missing")

    def test_zero_exit_crashes_and_nonzero_status_are_not_green(self):
        for text in ("thread 1 panic: injected", "PANIC: injected", 'PANIC in test "sample": injected',
                     "Segmentation fault", "TESTS FAILED",
                     "[1/1] LEAK: sample", "error: compile error"):
            with self.assertRaises(RuntimeError):
                ci.green({"exit": 0, "reason": None}, text)
        for result in ({"exit": 1, "reason": None}, {"exit": 0, "reason": "deadline"}):
            with self.assertRaises(RuntimeError):
                ci.green(result, "ALL TESTS PASSED")
        ci.green({"exit": 0, "reason": None}, "[1/1] PASS: failure recovery (1ms)")

    def test_full_run_requires_reports_and_every_native_test(self):
        names = ci.re.findall(r'^test "([^"]+)"',
                              (ROOT / "tests/runtime_darwin.zig").read_text(), ci.re.M)
        text = "\n".join(f"[1/1] PASS: {name} (1ms)" for name in names)
        text += "\n" + "\n".join(f"[1/1] SKIP: {name} (1ms)" for name in ci.SKIPS)
        text += "\nztest: 1 passed, 0 failed, 0 skipped (of 1 total)\nALL TESTS PASSED\n" * 5
        result = {"exit": 0, "reason": None}
        ci.full_green(result, text, ROOT)
        for bad in (text.replace(names[0], "missing"), text.replace("SKIP:", "PASS:", 1),
                    text.replace("ALL TESTS PASSED", "missing", 1),
                    text.replace("of 1 total", "of 2 total", 1), text + "\nthread 1 panic: crash"):
            with self.assertRaises(RuntimeError):
                ci.full_green(result, bad, ROOT)

    def test_red_requires_the_intended_assertion(self):
        control = controls.CONTROLS[0]
        tests = (ROOT / "tests/runtime_darwin.zig").read_text()
        line = controls.assertion_lines(tests, control).start
        text = (f"[1/1] FAIL: {control.test} — error.{control.error} (1ms)\n"
                f"tests/runtime_darwin.zig:{line}:5\n"
                "ztest: 0 passed, 1 failed, 0 skipped (of 1 total)")
        result = {"exit": 1, "reason": None}
        ci.intended_red(result, text, control, tests)
        for bad in ("error: compilation errors", text.replace(str(line), "99999"),
                    text.replace(control.error, "BindFailed"), text + "\npanic: crash"):
            with self.assertRaises(RuntimeError):
                ci.intended_red(result, bad, control, tests)
        for status in ({"exit": 0, "reason": None}, {"exit": -9, "reason": "deadline"}):
            with self.assertRaises(RuntimeError):
                ci.intended_red(status, text, control, tests)

    def test_red_rejects_abnormal_exits_and_diagnostics(self):
        control, tests, text = valid_red()
        ci.intended_red({"exit": 1, "reason": None}, text, control, tests)
        for status in (-11, 2, 137, -9, 0):
            with self.subTest(status=status), self.assertRaises(RuntimeError):
                ci.intended_red({"exit": status, "reason": None}, text, control, tests)
        for diagnostic in ("Segmentation fault", "sEgMeNtAtIoN fAuLt", "Bus error",
                           "error: memory address 0x1234 leaked:", "[1/1] LEAK: sample",
                           'PANIC in test "sample": injected', "PANIC: injected", "panic: injected",
                           "error: 1 compilation errors", "error: compilation failed",
                           "error: unable to load compiler input", "error: unknown build option",
                           "src/runtime.zig:10:2: error: expected type 'u32', found 'u64'"):
            with self.subTest(diagnostic=diagnostic), self.assertRaises(RuntimeError):
                ci.intended_red({"exit": 1, "reason": None}, text + diagnostic + "\n", control, tests)
        for bad in (text.replace("1 failed", "2 failed"), text.replace("0 skipped", "1 skipped"),
                    text.replace("of 1 total", "of 2 total"), text + text,
                    text.replace(control.test, "different test"),
                    text.replace("(of 1 total)", "(of 1 total"),
                    text.replace("(1ms)", "(1ms")):
            with self.subTest(report=bad), self.assertRaises(RuntimeError):
                ci.intended_red({"exit": 1, "reason": None}, bad, control, tests)

    def test_real_sigsegv_is_not_an_assertion_failure(self):
        control, tests, text = valid_red()
        source = ("import os, resource, signal\n"
                  "resource.setrlimit(resource.RLIMIT_CORE, (0, 0))\n"
                  f"print({text!r}, flush=True)\n"
                  "os.kill(os.getpid(), signal.SIGSEGV)\n")
        with tempfile.TemporaryDirectory(prefix="z53-sigsegv-test-") as directory:
            root = Path(directory)
            result, output = watchdog.run([sys.executable, "-c", source], root, root,
                                          "sigsegv", seconds=3)
            self.assertEqual(-signal.SIGSEGV, result["exit"])
            self.assertEqual(result, json.loads((root / "sigsegv.json").read_text()))
            with self.assertRaises(RuntimeError):
                ci.intended_red(result, output, control, tests)

    def test_empty_crash_artifacts_are_not_green(self):
        with tempfile.TemporaryDirectory(prefix="z53-crash-test-") as directory:
            root = Path(directory)
            evidence = root / "evidence"
            evidence.mkdir()
            crash = root / "crash"
            crash.touch()
            with self.assertRaises(RuntimeError):
                ci.crash_inputs(root, evidence, "file")
            self.assertEqual(b"", (evidence / "file.crash").read_bytes())
            crash.unlink()
            crash.mkdir()
            with self.assertRaises(RuntimeError):
                ci.crash_inputs(root, evidence, "directory")

    def test_controls_restore_after_success_and_exception(self):
        with tempfile.TemporaryDirectory(prefix="z53-control-test-") as directory:
            root = Path(directory)
            for relative in {c.path for c in controls.CONTROLS} | {"tests/runtime_darwin.zig"}:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)
            evidence = root / "evidence"
            evidence.mkdir()

            def hashes(path):
                return {str(p.relative_to(path)): hashlib.sha256(p.read_bytes()).hexdigest()
                        for folder in ("src", "tests") for p in (path / folder).rglob("*.zig")}

            original = hashes(root)
            visited = []

            def batch(_root, _scratch, _evidence, name, _command):
                control = next(c for c in controls.CONTROLS if c.name == name)
                self.assertNotEqual(original, hashes(root))
                visited.append(name)
                tests = (root / "tests/runtime_darwin.zig").read_text()
                line = controls.assertion_lines(tests, control).start
                return {"exit": 1, "reason": None}, (
                    f"[1/1] FAIL: {control.test} — error.{control.error} (1ms)\n"
                    f"tests/runtime_darwin.zig:{line}:5\n"
                    "ztest: 0 passed, 1 failed, 0 skipped (of 1 total)")

            with patch.object(ci, "hashes", hashes), patch.object(ci, "git", return_value=""):
                with patch.object(ci, "batch", batch):
                    ci.controls(root, root, evidence)
                self.assertEqual(len(controls.CONTROLS), len(visited))
                self.assertEqual(original, hashes(root))
                with patch.object(ci, "batch", side_effect=RuntimeError("injected command failure")):
                    with self.assertRaisesRegex(RuntimeError, "injected command failure"):
                        ci.controls(root, root, evidence)
                self.assertEqual(original, hashes(root))


class CancellationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="z53-cancel-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        for relative in {c.path for c in controls.CONTROLS} | {"tests/runtime_darwin.zig"}:
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        binary = self.root / "out/bin/z53"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"mock executable")
        self.calls = []
        self.original = self.hashes(self.root)
        for target in (patch.object(ci, "hashes", self.hashes),
                       patch.object(ci, "git", return_value=""),
                       patch.object(ci, "full_green"),
                       patch.object(watchdog, "cancellation_signal", None, create=True)):
            target.start()
            self.addCleanup(target.stop)
        for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            previous = signal.signal(number, ci.interrupted)
            self.addCleanup(signal.signal, number, previous)

    @staticmethod
    def hashes(root):
        return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                for folder in ("src", "tests") for p in (root / folder).rglob("*.zig")}

    def test_ordinary_control_failure_still_validates_restored_source(self):
        def batch(_root, _scratch, _evidence, name, _command):
            self.calls.append(name)
            if name == controls.CONTROLS[0].name:
                raise RuntimeError("ordinary control failure")
            self.assertEqual(self.original, self.hashes(self.root))
            return {"exit": 0, "reason": None}, ""

        with patch.object(ci, "batch", batch):
            with self.assertRaisesRegex(RuntimeError, "ordinary control failure"):
                ci.native(self.root, self.root, self.evidence)
        self.assertEqual(["restored-full", "restored-lint", "restored-lint-explicit",
                          "restored-format"], self.calls[-4:])
        self.assertEqual(self.original, self.hashes(self.root))

    def test_latched_signal_between_controls_starts_no_batch(self):
        control = controls.CONTROLS[0]

        def batch(_root, _scratch, _evidence, name, _command):
            self.calls.append(name)
            if name == control.name:
                return {"exit": 1, "reason": None}, valid_red()[2]
            return {"exit": 0, "reason": None}, ""

        write_text = Path.write_text

        def restored(*args, **kwargs):
            result = write_text(*args, **kwargs)
            if args[0].name == f"{control.name}.restored.json":
                os.kill(os.getpid(), signal.SIGHUP)
            return result

        with patch.object(ci, "batch", batch), patch.object(Path, "write_text", restored):
            with self.assertRaisesRegex(RuntimeError, "signal 1"):
                ci.native(self.root, self.root, self.evidence)
        self.assertEqual(control.name, self.calls[-1])
        self.assertEqual(self.original, self.hashes(self.root))

    def test_main_cancellation_preserves_cleanup_artifacts(self):
        worktrees = []
        write_text = Path.write_text

        def git(root, *args):
            if args[:2] == ("rev-parse", "HEAD"):
                return "test-head\n"
            if args[:2] == ("worktree", "add"):
                worktree = Path(args[3])
                for folder in ("src", "tests"):
                    shutil.copytree(root / folder, worktree / folder)
                worktrees.append(worktree)
            if args[:2] == ("worktree", "remove"):
                os.kill(os.getpid(), signal.SIGINT)
                shutil.rmtree(args[3])
            return ""

        def write(path, text, *args, **kwargs):
            # The first signal arrives after native returns. Later signals cannot skip artifacts.
            if path.name in ("source-after.json", "isolated-after.json", "outcome.json"):
                os.kill(os.getpid(), signal.SIGHUP)
            return write_text(path, text, *args, **kwargs)

        with patch.object(ci, "git", git), patch.object(ci, "native"), \
                patch.object(ci.platform, "system", return_value="Darwin"), \
                patch.object(ci.platform, "machine", return_value="arm64"), \
                patch.object(ci.resource, "setrlimit"), patch.object(Path, "cwd", return_value=self.root), \
                patch.object(Path, "write_text", write), \
                patch.dict(os.environ, GITHUB_SHA="test-head", RUNNER_TEMP=str(self.root)):
            with self.assertRaisesRegex(RuntimeError, "signal 1"):
                ci.main()
        evidence = self.root / "darwin-evidence"
        for name in ("source-before", "source-after", "isolated-after"):
            self.assertEqual(self.original, json.loads((evidence / f"{name}.json").read_text()))
        outcome = json.loads((evidence / "outcome.json").read_text())
        self.assertEqual("cancelled", outcome["native_candidate"])
        self.assertEqual(signal.SIGHUP, outcome["signal"])
        self.assertTrue(outcome["published_source_unchanged"])
        self.assertTrue(outcome["no_staged_files"])
        self.assertEqual(1, len(worktrees))
        self.assertFalse(worktrees[0].parent.exists())
        self.assertEqual(self.original, self.hashes(self.root))

    def test_cancellation_before_batch_starts_no_process(self):
        os.kill(os.getpid(), signal.SIGTERM)
        with patch.object(watchdog.subprocess, "Popen") as spawn:
            with self.assertRaisesRegex(RuntimeError, "signal 15"):
                ci.batch(self.root, self.root, self.evidence, "cancelled", ["not-a-command"])
            spawn.assert_not_called()

    def test_cancellation_during_restored_validation_stops_later_batches(self):
        def batch(_root, _scratch, _evidence, name, _command):
            self.calls.append(name)
            if name == controls.CONTROLS[0].name:
                raise RuntimeError("ordinary control failure")
            self.assertEqual(self.original, self.hashes(self.root))
            if name == "restored-full":
                os.kill(os.getpid(), signal.SIGTERM)
            return {"exit": 0, "reason": None}, ""

        with patch.object(ci, "batch", batch):
            with self.assertRaisesRegex(RuntimeError, "signal 15"):
                ci.native(self.root, self.root, self.evidence)
        self.assertEqual("restored-full", self.calls[-1])
        self.assertEqual(self.original, self.hashes(self.root))

    def test_first_signal_during_watchdog_cleanup_writes_status(self):
        kill_group = watchdog.kill_group
        signals = []

        def kill(process, number):
            signals.append(number)
            kill_group(process, number)
            os.kill(os.getpid(), signal.SIGINT)

        with patch.object(watchdog, "kill_group", kill):
            with self.assertRaisesRegex(RuntimeError, "signal 2"):
                watchdog.run([sys.executable, "-c", "pass"], self.root, self.evidence, "cleanup", seconds=3)
        self.assertEqual([signal.SIGTERM, signal.SIGKILL], signals)
        status = json.loads((self.evidence / "cleanup.json").read_text())
        self.assertEqual("signal 2", status["reason"])
        self.assertEqual(0, status["exit"])

    def test_real_signals_cancel_controls_and_finish_cleanup(self):
        for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            for closed_stdout in (False, True):
                with self.subTest(signal=number, closed_stdout=closed_stdout):
                    self.real_cancellation(number, closed_stdout)

    def real_cancellation(self, number, closed_stdout):
        self.calls.clear()
        watchdog.cancellation_signal = None
        for path in self.root.glob("pid-*"):
            path.unlink()
        processes, selectors, sent, cleanup_signals = [], [], [], []
        stop = threading.Event()
        source = ("import os, pathlib, signal, time\n"
                  "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                  "os.fork()\n"
                  "pathlib.Path('pid-' + str(os.getpid())).touch()\n"
                  "if directory := os.environ.get('Z53_HARNESS_CANCEL_PROBE'):\n"
                  " pathlib.Path(directory, 'fixture-' + str(os.getpid()) + '.pid').touch()\n"
                  + ("os.close(1); os.close(2)\n" if closed_stdout else "")
                  + "time.sleep(30)\n")
        popen, selector_type, kill_group = subprocess.Popen, watchdog.selectors.DefaultSelector, watchdog.kill_group

        def spawn(*args, **kwargs):
            process = popen(*args, **kwargs)
            processes.append(process)
            return process

        def select():
            selector = selector_type()
            selectors.append(selector)
            return selector

        def kill(process, sig):
            cleanup_signals.append(sig)
            kill_group(process, sig)
            if sig == signal.SIGTERM:
                # Real repeated signals arrive inside the watchdog cleanup path.
                os.kill(os.getpid(), signal.SIGHUP)
                os.kill(os.getpid(), signal.SIGINT)

        def batch(root, _scratch, evidence, name, _command):
            self.calls.append(name)
            if name == controls.CONTROLS[0].name:
                self.assertNotEqual(self.original, self.hashes(root))
                return watchdog.run([sys.executable, "-c", source], root, evidence, name, seconds=4)
            return {"exit": 0, "reason": None}, ""

        thread = threading.Thread(target=self.send_signal, args=(stop, sent, number))
        started = time.monotonic()
        try:
            with patch.object(ci, "batch", batch), patch.object(watchdog.subprocess, "Popen", spawn), \
                    patch.object(watchdog.selectors, "DefaultSelector", select), \
                    patch.object(watchdog, "kill_group", kill):
                thread.start()
                with self.assertRaisesRegex(RuntimeError, f"signal {number}"):
                    ci.native(self.root, self.root, self.evidence)
            self.assertEqual([number], sent)
            self.assertLess(time.monotonic() - started, 2.5)
            self.assertEqual([signal.SIGTERM, signal.SIGKILL], cleanup_signals)
            self.assert_cancelled_cleanup(number, processes, selectors, closed_stdout)
        finally:
            stop.set()
            thread.join(timeout=4)
            # The red run must also own teardown if the production finally fails.
            for process in processes:
                kill_group(process, signal.SIGKILL)
                process.wait(timeout=5)
                process.stdout.close()
            for selector in selectors:
                selector.close()
            self.assert_children_dead()
            self.assertFalse(thread.is_alive())

    def send_signal(self, stop, sent, number):
        deadline = time.monotonic() + 3
        while not stop.wait(0.01) and time.monotonic() < deadline:
            if len(list(self.root.glob("pid-*"))) == 2:
                if not stop.wait(0.15):
                    sent.append(number)
                    os.kill(os.getpid(), number)
                return

    def assert_children_dead(self):
        states = {}
        for path in self.root.glob("pid-*"):
            state = subprocess.run(["ps", "-o", "stat=", "-p", path.name[4:]],
                                   capture_output=True, text=True, timeout=5).stdout.strip()
            self.assertTrue(not state or state.startswith("Z"), (path.name, state))
            states[path.name[4:]] = state or "absent"
        return states

    def assert_cancelled_cleanup(self, number, processes, selectors, closed_stdout):
        status = json.loads((self.evidence / f"{controls.CONTROLS[0].name}.json").read_text())
        self.assertEqual(f"signal {number}", status["reason"])
        self.assertEqual(-signal.SIGKILL, status["exit"])
        self.assertEqual(controls.CONTROLS[0].name, self.calls[-1])
        self.assertEqual(self.original, self.hashes(self.root))
        restored = self.evidence / f"{controls.CONTROLS[0].name}.restored.json"
        self.assertEqual(self.original, json.loads(restored.read_text()))
        self.assertTrue(all(selector.get_map() is None for selector in selectors))
        for process in processes:
            self.assertTrue(process.stdout.closed)
            with self.assertRaises(ChildProcessError):
                os.waitpid(process.pid, os.WNOHANG)
        print(json.dumps({"signal": number, "closed_stdout": closed_stdout,
                          "elapsed_s": status["elapsed_s"], "reason": status["reason"],
                          "leader_reaped": True, "children": self.assert_children_dead(),
                          "source_restored": True, "extra_batches": 0}), flush=True)


class WatchdogTests(unittest.TestCase):
    def run_fixture(self, source, seconds=3):
        with tempfile.TemporaryDirectory(prefix="z53-watchdog-test-") as directory:
            root = Path(directory)
            return watchdog.run([sys.executable, "-c", source], root, root, "mock", seconds=seconds)

    def test_exit_status_and_bounded_log(self):
        result, text = self.run_fixture("print('success')")
        self.assertEqual(0, result["exit"])
        self.assertEqual("success\n", text)
        result, _ = self.run_fixture("raise SystemExit(7)")
        self.assertEqual(7, result["exit"])
        with patch.object(watchdog, "LOG_BYTES_MAX", 1024):
            result, text = self.run_fixture("print('x' * 2048)")
        self.assertEqual("log bound", result["reason"])
        self.assertEqual(1024, len(text))

    def test_darwin_eperm_log_bound_cleanup_preserves_evidence(self):
        # SPEC §9.5: injected errno reproduces the native log-bound cleanup failure (#1).
        processes, selectors, calls = [], [], []
        popen, selector_type, killpg = subprocess.Popen, watchdog.selectors.DefaultSelector, os.killpg

        def spawn(*args, **kwargs):
            process = popen(*args, **kwargs)
            processes.append(process)
            return process

        def select():
            selector = selector_type()
            selectors.append(selector)
            return selector

        def kill(pgid, number):
            self.assertEqual(processes[0].pid, pgid)
            calls.append(number)
            if number == signal.SIGTERM:
                # This wait fixes the exit state. It does not prove native zombie errno behavior.
                processes[0].wait(timeout=3)
                raise PermissionError(errno.EPERM, "injected Darwin EPERM")
            return killpg(pgid, number)

        with tempfile.TemporaryDirectory(prefix="z53-eperm-test-") as directory:
            root = Path(directory)
            try:
                with patch.object(watchdog.sys, "platform", "darwin"), \
                        patch.object(watchdog, "LOG_BYTES_MAX", 1024), \
                        patch.object(watchdog.subprocess, "Popen", spawn), \
                        patch.object(watchdog.selectors, "DefaultSelector", select), \
                        patch.object(watchdog.os, "killpg", kill):
                    result, text = watchdog.run([sys.executable, "-c", "print('x' * 2048)"],
                                                root, root, "log-bound", seconds=3)
                self.assertEqual("log bound", result["reason"])
                self.assertEqual(0, result["exit"])
                self.assertEqual("x" * 1024, text)
                self.assertEqual(result, json.loads((root / "log-bound.json").read_text()))
                self.assertEqual([signal.SIGTERM, 0, signal.SIGKILL], calls)
                self.assertTrue(processes[0].stdout.closed)
                self.assertTrue(all(selector.get_map() is None for selector in selectors))
                with self.assertRaises(ChildProcessError):
                    os.waitpid(processes[0].pid, os.WNOHANG)
            finally:
                for process in processes:
                    try:
                        killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=5)
                    process.stdout.close()
                for selector in selectors:
                    selector.close()

    def test_darwin_eperm_reaps_before_exact_group_check(self):
        # SPEC §9.5: injected states require a reap and ESRCH, not just leader exit (#1).
        process = Mock(pid=12345)
        process.poll.return_value = 0
        events = Mock()
        events.attach_mock(process.poll, "poll")
        denied = PermissionError(errno.EPERM, "injected Darwin EPERM")
        with patch.object(watchdog.sys, "platform", "darwin"), \
                patch.object(watchdog.os, "killpg", side_effect=[denied, ProcessLookupError(errno.ESRCH, "absent")]) as kill:
            events.attach_mock(kill, "killpg")
            watchdog.kill_group(process, signal.SIGTERM)
        self.assertEqual([call.killpg(process.pid, signal.SIGTERM), call.poll(),
                          call.killpg(process.pid, 0)], events.mock_calls)

    def test_eperm_rejects_live_unowned_and_unknown_groups(self):
        # SPEC §9.5: injected permission failures must never become cleanup success (#1).
        for platform, status, number, probe in (
                ("linux", 0, errno.EPERM, None),
                ("darwin", 0, errno.EACCES, None),
                ("darwin", None, errno.EPERM, None),
                ("darwin", 0, errno.EPERM, None),
                ("darwin", 0, errno.EPERM, PermissionError(errno.EPERM, "unowned")),
                ("darwin", 0, errno.EPERM, OSError(errno.EIO, "unknown"))):
            with self.subTest(platform=platform, status=status, errno=number, probe=probe):
                process = Mock(pid=12345)
                process.poll.return_value = status
                denied = PermissionError(number, "injected permission failure")
                with patch.object(watchdog.sys, "platform", platform), \
                        patch.object(watchdog.os, "killpg", side_effect=[denied, probe]) as kill:
                    with self.assertRaises(OSError) as caught:
                        watchdog.kill_group(process, signal.SIGTERM)
                self.assertIs(probe if probe is not None else denied, caught.exception)
                if platform != "darwin" or number != errno.EPERM:
                    process.poll.assert_not_called()
                else:
                    process.poll.assert_called_once_with()
                self.assertEqual(2 if platform == "darwin" and status == 0 and number == errno.EPERM
                                 else 1, kill.call_count)

    def test_darwin_eperm_for_live_owned_leader_is_an_error(self):
        # SPEC §9.5: a real live target remains an error under injected EPERM (#1).
        with subprocess.Popen([sys.executable, "-c", "input()"], stdin=subprocess.PIPE,
                              start_new_session=True) as process:
            try:
                denied = PermissionError(errno.EPERM, "injected live-target EPERM")
                with patch.object(watchdog.sys, "platform", "darwin"), \
                        patch.object(watchdog.os, "killpg", side_effect=denied) as kill:
                    with self.assertRaises(PermissionError) as caught:
                        watchdog.kill_group(process, signal.SIGTERM)
                self.assertIs(denied, caught.exception)
                kill.assert_called_once_with(process.pid, signal.SIGTERM)
                self.assertIsNone(process.poll())
            finally:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)

    def test_storage_bound_still_stops_the_command(self):
        with tempfile.TemporaryDirectory(prefix="z53-storage-test-") as directory:
            root = Path(directory)
            (root / "oversize").write_bytes(b"x" * 2048)
            with patch.object(watchdog, "STORAGE_BYTES_MAX", 1024):
                result, _ = watchdog.run([sys.executable, "-c", "import time; time.sleep(30)"],
                                          root, root, "storage", seconds=3, storage=root)
            self.assertEqual("storage bound", result["reason"])
            self.assertLess(result["elapsed_s"], 1)

    def test_exited_leader_closed_stdout_descendant_is_killed(self):
        source = ("import os, signal, time\n"
                  "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                  "child = os.fork()\n"
                  "if child:\n"
                  " print(child, flush=True)\n"
                  " os._exit(0)\n"
                  "os.close(1); os.close(2)\n"
                  "time.sleep(30)\n")
        # SPEC §9.5: leader exit never authorizes a live-descendant cleanup skip (#1).
        processes, signals = [], []
        popen, kill_group = subprocess.Popen, watchdog.kill_group

        def spawn(*args, **kwargs):
            process = popen(*args, **kwargs)
            processes.append(process)
            return process

        def kill(process, number):
            if number == signal.SIGTERM:
                self.assertEqual(0, process.wait(timeout=3))
                os.killpg(process.pid, 0)
            signals.append(number)
            kill_group(process, number)

        try:
            with patch.object(watchdog.subprocess, "Popen", spawn), \
                    patch.object(watchdog, "kill_group", kill):
                result, text = self.run_fixture(source)
            self.assertEqual([signal.SIGTERM, signal.SIGKILL], signals)
            self.assertEqual(0, result["exit"])
            self.assertIsNone(result["reason"])
            self.assertLess(result["elapsed_s"], 1)
            state = subprocess.run(["ps", "-o", "stat=", "-p", text.strip()],
                                   capture_output=True, text=True, timeout=5).stdout.strip()
            self.assertTrue(not state or state.startswith("Z"), state)
        finally:
            for process in processes:
                kill_group(process, signal.SIGKILL)
                process.wait(timeout=5)
                process.stdout.close()

    def test_deadline_kills_term_resistant_descendant(self):
        source = ("import os, pathlib, signal, time\n"
                  "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                  "child = os.fork()\n"
                  "if directory := os.environ.get('Z53_HARNESS_CANCEL_PROBE'):\n"
                  " pathlib.Path(directory, 'fixture-' + str(os.getpid()) + '.pid').touch()\n"
                  "print(os.getpid(), flush=True)\n"
                  "time.sleep(60)\n")
        result, text = self.run_fixture(source, seconds=0.5)
        self.assertEqual("deadline", result["reason"])
        self.assertNotEqual(0, result["exit"])
        self.assertLess(result["elapsed_s"], 3)
        for process in text.splitlines():
            state = subprocess.run(["ps", "-o", "stat=", "-p", process],
                                   capture_output=True, text=True, timeout=5).stdout.strip()
            self.assertTrue(not state or state.startswith("Z"), (process, state))


class NestedCancellationTests(unittest.TestCase):
    # SPEC §1.2 and §9.5: the actual CI harness owns its detached fixtures through cancellation.
    def test_ci_harness_cancellation_releases_owned_fixtures(self):
        for phase in ("running", "cleanup", "signal-tests"):
            watchdog.check_harness_cancelled()
            with self.subTest(phase=phase):
                self.cancel_harness(phase)

    @staticmethod
    def runner_source():
        return ("import json, os, pathlib, runpy, signal\n"
                  "ci = runpy.run_path('tests/darwin-ci-test.py', run_name='nested_driver')['ci']\n"
                  "root = pathlib.Path.cwd()\n"
                  "scratch = pathlib.Path(os.environ['Z53_HARNESS_CANCEL_PROBE'])\n"
                  "for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):\n"
                  " signal.signal(number, ci.interrupted)\n"
                  "cleanup = ci.watchdog.cleanup_harness\n"
                  "def release(process):\n"
                  " (scratch / 'outer-cancelled').touch()\n"
                  " cleanup(process)\n"
                  "ci.watchdog.cleanup_harness = release\n"
                  "batch, calls = ci.batch, []\n"
                  "def invoke(root, scratch, evidence, name, command):\n"
                  " calls.append(name)\n"
                  " if name == 'harness':\n"
                  "  return batch(root, scratch, evidence, name, command)\n"
                  " return {'exit': 0, 'reason': None}, ''\n"
                  "ci.batch = invoke\n"
                  "try:\n"
                  " ci.native(root, scratch, scratch / 'evidence')\n"
                  "finally:\n"
                  " (scratch / 'calls.json').write_text(json.dumps(calls))\n")

    def cancel_harness(self, phase):
        with tempfile.TemporaryDirectory(prefix="z53-nested-test-") as directory:
            root = Path(directory)
            env = dict(os.environ, Z53_HARNESS_CANCEL_PROBE=directory,
                       Z53_HARNESS_CANCEL_PHASE=phase, TMPDIR=directory,
                       PYTHONDONTWRITEBYTECODE="1")
            with (root / "runner.log").open("wb") as log:
                runner = subprocess.Popen([sys.executable, "-c", self.runner_source()], cwd=ROOT, env=env,
                                          stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            pids, harness = [], None
            try:
                self.wait_for(lambda: len(list(root.glob("fixture-*.pid"))) == 2)
                pids = [int(path.stem[8:]) for path in root.glob("fixture-*.pid")]
                harness = int((root / "harness.pid").read_text())
                watchdog.check_harness_cancelled()
                if phase == "cleanup":
                    self.wait_for(lambda: (root / "inner-cleanup").exists())
                watchdog.check_harness_cancelled()
                started = time.monotonic()
                os.kill(runner.pid, signal.SIGTERM)
                self.wait_for(lambda: (root / "outer-cancelled").exists() or runner.poll() is not None)
                watchdog.check_harness_cancelled()
                self.wait_for(lambda: (root / "inner-cleanup").exists() or runner.poll() is not None)
                watchdog.check_harness_cancelled()
                # These real signals arrive during the inner TERM-resistant cleanup wait.
                if runner.poll() is None:
                    for number in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
                        os.kill(runner.pid, number)
                        os.kill(harness, signal.SIGUSR1)
                runner.wait(timeout=4)
                watchdog.check_harness_cancelled()
                self.assertNotEqual(0, runner.returncode)
                self.assertLess(time.monotonic() - started, 3)
                states = {pid: self.state(pid) for pid in [*pids, harness]}
                self.assertTrue(all(not state or state.startswith("Z") for state in states.values()), states)
                status = json.loads((root / "evidence/harness.json").read_text())
                self.assertEqual("signal 15", status["reason"])
                self.assertEqual("harness", json.loads((root / "calls.json").read_text())[-1])
                self.assertEqual(-signal.SIGINT, status["exit"])
                print(json.dumps({"nested_phase": phase, "pids": states, "outer": status}), flush=True)
            finally:
                # Cancel the driver before fallback cleanup so it cannot start another fixture.
                if runner.poll() is None:
                    runner.send_signal(signal.SIGTERM)
                    try:
                        runner.wait(timeout=7)
                    except subprocess.TimeoutExpired:
                        pass
                # Stop owners before the final read of their exact fixture records.
                watchdog.kill_group(runner, signal.SIGKILL)
                runner.wait(timeout=5)
                if (root / "harness.pid").exists():
                    harness = int((root / "harness.pid").read_text())
                    try:
                        os.killpg(harness, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                pids = [int(path.stem[8:]) for path in root.glob("fixture-*.pid")]
                for pid in pids:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                self.wait_for(lambda: all(not (state := self.state(pid)) or state.startswith("Z")
                                         for pid in [*pids, *([harness] if harness else [])]))
                print(json.dumps({"nested_cleanup": phase,
                                  "fixtures": {pid: self.state(pid) or "absent" for pid in pids}}), flush=True)

    def wait_for(self, predicate):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.01)
        self.fail("The owned fixture did not reach its expected state within three seconds.")

    @staticmethod
    def state(pid):
        return subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True,
                              text=True, timeout=1).stdout.strip()


class HarnessResult(unittest.TextTestResult):
    def startTest(self, test):
        watchdog.check_harness_cancelled()
        super().startTest(test)


def main():
    signal.signal(signal.SIGUSR1, watchdog.cancel_harness)
    # The cancellation regression runs one existing fixture, never another regression.
    probe = os.environ.get("Z53_HARNESS_CANCEL_PROBE")
    if probe:
        directory = Path(probe)
        (directory / "harness.pid").write_text(str(os.getpid()))
        kill_group = watchdog.kill_group

        def kill(process, number):
            kill_group(process, number)
            if number == signal.SIGTERM:
                (directory / "inner-cleanup").touch()

        watchdog.kill_group = kill
        test = "WatchdogTests.test_deadline_kills_term_resistant_descendant"
        if os.environ.get("Z53_HARNESS_CANCEL_PHASE") == "signal-tests":
            test = "CancellationTests.test_real_signals_cancel_controls_and_finish_cleanup"
        arguments = [sys.argv[0], test]
    else:
        arguments = sys.argv
    runner = unittest.TextTestRunner(verbosity=2, resultclass=HarnessResult)
    program = unittest.main(argv=arguments, testRunner=runner, exit=False)
    watchdog.check_harness_cancelled()
    # Preserve normal assertion failures as a nonzero harness exit.
    raise SystemExit(not program.result.wasSuccessful())


if __name__ == "__main__":
    main()
