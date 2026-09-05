"""Bound native CI commands and their compact evidence (#1)."""

import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import subprocess
import time

LOG_BYTES_MAX = 2 * 1024 * 1024
STORAGE_BYTES_MAX = 1024 * 1024 * 1024
cancellation_signal = None
harness_cancellation_signal = None


class Cancelled(RuntimeError):
    pass


def cancel(number):
    # Signal handlers only latch. Repeated signals cannot interrupt cleanup or artifact writes.
    global cancellation_signal
    if cancellation_signal is None:
        cancellation_signal = number


def cancel_harness(number, _frame):
    # SIGUSR1 belongs to the outer CI watchdog, not the harness signal tests.
    global harness_cancellation_signal
    if harness_cancellation_signal is None:
        harness_cancellation_signal = number


def check_harness_cancelled():
    if harness_cancellation_signal is not None:
        # unittest propagates KeyboardInterrupt but catches ordinary exceptions.
        raise KeyboardInterrupt("The CI watchdog cancelled the harness.")


def check_cancelled():
    check_harness_cancelled()
    if cancellation_signal is not None:
        raise Cancelled(f"The runner received signal {cancellation_signal}.")


def storage_bytes(root):
    total = 0
    for directory, _, files in os.walk(root):
        for name in files:
            path = Path(directory, name)
            if not path.is_symlink():
                try:
                    total += path.stat().st_size
                except FileNotFoundError:
                    pass
    return total


def kill_group(process, sig):
    try:
        os.killpg(process.pid, sig)
    except ProcessLookupError:
        pass


def cleanup_group(process):
    kill_group(process, signal.SIGTERM)
    try:
        process.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        pass
    kill_group(process, signal.SIGKILL)
    process.wait(timeout=5)


def cleanup_harness(process):
    # The harness owns detached fixtures. Let its finally blocks release them first.
    try:
        process.send_signal(signal.SIGUSR1)
        # Inner waits: 5.5s watchdog, 4s thread, 5s fallback reap, two 5s PID checks.
        process.wait(timeout=25)
    except subprocess.TimeoutExpired:
        pass
    finally:
        cleanup_group(process)


def run(command, cwd, evidence, name, *, seconds=180, env=None, storage=None,
        cleanup=cleanup_group):
    """Preserve nonzero status, deadlines, and bounded logs without shell pipelines."""
    check_cancelled()
    evidence.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(cwd).free < STORAGE_BYTES_MAX:
        raise RuntimeError("Less than 1 GiB remains before the command.")
    start = time.monotonic()
    result = {"command": command, "cwd": str(cwd), "deadline_s": seconds}
    check_cancelled()
    process = subprocess.Popen(command, cwd=cwd, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, start_new_session=True)
    reason = None
    written = 0
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    os.set_blocking(process.stdout.fileno(), False)
    next_storage_check = start
    try:
        with (evidence / f"{name}.log").open("wb") as log:
            # Poll cancellation even after stdout closes. Selectors can suppress InterruptedError.
            while selector.get_map() or process.poll() is None:
                check_cancelled()
                now = time.monotonic()
                if now - start >= seconds:
                    reason = "deadline"
                    break
                if storage is not None and now >= next_storage_check:
                    if storage_bytes(storage) > STORAGE_BYTES_MAX:
                        reason = "storage bound"
                        break
                    next_storage_check = now + 1
                for key, _ in selector.select(min(0.1, seconds - (now - start))):
                    data = os.read(key.fd, 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    remaining = LOG_BYTES_MAX - written
                    log.write(data[:remaining])
                    written += len(data[:remaining])
                    if len(data) > remaining:
                        reason = "log bound"
                        break
                if reason:
                    break
    finally:
        # Even an exited leader can leave descendants with closed output descriptors.
        cleanup(process)
        selector.close()
        process.stdout.close()
        if cancellation_signal is not None:
            reason = f"signal {cancellation_signal}"
        result.update(exit=process.returncode, reason=reason,
                      elapsed_s=round(time.monotonic() - start, 3), log_bytes=written)
        (evidence / f"{name}.json").write_text(json.dumps(result, indent=2) + "\n")
    check_cancelled()
    print(f"{name}: exit={result['exit']} reason={reason}", flush=True)
    return result, (evidence / f"{name}.log").read_text(errors="replace")
