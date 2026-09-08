#!/usr/bin/env python3
"""SPEC §9.4 / #1: bounded comparisons on owned loopback listeners."""

import argparse
import contextlib
import hashlib
import json
import os
import pathlib
import random
import re
import shutil
import socket
import subprocess
import time


def command(arguments, timeout=15):
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    return result.stdout + result.stderr


def port():
    for _ in range(16):
        with socket.socket() as tcp, socket.socket(type=socket.SOCK_DGRAM) as udp:
            tcp.bind(("127.0.0.1", 0))
            number = tcp.getsockname()[1]
            try:
                udp.bind(("127.0.0.1", number))
                return number
            except OSError:
                continue
    raise RuntimeError("No unused loopback port")


@contextlib.contextmanager
def server(binary, config, number, output, cpu):
    environment = dict(os.environ, GOMAXPROCS="1", GOGC="100")
    for name in ("GODEBUG", "GOMEMLIMIT", "LD_LIBRARY_PATH"):
        environment.pop(name, None)
    flag = "-conf" if pathlib.Path(binary).name == "coredns" else "-c"
    arguments = ["taskset", "-c", str(cpu), binary, flag, str(config)]
    with open(output, "wb") as sink:
        process = subprocess.Popen(arguments, stdout=sink, stderr=sink, env=environment)
        try:
            # A completed DNS exchange, not a TCP handshake, establishes readiness.
            for _ in range(20):
                if process.poll() is not None:
                    raise RuntimeError(f"Server exited: {arguments}")
                try:
                    answer = command(["dig", "@127.0.0.1", "-p", str(number),
                                      "ready.bench.test.", "A", "+short", "+time=1", "+tries=1"], 2)
                    if answer.strip() == "192.0.2.1":
                        break
                except RuntimeError:
                    pass
                time.sleep(0.05)
            else:
                raise RuntimeError("DNS readiness deadline")
            yield process
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def cpu_seconds(pid):
    fields = pathlib.Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


def rss_kib(pid):
    status = pathlib.Path(f"/proc/{pid}/status").read_text()
    return int(re.search(r"^VmRSS:\s+(\d+)", status, re.M)[1])


def measure(root, data, number, protocol, outstanding, label, duration=None):
    arguments = ["taskset", "-c", "0,3", "dnsperf", "-s", "127.0.0.1", "-p", str(number),
                 "-d", str(data), "-m", protocol, "-T", "1", "-c", str(outstanding),
                 "-q", str(outstanding), "-t", "1"]
    arguments += ["-n", "1"] if duration is None else ["-l", str(duration)]
    output = command(arguments, 15)
    (root / f"{label}.txt").write_text("$ " + " ".join(arguments) + "\n" + output)
    result = {}
    for field, pattern in {
        "sent": r"Queries sent:\s+(\d+)",
        "completed": r"Queries completed:\s+(\d+)",
        "lost": r"Queries lost:\s+(\d+)",
        "qps": r"Queries per second:\s+([\d.]+)",
        "latency_s": r"Average Latency \(s\):\s+([\d.]+)",
        "runtime_s": r"Run time \(s\):\s+([\d.]+)",
    }.items():
        result[field] = float(re.search(pattern, output)[1])
    if result["completed"] == 0 or not re.search(r"Response codes:\s+NOERROR \d+ \(100\.00%\)", output):
        raise RuntimeError("Missing successful answers: " + output)
    return result


def run_variant(options, root, data, upstream, upstream_log, variant, binary, count, trial):
    number = port()
    prefix = f"{count}-{trial}-{variant}"
    config = root / f"{prefix}.conf"
    if variant == "coredns":
        config.write_text(f""".:{number} {{
    bind 127.0.0.1
    log
    errors
    cache 3600
    forward . 127.0.0.1:{upstream} {{
        policy sequential
        max_fails 0
    }}
}}
""")
    else:
        config.write_text(f""".{{
    .listen = .{{ "127.0.0.1:{number}" }},
    .zones = .{{ .{{
        .suffix = ".",
        .upstreams = .{{ .{{ .address = "127.0.0.1:{upstream}" }} }},
        .max_fails = 0,
    }} }},
}}
""")
    with server(binary, config, number, os.devnull, 2) as process:
        warm = measure(root, data, number, "udp", 1, prefix + "-warm")
        assert warm["sent"] == count and warm["completed"] == count and warm["lost"] == 0
        upstream_bytes = upstream_log.stat().st_size
        rows = []
        cases = [("udp", 1), ("udp", 32), ("tcp", 32)]
        for protocol, outstanding in cases:
            label = f"{prefix}-{protocol}-{outstanding}"
            before = cpu_seconds(process.pid)
            result = measure(root, data, number, protocol, outstanding, label, 1 if options.smoke else 3)
            result.update(variant=variant, names=count, trial=trial, protocol=protocol,
                          outstanding=outstanding, cpu_s=cpu_seconds(process.pid) - before,
                          rss_kib=rss_kib(process.pid))
            result["upstream_bytes"] = upstream_log.stat().st_size - upstream_bytes
            assert result["upstream_bytes"] == 0, "Cache workload reached the upstream"
            rows.append(result)
            print(json.dumps(result), flush=True)
        return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--safe", required=True)
    parser.add_argument("--fast", required=True)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--smoke", action="store_true")
    options = parser.parse_args()
    root = options.output
    root.mkdir()
    variants = [("safe", options.safe), ("fast", options.fast), ("coredns", shutil.which("coredns"))]
    metadata = {"uname": list(os.uname()), "source": command(["git", "rev-parse", "HEAD"]).strip(),
                "core_version": command(["coredns", "-version"]), "dnsperf": shutil.which("dnsperf"),
                "resolver_cpu": 2, "generator_cpus": [0, 3], "upstream_cpu": 1,
                "logging": "enabled, both resolver sinks /dev/null", "GOMAXPROCS": 1,
                "binaries": {name: {"path": str(pathlib.Path(path).resolve()),
                                    "sha256": hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()}
                             for name, path in variants}}
    (root / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    upstream = port()
    config = root / "upstream.Corefile"
    upstream_log = root / "upstream.log"
    config.write_text(f"""bench.test:{upstream} {{
    bind 127.0.0.1
    log
    template IN A {{
        answer "{{{{ .Name }}}} 3600 IN A 192.0.2.1"
    }}
}}
""")
    results = []
    with server(shutil.which("coredns"), config, upstream, upstream_log, 1):
        for count in ([64] if options.smoke else [1, 4096]):
            names = [f"q{index:05}.bench.test. A\n" for index in range(count)]
            random.Random(53).shuffle(names)
            data = root / f"queries-{count}.txt"
            data.write_text("".join(names))
            for trial in range(1 if options.smoke else 3):
                order = variants[trial:] + variants[:trial]
                for variant, binary in order:
                    results.extend(run_variant(options, root, data, upstream, upstream_log,
                                               variant, binary, count, trial))
                    (root / "results.json").write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    main()
