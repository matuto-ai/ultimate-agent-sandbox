#!/usr/bin/env python3
"""Bounded feasibility observations inside the disposable Fedora VM only.

This is not Room launch qualification. The only state change is loading three
guest kernel modules; no mounts, firewall rules, networking, or quotas are made.
Run from the trusted cloud-init payload, never on the operator's host.
"""
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys


REQUIRED_CHECKS = (
    "selinux_enforcing", "cgroup_v2", "cgroup_controllers",
    "kernel_features", "filesystem_modules", "network_absent",
)
BOOL_FEATURES = (
    "CONFIG_NAMESPACES", "CONFIG_USER_NS", "CONFIG_PID_NS", "CONFIG_IPC_NS",
    "CONFIG_UTS_NS", "CONFIG_NET_NS", "CONFIG_SECCOMP", "CONFIG_SECCOMP_FILTER",
    "CONFIG_CGROUPS", "CONFIG_MEMCG", "CONFIG_CGROUP_PIDS", "CONFIG_CGROUP_SCHED",
    "CONFIG_FAIR_GROUP_SCHED", "CONFIG_CFS_BANDWIDTH", "CONFIG_SECURITY_SELINUX",
    "CONFIG_NETFILTER", "CONFIG_XFS_QUOTA",
)
MODULE_FEATURES = (
    "CONFIG_XFS_FS", "CONFIG_OVERLAY_FS", "CONFIG_NF_TABLES",
    "CONFIG_NF_CONNTRACK", "CONFIG_NF_NAT", "CONFIG_BRIDGE", "CONFIG_VETH",
)
MAX_REPORT_BYTES = 16384


def read_bounded(path, limit=65536):
    with open(path, "rb") as source:
        value = source.read(limit + 1)
    if len(value) > limit:
        raise ValueError("observation exceeds read limit")
    return value.decode("utf-8", errors="strict").strip()


def diagnostic(error):
    # JSON encoding escapes control characters; avoid unbounded exception text.
    return (type(error).__name__ + ": " + str(error))[:512]


def command(program, *arguments):
    executable = next((str(Path(root) / program) for root in ("/usr/sbin", "/usr/bin", "/sbin", "/bin")
                       if (Path(root) / program).is_file()), None)
    if executable is None:
        return {"returncode": None, "stdout": "", "error": "COMMAND_UNAVAILABLE:" + program}
    try:
        result = subprocess.run([executable, *arguments], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=15, check=False, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
        return {"returncode": result.returncode,
                "stdout": result.stdout[:512].decode("utf-8", errors="replace").strip(),
                "error": result.stderr[:512].decode("utf-8", errors="replace").strip()}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"returncode": None, "stdout": "", "error": diagnostic(error)}


def observe_selinux():
    result = command("getenforce")
    observation = {"getenforce": result}
    try:
        observation["sysfs_enforce"] = read_bounded("/sys/fs/selinux/enforce", 16)
    except (OSError, ValueError, UnicodeError) as error:
        observation["sysfs_error"] = diagnostic(error)
    passed = (result["returncode"] == 0 and result["stdout"] == "Enforcing"
              and observation.get("sysfs_enforce") == "1")
    return passed, observation


def observe_cgroup_v2():
    entries = []
    for line in read_bounded("/proc/self/mountinfo", 1048576).splitlines():
        before, separator, after = line.partition(" - ")
        fields, filesystem = before.split(), after.split()
        if separator and len(fields) >= 6 and filesystem and fields[4] == "/sys/fs/cgroup":
            entries.append({"filesystem": filesystem[0], "options": fields[5]})
    return len(entries) == 1 and entries[0]["filesystem"] == "cgroup2", {"mounts": entries[:8]}


def observe_controllers():
    controllers = read_bounded("/sys/fs/cgroup/cgroup.controllers", 4096).split()
    required = {"cpu", "memory", "pids"}
    return required <= set(controllers), {"available": sorted(controllers)[:32],
                                         "missing": sorted(required - set(controllers))}


def observe_kernel_features(kernel):
    if not re.fullmatch(r"[A-Za-z0-9._+\-]{1,256}", kernel):
        raise ValueError("unexpected kernel release")
    path = "/boot/config-" + kernel
    config = {}
    wanted = set(BOOL_FEATURES + MODULE_FEATURES)
    for line in read_bounded(path, 1048576).splitlines():
        name, separator, value = line.partition("=")
        if separator and name in wanted:
            if name in config:
                raise ValueError("duplicate kernel config symbol")
            config[name] = value[:32]
    observed = {name: config.get(name, "not-set") for name in sorted(wanted)}
    missing = [name for name in BOOL_FEATURES if config.get(name) != "y"]
    missing += [name for name in MODULE_FEATURES if config.get(name) not in {"y", "m"}]
    return not missing, {"config_path": path, "features": observed, "unsupported": sorted(missing)}


def observe_modules():
    # Allowed only in this disposable guest. No persistent module configuration.
    commands = {name: command("modprobe", "--", name) for name in ("xfs", "overlay", "nf_tables")}
    observation = {"modprobe": commands}
    try:
        available = sorted({line.split()[-1] for line in read_bounded("/proc/filesystems").splitlines() if line.split()})
        observation["filesystems"] = available[:64]
        observation["nf_tables_loaded"] = Path("/sys/module/nf_tables").is_dir()
    except (OSError, ValueError, UnicodeError) as error:
        observation["read_error"] = diagnostic(error)
        return False, observation
    passed = (all(item["returncode"] == 0 for item in commands.values())
              and {"xfs", "overlay"} <= set(available) and observation["nf_tables_loaded"])
    return passed, observation


def observe_network_absent():
    # No sockets, connections, or interface mutations; VM has no NIC attached.
    interfaces = sorted(entry.name for entry in Path("/sys/class/net").iterdir())
    return interfaces == ["lo"], {"interfaces": interfaces[:64]}


def build_report(nonce):
    kernel = os.uname().release
    checks = {}
    functions = (
        observe_selinux, observe_cgroup_v2, observe_controllers,
        lambda: observe_kernel_features(kernel), observe_modules, observe_network_absent,
    )
    for name, observe in zip(REQUIRED_CHECKS, functions):
        try:
            passed, observation = observe()
            checks[name] = {"status": "passed" if passed is True else "failed", "observation": observation}
        except Exception as error:
            # One unavailable observation must not erase the remaining results.
            checks[name] = {"status": "failed", "observation": {"error": diagnostic(error)}}
    try:
        uptime = float(read_bounded("/proc/uptime", 128).split()[0])
        if not math.isfinite(uptime) or uptime < 0:
            raise ValueError("invalid guest uptime")
    except (OSError, ValueError, IndexError, UnicodeError) as error:
        uptime = None
        checks["kernel_features"]["status"] = "failed"
        checks["kernel_features"]["observation"]["uptime_error"] = diagnostic(error)
    return {"version": 1, "nonce": nonce, "checks": checks,
            "kernel": kernel[:256], "guest_uptime_seconds": uptime}


def main(arguments=None):
    arguments = sys.argv[1:] if arguments is None else arguments
    if len(arguments) != 1 or not re.fullmatch(r"[0-9a-f]{32}", arguments[0]):
        print("usage: guest_probe.py LOWERCASE_HEX_NONCE_32", file=sys.stderr)
        return 2
    nonce = arguments[0]
    try:
        if read_bounded("/run/uas-vm-fixture", 64) != nonce:
            raise ValueError("fixture marker mismatch")
    except (OSError, ValueError, UnicodeError):
        print("guest probe requires this boot's disposable NoCloud fixture marker", file=sys.stderr)
        return 2
    report = build_report(nonce)
    payload = json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False)
    # The login console can leave an unterminated ANSI prompt on this UART.
    # Start our nonce-bound record on its own line; the parser stays strict.
    line = ("\nUAS_VM_REPORT:" + nonce + ":" + payload + "\n").encode("ascii")
    if len(line) > MAX_REPORT_BYTES:
        # Preserve a valid complete failure report rather than truncate JSON.
        report["checks"] = {name: {"status": "failed", "observation": {"error": "REPORT_TOO_LARGE"}}
                            for name in REQUIRED_CHECKS}
        payload = json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False)
        line = ("\nUAS_VM_REPORT:" + nonce + ":" + payload + "\n").encode("ascii")
    try:
        descriptor = os.open("/dev/ttyS0", os.O_WRONLY | os.O_NOCTTY | os.O_CLOEXEC)
        try:
            remaining = memoryview(line)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise OSError("serial write made no progress")
                remaining = remaining[written:]
        finally:
            os.close(descriptor)
    except OSError as error:
        print("guest report could not reach serial: " + diagnostic(error), file=sys.stderr)
        return 1
    return 0 if all(item["status"] == "passed" for item in report["checks"].values()) else 1


if __name__ == "__main__":
    sys.exit(main())
