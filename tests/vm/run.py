#!/usr/bin/env python3
"""Account-free, no-NIC Fedora/QEMU TCG feasibility test; not a Room launcher."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time
import uuid

HERE = Path(__file__).resolve().parent
BOOT_TIMEOUT = 600
LOG_LIMIT = 16 * 1024 * 1024
REQUIRED_CHECKS = {"selinux_enforcing", "cgroup_v2", "cgroup_controllers", "kernel_features", "filesystem_modules", "network_absent"}


def command(arguments, *, timeout=60):
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError(f"{arguments[0]} failed ({result.returncode}): {result.stderr[-4096:]}")
    return result.stdout


def download(url, path, maximum):
    # No credentials; HTTPS-only redirects, finite time and byte budgets.
    command(["curl", "--fail", "--location", "--silent", "--show-error",
             "--proto", "=https", "--proto-redir", "=https", "--max-time", "300",
             "--max-filesize", str(maximum), "--output", str(path), url], timeout=310)
    if path.stat().st_size > maximum:
        raise RuntimeError("download exceeded its byte budget")


def verify_signed_checksum(lock, status, checksum):
    fingerprints = [line.split()[2] for line in status.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")]
    if fingerprints != [lock["signing_fingerprint"]]:
        raise RuntimeError("checksum signer does not match pinned Fedora release key")
    pattern = r"^SHA256 \(" + re.escape(lock["filename"]) + r"\) = ([0-9a-f]{64})$"
    if re.findall(pattern, checksum, re.MULTILINE) != [lock["sha256"]]:
        raise RuntimeError("signed image checksum does not match repository pin")


def fetch_image(lock, directory):
    checksum, keyring, image = (directory / name for name in ("CHECKSUM", "fedora.gpg", lock["filename"]))
    download(lock["checksum_url"], checksum, 65536)
    download(lock["keyring_url"], keyring, 1024 * 1024)
    home = directory / "gnupg"
    home.mkdir(mode=0o700)
    status = command(["gpg", "--no-options", "--homedir", str(home), "--batch", "--no-auto-key-retrieve",
                      "--no-default-keyring", "--keyring", str(keyring), "--status-fd", "1", "--verify", str(checksum)])
    verify_signed_checksum(lock, status, checksum.read_text())
    download(lock["image_url"], image, lock["image_bytes"])
    with image.open("rb") as source:
        actual = hashlib.file_digest(source, "sha256").hexdigest()
    if image.stat().st_size != lock["image_bytes"] or actual != lock["sha256"]:
        raise RuntimeError("downloaded image differs from verified repository pin")
    info = json.loads(command(["qemu-img", "info", "--output=json", str(image)]))
    if info["format"] != "qcow2" or info.get("backing-filename"):
        raise RuntimeError("expected a standalone qcow2 image")
    image.chmod(0o444)
    return image


def seed(directory, nonce):
    # JSON is valid YAML. No passwords, authorized keys, packages or network URLs.
    payload = {"disable_root": True, "ssh_pwauth": False, "users": [],
               "write_files": [{"path": "/run/uas-vm-probe.py", "permissions": "0600", "encoding": "b64",
                                "content": base64.b64encode((HERE / "guest_probe.py").read_bytes()).decode()},
                               {"path": "/run/uas-vm-fixture", "permissions": "0600", "content": nonce}],
               "runcmd": [["python3", "/run/uas-vm-probe.py", nonce]],
               "power_state": {"mode": "poweroff", "delay": "now", "timeout": 30, "condition": True}}
    user_data, metadata = directory / "user-data", directory / "meta-data"
    user_data.write_text("#cloud-config\n" + json.dumps(payload))
    metadata.write_text(json.dumps({"instance-id": "uas-vm-" + nonce, "local-hostname": "uas-vm-fixture"}))
    result = directory / "seed.iso"
    command(["cloud-localds", str(result), str(user_data), str(metadata)])
    return result


def qemu_arguments(directory, overlay, seed_image):
    # Deliberately no KVM, network backend, host forwarding, shared filesystem,
    # host device, runtime socket, monitor listener, or privileged QEMU process.
    return ["qemu-system-x86_64", "-machine", "q35", "-accel", "tcg,thread=multi",
            "-cpu", "max", "-smp", "2", "-m", "2048", "-nodefaults", "-display", "none",
            "-monitor", "none", "-serial", "file:" + str(directory / "serial.log"),
            "-nic", "none", "-no-reboot", "-boot", "order=c,menu=off",
            "-drive", f"file={overlay},format=qcow2,if=virtio",
            "-drive", f"file={seed_image},format=raw,if=virtio,readonly=on"]


def parse_report(serial, nonce):
    prefix = "UAS_VM_REPORT:" + nonce + ":"
    reports = [line[len(prefix):] for line in serial.splitlines() if line.startswith(prefix)]
    if len(reports) != 1 or len(reports[0]) > 65536:
        raise RuntimeError("expected one bounded report from this guest boot")
    result = json.loads(reports[0])
    if result.get("version") != 1 or result.get("nonce") != nonce or set(result.get("checks", {})) != REQUIRED_CHECKS:
        raise RuntimeError("incomplete or mismatched guest report")
    if any(check.get("status") != "passed" for check in result["checks"].values()):
        raise RuntimeError("guest prerequisites failed: " + json.dumps(result, sort_keys=True))
    return result


def stop_process(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def boot(directory, arguments, nonce):
    started = time.monotonic()
    with (directory / "qemu.log").open("w") as output:
        process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=output, stderr=output)
        try:
            while process.poll() is None:
                if time.monotonic() - started > BOOT_TIMEOUT:
                    raise RuntimeError("TCG boot/prerequisite/shutdown exceeded 600 seconds")
                if any(path.exists() and path.stat().st_size > LOG_LIMIT for path in (directory / "qemu.log", directory / "serial.log")):
                    raise RuntimeError("guest log budget exceeded")
                time.sleep(1)
            if process.returncode != 0:
                raise RuntimeError(f"QEMU exited {process.returncode}")
            report = parse_report((directory / "serial.log").read_text(errors="replace"), nonce)
            return report, round(time.monotonic() - started, 3)
        finally:
            stop_process(process)


def main():
    # This test is deliberately CI-only: do not install packages or invoke VM
    # infrastructure on an unselected user host from a convenience command.
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.geteuid() == 0:
        raise RuntimeError("run only as the unprivileged user on a disposable GitHub Actions runner")
    lock = json.loads((HERE / "fedora-image.json").read_text())
    started = time.monotonic()
    nonce = uuid.uuid4().hex
    directory = None
    try:
        with tempfile.TemporaryDirectory(prefix="uas-fedora-vm-") as temporary:
            directory = Path(temporary)
            try:
                print("Host QEMU:", command(["qemu-system-x86_64", "--version"]).splitlines()[0], flush=True)
                image = fetch_image(lock, directory)
                download_seconds = round(time.monotonic() - started, 3)
                overlay = directory / "guest.qcow2"
                command(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(image), str(overlay)])
                report, boot_seconds = boot(directory, qemu_arguments(directory, overlay, seed(directory, nonce)), nonce)
                print("VM feasibility:", json.dumps({"image_sha256": lock["sha256"], "image_signature_verified": True,
                    "accelerator": "tcg", "download_verify_seconds": download_seconds,
                    "boot_probe_shutdown_seconds": boot_seconds, "guest": report}, sort_keys=True), flush=True)
            except BaseException:
                for name in ("qemu.log", "serial.log"):
                    path = directory / name
                    if path.exists():
                        with path.open("rb") as log:
                            log.seek(max(0, path.stat().st_size - 32768))
                            print(name + " tail:", log.read(32768).decode(errors="replace"), flush=True)
                raise
    finally:
        print("VM cleanup:", json.dumps({"temporary_directory_removed": directory is None or not directory.exists(),
              "elapsed_seconds": round(time.monotonic() - started, 3)}), flush=True)


if __name__ == "__main__":
    # TERM on workflow cancellation still unwinds process and disk cleanup.
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    main()
