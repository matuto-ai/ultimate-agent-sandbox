#!/usr/bin/env python3
"""Prepare a read-only, signed-RPM/source payload for the no-NIC CI guest.

This does not install RPMs, mount filesystems, or run a guest on the host. DNF is
only a resolver against explicit Fedora HTTPS repositories. Downloads are bounded
HTTPS-only curl transfers and RPM signatures are checked with an isolated key DB.
Actual Fedora/Ubuntu package-tool compatibility is established by the VM CI job,
not by the offline unit contracts. Signed dependencies are recorded, not claimed
to be a reproducibly pinned package closure.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import time
from urllib.parse import unquote, urlsplit
import uuid


PACKAGES = ("moby-engine", "docker-cli", "container-selinux", "nftables", "iproute", "xfsprogs", "policycoreutils", "shadow-utils")
REPOSITORIES = {
    "fedora": "https://dl.fedoraproject.org/pub/fedora/linux/releases/44/Everything/x86_64/os/",
    "updates": "https://dl.fedoraproject.org/pub/fedora/linux/updates/44/Everything/x86_64/",
}
MAX_PACKAGES = 512
MAX_PACKAGE_BYTES = 128 * 1024 * 1024
MAX_PACKAGE_TOTAL = 1024 * 1024 * 1024
MAX_WORK_BYTES = 2 * 1024 * 1024 * 1024
MAX_COMMAND_OUTPUT = 4 * 1024 * 1024
MAX_SOURCE_BYTES = 4 * 1024 * 1024
BUILD_TIMEOUT = 1200


def _stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def _bytes(directory):
    return sum(path.stat().st_size for path in directory.rglob("*") if path.is_file())


def command(arguments, *, directory, timeout=300, environment=None):
    """Bound logs/time/workspace; do not inherit account/config environment."""
    identifier = uuid.uuid4().hex
    stdout, stderr = (directory / (identifier + suffix) for suffix in (".out", ".err"))
    env = {"PATH": os.defpath, "HOME": str(directory / "home"), "LC_ALL": "C",
           "GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off", "GO111MODULE": "off",
           "GOCACHE": str(directory / "go-cache"), "GOPATH": str(directory / "go-path"),
           "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64"}
    if environment:
        env.update(environment)
    started = time.monotonic()
    executable = shutil.which(arguments[0])
    if executable is None:
        raise RuntimeError("required payload tool unavailable: " + str(arguments[0]))
    with stdout.open("xb") as output, stderr.open("xb") as errors:
        process = subprocess.Popen([executable, *arguments[1:]], stdin=subprocess.DEVNULL, stdout=output,
                                   stderr=errors, env=env, cwd=directory)
        try:
            while process.poll() is None:
                if time.monotonic() - started > timeout:
                    raise RuntimeError("payload command timed out: " + str(arguments[0]))
                if max(stdout.stat().st_size, stderr.stat().st_size) > MAX_COMMAND_OUTPUT:
                    raise RuntimeError("payload command output budget exceeded")
                if _bytes(directory) > MAX_WORK_BYTES:
                    raise RuntimeError("payload workspace byte budget exceeded")
                time.sleep(0.2)
            if max(stdout.stat().st_size, stderr.stat().st_size) > MAX_COMMAND_OUTPUT:
                raise RuntimeError("payload command output budget exceeded")
            if _bytes(directory) > MAX_WORK_BYTES:
                raise RuntimeError("payload workspace byte budget exceeded")
            if process.returncode:
                detail = stderr.read_bytes()[-2048:].decode(errors="replace")
                raise RuntimeError(f"{arguments[0]} failed ({process.returncode}): {detail}")
        finally:
            _stop(process)
    return stdout.read_text(errors="strict")


def package_urls(output):
    """DNF also prints informational lines; every URL it prints must be safe."""
    result, names = [], set()
    for line in output.splitlines():
        line = line.strip()
        if "://" not in line:
            continue
        parsed = urlsplit(line)
        name = unquote(PurePosixPath(parsed.path).name)
        if (parsed.scheme != "https" or parsed.username or parsed.password or parsed.port
                or not parsed.hostname or not (parsed.hostname == "fedoraproject.org"
                                               or parsed.hostname.endswith(".fedoraproject.org"))
                or parsed.query or parsed.fragment or not re.fullmatch(r"[A-Za-z0-9._+~\-]+\.rpm", name)):
            raise RuntimeError("resolver returned an unexpected package URL")
        if name in names:
            raise RuntimeError("resolver returned duplicate package filenames")
        names.add(name)
        result.append((name, line))
    if not 1 <= len(result) <= MAX_PACKAGES:
        raise RuntimeError("resolved package count is outside its budget")
    return sorted(result)


def verify_key_listing(output, fingerprint):
    primary, waiting, public_keys = [], False, 0
    for line in output.splitlines():
        fields = line.split(":")
        if fields[0] == "pub":
            public_keys += 1
            waiting = True
        elif fields[0] == "fpr" and waiting:
            if len(fields) <= 9:
                raise RuntimeError("malformed signing-key observation")
            primary.append(fields[9].upper())
            waiting = False
    if public_keys != 1 or primary != [fingerprint] or waiting:
        raise RuntimeError("exported signing key does not match the exact Fedora release key")


def verify_signature_output(output):
    # A digest-only OK is not authentication. The private DB has exactly one
    # independently fingerprint-checked Fedora release certificate.
    lines = [line.strip() for line in output.splitlines()]
    signature = [line for line in lines if "signature" in line.lower()]
    if (not signature or any(not line.endswith(": OK") for line in signature)
            or any(token in output.upper() for token in ("NOT OK", "NOKEY", "NOTFOUND", ": BAD"))):
        raise RuntimeError("RPM has no verified release-key signature")


def package_metadata(filename, output):
    """Require one bounded NEVRA record; show actionable, escaped CI failures."""
    metadata = output.removesuffix("\n").split("\t")
    if (len(output) > 2048 or not output.endswith("\n") or output.count("\n") != 1
            or len(metadata) != 5
            or not all(re.fullmatch(r"[A-Za-z0-9._+~^\-]{1,256}", item) for item in metadata)
            or not metadata[1].isascii() or not metadata[1].isdigit()
            or metadata[4] not in ("x86_64", "noarch")):
        # repr prevents terminal control characters/newlines from escaping this
        # diagnostic, and truncation bounds even malformed signed metadata.
        detail = repr(output[:512])[:2048]
        raise RuntimeError(f"unexpected RPM metadata for {filename[:200]!r}: {detail}")
    return metadata


def source_files(repository_root, paths):
    root = Path(repository_root)
    if not root.is_absolute() or root.resolve() != root or not root.is_dir():
        raise ValueError("repository root must be a canonical existing directory")
    if (not isinstance(paths, (tuple, list)) or not 1 <= len(paths) <= 64
            or any(type(value) is not str for value in paths) or len(set(paths)) != len(paths)):
        raise ValueError("an explicit bounded unique source allowlist is required")
    selected, total = [], 0
    for value in paths:
        if type(value) is not str or "\\" in value:
            raise ValueError("unsafe source path")
        relative = PurePosixPath(value)
        if (relative.is_absolute() or str(relative) != value or any(part in (".", "..", ".git") for part in relative.parts)
                or not relative.parts or any(ord(char) < 32 or ord(char) == 127 for char in value)):
            raise ValueError("unsafe source path")
        path = root / value
        if path.resolve() != path or not path.is_file() or path.stat().st_nlink != 1:
            raise ValueError("source must be an ordinary non-symlinked file")
        size = path.stat().st_size
        total += size
        if size > 1024 * 1024 or total > MAX_SOURCE_BYTES:
            raise ValueError("source byte budget exceeded")
        selected.append((value, path))
    return selected


def build_payload(directory, repository_root, nonce, *, source_paths):
    """Return an owned read-only ISO; all installations occur later in guest.

    ``source_paths`` is the caller's explicit repository-relative allowlist. The
    resulting files are under ``/repo`` on ISO label ``UAS_PAYLOAD``. The static
    existing Go fixture is ``/fixture``; signed packages are ``/rpms`` and the
    fingerprint-checked certificate and manifest are at the ISO root.
    """
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.geteuid() == 0:
        raise RuntimeError("payload preparation runs only as unprivileged disposable CI user")
    if not re.fullmatch(r"[0-9a-f]{32}", nonce):
        raise ValueError("invalid fixture nonce")
    directory, repository_root = Path(directory), Path(repository_root)
    if not directory.is_absolute() or directory.resolve() != directory or not directory.is_dir():
        raise ValueError("owned build parent must be a canonical existing directory")
    selected = source_files(repository_root, source_paths)
    fixture = source_files(repository_root, ["tests/vm/boundary_fixture.go"])[0][1]
    if "tests/vm/boundary_fixture.go" not in source_paths:
        raise ValueError("the explicit allowlist must contain the compiled fixture source")
    lock_path = source_files(repository_root, ["tests/vm/fedora-image.json"])[0][1]
    lock = json.loads(lock_path.read_text())
    fingerprint = lock["signing_fingerprint"]
    if (lock["release"] != "44-1.7" or not re.fullmatch(r"[A-F0-9]{40}", fingerprint)
            or lock["keyring_url"] != "https://fedoraproject.org/fedora.gpg"):
        raise ValueError("payload expects the reviewed Fedora 44 image lock")
    work = directory / "payload-build"
    work.mkdir(mode=0o700)  # Never adopt/overwrite a previous partial build.
    for name in ("home", "gnupg", "rpmdb", "installroot", "repos", "cache", "persist", "logs", "payload"):
        (work / name).mkdir(mode=0o700)
    payload = work / "payload"
    packages = payload / "rpms"
    packages.mkdir()
    (payload / "repo").mkdir()
    started = time.monotonic()

    def run(arguments, timeout=300):
        remaining = BUILD_TIMEOUT - (time.monotonic() - started)
        if remaining <= 0:
            raise RuntimeError("payload build exceeded its total time budget")
        return command(arguments, directory=work, timeout=min(timeout, remaining))

    def fetch(url, target, maximum):
        if maximum <= 0:
            raise RuntimeError("download byte budget exhausted")
        run(["curl", "--fail", "--location", "--silent", "--show-error", "--proto", "=https",
             "--proto-redir", "=https", "--max-time", "120", "--max-filesize", str(maximum),
             "--output", str(target), url], timeout=130)
        if not target.is_file() or target.is_symlink() or target.stat().st_size > maximum:
            raise RuntimeError("download is missing or exceeded its byte budget")

    keyring = work / "fedora.gpg"
    fetch(lock["keyring_url"], keyring, 1024 * 1024)
    gpg = ["gpg", "--no-options", "--homedir", str(work / "gnupg"), "--batch", "--no-auto-key-retrieve"]
    key = payload / "fedora-44.asc"
    key.write_text(run([*gpg, "--no-default-keyring", "--keyring", str(keyring), "--armor", "--export", fingerprint]))
    verify_key_listing(run([*gpg, "--with-colons", "--fingerprint", "--show-keys", str(key)]), fingerprint)
    run(["rpm", "--dbpath", str(work / "rpmdb"), "--initdb"])
    run(["rpmkeys", "--dbpath", str(work / "rpmdb"), "--import", str(key)])
    config = work / "dnf.conf"
    config.write_text("[main]\nplugins=1\ngpgcheck=1\nsslverify=1\ninstall_weak_deps=False\n"
                      "keepcache=True\nskip_if_unavailable=False\ntimeout=30\nretries=2\n")
    repository = work / "repos/fedora.repo"
    repository.write_text("".join(f"[{name}]\nname=UAS Fedora 44 {name}\nbaseurl={url}\nenabled=1\n"
                                  f"gpgcheck=1\ngpgkey=file://{key}\nsslverify=1\nskip_if_unavailable=0\n\n"
                                  for name, url in REPOSITORIES.items()))
    dnf = ["dnf", "--config", str(config), "--releasever=44", "--forcearch=x86_64",
           "--installroot", str(work / "installroot"), "--setopt=reposdir=" + str(work / "repos"),
           "--setopt=cachedir=" + str(work / "cache"), "--setopt=persistdir=" + str(work / "persist"),
           "--setopt=logdir=" + str(work / "logs"), "--disableplugin=*", "--enableplugin=download"]
    # forcearch sets the solver basearch, not the download query's architecture
    # filter: DNF4 otherwise selects all compatible arches, including i686.
    urls = package_urls(run([*dnf, "download", "--arch=x86_64,noarch", "--resolve", "--alldeps", "--url", "--urlprotocol=https",
                             *PACKAGES], timeout=600))
    manifest = {"version": 1, "nonce": nonce, "release": "44", "signing_fingerprint": fingerprint,
                "key": {"file": key.name, "sha256": hashlib.sha256(key.read_bytes()).hexdigest(), "bytes": key.stat().st_size},
                "packages": [], "source": [], "dependencies_reproducibly_pinned": False}
    total = 0
    for name, url in urls:
        target = packages / name
        fetch(url, target, min(MAX_PACKAGE_BYTES, MAX_PACKAGE_TOTAL - total))
        total += target.stat().st_size
        if total > MAX_PACKAGE_TOTAL:
            raise RuntimeError("RPM bundle byte budget exceeded")
        verify_signature_output(run(["rpmkeys", "--dbpath", str(work / "rpmdb"), "--checksig", "--verbose", str(target)]))
        metadata = package_metadata(name, run(["rpm", "--dbpath", str(work / "rpmdb"), "-qp", "--queryformat",
                        "%{NAME}\\t%{EPOCHNUM}\\t%{VERSION}\\t%{RELEASE}\\t%{ARCH}\\n", str(target)]))
        with target.open("rb") as value:
            digest = hashlib.file_digest(value, "sha256").hexdigest()
        manifest["packages"].append({"file": name, "name": metadata[0], "epoch": metadata[1],
                                     "version": metadata[2], "release": metadata[3], "arch": metadata[4],
                                     "bytes": target.stat().st_size, "sha256": digest, "signature_verified": True})
    if not set(PACKAGES) <= {item["name"] for item in manifest["packages"]}:
        raise RuntimeError("resolved package bundle omitted a required package")
    for name, source in selected:
        target = payload / "repo" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        target.chmod(0o444)
        manifest["source"].append({"file": name, "bytes": target.stat().st_size,
                                    "sha256": hashlib.sha256(target.read_bytes()).hexdigest()})
    # Compile the exact copied bytes whose digest is in the manifest, not a
    # mutable original path that could diverge after the source copy.
    run(["go", "build", "-trimpath", "-ldflags=-s -w", "-o", str(payload / "fixture"),
         str(payload / "repo/tests/vm/boundary_fixture.go")], timeout=120)
    binary = payload / "fixture"
    if not binary.is_file() or not 0 < binary.stat().st_size <= 32 * 1024 * 1024:
        raise RuntimeError("static fixture is missing or exceeds its byte budget")
    manifest["fixture"] = {"sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "bytes": binary.stat().st_size}
    (payload / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")
    iso = work / "payload.iso"
    run(["genisoimage", "-quiet", "-output", str(iso), "-volid", "UAS_PAYLOAD", "-joliet", "-rock", str(payload)])
    if not iso.is_file() or iso.stat().st_size > MAX_PACKAGE_TOTAL + 64 * 1024 * 1024:
        raise RuntimeError("payload ISO is missing or exceeds its byte budget")
    iso.chmod(0o444)
    print("VM payload:", json.dumps({"packages": len(manifest["packages"]), "package_bytes": total,
          "signing_fingerprint": fingerprint, "manifest_sha256": hashlib.sha256((payload / "manifest.json").read_bytes()).hexdigest(),
          "package_versions": [f"{p['name']}-{p['epoch']}:{p['version']}-{p['release']}.{p['arch']}" for p in manifest["packages"]],
          "dependencies_reproducibly_pinned": False}, sort_keys=True), flush=True)
    return iso
