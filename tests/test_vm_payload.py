"""Offline preparation contracts; no RPM download/install or VM execution."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch


SPEC = importlib.util.spec_from_file_location("vm_payload", Path(__file__).parent / "vm/prepare_payload.py")
payload = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(payload)
FINGERPRINT = "36F612DCF27F7D1A48A835E4DBFCF71C6D9F90A6"


class VMPayloadTests(unittest.TestCase):
    def test_requires_explicit_disposable_ci_before_any_effect(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(payload, "command") as command:
            with self.assertRaises(RuntimeError):
                payload.build_payload(Path("/tmp"), Path("/tmp"), "a" * 32, source_paths=[])
            command.assert_not_called()
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}), patch.object(payload.os, "geteuid", return_value=0):
            with self.assertRaises(RuntimeError):
                payload.build_payload(Path("/tmp"), Path("/tmp"), "a" * 32, source_paths=[])

    def test_resolver_urls_are_https_official_bounded_unique_and_plain_rpms(self):
        url = "https://dl.fedoraproject.org/pub/fedora/linux/Packages/m/moby-engine-1.fc44.x86_64.rpm"
        self.assertEqual([("moby-engine-1.fc44.x86_64.rpm", url)], payload.package_urls("info\n" + url))
        for bad in ("", url + "\n" + url, url.replace("https:", "http:"),
                    url.replace("dl.fedoraproject.org", "fedoraproject.org.attacker.invalid"),
                    url.replace("https://", "https://account:password@"), url + "?download=1",
                    url.replace("moby-engine-1.fc44.x86_64.rpm", "%2fescape.rpm")):
            with self.subTest(bad=bad), self.assertRaises(RuntimeError):
                payload.package_urls(bad)
        with patch.object(payload, "MAX_PACKAGES", 1), self.assertRaises(RuntimeError):
            payload.package_urls(url + "\n" + url.replace("moby-engine", "docker-cli"))

    def test_only_exact_single_primary_signing_certificate_is_accepted(self):
        key = "pub:::::::::\nfpr:::::::::" + FINGERPRINT + ":\nuid:::::::::Fedora:\n"
        payload.verify_key_listing(key, FINGERPRINT)
        for bad in (key + key, "pub:::::::::\n" + key, key.replace(FINGERPRINT, "F" * 40),
                    "", "pub:::::::::\n", "pub:::::::::\nfpr:\n"):
            with self.assertRaises(RuntimeError):
                payload.verify_key_listing(bad, FINGERPRINT)

    def test_digest_only_unknown_key_bad_and_missing_signatures_fail(self):
        good = "file.rpm:\n    Header V4 RSA/SHA256 Signature, key ID 6d9f90a6: OK\n    Payload SHA256 digest: OK\n"
        payload.verify_signature_output(good)
        for bad in ("file.rpm: digests OK", good.replace(": OK", ": BAD", 1),
                    good.replace(": OK", ": NOKEY", 1), good + "signature: NOTFOUND\n", ""):
            with self.assertRaises(RuntimeError):
                payload.verify_signature_output(bad)

    def test_source_allowlist_rejects_traversal_symlinks_hardlinks_and_size(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "file.py").write_text("fixture")
            self.assertEqual([("file.py", root / "file.py")], payload.source_files(root, ["file.py"]))
            (root / "alias.py").symlink_to(root / "file.py")
            for paths in ([], ["file.py", "file.py"], ["../file.py"], ["/file.py"], ["./file.py"],
                          ["alias.py"], [".git/config"], [None]):
                with self.subTest(paths=paths), self.assertRaises(ValueError):
                    payload.source_files(root, paths)
            os.link(root / "file.py", root / "hard.py")
            with self.assertRaises(ValueError):
                payload.source_files(root, ["file.py"])
            (root / "hard.py").unlink()
            with patch.object(payload, "MAX_SOURCE_BYTES", 2), self.assertRaises(ValueError):
                payload.source_files(root, ["file.py"])

    def test_command_restricts_environment_and_terminates_only_owned_process(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            process = Mock()
            process.poll.return_value = None
            with patch.object(payload.subprocess, "Popen", return_value=process) as launch, \
                    patch.object(payload.shutil, "which", return_value="/usr/bin/fixture-tool"), \
                    patch.object(payload.time, "monotonic", side_effect=[0, 2]), \
                    patch.dict(os.environ, {"SECRET_TOKEN": "must-not-leak", "HTTP_PROXY": "must-not-leak"}):
                with self.assertRaises(RuntimeError):
                    payload.command(["fixture-tool"], directory=directory, timeout=1)
            env = launch.call_args.kwargs["env"]
            self.assertNotIn("SECRET_TOKEN", env)
            self.assertNotIn("HTTP_PROXY", env)
            self.assertEqual("off", env["GOPROXY"])
            self.assertEqual(str(directory / "home"), env["HOME"])
            process.terminate.assert_called_once()
            process.wait.assert_called_once_with(timeout=5)
            process.kill.assert_not_called()

    def test_complete_build_is_private_offline_install_free_and_manifest_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, build = root / "repo", root / "build"
            repo.mkdir(); build.mkdir()
            (repo / "tests/vm").mkdir(parents=True)
            (repo / "uas").mkdir()
            (repo / "uas/__init__.py").write_text("# synthetic fixture source\n")
            (repo / "tests/vm/boundary_fixture.go").write_text("package main\nfunc main() {}\n")
            (repo / "tests/vm/fedora-image.json").write_text(json.dumps({
                "release": "44-1.7", "keyring_url": "https://fedoraproject.org/fedora.gpg",
                "signing_fingerprint": FINGERPRINT}))
            calls = []

            def fake(arguments, *, directory, **kwargs):
                calls.append(arguments)
                program = arguments[0]
                if program == "curl":
                    Path(arguments[arguments.index("--output") + 1]).write_bytes(b"synthetic fixture bytes")
                elif program == "gpg":
                    if "--export" in arguments:
                        return "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfixture\n"
                    return "pub:::::::::\nfpr:::::::::" + FINGERPRINT + ":\n"
                elif program == "dnf":
                    return "\n".join("https://dl.fedoraproject.org/pub/fedora/linux/Packages/" + name + "-1-1.fc44.x86_64.rpm"
                                     for name in payload.PACKAGES)
                elif program == "rpmkeys" and "--checksig" in arguments:
                    return "Header V4 RSA/SHA256 Signature, key ID 6d9f90a6: OK\nPayload SHA256 digest: OK\n"
                elif program == "rpm" and "-qp" in arguments:
                    name = Path(arguments[-1]).name.removesuffix("-1-1.fc44.x86_64.rpm")
                    return name + "\t0\t1\t1.fc44\tx86_64\n"
                elif program == "go":
                    Path(arguments[arguments.index("-o") + 1]).write_bytes(b"synthetic static fixture")
                elif program == "genisoimage":
                    Path(arguments[arguments.index("-output") + 1]).write_bytes(b"synthetic ISO")
                return ""

            sources = ["uas/__init__.py", "tests/vm/boundary_fixture.go"]
            with patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}), patch.object(payload.os, "geteuid", return_value=1000), patch.object(payload, "command", side_effect=fake):
                iso = payload.build_payload(build, repo, "a" * 32, source_paths=sources)
                with self.assertRaises(FileExistsError):
                    payload.build_payload(build, repo, "a" * 32, source_paths=sources)
            self.assertEqual(0o444, iso.stat().st_mode & 0o777)
            manifest = json.loads((build / "payload-build/payload/manifest.json").read_text())
            self.assertEqual("a" * 32, manifest["nonce"])
            self.assertEqual(FINGERPRINT, manifest["signing_fingerprint"])
            self.assertEqual("fedora-44.asc", manifest["key"]["file"])
            self.assertEqual(set(payload.PACKAGES), {item["name"] for item in manifest["packages"]})
            self.assertFalse(manifest["dependencies_reproducibly_pinned"])
            self.assertEqual(set(sources), {item["file"] for item in manifest["source"]})
            self.assertTrue((build / "payload-build/payload/repo/uas/__init__.py").is_file())
            for arguments in calls:
                self.assertNotIn("sudo", arguments)
                self.assertNotIn("--nogpgcheck", arguments)
                if arguments[0] in ("rpm", "rpmkeys"):
                    self.assertEqual(str(build / "payload-build/rpmdb"), arguments[arguments.index("--dbpath") + 1])
                    self.assertNotIn("-i", arguments)
                    self.assertNotIn("-U", arguments)
                if arguments[0] == "dnf":
                    self.assertIn("--url", arguments)
                    self.assertIn("--resolve", arguments)
                    self.assertIn("--alldeps", arguments)
                    self.assertNotIn("install", arguments)
                if arguments[0] == "curl":
                    self.assertEqual("=https", arguments[arguments.index("--proto-redir") + 1])
                if arguments[0] == "go":
                    self.assertEqual(str(build / "payload-build/payload/repo/tests/vm/boundary_fixture.go"), arguments[-1])


if __name__ == "__main__":
    unittest.main()
