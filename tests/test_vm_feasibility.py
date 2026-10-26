"""Offline harness contracts, not evidence that a VM booted."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location("vm_runner", Path(__file__).parent / "vm/run.py")
vm = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vm)


class VMFeasibilityTests(unittest.TestCase):
    def test_report_requires_this_boot_and_all_observed_prerequisites(self):
        nonce = "a" * 32
        report = {"version": 1, "nonce": nonce, "checks": {
            name: {"status": "passed", "observation": "synthetic unit fixture"} for name in vm.REQUIRED_CHECKS}}
        def line(value=report):
            return "UAS_VM_REPORT:" + nonce + ":" + json.dumps(value)
        self.assertEqual(report, vm.parse_report("boot noise\n" + line() + "\npoweroff\n", nonce))
        for serial in ("", line() + "\n" + line(), line().replace(nonce, "b" * 32)):
            with self.assertRaises(RuntimeError): vm.parse_report(serial, nonce)
        for name in vm.REQUIRED_CHECKS:
            changed = json.loads(json.dumps(report)); del changed["checks"][name]
            with self.assertRaises(RuntimeError): vm.parse_report(line(changed), nonce)
            changed["checks"][name] = {"status": "failed", "observation": "missing"}
            with self.assertRaises(RuntimeError): vm.parse_report(line(changed), nonce)

    def test_signer_and_image_digest_both_match_pins_without_fallback(self):
        lock = json.loads((vm.HERE / "fedora-image.json").read_text())
        status = "[GNUPG:] VALIDSIG " + lock["signing_fingerprint"] + " remainder"
        checksum = f"SHA256 ({lock['filename']}) = {lock['sha256']}\n"
        vm.verify_signed_checksum(lock, status, checksum)
        for bad_status, bad_checksum in ((status.replace(lock["signing_fingerprint"], "F" * 40), checksum),
                                         (status, checksum.replace(lock["sha256"], "f" * 64)),
                                         (status, checksum + checksum), ("", checksum)):
            with self.assertRaises(RuntimeError): vm.verify_signed_checksum(lock, bad_status, bad_checksum)

    def test_qemu_is_tcg_no_nic_no_shares_and_only_temporary_disks(self):
        root = Path("/tmp/uas-owned")
        args = vm.qemu_arguments(root, root / "guest.qcow2", root / "seed.iso")
        self.assertEqual("tcg,thread=multi", args[args.index("-accel") + 1])
        self.assertEqual("none", args[args.index("-nic") + 1])
        self.assertEqual("none", args[args.index("-monitor") + 1])
        for option in ("-enable-kvm", "-netdev", "-fsdev", "-virtfs", "-device", "-daemonize"):
            self.assertNotIn(option, args)
        self.assertFalse(any("hostfwd" in value or "/dev/kvm" in value for value in args))
        self.assertTrue(all(value.startswith("file=/tmp/uas-owned/") for index, value in enumerate(args) if index and args[index - 1] == "-drive"))

    def test_cleanup_terminates_then_kills_only_owned_process_on_timeout(self):
        process = Mock()
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired("qemu", 5), 0]
        vm.stop_process(process)
        process.terminate.assert_called_once()
        process.kill.assert_called_once()
        self.assertEqual(2, process.wait.call_count)

    def test_no_implicit_vm_run_outside_disposable_ci(self):
        with patch.dict("os.environ", {}, clear=True), patch.object(vm, "fetch_image") as fetch:
            with self.assertRaises(RuntimeError): vm.main()
            fetch.assert_not_called()

    def test_seed_has_no_password_keys_packages_or_network_urls(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(vm, "command") as command:
            path = Path(temporary)
            vm.seed(path, "a" * 32)
            payload = json.loads((path / "user-data").read_text().split("\n", 1)[1])
            self.assertFalse(payload["ssh_pwauth"])
            self.assertEqual([], payload["users"])
            self.assertNotIn("packages", payload)
            self.assertNotIn("password", payload)
            self.assertEqual("poweroff", payload["power_state"]["mode"])
            self.assertEqual("cloud-localds", command.call_args.args[0][0])
