"""Pure mocked native boot ordering; no guest commands or listeners are run."""
from contextlib import ExitStack
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch, mock_open

sys.path.insert(0, str(Path(__file__).parent / 'vm'))
import guest_boundary as boundary
import guest_workstation as guest
import native_rootfs

NONCE = 'a' * 32


class StopAtProfile(Exception):
    pass


class NativeBootOrderTests(unittest.TestCase):
    def test_rootfs_finishes_before_engine_start_and_profile(self):
        events = []
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory)
            stack.enter_context(patch.object(guest, 'Path', side_effect=lambda value: root / Path(value).name))
            stack.enter_context(patch.object(native_rootfs, 'build_rootfs', side_effect=lambda *a, **k: events.append('rootfs')))
            stack.enter_context(patch.object(guest, 'emit_evidence', side_effect=lambda kind,*a: events.append('evidence:'+kind)))
            stack.enter_context(patch.object(boundary, 'start_engine', side_effect=lambda: events.append('start')))
            def profile(*args):
                events.append('profile')
                raise StopAtProfile()
            stack.enter_context(patch.object(guest, 'engine_profile', side_effect=profile))
            commands = stack.enter_context(patch.object(guest, 'run'))
            with self.assertRaises(StopAtProfile):
                guest.scenario(NONCE, {'profile': 'native-pi-v1'})
            self.assertEqual(events, ['rootfs', 'evidence:completed-rootfs', 'start', 'profile',
                                      'evidence:check-guest_cleanup'])
            commands.assert_not_called()

    def test_failed_rootfs_preflight_never_starts_engine(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory)
            stack.enter_context(patch.object(guest, 'Path', side_effect=lambda value: root / Path(value).name))
            stack.enter_context(patch.object(native_rootfs, 'build_rootfs', side_effect=RuntimeError('preflight failed')))
            start = stack.enter_context(patch.object(boundary, 'start_engine'))
            profile = stack.enter_context(patch.object(guest, 'engine_profile'))
            commands = stack.enter_context(patch.object(guest, 'run'))
            with self.assertRaisesRegex(RuntimeError, 'preflight failed'):
                guest.scenario(NONCE, {'profile': 'native-pi-v1'})
            start.assert_not_called(); profile.assert_not_called(); commands.assert_not_called()

    def test_native_entrypoint_explicitly_defers_engine_start(self):
        manifest = {'profile': 'native-pi-v1'}
        with patch.object(sys, 'argv', ['guest', NONCE, 'digest']), \
             patch.object(boundary, 'install') as install, \
             patch.object(boundary, 'verify_payload', return_value=manifest), \
             patch.object(guest, 'scenario', return_value={name: {} for name in guest.REQUIRED}), \
             patch('builtins.open', mock_open()):
            guest.main()
        install.assert_called_once_with(NONCE, 'digest', exact_roots=guest.NATIVE_PACKAGE_PROFILE,
                                        defer_engine_start=True)

    def install_context(self, directory, manifest):
        root = Path(directory)
        marker = root / 'marker'; marker.write_text(NONCE)
        net = root / 'net'; net.mkdir(); (net / 'lo').mkdir()
        def mapped(value):
            if value == '/run/uas-vm-fixture': return marker
            if value == '/sys/class/net': return net
            target = root / str(value).lstrip('/')
            target.parent.mkdir(parents=True, exist_ok=True)
            return target
        stack = ExitStack()
        stack.enter_context(patch.object(boundary, 'Path', side_effect=mapped))
        stack.enter_context(patch.object(boundary, 'PAYLOAD', root / 'payload'))
        stack.enter_context(patch.object(boundary, 'ROOT', root / 'repo'))
        (root / 'repo').mkdir(); (root / 'repo/fixture').touch()
        stack.enter_context(patch.object(boundary.os, 'geteuid', return_value=0))
        stack.enter_context(patch.object(boundary, 'run', return_value='Enforcing\n'))
        stack.enter_context(patch.object(boundary, 'verify_payload', return_value=manifest))
        stack.enter_context(patch.object(boundary.shutil, 'copytree'))
        stack.enter_context(patch.object(boundary.shutil, 'copyfile'))
        stack.enter_context(patch.object(boundary, 'install_packages'))
        return stack

    def test_default_synthetic_install_starts_engine_native_deferral_does_not(self):
        for defer in (False, True):
            with self.subTest(defer=defer), tempfile.TemporaryDirectory() as directory:
                manifest = {'profile': 'native-pi-v1' if defer else 'static-fixture'}
                with self.install_context(directory, manifest), patch.object(boundary, 'start_engine') as start:
                    kwargs = {'defer_engine_start': True} if defer else {}
                    boundary.install(NONCE, 'digest', **kwargs)
                    self.assertEqual(start.call_count, 0 if defer else 1)

    def test_non_native_payload_cannot_defer_engine(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.install_context(directory, {'profile': 'static-fixture'}), \
                 patch.object(boundary, 'start_engine') as start, \
                 patch.object(boundary, 'install_packages') as packages:
                with self.assertRaises((RuntimeError, AssertionError, ValueError)):
                    boundary.install(NONCE, 'digest', defer_engine_start=True)
                start.assert_not_called(); packages.assert_not_called()

    def test_start_engine_retains_security_check_after_systemctl(self):
        events = []
        def run(*args, **kwargs):
            events.append(args)
            return 'installed roots\n'
        with patch.object(boundary, 'run', side_effect=run), \
             patch.object(boundary, 'require_engine_security', side_effect=lambda: events.append(('security',))), \
             patch('builtins.print'):
            boundary.start_engine()
        self.assertEqual(events[0], ('systemctl', 'start', 'docker'))
        self.assertEqual(events[1], ('security',))
        self.assertEqual(events[2][:3], ('rpm', '-q', '--queryformat'))
        self.assertEqual(events[2][4:], boundary.REQUIRED_PACKAGES)

    def test_guard_reports_individual_facts_without_weakening_conditions(self):
        cases = [
            (0, 0, 0o600, NONCE, ['lo'], None),
            (1, 0, 0o600, NONCE, ['lo'], 'effective_uid'),
            (0, 1, 0o600, NONCE, ['lo'], 'marker_uid'),
            (0, 0, 0o644, NONCE, ['lo'], 'marker_mode'),
            (0, 0, 0o600, 'b' * 32, ['lo'], 'marker_nonce_matches'),
            (0, 0, 0o600, NONCE, ['lo', 'docker0'], 'loopback_only'),
            (0, 0, 0o600, NONCE, [], 'loopback_only'),
        ]
        for euid, uid, mode, contents, names, failure in cases:
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                marker = root / 'marker'; marker.write_text(contents)
                net = root / 'net'; net.mkdir()
                for name in names: (net / name).mkdir()
                def mapped(value):
                    return marker if value == '/run/uas-vm-fixture' else net
                with patch.object(native_rootfs, 'Path', side_effect=mapped), \
                     patch.object(native_rootfs.os, 'geteuid', return_value=euid), \
                     patch.object(native_rootfs, 'ordinary', return_value=SimpleNamespace(st_uid=uid, st_mode=mode)), \
                     patch('builtins.print') as printed:
                    if failure is None:
                        native_rootfs.guest_guard(NONCE)
                        self.assertIn('"loopback_only": true', printed.call_args.args[1])
                        self.assertNotIn(NONCE, printed.call_args.args[1])
                    else:
                        with self.assertRaises(RuntimeError) as caught:
                            native_rootfs.guest_guard(NONCE)
                        message = str(caught.exception)
                        self.assertIn(failure, message)
                        self.assertNotIn(NONCE, message)
                        self.assertNotIn('b' * 32, message)
                        self.assertLess(len(message), 2048)
                        printed.assert_not_called()


if __name__ == '__main__':
    unittest.main()
