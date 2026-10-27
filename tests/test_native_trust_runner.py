"""Fixed trust runner contracts, no command or installroot execution."""
import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

VM = Path(__file__).parent / 'vm'
SPEC = importlib.util.spec_from_file_location('trust_boundary', VM / 'guest_boundary.py')
boundary = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(boundary)
REAL_NATIVE_COMMAND = boundary.native_command


class NativeTrustRunnerTests(unittest.TestCase):
    def setUp(self):
        self.command = ('/usr/bin/chroot', '/var/lib/uas-native-rootfs', '/usr/bin/env', '-i', 'fixed')
        self.addCleanup(patch.stopall)
        self.commands = unittest.mock.Mock(return_value=(self.command,))
        patch.dict(sys.modules, {'native_trust': types.SimpleNamespace(fixed_commands=self.commands)}).start()
        self.execute = patch.object(boundary, 'native_command', return_value=(0, {'stdout': {'output': 'ok'}, 'stderr': {'output': ''}})).start()
        self.old = patch.object(boundary.subprocess, 'run').start()

    def test_fixed_command_uses_owned_group_bounded_runner(self):
        self.assertEqual(boundary.run(*self.command, native_trust_context=True), 'ok')
        self.commands.assert_called_once_with(Path('/var/lib/uas-native-rootfs'))
        self.execute.assert_called_once_with(self.command, timeout=90, phase='trust-generation')
        self.old.assert_not_called()

    def test_modified_argv_root_timeout_fds_or_dual_mode_rejected(self):
        for args, kwargs in ((self.command + ('extra',), {}),
                (('/usr/bin/chroot', '/other', *self.command[2:]), {}),
                (self.command, {'timeout': 91}), (self.command, {'pass_fds': (4,)}),
                (self.command, {'native_failure_context': True}),
                (self.command, {'native_failure_context': 0})):
            with self.subTest(args=args, kwargs=kwargs), self.assertRaises(ValueError):
                boundary.run(*args, native_trust_context=True, **kwargs)
        self.execute.assert_not_called(); self.old.assert_not_called()

    def test_nonbool_flag_rejected(self):
        for flag in (None, 1, 'yes'):
            with self.assertRaises(ValueError): boundary.run(*self.command, native_trust_context=flag)
        self.execute.assert_not_called(); self.old.assert_not_called()

    def test_returncode_and_bounded_context_survive_failure(self):
        self.execute.return_value = (7, {'stdout': {'output': 'first'}, 'stderr': {'output': 'error'}})
        with self.assertRaisesRegex(RuntimeError, '"returncode": 7') as error:
            boundary.run(*self.command, native_trust_context=True)
        self.assertIn('error', str(error.exception)); self.old.assert_not_called()

    def test_hard_timeout_propagates_without_default_retry(self):
        self.execute.side_effect = boundary.subprocess.TimeoutExpired(self.command, 90)
        with self.assertRaises(boundary.subprocess.TimeoutExpired):
            boundary.run(*self.command, native_trust_context=True)
        self.execute.assert_called_once(); self.old.assert_not_called()

    def test_invalid_progress_phase_has_no_child(self):
        with patch.object(boundary.subprocess, 'Popen') as child:
            with self.assertRaises(ValueError):
                REAL_NATIVE_COMMAND(('anything',), timeout=90, phase='arbitrary')
        child.assert_not_called()
