"""Pure native RPM failure diagnostics; no package commands are executed."""
import ast
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

OFFLINE_DNF = ('dnf', '--installroot=/var/lib/uas-native-rootfs', '--disablerepo=*',
               '--enablerepo=uas-native', '--setopt=tsflags=noscripts',
               '--setopt=uas-native.gpgcheck=1', 'install', 'python3')

VM = Path(__file__).parent / 'vm'
SPEC = importlib.util.spec_from_file_location('rpm_diagnostic_boundary', VM / 'guest_boundary.py')
boundary = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(boundary)


class NativeRpmDiagnosticsTests(unittest.TestCase):
    def test_early_and_middle_errors_survive_long_progress(self):
        text = 'ERROR earliest signed RPM unpack cause\n' + 'progress\n' * 9000
        text += 'cpio: middle transaction cause\n' + 'progress\n' * 9000 + 'last progress\n'
        value = boundary.failure_context(text)
        self.assertEqual(value['bytes'], len(text.encode()))
        self.assertIs(value['truncated'], True)
        self.assertEqual(value['first_error_lines'], [
            'ERROR earliest signed RPM unpack cause\n', 'cpio: middle transaction cause\n'])
        self.assertTrue(value['output'].startswith('ERROR earliest'))
        self.assertTrue(value['output'].endswith('last progress\n'))
        self.assertIn('[... bounded output omitted ...]', value['output'])
        self.assertNotIn('middle transaction cause', value['output'])

    def test_small_and_exact_limit_outputs_retained_without_truncation(self):
        for text in ('', 'fatal: small\n', 'x' * 65536, 'é' * 32768):
            with self.subTest(bytes=len(text.encode())):
                value = boundary.failure_context(text)
                self.assertEqual(value['output'], text)
                self.assertEqual(value['bytes'], len(text.encode()))
                self.assertIs(value['truncated'], False)
        self.assertIs(boundary.failure_context('x' * 65537)['truncated'], True)

    def test_first_eight_matching_lines_only_and_multibyte_byte_bounds(self):
        text = ''.join('error ' + '€' * 250 + str(i) + '\n' for i in range(12))
        value = boundary.failure_context(text)
        self.assertEqual(len(value['first_error_lines']), 8)
        self.assertTrue(value['first_error_lines_truncated'])
        self.assertTrue(value['first_error_limit_reached'])
        self.assertTrue(all(len(line.encode()) <= 512 for line in value['first_error_lines']))
        huge = '€' * 50000
        value = boundary.failure_context(huge)
        pieces = value['output'].split('\n[... bounded output omitted ...]\n')
        self.assertEqual(len(pieces), 2)
        self.assertTrue(all(len(piece.encode()) <= 32768 for piece in pieces))
        self.assertEqual(value['bytes'], 150000)
        self.assertTrue(value['truncated'])

    def test_error_markers_case_insensitive_benign_progress_not_selected(self):
        text = 'ordinary progress\nUnpacking package\nRunning scriptlet\nERROR a\nFailure b\nFATAL c\nCPIO: d\n'
        self.assertEqual(boundary.failure_context(text)['first_error_lines'], text.splitlines(True)[3:])

    def test_default_exception_retains_exact_old_tails(self):
        stdout = 'early stdout error\n' + 'o' * 5000
        stderr = 'early stderr error\n' + 'e' * 5000
        result = subprocess.CompletedProcess(('dnf',), 7, stdout, stderr)
        with patch.object(boundary.subprocess, 'run', return_value=result) as execute:
            with self.assertRaises(RuntimeError) as caught:
                boundary.run('dnf', 'install', 'python3', timeout=900)
        self.assertEqual(str(caught.exception), 'dnf failed: ' + stderr[-2048:] + ' ' + stdout[-2048:])
        execute.assert_called_once_with(('dnf', 'install', 'python3'), stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=900, check=False, pass_fds=())

    def test_optin_failure_names_streams_and_returncode_without_extra_effects(self):
        stdout = 'progress\n' * 10000 + 'unpack middle failure\n' + 'progress\n' * 10000
        stderr = 'fatal first stderr\n' + 'progress\n' * 10000
        result = subprocess.CompletedProcess(('dnf',), 9, stdout, stderr)
        with patch.object(boundary.subprocess, 'run', return_value=result) as execute, \
             patch('builtins.open', side_effect=AssertionError('unexpected log read')), \
             patch.object(boundary.os, 'getenv', side_effect=AssertionError('unexpected environment read')):
            with self.assertRaises(RuntimeError) as caught:
                boundary.run(*OFFLINE_DNF, timeout=900, pass_fds=(7,), native_failure_context=True)
        prefix = 'native rootfs command failed: '
        self.assertTrue(str(caught.exception).startswith(prefix))
        value = json.loads(str(caught.exception)[len(prefix):])
        self.assertEqual(set(value), {'tool', 'returncode', 'stdout', 'stderr'})
        self.assertEqual((value['tool'], value['returncode']), ('dnf', 9))
        self.assertEqual(value['stdout']['first_error_lines'], ['unpack middle failure\n'])
        self.assertEqual(value['stderr']['first_error_lines'], ['fatal first stderr\n'])
        execute.assert_called_once_with(OFFLINE_DNF, stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=900, check=False, pass_fds=(7,))

    def test_invalid_optin_rejected_before_subprocess_success_unchanged(self):
        with patch.object(boundary.subprocess, 'run') as execute:
            for value in (1, 0, None, 'true'):
                with self.assertRaises(ValueError): boundary.run('dnf', native_failure_context=value)
            execute.assert_not_called()
        for flag in (True, False):
            with patch.object(boundary.subprocess, 'run', return_value=subprocess.CompletedProcess(('dnf',), 0, 'ok\n', '')) as execute:
                self.assertEqual(boundary.run(*OFFLINE_DNF, native_failure_context=flag), 'ok\n')
                self.assertEqual(execute.call_count, 1)

    def test_optin_rejects_other_tools_and_missing_offline_flags_before_execution(self):
        invalid = [(), ('cat', '/etc/passwd'), ('sh',) + OFFLINE_DNF[1:]]
        invalid.extend(OFFLINE_DNF[:index] + OFFLINE_DNF[index + 1:] for index in range(1, 6))
        with patch.object(boundary.subprocess, 'run') as execute:
            for arguments in invalid:
                with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                    boundary.run(*arguments, native_failure_context=True)
            execute.assert_not_called()

    def test_only_native_installroot_dnf_opts_in_with_existing_safety_options(self):
        calls = []
        for path in VM.glob('*.py'):
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, ast.Call) and any(k.arg == 'native_failure_context' for k in node.keywords):
                    calls.append((path.name, node))
        self.assertEqual(len(calls), 1)
        filename, call = calls[0]
        self.assertEqual(filename, 'native_rootfs.py')
        self.assertEqual(ast.literal_eval(call.args[0]), 'dnf')
        constants = [arg.value for arg in call.args if isinstance(arg, ast.Constant)]
        for required in ('--setopt=tsflags=noscripts', '--setopt=install_weak_deps=False',
                         '--disablerepo=*', '--setopt=uas-native.gpgcheck=1', '--setopt=localpkg_gpgcheck=True', 'install'):
            self.assertIn(required, constants)
        self.assertTrue(next(k.value.value for k in call.keywords if k.arg == 'native_failure_context'))


if __name__ == '__main__': unittest.main()
