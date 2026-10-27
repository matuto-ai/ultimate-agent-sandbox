"""Pure/mocked image-import diagnostics; no native, daemon or listener execution."""
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).parent / 'vm'))
import guest_boundary as boundary
import guest_workstation as guest

COMMAND = ('docker', 'import', '/var/lib/uas-native-rootfs.tar')


class NativeImportRunnerTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        self.execute = patch.object(boundary, 'native_command', return_value=(0, {
            'stdout': {'output': 'sha256:' + 'a' * 64}, 'stderr': {'output': ''}})).start()
        self.generic = patch.object(boundary.subprocess, 'run').start()

    def test_exact_file_argv_uses_owned_runner_and_original_deadline(self):
        self.assertEqual(boundary.run(*COMMAND, timeout=120, native_import_context=True), 'sha256:' + 'a' * 64)
        self.execute.assert_called_once_with(COMMAND, timeout=120, phase='image-import')
        self.generic.assert_not_called()

    def test_changed_path_stdin_options_timeout_fds_or_dual_mode_rejected(self):
        for args, options in ((COMMAND[:-1] + ('-',), {}), (COMMAND + ('tag',), {}),
                (COMMAND[:-1] + ('/other.tar',), {}), (COMMAND, {'timeout': 121}),
                (COMMAND, {'pass_fds': (4,)}), (COMMAND, {'native_failure_context': True}),
                (COMMAND, {'native_trust_context': True}), (COMMAND, {'native_trust_context': 0})):
            with self.subTest(args=args, options=options), self.assertRaises(ValueError):
                boundary.run(*args, native_import_context=True, **{'timeout': 120, **options})
        self.execute.assert_not_called(); self.generic.assert_not_called()

    def test_nonboolean_flag_rejected(self):
        for value in (1, None, 'true'):
            with self.assertRaises(ValueError): boundary.run(*COMMAND, timeout=120, native_import_context=value)
        self.execute.assert_not_called(); self.generic.assert_not_called()

    def test_failure_and_timeout_preserved_without_retry(self):
        self.execute.return_value = (7, {'stderr': {'output': 'error import'}, 'stdout': {'output': ''}})
        with self.assertRaisesRegex(RuntimeError, 'error import'):
            boundary.run(*COMMAND, timeout=120, native_import_context=True)
        self.execute.side_effect = subprocess.TimeoutExpired(COMMAND, 120)
        with self.assertRaises(subprocess.TimeoutExpired):
            boundary.run(*COMMAND, timeout=120, native_import_context=True)
        self.assertEqual(self.execute.call_count, 2); self.generic.assert_not_called()

    def test_generic_import_remains_unchanged_without_opt_in(self):
        self.generic.return_value = SimpleNamespace(returncode=0, stdout='ok')
        self.assertEqual(boundary.run(*COMMAND, timeout=120), 'ok')
        self.execute.assert_not_called(); self.generic.assert_called_once()


class NativeImageEvidenceTests(unittest.TestCase):
    def test_chunked_completed_evidence_is_bounded_lossless_and_digest_bound(self):
        document = {'trust': {'inputs': ['x' * 5000]}, 'rootfs_entries': 123, 'rootfs_bytes': 456}
        with patch('builtins.print') as output:
            guest.emit_evidence('completed-rootfs', document)
        records = [json.loads(call.args[1]) for call in output.call_args_list]
        text = ''.join(item['json_fragment'] for item in records)
        self.assertEqual(json.loads(text), document)
        self.assertEqual([item['part'] for item in records], list(range(1, len(records) + 1)))
        self.assertTrue(all(item['parts'] == len(records) for item in records))
        self.assertTrue(all(item['sha256'] == hashlib.sha256(text.encode()).hexdigest() for item in records))
        self.assertTrue(all(len(item['json_fragment']) <= 2048 for item in records))

    def test_oversized_document_rejected_before_emission(self):
        with patch('builtins.print') as output, self.assertRaises(AssertionError):
            guest.emit_evidence('completed-rootfs', {'unexpected': 'x' * 16384})
        output.assert_not_called()

    def test_success_samples_same_owned_daemon_and_preserves_file_transport(self):
        facts = Mock(); facts.sample.return_value = {'daemon': {'pid': 42}}
        with patch.object(guest, 'ImportDaemonFacts', return_value=facts), \
                patch.object(guest, 'run', return_value='sha256:' + 'a' * 64 + '\n') as run, \
                patch.object(guest, 'emit_evidence') as emit, \
                patch.object(guest, 'import_failure_diagnostics') as logs, patch('builtins.print'):
            self.assertEqual(guest.import_image(Path(COMMAND[-1])), 'sha256:' + 'a' * 64)
        run.assert_called_once_with(*COMMAND, timeout=120, native_import_context=True)
        self.assertEqual([call.args[0] for call in emit.call_args_list], ['import-start', 'import-end'])
        self.assertEqual(facts.sample.call_count, 2); facts.close.assert_called_once(); logs.assert_not_called()

    def test_failure_samples_and_logs_before_close_without_masking_or_retry(self):
        events = []; facts = Mock(); facts.sample.return_value = {'daemon_error': 'PermissionError'}
        facts.close.side_effect = lambda: events.append('close')
        error = subprocess.TimeoutExpired(COMMAND, 120)
        with patch.object(guest, 'ImportDaemonFacts', return_value=facts), \
                patch.object(guest, 'run', side_effect=error) as run, \
                patch.object(guest, 'emit_evidence') as emit, \
                patch.object(guest, 'import_failure_diagnostics', side_effect=lambda: events.append('logs')), \
                patch('builtins.print'), self.assertRaises(subprocess.TimeoutExpired) as caught:
            guest.import_image(Path(COMMAND[-1]))
        self.assertIs(caught.exception, error); run.assert_called_once()
        self.assertEqual([call.args[0] for call in emit.call_args_list], ['import-start', 'import-failure'])
        self.assertEqual(events, ['logs', 'close'])

    def test_fixed_logs_retain_nonzero_empty_and_bounded_output(self):
        results = [SimpleNamespace(returncode=1, stdout=b'', stderr=b''),
                   SimpleNamespace(returncode=0, stdout=b'x' * 20000, stderr=b'end')]
        with patch.object(guest.subprocess, 'run', side_effect=results) as run, \
                patch.object(guest, 'emit_evidence') as emit:
            guest.import_failure_diagnostics()
        self.assertEqual([call.args[0] for call in emit.call_args_list], ['kernel-avc', 'docker-journal'])
        self.assertEqual(emit.call_args_list[0].args[1]['returncode'], 1)
        self.assertEqual(emit.call_args_list[0].args[1]['output'], '')
        self.assertTrue(emit.call_args_list[1].args[1]['truncated'])
        self.assertEqual(len(emit.call_args_list[1].args[1]['output']), 8192)
        self.assertTrue(all(call.kwargs['timeout'] == 5 for call in run.call_args_list))
        self.assertIn('--grep=avc:.*denied', run.call_args_list[0].args[0])
        self.assertEqual(run.call_args_list[1].args[0], ('journalctl', '-u', 'docker', '--no-pager', '-n', '30'))

    def test_unavailable_diagnostics_recorded_not_silently_ignored(self):
        with patch.object(guest.subprocess, 'run', side_effect=PermissionError), \
                patch.object(guest, 'emit_evidence') as emit:
            guest.import_failure_diagnostics()
        self.assertEqual(emit.call_count, 2)
        self.assertTrue(all(call.args[1] == {'unavailable': 'PermissionError'} for call in emit.call_args_list))

    def test_diagnostic_failures_never_replace_original_import_exception(self):
        for failing in ('sample','emit','logs','close','writer','constructor'):
            with self.subTest(failing=failing), ExitStack() as stack:
                facts=Mock();facts.sample.return_value={}
                factory=stack.enter_context(patch.object(guest,'ImportDaemonFacts',return_value=facts))
                emit=stack.enter_context(patch.object(guest,'emit_evidence'))
                logs=stack.enter_context(patch.object(guest,'import_failure_diagnostics'))
                writer=stack.enter_context(patch('builtins.print'))
                target={'sample':facts.sample,'emit':emit,'logs':logs,'close':facts.close,
                        'writer':writer,'constructor':factory}[failing]
                target.side_effect=OSError('diagnostic failure')
                original=subprocess.TimeoutExpired(COMMAND,120)
                run=stack.enter_context(patch.object(guest,'run',side_effect=original))
                with self.assertRaises(subprocess.TimeoutExpired) as caught:
                    guest.import_image(Path(COMMAND[-1]))
                self.assertIs(caught.exception,original);run.assert_called_once()
                if failing!='constructor':facts.close.assert_called_once()
                if failing!='writer':
                    self.assertTrue(any(call.args[0]=='Native image diagnostic unavailable:'
                                        for call in writer.call_args_list))

    def test_diagnostic_failures_never_lose_successful_image_id(self):
        for failing in ('sample','emit','close','writer','constructor'):
            with self.subTest(failing=failing), ExitStack() as stack:
                facts=Mock();facts.sample.return_value={}
                factory=stack.enter_context(patch.object(guest,'ImportDaemonFacts',return_value=facts))
                emit=stack.enter_context(patch.object(guest,'emit_evidence'))
                writer=stack.enter_context(patch('builtins.print'))
                logs=stack.enter_context(patch.object(guest,'import_failure_diagnostics'))
                target={'sample':facts.sample,'emit':emit,'close':facts.close,
                        'writer':writer,'constructor':factory}[failing]
                target.side_effect=OSError('diagnostic failure')
                image='sha256:'+'a'*64
                run=stack.enter_context(patch.object(guest,'run',return_value=image+'\n'))
                self.assertEqual(guest.import_image(Path(COMMAND[-1])),image)
                run.assert_called_once();logs.assert_not_called()
                if failing!='constructor':facts.close.assert_called_once()


class NativeImportDaemonTests(unittest.TestCase):
    def mocks(self):
        stack = ExitStack(); self.addCleanup(stack.close)
        self.run = stack.enter_context(patch.object(guest, 'run', return_value='42\n'))
        self.pidfd = stack.enter_context(patch.object(guest.os, 'pidfd_open', return_value=80))
        self.open = stack.enter_context(patch.object(guest.os, 'open', return_value=81))
        self.close = stack.enter_context(patch.object(guest.os, 'close'))
        stack.enter_context(patch.object(guest.os, 'fstat', return_value=SimpleNamespace(st_uid=0)))
        self.exe = stack.enter_context(patch.object(guest.os, 'readlink', return_value='/usr/bin/dockerd'))
        self.poller = Mock(); self.poller.poll.return_value = []
        stack.enter_context(patch.object(guest.select, 'poll', return_value=self.poller))
        fields = ['S'] + ['0'] * 19; fields[11] = '12'; fields[12] = '13'; fields[19] = '456'
        self.stat = '42 (dockerd) ' + ' '.join(fields)
        self.io = '\n'.join(key + ': 9' for key in guest.ImportDaemonFacts.IO_KEYS)
        self.read = stack.enter_context(patch.object(guest.ImportDaemonFacts, '_read',
            side_effect=lambda name: self.stat if name == 'stat' else self.io))
        stack.enter_context(patch.object(guest.os, 'statvfs', return_value=SimpleNamespace(
            f_bfree=10, f_bavail=9, f_frsize=4096, f_ffree=0, f_blocks=100)))
        stack.enter_context(patch.object(guest.os, 'sysconf', return_value=100))
        return stack

    def test_live_same_task_cpu_io_and_filesystem_facts(self):
        with self.mocks():
            facts = guest.ImportDaemonFacts(); value = facts.sample(); facts.close()
            self.pidfd.assert_called_once_with(42, 0)
            self.assertEqual(value['daemon']['starttime_ticks'], 456)
            self.assertEqual(value['daemon']['utime_ticks'], 12)
            self.assertEqual(value['daemon']['stime_ticks'], 13)
            self.assertEqual(value['daemon']['clock_ticks_per_second'], 100)
            self.assertEqual(value['daemon']['io']['read_bytes'], 9)
            self.assertEqual(value['docker_filesystem']['free_inodes'], 0)
            self.assertEqual(value['docker_filesystem']['free_bytes'], 40960)
            self.assertEqual([call.args[0] for call in self.close.call_args_list], [81, 80])
            self.assertTrue(all(call.args == (0,) for call in self.poller.poll.call_args_list))

    def test_dead_or_replaced_task_never_returns_counters(self):
        for mode in ('dead', 'replaced', 'invalid-io'):
            with self.subTest(mode=mode), self.mocks():
                facts = guest.ImportDaemonFacts()
                if mode == 'dead': self.poller.poll.return_value = [(80, 1)]
                elif mode == 'replaced': self.stat = self.stat[:-3] + '999'
                else: self.io += '\nunexpected: 1'
                value = facts.sample(); facts.close()
                self.assertNotIn('daemon', value); self.assertIn('daemon_error', value)
                self.assertIn('docker_filesystem', value)

    def test_constructor_failure_closes_partially_acquired_fds(self):
        with self.mocks():
            self.exe.side_effect = PermissionError
            facts = guest.ImportDaemonFacts()
            self.assertEqual(facts.sample()['daemon_error'], 'PermissionError')
            facts.close()
            self.assertEqual([call.args[0] for call in self.close.call_args_list], [81, 80])

    def test_missing_or_invalid_daemon_does_not_open_arbitrary_proc_path(self):
        with self.mocks():
            self.run.return_value = '../../other'
            facts = guest.ImportDaemonFacts()
            self.assertEqual(facts.sample()['daemon_error'], 'AssertionError')
            self.pidfd.assert_not_called(); self.open.assert_not_called()

    def test_close_failure_is_reported_after_all_fds_attempted_without_retry(self):
        with self.mocks():
            facts=guest.ImportDaemonFacts();error=OSError('close failure')
            self.close.side_effect=[error,None]
            with self.assertRaises(OSError) as caught:facts.close()
            self.assertIs(caught.exception,error)
            self.assertEqual([call.args[0] for call in self.close.call_args_list],[81,80])
            facts.close();self.assertEqual(self.close.call_count,2)

    def test_proc_reads_have_fixed_small_bound_and_close_on_oversize(self):
        facts = guest.ImportDaemonFacts.__new__(guest.ImportDaemonFacts); facts.procfd = 81
        with patch.object(guest.os, 'open', return_value=82) as opened, \
                patch.object(guest.os, 'read', return_value=b'x' * 4097) as read, \
                patch.object(guest.os, 'close') as close, self.assertRaises(AssertionError):
            facts._read('stat')
        self.assertEqual(opened.call_args.kwargs['dir_fd'], 81)
        self.assertTrue(opened.call_args.args[1] & guest.os.O_NOFOLLOW)
        read.assert_called_once_with(82, 4097); close.assert_called_once_with(82)


if __name__ == '__main__': unittest.main()
