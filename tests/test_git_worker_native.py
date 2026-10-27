"""Pure/mocked worker composition; no native process, socket or thread runs."""
import base64
from copy import deepcopy
import errno
import hashlib
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from uas.git_policy import parse_git
from uas.git_provenance import parse_commit
from uas.git_runtime import GitResult
from uas.git_worker_native import (GitWorkerError, MAX_BLOB, WorkerBridge, _remap_backend,
    _head_ref, _transaction, execute_native, receive_blob, send_blob, ssh_shim_main, shim_stream,
    validate_configuration, worker_main)
from uas.kernel_origin import OriginDenied, Record


def config(argv=None):
    return {'kind': 'execute', 'version': 1, 'operation_id': 'operation-one', 'invoked_as': 'git',
        'argv': argv or ['commit', '-m', 'Change'],
        'binding': {'room_id': 'room-a', 'project_id': 'project-a', 'repository': 'owner/repo', 'host': 'github.com'},
        'identity': {'actor_id': 'actor-a', 'name': 'Actor A', 'email': 'a@example.invalid'},
        'view': {'worktree': '/project', 'gitdir': '/project/.git', 'common': '/project/.git',
                 'config': '/project/.git/config', 'helpers': '/opt/uas/git-helpers', 'checkout_owner': 65532},
        'backend_sha256': 'a' * 64}


def commit(*, parents=(), message=b'Change\n', author='Actor A <a@example.invalid> 123 +0000'):
    raw = ('tree ' + 'a' * 40 + '\n' + ''.join('parent ' + oid + '\n' for oid in parents)
           + 'author ' + author + '\ncommitter Actor A <a@example.invalid> 123 +0000\n\n').encode() + message
    return parse_commit(raw).oid, raw


class BlobTests(unittest.TestCase):
    def frames(self, name, raw):
        frames = []
        with patch('uas.git_worker_native.send', side_effect=lambda _, value: frames.append(value)):
            send_blob(object(), name, raw)
        return frames

    def test_bounded_blob_roundtrip_empty_binary_multi_and_maximum(self):
        for raw in (b'', b'\xff\x00payload', b'x' * 32769, b'x' * MAX_BLOB):
            frames = self.frames('source', raw)
            self.assertEqual(raw, receive_blob('source', iter(frames).__next__))
            self.assertEqual(hashlib.sha256(raw).hexdigest(), frames[0]['sha256'])
            self.assertTrue(all(len(base64.b64decode(part['data'])) <= 32768 for part in frames[1:]))

    def test_shape_sequence_name_count_digest_and_canonical_encoding_are_binding(self):
        original = self.frames('source', b'a' * 32769)
        mutations = []
        for key, value in (('bytes', -1), ('bytes', MAX_BLOB + 1), ('count', 3), ('count', True),
                           ('name', 'commit'), ('sha256', 'f' * 64), ('extra', 'forbidden')):
            frames = deepcopy(original)
            frames[0][key] = value
            mutations.append(frames)
        for key, value in (('index', 1), ('index', False), ('name', 'commit'), ('data', 'Zh=='),
                           ('data', 'Zg==\n'), ('extra', 'forbidden')):
            frames = deepcopy(original)
            frames[1][key] = value
            mutations.append(frames)
        for frames in mutations:
            with self.assertRaises(GitWorkerError):
                receive_blob('source', iter(frames).__next__)
        for name, data in (('unknown', b'x'), ([], b'x'), ('stdout', 'text'), ('stdout', b'x' * (MAX_BLOB + 1))):
            with self.assertRaises(GitWorkerError):
                self.frames(name, data)


class ConfigurationTests(unittest.TestCase):
    def test_exact_trusted_configuration_and_policy_revalidation(self):
        binding, identity, command = validate_configuration(config())
        self.assertEqual(('owner/repo', 'actor-a', 'commit'), (binding.repository, identity.actor_id, command.command))
        for changed in ({'kind': 'other'}, {'version': True}, {'backend_sha256': 'bad'},
                        {'argv': ['-c', 'core.hooksPath=/tmp', 'commit']}, {'extra': 'unknown'}):
            value = config()
            value.update(changed)
            with self.assertRaises(GitWorkerError):
                validate_configuration(value)
        for key, field, value in (('identity', 'name', 'Injected\nAuthor'),
                                  ('binding', 'host', 'evil.invalid'), ('view', 'checkout_owner', 0)):
            document = config()
            document[key][field] = value
            with self.assertRaises(GitWorkerError):
                validate_configuration(document)

    def test_unborn_head_ref_is_read_only_from_bound_gitdir_no_symlink_follow(self):
        import os
        import stat
        runtime = SimpleNamespace(view=SimpleNamespace(gitdir_fd=123))
        raw = b'ref: refs/heads/feature\n'
        with patch('uas.git_worker_native.os.open', return_value=456) as opened, \
             patch('uas.git_worker_native.os.fstat', return_value=SimpleNamespace(st_mode=stat.S_IFREG, st_size=len(raw))), \
             patch('uas.git_worker_native.os.read', return_value=raw), \
             patch('uas.git_worker_native.os.close') as close:
            self.assertEqual('refs/heads/feature', _head_ref(runtime, None, lambda: True))
        self.assertEqual('HEAD', opened.call_args.args[0])
        self.assertTrue(opened.call_args.args[1] & os.O_NOFOLLOW)
        self.assertEqual(123, opened.call_args.kwargs['dir_fd'])
        close.assert_called_once_with(456)

    def test_reserved_backend_slot_cannot_overwrite_existing_owned_descriptor(self):
        with patch('uas.git_worker_native.os.fstat', return_value=object()), \
             patch('uas.git_worker_native.os.dup2') as dup, patch('uas.git_worker_native.os.close') as close:
            with self.assertRaises(GitWorkerError):
                _remap_backend([23])
            dup.assert_not_called()
            close.assert_not_called()
        owned = [23]
        with patch('uas.git_worker_native.os.fstat', side_effect=OSError(errno.EBADF, 'fixture')), \
             patch('uas.git_worker_native.os.dup2') as dup, patch('uas.git_worker_native.os.close') as close:
            self.assertEqual(19, _remap_backend(owned))
            self.assertEqual([19], owned)
            dup.assert_called_once_with(23, 19, inheritable=False)
            close.assert_called_once_with(23)

    def test_backend_close_uncertainty_never_restores_released_descriptor_ownership(self):
        owned = [23]
        with patch('uas.git_worker_native.os.fstat', side_effect=OSError(errno.EBADF, 'fixture')), \
             patch('uas.git_worker_native.os.dup2'), patch('uas.git_worker_native.os.close', side_effect=OSError()):
            with self.assertRaises(OSError):
                _remap_backend(owned)
        self.assertEqual([19], owned)

    def test_shim_rejects_bad_args_before_socket_creation(self):
        for argv in (None, [], ['--fd', '3'], ['--fd', 3, 'host'], ['--fd', '2', 'host'],
                     ['--fd', '03', 'host'], ['--fd', '1048577', 'host'], ['--other', '3', 'host']):
            with patch('uas.git_worker_native.socket.socket') as sock, self.assertRaises(GitWorkerError):
                ssh_shim_main(argv)
            sock.assert_not_called()

    def test_reference_transaction_receives_exact_operation_head_ref_and_abort_kind(self):
        for argv, kind in ((['commit', '-m', 'Change'], 'commit'),
                           (['cherry-pick', 'a' * 40], 'cherry-pick'),
                           (['cherry-pick', '--abort'], 'abort')):
            document = config(argv)
            with patch('uas.git_transaction.ReferenceTransaction') as receipt:
                self.assertIs(receipt.return_value,
                    _transaction(document, parse_git('git', argv), 'b' * 40, 'refs/heads/main'))
            receipt.assert_called_once_with('operation-one', expected_old='b' * 40,
                                            expected_ref='refs/heads/main', kind=kind)

    def test_malformed_first_shim_response_disposes_held_worker_origin(self):
        channel = Mock()
        channel.__enter__ = Mock(return_value=channel)
        channel.__exit__ = Mock(return_value=False)
        with patch('uas.git_worker_native.socket.socket', return_value=channel), \
             patch('uas.git_worker_native.enable'), patch('uas.git_worker_native.send'), \
             patch('uas.git_worker_native.os.getuid', return_value=65530), \
             patch('uas.git_worker_native.os.getgid', return_value=65532), \
             patch('uas.git_worker_native.receive', return_value=Record(b'not-json', (100, 65530, 65532), -1)), \
             patch('uas.git_worker_native.HeldOrigin') as held:
            with self.assertRaises(Exception):
                ssh_shim_main(['--fd', '3', 'git@github.com', "git-upload-pack 'owner/repo.git'"])
        held.return_value.close.assert_called_once()


class NativeCompositionTests(unittest.TestCase):
    def setUp(self):
        self.channel = object()
        self.supervisor = SimpleNamespace(revoked=False, pidfd=123, require=Mock())
        self.bridge = SimpleNamespace(failure=None, start=Mock(), stop=Mock(), current=Mock(return_value=True))
        self.enterContext(patch('uas.git_worker_native.alive', return_value=True))
        self.frames = []
        self.enterContext(patch('uas.git_worker_native.send', side_effect=lambda _, value: self.frames.append(value)))
        self.replies = self.enterContext(patch('uas.git_worker_native._supervisor_value', side_effect=[
            {'kind': 'go', 'operation_id': 'operation-one'}, {'kind': 'receipt', 'status': 'COMPLETED'}]))
        self.old_parent, self.old_raw = commit(message=b'Older\n')
        self.head, self.head_raw = commit(parents=(self.old_parent,), message=b'Existing\n')
        self.source, self.source_raw = commit(author='Source <source@example.invalid> 122 +0000', message=b'Source\n')
        self.created, self.created_raw = commit(parents=(self.head,), message=b'New\n')
        self.objects = {self.head: self.head_raw, self.source: self.source_raw, self.created: self.created_raw}
        self.conflict_before = self.conflict_after = None
        self.native_returncode = 0
        self.native_stdout = b'[main ' + self.created.encode() + b'] New\n'
        self.executed = []
        self.did_mutate = False
        self.runtime = SimpleNamespace(run=Mock(side_effect=self.native))
        self.transaction = SimpleNamespace(committed_oid=Mock(side_effect=lambda **_: self.created if self.native_returncode == 0 else None))
        self.context = Mock()
        self.context.__enter__ = Mock(return_value=self.transaction)
        self.context.__exit__ = Mock(return_value=False)
        self.transaction_factory = self.enterContext(patch('uas.git_worker_native._transaction', return_value=self.context))

    def native(self, command, **kwargs):
        self.executed.append(command)
        self.assertTrue(kwargs['current']())
        if command.command == 'rev-parse':
            if command.args == ('--symbolic-full-name', 'HEAD'):
                return GitResult(0, b'refs/heads/main\n', b'')
            if command.args[-1] == 'HEAD':
                self.assertFalse(self.did_mutate, 'post-command mutable HEAD is not creation evidence')
                oid = self.head
            else:
                oid = self.conflict_after if self.did_mutate else self.conflict_before
            return GitResult(0, (oid + '\n').encode(), b'') if oid else GitResult(128, b'', b'No ref')
        if command.command == 'cat-file':
            return GitResult(0, self.objects[command.args[-1]], b'')
        self.did_mutate = True
        return GitResult(self.native_returncode, self.native_stdout, b'bounded native stderr')

    def run_native(self, document=None):
        return execute_native(self.channel, self.supervisor, document or config(), self.runtime, self.bridge)

    def test_commit_only_runs_after_exact_go_and_uses_created_oid_not_mutable_head(self):
        result = self.run_native()
        self.assertEqual({'kind': 'receipt', 'status': 'COMPLETED'}, result)
        self.assertEqual({'kind': 'preflight', 'head': self.head, 'head_ref': 'refs/heads/main',
                          'parent': self.head, 'source_oid': None}, self.frames[0])
        terminal = next(frame for frame in self.frames if frame['kind'] == 'result')
        self.assertEqual(self.created, terminal['commit_oid'])
        self.assertEqual(0, terminal['returncode'])
        self.assertFalse(terminal['conflict'])
        self.assertEqual(['stdout', 'stderr', 'commit'], [frame['name'] for frame in self.frames if frame['kind'] == 'blob'])
        self.bridge.start.assert_called_once()
        self.bridge.stop.assert_called_once()
        self.transaction.committed_oid.assert_called_once_with(required=True)
        self.assertEqual((self.head, 'refs/heads/main'), self.transaction_factory.call_args.args[2:])

    def test_amend_reports_previous_commit_first_parent(self):
        self.created, self.created_raw = commit(parents=(self.old_parent,), message=b'Amended\n')
        self.objects[self.created] = self.created_raw
        self.native_stdout = b'[main ' + self.created.encode() + b'] Amended\n'
        self.run_native(config(['commit', '--amend', '-m', 'Amended']))
        self.assertEqual(self.old_parent, self.frames[0]['parent'])
        self.assertIn(parse_git('git', ['cat-file', '-p', self.head]), self.executed)

    def test_cherry_source_is_exact_native_object_before_go(self):
        self.run_native(config(['cherry-pick', self.source]))
        self.assertEqual(self.source, self.frames[0]['source_oid'])
        self.assertEqual('source', self.frames[1]['name'])
        source_frames = iter(self.frames[1:3])
        self.assertEqual(self.source_raw, receive_blob('source', source_frames.__next__))

    def test_continue_uses_actual_conflict_head_as_hint_without_declaring_anchor(self):
        self.conflict_before = self.source
        self.run_native(config(['cherry-pick', '--continue']))
        self.assertEqual(self.source, self.frames[0]['source_oid'])
        self.assertNotIn('anchor', repr(self.frames))

    def test_conflict_and_abort_do_not_fabricate_created_commit(self):
        self.native_returncode = 1
        self.native_stdout = b'Auto-merging file\nCONFLICT\n'
        self.conflict_after = self.source
        self.run_native(config(['cherry-pick', self.source]))
        terminal = next(frame for frame in self.frames if frame['kind'] == 'result')
        self.assertTrue(terminal['conflict'])
        self.assertIsNone(terminal['commit_oid'])
        self.setUp()
        self.conflict_before = self.source
        self.native_stdout = b''
        self.run_native(config(['cherry-pick', '--abort']))
        terminal = next(frame for frame in self.frames if frame['kind'] == 'result')
        self.assertIsNone(terminal['commit_oid'])

    def test_denial_or_wrong_operation_go_never_executes_mutation(self):
        for reply in ({'kind': 'deny', 'code': 'FORBIDDEN'}, {'kind': 'go', 'operation_id': 'another'}):
            self.replies.side_effect = [reply]
            with self.assertRaises(GitWorkerError):
                self.run_native()
            self.assertFalse(self.did_mutate)
            self.bridge.start.assert_not_called()

    def test_filename_and_forged_stdout_headers_are_not_commit_authority(self):
        self.native_stdout = b'Auto-merging path\n[main ' + self.head.encode() + b'] Forged-looking\n'
        self.run_native(config(['cherry-pick', self.source]))
        terminal = next(frame for frame in self.frames if frame['kind'] == 'result')
        self.assertEqual(self.created, terminal['commit_oid'])

    def test_missing_partial_or_multiple_receipt_never_falls_back_to_output_or_head(self):
        for failure in (GitWorkerError('GIT_TRANSACTION_UNKNOWN'), GitWorkerError('GIT_TRANSACTION_MULTIPLE')):
            self.transaction.committed_oid.side_effect = failure
            self.replies.side_effect = [{'kind': 'go', 'operation_id': 'operation-one'}]
            self.did_mutate = False
            self.frames.clear()
            with self.assertRaises(GitWorkerError):
                self.run_native()
            self.assertFalse(any(frame['kind'] == 'result' for frame in self.frames))

    def test_created_raw_must_hash_to_native_reported_oid(self):
        self.objects[self.created] = self.head_raw
        with self.assertRaises(GitWorkerError) as caught:
            self.run_native()
        self.assertEqual('GIT_NATIVE_OBJECT_CHANGED', caught.exception.code)

    def test_transaction_admission_failure_never_starts_bridge_or_mutates(self):
        self.context.__enter__.side_effect = GitWorkerError('GIT_TRANSACTION_UNKNOWN')
        with self.assertRaises(GitWorkerError):
            self.run_native()
        self.bridge.start.assert_not_called()
        self.assertFalse(self.did_mutate)

    def test_bridge_start_failure_closes_transaction_without_native_mutation(self):
        self.bridge.start.side_effect = RuntimeError('thread start failed')
        with self.assertRaises(RuntimeError):
            self.run_native()
        self.context.__exit__.assert_called_once()
        self.assertFalse(self.did_mutate)

    def test_final_receipt_is_required_and_runtime_failure_stops_bridge(self):
        self.replies.side_effect = [{'kind': 'go', 'operation_id': 'operation-one'}, {'kind': 'wrong'}]
        with self.assertRaises(GitWorkerError) as caught:
            self.run_native()
        self.assertEqual('GIT_RECEIPT_UNKNOWN', caught.exception.code)
        self.setUp()
        original = self.runtime.run.side_effect
        def failing(command, **kwargs):
            if command.kind == 'commit':
                raise RuntimeError('native failure')
            return original(command, **kwargs)
        self.runtime.run.side_effect = failing
        with self.assertRaises(RuntimeError):
            self.run_native()
        self.bridge.stop.assert_called_once()


class ViewOwnershipTests(unittest.TestCase):
    def test_worker_opens_configured_paths_inside_namespace_and_closes_every_owned_fd(self):
        channel = Mock()
        supervisor = SimpleNamespace(pidfd=4)
        local, remote = Mock(), Mock()
        remote.fileno.return_value = 107
        temporary = Mock()
        temporary.__enter__ = Mock(return_value='/private/empty-home')
        temporary.__exit__ = Mock(return_value=False)
        with patch('uas.git_worker_native._remap_backend', side_effect=lambda owned: owned.__setitem__(0, 19)), \
             patch('uas.git_worker.open_inside', side_effect=[101, 102, 103, 104, 105]) as opened, \
             patch('uas.git_worker_native.os.close') as close, \
             patch('uas.git_worker_native.RuntimeView') as view, \
             patch('uas.git_worker_native.SealedGit') as backend, \
             patch('uas.git_worker_native.socket.socketpair', return_value=(local, remote)), \
             patch('uas.git_worker_native.enable') as enable, \
             patch('uas.git_worker_native.tempfile.TemporaryDirectory', return_value=temporary), \
             patch('uas.git_worker_native.GitRuntime') as runtime, \
             patch('uas.git_worker_native.execute_native', return_value={'kind': 'receipt', 'status': 'COMPLETED'}):
            worker_main(channel, config(), 20, supervisor)
        self.assertEqual(['/project', '/project/.git', '/project/.git', '/project/.git/config', '/opt/uas/git-helpers'],
                         [call.args[0] for call in opened.call_args_list])
        self.assertEqual(65532, view.call_args.kwargs['checkout_owner'])
        self.assertEqual(103, view.call_args.kwargs['common_fd'])
        self.assertEqual({19, 101, 102, 103, 104, 105}, {call.args[0] for call in close.call_args_list})
        self.assertEqual(6, close.call_count)
        local.close.assert_called_once()
        remote.close.assert_called_once()
        self.assertEqual(2, enable.call_count)

    def test_invalid_configuration_still_disposes_received_backend(self):
        with patch('uas.git_worker_native.os.close') as close:
            with self.assertRaises(GitWorkerError):
                worker_main(Mock(), {}, 20, Mock())
        close.assert_called_once_with(20)


class WorkerFailureQuiescenceTests(unittest.TestCase):
    """Worker failure protocol with only fabricated native/descriptor objects."""
    def setUp(self):
        self.local, self.remote = Mock(), Mock()
        self.remote.fileno.return_value = 107
        self.temporary = Mock()
        self.temporary.__enter__ = Mock(return_value='/private/empty-home')
        self.temporary.__exit__ = Mock(return_value=False)
        self.runtime = SimpleNamespace(quiescent=True)
        self.bridge = SimpleNamespace(thread=None)
        self.enterContext(patch('uas.git_worker_native._remap_backend', side_effect=lambda owned: owned.__setitem__(0, 19)))
        self.enterContext(patch('uas.git_worker.open_inside', side_effect=[101, 102, 103, 104, 105]))
        self.closed = self.enterContext(patch('uas.git_worker_native.os.close'))
        self.enterContext(patch('uas.git_worker_native.RuntimeView'))
        self.enterContext(patch('uas.git_worker_native.SealedGit'))
        self.enterContext(patch('uas.git_worker_native.socket.socketpair', return_value=(self.local, self.remote)))
        self.enterContext(patch('uas.git_worker_native.enable'))
        self.enterContext(patch('uas.git_worker_native.tempfile.TemporaryDirectory', return_value=self.temporary))
        self.enterContext(patch('uas.git_worker_native.GitRuntime', return_value=self.runtime))
        self.enterContext(patch('uas.git_worker_native.WorkerBridge', return_value=self.bridge))
        self.execution = self.enterContext(patch('uas.git_worker_native.execute_native', side_effect=RuntimeError('private execution details')))
        self.send = self.enterContext(patch('uas.git_worker_native.send'))

    def test_verified_native_and_bridge_quiescence_permit_typed_failure_after_disposal(self):
        self.bridge.thread = SimpleNamespace(is_alive=Mock(return_value=False))
        result = worker_main(Mock(), config(), 20, Mock())
        self.assertEqual({'kind': 'receipt', 'status': 'FAILED'}, result)
        self.send.assert_called_once()
        self.assertEqual({'kind': 'worker-failed', 'code': 'GIT_WORKER_COMMAND_FAILED'}, self.send.call_args.args[1])
        self.assertEqual([105, 104, 103, 102, 101, 19], [call.args[0] for call in self.closed.call_args_list])
        self.local.close.assert_called_once()
        self.remote.close.assert_called_once()
        self.temporary.__exit__.assert_called_once()

    def test_uncertain_native_cleanup_never_returns_or_sends_failure_as_quiescence(self):
        self.runtime.quiescent = False
        with self.assertRaises(RuntimeError):
            worker_main(Mock(), config(), 20, Mock())
        self.send.assert_not_called()
        self.assertEqual(6, self.closed.call_count)

    def test_live_bridge_prevents_outer_exit_handshake_even_with_native_quiescence(self):
        self.bridge.thread = SimpleNamespace(is_alive=Mock(return_value=True))
        with self.assertRaises(RuntimeError):
            worker_main(Mock(), config(), 20, Mock())
        self.send.assert_not_called()

    def test_resource_disposal_failure_prevents_return_to_outer_quiescent_handshake(self):
        self.execution.side_effect = None
        self.execution.return_value = {'kind': 'receipt', 'status': 'COMPLETED'}
        self.remote.close.side_effect = OSError('uncertain socket disposal')
        with self.assertRaises(OSError):
            worker_main(Mock(), config(), 20, Mock())
        self.send.assert_not_called()
        self.local.close.assert_called_once()
        self.temporary.__exit__.assert_called_once()
        self.assertEqual(6, self.closed.call_count)

    def test_backend_disposal_failure_cannot_return_after_typed_failure(self):
        def close(fd):
            if fd == 19:
                raise OSError('backend close uncertain')
        self.closed.side_effect = close
        with self.assertRaises(OSError):
            worker_main(Mock(), config(), 20, Mock())
        self.assertEqual(['worker-failed'], [call.args[1]['kind'] for call in self.send.call_args_list])
        self.assertEqual(6, self.closed.call_count)


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.channel, self.local = object(), object()
        self.supervisor = SimpleNamespace(pidfd=123, revoked=False, require=Mock())
        self.bridge = WorkerBridge(self.channel, self.supervisor, self.local)
        self.enterContext(patch('uas.git_worker_native.alive', return_value=True))
        self.enterContext(patch('uas.git_worker_native.os.getuid', return_value=65530))
        self.enterContext(patch('uas.git_worker_native.os.getgid', return_value=65532))

    def test_bridge_authenticates_each_supervisor_record_and_never_accepts_actor_from_shim(self):
        records = [Record(json.dumps(value).encode(), (100, 65530, 65532), -1) for value in (
            {'kind': 'ssh-open', 'argv': ['git@github.com', "git-upload-pack 'owner/repo.git'"]},
            {'kind': 'data', 'data': 'eA=='}, {'kind': 'shim-finished'})]
        selector = Mock()
        selector.__enter__ = Mock(return_value=selector)
        selector.__exit__ = Mock(return_value=False)
        step = [0]
        def select(_):
            sequence = ['shim', 'supervisor', 'shim', 'supervisor', 'shim']
            if step[0] == len(sequence):
                self.bridge.stopping.set()
                return []
            label = sequence[step[0]]
            step[0] += 1
            return [(SimpleNamespace(data=label), 1)]
        selector.select.side_effect = select
        sent = []
        with patch('uas.git_worker_native.selectors.DefaultSelector', return_value=selector), \
             patch('uas.git_worker_native.receive', side_effect=records), \
             patch('uas.git_worker_native.HeldOrigin') as held, \
             patch('uas.git_worker_native._supervisor_value', side_effect=[{'kind': 'ready'},
                  {'kind': 'exit', 'code': 0, 'status': 'OK'}]) as received, \
             patch('uas.git_worker_native.send', side_effect=lambda channel, value: sent.append((channel, value))):
            self.bridge._loop()
        self.assertIsNone(self.bridge.failure)
        self.assertEqual(2, received.call_count)
        self.assertTrue(all(call.args == (self.channel, self.supervisor) for call in received.call_args_list))
        self.assertEqual(2, held.return_value.require.call_count)
        held.return_value.close.assert_called_once()
        self.assertEqual(['ssh-open', 'ready', 'data', 'exit', 'stream-finished', 'shim-finish-ack'], [value['kind'] for _, value in sent])

    def terminal_sequence(self, tail, *, terminal=None, authority_error=False, stop_before_finish=False):
        opened = {'kind': 'ssh-open', 'argv': ['git@github.com', "git-upload-pack 'owner/repo.git'"]}
        records = [Record(json.dumps(value).encode(), (100, 65530, 65532), -1)
                   for value in [opened, *tail]]
        selector = Mock(__enter__=Mock(), __exit__=Mock(return_value=False))
        selector.__enter__.return_value = selector
        labels = iter(['shim', 'supervisor', *(['shim'] * len(tail))])
        def select(_):
            label = next(labels, None)
            if label is None:
                self.bridge.stopping.set()
                return []
            return [(SimpleNamespace(data=label), 1)]
        selector.select.side_effect = select
        sent = []
        with patch('uas.git_worker_native.selectors.DefaultSelector', return_value=selector), \
             patch('uas.git_worker_native.receive', side_effect=records), \
             patch('uas.git_worker_native.HeldOrigin') as held, \
             patch('uas.git_worker_native._supervisor_value', return_value=terminal or {'kind':'exit','code':0,'status':'OK'}), \
             patch('uas.git_worker_native.send', side_effect=lambda channel, value: sent.append((channel,value))):
            if authority_error:
                held.return_value.require.side_effect = OriginDenied('wrong or dead shim')
            self.bridge._loop()
        return sent, held

    def test_terminal_crossed_input_is_authenticated_drained_and_never_forwarded(self):
        sent, held = self.terminal_sequence([{'kind':'data','data':'eA=='}, {'kind':'eof'}, {'kind':'shim-finished'}])
        self.assertIsNone(self.bridge.failure)
        self.assertFalse(self.bridge._active)
        self.assertEqual(3, held.return_value.require.call_count)
        held.return_value.close.assert_called_once()
        self.assertEqual([{'kind':'ssh-open','argv':['git@github.com', "git-upload-pack 'owner/repo.git'"]}, {'kind':'stream-finished'}],
                         [value for channel,value in sent if channel is self.channel])
        self.assertEqual(['exit','shim-finish-ack'], [value['kind'] for channel,value in sent if channel is self.local])

    def test_terminal_drain_rejects_duplicate_eof_data_after_eof_and_unknown_frame(self):
        for tail in ([{'kind':'eof'},{'kind':'eof'}],
                     [{'kind':'eof'},{'kind':'data','data':'eA=='}],
                     [{'kind':'cancel'}], [{'kind':'ssh-open','argv':['x']}],
                     [{'kind':'shim-finished','extra':True}]):
            with self.subTest(tail=tail):
                self.bridge = WorkerBridge(self.channel,self.supervisor,self.local)
                self.terminal_sequence(tail)
                self.assertEqual('GIT_WORKER_BRIDGE_FAILED',self.bridge.failure)
                self.assertTrue(self.bridge.cancelled.is_set())

    def test_terminal_drain_keeps_live_identity_and_byte_bound(self):
        self.terminal_sequence([{'kind':'eof'}], authority_error=True)
        self.assertEqual('GIT_WORKER_BRIDGE_FAILED',self.bridge.failure)
        self.bridge = WorkerBridge(self.channel,self.supervisor,self.local)
        with patch('uas.git_worker_native.MAX_BYTES',0):
            self.terminal_sequence([{'kind':'data','data':'eA=='}])
        self.assertEqual('GIT_WORKER_BRIDGE_FAILED',self.bridge.failure)

    def test_terminal_without_finish_is_incomplete_and_refusal_requires_same_barrier(self):
        self.terminal_sequence([])
        self.assertEqual('GIT_WORKER_BRIDGE_INCOMPLETE',self.bridge.failure)
        self.bridge = WorkerBridge(self.channel,self.supervisor,self.local)
        self.terminal_sequence([{'kind':'shim-finished'}],terminal={'kind':'refused','error':'DENIED','record':None})
        self.assertIsNone(self.bridge.failure)

    def test_supervisor_authentication_failure_cancels_and_fences_bridge(self):
        selector = Mock()
        selector.__enter__ = Mock(return_value=selector)
        selector.__exit__ = Mock(return_value=False)
        selector.select.return_value = [(SimpleNamespace(data='supervisor'), 1)]
        with patch('uas.git_worker_native.selectors.DefaultSelector', return_value=selector), \
             patch('uas.git_worker_native._supervisor_value', side_effect=RuntimeError('wrong process')), \
             patch('uas.git_worker_native.send') as send:
            self.bridge._loop()
        self.assertEqual('GIT_WORKER_BRIDGE_FAILED', self.bridge.failure)
        self.assertTrue(self.bridge.cancelled.is_set())
        send.assert_not_called()


class ShimChannel:
    def __init__(self):
        self.sent = []
        self.send = Mock(side_effect=self._send)
    def fileno(self):
        return 700001
    def setblocking(self, value):
        self.blocking = value
    def _send(self, packet):
        self.sent.append(json.loads(packet))
        return len(packet)


class ShimPoll:
    def __init__(self, ticks):
        self.ticks = iter(ticks)
        self.watched = {}
    def __enter__(self):
        return self
    def __exit__(self, *_):
        pass
    def register(self, fd, events, label):
        self.watched[fd] = (events, label)
    def modify(self, fd, events, label):
        self.register(fd, events, label)
    def unregister(self, fd):
        del self.watched[fd]
    def select(self, timeout):
        if not 0 < timeout <= .1:
            raise AssertionError('unbounded shim poll')
        result = []
        for label, events in next(self.ticks):
            configured = next((bits for bits, name in self.watched.values() if name == label), None)
            if configured is None or not configured & events:
                raise AssertionError('unregistered shim event')
            result.append((SimpleNamespace(data=label), events))
        return result


class ShimPumpTests(unittest.TestCase):
    def setUp(self):
        self.channel = ShimChannel()
        self.worker = SimpleNamespace(pidfd=123, revoked=False, require=Mock())
        self.enterContext(patch('uas.git_worker_native.alive', return_value=True))
        self.enterContext(patch('uas.git_worker_native.os.set_blocking'))

    def pump(self, ticks, frames=(), reads=(), writes=(), **kwargs):
        records = [Record(json.dumps(frame).encode(), (100, 65530, 65532), -1) for frame in frames]
        with patch('uas.git_worker_native.selectors.DefaultSelector', return_value=ShimPoll(ticks)), \
             patch('uas.git_worker_native.receive', side_effect=records), \
             patch('uas.git_worker_native.os.read', side_effect=reads) as read, \
             patch('uas.git_worker_native.os.write', side_effect=writes) as write:
            self.read, self.write = read, write
            return shim_stream(self.channel, self.worker, **kwargs)

    def test_stdio_roundtrip_waits_for_queued_output_after_durable_exit(self):
        writes = []
        def write(fd, data):
            count = min(2, len(data))
            writes.append(bytes(data[:count]))
            return count
        result = self.pump([[('stdin', 1)], [('channel', 2), ('stdin', 1)],
            [('channel', 3)], [('stdout', 2), ('channel', 1)], [('stdout', 2)], [('channel',2)], [('channel',1)]],
            frames=[{'kind': 'data', 'data': base64.b64encode(b'abcd').decode()},
                    {'kind': 'exit', 'code': 0, 'status': 'OK'}, {'kind':'shim-finish-ack'}], reads=[b'input', b''], writes=write)
        self.assertEqual(0, result)
        self.assertEqual(b'abcd', b''.join(writes))
        self.assertEqual(['data', 'eof', 'shim-finished'], [frame['kind'] for frame in self.channel.sent])
        self.assertEqual(b'input', base64.b64decode(self.channel.sent[0]['data']))
        self.assertEqual(3, self.worker.require.call_count)
        self.assertTrue(all(type(call.args[0]) is Record for call in self.worker.require.call_args_list))

    def test_input_and_output_limits_refuse_before_unbounded_forwarding(self):
        with patch('uas.git_worker_native.MAX_BYTES', 3):
            with self.assertRaises(GitWorkerError) as caught:
                self.pump([[('stdin', 1)]], reads=[b'abcd'])
            self.assertEqual('GIT_SHIM_INPUT_LIMIT', caught.exception.code)
            self.assertFalse(self.channel.sent)
            with self.assertRaises(GitWorkerError) as caught:
                self.pump([[('channel', 1)]], frames=[{'kind': 'data', 'data': 'YWJjZA=='}])
            self.assertEqual('GIT_SHIM_OUTPUT_LIMIT', caught.exception.code)
            self.write.assert_not_called()

    def test_worker_exit_revocation_and_wrong_record_abort_without_native_process_effects(self):
        self.worker.revoked = True
        with self.assertRaises(GitWorkerError):
            self.pump([])
        self.worker.revoked = False
        self.worker.require.side_effect = OriginDenied('wrong task')
        with self.assertRaises(OriginDenied):
            self.pump([[('channel', 1)]], frames=[{'kind': 'exit', 'code': 0, 'status': 'OK'}])

    def test_refusal_is_literal_nonzero_not_a_new_transport_attempt(self):
        result = self.pump([[('channel', 1)], [('channel',2)], [('channel',1)]], frames=[{'kind': 'refused', 'error': 'FORBIDDEN', 'record': None}, {'kind':'shim-finish-ack'}])
        self.assertEqual(128, result)
        self.assertEqual([{'kind':'shim-finished'}],self.channel.sent)

    def initial_refusal(self, ack, *, authentication_error=False):
        self.channel.settimeout = Mock()
        # Special methods are resolved on the type, not the instance.
        records = [Record(json.dumps(value).encode(), (100,65530,65532), -1)
                   for value in ({'kind':'refused','error':'DENIED','record':None}, ack)]
        if authentication_error:
            self.worker.require.side_effect = OriginDenied('wrong or dead worker')
        with patch.object(ShimChannel, '__enter__', lambda channel: channel, create=True), \
             patch.object(ShimChannel, '__exit__', lambda *args: False, create=True), \
             patch('uas.git_worker_native.socket.socket', return_value=self.channel), \
             patch('uas.git_worker_native.enable'), \
             patch('uas.git_worker_native.send') as send, \
             patch('uas.git_worker_native.os.getuid', return_value=65530), \
             patch('uas.git_worker_native.os.getgid', return_value=65532), \
             patch('uas.git_worker_native.HeldOrigin', return_value=self.worker), \
             patch('uas.git_worker_native.receive', side_effect=records), \
             patch('uas.git_worker_native.selectors.DefaultSelector', return_value=ShimPoll([[('channel',2)],[('channel',1)]])), \
             patch('uas.git_worker_native.os.read') as read, \
             patch('uas.git_worker_native.os.write') as write:
            self.worker.close = Mock()
            self.read, self.write, self.initial_send = read, write, send
            return ssh_shim_main(['--fd','3','git@github.com',"git-upload-pack 'owner/repo.git'"])

    def test_initial_refusal_entrypoint_finishes_before_return_without_stdio(self):
        self.assertEqual(128, self.initial_refusal({'kind':'shim-finish-ack'}))
        self.assertEqual([{'kind':'shim-finished'}], self.channel.sent)
        self.assertEqual(['ssh-open'], [call.args[1]['kind'] for call in self.initial_send.call_args_list])
        self.worker.require.assert_called_once()
        self.worker.close.assert_called_once()
        self.read.assert_not_called()
        self.write.assert_not_called()

    def test_initial_refusal_wrong_ack_or_worker_cannot_return_successfully(self):
        for ack, wrong_worker in (({'kind':'ready'},False), ({'kind':'shim-finish-ack','extra':True},False),
                                  ({'kind':'shim-finish-ack'},True)):
            with self.subTest(ack=ack, wrong_worker=wrong_worker):
                self.worker.require.reset_mock(side_effect=True)
                with self.assertRaises((GitWorkerError,OriginDenied)):
                    self.initial_refusal(ack, authentication_error=wrong_worker)
                self.worker.close.assert_called_once()
                self.assertEqual('cancel', self.initial_send.call_args.args[1]['kind'])

    def test_terminal_discards_unsent_input_and_waits_for_authenticated_finish_ack(self):
        result = self.pump([[('stdin',1)],[('channel',1)],[('channel',2)],[('channel',1)]],
            frames=[{'kind':'exit','code':0,'status':'OK'},{'kind':'shim-finish-ack'}],reads=[b'unsent'])
        self.assertEqual(0,result)
        self.assertEqual([{'kind':'shim-finished'}],self.channel.sent)
        self.assertEqual(2,self.worker.require.call_count)

    def test_early_or_wrong_finish_ack_fences(self):
        with self.assertRaises(GitWorkerError):
            self.pump([[('channel',1)]],frames=[{'kind':'shim-finish-ack'}])
        with self.assertRaises(GitWorkerError):
            self.pump([[('channel',1)],[('channel',2)],[('channel',1)]],
                frames=[{'kind':'exit','code':0,'status':'OK'},{'kind':'data','data':'eA=='}])



if __name__ == '__main__':
    unittest.main()
