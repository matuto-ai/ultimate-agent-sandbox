"""Pure/mocked Supervisor worker bootstrap and SCM_RIGHTS ownership tests."""
import array
from contextlib import ExitStack, nullcontext
import json
import os
import socket
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from uas.git_worker import (GitExecLaunch, TrustedGitWorker, WORKER, _STATUS,
    main, open_inside, receive_configuration, worker_ready)
from uas.kernel_origin import OriginDenied, SCM_PIDFD
from uas.ledger import LedgerError
from uas.workstation_exec import ExecUnavailable


def descriptors(kind, *fds):
    return (socket.SOL_SOCKET, kind, array.array('i', fds).tobytes())


class ConfigurationReceiptTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.channel, self.peer = Mock(), Mock()
        self.supervisor = SimpleNamespace(close=Mock())
        def hold(record):
            self.record = record
            record.pidfd = -1
            return self.supervisor
        self.peer.hold.side_effect = hold
        self.close = self.stack.enter_context(patch('uas.git_worker.os.close'))
        self.inheritable = self.stack.enter_context(patch('uas.git_worker.os.get_inheritable', return_value=False))
        self.credentials = (socket.SOL_SOCKET, socket.SCM_CREDENTIALS, struct.pack('3i', 123, 0, 0))
        self.ancillary = [self.credentials, descriptors(SCM_PIDFD, 30), descriptors(socket.SCM_RIGHTS, 40)]

    def receive(self, *, data=b'{"kind":"execute"}', ancillary=None, flags=0):
        self.channel.recvmsg.return_value = (data, self.ancillary if ancillary is None else ancillary, flags, None)
        return receive_configuration(self.channel, self.peer)

    def test_exact_one_backend_and_connected_peer_record_transfer_ownership_once(self):
        document, backend, supervisor = self.receive()
        self.assertEqual({'kind': 'execute'}, document)
        self.assertEqual(40, backend)
        self.assertIs(supervisor, self.supervisor)
        self.assertEqual((123, 0, 0), self.record.credentials)
        self.assertEqual(-1, self.record.pidfd)
        self.close.assert_not_called()
        self.assertTrue(self.channel.recvmsg.call_args.args[2] & socket.MSG_CMSG_CLOEXEC)

    def test_truncation_missing_or_extra_rights_and_ancillary_all_dispose_installed_fds(self):
        cases = [(self.ancillary, socket.MSG_TRUNC, {30, 40}),
                 (self.ancillary, socket.MSG_CTRUNC, {30, 40}),
                 ([self.credentials, descriptors(SCM_PIDFD, 30)], 0, {30}),
                 ([self.credentials, descriptors(SCM_PIDFD, 30), descriptors(socket.SCM_RIGHTS, 40, 41)], 0, {30, 40, 41}),
                 ([self.credentials, descriptors(SCM_PIDFD, 30, 31), descriptors(socket.SCM_RIGHTS, 40)], 0, {30, 31, 40}),
                 (self.ancillary + [self.credentials], 0, {30, 40}),
                 (self.ancillary + [(999, 999, b'bad')], 0, {30, 40})]
        for ancillary, flags, expected in cases:
            self.close.reset_mock()
            with self.subTest(ancillary=ancillary, flags=flags), self.assertRaises(OriginDenied):
                self.receive(ancillary=ancillary, flags=flags)
            self.assertEqual(expected, {call.args[0] for call in self.close.call_args_list})
            self.assertEqual(len(expected), self.close.call_count)
        self.peer.hold.assert_not_called()

    def test_malformed_negative_or_partial_descriptor_data_cannot_abort_remaining_cleanup(self):
        for raw in (array.array('i', [-1, 40]).tobytes(), array.array('i', [40]).tobytes() + b'x'):
            self.close.reset_mock()
            ancillary = [self.credentials, descriptors(SCM_PIDFD, 30), (socket.SOL_SOCKET, socket.SCM_RIGHTS, raw)]
            with self.assertRaises(OriginDenied):
                self.receive(ancillary=ancillary)
            self.assertEqual({30, 40}, {call.args[0] for call in self.close.call_args_list})

    def test_one_close_failure_does_not_skip_other_received_descriptors(self):
        self.close.side_effect = lambda fd: (_ for _ in ()).throw(OSError('uncertain')) if fd == 40 else None
        with self.assertRaises(OSError):
            self.receive(flags=socket.MSG_TRUNC)
        self.assertEqual([40, 30], [call.args[0] for call in self.close.call_args_list])

    def test_inheritable_or_wrong_process_receipt_rejects_and_closes_all(self):
        self.inheritable.side_effect = lambda fd: fd == 40
        with self.assertRaises(OriginDenied):
            self.receive()
        self.assertEqual({30, 40}, {call.args[0] for call in self.close.call_args_list})
        self.inheritable.side_effect = None
        self.peer.hold.side_effect = OriginDenied('not connected peer')
        self.close.reset_mock()
        with self.assertRaises(OriginDenied):
            self.receive()
        self.assertEqual({30, 40}, {call.args[0] for call in self.close.call_args_list})

    def test_bad_json_closes_transferred_supervisor_and_backend_even_if_supervisor_close_fails(self):
        for failure in (None, OSError('uncertain supervisor close')):
            self.close.reset_mock()
            self.supervisor.close.reset_mock()
            self.supervisor.close.side_effect = failure
            with self.assertRaises(Exception):
                self.receive(data=b'[]')
            self.supervisor.close.assert_called_once_with()
            self.close.assert_called_once_with(40)


def launch(state='active'):
    value = object.__new__(GitExecLaunch)
    value.state = state
    value.channel = Mock()
    value.channel.sendmsg.side_effect = lambda packets, ancillary: len(packets[0])
    value.seat = SimpleNamespace(room_id='room', participant_id='seat-a', slot='seat-a')
    value.endpoint = SimpleNamespace(require=Mock())
    value.origin = SimpleNamespace(require=Mock(), revoke=Mock(), pidfd=123, identity=(4, 99), revoked=False)
    value.require_record = Mock()
    value._save = Mock()
    value.activate = Mock(side_effect=lambda predicate: setattr(value, 'state', 'active') if predicate(value) else None)
    return value


class TrustedWorkerTests(unittest.TestCase):
    def test_only_exact_active_trusted_launch_and_fixed_recipe(self):
        for value in (object(), SimpleNamespace(state='active'), launch('released')):
            with self.assertRaises(OriginDenied):
                TrustedGitWorker(value)
        value = launch()
        spec = value._create_spec()
        self.assertEqual('65530:65532', spec['User'])
        self.assertEqual([WORKER, 'seat-a'], spec['Cmd'])
        self.assertEqual([], spec['Env'])
        self.assertFalse(spec['Privileged'])

    def test_configuration_is_one_shot_one_descriptor_and_no_replay_after_send_uncertainty(self):
        for outcome in ('success', 'short', 'exception'):
            value = launch()
            worker = TrustedGitWorker(value)
            if outcome == 'short':
                value.channel.sendmsg.side_effect = lambda packets, ancillary: len(packets[0]) - 1
            elif outcome == 'exception':
                value.channel.sendmsg.side_effect = OSError('uncertain send')
            if outcome == 'success':
                worker.configure({'kind': 'execute'}, 19)
            else:
                with self.assertRaises(Exception):
                    worker.configure({'kind': 'execute'}, 19)
            packets, ancillary = value.channel.sendmsg.call_args.args
            self.assertEqual({'kind': 'execute'}, json.loads(packets[0]))
            self.assertEqual((socket.SOL_SOCKET, socket.SCM_RIGHTS), ancillary[0][:2])
            self.assertEqual([19], list(ancillary[0][2]))
            with self.assertRaisesRegex(LedgerError, 'ALREADY_CONSUMED'):
                worker.configure({'kind': 'execute'}, 19)
            self.assertEqual(1, value.channel.sendmsg.call_count)

    def test_size_or_endpoint_failure_consumes_attempt_before_transport(self):
        for document, error in (({'data': 'x' * 65536}, None), ({'kind': 'execute'}, OSError('replaced endpoint'))):
            value = launch()
            value.endpoint.require.side_effect = error
            worker = TrustedGitWorker(value)
            with self.assertRaises(Exception):
                worker.configure(document, 19)
            self.assertTrue(worker.used)
            value.channel.sendmsg.assert_not_called()

    def test_record_checks_current_room_participant_and_reply_rechecks_endpoint(self):
        value = launch()
        worker = TrustedGitWorker(value)
        record = SimpleNamespace(data=b'{"kind":"preflight"}')
        with patch('uas.git_worker.receive', return_value=nullcontext(record)):
            self.assertEqual({'kind': 'preflight'}, worker.receive())
        value.require_record.assert_called_once_with(record, room_id='room', participant_id='seat-a')
        with patch('uas.git_worker.send') as send:
            worker.reply({'kind': 'go'})
        value.endpoint.require.assert_called_once()
        send.assert_called_once_with(value.channel, {'kind': 'go'})

    def test_all_readiness_failures_revoke_persist_uncertainty_and_never_retry(self):
        for failure in ('receive', 'origin', 'json', 'boundary', 'activate'):
            value = launch('released')
            ready = {'kind': 'GIT_WORKER_READY', 'version': 1, 'uid': 65530, 'gid': 65532, 'kernel_status': _STATUS}
            raw = json.dumps(ready).encode()
            if failure == 'origin': value.origin.require.side_effect = OriginDenied('wrong record')
            if failure == 'json': raw = b'[]'
            if failure == 'boundary': raw = b'{"kind":"fake-ready"}'
            if failure == 'activate': value.activate.side_effect = ExecUnavailable('lost admission')
            with patch('uas.git_worker.receive', return_value=nullcontext(SimpleNamespace(data=raw))) as receive:
                if failure == 'receive': receive.side_effect = OSError('lost')
                with self.subTest(failure=failure), self.assertRaises(Exception):
                    value.attach_worker()
                self.assertEqual('uncertain', value.state)
                value.origin.revoke.assert_called_once()
                value._save.assert_called_once()
                count = receive.call_count
                with self.assertRaises(ExecUnavailable):
                    value.attach_worker()
                self.assertEqual(count, receive.call_count)

    def test_exact_fixed_ready_record_activates_once(self):
        value = launch('released')
        ready = {'kind': 'GIT_WORKER_READY', 'version': 1, 'uid': 65530, 'gid': 65532, 'kernel_status': _STATUS}
        with patch('uas.git_worker.receive', return_value=nullcontext(SimpleNamespace(data=json.dumps(ready).encode()))):
            self.assertIsInstance(value.attach_worker(), TrustedGitWorker)
        self.assertEqual('active', value.state)
        value.origin.revoke.assert_not_called()

    def test_ready_numeric_fields_are_exact_integers_not_bool_or_float_equivalents(self):
        for field, replacement in (('version', True), ('version', 1.0), ('uid', 65530.0), ('gid', 65532.0)):
            value = launch('released')
            ready = {'kind': 'GIT_WORKER_READY', 'version': 1, 'uid': 65530, 'gid': 65532, 'kernel_status': _STATUS}
            ready[field] = replacement
            with patch('uas.git_worker.receive', return_value=nullcontext(SimpleNamespace(data=json.dumps(ready).encode()))):
                with self.subTest(field=field, replacement=replacement), self.assertRaises(ExecUnavailable):
                    value.attach_worker()
            self.assertEqual('uncertain', value.state)
            value.activate.assert_not_called()


class InsideAndMainTests(unittest.TestCase):
    def test_every_path_component_is_canonical_nofollow_inside_namespace(self):
        with patch('uas.git_worker.os.open', side_effect=[50, 51, 52, 53]) as opened, patch('uas.git_worker.os.close') as close:
            self.assertEqual(53, open_inside('/project/.git/config', directory=False))
        self.assertEqual(['/', 'project', '.git', 'config'], [call.args[0] for call in opened.call_args_list])
        self.assertEqual([50, 51, 52], [call.args[0] for call in close.call_args_list])
        for call in opened.call_args_list[1:]:
            self.assertTrue(call.args[1] & os.O_NOFOLLOW)
        for path in ('relative', '//project', '/project/../etc', '/project//x', '/project/./x', '/project\x00x'):
            with patch('uas.git_worker.os.open') as opened, self.assertRaises(OriginDenied):
                open_inside(path, directory=True)
            opened.assert_not_called()

    def test_close_uncertainty_never_retries_old_fd_or_leaks_new_parent(self):
        with patch('uas.git_worker.os.open', side_effect=[50, 51]), patch('uas.git_worker.os.close', side_effect=[OSError('uncertain'), None]) as close:
            with self.assertRaises(OSError):
                open_inside('/project/config', directory=False)
        self.assertEqual([50, 51], [call.args[0] for call in close.call_args_list])

    def test_final_parent_close_failure_disposes_unreturned_result(self):
        with patch('uas.git_worker.os.open', side_effect=[50, 51]), patch('uas.git_worker.os.close', side_effect=[OSError('uncertain'), None]) as close:
            with self.assertRaises(OSError):
                open_inside('/config', directory=False)
        self.assertEqual([50, 51], [call.args[0] for call in close.call_args_list])

    def test_worker_ready_has_fixed_identity_and_exact_kernel_status(self):
        for uid, gid, status, okay in ((65530, 65532, _STATUS, True), (65532, 65532, _STATUS, False),
            (65530, 0, _STATUS, False), (65530, 65532, _STATUS | {'NoNewPrivs': '0'}, False)):
            with patch('uas.git_worker.os.getuid', return_value=uid), patch('uas.git_worker.os.getgid', return_value=gid), \
                 patch('uas.workstation_probe.process_status', return_value=status), patch('uas.git_worker.send') as send:
                if okay:
                    worker_ready('channel')
                    self.assertEqual({'kind': 'GIT_WORKER_READY', 'version': 1, 'uid': 65530, 'gid': 65532, 'kernel_status': _STATUS}, send.call_args.args[1])
                else:
                    with self.assertRaises(OriginDenied): worker_ready('channel')
                    send.assert_not_called()

    def test_main_uses_only_connector_fd3_and_disposes_peer_and_supervisor_on_all_outcomes(self):
        for failure in (None, 'worker', 'peer-close'):
            channel, peer, supervisor = Mock(), Mock(), Mock()
            channel.__enter__ = Mock(return_value=channel)
            channel.__exit__ = Mock(return_value=False)
            if failure == 'peer-close': peer.close.side_effect = OSError('uncertain')
            document = {'kind': 'execute', 'operation_id': 'operation-one'}
            acknowledgement = {'kind': 'GIT_WORKER_EXIT_ACK', 'version': 1, 'operation_id': 'operation-one'}
            record = SimpleNamespace(data=json.dumps(acknowledgement).encode())
            with patch('uas.git_worker.socket.socket', return_value=channel) as socket_ctor, \
                 patch('uas.git_worker.enable'), patch('uas.git_endpoint.EndpointPeer', return_value=peer), \
                 patch('uas.git_worker.worker_ready') as ready, \
                 patch('uas.git_worker.receive_configuration', return_value=(document, 19, supervisor)), \
                 patch('uas.git_worker.send') as send, \
                 patch('uas.git_worker.receive', return_value=nullcontext(record)), \
                 patch('uas.git_worker_native.worker_main', return_value='done') as worker:
                if failure == 'worker': worker.side_effect = OriginDenied('native refused')
                if failure is None:
                    self.assertEqual('done', main())
                else:
                    with self.assertRaises(Exception): main()
                socket_ctor.assert_called_once_with(fileno=3)
                ready.assert_called_once_with(channel)
                worker.assert_called_once_with(channel, document, 19, supervisor)
                if failure == 'worker':
                    send.assert_not_called()
                    supervisor.require.assert_not_called()
                else:
                    send.assert_called_once_with(channel, {'kind': 'GIT_WORKER_QUIESCENT', 'version': 1,
                                                          'operation_id': 'operation-one'})
                    supervisor.require.assert_called_once_with(record)
            peer.close.assert_called_once()
            supervisor.close.assert_called_once()

    def test_main_quiescence_requires_exact_live_supervisor_exit_acknowledgement(self):
        expected = {'kind': 'GIT_WORKER_EXIT_ACK', 'version': 1, 'operation_id': 'operation-one'}
        for change in ({'version': True}, {'version': 1.0}, {'operation_id': 'different'},
                       {'kind': 'close'}, {'extra': 1}, {'wrong_record': True}):
            with self.subTest(change=change):
                channel, peer, supervisor = Mock(), Mock(), Mock()
                channel.__enter__ = Mock(return_value=channel)
                channel.__exit__ = Mock(return_value=False)
                response = expected | change
                if 'wrong_record' in change:
                    response = expected
                    supervisor.require.side_effect = OriginDenied('different live process')
                record = SimpleNamespace(data=json.dumps(response).encode())
                with patch('uas.git_worker.socket.socket', return_value=channel), \
                     patch('uas.git_worker.enable'), patch('uas.git_endpoint.EndpointPeer', return_value=peer), \
                     patch('uas.git_worker.worker_ready'), \
                     patch('uas.git_worker.receive_configuration', return_value=({'operation_id': 'operation-one'}, 19, supervisor)), \
                     patch('uas.git_worker_native.worker_main', return_value='done'), \
                     patch('uas.git_worker.send') as send, \
                     patch('uas.git_worker.receive', return_value=nullcontext(record)):
                    with self.assertRaises(OriginDenied):
                        main()
                self.assertEqual(1, send.call_count)
                supervisor.require.assert_called_once_with(record)
                peer.close.assert_called_once()
                supervisor.close.assert_called_once()


class WorkerExitProofTests(unittest.TestCase):
    """No socket, pidfd, selector or clock observation here touches the kernel."""
    def setUp(self):
        self.value = launch()
        self.value.close = Mock()
        self.value.channel.gettimeout.return_value = 40
        self.worker = TrustedGitWorker(self.value)
        self.message = {'kind': 'GIT_WORKER_QUIESCENT', 'version': 1, 'operation_id': 'operation-one'}
        self.record = SimpleNamespace(data=json.dumps(self.message).encode())
        self.received = self.enterContext(patch('uas.git_worker.receive', return_value=nullcontext(self.record)))
        self.send = self.enterContext(patch('uas.git_worker.send'))
        self.clock = self.enterContext(patch('uas.git_worker.time.monotonic', return_value=0))
        self.dup = self.enterContext(patch('uas.git_worker.os.dup', return_value=456))
        self.identity = self.enterContext(patch('uas.git_worker._identity', return_value=(4, 99)))
        self.close = self.enterContext(patch('uas.git_worker.os.close'))
        self.alive = self.enterContext(patch('uas.git_worker.alive', side_effect=lambda fd: not self.send.called))
        self.select = self.enterContext(patch('uas.git_worker.select.select'))

    def test_authenticated_quiescence_ack_then_exact_held_task_exit(self):
        self.alive.side_effect = [True, True, False]
        result = self.worker.finish('operation-one')
        self.assertEqual({'worker_identity': [4, 99], 'quiescent': True, 'exited': True}, result)
        self.value.require_record.assert_called_once_with(self.record, room_id='room', participant_id='seat-a')
        self.send.assert_called_once_with(self.value.channel,
            {'kind': 'GIT_WORKER_EXIT_ACK', 'version': 1, 'operation_id': 'operation-one'})
        self.select.assert_called_once_with([456], [], [], .05)
        self.dup.assert_called_once_with(123)
        self.identity.assert_called_once_with(456)
        self.assertEqual([456, 456, 456], [call.args[0] for call in self.alive.call_args_list])
        self.close.assert_called_once_with(456)
        self.assertEqual([2, 40], [call.args[0] for call in self.value.channel.settimeout.call_args_list])
        self.value.close.assert_not_called()
        self.value.channel.close.assert_not_called()

    def test_quiescence_packet_without_held_exit_times_out_and_never_closes_as_proof(self):
        self.alive.return_value = True
        self.alive.side_effect = None
        self.clock.side_effect = [0, .1, .2, 2]
        with self.assertRaises(OriginDenied):
            self.worker.finish('operation-one')
        self.select.assert_called_once_with([456], [], [], .05)
        self.close.assert_called_once_with(456)
        self.value.channel.settimeout.assert_called_with(40)
        self.value.close.assert_not_called()
        self.value.channel.close.assert_not_called()

    def test_wrong_origin_or_receive_failure_never_gets_exit_ack(self):
        for failure in ('identity', 'timeout'):
            self.send.reset_mock()
            if failure == 'identity':
                self.value.require_record.side_effect = OriginDenied('wrong task')
            else:
                self.value.require_record.side_effect = None
                self.received.side_effect = TimeoutError('no quiescence')
            with self.subTest(failure=failure), self.assertRaises((OriginDenied, TimeoutError)):
                self.worker.finish('operation-one')
            self.send.assert_not_called()
            self.select.assert_not_called()
            self.assertTrue(all(call.args == (456,) for call in self.alive.call_args_list))
            self.value.channel.settimeout.assert_called_with(40)

    def test_quiescence_shape_operation_and_version_are_exact_before_ack(self):
        for change in ({'kind': 'result'}, {'version': True}, {'version': 1.0},
                       {'operation_id': 'different'}, {'extra': True}):
            self.record.data = json.dumps(self.message | change).encode()
            with self.subTest(change=change), self.assertRaises(OriginDenied):
                self.worker.finish('operation-one')
            self.send.assert_not_called()
            self.select.assert_not_called()

    def test_late_quiescence_is_not_acknowledged(self):
        self.clock.side_effect = [0, 2]
        with self.assertRaises(OriginDenied):
            self.worker.finish('operation-one')
        self.send.assert_not_called()
        self.alive.assert_called_once_with(456)

    def test_invalid_deadline_refuses_before_any_channel_observation(self):
        for timeout in (True, 0, 3, float('nan'), '2'):
            with self.subTest(timeout=timeout), self.assertRaises(OriginDenied):
                self.worker.finish('operation-one', timeout=timeout)
        self.value.channel.gettimeout.assert_not_called()
        self.received.assert_not_called()

    def test_closed_or_revoked_origin_cannot_stand_in_for_observed_exit(self):
        for pidfd, revoked in ((-1, False), (123, True)):
            self.value.origin.pidfd, self.value.origin.revoked = pidfd, revoked
            with self.subTest(pidfd=pidfd, revoked=revoked), self.assertRaises(OriginDenied):
                self.worker.finish('operation-one')
        self.value.close.assert_not_called()

    def test_post_ack_original_close_or_swap_still_waits_only_independently_owned_task(self):
        for field, changed in (('pidfd', -1), ('pidfd', 124), ('identity', (4, 100)), ('revoked', True)):
            self.value.origin.pidfd, self.value.origin.identity, self.value.origin.revoked = 123, (4, 99), False
            self.send.reset_mock()
            self.alive.reset_mock()
            self.select.reset_mock()
            self.alive.side_effect = [True, True, False]
            self.send.side_effect = lambda *args, key=field, replacement=changed: setattr(self.value.origin, key, replacement)
            with self.subTest(field=field, changed=changed):
                result = self.worker.finish('operation-one')
            self.assertEqual({'worker_identity': [4, 99], 'quiescent': True, 'exited': True}, result)
            self.assertEqual([456, 456, 456], [call.args[0] for call in self.alive.call_args_list])
            self.select.assert_called_once_with([456], [], [], .05)

    def test_stale_duplicate_identity_or_initially_dead_task_never_receives_or_acks(self):
        for mismatch in ('identity', 'dead'):
            self.identity.return_value = (4, 100) if mismatch == 'identity' else (4, 99)
            self.alive.side_effect = None
            self.alive.return_value = False
            with self.subTest(mismatch=mismatch), self.assertRaises(OriginDenied):
                self.worker.finish('operation-one')
        self.received.assert_not_called()
        self.send.assert_not_called()
        self.assertEqual([456, 456], [call.args[0] for call in self.close.call_args_list])

    def test_duplicate_failure_or_final_close_uncertainty_never_yields_exit_proof(self):
        self.dup.side_effect = OSError('duplicate unavailable')
        with self.assertRaises(OSError):
            self.worker.finish('operation-one')
        self.close.assert_not_called()
        self.received.assert_not_called()
        self.dup.side_effect = None
        self.close.side_effect = OSError('duplicate close uncertain')
        with self.assertRaises(OSError):
            self.worker.finish('operation-one')
        self.close.assert_called_once_with(456)


if __name__ == '__main__':
    unittest.main()
