"""Pure/mocked helper lifecycle tests. No sockets, native payloads or kernel probes."""
import copy
import hashlib
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from uas import artifact_helper as helper
from uas.artifact_protocol import ArtifactError, canonical, expected_header, scope_digest
from uas.kernel_origin import HeldOrigin, ReceiverIdentity, Record

SCOPE = {'version': 1, 'evaluation_id': 'evaluation-a', 'room_id': 'alpha',
    'room_instance': 'instance-a', 'project_id': 'project-a', 'repository': 'org/repo',
    'run_id': 'run-a', 'generation': 1, 'participant_id': 'alice', 'policy_id': 'default',
    'policy_version': 1, 'policy_digest': 'a' * 64, 'gate_id': 'artifact', 'config_digest': 'b' * 64}
TARGET = {'target_id': 'c' * 32, 'head_sha': 'd' * 40, 'tree_sha': 'e' * 40,
    'manifest_sha256': 'f' * 64, 'source_digest': '1' * 64,
    'device': 1, 'inode': 2, 'entries': 1, 'expanded_bytes': 3}
PATHS = ['file.txt']


def origin():
    value = object.__new__(HeldOrigin)
    value.pidfd, value.identity, value.credentials = 40, (3, 4), (22, 165530, 165530)
    value.revoked, value._receiver = False, None
    value.require = Mock()
    value.close = Mock()
    return value


def workstation():
    return helper.GateWorkstation('alpha', 'instance-a', *[c * 64 for c in '123456'], 'hub')


def bound_document():
    return {'version': 1, 'kind': 'GATE_BIND', 'exchange_id': '1' * 32,
        'controller': '2' * 32, 'scope': copy.deepcopy(SCOPE), 'target': copy.deepcopy(TARGET),
        'profile': 'artifacts-v1-source', 'profile_digest': '3' * 64,
        'mapping_digest': '4' * 64, 'receiver_context': 'hub', 'origin_identity': [3, 4]}


class ArtifactHelperPureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='uas-artifact-lifecycle-pure-')
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def launch(self):
        endpoint = object.__new__(helper.GateEndpointLease)
        endpoint.require = Mock(return_value=True)
        lease = Mock()
        lease.document.return_value = copy.deepcopy(TARGET)
        lease.recheck.return_value = lease.recheck_binding.return_value = lease.cleanup.return_value = True
        lease.postverify.return_value = copy.deepcopy(TARGET)
        admission = Mock(); admission.require.return_value = True
        engine = Mock(); engine.create.return_value = '9' * 64
        result = helper.GateHelperLaunch(engine, workstation(), endpoint, self.root / 'launch.json',
            admission=admission, target_lease=lease, scope=copy.deepcopy(SCOPE))
        return result

    def test_workstation_has_no_actor_or_participant_authority(self):
        self.assertEqual(set(workstation().__dict__), {'room_id', 'room_instance', 'container_id',
            'image_digest', 'profile_digest', 'bootstrap_digest', 'evaluator_digest', 'mapping_digest', 'receiver_context'})
        with self.assertRaises(ArtifactError):
            helper.GateWorkstation('alpha', 'instance-a', *['x' * 64] * 6, 'hub')

    def test_constructor_rejects_other_room_and_preserves_no_effects(self):
        launch = self.launch()
        self.assertFalse(launch.engine.mock_calls)
        self.assertFalse(launch.journal_path.exists())
        with self.assertRaises(ArtifactError):
            helper.GateHelperLaunch(launch.engine, workstation(), launch.endpoint,
                self.root / 'wrong', admission=launch.admission, target_lease=launch.target_lease,
                scope={**SCOPE, 'room_id': 'other'})

    def test_admission_denial_precedes_journal_and_engine(self):
        launch = self.launch(); launch.admission.require.return_value = False
        with self.assertRaises(ArtifactError):
            launch.start(Mock())
        launch.engine.create.assert_not_called()
        self.assertFalse(launch.journal_path.exists())

    def test_source_change_precedes_engine(self):
        launch = self.launch(); launch.target_lease.recheck.return_value = False
        with self.assertRaises(ArtifactError):
            launch.start(Mock())
        launch.engine.create.assert_not_called()

    def test_existing_journal_is_not_adopted_or_overwritten(self):
        launch = self.launch(); launch.journal_path.write_text('uncertain')
        with patch.object(helper, 'enable'), self.assertRaises(FileExistsError):
            launch.start(Mock())
        self.assertEqual(launch.journal_path.read_text(), 'uncertain')
        launch.engine.create.assert_not_called()

    def test_create_uncertainty_keeps_journal_and_blocks_retry(self):
        launch = self.launch(); launch.engine.create.side_effect = OSError('lost reply')
        with patch.object(helper, 'enable'), self.assertRaises(OSError):
            launch.start(Mock())
        self.assertEqual(launch.state, 'quarantined')
        self.assertTrue(launch.journal_path.exists())
        with self.assertRaises(ArtifactError):
            launch.start(Mock())
        self.assertEqual(launch.engine.create.call_count, 1)
        launch.target_lease.mark_launch_possible.assert_called_once()
        document = launch.engine.create.call_args.args[1]
        self.assertEqual(document['User'], '65530:65530')
        self.assertEqual(document['Cmd'], ['/opt/uas/bin/artifact-bootstrap'])
        self.assertEqual(document['Env'], [])
        self.assertFalse(document['Privileged'])
        self.assertNotIn('challenge', launch.journal_path.read_text())
        launch.close()

    def test_journal_replacement_and_hardlink_rejected(self):
        path = self.root / 'journal'
        journal = helper._LaunchJournal(path)
        journal.append({'stage': 'intent'})
        replacement = self.root / 'replacement'; replacement.write_text('other')
        os.replace(replacement, path)
        with self.assertRaises(ArtifactError):
            journal.append({'stage': 'second'})
        journal.close()
        path.unlink()
        journal = helper._LaunchJournal(path)
        os.link(path, self.root / 'hardlink')
        with self.assertRaises(ArtifactError):
            journal.append({'stage': 'second'})
        journal.close()

    def test_launch_success_needs_kernel_origin_and_rechecks_before_release(self):
        launch = self.launch(); channel = Mock(); channel.send.side_effect = lambda p: len(p)
        listener = Mock(); listener.accept.return_value = (channel, None)
        record = Record(b'AGH1' + b'z' * 32, (22, 165530, 165530), -1)
        held = origin()
        launch.engine.inspect.return_value = {'ID': '9' * 64, 'ContainerID': '1' * 64,
                                             'Running': True, 'Pid': 22}
        with patch.object(helper, 'enable'), patch.object(helper, 'receive', return_value=record), \
                patch.object(helper, 'HeldOrigin', return_value=held), \
                patch.object(helper, 'alive', return_value=True), \
                patch.object(helper.secrets, 'token_bytes', return_value=b'z' * 32):
            launch.start(listener)
        self.assertEqual(launch.state, 'bound')
        self.assertEqual(channel.send.call_args.args[0], b'AGR1' + b'c' * 32)
        self.assertEqual(launch.admission.require.call_count, 2)
        self.assertEqual(launch.target_lease.recheck.call_count, 2)
        launch.close()

    def test_wrong_helper_uid_cannot_be_bound(self):
        launch = self.launch(); listener = Mock(); listener.accept.return_value = (Mock(), None)
        record = Record(b'AGH1' + b'z' * 32, (22, 165532, 165532), -1)
        with patch.object(helper, 'enable'), patch.object(helper, 'receive', return_value=record), \
                patch.object(helper.secrets, 'token_bytes', return_value=b'z' * 32), \
                self.assertRaises(ArtifactError):
            launch.start(listener)
        self.assertIsNone(launch.origin)
        self.assertEqual(launch.state, 'quarantined')
        launch.close()

    def terminal_launch(self):
        launch = self.launch()
        launch.origin, launch.state = origin(), 'running'
        launch.exec_id, launch.deadline = '9' * 64, 9999999999
        launch.binding = bound_document()
        launch.journal = helper._LaunchJournal(launch.journal_path)
        launch.engine.inspect.return_value = {'ID': '9' * 64, 'ContainerID': '1' * 64,
            'Running': False, 'ExitCode': 0}
        return launch

    def test_final_requires_held_exit_then_engine_exit_then_postproof_cleanup(self):
        launch = self.terminal_launch()
        with patch.object(launch, '_exit', return_value=True):
            result = launch.finish(final_digest=scope_digest(SCOPE, TARGET))
        self.assertEqual(result, {'exit_confirmed': True, 'post_target': TARGET,
            'cleanup': True, 'quarantine_ref': None, 'launch_state': 'exited'})
        launch.target_lease.mark_exit_confirmed.assert_called_once()
        launch.target_lease.recheck_binding.assert_called_once()
        launch.target_lease.recheck.assert_not_called()
        launch.target_lease.postverify.assert_called_once()
        launch.target_lease.cleanup.assert_called_once()
        launch.close()

    def test_unconfirmed_exit_never_inspects_success_or_cleans(self):
        launch = self.terminal_launch()
        with patch.object(launch, '_exit', return_value=False):
            result = launch.finish(final_digest=scope_digest(SCOPE, TARGET))
        self.assertFalse(result['cleanup']); self.assertEqual(result['launch_state'], 'unknown')
        launch.engine.inspect.assert_not_called(); launch.target_lease.cleanup.assert_not_called()
        launch.close()

    def test_nonzero_exit_postmutation_and_cleanupfailure_never_succeed(self):
        for failure in ('exit', 'post', 'cleanup'):
            with self.subTest(failure=failure):
                launch = self.terminal_launch()
                if failure == 'exit': launch.engine.inspect.return_value['ExitCode'] = 1
                elif failure == 'post': launch.target_lease.postverify.return_value = False
                else: launch.target_lease.cleanup.return_value = False
                with patch.object(launch, '_exit', return_value=True):
                    result = launch.finish(final_digest=scope_digest(SCOPE, TARGET))
                self.assertFalse(result['cleanup']); self.assertIsNotNone(result['quarantine_ref'])
                self.assertEqual(result['launch_state'], 'exited')
                launch.close(); launch.journal_path.unlink()

    def test_abort_without_held_identity_never_removes_target(self):
        launch = self.launch()
        result = launch.abort()
        self.assertFalse(result['cleanup']); self.assertEqual(result['launch_state'], 'unknown')
        launch.target_lease.cleanup.assert_not_called()

    def test_offer_metadata_is_defensive_and_not_helper_claimed(self):
        offer = helper.GateOffer(bound_document(), Mock(), origin(), PATHS)
        doc = offer.document(); doc['profile_digest'] = 'bad'
        self.assertEqual(offer.document()['profile_digest'], '3' * 64)
        self.assertEqual(offer.document()['provenance'], 'workstation-local / tamper-evident')
        self.assertNotIn('pid', offer.document())

    def test_offer_ack_is_exact_live_final_and_single_use(self):
        channel = Mock(); channel.send.side_effect = lambda data: len(data)
        offer = helper.GateOffer(bound_document(), channel, origin(), PATHS)
        with self.assertRaises(ArtifactError): offer.acknowledge_final({})
        offer.final = expected_header(SCOPE, TARGET, PATHS, kind='final'); offer.state = 'final'
        with patch.object(helper, 'alive', return_value=True), \
                patch.object(helper.select, 'poll') as poll:
            poll.return_value.poll.return_value = []
            offer.acknowledge_final(offer.final)
        self.assertEqual(channel.send.call_args.args[0], b'AGA1' + bytes.fromhex(scope_digest(SCOPE, TARGET)))
        with self.assertRaises(ArtifactError): offer.acknowledge_final(offer.final)

    def test_offer_pending_extra_record_is_rejected_before_ack(self):
        channel = Mock(); offer = helper.GateOffer(bound_document(), channel, origin(), PATHS)
        offer.final = expected_header(SCOPE, TARGET, PATHS, kind='final'); offer.state = 'final'
        with patch.object(helper, 'alive', return_value=True), \
                patch.object(helper.select, 'poll') as poll, \
                patch.object(helper, 'receive', return_value=Record(b'extra', (0, 0, 0), -1)):
            poll.return_value.poll.return_value = [(3, 1)]
            with self.assertRaises(ArtifactError): offer.acknowledge_final(offer.final)
        channel.send.assert_not_called()

    def test_offer_exit_requires_pidfd_readiness_not_eof(self):
        channel = Mock(); channel.recv.return_value = b''
        offer = helper.GateOffer(bound_document(), channel, origin(), PATHS); offer.state = 'acked'
        with patch.object(helper.select, 'poll') as poll, patch.object(helper, 'alive', return_value=True), \
                patch.object(helper, '_identity', return_value=(3, 4)):
            poll.return_value.poll.return_value = []
            with self.assertRaises(ArtifactError): offer.confirm_exit()
        channel.recv.assert_not_called()

    def test_offer_extra_output_after_exit_rejected(self):
        channel = Mock(); channel.recv.return_value = b'x'
        offer = helper.GateOffer(bound_document(), channel, origin(), PATHS); offer.state = 'acked'
        with patch.object(helper.select, 'poll') as poll, patch.object(helper, 'alive', return_value=False), \
                patch.object(helper, '_identity', return_value=(3, 4)):
            poll.return_value.poll.return_value = [(40, 1)]
            with self.assertRaises(ArtifactError): offer.confirm_exit()

    def test_offer_records_are_ordered_bounded_and_authenticated(self):
        from uas.artifact_protocol import _HEADER, _ITEM
        digest = bytes.fromhex(scope_digest(SCOPE, TARGET))
        head = lambda kind: _HEADER.pack(kind, digest, bytes.fromhex(TARGET['target_id']),
            bytes.fromhex(TARGET['manifest_sha256']), 1, 2, 1)
        item = _ITEM.pack(b'AGI1', 0, hashlib.sha256(PATHS[0].encode()).digest(), 1, 3, 0, 0)
        records = [Record(raw, (22, 165530, 165530), -1) for raw in (head(b'AGS1'), item, head(b'AGF1'))]
        channel = Mock(); channel.send.side_effect = lambda raw: len(raw)
        held = origin(); offer = helper.GateOffer(bound_document(), channel, held, PATHS)
        with patch.object(helper, 'alive', return_value=True), patch.object(helper, 'receive', side_effect=records):
            values = list(offer.records())
        self.assertEqual([v['kind'] for v in values], ['header', 'item', 'final'])
        self.assertEqual(held.require.call_count, 3)
        with self.assertRaises(ArtifactError): list(offer.records())

    def test_control_client_cannot_finish_naked_json_or_live_offer(self):
        receiver = ReceiverIdentity(65530, 65530, 'hub', '4' * 64)
        client = helper.GateControlClient(Mock(), supervisor=origin(), receiver=receiver,
            profile_digest='3' * 64, controller='2' * 32, control_lock=threading.Lock())
        with self.assertRaises(ArtifactError): client.finish(TARGET, {})
        offer = helper.GateOffer(bound_document(), Mock(), origin(), PATHS)
        with self.assertRaises(ArtifactError): client.finish(TARGET, offer)

    def test_service_never_reconstructs_unknown_or_restarted_launch(self):
        targets = Mock()
        service = helper.GateSupervisorService(Mock(), targets, launch_factory=Mock(), listener=Mock())
        result = service.handle('reconcile', {'evaluation_id': 'old-eval'})
        self.assertEqual(result['launch_state'], 'unknown'); self.assertFalse(result['cleanup'])
        targets.reconcile.assert_not_called()

    def test_service_partial_prepare_is_never_replayed_and_can_clean_beforelaunch(self):
        targets = Mock(); targets.prepare.side_effect = ArtifactError('PREPARE_FAILED')
        targets.reconcile.return_value = True
        service = helper.GateSupervisorService(Mock(), targets, launch_factory=Mock(), listener=Mock())
        payload = {'scope': SCOPE, 'source': {}}
        with self.assertRaises(ArtifactError): service.handle('prepare', payload)
        with self.assertRaises(ArtifactError): service.handle('prepare', payload)
        self.assertEqual(targets.prepare.call_count, 1)
        result = service.handle('abort', {'evaluation_id': SCOPE['evaluation_id'], 'target': None})
        self.assertEqual(result['launch_state'], 'never-launched'); self.assertTrue(result['cleanup'])

    def test_control_packet_rejects_duplicate_noncanonical_and_unknown(self):
        for raw in (b'{"x":1,"x":2}', b'{"x": 1}', b'[]', b'NaN'):
            with self.assertRaises(ArtifactError): helper._document(raw)
        service = helper.GateSupervisorService(Mock(), Mock(), launch_factory=Mock(), listener=Mock())
        with self.assertRaises(ArtifactError): service.handle('exec', {'argv': ['/bin/sh']})

class ArtifactGateTransportPureTests(unittest.TestCase):
    def receiver(self):
        return ReceiverIdentity(65530, 65530, 'hub', '4' * 64)

    def control(self, document, rights=(51, 52), extra=None):
        import array
        import socket
        import struct
        ancillary = [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS, struct.pack('3i', 11, 165533, 165533)),
                     (socket.SOL_SOCKET, helper.SCM_PIDFD, array.array('i', [50]).tobytes())]
        if rights:
            ancillary.append((socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', rights).tobytes()))
        if extra: ancillary.append(extra)
        result = Mock(); result.recvmsg.return_value = canonical(document), ancillary, 0, None
        return result

    def receive(self, control):
        return helper.receive_gate_bind(control, origin(), scope=SCOPE, target=TARGET, paths=PATHS,
            receiver=self.receiver(), profile_digest='3' * 64,
            exchange_id='1' * 32, controller='2' * 32)

    def test_wrong_scope_closes_all_received_descriptors(self):
        document = bound_document(); document['scope']['run_id'] = 'other-run'
        control = self.control(document)
        with patch.object(helper, 'alive', return_value=True), \
                patch.object(helper, '_identity', return_value=(3, 4)), \
                patch.object(helper.os, 'get_inheritable', return_value=False), \
                patch.object(helper.os, 'close') as close, self.assertRaises(ArtifactError):
            self.receive(control)
        self.assertEqual(sorted(call.args[0] for call in close.call_args_list), [50, 51, 52])

    def test_mapping_or_receiver_context_substitution_closes_all_descriptors(self):
        for key, value in (('mapping_digest', '9' * 64), ('receiver_context', 'other-hub')):
            document = bound_document(); document[key] = value
            with patch.object(helper, 'alive', return_value=True), \
                    patch.object(helper, '_identity', return_value=(3, 4)), \
                    patch.object(helper.os, 'get_inheritable', return_value=False), \
                    patch.object(helper.os, 'close') as close, self.assertRaises(ArtifactError):
                self.receive(self.control(document))
            self.assertEqual(sorted(call.args[0] for call in close.call_args_list), [50, 51, 52])

    def test_wrong_fd_count_rejects_and_closes_all_not_adopted(self):
        control = self.control(bound_document(), rights=(51, 52, 53))
        with patch.object(helper, 'alive', return_value=True), \
                patch.object(helper.os, 'get_inheritable', return_value=False), \
                patch.object(helper.os, 'close') as close, self.assertRaises(ArtifactError):
            self.receive(control)
        self.assertEqual(sorted(call.args[0] for call in close.call_args_list), [50, 51, 52, 53])

    def test_unknown_ancillary_rejected(self):
        control = self.control(bound_document(), extra=(999, 999, b'x'))
        with patch.object(helper, 'alive', return_value=True), \
                patch.object(helper.os, 'close') as close, self.assertRaises(ArtifactError):
            self.receive(control)
        self.assertEqual(close.call_count, 3)

    def test_authenticated_start_error_never_becomes_offer(self):
        document = {'version': 1, 'kind': 'GATE_REPLY', 'exchange_id': '1' * 32,
                    'controller': '2' * 32, 'error': 'GATE_BOUNDARY_NOT_ADMITTED'}
        control = self.control(document, rights=())
        with patch.object(helper, 'alive', return_value=True), \
                patch.object(helper.os, 'get_inheritable', return_value=False), \
                patch.object(helper.os, 'close') as close:
            with self.assertRaisesRegex(ArtifactError, 'GATE_BOUNDARY_NOT_ADMITTED'):
                self.receive(control)
        close.assert_called_once_with(50)

    def test_wrong_namespace_mapping_fails_before_receive(self):
        control = Mock()
        for uid in (165532, 165530, 65532):
            bad = ReceiverIdentity(uid, uid, 'hub', '4' * 64)
            with self.assertRaises(ArtifactError):
                helper.receive_gate_bind(control, origin(), scope=SCOPE, target=TARGET, paths=PATHS,
                    receiver=bad, profile_digest='3' * 64, exchange_id='1' * 32, controller='2' * 32)
        control.recvmsg.assert_not_called()

    def test_transferred_process_identity_not_claimed_pid_and_channel_checked(self):
        import socket
        channel = Mock(); channel.family = socket.AF_UNIX
        channel.getsockopt.side_effect = [socket.SOCK_SEQPACKET, 0]
        document = bound_document(); control = self.control(document)
        def held_init(self, record, *, receiver=None):
            self.pidfd, record.pidfd = record.pidfd, -1
            self.identity, self.credentials = (3, 4), (0, 65530, 65530)
            self._receiver, self.revoked = receiver, False
        with patch.object(helper, 'alive', return_value=True), \
                patch.object(helper, '_identity', return_value=(3, 4)), \
                patch.object(helper.os, 'get_inheritable', return_value=False), \
                patch.object(helper.os, 'close') as close, \
                patch.object(helper.socket, 'socket', return_value=channel), \
                patch.object(helper, 'enable'), patch.object(HeldOrigin, '__init__', held_init):
            offer = self.receive(control)
        self.assertIs(type(offer), helper.GateOffer)
        self.assertEqual(offer.origin.pidfd, 52)
        self.assertEqual(offer.origin.receiver.mapping_digest, '4' * 64)
        channel.getpeername.assert_called_once(); close.assert_called_once_with(50)

    def test_client_start_has_no_paths_in_control_and_never_retries(self):
        control = Mock(); control.send.side_effect = lambda raw: len(raw)
        client = helper.GateControlClient(control, supervisor=origin(), receiver=self.receiver(),
            profile_digest='3' * 64, controller='2' * 32, control_lock=threading.Lock())
        with patch.object(helper, 'alive', return_value=True), \
                patch.object(helper, 'receive_gate_bind', side_effect=ArtifactError('UNKNOWN')):
            with self.assertRaises(ArtifactError): client.start(SCOPE, TARGET, PATHS)
            with self.assertRaises(ArtifactError): client.start(SCOPE, TARGET, PATHS)
        self.assertEqual(control.send.call_count, 1)
        request = helper._document(control.send.call_args.args[0])
        self.assertEqual(set(request['payload']), {'scope', 'target'})
        self.assertNotIn('paths', request['payload'])

    def test_control_reply_requires_live_sender_and_exact_exchange(self):
        client = helper.GateControlClient(Mock(), supervisor=origin(), receiver=self.receiver(),
            profile_digest='3' * 64, controller='2' * 32, control_lock=threading.Lock())
        wrong = {'version': 1, 'kind': 'GATE_REPLY', 'controller': '2' * 32,
                 'exchange_id': '9' * 32, 'result': {'cleanup': True}}
        with patch.object(helper, 'receive', return_value=Record(canonical(wrong), (0, 0, 0), -1)):
            with self.assertRaises(ArtifactError): client._reply('1' * 32)
        client.supervisor.require.assert_called_once()

    def test_dispatch_uses_only_authenticated_hub_and_never_generic_commands(self):
        service = helper.GateSupervisorService(Mock(), Mock(), launch_factory=Mock(), listener=Mock())
        command = {'version': 1, 'kind': 'GATE_CONTROL', 'command': 'execute',
                   'controller': '2' * 32, 'exchange_id': '1' * 32, 'payload': {'argv': ['/bin/sh']}}
        control = Mock(); control.send.side_effect = lambda raw: len(raw)
        held = origin()
        with patch.object(helper, 'alive', return_value=True), \
                patch.object(helper, 'receive', return_value=Record(canonical(command), (0, 0, 0), -1)):
            helper.dispatch_gate_control(control, held, service, controller='2' * 32)
        held.require.assert_called_once()
        reply = helper._document(control.send.call_args.args[0])
        self.assertEqual(reply['error'], 'UNSUPPORTED_GATE_CONTROL')
        service.launch_factory.assert_not_called()

class ArtifactLifecycleRegressionTests(unittest.TestCase):
    def test_invalid_pollfd_is_not_actual_exit(self):
        self.assertFalse(helper._exited_events([(40, helper.select.POLLNVAL)], 40))
        self.assertFalse(helper._exited_events([(40, helper.select.POLLERR | helper.select.POLLIN)], 40))
        self.assertFalse(helper._exited_events([(41, helper.select.POLLIN)], 40))
        self.assertTrue(helper._exited_events([(40, helper.select.POLLIN | helper.select.POLLHUP)], 40))

    def test_confirm_exit_rejects_reused_pidfd(self):
        offer = helper.GateOffer(bound_document(), Mock(), origin(), PATHS); offer.state = 'acked'
        with patch.object(helper, '_identity', return_value=(99, 99)), \
                patch.object(helper.select, 'poll') as poll:
            with self.assertRaises(ArtifactError): offer.confirm_exit()
        poll.assert_not_called()

    def test_immutable_offer_scope_is_not_alias_of_bind_packet(self):
        doc = bound_document(); offer = helper.GateOffer(doc, Mock(), origin(), PATHS)
        doc['scope']['run_id'] = 'changed'; doc['target']['inode'] = 999
        self.assertEqual(offer.scope['run_id'], SCOPE['run_id'])
        self.assertEqual(offer.target['inode'], TARGET['inode'])

class ArtifactMetadataCapacityTests(unittest.TestCase):
    def test_service_lifetime_capacity_is_not_just_inflight(self):
        targets = Mock(); service = helper.GateSupervisorService(Mock(), targets,
            launch_factory=Mock(), listener=Mock())
        service._prepared = {'prior-' + str(i): None for i in range(helper.MAX_EVALUATIONS)}
        with self.assertRaises(ArtifactError):
            service.handle('prepare', {'scope': SCOPE, 'source': {}})
        targets.prepare.assert_not_called()

    def test_journal_capacity_includes_prior_controller_markers(self):
        with tempfile.TemporaryDirectory(prefix='uas-artifact-capacity-pure-') as directory:
            root = Path(directory)
            for i in range(helper.MAX_EVALUATIONS):
                (root / ('old-' + str(i))).write_text('{}')
            with self.assertRaises(ArtifactError): helper._LaunchJournal(root / 'new')
            self.assertFalse((root / 'new').exists())
