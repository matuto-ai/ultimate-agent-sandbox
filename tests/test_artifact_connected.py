"""Real Hub/client/dispatch/service/offer codecs, with wholly mocked kernel I/O.

No socket, listener, Engine exec, static payload or native isolation is exercised.
This connects policy and lifecycle contracts; it is NOT boundary qualification.
"""
import array
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import socket
import struct
import threading
import time
import unittest
from unittest.mock import Mock, patch

from uas import artifact_helper as helper
from uas.artifact_protocol import _HEADER, _ITEM, canonical, scope_digest
from uas.gate_evaluation import ArtifactGateHub
from uas.kernel_origin import HeldOrigin, ReceiverIdentity, Record
import test_gate_evaluation as policy_tests
from test_gate_evaluation import FakeControl, ORIGIN


def held(fd=80, credentials=(22, 165530, 165530)):
    value = object.__new__(HeldOrigin)
    value.pidfd, value.identity, value.credentials = fd, (3, 4), credentials
    value.revoked, value._receiver = False, None
    value.require, value.close = Mock(), Mock()
    return value


class ConnectedHarness:
    def __init__(self, case):
        self.case, self.source = case, deepcopy(FakeControl().source)
        self.helper_alive, self.raw = True, []
        self.paths, self.request_count = [], None
        self.commands = []
        self.target = self.scope = self.launch = None
        self.change_head = False
        self.cleanup_ok = True
        self.malformed = False
        self.exit_code = 0
        self.client_endpoint = Mock()
        self.server_endpoint = Mock()
        self.client_endpoint.send.side_effect = self.control_send
        self.client_endpoint.recvmsg.side_effect = lambda *_: self.binding_packet
        self.server_endpoint.send.side_effect = self.control_reply
        self.server_endpoint.sendmsg.side_effect = self.control_bind
        self.helper_channel = Mock()
        self.helper_channel.family = socket.AF_UNIX
        self.helper_channel.fileno.return_value = 51
        self.helper_channel.getsockopt.side_effect = lambda level, name: socket.SOCK_SEQPACKET if name == socket.SO_TYPE else 0
        self.helper_channel.send.side_effect = self.helper_send
        self.helper_channel.recv.return_value = b''
        self.resolver, self.targets, self.lease = Mock(), Mock(), Mock()
        self.resolver.resolve.side_effect = lambda **_: deepcopy(self.source)
        self.resolver.current.side_effect = lambda _: deepcopy(self.source)
        self.targets.prepare.side_effect = self.prepare
        self.targets.lease.return_value = self.lease
        self.targets.reconcile.return_value = {'cleanup': True, 'quarantine_ref': None}
        self.lease.recheck.return_value = self.lease.recheck_binding.return_value = True
        self.lease.postverify.side_effect = lambda: deepcopy(self.target)
        self.lease.cleanup.side_effect = self.cleanup
        self.engine = Mock()
        self.engine.inspect.side_effect = lambda _: {'ID': '9' * 64, 'ContainerID': '1' * 64,
            'Running': self.helper_alive, 'Pid': 22, 'ExitCode': self.exit_code}
        self.service = helper.GateSupervisorService(self.resolver, self.targets,
            launch_factory=self.launch_factory, listener=Mock())
        self.hub_origin, self.supervisor = held(80), held(81)
        self.client = helper.GateControlClient(self.client_endpoint, supervisor=self.supervisor,
            receiver=ReceiverIdentity(65530, 65530, 'hub', '4' * 64),
            profile_digest='3' * 64, controller='2' * 32, control_lock=threading.Lock())

    def prepare(self, scope, source):
        self.scope = deepcopy(scope)
        self.target = {'target_id': scope['evaluation_id'][-32:], 'head_sha': source['head_sha'],
            'tree_sha': 'c' * 40, 'manifest_sha256': 'f' * 64, 'source_digest': source['source_digest'],
            'device': 1, 'inode': 100, 'entries': 1, 'expanded_bytes': 10}
        self.lease.document.return_value = deepcopy(self.target)
        return deepcopy(self.target)

    def cleanup(self):
        if self.change_head:
            self.source['head_sha'] = '2' * 40
        return self.cleanup_ok

    def launch_factory(self, scope, target, lease):
        endpoint = object.__new__(helper.GateEndpointLease)
        endpoint.require = Mock(return_value=True)
        workstation = helper.GateWorkstation('alpha', 'room-instance', '1' * 64, '2' * 64,
                                             '3' * 64, '5' * 64, '6' * 64, '4' * 64, 'hub')
        launch = helper.GateHelperLaunch(self.engine, workstation, endpoint,
            self.case.path.parent / 'unused-mocked-launch-journal', admission=Mock(),
            target_lease=lease, scope=scope)
        # Only startup kernel/Engine effects and journal I/O are mocked. Real
        # transfer, finish, exit proof reduction and cleanup sequencing remain.
        def start(_):
            launch.origin = held(42)
            launch.channel = Mock(); launch.channel.fileno.return_value = 51
            launch.state, launch.exec_id = 'bound', '9' * 64
            launch.deadline = time.monotonic() + 15
            launch.journal = Mock()
            return launch
        launch.start = start
        self.launch = launch
        return launch

    def control_send(self, data):
        self.request = data
        self.commands.append(helper._document(data)['command'])
        helper.dispatch_gate_control(self.server_endpoint, self.hub_origin, self.service,
                                     controller='2' * 32)
        return len(data)

    def control_reply(self, data):
        self.reply = data
        return len(data)

    def control_bind(self, packets, ancillary):
        data = b''.join(packets)
        self.binding_packet = (data, [
            (socket.SOL_SOCKET, socket.SCM_CREDENTIALS, struct.pack('3i', 11, 165533, 165533)),
            (socket.SOL_SOCKET, helper.SCM_PIDFD, array.array('i', [50]).tobytes()),
            *[(level, kind, bytes(raw)) for level, kind, raw in ancillary]], 0, None)
        return len(data)

    def helper_send(self, packet):
        if packet[:4] == b'AGQ1':
            self.request_count = _HEADER.unpack(packet)[-1]
        elif packet[:4] == b'AGP1':
            _, index, length = struct.unpack('!4sII', packet[:12])
            self.case.assertEqual(index, len(self.paths))
            self.case.assertEqual(length, len(packet[12:]))
            self.paths.append(packet[12:])
            if len(self.paths) == self.request_count:
                digest = bytes.fromhex(scope_digest(self.scope, self.target))
                def head(kind):
                    return _HEADER.pack(kind, digest, bytes.fromhex(self.target['target_id']),
                        bytes.fromhex(self.target['manifest_sha256']), 1, 100, len(self.paths))
                self.raw = [head(b'AGS1')] + [_ITEM.pack(b'AGI1', i,
                    hashlib.sha256(path).digest(), 1, 10, 0, 0) for i, path in enumerate(self.paths)] + [head(b'AGF1')]
                if self.malformed:
                    self.raw[1] = b'not-an-item'
        elif packet[:4] == b'AGA1':
            self.helper_alive = False
        else:
            raise AssertionError('unexpected helper request packet')
        return len(packet)

    def receive(self, channel):
        if channel is self.server_endpoint:
            return Record(self.request, (11, 165531, 165531), -1)
        if channel is self.client_endpoint:
            return Record(self.reply, (11, 165533, 165533), -1)
        if channel is self.helper_channel:
            return Record(self.raw.pop(0), (22, 165530, 165530), -1)
        raise AssertionError('unrecognized private channel')

    def poll(self):
        watched = []
        result = Mock()
        result.register.side_effect = lambda fd, *_: watched.append(fd)
        result.poll.side_effect = lambda *_: [(watched[0], helper.select.POLLIN)] if watched[0] == 42 and not self.helper_alive else []
        return result

    def patches(self):
        stack = ExitStack()
        def initialize(value, record, *, receiver=None):
            value.pidfd, record.pidfd = record.pidfd, -1
            value.identity, value.credentials = (3, 4), (22, 165530, 165530)
            value._receiver, value.revoked = receiver, False
            value.require, value.close = Mock(), Mock()
        for target, name, replacement in (
                (helper, 'receive', self.receive), (helper, 'enable', lambda _: None),
                (helper, 'alive', lambda fd: self.helper_alive if fd == 42 else True),
                (helper, '_identity', lambda _: (3, 4)),
                (helper.os, 'get_inheritable', lambda _: False), (helper.os, 'close', lambda _: None),
                (helper.socket, 'socket', lambda **_: self.helper_channel),
                (helper.select, 'poll', self.poll), (HeldOrigin, '__init__', initialize)):
            stack.enter_context(patch.object(target, name, replacement))
        return stack


class ArtifactConnectedTests(unittest.TestCase):
    setUp = policy_tests.GateEvaluationTests.setUp
    seed = policy_tests.GateEvaluationTests.seed
    construct = policy_tests.GateEvaluationTests.construct

    def run_connected(self, configure=lambda _: None):
        fixture = ConnectedHarness(self)
        configure(fixture)
        hub = ArtifactGateHub(self.ledger, self.binding, fixture.client, authorize=lambda *_: self.allowed)
        with fixture.patches():
            row = hub.evaluate('connected', 'run-one', 1, self.gate, origin=ORIGIN)
            projection = hub.projection('run-one', 1, self.gate, origin=ORIGIN)
            calls = list(fixture.commands)
            retry = hub.evaluate('connected', 'run-one', 1, self.gate, origin=ORIGIN)
            self.assertEqual(calls, fixture.commands)
            self.assertEqual(row, retry)
        return fixture, row, projection

    def test_real_control_dispatch_offer_and_hub_complete_one_attempt(self):
        fixture, row, projection = self.run_connected()
        self.assertEqual('passed', row['result']['verdict'])
        self.assertEqual('passed', projection['state'])
        self.assertEqual(['resolve', 'prepare', 'current', 'start', 'finish', 'current', 'current'], fixture.commands)
        fixture.lease.postverify.assert_called_once()
        fixture.lease.recheck_binding.assert_called_once()
        fixture.lease.cleanup.assert_called_once()
        fixture.engine.create.assert_not_called()  # Startup is explicitly mocked.
        self.assertEqual([b'README.md'], fixture.paths)
        self.assertGreater(fixture.hub_origin.require.call_count, 0)
        self.assertGreater(fixture.supervisor.require.call_count, 0)

    def test_real_cleanup_failure_is_error_quarantine_and_no_implicit_second_cleanup(self):
        fixture, row, projection = self.run_connected(lambda f: setattr(f, 'cleanup_ok', False))
        self.assertEqual('error', row['result']['verdict'])
        self.assertFalse(row['operational']['cleanup'])
        self.assertEqual('error', projection['state'])
        fixture.lease.cleanup.assert_called_once()
        self.assertNotIn('abort', fixture.commands)

    def test_real_successful_exit_path_still_rejects_nonzero_engine_status(self):
        fixture, row, _ = self.run_connected(lambda f: setattr(f, 'exit_code', 7))
        self.assertEqual('error', row['result']['verdict'])
        fixture.lease.postverify.assert_not_called()
        fixture.lease.cleanup.assert_not_called()

    def test_head_change_at_cleanup_preserves_history_and_stales_projection(self):
        fixture, row, projection = self.run_connected(lambda f: setattr(f, 'change_head', True))
        self.assertEqual('passed', row['result']['verdict'])
        self.assertEqual('stale', projection['state'])
        self.assertEqual('a' * 40, row['result']['source']['head_sha'])
        self.assertEqual(['head_sha'], projection['changed_dependencies'])

    def test_malformed_binary_fact_never_acks_and_unknown_task_remains_reserved(self):
        fixture, row, _ = self.run_connected(lambda f: setattr(f, 'malformed', True))
        self.assertEqual('error', row['result']['verdict'])
        self.assertTrue(fixture.helper_alive)
        self.assertFalse(row['operational']['cleanup'])
        self.assertNotIn('finish', fixture.commands)
        fixture.lease.cleanup.assert_not_called()


if __name__ == '__main__':
    unittest.main()
