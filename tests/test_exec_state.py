"""Launch decisions with simulated Engine/bootstrap and real socketpair records.

This is not the separately blocked filesystem-socket/bootstrap integration.
"""
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from uas.kernel_origin import OriginDenied, OriginUnavailable, enable, probe, receive
from uas.workstation_exec import ExecLaunch, ExecSeat, ExecUnavailable


class Endpoint:
    replaced = False
    def require(self):
        if self.replaced:
            raise ExecUnavailable('endpoint replaced')


class Listener:
    def __init__(self, channel):
        self.channel = channel
    def settimeout(self, value):
        pass
    def accept(self):
        return self.channel, None


class Stream:
    def __init__(self, channel, corrupt):
        self.channel, self.corrupt = channel, corrupt
    def write(self, data, *, timeout):
        self.channel.send(b'UAS1' + (b'x' * 32 if self.corrupt else data))
    def close(self):
        pass


class Engine:
    def __init__(self, channel):
        self.channel, self.calls = channel, []
        self.failure = self.wrong = None
        self.corrupt = False
    def create(self, container, document):
        self.calls.append(('create', container, document))
        if self.failure == 'create':
            raise OSError('uncertain create')
        return 'b' * 64
    def start(self, exec_id):
        self.calls.append(('start', exec_id))
        if self.failure == 'start':
            raise OSError('uncertain start')
        return Stream(self.channel, self.corrupt)
    def inspect(self, exec_id):
        self.calls.append(('inspect', exec_id))
        if self.failure == 'inspect':
            raise OSError('uncertain inspect')
        result = {'ID': 'b'*64, 'ContainerID': 'a'*64, 'Pid': os.getpid(), 'Running': True}
        if self.wrong:
            result[self.wrong[0]] = self.wrong[1]
        return result


class ExecStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            probe()
        except OriginUnavailable as error:
            raise unittest.SkipTest(str(error))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.left, self.right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        enable(self.left)
        self.addCleanup(self.left.close); self.addCleanup(self.right.close)
        self.engine, self.endpoint = Engine(self.right), Endpoint()
        self.seat = ExecSeat('alpha', 'instance', 'alice', 'actor-a', 'seat-a', 'a'*64, os.getuid(), os.getgid())
        self.attempt = ExecLaunch(self.engine, self.seat, self.endpoint, Path(self.temp.name)/'attempt', timeout=2)
        self.addCleanup(self.attempt.close)
        self.listener = Listener(self.left)

    def launch(self):
        # Only the listener wrapper is simulated. The received record/pidfd is
        # genuine and tested independently; no filesystem endpoint is created.
        with patch('uas.workstation_exec.enable'):
            self.attempt.launch(self.listener)

    def test_fixed_create_recipe_and_scope(self):
        self.launch()
        self.assertEqual(self.right.recv(64), b'UAS-RELEASE-1\n')
        self.assertEqual(self.engine.calls[0][2]['Cmd'], ['/opt/uas/bin/pi-connector', 'seat-a'])
        self.assertEqual(self.engine.calls[0][2]['User'], '65532:65532')
        self.attempt.activate(lambda _: True)
        self.right.send(b'peer')
        with receive(self.left) as record:
            self.attempt.require_record(record, room_id='alpha', participant_id='alice')
            with self.assertRaises(OriginDenied):
                self.attempt.require_record(record, room_id='beta', participant_id='alice')
            self.endpoint.replaced = True
            with self.assertRaises(ExecUnavailable):
                self.attempt.require_record(record, room_id='alpha', participant_id='alice')
            self.assertTrue(self.attempt.origin.revoked)

    def test_create_start_inspect_uncertainty_and_no_retry(self):
        for stage in ('create', 'start', 'inspect'):
            with self.subTest(stage=stage):
                self.engine.failure = stage
                attempt = ExecLaunch(self.engine, self.seat, self.endpoint, Path(self.temp.name)/stage)
                try:
                    with patch('uas.workstation_exec.enable'), self.assertRaises(OSError):
                        attempt.launch(self.listener)
                    count = len(self.engine.calls)
                    self.assertEqual(attempt.state, 'uncertain')
                    with self.assertRaises(ExecUnavailable):
                        attempt.launch(self.listener)
                    self.assertEqual(count, len(self.engine.calls))
                finally:
                    attempt.close()

    def test_replayed_or_unmatched_challenge_cannot_bind(self):
        self.engine.corrupt = True
        with self.assertRaises(OriginDenied):
            self.launch()
        self.assertIsNone(self.attempt.origin)
        self.assertIsNone(self.attempt.challenge)
        self.assertEqual(self.attempt.state, 'uncertain')

    def test_expired_attempt_never_releases(self):
        original = self.engine.inspect
        def inspect(exec_id):
            value = original(exec_id)
            self.attempt.deadline = 0
            return value
        self.engine.inspect = inspect
        with self.assertRaises(ExecUnavailable):
            self.launch()
        self.assertTrue(self.attempt.origin.revoked)
        self.assertEqual(self.attempt.state, 'uncertain')

    def test_stale_inspect_wrong_pid_container_exec_or_state(self):
        # A fresh pair is needed after each denied attempt closes its transport.
        for wrong in [('Pid', os.getpid()+1), ('ContainerID', 'c'*64), ('ID', 'c'*64), ('Running', False)]:
            with self.subTest(wrong=wrong):
                left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                enable(left)
                engine = Engine(right); engine.wrong = wrong
                attempt = ExecLaunch(engine, self.seat, self.endpoint, Path(self.temp.name)/wrong[0])
                try:
                    with patch('uas.workstation_exec.enable'), self.assertRaises(ExecUnavailable):
                        attempt.launch(Listener(left))
                    self.assertTrue(attempt.origin.revoked)
                finally:
                    attempt.close(); left.close(); right.close()

    def test_restart_marker_is_never_overwritten_or_adopted(self):
        self.attempt.journal.write_text('{"incarnation":"other","state":"starting"}')
        original = self.attempt.journal.read_bytes()
        with self.assertRaises(FileExistsError):
            self.launch()
        self.attempt.close()
        self.assertEqual(self.attempt.journal.read_bytes(), original)
        self.assertEqual(self.engine.calls, [])

    def test_native_failure_and_audit_failure_cannot_activate(self):
        self.launch()
        with self.assertRaises(ExecUnavailable):
            self.attempt.activate(lambda _: False)
        self.assertEqual(self.attempt.state, 'released')
        with patch.object(self.attempt, '_save', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                self.attempt.activate(lambda _: True)
        self.assertTrue(self.attempt.origin.revoked)
        self.assertEqual(self.attempt.state, 'uncertain')

    def test_revoke_precedes_disposal(self):
        self.launch()
        stream = self.attempt.transport
        def close():
            self.assertTrue(self.attempt.origin.revoked)
            self.assertEqual(json.loads(self.attempt.journal.read_text())['state'], 'revoked')
        stream.close = close
        self.attempt.close()
