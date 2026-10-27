"""Compiled bootstrap + real kernel objects; Engine adapter is a test double.

No test here claims Docker, SELinux or actual Pi qualification.
"""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import unittest

from uas.kernel_origin import OriginDenied, OriginUnavailable, probe, receive
from uas.workstation_exec import EndpointLease, ExecLaunch, ExecSeat, ExecUnavailable

ROOT = Path(__file__).resolve().parents[1]
CONTAINER, EXEC = 'a' * 64, 'b' * 64


class ChildStream:
    def __init__(self, process):
        self.process = process
    def write(self, data, *, timeout):
        self.process.stdin.write(data); self.process.stdin.flush()
    def close(self):
        self.process.stdin.close()


class EngineDouble:
    def __init__(self, connector):
        self.connector = connector
        self.calls = []
        self.process = None
        self.failure = None
        self.wrong = None
    def create(self, container, document):
        self.calls.append(('create', container, document))
        if self.failure == 'create':
            raise OSError('lost create response')
        return EXEC
    def start(self, exec_id):
        self.calls.append(('start', exec_id))
        if self.failure == 'start':
            raise OSError('lost start response')
        self.process = subprocess.Popen([str(self.connector), 'seat-a'], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return ChildStream(self.process)
    def inspect(self, exec_id):
        self.calls.append(('inspect', exec_id))
        if self.failure == 'inspect':
            raise OSError('inspect unavailable')
        value = {'ID': EXEC, 'ContainerID': CONTAINER, 'Pid': self.process.pid, 'Running': True}
        if self.wrong:
            key, field = self.wrong
            value[key] = field
        return value
    def close(self):
        if self.process:
            if self.process.poll() is None:
                self.process.terminate()
            self.process.wait(timeout=2)
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                stream.close()


@unittest.skipUnless(os.environ.get("UAS_WORKSTATION_CONNECTOR_TEST") == "1",
                     "set UAS_WORKSTATION_CONNECTOR_TEST=1 for local filesystem-socket bootstrap integration")
class WorkstationExecTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('cc'):
            raise unittest.SkipTest('C compiler unavailable')
        try:
            probe()
        except OriginUnavailable as error:
            raise unittest.SkipTest(str(error))
        cls.build = tempfile.TemporaryDirectory(prefix='uas-bootstrap-')
        cls.root = Path(cls.build.name)
        cls.endpoint = cls.root / 'endpoint' / 'peer.sock'
        cls.connector = cls.root / 'connector'
        (cls.root / 'node/bin').mkdir(parents=True)
        # Fake target proves exec identity only. It is NOT native Pi evidence.
        source = cls.root / 'native-test.c'
        source.write_text('#include <unistd.h>\n#include <sys/socket.h>\n'
                          'int main(void) { if(send(3,"native-test",11,0)!=11)return 1; '
                          'char c; while(read(0,&c,1)>0){} return 0; }\n')
        subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', str(source), '-o',
                        str(cls.root / 'node/bin/node')], check=True, capture_output=True)
        subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-O2',
                        '-DUAS_ROOT="' + str(cls.root) + '"',
                        '-DUAS_ENDPOINT="' + str(cls.endpoint) + '"',
                        '-DUAS_WORKSPACE="' + str(cls.root) + '"',
                        str(ROOT / 'runtime/workstation/pi_connector.c'), '-o', str(cls.connector)],
                       check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def setUp(self):
        self.endpoint.parent.mkdir(mode=0o710)
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.listener.bind(str(self.endpoint)); self.listener.listen(4)
        self.endpoint.chmod(0o620)
        self.control = tempfile.TemporaryDirectory(prefix='uas-exec-control-')
        self.engine = EngineDouble(self.connector)
        self.lease = EndpointLease(self.endpoint, owner=os.getuid(), group=os.getgid())
        self.seat = ExecSeat('alpha', 'instance', 'alice', 'actor-a', 'seat-a', CONTAINER,
                             os.getuid(), os.getgid())
        self.launch = ExecLaunch(self.engine, self.seat, self.lease,
                                 Path(self.control.name) / 'attempt.json', timeout=2)

    def tearDown(self):
        self.launch.close()
        self.engine.close()
        self.listener.close()
        self.endpoint.unlink(missing_ok=True)
        self.endpoint.parent.rmdir()
        self.control.cleanup()

    def test_fixed_bootstrap_same_task_through_exec_and_actor_scope(self):
        self.launch.launch(self.listener)
        self.assertEqual(self.launch.state, 'released')
        self.assertEqual(self.launch.origin.credentials[0], self.engine.process.pid)
        with receive(self.launch.channel) as record:
            self.assertEqual(record.data, b'native-test')
            self.launch.origin.require(record)
            with self.assertRaises(OriginDenied):
                self.launch.require_record(record, room_id='alpha', participant_id='alice')
            self.launch.activate(lambda _: True)  # synthetic native gate, explicit
            self.launch.require_record(record, room_id='alpha', participant_id='alice')
            for room, participant in (('beta', 'alice'), ('alpha', 'bob')):
                with self.assertRaises(OriginDenied):
                    self.launch.require_record(record, room_id=room, participant_id=participant)
            self.launch.revoke()
            with self.assertRaises(OriginDenied):
                self.launch.require_record(record, room_id='alpha', participant_id='alice')
        self.assertIsNone(self.launch.challenge)
        saved = json.loads(self.launch.journal.read_text())
        self.assertNotIn('pid', saved)
        self.assertNotIn('challenge', saved)

    def test_uncertain_engine_operations_never_blindly_retry(self):
        for stage in ('create', 'start', 'inspect'):
            with self.subTest(stage=stage):
                self.engine.failure = stage
                attempt = ExecLaunch(self.engine, self.seat, self.lease,
                                     Path(self.control.name) / (stage + '.json'), timeout=2)
                try:
                    with self.assertRaises(OSError):
                        attempt.launch(self.listener)
                    self.assertEqual(attempt.state, 'uncertain')
                    count = len(self.engine.calls)
                    with self.assertRaises(ExecUnavailable):
                        attempt.launch(self.listener)
                    self.assertEqual(len(self.engine.calls), count)
                finally:
                    attempt.close(); self.engine.close()

    def test_wrong_exec_container_or_pid_does_not_activate(self):
        for key, value in (('ID', 'c'*64), ('ContainerID', 'c'*64), ('Pid', os.getpid()), ('Running', False)):
            with self.subTest(key=key):
                self.engine.wrong = key, value
                attempt = ExecLaunch(self.engine, self.seat, self.lease,
                                     Path(self.control.name) / (key + '.json'), timeout=2)
                try:
                    with self.assertRaises(ExecUnavailable):
                        attempt.launch(self.listener)
                    self.assertTrue(attempt.origin.revoked)
                finally:
                    attempt.close(); self.engine.close()

    def test_existing_attempt_blocks_restart_without_overwrite(self):
        self.launch.journal.write_text('{"incarnation":"other","state":"starting"}')
        before = self.launch.journal.read_bytes()
        with self.assertRaises(FileExistsError):
            self.launch.launch(self.listener)
        self.launch.close()
        self.assertEqual(self.engine.calls, [])
        self.assertEqual(self.launch.journal.read_bytes(), before)

    def test_endpoint_replacement_fences_active_origin(self):
        self.launch.launch(self.listener)
        with receive(self.launch.channel) as record:
            self.launch.activate(lambda _: True)
            self.endpoint.unlink()
            replacement = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            try:
                replacement.bind(str(self.endpoint)); self.endpoint.chmod(0o620)
                with self.assertRaises(ExecUnavailable):
                    self.launch.require_record(record, room_id='alpha', participant_id='alice')
            finally:
                replacement.close()

    def test_dumpability_disabled_before_challenge_and_no_arbitrary_arguments(self):
        process = subprocess.Popen([str(self.connector), 'seat-a'], stdin=subprocess.PIPE)
        channel, _ = self.listener.accept()
        try:
            # Connector is blocked reading challenge, prior to any native code.
            # A non-dumpable task's fd directory is inaccessible to this peer.
            with self.assertRaises(PermissionError):
                os.readlink('/proc/' + str(process.pid) + '/fd/0')
        finally:
            process.stdin.close(); channel.close(); process.wait(timeout=2)
        for arguments in ([], ['seat-c'], ['seat-a', '/bin/sh']):
            result = subprocess.run([str(self.connector), *arguments], timeout=2)
            self.assertEqual(result.returncode, 125)
