"""Pure external Git Broker composition and endpoint protocol tests."""
from dataclasses import asdict
import hashlib
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

from uas.forge import ForgeBinding
from uas.forge_audit import ForgeAudit
from uas.git_audit import GitAudit
from uas.git_policy import GitTarget
from uas.git_service import ExternalGitBroker, origin_from_document, validate_reply
from uas.git_stream import GitStreamReceipt
from uas.git_transport import SshTransport, GitTransportError
from uas.kernel_origin import OriginDenied
from uas.ledger import LedgerError, Origin


class GitServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.forge = ForgeAudit(Path(self.tmp.name) / 'audit.db', 'deployment')
        self.addCleanup(self.forge.close)
        self.audit = GitAudit(self.forge)
        self.binding = ForgeBinding('room', 'project', 'org/repo', 'github.com')
        self.transport = object.__new__(SshTransport)
        self.transport.binding, self.transport.failed = self.binding, False
        self.transport.open, self.transport.close = Mock(return_value=Mock()), Mock()
        self.broker = ExternalGitBroker(self.binding, 'instance', self.audit, self.transport)
        self.origin = Origin('alice', 'seat-a', 'inc-a', 'epoch1', ('git-read', 'git-push'))
        self.channel = Mock(); self.channel.gettimeout.return_value = 35
        self.channel.send.side_effect = len
        self.supervisor = SimpleNamespace(require=Mock(), revoked=False, pidfd=5)
        for target in ('os.fork', 'os.pidfd_open', 'socket.socket', 'socket.socketpair', 'subprocess.Popen'):
            patch(target, side_effect=AssertionError('native effect forbidden')).start()
        self.addCleanup(patch.stopall)

    def request(self, service='git-upload-pack', repo='org/repo'):
        return {'kind': 'GIT_OPEN', 'id': 'op', 'binding': self.broker.scope(),
                'origin': self.origin.canonical(), 'argv': ['git@github.com', f"{service} '{repo}.git'"]}

    def receipt(self):
        return GitStreamReceipt(0, 0, 0, hashlib.sha256(b'').hexdigest(), hashlib.sha256(b'').hexdigest(), 0, 'SUCCEEDED')

    def test_good_stream_audits_and_restores_channel_mode(self):
        with patch('uas.git_stream.proxy_ssh', return_value=self.receipt()):
            self.broker.run(self.channel, self.supervisor, self.request())
        self.channel.settimeout.assert_called_with(35)
        self.assertIn(b'"status":"OK"', self.channel.send.call_args.args[0])
        self.assertEqual(self.forge._db.execute('SELECT count(*) FROM git_terminals').fetchone()[0], 1)

    def test_exact_retry_never_recontacts(self):
        with patch('uas.git_stream.proxy_ssh', return_value=self.receipt()):
            self.broker.run(self.channel, self.supervisor, self.request())
            self.broker.run(self.channel, self.supervisor, self.request())
        self.transport.open.assert_called_once()
        self.assertIn(b'GIT_STREAM_ALREADY_CONSUMED', self.channel.send.call_args.args[0])

    def test_no_credential_is_terminal_no_contact(self):
        self.transport.open.side_effect = GitTransportError('SSH_CREDENTIAL_UNAVAILABLE')
        self.broker.run(self.channel, self.supervisor, self.request('git-receive-pack'))
        self.assertIn(b'"contact":"none"', self.channel.send.call_args.args[0])

    def test_uncertain_launch_push_never_claims_no_contact(self):
        self.transport.open.side_effect = GitTransportError('SSH_LAUNCH_UNKNOWN')
        self.broker.run(self.channel, self.supervisor, self.request('git-receive-pack'))
        self.assertIn(b'UNKNOWN_OUTCOME', self.channel.send.call_args.args[0])
        self.assertIn(b'write-possible', self.channel.send.call_args.args[0])

    def test_cross_project_push_denied_before_start(self):
        with self.assertRaises(Exception):
            self.broker.run(self.channel, self.supervisor, self.request('git-receive-pack', 'other/repo'))
        self.transport.open.assert_not_called()
        self.assertEqual(self.forge._db.execute('SELECT count(*) FROM git_starts').fetchone()[0], 0)

    def test_bad_capability_structure_is_typed_denial(self):
        for value in ([{}], [3], ['git-read', 'git-read']):
            with self.subTest(value=value), self.assertRaises(LedgerError):
                origin_from_document({**self.origin.canonical(), 'capabilities': value})

    def test_terminal_advertisements_are_closed_and_scoped(self):
        target = GitTarget('github.com', 'org/repo', 'git-upload-pack')
        good = {'kind': 'exit', 'code': 0, 'status': 'OK', 'repository': 'org/repo', 'advertised': ['a' * 40]}
        self.assertEqual(validate_reply(good, target, streaming=True), good)
        for changes in ({'repository': 'evil/repo'}, {'status': 'FAILED'}, {'code': False},
                        {'advertised': [{}]}, {'advertised': ['A' * 40]}, {'advertised': ['a' * 40] * 2}):
            with self.subTest(changes=changes), self.assertRaises(OriginDenied):
                validate_reply({**good, **changes}, target, streaming=True)
        with self.assertRaises(OriginDenied):
            validate_reply(good, GitTarget('github.com', 'org/repo', 'git-receive-pack'), streaming=True)

    def test_unknown_server_frame_never_forwarded(self):
        with self.assertRaises(OriginDenied):
            validate_reply({'kind': 'shell', 'argv': ['sh']}, GitTarget('github.com', 'org/repo', 'git-upload-pack'), streaming=True)
