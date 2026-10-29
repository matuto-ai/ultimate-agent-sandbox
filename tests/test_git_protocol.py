"""Shared control codec parity and launcher-only dependency closure, no effects."""
import importlib
import json
import sys
import unittest
from unittest.mock import Mock, patch

from uas import git_protocol as protocol
from uas import git_service as service
from uas import git_worker_native as worker
from uas import ledger, typed_json
from uas.kernel_origin import OriginDenied


class GitProtocolTests(unittest.TestCase):
    def test_existing_consumers_reexport_same_functions_and_error_classes(self):
        self.assertIs(service.decode, protocol.decode)
        self.assertIs(service.send, protocol.send)
        self.assertIs(worker.receive_blob, protocol.receive_blob)
        self.assertIs(worker.GitWorkerError, protocol.GitWorkerError)
        self.assertIs(ledger.LedgerError, typed_json.LedgerError)
        self.assertIs(ledger._json, typed_json._json)
        self.assertEqual(ledger.MAX_JSON_BYTES, typed_json.MAX_JSON_BYTES)
        self.assertEqual(ledger.MAX_SEQUENCE, typed_json.MAX_SEQUENCE)

    def test_canonical_send_shared_unicode_order_types_and_exact_limit(self):
        channel = Mock(); channel.send.side_effect = len
        for value in ({'z': [True, 1, 1.0, None], 'a': 'é'}, {'x': 'x' * 65528}):
            for send in (protocol.send, service.send):
                send(channel, value)
                self.assertEqual(ledger._json(value).encode(), channel.send.call_args.args[0])
                self.assertEqual(value, protocol.decode(channel.send.call_args.args[0]))
        for send in (protocol.send, service.send):
            with self.assertRaises(OriginDenied): send(channel, {'x': 'x' * 65529})
            channel.send.return_value = 0; channel.send.side_effect = None
            with self.assertRaises(OriginDenied): send(channel, {'ok': True})
            channel.send.side_effect = len

    def test_typed_encoder_limits_and_failure_identity(self):
        deeply = None
        for _ in range(34): deeply = [deeply]
        invalid = [float('nan'), float('inf'), 2**63, -(2**63), {1: 'x'}, (), object(),
                   [None] * 4097, {str(i): None for i in range(4097)},
                   '\ud800', deeply, 'x' * (typed_json.MAX_JSON_BYTES + 1)]
        for value in invalid:
            for send in (protocol.send, service.send):
                with self.subTest(value_type=type(value).__name__), self.assertRaises(ledger.LedgerError) as caught:
                    send(Mock(), value)
                self.assertEqual('INVALID_JSON', caught.exception.code)

    def test_decode_rejects_size_shape_duplicate_unicode_and_truncation(self):
        invalid = [None, '', bytearray(b'{}'), b'', b'x' * 65537, b'[]', b'null', b'1',
                   b'{', b'{"x":', b'{"x":1,"x":2}', b'{"x":{"a":1,"a":2}}', b'\xff',
                   b'[' * 2000 + b']' * 2000]
        for raw in invalid:
            for decode in (protocol.decode, service.decode):
                with self.subTest(raw_type=type(raw).__name__), self.assertRaises(OriginDenied): decode(raw)
        # Preserve existing decode semantics, not a new protocol tightening.
        self.assertTrue(protocol.decode(b'{"x":NaN}')['x'] != protocol.decode(b'{"x":NaN}')['x'])

    def test_blob_both_receivers_preserve_truncation_and_callback_auth_failures(self):
        channel = Mock(); channel.send.side_effect = len
        worker.send_blob(channel, 'stdout', b'hello')
        frames = [protocol.decode(call.args[0]) for call in channel.send.call_args_list]
        for receive in (worker.receive_blob, protocol.receive_blob):
            self.assertEqual(b'hello', receive('stdout', iter(frames).__next__))
            for truncated in ([], frames[:1]):
                with self.assertRaises(StopIteration): receive('stdout', iter(truncated).__next__)
            denied = OriginDenied('unauthenticated record')
            with self.assertRaises(OriginDenied) as caught: receive('stdout', Mock(side_effect=denied))
            self.assertIs(denied, caught.exception)

    def test_launcher_import_and_parse_have_no_server_or_database_dependency(self):
        forbidden = {'uas.git_service', 'uas.git_worker_native', 'uas.git_runtime',
                     'uas.git_transaction', 'uas.git_provenance', 'uas.git_audit',
                     'uas.git_transport', 'uas.forge', 'uas.ledger', 'uas.lifecycle', 'sqlite3', '_sqlite3'}
        class Reject:
            def find_spec(self, fullname, path=None, target=None):
                if fullname in forbidden:
                    raise AssertionError('launcher imported server/storage: ' + fullname)
        with patch.dict(sys.modules):
            for name in list(sys.modules):
                if name == 'uas' or name.startswith('uas.') or name in forbidden:
                    del sys.modules[name]
            guard = Reject(); sys.meta_path.insert(0, guard)
            try:
                launcher = importlib.import_module('uas.git_launcher')
                launcher.parse_git('git', ['status'])
                self.assertFalse(forbidden.intersection(sys.modules))
                self.assertIn('uas.git_protocol', sys.modules)
                self.assertIn('uas.typed_json', sys.modules)
            finally:
                sys.meta_path.remove(guard)
