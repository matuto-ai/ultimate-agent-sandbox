"""Pure extraction of the hosted-only tracer; no fixture/native module import."""
import ast
import hashlib
import io
import json
from pathlib import Path
import socket
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]


class ReceiptDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.output = io.StringIO()
        self.record = SimpleNamespace(credentials=(123, 65530, 65532), pidfd=9)
        self.original = {}
        self.receipt = ModuleType('uas.git_transaction')
        self.receipt.ReferenceTransaction = type('Receipt', (), {})
        self.receipt.TransactionSequence = type('Sequence', (), {})
        for owner, name, result in ((self.receipt, 'receive', self.record),
                (self.receipt, '_decode', {'phase': 'prepared', 'nonce': 'SECRET_NONCE'}),
                (self.receipt.ReferenceTransaction, '_record', None),
                (self.receipt.ReferenceTransaction, '_authenticate', None),
                (self.receipt.TransactionSequence, '_classify', ('target',)),
                (self.receipt.TransactionSequence, 'accept', None)):
            method = Mock(return_value=result)
            setattr(owner, name, method)
            self.original[name] = method
        self.raw = (('a' * 40) + ' ' + ('b' * 40) + ' refs/heads/main\n').encode()
        self.receipt.parse_updates = Mock(return_value=(('a' * 40, 'b' * 40, 'refs/heads/main'),))
        fake_os = SimpleNamespace(fstat=Mock(return_value=SimpleNamespace(st_dev=1, st_ino=2)),
                                 getsid=Mock(return_value=120), getpgid=Mock(return_value=120))
        namespace = dict(hashlib=hashlib, json=json, os=fake_os, Path=Path,
                         socket=socket, sys=SimpleNamespace(stderr=self.output))
        tree = ast.parse((ROOT / 'tests/linux/git_smoke.py').read_text())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                        and n.name == 'install_receipt_diagnostics')
        exec(compile(ast.Module(body=[function], type_ignores=[]), '<reviewed-diagnostic>', 'exec'), namespace)
        package = ModuleType('uas')
        package.git_transaction = self.receipt
        with patch.dict('sys.modules', {'uas': package, 'uas.git_transaction': self.receipt}):
            namespace['install_receipt_diagnostics']()
        self.proof = SimpleNamespace(expected_old='a' * 40, expected_ref='refs/heads/main',
            kind='commit', count=0, target_count=0, pending=None, preparing=None,
            created=None, failed=False)

    def test_original_calls_results_and_kernel_metadata_are_preserved(self):
        self.assertIs(self.record, self.receipt.receive('channel'))
        self.original['receive'].assert_called_once_with('channel')
        self.receipt.ReferenceTransaction._authenticate('receipt', self.record)
        self.original['_authenticate'].assert_called_once_with('receipt', self.record)
        self.receipt.TransactionSequence.accept(self.proof, 'prepared', self.raw)
        self.original['accept'].assert_called_once_with(self.proof, 'prepared', self.raw)
        rows = [json.loads(line) for line in self.output.getvalue().splitlines()]
        self.assertEqual([1, 2], rows[0]['pidfd_inode'])
        self.assertEqual(120, rows[0]['session'])
        self.assertEqual('refs/heads/main', rows[-1]['updates'][0][2])

    def test_original_failure_identity_is_rethrown_without_secret_or_exception_text(self):
        failure = ValueError('SECRET_EXCEPTION_CONTENT')
        self.original['accept'].side_effect = failure
        self.receipt._decode(b'SECRET_PACKET')
        with self.assertRaises(ValueError) as raised:
            self.receipt.TransactionSequence.accept(self.proof, 'prepared', self.raw)
        self.assertIs(failure, raised.exception)
        text = self.output.getvalue()
        for secret in ('SECRET_EXCEPTION_CONTENT', 'SECRET_NONCE', 'SECRET_PACKET'):
            self.assertNotIn(secret, text)
        self.assertIn('"state": "failure"', text)
        self.assertIn('"frames":', text)

    def test_diagnostic_write_failure_cannot_mask_original_result_or_error(self):
        self.output.close()
        self.assertIs(self.record, self.receipt.receive('channel'))
        failure = RuntimeError('private')
        self.original['_record'].side_effect = failure
        with self.assertRaises(RuntimeError) as raised:
            self.receipt.ReferenceTransaction._record('receipt', self.record)
        self.assertIs(failure, raised.exception)

    def test_keyword_arguments_and_unexpected_diagnostic_shape_preserve_original_calls(self):
        self.receipt.TransactionSequence.accept(self.proof, phase='prepared', raw=self.raw)
        self.original['accept'].assert_called_once_with(self.proof, phase='prepared', raw=self.raw)
        self.receipt.ReferenceTransaction._authenticate('receipt', record=self.record)
        self.original['_authenticate'].assert_called_once_with('receipt', record=self.record)
        sentinel = object()
        self.original['_decode'].return_value = sentinel
        self.assertIs(sentinel, self.receipt._decode(b'private'))
        failure = RuntimeError('private')
        self.original['accept'].side_effect = failure
        with self.assertRaises(RuntimeError) as raised:
            self.receipt.TransactionSequence.accept(self.proof, phase='prepared', raw=self.raw)
        self.assertIs(failure, raised.exception)

    def test_invalid_updates_are_redacted_and_failure_budget_survives_success_budget(self):
        self.receipt.parse_updates.side_effect = ValueError('SECRET_INVALID_BODY')
        self.receipt.TransactionSequence.accept(self.proof, 'prepared', b'SECRET_INVALID_BODY')
        self.assertNotIn('SECRET_INVALID_BODY', self.output.getvalue())
        self.assertIn('REDACTED_INVALID', self.output.getvalue())
        for _ in range(150):
            self.receipt.receive('channel')
        failure = RuntimeError('private')
        self.original['_record'].side_effect = failure
        for _ in range(12):
            with self.assertRaises(RuntimeError):
                self.receipt.ReferenceTransaction._record('receipt', self.record)
        rows = [json.loads(line) for line in self.output.getvalue().splitlines()]
        self.assertEqual(128 + 8, len(rows))
        self.assertEqual(8, sum(row['state'] == 'failure' for row in rows))
