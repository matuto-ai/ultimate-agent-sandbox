"""Pure extracted diagnostic checks; never import or run a native fixture."""
import ast
import io
import json
from pathlib import Path
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]


class BridgeDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.output = io.StringIO()
        self.previous = object()
        self.tracers = []
        self.sys = SimpleNamespace(stderr=self.output, gettrace=Mock(return_value=self.previous),
                                   settrace=Mock(side_effect=self.tracers.append))
        self.fail = None
        self.calls = []
        self.events = []
        def original(bridge):
            self.calls.append(bridge)
            trace = self.tracers[-1]
            for event, value, error in self.events:
                frame = SimpleNamespace(f_code=original.__code__, f_lineno=123,
                    f_locals={'value': value, 'key': SimpleNamespace(data='shim')})
                trace(frame, event, (type(error), error, None) if error else None)
            if self.fail is not None:
                raise self.fail
            return self.sentinel
        self.original = original
        self.sentinel = object()
        self.worker = ModuleType('uas.git_worker_native')
        self.worker.WorkerBridge = type('Bridge', (), {'_loop': original})
        package = ModuleType('uas')
        package.git_worker_native = self.worker
        tree = ast.parse((ROOT / 'tests/linux/git_stream_smoke.py').read_text())
        node = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                    and n.name == 'install_bridge_diagnostics')
        namespace = {'sys': self.sys, 'json': json, 'Path': Path}
        exec(compile(ast.Module(body=[node], type_ignores=[]), '<pure-bridge-diagnostic>', 'exec'), namespace)
        with patch.dict('sys.modules', {'uas': package, 'uas.git_worker_native': self.worker}):
            namespace['install_bridge_diagnostics']()
        self.bridge = self.worker.WorkerBridge()
        self.bridge._active = True

    def test_original_return_and_trace_restoration_are_unchanged(self):
        self.assertIs(self.sentinel, self.bridge._loop())
        self.assertEqual([self.bridge], self.calls)
        self.assertIs(self.previous, self.tracers[-1])

    def test_first_inner_exception_and_frame_kind_are_bounded_and_redacted(self):
        error = ValueError('SECRET_EXCEPTION')
        self.events = [('line', {'kind': 'data', 'data': 'SECRET_PACKET'}, None),
                       ('exception', {'kind': 'private-kind', 'argv': ['SECRET_ARGV']}, error)]
        self.assertIs(self.sentinel, self.bridge._loop())
        text = self.output.getvalue()
        for secret in ('SECRET_EXCEPTION', 'SECRET_PACKET', 'SECRET_ARGV', 'private-kind'):
            self.assertNotIn(secret, text)
        rows = [json.loads(line) for line in text.splitlines()]
        self.assertEqual(['data', 'REDACTED'], [row['kind'] for row in rows])
        self.assertEqual('ValueError', rows[-1]['error_type'])
        self.assertEqual('shim', rows[-1]['direction'])
        self.assertTrue(rows[-1]['active'])

    def test_original_failure_identity_and_failed_output_are_preserved(self):
        self.fail = RuntimeError('SECRET_FAILURE')
        self.events = [('exception', {'kind': 'eof'}, self.fail)]
        self.output.close()
        with self.assertRaises(RuntimeError) as caught:
            self.bridge._loop()
        self.assertIs(self.fail, caught.exception)
        self.assertIs(self.previous, self.tracers[-1])
        self.assertEqual([self.bridge], self.calls)

    def test_failure_budget_is_separate_and_bounded(self):
        self.events = [('line', {'kind': 'data'}, None) for _ in range(70)]
        self.events += [('exception', {'kind': 'eof'}, ValueError('private')) for _ in range(12)]
        self.bridge._loop()
        rows = [json.loads(line) for line in self.output.getvalue().splitlines()]
        self.assertEqual(72, len(rows))
        self.assertEqual(8, sum(row['fixture_bridge_stage'] == 'exception' for row in rows))
