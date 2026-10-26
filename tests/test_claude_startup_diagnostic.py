"""Pure partial-constructor failures; no process, SDK, listener or credentials."""
import json
import unittest
from unittest.mock import Mock, patch
from uas.claude_runtime import FixtureClaudeReceiver, ClaudeSignals, _sdk_startup_diagnostic


class StartupDiagnosticTests(unittest.TestCase):
    def record(self, **changes):
        return json.dumps({'type':'fixture-host-diagnostic', 'reason':'native-initialize-timeout',
                           'fence':'native-initialize-timeout', 'exit_code':2, **changes})

    def test_arbitrary_stderr_keys_tokens_controls_paths_and_content_are_never_reported(self):
        secret = 'Authorization: Bearer fixture-only-secret\n\x1b[31m token=secret /private/file peer-content'
        for lines in ([secret], [self.record(reason=secret, fence=secret, exit_code=secret)],
                      [self.record(extra=secret)], [self.record(), self.record()],
                      [self.record(reason='x' * 400)], [self.record(reason=['bad'])]):
            with self.subTest(lines=lines):
                output = json.dumps(_sdk_startup_diagnostic(lines), ensure_ascii=True)
                for forbidden in ('Authorization', 'Bearer', 'fixture-only', 'token=', '/private', 'peer-content', '\x1b'):
                    self.assertNotIn(forbidden, output)
                self.assertLess(len(output), 200)
        self.assertEqual(_sdk_startup_diagnostic([secret, self.record()])['reason'], 'native-initialize-timeout')

    def lifecycle(self, **changes):
        return {'phase': 'native-initialize', 'initialization_ms': 1500,
                'before_cleanup': {'state': 'live', 'exit_code': None, 'signal': None, 'kernel': 'S'},
                'final_native': {'state': 'exited', 'exit_code': None, 'signal': 'SIGTERM', 'kernel': None},
                'cleanup': 'complete', 'cleanup_failures': 0, 'forced_kill': False, **changes}

    def test_lifecycle_preserves_host_vs_native_exit_and_cleanup_facts(self):
        for before, final, cleanup in (
            ({'state': 'not-spawned', 'exit_code': None, 'signal': None, 'kernel': None},
             {'state': 'not-spawned', 'exit_code': None, 'signal': None, 'kernel': None}, 'complete'),
            ({'state': 'live', 'exit_code': None, 'signal': None, 'kernel': 'S'},
             {'state': 'exited', 'exit_code': None, 'signal': 'SIGKILL', 'kernel': None}, 'incomplete'),
            ({'state': 'exited', 'exit_code': 7, 'signal': None, 'kernel': None},
             {'state': 'exited', 'exit_code': 7, 'signal': None, 'kernel': None}, 'complete')):
            facts = self.lifecycle(before_cleanup=before, final_native=final, cleanup=cleanup,
                                   cleanup_failures=1 if cleanup == 'incomplete' else 0,
                                   forced_kill=cleanup == 'incomplete')
            parsed = _sdk_startup_diagnostic([self.record(lifecycle=facts)])
            self.assertEqual(parsed['exit_code'], 2)  # Host status, not native status.
            self.assertEqual(parsed['lifecycle'], facts)
            self.assertLess(len(json.dumps(parsed)), 1536)

    def test_lifecycle_schema_bounds_and_secret_text_are_allowlisted(self):
        secret = 'Authorization: Bearer fixture-only-secret token=/private/peer-content'
        bad_native = {'state': secret, 'exit_code': True, 'signal': ['SIGTERM'], 'kernel': secret}
        cases = [None, secret, {'extra': secret}, self.lifecycle(extra=secret),
                 self.lifecycle(phase=secret, initialization_ms=60001, before_cleanup=bad_native,
                                final_native={**bad_native, 'extra': secret}, cleanup=secret,
                                cleanup_failures=-1, forced_kill='true'),
                 self.lifecycle(initialization_ms=True, cleanup_failures=256)]
        for facts in cases:
            with self.subTest(facts=facts):
                parsed = _sdk_startup_diagnostic([self.record(lifecycle=facts)])
                wire = json.dumps(parsed)
                self.assertNotIn(secret, wire)
                self.assertLess(len(wire), 1536)
                self.assertIsNone(parsed['lifecycle']['initialization_ms'])
                self.assertIsNone(parsed['lifecycle']['cleanup_failures'])
        self.assertEqual(_sdk_startup_diagnostic([self.record(lifecycle='x' * 1536)]),
                         {'reason': 'unavailable', 'fence': 'unavailable', 'exit_code': None})
        self.assertEqual(_sdk_startup_diagnostic([self.record(lifecycle=self.lifecycle()), self.record()]),
                         {'reason': 'unavailable', 'fence': 'unavailable', 'exit_code': None})

    def test_partial_constructor_reports_after_all_cleanup_and_preserves_original_cause(self):
        for cleanup_failure in (False, True):
            with self.subTest(cleanup_failure=cleanup_failure):
                original = RuntimeError('original startup fault')
                cause = ValueError('original cause')
                original.__cause__ = cause
                instances = []
                child = Mock(returncode=None)
                db, owner = Mock(), Mock()
                def partial(receiver, *args):
                    instances.append(receiver)
                    receiver.process, receiver.db, receiver.owner = child, db, owner
                    receiver.signals = ClaudeSignals('not-reported-session')
                    receiver.signals.hold('transport-loss')
                    raise original
                def dispose(*args):
                    # Typed evidence arrives during disposal, before report.
                    instances[0].errors.append(self.record(lifecycle=self.lifecycle(
                        cleanup='incomplete' if cleanup_failure else 'complete',
                        cleanup_failures=int(cleanup_failure))))
                    child.returncode = -15
                    if cleanup_failure:
                        raise OSError('Authorization: Bearer fixture-only-secret')
                with patch.object(FixtureClaudeReceiver, '_open_journal', autospec=True, side_effect=partial), \
                     patch('uas.claude_runtime._dispose_sdk_process', side_effect=dispose) as cleanup:
                    with self.assertRaises(RuntimeError) as caught:
                        FixtureClaudeReceiver('unused', sdk_install='unused', node='unused', cwd='unused', home='unused',
                            gateway_url='unused', fixture_key='fixture-only-secret', journal='unused', scope={})
                self.assertIs(caught.exception, original)
                self.assertIs(caught.exception.__cause__, cause)
                cleanup.assert_called_once()
                for resource in (child.stdin, child.stdout, child.stderr, db, owner):
                    resource.close.assert_called_once()
                note = caught.exception.__notes__[-1]
                self.assertNotIn('fixture-only-secret', note)
                self.assertNotIn('not-reported-session', note)
                facts = json.loads(note.split(': ', 1)[1])
                self.assertEqual(facts['cleanup_succeeded'], not cleanup_failure)
                self.assertTrue(facts['resources_released'])
                self.assertTrue(facts['host_reaped'])
                self.assertEqual(facts['host_returncode'], -15)
                self.assertFalse(facts['initialized'])
                self.assertFalse(facts['ready'])
                self.assertTrue(facts['fenced_before_cleanup'])
                self.assertEqual(facts['host']['reason'], 'native-initialize-timeout')
                self.assertEqual(facts['host']['lifecycle']['cleanup'],
                                 'incomplete' if cleanup_failure else 'complete')
                self.assertEqual(facts['host']['lifecycle']['cleanup_failures'], int(cleanup_failure))
