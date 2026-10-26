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
                    instances[0].errors.append(self.record())
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
