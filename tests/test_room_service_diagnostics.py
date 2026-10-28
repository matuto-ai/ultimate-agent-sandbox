"""Pure fixture diagnostics: no VM, native process, socket or kernel evidence."""
import ast
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

VM = Path(__file__).parent / 'vm'
sys.path.insert(0, str(VM))
try:
    from room_service import ObservedAuthority, require_help_reply
finally:
    sys.path.pop(0)


class DiagnosticsTests(unittest.TestCase):
    def test_first_help_refusal_is_terminal_before_second_request(self):
        checks = {}
        with self.assertRaisesRegex(RuntimeError, 'mounted help refused'):
            require_help_reply(None, checks, 0)
        self.assertEqual([None], checks['help_replies'])

    def test_help_success_and_nonhelp_refusal(self):
        checks = {}
        require_help_reply({'code': 0, 'status': 'OK', 'stdout': b'not retained'}, checks, 0)
        require_help_reply(None, checks, 1)
        self.assertEqual([{'code': 0, 'status': 'OK'}, None], checks['help_replies'])
        with self.assertRaisesRegex(RuntimeError, 'non-help unexpectedly admitted'):
            require_help_reply({'code': 0, 'status': 'OK'}, {}, 1)
        with self.assertRaisesRegex(RuntimeError, 'mounted help refused'):
            require_help_reply({'code': 128, 'status': 'ERROR'}, {}, 0)

    def test_bind_denial_keeps_original_exception_and_first_failure(self):
        original = RuntimeError('lineage admission deadline exceeded')
        delegate = Mock(); delegate.bind.side_effect = original
        checks = {}; observed = ObservedAuthority(delegate, checks, lambda: None)
        with self.assertRaises(RuntimeError) as caught: observed.bind('record')
        self.assertIs(original, caught.exception)
        self.assertEqual({'operation':'bind', 'phase':'lineage', 'error_type':'RuntimeError',
                          'message':str(original)}, checks['authority_failure'])
        delegate.current.side_effect = ValueError('later')
        with self.assertRaises(ValueError): observed.current()
        self.assertEqual('bind', checks['authority_failure']['operation'])
        delegate.bind.assert_called_once_with('record')

    def test_admitted_binding_still_rechecks_and_closes_same_authority(self):
        binding = SimpleNamespace(origin=object(), current=Mock(return_value=True),
                                  require=Mock(return_value=True), close=Mock())
        delegate = SimpleNamespace(bind=Mock(return_value=binding), close=Mock())
        checks = {}; observed = ObservedAuthority(delegate, checks, lambda: None)
        admitted = observed.bind('record')
        self.assertIs(binding.origin, admitted.origin)
        self.assertTrue(admitted.current()); self.assertTrue(admitted.require('next'))
        admitted.close(); observed.close()
        binding.current.assert_called_once_with(); binding.require.assert_called_once_with('next')
        binding.close.assert_called_once_with(); delegate.close.assert_called_once_with()
        self.assertNotIn('authority_failure', checks)
        self.assertEqual(3, len({key.split('.')[0] for key in checks['authority_phases']}))

    def test_current_denial_bounded_without_replacing_exception(self):
        error = RuntimeError('x' * 1000)
        checks = {}; binding = Mock(); binding.current.side_effect = error
        with self.assertRaises(RuntimeError) as caught: ObservedAuthority(binding, checks, lambda: None).current()
        self.assertIs(error, caught.exception)
        self.assertEqual(256, len(checks['authority_failure']['message']))
        self.assertEqual('current', checks['authority_failure']['operation'])

    def test_stage_and_partial_evidence_are_assigned_before_effects(self):
        text = (VM/'room_service.py').read_text()
        self.assertLess(text.index("checks['stage'] = 'help_accept'"), text.index('select.select([listener, launch.channel]'))
        self.assertLess(text.index('require_help_reply(replies[-1]'), text.index("control({'kind': 'HELP_ONLY_PROVED'})"))
        self.assertIn('launch.origin.require(record)', text)
        guest = (VM/'guest_room.py').read_text()
        self.assertLess(guest.index("checks['endpoint_service'] = {}"), guest.index("prove_service(supervisors['alpha']"))
        self.assertIn("checks=checks['endpoint_service']", guest)
        self.assertIn("checks.update(status='failed', error_type=type(error).__name__)", text)

    def test_bootstrap_error_report_does_not_export_exception_text(self):
        tree = ast.parse((VM.parent.parent/'uas/room_probe.py').read_text())
        handlers = [n for n in ast.walk(tree) if isinstance(n, ast.ExceptHandler)
                    and "'BOOTSTRAP_FAILED'" in ast.unparse(n)]
        self.assertEqual(1, len(handlers))
        text = ast.unparse(handlers[0])
        self.assertIn("'stage': stage", text)
        self.assertIn("'error_type': type(error).__name__[:64]", text)
        self.assertNotIn('str(error)', text)
        self.assertIsInstance(handlers[0].body[-1], ast.Raise)

    def test_failure_sender_holds_for_bounded_authenticated_ack(self):
        probe = (VM.parent.parent/'uas/room_probe.py').read_text()
        start = probe.index("'kind': 'BOOTSTRAP_FAILED'")
        tail = probe[start:probe.index('except Exception:', start)]
        self.assertLess(tail.index('channel.settimeout(5)'), tail.index('with receive(channel)'))
        self.assertLess(tail.index('peer.require(record)'), tail.index("'BOOTSTRAP_FAILURE_RECORDED'"))
        service = (VM/'room_service.py').read_text()
        start = service.index('if launch.channel in ready:')
        tail = service[start:service.index("raise RuntimeError('bootstrap ended", start)]
        self.assertLess(tail.index('launch.origin.require(record)'), tail.index("checks['bootstrap_failure'] = value"))
        self.assertLess(tail.index("checks['bootstrap_failure'] = value"), tail.index("'BOOTSTRAP_FAILURE_RECORDED'"))
