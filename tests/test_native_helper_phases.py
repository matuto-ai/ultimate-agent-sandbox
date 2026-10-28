"""Controlled native initialization phases; no native launch or process proof."""
import unittest
from unittest.mock import Mock,patch
from uas import claude_native_admission as m
from uas.kernel_origin import OriginDenied
import test_claude_native_admission as fixture

class NativeHelperPhaseTests(unittest.TestCase):
    def setUp(self):
        self.root=fixture.fixture();r=self.root
        r.launch=Mock();r._receive_helper=Mock();r._receive_forge_helper=Mock()
        r.attach_native=Mock();r._fail=Mock();r.helper_lease=Mock()
        self.args=dict(journal='/unused',control=None,hub_origin=None,controller='f'*32,
                       control_lock=None,operation_id='a'*32,epoch=1)

    def test_prepared_proof_has_no_admission_effect_until_explicit_consume(self):
        with patch.object(m,'NativeClaudeSupervisorAdmission') as admission:
            self.root.prepare_helper(None,**self.args)
            self.root.attach_native.assert_called_once();admission.assert_not_called()
            self.root.helper_lease.admit.assert_not_called()
            self.root.admit_prepared_helper()
            admission.return_value.admit.assert_called_once_with('a'*32,1)
            with self.assertRaisesRegex(OriginDenied,'one prepared'):self.root.admit_prepared_helper()
            self.assertEqual(admission.return_value.admit.call_count,1)

    def test_pause_between_phases_does_not_renew_deadline(self):
        with patch.object(m.time,'monotonic',return_value=0),patch.object(m,'NativeClaudeSupervisorAdmission') as admission:
            self.root.prepare_helper(None,timeout=8,**self.args)
            with patch.object(m.time,'monotonic',return_value=9):
                with self.assertRaises(TimeoutError):self.root.admit_prepared_helper()
            admission.assert_not_called();self.root._fail.assert_called_once()
            with self.assertRaises(OriginDenied):self.root.admit_prepared_helper()

    def test_disconnected_authorization_between_phases_prevents_transfer(self):
        allowed=[True]
        with patch.object(m,'NativeClaudeSupervisorAdmission') as admission:
            self.root.prepare_helper(None,authorize=lambda:allowed[0],**self.args)
            allowed[0]=False
            with self.assertRaisesRegex(OriginDenied,'authorization revoked'):self.root.admit_prepared_helper()
            admission.assert_not_called()

    def test_unknown_admission_only_retains_status_owner_never_resends(self):
        with patch.object(m,'NativeClaudeSupervisorAdmission') as admission:
            self.root.prepare_helper(None,**self.args)
            admission.return_value.admit.side_effect=TimeoutError('unknown')
            with self.assertRaises(TimeoutError):self.root.admit_prepared_helper()
            self.root._fail.assert_not_called();self.assertIs(self.root.native_admission,admission.return_value)
            with self.assertRaises(OriginDenied):self.root.admit_prepared_helper()
            admission.return_value.admit.assert_called_once()
