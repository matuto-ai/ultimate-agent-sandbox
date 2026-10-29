"""Canonical activation consumes local SAFE observation, no locked SDK call."""
import unittest
from uas.ledger import LedgerError
import test_native_run_admission_adversarial as fixture

class NativeActivationObservationTests(unittest.TestCase):
    seed=fixture.NativeRunAdversarialTests.seed
    open=fixture.NativeRunAdversarialTests.open

    def setUp(self):
        fixture.NativeRunAdversarialTests.setUp(self)
        self.calls=[];self.samples=[];self.after_sample=lambda handle,sample:None
        launch=self.launcher.launch
        def wrapped(*args,**kwargs):
            handle=launch(*args,**kwargs);receiver=handle.launch.native_receiver
            observe=receiver.observe;prepare=receiver.prepare_admission_observation
            validate=receiver.validate_admission_observation
            def unlocked(kind):
                self.assertFalse(self.supervisor._lifecycle_scopes,'SDK I/O under lifecycle')
                self.assertFalse(self.ledger._connection().in_transaction,'SDK I/O under ledger')
                self.calls.append(kind)
            def observed():unlocked('observe');return observe()
            def prepared():
                unlocked('prepare');sample=prepare();self.samples.append(sample)
                self.after_sample(handle,sample)
                return sample
            def validated(sample,*,consume=False):
                self.calls.append(('consume' if consume else 'validate',self.ledger._connection().in_transaction))
                self.assertTrue(self.supervisor._lifecycle_scopes)
                if consume:self.assertTrue(self.ledger._connection().in_transaction)
                return validate(sample,consume=consume)
            receiver.observe=observed;receiver.prepare_admission_observation=prepared
            receiver.validate_admission_observation=validated
            return handle
        self.launcher.launch=wrapped

    def test_sdk_calls_are_unlocked_and_only_final_reducer_consumes_once(self):
        run=self.open()
        self.assertEqual(run['status'],'ACTIVE')
        self.assertEqual(self.calls.count('observe'),1);self.assertEqual(self.calls.count('prepare'),1)
        self.assertEqual(self.calls.count(('consume',True)),1)
        self.assertIsNone(self.admission._activation_observation)
        self.assertTrue(self.samples[0].consumed)
        self.open();self.assertEqual(self.calls.count('prepare'),1)

    def test_observation_invalidated_before_commit_cannot_activate(self):
        original=self.admission._current_context
        def changed(*args):
            self.samples[-1].valid=False
            return original(*args)
        self.admission._current_context=changed
        with self.assertRaisesRegex(LedgerError,'SAMPLE_STALE'):self.open()
        self.assertFalse(self.ledger.snapshot()['state'].get('runs'))
        self.assertIsNone(self.admission._activation_observation)
        self.assertFalse(self.samples[0].consumed)

    def test_attachment_lost_during_observation_refuses_and_clears_sample(self):
        self.after_sample=lambda handle,sample:self.seed(lambda state:state['peer_traffic']['connections'][self.participant].update(readiness='lost'))
        with self.assertRaisesRegex(LedgerError,'STALE_CONNECTION'):self.open()
        self.assertFalse(self.ledger.snapshot()['state'].get('runs'))
        self.assertIsNone(self.admission._activation_observation)

    def test_no_prepared_sample_cannot_be_used_as_safe_cache(self):
        with self.assertRaisesRegex(LedgerError,'OBSERVATION_REQUIRED'):
            self.admission._safe_handle(object())
