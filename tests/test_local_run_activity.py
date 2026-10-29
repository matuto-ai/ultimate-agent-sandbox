"""Canonical local Run service, controlled native I/O and TLS, no external effects."""
from types import SimpleNamespace as N
from unittest.mock import Mock, patch
import hashlib
import unittest

import test_native_session_driver as driver_fixture
import test_local_manager as tls_fixture
from uas import human_mtls
from uas.local_native_run_session import LocalNativeRunSession
from uas.local_run_activity import LocalRunActivity, LocalRunIdentity
from uas.native_run_admission import NativeHumanRunRequest
from uas.ledger import LedgerError


class LocalRunActivityTests(unittest.TestCase):
    def setUp(self):
        fixture=driver_fixture.NativeSessionDriverTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        self.f=fixture;self.c=fixture.c
        self.host=object.__new__(LocalNativeRunSession)
        self.host.supervisor=self.c.supervisor
        self.host.plan=N(operation_timeout_seconds=180)
        self.host.operation_current=Mock()
        self.c.admission.checkout_client.deadline=120
        session=self.c.session
        self.fingerprint=hashlib.sha256(b'test-client').hexdigest()
        grant=human_mtls.HumanActionGrant(session.deployment_id,session.room_id,session.instance_id,
            session.manager_id,session.human,('open-run','authorize-run-request'))
        self.bindings=human_mtls.HumanActionBindings({self.fingerprint:grant})
        with patch.object(human_mtls.ssl,'SSLSocket',tls_fixture.TLS):
            connection=self.bindings.accept(tls_fixture.TLS())
            with connection.request({'version':1,'action':'open-run','payload':{'operation_id':'open','issue_number':1}}) as (_,human):
                self.human=human
                request=NativeHumanRunRequest('open',1,self.c.participant,human)
                lease=connection.run_admission_lease(human,'open',1)
                self.activity=LocalRunActivity(self.c.admission,self.c.recruitment,request,fixture.budget,
                                               grant=lease,host=self.host)
            connection.close()

    def test_original_human_expires_while_work_survives_180_seconds(self):
        self.assertFalse(self.human.allowed('open-run'))
        self.assertIs(type(self.activity.request),LocalRunIdentity)
        self.assertFalse(hasattr(self.activity.request,'session'))
        self.f.now=1000
        self.assertEqual(self.activity.step()['status'],'ACTIVE')
        self.c.pi._delivery_exchange.assert_called_once()
        self.assertIsNone(self.c.admission._session)
        self.assertIsNone(self.c.recruitment._session)

    def test_revoked_grant_fences_without_native_effects(self):
        self.bindings.revoke(self.fingerprint)
        self.assertEqual(self.activity.step()['status'],'attention')
        self.c.pi._delivery_exchange.assert_not_called()
        self.activity.step();self.c.pi._delivery_exchange.assert_not_called()

    def test_changed_generation_or_policy_is_not_resumed_by_a_new_tick(self):
        self.c.seed(lambda state:state['runs'][self.c.run_id].update(generation=2))
        result=self.activity.step()
        self.assertEqual(result['reason'],'LOCAL_ADMITTED_RUN_CHANGED')
        self.c.pi._delivery_exchange.assert_not_called()

    def test_pause_holds_traffic_and_same_generation_resume_works(self):
        self.c.seed(lambda state:state['runs'][self.c.run_id].update(status='PAUSED'))
        self.assertEqual(self.activity.step()['status'],'PAUSED')
        self.c.pi._delivery_exchange.assert_not_called()
        self.c.seed(lambda state:state['runs'][self.c.run_id].update(status='ACTIVE'))
        self.assertEqual(self.activity.step()['status'],'ACTIVE')
        self.c.pi._delivery_exchange.assert_called_once()

    def test_unknown_delivery_never_retries_on_next_tick(self):
        self.c.pi._delivery_exchange.side_effect=TimeoutError('uncertain')
        result=self.activity.step()
        self.assertEqual(result['status'],'attention')
        self.assertEqual(result['reason'],'LOCAL_RUN_EFFECT_UNKNOWN')
        self.activity.step();self.c.pi._delivery_exchange.assert_called_once()

    def test_completed_canonical_run_has_no_new_native_effects(self):
        self.f.close_run()
        self.assertEqual(self.activity.step()['outcome'],'completed')
        self.c.pi._delivery_exchange.assert_not_called()

    def test_each_turn_performs_at_most_one_delivery(self):
        self.activity.step()
        self.assertEqual(self.c.pi._delivery_exchange.call_count,1)
        self.f.root.native_admission._delivery_exchange.assert_not_called()
        self.f.now=1
        self.activity.step()
        self.assertEqual(self.f.root.native_admission._delivery_exchange.call_count,1)

    def test_old_qualification_loop_cannot_be_used_for_local_activity(self):
        with self.assertRaisesRegex(LedgerError,'LOCAL_RUN_STEP_REQUIRED'):self.activity.run()
