"""Actual receiver correlation with in-memory records; no threads or native I/O."""
import base64
import io
import json
import threading
import unittest
from collections import deque
from types import SimpleNamespace as N
from unittest.mock import patch
from uas.pi_runtime import FixturePiRpcReceiver, NativeUnavailable
from uas.peer import Readiness

class PiAdmissionObservationTests(unittest.TestCase):
    def setUp(self):
        self.r=object.__new__(FixturePiRpcReceiver);r=self.r
        r._condition=threading.Condition();r.timeout=.1;r._ended=False;r._transport_fenced=False
        r._event_revision=r._request_revision=0;r._response_revisions={};r._notification_revisions={}
        r._admission_observation=None;r._responses={};r._notifications={};r._rpc_pending=set();r._native_pending=set()
        r.events=deque(maxlen=512);r.errors=[];r.scope={'run_id':'run','generation':1};r._binding={'session_id':'session'}
        r._startup_stage=lambda *a:None;r._alive=lambda:True
        self.mode='normal';self.writes=0
        def write(wire,deadline):
            self.writes+=1;request=json.loads(wire);payload=json.loads(base64.urlsafe_b64decode(request['message'].split(' ',1)[1]))
            notification={'type':'extension_ui_request','method':'notify','message':json.dumps({'uas':1,'request_id':payload['request_id'],'state':{'session_id':'session','readiness':'safe'}})}
            response={'type':'response','id':request['id'],'success':True}
            records=[notification,response]
            if self.mode=='reverse':records.reverse()
            if self.mode=='between':records.insert(1,{'type':'agent_start'})
            if self.mode=='after':records.append({'type':'agent_start'})
            if self.mode=='duplicate':records.append(response)
            r.process=N(stdout=io.BytesIO(b''.join(json.dumps(x).encode()+b'\n' for x in records)))
            r._read() # Synchronous controlled reader; EOF intentionally simulated here.
            r._ended=False # Fixture's transport remains open after this finite batch.
        r._write=write
    def test_exact_pair_both_orders_and_one_shot(self):
        for mode in ('normal','reverse'):
            self.mode=mode;sample=self.r.prepare_admission_observation()
            self.assertIs(Readiness.SAFE,self.r.validate_admission_observation(sample))
            self.assertIs(Readiness.SAFE,self.r.validate_admission_observation(sample,consume=True))
            with self.assertRaises(NativeUnavailable):self.r.validate_admission_observation(sample)
        self.assertEqual(2,self.writes)
    def test_intervening_later_or_duplicate_records_deny(self):
        for mode in ('between','after','duplicate'):
            self.mode=mode
            with self.assertRaises(NativeUnavailable):self.r.prepare_admission_observation()
    def test_late_event_eof_fence_scope_binding_or_age_deny(self):
        for field,value in (('_ended',True),('_transport_fenced',True),('_event_revision',999),('_request_revision',999),('scope',{'run_id':'other'}),('_binding',{'session_id':'other'})):
            case=PiAdmissionObservationTests();case.setUp();sample=case.r.prepare_admission_observation();setattr(case.r,field,value)
            with self.assertRaises(NativeUnavailable):case.r.validate_admission_observation(sample,consume=True)
        sample=self.r.prepare_admission_observation()
        with patch('uas.pi_runtime.time.monotonic',return_value=self.r._admission_observation[6]+1.01):
            with self.assertRaises(NativeUnavailable):self.r.validate_admission_observation(sample)
    def test_outgoing_request_invalidates_before_write(self):
        sample=self.r.prepare_admission_observation()
        def refuse(wire,deadline):
            with self.assertRaises(NativeUnavailable):self.r.validate_admission_observation(sample)
            raise NativeUnavailable('controlled write stop')
        self.r._write=refuse
        with self.assertRaises(NativeUnavailable):self.r.rpc('prompt',message='pending')
    def test_foreign_sample_thread_and_discard_are_local(self):
        sample=self.r.prepare_admission_observation()
        with self.assertRaises(NativeUnavailable):self.r.validate_admission_observation(object())
        with patch('uas.pi_runtime.threading.get_ident',return_value=-1):
            with self.assertRaises(NativeUnavailable):self.r.validate_admission_observation(sample)
        self.r.discard_admission_observation(object());self.r.validate_admission_observation(sample)
        self.r.discard_admission_observation(sample)
        with self.assertRaises(NativeUnavailable):self.r.validate_admission_observation(sample)
        self.assertEqual(1,self.writes)
    def test_ordinary_observe_preserved(self):
        self.assertIs(Readiness.SAFE,self.r.observe());self.assertEqual(1,self.writes)
