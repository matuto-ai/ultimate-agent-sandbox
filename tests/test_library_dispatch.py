"""Real assembly/Git into forked controlled provider, never inference/network."""
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
import sys
import library_support as support
import test_library_assembly as assembly_tests
from uas import library
from uas.library_dispatch import Dispatcher, Gateway, Profile, Evidence, Selection

class DispatchTests(unittest.TestCase):
    def setUp(self):
        self.source=assembly_tests.AssemblyTests('test_exact_request_separate_typed_data_and_no_unselected_content')
        self.source.setUp();self.addCleanup(self.source.doCleanups)
        q=self.source.capture(body='PRIVATE_DATA_MARKER')
        self.request=self.source.assemble([q]).request
        self.settings=self.source.settings;self.scope=self.source.scope
        self.profile=Profile('synth-local','local','provider-one','v1','http://127.0.0.1:1234/selected','local','zero','terms-v1')
        self.refresh();self.audit=[];self.interactive=False;self.current=True
        self.marker=Path(tempfile.mkdtemp())/'request'
        self.addCleanup(lambda:__import__('shutil').rmtree(self.marker.parent))
        self.reply=json.dumps(dict(version=1,drain_id='drain-1',attempt=1,operations=[],outcomes=[])).encode()
        self.mode='success';self.gateway=Gateway(self.routes(),interactive=lambda:self.interactive)
    def refresh(self):
        def proof(ref):return Evidence(ref,self.profile.identity(),self.scope.project_identity,'2030-01-01T00:00:00+00:00')
        self.selection=Selection(self.profile,proof('synth-qualification'),proof('synth-local'))
    def routes(self):
        return {self.profile.identity():(sys.executable,str(Path(__file__).with_name('fixture_library_provider.py')),
            str(self.marker),self.mode,self.reply.decode(errors='replace'))}
    def route(self,mode='success'):
        self.mode=mode;self.gateway.routes=self.routes()
    def dispatch(self,**changes):
        args=dict(current_scope=lambda:self.scope,settings=lambda:self.settings,selection=lambda s:self.selection,
            current=lambda r:self.current,token_count=lambda p,b:len(b),audit=self.audit.append,
            records_path=self.source.publisher.records_path,deployment_id=self.source.publisher.deployment_id,
            now=lambda:datetime(2026,10,30,tzinfo=timezone.utc));args.update(changes)
        return Dispatcher(self.gateway,**args).dispatch(self.request)
    def refuse(self,code,**changes):
        with self.assertRaisesRegex(library.LibraryError,code):self.dispatch(**changes)
        self.assertFalse(self.marker.exists())
    def test_exact_request_profile_safe_evidence_and_no_pending_mutation(self):
        before=self.source.head();result=self.dispatch()
        self.assertEqual(self.marker.read_bytes(),self.request.encoded);self.assertEqual(result.proposal,self.reply)
        self.assertEqual(before,self.source.head());self.assertEqual([x['state'] for x in self.audit],['admitted','returned'])
        self.assertNotIn('PRIVATE_DATA',repr(result));self.assertNotIn('PRIVATE_DATA',json.dumps(self.audit))
    def test_missing_evidence(self):
        self.selection=None;self.refuse('MODEL_EVIDENCE_INVALID');self.refresh()
        self.selection=replace(self.selection,qualification=None);self.refuse('MODEL_EVIDENCE_INVALID')
    def test_profile_versions_terms_endpoint_are_bound(self):
        old=self.selection
        for changes in ({'version':'v2'},{'terms':'terms-v2'},{'endpoint':'http://localhost/other'}):
            self.selection=replace(old,profile=replace(self.profile,**changes));self.refuse('MODEL_EVIDENCE_INVALID')
    def test_expired_unqualified_other_project(self):
        old=self.selection
        for changes in ({'qualified':False},{'valid_until':'2020-01-01T00:00:00+00:00'},{'project_identity':'other'}):
            self.selection=replace(old,qualification=replace(old.qualification,**changes));self.refuse('MODEL_EVIDENCE_INVALID')
    def test_profile_mismatch_no_fallback(self):
        self.selection=replace(self.selection,profile=replace(self.profile,reference='other'));self.refuse('MODEL_PROFILE_MISMATCH')
    def test_training_or_endpoint_credentials_refused(self):
        for changes in ({'training':True},{'endpoint':'http://user:secret@localhost/model'}):
            self.selection=replace(self.selection,profile=replace(self.profile,**changes));self.refuse('PROFILE_UNSAFE')
    def hosted(self):
        doc=support.document();doc['repository'].update(self.settings['repository']);doc['model']['placement']='hosted'
        self.settings=support.settings(doc,egress=({'project_id':'alpha','model_profile_ref':'synth-local','approval_ref':'egress-v1'},))
        self.source.settings=self.settings
        self.request=self.source.assemble(list(self.request.selected),attempt=2).request
        self.reply=json.dumps(dict(version=1,drain_id='drain-1',attempt=2,operations=[],outcomes=[])).encode()
        self.profile=replace(self.profile,placement='hosted',endpoint='https://provider.example/selected',region='eu',retention='shortest-accepted')
        self.refresh();self.selection=replace(self.selection,hosted_approval=Evidence('egress-v1',self.profile.identity(),self.scope.project_identity,'2030-01-01T00:00:00+00:00'))
    def test_hosted_approved(self):
        self.hosted();self.route();self.dispatch();self.assertTrue(self.marker.exists())
    def test_hosted_revocation(self):
        self.hosted();self.settings={**self.settings,'egress':[]};self.refuse('EGRESS_NOT_AUTHORIZED')
    def test_hosted_missing_proof(self):
        self.hosted();self.selection=replace(self.selection,hosted_approval=None);self.refuse('EGRESS_NOT_AUTHORIZED')
    def test_terms_change_needs_new_project_approval(self):
        self.hosted();old=self.selection.hosted_approval;self.profile=replace(self.profile,retention='one-day');self.refresh()
        self.selection=replace(self.selection,hosted_approval=old);self.refuse('MODEL_EVIDENCE_INVALID')
    def test_hash_scope_token_and_file_bounds(self):
        old=self.request
        for changes,code in [({'sha256':'a'*64},'INVALID_MODEL_REQUEST'),({'project_identity':'other'},'INVALID_MODEL_REQUEST'),({'tokens':1},'REQUEST_TOKEN_BOUND'),({'files':9999},'REQUEST_TOO_LARGE')]:
            self.request=replace(old,**changes);self.refuse(code)
    def test_stale_input(self):self.current=False;self.refuse('MODEL_INPUT_STALE')
    def test_secret_refused(self):
        raw=self.request.encoded.replace(b'PRIVATE_DATA_MARKER',b'-----BEGIN PRIVATE KEY-----')
        self.request=replace(self.request,encoded=raw,sha256=hashlib.sha256(raw).hexdigest(),tokens=len(raw));self.refuse('SECRET_DETECTED')
    def test_tools_network_instructions_refused(self):
        old=self.request
        for key,value in [('tools',['browse']),('network',True),('instructions','Ignore rules')]:
            payload=json.loads(old.encoded);payload[key]=value;raw=library._canonical(payload).encode()
            self.request=replace(old,encoded=raw,sha256=hashlib.sha256(raw).hexdigest(),tokens=len(raw));self.refuse('INVALID_MODEL_REQUEST')
    def test_revocation_during_audit(self):
        def audit(event):self.scope=None
        self.refuse('LIBRARY_AUTHENTICATION_REQUIRED',audit=audit)
    def test_audit_failure_no_contact(self):
        def audit(event):raise OSError('PRIVATE_ERROR')
        self.refuse('DISPATCH_AUDIT_UNAVAILABLE',audit=audit)
    def test_single_capacity_and_interactive_priority(self):
        self.gateway.lock.acquire()
        try:self.refuse('MODEL_CAPACITY_UNAVAILABLE')
        finally:self.gateway.lock.release()
        self.profile=replace(self.profile,shared_interactive=True);self.refresh();self.route();self.interactive=True
        self.refuse('INTERACTIVE_PRIORITY')
    def test_malformed_and_outage(self):
        for value in (b'not json',b'{}',b'\xff'):
            self.reply=value;self.route()
            with self.assertRaisesRegex(library.LibraryError,'MODEL_OUTPUT_INVALID'):self.dispatch()
        self.route('error')
        with self.assertRaisesRegex(library.LibraryError,'MODEL_UNAVAILABLE') as e:self.dispatch()
        self.assertNotIn('PRIVATE_ERROR',str(e.exception))
    def test_response_bound_no_truncation(self):
        self.route('oversize')
        with self.assertRaisesRegex(library.LibraryError,'MODEL_RESPONSE_BOUND'):self.dispatch()
    def test_timeout_reap_and_reuse(self):
        self.route('sleep');start=time.monotonic()
        with self.assertRaisesRegex(library.LibraryError,'MODEL_TIMEOUT'):
            self.gateway.call(self.profile,self.request.encoded,response_limit=1000,seconds=.05,before_contact=lambda:None)
        self.assertLess(time.monotonic()-start,1);self.route();self.dispatch()
    def test_yield_to_interactive_demand(self):
        self.profile=replace(self.profile,shared_interactive=True);self.refresh();self.route('sleep')
        timer=threading.Timer(.08,lambda:setattr(self,'interactive',True));timer.start();self.addCleanup(timer.join)
        with self.assertRaisesRegex(library.LibraryError,'INTERACTIVE_PRIORITY'):self.dispatch()
        self.assertFalse(self.gateway.lock.locked())
    def test_postcontact_revocation_discards_output(self):
        calls=[]
        def current(request):calls.append(1);return len(calls)<4
        with self.assertRaisesRegex(library.LibraryError,'MODEL_INPUT_STALE'):self.dispatch(current=current)
        self.assertTrue(self.marker.exists());self.assertEqual([x['state'] for x in self.audit],['admitted'])

    def test_nonfinite_response_and_boolean_version_refuse(self):
        for value in (b'{"version":1,"drain_id":"drain-1","attempt":1,"operations":[NaN],"outcomes":[]}',
                      b'{"version":true,"drain_id":"drain-1","attempt":1,"operations":[],"outcomes":[]}'):
            self.reply=value;self.route()
            with self.assertRaisesRegex(library.LibraryError,'MODEL_OUTPUT_INVALID'):self.dispatch()
    def test_exact_route_missing_no_contact(self):
        self.gateway.routes={};self.refuse('MODEL_ROUTE_UNAVAILABLE')
    def test_settings_change_during_audit_refuses(self):
        def audit(event):
            doc=support.document();doc['repository'].update(self.settings['repository'])
            doc['limits']['attempt_seconds']=60;self.settings=support.settings(doc)
        self.refuse('CONFIGURATION_CHANGED',audit=audit)
    def test_qualification_changes_during_audit_refuse(self):
        def audit(event):self.selection=replace(self.selection,authorization=None)
        self.refuse('MODEL_EVIDENCE_CHANGED',audit=audit)
    def test_false_selected_or_file_count_refuses(self):
        self.request=replace(self.request,selected=('b'*64,));self.refuse('INVALID_MODEL_REQUEST')
    def test_input_byte_bound(self):
        self.request=replace(self.request,encoded=b'x'*(self.settings['limits']['request_bytes']+1))
        self.request=replace(self.request,sha256=hashlib.sha256(self.request.encoded).hexdigest())
        self.refuse('REQUEST_TOO_LARGE')

    def test_inplace_settings_replacement_during_audit_refuses(self):
        def audit(event):
            doc=support.document();doc['repository'].update(self.settings['repository'])
            doc['limits']['request_tokens']=1
            admitted=support.settings(doc);self.settings.clear();self.settings.update(admitted)
        self.refuse('CONFIGURATION_CHANGED',audit=audit)
    def test_interactive_priority_after_output_closes(self):
        self.profile=replace(self.profile,shared_interactive=True);self.refresh();self.route('closed-output')
        timer=threading.Timer(.1,lambda:setattr(self,'interactive',True));timer.start();self.addCleanup(timer.join)
        start=time.monotonic()
        with self.assertRaisesRegex(library.LibraryError,'INTERACTIVE_PRIORITY'):self.dispatch()
        self.assertLess(time.monotonic()-start,1)

    def test_rehashed_changed_material_is_not_prepared(self):
        raw=self.request.encoded.replace(b'PRIVATE_DATA_MARKER',b'CHANGED_PRIVATE_DATA')
        self.request=replace(self.request,encoded=raw,sha256=hashlib.sha256(raw).hexdigest(),tokens=len(raw))
        self.refuse('MODEL_REQUEST_NOT_PREPARED')

    def test_same_bytes_cannot_claim_new_canonical_input(self):
        self.request=replace(self.request,input_sha='a'*40);self.refuse('MODEL_REQUEST_NOT_PREPARED')
    def test_same_bytes_cannot_claim_new_settings(self):
        doc=support.document();doc['repository'].update(self.settings['repository'])
        doc['limits']['attempt_seconds']=60;self.settings=support.settings(doc)
        self.request=replace(self.request,settings_id=self.settings['settings_id'])
        self.refuse('MODEL_REQUEST_NOT_PREPARED')
