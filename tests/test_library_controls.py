"""Actual private Unix socket, service, SQLite and Git operator acceptance."""
from copy import deepcopy
from datetime import timedelta
import json
import multiprocessing
import os
from pathlib import Path
import socket
import sqlite3
import threading
import time
import unittest
from unittest.mock import Mock, patch

import library_support as support
import test_library_service as service_fixture
from uas import library
from uas.library_controls import Controls, canonical, request, serve
from uas.library_records import LibraryRecords


class ControlsTests(unittest.TestCase):
    def setUp(self):
        self.fx = service_fixture.ServiceTests('test_metadata_outbox_contains_no_model_or_draft_content')
        self.fx.setUp(); self.addCleanup(self.fx.doCleanups)
        self.service = self.fx.service; self.source = self.fx.source
        self.controls = Controls(self.service)
        self.allowed = True; self.connected = True
        self.principal = library.LocalHuman('bruno','human-actor','grant-1',
            lambda p, key, action: self.allowed and key == self.source.scope.project_identity
                and action in ('library-drain','library-retry'), lambda:self.connected)
        self.root = self.source.base/'operator';self.root.mkdir(mode=0o700)
    def close(self): pass
    def observed(self, kind='drain'):
        result=self.send(dict(version=1,action='observe',project_id='alpha',for_action=kind))
        self.assertEqual(result['outcome'],'observed',result)
        return result['result']
    def value(self, kind='drain', ident='request-1'):
        observed=self.observed(kind)
        result=dict(version=1,action=kind,project_id='alpha',request_id=ident,
                    settings_id=observed['settings_id'],observed_version=observed['observed_version'])
        if kind=='retry':result['drain_id']=observed['drain_id']
        return result
    def send(self, value):
        try:return {'outcome':'observed','result':self.controls.handle(canonical(value),self.principal)}
        except library.LibraryError as error:return {'outcome':'unknown','error':error.code}
    def state(self):return deepcopy(self.service.scheduler._entries[self.source.scope.project_identity]['state'])
    def test_operational_ack_no_git_or_model_and_exact_retry(self):
        before=self.source.count();value=self.value();first=self.send(value)
        self.assertEqual(first['result']['outcome'],'ACKNOWLEDGED')
        self.assertIsNone(first['result']['publication'])
        state=self.state();self.assertEqual(self.send(value),first)
        self.assertEqual(self.state(),state);self.assertEqual(self.source.count(),before)
        self.assertFalse(self.fx.fixture.marker.exists())
    def test_changed_request_id_payload_or_actor_conflicts(self):
        value=self.value();self.send(value)
        changed={**value,'observed_version':'a'*64}
        self.assertEqual(self.send(changed)['error'],'ID_CONFLICT')
        self.principal=library.LocalHuman('other','other-actor','grant-2',lambda *a:True,lambda:True)
        self.assertEqual(self.send(value)['error'],'ID_CONFLICT')
    def test_revoked_human_cannot_read_previous_receipt(self):
        value=self.value();self.send(value);state=self.state();self.allowed=False
        self.assertEqual(self.send(value)['error'],'FORBIDDEN');self.assertEqual(self.state(),state)
    def test_os_owner_settings_scope_and_participant_badge_are_not_project_grants(self):
        value=self.value()
        self.principal=library.LocalHuman('settings','settings-actor','version',
            lambda p,key,action:key is None and action==library.SETTINGS_CAPABILITY,lambda:True)
        self.assertEqual(library.local_settings_scope(self.principal).subject,'operator')
        self.assertEqual(self.send(value)['error'],'FORBIDDEN')
        self.principal=self.source.scope
        self.assertEqual(self.send(value)['error'],'LIBRARY_AUTHENTICATION_REQUIRED')
    def test_cross_project_unknown_and_caller_authority_fields_refused(self):
        value=self.value();before=self.state()
        self.assertEqual(self.send({**value,'project_id':'beta'})['error'],'PROJECT_UNAVAILABLE')
        for field in ('actor_id','human_id','participant_id','path','command','capabilities'):
            with self.assertRaises(library.LibraryError):request(self.root,{**value,field:'forged'})
        self.assertEqual(self.state(),before)
    def test_new_request_revalidates_configuration_and_target_state(self):
        value=self.value();self.service.scheduler.request(self.source.scope.project_identity)
        self.assertEqual(self.send(value)['error'],'STALE_CONTROL_STATE')
        value=self.value();doc=support.document();doc['repository']=deepcopy(self.source.settings['repository'])
        doc['limits']['coalesce_seconds']+=1
        self.source.settings=support.settings(doc)
        entry=self.service.scheduler._entries[self.source.scope.project_identity]
        original=entry['runner'].assembler.settings
        entry['runner'].assembler.settings=lambda:self.source.settings
        try:self.assertEqual(self.send(value)['error'],'STALE_CONTROL_STATE')
        finally:entry['runner'].assembler.settings=original
    def test_absent_hub_room_and_participant_session_do_not_remove_human_controls(self):
        self.fx.available=False;self.source.fresh=None
        value=self.value();result=self.send(value)
        self.assertEqual(result['result']['outcome'],'ACKNOWLEDGED');self.assertFalse(self.fx.path.exists())
    def test_no_blocked_bypass_and_retry_preserves_complete_original_batch(self):
        self.fx.mode='oversize'
        # Fixture invalid mode is provider-invalid output; block exact selected batch.
        for delay in (5,30,120):
            self.service.tick();self.fx.now+=timedelta(seconds=delay)
        state=self.state()
        self.assertEqual(state['state'],'BLOCKED')
        state=self.state();self.assertTrue(state['selected'])
        self.assertEqual(self.send(self.value())['error'],'PROJECT_BLOCKED')
        self.source.capture('later')
        value=self.value('retry');result=self.send(value)
        self.assertEqual(result['result']['outcome'],'ACKNOWLEDGED')
        ready=self.state();self.assertEqual(ready['selected'],state['selected']);self.assertEqual(ready['drain_id'],state['drain_id'])
        self.fx.mode='success';self.service.tick()
        with LibraryRecords(self.source.records,'deployment-1') as records:
            attempts=[r for r in records.iter_drain(state['drain_id'],project_identity=self.source.scope.project_identity)
                      if r['kind']=='synthesis-attempt']
        self.assertGreater(max(r['manifest']['attempt'] for r in attempts),state['attempt'])
    def test_stale_retry_drain_and_nonblocked_retry_refused(self):
        value=self.value();value.update(action='retry',drain_id='made-up')
        self.assertEqual(self.send(value)['error'],'STALE_CONTROL_STATE')
    def test_accepted_receipt_retry_after_scheduler_moves_does_not_schedule_again(self):
        value=self.value();first=self.send(value);self.service.tick();state=self.state()
        self.assertEqual(self.send(value),first);self.assertEqual(self.state(),state)
    def test_lost_response_after_atomic_commit_reconciles_without_repeat(self):
        value=self.value();original=LibraryRecords._commit;lost=[False]
        def commit(records):
            original(records)
            if not lost[0]:lost[0]=True;raise sqlite3.OperationalError('lost commit ack')
        with patch.object(LibraryRecords,'_commit',commit):result=self.send(value)
        self.assertEqual(result['outcome'],'unknown');self.assertEqual(result['error'],'RECORD_UNCERTAIN')
        self.assertTrue(self.service.scheduler._failed)
        again=self.send(value);self.assertEqual(again['result']['outcome'],'ACKNOWLEDGED')
        with LibraryRecords(self.source.records,'deployment-1') as records:
            saved=records.latest_schedule(self.source.scope.project_identity)
        sequence=saved['manifest']['sequence'];self.assertEqual(self.send(value),again)
        with LibraryRecords(self.source.records,'deployment-1') as records:
            self.assertEqual(records.latest_schedule(self.source.scope.project_identity)['manifest']['sequence'],sequence)
    def test_transaction_rollback_contains_neither_schedule_nor_ack(self):
        value=self.value();state=self.state()
        with patch.object(LibraryRecords,'_commit',side_effect=sqlite3.OperationalError('disk')):
            self.assertEqual(self.send(value)['error'],'RECORD_UNCERTAIN')
        with LibraryRecords(self.source.records,'deployment-1') as records:
            self.assertEqual(records.latest_schedule(self.source.scope.project_identity)['manifest'],state)
            operation='human-control-'+library._digest([self.source.scope.project_identity,value['request_id']])
            self.assertIsNone(records.record(operation,project_identity=self.source.scope.project_identity))
    def test_actual_process_death_after_transaction_restarts_with_one_ack(self):
        self.close();value=dict(version=1,action='drain',project_id='alpha',request_id='crash',
            settings_id=self.source.settings['settings_id'],
            observed_version=self.controls.handle(canonical(dict(version=1,action='observe',project_id='alpha',for_action='drain')),self.principal)['observed_version'])
        def child():
            os.close(self.service.publisher._lease)
            original=LibraryRecords._commit
            def commit(records):original(records);os._exit(42)
            LibraryRecords._commit=commit
            self.controls.handle(canonical(value),self.principal)
        process=multiprocessing.get_context('fork').Process(target=child);process.start();process.join(3)
        if process.is_alive():process.kill();process.join();self.fail('child timeout')
        self.assertEqual(process.exitcode,42);process.close()
        self.fx.restart();controls=Controls(self.fx.service)
        first=controls.handle(canonical(value),self.principal)
        self.assertEqual(first['outcome'],'ACKNOWLEDGED')
        state=deepcopy(self.fx.service.scheduler._entries[self.source.scope.project_identity]['state'])
        self.assertEqual(controls.handle(canonical(value),self.principal),first)
        self.assertEqual(self.fx.service.scheduler._entries[self.source.scope.project_identity]['state'],state)

    def test_duplicate_json_oversize_and_untrusted_actions_refuse(self):
        for raw in (b'{"version":1,"version":1}', b'x'*(8193)):
            with self.assertRaises(library.LibraryError):self.controls.handle(raw,self.principal)
        for action in ('shell','edit','pause-participant','settings-update','archive'):
            with self.assertRaises(library.LibraryError):request(self.root,dict(version=1,action=action,project_id='alpha'))


    def test_metadata_records_do_not_contain_draft_body_or_privileged_paths(self):
        result=self.send(self.value());self.assertIsNone(result['result']['publication'])
        raw=self.source.records.read_bytes()
        self.assertNotIn(b'Selected draft data.',raw);self.assertNotIn(str(self.source.target).encode(),canonical(result))
        self.assertNotIn(b'credential_ref',canonical(result))

    def test_current_grant_new_authority_version_can_reconcile_original_receipt(self):
        value=self.value();first=self.send(value);state=self.state()
        self.principal=library.LocalHuman('bruno','human-actor','grant-2',lambda *args:True,lambda:True)
        self.assertEqual(self.send(value),first);self.assertEqual(self.state(),state)
    def test_content_change_requires_fresh_observation(self):
        value=self.value();self.source.capture('new-content')
        self.assertEqual(self.send(value)['error'],'STALE_CONTROL_STATE')
    def test_prebatch_block_uses_explicit_null_not_fake_drain_identity(self):
        entry=self.service.scheduler._entries[self.source.scope.project_identity]
        with self.service.scheduler._lock:
            self.service.scheduler._save(entry,{**self.state(),'state':'BLOCKED','due':None,'reason':'PROJECT_QUEUE_INVALID'},self.fx.now)
        value=self.value('retry');self.assertIsNone(value['drain_id'])
        result=self.send(value);self.assertEqual(result['result']['outcome'],'ACKNOWLEDGED')
        self.assertIsNone(result['result']['drain_id'])
        self.assertEqual(self.service.tick()['state'],'COMMITTED')
    def test_current_archival_cannot_be_released_by_operator_retry(self):
        value=self.value()
        path='projects/'+self.source.scope.project_path+'/index.md'
        self.source.mutate({path:self.source.root_bytes()+b'\nLibrary state: archived\n'})
        self.assertEqual(self.send(value)['error'],'PROJECT_ARCHIVED')



class SocketControlsTests(ControlsTests):
    def setUp(self):
        # Detect only the sandbox's known EPERM boundary, never skip code failures.
        import errno
        probe = None
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            try:
                probe = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                probe.bind(folder+'/probe.sock')
            except OSError as error:
                if error.errno == errno.EPERM and os.environ.get('GITHUB_ACTIONS') != 'true':
                    self.skipTest('environment denies Unix socket bind')
                raise
            finally:
                if probe is not None: probe.close()
        super().setUp()
        self.stop = threading.Event();self.errors=[]
        self.authenticate = Mock(side_effect=lambda uid:self.principal)
        def run():
            try: serve(self.root,self.controls,authenticate=self.authenticate,stopped=self.stop.is_set)
            except BaseException as error:self.errors.append(error)
        self.thread=threading.Thread(target=run);self.thread.start()
        self.addCleanup(self.close)
        deadline=time.monotonic()+2
        while not (self.root/'library-operator.sock').exists() and time.monotonic()<deadline:time.sleep(.005)
        self.assertTrue((self.root/'library-operator.sock').exists())
    def close(self):
        self.stop.set();self.thread.join(3)
        self.assertFalse(self.thread.is_alive());self.assertFalse(self.errors)
    def send(self, value):return request(self.root,value)
    def test_disconnected_sender_does_not_roll_back_schedule(self):
        value=self.value();endpoint=self.root/'library-operator.sock'
        with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as channel:
            channel.connect(str(endpoint));channel.sendall(canonical(value))
        deadline=time.monotonic()+2
        while self.state()['sequence']==1 and time.monotonic()<deadline:time.sleep(.005)
        result=self.send(value);state=self.state()
        self.assertEqual(result['result']['outcome'],'ACKNOWLEDGED');self.assertEqual(self.send(value),result)
        self.assertEqual(self.state(),state)
    def test_peer_owner_checked_before_human_resolver(self):
        value=self.value()
        self.authenticate.reset_mock();before=self.state()
        with patch('uas.library_controls.peer_owner',side_effect=library.LibraryError('LOCAL_OPERATOR_REQUIRED')):
            # Raw client avoids replacing its own verification while exercising server.
            with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as channel:
                channel.connect(str(self.root/'library-operator.sock'))
                try:
                    channel.sendall(canonical(value))
                    data=channel.recv(16385)
                except (ConnectionResetError, BrokenPipeError):
                    data=b''  # kernel refusal may close with an unread queued packet
                if data: self.assertEqual(json.loads(data)['error'],'LOCAL_OPERATOR_REQUIRED')
        self.authenticate.assert_not_called()
        self.assertEqual(self.state(),before)
    def test_private_root_and_existing_endpoint_not_adopted(self):
        public=self.source.base/'public';public.mkdir(mode=0o755)
        with self.assertRaisesRegex(library.LibraryError,'ROOT_UNSAFE'):
            serve(public,self.controls,authenticate=lambda _:self.principal,stopped=lambda:True)
        with self.assertRaisesRegex(library.LibraryError,'ALREADY_ACTIVE'):
            serve(self.root,self.controls,authenticate=lambda _:self.principal,stopped=lambda:True)
        self.assertTrue((self.root/'library-operator.sock').exists())
    def test_socket_process_death_releases_lock_and_stale_endpoint_recovers(self):
        self.close()
        child=multiprocessing.get_context('fork').Process(target=serve,args=(self.root,self.controls),
            kwargs=dict(authenticate=lambda uid:self.principal,stopped=lambda:False))
        child.start()
        endpoint=self.root/'library-operator.sock';deadline=time.monotonic()+2
        while not endpoint.exists() and time.monotonic()<deadline:time.sleep(.005)
        self.assertTrue(endpoint.exists());child.kill();child.join(2);child.close()
        self.assertTrue(endpoint.exists())
        errors=[];stop=threading.Event()
        def run():
            try:serve(self.root,self.controls,authenticate=lambda uid:self.principal,stopped=stop.is_set)
            except BaseException as error:errors.append(error)
        thread=threading.Thread(target=run);thread.start()
        try:
            deadline=time.monotonic()+2
            while True:
                try:result=request(self.root,dict(version=1,action='observe',project_id='alpha',for_action='drain'));break
                except (ConnectionRefusedError,FileNotFoundError):
                    if time.monotonic()>deadline:raise
                    time.sleep(.005)
            self.assertEqual(result['outcome'],'observed')
        finally:stop.set();thread.join(2)
        self.assertFalse(errors);self.assertFalse(thread.is_alive())
