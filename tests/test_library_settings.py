"""Durable shared settings through the real owner and existing service consumers."""
from copy import deepcopy
from datetime import datetime, timezone
import json
import multiprocessing
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch
import library_support as support
import test_library_attempts as attempts_fixture
import test_library_enqueue as enqueue_fixture
from uas import library
from uas.library_settings import SettingsOwner, canonical
from uas.library_enqueue import EnqueueEndpoint
from uas.library_records import LibraryRecords


class SettingsTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name); self.base=support.settings();self.allowed=True;self.connected=True
        self.principal=library.LocalHuman('human','actor','grant-1',
            lambda p,key,action:self.allowed and key is None and action==library.SETTINGS_CAPABILITY,
            lambda:self.connected)
        self.owner=self.make(); self.owner.initialize({k:deepcopy(self.base[k]) for k in ('limits','filters')})
    def make(self):return SettingsOwner(self.root/'settings.db','installation',lambda:self.base,
        now=lambda:datetime(2026,10,30,tzinfo=timezone.utc))
    def observe(self, owner=None):return (owner or self.owner).handle(canonical(dict(version=1,
        action='settings-observe',deployment='installation')).encode(),self.principal)
    def value(self, ident='change-1'):
        state=self.observe(); state['shared']['limits']['coalesce_seconds']+=1
        return dict(version=1,action='settings-update',deployment='installation',request_id=ident,
            configuration_version=state['configuration_version'],settings_id=state['settings_id'],shared=state['shared'])
    def send(self,value,owner=None):return (owner or self.owner).handle(canonical(value).encode(),self.principal)
    def error(self,code,call):
        with self.assertRaises(library.LibraryError) as result:call()
        self.assertEqual(result.exception.code,code)
    def test_final_config_callback_revocation_cannot_commit(self):
        value=self.value();calls=[]
        def revoke():
            calls.append(1)
            if len(calls)==3:self.allowed=False
            return self.base
        self.owner.authority_settings=revoke
        with self.assertRaises(library.LibraryError):self.send(value)
        with sqlite3.connect(self.owner.path) as db:
            self.assertEqual(db.execute('SELECT revision FROM active').fetchone()[0],1)
            self.assertEqual(db.execute('SELECT count(*) FROM requests').fetchone()[0],0)
    def test_receipt_corruption_fails_closed(self):
        value=self.value();self.send(value)
        with sqlite3.connect(self.owner.path) as db:db.execute("UPDATE requests SET receipt='null'")
        self.error('SETTINGS_STORE_INVALID',lambda:self.send(value))
    def test_observe_rechecks_authority_after_config_read(self):
        def revoke():self.allowed=False;return self.base
        self.owner.authority_settings=revoke
        with self.assertRaises(library.LibraryError):self.observe()
    def test_revision_overflow_does_not_poison_store(self):
        with sqlite3.connect(self.owner.path) as db:db.execute('UPDATE active SET revision=?',(2**53-1,))
        value=self.value();result=self.send(value)
        self.assertEqual(result['outcome'],'REJECTED')
        self.assertEqual(self.observe()['configuration_version'],2**53-1)
    def test_atomic_durable_version_no_git_and_exact_retry_restart(self):
        before=self.owner();value=self.value();result=self.send(value)
        self.assertEqual(result['outcome'],'CONFIGURED');self.assertEqual(result['configuration_version'],2)
        self.assertIsNone(result['publication']);self.assertEqual(result['prior_sha256'],before['settings_id'])
        self.assertEqual(self.observe()['settings_id'],result['resulting_sha256'])
        self.assertEqual(self.send(value,self.make()),result)
        self.assertEqual(self.observe(self.make())['configuration_version'],2)
    def test_configuration_id_aba_is_fenced_by_revision(self):
        original=self.value();self.send(original)
        revert=self.value('revert');revert['shared']['limits']['coalesce_seconds']-=2;self.send(revert)
        stale={**original,'request_id':'new-request'}
        self.assertEqual(self.send(stale)['reason'],'STALE_SETTINGS')
    def test_wrong_scope_and_current_authority_never_create_content_grant(self):
        value=self.value();wrong={**value,'deployment':'elsewhere'}
        self.error('WRONG_SETTINGS_SCOPE',lambda:self.send(wrong))
        self.allowed=False;self.error('FORBIDDEN',lambda:self.send(value))
        self.allowed=True
        self.error('FORBIDDEN',lambda:library.local_human_scope(self.principal,binding=support.binding(),kind='drain'))
        with self.assertRaises(library.LibraryError):self.owner.handle(canonical(value).encode(),library.participant_scope(support.ORIGIN,binding=support.binding()))
    def test_revocation_blocks_historical_receipt_and_observe(self):
        value=self.value();self.send(value);self.allowed=False
        self.error('FORBIDDEN',lambda:self.send(value));self.error('FORBIDDEN',self.observe)
    def test_actor_change_or_payload_reuse_conflicts(self):
        value=self.value();self.send(value)
        self.error('ID_CONFLICT',lambda:self.send({**value,'settings_id':'f'*64}))
        self.principal=library.LocalHuman('other','other','new',lambda *a:True,lambda:True)
        self.error('ID_CONFLICT',lambda:self.send(value))
    def test_invalid_limits_and_unqualified_filters_rejected_atomically(self):
        for i,mutate in enumerate((lambda s:s['limits'].update(body_bytes=0),
             lambda s:s['limits'].update(body_bytes=True),lambda s:s['limits'].update(attempt_seconds=3601),
             lambda s:s['filters'].update(heuristic='block'),lambda s:s.update(egress=[]),
             lambda s:s.update(model={'profile_ref':'unqualified'}),lambda s:s['limits'].pop('body_bytes'))):
            before=self.observe();value=self.value('invalid-'+str(i));mutate(value['shared'])
            result=self.send(value);self.assertEqual(result['outcome'],'REJECTED')
            self.assertEqual(self.observe(),before);self.assertEqual(self.send(value),result)
    def test_arbitrary_values_never_enter_safe_audit(self):
        value=self.value();value['shared']['limits']['body_bytes']='TOP_SECRET_SENTINEL'
        result=self.send(value);self.assertEqual(result['outcome'],'REJECTED')
        self.assertNotIn('TOP_SECRET_SENTINEL',canonical(result))
        self.assertNotIn(b'TOP_SECRET_SENTINEL',self.owner.path.read_bytes())
        value=self.value('good');result=self.send(value)
        self.assertEqual(result['changed_keys'],['limits.coalesce_seconds'])
        self.assertEqual(result['actor_id'],'actor');self.assertEqual(result['validation_outcome'],'CONFIGURED')
        self.assertNotIn('shared',result)
    def test_malformed_wire_does_not_update(self):
        for raw in (b'{"version":1,"version":1}',b'{}',b'null',b'x'*65537):
            with self.assertRaises(library.LibraryError):self.owner.handle(raw,self.principal)
        self.assertEqual(self.observe()['configuration_version'],1)
    def test_missing_active_and_malformed_state_fail_closed_no_defaults(self):
        with sqlite3.connect(self.owner.path) as db:db.execute('DELETE FROM active')
        self.error('SETTINGS_STORE_INVALID',self.owner)
        self.error('SETTINGS_ALREADY_EXISTS',lambda:self.owner.initialize({k:self.base[k] for k in ('limits','filters')}))
        self.owner.path.unlink();self.error('SETTINGS_UNAVAILABLE',self.owner)
        self.assertFalse(self.owner.path.exists())
    def test_unsafe_active_maxima_with_valid_hash_fails_closed(self):
        value=self.value()['shared'];value['limits']['body_bytes']=library.MAXIMA['body_bytes']+1
        with sqlite3.connect(self.owner.path) as db:db.execute('UPDATE active SET shared=?,digest=?',(canonical(value),library._digest(value)))
        with self.assertRaises(library.LibraryError):self.owner()
    def test_current_authority_rechecked_before_commit(self):
        value=self.value();called=[0]
        def authorize(*args):called[0]+=1;return called[0]==1
        self.principal=library.LocalHuman('human','actor','grant-1',authorize,lambda:True)
        self.error('FORBIDDEN',lambda:self.send(value));self.assertEqual(self.owner()['settings_id'],value['settings_id'])
    def test_lost_commit_response_reconciles_without_second_write(self):
        value=self.value();commit=self.owner._commit
        def lost(db):commit(db);raise sqlite3.OperationalError('lost')
        with patch.object(self.owner,'_commit',side_effect=lost):self.error('SETTINGS_OUTCOME_UNKNOWN',lambda:self.send(value))
        result=self.send(value,self.make());self.assertEqual(result['configuration_version'],2)
        self.assertEqual(self.observe()['configuration_version'],2)
    def test_rollback_does_not_leave_receipt_or_configuration(self):
        value=self.value()
        with patch.object(self.owner,'_commit',side_effect=sqlite3.OperationalError('disk')):
            self.error('SETTINGS_OUTCOME_UNKNOWN',lambda:self.send(value))
        self.assertEqual(self.observe()['configuration_version'],1)
        self.assertEqual(self.send(value)['outcome'],'CONFIGURED')
    def test_actual_process_death_after_commit_reconciles(self):
        value=self.value()
        def child():
            owner=self.make();commit=owner._commit
            def stop(db):commit(db);os._exit(42)
            owner._commit=stop;self.send(value,owner)
        process=multiprocessing.get_context('fork').Process(target=child);process.start();process.join(3)
        if process.is_alive():process.kill();process.join();self.fail('timeout')
        self.assertEqual(process.exitcode,42);process.close()
        self.assertEqual(self.send(value)['configuration_version'],2)
    def test_two_concurrent_updates_one_version_wins(self):
        values=[self.value('a'),self.value('b')];results=[]
        threads=[threading.Thread(target=lambda v=v:results.append(self.send(v,self.make()))) for v in values]
        for thread in threads:thread.start()
        for thread in threads:thread.join(3);self.assertFalse(thread.is_alive())
        self.assertEqual(sorted(r['outcome'] for r in results),['CONFIGURED','REJECTED'])
        self.assertEqual(self.observe()['configuration_version'],2)
    def test_old_new_operations_race_and_detached_values(self):
        original=self.owner()
        with self.owner.operation():
            detached=self.owner();detached['limits']['body_bytes']=1
            self.send(self.value())
            self.assertEqual(self.owner(),original)
            observed=[];thread=threading.Thread(target=lambda:observed.append(self.owner()))
            thread.start();thread.join(2)
            self.assertNotEqual(observed[0]['settings_id'],original['settings_id'])
        self.assertNotEqual(self.owner()['settings_id'],original['settings_id'])
    def test_pinned_operation_does_not_pin_egress_or_route_authority(self):
        with self.owner.operation():
            self.base['model']['profile_ref']='other'
            self.base['settings_id']=library._settings_id(self.base)
            self.assertEqual(self.owner()['model']['profile_ref'],'other')
    def test_corrupt_active_config_blocks_even_pinned_operation(self):
        with self.owner.operation():
            with sqlite3.connect(self.owner.path) as db:db.execute("UPDATE active SET digest='wrong'")
            self.error('SETTINGS_STORE_INVALID',self.owner)
    def test_bounded_capacity_refuses_new_identity_but_exact_retry_works(self):
        value=self.value();result=self.send(value)
        with patch('uas.library_settings.MAX_REQUESTS',1):
            self.assertEqual(self.send(value),result)
            self.error('SETTINGS_CAPACITY_EXHAUSTED',lambda:self.send(self.value('second')))
    def test_read_does_not_create_missing_db_or_adopt_foreign_schema(self):
        foreign=self.root/'foreign.db'
        with sqlite3.connect(foreign) as db:db.execute('CREATE TABLE unrelated (secret TEXT)')
        foreign.chmod(0o600)
        owner=SettingsOwner(foreign,'installation',lambda:self.base)
        self.error('SETTINGS_STORE_INVALID',owner)
    def test_symbolic_or_public_file_refused(self):
        self.owner.path.chmod(0o644);self.error('SETTINGS_STORE_UNSAFE',self.owner)
        self.owner.path.chmod(0o600);link=self.root/'link.db';link.symlink_to(self.owner.path)
        self.error('SETTINGS_STORE_UNSAFE',SettingsOwner(link,'installation',lambda:self.base))


class ConsumerTests(unittest.TestCase):
    def test_actual_enqueue_uses_new_limit_without_restart(self):
        fixture=enqueue_fixture.EnqueueTests('test_real_publication_metadata_and_separate_visibility')
        fixture.setUp();self.addCleanup(fixture.doCleanups)
        root=fixture.base/'config';root.mkdir(mode=0o700)
        owner=SettingsOwner(root/'settings.db','installation',lambda:fixture.settings)
        owner.initialize({k:fixture.settings[k] for k in ('filters','limits')})
        principal=library.LocalHuman('human','actor','v1',lambda *a:True,lambda:True)
        endpoint=EnqueueEndpoint(fixture.publisher,settings=owner)
        def enqueue(ident,title):return endpoint.contact(scope=fixture.scope,current=lambda:True,
            operation_id=ident,request_id=ident,value=support.value(title=title),at=support.AT,run_id=None)
        self.assertEqual(enqueue('first','Longer title').outcome,'DURABLY_QUEUED')
        before=owner();data={k:deepcopy(before[k]) for k in ('filters','limits')};data['limits']['title_chars']=3
        owner.handle(canonical(dict(version=1,action='settings-update',deployment='installation',request_id='lower',
            configuration_version=1,settings_id=before['settings_id'],shared=data)).encode(),principal)
        self.assertEqual(enqueue('second','Longer title').outcome,'REJECTED')
        self.assertEqual(enqueue('third','Yes').outcome,'DURABLY_QUEUED')
    def test_actual_inflight_attempt_retains_starting_settings(self):
        fixture=attempts_fixture.AttemptTests('test_git_lock_is_free_during_provider_latency')
        fixture.setUp();self.addCleanup(fixture.doCleanups)
        root=fixture.source.base/'config';root.mkdir(mode=0o700)
        owner=SettingsOwner(root/'settings.db','installation',lambda:fixture.source.settings)
        owner.initialize({k:fixture.source.settings[k] for k in ('filters','limits')})
        principal=library.LocalHuman('human','actor','v1',lambda *a:True,lambda:True)
        old=owner();runner=fixture.runner();runner.assembler.settings=owner;runner.dispatcher.settings=owner
        def changed(event):
            if event['state']=='admitted':
                data={k:deepcopy(old[k]) for k in ('limits','filters')};data['limits']['coalesce_seconds']+=1
                owner.handle(canonical(dict(version=1,action='settings-update',deployment='installation',request_id='race',
                    configuration_version=1,settings_id=old['settings_id'],shared=data)).encode(),principal)
        original=runner._run
        def before_admission(**arguments):
            changed({'state':'admitted'})
            return original(**arguments)
        runner._run=before_admission
        result=runner.run(drain_id='drain-1',attempt=1,selected=fixture.selected,at=support.AT)
        self.assertEqual(result.state,'COMMITTED')
        self.assertNotEqual(owner()['settings_id'],old['settings_id'])
        with fixture.records() as records:self.assertEqual(records.record(fixture.operation_id(),project_identity=fixture.source.scope.project_identity)['settings_id'],old['settings_id'])


class SettingsTransportTests(unittest.TestCase):
    native = False
    def setUp(self):
        import test_library_controls as controls_fixture
        cls=controls_fixture.SocketControlsTests if self.native else controls_fixture.ControlsTests
        self.fx=cls('test_no_blocked_bypass_and_retry_preserves_complete_original_batch')
        self.fx.setUp();self.addCleanup(self.fx.doCleanups)
        self.owner=SettingsOwner(self.fx.root/'settings.db','installation',lambda:self.fx.source.settings)
        self.owner.initialize({k:self.fx.source.settings[k] for k in ('limits','filters')})
        self.fx.controls.settings_owner=self.owner
        self.fx.principal=library.LocalHuman('operator','operator','v1',
            lambda p,key,action:key is None and action==library.SETTINGS_CAPABILITY,lambda:True)
    def test_operator_only_transport_update_restart_retry_and_no_project(self):
        observe=dict(version=1,action='settings-observe',deployment='installation')
        before=self.fx.send(observe)['result'];before['shared']['limits']['coalesce_seconds']+=1
        value=dict(version=1,action='settings-update',deployment='installation',request_id='transport',
            configuration_version=before['configuration_version'],settings_id=before['settings_id'],shared=before['shared'])
        result=self.fx.send(value);self.assertEqual(result['result']['outcome'],'CONFIGURED')
        self.fx.controls.settings_owner=SettingsOwner(self.owner.path,'installation',lambda:self.fx.source.settings)
        self.assertEqual(self.fx.send(value),result)
        self.assertEqual(self.fx.send(dict(version=1,action='observe',project_id='alpha',for_action='drain'))['outcome'],'unknown')
        self.fx.principal=library.LocalHuman('project','project','v1',lambda p,key,action:key is not None,lambda:True)
        self.assertEqual(self.fx.send(observe)['outcome'],'unknown')


class NativeSettingsTransportTests(SettingsTransportTests):
    native = True
