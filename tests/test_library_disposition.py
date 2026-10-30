"""T24 real Git/SQLite/service rejection and crash recovery; no live user data."""
from copy import deepcopy
import json
import unittest
from unittest.mock import patch

import test_library_controls as fixture
from uas import library
from uas.library_controls import canonical
from uas.library_records import LibraryRecords
from uas import library_disposition as disposition


class DispositionBase(unittest.TestCase):
    def setUp(self):
        self.fx=fixture.ControlsTests('test_operational_ack_no_git_or_model_and_exact_retry')
        self.fx.setUp();self.addCleanup(self.fx.doCleanups)
        self.source=self.fx.source;self.service=self.fx.service;self.controls=self.fx.controls
        self.q=self.fx.fx.fixture.q;self.allowed=True
        self.principal=library.LocalHuman('human','actor','grant',lambda p,key,action:self.allowed
            and key==self.source.scope.project_identity and action in ('library-reject','library-inspect'),lambda:True)
    def send(self,value):
        return self.controls.handle(canonical(value),self.principal)
    def value(self,reason='PRIVATE_HUMAN_REASON not relevant.',request='reject-one'):
        observed=self.send(dict(version=1,action='observe',for_action='inspect',project_id='alpha',queue_id=self.q))
        state=self.entry()['state']
        return dict(version=1,action='reject',project_id='alpha',queue_id=self.q,
            drain_id=state['drain_id'] if self.q in state['selected'] and state['state']!='DISPOSED' else None,reason=reason,
            request_id=request,settings_id=observed['settings_id'],observed_version=observed['observed_version'])
    def entry(self):return self.service.scheduler._entries[self.source.scope.project_identity]
    def blocked(self,second=True,attempt=1,drain='original-drain'):
        other=self.source.capture('untouched',body='UNCHANGED_DRAFT') if second else None
        entry=self.entry();state=entry['state']
        self.service.scheduler._save(entry,{**state,'state':'BLOCKED','drain_id':drain,
            'selected':[self.q]+([other] if other else []),'attempt':attempt,'reason':'MODEL_FAILURE','due':None},self.service.scheduler.now())
        return other
    def restart(self):
        self.fx.fx.restart();self.service=self.fx.fx.service;self.controls.service=self.service
    def refused(self,value,code):
        with self.assertRaises(library.LibraryError) as error:self.send(value)
        self.assertEqual(error.exception.code,code)


class DispositionTests(DispositionBase):
    def test_pending_reject_one_commit_history_and_exact_retry(self):
        value=self.value();before=self.source.count();old=self.source.head()
        result=self.send(value)
        self.assertEqual(result['outcome'],'COMMITTED');self.assertEqual(result['publication']['commit_sha'],self.source.head())
        self.assertEqual(self.source.count(),before+1);self.assertEqual(self.send(value),result)
        _,tree=self.source.publisher.project_snapshot(self.source.scope,self.source.settings,current=lambda:None)
        prefix='projects/'+self.source.scope.project_path
        self.assertNotIn(prefix+'/pending/'+self.q+'.md',tree.files)
        self.assertNotIn(self.q,tree.files[prefix+'/pending/index.md'].decode())
        _,historic=self.source.publisher.project_snapshot_at(self.source.scope,self.source.settings,old,current=lambda:None)
        self.assertIn(prefix+'/pending/'+self.q+'.md',historic.files)
        self.assertIn(value['reason'],tree.files[prefix+'/log.md'].decode())
    def test_blocked_atomic_disposal_retains_untouched_and_never_retries(self):
        other=self.blocked();untouched=self.source.contents('pending/'+other+'.md');value=self.value()
        result=self.send(value);state=self.entry()['state']
        self.assertEqual(state['state'],'DISPOSED');self.assertEqual(state['selected'],[self.q,other])
        self.assertEqual(self.source.contents('pending/'+other+'.md'),untouched)
        transition=state['transition'];self.assertEqual(transition['phase'],'OPERATOR_DISPOSED')
        self.assertEqual([o['kind'] for o in transition['outcomes']],['rejected','retained'])
        self.assertEqual(transition['resulting_sha'],result['publication']['commit_sha'])
        self.restart();self.assertEqual(self.entry()['state'],state)
        with self.assertRaises(library.LibraryError) as e:self.service.scheduler.request(self.source.scope.project_identity,retry=True)
        self.assertEqual(e.exception.code,'DRAIN_DISPOSED')
        self.assertIsNone(self.service.tick());self.assertFalse(self.fx.fx.fixture.marker.exists())
    def test_zero_attempt_blocked_disposal(self):
        self.blocked(attempt=0);self.send(self.value());self.assertEqual(self.entry()['state']['state'],'DISPOSED')
    def test_active_and_direct_attempt_lock_busy(self):
        self.blocked();value=self.value();self.entry()['state']['state']='ACTIVE';before=self.source.count()
        self.refused(value,'CONTROL_BUSY');self.assertEqual(self.source.count(),before)
        self.entry()['state']['state']='BLOCKED';self.source.publisher.synthesis_lock.acquire()
        try:self.refused(value,'CONTROL_BUSY')
        finally:self.source.publisher.synthesis_lock.release()
    def test_conflicting_id_current_revocation_and_historical_config_replay(self):
        value=self.value();result=self.send(value)
        self.refused({**value,'reason':'Changed'},'ID_CONFLICT')
        self.allowed=False;self.refused(value,'FORBIDDEN');self.allowed=True
        from library_support import document,settings
        doc=document();doc['repository']=deepcopy(self.source.settings['repository']);doc['limits']['body_bytes']=10
        self.source.settings=settings(doc)
        self.assertEqual(self.send(value),result)
    def test_stale_inspection_and_configuration_no_write(self):
        value=self.value();self.source.capture('newer');before=self.source.count()
        self.refused(value,'STALE_INSPECTION');self.assertEqual(self.source.count(),before)
    def test_content_gate_non_bypassable(self):
        for reason in ('ghp_'+'A1b2'*10,'-----BEGIN RSA PRIVATE KEY-----', '<script>bad</script>','![image](https://example.test/image)','[external](https://example.test/doc)'):
            value=self.value(reason=reason);before=self.source.count()
            with self.assertRaises(library.LibraryError):self.send(value)
            self.assertEqual(self.source.count(),before)
    def test_revocation_at_final_publication_fence(self):
        value=self.value();original=self.source.publisher.publish;before=self.source.count()
        def publish(*a,**kw):self.allowed=False;return original(*a,**kw)
        with patch.object(self.source.publisher,'publish',publish):self.refused(value,'FORBIDDEN')
        self.assertEqual(self.source.count(),before)
