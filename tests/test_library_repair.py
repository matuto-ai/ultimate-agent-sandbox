"""T37 public human repair requests with disposable real Git and service restart."""
from copy import deepcopy
from types import SimpleNamespace
import library_support as support
import unittest
from unittest.mock import patch
import test_library_controls as fixture
import test_library_compiler as compiler_fixture
from uas import library, library_bundle as bundle, library_gate as gate, library_repair as repair
from uas.library_controls import canonical
from uas.library_indexes import reconstruct
from uas.library_compiler import _document, _label


class RepairTests(unittest.TestCase):
    def setUp(self):
        self.fx = fixture.ControlsTests('test_operational_ack_no_git_or_model_and_exact_retry')
        self.fx.setUp(); self.addCleanup(self.fx.doCleanups)
        self.source = self.fx.source; self.service = self.fx.service; self.controls = self.fx.controls
        self.q = self.fx.fx.fixture.q; self.allowed = True
        self.principal = library.LocalHuman('human','actor','grant',lambda p,key,action:self.allowed
            and key==self.source.scope.project_identity and action=='library-repair',lambda:True)
        self.prefix = 'projects/'+self.source.scope.project_path
    def send(self, value): return self.controls.handle(canonical(value), self.principal)
    def observe(self): return self.send(dict(version=1,action='observe',for_action='repair',project_id='alpha'))
    def value(self, request='repair-one'):
        observed = self.observe()
        return dict(version=1,action='repair',project_id='alpha',request_id=request,
            settings_id=observed['settings_id'],observed_version=observed['observed_version'])
    def mutate(self, relative, data): self.source.mutate({self.prefix+'/'+relative:data})
    def missing_entry(self):
        compiled=compiler_fixture.CompilerTests('test_public_compile_valid_complete_and_deterministic')
        compiled.setUp(); result=compiled.compile()
        self.source.mutate({self.prefix+'/decisions/use-sqlite.md':result.tree.files[compiled.prefix+'/decisions/use-sqlite.md'],
            self.prefix+'/decisions/index.md':('# Decisions\n\n'+gate.NOTICE+'\n').encode()})
    def missing_pending(self):
        self.mutate('pending/index.md', ('# Pending\n\n'+gate.NOTICE+'\n').encode())
    def tree(self): return self.source.publisher.project_snapshot(self.source.scope,self.source.settings,current=lambda:None)[1]
    def refused(self, value, code):
        with self.assertRaises(library.LibraryError) as e: self.send(value)
        self.assertEqual(e.exception.code,code)
    def test_missing_generated_entry_repairs_only_indexes_and_exact_replay(self):
        self.missing_entry(); before=self.tree(); value=self.value(); count=self.source.count()
        result=self.send(value); after=self.tree()
        self.assertEqual(result['outcome'],'COMMITTED'); self.assertEqual(result['publication']['commit_sha'],self.source.head())
        self.assertEqual(self.source.count(),count+1)
        changed=[p for p in before.files if before.files[p]!=after.files[p]]
        self.assertEqual(changed,[self.prefix+'/decisions/index.md'])
        self.assertIn(b'use-sqlite.md',after.files[changed[0]])
        self.assertEqual(self.send(value),result); self.assertEqual(self.source.count(),count+1)
        self.assertFalse(self.fx.fx.fixture.marker.exists())
    def test_root_service_links_rebuilt_without_rewriting_authored_root(self):
        original=self.source.contents('index.md')
        self.mutate('index.md',original.replace('* [Research](research/index.md)\n','').encode())
        self.send(self.value()); self.assertEqual(self.source.contents('index.md'),original)
        authored=original+'\nHuman root note.\n'; self.mutate('index.md',authored.encode())
        self.assertIn({'path':'index.md','reason':'AUTHORED_OR_UNCERTAIN_INDEX'},self.observe()['reports'])
        self.send(self.value('authored-root')); self.assertEqual(self.source.contents('index.md'),authored)
    def test_noop_audited_without_git_commit(self):
        self.send(self.value()); count=self.source.count()
        value=self.value('no-change'); result=self.send(value)
        self.assertEqual(result['outcome'],'ACKNOWLEDGED'); self.assertEqual(result['reason'],'REPAIR_NO_CHANGE')
        self.assertEqual(self.source.count(),count); self.assertEqual(self.send(value),result)
    def test_authored_index_and_unknown_material_preserved_reported(self):
        old=self.source.contents('context/index.md').encode()+b'\nMy authored knowledge.\n'
        self.mutate('context/index.md',old); self.missing_entry(); observed=self.observe()
        self.assertIn({'path':'context/index.md','reason':'AUTHORED_OR_UNCERTAIN_INDEX'},observed['reports'])
        self.send(self.value()); self.assertEqual(self.source.contents('context/index.md').encode(),old)
    def test_uncertain_malformed_index_does_not_get_overwritten(self):
        old=b'Authored uncertain text without a heading.\n'
        self.mutate('context/index.md',old); value=self.value(); count=self.source.count()
        self.refused(value,'INVALID_INDEX'); self.assertEqual(self.source.count(),count)
        self.assertEqual(self.source.contents('context/index.md').encode(),old)
    def test_damaged_history_never_fabricated(self):
        self.missing_entry(); old=b'# Damaged history without dated entries\n'
        self.mutate('log.md',old); value=self.value(); count=self.source.count()
        self.refused(value,'MISSING_LOG_ENTRY'); self.assertEqual(self.source.count(),count)
        self.assertEqual(self.source.contents('log.md').encode(),old)
    def test_archive_and_missing_identity_fail_closed(self):
        self.mutate('index.md',self.source.contents('index.md').encode()+b'\nLibrary state: archived\n')
        self.refused(dict(version=1,action='observe',for_action='repair',project_id='alpha'),'PROJECT_ARCHIVED')
    def test_changed_input_and_config_fenced(self):
        value=self.value(); self.source.capture('new-input'); self.refused(value,'STALE_CONTROL_STATE')
        value=self.value(); doc=support.document(); doc['repository']=deepcopy(self.source.settings['repository'])
        doc['limits']['coalesce_seconds']+=1; self.source.settings=support.settings(doc)
        self.refused(value,'STALE_CONTROL_STATE')
    def test_current_authority_and_untrusted_wire(self):
        value=self.value(); self.allowed=False; self.refused(value,'FORBIDDEN'); self.allowed=True
        self.refused({**value,'actor_id':'forged'},'INVALID_CONTROL_REQUEST')
        self.principal=self.source.scope; self.refused(value,'LIBRARY_AUTHENTICATION_REQUIRED')
    def test_revoked_at_publish_and_stale_remote_no_publication(self):
        self.missing_entry(); value=self.value(); count=self.source.count(); original=self.source.publisher.publish
        def revoked(*a,**kw): self.allowed=False; return original(*a,**kw)
        with patch.object(self.source.publisher,'publish',revoked): self.refused(value,'FORBIDDEN')
        self.assertEqual(self.source.count(),count)
    def test_remote_input_change_at_publication_requires_new_observation(self):
        self.missing_entry(); value=self.value(); original=self.source.publisher.publish
        def changed(*a,**kw):
            self.mutate('log.md',self.source.contents('log.md').encode()+b'\nExternal authored history.\n')
            return original(*a,**kw)
        with patch.object(self.source.publisher,'publish',changed):
            with self.assertRaises(library.LibraryError): self.send(value)
        count=self.source.count(); self.refused(value,'CONTROL_OUTCOME_UNKNOWN')
        self.assertEqual(self.source.count(),count)
        self.assertIn('External authored history.',self.source.contents('log.md'))
        self.assertEqual(self.send(self.value('fresh'))['outcome'],'COMMITTED')
    def test_repair_gate_cannot_smuggle_concepts_or_history(self):
        self.missing_entry(); tree=self.tree(); proposed,_=reconstruct(self.source.scope,tree)
        for relative in ('pending/'+self.q+'.md','log.md'):
            files=dict(proposed.files); files[self.prefix+'/'+relative]+=b'\nMutated by caller\n'
            with self.assertRaises(library.LibraryError) as e:
                gate.validate(self.source.scope,self.source.settings,proposed=bundle.Tree(files),current=tree,repair=True)
            self.assertEqual(e.exception.code,'INVALID_REPAIR')
    def test_deadline_refusal_releases_turn_without_publication(self):
        self.missing_entry(); value=self.value(); count=self.source.count()
        from uas import library_deadline
        with patch.object(repair,'reconstruct',side_effect=library.LibraryError('ATTEMPT_TIMEOUT','deadline')):
            self.refused(value,'ATTEMPT_TIMEOUT')
        self.assertEqual(self.source.count(),count)
        for lock in (self.service.scheduler._turn,self.source.publisher.synthesis_lock):
            self.assertTrue(lock.acquire(blocking=False)); lock.release()
    def test_busy_turn_and_synthesis_never_preempt(self):
        value=self.value()
        for lock in (self.service.scheduler._turn,self.source.publisher.synthesis_lock):
            lock.acquire()
            try:self.refused(value,'CONTROL_BUSY')
            finally:lock.release()
    def test_fairness_yields_to_older_project_and_persists_served(self):
        entry=self.controls._entry('alpha'); other=deepcopy({k:v for k,v in entry.items() if k=='state'})
        other['scope']=SimpleNamespace(project_id='beta')
        other['state'].update(state='READY',due=self.service.scheduler.now().isoformat(),served=0)
        entry['state']['served']=1; self.service.scheduler._entries['older']=other
        value=self.value(); self.refused(value,'REPAIR_YIELD_REQUIRED')
        del self.service.scheduler._entries['older']; old=entry['state']['served']; self.send(value)
        self.assertGreater(entry['state']['served'],old)
    def test_lost_ack_restart_reconciles_no_second_publication(self):
        self.missing_entry(); value=self.value(); original=self.source.publisher.publish
        def lost(*a,**kw): original(*a,**kw); raise OSError('lost acknowledgement')
        with patch.object(self.source.publisher,'publish',lost):
            with self.assertRaises(OSError): self.send(value)
        count=self.source.count(); self.fx.fx.restart(); self.service=self.fx.fx.service; self.controls.service=self.service
        result=self.send(value); self.assertEqual(result['outcome'],'COMMITTED'); self.assertEqual(self.source.count(),count)
        self.assertEqual(self.send(value),result)
    def test_unpublished_unknown_never_reapplies_and_conflicting_replay_denied(self):
        self.missing_entry(); value=self.value()
        with patch.object(self.source.publisher,'publish',side_effect=OSError('before push')):
            with self.assertRaises(OSError): self.send(value)
        count=self.source.count(); self.refused(value,'CONTROL_OUTCOME_UNKNOWN'); self.assertEqual(self.source.count(),count)
        self.refused({**value,'observed_version':'a'*64},'ID_CONFLICT')
    def test_unknown_nested_material_is_preserved(self):
        self.mutate('context/opaque/data.txt',b'not a concept')
        self.missing_entry(); self.send(self.value())
        self.assertEqual(self.source.contents('context/opaque/data.txt'),'not a concept')
    def test_conflicting_parked_evidence_preserved_reported(self):
        self.service.tick(); old=self.source.contents('pending/index.md')
        parked=next(line for line in old.splitlines() if 'DRAFT PARKED:' in line)
        data=(old+'\n'+parked.replace('NEEDS_EVIDENCE','OTHER_REASON')+'\n').encode()
        self.mutate('pending/index.md',data)
        self.assertIn({'path':'pending/index.md','reason':'AUTHORED_OR_UNCERTAIN_INDEX'},self.observe()['reports'])
        self.send(self.value()); self.assertEqual(self.source.contents('pending/index.md').encode(),data)
    def test_truncated_structurally_valid_history_cannot_resurrect_pending(self):
        self.service.tick(); log=self.source.contents('log.md')
        self.mutate('log.md',log.split('* **Synthesis**:')[0].encode()); self.missing_pending()
        queue=self.source.contents('pending/'+self.q+'.md'); count=self.source.count()
        self.assertIn({'path':'pending/index.md','reason':'UNCERTAIN_QUEUE_HISTORY'},self.observe()['reports'])
        self.refused(self.value(),'MISSING_INDEX_ENTRY'); self.assertEqual(self.source.count(),count)
        self.assertEqual(self.source.contents('pending/'+self.q+'.md'),queue)
    def test_parked_labels_preserved_and_missing_marker_not_resurrected(self):
        self.service.tick()
        old=self.source.contents('pending/index.md'); self.assertIn('DRAFT PARKED:',old)
        self.send(self.value()); self.assertIn('DRAFT PARKED:',self.source.contents('pending/index.md'))
        self.missing_pending(); observed=self.observe()
        self.assertIn({'path':'pending/index.md','reason':'UNCERTAIN_QUEUE_HISTORY'},observed['reports'])
        count=self.source.count(); self.refused(self.value('missing-park'),'MISSING_INDEX_ENTRY')
        self.assertEqual(self.source.count(),count)


if __name__ == '__main__': unittest.main()
