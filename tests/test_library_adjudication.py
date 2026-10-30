"""T25 authenticated service action against disposable Git, not user content."""
from copy import deepcopy
import unicodedata
from unittest.mock import patch

import test_library_disposition as rejection
import test_library_disposition_recovery as recovery
from uas import library, library_bundle as bundle
from uas.library_controls import canonical


class AdjudicationBase(rejection.DispositionBase):
    def setUp(self):
        super().setUp()
        self.principal=library.LocalHuman('human','actor','grant',lambda p,key,action:self.allowed
            and key==self.source.scope.project_identity and action in ('library-adjudicate','library-inspect'),lambda:True)
    def value(self,reason='PRIVATE_HUMAN_RATIONALE exact reasoning.',request='adjudicate-one'):
        value=super().value(reason=reason,request=request)
        value.update(action='adjudicate',conclusion='PRIVATE_HUMAN_CONCLUSION Keep the selected policy.',rationale=value.pop('reason'))
        return value


class AdjudicationTests(AdjudicationBase):
    def test_faithful_canonical_decision_provenance_and_no_verification(self):
        value=self.value();value['conclusion']='Cafe\u0301\r\n  preserve spaces\tand `code`\rnext'
        value['rationale']='Reason\n\n* exact emphasis *\n'
        before=self.source.count();old=self.source.head();result=self.send(value)
        self.assertEqual(result['outcome'],'COMMITTED');self.assertEqual(result['publication']['commit_sha'],self.source.head())
        self.assertEqual(self.source.count(),before+1);self.assertEqual(self.send(value),result)
        decision=self.source.contents('decisions/adjudication-'+self.q+'.md')
        meta,body=bundle.frontmatter(decision,'decision')
        self.assertEqual(str(meta['verified']),'false');self.assertEqual(str(meta['generated']),'false')
        expected=unicodedata.normalize('NFC',value['conclusion'].replace('\r\n','\n').replace('\r','\n'))
        self.assertIn('## Human conclusion\n\n'+expected+'\n\n## Human rationale\n\n'+value['rationale'],body)
        self.assertIn('Human identity: human\nActor identity: actor',body)
        self.assertIn('Input commit: '+old,body);self.assertIn('Source draft: '+self.q,body)
        self.assertNotIn(self.q,self.source.contents('pending/index.md'))
        self.assertIn('adjudication-'+self.q,self.source.contents('decisions/index.md'))
        self.assertFalse(self.fx.fx.fixture.marker.exists())
    def test_blocked_disposal_retains_work(self):
        other=self.blocked();untouched=self.source.contents('pending/'+other+'.md');value=self.value()
        result=self.send(value);state=deepcopy(self.entry()['state'])
        self.assertEqual(state['state'],'DISPOSED');self.assertEqual(state['selected'],[self.q,other])
        self.assertEqual(self.source.contents('pending/'+other+'.md'),untouched)
        self.assertEqual([o['kind'] for o in state['transition']['outcomes']],['adjudicated','retained'])
        self.assertEqual(state['transition']['resulting_sha'],result['publication']['commit_sha'])
        self.restart();self.assertEqual(self.entry()['state'],state);self.assertIsNone(self.service.tick())
        self.assertFalse(self.fx.fx.fixture.marker.exists())
    def test_private_bodies_only_in_canonical_git(self):
        self.blocked();value=self.value();self.send(value);self.service.flush()
        for path in [*self.source.base.glob('*.db*'),self.fx.fx.path]:
            text=path.read_bytes()
            for marker in (b'PRIVATE_HUMAN_RATIONALE',b'PRIVATE_HUMAN_CONCLUSION'):self.assertNotIn(marker,text)
        for marker in ('PRIVATE_HUMAN_RATIONALE','PRIVATE_HUMAN_CONCLUSION'):
            self.assertIn(marker,self.source.contents('decisions/adjudication-'+self.q+'.md'))
    def test_conflict_revocation_and_historical_settings_retry(self):
        value=self.value();receipt=self.send(value)
        for key in ('conclusion','rationale'):self.refused({**value,key:'Changed'},'ID_CONFLICT')
        self.allowed=False;self.refused(value,'FORBIDDEN');self.allowed=True
        from library_support import document,settings
        doc=document();doc['repository']=deepcopy(self.source.settings['repository']);doc['limits']['body_bytes']=10
        self.source.settings=settings(doc);self.assertEqual(self.send(value),receipt)
    def test_each_authored_field_cannot_bypass_policy(self):
        for key in ('conclusion','rationale'):
            for text in ('ghp_'+'A1b2'*10,'<script>x</script>','![x](https://example.test/x)','[x](https://example.test/x)','\x00','  '):
                value=self.value();value[key]=text;before=self.source.count()
                with self.assertRaises(library.LibraryError):self.send(value)
                self.assertEqual(self.source.count(),before)
    test_busy = rejection.DispositionTests.test_active_and_direct_attempt_lock_busy
    test_stale = rejection.DispositionTests.test_stale_inspection_and_configuration_no_write
    test_final_authority_fence = rejection.DispositionTests.test_revocation_at_final_publication_fence
    test_cross_project_and_forgery = recovery.RecoveryTests.test_wire_scope_and_cross_project_forgery_refused

    def test_existing_verified_concept_is_unchanged(self):
        self.send(self.value());path='decisions/adjudication-'+self.q+'.md'
        data=self.source.contents(path).replace('verified: false','verified: true').encode()
        full='projects/'+self.source.scope.project_path+'/'+path
        self.source.mutate({full:data})
        self.q=self.source.capture('another-human-draft')
        self.send(self.value(request='another-adjudication'))
        self.assertEqual(self.source.contents(path).encode(),data)
    def test_disposition_marker_text_cannot_inject_recovery(self):
        self.blocked();value=self.value()
        value['rationale']='Reason\nLibrary disposition receipt {"fake":true}'
        self.send(value);self.restart()
        self.assertEqual(self.entry()['state']['state'],'DISPOSED')
