"""Untrusted proposal -> pure complete-tree gate, with no partial writes."""
from copy import deepcopy
import hashlib
import unittest

import library_support as support
from uas import library, library_bundle as bundle, library_gate as gate
from uas.library_enqueue import draft
from uas.library_registration import skeleton
from uas.library_compiler import compile_proposal, catalog


class CompilerTests(unittest.TestCase):
    def setUp(self):
        self.settings = support.settings()
        self.scope = library.participant_scope(support.ORIGIN, binding=support.binding())
        self.prefix = 'projects/' + self.scope.project_path
        self.current = skeleton(self.scope, support.AT)
        self.selected = []
        self.add_draft('request-1')

    def add_draft(self, request, body='Evidence supports this decision.', title='Use SQLite', sources=None):
        payload = {'type': 'decision', 'title': title, 'body': body,
                   'sources': sources if sources is not None else [{'resource': 'https://example.test/source'}]}
        op = library.capture(self.scope, self.settings, operation_id=request, request_id=request,
                             value=payload, at=support.AT)
        files = dict(self.current.files)
        files[self.prefix + '/pending/' + op.queue_id + '.md'] = draft(op)
        files[self.prefix + '/pending/index.md'] += ('* ['+title+']('+op.queue_id+'.md) - DRAFT.\n').encode()
        self.current = bundle.Tree(files)
        self.selected.append(op.queue_id)
        return op.queue_id

    def proposal(self):
        return {'version': 1, 'drain_id': 'drain-1', 'attempt': 1,
                'operations': [{'id': 'decision', 'op': 'create', 'type': 'decision',
                                'title': 'Use SQLite', 'description': 'Local storage choice',
                                'body': 'Use SQLite for local storage.', 'drafts': list(self.selected)}],
                'outcomes': [{'queue_id': q, 'kind': 'integrated', 'targets': ['decision']}
                             for q in self.selected]}

    def compile(self, proposal=None, **kwargs):
        return compile_proposal(self.scope, self.settings, current=self.current,
                 selected=tuple(self.selected), input_sha='a'*40, drain_id='drain-1', attempt=1,
                 at=support.AT, proposal=self.proposal() if proposal is None else proposal, **kwargs)

    def refuse(self, value, code=None):
        before = dict(self.current.files)
        copy = deepcopy(value)
        with self.assertRaises(library.LibraryError) as caught:
            self.compile(value)
        if code:
            self.assertEqual(caught.exception.code, code)
        self.assertEqual(dict(self.current.files), before)
        self.assertEqual(value, copy)
        return caught.exception

    def accepted(self, verified=False, extra=''):
        result = self.compile()
        files = dict(result.tree.files)
        path = self.prefix + '/decisions/use-sqlite.md'
        if verified:
            files[path] = files[path].replace(b'verified: false', b'verified: true')
        if extra:
            files[path] = files[path].replace(b'---\n', ('---\n'+extra).encode(), 1)
        self.current = bundle.Tree(files)
        self.selected = []
        self.add_draft('second-request')
        ref, entry = next(iter(catalog(self.scope, self.settings, current=self.current,
                                      selected=self.selected)['concepts'].items()))
        p = self.proposal()
        p['operations'][0] = {'id': 'decision', 'op': 'update', 'target': ref,
                              'title': entry['title'], 'description': entry['description'],
                              'body': entry['body'], 'drafts': list(self.selected)}
        p['outcomes'][0]['kind'] = 'merged'
        return p, path

    def test_public_compile_valid_complete_and_deterministic(self):
        before = dict(self.current.files)
        result = self.compile()
        self.assertEqual(result.tree.files, self.compile().tree.files)
        self.assertEqual(result.validation.bundle.files, result.tree.files)
        self.assertEqual(result.paths['decision'], 'decisions/use-sqlite.md')
        text = result.tree.files[self.prefix+'/decisions/use-sqlite.md'].decode()
        meta, body = bundle.frontmatter(text, 'concept')
        self.assertEqual(meta['status'], 'stable')
        self.assertEqual(str(meta['verified']), 'false')
        self.assertEqual(str(meta['generated']), 'true')
        self.assertIn(gate.NOTICE, body)
        self.assertIn('Input commit: '+ 'a'*40, body)
        self.assertIn(self.selected[0], body)
        self.assertEqual(meta['sources'], [{'resource': 'https://example.test/source'}])
        self.assertNotIn(self.prefix+'/pending/'+self.selected[0]+'.md', result.tree.files)
        self.assertEqual(dict(self.current.files), before)

    def test_lowercase_ascii_slug_and_collision_suffix(self):
        p = self.proposal()
        p['operations'][0]['title'] = 'Índice / SQLite !'
        self.assertEqual(self.compile(p).paths['decision'], 'decisions/indice-sqlite.md')
        self.accepted()
        r = self.compile()
        expected = library._digest(sorted(self.selected))
        self.assertEqual(r.paths['decision'], 'decisions/use-sqlite-'+expected+'.md')

    def test_index_title_reserved_and_non_latin_slug(self):
        p = self.proposal()
        p['operations'][0]['title'] = 'Index'
        self.assertIn('index-', self.compile(p).paths['decision'])
        p['operations'][0]['title'] = '知识'
        self.assertEqual(self.compile(p).paths['decision'], 'decisions/concept.md')

    def test_unknown_existing_reader_data_preserved(self):
        p, path = self.accepted(extra='custom: {nested: ["kept", true]}\nstale_after: "2020-01-01T00:00:00+00:00"\n')
        p['operations'][0]['body'] = 'Meaningfully revised.'
        files = dict(self.current.files)
        files[self.prefix+'/human.txt'] = b'Unknown authored reader data\n'
        files[self.prefix+'/research/index.md'] += b'\nHuman commentary stays.\n'
        self.current = bundle.Tree(files)
        result = self.compile(p)
        text = result.tree.files[path].decode()
        self.assertIn('custom: {nested: ["kept", true]}', text)
        self.assertIn('stale_after: "2020-01-01T00:00:00+00:00"', text)
        self.assertEqual(files[self.prefix+'/human.txt'], result.tree.files[self.prefix+'/human.txt'])
        self.assertEqual(files[self.prefix+'/research/index.md'], result.tree.files[self.prefix+'/research/index.md'])

    def test_unchanged_retains_exact_verified_bytes_and_merged_log(self):
        p, path = self.accepted(verified=True)
        result = self.compile(p)
        self.assertEqual(result.tree.files[path], self.current.files[path])
        self.assertIn(b'MERGED', result.tree.files[self.prefix+'/log.md'])
        self.assertEqual(result.outcomes[0]['kind'], 'merged')

    def test_changed_body_clears_current_verification(self):
        p, path = self.accepted(verified=True)
        p['operations'][0]['body'] = 'Changed rationale.'
        result = self.compile(p)
        meta, _ = bundle.frontmatter(result.tree.files[path].decode(), 'concept')
        self.assertEqual(str(meta['verified']), 'false')

    def test_deprecate_never_deletes_or_renames(self):
        p, path = self.accepted(verified=True)
        target = p['operations'][0]['target']
        p['operations'][0] = {'id':'decision','op':'deprecate','target':target,
                              'reason':'superseded','drafts':list(self.selected)}
        result = self.compile(p)
        self.assertIn(path, result.tree.files)
        meta, body = bundle.frontmatter(result.tree.files[path].decode(), 'concept')
        self.assertEqual(meta['status'], 'deprecated')
        self.assertEqual(str(meta['verified']), 'false')
        self.assertIn('superseded', body)

    def test_multiple_selected_drafts_merge_provenance(self):
        q2 = self.add_draft('request-2', sources=[{'resource':'https://example.test/two'}])
        result = self.compile()
        meta, body = bundle.frontmatter(result.tree.files[self.prefix+'/decisions/use-sqlite.md'].decode(), 'x')
        self.assertEqual(len(meta['sources']), 2)
        self.assertIn(q2, body)
        self.assertEqual(len(result.outcomes), 2)

    def test_park_valid_remainder_and_durable_parked_index(self):
        q2 = self.add_draft('request-2')
        p = self.proposal()
        p['operations'][0]['drafts'] = [self.selected[0]]
        p['outcomes'][1] = {'queue_id':q2,'kind':'parked','reason':'unresolved-contradiction'}
        result = self.compile(p)
        self.assertEqual(result.tree.files[self.prefix+'/pending/'+q2+'.md'],
                         self.current.files[self.prefix+'/pending/'+q2+'.md'])
        self.assertIn(b'DRAFT PARKED: unresolved-contradiction', result.tree.files[self.prefix+'/pending/index.md'])
        self.assertIn(self.prefix+'/decisions/use-sqlite.md', result.tree.files)

    def test_parking_only_keeps_draft_status(self):
        p = self.proposal()
        p['operations'] = []
        p['outcomes'] = [{'queue_id':self.selected[0],'kind':'parked','reason':'insufficient-evidence'}]
        result = self.compile(p)
        path = self.prefix+'/pending/'+self.selected[0]+'.md'
        self.assertEqual(self.current.files[path], result.tree.files[path])
        self.assertEqual(result.validation.bundle.removed, ())
        self.assertIn(b'PARKED', result.tree.files[self.prefix+'/log.md'])

    def test_unselected_draft_bytes_and_index_preserved(self):
        q2 = self.add_draft('request-2')
        self.selected.remove(q2)
        result = self.compile()
        path = self.prefix+'/pending/'+q2+'.md'
        self.assertEqual(self.current.files[path], result.tree.files[path])
        self.assertIn(q2.encode(), result.tree.files[self.prefix+'/pending/index.md'])

    def test_reordered_proposal_operations_same_output(self):
        q2 = self.add_draft('request-2')
        p = self.proposal()
        p['operations'][0]['drafts'] = [self.selected[0]]
        op2 = dict(p['operations'][0], id='other', type='context', title='Context', drafts=[q2])
        p['operations'].append(op2)
        p['outcomes'][1]['targets'] = ['other']
        first = self.compile(p)
        p['operations'].reverse()
        p['outcomes'].reverse()
        self.assertEqual(first.tree.files, self.compile(p).tree.files)

    def test_surrogate_fields_fail_with_safe_contract_error(self):
        for field in ('title', 'description', 'body'):
            p=self.proposal();p['operations'][0][field]='bad\ud800';self.refuse(p,'MALFORMED_UTF8')

    def test_model_cannot_set_owned_fields_paths_or_sources(self):
        for field in ('verified','stale_after','status','generated','path','sources','timestamp','actor'):
            p = self.proposal()
            p['operations'][0][field] = 'forbidden'
            with self.subTest(field=field):
                self.refuse(p, 'UNKNOWN_FIELD')

    def test_delete_rename_and_patch_rejected(self):
        for op in ('delete','rename','patch','verify'):
            p = self.proposal(); p['operations'][0]['op']=op
            self.refuse(p,'UNSAFE_PROPOSAL_OPERATION')

    def test_attempt_batch_schema_types_and_unknown_fields_rejected(self):
        for field, value in [('attempt',2),('attempt',True),('version',True),('drain_id','other')]:
            p=self.proposal(); p[field]=value; self.refuse(p)
        p=self.proposal();p['outcomes'][0]['kind']='verified';self.refuse(p)
        p=self.proposal();p['git_diff']='anything';self.refuse(p)

    def test_missing_or_conflicting_attribution_rejects_whole_result(self):
        self.add_draft('request-2')
        p=self.proposal();p['outcomes'].pop();self.refuse(p,'UNCERTAIN_ATTRIBUTION')
        p=self.proposal();p['outcomes'][1]=dict(p['outcomes'][0]);self.refuse(p,'UNCERTAIN_ATTRIBUTION')
        p=self.proposal();p['outcomes'][1]={'queue_id':self.selected[1],'kind':'parked','reason':'conflict'}
        self.refuse(p,'UNCERTAIN_ATTRIBUTION')
        p=self.proposal();p['operations'][0]['drafts']=[self.selected[0]];self.refuse(p,'UNCERTAIN_ATTRIBUTION')

    def test_unknown_unselected_and_duplicate_references_rejected(self):
        p=self.proposal();p['operations'][0]['drafts']=['f'*64];self.refuse(p)
        p=self.proposal();p['outcomes'][0]['targets']=['unknown'];self.refuse(p)
        p=self.proposal();p['operations'].append(deepcopy(p['operations'][0]));self.refuse(p)
        p,_=self.accepted();p['operations'][0]['target']='decisions/use-sqlite.md';self.refuse(p,'UNKNOWN_CONCEPT_REFERENCE')

    def test_two_operations_same_existing_target_rejected(self):
        p,_=self.accepted()
        p['operations'].append(dict(p['operations'][0],id='other'))
        p['outcomes'][0]['targets'].append('other')
        self.refuse(p,'DUPLICATE_TARGET')

    def test_merged_requires_existing_target(self):
        p=self.proposal();p['outcomes'][0]['kind']='merged';self.refuse(p,'INVALID_DRAFT_OUTCOME')

    def test_source_cannot_be_fabricated_from_unattributed_draft(self):
        self.add_draft('request-2',sources=[{'resource':'https://example.test/private'}])
        p=self.proposal();p['operations'][0]['drafts']=[self.selected[0]]
        p['outcomes'][1]={'queue_id':self.selected[1],'kind':'parked','reason':'conflict'}
        result=self.compile(p)
        self.assertNotIn(b'/private',result.tree.files[self.prefix+'/decisions/use-sqlite.md'])

    def test_complete_gate_refuses_body_policy_and_secret_atomically(self):
        for body in ('<b>HTML</b>', '![image](thing.png)', '[outside](https://example.test)',
                     'PRIVATE KEY\n-----BEGIN RSA PRIVATE KEY-----\nAAA'):
            p=self.proposal();p['operations'][0]['body']=body;self.refuse(p)

    def test_research_without_source_rejected(self):
        files=dict(self.current.files);q=self.selected[0];path=self.prefix+'/pending/'+q+'.md'
        files[path]=files[path].replace(b'sources:\n  - resource: "https://example.test/source"\n',b'')
        self.current=bundle.Tree(files)
        p=self.proposal();p['operations'][0]['type']='research';self.refuse(p,'SOURCE_REQUIRED')

    def test_proposal_limits_no_silent_truncation(self):
        p=self.proposal();p['operations'][0]['body']='x'*(self.settings['limits']['body_bytes']+1)
        self.refuse(p)
        p=self.proposal();p['operations'][0]['title']='x'*201;self.refuse(p)
        p=self.proposal();p['operations'][0]['body']='e\u0301';self.refuse(p,'NON_CANONICAL_TEXT')

    def test_invalid_complete_tree_and_cross_project_inputs(self):
        files=dict(self.current.files);files.pop(self.prefix+'/context/index.md')
        self.current=bundle.Tree(files);self.refuse(self.proposal())
        self.setUp();files=dict(self.current.files);files['projects/foreign/index.md']=b'foreign'
        self.current=bundle.Tree(files);self.refuse(self.proposal(),'FOREIGN_PROJECT')

    def test_archived_project_and_missing_batch_refused(self):
        files=dict(self.current.files);files[self.prefix+'/index.md']+=b'\nLibrary state: archived\n'
        self.current=bundle.Tree(files);self.refuse(self.proposal(),'PROJECT_ARCHIVED')
        self.setUp();self.selected=['f'*64];self.refuse(self.proposal(),'SELECTED_DRAFT_MISSING')

    def test_unknown_supported_reader_type_never_rewritten(self):
        p,path=self.accepted()
        files=dict(self.current.files);files[path]=files[path].replace(b'type: "decision"',b'type: "future-type"')
        self.current=bundle.Tree(files);self.refuse(p,'UNSUPPORTED_TYPE')

    def test_complex_authored_index_is_not_silently_destroyed(self):
        p,path=self.accepted()
        p['operations'][0]['title']='New title'
        files=dict(self.current.files)
        files[self.prefix+'/decisions/index.md']=files[self.prefix+'/decisions/index.md'].replace(
            b'* [Use SQLite](use-sqlite.md)',b'Authored prose [Use SQLite](use-sqlite.md)')
        self.current=bundle.Tree(files);self.refuse(p,'INDEX_ENTRY_NOT_REPRODUCIBLE')

    def test_broken_preexisting_index_link_resolves_without_raw_exception(self):
        files=dict(self.current.files);key=self.prefix+'/decisions/index.md'
        files[key]+=b'* [Use SQLite](use-sqlite.md)\n';self.current=bundle.Tree(files)
        result=self.compile()
        self.assertEqual(result.tree.files[key].count(b'](use-sqlite.md)'),1)
        files[key]+=b'* [Use SQLite](use-sqlite.md) - preserve my prose\n'
        self.current=bundle.Tree(files);self.refuse(self.proposal(),'INDEX_ENTRY_NOT_REPRODUCIBLE')

    def test_authored_index_suffix_is_not_silently_rewritten(self):
        p,path=self.accepted();p['operations'][0]['body']='Changed content.'
        files=dict(self.current.files)
        key=self.prefix+'/decisions/index.md'
        lines=files[key].decode().splitlines()
        lines=[('* [Use SQLite](use-sqlite.md) - Human rationale that must survive.'
                if line.startswith('* [Use SQLite]') else line) for line in lines]
        files[key]=('\n'.join(lines)+'\n').encode();self.current=bundle.Tree(files)
        self.refuse(p,'INDEX_ENTRY_NOT_REPRODUCIBLE')

    def test_authored_fenced_and_indented_index_examples_preserved(self):
        p,path=self.accepted()
        p['operations'][0]['body']='Changed content.'
        example='\n## Human example\n```markdown\n* [Use SQLite](use-sqlite.md) - historical example; do not rewrite.\n```\n\n    * [Use SQLite](use-sqlite.md) - indented example\n'
        files=dict(self.current.files);files[self.prefix+'/decisions/index.md']+=example.encode()
        self.current=bundle.Tree(files)
        result=self.compile(p)
        self.assertIn(example.strip().encode(),result.tree.files[self.prefix+'/decisions/index.md'])

    def test_escaped_punctuation_titles_decode_without_weakening_match(self):
        for title in ('PRIVATE_TITLE_MARKER', 'A [nested] title', r'A \ path', 'Use *stars* and `code`', 'A ! title'):
            p=self.proposal();p['operations'][0]['title']=title
            with self.subTest(title=title):
                result=self.compile(p)
                self.assertEqual(bundle.frontmatter(result.tree.files[self.prefix+'/'+result.paths['decision']].decode(),'x')[0]['title'],title)

    def test_log_history_and_unchanged_external_reader_data_preserved(self):
        old=self.current.files[self.prefix+'/log.md']
        result=self.compile()
        self.assertTrue(result.tree.files[self.prefix+'/log.md'].startswith(old))
        self.assertEqual(result.input_sha,'a'*40)
        self.assertEqual(len(result.proposal_sha256),64)

    def test_immutable_outputs_do_not_mutate_model_input(self):
        p=self.proposal();before=deepcopy(p);result=self.compile(p)
        self.assertEqual(p,before)
        with self.assertRaises(TypeError):result.paths['decision']='evil'
        with self.assertRaises(TypeError):result.tree.files['evil']=b'evil'
        with self.assertRaises(TypeError):result.outcomes[0]['kind']='evil'


if __name__ == '__main__':
    unittest.main()
