"""Read-only diagnostics: public scan and real publisher/event composition."""
from copy import deepcopy
import hashlib
import json
import threading
import unittest
from unittest.mock import patch

import library_support as support
import test_library_registration as registration
from uas import library, library_bundle as bundle
from uas.library_diagnostics import Scanner, Diagnostics, digest
from uas.library_registration import skeleton
from uas.library_sources import CapturedSource, Resolver

SHA = 'a' * 40
NOW = '2026-10-30T03:00:00+00:00'
PRIVATE = 'unique private sentence NEVER_IN_REPORT'
SECRET = 'sk-proj-' + 'q' * 32


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.scope = library.participant_scope(support.ORIGIN, binding=support.binding())
        self.fresh = self.scope
        self.settings = support.settings()
        self.prefix = 'projects/' + self.scope.project_path + '/'
        self.files = dict(skeleton(self.scope, support.AT).files)

    def scanner(self, **kwargs):
        return Scanner(self.scope, self.settings, current_scope=lambda:self.fresh,
                       clock=lambda:NOW, **kwargs)

    def run_scan(self, **kwargs):
        return self.scanner(**kwargs).scan(SHA, bundle.Tree(self.files))

    def concept(self, path='context/first.md', body=PRIVATE, extra='', sources=None, indexed=True):
        kind = {'context':'context', 'decisions':'decision', 'research':'research', 'pending':'context'}[path.split('/')[0]]
        status = 'draft' if path.startswith('pending/') else 'stable'
        text = f'---\ntype: {kind}\ntitle: First\nstatus: {status}\n' + extra
        if sources is not None:
            text += 'sources:\n' + ''.join('  - resource: "' + x['resource'] + '"\n' + ''.join(
                '    ' + k + ': "' + v + '"\n' for k,v in x.items() if k != 'resource') for x in sources)
        self.files[self.prefix + path] = (text + '---\n' + body + '\n').encode()
        if indexed:
            index = self.prefix + path.split('/')[0] + '/index.md'
            self.files[index] += ('\n* [First](' + path.split('/')[1] + ')\n').encode()

    @staticmethod
    def codes(report, category=None):
        return {x['code'] for x in report['findings'] if category is None or x['category'] == category}

    def test_empty_registered_bundle_complete_and_no_mutation(self):
        before = dict(self.files)
        result = self.run_scan()
        self.assertTrue(result['complete']); self.assertTrue(result['no_findings'])
        self.assertEqual(result['input_sha'], SHA)
        self.assertEqual(result['rule_version'], 'library-diagnostics-1')
        self.assertEqual(result['configuration_sha256'], digest(self.settings))
        self.assertEqual(result['resulting_references'], [])
        self.assertEqual(self.files, before)

    def test_structure_each_supported_document_kind_and_relationship(self):
        cases = [
            ('index.md', b'---\nokf_version: "0.1"\n---\n# X\n', 'INVALID_OKF_VERSION'),
            ('log.md', b'# log\n', 'MISSING_LOG_ENTRY'),
            ('context/index.md', b'no heading\n', 'INVALID_INDEX'),
            ('context/first.md', b'no frontmatter', 'MISSING_FRONTMATTER'),
            ('context/first.md', b'---\ntype: decision\ntitle: X\n---\nX', 'TYPE_MISMATCH'),
            ('context/first.md', b'---\ntype: context\nstatus: draft\n---\nX', 'INCOHERENT_STATUS'),
            ('research/first.md', b'---\ntype: research\n---\nX', 'SOURCE_REQUIRED'),
            ('context/first.md', b'\xff', 'MALFORMED_UTF8'),
            ('context/first.md', b'---\ntype: context\ntype: context\n---\nX', 'DUPLICATE_YAML_KEY'),
        ]
        base = dict(self.files)
        for path, raw, expected in cases:
            with self.subTest(expected=expected):
                self.files = dict(base); self.files[self.prefix + path] = raw
                self.assertIn(expected, self.codes(self.run_scan(), 'violation'))
        self.files = dict(base); del self.files[self.prefix+'pending/index.md']
        self.assertIn('MISSING_REQUIRED_FILE', self.codes(self.run_scan(), 'violation'))
        self.files = dict(base); self.concept(indexed=False)
        result = self.run_scan()
        self.assertIn('MISSING_INDEX_ENTRY', self.codes(result, 'violation'))
        self.assertIn('ISOLATED_CONCEPT', self.codes(result, 'observation'))

    def test_observations_are_not_errors_and_only_accepted_concepts_count_incoming(self):
        self.concept(body='[missing](missing.md)', extra='stale_after: "2026-10-01"\n')
        self.concept('pending/'+'d'*64+'.md', body='[First](/context/first.md)')
        self.files[self.prefix+'log.md'] += b'\n* [First](context/first.md)\n'
        report = self.run_scan()
        self.assertFalse(self.codes(report, 'violation'))
        self.assertTrue({'ISOLATED_CONCEPT','BROKEN_INTERNAL_LINK','FRESHNESS_ELAPSED','OPTIONAL_SOURCE_MISSING'} <= self.codes(report, 'observation'))
        self.concept('decisions/second.md', body='[First](/context/first.md)')
        report = self.run_scan()
        first = digest(self.prefix+'context/first.md')
        self.assertFalse(any(x['code']=='ISOLATED_CONCEPT' and x['location_sha256']==first for x in report['findings']))

    def test_self_links_code_and_index_links_do_not_make_concept_nonisolated(self):
        self.concept(body='[self](first.md)\n```\n[x](/context/first.md)\n```')
        self.assertIn('ISOLATED_CONCEPT', self.codes(self.run_scan()))
        self.concept('decisions/second.md',body='[ref][id]\n\n[id]: /context/first.md')
        result = self.run_scan()
        first = digest(self.prefix+'context/first.md')
        self.assertFalse(any(x['code']=='ISOLATED_CONCEPT' and x['location_sha256']==first for x in result['findings']))

    def test_invalid_draft_in_accepted_directory_does_not_count_incoming(self):
        self.concept()
        self.concept('decisions/second.md', body='[First](/context/first.md)')
        path=self.prefix+'decisions/second.md'
        self.files[path]=self.files[path].replace(b'status: stable', b'status: draft')
        result=self.run_scan()
        self.assertIn('INCOHERENT_STATUS',self.codes(result))
        first=digest(self.prefix+'context/first.md')
        self.assertTrue(any(x['code']=='ISOLATED_CONCEPT' and x['location_sha256']==first for x in result['findings']))

    def test_malformed_documents_leave_dependencies_unchecked_and_graph_uncertain(self):
        self.concept()
        self.files[self.prefix+'decisions/bad.md']=b'\xff'
        result=self.run_scan()
        self.assertFalse(result['complete']); self.assertIsNone(result['no_findings'])
        self.assertTrue(result['coverage']['unchecked'])
        self.assertNotIn('ISOLATED_CONCEPT',self.codes(result))
        self.files[self.prefix+'decisions/bad.md']=b'not frontmatter'
        result=self.run_scan(); self.assertFalse(result['complete'])
        self.assertNotIn('ISOLATED_CONCEPT',self.codes(result))

    def test_unused_reference_definition_is_not_an_edge_or_broken_link(self):
        self.concept()
        self.concept('decisions/second.md', body='No link.\n\n[unused]: /context/first.md\n[also]: missing.md')
        result=self.run_scan()
        first=digest(self.prefix+'context/first.md')
        self.assertTrue(any(x['code']=='ISOLATED_CONCEPT' and x['location_sha256']==first for x in result['findings']))
        self.assertNotIn('BROKEN_INTERNAL_LINK',self.codes(result))

    def test_image_alt_children_do_not_count_as_incoming_links(self):
        self.concept()
        self.concept('decisions/second.md', body='![alt [nested](/context/first.md)](image.png)')
        result=self.run_scan()
        first=digest(self.prefix+'context/first.md')
        self.assertTrue(any(x['code']=='ISOLATED_CONCEPT' and x['location_sha256']==first for x in result['findings']))

    def test_unknown_reader_metadata_types_and_external_links_tolerated(self):
        self.concept(extra='unknown_key: value\n',body='[old](https://example.test/doc)')
        p=self.prefix+'context/first.md'; self.files[p]=self.files[p].replace(b'type: context', b'type: existing')
        self.assertFalse(self.codes(self.run_scan(), 'violation'))

    def test_source_not_checked_unavailable_mismatch_and_verified_are_distinct(self):
        raw=b'exact material\n'; resource='https://capture.test/objects/'+digest(raw)+'/item'
        decl={'resource':resource,'range':'1-1','sha256':digest(raw)}
        self.concept(sources=[decl])
        result=self.run_scan()
        self.assertIn('SOURCE_NOT_CHECKED', self.codes(result, 'unchecked'))
        self.assertFalse(result['complete']); self.assertIsNone(result['no_findings'])
        self.assertTrue(result['coverage']['unchecked'])
        source=CapturedSource(resource=resource,content=raw,project_identity=self.scope.project_identity)
        allowed=True
        resolver=Resolver(source=source,current_scope=lambda:self.fresh,source_allowed=lambda *a:allowed)
        result=self.run_scan(sources={resource:resolver})
        self.assertEqual(result['coverage']['sources'][0]['state'],'checked')
        allowed=False
        result=self.run_scan(sources={resource:resolver})
        self.assertIn('SOURCE_UNAVAILABLE',self.codes(result,'unavailable'))
        self.assertFalse(result['complete']); self.assertIsNone(result['no_findings'])
        self.assertFalse(self.codes(result,'mismatch'))
        allowed=True
        p=self.prefix+'context/first.md'; self.files[p]=self.files[p].replace(decl['sha256'].encode(),b'0'*64)
        # Resource hash is also changed above; restore it to retain captured identity.
        self.files[p]=self.files[p].replace(('objects/'+'0'*64).encode(),('objects/'+digest(raw)).encode())
        result=self.run_scan(sources={resource:resolver})
        self.assertIn('SOURCE_PROVENANCE_MISMATCH',self.codes(result,'mismatch'))
        self.files[p]=self.files[p].replace(b'range: "1-1"',b'range: "2-2"')
        self.assertIn('SOURCE_PROVENANCE_MISMATCH',self.codes(self.run_scan(sources={resource:resolver}),'mismatch'))

    def test_local_concept_range_hash_and_missing_material(self):
        self.concept(sources=[{'resource':'decisions/missing.md','range':'1-1','sha256':'a'*64}])
        self.assertIn('SOURCE_NOT_CHECKED',self.codes(self.run_scan()))
        self.concept('decisions/missing.md')
        self.assertIn('SOURCE_PROVENANCE_MISMATCH',self.codes(self.run_scan(),'mismatch'))

    def test_source_branch_advancing_is_not_a_mismatch(self):
        decl={'resource':'https://github.com/acme/alpha/blob/'+SHA+'/doc.md','range':'1-1','sha256':'b'*64}
        self.concept(sources=[decl]); result=self.run_scan()
        self.assertIn('SOURCE_NOT_CHECKED',self.codes(result))
        self.assertFalse(self.codes(result,'mismatch'))

    def test_metadata_only_private_paths_content_and_secret_values_absent(self):
        self.concept(body=PRIVATE+' '+SECRET+' [broken](sensitive-target.md)')
        self.files[self.prefix+'private-'+SECRET+'.md']=b'authored unknown text'
        result=self.run_scan(); output=json.dumps(result)
        for value in (PRIVATE,SECRET,'sensitive-target','context/first.md','authored unknown text'):
            self.assertNotIn(value,output)
        for item in result['findings']:
            self.assertEqual(len(item['finding_id']),64)
            self.assertEqual(len(item['content_sha256']),64)

    def test_partial_interrupt_and_budget_never_clean_or_erase_prior_scope(self):
        self.concept(); scanner=self.scanner()
        full=scanner.scan(SHA,bundle.Tree(self.files))
        partial=scanner.scan(SHA,bundle.Tree(self.files),cancelled=lambda:True)
        self.assertFalse(partial['complete']); self.assertIsNone(partial['no_findings'])
        self.assertTrue(partial['coverage']['unchecked']); self.assertTrue(full['findings'])
        limited=self.run_scan(max_units=2)
        self.assertFalse(limited['complete']); self.assertIsNone(limited['no_findings'])
        times=iter([0,31]); report=self.run_scan(monotonic=lambda:next(times))
        self.assertFalse(report['complete'])

    def test_findings_correlate_across_sha_but_change_content_or_config_reassesses(self):
        self.concept(); first=self.run_scan()
        second=self.scanner().scan('b'*40,bundle.Tree(self.files))
        self.assertEqual(first['findings'],second['findings'])
        self.assertNotEqual(first['scan_id'],second['scan_id'])
        self.files[self.prefix+'context/first.md']+=b'\nchanged\n'
        self.assertNotEqual(first['findings'],self.run_scan()['findings'])
        document=support.document(); document['limits']['scan_documents']+=1; settings=support.settings(document)
        result=Scanner(self.scope,settings,current_scope=lambda:self.scope,clock=lambda:NOW).scan(SHA,bundle.Tree(self.files))
        self.assertNotEqual(result['configuration_sha256'],first['configuration_sha256'])

    def test_archived_read_only_and_no_model_source_fetch_or_drafts(self):
        self.files[self.prefix+'index.md']+=b'\nLibrary state: archived\n'
        before=dict(self.files)
        with patch('subprocess.Popen',side_effect=AssertionError('unexpected process')):
            result=self.run_scan()
        self.assertTrue(result['complete']); self.assertEqual(self.files,before)

    def test_authority_revocation_returns_no_content_report(self):
        self.fresh=None
        with self.assertRaises(library.LibraryError):self.run_scan()

    def test_bounds_symlinks_foreign_paths_and_missing_snapshot(self):
        document=support.document(); document['limits']['scan_documents']=1; self.settings=support.settings(document)
        report=self.run_scan(); self.assertFalse(report['complete'])
        self.settings=support.settings()
        report=self.scanner().scan(SHA,bundle.Tree(self.files,('secret-link',)))
        self.assertIn('SYMLINK_NOT_ALLOWED',self.codes(report))
        self.files['foreign/secret']=b'text'
        self.assertIn('FOREIGN_PROJECT',self.codes(self.run_scan()))
        report=self.scanner().scan(None,bundle.Tree({}))
        self.assertIsNone(report['no_findings'])


class EventTests(unittest.TestCase):
    setUp=registration.RegistrationTests.setUp
    make_scope=registration.RegistrationTests.make_scope
    make_publisher=registration.RegistrationTests.make_publisher
    operation=registration.RegistrationTests.operation
    register=registration.RegistrationTests.register
    head=registration.RegistrationTests.head
    count=registration.RegistrationTests.count
    mutate=registration.RegistrationTests.mutate
    root=registration.RegistrationTests.root
    root_bytes=registration.RegistrationTests.root_bytes

    def worker(self,**kwargs):
        scanner=Scanner(self.scope,self.settings,current_scope=lambda:self.fresh,clock=lambda:NOW)
        worker=Diagnostics(self.publisher,scanner,**kwargs)
        self.addCleanup(worker.close)
        return worker

    def test_startup_successful_changes_explicit_and_restart(self):
        worker=self.worker().start(); self.assertTrue(worker.wait_idle())
        self.assertFalse(worker.reports[-1]['complete'])
        result=self.register(); self.assertTrue(worker.wait_idle())
        report=worker.reports[-1]; self.assertEqual(report['input_sha'],result.commit_sha)
        self.assertTrue(report['complete']); before=self.count()
        worker.request(); self.assertTrue(worker.wait_idle())
        self.assertEqual(self.count(),before)
        self.assertNotEqual(report['scan_id'],worker.reports[-1]['scan_id'])
        worker.close()
        restored=self.worker().start(); self.assertTrue(restored.wait_idle())
        self.assertEqual(restored.reports[-1]['input_sha'],self.head())

    def test_coalesces_and_failure_cannot_veto_publication_no_timer(self):
        entered=threading.Event(); release=threading.Event()
        def sink(report):
            entered.set(); release.wait(3)
            raise RuntimeError(PRIVATE+SECRET)
        worker=self.worker(sink=sink).start(); self.assertTrue(entered.wait(3))
        for _ in range(30):worker.request()
        result=self.register(); self.assertIsNotNone(result.commit_sha)
        release.set(); self.assertTrue(worker.wait_idle())
        self.assertEqual(worker.last_error,'SCAN_UNAVAILABLE')
        self.assertNotIn(SECRET,str(worker.last_error))
        self.assertLessEqual(worker._processed,40)
        worker.sink=None; worker.request(); self.assertTrue(worker.wait_idle())
        count=len(worker.reports)
        # A no-event idle wait does not schedule a new scan.
        self.assertTrue(worker.wait_idle()); self.assertEqual(count,len(worker.reports))

    def test_old_sha_remains_historical_and_partial_report_does_not_replace(self):
        self.register(); worker=self.worker().start(); self.assertTrue(worker.wait_idle())
        old=worker.reports[-1]
        self.mutate({self.root():self.root_bytes()+b'\nchanged\n'})
        self.publisher.reconnect(); self.assertTrue(worker.wait_idle())
        self.assertNotEqual(old['input_sha'],worker.reports[-1]['input_sha'])
        self.assertIn(old,worker.reports)
        worker.scanner.max_units=1; worker.request(); self.assertTrue(worker.wait_idle())
        self.assertFalse(worker.reports[-1]['complete']); self.assertIn(old,worker.reports)
        copied=worker.reports; copied[0]['findings'].append('not internal')
        self.assertNotEqual(copied,worker.reports)
