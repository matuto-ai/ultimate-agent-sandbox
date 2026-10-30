"""T14 public resolver: real local Git objects, no network/model or host changes."""
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from uas import library as contracts
from uas import library_gate as gate
from uas.library_sources import CapturedSource, GitSource, Resolver, READ_SECONDS
from test_library import admit, binding, ORIGIN, OTHER


def sha(raw): return hashlib.sha256(raw).hexdigest()


class SourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.work = cls.root/'work'; cls.bare = cls.root/'source.git'
        cls.work.mkdir(mode=0o700)
        cls.env = {'PATH':'/usr/bin:/bin', 'HOME':str(cls.root), 'GIT_CONFIG_NOSYSTEM':'1',
                   'GIT_CONFIG_GLOBAL':'/dev/null', 'LANG':'C', 'LC_ALL':'C'}
        cls.git('init', '-q', str(cls.work))
        cls.git('-C',str(cls.work),'config','user.email','test@example.test')
        cls.git('-C',str(cls.work),'config','user.name','Test')
        (cls.work/'docs').mkdir()
        cls.raw = b'private first line\r\nrequested text \xc3\xa9\r\nprivate last line\n'
        files = {'docs/note.md':cls.raw, 'binary':b'a\0b', 'wrong-encoding':b'\xff',
                 'archive.zip':b'PK\x03\x04body', 'hidden-archive':b'PK\x03\x04body',
                 'huge':b'x'*65537, 'empty':b'', 'secret':b'sk-proj-'+b'x'*30+b'\n',
                 'unicode':b'one\xe2\x80\xa8two\nlast', 'no-final-newline':b'one\ntwo',
                 'tar':b'x'*257+b'ustar'+b'x'*10}
        for name, raw in files.items(): (cls.work/name).write_bytes(raw)
        (cls.work/'link').symlink_to('docs/note.md')
        cls.git('-C',str(cls.work),'add','.')
        cls.git('-C',str(cls.work),'commit','-qm','fixture')
        cls.commit = cls.git('-C',str(cls.work),'rev-parse','HEAD').decode().strip()
        cls.git('-C',str(cls.work),'update-index','--add','--cacheinfo','160000,'+cls.commit+',submodule')
        cls.git('-C',str(cls.work),'commit','-qm','gitlink')
        cls.commit = cls.git('-C',str(cls.work),'rev-parse','HEAD').decode().strip()
        cls.git('clone','--bare','--quiet',str(cls.work),str(cls.bare))
        cls.bare.chmod(0o700)

    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()

    @classmethod
    def git(cls,*args):
        return subprocess.check_output(['/usr/bin/git',*args],env=cls.env,stderr=subprocess.DEVNULL)

    def setUp(self):
        self.scope = contracts.participant_scope(ORIGIN,binding=binding())
        self.fresh = self.scope
        self.allowed = True
        self.calls = []
        self.source = GitSource(self.bare,project_identity=self.scope.project_identity,
                                repository='github.com/acme/alpha')
        def allowed(scope,resource):
            self.calls.append((scope.project_identity,resource)); return self.allowed
        self.resolver = Resolver(source=self.source,current_scope=lambda:self.fresh,source_allowed=allowed)
        self.settings = admit()

    def declaration(self,path='docs/note.md',raw=None,lines='2-2',commit=None):
        raw = b'requested text \xc3\xa9\r\n' if raw is None else raw
        return {'resource':'https://github.com/acme/alpha/blob/'+(commit or self.commit)+'/'+path,
                'range':lines,'sha256':sha(raw)}

    def resolve(self, value=None, **kwargs):
        return self.resolver.resolve(kwargs.get('scope',self.scope),kwargs.get('settings',self.settings),
                                     self.declaration() if value is None else value)

    def refusal(self, code, value=None, **kwargs):
        with self.assertRaises(contracts.LibraryError) as error: self.resolve(value,**kwargs)
        self.assertEqual(error.exception.code,code)
        return error.exception

    def test_exact_pinned_range_and_crlf_bytes_without_adjacent_content(self):
        result = self.resolve()
        self.assertEqual(result.content,b'requested text \xc3\xa9\r\n')
        self.assertEqual(result.sha256,sha(result.content))
        self.assertEqual(result.source_sha256,sha(self.raw))
        self.assertTrue(result.immutable_identity.startswith(self.commit+':'))
        self.assertEqual(result.metadata()['range'],[2,2])
        self.assertGreater(len(self.calls),4) # fresh authorization around every Git read
        for output in (repr(result),json.dumps(result.metadata())):
            self.assertNotIn('requested text',output)
            self.assertNotIn('private first',output)
            self.assertNotIn('docs/note',output)
        self.assertEqual(self.resolve().content,result.content) # exact retry rechecks

    def test_new_head_does_not_change_old_pin_or_read_worktree(self):
        old = self.commit
        (self.work/'docs/note.md').write_text('new moving worktree\n')
        # Deliberately no clone update: pin resolves only immutable objects.
        self.assertEqual(self.resolve().content,b'requested text \xc3\xa9\r\n')
        self.assertTrue(self.resolve().immutable_identity.startswith(old+':'))

    def test_cross_project_and_denied_source_never_open_git(self):
        other = contracts.participant_scope(OTHER,binding=binding('beta','acme/beta','1002'))
        with patch('uas.library_sources.subprocess.Popen',side_effect=AssertionError('source I/O')):
            self.refusal('SOURCE_SCOPE_REFUSED',scope=other)
            self.allowed=False
            self.refusal('SOURCE_AUTHORITY_REVOKED')
            self.allowed=True; self.fresh=other
            self.refusal('SOURCE_AUTHORITY_REVOKED')
        self.fresh=self.scope
        wrong=self.declaration(); wrong['resource']=wrong['resource'].replace('/acme/alpha/','/acme/beta/')
        with patch('uas.library_sources.subprocess.Popen',side_effect=AssertionError('source I/O')):
            self.refusal('SOURCE_SCOPE_REFUSED',wrong)

    def test_revoked_during_read_discloses_no_result_and_retries_recheck(self):
        original=self.source._git
        def revoke(*args):
            result=original(*args); self.allowed=False; return result
        with patch.object(self.source,'_git',side_effect=revoke):
            self.refusal('SOURCE_AUTHORITY_REVOKED')
        with patch('uas.library_sources.subprocess.Popen',side_effect=AssertionError('read after revoke')):
            self.refusal('SOURCE_AUTHORITY_REVOKED')

    def test_unsupported_file_kinds_and_encoding(self):
        for name,code in [('binary','SOURCE_ENCODING_UNSUPPORTED'),('wrong-encoding','SOURCE_ENCODING_UNSUPPORTED'),
                          ('archive.zip','SOURCE_KIND_UNSUPPORTED'),('hidden-archive','SOURCE_KIND_UNSUPPORTED'),
                          ('tar','SOURCE_KIND_UNSUPPORTED'),('link','SOURCE_KIND_UNSUPPORTED'),
                          ('submodule','SOURCE_KIND_UNSUPPORTED'),('docs','SOURCE_KIND_UNSUPPORTED')]:
            with self.subTest(name=name): self.refusal(code,self.declaration(name,b'a','1-1'))

    def test_limits_reject_whole_document_and_excerpt_without_truncation(self):
        self.refusal('SOURCE_TOO_LARGE',self.declaration('huge',b'x','1-1'))
        changed=deepcopy(self.settings)
        from test_library import document
        config=document();config['limits']['body_bytes']=5
        settings=contracts.admit_settings(io.StringIO(json.dumps(config)))
        self.refusal('SOURCE_TOO_LARGE',settings=settings)
        self.refusal('SOURCE_RANGE_UNAVAILABLE',self.declaration(lines='2-4'))
        self.refusal('SOURCE_RANGE_UNAVAILABLE',self.declaration('empty',b'','1-1'))
        for lines in ['0-1','2-1','1-201','1-2147483648','1-1\n','x','1-'+('9'*100)]:
            value=self.declaration();value['range']=lines
            self.refusal('SOURCE_RANGE_INVALID',value)
        self.refusal('SOURCE_HASH_MISMATCH',self.declaration(raw=b'wrong'))

    def test_unpinned_and_unsafe_paths_refuse_before_io(self):
        for path in ['../secret','docs//note.md','/etc/passwd','docs/%2e%2e/secret','docs/note.md?x=1','-option']:
            with self.subTest(path=path),patch('uas.library_sources.subprocess.Popen',side_effect=AssertionError('I/O')):
                self.refusal('SOURCE_PATH_INVALID',self.declaration(path))
        self.refusal('SOURCE_IMMUTABLE_REQUIRED',self.declaration(commit='main'))
        for resource in ['https://example.test/current.txt','https://example.test/note?sha='+self.commit]:
            value=self.declaration();value['resource']=resource
            self.refusal('SOURCE_IMMUTABLE_REQUIRED',value)
        self.refusal('SOURCE_UNAVAILABLE',self.declaration(commit='a'*40))

    def test_same_identity_stale_epoch_is_not_current_authority(self):
        from dataclasses import replace
        self.fresh=contracts.participant_scope(replace(ORIGIN,authority_version='new-epoch'),binding=binding())
        with patch('uas.library_sources.subprocess.Popen',side_effect=AssertionError('I/O')):
            self.refusal('SOURCE_AUTHORITY_REVOKED')

    def test_no_secret_bytes_in_error_or_metadata(self):
        error=self.refusal('SECRET_DETECTED',self.declaration('secret',b'sk-proj-'+b'x'*30+b'\n','1-1'))
        for value in [str(error),repr(error),json.dumps(getattr(error,'evidence',None))]:
            self.assertNotIn('sk-proj-',value)
        self.assertNotIn('wrong',str(self.refusal('SOURCE_HASH_MISMATCH',self.declaration(raw=b'wrong'))))

    def test_utf8_line_separators_and_unterminated_line_are_exact(self):
        value=self.declaration('unicode',b'one\xe2\x80\xa8two\n','1-1')
        self.assertEqual(self.resolve(value).content,b'one\xe2\x80\xa8two\n')
        self.assertEqual(self.resolve(self.declaration('no-final-newline',b'two','2-2')).content,b'two')

    def test_git_environment_cannot_fetch_or_use_caller_config(self):
        original=subprocess.Popen
        def observed(argv,**kwargs):
            env=kwargs['env']
            self.assertEqual(env['GIT_NO_LAZY_FETCH'],'1')
            self.assertEqual(env['GIT_ALLOW_PROTOCOL'],'')
            self.assertEqual(env['GIT_CONFIG_GLOBAL'],'/dev/null')
            self.assertNotIn('GIT_CONFIG_COUNT',env)
            self.assertNotIn('HOME',env)
            self.assertIn('protocol.allow=never',argv)
            return original(argv,**kwargs)
        with patch.dict(os.environ,{'GIT_CONFIG_COUNT':'99','GIT_SSH_COMMAND':'secret-command'}), \
             patch('uas.library_sources.subprocess.Popen',side_effect=observed):
            self.resolve()

    def test_captured_snapshot_rejects_misleading_paths_before_gate(self):
        raw=b'captured only\n'
        digest=sha(raw)
        bad=[
            '/blob/'+digest+'/note.txt',
            '/prefix/objects/'+digest+'/note.txt',
            '/objects/'+digest,
            '/objects/'+digest.upper()+'/note.txt',
            '/objects/'+digest+'/../note.txt',
            '/objects/'+digest+'/%2e%2e/note.txt',
            '/objects/'+digest+'/a//note.txt',
            '/objects/'+digest+'/note.txt?x=1',
            '/objects/'+digest+'/note.txt#fragment',
        ]
        for path in bad:
            with self.subTest(path=path), patch('uas.library_sources.gate.source',
                                               side_effect=AssertionError('not explicit snapshot')):
                with self.assertRaises(contracts.LibraryError):
                    CapturedSource(project_identity=self.scope.project_identity,
                                   resource='https://evidence.example'+path,content=raw)

    def test_public_gate_snapshot_declaration_is_exact_not_incidental_hash(self):
        from test_library import CommitGateTests, source_entry
        fixture=CommitGateTests()
        _,current=fixture.initial(self.scope)
        digest=sha(b'captured only\n')
        bad=[
            '/prefix/objects/'+digest+'/note.txt',
            '/objects/'+digest+'/../note.txt',
            '/objects/'+digest+'/%2e%2e/note.txt',
            '/objects/'+digest+'/note.txt?x=1',
            '/objects/'+digest+'/note.txt#fragment',
            '/objects/'+digest+'/a//note.txt',
            '/objects/'+digest.upper()+'/note.txt',
            '/objects/'+digest,
        ]
        for path in bad:
            with self.subTest(path=path):
                resource='https://evidence.example'+path
                _,proposed=fixture.update(self.scope,sources=[source_entry(
                    resource,range_='1-1',sha256=digest)])
                with self.assertRaises(contracts.LibraryError):
                    fixture.validate(self.scope,self.settings,proposed,current=current)
        canonical='https://evidence.example/objects/'+digest+'/folder/note.txt'
        self.assertEqual(gate.source(canonical),
                         {'resource':canonical,'kind':'snapshot','pinned':True})

    def test_snapshot_shape_cannot_reclassify_positional_git_artifact(self):
        from test_library import CommitGateTests, source_entry
        raw=b'captured only\n'
        digest=sha(raw)
        fixture=CommitGateTests()
        _,current=fixture.initial(self.scope)
        for keyword in ('blob','raw','tree','src'):
            resource='https://github.com/objects/'+digest+'/'+keyword+'/main/doc.md'
            with self.subTest(keyword=keyword):
                self.assertFalse(gate.source(resource)['pinned'])
                _,proposed=fixture.update(self.scope,sources=[source_entry(
                    resource,range_='1-1',sha256=digest)])
                with self.assertRaises(contracts.LibraryError):
                    fixture.validate(self.scope,self.settings,proposed,current=current)
                with self.assertRaisesRegex(contracts.LibraryError,'SOURCE_IMMUTABLE_REQUIRED'):
                    CapturedSource(project_identity=self.scope.project_identity,
                                   resource=resource,content=raw)
        pinned='https://github.com/objects/'+digest+'/blob/'+('a'*40)+'/doc.md'
        self.assertEqual(gate.source(pinned)['kind'],'artifact')
        with self.assertRaisesRegex(contracts.LibraryError,'SOURCE_IMMUTABLE_REQUIRED'):
            CapturedSource(project_identity=self.scope.project_identity,resource=pinned,content=raw)

    def test_captured_immutable_external_snapshot_and_scope(self):
        raw=b'not selected\nselected external\n'
        resource='https://evidence.example/objects/'+sha(raw)+'/note.txt'
        captured=CapturedSource(project_identity=self.scope.project_identity,resource=resource,content=raw)
        resolver=Resolver(source=captured,current_scope=lambda:self.fresh,source_allowed=lambda scope,ref:self.allowed)
        declaration={'resource':resource,'range':'2-2','sha256':sha(b'selected external\n')}
        # This same source declaration is accepted by T05's shared policy.
        from test_library import CommitGateTests, source_entry
        fixture=CommitGateTests()
        _,current=fixture.initial(self.scope)
        _,proposed=fixture.update(self.scope,sources=[source_entry(resource,range_='2-2',sha256=declaration['sha256'])])
        accepted=fixture.validate(self.scope,self.settings,proposed,current=current)
        self.assertIn('context/pick-sqlite.md',accepted.bundle.added)
        with patch('uas.library_sources.subprocess.Popen',side_effect=AssertionError('no process')):
            result=resolver.resolve(self.scope,self.settings,declaration)
        self.assertEqual(result.content,b'selected external\n')
        self.assertEqual(result.immutable_identity,'sha256:'+sha(raw))
        self.assertNotIn('selected external',repr(captured))
        self.allowed=False
        with self.assertRaisesRegex(contracts.LibraryError,'SOURCE_AUTHORITY_REVOKED'):
            resolver.resolve(self.scope,self.settings,declaration)
        with self.assertRaisesRegex(contracts.LibraryError,'SOURCE_IMMUTABLE_REQUIRED'):
            CapturedSource(project_identity=self.scope.project_identity,resource=resource,content=b'changed')
        with self.assertRaisesRegex(contracts.LibraryError,'SOURCE_IMMUTABLE_REQUIRED'):
            CapturedSource(project_identity=self.scope.project_identity,resource='https://example.test/mutable',content=raw)

    def test_captured_read_revalidates_scope_without_any_filesystem_access(self):
        raw=b'captured only\n'
        resource='https://evidence.example/objects/'+sha(raw)+'/note.txt'
        source=CapturedSource(project_identity=self.scope.project_identity,resource=resource,content=raw)
        resolver=Resolver(source=source,current_scope=lambda:self.fresh,source_allowed=lambda *_:self.allowed)
        value={'resource':resource,'range':'1-1','sha256':sha(raw)}
        with patch('builtins.open',side_effect=AssertionError('file access')), \
             patch('os.open',side_effect=AssertionError('file access')), \
             patch('subprocess.Popen',side_effect=AssertionError('process access')):
            self.assertEqual(resolver.resolve(self.scope,self.settings,value).content,raw)
            self.fresh=contracts.participant_scope(OTHER,binding=binding('beta','acme/beta','1002'))
            with self.assertRaisesRegex(contracts.LibraryError,'SOURCE_AUTHORITY_REVOKED'):
                resolver.resolve(self.scope,self.settings,value)
        source._content=b'changed after capture'
        self.fresh=self.scope
        with self.assertRaisesRegex(contracts.LibraryError,'SOURCE_OBJECT_MISMATCH'):
            resolver.resolve(self.scope,self.settings,value)

    def test_authority_backend_error_is_safe_and_does_not_read_source(self):
        def unavailable(): raise RuntimeError('PRIVATE AUTHORITY ERROR BODY')
        resolver=Resolver(source=self.source,current_scope=unavailable,source_allowed=lambda *_:True)
        with patch('subprocess.Popen',side_effect=AssertionError('I/O')):
            with self.assertRaises(contracts.LibraryError) as error:
                resolver.resolve(self.scope,self.settings,self.declaration())
        self.assertEqual(error.exception.code,'SOURCE_AUTHORITY_UNAVAILABLE')
        self.assertNotIn('PRIVATE',str(error.exception))
        self.assertEqual(error.exception.evidence['source_ref_sha256'],sha(self.declaration()['resource'].encode()))

    def test_bounded_pipe_read_kills_and_reaps_on_excess_or_timeout(self):
        # Exercise the real bounded pipe loop with a deterministic local child,
        # not Docker/a VM or the Git network. The production executable stays fixed.
        original=subprocess.Popen
        processes=[]
        def launch(argv,**kwargs):
            process=original(['/usr/bin/python3','-c',self.program],**kwargs)
            processes.append(process)
            return process
        self.program='import os; os.write(1,b"x"*100); import time; time.sleep(10)'
        with patch('uas.library_sources.subprocess.Popen',side_effect=launch):
            with self.assertRaisesRegex(contracts.LibraryError,'SOURCE_TOO_LARGE'):
                self.source._git(['cat-file','-t',self.commit],8,lambda:None)
        self.assertIsNotNone(processes[-1].poll())
        self.program='import time; time.sleep(10)'
        with patch('uas.library_sources.subprocess.Popen',side_effect=launch), \
             patch('uas.library_sources.READ_SECONDS',.05):
            with self.assertRaisesRegex(contracts.LibraryError,'SOURCE_UNAVAILABLE'):
                self.source._git(['cat-file','-t',self.commit],8,lambda:None)
        self.assertIsNotNone(processes[-1].poll())

    def test_symlink_store_and_replaced_store_refuse(self):
        link=self.root/'source-link'
        link.symlink_to(self.bare,target_is_directory=True)
        self.addCleanup(link.unlink)
        with self.assertRaisesRegex(contracts.LibraryError,'SOURCE_STORE_INVALID'):
            GitSource(link,project_identity=self.scope.project_identity,repository='github.com/acme/alpha')
        self.source.identity=(0,0)
        with patch('subprocess.Popen',side_effect=AssertionError('I/O')):
            self.refusal('SOURCE_STORE_CHANGED')

    def test_malformed_unicode_is_a_safe_contract_failure(self):
        for resource in ['https://example.test/objects/'+('a'*64)+'/bad\ud800', '\ud800']:
            value=self.declaration();value['resource']=resource
            with patch('subprocess.Popen',side_effect=AssertionError('I/O')):
                self.refusal('SOURCE_DECLARATION_INVALID',value)
            with self.assertRaisesRegex(contracts.LibraryError,'SOURCE_DECLARATION_INVALID'):
                CapturedSource(project_identity=self.scope.project_identity,resource=resource,content=b'a')

    def test_nonbare_store_is_not_treated_as_source_clone(self):
        source=GitSource(self.work,project_identity=self.scope.project_identity,repository='github.com/acme/alpha')
        resolver=Resolver(source=source,current_scope=lambda:self.scope,source_allowed=lambda *_:True)
        with self.assertRaisesRegex(contracts.LibraryError,'SOURCE_UNAVAILABLE'):
            resolver.resolve(self.scope,self.settings,self.declaration())

    def test_missing_file_failure_does_not_echo_path(self):
        error=self.refusal('SOURCE_UNAVAILABLE',self.declaration('private-absent-name',b'a','1-1'))
        self.assertNotIn('private-absent-name',str(error))


if __name__ == '__main__': unittest.main()
