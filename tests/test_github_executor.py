"""Pure external-executor construction/response checks; no child executes."""
import hashlib
import io
import json
import os
import signal
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from uas.forge_read_service import ActorCredentialFile
from uas.github_executor import GhSurfaceTransport
from uas.github_read import ProviderFailure
from uas.ledger import LedgerError

class Pipe(io.BytesIO):
    def fileno(self):return 23
class Process:
    def __init__(self):self.stdout=Pipe();self.returncode=None;self.pid=999999
    def poll(self):return 0
    def wait(self,timeout=None):self.returncode=0;return 0
class Poll:
    def __init__(self):self.active=False
    def __enter__(self):return self
    def __exit__(self,*_):pass
    def register(self,file,events):self.file=file;self.active=True
    def get_map(self):return {23:True} if self.active else {}
    def select(self,timeout):return [(SimpleNamespace(fileobj=self.file),1)]
    def unregister(self,file):self.active=False

class ExecutorTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.path=self.root/'gh';self.path.write_bytes(b'fixed executable test bytes');self.path.chmod(0o555)
        self.pin=hashlib.sha256(self.path.read_bytes()).hexdigest();self.lookups=[]
    def transport(self):
        def credentials(actor,host):self.lookups.append((actor,host));return {'GH_TOKEN':'SECRET_TOKEN'}
        value=GhSurfaceTransport(self.path,self.pin,'actor-a',credentials);self.addCleanup(value.close);return value
    def execute(self, transport, path, response=b'HTTP/2.0 200 OK\nContent-Type: application/json\r\n\r\n{}',
                *,wait_effect=None,wait_error=None,**kwargs):
        self.process=Process()
        if wait_error is not None:
            def interrupted_wait(**_):
                self.process.returncode=0  # Child was reaped before interruption.
                raise wait_error
            self.process.wait=Mock(side_effect=interrupted_wait)
        with patch('uas.github_executor.subprocess.Popen',return_value=self.process) as launch, \
             patch('uas.github_executor.selectors.DefaultSelector',Poll), \
             patch('uas.github_executor.os.read',side_effect=[response,b'']), \
             patch('uas.github_executor.signal.getsignal',return_value=signal.SIG_DFL), \
             patch('uas.github_executor.os.waitid',return_value=SimpleNamespace(si_pid=999999),side_effect=wait_effect), \
             patch('uas.github_executor.os.killpg') as kill:
            self.launch=launch;self.kill=kill
            value=transport.get(path,**kwargs)
        return value
    def test_exact_external_actor_clean_env_pinned_fd_no_shell(self):
        transport=self.transport();self.execute(transport,'repos/other/repo/pulls/42')
        args,kw=self.launch.call_args
        self.assertEqual(f'/proc/self/fd/{transport.fd}',args[0][0])
        self.assertEqual((transport.fd,),kw['pass_fds']);self.assertIs(False,kw['shell'])
        self.kill.assert_called_once()
        self.assertEqual([('actor-a','github.com')],self.lookups)
        self.assertEqual('SECRET_TOKEN',kw['env']['GH_TOKEN'])
        self.assertNotIn('PATH',kw['env']);self.assertNotIn('SSH_AUTH_SOCK',kw['env'])
        self.assertNotIn('SECRET_TOKEN',' '.join(args[0]));self.assertFalse(Path(kw['cwd']).exists())
    def test_raw_diff_uses_only_fixed_accept_with_internal_endpoint(self):
        value=self.execute(self.transport(),'repos/owner/repo/pulls/42',accept='application/vnd.github.diff',
                           response=b'HTTP/2.0 200 OK\n\r\ndiff --git a/x b/x\n')
        self.assertTrue(value.body.startswith(b'diff'));self.assertIn('Accept: application/vnd.github.diff',self.launch.call_args.args[0])
    def test_source_faithful_gh_status_lf_headers_crlf_and_literal_404(self):
        # cli/cli v2.87.3 pkg/cmd/api/api.go:420-424,540-555.
        value=self.execute(self.transport(),'repos/other/repo',response=(
            b'HTTP/2.0 404 Not Found\nContent-Type: application/json\r\n'
            b'Link: <https://api.github.com/repos/other/repo?page=2>; rel="next"\r\n\r\n'
            b'{"message":"Not Found"}'))
        self.assertEqual(404,value.status);self.assertIn('rel="next"',value.headers['link'])
        self.assertEqual(b'{"message":"Not Found"}',value.body)
        with self.assertRaises(ProviderFailure):
            self.execute(self.transport(),'repos/other/repo',response=(
                b'HTTP/2.0 200 OK\nContent-Type: application/json\nBroken: x\r\n\r\n{}'))
    def test_echild_never_signals_released_numeric_identity_and_fences(self):
        for effect in (ChildProcessError(),[SimpleNamespace(si_pid=999999),ChildProcessError()]):
            transport=self.transport()
            with self.assertRaises(ProviderFailure):
                self.execute(transport,'repos/owner/repo',wait_effect=effect)
            self.kill.assert_not_called();self.assertTrue(transport.failed)
            with self.assertRaises(ProviderFailure),patch('uas.github_executor.subprocess.Popen') as launch:
                transport.get('repos/owner/repo')
            launch.assert_not_called()
    def test_wait_that_reaps_then_interrupts_never_retries_numeric_signal(self):
        transport=self.transport()
        with self.assertRaises(ProviderFailure):
            self.execute(transport,'repos/owner/repo',wait_error=KeyboardInterrupt())
        self.kill.assert_called_once();self.process.wait.assert_called_once()
        self.assertTrue(transport.failed)
    def test_auto_reap_disposition_refuses_before_spawn(self):
        with patch('uas.github_executor.signal.getsignal',return_value=signal.SIG_IGN), \
             patch('uas.github_executor.subprocess.Popen') as launch:
            with self.assertRaises(ProviderFailure):self.transport().get('repos/owner/repo')
        launch.assert_not_called()
    def test_path_replacement_keeps_pinned_inode_and_mutation_refuses(self):
        transport=self.transport();old=transport.identity
        self.path.rename(self.root/'old');self.path.write_bytes(b'other');self.path.chmod(0o555)
        self.execute(transport,'repos/owner/repo');self.assertEqual(old,transport.identity)
        oldpath=self.root/'old';oldpath.chmod(0o755);oldpath.write_bytes(b'mutated')
        with self.assertRaises(ProviderFailure):self.execute(transport,'repos/owner/repo')
    def test_host_shell_logs_api_and_unknown_query_never_spawn(self):
        transport=self.transport()
        for path in ['https://evil.test','user/tokens','repos/owner/repo/actions/jobs/4/logs',
                     'repos/owner/repo?secret=yes','repos/owner/repo?ref=x&ref=y',
                     'repos/owner/repo/contents/../secret','repos/owner/repo;id']:
            with self.subTest(path=path),patch('uas.github_executor.subprocess.Popen') as launch:
                with self.assertRaises((ProviderFailure,ValueError)):transport.get(path)
                launch.assert_not_called()
    def test_user_and_encoded_branch_are_allowed_only_internal_reads(self):
        transport=self.transport()
        for path in ['user','repos/owner/repo/commits/feature%2Ftopic',
                     'repos/owner/repo/issues?state=open&assignee=actor-a&per_page=100&page=1',
                     'repos/owner/repo/commits/'+'a'*40+'/check-runs?filter=all&per_page=100&page=1']:
            self.assertEqual(200,self.execute(transport,path).status)
    def test_credential_file_exact_actor_host_modes_no_environment_fallback(self):
        path=self.root/'credentials';path.write_text(json.dumps({'github.com':{'actor-a':'secret-a'}}));path.chmod(0o600)
        source=ActorCredentialFile(path);self.assertEqual({'GH_TOKEN':'secret-a'},source('actor-a','github.com'))
        for actor,host in [('actor-b','github.com'),('actor-a','evil.test')]:
            with patch.dict(os.environ,{'GH_TOKEN':'ambient-secret'}),self.assertRaises(ProviderFailure):source(actor,host)
        path.chmod(0o644)
        with self.assertRaises(ProviderFailure):source('actor-a','github.com')
    def test_nonexecutable_writable_symlink_or_wrong_pin_rejected(self):
        for mode in (0o644,0o777):
            self.path.chmod(mode)
            with self.assertRaises(LedgerError):self.transport()
        self.path.chmod(0o555);self.pin='f'*64
        with self.assertRaises(ProviderFailure):self.transport()
