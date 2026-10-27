"""Pure executor assertions; every process/kernel call is replaced."""
import hashlib
import signal
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_github_executor import Process, Poll
from uas.github_executor import GhSurfaceTransport
from uas.github_read import ProviderFailure


class MutationTransportTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        path=Path(self.temp.name)/'fixed';path.write_bytes(b'pin');path.chmod(0o555)
        self.transport=GhSurfaceTransport(path,hashlib.sha256(b'pin').hexdigest(),'actor',lambda *_:{'GH_TOKEN':'secret'})
        self.addCleanup(self.transport.close)

    def test_body_stdin_not_argv_clean_environment_and_fixed_post(self):
        process=Process();captured={}
        def launch(command,**kwargs):
            captured.update(command=command,**kwargs)
            captured['body']=kwargs['stdin'].read()
            return process
        with patch('uas.github_executor.subprocess.Popen',side_effect=launch), \
             patch('uas.github_executor.selectors.DefaultSelector',Poll), \
             patch('uas.github_executor.os.read',side_effect=[b'HTTP/2.0 201 Created\n\r\n{}',b'']), \
             patch('uas.github_executor.signal.getsignal',return_value=signal.SIG_DFL), \
             patch('uas.github_executor.os.waitid',return_value=SimpleNamespace(si_pid=999999)), \
             patch('uas.github_executor.os.killpg'):
            response=self.transport.mutate('POST','repos/owner/repo/issues',{'body':'private body'},repository='owner/repo')
        self.assertEqual(201,response.status)
        self.assertEqual(b'{"body":"private body"}',captured['body'])
        self.assertNotIn('private body',' '.join(captured['command']))
        self.assertEqual(['--input','-'],captured['command'][-2:])
        self.assertEqual('POST',captured['command'][6-1])
        self.assertNotIn('PATH',captured['env'])
        self.assertFalse(captured['shell'])

    def test_full_escaped_body_is_transported_but_oversize_raw_body_never_launches(self):
        import json
        from uas.github_mutation_routes import parse_mutation_route
        from uas.github_read import GitHubProject
        for char in ('"','\\','\n'):
            body=char*524287+'x'
            route=parse_mutation_route(['issue','comment','1','--body-file','-'],GitHubProject('owner/repo'),body=body)
            with patch.object(self.transport,'_execute',return_value='sent') as execute:
                self.assertEqual('sent',self.transport.mutate('POST','repos/owner/repo/issues/1/comments',
                    {'body':route.options['body']},repository='owner/repo'))
                encoded=execute.call_args.args[2]
                self.assertEqual(body,json.loads(encoded)['body'])
                self.assertGreater(len(encoded),1048576)
            with patch.object(self.transport,'_execute') as execute,self.assertRaises(ProviderFailure):
                self.transport.mutate('POST','repos/owner/repo/issues/1/comments',{'body':body+'x'},repository='owner/repo')
            execute.assert_not_called()

    def test_mutation_whitelist_rejects_cross_repo_merge_and_arbitrary_endpoint(self):
        with patch('uas.github_executor.subprocess.Popen') as launch:
            for method,path in [('POST','repos/other/repo/issues'),('PUT','repos/owner/repo/pulls/3/merge'),
                                ('POST','https://evil.invalid'),('DELETE','repos/owner/repo'),
                                ('POST','repos/owner/repo/actions/workflows/1/dispatches'),
                                ('DELETE','repos/owner/repo/issues/1/labels/..')]:
                with self.subTest(path=path),self.assertRaises(ProviderFailure):
                    self.transport.mutate(method,path,{},repository='owner/repo')
            launch.assert_not_called()
