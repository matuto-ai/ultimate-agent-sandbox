"""Real route/facade/provider composition with pure account-free responses."""
import base64
import unittest
from uas.forge_read_provider import BrokerReadProvider
from uas.github_read import GitHubProject, ProviderFailure
from uas.github_routes import parse_read_route
from test_github_surface import R, run, job, response
from test_github_logs import log_stream

class ReadProviderIntegration(unittest.TestCase):
    def setUp(self):self.calls=[];self.logs=[];self.project=GitHubProject(R)
    def transport(self,path):
        self.calls.append(path)
        value=job();value.pop('run_attempt',None)
        if path.endswith('/actions/jobs/9'):return response(value)
        if '/jobs?' in path:
            return response({'total_count':0,'jobs':[]} if '/attempts/3/' in path else {'total_count':1,'jobs':[value]})
        if path.endswith('/attempts/2'):return response(run(attempt=2))
        if path.endswith('/actions/runs/8'):return response(run(attempt=3))
        raise AssertionError(path)
    def log(self,path):self.logs.append(path);return log_stream(b'completed fixture log')
    def test_job_only_log_finds_its_historical_attempt_not_latest_run(self):
        provider=BrokerReadProvider(self.project,self.transport,self.log)
        result=provider.read(parse_read_route(['run','view','--job','9','--log'],self.project))
        self.assertEqual('OK',result['status'],result);self.assertEqual(2,result['attempt'])
        self.assertEqual(b'completed fixture log',base64.b64decode(result['tail']))
        self.assertEqual([f'repos/{R}/actions/jobs/9/logs'],self.logs)
    def test_failed_metadata_preserves_literal_not_found_and_no_log_contact(self):
        provider=BrokerReadProvider(self.project,lambda _:response({},404),self.log)
        result=provider.read(parse_read_route(['run','view','--job','9','--log'],self.project))
        self.assertEqual({'status':'NOT_FOUND','completeness':'unknown'},result);self.assertFalse(self.logs)
    def test_timeout_or_missing_actor_credentials_never_becomes_scope_error(self):
        for code in ['TIMEOUT','CREDENTIAL_UNAVAILABLE']:
            def fail(_):raise ProviderFailure(code)
            provider=BrokerReadProvider(self.project,fail,self.log)
            result=provider.read(parse_read_route(['run','view','--job','9','--log'],self.project))
            self.assertEqual(code,result['status']);self.assertFalse(self.logs)
