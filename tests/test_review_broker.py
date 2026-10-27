"""Controlled in-memory provider and temporary SQLite tests; no native I/O."""
from contextlib import nullcontext
from copy import deepcopy
from pathlib import Path
import json
import tempfile
import unittest
from types import SimpleNamespace

from uas.forge import ForgeBinding
from uas.forge_audit import ForgeAudit
from uas.forge_mutations import ExternalMutationBroker
from uas.forge_read import ExternalReadBroker
from uas.forge_read_provider import BrokerReadProvider
from uas.forge_read_service import ReadBrokerClient, ReviewBrokerClient
from uas.github_mutations import GitHubMutationProvider
from uas.github_read import GitHubProject
from uas.ledger import LedgerError, Origin
from uas.review_broker import BrokerReviewState, ExternalReviewBroker, review_origin, validate_review_observation
from test_github_surface import pull, review, response, R, HEAD, SHA, API
from test_github_mutations import MemoryGitHub

TARGET = {'repository': R, 'pull_number': 42, 'pull_id': 2042,
          'head_sha': HEAD, 'base_sha': SHA, 'base_ref': 'main'}


class Fixture:
    def __init__(self):
        self.pull, self.reviews = pull(), [review()]
        self.calls = []
        self.parents = [SHA, HEAD]
        self.before = None
    def __call__(self, path):
        self.calls.append(path)
        if self.before:
            value = self.before(path)
            if value is not None: return value
        base = 'repos/' + R
        if path == base + '/pulls/42': return response(self.pull)
        if path.startswith(base + '/pulls/42/reviews?'): return response(self.reviews)
        if path == base + '/commits/' + 'c'*40:
            return response({'sha': 'c'*40, 'url': API + '/commits/' + 'c'*40,
                             'parents': [{'sha': sha} for sha in self.parents]})
        raise AssertionError(path)
    def merge(self, actor_type='User'):
        self.pull.update(state='closed', merged=True, merged_by={'id': 81, 'type': actor_type, 'login': 'not-authority'})


class ReviewObservationTests(unittest.TestCase):
    def setUp(self): self.fixture = Fixture()
    def observe(self): return BrokerReviewState(GitHubProject(R), self.fixture).observe(TARGET)
    def test_normalizes_without_prose_and_keeps_exact_review_commit(self):
        result = self.observe()
        self.assertEqual('OK', result['status'])
        self.assertEqual(HEAD, result['reviews'][0]['commit_id'])
        self.assertNotIn('body', result['reviews'][0])
        self.assertIsNone(result['merge'])
        self.assertEqual(result, validate_review_observation(result, TARGET))
    def test_exact_human_merge_and_advanced_base(self):
        self.fixture.merge()
        self.fixture.pull['base']['sha'] = 'c'*40
        result = self.observe()
        self.assertEqual('OK', result['status'])
        self.assertEqual({'merger_id':81,'merger_type':'User','integration_sha':'c'*40,'method':'merge'}, result['merge'])
    def test_bot_is_not_renamed_human(self):
        self.fixture.merge('Bot')
        self.assertEqual('Bot', self.observe()['merge']['merger_type'])
    def test_unknown_type_squash_and_wrong_parent_fail_closed(self):
        self.fixture.merge('App')
        self.assertEqual('UNKNOWN_MERGER', self.observe()['status'])
        self.fixture.merge()
        for parents in ([SHA], [HEAD, SHA], ['d'*40, HEAD]):
            self.fixture.parents = parents
            self.assertEqual('UNSUPPORTED_MERGE_METHOD', self.observe()['status'])
    def test_mutating_head_or_merger_fails(self):
        self.fixture.pull['head']['sha'] = 'd'*40
        self.assertEqual('STALE_PULL', self.observe()['status'])
        self.fixture.pull = pull(); self.fixture.merge()
        count = 0
        def mutate(path):
            nonlocal count
            if path.endswith('/pulls/42'):
                count += 1
                if count == 2: self.fixture.pull['merged_by']['id'] = 82
        self.fixture.before = mutate
        self.assertEqual('STALE_PULL', self.observe()['status'])
    def test_duplicate_and_incomplete_reviews_fail_closed(self):
        self.fixture.reviews *= 2
        self.assertNotEqual('OK', self.observe()['status'])
        self.fixture.reviews = []
        self.fixture.before = lambda path: response([], headers={'link':'<ignored>; rel="next"'}) if '/reviews?' in path else None
        self.assertNotEqual('OK', self.observe()['status'])
        self.assertLessEqual(len(self.fixture.calls), 15)
    def test_forged_observation_schema_rejected(self):
        value = self.observe(); value['target']['head_sha'] = 'd'*40
        with self.assertRaises(LedgerError): validate_review_observation(value, TARGET)


class ReviewOwnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.audit = ForgeAudit(Path(self.temp.name)/'audit.db', 'deployment-a'); self.addCleanup(self.audit.close)
        self.fixture = Fixture()
        self.binding = ForgeBinding('room-a', 'project-a', R)
        self.provider = BrokerReadProvider(GitHubProject(R), self.fixture, None)
        self.mutations = ExternalMutationBroker(self.binding, 'instance-a', self.audit, {'actor-a':41}, lambda _: None)
        self.broker = ExternalReviewBroker(self.binding, 'instance-a', self.audit, 'actor-a', lambda _: self.provider, self.mutations)
    def execute(self, envelope, **kwargs):
        return self.broker.execute(envelope, origin=kwargs.get('origin', review_origin('instance-a')),
                                   authorize=kwargs.get('authorize', lambda:True))
    def test_audit_duplicate_does_not_read_again(self):
        envelope = {'id':'observe-a','kind':'review-observe','target':TARGET}
        first = self.execute(envelope); count = len(self.fixture.calls)
        self.assertEqual('OK', first['observation']['status'])
        self.assertEqual('INTERRUPTED_OBSERVATION', self.execute(envelope)['observation']['status'])
        self.assertEqual(count,len(self.fixture.calls))
        altered = deepcopy(envelope); altered['target']['head_sha']='d'*40
        with self.assertRaises(LedgerError): self.execute(altered)
    def test_caller_cannot_select_actor_or_origin(self):
        envelope = {'id':'observe-a','kind':'review-observe','target':TARGET}
        with self.assertRaises(LedgerError): self.execute(envelope, origin=Origin('actor-a','p','instance-a','hub-review-v1',('forge-review',)))
        with self.assertRaises(LedgerError): self.execute({**envelope,'actor':'actor-a'})
        with self.assertRaises(LedgerError): self.execute(envelope,authorize=lambda:False)
        self.assertEqual([],self.fixture.calls)
    def test_authority_revoked_during_observation_prevents_disclosure(self):
        active=True
        def revoke(path):
            nonlocal active
            active=False
        self.fixture.before=revoke
        with self.assertRaises(LedgerError):
            self.execute({'id':'read','kind':'review-observe','target':TARGET},authorize=lambda:active)
        self.assertEqual(1,len(self.fixture.calls))
    def test_private_dispatch_routes_to_review_owner(self):
        broker = ExternalReadBroker(self.binding,'instance-a',self.audit,lambda _:self.provider,Path(self.temp.name)/'results',reviews=self.broker)
        result = broker.execute({'id':'observe-a','kind':'review-observe','target':TARGET},origin=review_origin('instance-a'),authorize=lambda:True)
        self.assertEqual('OK',result['observation']['status'])
    def test_client_uses_authenticated_transport_and_exact_receipt(self):
        client = object.__new__(ReadBrokerClient)
        client.review_enabled=True;client.binding=self.binding;client.room_instance='instance-a'
        client.supervisor=SimpleNamespace(_locked=lambda:nullcontext(),_read=lambda:{'phase':'running','instance_id':'instance-a'})
        def prepare(envelope,origin,authorize): return envelope,origin,authorize
        client.prepare=prepare
        client.perform=lambda packet:self.broker.execute(packet[0],origin=packet[1],authorize=packet[2])
        adapter=ReviewBrokerClient(client)
        self.assertEqual('OK',adapter.observe(TARGET,'observe-a',authorize=lambda:True)['observation']['status'])


class CommentFixture(MemoryGitHub):
    def __init__(self):
        super().__init__()
        self.pulls[3] = pull(3, self.repository)
        self.pulls[3]['user'] = {'id':41,'login':'alice'}
        self.comments=[];self.lose=False
    def __call__(self, method, path, body=None):
        if method=='GET' and path.startswith(self.base+'/issues/3/comments?'):
            self.calls.append((method,path,None));return response(self.comments)
        result=super().__call__(method,path,body)
        if method=='POST' and path==self.base+'/issues/3/comments':
            value=json.loads(result.body)
            value['url']=self.api+'/issues/comments/'+str(value['id'])
            self.comments.append(value)
            if self.lose: raise OSError('simulated response loss')
        return result
    def read(self,path):
        if path.startswith(self.base+'/pulls/3/reviews?'): return response([])
        return self('GET',path)


class ReviewCommentTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.audit=ForgeAudit(Path(self.temp.name)/'audit.db','deployment-a');self.addCleanup(self.audit.close)
        self.fixture=CommentFixture();self.binding=ForgeBinding('room-a','project-a','owner/repo')
        self.target={**TARGET,'repository':'owner/repo','pull_number':3,'pull_id':2003}
        self.provider=BrokerReadProvider(GitHubProject('owner/repo'),self.fixture.read,None)
        mutations=ExternalMutationBroker(self.binding,'instance-a',self.audit,{'actor-a':41},lambda _:GitHubMutationProvider(GitHubProject('owner/repo'),self.fixture))
        self.broker=ExternalReviewBroker(self.binding,'instance-a',self.audit,'actor-a',lambda _:self.provider,mutations)
    def execute(self, kind='review-comment', body='Please change this',target=None,**attempt):
        return self.broker.execute({'id':'human-change','kind':kind,'target':target or self.target,'body':body,**attempt},origin=review_origin('instance-a'),authorize=lambda:True)
    def test_confirmed_comment_and_replay_are_one_write(self):
        first=self.execute()
        self.assertEqual('confirmed',first['status'])
        self.assertEqual(first,self.execute())
        self.assertEqual(1,len(self.fixture.effects))
        self.assertEqual('https://github.com/owner/repo/pull/3#issuecomment-701',first['comment_reference']['url'])
    def test_unknown_response_reconciles_no_second_post(self):
        self.fixture.lose=True
        self.assertEqual('unknown',self.execute()['status'])
        self.assertEqual('unknown',self.execute()['status'])
        self.assertEqual('confirmed',self.execute('review-reconcile')['status'])
        self.assertEqual(1,len(self.fixture.effects))
    def test_changed_body_target_and_stale_head_do_not_write(self):
        self.execute()
        with self.assertRaises(LedgerError): self.execute(body='other')
        with self.assertRaises(LedgerError): self.execute(target={**self.target,'head_sha':'d'*40})
        self.assertEqual(1,len(self.fixture.effects))
    def test_crash_before_dispatch_absent_journal_allows_same_write_resume(self):
        # Hub intent may exist, but no Broker dispatch or provider contact did.
        absent=self.execute('review-reconcile',reconciliation_id='absence-a')
        self.assertEqual('error',absent['status'])
        self.assertEqual(absent,self.execute('review-reconcile',reconciliation_id='absence-a'))
        self.assertEqual([],self.fixture.calls)
        self.assertEqual('review-mutation-absence',self.audit.read_record(absent['audit_reference'])['metadata']['route'])
        self.assertEqual('confirmed',self.execute(preflight_id='resume-a')['status'])
        self.assertEqual(1,len(self.fixture.effects))
        # Old absence cannot bypass a journal that now exists.
        self.assertEqual('confirmed',self.execute('review-reconcile',reconciliation_id='absence-a')['status'])
        self.assertEqual(1,len(self.fixture.effects))
    def test_explicit_new_preflight_attempt_recovers_without_changing_write(self):
        self.fixture.before=lambda method,path,body: response({},503) if path.endswith('/pulls/3') else None
        first=self.execute(preflight_id='preflight-a')
        self.assertEqual('error',first['status'])
        from uas.forge_mutations import digest
        key='mutation-'+digest([self.binding.room_id,'instance-a','human-change'])
        self.assertIsNone(self.audit.get_mutation(key))
        self.fixture.before=None
        self.assertEqual('error',self.execute(preflight_id='preflight-a')['status'])
        self.assertEqual('confirmed',self.execute(preflight_id='preflight-b')['status'])
        self.assertEqual(1,len(self.fixture.effects))
        self.assertEqual('confirmed',self.execute(preflight_id='preflight-c')['status'])
        self.assertEqual(1,len(self.fixture.effects))
    def test_explicit_new_reconciliation_attempt_recovers_without_post(self):
        self.fixture.lose=True
        self.assertEqual('unknown',self.execute()['status'])
        self.fixture.before=lambda method,path,body: response({},503) if path=='user' else None
        self.assertEqual('unknown',self.execute('review-reconcile',reconciliation_id='reconcile-a')['status'])
        self.fixture.before=None
        self.assertEqual('unknown',self.execute('review-reconcile',reconciliation_id='reconcile-a')['status'])
        self.assertEqual('confirmed',self.execute('review-reconcile',reconciliation_id='reconcile-b')['status'])
        self.assertEqual(1,len(self.fixture.effects))
    def test_changed_head_between_preflight_and_mutation_is_blocked(self):
        count=0
        def move(method,path,body):
            nonlocal count
            if method=='GET' and path==self.fixture.base+'/pulls/3':
                count+=1
                if count==3: self.fixture.pulls[3]['head']['sha']='d'*40
        self.fixture.before=move
        self.assertEqual('unknown',self.execute()['status'])
        self.assertEqual([],self.fixture.effects)
    def test_unknown_comment_reopen_preserves_no_duplicate(self):
        self.fixture.lose=True
        first=self.execute()
        self.assertEqual('unknown',first['status'])
        self.audit.close()
        self.audit=ForgeAudit(Path(self.temp.name)/'audit.db','deployment-a')
        self.addCleanup(self.audit.close)
        mutations=ExternalMutationBroker(self.binding,'instance-a',self.audit,{'actor-a':41},lambda _:GitHubMutationProvider(GitHubProject('owner/repo'),self.fixture))
        self.broker=ExternalReviewBroker(self.binding,'instance-a',self.audit,'actor-a',lambda _:self.provider,mutations)
        self.assertEqual(first,self.execute())
        self.assertEqual('confirmed',self.execute('review-reconcile')['status'])
        self.assertEqual(1,len(self.fixture.effects))
    def test_closed_or_stale_pull_blocks_initial_comment(self):
        self.fixture.pulls[3]['head']['sha']='d'*40
        self.assertEqual('error',self.execute()['status'])
        self.assertEqual([],self.fixture.effects)
