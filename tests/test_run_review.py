"""Pure Room ledger and existing peer outbox; explicit controlled external facts."""
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from uas.ledger import RoomLedger, Origin, Command, Event, Transition, LedgerError
from uas.peer import FixturePeerHub, FixtureParticipant, Readiness, RequestCommand, digest
from uas.gate_hub import _run_dependency_digest, _contribution_digest
from uas.gate_evaluation import _digest
from uas.run_review import RunReview

BUILDER = Origin('builder', 'builder-seat', 'inc', 'epoch', ('peer-traffic', 'implement'))
REVIEWER = Origin('reviewer', 'review-seat', 'inc', 'epoch', ('peer-traffic', 'review'))
HUMAN = Origin('human', 'human-seat', 'inc', 'human-epoch', ('human-control-run',))
TARGET = {'repository':'owner/repo', 'pull_number':3, 'pull_id':33,
          'head_sha':'a'*40, 'base_sha':'b'*40, 'base_ref':'main'}
URL = 'https://github.com/owner/repo/pull/3#pullrequestreview-'


class Identity:
    def __init__(self):
        self.contributors = ['builder']; self.active = True; self.depth = 0
        self.dispatcher=SimpleNamespace(reviewer_authority=lambda seat,run,generation:REVIEWER)
    @contextmanager
    def operation_fence(self, operation):
        self.depth += 1
        try: yield
        finally: self.depth -= 1
    def read_identity(self, run, actor, head, epoch):
        assert self.depth
        return {'actor_id':actor,'kind':'participant','active':self.active,'authority_epoch':'epoch',
                'capabilities':['review'],'contributors':self.contributors,
                'contribution_version':'known-1','history_status':'read'}


class Gates:
    def __init__(self, ledger, identity): self.ledger=ledger; self.identity=identity; self.passed=True
    def operation_gates(self, run_id, generation, operation, *, origin):
        state=self.ledger.snapshot()['state']; run=state['runs'][run_id]
        return {'operation':operation,'run_id':run_id,'generation':generation,'gates_satisfied':self.passed,
                'blockers':[] if self.passed else ['failed'], 'gates':[{'gate_id':'checks','state':'passed','evaluation_id':'eval'}],
                'policy_digest':_digest(run['policy']),'run_dependency_digest':_run_dependency_digest(run),
                'contribution_digest':_contribution_digest(state,run_id)}


class Broker:
    def __init__(self):
        self.calls=[]; self.reviews=[]; self.merged=False; self.who=7; self.kind='User'; self.status='OK'
        self.comment_status='confirmed'; self.receipts={}; self.head='a'*40; self.crash=False
    def observe(self,target,operation_id,*,authorize):
        assert authorize()
        if operation_id in self.receipts: return deepcopy(self.receipts[operation_id])
        self.calls.append(('observe',operation_id))
        if self.crash: raise RuntimeError('injected crash after durable external attempt')
        pull={'id':33,'number':3,'head':{'sha':self.head},'base':{'sha':'b'*40,'ref':'main','repo':{'full_name':'owner/repo'}},
              'draft':False,'merged':self.merged,'state':'closed' if self.merged else 'open','merge_commit_sha':'c'*40 if self.merged else None}
        value={'audit_reference':operation_id,'observation':{'status':self.status,'completeness':'complete',
            'target':deepcopy(target),'pull':pull,'reviews':deepcopy(self.reviews),
            'merge':{'merger_id':self.who,'merger_type':self.kind,'integration_sha':'c'*40,'method':'merge'} if self.merged else None}}
        self.receipts[operation_id]=value; return deepcopy(value)
    def comment(self,target,body,operation_id,*,authorize,preflight_id=None):
        assert authorize(); self.calls.append(('comment',operation_id)); return self.comment_receipt(operation_id)
    def reconcile_comment(self,target,body,operation_id,*,authorize,reconciliation_id=None):
        assert authorize(); self.calls.append(('reconcile',operation_id)); return self.comment_receipt(operation_id)
    def comment_receipt(self, op):
        return {'status':self.comment_status,'audit_reference':'comment-'+op,
            'comment_reference':{'kind':'comment','id':44,'url':'https://github.com/owner/repo/pull/3#issuecomment-44'}
                                if self.comment_status=='confirmed' else None}


class RunReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'room.db'; self.ledger=RoomLedger(self.path,'room'); self.addCleanup(self.ledger.close)
        self.peer=FixturePeerHub(self.ledger)
        self.peer.configure('configure',(FixtureParticipant('builder-seat','builder'),FixtureParticipant('review-seat','reviewer')),'run')
        self.n=0; self.allowed=True; self.identity=Identity(); self.gates=Gates(self.ledger,self.identity); self.broker=Broker()
        self.run={'run_id':'run','generation':1,'status':'ACTIVE','project_id':'project','repository':'owner/repo',
            'participant_id':'builder-seat','actor_id':'builder','checkout':{'slot':'main','branch':'refs/heads/work'},
            'gate_target':deepcopy(TARGET),'gate_target_binding':'binding',
            'policy':{'protected_operations':{'submit-for-review':['checks'],'complete':['checks']}}}
        self.seed(lambda state:state.update(runs={'run':deepcopy(self.run)},gate_evaluations={'eval':{
            'evaluation_id':'eval','scope':{'run_id':'run','gate_id':'checks'},'origin':{'actor_id':'builder'},
            'started':{'sequence':1},'result':{'verdict':'passed'}}}))
        self.construct()
        self.connection=self.peer.connect('connect-review','review-seat','inc',object())
        self.builder_connection=self.peer.connect('connect-builder','builder-seat','inc',object())
    @contextmanager
    def fence(self): yield
    def construct(self):
        self.owner=RunReview(self.ledger,self.gates,self.identity,self.broker,
            reviewers=[{'actor_id':'reviewer','participant_id':'review-seat','github_user_id':8}],
            target_fence=self.fence,authorize_human=lambda o:o==HUMAN,human_mergers=[7])
    def seed(self, mutate):
        self.n+=1
        def decide(state,_): mutate(state); return Transition(state,(Event('test.seed',{}),),{})
        self.ledger.apply(Command('seed-'+str(self.n),'test.seed','run',None,{}),HUMAN,authorize=lambda *_:True,decide=decide)
    def call(self, kind, op, payload, origin=BUILDER):
        return self.owner.submit({'id':op,'kind':kind,'run_id':'run','generation':1,'payload':payload},origin=origin,
                                 authorize=lambda:self.allowed,admission_operation='admission')
    def submit(self, op='submit'):
        review=self.state().get('run_reviews',{}).get('run',{}).get('current')
        request_id=review.get('implementation_request') if review else None
        if request_id and self.state()['peer_traffic']['traffic'][request_id]['status']=='QUEUED':
            self.deliver_accept(self.builder_connection,request_id,'implementation-'+op)
        return self.call('submit-for-review',op,{'target':deepcopy(TARGET),'evidence':['evidence:tests']})
    def deliver_accept(self, connection, request_id, operation):
        self.peer.observe(connection,Readiness.SAFE)
        offer=self.peer.prepare_delivery(connection,traffic_id=request_id); envelope=offer.envelope
        receipt={key:envelope[key] for key in ('delivery_id','participant_id','incarnation_id','context_generation')}
        receipt['digest']=digest(envelope); self.peer.confirm_delivery(connection,offer,receipt)
        self.peer.submit(connection,RequestCommand('accept-'+operation,'run',1,request_id,'accept'))

    def result(self, verdict='pass', op='result', submission='submit', review_id=1):
        row=self.state()['run_reviews']['run']['current']
        request=self.state()['peer_traffic']['traffic'][row['request_id']]
        if request['status']=='QUEUED':
            self.peer.observe(self.connection,Readiness.SAFE)
            offer=self.peer.prepare_delivery(self.connection,traffic_id=row['request_id'])
            envelope=offer.envelope
            receipt={key:envelope[key] for key in ('delivery_id','participant_id','incarnation_id','context_generation')}
            receipt['digest']=digest(envelope)
            self.peer.confirm_delivery(self.connection,offer,receipt)
            self.peer.submit(self.connection,RequestCommand('accept-'+submission,'run',1,row['request_id'],'accept'))
        native={'id':review_id,'html_url':URL+str(review_id),'pull_request_url':'https://api.github.com/repos/owner/repo/pulls/3',
            'user':{'id':8},'state':{'pass':'APPROVED','changes-requested':'CHANGES_REQUESTED','human-needed':'COMMENTED'}[verdict],
            'submitted_at':f'2026-10-27T21:00:{review_id:02d}Z','commit_id':'a'*40}
        self.broker.reviews=[native]
        return self.call('review-result',op,{'submission_id':submission,'verdict':verdict,'review_reference':URL+str(review_id),
                    'lenses':['Standards','Specification','Runtime']},REVIEWER)
    def complete(self, op='complete'):
        return self.owner.complete(op,'run',1,'submit',origin=HUMAN,authorize=lambda:self.allowed,admission_operation='admission')
    def state(self): return self.ledger.snapshot()['state']
    def error(self, code, call):
        with self.assertRaises(LedgerError) as ctx: call()
        self.assertEqual(code,ctx.exception.code)
    def control(self, action='add-rounds', rounds=2, op='control',submission='submit'):
        return self.owner.control(op,'run',1,{'submission_id':submission,'target':deepcopy(TARGET),'action':action,
            'rounds':rounds,'reason':'Explicit human decision'},human=HUMAN,authorize=lambda:self.allowed,admission_operation='admission')
    def changes(self, op='changes'):
        return self.owner.request_changes(op,'run',1,{'submission_id':'submit','target':deepcopy(TARGET),'body':'Please adjust the UI.'},
                 human=HUMAN,authorize=lambda:self.allowed,admission_operation='admission')
    def test_submission_uses_real_peer_outbox_and_exact_retry(self):
        row=self.submit(); self.assertEqual('REVIEWING',row['stage'])
        request=self.state()['peer_traffic']['traffic'][row['request_id']]
        self.assertEqual(['review-seat'],request['recipients']); self.assertEqual('QUEUED',request['status'])
        self.assertEqual(row,self.submit()); self.assertEqual(1,len(self.broker.calls))
    def test_pass_and_human_merge_record_integration_separately_and_replay(self):
        self.submit(); self.result(); self.broker.merged=True
        row=self.complete(); self.assertEqual('COMPLETED',row['stage']); self.assertEqual('CLOSED',self.state()['runs']['run']['status'])
        self.assertEqual('a'*40,row['completion']['candidate_sha']); self.assertEqual('c'*40,row['completion']['integration_sha'])
        count=len(self.broker.calls); self.assertEqual(row,self.complete()); self.assertEqual(count,len(self.broker.calls))
    def test_fifth_return_pauses_before_sixth_request_and_added_rounds(self):
        for i in range(1,6):
            op='submit'+str(i); self.submit(op); self.result('changes-requested','result'+str(i),op,i)
        state=self.state(); self.assertEqual(5,state['run_reviews']['run']['returns']); self.assertEqual('PAUSED',state['runs']['run']['status'])
        traffic=state['peer_traffic']['traffic']; self.assertEqual(9,len(traffic))
        self.control(submission='submit5'); self.assertEqual('ACTIVE',self.state()['runs']['run']['status'])
        self.assertEqual(10,len(self.state()['peer_traffic']['traffic']))
    def test_human_needed_does_not_consume_round_and_scoped_override(self):
        self.submit(); self.result('human-needed'); self.assertEqual(0,self.state()['run_reviews']['run']['returns'])
        self.control('override-review',None); self.broker.merged=True
        row=self.complete(); self.assertEqual('human-needed',row['result']); self.assertEqual('control',row['override_id'])
    def test_no_eligible_reviewer_or_contributor_never_falls_back(self):
        self.identity.contributors=['builder','reviewer']; row=self.submit()
        self.assertEqual('NO_ELIGIBLE_REVIEWER',row['reason']); self.assertEqual({},self.state()['peer_traffic']['traffic'])
    def test_gate_blocked_cannot_submit(self):
        self.gates.passed=False; self.error('GATE_OPERATION_BLOCKED',self.submit)
        self.assertNotIn('run_reviews',self.state())
    def test_known_edit_after_assignment_blocks_result(self):
        self.submit(); self.identity.contributors=['builder','reviewer']; self.error('REVIEWER_INELIGIBLE',self.result)
    def test_result_exact_retry_does_not_consume_two_rounds(self):
        self.submit(); first=self.result('changes-requested'); count=len(self.broker.calls)
        self.assertEqual(first,self.result('changes-requested')); self.assertEqual(1,self.state()['run_reviews']['run']['returns'])
        self.assertEqual(count,len(self.broker.calls))
    def test_wrong_head_does_not_consume_round(self):
        self.submit(); self.broker.head='d'*40; self.error('REVIEW_CANDIDATE_CHANGED',self.result)
        self.assertEqual(0,self.state()['run_reviews']['run']['returns'])
    def test_unavailable_review_does_not_consume_round(self):
        self.submit(); self.broker.status='UNAVAILABLE'; self.error('REVIEW_OBSERVATION_UNAVAILABLE',self.result)
        self.assertEqual(0,self.state()['run_reviews']['run']['returns'])
    def test_unauthorized_merger_and_bot_do_not_close(self):
        self.submit(); self.result(); self.broker.merged=True; self.broker.who=99
        self.assertEqual('ATTENTION',self.complete()['stage'])
        self.broker.who=7; self.broker.kind='Bot'; self.assertEqual('ATTENTION',self.complete('complete2')['stage'])
        self.assertEqual('ACTIVE',self.state()['runs']['run']['status'])
    def test_comment_unknown_then_reconcile_routes_once(self):
        self.submit(); self.result(); self.broker.comment_status='unknown'
        row=self.changes(); self.assertEqual('unknown',row['status']); count=len(self.state()['peer_traffic']['traffic'])
        self.assertEqual(row,self.changes()); self.assertEqual(1,len([x for x in self.broker.calls if x[0]=='comment']))
        self.broker.comment_status='confirmed'
        result=self.owner.reconcile_changes('changes',human=HUMAN,authorize=lambda:True,admission_operation='admission')
        self.assertEqual('confirmed',result['status']); self.assertEqual(count+1,len(self.state()['peer_traffic']['traffic']))
        self.assertEqual(result,self.owner.reconcile_changes('changes',human=HUMAN,authorize=lambda:True,admission_operation='admission'))
    def test_comment_confirmation_after_generation_change_does_not_route(self):
        self.submit(); self.result(); self.broker.comment_status='unknown'; self.changes()
        self.seed(lambda state:state['runs']['run'].update(generation=2)); self.broker.comment_status='confirmed'
        result=self.owner.reconcile_changes('changes',human=HUMAN,authorize=lambda:True,admission_operation='admission')
        self.assertEqual('stale',result['status']); self.assertEqual(1,len(self.state()['peer_traffic']['traffic']))
    def test_current_authority_required_on_retry(self):
        self.submit(); self.allowed=False; self.error('FORBIDDEN',self.submit)
    def test_cap_waiver_is_audited_not_a_review_pass(self):
        self.submit(); self.result('human-needed'); result=self.control('waive-cap',None)
        self.assertIsNone(self.state()['run_reviews']['run']['cap'])
        self.assertEqual(HUMAN.canonical(),result['audit']['human_origin'])
        self.assertEqual('human-needed',result['review']['result'])
        self.error('REVIEW_PASS_REQUIRED',self.complete)
    def test_pending_merge_keeps_waiting_then_fresh_poll_closes(self):
        self.submit(); self.result(); row=self.complete()
        self.assertEqual('AWAITING_HUMAN_MERGE',row['reason']); self.assertEqual('ACTIVE',self.state()['runs']['run']['status'])
        self.broker.merged=True; self.assertEqual('COMPLETED',self.complete('merged-now')['stage'])
    def test_stale_native_review_and_dismissal_cannot_qualify(self):
        self.submit()
        # Deliver using the actual outbox, then reject an intentionally stale native fact.
        self.broker.status='UNAVAILABLE'
        self.error('REVIEW_OBSERVATION_UNAVAILABLE',self.result)
        self.broker.status='OK'
        native=deepcopy(self.broker.reviews[0]); native['commit_id']='d'*40; self.broker.reviews=[native]
        payload={'submission_id':'submit','verdict':'pass','review_reference':URL+'1','lenses':['Standards','Specification','Runtime']}
        self.error('REVIEW_REFERENCE_UNVERIFIABLE',lambda:self.call('review-result','stale-review',payload,REVIEWER))
        native['commit_id']='a'*40; native['state']='DISMISSED'; self.broker.reviews=[native]
        self.error('REVIEW_REFERENCE_UNVERIFIABLE',lambda:self.call('review-result','dismissed-review',payload,REVIEWER))
        self.assertEqual(0,self.state()['run_reviews']['run']['returns'])
    def test_pending_review_and_native_approval_do_not_choose_typed_verdict(self):
        self.submit(); self.broker.status='UNAVAILABLE'; self.error('REVIEW_OBSERVATION_UNAVAILABLE',self.result)
        self.broker.status='OK'; payload={'submission_id':'submit','verdict':'changes-requested','review_reference':URL+'1',
            'lenses':['Standards','Specification','Runtime']}
        self.error('REVIEW_REFERENCE_UNVERIFIABLE',lambda:self.call('review-result','wrong-typed',payload,REVIEWER))
        self.broker.reviews[0]['state']='PENDING'; self.broker.reviews[0]['submitted_at']=None
        payload['verdict']='pass'
        self.error('REVIEW_REFERENCE_UNVERIFIABLE',lambda:self.call('review-result','pending-review',payload,REVIEWER))
    def test_same_reference_different_operation_cannot_consume_return(self):
        self.submit(); self.result('changes-requested'); self.submit('second')
        self.error('REVIEW_REFERENCE_REUSED',lambda:self.result('changes-requested','different-operation','second',1))
        self.assertEqual(1,self.state()['run_reviews']['run']['returns'])
    def test_lost_reviewer_delivery_receipt_is_same_offer_without_return(self):
        row=self.submit(); self.peer.observe(self.connection,Readiness.SAFE)
        first=self.peer.prepare_delivery(self.connection,traffic_id=row['request_id'])
        again=self.peer.prepare_delivery(self.connection,traffic_id=row['request_id'])
        self.assertEqual(first.envelope,again.envelope)
        self.assertEqual(0,self.state()['run_reviews']['run']['returns'])
        self.assertEqual('QUEUED',self.state()['peer_traffic']['traffic'][row['request_id']]['status'])
    def test_unconfirmed_delivery_cannot_submit_result(self):
        self.submit(); payload={'submission_id':'submit','verdict':'pass','review_reference':URL+'1',
            'lenses':['Standards','Specification','Runtime']}
        self.error('REVIEW_DELIVERY_REQUIRED',lambda:self.call('review-result','early-result',payload,REVIEWER))
    def test_room_restart_replays_completion_without_provider(self):
        self.submit(); self.result(); self.broker.merged=True; result=self.complete(); calls=len(self.broker.calls)
        self.ledger.close(); self.ledger=RoomLedger(self.path,'room'); self.addCleanup(self.ledger.close)
        self.gates.ledger=self.ledger; self.construct()
        self.assertEqual(result,self.complete()); self.assertEqual(calls,len(self.broker.calls))
    def test_reviewer_authority_epoch_mismatch_does_not_borrow_old_assignment(self):
        self.submit(); impostor=Origin('reviewer','review-seat','inc','new-epoch',('peer-traffic','review'))
        self.error('REVIEWER_REQUIRED',lambda:self.call('review-result','impostor',{
            'submission_id':'submit','verdict':'pass','review_reference':URL+'1',
            'lenses':['Standards','Specification','Runtime']},impostor))
    def test_unknown_merge_method_is_attention_without_closure(self):
        self.submit(); self.result(); self.broker.status='UNSUPPORTED_MERGE_METHOD'
        row=self.complete(); self.assertEqual('ATTENTION',row['stage'])
        self.assertEqual('ACTIVE',self.state()['runs']['run']['status'])
    def test_changed_head_human_override_does_not_forge_gates(self):
        self.submit(); self.result('human-needed'); self.control('override-review',None)
        self.gates.passed=False; self.broker.merged=True
        self.error('GATE_OPERATION_BLOCKED',self.complete)
    def test_generation_change_blocks_old_result_without_round(self):
        self.submit(); self.seed(lambda s:s['runs']['run'].update(generation=2))
        self.error('REVIEW_RUN_STALE',lambda:self.call('review-result','late',{'submission_id':'submit',
            'verdict':'pass','review_reference':URL+'1','lenses':['Standards','Specification','Runtime']},REVIEWER))
        self.assertEqual(0,self.state()['run_reviews']['run']['returns'])
    def test_confirmed_comment_changed_remote_head_does_not_route(self):
        self.submit(); self.result(); self.broker.comment_status='unknown'; self.changes()
        self.broker.head='d'*40; self.broker.comment_status='confirmed'
        row=self.owner.reconcile_changes('changes',human=HUMAN,authorize=lambda:True,admission_operation='admission')
        self.assertEqual('stale',row['status']); self.assertEqual(1,len(self.state()['peer_traffic']['traffic']))
    def test_manager_projection_is_passive_and_has_durable_sequence(self):
        self.submit(); before=self.ledger.snapshot(); calls=len(self.broker.calls)
        view=self.owner.snapshot_run('run')
        self.assertEqual(before['room_seq'],view['room_seq']); self.assertEqual('REVIEWING',view['review']['current']['stage'])
        self.assertTrue(view['review']['current']['updated_at']); self.assertEqual(before,self.ledger.snapshot())
        self.assertEqual(calls,len(self.broker.calls))
    def test_aggregate_result_requires_all_three_lenses(self):
        self.submit()
        self.error('INVALID_REVIEW_RESULT',lambda:self.call('review-result','partial',{
            'submission_id':'submit','verdict':'pass','review_reference':URL+'1','lenses':['Standards']},REVIEWER))
    def test_admitted_dispatcher_routes_exact_origin_and_admission(self):
        from uas.workstation_peer import AdmittedPeerDispatcher
        dispatcher=object.__new__(AdmittedPeerDispatcher)
        connection=object(); binding=object(); calls=[]
        dispatcher._connections={'admission':connection}
        dispatcher.hub=SimpleNamespace(_current=lambda c:c is connection)
        dispatcher.admissions=SimpleNamespace(recheck=lambda op,record:True)
        dispatcher._origin=lambda value:BUILDER
        dispatcher.reviews=SimpleNamespace(submit=lambda envelope,**kw:calls.append((envelope,kw)) or {'ok':True})
        envelope={'kind':'submit-for-review'}
        self.assertEqual({'ok':True},dispatcher._submit('admission',None,binding,envelope))
        self.assertIs(BUILDER,calls[0][1]['origin']); self.assertEqual('admission',calls[0][1]['admission_operation'])
        self.assertTrue(calls[0][1]['authorize']())
    def test_reconcile_explicit_new_attempt_can_recover_without_second_write(self):
        self.submit(); self.result(); self.broker.comment_status='unknown'; self.changes()
        args={'human':HUMAN,'authorize':lambda:True,'admission_operation':'admission'}
        first=self.owner.reconcile_changes('changes',reconciliation_id='read-first',**args)
        count=len(self.broker.calls)
        self.assertEqual(first,self.owner.reconcile_changes('changes',reconciliation_id='read-first',**args))
        self.assertEqual(count,len(self.broker.calls)); self.broker.comment_status='confirmed'
        result=self.owner.reconcile_changes('changes',reconciliation_id='read-next',**args)
        self.assertEqual('confirmed',result['status'])
        self.assertEqual(1,len([x for x in self.broker.calls if x[0]=='comment']))
    def test_proven_preflight_error_retries_same_action_with_explicit_read_attempt(self):
        self.submit(); self.result(); self.broker.comment_status='error'; row=self.changes()
        self.assertEqual('error',row['status'])
        args={'human':HUMAN,'authorize':lambda:True,'admission_operation':'admission'}
        first=self.owner.retry_changes_preflight('changes','preflight-first',**args); count=len(self.broker.calls)
        self.assertEqual(first,self.owner.retry_changes_preflight('changes','preflight-first',**args))
        self.assertEqual(count,len(self.broker.calls)); self.broker.comment_status='confirmed'
        result=self.owner.retry_changes_preflight('changes','preflight-next',**args)
        self.assertEqual('confirmed',result['status'])
        self.assertTrue(all(op=='changes' for kind,op in self.broker.calls if kind=='comment'))
    def test_unknown_write_is_never_preflight_retryable(self):
        self.submit(); self.result(); self.broker.comment_status='unknown'; self.changes()
        self.error('REVIEW_PREFLIGHT_RETRY_FORBIDDEN',lambda:self.owner.retry_changes_preflight('changes','other',
            human=HUMAN,authorize=lambda:True,admission_operation='admission'))
    def test_completion_closes_canonical_context_and_admission_without_fake_native_stop(self):
        self.submit(); self.result()
        self.seed(lambda s:s.update(run_admissions={'run':{'status':'ACTIVE'}},fixture_context={
            'runs':{'run':{'generation':1,'status':'OPEN','terminal_fact':None}},'participants':{}}))
        self.broker.merged=True; self.complete(); state=self.state()
        self.assertEqual('completed',state['runs']['run']['outcome'])
        self.assertEqual('CLOSED',state['run_admissions']['run']['status'])
        self.assertEqual('COMPLETED',state['fixture_context']['runs']['run']['terminal_fact'])
        self.assertNotIn('native_stop',state['runs']['run'])
    def test_dismissed_pass_is_rechecked_at_completion(self):
        self.submit(); self.result(); self.broker.merged=True; self.broker.reviews[0]['state']='DISMISSED'
        row=self.complete(); self.assertEqual('MERGE_REVIEW_STALE',row['reason'])
        self.assertEqual('ACTIVE',self.state()['runs']['run']['status'])
    def test_superseding_changes_recheck_blocks_completion(self):
        self.submit(); self.result(); self.broker.merged=True
        later=deepcopy(self.broker.reviews[0]); later.update(id=2,state='CHANGES_REQUESTED',submitted_at='2026-10-27T22:00:00Z',html_url=URL+'2')
        self.broker.reviews.append(later)
        self.assertEqual('MERGE_REVIEW_STALE',self.complete()['reason'])
    def test_populated_run_attention_outbox_is_valid_real_intent(self):
        from uas.forge_projections import validate_intent
        self.seed(lambda s:s['runs']['run'].update(issue_number=2,issue_id=22,github_user_id=8))
        self.identity.active=False; self.submit()
        intent=self.state()['forge_projections']['run']['desired']
        self.assertEqual(['lifecycle:attention','run:active'],validate_intent(intent)['labels'])
    def test_blocked_review_request_moves_to_attention_then_can_retry_without_round(self):
        row=self.submit(); self.seed(lambda s:s['peer_traffic']['traffic'][row['request_id']].update(status='BLOCKED'))
        result=self.owner.refresh_request('refresh','run',1,origin=HUMAN,authorize=lambda:True,admission_operation='admission')
        self.assertEqual('REVIEW_REQUEST_BLOCKED',result['reason']); self.assertEqual(0,self.state()['run_reviews']['run']['returns'])
        self.control('retry-review',None); self.assertEqual('REVIEWING',self.submit('second')['stage'])
    def test_review_timeout_does_not_consume_return(self):
        row=self.submit()
        def expire(s):
            s['runs']['run']['policy']['queue_timeout_seconds']=1
            s['peer_traffic']['traffic'][row['request_id']]['submitted_at']='2000-01-01T00:00:00+00:00'
        self.seed(expire)
        result=self.owner.refresh_request('timeout','run',1,origin=HUMAN,authorize=lambda:True,admission_operation='admission')
        self.assertEqual('REVIEW_QUEUE_TIMEOUT',result['reason']); self.assertEqual(0,self.state()['run_reviews']['run']['returns'])
    def test_interrupted_completion_requires_explicit_fresh_read_before_consume(self):
        self.submit(); self.result(); self.broker.merged=True
        original=self.owner._apply
        def interrupt(command,*args):
            if command.kind=='review.observe-completion': raise RuntimeError('crash before consuming transaction')
            return original(command,*args)
        self.owner._apply=interrupt
        with self.assertRaises(RuntimeError): self.complete()
        self.owner._apply=original; self.broker.head='d'*40; count=len(self.broker.calls)
        self.error('REVIEW_OBSERVATION_REQUIRES_FRESH_ATTEMPT',self.complete)
        self.assertEqual(count,len(self.broker.calls))
        row=self.owner.complete('complete','run',1,'submit',origin=HUMAN,authorize=lambda:True,
                                admission_operation='admission',observation_id='explicit-fresh-read')
        self.assertEqual('ATTENTION',row['stage']); self.assertEqual('ACTIVE',self.state()['runs']['run']['status'])
        self.assertEqual(count+1,len(self.broker.calls))
    def test_reviewer_in_other_run_is_not_selected(self):
        def unavailable(*args): raise LedgerError('REVIEW_PARTICIPANT_UNAVAILABLE')
        self.identity.dispatcher.reviewer_authority=unavailable
        self.assertEqual('NO_ELIGIBLE_REVIEWER',self.submit()['reason'])
    def test_manager_uses_one_supplied_room_cut(self):
        self.submit(); cut=self.ledger.snapshot(); self.result()
        self.assertEqual('REVIEWING',self.owner.snapshot_run('run',snapshot=cut)['review']['current']['stage'])
        wrong=deepcopy(cut); wrong['room_id']='wrong'
        self.error('REVIEW_SNAPSHOT_ROOM_MISMATCH',lambda:self.owner.snapshot_run('run',snapshot=wrong))
    def test_confirmed_comment_transient_target_read_recovers_without_second_post(self):
        self.submit(); self.result(); self.broker.comment_status='unknown'; self.changes()
        self.broker.comment_status='confirmed'; self.broker.status='UNAVAILABLE'
        args={'human':HUMAN,'authorize':lambda:True,'admission_operation':'admission'}
        first=self.owner.reconcile_changes('changes',reconciliation_id='read-one',**args)
        self.assertEqual('confirmed-awaiting-target',first['status'])
        self.broker.status='OK'
        result=self.owner.reconcile_changes('changes',reconciliation_id='read-two',**args)
        self.assertEqual('confirmed',result['status']); self.assertIn('implementation_request',result)
        self.assertEqual(1,len([x for x in self.broker.calls if x[0]=='comment']))
    def test_new_verified_target_supersedes_old_pass_without_inheriting_or_return(self):
        self.submit(); self.result(); target=deepcopy(TARGET); target['head_sha']='d'*40
        self.seed(lambda s:s['runs']['run'].update(gate_target=target,gate_target_binding='new-binding'))
        self.broker.head='d'*40
        row=self.call('submit-for-review','new-head',{'target':target,'evidence':['evidence:new']})
        self.assertEqual('REVIEWING',row['stage']); self.assertIsNone(row['result'])
        review=self.state()['run_reviews']['run']; self.assertEqual(0,review['returns'])
        self.assertEqual('SUPERSEDED',review['attempts'][0]['stage'])
    def test_revoked_reviewer_does_not_revoke_submitting_actor(self):
        from uas.kernel_origin import OriginDenied
        def revoked(*args): raise OriginDenied('revoked reviewer')
        self.identity.dispatcher.reviewer_authority=revoked
        self.assertEqual('NO_ELIGIBLE_REVIEWER',self.submit()['reason']); self.assertTrue(self.allowed)
    def test_new_generation_can_supersede_old_active_review(self):
        self.submit(); self.seed(lambda s:s['runs']['run'].update(generation=2))
        row=self.owner.submit({'id':'new-generation','kind':'submit-for-review','run_id':'run','generation':2,
            'payload':{'target':deepcopy(TARGET),'evidence':['evidence:new']}},origin=BUILDER,
            authorize=lambda:True,admission_operation='admission')
        self.assertEqual(2,row['generation']); self.assertEqual(0,self.state()['run_reviews']['run']['returns'])
        self.assertEqual('SUPERSEDED',self.state()['run_reviews']['run']['attempts'][0]['stage'])
    def test_initial_implementation_slot_is_settled_before_return_can_accept(self):
        def start(state):
            request,_=self.owner._request(state,state['runs']['run'],'initial-work','builder-seat','Implement issue','human')
            state['runs']['run']['implementation_request']=request
        self.seed(start); request=self.state()['runs']['run']['implementation_request']
        self.deliver_accept(self.builder_connection,request,'initial')
        self.submit(); self.assertEqual('COMPLETED',self.state()['peer_traffic']['traffic'][request]['status'])
        result=self.result('changes-requested')
        self.deliver_accept(self.builder_connection,result['implementation_request'],'returned')
        self.assertEqual('ACCEPTED',self.state()['peer_traffic']['traffic'][result['implementation_request']]['status'])
    def test_explicit_packet_attempt_recovers_interrupted_submit_same_command(self):
        from uas.workstation_peer import AdmittedPeerDispatcher
        dispatcher=object.__new__(AdmittedPeerDispatcher); connection=object()
        dispatcher._connections={'admission':connection}; dispatcher.hub=SimpleNamespace(_current=lambda c:True)
        dispatcher.admissions=SimpleNamespace(recheck=lambda op,record:True); dispatcher._origin=lambda b:BUILDER
        dispatcher.reviews=self.owner
        envelope={'id':'submit','kind':'submit-for-review','run_id':'run','generation':1,
                  'payload':{'target':deepcopy(TARGET),'evidence':['evidence:tests']}}
        original=self.owner._apply
        def interrupted(command,*args):
            if command.kind=='review.submit-for-review': raise RuntimeError('interrupted transaction')
            return original(command,*args)
        self.owner._apply=interrupted
        with self.assertRaises(RuntimeError): dispatcher._submit('admission',None,None,envelope)
        self.owner._apply=original
        self.error('REVIEW_OBSERVATION_REQUIRES_FRESH_ATTEMPT',lambda:dispatcher._submit('admission',None,None,envelope))
        envelope['observation_id']='explicit-packet-read'
        result=dispatcher._submit('admission',None,None,envelope)
        self.assertEqual('submit',result['submission_id']); self.assertEqual('REVIEWING',result['stage'])
    def test_comment_intent_crash_before_broker_recovers_proven_absence_same_action(self):
        self.submit(); self.result(); original=self.broker.comment
        def crash(*args,**kwargs): raise RuntimeError('crash before broker journal')
        self.broker.comment=crash
        with self.assertRaises(RuntimeError): self.changes()
        self.assertEqual('pending',self.state()['review_comments']['changes']['status'])
        self.broker.comment=original; self.broker.comment_status='error'
        args={'human':HUMAN,'authorize':lambda:True,'admission_operation':'admission'}
        absence=self.owner.reconcile_changes('changes',reconciliation_id='prove-absence',**args)
        self.assertEqual('error',absence['status']); self.broker.comment_status='confirmed'
        row=self.owner.retry_changes_preflight('changes','fresh-preflight',**args)
        self.assertEqual('confirmed',row['status'])
        self.assertEqual([('comment','changes')],[x for x in self.broker.calls if x[0]=='comment'])
