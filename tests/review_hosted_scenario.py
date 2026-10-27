"""Shared scenario for hosted real Broker and controlled admission/Reviewer.

The dispatcher, GateHub, RunReview and peer outbox are real. Admission identity
and Git source history are explicit fixtures, not native Participant evidence.
"""
from contextlib import contextmanager
from copy import deepcopy
from types import SimpleNamespace
from uas.forge_read_service import ReviewBrokerClient
from uas.gate_evaluation import GateRoomBinding
from uas.gate_hub import GateHub
from uas.gate_policy import compile_policy
from uas.kernel_origin import ReceiverIdentity
from uas.ledger import Command, Event, LedgerError, Origin, RoomLedger, Transition
from uas.peer import FixturePeerHub, FixtureParticipant, Readiness, RequestCommand, digest
from uas.run_review import RunReview
from uas.workstation_admission import AdmissionSeat, AdmittedBinding
from uas.workstation_peer import AdmittedPeerDispatcher

TARGET={'repository':'owner/repo','pull_number':11,'pull_id':111,'head_sha':'a'*40,'base_sha':'b'*40,'base_ref':'main'}


def exercise(client, ledger_path, phase):
    ledger=RoomLedger(ledger_path,'alpha')
    peer=FixturePeerHub(ledger)
    peer.configure('configure',(FixtureParticipant('builder-seat','builder'),FixtureParticipant('review-seat','reviewer')),'run')
    connections={actor:peer.connect('connect-'+actor,actor+'-seat','inc',object()) for actor in ('builder','review')}
    receiver=ReceiverIdentity(65533,65533,'fixture','a'*64)
    bindings={}
    for actor,identity,caps in [('builder','builder',('peer-traffic','implement')),('review','reviewer',('peer-traffic','review'))]:
        seat=AdmissionSeat('alpha','instance-1',actor+'-seat',identity,'fixture-profile',caps,receiver)
        bindings[actor]=AdmittedBinding(seat,actor,'inc',1,'d'*64)
    # Explicit fixture admission facts. Actual dispatcher derives Origins from
    # immutable typed bindings and checks exact current peer scope/connection.
    class AdmissionFixture:
        controller='fixture-controller'
        def __init__(self):
            self._authorization=SimpleNamespace(depth=0)
            self._active={key:(None,value) for key,value in bindings.items()}
            self.seats={key:value.seat for key,value in bindings.items()}
        def _check_current(self,key): return self._active[key]
        def recheck(self,key,record): return key in self._active and record is trusted_record
        @contextmanager
        def authorize(self,key,record):
            assert key in self._active
            self._authorization.depth+=1
            try: yield bindings[key]
            finally: self._authorization.depth-=1
    admissions=AdmissionFixture();trusted_record=object()
    dispatcher=object.__new__(AdmittedPeerDispatcher)
    dispatcher.admissions=admissions;dispatcher.hub=peer;dispatcher._connections=connections
    dispatcher.reviews=None;dispatcher.contributions=None
    class Identity:
        def __init__(self): self.dispatcher=dispatcher
        @contextmanager
        def operation_fence(self,operation):
            with admissions.authorize(operation,None): yield
        def __call__(self,run,actor,head): return self.read_identity(run,actor,head,None)
        def read_identity(self,run,actor,head,epoch):
            return {**dispatcher.actor_authority(actor,epoch),'contributors':['builder'],
                    'contribution_version':'fixture-known','history_status':'read'}
    identity=Identity()
    source={'room_instance':'instance-1','project_id':'project','repository':'owner/repo','run_id':'run',
            'participant_id':'builder-seat','slot_id':'primary','branch':'refs/heads/feature',
            'head_sha':'a'*40,'source_digest':'c'*64}
    control=SimpleNamespace(resolve=lambda *_:deepcopy(source),current=lambda *_:deepcopy(source))
    human=Origin('human','human-seat','session','human-epoch',('human-control-run',))
    gates=GateHub(ledger,GateRoomBinding('alpha','instance-1','project','owner/repo',128<<20),control,
                  authorize=lambda *_:True,identity=identity)
    @contextmanager
    def target_fence(): yield
    broker=ReviewBrokerClient(client)
    owner=RunReview(ledger,gates,identity,broker,reviewers=[{'actor_id':'reviewer','participant_id':'review-seat','github_user_id':8}],
                    target_fence=target_fence,authorize_human=lambda o:o==human,human_mergers=[7])
    dispatcher.attach_reviews(owner)
    def state(): return ledger.snapshot()['state']
    def call(kind,op,payload,actor='builder',attempt=None,generation=1):
        envelope={'id':op,'kind':kind,'run_id':'run','generation':generation,'payload':payload}
        if attempt: envelope['observation_id']=attempt
        return dispatcher._submit(actor,trusted_record,bindings[actor],envelope)
    def accept(actor,request_id,label):
        connection=connections[actor]
        peer.observe(connection,Readiness.SAFE)
        offer=peer.prepare_delivery(connection,traffic_id=request_id)
        packet=offer.envelope
        receipt={key:packet[key] for key in ('delivery_id','participant_id','incarnation_id','context_generation')}
        receipt['digest']=digest(packet)
        peer.confirm_delivery(connection,offer,receipt)
        peer.submit(connection,RequestCommand('accept-'+label,'run',1,request_id,'accept'))
    def result(verdict,submission,review_id,operation='result',attempt=None):
        return call('review-result',operation,{'submission_id':submission,'verdict':verdict,
            'review_reference':f'https://github.com/owner/repo/pull/11#pullrequestreview-{review_id}',
            'lenses':['Standards','Specification','Runtime']},'review',attempt)
    try:
        if phase=='prepare':
            policy=compile_policy({'id':'default','version':1,'gates':[{'id':'review-gate','kind':'decision',
                'config':{'statement_id':'review-ready','scope':'head','eligible_actors':['reviewer'],
                'relationship':'independent-reviewer','required_capability':'review','allow_self':False,'continuing_authority':True}}],
                'protected_operations':{'submit-for-review':['review-gate'],'complete':['review-gate']},
                'review_return_cap':5,'queue_timeout_seconds':30,'response_timeout_seconds':30},'policy')
            def seed(state,_):
                state['runs']={'run':{'run_id':'run','generation':1,'status':'ACTIVE','project_id':'project','repository':'owner/repo',
                    'actor_id':'builder','participant_id':'builder-seat','checkout':{'slot':'primary','branch':'refs/heads/feature'},
                    'policy':policy,'gate_target':deepcopy(TARGET),'gate_target_binding':'fixture-binding'}}
                return Transition(state,(Event('fixture.seed',{}),),{})
            ledger.apply(Command('seed','fixture.seed','run',None,{}),human,authorize=lambda *_:True,decide=seed)
            with identity.operation_fence('review'):
                gate=gates.submit('gate-approval','run',1,{'gate_id':'review-gate','statement_id':'review-ready',
                    'action':'approve','note':'Fixture independent decision','evidence_refs':['fixture:review']},origin=dispatcher._origin(bindings['review']))
            assert gate['result']['verdict']=='passed',gate
            submitted=call('submit-for-review','submit1',{'target':TARGET,'evidence':['fixture:tests']})
            assert submitted['stage']=='REVIEWING',submitted
            assert submitted['reviewer']['actor_id']=='reviewer' and submitted['generation']==1
            accept('review',submitted['request_id'],'review1')
            # Actual dispatcher rejects stale generation before a second request.
            try:call('submit-for-review','stale-generation',{'target':TARGET,'evidence':['fixture:tests']},generation=2)
            except LedgerError:pass
            else:raise AssertionError('stale generation accepted')
            absent=broker.reconcile_comment(TARGET,'fixture never dispatched','never-dispatched',authorize=lambda:True,reconciliation_id='absence')
            assert absent['status']=='error',absent
        elif phase in {'stale','outage'}:
            before=state()['run_reviews']['run']['returns']
            try: result('changes-requested','submit1',1,'changes-result',phase)
            except LedgerError: pass
            else: raise AssertionError('unverifiable review consumed')
            assert state()['run_reviews']['run']['returns']==before==0
            assert state()['run_reviews']['run']['current']['stage']=='REVIEWING'
        elif phase=='changes':
            row=result('changes-requested','submit1',1,'changes-result','recovered')
            assert state()['run_reviews']['run']['returns']==1
            accept('builder',row['implementation_request'],'implementation')
            submitted=call('submit-for-review','submit2',{'target':TARGET,'evidence':['fixture:corrected']})
            accept('review',submitted['request_id'],'review2')
        elif phase=='pass':
            row=result('pass','submit2',2,'pass-result','approved')
            assert row['stage']=='READY_FOR_HUMAN',row
        elif phase=='comment':
            payload={'submission_id':'submit2','target':TARGET,'body':'lose-fixture-comment: please refine'}
            row=owner.request_changes('human-changes','run',1,payload,human=human,authorize=lambda:True,admission_operation='review')
            assert row['status']=='unknown',row
            assert state()['run_reviews']['run']['current']['stage']=='READY_FOR_HUMAN'
            replay=owner.request_changes('human-changes','run',1,payload,human=human,authorize=lambda:True,admission_operation='review')
            assert replay==row
            recovered=owner.reconcile_changes('human-changes',human=human,authorize=lambda:True,
                admission_operation='review',reconciliation_id='comment-reconcile')
            assert recovered['status']=='confirmed',recovered
            accept('builder',recovered['implementation_request'],'human-implementation')
            submitted=call('submit-for-review','submit3',{'target':TARGET,'evidence':['fixture:human-corrected']})
            accept('review',submitted['request_id'],'review3')
        elif phase=='repass':
            row=result('pass','submit3',3,'repass-result','approved3')
            assert row['stage']=='READY_FOR_HUMAN',row
        elif phase=='merged':
            row=owner.complete('complete','run',1,'submit3',origin=human,authorize=lambda:True,admission_operation='review')
            assert row['stage']=='COMPLETED',row
            assert state()['runs']['run']['status']=='CLOSED'
            assert row['completion']['candidate_sha']=='a'*40 and row['completion']['integration_sha']=='c'*40
            assert state()['run_reviews']['run']['returns']==1
        else: raise AssertionError(phase)
        return {'phase':phase,'run_status':state()['runs']['run']['status'],
                'returns':state()['run_reviews']['run']['returns'],
                'dispatcher':'actual methods, controlled admission identity','gates':'actual GateHub decision',
                'provider':'synthetic account-free','native_participant':'not exercised'}
    finally: ledger.close()
