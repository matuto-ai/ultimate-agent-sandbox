"""Pure connected diff lifecycle + real audited Broker fixture, never native proof."""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

from test_gate_evaluation import FakeControl, ORIGIN, Interrupted
from test_gate_forge import Fixture, TARGET, R, HEAD
from test_gate_forge_hub import FixtureClient
from uas.artifact_protocol import profile_scope_digest
from uas.diff_protocol import PROFILE_ID, source_binding, diff_correlation
from uas.forge import ForgeBinding
from uas.forge_audit import ForgeAudit
from uas.forge_read_provider import BrokerReadProvider
from uas.gate_evaluation import GateRoomBinding, SCRATCH_BYTES, PROVENANCE
from uas.gate_forge import ExternalGateForgeBroker
from uas.gate_hub import GateHub, require_operation_gates
from uas.gate_policy import compile_policy
from uas.github_read import GitHubProject
from uas.ledger import Command, Event, LedgerError, RoomLedger, Transition

IMPLEMENTER=replace(ORIGIN,actor_id='builder-actor',capabilities=('implement',))


class DiffOffer:
    def __init__(self,control,scope,target,config):
        self.control,self.scope,self.target,self.config=control,scope,target,config
        self.acked=self.exited=self.closed=False
        self.correlation=diff_correlation(scope,target,config)
    def document(self):
        value={'source':'supervisor-one-shot-helper','provenance':PROVENANCE,
            'profile':PROFILE_ID,'profile_digest':'d'*64,'binding_digest':'e'*64,
            'scope_digest':profile_scope_digest(PROFILE_ID,self.scope,self.target)}
        self.control.mutate_document(value)
        return value
    def records(self):
        self.control.effect('records')
        records=[{'kind':'header','correlation':self.correlation}]
        records += [{'kind':'path','index':index,'path':path} for index,path in enumerate(self.control.paths)]
        records += [{'kind':'final','correlation':self.correlation,'count':len(self.control.paths)}]
        self.control.mutate_records(records)
        yield from records
    def acknowledge_final(self,record):
        self.control.effect('ack')
        if not self.control.alive:raise LedgerError('GATE_HELPER_LOST')
        assert record=={'kind':'final','correlation':self.correlation,'count':len(self.control.paths)}
        assert self.control.hub._row(self.scope['evaluation_id'])['phase']=='OBSERVED'
        self.acked=True
    def confirm_exit(self):
        self.control.effect('exit');assert self.acked
        self.exited=self.control.exit_confirmed
        return self.exited
    def close(self):self.closed=True


class DiffControl(FakeControl):
    profile=PROFILE_ID
    def __init__(self,owned):
        super().__init__();self.owned=owned;self.paths=['file.txt'];self.subject=None
        self.mutate_source=lambda _:None
    def resolve(self,run_id,participant_id,room_instance,subject):
        self.effect('resolve');self.subject=deepcopy(subject)
        value={**deepcopy(self.owned.source),'profile':PROFILE_ID,'subject':deepcopy(subject),
               'binding_digest':source_binding(self.owned.source,subject)}
        self.mutate_source(value)
        return value
    def current(self,source):
        self.effect('current')
        return {**deepcopy(self.owned.source),'profile':PROFILE_ID,'subject':deepcopy(source['subject']),
                'binding_digest':source_binding(self.owned.source,source['subject'])}
    def prepare(self,scope,source):
        self.effect('prepare')
        row=self.hub._row(scope['evaluation_id'])
        assert row['phase']=='STARTED' and row['reservation']['scratch_bytes']==2*SCRATCH_BYTES
        def node(side):
            return {'target_id':('1' if side=='base' else '2')*32,'head_sha':source['subject'][side+'_sha'],
                'tree_sha':'c'*40,'manifest_sha256':'f'*64,'source_digest':source['source_digest'],
                'device':1,'inode':100 if side=='base' else 101,'entries':2,'expanded_bytes':100}
        self.target={'version':1,'profile':PROFILE_ID,'source_digest':source['binding_digest'],
                     'subject':deepcopy(source['subject']),'base':node('base'),'head':node('head')}
        return deepcopy(self.target)
    def start(self,scope,target,config):
        self.effect('start')
        assert self.hub._row(scope['evaluation_id'])['phase']=='LAUNCH_RESERVED'
        self.offer=DiffOffer(self,scope,target,config)
        return self.offer
    def finish(self,target,offer):
        self.effect('finish');assert offer is self.offer and offer.exited and offer.acked
        post=deepcopy(target)
        if self.post_mutated:post['base']['manifest_sha256']='0'*64
        return {'post_target':post,'cleanup':self.cleanup,'launch_state':'exited','exit_confirmed':True,
                'quarantine_ref':None if self.cleanup else 'quarantine-pair'}


class DiffGateHubTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'room.db'
        self.ledger=RoomLedger(self.path,'alpha');self.addCleanup(lambda:self.ledger.close())
        self.audit=ForgeAudit(Path(self.tmp.name)/'audit.db','deployment');self.addCleanup(self.audit.close)
        self.fixture=Fixture();self.control=FakeControl();self.control.source.update(repository=R,head_sha=HEAD)
        self.diff=DiffControl(self.control)
        self.binding=GateRoomBinding('alpha','room-instance','project-alpha',R,128<<20)
        provider=BrokerReadProvider(GitHubProject(R),self.fixture,None)
        broker=ExternalGateForgeBroker(ForgeBinding('alpha','project-alpha',R),'room-instance',
            self.audit,'fixed-actor',lambda _:provider)
        self.client=FixtureClient(broker)
        self.policy=compile_policy({'id':'default','version':1,'gates':[{'id':'diff','kind':'mechanical',
            'evaluator':'diff-claims','config':{'allowed_paths':['file.txt'],'forbidden_paths':[],
                                              'require_nonempty':True}}],
            'protected_operations':{'submit-for-review':['diff'],'complete':['diff']},
            'review_return_cap':5,'queue_timeout_seconds':60,'response_timeout_seconds':60},'policy')
        self.run={'run_id':'run-one','generation':1,'status':'ACTIVE','project_id':'project-alpha',
            'repository':R,'actor_id':'builder-actor','participant_id':'builder','policy':self.policy,
            'checkout':{'slot':'primary','branch':'refs/heads/main'}}
        self.revision=0;self.seed(lambda s:s.update(runs={'run-one':deepcopy(self.run)}))
        self.allowed=True;self.construct()
        self.assertEqual(self.hub.bind_target('bind','run-one',1,TARGET,origin=ORIGIN)['status'],'BOUND')
        self.declare(['file.txt'])
        self.fixture.calls.clear();self.client.calls.clear();self.control.calls.clear();self.diff.calls.clear()
    def construct(self):
        self.hub=GateHub(self.ledger,self.binding,self.control,authorize=lambda *_:self.allowed,
            forge=self.client,diff=self.diff,authorize_target=lambda origin,_:origin==ORIGIN)
        self.control.hub=self.diff.hub=self.hub
    def seed(self,change):
        self.revision+=1
        def decide(state,_):
            change(state);return Transition(state,(Event('fixture.changed',{}),),{})
        self.ledger.apply(Command('seed-'+str(self.revision),'fixture.changed','run-one',None,{}),
                          ORIGIN,authorize=lambda *_:True,decide=decide)
    def declare(self,paths,operation='declare',origin=IMPLEMENTER):
        return self.hub.declare_diff(operation,'run-one',1,'diff',paths,origin=origin)
    def evaluate(self,operation='evaluate'):
        return self.hub.evaluate(operation,'run-one',1,'diff',origin=ORIGIN)
    def projection(self):return self.hub.projection('run-one',1,'diff',origin=ORIGIN)

    def test_positive_exact_diff_records_checks_both_revisions_and_broker_refresh(self):
        result=self.evaluate()['result']
        self.assertEqual(result['verdict'],'passed')
        self.assertEqual(result['target']['subject'],TARGET)
        self.assertEqual(result['target']['base']['head_sha'],TARGET['base_sha'])
        self.assertEqual(result['target']['head']['head_sha'],HEAD)
        self.assertTrue(all(row['ok'] for row in result['checks']))
        self.assertEqual(result['provenance'],PROVENANCE)
        self.assertTrue(result['subject_observation']['audit_reference'])
        self.assertEqual(self.projection()['state'],'passed')
        view=self.hub.operation_gates('run-one',1,'complete',origin=ORIGIN)
        self.assertTrue(view['gates_satisfied']);require_operation_gates(self.ledger.snapshot()['state'],view)
        self.assertEqual(self.ledger.snapshot()['state']['runs']['run-one']['status'],'ACTIVE')

    def test_actual_set_mismatch_and_forbidden_path_refute_claim(self):
        self.diff.paths=['other.txt']
        result=self.evaluate()['result']
        self.assertEqual(result['verdict'],'failed')
        self.assertEqual([check['ok'] for check in result['checks']],[False,True,False])
        self.assertFalse(self.hub.operation_gates('run-one',1,'complete',origin=ORIGIN)['gates_satisfied'])

    def test_empty_declaration_and_empty_diff_do_not_earn_required_nonempty_pass(self):
        self.declare([],'empty');self.diff.paths=[]
        result=self.evaluate()['result']
        self.assertEqual(result['verdict'],'failed')
        self.assertEqual([check['ok'] for check in result['checks']],[True,False])

    def test_declaration_requires_authenticated_implementer_and_real_binding(self):
        for origin in (ORIGIN,replace(IMPLEMENTER,actor_id='peer'),replace(IMPLEMENTER,capabilities=())):
            with self.assertRaisesRegex(LedgerError,'FORBIDDEN_GATE_DECLARATION'):
                self.declare(['file.txt'],'forbidden-'+origin.actor_id+str(len(origin.capabilities)),origin)
        self.seed(lambda s:s['runs']['run-one'].pop('gate_target_binding'))
        with self.assertRaisesRegex(LedgerError,'GATE_TARGET_BINDING_STALE'):self.declare(['file.txt'],'unbound')
        with self.assertRaises(LedgerError):self.evaluate()
        self.assertNotIn('prepare',self.diff.calls)

    def test_supervisor_cannot_substitute_base_with_matching_owned_head(self):
        def substitute(value):
            value['subject']['base_sha']='f'*40
            owned={key:val for key,val in value.items() if key not in ('profile','subject','binding_digest')}
            value['binding_digest']=source_binding(owned,value['subject'])
        self.diff.mutate_source=substitute
        with self.assertRaises(LedgerError):self.evaluate()
        self.assertNotIn('prepare',self.diff.calls)

    def test_child_ownership_digest_and_out_of_ledger_range_identity_are_refused(self):
        original=self.diff.prepare
        def bad_digest(scope,source):
            pair=original(scope,source)
            pair['base']['source_digest']=pair['head']['source_digest']='0'*64
            return pair
        self.diff.prepare=bad_digest
        result=self.evaluate('bad-child-digest')['result']
        self.assertEqual(result['verdict'],'error')
        self.assertNotIn('start',self.diff.calls)
        def bad_inode(scope,source):
            pair=original(scope,source);pair['base']['inode']=2**63
            return pair
        self.diff.prepare=bad_inode
        result=self.evaluate('bad-child-inode')['result']
        self.assertEqual(result['verdict'],'error')
        self.assertNotIn('start',self.diff.calls)

    def test_malformed_order_duplicate_verdict_and_final_count_never_pass(self):
        mutations=(lambda rows:rows.insert(2,deepcopy(rows[1])),lambda rows:rows[1].update(index=1),
                   lambda rows:rows[1].update(verdict='passed'),lambda rows:rows[-1].update(count=True),
                   lambda rows:rows[-1].update(correlation='0'*64))
        for index,mutate in enumerate(mutations):
            self.diff.mutate_records=mutate
            result=self.evaluate('malformed-'+str(index))['result']
            self.assertEqual(result['verdict'],'error')
            self.assertFalse(self.diff.offer.acked)

    def test_loss_mutation_and_cleanup_failure_preserve_error_and_reservation(self):
        self.diff.alive=False
        self.assertEqual(self.evaluate('lost')['result']['verdict'],'error')
        self.diff.alive=True;self.diff.post_mutated=True
        self.assertEqual(self.evaluate('mutated')['result']['verdict'],'error')
        self.diff.post_mutated=False;self.diff.cleanup=False
        row=self.evaluate('cleanup');self.assertEqual(row['result']['verdict'],'error')
        self.assertEqual(self.hub._row(row['evaluation_id'])['reservation']['scratch_bytes'],2*SCRATCH_BYTES)
        self.assertTrue(row['result']['cleanup']['quarantine_ref'])

    def test_base_change_after_helper_wait_is_fresh_broker_error(self):
        self.diff.at['finish']=lambda:self.fixture.pull['base'].update(sha='f'*40)
        self.assertEqual(self.evaluate()['result']['verdict'],'error')
        self.assertNotEqual(self.projection()['state'],'passed')

    def test_new_declaration_and_head_movement_stale_old_evidence(self):
        first=self.evaluate()['result']
        self.declare(['other.txt'],'new-declaration')
        self.assertEqual(self.projection()['state'],'stale')
        self.assertEqual(first['verdict'],'passed')
        self.declare(['file.txt'],'restore-declaration')
        self.control.source['head_sha']='f'*40
        self.assertEqual(self.projection()['state'],'stale')

    def test_exact_retry_does_not_repeat_helper_or_broker_and_conflict_refused(self):
        first=self.evaluate();calls=list(self.diff.calls),list(self.client.calls)
        self.assertEqual(self.evaluate(),first)
        self.assertEqual((self.diff.calls,self.client.calls),calls)
        with self.assertRaisesRegex(LedgerError,'ID_CONFLICT'):
            self.hub.evaluate('evaluate','run-one',1,'other',origin=ORIGIN)

    def test_inflight_and_recovery_never_fall_back_to_prior_pass(self):
        self.evaluate('first')
        self.diff.at['records']=lambda:(_ for _ in ()).throw(Interrupted())
        with self.assertRaises(Interrupted):self.evaluate('second')
        self.assertEqual(self.projection()['state'],'in-flight')
        calls=list(self.diff.calls)
        recovered=self.hub.recover_interrupted(self.hub.evaluation_id('second'))
        self.assertEqual(recovered['result']['verdict'],'error')
        self.assertEqual(self.projection()['state'],'error')
        self.assertNotIn('start',self.diff.calls[len(calls):])

    def test_completed_view_rejects_later_declaration_or_target_change(self):
        self.evaluate();view=self.hub.operation_gates('run-one',1,'complete',origin=ORIGIN)
        self.declare(['other.txt'],'late-declaration')
        with self.assertRaises(LedgerError):require_operation_gates(self.ledger.snapshot()['state'],view)
