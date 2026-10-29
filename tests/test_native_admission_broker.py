"""Actual canonical SQLite receipts; external/native boundaries are controlled."""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from uas.forge import ForgeBinding
from uas.forge_audit import ForgeAudit
from uas.forge_read import ExternalReadBroker
from uas.forge_read_provider import BrokerReadProvider
from uas.forge_read_service import ReadBrokerClient
from uas.github_read import GitHubProject, ProviderResponse
from uas.ledger import RoomLedger, Origin, Command, Event, Transition, LedgerError
from uas.lifecycle import Supervisor
from uas.native_admission_broker import NativeAdmissionBroker
from uas.peer import FixturePeerHub, FixtureParticipant


class NativeAdmissionBrokerTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.root=Path(tmp.name)
        self.ledger=RoomLedger(self.root/'room.db','room');self.addCleanup(self.ledger.close)
        self.audit=ForgeAudit(self.root/'audit.db','deployment');self.addCleanup(self.audit.close)
        self.binding=ForgeBinding('room','project','owner/repo')
        self.origin=Origin('actor','builder','incarnation','authority',('forge-read','implement'))
        self.supervisor=Supervisor(self.root/'control','room',object(),authorize=lambda *_:False,revoke=lambda *_:None)
        self.supervisor._read=lambda:{'phase':'running','instance_id':'instance','spec':{'project_id':'project'}}
        hub=FixturePeerHub(self.ledger);hub.configure('configure',(FixtureParticipant('builder','actor'),FixtureParticipant('reviewer','reviewer')),'run')
        self.serial=0
        self.seed(lambda s:s.update(run_admissions={'run':{'status':'PREPARING','participant_id':'builder',
            'actor_id':'actor','issue_number':1,'context_generation':1,'reservation':'x'*131072,
            'seat_binding':{'provider':'selected'},'admission_origin':self.origin.canonical(),'admission_operation':'open'}}))
        self.calls=[];self.allowed=True
        class Transport:
            def __init__(self,outer):self.outer=outer
            def get(self,path):return self.outer.transport(path)
            __call__=get
        self.provider=BrokerReadProvider(GitHubProject('owner/repo'),Transport(self),None)
        self.external=ExternalReadBroker(self.binding,'instance',self.audit,lambda actor:self.provider,self.root/'results')
        self.client=object.__new__(ReadBrokerClient);self.client.supervisor=self.supervisor;self.client.binding=self.binding
        self.client.room_instance='instance';self.client.closed=False;self.client._guards={}
        self.packets=[]
        def perform(packet):
            self.packets.append(deepcopy(packet))
            guard=self.client._guards.pop(packet['request_id'])[1]
            return {'admission':'not-evaluated','observation':self.external.execute(packet['envelope'],
                origin=self.origin,authorize=guard)}
        self.client.perform=perform
        self.broker=NativeAdmissionBroker(self.ledger,self.binding,self.client)
    def seed(self,change):
        self.serial+=1
        def decide(state,_):change(state);return Transition(state,(Event('test.seed',{}),),{})
        self.ledger.apply(Command('seed-'+str(self.serial),'seed','run',1,{}),self.origin,authorize=lambda *_:True,decide=decide)
    def transport(self,path):
        self.calls.append(path)
        if '/dependencies/' in path:value=[]
        elif '/labels?' in path:value=[{'id':2,'name':'delivery:bounded'}]
        else:value={'id':101,'number':1,'state':'open','url':'https://api.github.com/repos/owner/repo/issues/1',
                    'repository_url':'https://api.github.com/repos/owner/repo','assignees':[{'id':7,'login':'actor'}]}
        return ProviderResponse(200,json.dumps(value).encode(),{})
    def prepare(self,operation='read'):
        return self.broker.prepare({'id':operation,'kind':'forge-read','argv':['issue','view','1']},
            origin=self.origin,authorize=lambda:self.allowed,admission=True,admission_reservation='run')
    def test_real_provider_admission_schema_and_same_canonical_terminal_retry(self):
        intent=self.prepare();out=self.broker.perform(intent)
        self.assertEqual('bounded',out['delivery_class']['value']);self.assertEqual(7,out['issue']['assignees'][0]['id'])
        result=self.broker.complete(intent,out,authorize=lambda:True);calls=list(self.calls)
        self.assertEqual(result,self.broker.complete(intent,out,authorize=lambda:True))
        retry=self.prepare();self.assertIsNone(self.broker.perform(retry))
        self.assertEqual(result,self.broker.complete(retry,None,authorize=lambda:True));self.assertEqual(calls,self.calls)
        self.assertEqual(1,len(self.packets));self.assertEqual('read',result['operation_id'])
        self.assertEqual({},self.ledger.snapshot()['state']['forge_pending'])
    def test_changed_intent_fields_rejected_before_external_contact(self):
        intent=self.prepare();original=deepcopy({k:v for k,v in intent.items() if k!='_broker'})
        for field,value in [('operation','other'),('origin',replace(self.origin,actor_id='other')),
                            ('route',replace(intent['route'],issue_number=2)),('admission',False)]:
            with self.subTest(field=field):
                intent[field]=value
                with self.assertRaises(LedgerError):self.broker.perform(intent)
                intent.update(deepcopy(original))
        self.assertFalse(self.calls)
    def test_late_reservation_context_or_actor_change_denies(self):
        for field,value in [('actor_id','other'),('context_generation',2),('seat_binding',{'provider':'swapped'}),('status','ACTIVE')]:
            with self.subTest(field=field):
                old=deepcopy(self.ledger.snapshot()['state']['run_admissions']['run'])
                intent=self.prepare('late-'+field)
                self.seed(lambda s:s['run_admissions']['run'].update({field:value}))
                with self.assertRaises(LedgerError):self.broker.perform(intent)
                self.seed(lambda s:s['run_admissions'].update(run=old))
        self.assertFalse(self.calls)
    def test_late_authority_loss_blocks_terminal_but_not_recontacts(self):
        intent=self.prepare();out=self.broker.perform(intent);calls=list(self.calls);self.allowed=False
        with self.assertRaisesRegex(LedgerError,'FORBIDDEN'):self.broker.complete(intent,out,authorize=lambda:True)
        self.allowed=True;self.broker.complete(intent,out,authorize=lambda:True);self.assertEqual(calls,self.calls)
    def test_interrupted_canonical_intent_does_not_repeat_external_read(self):
        intent=self.prepare();self.broker.perform(intent);calls=list(self.calls)
        replacement=NativeAdmissionBroker(self.ledger,self.binding,self.client)
        self.broker=replacement;retry=self.prepare()
        result=self.broker.perform(retry);self.assertEqual('INTERRUPTED_OBSERVATION',result['status'])
        self.broker.complete(retry,result,authorize=lambda:True);self.assertEqual(calls,self.calls)
    def test_same_external_id_after_reply_loss_uses_audit_cache(self):
        envelope={'id':'lost','kind':'admission-read','issue_number':1}
        first=self.external.execute(envelope,origin=self.origin,authorize=lambda:True);calls=list(self.calls)
        self.assertEqual(first,self.external.execute(envelope,origin=self.origin,authorize=lambda:True));self.assertEqual(calls,self.calls)
        with self.assertRaises(LedgerError):self.external.execute({**envelope,'issue_number':2},origin=self.origin,authorize=lambda:True)
        self.assertEqual(calls,self.calls)
    def test_external_strict_shape_and_adapter_no_self_assignment(self):
        for number in (True,0,'1',10_000_000_000):
            with self.assertRaises(LedgerError):self.external.execute({'id':'bad','kind':'admission-read','issue_number':number},origin=self.origin,authorize=lambda:True)
        with self.assertRaisesRegex(LedgerError,'FORGE_WRITE_UNAVAILABLE'):
            self.broker.prepare({'id':'assign','kind':'forge-write','argv':['issue','edit','1','--add-assignee','@me']},
                origin=self.origin,authorize=lambda:True,admission=True,admission_reservation='run')
        self.assertIsNone(self.broker.assignments);self.assertFalse(self.calls)
    def test_participant_allowlist_and_live_challenge_include_host_route_only(self):
        # Read-audited static boundary assertion complements existing actual native ingress tests.
        import ast
        source=Path(__file__).parents[1]/'uas'
        tree=ast.parse((source/'native_host_forge.py').read_text())
        sets=[{v.value for v in n.elts if isinstance(v,ast.Constant)} for n in ast.walk(tree) if isinstance(n,ast.Set)]
        self.assertIn({'forge-read','forge-write','forge-reconcile'},sets)
        self.assertFalse(any('admission-read' in values for values in sets))
        tree=ast.parse((source/'forge_read_service.py').read_text())
        auth=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='current_authority')
        self.assertIn('admission-read',{n.value for n in ast.walk(auth) if isinstance(n,ast.Constant)})

    def test_actual_client_live_challenge_rejects_changed_reservation_before_disclosure(self):
        from contextlib import nullcontext
        from types import SimpleNamespace
        self.client.lock=nullcontext();self.client.worker=SimpleNamespace(pidfd=123)
        sent=[]
        self.client.channel=SimpleNamespace(send=lambda data:sent.append(json.loads(data)) or len(data))
        intent=self.prepare()
        original_perform=self.client.perform
        def real(packet):
            out=original_perform(packet)
            # Restore exact trusted packet registration consumed by controlled transport.
            from uas.forge_wire import request_json
            import hashlib
            self.client._guards[packet['request_id']]=(hashlib.sha256(request_json(packet).encode()).hexdigest(),self.broker._owned(intent))
            responses=iter([{'authorize':'a'*32},{'ok':True,'observation':out['observation']}])
            def receive(*args):
                answer=next(responses)
                if 'authorize' in answer:self.seed(lambda state:state['run_admissions']['run'].update(actor_id='replaced'))
                return answer
            with patch('uas.forge_read_service.alive',return_value=True),patch('uas.forge_read_service.send_result'),patch('uas.forge_read_service.receive_result',side_effect=receive):
                return ReadBrokerClient.perform(self.client,packet)
        self.client.perform=real
        with self.assertRaises(LedgerError):self.broker.perform(intent)
        self.assertEqual(False,sent[0]['allowed']);self.assertEqual({},self.client._guards)
        self.assertIsNone(self.ledger.operation_receipt('forge-terminal-'+intent['key'],self.origin,authorize=lambda:True))

    def test_unassigned_issue_remains_explicit_canonical_refusal(self):
        from uas.run_admission import RunAdmission
        intent=self.prepare();out=self.broker.perform(intent)
        out['issue']['assignees']=[]
        with self.assertRaisesRegex(LedgerError,'ASSIGNMENT_REQUIRED_NO_WRITE_SUPPORT'):
            RunAdmission._eligible(out,{'issue_number':1,'github_user_id':7})
        self.assertIsNone(self.broker.assignments)

    def test_invalid_client_admission_packet_never_registers_or_dispatches(self):
        for envelope in ({'id':'x','kind':'admission-read','issue_number':True},
                         {'id':'x','kind':'admission-read','issue_number':1,'actor':'other'}):
            with self.assertRaisesRegex(LedgerError,'INVALID_FORGE_ENVELOPE'):
                self.client.prepare(envelope,self.origin,authorize=lambda:True)
        self.assertEqual({},self.client._guards);self.assertFalse(self.calls)
