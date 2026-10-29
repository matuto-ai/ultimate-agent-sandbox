"""Three independent requests through real local graph/admission/reset reducers.

The Room ledger, request/grant scopes, retirement/reset reducers and successor
transaction are real. Native tasks, filesystem checkout observations, Engine
lifecycle effects and certificate transport are controlled external boundaries.
Completion is an explicit authoritative input, not a provider integration proof.
"""
from contextlib import ExitStack, contextmanager, nullcontext
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace as N
import hashlib
import json
import io
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from uas import human_mtls, local_native_graph
from uas.local_native_graph import LocalNativeGraph
from uas.local_native_run_session import LocalNativeRunSession
from uas.local_successor_checkout import LocalNativeCheckoutClient, reuse_primary
from uas.local_services import LocalServices
from uas.local_runtime_plan import LocalRuntimePlan
from uas.native_session import SessionBudget
from uas.native_reviewer_recruitment import NativeReviewerRecruitment
from uas.native_pi_retirement import NativePiRetirement
from uas.native_claude_retirement import NativeClaudeRetirement
from uas.native_host_forge import NativePiHostForge, NativeHostForge
from uas.native_review_host import NativeReviewIdentity, NativeReviewHost
from uas.claude_native_admission import NativeClaudeRoot, NativeClaudeSupervisorAdmission
from uas.native_helper import NativeDescendantLease
from uas.workstation_control import SupervisorAdmission
from uas.ledger import LedgerError, Origin
from uas.peer import Readiness
from uas.git_provenance import GitProvenance
from uas.artifact_target import ArtifactSourceResolver
from uas.kernel_origin import OriginDenied
import test_native_run_admission_adversarial as fixture
from test_local_manager import TLS


class ThreeLocalRunsTests(unittest.TestCase):
    def setUp(self):
        self.c=fixture.NativeRunAdversarialTests();self.c.setUp();self.addCleanup(self.c.doCleanups)
        c=self.c;self.events=[];self.proven=set();self.old=[];self.connections=[];self.now=0
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(human_mtls.ssl,'SSLSocket',TLS))
        self.stack.enter_context(patch('uas.local_run_activity.time.monotonic',side_effect=lambda:self.now))
        self.stack.enter_context(patch('uas.native_session.time.monotonic',side_effect=lambda:self.now))
        c.human=replace(c.human,capabilities=('human-open-run','human-control-run'))
        c.session=replace(c.session,human=c.human)
        action=human_mtls.HumanActionGrant(c.session.deployment_id,c.room['id'],'instance','manager',c.human,
                                         ('open-run','authorize-run-request'))
        self.bindings=human_mtls.HumanActionBindings({hashlib.sha256(b'test-client').hexdigest():action})
        self.lifecycle={'phase':'running','desired':'running','instance_id':'instance',
                        'spec':{'project_id':c.room['project']['id'],'config_digest':'sha256:fixture'}}
        c.supervisor._read=lambda:self.lifecycle
        # Use a real validated selected host with nondefault UID range for
        # every composed Run/Stop/terminal/reset flow; native effects stay doubled.
        from uas.local_native import LocalNativeProfile
        from tests.test_local_installation import native_selection
        from tests.test_local_host_plan import profile as host_selection
        document=native_selection(c.plan.config)
        host_profile=host_selection();host_profile['installation_id']=document['installation_id']
        host_profile['mapping']['offset']=500000
        document.update(version=2,profile='local-native-v2',host_profile=host_profile,
                        mapping={'offset':500000,'size':65536})
        for value in document['rooms'].values():
            value['workstation']['image_reference']=value['workstation']['image_id']
        native=LocalNativeProfile(c.plan.config,document,c.room['id'],c.plan.config['deployment']['state_root'])
        selection={'version':1,'profile':'local-runtime-v1','room_id':c.room['id'],
            'installation_id':native.nonce,'human_mergers':[7],
            **{k+'_manifest':{'path':'/installation/'+k+'.json','sha256':'a'*64}
               for k in ('pi','claude','broker')}}
        plan=LocalRuntimePlan(c.plan.config_text,selection,installation_digest='f'*64,native_profile=native)
        self.assertEqual(plan.native_profile.host_profile.owners['runtime'],565532)
        self.lifecycle['spec']['config_digest']='sha256:'+plan.config_digest
        c.launcher.plan=plan
        c.launcher.exec_seat=N(participant_id=c.participant);c.launcher.stack=self.stack
        c.launcher.control=object();c.launcher.budget=SessionBudget(180)
        root=tempfile.TemporaryDirectory();self.addCleanup(root.cleanup)
        c.launcher.resources['supervisor_directory']=root.name
        host=object.__new__(LocalNativeRunSession);self.host=host
        host.plan=plan;host.resources=c.launcher.resources;host.supervisor=c.supervisor
        host._thread=threading.get_ident();host._busy=host._paused=False
        host._cleanup_confirmed=True;host._attempts={}
        host._pause_receipt=host._transition_paused=False
        host.origin=N(revoked=False,pidfd=9001);host.parent_fd=9002;host.control=object()
        host.ready={'room_id':c.room['id'],'room_instance':'instance'}
        self.commands=[];self.control_receipts=io.BytesIO()
        self.stack.enter_context(patch('uas.local_native_run_session.alive',return_value=True))
        self.stack.enter_context(patch('uas.local_native_run_session.select.select',
            side_effect=lambda *args:([host.parent_fd] if self.commands else [],[],[])))
        real_read=__import__('os').read
        self.stack.enter_context(patch('uas.local_native_run_session.os.read',
            side_effect=lambda fd,n:self.commands.pop(0) if fd==host.parent_fd else real_read(fd,n)))
        self.stack.enter_context(patch('uas.local_native_run_session.sys.stdout',N(buffer=self.control_receipts)))
        host.participant_id=c.participant
        graph=object.__new__(LocalNativeGraph);host._graph=graph;self.graph=graph
        graph.host=host;graph.closed=False;graph.stack=self.stack;graph.admissions=[]
        graph.owner=c.admission;graph.launcher=c.launcher;graph.budget=c.launcher.budget
        graph.activity=graph.recruitment=graph.transition_retirement=None
        graph.suspended=False;graph.stop_observations=None;graph._stop_unknown=False
        graph.git_broker=None
        graph.git_operations=graph.git_resources=graph.gate_operations=graph.gate_resources=graph.gate_profile=None
        graph.provenance=GitProvenance(Path(root.name)/'git.db',c.room['id'],c.room['project']['id'])
        self.addCleanup(graph.provenance.close)
        graph.source=object.__new__(ArtifactSourceResolver);graph.source.supervisor=c.supervisor
        graph.source.repo=Path(root.name)
        def resolve(capability,run,participant,instance):
            capability.require(c.supervisor)
            return {'run_id':run,'participant_id':participant,'room_instance':instance,
                    'head_sha':'a'*40,'source_digest':'b'*64,'checkout':'primary'}
        graph.source.resolve_locked=resolve
        self.primary=None
        checkout=object.__new__(LocalNativeCheckoutClient);checkout.current=host.current
        checkout.deadline=180;checkout.after_reuse=graph.refresh_after_reuse;checkout.close=Mock()
        graph.checkout=checkout
        from uas.native_run_admission import NativeRunAdmission
        NativeRunAdmission.__init__(c.admission,c.launcher,c.admission.allocator,checkout)
        checkout._call=self.checkout_call
        self.services=object.__new__(LocalServices);self.services.operation_lock=threading.RLock()
        self.services._rooms={c.room['id']:{'process':host,'instance':'instance','runtime_phase':'active'}}
        self.resources=N(services=self.services,backend=N(profile=N(spec=lambda:deepcopy(self.lifecycle['spec']))),state=self.lifecycle,data={'instance':'instance'})
        self.services._rooms[c.room['id']]['runtime_owner']=self.resources
        def ensure(*args):
            self.commands.append(b'R');host.current()
            self.assertFalse(host._paused)
            self.services._rooms[c.room['id']].update(runtime_phase='active')
        self.services.ensure=ensure
        c.supervisor.backend=N(admit=lambda state:{'Id':'same-container','State':{'Running':state['phase']=='running'}})
        def stop():
            self.commands.append(b'P');host.current()
            self.assertTrue(host._pause_receipt);self.assertTrue(host._transition_paused)
            self.assertFalse(graph.closed);graph.require_retired();self.events.append('stop')
            self.lifecycle.update(phase='stopped',desired='stopped')
        def start(spec):
            self.assertEqual(spec,self.lifecycle['spec']);self.events.append('start')
            self.lifecycle.update(phase='running',desired='running')
        c.supervisor.stop=stop;c.supervisor.start=start
        c.launcher.launch=self.launch_pi
        self.stack.enter_context(patch.object(NativeReviewerRecruitment,'_launch',lambda owner,*args:self.launch_claude(owner,*args)))
        def capture(obj,held,*,lifecycle):
            lifecycle.require(c.supervisor);obj.held=held;obj.attempted=False
        def retire(obj,timeout=5):
            if not obj.attempted:self.events.append('retire');obj.attempted=True;self.proven.add(id(obj.held))
            return {'state':'exited'}
        def require(obj,held=None):
            if held is not obj.held or id(held) not in self.proven:raise OriginDenied('unverified held task')
            return True
        for cls in (NativePiRetirement,NativeClaudeRetirement):
            for name,fn in (('__init__',capture),('retire',retire),('require_exited',require),('close',lambda obj:None)):
                self.stack.enter_context(patch.object(cls,name,fn))
        # External Forge reads return the same eligible issue for independent Runs.
        self.client=c.broker.client;self.client.review_enabled=self.client.gate_enabled=True

    @contextmanager
    def request(self,operation):
        conn=self.bindings.accept(TLS())
        with conn.request({'version':1,'action':'open-run','payload':{'operation_id':operation,'issue_number':1}}) as (_,session):
            yield session,conn.run_admission_lease(session,operation,1)
        conn.close()

    def slot(self,run):
        c=self.c
        return {'run':run,'participant':c.participant,'active':True,'phase':'ready','reason':'ACTIVE','observed_dirty':False,
                'observed_head':'a'*40,'base':'a'*40,'path':'/owned/checkout','slot':'primary'}

    def checkout_call(self,kind,run,operation):
        c=self.c
        if kind=='OBSERVE':return self.slot(run)
        if kind=='ALLOCATE':
            self.assertIsNone(self.primary);self.primary={'run':run,'participant':c.participant,'active':True,'phase':'ready'}
            self.events.append('allocate');return self.slot(run)
        self.assertEqual(kind,'REUSE_PRIMARY')
        slots={'slots':{'primary':self.primary}}
        allocator=N(repo=Path('/owned/checkout'),_locked=lambda action:nullcontext(slots),
                    _quiescent=lambda primary:True,_observe=lambda *args:{'disposition':'clean'})
        def release(prior,participant,*,authorize):
            authorize();self.assertEqual(prior,self.primary['run']);self.primary['active']=False
            self.events.append('release');return {'disposition':'clean','active':False}
        def reserve(new,participant,*,authorize):
            authorize();self.assertFalse(self.primary['active']);self.primary.update(run=new,active=True)
            self.events.append('reserve');return self.slot(new)
        allocator.release=release;allocator.reserve=reserve
        handoff=N(local_resources=self.resources,attempted=set(),owner=c.supervisor,child=self.host,
                  allocator=allocator,deadline=9999999999,pins={},plan=self.host.plan,actors=c.admission.actors,
                  resources=self.resources,_held=lambda:None,_snapshot=lambda:c.ledger.snapshot()['state'])
        value=reuse_primary(handoff,{'version':1,'kind':kind,'run_id':run,'operation_id':operation})
        return value

    def launch_pi(self,run,pending,slot,*,authorize,reset=None):
        c=self.c;authorize();epoch=pending['context_generation'];self.events.append('pi'+str(epoch))
        scope={'room_id':c.room['id'],'participant_id':c.participant,'run_id':run,'generation':1,'context_generation':epoch}
        handle=object.__new__(SupervisorAdmission);handle.seat=N(participant_id=c.participant,actor_id=c.actor,room_id=c.room['id'])
        receiver=N(scope=scope,observe=lambda:Readiness.SAFE)
        receiver.prepare_admission_observation=lambda:N(receiver=receiver,consumed=False,valid=True)
        def validate(sample,*,consume=False):
            if sample.receiver is not receiver or sample.consumed or not sample.valid:raise LedgerError('STALE_SAMPLE')
            if consume:sample.consumed=True
            return Readiness.SAFE
        receiver.validate_admission_observation=validate;receiver.discard_admission_observation=lambda sample:setattr(sample,'valid',False)
        handle.launch=N(incarnation='pi-'+str(epoch),native_recipe=N(scope=scope,manifest_digest='manifest'),native_receiver=receiver,
            native_readiness={'scope':scope,'profile_digest':'manifest','native':{'session_id':'pi-session-'+str(epoch),
                'runtime_id':'pi-runtime-'+str(epoch),'source':'native-empty-session-and-no-pending-messages'}})
        handle._current=lambda:True
        if reset:reset.complete(handle)
        service=object.__new__(NativePiHostForge);service.client=self.client
        service.origin=Origin(c.actor,c.participant,'pi-'+str(epoch),'native-'+str(epoch),('forge-read','implement','peer-traffic'))
        service.binding=N(operation_id='pi-'+str(epoch),epoch=epoch);service._current=lambda:True
        service.helper=N(forge_channel=object());service.receive_once=Mock();handle.forge_service=service
        connection=c.hub.connect('admit-pi-'+str(epoch),c.participant,'pi-'+str(epoch),object(),context_generation=epoch)
        self.connections.append(connection)
        def delivery(kind,receipt=None):c.hub.observe(connection,Readiness.SAFE);return {'status':'HELD'}
        handle._delivery_exchange=delivery;handle._authority=nullcontext();handle._delivery_lock=nullcontext();handle._delivery_pending=None
        c.launcher.started[c.participant]=handle;self.old.append(handle)
        return handle

    def launch_claude(self,owner,operation,run,generation):
        c=self.c;owner._allowed();epoch=owner._context_generation;participant=owner.selected['participant']
        self.events.append('claude'+str(epoch))
        scope={'room_id':c.room['id'],'participant_id':participant,'run_id':run,'generation':generation,'context_generation':epoch}
        root=object.__new__(NativeClaudeRoot);root.recipe=N(scope=scope,session_id='claude-session-'+str(epoch))
        root.admission=None;root.incarnation='claude-'+str(epoch);root.forge_service=root.review_host=None
        root.current=lambda:True;root._prepared_initialization={'deadline':self.now+30,'epoch':epoch,'operation_id':'claude-'+str(epoch)}
        root._prepared_admit_started=False
        root._native_readiness_json=json.dumps({'scope':scope,'native':{'session_id':root.recipe.session_id,'source':'fresh-home-explicit-session-native-idle-no-input'}})
        root.helper_lease=object.__new__(NativeDescendantLease);root.helper_lease.root=root;root.helper_lease.state='released'
        root.helper_lease.current=lambda:True;root.helper_lease._lineage=N(current=lambda:True)
        owner.root=root
        if owner._reset:owner._reset.complete(root)
        service=object.__new__(NativeHostForge);service.client=self.client
        service.origin=Origin(owner.selected['actor'],participant,root.incarnation,'authority-'+str(epoch),('forge-read','review'))
        service.binding=N(operation_id='claude-'+str(epoch),epoch=epoch);service._current=lambda:True
        service.helper=N(forge_channel=object());service.receive_once=Mock()
        connection=c.hub.connect('admit-claude-'+str(epoch),participant,root.incarnation,object(),context_generation=epoch)
        self.connections.append(connection)
        root.native_admission=object.__new__(NativeClaudeSupervisorAdmission);root.native_admission.launch=root
        root.native_admission.seat=N(participant_id=participant,room_id=c.room['id']);root.native_admission._current=lambda:True
        root.native_admission.controller='controller';root.native_admission._authority=nullcontext()
        root.native_admission._delivery_lock=nullcontext();root.native_admission._delivery_pending=None
        root.native_admission._delivery_exchange=lambda *args:{'status':'HELD'}
        receipt={'version':1,'operation_id':'claude-'+str(epoch),'epoch':epoch,'controller':'controller','admission_digest':'digest'}
        root.admission={**receipt,'state':'admitted','receipt':receipt}
        root.forge_service=service
        root.review_host=NativeReviewHost((owner.pi.forge_service,service),c.ledger,owner.provenance,owner.resolver,owner.binding,
                                         reviewers=[],human_mergers=[7])
        return root

    def complete(self,run):
        def completion(state):
            state['runs'][run].update(status='CLOSED',outcome='completed',completion={'merge_sha':'f'*40},control_revision=0,control_pending=None)
            state['fixture_context']['runs'][run]['status']='CLOSED'
            state['run_admissions'][run]['status']='CLOSED'
        self.c.seed(completion)

    def active_stop_resume(self):
        with self.request('first') as (session,grant):
            receipt=self.host.open_human('first',1,session=session,grant=grant)
        self.commands.append(b'P');self.host.current()
        self.lifecycle.update(phase='stopped',desired='stopped')
        self.assertTrue(self.graph.suspended);self.assertFalse(self.graph.closed)
        self.assertEqual('ACTIVE',self.graph.activity._row()['status'])
        self.lifecycle.update(phase='running',desired='running')
        self.commands.append(b'R');self.host.current()
        return receipt

    @contextmanager
    def terminal_request(self,payload):
        c=self.c
        action=human_mtls.HumanActionGrant(c.session.deployment_id,c.room['id'],'instance','manager',c.human,
                                         ('terminal-stop',))
        bindings=human_mtls.HumanActionBindings({hashlib.sha256(b'test-client').hexdigest():action})
        connection=bindings.accept(TLS())
        with connection.request({'version':1,'action':'terminal-stop','payload':payload}) as (_,session):
            yield session
        connection.close()

    def terminal_payload(self,receipt):
        return {'operation_id':'explicit-end','run_id':receipt['run_id'],
                'generation':1,'control_revision':0,'reason':'operator-ended-interrupted-run'}

    def test_explicit_terminal_fresh_request_then_successor_resets_without_restop(self):
        from uas.local_manager_actions import LocalNativeRunActions
        receipt=self.active_stop_resume();actions=LocalNativeRunActions(self.host)
        payload=self.terminal_payload(receipt);workspace=deepcopy(self.primary)
        before=list(self.events)
        connection=self.bindings.accept(TLS())
        with self.assertRaisesRegex(LedgerError,'HUMAN_ACTION_DENIED'):
            with connection.request({'version':1,'action':'terminal-stop','payload':payload}):
                self.fail('missing terminal grant accepted')
        connection.close()
        with self.request('no-implicit-cancel') as (session,grant):
            with self.assertRaisesRegex(LedgerError,'LOCAL_PREVIOUS_RUN_NOT_COMPLETED'):
                actions.open({'operation_id':'no-implicit-cancel','issue_number':1},session,grant=grant)
            with self.assertRaisesRegex(LedgerError,'LOCAL_TERMINAL_AUTHENTICATION_REQUIRED'):
                actions.terminal(payload,session)
        self.assertEqual('ACTIVE',self.graph.activity._row()['status'])
        self.assertEqual(before,self.events)
        with self.terminal_request(payload) as session:pass
        with self.assertRaisesRegex(LedgerError,'LOCAL_TERMINAL_AUTHENTICATION_REQUIRED'):
            actions.terminal(payload,session)
        from uas.local_manager import LocalManager
        from test_local_manager import wire
        terminal_grant=human_mtls.HumanActionGrant(self.c.session.deployment_id,self.c.room['id'],
            'instance','manager',self.c.human,('terminal-stop',))
        terminal_bindings=human_mtls.HumanActionBindings({hashlib.sha256(b'test-client').hexdigest():terminal_grant})
        manager=LocalManager(terminal_bindings,lambda _:None,authority='localhost:8765',run_actions=actions)
        channel=TLS(wire({'version':1,'action':'terminal-stop','payload':payload}))
        manager.handle(channel)
        self.assertIn(b'200 OK',channel.output)
        result=json.loads(channel.output.split(b'\r\n\r\n',1)[1])
        self.assertEqual('CLOSED',result['status']);self.assertEqual('stopped',result['outcome'])
        self.assertEqual(2,result['generation']);self.assertEqual(workspace,self.primary)
        self.assertEqual(before,self.events)
        with self.terminal_request(payload) as session:
            self.assertEqual(result,actions.terminal(payload,session))
        # Repeated operator Stop/Start after explicit terminalization verifies
        # retained terminal proof, not obsolete pre-fence canonical observations.
        self.commands.append(b'P');self.host.current()
        self.lifecycle.update(phase='stopped',desired='stopped')
        self.lifecycle.update(phase='running',desired='running')
        self.commands.append(b'R');self.host.current()
        self.assertEqual(before,self.events)
        with self.request('second') as (session,grant):
            next_run=actions.open({'operation_id':'second','issue_number':1},session,grant=grant)
        self.assertNotEqual(receipt['run_id'],next_run['run_id'])
        self.assertEqual('ACTIVE',next_run['status']);self.assertEqual(2,self.events.count('retire'))
        state=self.c.ledger.snapshot()['state']
        for participant in (self.c.participant,self.host.plan.seats['claude']['participant']):
            self.assertEqual(2,state['fixture_context']['participants'][participant]['context_generation'])
        for connection in self.connections[:-2]:
            with self.assertRaisesRegex(LedgerError,'STALE_CONNECTION'):
                self.c.hub.observe(connection,Readiness.SAFE)

    def test_unknown_stop_observation_refuses_terminal_and_successor(self):
        from uas.local_manager_actions import LocalNativeRunActions
        receipt=self.active_stop_resume();actions=LocalNativeRunActions(self.host)
        before=list(self.events);workspace=deepcopy(self.primary)
        self.graph.stop_observations.unknown=True
        with self.terminal_request(self.terminal_payload(receipt)) as session:
            with self.assertRaisesRegex(LedgerError,'LOCAL_STOP_CLEANUP_UNKNOWN'):
                actions.terminal(self.terminal_payload(receipt),session)
        with self.request('forbidden-successor') as (session,grant):
            with self.assertRaisesRegex(LedgerError,'LOCAL_PREVIOUS_RUN_NOT_COMPLETED'):
                actions.open({'operation_id':'forbidden-successor','issue_number':1},session,grant=grant)
        self.assertEqual('ACTIVE',self.graph.activity._row()['status'])
        self.assertEqual(before,self.events);self.assertEqual(workspace,self.primary)

    def test_three_fresh_requests_keep_work_and_advance_native_contexts(self):
        self.three_runs(ordinary_stop=False)

    def test_completed_stop_resume_then_three_fresh_runs_no_duplicate_retirement(self):
        self.three_runs(ordinary_stop=True)

    def three_runs(self, *, ordinary_stop):
        receipts=[];sessions=[]
        for index in (1,2,3):
            operation='work-'+str(index)
            with self.request(operation) as (session,grant):
                receipt=self.host.open_human(operation,1,session=session,grant=grant)
            sessions.append(session);receipts.append(receipt)
            self.assertFalse(session.allowed('open-run'))
            with self.assertRaisesRegex(LedgerError,'FORBIDDEN'):
                self.host.open_human(operation,1,session=session,grant=grant)
            self.assertFalse(hasattr(self.graph.activity.request,'session'))
            self.now+=1000
            self.assertEqual(self.graph.step()['status'],'ACTIVE')
            counts=list(self.events)
            with self.request(operation) as (fresh,grant):
                self.assertEqual(receipt,self.host.open_human(operation,1,session=fresh,grant=grant))
            self.assertEqual(counts,self.events)
            state=self.c.ledger.snapshot()['state']
            for participant in (self.c.participant,self.host.plan.seats['claude']['participant']):
                self.assertEqual(index,state['fixture_context']['participants'][participant]['context_generation'])
            if index>1:
                with self.assertRaisesRegex(LedgerError,'STALE_CONNECTION|BINDING'):
                    self.c.admission._authority(self.old[-2])
                for connection in self.connections[:-2]:
                    with self.assertRaisesRegex(LedgerError,'STALE_CONNECTION'):
                        self.c.hub.observe(connection,Readiness.SAFE)
                previous=state['runs'][receipts[-2]['run_id']]
                self.assertEqual('VERIFIED',previous['native_stop']['status'])
            with self.request('premature-'+str(index)) as (fresh,grant):
                with self.assertRaisesRegex(LedgerError,'LOCAL_PREVIOUS_RUN_NOT_COMPLETED'):
                    self.host.open_human('premature-'+str(index),1,session=fresh,grant=grant)
            self.assertEqual(counts,self.events)
            self.complete(receipt['run_id'])
            if ordinary_stop and index<3:
                before=self.events.count('retire')
                self.commands.append(b'P');self.host.current()
                self.lifecycle.update(phase='stopped',desired='stopped')
                self.assertTrue(self.host._paused)
                self.assertIsNone(self.host.step())
                self.assertTrue(self.graph.suspended)
                self.assertFalse(self.graph.closed)
                self.assertEqual(before+2,self.events.count('retire'))
                self.assertFalse(self.graph.admissions)
                self.assertNotIn('native_stop',self.c.ledger.snapshot()['state']['runs'][receipt['run_id']])
                self.lifecycle.update(phase='running',desired='running')
                self.commands.append(b'R');self.host.current()
                self.assertFalse(self.host._paused)
                with patch.object(self.graph.activity,'step',side_effect=AssertionError('old activity resumed')):
                    self.assertEqual('CLOSED',self.graph.step()['status'])
                self.assertEqual(before+2,self.events.count('retire'))
        self.assertEqual(['allocate','pi1','claude1']+
                         ['retire','retire','stop','release','reserve','start','pi2','claude2']+
                         ['retire','retire','stop','release','reserve','start','pi3','claude3'],self.events)
        self.assertEqual(3,len({r['run_id'] for r in receipts}))
        self.assertEqual(3,len({id(s) for s in sessions}))
        self.assertEqual(2,self.events.count('stop'));self.assertEqual(2,self.events.count('start'))
        self.assertEqual(2,self.events.count('release'));self.assertEqual(2,self.events.count('reserve'))
        control=[json.loads(line) for line in self.control_receipts.getvalue().splitlines()]
        self.assertEqual(['participants-revoked','runtime-resumed']*(4 if ordinary_stop else 2),[r['status'] for r in control])
        self.assertIsNone(self.c.admission._session);self.assertIsNone(self.graph.recruitment._session)

if __name__=='__main__':unittest.main()
