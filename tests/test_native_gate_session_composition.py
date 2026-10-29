"""Consumed session constructor chain, real Room reducers; native boundaries inert."""
from contextlib import ExitStack
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace as N
import tempfile
import inspect
import unittest
from unittest.mock import Mock,patch

import test_native_run_admission_adversarial as run_fixture
from uas import native_session as session
from uas.artifact_helper import GateEndpointLease,GateWorkstation
from uas.artifact_protocol import PROFILE_ID
from uas.artifact_target import ArtifactSourceResolver
from uas.claude_native_admission import NativeClaudeRoot,NativeClaudeSupervisorAdmission
from uas.git_service import GitBrokerClient
from uas.native_git_resources import NativeGitResources,GitMountProfile,FIXED_ARTIFACTS,LOADER
from uas.native_git_operations import NativeGitOperations
from uas.native_gate_resources import NativeGateResources,NativeGateMountProfile,HELPERS,HOST_TOOLS
from uas.native_gate_operations import NativeGateOperations
from uas.native_gate_workflow import NativeGateWorkflow
from uas.native_run_admission import NativeRunLauncher,NativeHumanRunRequest
from uas.native_reviewer_recruitment import NativeReviewerRecruitment
from uas.native_review_host import NativeReviewHost
from uas.native_session_driver import NativeSessionDriver
from uas.native_pi_restore import NativePiSameRunRestore
from uas.native_checkout_handoff import NativeCheckoutClient
from uas.forge_read_service import ReadBrokerClient
from uas.ledger import Origin
from uas.workstation_exec import EndpointLease


class NativeGateSessionCompositionTests(unittest.TestCase):
    def setUp(self):
        c=run_fixture.NativeRunAdversarialTests();c.setUp();self.addCleanup(c.doCleanups);self.c=c
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.instance='a'*32;c.session=replace(c.session,instance_id=self.instance)
        c.supervisor._read=lambda:{'phase':'running','desired':'running','instance_id':self.instance,
            'spec':{'project_id':c.room['project']['id']}}
        c.broker.client.room_instance=self.instance
        for name in ('git','git_broker','gate'):
            c.plan.installation[name+'_manifest']={'path':'/installation/'+name+'.json','sha256':'b'*64}
        from uas.native_qualification import QualificationPlan
        c.plan=QualificationPlan(c.plan.config_text,c.plan.installation,installation_digest='b'*64)
        image=next(i['reference'] for i in c.plan.config['deployment']['images'] if i['id']==c.room['image'])
        git_manifest={'version':1,'profile':'native-git-primary-v1','image_reference':image,'image_id':'sha256:'+'e'*64,
            'artifacts':dict.fromkeys(FIXED_ARTIFACTS,'a'*64),'python_version':'3.11.9',
            'abi_artifacts':{LOADER:'b'*64,'/lib/x86_64-linux-gnu/libc.so.6':'c'*64},
            'uas_tree_sha256':'d'*64,'backend_sha256':'e'*64,'backend_path':'/mnt/uas-native/'+'a'*32+'/git-backend'}
        state={'room_id':c.room['id'],'instance_id':self.instance}
        self.git_profile=GitMountProfile.from_plan(c.plan,state,git_manifest,'b'*64,container_id='c'*64,mapping_digest='f'*64)
        gate_manifest={'version':1,'profile':PROFILE_ID,'image_reference':image,'image_id':git_manifest['image_id'],
            'helpers':dict.fromkeys(HELPERS,'a'*64),'host_materializer':dict.fromkeys(HOST_TOOLS,'b'*64)}
        self.gate_profile=NativeGateMountProfile.from_plan(c.plan,state,gate_manifest,'b'*64,container_id='c'*64,mapping_digest='f'*64)
        self.resources={'room_id':c.room['id'],'instance':self.instance,'supervisor_directory':str(self.root),
            'peer_path':'/run/uas-native/'+self.instance+'/peer/pi.sock','peer_fd':10001,'control_fd':10002,
            'workstation_id':'c'*64,'hub_ledger_path':c.ledger._db.execute('PRAGMA database_list').fetchone()[2],'mapping_digest':'f'*64,'git_backend_fd':10003}
        self.request=NativeHumanRunRequest('session-open',1,c.participant,c.session)
        self.provenance=session.GitProvenance(self.root/'git-history.db',c.room['id'],c.room['project']['id'])
        self.addCleanup(self.provenance.close)
        self.captured={};self.channels=[];self.fail_gate=False

    def execute(self):
        c=self.c;old_launch=c.launcher.launch;old_client=c.broker.client
        git_signature=inspect.signature(NativeGitResources.from_session)
        gate_signature=inspect.signature(NativeGateResources.from_session)
        source=object.__new__(ArtifactSourceResolver);source.supervisor=c.supervisor;source.repo=Path(c.room['project']['roots']['repo'])
        def resolved(cap,*args):
            cap.require(c.supervisor)
            return {'run_id':args[0],'participant_id':c.participant,'room_instance':self.instance,
                'head_sha':'a'*40,'source_digest':'b'*64,'checkout':'controlled'}
        source.resolve_locked=resolved
        source.resolve=lambda *args:None
        def read_init(client,channel,supervisor,binding,instance,**kwargs):
            client.supervisor=supervisor;client.binding=binding;client.room_instance=instance
            client.review_enabled=client.gate_enabled=True
            client.closed=False;client._guards=old_client._guards;client.perform=old_client.perform
        def git_init(client,channel,binding,instance,**kwargs):client.binding=binding;client.closed=False
        old_ctor=NativeRunLauncher.__init__
        def launcher_init(owner,*args,**kwargs):
            old_ctor(owner,*args,**kwargs);c.launcher=owner;c.hub=owner.hub
            self.captured['launcher']=owner
            self.assertIs(owner.gate_profile,self.gate_profile)
            self.assertEqual(owner.mounts[-2:],self.gate_profile.mounts)
        def native_launch(owner,run,pending,slot,*,authorize,**kwargs):
            handle=old_launch(run,pending,slot,authorize=authorize)
            handle.forge_service.client=owner.forge_broker.client
            return handle
        def checkout_init(owner,channel,*,deadline):
            owner.close=Mock(side_effect=channel.close)
            owner.allocate=c.admission.checkout_client.allocate;owner.observe=c.admission.checkout_client.observe
            self.captured['quota']=owner
        def recruit_native(recruitment,operation,run,generation):
            recruitment._allowed()
            self.assertIs(recruitment.launcher.gate_profile,self.gate_profile)
            selected=recruitment.selected
            root=object.__new__(NativeClaudeRoot);ingress=object.__new__(session.NativeHostForge)
            ingress.client=recruitment.owner.broker.client
            ingress.origin=Origin(selected['actor'],selected['participant'],'reviewer-incarnation','reviewer-authority',('forge-read','review'))
            ingress.binding=N(operation_id='reviewer-operation');ingress._current=Mock()
            recruitment.owner.launcher.hub.connect('admit-reviewer-operation',selected['participant'],'reviewer-incarnation',object())
            root.forge_service=ingress;root.native_admission=object.__new__(NativeClaudeSupervisorAdmission)
            root.review_host=NativeReviewHost((recruitment.pi.forge_service,ingress),c.ledger,recruitment.provenance,source,recruitment.binding,
                reviewers=[],human_mergers=[7])
            recruitment.root=root;self.captured['host']=root.review_host
            return root
        def git_resources(*args,**kwargs):
            git_signature.bind(*args,**kwargs)  # Native admission is mocked; API is not.
            value=object.__new__(NativeGitResources);value.profile=self.git_profile;value.gate_profile=self.gate_profile
            value.plan=c.plan;value.supervisor=c.supervisor;value.close=Mock();self.captured['git_resources']=value;return value
        def git_operations(value,owner,reviewer,resources,broker):
            value.owner=owner;value.reviewer=reviewer;value.resources=resources;value.close=Mock()
        def gate_resources(*args,**kwargs):
            gate_signature.bind(*args,**kwargs)
            self.assertIs(kwargs['gate_profile'],self.gate_profile)
            self.assertIs(kwargs['git_resources'],self.captured['git_resources'])
            self.assertIs(kwargs['quota_client'],self.captured['quota'])
            self.assertIs(kwargs['review_host'],self.captured['host'])
            if self.fail_gate:raise ValueError('controlled resource admission failure')
            value=object.__new__(NativeGateResources);value.review_host=kwargs['review_host'];value.supervisor=kwargs['supervisor']
            value.engine=args[2];value.room_id=c.room['id'];value.instance=self.instance
            value.workstation=GateWorkstation(c.room['id'],self.instance,*[x*64 for x in '123456'],'native-artifacts')
            value.require=Mock(return_value=True);value.reserve_capacity=Mock();value.listener=kwargs['listener']
            value.endpoint=object.__new__(GateEndpointLease)
            value.scratch_root=self.root/'scratch';value.journal_root=self.root/'targets';value.launch_journal_root=self.root/'launches'
            value.close=Mock();self.captured['gate_resources']=value;return value
        def driver_run(driver):
            host=driver.recruitment.root.review_host
            self.assertIs(type(host.gate_workflow),NativeGateWorkflow)
            self.assertIs(host.gates.control,host.gate_workflow.controls[PROFILE_ID])
            self.assertIs(host.gates.control.service.targets.resolver,source)
            self.assertIs(host.gates.control.service.resolver,host.sources)
            self.assertIs(host.identity.ledger,c.ledger);self.assertIs(host.identity.supervisor,c.supervisor)
            self.assertIs(driver.owner.launcher.gate_profile,self.gate_profile)
            self.assertIs(type(driver.pi_restoration),NativePiSameRunRestore)
            self.assertIs(driver.pi_restoration.owner,driver.owner)
            self.assertIs(driver.pi_restoration.recruitment,driver.recruitment)
            self.assertIs(driver.pi_restoration.graph.git,driver.git_operations)
            self.assertEqual(c.ledger.snapshot()['state']['runs'][driver.owner.run_id(self.request.operation_id)]['status'],'ACTIVE')
            self.captured['driver']=driver
            return {'current_run':driver.owner.run_id(self.request.operation_id),'outcome':'inconclusive'}
        def channel(*args,**kwargs):
            value=Mock();self.channels.append(value);return value
        def restoration_init(value,owner,recruitment,request,budget,*,git_operations=None):
            # This composition test supplies inert native roots; actual restore
            # capture/guards have their own finite source-only test inventory.
            value.owner=owner;value.recruitment=recruitment;value.request=request;value.budget=budget
            value.graph=N(git=git_operations)
        def endpoint_init(value,path,**kwargs):value.path=Path(path)
        metadata={'seats':[{'participant_id':s['participant'],'capabilities':next(p['capabilities'] for p in c.room['profiles'] if p['id']==s['profile'])+['peer-traffic']} for s in c.room['seats']]}
        targets=Mock();targets.resolver=source
        import os
        real_close=os.close
        with ExitStack() as stack:
            patches=[patch('os.getuid',return_value=165533),patch('os.getgid',return_value=165533),patch('os.umask'),
                patch('os.close',side_effect=lambda fd:None if fd>=10000 else real_close(fd)),
                patch.object(session,'probe'),patch('uas.native_qualification_backend.readonly_supervisor',return_value=c.supervisor),
                patch.object(EndpointLease,'__init__',endpoint_init),patch.object(session.socket,'socket',side_effect=channel),
                patch.object(session,'enable'),patch.object(session,'_hub',return_value=(Mock(),Mock(),{'controller':'a'*32},metadata)),
                patch.object(ReadBrokerClient,'__init__',read_init),patch.object(ReadBrokerClient,'close'),
                patch.object(GitBrokerClient,'__init__',git_init),patch.object(GitBrokerClient,'close'),
                patch.object(session,'RoomLedger',return_value=c.ledger),patch.object(session,'GitProvenance',return_value=self.provenance),patch.object(session,'CheckoutAllocator',return_value=c.admission.allocator),
                patch.object(session,'ArtifactSourceResolver',return_value=source),patch.object(NativeGitResources,'from_session',side_effect=git_resources),
                patch.object(NativeRunLauncher,'__init__',launcher_init),patch.object(NativeRunLauncher,'launch',native_launch),
                patch.object(NativeCheckoutClient,'__init__',checkout_init),patch.object(NativeCheckoutClient,'close'),
                patch.object(NativeReviewerRecruitment,'_launch',recruit_native),patch.object(NativeGitOperations,'__init__',git_operations),
                patch.object(NativePiSameRunRestore,'__init__',restoration_init),
                patch.object(session,'_gate_listener',side_effect=channel),patch.object(NativeGateResources,'from_session',side_effect=gate_resources),
                patch('uas.native_gate_operations.ArtifactTargets',return_value=targets),patch.object(NativeSessionDriver,'run',driver_run)]
            for value in patches:stack.enter_context(value)
            return session.run(c.plan,self.resources,10004,10005,10006,human_request=self.request)

    def test_authenticated_run_consumes_exact_gate_chain_and_canonical_active_run(self):
        result=self.execute()
        self.assertEqual(result['status'],'NATIVE_RUN_SESSION_FINISHED')
        self.assertIn('driver',self.captured)
        for value in self.channels:value.close.assert_called_once()
        self.captured['gate_resources'].close.assert_called_once()

    def test_late_gate_resource_failure_closes_owned_channels_and_never_enters_driver(self):
        self.fail_gate=True
        with self.assertRaisesRegex(ValueError,'controlled resource admission failure'):self.execute()
        self.assertNotIn('driver',self.captured)
        for value in self.channels:value.close.assert_called_once()
        self.captured['git_resources'].close.assert_called_once()
