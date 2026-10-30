"""Dynamic identity propagation with pure plans and controlled host observations."""
from copy import deepcopy
from types import SimpleNamespace as N
import unittest
from unittest.mock import patch

from uas import native_git_resources as git
from uas.local_native import LocalNativeProfile
from uas.local_host_profile import LocalHostProfile, HostProfileError
from uas.kernel_origin import OriginDenied
from uas.workstation_exec import ExecSeat
from tests import test_local_runtime_plan as local_fixture
from tests import test_native_git_supervisor as supervisor_fixture
from tests.test_local_host_plan import profile


def local_plan(offset=500000, *, git_enabled=False):
    fixture=local_fixture.LocalRuntimePlanTests();fixture.setUp()
    host=profile();host['installation_id']=fixture.doc['installation_id']
    host['mapping']['offset']=offset
    fixture.doc.update(version=2,profile='local-native-v2',host_profile=host,
                       mapping={'offset':offset,'size':65536})
    fixture.native=LocalNativeProfile(fixture.config,fixture.doc,'alpha',fixture.config['deployment']['state_root'])
    if git_enabled:
        fixture.selection.update({k+'_manifest':{'path':'/installation/'+k+'.json','sha256':'a'*64}
                                  for k in ('git','git_broker')})
    return fixture.plan()


class LocalGitGateIdentityTests(unittest.TestCase):
    def test_concrete_plan_selects_identity_and_qualification_remains_fixed(self):
        plan=local_plan()
        self.assertEqual(git.host_mapping(plan),(500000,65536))
        self.assertEqual(git.host_owners(plan)['runtime'],565532)
        self.assertEqual(git.host_owners(N())['runtime'],165532)
        with self.assertRaises(HostProfileError):
            git.host_owners(N(native_profile=plan.native_profile))

    def test_pid1_kernel_uid_gid_must_match_exact_selected_mapping(self):
        host=local_plan().native_profile.host_profile
        pid=123;cid='5'*64
        status=('Pid:123\nTgid:123\nPPid:1\nUid:565532 565532 565532 565532\n'
                'Gid:565532 565532 565532 565532\nNSpid:123 1\nNStgid:123 1\n').encode()
        stat_text='123 (sleep) S '+' '.join(['0']*18+['77'])
        group='0::/system.slice/docker-'+cid+'.scope\n'
        self.assertEqual(git.parse_process_binding(pid,cid,status,stat_text,group,host_profile=host)[1],77)
        for altered in (status.replace(b'565532',b'165532'),status.replace(b'Gid:565532',b'Gid:565530')):
            with self.assertRaisesRegex(OriginDenied,'mapping differs'):
                git.parse_process_binding(pid,cid,altered,stat_text,group,host_profile=host)
        with self.assertRaisesRegex(OriginDenied,'mapping differs'):
            git.parse_process_binding(pid,cid,status,stat_text,group)
        with self.assertRaisesRegex(OriginDenied,'validated host profile'):
            git.parse_process_binding(pid,cid,status,stat_text,group,host_profile=N(offset=500000))

    def test_actual_git_supervisor_accepts_admitted_dynamic_worker_only(self):
        fixture=supervisor_fixture.NativeGitSupervisorTests();fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.resources.plan=local_plan()
        fixture.resources.worker_host_uid=565530;fixture.resources.worker_host_gid=565532
        fixture.worker=ExecSeat('room','instance','participant','actor','seat-a','c'*64,565530,565532)
        self.assertIs(fixture.create().native_resources,fixture.resources)
        fixture.resources.worker_host_uid=165530
        with self.assertRaisesRegex(OriginDenied,'mapping differs'):fixture.create()

    def test_gate_revalidation_checks_dynamic_directory_owner_not_qualification_uid(self):
        from contextlib import nullcontext
        from pathlib import Path
        import stat
        from unittest.mock import Mock
        from uas import native_gate_resources as gate, native_qualification_backend as backend
        from uas.artifact_protocol import ArtifactError
        owner=gate.NativeGateResources();owner._closed=False;owner.deadline=100
        owner.plan=local_plan();owner._host_owners=git.host_owners(owner.plan)
        owner.workstation=N(host_profile=owner.plan.native_profile.host_profile);owner.room_id='alpha';owner.instance='1'*32;owner.container_id='4'*64
        owner.supervisor=N(_locked=nullcontext,_read=lambda:{'instance_id':owner.instance})
        owner.git_resources=Mock();owner.git_resources._container_pid=123
        owner.git_resources.profile.mount_tuples.return_value=()
        owner.data={'peer_path':'/owned/peer/pi.sock'}
        owner.profile=N(image_id='sha256:'+'4'*64,image_reference='selected',mount_tuples=lambda:())
        value={'State':{'Running':True,'Pid':123}};owner.engine=N(inspect_container=lambda _:deepcopy(value))
        owner.endpoint=Mock();owner.endpoint.path=Path('/owned/gate.sock')
        owner.listener=Mock();owner.listener.getsockname.return_value='/owned/gate.sock';owner.listener.getsockopt.return_value=1
        owner._listener_identity=(8,9)
        owner.scratch_root=Path('/scratch');owner.journal_root=Path('/journal');owner.launch_journal_root=Path('/launch')
        owner._directory_identities={key:(1,index) for index,key in enumerate(('scratch_root','journal_root','launch_journal_root'))}
        selected_uid=[565533]
        def metadata(path,**kwargs):
            key=next(k for k in owner._directory_identities if getattr(owner,k)==path)
            dev,ino=owner._directory_identities[key]
            return N(st_dev=dev,st_ino=ino,st_uid=selected_uid[0],st_gid=selected_uid[0],
                     st_mode=stat.S_IFDIR|(0o711 if key=='scratch_root' else 0o700))
        with (patch.object(gate.time,'monotonic',return_value=1),
              patch.object(backend,'validate_native_container'),
              patch.object(gate.os,'fstat',return_value=N(st_dev=8,st_ino=9)),
              patch.object(Path,'stat',metadata)):
            self.assertTrue(owner.require(owner.workstation))
            selected_uid[0]=165533
            with self.assertRaisesRegex(ArtifactError,'RESOURCE_REPLACED'):owner.require(owner.workstation)

    def test_reviewer_seat_maps_from_same_plan_before_recipe(self):
        from unittest.mock import Mock
        from uas import native_reviewer_recruitment as reviewer
        from uas.workstation_admission import ReceiverIdentity
        plan=local_plan()
        owner=reviewer.NativeReviewerRecruitment.__new__(reviewer.NativeReviewerRecruitment)
        owner.owner=N(room=plan.room);owner.selected=plan.seats['claude']
        owner._context_generation=1;owner._pin={'checkout':{'path':'/owned/repo'}}
        owner.profile={'capabilities':[]};owner._allowed=Mock()
        owner.launcher=N(plan=plan,resources={'instance':'1'*32,'supervisor_directory':'/owned/journal',
            'workstation_id':'4'*64,'claude_manifest_path':'/selected/claude.json','peer_path':'/owned/peer.sock'},
            admission_seat=N(receiver=ReceiverIdentity(65532,65532,'hub','b'*64)),mounts=())
        class AtRecipe(Exception):pass
        with patch.object(reviewer.NativeClaudeRecipe,'from_configuration',side_effect=AtRecipe) as recipe:
            with self.assertRaises(AtRecipe):owner._launch('operation','run',1)
        seat=recipe.call_args.kwargs['seat']
        self.assertEqual((seat.host_uid,seat.host_gid),(565532,565532))

    def test_native_git_admission_observes_dynamic_mapping_before_endpoint_handoff(self):
        from contextlib import ExitStack, nullcontext
        import hashlib, json, time
        from pathlib import Path
        from unittest.mock import Mock
        from uas.docker_exec_api import DockerExecAPI
        from uas.lifecycle import Supervisor
        from uas.local_native import LocalNativeObserver
        from uas import workstation_exec
        from tests import test_native_git_resources as fixture
        plan=local_plan(git_enabled=True)
        state={'room_id':'alpha','phase':'running','instance_id':'b'*32,
               'spec':{'config_digest':'sha256:'+plan.config_digest}}
        _,_,manifest=fixture.fixture()
        manifest.update(image_id=plan.native_profile.image_id,
                        image_reference=plan.native_profile.image_reference,
                        backend_path=str(plan.native_profile.state_root/'git-backend'))
        supervisor=Supervisor.__new__(Supervisor);supervisor.backend=LocalNativeObserver.__new__(LocalNativeObserver)
        supervisor._locked=nullcontext;supervisor._read=lambda:deepcopy(state)
        engine=DockerExecAPI.__new__(DockerExecAPI);engine.inspect_container=Mock(return_value={'State':{'Pid':123}})
        maps={'uid_map':'0 500000 65536\n','gid_map':'0 500000 65536\n','overflow_uid':65534,'overflow_gid':65534}
        mapping=hashlib.sha256(json.dumps(maps,sort_keys=True).encode()).hexdigest()
        endpoint=str(plan.native_profile.endpoints/state['instance_id']/'git'/'request.sock')
        resources={'instance':state['instance_id'],'workstation_id':'5'*64,'git_manifest_path':'/installation/git.json',
                   'mapping_digest':mapping,'git_backend_fd':50,'git_request_path':endpoint}
        class AtEndpoint(Exception):pass
        for actual_mapping in ('0 500000 65536\n','0 100000 65536\n'):
            with ExitStack() as stack:
                stack.enter_context(patch.object(git,'selection',return_value=manifest))
                stack.enter_context(patch.object(git.NativeGitResources,'_verify_container'))
                process=stack.enter_context(patch.object(git,'process_binding',return_value=(123,77)))
                stack.enter_context(patch.object(git.os,'pidfd_open',return_value=42))
                stack.enter_context(patch.object(git,'alive',return_value=True))
                stack.enter_context(patch.object(git,'_identity',return_value=(1,42)))
                stack.enter_context(patch.object(Path,'read_text',lambda p:'65534' if 'overflow' in str(p) else actual_mapping))
                stack.enter_context(patch.object(git,'verify_engine_payload'))
                stack.enter_context(patch.object(git,'require_sealed',return_value=(7,8)))
                stack.enter_context(patch.object(git.os,'close'))
                lease=stack.enter_context(patch.object(workstation_exec,'EndpointLease',side_effect=AtEndpoint))
                if actual_mapping==maps['uid_map']:
                    with self.assertRaises(AtEndpoint):
                        git.NativeGitResources.from_session(plan,resources,engine,supervisor=supervisor,deadline=time.monotonic()+1)
                    lease.assert_called_once_with(Path(endpoint),owner=565533,group=565532)
                    self.assertIs(process.call_args.kwargs['host_profile'],plan.native_profile.host_profile)
                else:
                    with self.assertRaisesRegex(OriginDenied,'observed mapping differs'):
                        git.NativeGitResources.from_session(plan,resources,engine,supervisor=supervisor,deadline=time.monotonic()+1)
                    lease.assert_not_called()
