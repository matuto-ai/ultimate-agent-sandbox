"""Pure local resource paths and imported-image binding; no native effects."""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uas import native_git_resources as git, native_gate_resources as gate
from uas.native_image_package import valid_image_reference, envelope, payload, inventory
from uas.config import _image, ConfigError
from uas.kernel_origin import OriginDenied
import test_local_runtime_plan as local_fixture
import test_native_git_resources as git_fixture
import test_native_pi_recipe as pi_fixture
import test_native_claude_recipe as claude_fixture

class LocalRuntimeMountTests(unittest.TestCase):
    def local(self):
        fixture=local_fixture.LocalRuntimePlanTests();fixture.setUp()
        fixture.selection.update({key:{'path':'/selected/'+key,'sha256':'d'*64}
            for key in ('git_manifest','git_broker_manifest','gate_manifest')})
        plan=fixture.plan();_,state,manifest=git_fixture.fixture()
        state['room_id']=plan.room['id']
        manifest.update(image_id=plan.native_profile.image_id,image_reference=plan.native_profile.image_reference,
                        backend_path=str(plan.native_profile.state_root/'git-backend'))
        return plan,state,manifest

    def test_exact_local_paths_no_nonce_or_hardcoded_qualification_root(self):
        plan,state,manifest=self.local()
        self.assertNotIn('nonce',plan.installation)
        self.assertEqual(git.validate_selection(manifest,plan),manifest)
        mounts=git.git_mounts(plan,state)
        self.assertEqual(mounts[0].source,str(plan.native_profile.endpoints/state['instance_id']/'git-views'))
        self.assertEqual(gate.paths(plan,state)['endpoint_root'],plan.native_profile.endpoints/state['instance_id']/'gate')
        self.assertEqual(gate.paths(plan,state)['scratch_root'],Path(plan.room['state_root'])/'instances'/state['instance_id']/'native/gate-targets')

    def test_local_image_backend_or_selected_state_drift_refused(self):
        plan,state,manifest=self.local()
        for key,value in [('image_id','sha256:'+'9'*64),('backend_path','/mnt/uas-native/'+'a'*32+'/git-backend'),('image_reference','native:latest')]:
            with self.subTest(key=key),self.assertRaises(OriginDenied):git.validate_selection({**manifest,key:value},plan)
        plan.installation['installation_id']='b'*32
        with self.assertRaises(ValueError):git.git_mounts(plan,state)

    def test_legacy_paths_preserved_and_ducktyped_local_roots_not_adopted(self):
        plan,state,manifest=git_fixture.fixture()
        plan.native_profile=SimpleNamespace(endpoints=Path('/untrusted'),state_root=Path('/untrusted'))
        self.assertEqual(git.endpoint_root(plan),Path('/run/uas-native'))
        self.assertEqual(git.backend_path(plan),Path('/mnt/uas-native')/plan.installation['nonce']/'git-backend')
        self.assertEqual(git.validate_selection(manifest,plan),manifest)

    def test_config_and_envelope_accept_only_exact_local_image_ids(self):
        identity='sha256:'+'a'*64
        _image(identity,'image')
        self.assertTrue(valid_image_reference(identity,identity))
        baked=payload('pi',dict.fromkeys(inventory('pi'),'b'*64))
        self.assertEqual(envelope(baked,image_reference=identity,image_id=identity)['image_reference'],identity)
        for value in ('latest','native:latest','sha256:'+'a'*63,'sha256:'+'A'*64):
            self.assertFalse(valid_image_reference(value,identity))
            with self.assertRaises(ConfigError):_image(value,'image')
        self.assertFalse(valid_image_reference('sha256:'+'c'*64,identity))

    def test_both_runtime_recipes_accept_matching_config_id_not_another_id(self):
        for fixture,make in ((pi_fixture.NativePiRecipeTests(),'recipe'),(claude_fixture.NativeClaudeRecipeTests(),'make')):
            fixture.setUp();fixture.manifest['image_reference']=fixture.manifest['image_id']
            recipe=getattr(fixture,make)();self.assertEqual(recipe.image_reference,recipe.image_id)
            fixture.manifest['image_reference']='sha256:'+'f'*64
            with self.assertRaises(ValueError):getattr(fixture,make)()

    def test_gate_local_image_pairing_is_exact(self):
        plan,state,_=self.local()
        manifest={'version':1,'profile':gate.PROFILE_ID,'image_id':plan.native_profile.image_id,
                  'image_reference':plan.native_profile.image_reference,
                  'helpers':dict.fromkeys(gate.HELPERS,'a'*64),'host_materializer':dict.fromkeys(gate.HOST_TOOLS,'b'*64)}
        self.assertEqual(gate.validate_selection(manifest,plan),manifest)
        with self.assertRaises(gate.ArtifactError):gate.validate_selection({**manifest,'image_id':'sha256:'+'f'*64},plan)


    def test_only_exact_local_readonly_observer_is_accepted(self):
        from contextlib import nullcontext
        from uas.local_native import LocalNativeObserver
        from uas.native_qualification_backend import NativeQualificationObserver
        from uas.lifecycle import Supervisor
        from uas.docker_exec_api import DockerExecAPI
        plan,_,_=self.local();owner=object.__new__(Supervisor)
        owner._locked=lambda:nullcontext();owner._read=lambda:None
        engine=object.__new__(DockerExecAPI)
        owner.backend=object.__new__(LocalNativeObserver)
        with self.assertRaisesRegex(OriginDenied,'current lifecycle required'):
            git.NativeGitResources.from_session(plan,{},engine,supervisor=owner,deadline=1)
        class Lookalike(LocalNativeObserver):pass
        for kind in (Lookalike,NativeQualificationObserver):
            owner.backend=object.__new__(kind)
            with self.assertRaisesRegex(OriginDenied,'canonical readonly owners required'):
                git.NativeGitResources.from_session(plan,{},engine,supervisor=owner,deadline=1)

    def test_gate_revalidation_uses_selected_local_mcs(self):
        from contextlib import nullcontext
        from unittest.mock import Mock
        from uas import native_qualification_backend as backend
        plan,state,_=self.local();owner=gate.NativeGateResources()
        owner._closed=False;owner.deadline=100;owner.workstation=SimpleNamespace(host_profile=plan.native_profile.host_profile)
        owner.room_id=plan.room['id'];owner.instance=state['instance_id'];owner.container_id='c'*64
        owner.supervisor=SimpleNamespace(_locked=lambda:nullcontext(),_read=lambda:state)
        owner.git_resources=Mock();owner.git_resources.profile.mount_tuples.return_value=()
        owner.plan=plan;owner._host_owners=plan.native_profile.host_profile.owners;owner.data={'peer_path':str(plan.native_profile.endpoints/state['instance_id']/'peer/pi.sock')}
        owner.profile=SimpleNamespace(image_id=plan.native_profile.image_id,image_reference=plan.native_profile.image_reference,mount_tuples=lambda:())
        owner.engine=Mock();owner.engine.inspect_container.return_value={}
        with patch.object(gate.time,'monotonic',return_value=1),patch.object(backend,'validate_native_container',side_effect=RuntimeError('stop before effects')) as validate:
            with self.assertRaisesRegex(RuntimeError,'stop before effects'):owner.require(owner.workstation)
            self.assertEqual(validate.call_args.kwargs['level'],plan.native_profile.level)

if __name__=='__main__':unittest.main()
