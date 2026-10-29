"""Exact artifacts projection on both actual recipe constructors; no effects."""
from dataclasses import replace
import unittest
from types import SimpleNamespace as N
from uas.native_gate_resources import NativeGateMountProfile, NativeGateMount, HELPERS, HOST_TOOLS
from uas.native_pi_recipe import NativeRecipeError
import test_native_git_recipe as git_fixture


class NativeGateRecipeTests(unittest.TestCase):
    def setUp(self):
        self.fixture=git_fixture.NativeGitRecipeTests();self.fixture.setUp()
        f=self.fixture
        declared=N(room=f.plan.room,config=f.plan.config,installation={**f.plan.installation,'gate_manifest':{'sha256':'b'*64},'git_manifest':{}})
        manifest={'version':1,'profile':'artifacts-v1-source','image_id':f.manifest['image_id'],
            'image_reference':f.manifest['image_reference'],'helpers':dict.fromkeys(HELPERS,'a'*64),
            'host_materializer':dict.fromkeys(HOST_TOOLS,'b'*64)}
        self.profile=NativeGateMountProfile.from_plan(declared,{'room_id':f.room['id'],'instance_id':'a'*32},manifest,'b'*64,
            container_id='c'*64,mapping_digest='f'*64)
        self.mounts=f.mounts+self.profile.mounts

    def recipe(self,runtime='pi',**changes):
        return self.fixture.recipe(runtime,**{'mounts':self.mounts,'gate_profile':self.profile,**changes})

    def test_both_recipes_consume_exact_fifteen_mounts_and_bind_digest(self):
        for runtime in ('pi','claude'):
            result=self.recipe(runtime)
            self.assertIs(result.gate_profile,self.profile)
            self.assertEqual(result.mounts,self.mounts);self.assertEqual(len(result.mounts),15)
            ordinary=self.fixture.recipe(runtime)
            self.assertNotEqual(result.identity,ordinary.identity)

    def test_missing_git_or_gate_profile_and_mutated_roles_deny(self):
        for runtime in ('pi','claude'):
            for changes in ({'git_profile':None},{'gate_profile':None},
                {'mounts':self.mounts[:-1]},
                {'mounts':self.fixture.mounts+tuple(reversed(self.profile.mounts))},
                {'mounts':self.fixture.mounts+(replace(self.profile.mounts[0],read_only=False),self.profile.mounts[1])},
                {'mounts':self.mounts+(NativeGateMount('/tmp/evil','/uas/evil'),)}):
                with self.subTest(runtime=runtime,changes=changes),self.assertRaises(NativeRecipeError):self.recipe(runtime,**changes)

    def test_profile_identity_or_document_drift_deny(self):
        for field in ('room_id','instance_id','container_id','image_id','mapping_digest','digest'):
            original=getattr(self.profile,field);object.__setattr__(self.profile,field,'other')
            with self.subTest(field=field),self.assertRaises(NativeRecipeError):self.recipe()
            object.__setattr__(self.profile,field,original)
        document=self.profile.document();document['mounts'][0]['source']='/other'
        self.assertNotEqual(document,self.profile.document())
