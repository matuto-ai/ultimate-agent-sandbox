"""Pure prepared projection contracts; no image/mount/native execution."""
from dataclasses import replace
from io import StringIO
from types import SimpleNamespace as N
import unittest
from unittest.mock import patch

from uas.native_git_resources import GitMountProfile, NativeGitMount, FIXED_ARTIFACTS, LOADER
from uas.native_git_recipe import base_mounts
from uas.native_pi_recipe import NativePiRecipe, NativeMount, NativeRecipeError
from uas.native_claude_recipe import NativeClaudeRecipe
from uas.workstation_exec import ExecSeat
from uas.kernel_origin import OriginDenied
import test_native_qualification as fixture


class NativeGitRecipeTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixture.NativeQualificationTests();self.fixture.setUp()
        self.fixture.config['rooms'][0]['seats'][0]['arguments']=['--provider','openai']
        self.plan=self.fixture.plan();self.room=self.plan.room
        selection={**self.plan.installation,'git_manifest':{'path':'/installation/git.json','sha256':'d'*64}}
        declared=N(config=self.plan.config,room=self.room,installation=selection)
        self.manifest={'version':1,'profile':'native-git-primary-v1',
            'image_reference':self.fixture.manifests['pi']['image_reference'],'image_id':'sha256:'+'e'*64,
            'artifacts':dict.fromkeys(FIXED_ARTIFACTS,'a'*64),'python_version':'3.11.9',
            'abi_artifacts':{LOADER:'b'*64,'/lib/x86_64-linux-gnu/libc.so.6':'c'*64},
            'uas_tree_sha256':'d'*64,'backend_sha256':'e'*64,
            'backend_path':'/mnt/uas-native/'+'a'*32+'/git-backend'}
        self.profile=GitMountProfile.from_plan(declared,{'room_id':self.room['id'],'instance_id':'a'*32},
            self.manifest,'d'*64,container_id='c'*64,mapping_digest='f'*64)
        self.peer='/run/uas-native/'+'a'*32+'/peer'
        runtime=self.room['state_root']+'/runtime'
        self.base=tuple(NativeMount(v,v,k=='reference') for k,v in self.room['project']['roots'].items())+(
            NativeMount(runtime,runtime,False),NativeMount(self.peer,self.peer,True))
        self.mounts=self.base+self.profile.mounts

    def recipe(self,runtime='pi',**changes):
        selected=self.plan.seats[runtime]
        seat=ExecSeat(self.room['id'],'a'*32,selected['participant'],selected['actor'],
            'seat-a' if runtime=='pi' else 'seat-b','c'*64,165532,165532)
        args={'seat':seat,'scope':{'room_id':self.room['id'],'participant_id':seat.participant_id,
                'run_id':'run','generation':1,'context_generation':1},
            'checkout':self.room['project']['roots']['repo'],'runtime_root':self.room['state_root']+'/runtime',
            'endpoint':self.peer+'/pi.sock','mounts':self.mounts,'git_profile':self.profile}
        if runtime=='claude':args.update(home=args['runtime_root']+'/seat-b/contexts/1/home',session_id='11111111-1111-4111-8111-111111111111')
        args.update(changes)
        cls=NativePiRecipe if runtime=='pi' else NativeClaudeRecipe
        with patch('uas.native_'+runtime+'_recipe.read_manifest',return_value=self.fixture.manifests[runtime]):
            return cls.from_configuration(StringIO(self.plan.config_text),self.room['id'],seat.participant_id,
                '/installation/'+runtime+'.json','b'*64,**args)

    def test_both_exact_recipes_consume_same_primary_projection(self):
        for runtime in ('pi','claude'):
            recipe=self.recipe(runtime)
            self.assertIs(recipe.git_profile,self.profile)
            self.assertEqual(recipe.mounts,self.mounts)
            self.assertEqual(len(recipe.mounts),13)

    def test_no_generic_opt_overlay_or_role_mount_without_profile(self):
        with self.assertRaises(NativeRecipeError):NativeMount('/tmp/evil','/opt/uas/bin',False)
        for runtime in ('pi','claude'):
            with self.assertRaises(NativeRecipeError):self.recipe(runtime,git_profile=None)

    def test_missing_reordered_extra_and_changed_roles_fail(self):
        variants=(self.mounts[:-1],self.base+tuple(reversed(self.profile.mounts)),
            self.mounts+(NativeGitMount('/tmp/extra','/opt/uas/bin',False),),
            self.base+(replace(self.profile.mounts[0],read_only=False),)+self.profile.mounts[1:])
        for mounts in variants:
            with self.subTest(mounts=mounts),self.assertRaises(NativeRecipeError):self.recipe(mounts=mounts)

    def test_successor_and_other_container_or_image_fail_before_launch(self):
        with self.assertRaises(OriginDenied):self.recipe(checkout=self.room['project']['roots']['checkouts']+'/later')
        seat=ExecSeat(self.room['id'],'a'*32,self.plan.seats['pi']['participant'],self.plan.seats['pi']['actor'],
            'seat-a','d'*64,165532,165532)
        with self.assertRaises(NativeRecipeError):self.recipe(seat=seat)
        self.fixture.manifests['pi']['image_id']='sha256:'+'f'*64
        with self.assertRaises(NativeRecipeError):self.recipe()
