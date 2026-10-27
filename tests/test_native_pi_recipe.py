"""Pure native recipe/Engine binding contracts; no native or network execution."""
from copy import deepcopy
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch, Mock

from uas.native_pi_recipe import ARTIFACTS, NativeMount, NativePiRecipe, NativeRecipeError
from uas.workstation_exec import ExecLaunch, ExecSeat, ExecUnavailable


class NativePiRecipeTests(unittest.TestCase):
    def setUp(self):
        self.seat = ExecSeat('room','instance','pi','builder','seat-a','c'*64,65532,65532)
        self.scope = {'room_id':'room','participant_id':'pi','run_id':'run','generation':1,'context_generation':2}
        self.manifest = {'version':1,'runtime':'pi','runtime_version':'1.4.0',
            'image_reference':'selected/image@sha256:'+'a'*64,'image_id':'sha256:'+'b'*64,
            'artifacts':{p:'d'*64 for p in ARTIFACTS}}
        self.mounts = (NativeMount('/project','/project',False),NativeMount('/runtime/room','/runtime/room',False),
            NativeMount('/control/peer','/peer',True),NativeMount('/references','/references',True))
        self.kw = dict(seat=self.seat,scope=self.scope,checkout='/project/checkouts/main',
            runtime_root='/runtime/room',endpoint='/peer/pi.sock',mounts=self.mounts,provider='anthropic',model='chosen-model')
        self.value = {'Id':'c'*64,'Image':'sha256:'+'b'*64,'Config':{'Image':self.manifest['image_reference']},
            'HostConfig':{'Privileged':False,'ReadonlyRootfs':True,'PidMode':'','IpcMode':'private',
                'NetworkMode':'room-network','CapAdd':None,'Devices':[],'DeviceRequests':[],
                'SecurityOpt':['no-new-privileges:true']},'ProcessLabel':'container_t:s0:c1,c2','State':{'Running':True},
            'Mounts':[{'Source':m.source,'Destination':m.destination,'RW':not m.read_only,'Type':'bind'} for m in self.mounts]}
    def recipe(self, **changes):
        with patch('uas.native_pi_recipe.read_manifest',return_value=deepcopy(self.manifest)):
            return NativePiRecipe('/private/native.json','e'*64,**(self.kw|changes))
    def test_consumed_native_spec_preserves_choices_and_canonical_scope(self):
        recipe=self.recipe()
        launch=ExecLaunch(Mock(),self.seat,NS(path='/peer/pi.sock'),'/private/launch.json',native_recipe=recipe)
        spec=launch._create_spec()
        self.assertEqual(spec['Cmd'],['/opt/uas/bin/pi-native-connector','/peer/pi.sock',
            '/project/checkouts/main','/runtime/room/seat-a','/runtime/room/seat-a/contexts/2/sessions','anthropic','chosen-model'])
        self.assertEqual(spec['Env'],[])
        self.assertFalse(spec['Privileged'])
        self.assertEqual(recipe.identity['manifest_digest'],'e'*64)
        self.assertNotIn('provider',recipe.identity)
    def test_fixture_default_is_unchanged_and_helpers_cannot_opt_in(self):
        launch=ExecLaunch(Mock(),self.seat,NS(path='/peer/pi.sock'),'/private/launch.json')
        self.assertEqual(launch._create_spec()['Cmd'],['/opt/uas/bin/pi-connector','seat-a'])
        class Helper(ExecLaunch): pass
        with self.assertRaisesRegex(ExecUnavailable,'canonical launch'):
            Helper(Mock(),self.seat,NS(path='/peer/pi.sock'),'/private/launch.json',native_recipe=self.recipe())
    def test_container_inspection_binds_exact_image_and_all_mounts(self):
        engine=NS(inspect_container=Mock(return_value=self.value))
        self.recipe().validate_container(engine)
        engine.inspect_container.assert_called_once_with('c'*64)
        for field in ('Image','Id'):
            bad=deepcopy(self.value);bad[field]='f'*64
            with self.assertRaises(NativeRecipeError):
                self.recipe().validate_container(NS(inspect_container=lambda _:bad))
        bad=deepcopy(self.value);bad['Mounts'][0]['Source']='/other'
        with self.assertRaises(NativeRecipeError):
            self.recipe().validate_container(NS(inspect_container=lambda _:bad))
        bad=deepcopy(self.value);bad['Mounts'].append(deepcopy(bad['Mounts'][0]))
        with self.assertRaises(NativeRecipeError):
            self.recipe().validate_container(NS(inspect_container=lambda _:bad))
    def test_boundary_mismatch_blocks_before_probe_journal_or_create(self):
        recipe=self.recipe();bad=deepcopy(self.value);bad['HostConfig']['Privileged']=True
        engine=Mock();engine.inspect_container.return_value=bad
        launch=ExecLaunch(engine,self.seat,NS(path='/peer/pi.sock'),'/private/launch.json',native_recipe=recipe)
        with patch('uas.workstation_exec.probe') as probe,patch.object(launch,'_save') as save:
            with self.assertRaises(NativeRecipeError):launch.launch(Mock())
            probe.assert_not_called();save.assert_not_called();engine.create.assert_not_called()
        self.assertEqual(launch.state,'new')
    def test_invalid_manifest_runtime_and_fields_fail(self):
        for key,value in (('runtime_version','9.9'),('version',True),('image_id','latest'),('artifacts',{})):
            saved=deepcopy(self.manifest);self.manifest[key]=value
            with self.assertRaises(NativeRecipeError):self.recipe()
            self.manifest=saved
    def test_overlay_alias_and_untyped_choices_rejected(self):
        for destination in ('/opt','/opt/uas/node','/usr/bin','/lib','/etc/ld.so.preload'):
            with self.assertRaises(NativeRecipeError):NativeMount('/source',destination,False)
        for changes in ({'provider':'--evil'},{'model':'model with spaces'}, {'runtime_root':'/project'},
                        {'scope':self.scope|{'generation':True}},{'checkout':'/project/../other'}):
            with self.assertRaises(NativeRecipeError):self.recipe(**changes)
        with self.assertRaises(NativeRecipeError):
            self.recipe(mounts=self.mounts+(NativeMount('/sub','/project/sub',False),))
    def test_recipe_payload_and_scope_are_checked_before_native_attachment(self):
        recipe=self.recipe()
        launch=ExecLaunch(Mock(),self.seat,NS(path='/peer/pi.sock'),'/private/launch.json',native_recipe=recipe)
        launch.state='released';launch.exec_id='f'*64
        # On rejected attachment the existing failure path fences the launch.
        launch.origin=NS(revoke=Mock())
        with patch.object(launch,'_save'),patch.object(launch,'close_transport'),\
             patch('uas.pi_runtime.FixturePiRpcReceiver.attach_workstation') as attach:
            with self.assertRaisesRegex(ExecUnavailable,'scope/payload'):
                launch.attach_native(journal='/private/native.db',scope=self.scope,profile_digest='0'*64)
            attach.assert_not_called()
            self.assertNotEqual(launch.state,'active')

    def test_recipe_is_immutable_and_exports_are_defensive(self):
        recipe=self.recipe()
        for key,value in (('provider','other'),('scope',{}),('image_id','other')):
            with self.assertRaisesRegex(NativeRecipeError,'immutable'):setattr(recipe,key,value)
        recipe.scope['generation']=99
        recipe.identity['scope']['generation']=99
        self.assertEqual(recipe.scope,self.scope)
        self.assertEqual(recipe.identity['scope'],self.scope)

    def test_configuration_preserves_explicit_choices_and_rejects_implicit_provider(self):
        roots={key:'/project/'+key for key in ('repo','workspace','reference','checkouts')}
        mounts=tuple(NativeMount(p,p,key=='reference') for key,p in roots.items())+(
            NativeMount('/control/room/runtime','/control/room/runtime',False),self.mounts[2])
        config={'deployment':{'providers':[{'id':'logical','runtime':'pi','model':'chosen-model'}],
            'images':[{'id':'image','reference':self.manifest['image_reference']}]},'rooms':[{
            'id':'room','state_root':'/control/room','image':'image','project':{'roots':roots},'seats':[{'participant':'pi','runtime':'pi',
            'actor':'builder','provider':'logical','arguments':['--provider','anthropic']}]}]}
        kwargs=dict(self.kw);kwargs.pop('provider');kwargs.pop('model');kwargs.update(checkout=roots['repo'],mounts=mounts,runtime_root='/control/room/runtime')
        with patch('uas.config.load',return_value=config),patch('uas.native_pi_recipe.read_manifest',return_value=self.manifest):
            recipe=NativePiRecipe.from_configuration(None,'room','pi','/private/native.json','e'*64,**kwargs)
            self.assertEqual((recipe.provider,recipe.model),('anthropic','chosen-model'))
            bad_mounts=tuple(m if m.source!='/control/room/runtime' else NativeMount('/control/room','/control/room',False) for m in mounts)
            with self.assertRaisesRegex(NativeRecipeError,'control-store exposure'):
                NativePiRecipe.from_configuration(None,'room','pi','/private/native.json','e'*64,**(kwargs|{'mounts':bad_mounts}))
            extra=mounts+(NativeMount('/control/room/credentials','/leak',True),)
            with self.assertRaisesRegex(NativeRecipeError,'control-store exposure'):
                NativePiRecipe.from_configuration(None,'room','pi','/private/native.json','e'*64,**(kwargs|{'mounts':extra}))
            config['rooms'][0]['seats'][0]['arguments']=[]
            with self.assertRaisesRegex(NativeRecipeError,'explicit native provider'):
                NativePiRecipe.from_configuration(None,'room','pi','/private/native.json','e'*64,**kwargs)
            config['deployment']['providers'][0]['endpoint']='https://custom.example'
            with self.assertRaisesRegex(NativeRecipeError,'custom provider endpoint'):
                NativePiRecipe.from_configuration(None,'room','pi','/private/native.json','e'*64,**kwargs)

    def test_complete_repository_configuration_resolves_into_consumed_recipe(self):
        import io,json
        from pathlib import Path
        config=json.loads((Path(__file__).parent/'fixtures/two-rooms.json').read_text())
        room=config['rooms'][0]; selected=next(s for s in room['seats'] if s['runtime']=='pi')
        selected['arguments']=['--provider','anthropic']
        provider=next(p for p in config['deployment']['providers'] if p['id']==selected['provider'])
        provider.pop('endpoint',None);provider['model']='chosen-model'
        config['deployment']['images'][0]['reference']=self.manifest['image_reference']
        roots=room['project']['roots']; runtime=room['state_root']+'/runtime'
        mounts=tuple(NativeMount(v,v,k=='reference') for k,v in roots.items())+(
            NativeMount(runtime,runtime,False),NativeMount(room['state_root']+'/peer','/peer',True))
        seat=ExecSeat(room['id'],'instance',selected['participant'],selected['actor'],'seat-a','c'*64,65532,65532)
        scope=self.scope|{'room_id':room['id'],'participant_id':selected['participant']}
        with patch('uas.native_pi_recipe.read_manifest',return_value=self.manifest):
            recipe=NativePiRecipe.from_configuration(io.StringIO(json.dumps(config)),room['id'],selected['participant'],
                '/private/native.json','e'*64,seat=seat,scope=scope,checkout=roots['repo'],runtime_root=runtime,
                endpoint='/peer/pi.sock',mounts=mounts)
        launch=ExecLaunch(Mock(),seat,NS(path='/peer/pi.sock'),'/private/launch.json',native_recipe=recipe)
        self.assertEqual(launch._create_spec()['WorkingDir'],roots['repo'])
        self.assertEqual(launch._create_spec()['Cmd'][-2:],['anthropic','chosen-model'])
