"""Pure immutable profile selection and packaging, not native execution proof."""
import io
import json
import unittest
from pathlib import Path
from unittest.mock import patch
import test_native_claude_recipe as recipe_tests
from uas.native_claude_recipe import NativeClaudeRecipe, ARTIFACTS
from uas.native_pi_recipe import NativeRecipeError

class ClaudeLibraryRecipeTests(recipe_tests.NativeClaudeRecipeFixture, unittest.TestCase):
    def test_library_profile_is_explicit_immutable_and_exact(self):
        ordinary=self.make();selected=self.make(tool_profile='library-capture-v1')
        self.assertNotEqual(ordinary.identity['recipe_sha256'],selected.identity['recipe_sha256'])
        self.assertEqual(selected.host_spec(manifest_in_image='/opt/uas/claude-manifest.json')['Cmd'][-1],'library-capture-v1')
        self.assertNotIn('library-capture-v1',ordinary.host_spec(manifest_in_image='/opt/uas/claude-manifest.json')['Cmd'])
        with self.assertRaises(NativeRecipeError): self.make(tool_profile='everything')
        with self.assertRaises(NativeRecipeError): selected.tool_profile='native-v1'
        self.assertIn('/opt/uas/runtime/library-capture.mjs',ARTIFACTS)
    def test_library_profile_keeps_auth_separate(self):
        from uas.runtime_provider import ProviderAuthReference
        ref=ProviderAuthReference('claude','chosen','subscription','claude-oauth-token')
        selected=self.make(provider_auth=ref,tool_profile='library-capture-v1')
        argv=selected.host_spec(manifest_in_image='/opt/uas/claude-manifest.json')['Cmd']
        self.assertEqual(argv[-2],selected.auth_path);self.assertEqual(argv[-1],'library-capture-v1')

    def test_configuration_requires_explicit_only_tool_and_capability(self):
        import copy
        from uas.workstation_exec import ExecSeat
        from uas.native_pi_recipe import NativeMount
        root=Path(__file__).resolve().parents[1]
        config=json.loads((root/'tests/fixtures/two-rooms.json').read_text())
        room=config['rooms'][0];selected=next(x for x in room['seats'] if x['runtime']=='claude')
        profile=next(x for x in room['profiles'] if x['id']==selected['profile'])
        provider=next(x for x in config['deployment']['providers'] if x['id']==selected['provider'])
        provider.pop('endpoint',None);provider['model']='claude-sonnet-4-6';selected['arguments']=[]
        next(x for x in config['deployment']['images'] if x['id']==room['image'])['reference']=self.manifest['image_reference']
        roots=room['project']['roots'];runtime=room['state_root']+'/runtime'
        mounts=tuple(NativeMount(v,v,k=='reference') for k,v in roots.items())+(NativeMount(runtime,runtime,False),NativeMount(room['state_root']+'/peer','/peer',True))
        seat=ExecSeat(room['id'],'instance',selected['participant'],selected['actor'],'seat-b','d'*64,65532,65532)
        scope={**self.args['scope'],'room_id':room['id'],'participant_id':selected['participant']}
        def build():
            with patch('uas.native_claude_recipe.read_manifest',return_value=copy.deepcopy(self.manifest)):
                return NativeClaudeRecipe.from_configuration(io.StringIO(json.dumps(config)),room['id'],selected['participant'],
                    '/trusted/manifest.json','a'*64,seat=seat,scope=scope,checkout=roots['repo'],
                    home=runtime+'/seat-b/contexts/1/home',runtime_root=runtime,endpoint='/peer/claude.sock',
                    session_id=self.args['session_id'],mounts=mounts)
        profile['tools']=['library.enqueue'];profile['capabilities']=['library:enqueue']
        self.assertEqual(build().tool_profile,'library-capture-v1')
        profile['tools'].append('gh')
        with self.assertRaises(NativeRecipeError):build()
        profile['tools']=['library.enqueue'];profile['capabilities']=[]
        with self.assertRaises(NativeRecipeError):build()
        profile['tools']=[];self.assertEqual(build().tool_profile,'native-v1')
        profile['tools']=['Read','Bash']
        with self.assertRaises(NativeRecipeError):build()
        roots['reference']='/project/reference'
        mounts=tuple(NativeMount(v,v,k=='reference') for k,v in roots.items())+(NativeMount(runtime,runtime,False),NativeMount(room['state_root']+'/peer','/peer',True))
        self.assertEqual(build().tool_profile,'library-read-v1')
        for mixed in (['Read'],['Bash'],['Read','Bash','library.enqueue'],['Read','Bash','gh']):
            profile['tools']=mixed
            with self.assertRaises(NativeRecipeError):build()

    def test_native_read_requires_separate_fixed_readonly_projection_and_identity(self):
        from uas.native_pi_recipe import NativeMount
        with self.assertRaises(NativeRecipeError): self.make(tool_profile='library-read-v1')
        mounts=(NativeMount('/project/repo','/project/repo',False),
                NativeMount('/published/project-a','/project/reference',True),
                NativeMount('/runtime','/runtime',False),NativeMount('/sockets','/transport',True))
        selected=self.make(tool_profile='library-read-v1',mounts=mounts)
        self.assertEqual(selected.host_spec(manifest_in_image='/opt/uas/claude-manifest.json')['Cmd'][-1],'library-read-v1')
        self.assertEqual(selected.identity['native_cwd'],'/project/reference')
        self.assertEqual(selected.identity['checkout'],'/project/repo')
        self.assertNotEqual(selected.identity['recipe_sha256'],self.make().identity['recipe_sha256'])
        with self.assertRaises(NativeRecipeError): self.make(tool_profile='library-read-v1',mounts=tuple(
            NativeMount(m.source,m.destination,False) if m.destination=='/project/reference' else m for m in mounts))
        for artifact in ('/opt/uas/runtime/claude/library-read.mjs','/opt/uas/runtime/pi/library-scan.mjs',
                         '/opt/uas/pi/node_modules/yaml/package.json','/opt/uas/pi/node_modules/yaml/dist/index.js'):
            self.assertIn(artifact,ARTIFACTS)
