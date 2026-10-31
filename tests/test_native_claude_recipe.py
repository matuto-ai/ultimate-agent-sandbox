from uas.native_image_package import envelope
"""Pure recipe/source contracts only; no native launch or kernel evidence."""
import copy
from pathlib import Path
import unittest
from unittest.mock import patch
from uas.native_claude_recipe import NativeClaudeRecipe, ARTIFACTS
from uas.native_pi_recipe import NativeMount, NativeRecipeError
from uas.workstation_exec import ExecSeat

ROOT=Path(__file__).resolve().parents[1]
class NativeClaudeRecipeFixture:
    """Reusable recipe inputs, without rediscovering the ordinary profile tests."""
    def setUp(self):
        self.manifest={'version':1,'runtime':'claude','runtime_version':'2.1.310','sdk_version':'0.3.310',
            'image_reference':'registry/image@sha256:'+'a'*64,'image_id':'sha256:'+'b'*64,
            'artifacts':{key:'c'*64 for key in ARTIFACTS}}
        self.manifest = envelope({key: value for key, value in self.manifest.items()
            if key not in ('image_reference', 'image_id')},
            image_reference=self.manifest['image_reference'], image_id=self.manifest['image_id'])
        self.args=dict(seat=ExecSeat('room','instance','reviewer','actor','seat-b','d'*64,65532,65532),
            scope={'room_id':'room','participant_id':'reviewer','run_id':'run','generation':1,'context_generation':1},
            checkout='/project/repo',home='/runtime/seat-b/contexts/1/home',runtime_root='/runtime',endpoint='/transport/claude.sock',
            model='claude-sonnet-4-6',session_id='11111111-1111-4111-8111-111111111111',
            mounts=(NativeMount('/project','/project',False),NativeMount('/runtime','/runtime',False),
                    NativeMount('/sockets','/transport',True)))
    def make(self,**changes):
        args={**self.args,**changes}
        with patch('uas.native_claude_recipe.read_manifest',return_value=copy.deepcopy(self.manifest)):
            return NativeClaudeRecipe('/trusted/manifest.json','a'*64,**args)
class NativeClaudeRecipeTests(NativeClaudeRecipeFixture, unittest.TestCase):
    def test_provider_reference_does_not_share_native_context(self):
        from uas.runtime_provider import ProviderAuthReference
        ref=ProviderAuthReference('claude','chosen','subscription','claude-oauth-token')
        recipe=self.make(provider_auth=ref)
        self.assertEqual(recipe.require_provider_auth(),ref)
        self.assertIn('/providers/subscription/token',recipe.auth_path)
        self.assertNotIn('/contexts/',recipe.auth_path)
        self.assertEqual(recipe.host_spec(manifest_in_image='/opt/uas/claude-manifest.json')['Cmd'][-1],recipe.auth_path)
        with self.assertRaises(ValueError):self.make().require_provider_auth()

    def test_explicit_fixed_host_no_secret(self):
        recipe=self.make(); spec=recipe.host_spec(manifest_in_image='/opt/uas/claude-manifest.json')
        self.assertEqual(spec['Cmd'][:2],['/opt/uas/bin/claude-host-bootstrap','/transport/claude.sock'])
        self.assertEqual(spec['Env'],[]); self.assertNotIn('challenge',str(spec)); self.assertEqual(recipe.identity['runtime'],'claude')
    def test_recipe_and_returned_identity_immutable(self):
        recipe=self.make(); scope=recipe.scope; scope['generation']=99
        self.assertEqual(recipe.scope['generation'],1)
        with self.assertRaises(NativeRecipeError): recipe.model='other'
    def test_no_mutable_or_other_manifest(self):
        self.manifest['artifacts']['/workspace/tool.mjs']='f'*64
        with self.assertRaises(NativeRecipeError): self.make()
    def test_no_implicit_model_or_session(self):
        for changes in ({'model':None},{'model':'model --extra'},{'session_id':'auto'},{'resume':1}):
            with self.assertRaises(NativeRecipeError): self.make(**changes)
    def test_exact_scope_and_mounts(self):
        wrong={**self.args['scope'],'participant_id':'other'}
        with self.assertRaises(NativeRecipeError): self.make(scope=wrong)
        with self.assertRaises(NativeRecipeError): self.make(home='/project/home')
        with self.assertRaises(NativeRecipeError): self.make(mounts=(self.args['mounts'][0],NativeMount('/state','/runtime',False),self.args['mounts'][2]))
        with self.assertRaises(NativeRecipeError): self.make(mounts=self.args['mounts']*2)
    def test_manifest_location_not_caller_tool(self):
        with self.assertRaises(NativeRecipeError): self.make().host_spec(manifest_in_image='/project/manifest.json')
    def test_bootstrap_preserves_sdk_stdio_and_native_identity(self):
        source=(ROOT/'runtime/claude/native-bootstrap.c').read_text()
        self.assertIn('read(3,packet+4+n,32-n)',source)
        self.assertIn('execve(argv[2],argv+2,environ)',source)
        self.assertNotIn('fork(',source); self.assertNotIn('read(0,',source); self.assertIn('dup2(peer,3)',source)
        self.assertIn('close_range(4,~0U,0)',source)
        self.assertLess(source.index('UAS-RELEASE-1'),source.index('execve('))
    def test_host_uses_forwarded_sdk_signal_and_fixed_tools(self):
        source=(ROOT/'runtime/claude/native-host.mjs').read_text()
        self.assertIn('signal:options.signal',source); self.assertIn("stdio:['pipe','pipe','pipe','pipe']",source)
        self.assertIn('native-child-awaits-supervisor-admission',source)
        self.assertNotIn('createSdkMcpServer',source)
        policy=(ROOT/'runtime/claude/native-policy.mjs').read_text()
        self.assertIn('strictMcpConfig:true',policy); self.assertIn('settingSources:[]',policy)
        self.assertNotIn('...process.env',policy.replace('// No spread of ambient process.env',''))
    def test_helper_does_not_accept_identity(self):
        source=(ROOT/'runtime/claude/mcp-connector.c').read_text()
        self.assertIn('UAS-CLAUDE-MCP-1',source); self.assertIn('close_range(5,~0U,0)',source)
        self.assertIn('execve(args[0],args,env)',source)
        self.assertNotIn('getenv(',source); self.assertNotIn('fork(',source)
    def test_complete_configuration_repo_and_checkout(self):
        import io
        import json
        config=json.loads((ROOT/'tests/fixtures/two-rooms.json').read_text())
        room=config['rooms'][0]
        selected=next(s for s in room['seats'] if s['runtime']=='claude')
        selected['arguments']=[]
        provider=next(p for p in config['deployment']['providers'] if p['id']==selected['provider'])
        provider.pop('endpoint',None); provider['model']='claude-sonnet-4-6'
        image=next(i for i in config['deployment']['images'] if i['id']==room['image'])
        image['reference']=self.manifest['image_reference']
        roots=room['project']['roots']; runtime=room['state_root']+'/runtime'
        mounts=tuple(NativeMount(v,v,k=='reference') for k,v in roots.items())+(
            NativeMount(runtime,runtime,False),NativeMount(room['state_root']+'/peer','/peer',True))
        seat=ExecSeat(room['id'],'instance',selected['participant'],selected['actor'],'seat-b','d'*64,65532,65532)
        scope={**self.args['scope'],'room_id':room['id'],'participant_id':selected['participant']}
        for checkout in (roots['repo'],roots['checkouts']+'/review-slot'):
            with patch('uas.native_claude_recipe.read_manifest',return_value=copy.deepcopy(self.manifest)):
                recipe=NativeClaudeRecipe.from_configuration(io.StringIO(json.dumps(config)),room['id'],selected['participant'],
                    '/trusted/manifest.json','a'*64,seat=seat,scope=scope,checkout=checkout,
                    home=runtime+'/seat-b/contexts/1/home',runtime_root=runtime,endpoint='/peer/claude.sock',
                    session_id=self.args['session_id'],mounts=mounts)
            self.assertEqual(recipe.checkout,checkout)
            self.assertEqual(recipe.model,'claude-sonnet-4-6')
    def test_fresh_home_precedes_sdk_start(self):
        source=(ROOT/'runtime/claude/native-host.mjs').read_text()
        self.assertIn('mkdirSync(home,{mode:0o700})',source)
        self.assertLess(source.index('mkdirSync(home,'),source.index('query=createQuery('))
        self.assertIn('exclusive-new-home-explicit-session-no-input',source)

    def test_baked_payload_digest_mismatch_rejected(self):
        self.manifest['payload_manifest_digest'] = '0' * 64
        with self.assertRaisesRegex(NativeRecipeError, 'baked payload'):
            self.make()

    def test_host_gets_payload_not_external_envelope_digest(self):
        recipe = self.make()
        spec = recipe.host_spec(manifest_in_image='/opt/uas/claude-manifest.json')
        self.assertEqual(spec['Cmd'][-1], recipe.payload_manifest_digest)
        self.assertEqual(recipe.identity['manifest_digest'], 'a' * 64)
        self.assertNotEqual(recipe.manifest_digest, recipe.payload_manifest_digest)
