from .runtime_provider import ProviderAuthReference, select_reference, require_reference
"""Immutable installation-selected Claude SDK/native payload; not Actor admission.

A native child owner must use the separate kernel rendezvous. This recipe cannot
be passed to Pi's exact Engine-task ExecLaunch or enable live mode by itself.
"""
import hashlib
import json
import re
import uuid
from pathlib import Path
from .native_pi_recipe import (NativeRecipeError, NativeMount, NativePiRecipe,
                               read_manifest, path, below, SHA, CHOICE, verify_payload_manifest)

ROOT = '/opt/uas'
HOST = ROOT + '/runtime/claude/native-host.mjs'
HOST_BOOTSTRAP = ROOT + '/bin/claude-host-bootstrap'
BOOTSTRAP = ROOT + '/bin/claude-native-bootstrap'
HELPER = ROOT + '/bin/claude-mcp-connector'
BINARY = ROOT + '/claude/claude'
ARTIFACTS = frozenset((HOST, HOST_BOOTSTRAP, BOOTSTRAP, HELPER, BINARY, ROOT+'/node/bin/node',
    ROOT+'/claude-sdk/node_modules/@anthropic-ai/claude-agent-sdk/package.json',
    ROOT+'/claude-sdk/node_modules/@anthropic-ai/claude-agent-sdk/sdk.mjs',
    *(ROOT+'/runtime/claude/'+name for name in ('native-policy.mjs','mcp-server.mjs',
       'mcp-tools.mjs','sdk-policy.mjs','sdk-resources.mjs','sdk-diagnostics.mjs')),
    ROOT+'/runtime/pi/channel.mjs',ROOT+'/runtime/provider-auth.mjs'))


class NativeClaudeRecipe:
    def __setattr__(self, key, value):
        if getattr(self, '_frozen', False): raise NativeRecipeError('immutable native Claude recipe')
        object.__setattr__(self,key,value)

    @property
    def identity(self): return json.loads(self._identity)
    @property
    def scope(self): return json.loads(self._scope)

    def __init__(self, manifest_path, manifest_digest, *, seat, scope, checkout,
                 home, runtime_root, endpoint, model, session_id, mounts, resume=False, provider_auth=None):
        from .workstation_exec import ExecSeat
        if type(seat) is not ExecSeat or type(resume) is not bool:
            raise NativeRecipeError('trusted typed native seat required')
        manifest = read_manifest(manifest_path,manifest_digest)
        if (type(manifest) is not dict or set(manifest) != {'version','runtime','runtime_version',
                'sdk_version','image_reference','image_id','artifacts','payload_manifest_digest'}
                or type(manifest['version']) is not int or manifest['version'] != 1
                or manifest['runtime'] != 'claude' or manifest['runtime_version'] != '2.1.310'
                or manifest['sdk_version'] != '0.3.310'
                or type(manifest['image_reference']) is not str
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}@sha256:[0-9a-f]{64}',manifest['image_reference'])
                or type(manifest['image_id']) is not str or not re.fullmatch(r'sha256:[0-9a-f]{64}',manifest['image_id'])
                or type(manifest['artifacts']) is not dict or set(manifest['artifacts']) != ARTIFACTS
                or any(type(x) is not str or not SHA.fullmatch(x) for x in manifest['artifacts'].values())):
            raise NativeRecipeError('invalid selected Claude manifest')
        self.payload_manifest_digest = verify_payload_manifest(manifest)
        if (type(scope) is not dict or set(scope) != {'room_id','participant_id','run_id','generation','context_generation'}
                or scope['room_id'] != seat.room_id or scope['participant_id'] != seat.participant_id
                or type(scope['run_id']) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',scope['run_id'])
                or any(type(scope[x]) is not int or not 1 <= scope[x] < 2**53 for x in ('generation','context_generation'))):
            raise NativeRecipeError('exact native context scope required')
        if type(model) is not str or not CHOICE.fullmatch(model): raise NativeRecipeError('explicit native model required')
        try:
            if type(session_id) is not str or str(uuid.UUID(session_id)) != session_id: raise ValueError()
        except (ValueError,AttributeError): raise NativeRecipeError('explicit native session required') from None
        self.checkout,self.home,self.endpoint=map(path,(checkout,home,endpoint))
        self.runtime_root=path(runtime_root)
        if not below(home,runtime_root+'/'+seat.slot+'/contexts/'+str(scope['context_generation'])):
            raise NativeRecipeError('owned native context subtree required')
        if len(endpoint.encode())>=108 or below(checkout,home) or below(home,checkout):
            raise NativeRecipeError('separate canonical paths required')
        if (type(mounts) is not tuple or not 1<=len(mounts)<=16 or any(type(x) is not NativeMount for x in mounts)):
            raise NativeRecipeError('admitted immutable mount contract required')
        for i,m in enumerate(mounts):
            if any(below(m.destination,n.destination) or below(n.destination,m.destination) for n in mounts[i+1:]):
                raise NativeRecipeError('overlapping mounts denied')
        selected=[]
        for value in (checkout,home,endpoint):
            matches=[m for m in mounts if below(value,m.destination)]
            if len(matches)!=1: raise NativeRecipeError('missing owned mount')
            selected.append(matches[0])
        if (len(set(selected))!=3 or selected[0].read_only or selected[1].read_only
                or selected[0].source!=selected[0].destination
                or selected[1].source!=runtime_root or selected[1].destination!=runtime_root):
            raise NativeRecipeError('separate writable checkout/runtime mounts required')
        if provider_auth is not None: require_reference(provider_auth, 'claude')
        self.provider_auth = provider_auth
        self.auth_path = None if provider_auth is None else provider_auth.path(runtime_root)
        self.seat,self.mounts,self.model,self.session_id,self.resume=seat,mounts,model,session_id,resume
        self.manifest_path,self.manifest_digest=path(str(manifest_path)),manifest_digest
        self.image_id,self.image_reference=manifest['image_id'],manifest['image_reference']
        self._scope=json.dumps(scope,sort_keys=True)
        identity={'runtime':'claude','runtime_version':'2.1.310','sdk_version':'0.3.310',
            'manifest_digest':manifest_digest,'payload_manifest_digest':self.payload_manifest_digest,'image_id':self.image_id,'image_reference':self.image_reference,
            'scope':scope,'checkout':checkout,'home':home,'runtime_root':runtime_root,'endpoint':endpoint,'model':model,
            'session_id':session_id,'resume':resume,'provider_auth':None if provider_auth is None else provider_auth.document(),'mounts':[m.__dict__ for m in mounts]}
        identity['recipe_sha256']=hashlib.sha256(json.dumps(identity,sort_keys=True).encode()).hexdigest()
        self._identity=json.dumps(identity,sort_keys=True); self._frozen=True

    @classmethod
    def from_configuration(cls, source, room_id, participant_id, manifest_path, manifest_digest,
                           *, seat, scope, checkout, home, runtime_root, endpoint, session_id, mounts, resume=False):
        from .config import load
        config=load(source)
        room=next((r for r in config['rooms'] if r['id']==room_id),None)
        selected=next((x for x in room['seats'] if x['participant']==participant_id),None) if room else None
        if (selected is None or selected['runtime']!='claude' or seat.room_id!=room_id
                or seat.participant_id!=participant_id or selected['actor']!=seat.actor_id):
            raise NativeRecipeError('configured native Claude seat mismatch')
        if runtime_root!=room['state_root']+'/runtime' or len(mounts)!=6 or any(below(room['state_root'],m.source) for m in mounts):
            raise NativeRecipeError('dedicated runtime subtree without control-store exposure required')
        provider=next(p for p in config['deployment']['providers'] if p['id']==selected['provider'])
        if 'endpoint' in provider: raise NativeRecipeError('custom Claude endpoint requires separate qualification')
        args=selected['arguments']
        if args and (len(args)!=2 or args[0]!='--model'): raise NativeRecipeError('only explicit native model argument supported')
        model=args[1] if args else provider.get('model')
        if model is None or ('model' in provider and model!=provider['model']):
            raise NativeRecipeError('missing or conflicting native model choice')
        roots=room['project']['roots']
        if checkout!=roots['repo'] and str(Path(checkout).parent)!=roots['checkouts']:
            raise NativeRecipeError('owned configured checkout required')
        for key in ('repo','workspace','reference','checkouts'):
            found=[m for m in mounts if m.source==roots[key] and m.destination==roots[key]]
            if len(found)!=1 or found[0].read_only!=(key=='reference'): raise NativeRecipeError('configured Project mount mismatch')
        result=cls(manifest_path,manifest_digest,seat=seat,scope=scope,checkout=checkout,home=home,
            runtime_root=runtime_root,endpoint=endpoint,model=model,session_id=session_id,mounts=mounts,resume=resume,
            provider_auth=select_reference(provider,'claude'))
        image=next(i for i in config['deployment']['images'] if i['id']==room['image'])
        if result.image_reference!=image['reference']: raise NativeRecipeError('selected configured image mismatch')
        return result

    def validate_container(self, engine):
        # Same exact immutable image + mount inventory checks, not Pi identity.
        return NativePiRecipe.validate_container(self,engine)

    def host_spec(self, *, manifest_in_image):
        """Host only. Owner supplies challenge on stdin then the SDK control stream.

        Selected manifest is a baked immutable image artifact, not a new mutable
        mount. Owner must corroborate its digest/image before starting the host.
        """
        if manifest_in_image != '/opt/uas/claude-manifest.json':
            raise NativeRecipeError('fixed image manifest location required')
        return {'AttachStdin':True,'AttachStdout':True,'AttachStderr':True,'Tty':False,
            'Privileged':False,'User':'65532:65532','WorkingDir':self.checkout,
            'Cmd':[HOST_BOOTSTRAP,self.endpoint,self.checkout,self.home,self.model,
                self.session_id,'1' if self.resume else '0',manifest_in_image,self.payload_manifest_digest] + ([] if self.provider_auth is None else [self.auth_path]), 'Env':[]}

    def require_provider_auth(self):
        return require_reference(self.provider_auth, 'claude')
