"""Pinned local runtime declarations, never a disposable qualification or grant.

Only public selected manifests are read. Credentials, Engine effects and actual
HumanSession authority remain with the canonical runtime owners.
"""
from copy import deepcopy
from io import StringIO
import hashlib
import re

from .config import load
from .local_native import LocalNativeProfile
from .native_image_package import canonical, payload
from .native_pi_recipe import read_manifest, path, SHA
from .native_qualification import (QualificationError, validate_runtime_pair,
    validate_human_mergers, native_review_configuration, broker_selection,
    git_broker_selection)


REQUIRED = {'version','profile','room_id','installation_id','pi_manifest',
            'claude_manifest','broker_manifest','human_mergers'}
OPTIONAL = {'operation_timeout_seconds','git_manifest','git_broker_manifest','gate_manifest'}


def require(condition, code):
    if not condition: raise QualificationError(code)


class LocalRuntimePlan:
    def __init__(self, config_text, installation, *, installation_digest, native_profile):
        require(type(config_text) is str and len(config_text.encode())<=1048576,'CONFIGURATION_REQUIRED')
        require(type(native_profile) is LocalNativeProfile,'LOCAL_NATIVE_PROFILE_REQUIRED')
        config=load(StringIO(config_text))
        require(type(installation) is dict and REQUIRED <= set(installation)
                and not set(installation)-REQUIRED-OPTIONAL,'INVALID_LOCAL_RUNTIME_SELECTION')
        selected=deepcopy(installation)
        require(type(selected['version']) is int and selected['version']==1
                and selected['profile']=='local-runtime-v1'
                and type(selected['installation_id']) is str
                and re.fullmatch('[0-9a-f]{32}',selected['installation_id'])
                and selected['installation_id']==native_profile.nonce,'INVALID_LOCAL_RUNTIME_SELECTION')
        require(type(installation_digest) is str and SHA.fullmatch(installation_digest),'INVALID_INSTALLATION_REFERENCE')
        timeout=selected.get('operation_timeout_seconds',180)
        require(type(timeout) is int and 1<=timeout<=180,'INVALID_LOCAL_OPERATION_TIMEOUT')
        require(('git_manifest' in selected)==('git_broker_manifest' in selected)
                and ('gate_manifest' not in selected or 'git_manifest' in selected),'LOCAL_RUNTIME_RESOURCE_SELECTION')
        rooms=[r for r in config['rooms'] if r['id']==selected['room_id']]
        require(len(rooms)==1 and rooms[0]==native_profile.room,'LOCAL_RUNTIME_ROOM_BINDING')
        self.room=deepcopy(rooms[0]);self.config=config
        self.config_text=config_text
        self._source_digest=hashlib.sha256(config_text.encode()).hexdigest()
        self.config_digest=hashlib.sha256(canonical(config)).hexdigest()
        require(self.config_digest==native_profile.config_digest,'LOCAL_RUNTIME_CONFIG_BINDING')
        self.seats=validate_runtime_pair(config,self.room)
        validate_human_mergers(selected['human_mergers'])
        for name,ref in selected.items():
            if not name.endswith('_manifest'):continue
            require(type(ref) is dict and set(ref)=={'path','sha256'},'INVALID_INSTALLATION_REFERENCE')
            try:path(ref['path'])
            except (TypeError,ValueError):raise QualificationError('INVALID_INSTALLATION_REFERENCE') from None
            require(type(ref['sha256']) is str and SHA.fullmatch(ref['sha256']),'INVALID_INSTALLATION_REFERENCE')
        self.native_profile=native_profile
        self.operation_timeout_seconds=timeout
        self.installation=selected;self.installation_digest=installation_digest
        self._native_digest=native_profile.digest
        self._declarations=canonical({'configuration':config,'installation':selected})
        self._bound_state=self._bindings()

    def _bindings(self):
        return canonical({'native_digest':self.native_profile.digest,
            'native_document':self.native_profile.native_document,
            'host_profile':self.native_profile.host_profile.document(),
            'native_room':self.native_profile.room,'native_paths':self.native_profile.paths,
            'native_image_id':self.native_profile.image_id,'native_image_reference':self.native_profile.image_reference,
            'native_config_digest':self.native_profile.config_digest,
            'room':self.room,'seats':self.seats,'timeout':self.operation_timeout_seconds})

    @classmethod
    def read(cls,config_text,installation_path,installation_digest,*,native_profile):
        try:selection=read_manifest(installation_path,installation_digest)
        except (OSError,ValueError,TypeError):
            raise QualificationError('INSTALLATION_REFERENCE_UNVERIFIABLE') from None
        return cls(config_text,selection,installation_digest=installation_digest,native_profile=native_profile)

    def require_unchanged(self):
        require(hashlib.sha256(self.config_text.encode()).hexdigest()==self._source_digest
                and canonical({'configuration':self.config,'installation':self.installation})==self._declarations
                and self.native_profile.digest==self._native_digest
                and self.native_profile.room==self.room
                and self.native_profile.config_digest==self.config_digest
                and self._bindings()==self._bound_state,
                'LOCAL_RUNTIME_SELECTION_CHANGED')

    def review_configuration(self):
        self.require_unchanged()
        return native_review_configuration(self.config,self.seats,self.installation['human_mergers'])

    def check(self):
        """Metadata only: no credential access or admission/qualification claim."""
        self.require_unchanged();images={};problems=[]
        try:self.review_configuration()
        except QualificationError as error:problems.append(error.code)
        for runtime in ('pi','claude'):
            ref=self.installation[runtime+'_manifest']
            try:
                manifest=read_manifest(ref['path'],ref['sha256'])
                baked=payload(runtime,manifest.get('artifacts'))
                expected={**baked,'image_id':self.native_profile.image_id,
                    'image_reference':self.native_profile.image_reference,
                    'payload_manifest_digest':hashlib.sha256(canonical(baked)).hexdigest()}
                require(canonical(manifest)==canonical(expected),'LOCAL_RUNTIME_IMAGE_BINDING')
                images[runtime]={'sha256':ref['sha256'],'image_id':self.native_profile.image_id,
                                 'image_reference':self.native_profile.image_reference}
            except (OSError,ValueError,TypeError,AttributeError):
                problems.append(runtime.upper()+'_IMAGE_MANIFEST_UNAVAILABLE')
        try:broker_selection(self)
        except (OSError,ValueError,TypeError):problems.append('BROKER_INSTALLATION_UNAVAILABLE')
        if 'git_manifest' in self.installation:
            try:git_broker_selection(self)
            except (OSError,ValueError,TypeError):problems.append('GIT_BROKER_INSTALLATION_UNAVAILABLE')
        return {'version':1,'profile':'local-runtime-v1','room_id':self.room['id'],
            'configuration_sha256':self.config_digest,'installation_sha256':self.installation_digest,
            'mode':'check-only','effects':False,'images':images,
            'missing_prerequisites':sorted(set(problems)),
            'unobserved':['owned-runtime-resources','provider-authentication','native-process-admission',
                          'authenticated-human-session','git-gate-resource-binding']}
