"""Compose existing public runtime references; never provision credentials."""
import hashlib
import json
from io import StringIO
from pathlib import Path

from .config import load
from .local_host_profile import canonical,require
from .local_prepare import read_file,write_output
from .local_installation import document,reference
from .local_native import LocalNativeProfile
from .local_runtime_plan import LocalRuntimePlan


def _read_reference(value):
    reference(value)
    raw=read_file(value['path'])
    require(hashlib.sha256(raw).hexdigest()==value['sha256'],'RUNTIME_HANDOFF_REFERENCE_CHANGED')
    return raw


def prepare_runtime(prepared, *, broker_manifest, human_mergers, room_id=None,
                    git_manifest=None,git_broker_manifest=None,gate_manifest=None,output=None):
    root=Path(prepared)
    installation=document(read_file(root/'installation-selection.json'))
    require(installation.get('native') is not None,'RUNTIME_HANDOFF_NATIVE_REQUIRED')
    text=_read_reference(installation['project']).decode('utf-8');config=load(StringIO(text))
    native=document(_read_reference(installation['native']))
    if room_id is None:
        require(len(config['rooms'])==1,'RUNTIME_HANDOFF_ROOM_REQUIRED');room_id=config['rooms'][0]['id']
    profile=LocalNativeProfile(config,native,room_id,config['deployment']['state_root'])
    output=Path(output) if output is not None else root/('runtime-'+room_id)
    require(output.is_absolute() and output!=Path(profile.storage) and Path(profile.storage) not in output.parents,
            'RUNTIME_HANDOFF_INSIDE_STORAGE')
    refs={name:document(read_file(root/(name+'-reference.json'))) for name in ('pi','claude')}
    for ref in refs.values():_read_reference(ref)
    sources={'broker':broker_manifest,'git':git_manifest,'git_broker':git_broker_manifest,'gate':gate_manifest}
    require(broker_manifest is not None,'RUNTIME_HANDOFF_BROKER_REQUIRED')
    for name,filename in sources.items():
        if filename is not None:
            raw=read_file(filename);document(raw)
            refs[name]={'path':str(Path(filename)),'sha256':hashlib.sha256(raw).hexdigest()}
    selected={'version':1,'profile':'local-runtime-v1','room_id':room_id,'installation_id':profile.nonce,
              'human_mergers':human_mergers,**{k+'_manifest':v for k,v in refs.items()}}
    raw=canonical(selected);sha=hashlib.sha256(raw).hexdigest()
    plan=LocalRuntimePlan(text,selected,installation_digest=sha,native_profile=profile)
    # Existing owners validate payloads, Broker metadata, paired Git/Gate schemas
    # and exact image/config bindings. None opens referenced credential contents.
    checked=plan.check();require(not checked['missing_prerequisites'],'RUNTIME_HANDOFF_METADATA_MISSING: '+','.join(checked['missing_prerequisites']))
    profile.bind_runtime(plan)
    reference_value={'path':str(output/'runtime.json'),'sha256':sha}
    for ref in refs.values():_read_reference(ref)
    require(_read_reference(installation['project']).decode('utf-8')==text,'RUNTIME_HANDOFF_PROJECT_CHANGED')
    require(document(_read_reference(installation['native']))==native,'RUNTIME_HANDOFF_NATIVE_CHANGED')
    write_output(output,{'runtime.json':raw,'runtime-reference.json':canonical(reference_value)})
    return {'status':'runtime-descriptor-prepared','room_id':room_id,'reference':str(output/'runtime-reference.json'),
            'host_effects':False,'next':'select-runtime before first Room start; credentials and Run admission are separate'}
