"""Single explicit native setup flow: Engine bootstrap then canonical Rooms.

No package installation, VM, image build, provider login or runtime start.
"""
from copy import deepcopy
import hashlib
from io import StringIO
import json
import os
from pathlib import Path

from .local_host_profile import canonical,digest,require,LocalHostProfile
from .local_host_observe import inspect
from .local_host_plan import plan as host_plan,observation_digest
from .local_prepare import read_file,verified_output,prepare,output_parent
from .local_room_prepare import request,apply as apply_rooms
from . import local_engine_prepare as engine


def proposal(project_path,settings_path,workstation_output,hub_output,revision,*,
             host_receipt_root,engine_receipt_root=None,account_uid=None,account_gid=None,allocation_bytes=None):
    from .config import load
    from .local_engine_observe import inspect_exclusive
    raw_project=read_file(project_path);raw_settings=read_file(settings_path)
    config=load(StringIO(raw_project.decode()));settings=json.loads(raw_settings)
    profile=LocalHostProfile.parse(settings['host_profile'])
    require(settings['version']==2,'SETUP_SELECTED_PROFILE_REQUIRED')
    ws,_=verified_output(workstation_output,revision,hub=False);hub,_=verified_output(hub_output,revision,hub=True)
    images={r['id']:r['reference'] for r in config['deployment']['images']}
    require(all(images[r['image']]==ws['image_id'] for r in config['rooms']),'SETUP_SELECTED_IMAGE')
    storage=Path(settings['storage_root'])
    require(all(Path(v)!=storage and storage not in Path(v).parents for v in (project_path,settings_path)),
            'SETUP_BOOTSTRAP_INSIDE_STORAGE')
    if engine_receipt_root is not None:
        roots=[Path(engine_receipt_root),storage,Path(settings['endpoints_root']),Path(host_receipt_root)]
        require(all(a!=b and a not in b.parents and b not in a.parents for i,a in enumerate(roots) for b in roots[i+1:]),'SETUP_RECEIPT_OVERLAP')
    bootstrap=None
    if profile.mode=='owned':
        require(engine_receipt_root is not None,'SETUP_ENGINE_RECEIPT_REQUIRED')
        bootstrap=engine.plan(profile.document(),inspect_exclusive(profile.document()),
            receipt_root=engine_receipt_root,account_uid=account_uid,account_gid=account_gid)
        settings=deepcopy(settings);settings['host_profile']=bootstrap['artifacts']['admission_profile']
    else:require(engine_receipt_root is account_uid is account_gid is None,'SETUP_REUSE_HAS_NO_BOOTSTRAP')
    current=inspect(settings['host_profile'],storage_parent=str(Path(settings['storage_root']).parent),
        proposed_paths=[settings['storage_root'],settings['endpoints_root'],host_receipt_root])
    planned=host_plan(settings['host_profile'],current,storage_root=settings['storage_root'],
        endpoints_root=settings['endpoints_root'],receipt_root=host_receipt_root,allocation_bytes=allocation_bytes)
    allowed={'SELECTED_ENGINE_UNAVAILABLE','REUSE_REQUIRES_EXISTING_MAPPING'} if bootstrap else set()
    require(set(planned['blockers'])<=allowed,'SETUP_HOST_BLOCKED')
    selected=request(planned,config,settings,ws,hub)
    body={'version':1,'inputs':{'project':str(Path(project_path)),'settings':str(Path(settings_path))},
          'input_hashes':{'project':hashlib.sha256(raw_project).hexdigest(),'settings':hashlib.sha256(raw_settings).hexdigest()},
          'workstation_output':str(Path(workstation_output)),'hub_output':str(Path(hub_output)),
          'revision':revision,'engine':bootstrap,'host_observed':current,'rooms':selected,
          'allocation_bytes':allocation_bytes}
    return {**body,'plan_id':digest(body)}


def _unchanged_inputs(value):
    from .config import load
    for name,path in value['inputs'].items():require(hashlib.sha256(read_file(path)).hexdigest()==value['input_hashes'][name],'SETUP_INPUT_CHANGED')
    config=load(StringIO(read_file(value['inputs']['project']).decode()))
    original=json.loads(read_file(value['inputs']['settings']));settings=deepcopy(original)
    if value['engine'] is not None:
        engine._verify_plan(value['engine'])
        require(value['engine']['profile']==original['host_profile'],'SETUP_ENGINE_SELECTION_CHANGED')
        settings['host_profile']=value['engine']['artifacts']['admission_profile']
    require(config==value['rooms']['config'] and settings==value['rooms']['settings'],'SETUP_SELECTION_CHANGED')
    ws,_=verified_output(value['workstation_output'],value['revision'],hub=False)
    hub,_=verified_output(value['hub_output'],value['revision'],hub=True)
    require(ws==value['rooms']['workstation'] and hub==value['rooms']['hub'],'SETUP_IMAGE_CHANGED')
    selected=value['rooms']['host_plan']
    expected=host_plan(settings['host_profile'],value['host_observed'],storage_root=settings['storage_root'],
        endpoints_root=settings['endpoints_root'],receipt_root=selected['receipt_root'],allocation_bytes=value['allocation_bytes'])
    require(expected==selected,'SETUP_HOST_PLAN_CHANGED')


def apply(value,output_directory):
    require(os.geteuid()==0,'SETUP_ROOT_REQUIRED')
    require(value['plan_id']==digest({k:v for k,v in value.items() if k!='plan_id'}),'SETUP_PLAN_CHANGED')
    _unchanged_inputs(value)
    selected=value['rooms'];settings=selected['settings'];old=value['host_observed'];bootstrap=value['engine']
    # Reconstruct pure semantics, never trust arbitrary rehashed Room operations.
    from .local_room_prepare import _verify
    _verify(selected)
    output=Path(output_directory);require(output.is_absolute() and not os.path.lexists(output),'SETUP_OUTPUT_MUST_BE_NEW')
    storage=Path(settings['storage_root'])
    require(output!=storage and storage not in output.parents,'SETUP_BOOTSTRAP_INSIDE_STORAGE')
    fd=output_parent(output.parent);os.close(fd)
    if bootstrap is not None:
        ready=engine.apply(bootstrap)
        require(ready['profile']==settings['host_profile'] and ready['plan_id']==bootstrap['plan_id'],'SETUP_ENGINE_HANDOFF')
    derived_path=Path(bootstrap['receipt_root'])/'setup-room-request.json' if bootstrap else None
    if derived_path is not None and os.path.lexists(derived_path):
        recorded=json.loads(read_file(derived_path))
        engine._file(derived_path,canonical(recorded))
        require(type(recorded) is dict and set(recorded)=={'setup_plan','request'}
                and recorded['setup_plan']==value['plan_id'],'SETUP_RECORDED_PLAN_CHANGED')
        derived=recorded['request'];_verify(derived)
        require(all(derived[key]==selected[key] for key in ('config','settings','workstation','hub','ancestors','lock_path')),
                'SETUP_RECORDED_SELECTION_CHANGED')
    elif bootstrap is None:derived=selected
    else:
        current=inspect(settings['host_profile'],storage_parent=selected['host_plan']['storage_parent'],
            proposed_paths=[settings['storage_root'],settings['endpoints_root'],selected['host_plan']['receipt_root']])
        expected=deepcopy(old)
        p=LocalHostProfile.parse(ready['profile']);p.verify_engine(current['engine'])
        expected['engine']=current['engine']
        for key in ('subuid','subgid'):
            expected[key]=[*expected[key],{'user':p.remap_user,'offset':p.offset,'size':p.size}]
        expected['allocated_ids']=sorted(set(expected['allocated_ids'])|{bootstrap['account']['uid'],bootstrap['account']['gid']})
        require(observation_digest(expected)==observation_digest(current),'SETUP_HOST_CHANGED')
        planned=host_plan(settings['host_profile'],current,storage_root=settings['storage_root'],endpoints_root=settings['endpoints_root'],
            receipt_root=selected['host_plan']['receipt_root'],allocation_bytes=value['allocation_bytes'])
        require(not planned['blockers'],'SETUP_HOST_BLOCKED')
        derived=request(planned,selected['config'],settings,selected['workstation'],selected['hub'])
        engine._file(derived_path,canonical({'setup_plan':value['plan_id'],'request':derived}),create=True)
    planned=derived['host_plan']
    result=apply_rooms(derived)
    _unchanged_inputs(value)
    # Persist the already-declared admission settings privately, not a manual
    # JSON handoff or rewrite of the user's original selection.
    path=Path(planned['receipt_root'])/'setup-settings.json'
    engine._file(path,canonical(settings),create=not os.path.lexists(path))
    handoff=prepare(value['inputs']['project'],str(path),value['workstation_output'],value['hub_output'],
        value['revision'],str(output),**({'owned_xfs':result['native']['owned_xfs']} if result['native']['version']==3 else {}))
    require(json.loads(read_file(output/'native.json'))==result['native'],'SETUP_NATIVE_HANDOFF_CHANGED')
    _unchanged_inputs(value)
    return {'version':1,'status':'local-host-prepared','plan_id':value['plan_id'],'handoff':handoff,
            'remaining':['image-load-and-native-runtime-admission']}


def main(argv=None):
    import argparse
    from .local_prepare import write_output
    parser=argparse.ArgumentParser(description='Explicit first-Engine or existing-Engine native setup')
    sub=parser.add_subparsers(dest='action',required=True)
    planning=sub.add_parser('plan')
    for name in ('project','settings','workstation-output','hub-output','revision','host-receipt-root','output'):
        planning.add_argument('--'+name,required=True)
    planning.add_argument('--engine-receipt-root')
    for name in ('account-uid','account-gid','allocation-bytes'):planning.add_argument('--'+name,type=int)
    applying=sub.add_parser('apply');applying.add_argument('--plan',required=True);applying.add_argument('--output',required=True)
    args=parser.parse_args(argv)
    if args.action=='plan':
        value=proposal(args.project,args.settings,args.workstation_output,args.hub_output,args.revision,
            host_receipt_root=args.host_receipt_root,engine_receipt_root=args.engine_receipt_root,
            account_uid=args.account_uid,account_gid=args.account_gid,allocation_bytes=args.allocation_bytes)
        write_output(Path(args.output),{'request.json':canonical(value)})
        result={'status':'planned','plan_id':value['plan_id'],'request':str(Path(args.output)/'request.json')}
    else:result=apply(json.loads(read_file(args.plan)),args.output)
    print(json.dumps(result,sort_keys=True));return 0


if __name__=='__main__':raise SystemExit(main())
