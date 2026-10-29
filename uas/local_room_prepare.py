"""Explicit per-installation preparation, using the existing native-v1 consumer.

No command runs on import. The request is a reviewable proposal, not a receipt
or host admission proof. Only an explicit root invocation can apply it.
"""
from copy import deepcopy
import fcntl
import ipaddress
import hashlib
import json
import re
import time
import os
from pathlib import Path

from .local_host_profile import canonical, digest, require, LocalHostProfile
from .local_host_apply import apply as apply_host, owned_directory
from .local_host_observe import canonical_node, inspect
from .local_host_receipt import PreparationReceipt
from .local_prepare import assemble, directory_identity
from .local_native import LocalNativeProfile
from .local_room_resources import reserve_quota, prepare_leaf
from .local_host_process import run_fixed


def request(host_plan, config, settings, workstation, hub):
    """Bind all user selections before effects; no path probes or mutation."""
    require(type(host_plan) is dict and host_plan.get('plan_id') ==
            digest({k:v for k,v in host_plan.items() if k!='plan_id'}), 'ROOM_HOST_PLAN')
    require(settings.get('installation_id') == host_plan['profile']['installation_id']
            and settings.get('storage_root') == host_plan['storage_root']
            and settings.get('endpoints_root') == host_plan['endpoints_root'], 'ROOM_HOST_BINDING')
    # Exercise the canonical consumer's pure selection/path constraints with
    # synthetic DISTINCT identities. These never leave this validation call and
    # never stand in for observed identities in the returned handoff.
    declared = {}
    def planned_identity(path):
        if path not in declared: declared[path] = [1,len(declared)+1]
        return declared[path]
    native=assemble(config, settings, workstation, hub, observe=planned_identity)
    from .local_native import selected_host
    require(selected_host(native).document()==host_plan['profile'], 'ROOM_ENGINE_BINDING')
    root = Path(settings['storage_root'])
    paths = [Path(p) for room in config['rooms'] for p in
             [*room['project']['roots'].values(),room['state_root']+'/runtime']]
    require(all(root in path.parents for path in paths), 'ROOM_PATH_SCOPE')
    ancestors = {parent for path in paths for parent in path.parents
                 if root in parent.parents}
    require(not ancestors.intersection(paths), 'ROOM_PARENT_IS_RUNTIME_OWNED')
    body = {'version':1, 'host_plan':deepcopy(host_plan), 'config':deepcopy(config),
            'settings':deepcopy(settings), 'workstation':deepcopy(workstation), 'hub':deepcopy(hub),
            'lock_path':host_plan['storage_parent'],
            'ancestors':[str(p) for p in sorted(ancestors,key=lambda p:(len(p.parts),str(p)))]}
    require(len(canonical(body))<=65536,'ROOM_REQUEST_BOUND')
    return dict(body, request_id=digest(body))


def _verify(value):
    expected=request(value['host_plan'],value['config'],value['settings'],value['workstation'],value['hub'])
    require(value==expected,'ROOM_REQUEST_CHANGED')
    return expected


def _operations(value, identity):
    settings=value['settings'];storage=settings['storage_root']
    operations=[{'kind':'prepare-room-parent','path':path} for path in value['ancestors']]
    for room in value['config']['rooms']:
        selected=settings['rooms'][room['id']]
        operations.append({'kind':'reserve-room-quota','storage_root':storage,
            'storage_identity':identity,'project_id':selected['quota_project_id'],
            'disk_bytes':room['resources']['disk_bytes']})
        for path in [*room['project']['roots'].values(),room['state_root']+'/runtime']:
            operations.append({'kind':'prepare-room-leaf','storage_root':storage,
                'storage_identity':identity,'path':path,'project_id':selected['quota_project_id'],
                'mcs_level':selected['mcs_level']})
    body={'version':1,'request_id':value['request_id'],'operations':operations}
    return dict(body,plan_id=digest(body))


def observed_engine_allocations(profile_document):
    """Read only required labels/subnets, never container config or secrets."""
    profile=LocalHostProfile.parse(profile_document)
    result={'levels':set(),'networks':set()}
    deadline=time.monotonic()+10
    remaining=1024*1024
    def read(args):
        nonlocal remaining
        require(time.monotonic()<deadline and remaining>0,'ROOM_ENGINE_OBSERVATION_BOUND')
        raw=run_fixed(profile.docker_argv(args),limit=remaining,deadline=deadline)
        remaining-=len(raw.encode('utf-8'))
        require(time.monotonic()<deadline and remaining>=0,'ROOM_ENGINE_OBSERVATION_BOUND')
        return raw
    for resource in ('container','network'):
        args=['ps','-a','--no-trunc','--format','{{.ID}}'] if resource=='container' else ['network','ls','--no-trunc','--format','{{.ID}}']
        ids=read(args).splitlines()
        require(len(ids)<=4096 and len(set(ids))==len(ids) and
                all(re.fullmatch('[0-9a-f]{64}',item) for item in ids),'ROOM_ENGINE_INVENTORY')
        if not ids:continue
        # One bounded projected call per resource, not one ten-second call per
        # object. Four calls share one deadline and one total output budget.
        template='{"id":{{json .Id}},"value":[{{json .ProcessLabel}},{{json .MountLabel}}]}' if resource=='container' else '{"id":{{json .Id}},"value":{{json .IPAM.Config}}}'
        lines=read([resource,'inspect','--format',template,*ids]).splitlines()
        require(len(lines)==len(ids),'ROOM_ENGINE_PROJECTION')
        seen=set()
        for line in lines:
            row=json.loads(line)
            require(type(row) is dict and set(row)=={'id','value'} and row['id'] in ids
                    and row['id'] not in seen,'ROOM_ENGINE_PROJECTION')
            seen.add(row['id']);value=row['value']
            if resource=='container':
                require(type(value) is list and len(value)==2 and all(type(v) is str for v in value),'ROOM_ENGINE_LABELS')
                for label in value:
                    if not label:continue
                    pieces=label.split(':',3)
                    require(len(pieces)==4,'ROOM_ENGINE_LABELS')
                    result['levels'].add(pieces[3])
            else:
                require(value is None or type(value) is list,'ROOM_ENGINE_NETWORKS')
                for row in value or []:
                    require(type(row) is dict and type(row.get('Subnet')) is str,'ROOM_ENGINE_NETWORKS')
                    result['networks'].add(str(ipaddress.ip_network(row['Subnet'],strict=False)))
    return result


def apply(value):
    value=_verify(value)
    require(os.geteuid()==0,'ROOM_APPLY_ROOT_REQUIRED')
    host=value['host_plan'];settings=value['settings']
    lock_path=Path(value['lock_path']);lock_identity=canonical_node(lock_path)
    require(lock_identity.st_uid==0 and not lock_identity.st_mode&0o022,'ROOM_LOCK_OWNER')
    lock=os.open(lock_path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        held=os.fstat(lock)
        require((held.st_dev,held.st_ino)==(lock_identity.st_dev,lock_identity.st_ino),'ROOM_LOCK_CHANGED')
        # Existing root-owned directory inode, explicitly declared in the request.
        # Coordinates this installer only, never claims to lock external admins.
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        current=inspect(host['profile'],storage_parent=host['storage_parent'],
                        proposed_paths=[host['storage_root'],host['endpoints_root'],host['receipt_root']])
        allocations=observed_engine_allocations(host['profile'])
        require(not any(row['mcs_level'] in allocations['levels'] for row in settings['rooms'].values()),
                'ROOM_MCS_COLLISION')
        networks=[ipaddress.ip_network(n) for n in [*current['networks'],*allocations['networks']]]
        require(not any(ipaddress.ip_network(row['subnet']).overlaps(n)
                        for row in settings['rooms'].values() for n in networks if n.version==4),'ROOM_NETWORK_COLLISION')
        apply_host(host)
        identity=directory_identity(settings['storage_root'])
        plan=_operations(value,identity)
        receipt_path=Path(host['receipt_root'])/'rooms'
        owned_directory(receipt_path,plan_id=plan['plan_id'],operation='room-receipts',
                        owner_uid=0,mode=0o700,create=not os.path.lexists(receipt_path))
        with PreparationReceipt(receipt_path,plan,owner_uid=0) as receipt:
            for index,op in enumerate(plan['operations']):
                if op['kind']=='prepare-room-parent':
                    state=receipt.state(index)
                    create=receipt.intent(index) if state['state']=='not-started' else False
                    parent=canonical_node(Path(op['path']).parent)
                    require(parent.st_dev==identity[0],'ROOM_PARENT_DEVICE')
                    evidence=owned_directory(Path(op['path']),plan_id=plan['plan_id'],
                        operation='room-parent',owner_uid=0,mode=0o711,create=create,
                        repair_partial=state['state']=='unknown',
                        expected_parent_identity=[parent.st_dev,parent.st_ino])
                    if state['state']=='confirmed':require(evidence==state['evidence'],'ROOM_PARENT_DRIFT')
                    else:receipt.confirm(index,evidence)
                elif op['kind']=='reserve-room-quota':reserve_quota(receipt,index)
                else:prepare_leaf(receipt,index)
        # Real inode collection and the canonical storage observer are mandatory
        # after effects. This does not start containers or fabricate image builds.
        native=assemble(value['config'],settings,value['workstation'],value['hub'])
        for room in value['config']['rooms']:
            LocalNativeProfile(value['config'],native,room['id'],
                value['config']['deployment']['state_root']).observe_storage()
        require(directory_identity(str(lock_path))==[held.st_dev,held.st_ino],'ROOM_LOCK_CHANGED')
        return {'version':1,'request_id':value['request_id'],'status':'room-storage-prepared',
                'native':native,'remaining':['image-build-evidence-handoff','native-runtime-admission']}
    finally:os.close(lock)


def file_request(host_plan_path, project_path, settings_path, workstation_output, hub_output, revision):
    """Read-only proposal with exact build evidence, reusable by explicit apply."""
    from io import StringIO
    from .config import load
    from .local_prepare import read_file, verified_output
    require(type(revision) is str and re.fullmatch('[0-9a-f]{40}',revision),'ROOM_SOURCE_REVISION')
    inputs={key:str(Path(path)) for key,path in
            [('host_plan',host_plan_path),('project',project_path),('settings',settings_path)]}
    raw={key:read_file(path) for key,path in inputs.items()}
    config=load(StringIO(raw['project'].decode('utf-8')))
    settings=json.loads(raw['settings']);host=json.loads(raw['host_plan'])
    ws,_=verified_output(workstation_output,revision,hub=False)
    hub,_=verified_output(hub_output,revision,hub=True)
    images={row['id']:row['reference'] for row in config['deployment']['images']}
    require(all(images[room['image']]==ws['image_id'] for room in config['rooms']),'ROOM_SELECTED_IMAGE')
    body={'version':1,'inputs':inputs,'input_hashes':{key:hashlib.sha256(value).hexdigest() for key,value in raw.items()},
          'workstation_output':str(Path(workstation_output)),'hub_output':str(Path(hub_output)),
          'revision':revision,'request':request(host,config,settings,ws,hub)}
    return dict(body,envelope_id=digest(body))


def apply_file(envelope_path, output_directory):
    """One explicit apply and canonical #198 metadata handoff; no runtime start."""
    from .local_prepare import read_file, prepare, output_parent
    require(os.geteuid()==0,'ROOM_APPLY_ROOT_REQUIRED')
    value=json.loads(read_file(envelope_path))
    rebuilt=file_request(value['inputs']['host_plan'],value['inputs']['project'],value['inputs']['settings'],
                         value['workstation_output'],value['hub_output'],value['revision'])
    require(value==rebuilt,'ROOM_INPUT_CHANGED')
    output=Path(output_directory)
    require(output.is_absolute() and not os.path.lexists(output),'ROOM_OUTPUT_MUST_BE_NEW')
    parent=output_parent(output.parent);os.close(parent)
    result=apply(value['request'])
    require(file_request(value['inputs']['host_plan'],value['inputs']['project'],value['inputs']['settings'],
                         value['workstation_output'],value['hub_output'],value['revision'])==value,
            'ROOM_INPUT_CHANGED_DURING_APPLY')
    # Same existing artifact/source checks and exclusive output contract as the
    # manual prepared-host path. Unknown output writes are preserved, not retried.
    handoff=prepare(value['inputs']['project'],value['inputs']['settings'],
                    value['workstation_output'],value['hub_output'],value['revision'],output_directory)
    require(file_request(value['inputs']['host_plan'],value['inputs']['project'],value['inputs']['settings'],
                         value['workstation_output'],value['hub_output'],value['revision'])==value,
            'ROOM_INPUT_CHANGED_DURING_HANDOFF')
    observed_native=read_file(output/'native.json')
    selection=json.loads(read_file(output/'installation-selection.json'))
    expected_reference={'path':str(output/'native.json'),'sha256':hashlib.sha256(observed_native).hexdigest()}
    require(json.loads(observed_native)==result['native']
            and selection['project']=={'path':value['inputs']['project'],'sha256':value['input_hashes']['project']}
            and selection['native']==expected_reference
            and json.loads(read_file(output/'native-reference.json'))==expected_reference
            and handoff['native']==expected_reference, 'ROOM_HANDOFF_CHANGED')
    return {'version':1,'status':'local-host-prepared','request_id':result['request_id'],
            'handoff':handoff,'remaining':['native-runtime-admission']}


def main(argv=None):
    import argparse
    from .local_prepare import write_output
    parser=argparse.ArgumentParser(description='Explicit persistent local host preparation')
    sub=parser.add_subparsers(dest='action',required=True)
    planning=sub.add_parser('plan')
    for name in ('host-plan','project','settings','workstation-output','hub-output','revision','output'):
        planning.add_argument('--'+name,required=True)
    applying=sub.add_parser('apply');applying.add_argument('--plan',required=True);applying.add_argument('--output',required=True)
    args=parser.parse_args(argv)
    if args.action=='plan':
        value=file_request(args.host_plan,args.project,args.settings,args.workstation_output,args.hub_output,args.revision)
        write_output(Path(args.output),{'request.json':canonical(value)})
        result={'status':'planned','envelope_id':value['envelope_id'],'request':str(Path(args.output)/'request.json')}
    else:result=apply_file(args.plan,args.output)
    print(json.dumps(result,sort_keys=True))
    return 0


if __name__=='__main__':raise SystemExit(main())
