"""Read-only first-user host choices; no image, provider or host effects.

Generated defaults are proposals, not reservations. Canonical plan/apply owners
re-observe every selected identity and collision before any privileged effect.
"""
from copy import deepcopy
from io import StringIO
import ipaddress
import json
import os
from pathlib import Path
import re
import time
import uuid

from .local_host_profile import LocalHostProfile,absolute_path,digest,require
from .local_host_observe import inspect,canonical_node
from .local_host_plan import interval,plan as host_plan
from .local_engine_observe import inspect_exclusive,_processes
from .local_room_prepare import observed_engine_allocations
from .local_room_resources import observe_quotas


def _defaults(parent,identifier):
    stem='uas-'+identifier[:16]
    return {'storage_root':parent+'/'+stem+'-data','endpoints_root':'/run/'+stem,
            'host_receipt_root':parent+'/'+stem+'-prepare',
            'engine_receipt_root':parent+'/'+stem+'-engine-prepare',
            'account_uid':None,'account_gid':None}


def _free_ids(observed):
    used=set(observed['allocated_ids'])
    spans=[interval(row) for key in ('subuid','subgid') for row in observed[key]]
    ids=next((n for n in range(999,99,-1) if n not in used and all(not a<=n<b for a,b in spans)),None)
    require(ids is not None,'GUIDED_SYSTEM_IDS_EXHAUSTED')
    spans.extend((n,n+1) for n in used)
    for start in range(1048576,2**31-65535,65536):
        if all(max(start,a)>=min(start+65536,b) for a,b in spans):return ids,start
    require(False,'GUIDED_SUBRANGES_EXHAUSTED')


def _profile(identifier,mode,socket,data,execution,user,offset):
    return LocalHostProfile.parse({'version':1,'profile':'local-host-v1','installation_id':identifier,
        'mode':mode,'engine':{'version':'29.8.2','socket':socket,'data_root':data,'exec_root':execution},
        'mapping':{'user':user,'offset':offset,'size':65536}}).document()


def _existing(identifier,socket,observed):
    engine=observed['engine'];root=engine['docker_root']
    match=re.fullmatch(r'(.+)/([0-9]+)\.\2',root)
    require(match is not None,'GUIDED_EXISTING_MAPPING_UNKNOWN')
    offset=int(match.group(2))
    names=[]
    for row in observed['subuid']:
        if row['offset']==offset and row['size']==65536 and row in observed['subgid']:names.append(row['user'])
    require(len(names)==1,'GUIDED_EXISTING_MAPPING_AMBIGUOUS')
    daemons=[r for r in _processes() if Path(r['exe']).name=='dockerd']
    require(len(daemons)==1 and daemons[0]['uid']==[0]*4
            and daemons[0]['netns']==os.readlink('/proc/self/ns/net'),'GUIDED_EXISTING_DAEMON_AMBIGUOUS')
    daemon=daemons[0];flags=daemon['arguments'];settings={}
    config=flags.get('--config-file','/etc/docker/daemon.json')
    if os.path.lexists(config):
        canonical_node(Path(config).parent)
        from .local_prepare import read_file
        node=Path(config).lstat()
        require(node.st_uid==0 and not node.st_mode&0o022,'GUIDED_ENGINE_CONFIG_OWNER')
        settings=json.loads(read_file(config));require(type(settings) is dict,'GUIDED_ENGINE_CONFIG')
    else:require('--config-file' not in flags,'GUIDED_ENGINE_CONFIG_MISSING')
    # Pinned Engine defaults are used only when neither configuration nor CLI
    # selects a different value; custom listeners must be explicitly evidenced.
    hosts=settings.get('hosts',['unix:///var/run/docker.sock'])
    require(type(hosts) is list and any(type(h) is str and h.startswith('unix://') and
            os.path.realpath(h[7:])==socket for h in hosts),'GUIDED_ENGINE_SOCKET_UNPROVEN')
    execution=flags.get('--exec-root',settings.get('exec-root','/var/run/docker'))
    data=flags.get('--data-root',settings.get('data-root','/var/lib/docker'))
    require(type(execution) is str and type(data) is str and os.path.realpath(data)==match.group(1),
            'GUIDED_ENGINE_DATA_ROOT_UNPROVEN')
    selected=_profile(identifier,'reuse',socket,match.group(1),os.path.realpath(execution),names[0],offset)
    LocalHostProfile.parse(selected).verify_engine(engine)
    return selected


def inspect_host(parent='/var/lib',installation_id=None,engine_socket='/run/docker.sock'):
    parent=absolute_path(parent);engine_socket=absolute_path(engine_socket)
    identifier=installation_id or uuid.uuid4().hex
    require(type(identifier) is str and re.fullmatch('[0-9a-f]{32}',identifier),'GUIDED_INSTALLATION_ID')
    defaults=_defaults(parent,identifier);initial=_profile(identifier,'reuse',engine_socket,'/var/lib/docker','/run/docker','dockremap',100000)
    observed=inspect(initial,storage_parent=parent,proposed_paths=[defaults[k] for k in ('storage_root','endpoints_root','host_receipt_root','engine_receipt_root')])
    result={'version':1,'installation_id':identifier,'parent':parent,'profile':None,'host_observed':observed,
            'defaults':defaults,'engine_observed':None,'blockers':[]}
    try:
        if observed['engine'] is not None:selected=_existing(identifier,engine_socket,observed)
        else:
            account,offset=_free_ids(observed);stem='uas-'+identifier[:16]
            selected=_profile(identifier,'owned','/run/'+stem+'-engine.sock',parent+'/'+stem+'-engine',
                '/run/'+stem+'-engine','uas'+identifier[:12],offset)
            defaults.update(account_uid=account,account_gid=account)
            evidence=inspect_exclusive(selected);result['engine_observed']=evidence
            result['blockers'].extend(evidence['blockers'])
            if any(row['name']==selected['mapping']['user'] for kind in ('passwd','group') for row in evidence['accounts'][kind]):
                result['blockers'].append('GUIDED_ACCOUNT_NAME_OCCUPIED')
        result['profile']=selected
    except (ValueError,OSError,KeyError) as exc:result['blockers'].append(getattr(exc,'code','GUIDED_ENGINE_DISCOVERY_UNKNOWN'))
    if observed['selinux']!='Enforcing':result['blockers'].append('SELINUX_ENFORCING_REQUIRED')
    if observed['occupied_paths']:result['blockers'].append('GUIDED_OWNED_PATH_OCCUPIED')
    result['blockers']=sorted(set(result['blockers']))
    return result


def _used_categories(levels):
    used=set()
    for level in levels:
        require(type(level) is str and level.startswith('s0'),'GUIDED_MCS_INVENTORY')
        if level=='s0':continue
        require(level.startswith('s0:'),'GUIDED_MCS_INVENTORY')
        for part in level[3:].split(','):
            match=re.fullmatch(r'c([0-9]+)(?:\.c([0-9]+))?',part)
            require(match is not None,'GUIDED_MCS_INVENTORY')
            a=int(match.group(1));b=int(match.group(2) or a)
            require(0<=a<=b<=1023,'GUIDED_MCS_INVENTORY');used.update(range(a,b+1))
    return used


def select_rooms(config,inspection,allocation_bytes=None):
    from .config import load
    require(type(inspection) is dict and inspection.get('version')==1 and not inspection['blockers'],'GUIDED_HOST_BLOCKED')
    load(StringIO(json.dumps(config)))  # validate without serializing normalized internal fields
    selected=LocalHostProfile.parse(inspection['profile'])
    observed=inspection['host_observed'];defaults=inspection['defaults'];root=defaults['storage_root']
    require(1<=len(config['rooms'])<=64,'GUIDED_ROOM_BOUND')
    allocations=observed_engine_allocations(selected.document()) if selected.mode=='reuse' else {'levels':set(),'networks':set()}
    categories=_used_categories(allocations['levels']);networks=[ipaddress.ip_network(n) for n in [*observed['networks'],*allocations['networks']]]
    xfs=observed['storage']['filesystem']=='xfs' and observed['storage']['project_accounting'] and observed['storage']['project_enforcement']
    if not xfs:require(type(allocation_bytes) is int,'GUIDED_EXPLICIT_STORAGE_BUDGET_REQUIRED')
    output=deepcopy(config);output['deployment']['state_root']=root+'/control'
    rooms={};quota_ids=set();deadline=time.monotonic()+30;quota_checks=0
    for room in output['rooms']:
        room['state_root']=root+'/control/'+room['id']
        room['project']['roots']={name:root+'/projects/'+room['project']['id']+'/'+name for name in room['project']['roots']}
        free=[n for n in range(1024) if n not in categories];require(len(free)>=2,'GUIDED_MCS_EXHAUSTED')
        a,b=free[:2];categories.update((a,b))
        network=None
        for index in range(4096):
            candidate=ipaddress.ip_network('172.'+str(16+index//256)+'.'+str(index%256)+'.0/24')
            if all(n.version!=4 or not candidate.overlaps(n) for n in networks):network=candidate;break
        require(network is not None,'GUIDED_NETWORK_EXHAUSTED');networks.append(network)
        seed=int(digest({'installation':inspection['installation_id'],'room':room['id']})[:8],16)%1000000000+10000
        for attempt in range(8):
            project=seed+attempt
            if project in quota_ids:continue
            if xfs:
                require(quota_checks<64 and time.monotonic()<deadline,'GUIDED_QUOTA_OBSERVATION_BOUND');quota_checks+=1
                state=observe_quotas(inspection['parent'],project)
                if any(project in values for values in state.values()):continue
            break
        else:require(False,'GUIDED_QUOTA_CANDIDATES_BUSY')
        quota_ids.add(project);rooms[room['id']]={'quota_project_id':project,'mcs_level':f's0:c{a},c{b}',
            'subnet':str(network),'gateway':str(network.network_address+1)}
    load(StringIO(json.dumps(output)))
    settings={'version':2,'installation_id':inspection['installation_id'],'storage_root':root,
        'endpoints_root':defaults['endpoints_root'],'engine_version':selected.engine_version,
        'mapping':{'offset':selected.offset,'size':selected.size},'host_profile':selected.document(),'rooms':rooms}
    admission=selected.document();admission['mode']='reuse'
    planned=host_plan(admission,observed,storage_root=root,endpoints_root=defaults['endpoints_root'],
        receipt_root=defaults['host_receipt_root'],allocation_bytes=allocation_bytes)
    expected={'SELECTED_ENGINE_UNAVAILABLE','REUSE_REQUIRES_EXISTING_MAPPING'} if selected.mode=='owned' else set()
    blockers=sorted(set(planned['blockers'])-expected)
    return {'version':1,'config':output,'settings':settings,'host_plan':planned,'allocation_bytes':allocation_bytes,
            'blockers':blockers,'inspection_digest':digest(inspection),'defaults':deepcopy(defaults)}
