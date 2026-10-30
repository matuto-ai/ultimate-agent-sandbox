"""Explicit first-root-Engine bootstrap, not a general package installer.

Only a reviewed plan may create its exact system account, ranges and owned unit.
An existing foreign Docker footprint is never disabled, rewritten or adopted.
All effects have append-only receipts; an uncertain effect is observed, not retried.
"""
from copy import deepcopy
import fcntl
import json
import os
from pathlib import Path
import stat
import time

from .local_host_profile import LocalHostProfile,absolute_path,canonical,digest,require
from .local_host_observe import canonical_node,read_text,subordinate
from .local_host_receipt import PreparationReceipt
from .local_host_process import run_fixed


def artifacts(profile_document,receipt_root):
    p=LocalHostProfile.parse(profile_document)
    require(p.mode=='owned','ENGINE_OWNED_SELECTION')
    root=absolute_path(receipt_root)
    unit='uas-engine-'+p.installation_id+'.service'
    config={'hosts':['unix://'+p.socket],'data-root':p.data_root,'exec-root':p.exec_root,
            'pidfile':p.exec_root+'/docker.pid','userns-remap':p.remap_user+':'+p.remap_user,
            'selinux-enabled':True,'bridge':'none','live-restore':False,'group':'root',
            'storage-driver':'overlay2','features':{'containerd-snapshotter':False},
            'exec-opts':['native.cgroupdriver=systemd'],'ip-forward':False}
    # dockerd starts its own managed containerd; no separate management daemon.
    service='\n'.join(['[Unit]','Description=Ultimate Sandbox owned Engine '+p.installation_id,
        'After=network-online.target','Wants=network-online.target','', '[Service]',
        'Type=notify','ExecStart=/usr/bin/dockerd --config-file='+root+'/daemon.json',
        'Restart=no','TimeoutStartSec=60','TimeoutStopSec=30',
        'Delegate=yes','KillMode=process','LimitNOFILE=1048576','TasksMax=infinity',
        '', '[Install]','WantedBy=multi-user.target',''])
    admission=p.document();admission['mode']='reuse'
    return {'unit':unit,'unit_path':'/etc/systemd/system/'+unit,'config_path':root+'/daemon.json',
            'config':config,'service':service,'admission_profile':admission}


def plan(profile_document,observed,*,receipt_root,account_uid,account_gid):
    p=LocalHostProfile.parse(profile_document);a=artifacts(profile_document,receipt_root)
    require(type(account_uid) is int and type(account_gid) is int
            and 100<=account_uid<1000 and 100<=account_gid<1000,'ENGINE_SYSTEM_ACCOUNT_SELECTION')
    require(type(observed) is dict and observed.get('version')==1 and observed.get('complete') is True
            and observed.get('engine_version')==p.engine_version and observed.get('ipv4_forwarding')=='1','ENGINE_OBSERVATION')
    require(not observed['blockers'],'ENGINE_NOT_PRISTINE')
    parent=observed.get('socket_parent')
    require(type(parent) is dict and set(parent)=={'path','identity'} and parent['path']==str(Path(p.socket).parent)
            and type(parent['identity']) is list and len(parent['identity'])==2
            and all(type(n) is int and n>=0 for n in parent['identity']) and parent['identity'][1]>0,'ENGINE_SOCKET_PARENT')
    # Exact IDs are explicit plan inputs, never selected by a race-prone useradd default.
    require(not any(r['name']==p.remap_user or r['uid']==account_uid for r in observed['accounts']['passwd']), 'ENGINE_ACCOUNT_CONFLICT')
    require(not any(r['name']==p.remap_user or r['gid']==account_gid for r in observed['accounts']['group']), 'ENGINE_ACCOUNT_CONFLICT')
    for key in ('subuid','subgid'):
        for row in observed[key]:
            require(row['user']!=p.remap_user and
                    max(row['offset'],p.offset)>=min(row['offset']+row['size'],p.offset+p.size), 'ENGINE_SUBRANGE_CONFLICT')
    require(not any(p.offset<=r['uid']<p.offset+p.size for r in observed['accounts']['passwd'])
            and not any(p.offset<=r['gid']<p.offset+p.size for r in observed['accounts']['group']),'ENGINE_MAPPING_ACCOUNT_CONFLICT')
    roots=[Path(receipt_root),Path(p.data_root),Path(p.exec_root)]
    require(all(x!=y and x not in y.parents and y not in x.parents for i,x in enumerate(roots) for y in roots[i+1:]),'ENGINE_PATH_OVERLAP')
    require(all(Path(p.socket)!=x and x not in Path(p.socket).parents for x in roots),'ENGINE_SOCKET_OVERLAP')
    body={'version':1,'profile':p.document(),'receipt_root':absolute_path(receipt_root),
          'account':{'name':p.remap_user,'uid':account_uid,'gid':account_gid,'home':'/nonexistent','shell':'/usr/sbin/nologin'},
          'artifacts':a,'observed':deepcopy(observed),
          'operations':[{'kind':k} for k in ('group','account','subuid','subgid','directories','config','validate','unit','reload','enable','start')]}
    return {**body,'plan_id':digest(body)}


def _account_snapshot():
    result={'passwd':[],'group':[]}
    for kind,fields in (('passwd',7),('group',4)):
        for line in read_text('/etc/'+kind).splitlines():
            if not line or line.startswith('#'):continue
            row=line.split(':');require(len(row)==fields,'ENGINE_ACCOUNT_FORMAT')
            if kind=='passwd':result[kind].append({'name':row[0],'uid':int(row[2]),'gid':int(row[3]),'home':row[5],'shell':row[6]})
            else:result[kind].append({'name':row[0],'gid':int(row[2]),'members':row[3]})
    return result


def _accounts_guard(value,*,complete=False):
    p=LocalHostProfile.parse(value['profile']);expected=value['account'];current=_account_snapshot()
    before=value['observed']['accounts']
    # Preserve every other account exactly; an unrelated concurrent administrator
    # update makes this plan stale rather than broadening its authority.
    for kind,idkey in (('passwd','uid'),('group','gid')):
        rows=current[kind];selected=[r for r in rows if r['name']==p.remap_user]
        require([r for r in rows if r['name']!=p.remap_user]==before[kind],'ENGINE_ACCOUNT_DATABASE_CHANGED')
        require(len(selected)<=1,'ENGINE_ACCOUNT_CONFLICT')
        if selected:
            target=expected if kind=='passwd' else {'name':p.remap_user,'gid':expected['gid'],'members':''}
            require(selected[0]==target,'ENGINE_ACCOUNT_CONFLICT')
        elif complete:require(False,'ENGINE_ACCOUNT_REQUIRED')
    for kind in ('subuid','subgid'):
        rows=subordinate(read_text('/etc/'+kind));other=[r for r in rows if r['user']!=p.remap_user]
        require(other==value['observed'][kind],'ENGINE_SUBRANGE_DATABASE_CHANGED')
        selected=[r for r in rows if r['user']==p.remap_user]
        require(not selected or selected==[{'user':p.remap_user,'offset':p.offset,'size':p.size}],'ENGINE_SUBRANGE_CONFLICT')
    return current


def _file(path,raw,*,create=False):
    path=Path(path);canonical_node(path.parent)
    if create:
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:require(os.write(fd,raw)==len(raw),'ENGINE_FILE_INCOMPLETE');os.fsync(fd)
        finally:os.close(fd)
        parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(parent)
        finally:os.close(parent)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        n=os.fstat(fd)
        require(stat.S_ISREG(n.st_mode) and n.st_uid==n.st_gid==0 and n.st_nlink==1
                and stat.S_IMODE(n.st_mode)==0o600 and n.st_size==len(raw)
                and os.read(fd,len(raw)+1)==raw,'ENGINE_FILE_OWNERSHIP')
        return [n.st_dev,n.st_ino]
    finally:os.close(fd)


def _unit_state(unit):
    raw=run_fixed(['/usr/bin/systemctl','show',unit,'--property=FragmentPath,ActiveState,UnitFileState,MainPID,ControlGroup,DropInPaths','--no-pager'])
    rows=dict(line.split('=',1) for line in raw.splitlines())
    require(set(rows)=={'FragmentPath','ActiveState','UnitFileState','MainPID','ControlGroup','DropInPaths'},'ENGINE_UNIT_OBSERVATION')
    return rows


def _effect(value,kind):
    p=LocalHostProfile.parse(value['profile']);a=value['artifacts'];account=value['account']
    if kind=='group':run_fixed(['/usr/sbin/groupadd','--system','--gid',str(account['gid']),p.remap_user])
    elif kind=='account':run_fixed(['/usr/sbin/useradd','--system','--no-create-home','--no-log-init','--uid',str(account['uid']),
        '--gid',str(account['gid']),'--home-dir','/nonexistent','--shell','/usr/sbin/nologin','--key','SUB_UID_COUNT=0','--key','SUB_GID_COUNT=0',p.remap_user])
    elif kind in ('subuid','subgid'):run_fixed(['/usr/sbin/usermod','--add-'+kind+'s',str(p.offset)+'-'+str(p.offset+p.size-1),p.remap_user])
    elif kind=='directories':
        from .local_host_apply import owned_directory
        for target in (p.data_root,p.exec_root):
            owned_directory(target,plan_id=value['plan_id'],operation={'kind':'engine-directory','path':target},owner_uid=0,mode=0o711,create=True)
    elif kind=='config':_file(a['config_path'],canonical(a['config']),create=True)
    elif kind=='validate':run_fixed(['/usr/bin/dockerd','--validate','--config-file',a['config_path']])
    elif kind=='unit':_file(a['unit_path'],a['service'].encode(),create=True)
    elif kind=='reload':run_fixed(['/usr/bin/systemctl','daemon-reload'])
    elif kind=='enable':run_fixed(['/usr/bin/systemctl','--quiet','enable',a['unit']])
    elif kind=='start':
        _socket_parent_guard(value)
        run_fixed(['/usr/bin/systemctl','start','--no-block',a['unit']])
    else:require(False,'ENGINE_OPERATION')


def _observe_step(value,kind):
    p=LocalHostProfile.parse(value['profile']);a=value['artifacts'];account=value['account'];identity=[0,0]
    current=_accounts_guard(value)
    if kind in ('group','account'):
        rows=current['group' if kind=='group' else 'passwd']
        require(any(r['name']==p.remap_user for r in rows),'ENGINE_EFFECT_UNCONFIRMED')
        identity=[account['gid'],account['uid']]
    elif kind in ('subuid','subgid'):
        require([r for r in subordinate(read_text('/etc/'+kind)) if r['user']==p.remap_user]
                ==[{'user':p.remap_user,'offset':p.offset,'size':p.size}],'ENGINE_EFFECT_UNCONFIRMED')
    elif kind=='directories':
        from .local_host_apply import owned_directory
        evidence=[]
        for target in (p.data_root,p.exec_root):
            evidence.append(owned_directory(target,plan_id=value['plan_id'],operation={'kind':'engine-directory','path':target},owner_uid=0,mode=0o711,create=False))
        return {'identity':[0,0],'observed_sha256':digest(evidence)}
    elif kind=='config':identity=_file(a['config_path'],canonical(a['config']))
    elif kind=='validate':
        identity=_file(a['config_path'],canonical(a['config']))
        run_fixed(['/usr/bin/dockerd','--validate','--config-file',a['config_path']])
    elif kind=='unit':identity=_file(a['unit_path'],a['service'].encode())
    elif kind in ('reload','enable','start'):
        _file(a['unit_path'],a['service'].encode());_file(a['config_path'],canonical(a['config']))
        unit=_unit_state(a['unit']);require(unit['FragmentPath']==a['unit_path'] and unit['DropInPaths']=='','ENGINE_UNIT_FOREIGN')
        if kind in ('enable','start'):require(unit['UnitFileState']=='enabled','ENGINE_UNIT_NOT_ENABLED')
        if kind=='start':
            require(unit['ActiveState']=='active' and unit['MainPID'].isascii() and unit['MainPID'].isdecimal()
                    and int(unit['MainPID'])>1 and unit['ControlGroup']=='/system.slice/'+a['unit'],'ENGINE_START_UNCONFIRMED')
            from .local_host_observe import command
            node=canonical_node(p.socket,directory=False)
            require(node.st_uid==0 and not node.st_mode&0o002,'ENGINE_SOCKET_OWNER')
            p.verify_engine({'version':command(p.docker_argv(['version','--format','{{.Server.Version}}'])),
                'docker_root':command(p.docker_argv(['info','--format','{{.DockerRootDir}}'])),
                'security_options':json.loads(command(p.docker_argv(['info','--format','{{json .SecurityOptions}}']))),
                'socket_identity':[node.st_dev,node.st_ino]})
    else:require(False,'ENGINE_OPERATION')
    return {'identity':identity,'observed_sha256':digest({'kind':kind,'plan_id':value['plan_id']})}


def _verify_plan(value):
    require(type(value) is dict and set(value)=={'version','profile','receipt_root','account','artifacts','observed','operations','plan_id'},'ENGINE_PLAN')
    expected=plan(value['profile'],value['observed'],receipt_root=value['receipt_root'],
                  account_uid=value['account']['uid'],account_gid=value['account']['gid'])
    require(value==expected,'ENGINE_PLAN_CHANGED')


def _socket_parent_guard(value):
    from .local_engine_observe import socket_parent
    require(socket_parent(LocalHostProfile.parse(value['profile']))==value['observed']['socket_parent'],
            'ENGINE_SOCKET_PARENT_CHANGED')


def _guard(value,receipt=None):
    """Re-observe the global boundary; only receipt-proven owned effects exempt."""
    from .local_engine_observe import inspect_exclusive
    observed=inspect_exclusive(value['profile'],owned=None if receipt is None else value)
    require(observed.get('complete') is True and not observed['blockers'],'ENGINE_FOREIGN_FOOTPRINT')
    require(observed['units']==value['observed']['units'],'ENGINE_SYSTEM_UNITS_CHANGED')
    require(observed['socket_parent']==value['observed']['socket_parent'],'ENGINE_SOCKET_PARENT_CHANGED')
    _socket_parent_guard(value)
    require(observed['tools']==value['observed']['tools'],'ENGINE_TOOLS_CHANGED')
    current=_accounts_guard(value)
    p=LocalHostProfile.parse(value['profile'])
    for kind,index,rows in [('group',0,current['group']),('account',1,current['passwd'])]:
        present=any(r['name']==p.remap_user for r in rows)
        require(not present or receipt is not None and receipt.state(index)['state']!='not-started','ENGINE_UNOWNED_ACCOUNT')
    for kind,index in [('subuid',2),('subgid',3)]:
        present=any(r['user']==p.remap_user for r in subordinate(read_text('/etc/'+kind)))
        require(not present or receipt is not None and receipt.state(index)['state']!='not-started','ENGINE_UNOWNED_RANGE')
    return observed


def apply(value):
    """Run only this explicit plan; caller must have installation authority."""
    _verify_plan(value);require(os.geteuid()==0,'ENGINE_ROOT_REQUIRED')
    from .local_host_apply import owned_directory
    root=Path(value['receipt_root']);resume=os.path.lexists(root)
    if not resume:_guard(value)
    owned_directory(root,plan_id=value['plan_id'],operation='engine-receipt-root',owner_uid=0,mode=0o700,create=not resume)
    with PreparationReceipt(root,value,owner_uid=0) as receipt:
        fcntl.flock(receipt.fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        for index,operation in enumerate(value['operations']):
            _guard(value,receipt)
            state=receipt.state(index);kind=operation['kind']
            if state['state']=='not-started':
                require(receipt.intent(index),'ENGINE_INTENT_UNCERTAIN')
                _effect(value,kind)
            # A tool timeout is not retried here or on later apply. Observation
            # may confirm its exact result, otherwise the owner stays unknown.
            if kind=='start':
                deadline=time.monotonic()+60
                while True:
                    status=_unit_state(value['artifacts']['unit'])
                    require(status['FragmentPath']==value['artifacts']['unit_path'],'ENGINE_UNIT_FOREIGN')
                    if status['ActiveState']=='active':break
                    require(status['ActiveState'] in ('inactive','activating') and time.monotonic()<deadline,'ENGINE_START_UNCONFIRMED')
                    time.sleep(.1)
            observed=_observe_step(value,kind)
            if state['state']=='confirmed':require(observed==state['evidence'],'ENGINE_CONFIRMED_DRIFT')
            else:receipt.confirm(index,observed)
        _guard(value,receipt);_observe_step(value,'start')
        receipt._guard()
        result={'version':1,'plan_id':value['plan_id'],'receipt_root':str(root),
                'receipt_identity':list(receipt.identity),'status':'owned-engine-ready',
                'profile':value['artifacts']['admission_profile']}
        receipt._append('result.json',result)
        return result
