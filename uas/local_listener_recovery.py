"""Owned-v3 volatile listener layout recovery; never repair durable Room data.

The caller retains the installation lock and validates stopped container/Hub and
exact volume ownership before entry. This module creates no listener or process.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid

from . import native_qualification_backend as native
from .local_host_profile import canonical, digest, require
from .local_xfs_storage import boot_id

MANIFEST='listener-recovery.json'
PREFIX='listener-recovery-'
LIMIT=65536


def _read(fd,name):
    try:child=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
    except FileNotFoundError:return None
    try:
        node=os.fstat(child)
        require(stat.S_ISREG(node.st_mode) and node.st_uid==node.st_gid==0
                and stat.S_IMODE(node.st_mode)==0o600 and node.st_nlink==1
                and 0<node.st_size<=LIMIT,'LISTENER_RECORD_OWNER')
        raw=os.read(child,LIMIT+1);value=json.loads(raw)
        require(canonical(value)==raw,'LISTENER_RECORD_ENCODING')
        return value
    finally:os.close(child)


def _append(fd,name,value):
    prior=_read(fd,name)
    if prior is not None:
        require(prior==value,'LISTENER_RECORD_CONFLICT');return False
    raw=canonical(value);require(len(raw)<=LIMIT,'LISTENER_RECORD_BOUND')
    child=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=fd)
    try:
        require(os.write(child,raw)==len(raw),'LISTENER_RECORD_INCOMPLETE')
        os.fsync(child)
    finally:os.close(child)
    os.fsync(fd);return True


def _dir(path,uid,gid,mode):
    path=Path(path);node=path.lstat()
    require(path.resolve()==path and stat.S_ISDIR(node.st_mode)
            and (node.st_uid,node.st_gid)==(uid,gid) and stat.S_IMODE(node.st_mode)==mode,
            'LISTENER_DIRECTORY_OWNER')
    return [node.st_dev,node.st_ino]


def _label(path,level):
    value=native.command('stat','-c','%C',str(path)).strip()
    require(type(value) is str and len(value)<=256 and
            re.fullmatch(r'[A-Za-z0-9_]+:object_r:container_file_t:'+re.escape(level),value),
            'LISTENER_DIRECTORY_LABEL')
    return value


def _selection(backend,state):
    profile=backend.profile
    require(profile.native_document['version']==3,'LISTENER_V3_REQUIRED')
    profile.require_host_unchanged();backend._binding(state)
    require(os.geteuid()==0,'LISTENER_ROOT_REQUIRED')
    layout=backend.layout(state);parent=layout['supervisor'].parent
    root=backend.endpoints/state['instance_id'];owners=profile.owners
    native_id=_dir(parent,0,0,0o711)
    stable=profile.storage_identity(parent)
    require(stable==[0,native_id[1]],'LISTENER_DURABLE_FILESYSTEM')
    volatile={key:{'path':str(layout[key]),'uid':owners['supervisor'],
        'gid':owners['gate'] if key=='gate' else owners['hub'] if key=='control' else owners['runtime'],
        'mode':0o710} for key in ('peer','control','git','gate') if key in layout}
    require(set(volatile)==({'peer','control'}|({'git'} if profile.git_manifest is not None else set())|
                           ({'gate'} if profile.gate_manifest is not None else set())), 'LISTENER_LAYOUT_SELECTION')
    require(all(Path(value['path'])==root/key for key,value in volatile.items()),'LISTENER_LAYOUT_PATH')
    durable={}
    for key in ('supervisor','broker','hub','git-broker'):
        if key not in layout:continue
        owner=owners['broker'] if key in ('broker','git-broker') else owners['supervisor']
        group=owners['hub'] if key=='hub' else owner
        mode=0o2770 if key=='hub' else 0o700
        actual=_dir(layout[key],owner,group,mode)
        identity=profile.storage_identity(layout[key])
        require(identity==[0,actual[1]],'LISTENER_DURABLE_FILESYSTEM')
        durable[key]={'path':str(layout[key]),'identity':identity,'uid':owner,'gid':group,'mode':mode}
    gate=None
    if profile.gate_manifest is not None:
        from .native_gate_resources import paths
        selected=paths(profile.gate_plan,state);gate={}
        for key in ('scratch_root','journal_root','launch_journal_root'):
            name=selected[key];mode=0o711 if key=='scratch_root' else 0o700
            actual=_dir(name,owners['supervisor'],owners['supervisor'],mode)
            identity=profile.storage_identity(name)
            require(identity==[0,actual[1]] and native.project_attributes(name)==(profile.project_id,True),
                    'LISTENER_GATE_DURABLE_PROOF')
            label=native.command('stat','-c','%C',str(name)).strip()
            require(type(label) is str and 0<len(label)<=256,'LISTENER_GATE_LABEL')
            if key=='scratch_root':_label(name,backend.level)
            gate[key]={'path':str(name),'identity':identity,'label':label}
    return parent,root,{'binding':backend._endpoint_record(state),'native_identity':stable,
                       'volatile':volatile,'durable':durable,'gate':gate}


def _gate_record(backend,state,description):
    gate=description['gate']
    if gate is None:return None
    return {'version':1,'instance':state['instance_id'],'profile_digest':backend.profile.digest,
        'paths':{key:{'path':entry['path'],'identity':native.directory_identity(entry['path'])}
                 for key,entry in gate.items()}}


def _git_expected(backend):
    if backend.profile.git_manifest is None:return None
    from .forge import ForgeBinding
    from .git_runtime import compile_git_config
    room=backend.profile.git_plan.room
    binding=ForgeBinding(room['id'],room['project']['id'],room['project']['repository'])
    return {'config':compile_git_config(binding),'commondir':b'/opt/uas/git-views/primary/common\n'}


def _observe(backend,state,root,description):
    identity=_dir(root,0,0,0o711);fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        require(_read(fd,'owner.json')=={**description['binding'],'identity':identity},'LISTENER_OWNER_BINDING')
        gate=_gate_record(backend,state,description)
        if gate is not None:require(_read(fd,'gate-scratch.json')==gate,'LISTENER_GATE_BINDING')
    finally:os.close(fd)
    paths={}
    for key,value in description['volatile'].items():
        paths[key]={'identity':_dir(value['path'],value['uid'],value['gid'],value['mode']),
                    'label':_label(value['path'],backend.level)}
    git={};expected=_git_expected(backend)
    if expected is not None:
        offset=backend.profile.host_profile.offset
        for name in ('git-views','git-views/primary','git-views/primary/gitdir','git-views/primary/common','git-fixed','git-workspace'):
            git[name]={'identity':_dir(root/name,offset,offset,0o755),'label':_label(root/name,backend.level)}
        for name,raw in expected.items():
            file=root/'git-fixed'/name;fd=os.open(file,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
            try:
                node=os.fstat(fd)
                require(stat.S_ISREG(node.st_mode) and (node.st_uid,node.st_gid)==(offset,offset)
                        and stat.S_IMODE(node.st_mode)==0o444 and node.st_nlink==1 and node.st_size==len(raw)
                        and os.read(fd,len(raw)+1)==raw,'LISTENER_GIT_OVERLAY')
                git['git-fixed/'+name]={'identity':[node.st_dev,node.st_ino],'sha256':hashlib.sha256(raw).hexdigest()}
            finally:os.close(fd)
    return {'identity':identity,'paths':paths,'git':git}


def _proof_shape(backend,description,value):
    require(type(value) is dict and set(value)=={'identity','paths','git'}
            and type(value['paths']) is dict and set(value['paths'])==set(description['volatile'])
            and type(value['git']) is dict,'LISTENER_PROOF_SHAPE')
    def identity(row):
        require(type(row) is list and len(row)==2 and all(type(n) is int and n>=0 for n in row)
                and row[1]>0,'LISTENER_PROOF_IDENTITY')
    identity(value['identity'])
    def directory(row):
        require(type(row) is dict and set(row)=={'identity','label'},'LISTENER_PROOF_SHAPE')
        identity(row['identity'])
        require(type(row['label']) is str and len(row['label'])<=256 and
                re.fullmatch(r'[A-Za-z0-9_]+:object_r:container_file_t:'+re.escape(backend.level),row['label']),
                'LISTENER_PROOF_LABEL')
    for row in value['paths'].values():directory(row)
    expected=_git_expected(backend)
    dirs={'git-views','git-views/primary','git-views/primary/gitdir','git-views/primary/common','git-fixed','git-workspace'}
    require(set(value['git'])==(dirs|{'git-fixed/'+name for name in expected} if expected is not None else set()),
            'LISTENER_PROOF_GIT')
    if expected is not None:
        for name in dirs:directory(value['git'][name])
        for name,raw in expected.items():
            row=value['git']['git-fixed/'+name]
            require(type(row) is dict and set(row)=={'identity','sha256'}
                    and row['sha256']==hashlib.sha256(raw).hexdigest(),'LISTENER_PROOF_GIT')
            identity(row['identity'])


def _open_native(parent,description,profile):
    fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        node=os.fstat(fd);named=parent.lstat()
        require(profile.storage_identity(parent)==description['native_identity']
                and (node.st_dev,node.st_ino)==(named.st_dev,named.st_ino),'LISTENER_DURABLE_CHANGED')
        require(stat.S_ISDIR(node.st_mode) and node.st_uid==node.st_gid==0
                and stat.S_IMODE(node.st_mode)==0o711 and [0,node.st_ino]==description['native_identity'],
                'LISTENER_DURABLE_CHANGED')
        return fd
    except BaseException:os.close(fd);raise


def record_layout(backend,state):
    if backend.profile.native_document['version']!=3:return
    parent,root,description=_selection(backend,state)
    proof=_observe(backend,state,root,description)
    value={'version':1,'boot_id':boot_id(),'description':description,'initial':proof}
    fd=_open_native(parent,description,backend.profile)
    try:_append(fd,MANIFEST,value)
    finally:os.close(fd)


def _history(fd,binding):
    result={};count=0
    with os.scandir(fd) as entries:
        for entry in entries:
            count+=1;require(count<=4096,'LISTENER_HISTORY_BOUND')
            if not entry.name.startswith(PREFIX):continue
            match=re.fullmatch(re.escape(PREFIX)+r'([0-9a-f-]{36})\.(intent|confirmed)\.json',entry.name)
            require(match is not None,'LISTENER_HISTORY_NAME')
            generation,kind=match.groups();require(str(uuid.UUID(generation))==generation,'LISTENER_HISTORY_NAME')
            result.setdefault(generation,{})[kind]=_read(fd,entry.name)
    require(len(result)<=128,'LISTENER_HISTORY_BOUND')
    for generation,row in result.items():
        expected={'binding':binding,'boot_id':generation}
        require(row.get('intent')==expected,'LISTENER_HISTORY_SCOPE')
        if 'confirmed' in row:
            require(type(row['confirmed']) is dict and set(row['confirmed'])=={'binding','boot_id','layout'}
                    and row['confirmed']['binding']==binding and row['confirmed']['boot_id']==generation,
                    'LISTENER_HISTORY_SCOPE')
    return result


def recover_layout(backend,state):
    parent,root,description=_selection(backend,state)
    fd=_open_native(parent,description,backend.profile)
    try:
        manifest=_read(fd,MANIFEST)
        require(type(manifest) is dict and set(manifest)=={'version','boot_id','description','initial'}
                and type(manifest['version']) is int and manifest['version']==1 and manifest['description']==description
                and type(manifest['boot_id']) is str and str(uuid.UUID(manifest['boot_id']))==manifest['boot_id'],
                'LISTENER_RECOVERY_MANIFEST')
        _proof_shape(backend,description,manifest['initial'])
        binding=digest(manifest);generation=boot_id();history=_history(fd,binding);prior=history.get(generation)
        for row in history.values():
            if 'confirmed' in row:_proof_shape(backend,description,row['confirmed']['layout'])
        if os.path.lexists(root):
            require(prior is None or 'confirmed' in prior,'LISTENER_RECOVERY_UNKNOWN')
            observed=_observe(backend,state,root,description)
            known=[manifest['initial']]+[row['confirmed']['layout'] for row in history.values() if 'confirmed' in row]
            require(observed in known,'LISTENER_LAYOUT_CHANGED')
            if prior is not None:require(observed==prior['confirmed']['layout'],'LISTENER_LAYOUT_CHANGED')
            return False
        require(generation!=manifest['boot_id'],'LISTENER_SAME_BOOT_LOSS')
        require(prior is None,'LISTENER_RECOVERY_UNKNOWN')
        require(len(history)<128,'LISTENER_HISTORY_BOUND')
        # The endpoint parent was independently recovered by host preparation.
        parent_info=backend.endpoints.lstat()
        require(backend.endpoints.resolve()==backend.endpoints and stat.S_ISDIR(parent_info.st_mode)
                and parent_info.st_uid==parent_info.st_gid==0 and not parent_info.st_mode&0o022,
                'LISTENER_ENDPOINT_PARENT')
        step=PREFIX+generation
        require(_append(fd,step+'.intent.json',{'binding':binding,'boot_id':generation}),
                'LISTENER_RECOVERY_UNKNOWN')
        root.mkdir(mode=0o711);os.chown(root,0,0);os.chmod(root,0o711)
        for value in description['volatile'].values():
            path=Path(value['path']);path.mkdir(mode=value['mode'])
            os.chown(path,value['uid'],value['gid']);os.chmod(path,value['mode'])
            native.command('chcon','-t','container_file_t','-l',backend.level,str(path))
        if backend.profile.git_manifest is not None:
            from .native_git_resources import prepare_views
            prepare_views(backend.profile.git_plan,state)
            for name in ('git-views','git-fixed','git-workspace'):
                native.command('chcon','-R','-t','container_file_t','-l',backend.level,str(root/name))
        current_parent,current_root,current=_selection(backend,state)
        require(current_parent==parent and current_root==root and current==description,'LISTENER_DURABLE_CHANGED')
        newfd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            gate=_gate_record(backend,state,description)
            if gate is not None:_append(newfd,'gate-scratch.json',gate)
            _append(newfd,'owner.json',{**description['binding'],'identity':native.directory_identity(root)})
        finally:os.close(newfd)
        proof=_observe(backend,state,root,description)
        held=os.fstat(fd);named=parent.lstat()
        require((held.st_dev,held.st_ino)==(named.st_dev,named.st_ino),'LISTENER_DURABLE_CHANGED')
        _append(fd,step+'.confirmed.json',{'binding':binding,'boot_id':generation,'layout':proof})
        return True
    finally:os.close(fd)
