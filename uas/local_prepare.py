"""Read-only prepared-host scaffold; writes new metadata, never provisions host.

Reports are selected build evidence, not an Engine or isolation observation.
Only dev/inode values are observed here; quota/MCS/network remain explicit
operator declarations that native admission must independently verify.
"""
import argparse
from copy import deepcopy
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import re
import stat

from .config import load
from .local_installation import canonical, document, reference
from .local_native import LOCAL_HUB_COMMAND, LocalNativeProfile, validate_document, owned_xfs_selection
from .native_image_package import payload, envelope

MAX_BYTES=1024*1024


def require(ok,message):
    if not ok:raise ValueError(message)


def read_file(filename):
    path=Path(filename)
    require(path.is_absolute() and path.resolve()==path,'canonical absolute input path required')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink==1
                and before.st_uid in (0,os.geteuid()) and not before.st_mode&0o022
                and 0<before.st_size<=MAX_BYTES,'bounded owned input required')
        with os.fdopen(fd,'rb',closefd=False) as source:raw=source.read(MAX_BYTES+1)
        after=os.fstat(fd)
        keys=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')
        require(tuple(getattr(before,k) for k in keys)==tuple(getattr(after,k) for k in keys),'input changed during read')
        require(len(raw)==before.st_size,'input changed during read')
        return raw
    finally:os.close(fd)


def directory_identity(filename):
    """Held nofollow chain, including ancestors; no fabricated default IDs."""
    selected=Path(filename)
    require(selected.is_absolute() and selected!=Path('/') and '..' not in selected.parts
            and str(selected)==filename,'canonical existing directory required')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in selected.parts[1:]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=child
        info=os.fstat(fd)
        return [info.st_dev,info.st_ino]
    finally:os.close(fd)


def output_parent(path):
    """Hold a trusted nofollow chain; /tmp alone may be root-owned sticky."""
    require(path.is_absolute() and path != Path('/') and '..' not in path.parts,
            'canonical output parent required')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        current=Path('/')
        for part in (None,*path.parts[1:]):
            if part is not None:
                child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                os.close(fd);fd=child;current=current/part
            info=os.fstat(fd)
            sticky_tmp=(current==Path('/tmp') and info.st_uid==0
                        and bool(info.st_mode&stat.S_ISVTX))
            require(info.st_uid in (0,os.geteuid()) and
                    (not info.st_mode&0o022 or sticky_tmp),
                    'unsafe output parent ownership or permissions')
        return fd
    except BaseException:
        os.close(fd);raise


def write_output(output,files):
    parent=output_parent(output.parent)
    directory=None
    try:
        try:os.stat(output.name,dir_fd=parent,follow_symlinks=False)
        except FileNotFoundError:pass
        else:raise ValueError('output must not exist; inspect prior partial result instead of overwriting')
        os.mkdir(output.name,0o700,dir_fd=parent)
        directory=os.open(output.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        identity=os.fstat(directory)
        require(identity.st_uid==os.geteuid() and not identity.st_mode&0o077,
                'new output ownership or permissions changed')
        for name,value in files.items():
            fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
            with os.fdopen(fd,'wb') as target:
                target.write(value);target.flush();os.fsync(target.fileno())
        os.fsync(directory);os.fsync(parent)
        # Reopen the complete pathname to detect replacement of any ancestor.
        observed=directory_identity(str(output))
        require(observed==[identity.st_dev,identity.st_ino],
                'output pathname changed; inspect retained partial result, do not retry')
    finally:
        if directory is not None:os.close(directory)
        os.close(parent)


def verified_output(directory,revision,*,hub):
    directory=Path(directory)
    report=document(read_file(directory/'report.json'))
    require(type(report.get('version')) is int and report['version']==1
            and report.get('source_revision')==revision and report.get('status')=='passed'
            and report.get('stage')=='complete' and report.get('build_execution')=='completed'
            and report.get('container_cleanup')=='complete',
            'passed exact-revision build/readback report required')
    image_id=report.get('image_id')
    require(type(image_id) is str and re.fullmatch('sha256:[0-9a-f]{64}',image_id),'exact observed image ID required')
    payloads={}
    def selected_payload(name):
        raw=read_file(directory/('artifacts/'+name))
        if not hub:
            require(report.get('retained_artifacts',{}).get(name)=={'sha256':hashlib.sha256(raw).hexdigest(),'size':len(raw)},
                    'report/artifact byte binding mismatch')
        return document(raw)
    if hub:
        value=selected_payload('hub-payload.json')
        require(set(value)=={'version','profile','python_version','artifacts'}
                and type(value['version']) is int and value['version']==1
                and value['profile']=='fixed-hub-v1' and type(value['artifacts']) is dict
                and type(value['python_version']) is str and re.fullmatch(r'3\.11\.[0-9]{1,3}',value['python_version'])
                and value['python_version']==report.get('selection',{}).get('python_version'),
                'exact Hub payload required')
        require(all(type(k) is str and type(v) is str and re.fullmatch('[0-9a-f]{64}',v)
                    for k,v in value['artifacts'].items()),'Hub artifact hashes required')
        from .native_hub_image import source_inventory, BINARIES
        sources=source_inventory(Path(__file__).resolve().parents[1])
        require(set(value['artifacts'])==set(sources)|BINARIES
                and all(value['artifacts'].get(name)==digest for name,digest in sources.items()),
                'Hub source payload must match this exact checked-out implementation')
        local=Path(__file__).with_name('local_hub.py').read_bytes()
        require(value['artifacts'].get('/opt/uas/uas/local_hub.py')==hashlib.sha256(local).hexdigest(),
                'current persistent local Hub payload required; old qualification Hub is not usable')
        require(report.get('hub_payload',{}).get('manifest_sha256')==hashlib.sha256(canonical(value)).hexdigest(),
                'Hub report/payload digest mismatch')
    else:
        for runtime in ('pi','claude'):
            value=selected_payload(runtime+'-payload.json')
            expected=payload(runtime,value.get('artifacts'))
            require(canonical(value)==canonical(expected),'exact native payload required')
            require(report.get('native_payloads',{}).get(runtime,{}).get('manifest_sha256')==hashlib.sha256(canonical(value)).hexdigest(),
                    'native report/payload digest mismatch')
            payloads[runtime]=value
    image= {'image_id':image_id,'image_reference':image_id,**({'entrypoint':LOCAL_HUB_COMMAND[:]} if hub else {})}
    return image,payloads


def assemble(config,settings,workstation,hub,*,observe=directory_identity):
    require(type(settings) is dict and type(settings.get('version')) is int
            and settings['version'] in (1,2,3), 'exact host selections required')
    require(set(settings)==({'version','installation_id','storage_root','endpoints_root','engine_version','mapping','rooms'}
            | ({'host_profile'} if settings['version']>=2 else set())
            | ({'owned_xfs'} if settings['version']==3 else set())), 'exact host selections required')
    require(type(settings['rooms']) is dict and set(settings['rooms'])=={r['id'] for r in config['rooms']},
            'host selections must cover every Project Room exactly')
    native={**deepcopy(settings),'profile':'local-native-v'+str(settings['version']),'rooms':{}}
    raw_observe=observe
    if settings['version']==3:
        from .local_xfs_storage import verify_owned_mount
        selection=owned_xfs_selection(settings['owned_xfs'])
        mounted=verify_owned_mount(selection,Path(settings['storage_root']))
        require(mounted['image_identity']==selection['image_identity'],'owned XFS image identity mismatch')
        def observe_storage(name):
            actual=raw_observe(name)
            require(actual[0]==mounted['identity'][0], 'owned XFS filesystem mismatch')
            return [0,actual[1]]
        observe=observe_storage
    if settings['version']==3:
        require(raw_observe(settings['storage_root'])==mounted['identity'], 'owned XFS root identity mismatch')
    storage_identity=observe(settings['storage_root'])
    raw_observe(settings['endpoints_root'])
    for room in config['rooms']:
        declared=settings['rooms'][room['id']]
        require(type(declared) is dict and set(declared)=={'quota_project_id','mcs_level','subnet','gateway'},
                'exact per-Room quota/MCS/network declarations required')
        paths={**room['project']['roots'],'runtime':room['state_root']+'/runtime'}
        native['rooms'][room['id']]={**deepcopy(declared),'root_identity':storage_identity[:],
            'paths':{key:{'path':name,'identity':observe(name)} for key,name in paths.items()},
            'workstation':deepcopy(workstation),'hub':deepcopy(hub)}
    native=validate_document(native)
    for room in config['rooms']:
        LocalNativeProfile(config,native,room['id'],config['deployment']['state_root'])
    return native


def prepare(project,settings,workstation_output,hub_output,revision,output_directory, *, owned_xfs=None):
    require(type(revision) is str and re.fullmatch('[0-9a-f]{40}',revision),'full selected source revision required')
    project=Path(project);raw=read_file(project);config=load(StringIO(raw.decode('utf-8')))
    selected=document(read_file(settings))
    if owned_xfs is not None:
        require(selected['version']==2,'owned XFS requires version-2 explicit Engine selections')
        selected={**selected,'version':3,'owned_xfs':owned_xfs}
    ws,payloads=verified_output(workstation_output,revision,hub=False)
    hub,unused=verified_output(hub_output,revision,hub=True)
    images={image['id']:image['reference'] for image in config['deployment']['images']}
    require(all(images[room['image']]==ws['image_id'] for room in config['rooms']),
            'Project selected image references must equal observed Workstation config ID '+ws['image_id']+'; update explicit Project selections first')
    native=assemble(config,selected,ws,hub)
    output=Path(output_directory)
    require(output.is_absolute() and output.resolve()==output and output.parent.is_dir(),
            'canonical output with existing parent required')
    require(not os.path.lexists(output),'output must not exist; inspect prior partial result instead of overwriting')
    native_raw=canonical(native)
    ref={'path':str(output/'native.json'),'sha256':hashlib.sha256(native_raw).hexdigest()}
    reference(ref)
    installation={'version':1,'project':{'path':str(project),'sha256':hashlib.sha256(raw).hexdigest()},
                  'native':ref,'manager':None}
    # All validation and observations precede the first write. On write/fsync
    # failure preserve the partial directory for inspection, never auto-retry.
    files={'native.json':native_raw,'native-reference.json':canonical(ref),
           'installation-selection.json':canonical(installation)}
    runtime_refs={}
    for runtime,value in payloads.items():
        raw_envelope=canonical(envelope(value,image_reference=ws['image_id'],image_id=ws['image_id']))
        runtime_refs[runtime]={'path':str(output/(runtime+'.json')),'sha256':hashlib.sha256(raw_envelope).hexdigest()}
        files[runtime+'.json']=raw_envelope
        files[runtime+'-reference.json']=canonical(runtime_refs[runtime])
    handoff={'version':1,'deployment_id':config['deployment']['id'],
             'room_ids':[room['id'] for room in config['rooms']],
             'configuration_sha256':hashlib.sha256(canonical(config)).hexdigest(),
             'project_file_sha256':hashlib.sha256(raw).hexdigest(),'source_revision':revision,
             'workstation_image_id':ws['image_id'],'hub_image_id':hub['image_id'],
             'runtime_manifests':runtime_refs,'host_security':'not-observed'}
    files['handoff.json']=canonical(handoff)
    write_output(output,files)
    return {'status':'prepared-metadata','native':ref,'selection':str(output/'installation-selection.json'),
            'source_revision':revision,'host_security':'not-observed','images':'reports-selected-not-engine-observed'}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('project','settings','workstation-output','hub-output','source-revision','output-directory'):
        parser.add_argument('--'+name,required=True)
    args=parser.parse_args(argv)
    result=prepare(args.project,args.settings,args.workstation_output,args.hub_output,args.source_revision,args.output_directory)
    print(json.dumps(result,sort_keys=True));return 0


if __name__=='__main__':raise SystemExit(main())
