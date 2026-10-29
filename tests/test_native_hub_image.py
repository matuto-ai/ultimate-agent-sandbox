"""Guarded source and mocked orchestration, not a Hub/Docker execution."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
import stat
from unittest.mock import patch

from uas.native_hub_image import dockerfile, source_inventory, validate_payload, COMMAND, BINARIES, MANIFEST

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('hub_image_check',ROOT/'runtime/native/check-hub-image.py')
CHECK = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(CHECK)
SELECTION = json.loads((ROOT/'runtime/native/hub-image-check-selection.json').read_bytes())


class NativeHubImageTests(unittest.TestCase):
    def test_recipe_matches_existing_consumer_without_service_start(self):
        from uas.native_qualification_backend import HUB_COMMAND
        self.assertEqual(COMMAND,HUB_COMMAND)
        recipe=dockerfile(SELECTION)
        for part in ('USER 65531:65531','PYTHONPATH=/opt/uas','COPY uas/*.py /opt/uas/uas/',
                     'python3.11=3.11.2-6+deb12u9','tini=0.19.0-1+b3',
                     'ENTRYPOINT ["/opt/uas/bin/tini"]', 'WORKDIR /'):
            self.assertIn(part,recipe)
        self.assertNotIn('RUN python -m',recipe)
        self.assertNotIn('COPY . ',recipe)
        for change in ({'base_image':'node:latest'}, {'python_version':'3.12.0'},
                       {'tini_package':'1; id'}, {'extra':True}):
            with self.assertRaises(ValueError): dockerfile({**SELECTION,**change})

    def test_source_inventory_is_exact_and_bounded(self):
        values=source_inventory(ROOT)
        self.assertIn('/opt/uas/uas/workstation_service.py',values)
        self.assertEqual(len(values),len(list((ROOT/'uas').glob('*.py'))))
        self.assertEqual(values['/opt/uas/uas/workstation_service.py'],
                         hashlib.sha256((ROOT/'uas/workstation_service.py').read_bytes()).hexdigest())
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(ValueError): source_inventory(Path(folder))

    def value(self,sources):
        return {'version':1,'profile':'fixed-hub-v1','python_version':'3.11.2',
                'artifacts':{**sources,**dict.fromkeys(BINARIES,'a'*64)}}

    def test_payload_requires_exact_revision_sources_and_every_installed_file(self):
        sources={'/opt/uas/uas/__init__.py':'b'*64,'/opt/uas/uas/workstation_service.py':'c'*64}
        value=self.value(sources); seen=[]
        def read(path): seen.append(path); return {'sha256':value['artifacts'][path]}
        self.assertEqual(validate_payload(value,sources,'3.11.2',read)['artifact_count'],4)
        self.assertEqual(set(seen),set(value['artifacts']))
        for change in ({'version':True},{'profile':'other'},{'python_version':'3.11.3'},
                       {'artifacts':{}},{'extra':True}):
            with self.assertRaises(ValueError): validate_payload({**value,**change},sources,'3.11.2',read)
        wrong=copy.deepcopy(value);wrong['artifacts']['/opt/uas/uas/__init__.py']='d'*64
        with self.assertRaises(ValueError): validate_payload(wrong,sources,'3.11.2',read)
        with self.assertRaises(ValueError): validate_payload(value,sources,'3.11.2',lambda p:{'sha256':'f'*64})

    def scenario(self,failure=None,cleanup_failure=False,retain_archive=False):
        image='sha256:'+'b'*64;cid='c'*64;commands=[];owner=None
        sources={'/opt/uas/uas/__init__.py':hashlib.sha256(b'').hexdigest(),
                 '/opt/uas/uas/workstation_service.py':hashlib.sha256(b'').hexdigest()}
        value=self.value(sources)
        with tempfile.TemporaryDirectory() as temporary:
            output=Path(temporary)/'result'
            def command(args,**kw):
                nonlocal owner
                commands.append(args)
                if args[:2]==['git','rev-parse']:return b'd'*40
                if args[:2]==['git','status']:return b''
                if args[:2]==['git','archive']:
                    target=next(x.split('=',1)[1] for x in args if x.startswith('--output='))
                    with tarfile.open(target,'w'): pass
                    return
                if 'build' in args:
                    if failure=='build':raise ValueError('build failed')
                    if failure=='timeout':raise subprocess.TimeoutExpired(args,600)
                    (output/'image-id').write_text(image);return
                if 'image' in args:
                    return json.dumps([{'Id':image,'Os':'linux','Architecture':'amd64','Config':{
                        'User':'0:0' if failure=='image-config' else '65531:65531','Entrypoint':COMMAND[:1],'Cmd':COMMAND[1:],'WorkingDir':'/',
                        'Env':['PYTHONPATH=/opt/uas','PYTHONDONTWRITEBYTECODE=1']}}]).encode()
                if 'create' in args:
                    owner=next(x.split('=',1)[1] for x in args if x.startswith('--name='))
                    if failure=='create':raise TimeoutError('uncertain create')
                    return cid.encode()
                if 'ls' in args:return b'' if failure=='create' else b'{"ID":"owned"}'
                if 'inspect' in args:
                    return json.dumps([{'Id':cid,'Name':'/'+owner,'Image':image,
                        'Config':{'Labels':{'io.uas.image-check':owner.removeprefix('uas-image-check-')}},
                        'State':{'Status':'created','Running':False}}]).encode()
                if 'rm' in args:
                    if cleanup_failure:raise TimeoutError('cleanup failed')
                    return b''
                raise AssertionError(args)
            def read(container,path):
                self.assertEqual(container,cid)
                if failure=='readback':raise ValueError('readback failed')
                return {'data':CHECK.canonical(value)} if path==MANIFEST else {'sha256':value['artifacts'][path]}
            original_write=Path.write_bytes
            def write(path,data):
                if failure=='retain' and path.name=='hub-payload.json':raise OSError('retention failed')
                return original_write(path,data)
            argv=['check-hub','--selection',str(ROOT/'runtime/native/hub-image-check-selection.json'),'--output',str(output)]
            if retain_archive:argv.append('--retain-image-archive')
            def export(image_id,directory,**kwargs):
                self.assertEqual(image_id,image)
                self.assertEqual(kwargs['readback']['image_id'],image)
                self.assertIn('hub_payload',kwargs['readback'])
                self.assertEqual(kwargs['artifact_name'],'hub-image.tar')
                self.assertEqual(kwargs['max_bytes'],1024**3)
                if failure=='archive':raise ValueError('archive failed')
                return {'image_id':image,'archive_sha256':'e'*64}
            with patch.object(CHECK,'export_archive',side_effect=export) as saved, \
                 patch.object(CHECK.sys,'argv',argv),patch.object(CHECK.COMMON,'command',side_effect=command), \
                 patch.object(CHECK.COMMON,'read_file',side_effect=read), \
                 patch.object(CHECK,'source_inventory',return_value=sources), \
                 patch.object(Path,'write_bytes',write),patch('builtins.print'):
                code=CHECK.main()
                self.assertEqual(saved.call_count,1 if retain_archive and failure in (None,'archive') else 0)
            report=json.loads((output/'report.json').read_bytes())
            retained=(output/'artifacts/hub-payload.json').exists()
        self.assertFalse(any('start' in c or 'push' in c or 'run' in c for c in commands))
        self.assertLessEqual(len([c for c in commands if 'build' in c]),1)
        self.assertLessEqual(len([c for c in commands if 'create' in c]),1)
        return code,report,retained

    def test_main_build_identity_readback_retention_and_cleanup(self):
        code,report,retained=self.scenario()
        self.assertEqual(code,0);self.assertTrue(retained)
        self.assertEqual(report['container_cleanup'],'complete')
        self.assertEqual(report['build_execution'],'completed')
        self.assertEqual(report['native_lifecycle'],'not-run')

    def test_main_fails_each_boundary_and_preserves_unknown_build(self):
        for failure in ('build','timeout','image-config','create','readback','retain'):
            with self.subTest(failure=failure):
                code,report,retained=self.scenario(failure)
                self.assertEqual(code,1);self.assertFalse(retained)
                if failure=='timeout':self.assertEqual(report['build_execution'],'unknown-daemon-outcome')
                if failure=='create':self.assertEqual(report['container_cleanup'],'failed')

    def test_cleanup_cannot_mask_primary_failure_or_claim_success(self):
        code,report,_=self.scenario('readback',True)
        self.assertEqual(code,1);self.assertIn('readback failed',report['error'])
        self.assertEqual(report['container_cleanup'],'failed')
        self.assertEqual(self.scenario(cleanup_failure=True)[0],1)

    def producer(self, failure=None):
        spec=importlib.util.spec_from_file_location('hub_prepare',ROOT/'runtime/native/prepare-hub.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        nodes={}
        def add(path,data=b'fixture',*,kind=stat.S_IFREG,uid=0,size=None):
            nodes[path]={'data':data,'kind':kind,'uid':uid,'size':len(data) if size is None else size,'mode':0o644}
        add('/usr/bin/tini');add('/usr/bin/python3.11')
        add('/opt/uas/uas/__init__.py',b'');add('/opt/uas/uas/workstation_service.py')
        if failure=='alias':add('/usr/bin/python3')
        else:add('/usr/bin/python3',kind=stat.S_IFLNK)
        if failure=='symlink':nodes['/opt/uas/uas/workstation_service.py']['kind']=stat.S_IFLNK
        if failure=='owner':nodes['/opt/uas/uas/workstation_service.py']['uid']=1
        if failure=='size':nodes['/opt/uas/uas/workstation_service.py']['size']=262145
        if failure=='missing':del nodes['/opt/uas/uas/workstation_service.py']
        if failure=='binary-size':nodes['/usr/bin/tini']['size']=16*1024*1024+1
        class FakePath:
            def __init__(self,path):self.path=str(path)
            def __str__(self):return self.path
            def __truediv__(self,part):return FakePath(self.path+'/'+part)
            def __lt__(self,other):return self.path<other.path
            def mkdir(self,**kw):pass
            def exists(self):return self.path in nodes
            def is_symlink(self):return self.exists() and nodes[self.path]['kind']==stat.S_IFLNK
            def is_file(self):return self.exists() and nodes[self.path]['kind']==stat.S_IFREG
            def unlink(self):del nodes[self.path]
            def glob(self,pattern):return [FakePath(p) for p in nodes if p.startswith(self.path+'/') and p.endswith('.py')]
            def lstat(self):
                n=nodes[self.path];return SimpleNamespace(st_mode=n['kind']|n['mode'],st_uid=n['uid'],st_size=n['size'])
            def chmod(self,mode):nodes[self.path]['mode']=mode
            def read_bytes(self):return nodes[self.path]['data']
            def write_text(self,data):add(self.path,data.encode())
        def copy(source,target):nodes[str(target)]=dict(nodes[str(source)])
        argv=['prepare-hub','3.11.3' if failure=='version' else '3.11.2']
        with patch.object(module,'Path',FakePath),patch.object(module.shutil,'copyfile',side_effect=copy), \
             patch.object(module.sys,'argv',argv),patch.object(module.sys,'version_info',(3,11,2)):
            module.main()
        return nodes

    def test_build_producer_copies_regular_fixed_entries_and_exact_manifest(self):
        nodes=self.producer()
        value=json.loads(nodes[MANIFEST]['data'])
        self.assertEqual(value['profile'],'fixed-hub-v1')
        self.assertEqual(value['python_version'],'3.11.2')
        self.assertEqual(set(value['artifacts']),BINARIES|{'/opt/uas/uas/__init__.py','/opt/uas/uas/workstation_service.py'})
        for path,digest in value['artifacts'].items():
            self.assertEqual(digest,hashlib.sha256(nodes[path]['data']).hexdigest())
            self.assertEqual(nodes[path]['mode'],0o555 if path in BINARIES else 0o444)
        self.assertEqual(nodes[MANIFEST]['mode'],0o444)
        self.assertEqual(nodes['/usr/bin/python3']['kind'],stat.S_IFREG)

    def test_build_producer_rejects_version_alias_metadata_and_size(self):
        for failure in ('version','alias','symlink','owner','size','missing','binary-size'):
            with self.subTest(failure=failure),self.assertRaises(ValueError):self.producer(failure)

    def test_optional_archive_is_bound_to_verified_hub_and_failure_cleans_container(self):
        code,report,_=self.scenario(retain_archive=True)
        self.assertEqual(code,0);self.assertEqual(report['archive_export'],'complete')
        code,report,_=self.scenario('archive',retain_archive=True)
        self.assertEqual(code,1);self.assertEqual(report['archive_export'],'failed')
        self.assertEqual(report['container_cleanup'],'complete')
        code,report,_=self.scenario('readback',retain_archive=True)
        self.assertEqual(code,1);self.assertEqual(report['archive_export'],'not-started')
