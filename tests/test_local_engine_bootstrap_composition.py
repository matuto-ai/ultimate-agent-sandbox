"""Actual bootstrap/observer/receipt composition with inert host boundaries."""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace as N
import unittest
from unittest.mock import patch
from uas import local_engine_prepare as e, local_engine_observe as o
from uas.local_host_profile import LocalHostProfile,HostProfileError,digest


class EngineWorld:
    def __init__(self,root):
        self.root=root;self.dirs={};self.files={};self.group=False;self.account=False
        self.subuid=False;self.subgid=False;self.enabled=False;self.active=False;self.reload=False
        self.commands=[];self.unknown_start=False
        self.profile=LocalHostProfile('a'*32,'owned',str(root/'engine.sock'),str(root/'data'),str(root/'exec'),'uasowned',500000,65536)
        self.unit='uas-engine-'+'a'*32+'.service';self.unit_path='/etc/systemd/system/'+self.unit
        self.real_stat=os.stat;self.real_fstat=os.fstat;self.real_lstat=os.lstat;self.real_exists=os.path.lexists
    def rooted(self,n):
        fields=list(n);fields[4]=fields[5]=0;return os.stat_result(fields)
    def lstat(self,path,*a,**k):
        if str(path)==self.profile.socket and self.active:return N(st_mode=stat.S_IFSOCK|0o660,st_uid=0,st_gid=0,st_dev=1,st_ino=999)
        return self.rooted(self.real_lstat(path,*a,**k))
    def exists(self,path):return str(path) in self.files or str(path)==self.profile.socket and self.active or self.real_exists(path)
    def tool(self,path):return {'path':path,'identity':[1,2],'sha256':'a'*64}
    def text(self,path):
        path=str(path)
        if path=='/proc/sys/net/ipv4/ip_forward':return '1'
        if path=='/etc/group':return 'uasowned:x:982:' if self.group else ''
        if path=='/etc/passwd':return 'uasowned:x:981:982::/nonexistent:/usr/sbin/nologin' if self.account else ''
        if path in ('/etc/subuid','/etc/subgid'):
            return 'uasowned:500000:65536' if getattr(self,path.split('/')[-1]) else ''
        raise AssertionError(path)
    def file(self,path,raw,*,create=False):
        path=str(path)
        if create:
            if path in self.files:raise FileExistsError(path)
            self.files[path]=(raw,[1,len(self.files)+40])
        if path not in self.files:raise FileNotFoundError(path)
        if self.files[path][0]!=raw:raise HostProfileError('ENGINE_FILE_OWNERSHIP')
        return self.files[path][1]
    def directory(self,path,*,plan_id,operation,owner_uid,mode,create,**kw):
        path=Path(path);key=str(path);binding=(plan_id,operation,mode)
        if create:
            path.mkdir(mode=mode);path.chmod(mode);self.dirs[key]=binding
        if self.dirs.get(key)!=binding:raise HostProfileError('FOREIGN_DIRECTORY')
        n=self.real_stat(path)
        return {'identity':[n.st_dev,n.st_ino],'observed_sha256':digest(binding)}
    def footprints(self,profile):
        rows=[{'path':path} for path in (profile.data_root,profile.exec_root) if self.real_exists(path)]
        if self.active:rows.append({'path':profile.socket})
        return rows
    def processes(self):
        if not self.active:return []
        result=[]
        for pid,exe,args in [(100,'/usr/bin/dockerd',['/usr/bin/dockerd','--config-file='+str(self.root/'receipt'/'daemon.json')]),
                             (101,'/usr/bin/containerd',['containerd','--config',self.profile.exec_root+'/containerd/containerd.toml'])]:
            flags={'--config-file':args[1].split('=',1)[1]} if pid==100 else {'--config':args[2]}
            result.append({'pid':pid,'exe':exe,'arguments':flags,'arguments_sha256':hashlib.sha256('\0'.join(args).encode()).hexdigest(),
                'uid':[0]*4,'cgroup':'0::/system.slice/'+self.unit,'netns':'net:[1]'})
        return result
    def command(self,args,**kw):
        self.commands.append(args)
        if args[0]=='/usr/sbin/groupadd':self.group=True;return ''
        if args[0]=='/usr/sbin/useradd':self.account=True;return ''
        if args[0]=='/usr/sbin/usermod':setattr(self,args[1][6:-1],True);return ''
        if args[0]=='/usr/bin/dockerd':return 'Docker version 29.8.2, build abc123' if '--version' in args else ''
        if args[0]=='/usr/bin/docker':
            if 'version' in args:return '29.8.2'
            if '{{.DockerRootDir}}' in args:return self.profile.docker_root
            return json.dumps(['name=seccomp,profile=builtin','name=selinux','name=userns'])
        if args[0]=='/usr/bin/systemctl':
            if 'show' in args:
                if self.unit in args:
                    return '\n'.join(['FragmentPath='+self.unit_path,'ActiveState='+('active' if self.active else 'inactive'),
                        'UnitFileState='+('enabled' if self.enabled else 'disabled'),'MainPID='+('100' if self.active else '0'),
                        'ControlGroup=/system.slice/'+self.unit,'DropInPaths='])
                return 'LoadState=not-found\nActiveState=inactive\nUnitFileState=\nFragmentPath='
            if 'daemon-reload' in args:self.reload=True
            elif 'enable' in args:self.enabled=True
            elif 'start' in args:
                self.active=True
                if self.unknown_start:raise OSError('lost start acknowledgement')
            return ''
        if args[0].endswith('nft'):return '{"nftables":[]}'
        if args[0].endswith('tables-save'):return '*filter\n:INPUT ACCEPT [0:0]\nCOMMIT'
        raise AssertionError(args)
    def installed(self):
        stack=ExitStack()
        for module in (e,o):
            stack.enter_context(patch.object(module,'read_text',side_effect=self.text))
            stack.enter_context(patch.object(module,'run_fixed',side_effect=self.command))
        stack.enter_context(patch('uas.local_host_observe.command',side_effect=self.command))
        stack.enter_context(patch.object(e,'_file',side_effect=self.file))
        stack.enter_context(patch('uas.local_host_apply.owned_directory',side_effect=self.directory))
        stack.enter_context(patch.object(e,'canonical_node',side_effect=lambda path,**kw:self.lstat(path)))
        stack.enter_context(patch.object(o,'socket_parent',side_effect=lambda profile:{'path':str(Path(profile.socket).parent),'identity':[self.real_stat(self.root).st_dev,self.real_stat(self.root).st_ino]}))
        stack.enter_context(patch.object(o,'_tool',side_effect=self.tool))
        stack.enter_context(patch.object(o,'_processes',side_effect=self.processes))
        stack.enter_context(patch.object(o,'_footprints',side_effect=self.footprints))
        stack.enter_context(patch.object(o,'_entries',return_value=[]))
        stack.enter_context(patch.object(os,'readlink',return_value='net:[1]'))
        stack.enter_context(patch.object(os,'geteuid',return_value=0))
        stack.enter_context(patch.object(os,'stat',side_effect=lambda *a,**k:self.rooted(self.real_stat(*a,**k))))
        stack.enter_context(patch.object(os,'fstat',side_effect=lambda *a,**k:self.rooted(self.real_fstat(*a,**k))))
        stack.enter_context(patch.object(os,'lstat',side_effect=self.lstat))
        stack.enter_context(patch.object(os.path,'lexists',side_effect=self.exists))
        return stack


class BootstrapCompositionTests(unittest.TestCase):
    def world(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);return EngineWorld(Path(temp.name))
    def test_unsafe_missing_or_replaced_socket_parent_refuses_before_any_effect(self):
        for failure in (HostProfileError('HOST_PATH_ANCESTOR'),FileNotFoundError(),{'path':'/different','identity':[1,999]}):
            w=self.world()
            with self.subTest(failure=str(failure)),w.installed():
                plan=e.plan(w.profile.document(),o.inspect_exclusive(w.profile.document()),receipt_root=str(w.root/'receipt'),account_uid=981,account_gid=982)
                boundary=patch.object(o,'socket_parent',**({'side_effect':failure} if isinstance(failure,Exception) else {'return_value':failure}))
                with boundary,self.assertRaises((HostProfileError,FileNotFoundError)):e.apply(plan)
            self.assertFalse(w.group);self.assertFalse(w.account);self.assertEqual(sum('start' in args for args in w.commands),0)

    def test_parent_substitution_immediately_before_start_refuses_issuance(self):
        w=self.world()
        with w.installed():
            plan=e.plan(w.profile.document(),o.inspect_exclusive(w.profile.document()),receipt_root=str(w.root/'receipt'),account_uid=981,account_gid=982)
            with patch.object(o,'socket_parent',return_value={'path':str(w.root),'identity':[1,999]}),self.assertRaisesRegex(HostProfileError,'PARENT_CHANGED'):
                e._effect(plan,'start')
        self.assertEqual(sum('start' in args for args in w.commands),0)

    def test_actual_apply_observer_and_receipts_complete_then_reconcile(self):
        w=self.world()
        with w.installed():
            observed=o.inspect_exclusive(w.profile.document());self.assertEqual(observed['blockers'],[])
            plan=e.plan(w.profile.document(),observed,receipt_root=str(w.root/'receipt'),account_uid=981,account_gid=982)
            result=e.apply(plan);again=e.apply(plan)
        self.assertEqual(result,again)
        self.assertEqual(sum('start' in args for args in w.commands),1)
        self.assertTrue((w.root/'receipt'/'result.json').is_file())
        self.assertTrue(all((w.root/'receipt'/f'{i}.confirmed.json').is_file() for i in range(len(plan['operations']))))
    def test_uncertain_start_observed_without_second_start_command(self):
        w=self.world();w.unknown_start=True
        with w.installed():
            observed=o.inspect_exclusive(w.profile.document())
            plan=e.plan(w.profile.document(),observed,receipt_root=str(w.root/'receipt'),account_uid=981,account_gid=982)
            with self.assertRaises(OSError):e.apply(plan)
            w.unknown_start=False;result=e.apply(plan)
        self.assertEqual(result['status'],'owned-engine-ready')
        self.assertEqual(sum('start' in args for args in w.commands),1)
    def test_foreign_daemon_after_start_blocks_result_receipt(self):
        w=self.world();actual=w.processes
        def foreign():
            rows=actual()
            if rows:rows.append({**rows[-1],'pid':102,'cgroup':'0::/system.slice/foreign.service'})
            return rows
        with w.installed():
            observed=o.inspect_exclusive(w.profile.document())
            plan=e.plan(w.profile.document(),observed,receipt_root=str(w.root/'receipt'),account_uid=981,account_gid=982)
            with patch.object(o,'_processes',side_effect=foreign),self.assertRaisesRegex(HostProfileError,'FOREIGN_FOOTPRINT'):e.apply(plan)
        self.assertFalse((w.root/'receipt'/'result.json').exists())
    def test_changed_owned_unit_on_resume_is_not_adopted(self):
        w=self.world();w.unknown_start=True
        with w.installed():
            observed=o.inspect_exclusive(w.profile.document())
            plan=e.plan(w.profile.document(),observed,receipt_root=str(w.root/'receipt'),account_uid=981,account_gid=982)
            with self.assertRaises(OSError):e.apply(plan)
            raw,identity=w.files[w.unit_path];w.files[w.unit_path]=(raw+b'changed',identity)
            with self.assertRaisesRegex(HostProfileError,'FOREIGN_FOOTPRINT'):e.apply(plan)
        self.assertEqual(sum('start' in args for args in w.commands),1)
    def test_foreign_dropin_refuses_observed_service(self):
        w=self.world();original=w.command
        def command(args,**kw):
            raw=original(args,**kw)
            return raw.replace('DropInPaths=','DropInPaths=/etc/systemd/system/foreign.conf') if w.unit in args and 'show' in args else raw
        w.command=command
        with w.installed():
            observed=o.inspect_exclusive(w.profile.document())
            plan=e.plan(w.profile.document(),observed,receipt_root=str(w.root/'receipt'),account_uid=981,account_gid=982)
            with self.assertRaisesRegex(HostProfileError,'ENGINE_UNIT_FOREIGN'):e.apply(plan)
        self.assertEqual(sum('start' in args for args in w.commands),0)
    def test_nonhost_network_namespace_refuses_owned_processes(self):
        w=self.world()
        with w.installed():
            observed=o.inspect_exclusive(w.profile.document())
            plan=e.plan(w.profile.document(),observed,receipt_root=str(w.root/'receipt'),account_uid=981,account_gid=982)
            with patch.object(os,'readlink',return_value='net:[other]'),self.assertRaisesRegex(HostProfileError,'FOREIGN_FOOTPRINT'):e.apply(plan)
        self.assertFalse((w.root/'receipt'/'result.json').exists())
