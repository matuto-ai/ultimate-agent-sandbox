"""Fixed Gate selection and Supervisor-owned listener; native boundaries controlled."""
from contextlib import ExitStack
from copy import deepcopy
from pathlib import Path
import socket
import stat
import tempfile
from types import SimpleNamespace as N
import unittest
from unittest.mock import Mock, patch

import test_native_qualification as plan_fixture
import test_native_git_qualification as git_fixture
from uas.artifact_protocol import ArtifactError
from uas.native_qualification import QualificationError, execute
from uas.native_session import _gate_listener


class NativeGateSessionTests(unittest.TestCase):
    def selection(self):
        f=plan_fixture.NativeQualificationTests();f.setUp()
        for name in ('git','git_broker','gate'):
            f.selection[name+'_manifest']={'path':'/installation/'+name+'.json','sha256':'f'*64}
        return f

    def test_gate_selection_requires_both_git_refs_and_exact_manifest_reference(self):
        f=self.selection();self.assertIn('gate_manifest',f.plan().installation)
        for name in ('git','git_broker'):
            bad=self.selection();del bad.selection[name+'_manifest']
            with self.assertRaisesRegex(QualificationError,'INVALID_NATIVE_SELECTION'):bad.plan()
        for value in ({'path':'relative','sha256':'f'*64}, {'path':'/installation/gate.json','sha256':'bad'},
                      {'path':'/installation/gate.json','sha256':'f'*64,'trusted':True}):
            bad=self.selection();bad.selection['gate_manifest']=value
            with self.assertRaises(QualificationError):bad.plan()
        legacy=plan_fixture.NativeQualificationTests();legacy.setUp();self.assertNotIn('gate_manifest',legacy.plan().installation)

    def test_root_launch_adds_helper_group_only_to_selected_trusted_host(self):
        for enabled in (False,True):
            with self.subTest(enabled=enabled),tempfile.TemporaryDirectory() as temporary:
                fixture=git_fixture.NativeGitQualificationTests();self.addCleanup(fixture.doCleanups)
                plan,events,broker,git,child,spawns,startup=fixture.wrapped(Path(temporary))
                if enabled:plan.installation['gate_manifest']={}
                execute(plan)
                rows={role:kw for role,argv,kw in spawns}
                self.assertEqual(rows['broker']['extra_groups'],[]);self.assertEqual(rows['git']['extra_groups'],[])
                self.assertEqual(165530 in rows['child']['extra_groups'],enabled)
                self.assertEqual((rows['child']['user'],rows['child']['group']),(165533,165533))
                self.assertEqual(rows['child']['extra_groups'].count(165530),int(enabled))
                fixture.doCleanups()

    def listener(self,**overrides):
        instance='a'*32;path=Path('/run/uas-native')/instance/'gate'/'gate.sock'
        resources={'instance':instance,'gate_endpoint_path':str(path)}
        resources.update(overrides.pop('resources',{}))
        parent=N(st_mode=stat.S_IFDIR|0o710,st_uid=165533,st_gid=165530,st_dev=1,st_ino=10)
        node=N(st_mode=stat.S_IFSOCK|0o620,st_uid=165533,st_gid=165530,st_dev=1,st_ino=20)
        for key,value in overrides.pop('parent',{}).items():setattr(parent,key,value)
        channel=Mock();channel.family=socket.AF_UNIX;channel.type=socket.SOCK_SEQPACKET;events=[]
        channel.getsockopt.side_effect=lambda level,option:socket.SOCK_SEQPACKET if option==socket.SO_TYPE else 1
        for name in ('setsockopt','bind','listen','close'):
            getattr(channel,name).side_effect=lambda *args,_name=name,**kw:events.append((_name,args))
        stack=ExitStack();self.addCleanup(stack.close)
        factory=stack.enter_context(patch('socket.socket',return_value=channel))
        stack.enter_context(patch('os.path.lexists',return_value=overrides.pop('exists',False)))
        stack.enter_context(patch.object(Path,'lstat',return_value=parent))
        stack.enter_context(patch.object(Path,'resolve',lambda value,**kw:value))
        stack.enter_context(patch('os.getuid',return_value=overrides.pop('uid',165533)))
        stack.enter_context(patch('os.getgroups',return_value=overrides.pop('groups',[165530])))
        chown=stack.enter_context(patch('os.chown',side_effect=lambda *args,**kw:events.append(('chown',args))))
        chmod=stack.enter_context(patch('os.chmod',side_effect=lambda *args,**kw:events.append(('chmod',args))))
        label=stack.enter_context(patch('os.getxattr',return_value=overrides.pop('label',b'system_u:object_r:container_file_t:s0:c301,c302\0')))
        policy=stack.enter_context(patch('os.setxattr',side_effect=AssertionError('policy repair')))
        unlink=stack.enter_context(patch('os.unlink',side_effect=AssertionError('uncertain endpoint deletion')))
        stack.enter_context(patch('uas.artifact_helper._directory',return_value=55))
        stack.enter_context(patch('os.fstat',return_value=parent))
        original_stat=__import__('os').stat
        node_stat=stack.enter_context(patch('os.stat',side_effect=lambda name,*a,**kw:node if kw.get('dir_fd')==55 else original_stat(name,*a,**kw)))
        stack.enter_context(patch('os.close'))
        self.assertFalse(overrides,overrides)
        return N(resources=resources,path=path,parent=parent,node=node,channel=channel,events=events,
                 factory=factory,chown=chown,chmod=chmod,label=label,policy=policy,unlink=unlink,node_stat=node_stat,stack=stack)

    def test_listener_is_created_by_supervisor_and_keeps_exact_kernel_channel(self):
        f=self.listener();result=_gate_listener(f.resources)
        self.assertIs(result,f.channel)
        f.factory.assert_called_once_with(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        f.channel.bind.assert_called_once_with(str(f.path));f.channel.listen.assert_called_once_with(8)
        f.chown.assert_called_once_with(f.path,165533,165530);f.chmod.assert_called_once_with(f.path,0o620)
        f.label.assert_called_once_with(f.path,'security.selinux',follow_symlinks=False)
        names=[name for name,args in f.events]
        self.assertLess(names.index('setsockopt'),names.index('bind'));self.assertLess(names.index('bind'),names.index('chown'))
        self.assertLess(names.index('chmod'),names.index('listen'))
        f.channel.close.assert_not_called();f.policy.assert_not_called();f.unlink.assert_not_called()

    def test_invalid_owner_group_mode_path_and_existing_endpoint_fail_before_socket(self):
        cases=[{'uid':0},{'groups':[]},{'parent':{'st_uid':0}},{'parent':{'st_gid':165532}},
               {'parent':{'st_mode':stat.S_IFDIR|0o777}},{'parent':{'st_mode':stat.S_IFLNK|0o710}},
               {'resources':{'gate_endpoint_path':'/tmp/gate.sock'}},{'exists':True}]
        for case in cases:
            with self.subTest(case=case):
                f=self.listener(**case)
                with self.assertRaises(QualificationError):_gate_listener(f.resources)
                f.factory.assert_not_called();f.chown.assert_not_called();f.chmod.assert_not_called();f.stack.close()

    def test_invalid_instance_never_creates_listener_even_with_matching_claimed_path(self):
        for instance in ('../escape','A'*32,'a'*31,'a'*33,'g'*32,None,True):
            with self.subTest(instance=instance):
                path='/run/uas-native/'+str(instance)+'/gate/gate.sock'
                f=self.listener(resources={'instance':instance,'gate_endpoint_path':path})
                with self.assertRaises(QualificationError):_gate_listener(f.resources)
                f.factory.assert_not_called();f.chown.assert_not_called();f.chmod.assert_not_called();f.stack.close()

    def test_missing_or_wrong_stock_label_closes_without_policy_or_cleanup_repair(self):
        for label in (b'unconfined_u:object_r:container_file_t:s0',b'system_u:object_r:container_file_t:s0:c1,c2',None):
            with self.subTest(label=label):
                f=self.listener(label=label)
                if label is None:f.label.side_effect=OSError('no SELinux label')
                with self.assertRaises((QualificationError,OSError)):_gate_listener(f.resources)
                f.channel.close.assert_called_once_with();f.policy.assert_not_called();f.unlink.assert_not_called();f.stack.close()

    def test_endpoint_replacement_and_bind_failure_close_without_retry(self):
        f=self.listener();replacement=N(**vars(f.node));replacement.st_ino+=1
        nodes=iter((f.node,replacement));prior_stat=f.node_stat.side_effect
        f.node_stat.side_effect=lambda name,*a,**kw:next(nodes) if kw.get('dir_fd')==55 else prior_stat(name,*a,**kw)
        with self.assertRaisesRegex(ArtifactError,'GATE_ENDPOINT_REPLACED'):_gate_listener(f.resources)
        f.channel.close.assert_called_once_with();f.channel.bind.assert_called_once();f.unlink.assert_not_called();f.stack.close()
        f=self.listener();f.channel.bind.side_effect=OSError('bind failed')
        with self.assertRaises(OSError):_gate_listener(f.resources)
        f.channel.close.assert_called_once_with();f.chown.assert_not_called();f.chmod.assert_not_called()
        f.channel.listen.assert_not_called();f.unlink.assert_not_called()
