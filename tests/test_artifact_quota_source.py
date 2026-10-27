"""Pure/mocked quota-proof tests: no native ioctl, fallocate, timers or VM."""
from contextlib import ExitStack
from copy import deepcopy
import errno
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

SOURCE = Path(__file__).parent / 'vm/artifact_quota_probe.py'
SPEC = importlib.util.spec_from_file_location('artifact_quota_source_probe', SOURCE)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def facts(room='alpha'):
    return {'version': 1, 'room': room, 'project_id': probe.PROJECTS[room], 'device': 77,
            'hard_limit_bytes': 256 << 20, 'accounting': True, 'enforcement': True,
            'user_enforcement': False, 'group_enforcement': False, 'filesystem': 'xfs'}


def node(inode, *, directory=False, uid=probe.UID, device=77, size=0, blocks=0):
    return SimpleNamespace(st_dev=device, st_ino=inode, st_uid=uid, st_gid=uid,
        st_mode=(stat.S_IFDIR | 0o755) if directory else (stat.S_IFREG | 0o600),
        st_nlink=1, st_size=size, st_blocks=blocks)


class SimulatedKernel:
    """Only in-memory observations; never calls corresponding host syscalls."""
    def __init__(self, denied=errno.ENOSPC):
        self.nodes={10:node(1,directory=True,uid=0),11:node(2,directory=True),12:node(3)}
        self.attributes={10:{'project_id':0,'flags':0},
                         11:{'project_id':301,'flags':probe.FS_XFLAG_PROJINHERIT},
                         12:{'project_id':301,'flags':0}}
        self.free=[(2<<30)//4096]*3
        self.present=False
        self.denied=denied
        self.positive_error=None
        self.cleanup_error=None
        self.calls=[]
        self.space_calls=0
        self.attribute_calls=0
        self.os=SimpleNamespace(**{name:getattr(os,name) for name in (
            'O_RDONLY','O_DIRECTORY','O_NOFOLLOW','O_CLOEXEC','O_CREAT','O_EXCL','O_RDWR')},
            open=Mock(side_effect=self.open),close=Mock(),fstat=Mock(side_effect=lambda fd:self.nodes[fd]),
            stat=Mock(side_effect=self.stat),fstatvfs=Mock(side_effect=self.statvfs),
            fsync=Mock(),posix_fallocate=Mock(side_effect=self.allocate),unlink=Mock(side_effect=self.unlink))
    def open(self,name,flags,mode=0o777,*,dir_fd=None):
        self.calls.append(('open',name))
        if name=='alpha' and dir_fd==10:return 11
        if name==probe.NAME and dir_fd==11:
            if self.present:raise FileExistsError()
            self.present=True
            return 12
        raise AssertionError('unexpected simulated path')
    def stat(self,name,*,dir_fd,follow_symlinks):
        if name=='alpha' and dir_fd==10:return self.nodes[11]
        if name==probe.NAME and dir_fd==11:
            if not self.present:raise FileNotFoundError()
            return self.nodes[12]
        raise AssertionError('unexpected simulated stat')
    def statvfs(self,fd):
        if fd!=10:raise AssertionError('must observe unquota-clamped global root')
        free=self.free[min(self.space_calls,len(self.free)-1)];self.space_calls+=1
        return SimpleNamespace(f_frsize=4096,f_bfree=free,f_bavail=free)
    def attrs(self,fd):
        self.attribute_calls+=1
        return dict(self.attributes[fd])
    def allocate(self,fd,offset,length):
        self.calls.append(('allocate',length))
        if fd!=12 or offset!=0:raise AssertionError('unexpected simulated allocation')
        if length==probe.POSITIVE_BYTES and self.positive_error:
            raise OSError(self.positive_error,'simulated positive denial')
        if length==probe.REQUEST_BYTES and self.denied is not None:
            raise OSError(self.denied,'simulated oversized denial')
        self.nodes[12].st_size=length
        self.nodes[12].st_blocks=(length+511)//512
    def unlink(self,name,*,dir_fd):
        self.calls.append(('unlink',name))
        if self.cleanup_error:raise OSError(self.cleanup_error,'simulated cleanup denial')
        if name!=probe.NAME or dir_fd!=11:raise AssertionError('unexpected simulated unlink')
        self.present=False;self.nodes[12].st_nlink=0
    def run(self,evidence=None):
        value={'phase':'initial','owned_cleanup':False} if evidence is None else evidence
        with patch.object(probe,'os',self.os),patch.object(probe,'open_mount',return_value=10), \
                patch.object(probe,'attributes',side_effect=self.attrs):
            probe.exercise('alpha',facts(),value)
        return value


class QuotaFactsTests(unittest.TestCase):
    def test_only_exact_parent_observed_contract_without_quota_inflation(self):
        for room in ('alpha','beta'):
            value=facts(room)
            self.assertEqual(probe.parent_facts(json.dumps(value).encode(),room),value)
        for key,value in [('version',True),('project_id',True),('project_id',303),('device',True),
                          ('hard_limit_bytes',512<<20),('accounting',False),('enforcement',False),
                          ('user_enforcement',True),('group_enforcement',True),('filesystem','ext4'),('room','beta')]:
            candidate=facts();candidate[key]=value
            with self.subTest(key=key,value=value),self.assertRaises(probe.ProbeError):
                probe.parent_facts(json.dumps(candidate).encode(),'alpha')
        for candidate in ({**facts(),'path':'/caller/path'}, {key:value for key,value in facts().items() if key!='device'}):
            with self.assertRaises(probe.ProbeError):probe.parent_facts(json.dumps(candidate).encode(),'alpha')
    def test_bounded_canonical_shape_and_duplicates_fail(self):
        for raw in (b'',b'x'*4097,b'{}',b'[]',b'\xff',b'{"device":77,"device":77}'):
            with self.subTest(raw=raw[:30]),self.assertRaises(probe.ProbeError):probe.parent_facts(raw,'alpha')
    def test_getxattr_is_query_only_exact_28byte_uapi_and_mutated_buffer(self):
        def ioctl(fd,command,buffer,mutable):
            self.assertEqual((fd,command,mutable),(9,0x801c581f,True))
            self.assertEqual(len(buffer),28);self.assertEqual(buffer,bytearray(28))
            probe.FSXATTR.pack_into(buffer,0,0x200,0,0,301,0,b'\0'*8)
        with patch.object(probe.fcntl,'ioctl',side_effect=ioctl) as queried:
            self.assertEqual(probe.attributes(9),{'project_id':301,'flags':0x200})
        queried.assert_called_once()
    def test_unsupported_ioctl_propagates_not_guessed_from_config(self):
        with patch.object(probe.fcntl,'ioctl',side_effect=OSError(errno.ENOTTY,'unsupported')):
            with self.assertRaises(OSError):probe.attributes(9)


class QuotaProofTests(unittest.TestCase):
    def test_project_enospc_or_edquot_only_after_all_positive_prerequisites(self):
        for denied in (errno.ENOSPC,errno.EDQUOT):
            kernel=SimulatedKernel(denied);value=kernel.run()
            self.assertTrue(value['project_hard_quota_enforced']);self.assertTrue(value['owned_cleanup'])
            self.assertEqual(value['observed_errno'],denied);self.assertEqual(value['positive_bytes'],1<<20)
            self.assertEqual(value['requested_bytes'],(256<<20)+4096)
            self.assertEqual(value['membership']['room']['project_id'],301)
            self.assertEqual(value['membership_after']['file']['project_id'],301)
            self.assertEqual(kernel.os.posix_fallocate.call_args_list[0].args,(12,0,1<<20))
            self.assertEqual(kernel.os.posix_fallocate.call_args_list[1].args,(12,0,(256<<20)+4096))
            self.assertEqual(kernel.space_calls,3);self.assertFalse(kernel.present)
    def test_errno_alone_or_other_failure_never_qualifies(self):
        for denied in (None,errno.EPERM,errno.EIO,errno.EFBIG,errno.ENOTSUP):
            kernel=SimulatedKernel(denied);evidence={'phase':'initial'}
            with self.subTest(denied=denied),self.assertRaises(probe.ProbeError):kernel.run(evidence)
            self.assertNotIn('project_hard_quota_enforced',evidence);self.assertTrue(evidence['owned_cleanup'])
    def test_positive_denial_never_becomes_quota_success_and_is_cleaned(self):
        for denied in (errno.ENOSPC,errno.EDQUOT,errno.EACCES):
            kernel=SimulatedKernel();kernel.positive_error=denied;evidence={'phase':'initial'}
            with self.subTest(denied=denied),self.assertRaises(OSError):kernel.run(evidence)
            self.assertEqual(evidence['phase'],'positive-allocation')
            self.assertNotIn('project_hard_quota_enforced',evidence)
            self.assertEqual(kernel.os.posix_fallocate.call_count,1);self.assertTrue(evidence['owned_cleanup'])
    def test_positive_sparse_size_without_allocated_blocks_fails(self):
        kernel=SimulatedKernel();original=kernel.allocate
        def sparse(*args):original(*args);kernel.nodes[12].st_blocks=0
        kernel.os.posix_fallocate.side_effect=sparse
        with self.assertRaisesRegex(probe.ProbeError,'POSITIVE_ALLOCATION_UNPROVEN'):kernel.run()
        self.assertEqual(kernel.os.posix_fallocate.call_count,1)
    def test_wrong_project_or_missing_inheritance_or_quota_clamped_global_root_fails(self):
        for fd,changes in ((10,{'project_id':301}),(10,{'flags':0x200}),
                           (11,{'project_id':303}),(11,{'flags':0}),(12,{'project_id':0})):
            kernel=SimulatedKernel();kernel.attributes[fd].update(changes)
            with self.subTest(fd=fd,changes=changes),self.assertRaises(probe.ProbeError):kernel.run()
            kernel.os.posix_fallocate.assert_not_called()
    def test_device_and_ownership_mismatch_stop_before_allocation(self):
        for fd,field,value in ((11,'st_dev',99),(12,'st_dev',99),(11,'st_uid',0),(12,'st_nlink',2)):
            kernel=SimulatedKernel();setattr(kernel.nodes[fd],field,value)
            with self.subTest(fd=fd,field=field),self.assertRaises(probe.ProbeError):kernel.run()
            kernel.os.posix_fallocate.assert_not_called()
    def test_insufficient_global_space_before_or_after_denial_fails(self):
        for position in range(3):
            kernel=SimulatedKernel();kernel.free[position]=100;evidence={'phase':'initial'}
            with self.subTest(position=position),self.assertRaisesRegex(probe.ProbeError,'INSUFFICIENT_GLOBAL_SPACE'):
                kernel.run(evidence)
            self.assertNotIn('project_hard_quota_enforced',evidence)
    def test_cleanup_failure_retains_resource_and_never_sets_success(self):
        kernel=SimulatedKernel();kernel.cleanup_error=errno.EPERM;evidence={'phase':'initial'}
        with self.assertRaises(OSError):kernel.run(evidence)
        self.assertEqual(evidence['phase'],'owned-cleanup');self.assertFalse(evidence['owned_cleanup'])
        self.assertTrue(kernel.present);self.assertNotIn('project_hard_quota_enforced',evidence)
    def test_exclusive_existing_probe_not_adopted_or_removed(self):
        kernel=SimulatedKernel();kernel.present=True
        with self.assertRaises(FileExistsError):kernel.run()
        kernel.os.unlink.assert_not_called();kernel.os.posix_fallocate.assert_not_called()
    def test_post_denial_project_recheck_required(self):
        kernel=SimulatedKernel();original=kernel.allocate
        def alter(fd,offset,length):
            try:return original(fd,offset,length)
            finally:
                if length==probe.REQUEST_BYTES:kernel.attributes[12]['project_id']=303
        kernel.os.posix_fallocate.side_effect=alter
        with self.assertRaisesRegex(probe.ProbeError,'FILE_PROJECT_ASSIGNMENT_MISMATCH'):kernel.run()


class QuotaDiagnosticTests(unittest.TestCase):
    def invoke(self,*,machine='x86_64',failure=None):
        output=io.StringIO();raw=json.dumps(facts()).encode()
        mocked_os=SimpleNamespace(getuid=lambda:165533,getgid=lambda:165533,
                                  uname=lambda:SimpleNamespace(machine=machine))
        stream=SimpleNamespace(buffer=io.BytesIO(raw))
        marker=Mock();marker.lstat.return_value=node(9,uid=0)
        with ExitStack() as stack:
            stack.enter_context(patch.object(probe,'os',mocked_os))
            stack.enter_context(patch.object(probe,'signal',Mock()))
            stack.enter_context(patch.object(probe,'Path',return_value=marker))
            stack.enter_context(patch.object(probe.sys,'argv',['artifact_quota_probe.py','alpha']))
            stack.enter_context(patch.object(probe.sys,'stdin',stream))
            stack.enter_context(patch.object(probe.sys,'stdout',output))
            exercise=stack.enter_context(patch.object(probe,'exercise',side_effect=failure))
            code=probe.main()
        return code,json.loads(output.getvalue()),exercise
    def test_unsupported_abi_fails_before_ioctl_or_allocation(self):
        code,value,exercise=self.invoke(machine='aarch64')
        self.assertEqual(code,1);self.assertEqual(value['error_code'],'UNSUPPORTED_IOCTL_ABI')
        exercise.assert_not_called()
    def test_typed_phase_and_errno_preserved_without_arbitrary_error_string(self):
        def denied(room,facts,evidence):
            evidence['phase']='positive-allocation'
            raise OSError(errno.EACCES,'private untrusted arbitrary text must not escape')
        code,value,_=self.invoke(failure=denied)
        self.assertEqual(code,1);self.assertEqual(value['errno'],errno.EACCES)
        self.assertEqual(value['phase'],'positive-allocation');self.assertEqual(value['error_type'],'PermissionError')
        self.assertNotIn('private untrusted',json.dumps(value))
        self.assertNotIn('project_hard_quota_enforced',value)


if __name__=='__main__':unittest.main()
