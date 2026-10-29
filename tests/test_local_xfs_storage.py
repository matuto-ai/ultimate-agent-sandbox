"""Owned XFS state machine with inert syscall/command observations only."""
from contextlib import ExitStack
from copy import deepcopy
from pathlib import Path
import stat
from types import SimpleNamespace as N
import unittest
from unittest.mock import Mock, patch, mock_open
import uuid

from uas import local_xfs_storage as xfs
from uas.local_host_profile import HostProfileError


class Receipt:
    def __init__(self):
        self.root=Path('/owned/install');self.fd=20;self.records={};self.evidence=None
        self.plan={'plan_id':'a'*64,'storage_identity':[11,12],
            'operations':[{'kind':'prepare-owned-xfs-file','format_existing_device':False,
                           'bytes':512*1024**2,'path':'/owned/data'}]}
    def _guard(self):pass
    def _read(self,name):return deepcopy(self.records.get(name))
    def _append(self,name,value):
        if name in self.records:
            if self.records[name]!=value:raise HostProfileError('HOST_RECEIPT_CONFLICT')
            return False
        self.records[name]=deepcopy(value);return True
    def state(self,index):
        return {'state':'confirmed','evidence':deepcopy(self.evidence)} if self.evidence else {'state':'not-started'}
    def intent(self,index):pass
    def confirm(self,index,evidence):self.evidence=deepcopy(evidence)


class Harness:
    def __init__(self):
        self.receipt=Receipt();self.size=self.receipt.plan['operations'][0]['bytes']
        self.exists=False;self.allocated=False;self.uuid=None;self.current=None
        self.uid=0;self.nlink=1;self.inode=22;self.mode=stat.S_IFREG|0o600
        self.fail=None;self.after=False;self.counts={'create':0,'allocate':0,'format':0,'mount':0}
        self.expected_uuid=str(uuid.UUID(hex='a'*32));self.directory=Mock(return_value={'identity':[11,33]})
    def step(self,name,effect):
        self.counts[name]+=1
        if self.fail==name and not self.after:raise TimeoutError(name)
        effect()
        if self.fail==name:raise TimeoutError(name)
    def open(self,path,flags,*args,**kwargs):
        if flags & xfs.os.O_CREAT:
            if self.exists:raise FileExistsError('foreign existing image')
            self.step('create',lambda:setattr(self,'exists',True))
        elif not self.exists:raise FileNotFoundError('image')
        return 40
    def fstat(self,fd):
        if fd==20:return N(st_dev=11)
        return N(st_mode=self.mode,st_uid=self.uid,st_gid=0,st_nlink=self.nlink,
            st_dev=11,st_ino=self.inode,st_size=self.size if self.allocated else 0,
            st_blocks=self.size//512 if self.allocated else 0)
    def allocate(self,*args):self.step('allocate',lambda:setattr(self,'allocated',True))
    def command(self,args):
        if args[0]=='/usr/sbin/mkfs.xfs':
            assert '-f' not in args and '-K' in args
            self.step('format',lambda:setattr(self,'uuid',self.expected_uuid))
        elif args[0]=='/usr/bin/mount':
            assert args==['/usr/bin/mount','-t','xfs','-o','loop,prjquota,nodev,nosuid','/owned/install/storage.xfs','/owned/data']
            self.step('mount',lambda:setattr(self,'current',{'identity':[99,128],'image_identity':[11,22]}))
        else:raise AssertionError('unexpected command')
    def installed(self):
        stack=ExitStack()
        for name,value in [('geteuid',lambda:0),('fstat',self.fstat),('open',self.open),
            ('close',lambda *_:None),('fsync',lambda *_:None),('posix_fallocate',self.allocate),
            ('fstatvfs',lambda *_:N(f_bavail=2**30,f_frsize=4096))]:
            stack.enter_context(patch.object(xfs.os,name,side_effect=value))
        stack.enter_context(patch.object(xfs,'filesystem_uuid',side_effect=lambda _:self.uuid))
        stack.enter_context(patch.object(xfs,'mounted',side_effect=lambda *_:deepcopy(self.current)))
        stack.enter_context(patch.object(xfs,'run_fixed',side_effect=self.command))
        stack.enter_context(patch.object(Path,'lstat',return_value=N(st_ino=22)))
        return stack
    def prepare(self):return xfs.prepare(self.receipt,0,make_directory=self.directory)


class XfsStorageTests(unittest.TestCase):
    def test_complete_then_repeat_observes_without_reissuing_any_action(self):
        h=Harness()
        with h.installed():
            first=h.prepare();self.assertEqual(first,h.prepare())
        self.assertEqual(h.counts,dict.fromkeys(h.counts,1))

    def test_unknown_allocation_format_or_mount_never_reissues(self):
        for stage in ('allocate','format','mount'):
            with self.subTest(stage=stage):
                h=Harness();h.fail=stage
                with h.installed():
                    with self.assertRaises(TimeoutError):h.prepare()
                    h.fail=None
                    with self.assertRaises(HostProfileError):h.prepare()
                self.assertEqual(h.counts[stage],1)
                self.assertNotIn('xfs-'+stage+'.confirmed.json',h.receipt.records)

    def test_lost_success_reconciles_observation_without_repeating_action(self):
        for stage in ('allocate','format','mount'):
            with self.subTest(stage=stage):
                h=Harness();h.fail=stage;h.after=True
                with h.installed():
                    with self.assertRaises(TimeoutError):h.prepare()
                    h.fail=None;h.prepare();h.prepare()
                self.assertEqual(h.counts,dict.fromkeys(h.counts,1))

    def test_image_created_without_ownership_receipt_is_not_adopted(self):
        h=Harness();h.fail='create';h.after=True
        with h.installed():
            with self.assertRaises(TimeoutError):h.prepare()
            h.fail=None
            with self.assertRaisesRegex(HostProfileError,'XFS_IMAGE_OWNERSHIP_UNKNOWN'):h.prepare()
        self.assertEqual(h.counts,{'create':1,'allocate':0,'format':0,'mount':0})

    def test_foreign_existing_image_is_not_opened_or_formatted(self):
        h=Harness();h.exists=True
        with h.installed():
            with self.assertRaises(FileExistsError):h.prepare()
            with self.assertRaisesRegex(HostProfileError,'XFS_IMAGE_OWNERSHIP_UNKNOWN'):h.prepare()
        self.assertEqual(h.counts,dict.fromkeys(h.counts,0))

    def test_changed_owned_inode_mode_uid_or_link_count_refuses(self):
        for attr,value in (('inode',23),('uid',1),('nlink',2),('mode',stat.S_IFREG|0o644)):
            with self.subTest(attr=attr):
                h=Harness()
                with h.installed():
                    h.prepare();counts=deepcopy(h.counts);setattr(h,attr,value)
                    with self.assertRaises(HostProfileError):h.prepare()
                self.assertEqual(counts,h.counts)

    def test_existing_matching_mount_without_scoped_intent_is_not_adopted(self):
        h=Harness();h.fail='mount'
        with h.installed():
            with self.assertRaises(TimeoutError):h.prepare()
            del h.receipt.records['xfs-mount.intent.json']
            h.current={'identity':[99,128],'image_identity':[11,22]};h.fail=None
            with self.assertRaisesRegex(HostProfileError,'XFS_MOUNT_OWNERSHIP_UNKNOWN'):h.prepare()
        self.assertEqual(h.counts['mount'],1)

    def test_confirmed_mount_identity_drift_refuses_even_before_final_confirmation(self):
        h=Harness()
        with h.installed():
            h.prepare();h.receipt.evidence=None
            h.current['identity']=[99,129]
            with self.assertRaisesRegex(HostProfileError,'XFS_CONFIRMED_DRIFT'):h.prepare()
        self.assertEqual(h.counts['mount'],1)

    def test_foreign_mount_image_identity_refuses(self):
        h=Harness();h.fail='mount';h.after=True
        with h.installed():
            with self.assertRaises(TimeoutError):h.prepare()
            h.current['image_identity']=[11,23];h.fail=None
            with self.assertRaisesRegex(HostProfileError,'XFS_MOUNT_IMAGE_CHANGED'):h.prepare()
        self.assertIsNone(h.receipt.evidence)

    def test_step_rejects_foreign_scope_and_orphan_confirmation(self):
        for record,value in [('intent',{'plan_id':'b'*64,'step':'xfs-format'}),('confirmed',{})]:
            r=Receipt();r.records['xfs-format.'+record+'.json']=value;action=Mock();observe=Mock()
            with self.assertRaises(HostProfileError):xfs._step(r,'xfs-format',action,observe)
            action.assert_not_called();observe.assert_not_called()

    def test_mounted_observer_rejects_foreign_type_backing_or_missing_quota(self):
        good='1 0 7:0 / /owned/data rw,nodev,nosuid - xfs /dev/loop0 rw,prjquota\n'
        for row,backing,report in [(good.replace(' - xfs ',' - ext4 '),'/owned/install/storage.xfs',''),
            (good,'/foreign/image',''),(good,'/owned/install/storage.xfs','Project quota state on /owned/data\nAccounting: OFF\nEnforcement: OFF\n')]:
            with self.subTest(row=row,backing=backing),patch('builtins.open',mock_open(read_data=row)),patch.object(Path,'read_text',return_value=backing),patch.object(Path,'lstat',return_value=N(st_mode=stat.S_IFREG,st_dev=11,st_ino=22)),patch.object(xfs,'canonical_node',return_value=N(st_dev=99,st_ino=128,st_uid=0,st_gid=0,st_mode=stat.S_IFDIR|0o711)),patch.object(xfs,'run_fixed',return_value=report):
                with self.assertRaises(HostProfileError):xfs.mounted(Path('/owned/data'),Path('/owned/install/storage.xfs'))

    def test_allocation_bound_and_space_refuse_before_image_creation(self):
        for value in (0,True,512*1024**2+1,1024**4+1024**2):
            h=Harness();h.receipt.plan['operations'][0]['bytes']=value
            with h.installed(),self.assertRaisesRegex(HostProfileError,'XFS_ALLOCATION_BOUND'):h.prepare()
            self.assertFalse(h.exists)
        h=Harness()
        with h.installed(),patch.object(xfs.os,'fstatvfs',return_value=N(f_bavail=0,f_frsize=4096)):
            with self.assertRaisesRegex(HostProfileError,'XFS_ALLOCATION_SPACE'):h.prepare()
        self.assertFalse(h.exists)

    def test_mountpoint_changed_after_unknown_mount_refuses_without_retry(self):
        h=Harness();h.fail='mount'
        with h.installed():
            with self.assertRaises(TimeoutError):h.prepare()
            h.fail=None;h.directory.return_value={'identity':[11,34]}
            with self.assertRaisesRegex(HostProfileError,'XFS_MOUNTPOINT_CHANGED'):h.prepare()
        self.assertEqual(h.counts['mount'],1)
