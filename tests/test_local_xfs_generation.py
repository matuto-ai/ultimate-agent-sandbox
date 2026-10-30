"""Independent boot-generation reconciliation and read-only verifier tests."""
from contextlib import ExitStack
from copy import deepcopy
from pathlib import Path
import stat
from types import SimpleNamespace as N
import unittest
from unittest.mock import patch, Mock
from uas import local_xfs_storage as xfs, local_host_apply as apply
from uas.local_host_profile import HostProfileError, canonical
from tests.test_local_xfs_storage import Harness

BOOT_A='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
BOOT_B='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'


class XfsGenerationTests(unittest.TestCase):
    def stable(self,h):return xfs.prepare(h.receipt,0,make_directory=h.directory,stable=True)
    def test_sameboot_unknown_mount_never_reissued(self):
        h=Harness();h.fail='mount'
        with h.installed(),patch.object(xfs,'boot_id',return_value=BOOT_A):
            with self.assertRaises(TimeoutError):self.stable(h)
            h.fail=None
            with self.assertRaisesRegex(HostProfileError,'XFS_MOUNT_UNKNOWN'):self.stable(h)
        self.assertEqual(h.counts['mount'],1)
    def test_newboot_issues_one_mount_generation_preserving_stable_evidence(self):
        h=Harness()
        with h.installed(),patch.object(xfs,'boot_id',return_value=BOOT_A):
            first=self.stable(h)
        self.assertEqual(first['identity'],[0,128])
        h.current=None;old_command=h.command
        def command(args):
            old_command(args)
            if args[0]=='/usr/bin/mount':h.current['identity'][0]=100
        h.command=command
        with h.installed(),patch.object(xfs,'boot_id',return_value=BOOT_B):
            self.assertEqual(first,self.stable(h));self.assertEqual(first,self.stable(h))
        self.assertEqual(h.counts,{'create':1,'allocate':1,'format':1,'mount':2})
        self.assertEqual(h.receipt.records['xfs-mount-'+BOOT_A+'.confirmed.json']['identity'],[99,128])
        self.assertEqual(h.receipt.records['xfs-mount-'+BOOT_B+'.confirmed.json']['identity'],[100,128])
    def test_newboot_can_mount_after_oldboot_unknown_without_reformatting(self):
        h=Harness();h.fail='mount'
        with h.installed(),patch.object(xfs,'boot_id',return_value=BOOT_A):
            with self.assertRaises(TimeoutError):self.stable(h)
        h.fail=None
        with h.installed(),patch.object(xfs,'boot_id',return_value=BOOT_B):self.stable(h)
        self.assertEqual(h.counts,{'create':1,'allocate':1,'format':1,'mount':2})
    def test_sameboot_device_drift_is_not_normalized_away(self):
        h=Harness()
        with h.installed(),patch.object(xfs,'boot_id',return_value=BOOT_A):
            self.stable(h);h.current['identity'][0]=100
            with self.assertRaisesRegex(HostProfileError,'XFS_CONFIRMED_DRIFT'):self.stable(h)
    def test_foreign_mount_or_changed_image_uuid_refused_across_boots(self):
        for drift in ('mount','uuid','inode'):
            h=Harness()
            with h.installed(),patch.object(xfs,'boot_id',return_value=BOOT_A):self.stable(h)
            if drift=='mount':pass  # Existing mount has no newboot issuance intent.
            else:
                h.current=None
                if drift=='uuid':h.uuid=BOOT_B
                else:h.inode=23
            with h.installed(),patch.object(xfs,'boot_id',return_value=BOOT_B),self.assertRaises(HostProfileError):self.stable(h)
            self.assertEqual(h.counts['mount'],1);self.assertEqual(h.counts['format'],1)
    def test_currentboot_policy_cannot_be_upgraded_or_downgraded_implicitly(self):
        h=Harness()
        with h.installed():h.prepare()
        with h.installed(),patch.object(xfs,'boot_id',return_value=BOOT_A),self.assertRaisesRegex(HostProfileError,'XFS_STABLE_POLICY_REQUIRED'):self.stable(h)
        h=Harness();h.fail='mount'
        with h.installed(),patch.object(xfs,'boot_id',return_value=BOOT_A):
            with self.assertRaises(TimeoutError):self.stable(h)
            h.fail=None
            with self.assertRaises(HostProfileError):h.prepare()
        self.assertEqual(h.counts['mount'],1)


class OwnedMountVerifierTests(unittest.TestCase):
    def setUp(self):
        self.h=Harness();self.h.receipt.plan['storage_root']='/owned/data'
        with self.h.installed(),patch.object(xfs,'boot_id',return_value=BOOT_A):
            xfs.prepare(self.h.receipt,0,make_directory=self.h.directory,stable=True)
        self.selection=xfs.selection(self.h.receipt)
    def boundaries(self):
        from uas import local_host_receipt
        stack=ExitStack();raw=canonical(self.h.receipt.plan)
        opened=Mock();opened.__enter__=Mock(return_value=self.h.receipt);opened.__exit__=Mock(return_value=False)
        stack.enter_context(patch.object(local_host_receipt,'PreparationReceipt',return_value=opened))
        stack.enter_context(patch.object(xfs,'canonical_node',return_value=N(st_uid=0,st_gid=0,st_mode=stat.S_IFDIR|0o700)))
        stack.enter_context(patch.object(xfs.os,'open',side_effect=lambda path,*a,**k:50 if str(path).endswith('/plan.json') else 40))
        stack.enter_context(patch.object(xfs.os,'close'))
        def fstat(fd):
            if fd==50:return N(st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1,st_size=len(raw))
            return self.h.fstat(fd)
        stack.enter_context(patch.object(xfs.os,'fstat',side_effect=fstat))
        stack.enter_context(patch.object(xfs.os,'read',return_value=raw))
        stack.enter_context(patch.object(xfs,'filesystem_uuid',side_effect=lambda _:self.h.uuid))
        stack.enter_context(patch.object(xfs,'mounted',side_effect=lambda *_:deepcopy(self.h.current)))
        stack.enter_context(patch.object(xfs,'boot_id',return_value=BOOT_A))
        return stack
    def test_real_verifier_accepts_path_or_string_after_exact_receipts(self):
        with self.boundaries():
            self.assertEqual(xfs.verify_owned_mount(self.selection,'/owned/data'),self.h.current)
            self.assertEqual(xfs.verify_owned_mount(self.selection,Path('/owned/data')),self.h.current)
    def test_real_verifier_rejects_wrong_scope_uuid_image_or_mount_evidence(self):
        for drift in ('scope','uuid','inode','intent','confirmation'):
            with self.subTest(drift=drift):
                self.setUp()
                if drift=='uuid':self.h.uuid=BOOT_B
                if drift=='inode':self.h.inode=23
                if drift=='intent':del self.h.receipt.records['xfs-mount-'+BOOT_A+'.intent.json']
                if drift=='confirmation':self.h.current['identity'][0]=100
                with self.boundaries(),self.assertRaises(HostProfileError):
                    xfs.verify_owned_mount(self.selection,'/foreign' if drift=='scope' else '/owned/data')
    def test_selection_never_overrides_private_image_or_plan_authority(self):
        for key,value in [('image_identity',[11,23]),('uuid',BOOT_B),('plan_id','b'*64)]:
            selected=deepcopy(self.selection);selected[key]=value
            with self.boundaries(),self.assertRaises(HostProfileError):xfs.verify_owned_mount(selected,'/owned/data')

    def test_stable_owned_directory_rejects_foreign_child_before_marker(self):
        parent=N(st_uid=0,st_mode=stat.S_IFDIR|0o711,st_dev=99,st_ino=2)
        child=N(st_uid=0,st_mode=stat.S_IFDIR|0o711,st_dev=100,st_ino=3)
        with patch.object(apply,'canonical_node',return_value=parent),patch.object(xfs,'verify_owned_mount',return_value=self.h.current),patch.object(apply.os,'open',side_effect=[10,20]) as opened,patch.object(apply.os,'close'),patch.object(apply.os,'fstat',side_effect=[parent,child]):
            with self.assertRaisesRegex(HostProfileError,'XFS_PATH_DEVICE'):
                apply.owned_directory('/owned/data/control',plan_id='a'*64,operation='control',owner_uid=0,mode=0o711,create=False,owned_xfs=self.selection,storage_root='/owned/data')
            self.assertEqual(opened.call_count,2)
