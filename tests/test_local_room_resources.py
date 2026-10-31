"""Controlled effect models plus ordinary temp files; no privileged commands."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from uas import local_room_resources as resources
from uas.local_host_profile import HostProfileError, digest
from uas.local_host_receipt import PreparationReceipt


class RoomResourceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.storage=self.root/'storage';self.storage.mkdir(mode=0o700)
        self.leaf=self.storage/'repo';self.receipts=self.root/'receipts';self.receipts.mkdir(mode=0o700)
        self.real_stat=os.stat;self.real_fstat=os.fstat
        self.owners={};self.attributes={};self.labels={};self.quotas={};self.calls=[];self.failure=None
        def remap(info):
            fields=list(info);fields[4],fields[5]=self.owners.get(info.st_ino,(0,0))
            return os.stat_result(fields)
        self.fake_stat=lambda *a,**kw:remap(self.real_stat(*a,**kw))
        self.fake_fstat=lambda *a,**kw:remap(self.real_fstat(*a,**kw))
        for name,value in [('os.geteuid',lambda:0),('os.stat',self.fake_stat),('os.fstat',self.fake_fstat),
                           ('canonical_node',lambda p:self.fake_stat(p)),
                           ('project_attributes',lambda p:self.attributes.get(str(p),(0,False))),
                           ('run_fixed',self.command),('os.fchown',self.chown)]:
            stub=patch('uas.local_room_resources.'+name,value);stub.start();self.addCleanup(stub.stop)
        info=self.storage.stat();identity=[info.st_dev,info.st_ino]
        quota={'kind':'reserve-room-quota','storage_root':str(self.storage),'storage_identity':identity,
               'project_id':1200,'disk_bytes':64*1024**2}
        leaf={'kind':'prepare-room-leaf','storage_root':str(self.storage),'storage_identity':identity,
              'path':str(self.leaf),'project_id':1200,'mcs_level':'s0:c200,c201'}
        from tests.test_local_host_plan import profile
        body={'version':1,'operations':[quota,leaf],'host_profile':profile()};self.plan=dict(body,plan_id=digest(body))
        self.receipt=PreparationReceipt(self.receipts,self.plan,owner_uid=0)
        self.addCleanup(self.receipt.close)

    def command(self,args):
        self.calls.append(args)
        if args[0]=='/usr/bin/stat':return self.labels.get(args[-1],'unconfined_u:object_r:user_tmp_t:s0')
        if args[0]=='/usr/bin/chcon':
            self.labels[args[-1]]='system_u:object_r:container_file_t:'+args[-2]
            if self.failure=='chcon':self.failure=None;raise OSError('lost label acknowledgement')
            return ''
        command=args[-2]
        if command.startswith('report '):
            inode=' -i ' in command
            selected = int(command.split(' -L ')[1].split()[0]) if ' -L ' in command else None
            return ('' if selected is not None else '#0 1 0 0 00 [------]\n')+''.join(
                '#'+str(key)+' 0 0 '+str(0 if inode else value)+' 00 [------]\n'
                for key,value in sorted(self.quotas.items()) if selected is None or key == selected)
        if command.startswith('limit '):
            if self.failure=='quota-before':self.failure=None;raise OSError('before quota effect')
            self.quotas[int(command.split()[-1])]=int(command.split('bhard=')[1].split('k')[0])
            if self.failure=='quota':self.failure=None;raise OSError('lost quota acknowledgement')
            return ''
        if command.startswith('project '):
            parts=command.split();self.attributes[parts[3]]=(int(parts[4]),True)
            if self.failure=='project':self.failure=None;raise OSError('lost project acknowledgement')
            return ''
        raise AssertionError(args)

    def chown(self,fd,uid,gid):
        self.owners[self.real_fstat(fd).st_ino]=(uid,gid)
        if self.failure=='chown':self.failure=None;raise OSError('lost ownership acknowledgement')

    def effect_count(self,prefix):
        return len([a for a in self.calls if (a[0]=='/usr/bin/chcon' and prefix=='chcon')
                    or (a[0]=='/usr/sbin/xfs_quota' and a[-2].startswith(prefix))])

    def reserve(self):return resources.reserve_quota(self.receipt,0)
    def prepare(self):return resources.prepare_leaf(self.receipt,1)

    def test_quota_then_leaf_handoff_and_idempotent_observation(self):
        self.reserve();evidence=self.prepare()
        self.assertEqual(list(self.leaf.iterdir()),[])
        self.assertTrue((self.storage/'.repo.uas-owner.json').exists())
        self.assertEqual(self.owners[self.leaf.stat().st_ino],(165532,165532))
        self.assertEqual(self.attributes[str(self.leaf)],(1200,True))
        (self.leaf/'human.txt').write_text('keep')
        self.assertEqual(self.prepare(),evidence)
        self.assertEqual((self.leaf/'human.txt').read_text(),'keep')
        self.assertEqual(self.effect_count('limit'),1)
        self.assertEqual(self.effect_count('project'),1)
        self.assertEqual(self.effect_count('chcon'),1)

    def readonly_plan(self, value=True):
        self.receipt.close()
        body={k:v for k,v in self.plan.items() if k!='plan_id'}
        body['operations']=[dict(op) for op in body['operations']]
        body['operations'][1]['readonly']=value
        self.plan=dict(body,plan_id=digest(body))
        directory=self.root/'readonly-receipts';directory.mkdir(mode=0o700)
        self.receipt=PreparationReceipt(directory,self.plan,owner_uid=0)
        self.addCleanup(self.receipt.close)

    def test_reference_leaf_stays_root_owned_and_readable_idempotently(self):
        self.readonly_plan();self.reserve();evidence=self.prepare()
        info=self.fake_stat(self.leaf)
        self.assertEqual((info.st_uid,info.st_gid),(0,0))
        self.assertEqual(info.st_mode & 0o777,0o755)
        self.assertNotIn(info.st_ino,self.owners)
        (self.leaf/'published.txt').write_text('keep')
        calls=list(self.calls)
        self.assertEqual(self.prepare(),evidence)
        self.assertEqual((self.leaf/'published.txt').read_text(),'keep')
        self.assertEqual(self.effect_count('project'),1);self.assertEqual(self.effect_count('chcon'),1)

    def test_reference_mode_drift_is_never_repaired(self):
        self.readonly_plan();self.reserve();self.prepare();self.leaf.chmod(0o700)
        with self.assertRaisesRegex(HostProfileError,'NOT_FRESH_EMPTY'):self.prepare()
        self.assertEqual(self.leaf.stat().st_mode & 0o777,0o700)

    def test_reference_populated_unknown_leaf_is_never_adopted(self):
        self.readonly_plan();self.reserve();self.failure='project'
        with self.assertRaises(OSError):self.prepare()
        (self.leaf/'human.txt').write_text('keep')
        with self.assertRaisesRegex(HostProfileError,'NOT_FRESH_EMPTY'):self.prepare()
        self.assertEqual(self.leaf.stat().st_mode & 0o777,0o700)
        self.assertEqual((self.leaf/'human.txt').read_text(),'keep')

    def test_reference_lost_final_mode_ack_is_observation_only(self):
        self.readonly_plan();self.reserve();real=os.fchmod
        def lost(fd,mode):real(fd,mode);raise OSError('lost final mode ack')
        with patch.object(resources.os,'fchmod',side_effect=lost):
            with self.assertRaises(OSError):self.prepare()
        self.assertEqual(self.receipt.state(1)['state'],'unknown')
        (self.leaf/'published.txt').write_text('keep')
        with patch.object(resources.os,'fchmod',side_effect=AssertionError('must not repair')):
            self.prepare()
        self.assertEqual(self.receipt.state(1)['state'],'confirmed')

    def test_readonly_role_requires_exact_boolean(self):
        self.readonly_plan('yes');self.reserve()
        with self.assertRaisesRegex(HostProfileError,'LEAF_ROLE'):self.prepare()
        self.assertFalse(self.leaf.exists())

    def test_quota_collision_before_intent(self):
        self.quotas[1200]=65536
        with self.assertRaisesRegex(HostProfileError,'ALREADY_ALLOCATED'):self.reserve()
        self.assertEqual(self.receipt.state(0),{'state':'not-started'})
        self.assertEqual(self.effect_count('limit'),0)

    def test_targeted_query_catches_id_missing_from_enumeration(self):
        self.quotas[1200]=65536
        original=self.command
        def truncated(args):
            if args[0]=='/usr/sbin/xfs_quota' and args[-2].startswith('report ') and ' -L ' not in args[-2]:
                return '#0 1 0 0 00 [------]'
            return original(args)
        with patch.object(resources,'run_fixed',truncated):
            with self.assertRaisesRegex(HostProfileError,'ALREADY_ALLOCATED'):self.reserve()
        self.assertEqual(self.effect_count('limit'),0)

    def test_wrong_target_row_cannot_prove_absence(self):
        original=self.command
        def wrong(args):
            if args[0]=='/usr/sbin/xfs_quota' and ' -L ' in args[-2]:
                return '#1201 0 0 0 00 [------]'
            return original(args)
        with patch.object(resources,'run_fixed',wrong):
            with self.assertRaisesRegex(HostProfileError,'QUOTA_RANGE'):self.reserve()
        self.assertEqual(self.effect_count('limit'),0)

    def test_unknown_quota_readback_does_not_repeat_effect(self):
        self.failure='quota'
        with self.assertRaises(OSError):self.reserve()
        self.assertEqual(self.receipt.state(0),{'state':'unknown'})
        self.reserve()
        self.assertEqual(self.effect_count('limit'),1)
        self.assertEqual(self.receipt.state(0)['state'],'confirmed')

    def test_verified_absent_quota_can_finish_same_intent(self):
        self.failure='quota-before'
        with self.assertRaises(OSError):self.reserve()
        self.assertNotIn(1200,self.quotas)
        self.reserve()
        self.assertEqual(self.effect_count('limit'),2)
        self.assertEqual(self.receipt.state(0)['state'],'confirmed')

    def test_unknown_quota_foreign_change_not_overwritten(self):
        self.failure='quota'
        with self.assertRaises(OSError):self.reserve()
        self.quotas[1200]=123
        with self.assertRaisesRegex(HostProfileError,'UNCONFIRMED'):self.reserve()
        self.assertEqual(self.quotas[1200],123)
        self.assertEqual(self.effect_count('limit'),1)

    def test_leaf_requires_confirmed_matching_quota(self):
        with self.assertRaisesRegex(HostProfileError,'RESERVATION_REQUIRED'):self.prepare()
        self.assertFalse(self.leaf.exists())

    def test_acknowledgement_cutpoints_reconcile_not_repeat(self):
        self.reserve();self.failure='project'
        with self.assertRaises(OSError):self.prepare()
        self.assertEqual(self.receipt.state(1),{'state':'unknown'})
        self.failure='chcon'
        with self.assertRaises(OSError):self.prepare()
        self.failure='chown'
        with self.assertRaises(OSError):self.prepare()
        self.prepare()
        self.assertEqual(self.effect_count('project'),1)
        self.assertEqual(self.effect_count('chcon'),1)
        self.assertEqual(self.receipt.state(1)['state'],'confirmed')

    def test_populated_root_owned_unknown_tree_never_scanned_or_repaired(self):
        self.reserve();self.failure='project'
        with self.assertRaises(OSError):self.prepare()
        (self.leaf/'human.txt').write_text('keep')
        before=(self.effect_count('project'),self.effect_count('chcon'))
        with self.assertRaisesRegex(HostProfileError,'NOT_FRESH_EMPTY'):self.prepare()
        self.assertEqual(before,(self.effect_count('project'),self.effect_count('chcon')))
        self.assertEqual((self.leaf/'human.txt').read_text(),'keep')

    def test_foreign_leaf_or_owner_record_never_adopted(self):
        self.reserve();self.leaf.mkdir();(self.leaf/'human.txt').write_text('keep')
        with self.assertRaises(FileExistsError):self.prepare()
        self.assertEqual(self.effect_count('project'),0)
        self.assertEqual((self.leaf/'human.txt').read_text(),'keep')

    def test_intent_failure_has_no_leaf_effect(self):
        self.reserve()
        with patch.object(self.receipt,'intent',side_effect=OSError('intent failure')):
            with self.assertRaises(OSError):self.prepare()
        self.assertFalse(self.leaf.exists())
        self.assertEqual(self.effect_count('project'),0)

    def test_parent_fsync_failure_does_not_adopt_unmarked_leaf(self):
        self.reserve();original=os.fsync;calls=[]
        def fail(fd):
            # Intent flushes file and receipt-dir first; leaf parent is storage.
            if self.real_fstat(fd).st_ino==self.storage.stat().st_ino:
                raise OSError('parent durability unknown')
            return original(fd)
        with patch('uas.local_room_resources.os.fsync',side_effect=fail):
            with self.assertRaises(OSError):self.prepare()
        self.assertTrue(self.leaf.exists())
        self.assertFalse((self.storage/'.repo.uas-owner.json').exists())
        with self.assertRaises(FileNotFoundError):self.prepare()
        self.assertEqual(self.effect_count('project'),0)

    def test_final_owner_drift_is_read_only(self):
        self.reserve();self.prepare();self.labels[str(self.leaf)]='wrong'
        before=(self.effect_count('project'),self.effect_count('chcon'))
        with self.assertRaisesRegex(HostProfileError,'HANDED_OFF_DRIFT'):self.prepare()
        self.assertEqual(before,(self.effect_count('project'),self.effect_count('chcon')))


class QuotaReportTests(unittest.TestCase):
    # Format-derived fixture, NOT a claim of execution on an XFS host.
    # xfsprogs quota/report.c report_mount and report_project_mount at:
    # https://github.com/tytso/xfsprogs/blob/07d66eb9dc15c52cb080d7c172a7a9dba532d4c9/quota/report.c
    # Numeric report prints ID, used/soft/hard, warning count, grace display;
    # report_project_mount's bounded range uses GETQUOTA rather than fallback
    # project-name enumeration. Blocks are KiB; inode counts are unscaled.

    def test_numeric_accounting_anchor_and_duplicates(self):
        self.assertEqual(resources.quota_rows('#0 10 0 0 00 [------]\n')[0]['used'],10)
        for bad in ('','\n','#12 0 0 1 00 [------]', '#0 -1 0 0 00 [------]',
                    '#0 0 0 0 00 [------]\n#0 0 0 0 00 [------]', 'warning ignored'):
            with self.assertRaises(HostProfileError):resources.quota_rows(bad)


if __name__=='__main__':unittest.main()
