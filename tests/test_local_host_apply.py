"""Apply orchestration uses fake effects; only directory helpers use temp files."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from uas.local_host_apply import apply, owned_directory
from uas.local_host_profile import HostProfileError
from tests.test_local_host_plan import selected, observation, profile


class FakeReceipt:
    fd = 777
    states = {}
    documents = {}
    def __init__(self, *args, **kwargs): pass
    def __enter__(self): return self
    def __exit__(self, *_): pass
    def state(self, i): return self.states.get(i, {'state':'not-started'})
    def _read(self, key): return self.documents.get(key)
    def _append(self, key, value): self.documents[key] = value
    def intent(self, i):
        if i in self.states: return False
        self.states[i] = {'state':'unknown'}
        return True
    def confirm(self, i, evidence): self.states[i] = {'state':'confirmed', 'evidence':evidence}


class ApplyTests(unittest.TestCase):
    def setUp(self):
        FakeReceipt.states = {}; FakeReceipt.documents = {}

    def test_nonroot_refused_before_observer(self):
        with patch('uas.local_host_apply.os.geteuid', return_value=1000), \
             patch('uas.local_host_apply.inspect', side_effect=AssertionError('must not observe')):
            with self.assertRaisesRegex(HostProfileError, 'ROOT_REQUIRED'): apply(selected())

    def test_unsupported_allocation_refused_before_effects(self):
        o=observation();o['storage']['filesystem']='btrfs'
        p=selected(o=o,allocation_bytes=1024**3)
        with patch('uas.local_host_apply.os.geteuid', return_value=0), \
             patch('uas.local_host_apply.owned_directory', side_effect=AssertionError('effect forbidden')):
            with self.assertRaisesRegex(HostProfileError, 'UNSUPPORTED_OPERATION'): apply(p)

    def test_selected_engine_profile_reaches_exact_observer(self):
        for field,value in (('socket','/run/another.sock'),('exec_root','/run/another'),
                            ('data_root','/var/lib/another')):
            doc=profile();doc['engine'][field]=value
            o=observation()
            if field=='data_root':o['engine']['docker_root']=value+'/100000.100000'
            p=selected(p=doc,o=o)
            with patch('uas.local_host_apply.os.geteuid',return_value=0), \
                 patch('uas.local_host_apply.inspect',side_effect=RuntimeError('selected observer')) as observe:
                with self.assertRaisesRegex(RuntimeError,'selected observer'):apply(p)
                self.assertEqual(observe.call_args.args[0],doc)

    def test_unintegrated_mapping_refused_before_observer(self):
        doc=profile();doc['mapping']['offset']=200000
        o=observation();o['subuid']=[doc['mapping']];o['subgid']=[doc['mapping']]
        o['engine']['docker_root']='/var/lib/docker/200000.200000'
        p=selected(p=doc,o=o)
        with patch('uas.local_host_apply.os.geteuid',return_value=0), \
             patch('uas.local_host_apply.inspect',side_effect=AssertionError('must not observe')):
            with self.assertRaisesRegex(HostProfileError,'PROFILE_INTEGRATION_REQUIRED'):apply(p)

    def test_fake_first_apply_then_confirmed_resume(self):
        evidence={'identity':[3,22],'observed_sha256':'b'*64}
        with patch('uas.local_host_apply.os.geteuid', return_value=0), \
             patch('uas.local_host_apply.os.path.lexists', return_value=False) as exists, \
             patch('uas.local_host_apply.inspect', return_value=observation()), \
             patch('uas.local_host_apply.owned_directory', return_value=evidence) as directory, \
             patch('uas.local_host_apply.PreparationReceipt', FakeReceipt), \
             patch('uas.local_host_apply.fcntl.flock'):
            result=apply(selected())
            self.assertEqual(result['status'],'owned-directories-prepared')
            self.assertFalse(result['native_ready'])
            self.assertEqual([c.kwargs['create'] for c in directory.call_args_list], [True,True,True])
            directory.reset_mock();exists.return_value=True
            self.assertEqual(apply(selected()),result)
            self.assertTrue(all(not c.kwargs['create'] for c in directory.call_args_list))
            self.assertTrue(all(not c.kwargs.get('repair_partial',False) for c in directory.call_args_list))

    def test_fake_unknown_operation_reconciles_not_recreates(self):
        p=selected();FakeReceipt.documents['observations.json']=observation()
        FakeReceipt.states[0]={'state':'unknown'}
        evidence={'identity':[3,22],'observed_sha256':'b'*64}
        with patch('uas.local_host_apply.os.geteuid', return_value=0), \
             patch('uas.local_host_apply.os.path.lexists', return_value=True), \
             patch('uas.local_host_apply.inspect', return_value=observation()), \
             patch('uas.local_host_apply.owned_directory', return_value=evidence) as directory, \
             patch('uas.local_host_apply.PreparationReceipt', FakeReceipt), \
             patch('uas.local_host_apply.fcntl.flock'):
            apply(p)
            first=directory.call_args_list[1]
            self.assertFalse(first.kwargs['create'])
            self.assertTrue(first.kwargs['repair_partial'])

    def test_fake_resume_changed_host_refused(self):
        FakeReceipt.documents['observations.json']=observation()
        o=observation();o['storage']['identity']=[5,99]
        with patch('uas.local_host_apply.os.geteuid', return_value=0), \
             patch('uas.local_host_apply.os.path.lexists', return_value=True), \
             patch('uas.local_host_apply.inspect', return_value=o), \
             patch('uas.local_host_apply.owned_directory') as directory, \
             patch('uas.local_host_apply.PreparationReceipt', FakeReceipt):
            with self.assertRaisesRegex(HostProfileError, 'HOST_DRIFT'): apply(selected())
            self.assertEqual(directory.call_count,1) # Receipt ownership only.


class OwnedDirectoryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.parent=Path(self.temp.name);self.parent.chmod(0o700)
        self.path=self.parent/'owned'
        self.args=dict(plan_id='a'*64,operation='prepare-owned-xfs-tree',
                       owner_uid=os.getuid(),mode=0o711)
        # This bypass is for the ordinary tempfile helper test only. The real
        # observer refuses writable /tmp ancestors; apply itself is never run.
        self.check=patch('uas.local_host_apply.canonical_node',lambda p:Path(p).stat())
        self.check.start();self.addCleanup(self.check.stop)

    def test_create_reconcile_preserves_human_file(self):
        value=owned_directory(self.path,create=True,**self.args)
        (self.path/'human.txt').write_text('keep')
        self.assertEqual(owned_directory(self.path,create=False,**self.args),value)
        self.assertEqual((self.path/'human.txt').read_text(),'keep')
        with self.assertRaises(FileExistsError): owned_directory(self.path,create=True,**self.args)

    def test_foreign_tree_never_adopted(self):
        self.path.mkdir();(self.path/'human.txt').write_text('keep');self.path.chmod(0o711)
        with self.assertRaises(FileNotFoundError): owned_directory(self.path,create=False,**self.args)
        self.assertEqual((self.path/'human.txt').read_text(),'keep')

    def test_identity_marker_and_symlink_refusal(self):
        owned_directory(self.path,create=True,**self.args)
        marker=self.path/'.uas-preparation.json';marker.write_text('{}')
        with self.assertRaisesRegex(HostProfileError,'MARKER'): owned_directory(self.path,create=False,**self.args)
        alias=self.parent/'alias';alias.symlink_to(self.path)
        with self.assertRaises(OSError): owned_directory(alias,create=False,**self.args)

    def test_interrupted_mode_change_only_after_marker(self):
        expected=owned_directory(self.path,create=True,**self.args)
        self.path.chmod(0o700)
        with self.assertRaisesRegex(HostProfileError,'OWNER'): owned_directory(self.path,create=False,**self.args)
        self.assertEqual(owned_directory(self.path,create=False,repair_partial=True,**self.args),expected)
        self.assertEqual(self.path.stat().st_mode&0o777,0o711)

    def test_storage_parent_identity_checked_before_mkdir(self):
        identity=[self.parent.stat().st_dev,self.parent.stat().st_ino]
        for bad in ([identity[0]+1,identity[1]],[identity[0],identity[1]+1]):
            with self.assertRaisesRegex(HostProfileError,'STORAGE_PARENT_CHANGED'):
                owned_directory(self.path,create=True,expected_parent_identity=bad,**self.args)
            self.assertFalse(self.path.exists())
        value=owned_directory(self.path,create=True,expected_parent_identity=identity,**self.args)
        self.assertEqual(value['identity'][0],identity[0])

    def test_actual_create_fault_cutpoints_preserve_unknown_directory(self):
        original_fsync=os.fsync
        # Order: parent fsync, marker fsync, complete-directory fsync.
        for cut in (1,2,3):
            target=self.parent/('cut'+str(cut));calls=[]
            def fail(fd):
                calls.append(fd)
                if len(calls)==cut:raise OSError('injected fsync loss')
                return original_fsync(fd)
            with patch('uas.local_host_apply.os.fsync',side_effect=fail):
                with self.assertRaises(OSError):owned_directory(target,create=True,**self.args)
            self.assertTrue(target.exists())
            if cut==1:
                # mkdir happened, no marker exists: unknown is not ownership.
                self.assertFalse((target/'.uas-preparation.json').exists())
                with self.assertRaises(FileNotFoundError):
                    owned_directory(target,create=False,repair_partial=True,**self.args)
                self.assertEqual(list(target.iterdir()),[])
            else:
                # Exact complete marker is present; replay safely reobserves it.
                evidence=owned_directory(target,create=False,repair_partial=True,**self.args)
                self.assertEqual(evidence['identity'],[target.stat().st_dev,target.stat().st_ino])
                self.assertEqual(target.stat().st_mode&0o777,0o711)

    def test_fchmod_failure_repairs_only_matching_marker(self):
        with patch('uas.local_host_apply.os.fchmod',side_effect=OSError('injected mode loss')):
            with self.assertRaises(OSError):owned_directory(self.path,create=True,**self.args)
        self.assertEqual(self.path.stat().st_mode&0o777,0o700)
        marker=self.path/'.uas-preparation.json';raw=marker.read_bytes()
        marker.write_text('{}')
        with self.assertRaisesRegex(HostProfileError,'MARKER'):
            owned_directory(self.path,create=False,repair_partial=True,**self.args)
        self.assertEqual(self.path.stat().st_mode&0o777,0o700)
        marker.write_bytes(raw)
        owned_directory(self.path,create=False,repair_partial=True,**self.args)
        self.assertEqual(self.path.stat().st_mode&0o777,0o711)


if __name__=='__main__':unittest.main()
