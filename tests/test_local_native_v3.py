"""Versioned owned-XFS identities; no mount, format, host command or probe."""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace as N
import stat
import unittest
from unittest.mock import patch
from uas import local_native as local, local_prepare as prepare, local_xfs_storage as xfs
from uas.lifecycle import LifecycleError
from uas.local_host_profile import HostProfileError
from tests.test_local_native import selections
from tests.test_local_host_plan import profile as host_profile


def selected():
    config,doc=selections();config['deployment']={'state_root':'/srv/uas/control'}
    doc.update(version=3,profile='local-native-v3',host_profile=host_profile(),
        owned_xfs={'receipt_root':'/srv/uas-receipt','plan_id':'a'*64,
            'image_identity':[1,22],'uuid':'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'})
    row=doc['rooms']['room'];row['root_identity'][0]=0
    for record in row['paths'].values():record['identity'][0]=0
    return config,doc


class LocalNativeV3Tests(unittest.TestCase):
    def setUp(self):
        self.config,self.doc=selected()
        self.mount={'identity':[99,2],'image_identity':[1,22]}
    def profile(self):return local.LocalNativeProfile(self.config,self.doc,'room','/srv/uas/control')
    def settings(self):
        result=deepcopy(self.doc);result.pop('profile')
        result['rooms']={key:{k:row[k] for k in ('quota_project_id','mcs_level','subnet','gateway')}
                         for key,row in result['rooms'].items()}
        return result
    def observed(self,device=99):
        rows={self.doc['storage_root']:[device,2],self.doc['endpoints_root']:[777,3]}
        rows.update({v['path']:[device,v['identity'][1]] for v in self.doc['rooms']['room']['paths'].values()})
        return lambda value:rows[str(value)][:]
    def assemble(self,observer):
        row=self.doc['rooms']['room']
        return prepare.assemble(self.config,self.settings(),row['workstation'],row['hub'],observe=observer)
    def test_v3_shape_is_exact_and_cannot_silently_normalize_legacy_identity(self):
        for field,value in [('receipt_root','/srv/uas/receipts'),('plan_id','x'*64),
                            ('image_identity',[True,22]),('image_identity',[1,0]),
                            ('uuid','not-a-uuid'),('uuid','AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA')]:
            doc=deepcopy(self.doc);doc['owned_xfs'][field]=value
            with self.subTest(field=field,value=value),self.assertRaises(LifecycleError):local.validate_document(doc)
        for identity in ([1,2],[0,0],[False,2]):
            doc=deepcopy(self.doc);doc['rooms']['room']['root_identity']=identity
            with self.assertRaises(LifecycleError):local.validate_document(doc)
        for version in (1,2):
            doc=deepcopy(self.doc);doc.update(version=version,profile='local-native-v'+str(version))
            with self.assertRaises(LifecycleError):local.validate_document(doc)
    def test_assemble_is_stable_across_mount_device_change_only_after_verification(self):
        with patch.object(xfs,'verify_owned_mount',return_value=self.mount,create=True) as verify:
            first=self.assemble(self.observed());verify.assert_called_once_with(self.doc['owned_xfs'],Path('/srv/uas'))
        self.mount['identity'][0]=100
        with patch.object(xfs,'verify_owned_mount',return_value=self.mount,create=True):
            second=self.assemble(self.observed(100))
        self.assertEqual(first,second)
        a=local.LocalNativeProfile(self.config,first,'room','/srv/uas/control')
        b=local.LocalNativeProfile(self.config,second,'room','/srv/uas/control')
        self.assertEqual(a.digest,b.digest);self.assertEqual(a.spec(),b.spec())
    def test_assemble_refuses_foreign_device_changed_image_or_root_inode(self):
        for changed in ({'identity':[99,3],'image_identity':[1,22]},
                        {'identity':[99,2],'image_identity':[1,23]},
                        {'identity':[100,2],'image_identity':[1,22]}):
            with patch.object(xfs,'verify_owned_mount',return_value=changed,create=True),self.assertRaises(ValueError):
                self.assemble(self.observed())
        observer=self.observed()
        def foreign(name):return [100,3] if name.endswith('/repo') else observer(name)
        with patch.object(xfs,'verify_owned_mount',return_value=self.mount,create=True),self.assertRaises(ValueError):
            self.assemble(foreign)
    def test_runtime_identity_reverifies_mount_each_time_and_rejects_foreignfs(self):
        profile=self.profile()
        with patch.object(xfs,'verify_owned_mount',return_value=self.mount,create=True) as verify,patch.object(local.native,'directory_identity',return_value=[99,3]):
            self.assertEqual(profile.storage_identity('/srv/uas/project/repo'),[0,3])
            self.assertEqual(profile.storage_identity('/srv/uas/project/repo'),[0,3]);self.assertEqual(verify.call_count,2)
        with patch.object(xfs,'verify_owned_mount',return_value=self.mount,create=True),patch.object(local.native,'directory_identity',return_value=[100,3]),self.assertRaisesRegex(LifecycleError,'LOCAL_NATIVE_STORAGE_FILESYSTEM'):
            profile.storage_identity('/srv/uas/project/repo')
    def test_runtime_refuses_verifier_wrong_uuid_image_or_root_inode(self):
        profile=self.profile()
        with patch.object(xfs,'verify_owned_mount',side_effect=HostProfileError('XFS_FORMAT_UNKNOWN'),create=True),self.assertRaises(HostProfileError):
            profile.storage_identity('/srv/uas')
        for changed in ({'identity':[99,2],'image_identity':[1,23]}, {'identity':[99,3],'image_identity':[1,22]}):
            with patch.object(xfs,'verify_owned_mount',return_value=changed,create=True),self.assertRaises(LifecycleError):
                profile.storage_identity('/srv/uas')
    def test_mutated_selection_and_external_path_refused_before_verifier(self):
        for mutate in (False,True):
            profile=self.profile()
            if mutate:profile.native_document['owned_xfs']['uuid']='b'*36
            with patch.object(xfs,'verify_owned_mount',create=True) as verify,self.assertRaises(LifecycleError):
                profile.storage_identity('/foreign' if not mutate else '/srv/uas')
            verify.assert_not_called()
    def test_legacy_profile_and_qualification_keep_exact_device_identity(self):
        config,doc=selections();legacy=local.LocalNativeProfile(config,doc,'room','/srv/uas/control')
        doc.update(version=2,profile='local-native-v2',host_profile=host_profile())
        legacy2=local.LocalNativeProfile(config,doc,'room','/srv/uas/control')
        qualification=object.__new__(local.native.NativeBoundaryProfile)
        with patch.object(xfs,'verify_owned_mount',create=True) as verify,patch.object(local.native,'directory_identity',return_value=[99,3]):
            self.assertEqual(legacy.storage_identity('/srv/uas/project/repo'),[99,3])
            self.assertEqual(legacy2.storage_identity('/srv/uas/project/repo'),[99,3])
            self.assertEqual(qualification.storage_identity('/srv/uas/project/repo'),[99,3])
            verify.assert_not_called()
    def test_inherited_storage_observer_uses_stable_identity_and_rejects_path_inode_change(self):
        profile=self.profile();observer=self.observed()
        def stat_node(path):
            path=str(path);runtime=path in profile.paths.values()
            return N(st_dev=99,st_ino=observer(path)[1] if path in profile.paths.values() or path=='/srv/uas' else 9,
                     st_uid=165532 if runtime else 0,st_gid=165532 if runtime else 0,
                     st_mode=stat.S_IFDIR|0o711)
        def command(*args,**kwargs):
            if args[:3]==('stat','-f','-c'):return 'xfs'
            if args[:3]==('stat','-c','%C'):return 'system_u:object_r:container_file_t:s0:c401,c402'
            if 'state -p' in args:return 'Accounting: ON\nEnforcement: ON'
            if 'report -p -b -n -N' in args:return '#401 0 0 10485760'
            name=args[-2].split(' -p ')[1].rsplit(' ',1)[0]
            return f'Checking project 401 (path {name})...\nProcessed 1 (/dev/null and cmdline) paths for project 401 with recursion depth infinite (-1).'
        with patch.object(profile,'guard'),patch.object(xfs,'verify_owned_mount',return_value=self.mount,create=True),patch.object(local.native,'directory_identity',side_effect=observer),patch.object(Path,'stat',stat_node),patch.object(local.native,'command',side_effect=command),patch.object(local.native,'project_attributes',return_value=(401,True)):
            self.assertTrue(profile.observe_storage())
            profile.boundary['paths']['repo']['identity']=[0,999]
            with self.assertRaisesRegex(LifecycleError,'PATH_IDENTITY'):profile.observe_storage()
