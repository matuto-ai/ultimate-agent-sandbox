"""Selected Gate host identity across launch and target ownership boundaries."""
from dataclasses import replace
from types import SimpleNamespace as N
import unittest
from unittest.mock import Mock, patch
from uas import artifact_helper as helper, artifact_target as target
from uas.artifact_protocol import ArtifactError
from uas.kernel_origin import Record
from tests.test_local_git_gate_identities import local_plan
from tests import test_artifact_helper as helper_fixture
from tests import test_artifact_target as target_fixture


class LocalArtifactIdentityTests(unittest.TestCase):
    def test_profile_is_validated_before_any_target_io(self):
        with self.assertRaisesRegex(ArtifactError, 'INVALID_GATE_HOST_PROFILE'):
            target.ArtifactTargets('/unused', '/unused', None,
                reserve_capacity=lambda *_: True, host_profile=N(offset=500000))
        host=local_plan().native_profile.host_profile
        with self.assertRaisesRegex(ArtifactError, 'INVALID_GATE_HOST_PROFILE'):
            helper.helper_host_identity(replace(host,size=1))
        self.assertEqual(helper.helper_host_identity(),(165530,165530))
        self.assertEqual(helper.helper_host_identity(host),(565530,565530))

    def test_bootstrap_origin_must_match_selected_uid_and_gid(self):
        for uid,gid,accepted in ((565530,565530,True),(165530,165530,False),(565530,165530,False)):
            with self.subTest(uid=uid,gid=gid):
                fixture=helper_fixture.ArtifactHelperPureTests();fixture.setUp()
                try:
                    launch=fixture.launch()
                    launch.workstation=replace(launch.workstation,host_profile=local_plan().native_profile.host_profile)
                    channel=Mock();channel.send.side_effect=lambda p:len(p)
                    listener=Mock();listener.accept.return_value=(channel,None)
                    record=Record(b'AGH1'+b'z'*32,(22,uid,gid),-1)
                    held=helper_fixture.origin();held.credentials=(22,uid,gid)
                    launch.engine.inspect.return_value={'ID':'9'*64,'ContainerID':'1'*64,'Running':True,'Pid':22}
                    with patch.object(helper,'enable'),patch.object(helper,'receive',return_value=record),patch.object(helper,'HeldOrigin',return_value=held),patch.object(helper,'alive',return_value=True),patch.object(helper.secrets,'token_bytes',return_value=b'z'*32):
                        if accepted:
                            launch.start(listener)
                            self.assertEqual(launch.state,'bound')
                            held.credentials=(22,165530,165530)
                            with self.assertRaisesRegex(ArtifactError,'GATE_EXEC_IDENTITY_UNVERIFIED'):
                                launch._inspect()
                        else:
                            with self.assertRaisesRegex(ArtifactError,'GATE_BOOTSTRAP_ORIGIN_MISMATCH'):
                                launch.start(listener)
                            self.assertIsNone(launch.origin)
                    launch.close()
                finally:fixture.tearDown()

    def test_target_prepare_selects_group_and_rejects_old_actual_group(self):
        fixture=target_fixture.TargetTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        scratch=fixture.root/'scratch';scratch.mkdir(mode=0o711)
        journals=fixture.root/'journals';journals.mkdir(mode=0o700)
        owner=target.ArtifactTargets(scratch,journals,fixture.resolver,
            reserve_capacity=lambda *_:True,host_profile=local_plan().native_profile.host_profile)
        scope={'version':1,'evaluation_id':'evaluation-a','room_id':'room-a','room_instance':'a'*32,
            'project_id':'project-a','repository':'owner/repo','run_id':'run-a','generation':1,
            'participant_id':'alice','policy_id':'policy-a','policy_version':1,'policy_digest':'b'*64,
            'gate_id':'gate-a','config_digest':'c'*64}
        source=fixture.resolve()
        with patch.object(target.os,'fchown') as chown, patch.object(target.os,'fstatvfs',return_value=N(f_frsize=4096,f_bsize=4096,f_bavail=1000000)):
            with self.assertRaisesRegex(ArtifactError,'ARTIFACT_HELPER_GROUP_UNAVAILABLE'):
                owner.prepare(scope,source)
        self.assertEqual(chown.call_args.args[1:],(-1,565530))

    def test_lease_recheck_rejects_changed_mapped_group(self):
        import os, stat
        fixture=target_fixture.TargetTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        lease=fixture.private_lease();lease.owner.helper_host_gid=565530
        real_fstat=os.fstat
        def observed(fd):
            node=real_fstat(fd)
            if (node.st_dev,node.st_ino)==tuple(lease.parent_identity):
                return N(st_dev=node.st_dev,st_ino=node.st_ino,st_uid=node.st_uid,
                         st_mode=stat.S_IFDIR|0o710,st_gid=group[0])
            return node
        group=[565530]
        with patch.object(target.os,'fstat',side_effect=observed):
            fd=lease._parent();os.close(fd)
            group[0]=165530
            with self.assertRaisesRegex(ArtifactError,'ARTIFACT_TARGET_OWNERSHIP_LOST'):
                lease._parent()
