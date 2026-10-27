"""Explicit synthetic command work ownership tests, no mounts/native effects."""
from copy import deepcopy
import threading
import unittest
from unittest.mock import Mock, patch

from uas.artifact_protocol import ArtifactError
from uas import command_target as target

SCOPE = {'version': 1, 'evaluation_id': 'evaluation-a', 'room_id': 'alpha',
    'room_instance': 'instance-a', 'project_id': 'project-a', 'repository': 'org/repo',
    'run_id': 'run-a', 'generation': 1, 'participant_id': 'alice', 'policy_id': 'default',
    'policy_version': 1, 'policy_digest': 'a' * 64, 'gate_id': 'command', 'config_digest': 'b' * 64}
SOURCE = {'room_instance': 'instance-a', 'project_id': 'project-a', 'repository': 'org/repo',
    'run_id': 'run-a', 'participant_id': 'alice', 'slot_id': 'primary',
    'branch': 'refs/heads/feature', 'head_sha': 'd' * 40, 'source_digest': 'a' * 64}


class CommandTargetPureTests(unittest.TestCase):
    def owner(self):
        owner = object.__new__(target.CommandTargets)
        owner.owned = {}; owner._lock = threading.RLock()
        owner.targets = Mock(); owner.targets.owned = {}
        owner._save = Mock(); owner._root = Mock(return_value=41)
        return owner

    def test_missing_fresh_mount_admission_refuses_before_filesystem_access(self):
        owner = object.__new__(target.CommandTargets)
        owner.work_root = '/not-accessed'; owner.admit_work = Mock(return_value=False)
        with patch.object(target, '_open_dir') as opened, self.assertRaises(ArtifactError):
            owner._root()
        opened.assert_not_called()

    def test_capacity_failure_retains_attempt_without_work_allocation_or_retry(self):
        owner = self.owner()
        owner.targets.prepare.side_effect = ArtifactError('ARTIFACT_ROOM_CAPACITY_UNAVAILABLE')
        with patch.object(target.os, 'mkdir') as mkdir, self.assertRaises(ArtifactError):
            owner.prepare(deepcopy(SCOPE), deepcopy(SOURCE))
        mkdir.assert_not_called(); owner._root.assert_not_called()
        self.assertEqual(owner.owned['evaluation-a'].phase, 'quarantined')
        with self.assertRaises(ArtifactError):
            owner.prepare(deepcopy(SCOPE), deepcopy(SOURCE))
        self.assertEqual(owner.targets.prepare.call_count, 1)

    def test_partial_base_preparation_is_retained_for_exact_reconciliation(self):
        owner = self.owner(); partial = Mock()
        owner.targets.owned['evaluation-a'] = partial
        owner.targets.prepare.side_effect = ArtifactError('ARTIFACT_MATERIALIZATION_TIMEOUT')
        with self.assertRaises(ArtifactError):
            owner.prepare(deepcopy(SCOPE), deepcopy(SOURCE))
        self.assertIs(owner.owned['evaluation-a'].base, partial)
        partial.cleanup.return_value = True
        self.assertTrue(owner.reconcile('evaluation-a')['cleanup'])
        partial.cleanup.assert_called_once()

    def test_uncertain_launch_cannot_cleanup_from_observer_exit_claim(self):
        owner = self.owner(); lease = target.CommandTargetLease(owner, 'evaluation-a', SOURCE)
        lease.base = Mock(); lease.launch_possible = True
        owner.owned['evaluation-a'] = lease
        self.assertFalse(owner.reconcile('evaluation-a')['cleanup'])
        lease.base.cleanup.assert_not_called(); owner._root.assert_not_called()
        with self.assertRaises(ArtifactError):
            lease.cleanup()

    def test_uncertain_work_creation_is_not_adopted_or_reported_removed(self):
        owner = self.owner(); lease = target.CommandTargetLease(owner, 'evaluation-a', SOURCE)
        lease.base = Mock(target_id='c' * 32); lease.work_create_possible = True
        with patch.object(target.os, 'stat', return_value=Mock()), patch.object(target.os, 'close'), self.assertRaises(ArtifactError):
            lease.cleanup()
        self.assertEqual(lease.phase, 'quarantined')
        lease.base.cleanup.assert_not_called()

    def test_unconfirmed_work_identity_or_nonempty_work_never_removes_base(self):
        for failure in ('identity', 'nonempty'):
            owner = self.owner(); lease = target.CommandTargetLease(owner, 'evaluation-a', SOURCE)
            lease.base = Mock(target_id='c' * 32); lease.work_identity = [2, 3]
            lease._work = Mock(side_effect=ArtifactError('COMMAND_WORK_IDENTITY_CHANGED') if failure == 'identity' else None,
                               return_value=42)
            with patch.object(target.os, 'listdir', return_value=['unremoved']), patch.object(target.os, 'close'), self.assertRaises(ArtifactError):
                lease.cleanup()
            lease.base.cleanup.assert_not_called()
            self.assertEqual(lease.phase, 'quarantined')

    def test_cleaned_work_does_not_rewrite_original_error_verdict(self):
        owner = self.owner(); lease = target.CommandTargetLease(owner, 'evaluation-a', SOURCE)
        lease.base = Mock(); lease.base.cleanup.return_value = True
        lease.phase = 'quarantined'; lease.launch_possible = lease.exit_confirmed = True
        self.assertTrue(lease.cleanup())
        self.assertEqual(lease.phase, 'removed')
        self.assertFalse(hasattr(lease, 'verdict'))
        self.assertTrue(lease.cleanup())
        lease.base.cleanup.assert_called_once()


if __name__ == '__main__':
    unittest.main()
