"""Pure partition/inventory tests; never discover or run the repository suite."""
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import Mock, patch


spec = importlib.util.spec_from_file_location('reviewed_ci_unit', Path(__file__).with_name('ci_unit.py'))
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)


def case(identifier):
    item = unittest.FunctionTestCase(lambda: None)
    item.id = lambda: identifier
    item.run = Mock(side_effect=AssertionError('selection must not run tests'))
    return item


class CIPartitionTests(unittest.TestCase):
    def test_fixed_measured_modules_and_every_future_module_default_to_remainder(self):
        self.assertEqual(ci.SLOW_MODULES, {'test_artifact_manual_source',
 'test_artifact_native_source',
 'test_checkouts',
 'test_claude_permission_policy',
 'test_forge_mutations',
 'test_gate_evaluation',
 'test_library_repair_native',
 'test_library_dispatch',
 'test_library_import',
 'test_participant_pi_launch',
 'test_peer',
 'test_peer_delivery_phases',
 'test_review_hosted',
 'test_room_control_plane',
 'test_run_review',
 'test_workstation_control',
 'test_workstation_peer'})
        self.assertEqual(ci.INTEGRATION_MODULES, {'test_command_native_source',
 'test_diff_native',
 'test_forge_assignment',
 'test_forge_projections',
 'test_forge_read_process',
 'test_gate_forge_hub',
 'test_ledger',
 'test_library_enqueue',
 'test_library_registration',
 'test_manager_action_host',
 'test_native_completed_reviewer_reset',
 'test_native_gate_completion',
 'test_native_reviewer_recruitment_adversarial',
 'test_native_reviewer_reset_adversarial',
 'test_native_session_driver',
 'test_native_session_human_actions',
 'test_native_trust',
 'test_participant',
 'test_run_admission'})
        self.assertEqual(ci.ADDITIONAL_MODULES, {'test_artifact_connected',
 'test_exec_state',
 'test_forge_capacity',
 'test_forge_mutation_audit',
 'test_forge_reconciliation',
 'test_gate_diff_hub',
 'test_library_git',
 'test_library_observations',
 'test_library_projection',
 'test_library_settings',
 'test_lifecycle',
 'test_local_room_prepare',
 'test_local_three_runs',
 'test_manager_read_model',
 'test_native_broker_audit_source',
 'test_native_claude_checks',
 'test_native_combined_image_package',
 'test_native_git_operations',
 'test_room_cli_diagnostics',
 'test_workstation_delivery'})
        self.assertEqual(ci.INSPECTION_MODULES, {'test_library_hub', 'test_library_inspection', 'test_library_relocation'})
        self.assertEqual(ci.SYNTHESIS_MODULES, {'test_context',
 'test_claude_participant_source',
 'test_claude_ci_cache',
 'test_library_attempts',
 'test_native_pi_reset_adversarial',
 'test_staged_source_closure'})
        self.assertEqual(ci.OPERATOR_MODULES, {'test_library_controls', 'test_git_payload', 'test_library_deployment'})
        self.assertEqual(ci.LIFECYCLE_MODULES, {'test_library_attention', 'test_library_records',
 'test_library_service', 'test_manager_library_transport',
 'test_local_library_wiring', 'test_local_library_model', 'test_local_library_transport'})
        self.assertEqual(ci.DISPOSITION_MODULES, {'test_library_retention',
 'test_library_adjudication',
 'test_library_adjudication_native',
 'test_library_adjudication_recovery',
 'test_library_disposition',
 'test_library_disposition_native'})
        self.assertEqual(ci.ARCHIVE_MODULES, {'test_host_capacity', 'test_library_promotion', 'test_local_native_terminal',
 'test_library_capture_frames', 'test_native_completed_retirement', 'test_library_archive_integration',
 'test_library_archive_native'})
        self.assertEqual('scheduler', ci.partition_for('test_library_disposition_recovery.Case.test_one'))
        self.assertEqual('maintenance', ci.partition_for('test_library_archive.Case.test_one'))
        self.assertEqual(ci.MAINTENANCE_MODULES, {'test_library_repair',
 'test_library_requeue', 'test_library_archive'})
        for module in ('test_local_library_wiring', 'test_local_library_model', 'test_local_library_transport'):
            self.assertEqual('lifecycle', ci.partition_for(module + '.Case.test_one'))
        self.assertEqual('operator', ci.partition_for('test_library_deployment.Case.test_one'))
        self.assertEqual('maintenance', ci.partition_for('test_library_repair.Case.test_one'))
        self.assertEqual('maintenance', ci.partition_for('test_library_requeue.Case.test_one'))
        self.assertEqual('operator', ci.partition_for('test_library_controls.Case.test_one'))
        self.assertEqual('inspection', ci.partition_for('test_library_inspection.Case.test_one'))
        workflow=(Path(__file__).resolve().parents[1]/'.github/workflows/verify.yaml').read_text()
        self.assertIn('- {partition: inspection, name: unit-inspection}', workflow)
        matrix=workflow.split('  unit-integration:',1)[1].split('  forge-broker-smoke:',1)[0]
        self.assertEqual(matrix.count('- {partition:'), 10)
        self.assertNotIn('needs:', matrix)
        self.assertEqual(ci.SCHEDULER_MODULES, {'test_library_scheduler', 'test_library_assembly',
 'test_library_disposition_recovery'})
        self.assertEqual('scheduler', ci.partition_for('test_library_scheduler.Case.test_one'))
        self.assertEqual('synthesis', ci.partition_for('test_library_attempts.Case.test_one'))
        self.assertFalse(ci.SLOW_MODULES & ci.INTEGRATION_MODULES)
        self.assertFalse(ci.ADDITIONAL_MODULES & (ci.SLOW_MODULES | ci.INTEGRATION_MODULES))
        for module in ci.ADDITIONAL_MODULES:
            self.assertEqual('additional', ci.partition_for(module + '.Case.test_one'))
        for module in ci.INTEGRATION_MODULES:
            self.assertEqual('integration', ci.partition_for(module + '.Case.test_one'))
        for module in ci.SLOW_MODULES:
            self.assertEqual('slow', ci.partition_for(module + '.Case.test_one'))
        for name in ('test_new_future.Case.test_one', 'test_git_new.Case.test_one',
                     'package.test_peer.Case.test_one', 'test_peer_future.Case.test_one'):
            self.assertEqual('remainder', ci.partition_for(name))

    def test_nested_standard_suite_is_complete_disjoint_and_never_executed_for_selection(self):
        slow, future = case('test_peer.Case.test_one'), case('test_future.Case.test_one')
        cases, groups = ci.partition_suite(unittest.TestSuite([unittest.TestSuite([slow]), future]))
        self.assertEqual([slow, future], cases)
        self.assertEqual({'archive': [], 'maintenance': [], 'lifecycle': [], 'disposition': [], 'inspection': [], 'operator': [], 'slow': [slow], 'integration': [], 'additional': [], 'scheduler': [], 'synthesis': [],
                          'remainder': [future]}, groups)
        slow.run.assert_not_called(); future.run.assert_not_called()

    def test_rebalanced_modules_each_run_once_without_changing_total_inventory(self):
        identifiers = [module + '.Case.test_one' for module in sorted(
            ci.ARCHIVE_MODULES | ci.MAINTENANCE_MODULES | ci.LIFECYCLE_MODULES | ci.DISPOSITION_MODULES | ci.SLOW_MODULES | ci.INTEGRATION_MODULES | ci.ADDITIONAL_MODULES | ci.SYNTHESIS_MODULES | ci.SCHEDULER_MODULES | ci.OPERATOR_MODULES | ci.INSPECTION_MODULES)]
        identifiers += ['test_future.Case.test_one', 'test_ci_partitions.Case.test_one']
        selected = [case(identifier) for identifier in identifiers]
        cases, groups = ci.partition_suite(unittest.TestSuite(selected))
        self.assertEqual([item.id() for item in cases], identifiers)
        self.assertEqual(len(groups['slow']), 17)
        self.assertEqual(len(groups['integration']), 19)
        self.assertEqual(len(groups['additional']), 20)
        self.assertEqual(len(groups['synthesis']), 6)
        self.assertEqual(len(groups['scheduler']), 3)
        self.assertEqual(len(groups['operator']), 3)
        self.assertEqual(len(groups['inspection']), 3)
        self.assertEqual(len(groups['lifecycle']), 7)
        self.assertEqual(len(groups['disposition']), 6)
        self.assertEqual(len(groups['maintenance']), 3)
        self.assertEqual(len(groups['archive']), 7)
        self.assertEqual(len(groups['remainder']), 2)
        self.assertEqual(sorted(item.id() for group in groups.values() for item in group),
                         sorted(identifiers))
        for item in selected:
            item.run.assert_not_called()

    def test_claude_source_and_cache_modules_move_whole_without_other_reassignment(self):
        moved = ['test_claude_participant_source.Native.test_current',
                 'test_claude_participant_source.Future.test_new',
                 'test_claude_ci_cache.Cache.test_current',
                 'test_claude_ci_cache.Future.test_new']
        untouched = ['test_claude_new.Future.test_new', 'test_future.Case.test_one']
        ids = moved + untouched
        cases, groups = ci.partition_suite(unittest.TestSuite(case(name) for name in ids))
        self.assertEqual(moved, [item.id() for item in groups['synthesis']])
        self.assertEqual(untouched, [item.id() for item in groups['remainder']])
        self.assertEqual(ids, [item.id() for item in cases])
        self.assertEqual(sorted(ids), sorted(item.id() for group in groups.values() for item in group))
        for item in cases:
            item.run.assert_not_called()

    def test_retention_moves_whole_to_disposition_without_other_reassignment(self):
        moved = ['test_library_retention.Retention.test_current',
                 'test_library_retention.Future.test_new']
        maintenance = ['test_library_repair.Case.test_current',
                       'test_library_requeue.Case.test_current']
        untouched = ['test_library_retention_future.Future.test_new']
        ids = moved + maintenance + untouched
        cases, groups = ci.partition_suite(unittest.TestSuite(case(name) for name in ids))
        self.assertEqual(moved, [item.id() for item in groups['disposition']])
        self.assertEqual(maintenance, [item.id() for item in groups['maintenance']])
        self.assertEqual(untouched, [item.id() for item in groups['remainder']])
        self.assertEqual(ids, [item.id() for item in cases])
        self.assertEqual(sorted(ids), sorted(item.id() for group in groups.values() for item in group))
        for item in cases:
            item.run.assert_not_called()

    def test_measured_headroom_moves_whole_modules_without_other_reassignment(self):
        archive_modules = ('test_host_capacity', 'test_library_promotion',
                           'test_local_native_terminal', 'test_library_capture_frames',
                           'test_native_completed_retirement')
        archive = [module + suffix for module in archive_modules
                   for suffix in ('.Case.test_current', '.Future.test_new')]
        slow = ['test_library_repair_native.Native.test_current',
                'test_library_repair_native.Future.test_new']
        remainder = ['test_host_capacity_future.Future.test_new']
        ids = archive + slow + remainder
        cases, groups = ci.partition_suite(unittest.TestSuite(case(name) for name in ids))
        self.assertEqual(archive, [item.id() for item in groups['archive']])
        self.assertEqual(slow, [item.id() for item in groups['slow']])
        self.assertEqual(remainder, [item.id() for item in groups['remainder']])
        self.assertEqual(sorted(ids), sorted(item.id() for group in groups.values() for item in group))
        for item in cases:
            item.run.assert_not_called()

    def test_archive_hot_modules_move_whole_to_existing_parallel_lanes(self):
        assignments = {'test_library_archive': 'maintenance',
                       'test_library_disposition_recovery': 'scheduler',
                       'test_library_archive_native': 'archive',
                       'test_library_archive_integration': 'archive',
                       'test_library_archive_future': 'remainder'}
        ids = [module + suffix for module in assignments
               for suffix in ('.Current.test_case', '.Future.test_added')]
        cases, groups = ci.partition_suite(unittest.TestSuite(case(name) for name in ids))
        for identifier in ids:
            expected = assignments[identifier.split('.', 1)[0]]
            self.assertEqual(expected, ci.partition_for(identifier))
            self.assertEqual(1, sum(item.id() == identifier for group in groups.values() for item in group))
        self.assertEqual(ids, [item.id() for item in cases])
        for item in cases:
            item.run.assert_not_called()

    def test_duplicate_ids_are_rejected_even_for_different_case_objects(self):
        with self.assertRaises(ValueError):
            ci.partition_suite(unittest.TestSuite([case('test_peer.Case.test_one'),
                                                   case('test_peer.Case.test_one')]))

    def test_missing_extra_duplicate_misplaced_or_unknown_partition_ids_refuse(self):
        slow, rest = 'test_peer.Case.test_one', 'test_future.Case.test_one'
        invalid = [({'slow': [], 'remainder': [rest]}),
                   ({'slow': [slow], 'remainder': [rest, 'test_other.Case.test_one']}),
                   ({'slow': [slow, slow], 'remainder': [rest]}),
                   ({'slow': [rest], 'remainder': [slow]}),
                   ({'slow': [slow], 'remainder': [rest], 'extra': []})]
        for groups in invalid:
            with self.subTest(groups=groups), self.assertRaises(ValueError):
                ci.verify_partition_ids([slow, rest], dict(archive=[], maintenance=[], lifecycle=[], disposition=[], inspection=[], integration=[], additional=[], synthesis=[], scheduler=[], operator=[], **groups))
        integration = 'test_participant.Case.test_one'
        additional = 'test_local_three_runs.Case.test_one'
        valid = {'archive': [], 'maintenance': [], 'lifecycle': [], 'disposition': [], 'inspection': [], 'operator': [], 'slow': [slow], 'integration': [integration],
                 'additional': [additional], 'scheduler': [], 'synthesis': [], 'remainder': [rest]}
        ci.verify_partition_ids([slow, integration, additional, rest], valid)
        for broken in ({'slow': [slow], 'remainder': [rest]},
                       dict(valid, integration=[]),
                       dict(valid, integration=[integration, integration]),
                       dict(valid, integration=[rest], remainder=[integration]),
                       dict(valid, additional=[]),
                       dict(valid, additional=[additional, additional])):
            with self.subTest(groups=broken), self.assertRaises(ValueError):
                ci.verify_partition_ids([slow, integration, additional, rest], broken)
        with self.assertRaises(ValueError):
            list(ci.leaves([object()]))

    def test_main_uses_full_standard_discovery_and_exact_requested_partition(self):
        for partition in ('all', *ci.PARTITIONS):
            slow, rest = case('test_peer.Case.test_one'), case('test_future.Case.test_one')
            integration = case('test_participant.Case.test_one')
            additional = case('test_local_three_runs.Case.test_one')
            inspection = case('test_library_inspection.Case.test_one')
            operator = case('test_library_controls.Case.test_one')
            scheduler = case('test_library_scheduler.Case.test_one')
            synthesis = case('test_library_attempts.Case.test_one')
            lifecycle = case('test_library_service.Case.test_one')
            disposition = case('test_library_adjudication.Case.test_one')
            maintenance = case('test_library_repair.Case.test_one')
            archive = case('test_library_archive_native.Case.test_one')
            loader = Mock(errors=[], discover=Mock(return_value=unittest.TestSuite(
                [archive, maintenance, lifecycle, disposition, slow, integration, additional, synthesis, scheduler, operator, inspection, rest])))
            runner = Mock()
            runner.run.return_value.wasSuccessful.return_value = True
            with patch.object(ci.unittest, 'TestLoader', return_value=loader), \
                    patch.object(ci.unittest, 'TextTestRunner', return_value=runner), \
                    patch.object(ci.sys, 'path', list(ci.sys.path)), redirect_stdout(io.StringIO()):
                self.assertEqual(0, ci.main([partition]))
            loader.discover.assert_called_once_with(str(Path(__file__).resolve().parent), pattern='test*.py')
            self.assertEqual(list(runner.run.call_args.args[0]),
                             [archive, maintenance, lifecycle, disposition, slow, integration, additional, synthesis, scheduler, operator, inspection, rest] if partition == 'all' else {
                                 'archive': [archive], 'maintenance': [maintenance], 'lifecycle': [lifecycle], 'disposition': [disposition], 'inspection': [inspection], 'operator': [operator], 'slow': [slow], 'integration': [integration],
                                 'additional': [additional], 'synthesis': [synthesis], 'scheduler': [scheduler], 'remainder': [rest]}[partition])
            for item in (archive, maintenance, lifecycle, disposition, slow, integration, additional, synthesis, scheduler, operator, inspection, rest):
                item.run.assert_not_called()

    def test_discovery_and_selected_test_failures_are_required_failures(self):
        loader = Mock(errors=['fixture import failure'])
        with patch.object(ci.unittest, 'TestLoader', return_value=loader), \
                patch.object(ci.unittest, 'TextTestRunner') as runner, \
                patch.object(ci.sys, 'path', list(ci.sys.path)), redirect_stderr(io.StringIO()):
            self.assertEqual(1, ci.main(['slow']))
        runner.assert_not_called()
        loader.errors = []
        loader.discover.return_value = unittest.TestSuite([case('test_peer.Case.test_one'),
                                                          case('test_future.Case.test_one'), case('test_participant.Case.test_one'),
                                                          case('test_local_three_runs.Case.test_one'), case('test_library_attempts.Case.test_one'), case('test_library_scheduler.Case.test_one'), case('test_library_controls.Case.test_one'), case('test_library_inspection.Case.test_one'), case('test_library_service.Case.test_one'), case('test_library_adjudication.Case.test_one'), case('test_library_repair.Case.test_one'), case('test_library_archive_native.Case.test_one')])
        runner = Mock(); runner.run.return_value.wasSuccessful.return_value = False
        with patch.object(ci.unittest, 'TestLoader', return_value=loader), \
                patch.object(ci.unittest, 'TextTestRunner', return_value=runner), \
                patch.object(ci.sys, 'path', list(ci.sys.path)), redirect_stdout(io.StringIO()):
            self.assertEqual(1, ci.main(['remainder']))
