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
        self.assertEqual(ci.SLOW_MODULES, {'test_library_dispatch', 'test_peer', 'test_checkouts',
                                          'test_gate_evaluation', 'test_forge_mutations',
                                          'test_artifact_manual_source',
                                          'test_run_review', 'test_staged_source_closure',
                                          'test_claude_permission_policy', 'test_artifact_native_source',
                          'test_workstation_control', 'test_peer_delivery_phases', 'test_participant_pi_launch', 'test_room_control_plane', 'test_workstation_peer', 'test_review_hosted'})
        self.assertEqual(ci.INTEGRATION_MODULES, {'test_library_assembly', 'test_context', 'test_library_registration',
            'test_native_pi_reset_adversarial', 'test_participant',
            'test_native_completed_reviewer_reset', 'test_native_reviewer_reset_adversarial',
            'test_command_native_source', 'test_forge_read_process', 'test_native_trust',
            'test_diff_native', 'test_gate_forge_hub', 'test_native_session_human_actions',
            'test_manager_action_host', 'test_forge_assignment',
    'test_native_reviewer_recruitment_adversarial', 'test_native_gate_completion', 'test_native_session_driver', 'test_ledger', 'test_run_admission', 'test_forge_projections'})
        self.assertEqual(ci.ADDITIONAL_MODULES, {
            'test_library_hub',
            'test_library_enqueue',
            'test_local_native_terminal', 'test_local_native_stop', 'test_local_three_runs',
            'test_library_git', 'test_library_projection', 'test_native_combined_image_package',
            'test_native_claude_checks', 'test_native_git_operations',
            'test_forge_mutation_audit', 'test_manager_read_model', 'test_library_records',
            'test_gate_diff_hub', 'test_artifact_connected', 'test_native_broker_audit_source',
            'test_local_room_prepare', 'test_forge_reconciliation', 'test_room_cli_diagnostics',
            'test_exec_state', 'test_workstation_delivery', 'test_lifecycle', 'test_forge_capacity',
        })
        self.assertEqual(ci.SYNTHESIS_MODULES, {'test_library_attempts', 'test_library_import'})
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
        self.assertEqual({'slow': [slow], 'integration': [], 'additional': [], 'synthesis': [],
                          'remainder': [future]}, groups)
        slow.run.assert_not_called(); future.run.assert_not_called()

    def test_rebalanced_modules_each_run_once_without_changing_total_inventory(self):
        identifiers = [module + '.Case.test_one' for module in sorted(
            ci.SLOW_MODULES | ci.INTEGRATION_MODULES | ci.ADDITIONAL_MODULES | ci.SYNTHESIS_MODULES)]
        identifiers += ['test_future.Case.test_one', 'test_ci_partitions.Case.test_one']
        selected = [case(identifier) for identifier in identifiers]
        cases, groups = ci.partition_suite(unittest.TestSuite(selected))
        self.assertEqual([item.id() for item in cases], identifiers)
        self.assertEqual(len(groups['slow']), 16)
        self.assertEqual(len(groups['integration']), 21)
        self.assertEqual(len(groups['additional']), 23)
        self.assertEqual(len(groups['synthesis']), 2)
        self.assertEqual(len(groups['remainder']), 2)
        self.assertEqual(sorted(item.id() for group in groups.values() for item in group),
                         sorted(identifiers))
        for item in selected:
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
                ci.verify_partition_ids([slow, rest], dict(integration=[], additional=[], synthesis=[], **groups))
        integration = 'test_context.Case.test_one'
        additional = 'test_local_native_terminal.Case.test_one'
        valid = {'slow': [slow], 'integration': [integration],
                 'additional': [additional], 'synthesis': [], 'remainder': [rest]}
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
            integration = case('test_context.Case.test_one')
            additional = case('test_local_native_terminal.Case.test_one')
            synthesis = case('test_library_attempts.Case.test_one')
            loader = Mock(errors=[], discover=Mock(return_value=unittest.TestSuite(
                [slow, integration, additional, synthesis, rest])))
            runner = Mock()
            runner.run.return_value.wasSuccessful.return_value = True
            with patch.object(ci.unittest, 'TestLoader', return_value=loader), \
                    patch.object(ci.unittest, 'TextTestRunner', return_value=runner), \
                    patch.object(ci.sys, 'path', list(ci.sys.path)), redirect_stdout(io.StringIO()):
                self.assertEqual(0, ci.main([partition]))
            loader.discover.assert_called_once_with(str(Path(__file__).resolve().parent), pattern='test*.py')
            self.assertEqual(list(runner.run.call_args.args[0]),
                             [slow, integration, additional, synthesis, rest] if partition == 'all' else {
                                 'slow': [slow], 'integration': [integration],
                                 'additional': [additional], 'synthesis': [synthesis], 'remainder': [rest]}[partition])
            for item in (slow, integration, additional, synthesis, rest):
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
                                                          case('test_future.Case.test_one'), case('test_context.Case.test_one'),
                                                          case('test_local_native_terminal.Case.test_one'), case('test_library_attempts.Case.test_one')])
        runner = Mock(); runner.run.return_value.wasSuccessful.return_value = False
        with patch.object(ci.unittest, 'TestLoader', return_value=loader), \
                patch.object(ci.unittest, 'TextTestRunner', return_value=runner), \
                patch.object(ci.sys, 'path', list(ci.sys.path)), redirect_stdout(io.StringIO()):
            self.assertEqual(1, ci.main(['remainder']))
