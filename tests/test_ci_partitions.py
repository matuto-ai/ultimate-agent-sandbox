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
        self.assertEqual(ci.SLOW_MODULES, {'test_peer', 'test_checkouts', 'test_forge_capacity',
                                          'test_gate_evaluation', 'test_forge_mutations'})
        for module in ci.SLOW_MODULES:
            self.assertEqual('slow', ci.partition_for(module + '.Case.test_one'))
        for name in ('test_new_future.Case.test_one', 'test_git_new.Case.test_one',
                     'package.test_peer.Case.test_one', 'test_peer_future.Case.test_one'):
            self.assertEqual('remainder', ci.partition_for(name))

    def test_nested_standard_suite_is_complete_disjoint_and_never_executed_for_selection(self):
        slow, future = case('test_peer.Case.test_one'), case('test_future.Case.test_one')
        cases, groups = ci.partition_suite(unittest.TestSuite([unittest.TestSuite([slow]), future]))
        self.assertEqual([slow, future], cases)
        self.assertEqual({'slow': [slow], 'remainder': [future]}, groups)
        slow.run.assert_not_called(); future.run.assert_not_called()

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
                ci.verify_partition_ids([slow, rest], groups)
        with self.assertRaises(ValueError):
            list(ci.leaves([object()]))

    def test_main_uses_full_standard_discovery_and_exact_requested_partition(self):
        for partition in ('all', 'slow', 'remainder'):
            slow, rest = case('test_peer.Case.test_one'), case('test_future.Case.test_one')
            loader = Mock(errors=[], discover=Mock(return_value=unittest.TestSuite([slow, rest])))
            runner = Mock()
            runner.run.return_value.wasSuccessful.return_value = True
            with patch.object(ci.unittest, 'TestLoader', return_value=loader), \
                    patch.object(ci.unittest, 'TextTestRunner', return_value=runner), \
                    patch.object(ci.sys, 'path', list(ci.sys.path)), redirect_stdout(io.StringIO()):
                self.assertEqual(0, ci.main([partition]))
            loader.discover.assert_called_once_with(str(Path(__file__).resolve().parent), pattern='test*.py')
            self.assertEqual(list(runner.run.call_args.args[0]),
                             [slow, rest] if partition == 'all' else [slow] if partition == 'slow' else [rest])
            slow.run.assert_not_called(); rest.run.assert_not_called()

    def test_discovery_and_selected_test_failures_are_required_failures(self):
        loader = Mock(errors=['fixture import failure'])
        with patch.object(ci.unittest, 'TestLoader', return_value=loader), \
                patch.object(ci.unittest, 'TextTestRunner') as runner, \
                patch.object(ci.sys, 'path', list(ci.sys.path)), redirect_stderr(io.StringIO()):
            self.assertEqual(1, ci.main(['slow']))
        runner.assert_not_called()
        loader.errors = []
        loader.discover.return_value = unittest.TestSuite([case('test_peer.Case.test_one'),
                                                          case('test_future.Case.test_one')])
        runner = Mock(); runner.run.return_value.wasSuccessful.return_value = False
        with patch.object(ci.unittest, 'TestLoader', return_value=loader), \
                patch.object(ci.unittest, 'TextTestRunner', return_value=runner), \
                patch.object(ci.sys, 'path', list(ci.sys.path)), redirect_stdout(io.StringIO()):
            self.assertEqual(1, ci.main(['remainder']))
