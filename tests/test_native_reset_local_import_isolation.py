"""Qualification completed resets must not require local-host packaging."""
import builtins
import unittest
from unittest.mock import patch

import test_native_repeated_reset as repeated
import test_native_completed_reviewer_reset as reviewer
from uas.native_completed_retirement import retirement_for, retirement_supported
from types import SimpleNamespace as N


class LocalImportIsolationTests(unittest.TestCase):
    def setUp(self):
        original=builtins.__import__
        def blocked(name,*args,**kwargs):
            if name in {'local_native_terminal','local_native_stop','uas.local_native_terminal','uas.local_native_stop'}:
                raise AssertionError('qualification imported local-only module: '+name)
            return original(name,*args,**kwargs)
        self.guard=patch('builtins.__import__',blocked);self.guard.start();self.addCleanup(self.guard.stop)
    def test_completed_pi_reset_and_fresh_proof_without_local_imports(self):
        case=repeated.RepeatedNativeResetTests();self.addCleanup(case.doCleanups)
        case.test_pi_third_run_uses_generation_three_and_exact_original_retirement()
    def test_completed_claude_reset_and_fresh_proof_without_local_imports(self):
        case=reviewer.CompletedReviewerResetTests();case.setUp();self.addCleanup(case.doCleanups)
        case.test_completed_retirement_reused_without_recapture_or_second_stop()
    def test_unknown_or_missing_proof_does_not_probe_local_modules(self):
        self.assertFalse(retirement_supported(object()))
        self.assertIsNone(retirement_for(N(_completed_retirements={}),{'operation_id':'absent'}))
    def test_reset_modules_first_execution_without_local_imports(self):
        import importlib.util
        import uas.native_pi_reset as pi_module
        import uas.native_reviewer_reset as reviewer_module
        for source in (pi_module,reviewer_module):
            spec=importlib.util.spec_from_file_location('uas._qualification_import_probe',source.__file__)
            module=importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
