"""Canonical initial context and native denial cuts, controlled effects only."""
from copy import deepcopy
from types import SimpleNamespace as N
import unittest
from unittest.mock import Mock,patch

from uas.context import FixtureContextHub,FixtureRun,initial_contexts
from uas.ledger import LedgerError
from uas.claude_native_admission import NativeClaudeHostLaunch,NativeClaudeRoot
from uas.kernel_origin import OriginDenied
from uas.workstation_exec import ExecUnavailable


class NativeReviewerRecruitmentTests(unittest.TestCase):
    def state(self):
        return {'fixture_context':initial_contexts({'reviewer':object()},FixtureRun('bootstrap')),
                'peer_traffic':{'connections':{},'traffic':{}}}

    def test_initial_reservation_selects_only_unopened_context(self):
        state=self.state();state['fixture_context']['runs']['target']={'status':'OPEN','generation':1}
        FixtureContextHub.reserve_unused_initial(state,'reviewer',FixtureRun('target'))
        row=state['fixture_context']['participants']['reviewer']
        self.assertEqual(row['reserved_run'],{'run_id':'target','generation':1})
        self.assertIsNone(row['bound_run']);self.assertEqual(row['context_generation'],1)
        self.assertEqual(state['fixture_context']['runs']['bootstrap']['status'],'OPEN')

    def test_connected_used_reset_or_started_context_cannot_be_relabelled(self):
        changes=[lambda s:s['peer_traffic']['connections'].update(reviewer={}),
                 lambda s:s['peer_traffic']['traffic'].update(work={'sender':'other','recipients':['reviewer']}),
                 lambda s:s['fixture_context']['participants']['reviewer'].update(bound_run={'run_id':'bootstrap','generation':1}),
                 lambda s:s['fixture_context']['participants']['reviewer'].update(context_generation=2),
                 lambda s:s['fixture_context']['participants']['reviewer'].update(reset={'status':'SUCCEEDED'})]
        for change in changes:
            state=self.state();state['fixture_context']['runs']['target']={'status':'OPEN','generation':1};change(state)
            before=deepcopy(state)
            with self.assertRaisesRegex(LedgerError,'UNUSED_NATIVE_CONTEXT_REQUIRED'):
                FixtureContextHub.reserve_unused_initial(state,'reviewer',FixtureRun('target'))
            self.assertEqual(state,before)
        self.assertFalse(FixtureContextHub.unused_initial(self.state(),'reviewer',native_started=True))

    def test_noncurrent_target_cannot_receive_initial_reservation(self):
        for status,generation in [('CLOSED',1),('OPEN',2)]:
            state=self.state();state['fixture_context']['runs']['target']={'status':status,'generation':generation}
            with self.assertRaisesRegex(LedgerError,'TARGET_RUN_UNAVAILABLE'):
                FixtureContextHub.reserve_unused_initial(state,'reviewer',FixtureRun('target'))

    def test_host_denial_precedes_auth_manifest_or_engine(self):
        host=object.__new__(NativeClaudeHostLaunch)
        host.recipe=N(require_provider_auth=Mock(),validate_container=Mock());host.engine=object()
        with self.assertRaisesRegex(OriginDenied,'authorization revoked'):
            host.launch(object(),authorize=lambda:False)
        host.recipe.require_provider_auth.assert_not_called();host.recipe.validate_container.assert_not_called()

    def test_host_passes_deny_fence_through_actual_engine_preflight(self):
        allowed=[True];host=object.__new__(NativeClaudeHostLaunch)
        host.recipe=N(require_provider_auth=Mock(),validate_container=Mock(side_effect=lambda *_:allowed.__setitem__(0,False)))
        host.engine=N(create=Mock());host.native_recipe=None;host.state='new';host.endpoint=N(require=Mock())
        host._save=Mock()
        with patch('uas.workstation_exec.probe'),patch('uas.workstation_exec.enable'):
            with self.assertRaisesRegex(ExecUnavailable,'authorization revoked'):
                host.launch(object(),authorize=lambda:allowed[0])
        host.engine.create.assert_not_called();host._save.assert_not_called()

    def test_native_helper_denial_after_fresh_proof_prevents_admit(self):
        allowed=[True];root=object.__new__(NativeClaudeRoot)
        root.state='new';root._initialize_started=False;root._fail=Mock()
        root.launch=Mock();root._receive_helper=Mock();root._receive_forge_helper=Mock()
        root.attach_native=Mock(side_effect=lambda **_:allowed.__setitem__(0,False))
        with patch('uas.claude_native_admission.NativeClaudeSupervisorAdmission') as admission:
            with self.assertRaisesRegex(OriginDenied,'authorization revoked'):
                root.initialize_helper(object(),journal='/private/journal',control=object(),hub_origin=object(),
                    controller='b'*32,control_lock=object(),operation_id='a'*32,epoch=1,authorize=lambda:allowed[0])
        admission.assert_not_called();root._fail.assert_called_once()
        self.assertTrue(root._initialize_started)
        with self.assertRaisesRegex(OriginDenied,'one bounded fresh'):
            root.initialize_helper(object(),journal='/private/journal',control=object(),hub_origin=object(),
                controller='b'*32,control_lock=object(),operation_id='a'*32,epoch=1,authorize=lambda:True)
