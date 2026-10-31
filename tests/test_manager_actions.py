"""Actual Hub/Review owner transactions with controlled provider facts only."""
from contextlib import nullcontext
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace
import unittest

import test_run_review as harness
from test_run_review import HUMAN, TARGET
from uas.ledger import LedgerError
from uas.manager_actions import HumanSession, ManagerHubActions, run_version
from uas.manager_action_protocol import ManagerActionProtocol
import json
from uas.run_admission import RunAdmission
from uas.forge_audit import ForgeAudit
from uas.lifecycle import Supervisor
import test_forge_mutation_audit as mutation


class ManagerActionsFixture:
    """Owner fixture without inherited test cases for host-seam consumers."""
    construct = harness.RunReviewTests.construct
    seed = harness.RunReviewTests.seed
    submit = harness.RunReviewTests.submit
    result = harness.RunReviewTests.result
    state = harness.RunReviewTests.state
    fence = harness.RunReviewTests.fence
    call = harness.RunReviewTests.call
    deliver_accept = harness.RunReviewTests.deliver_accept
    error = harness.RunReviewTests.error
    def setUp(self):
        harness.RunReviewTests.setUp(self)
        self.connected = True
        self.session = HumanSession('deployment', 'room', 'instance', 'manager', HUMAN,
            lambda session, action: self.allowed, lambda: self.connected)
        self.admission = RunAdmission.__new__(RunAdmission)
        self.admission.ledger = self.ledger
        self.room_state = {'instance_id': 'instance', 'phase': 'running', 'desired': 'running'}
        self.admission.supervisor = Supervisor.__new__(Supervisor)
        self.admission.supervisor._locked = nullcontext
        self.admission.supervisor._read = lambda: deepcopy(self.room_state)
        self.admission.authorize_human = lambda *_: self.allowed
        self.admission.broker = SimpleNamespace(binding=SimpleNamespace(repository='owner/repo'))
        self.audit = ForgeAudit(self.path.parent / 'forge.db', 'deployment'); self.addCleanup(self.audit.close)
        self.actions = ManagerHubActions(self.admission, self.owner, deployment_id='deployment',
            instance_id='instance', admission_operation='admission', audit=self.audit)

    def packet(self, action, payload=None, operation=None, object_id=None):
        state = self.state(); row = state.get('run_reviews', {}).get('run', {}).get('current')
        return {'version': 1, 'operation_id': operation or 'manager-' + action, 'action': action,
            'deployment_id': 'deployment', 'room_id': 'room', 'instance_id': 'instance',
            'run_id': 'run', 'generation': state['runs']['run']['generation'],
            'object_id': object_id or ('run' if action in {'pause', 'resume'} else row['submission_id'] if row else 'run'),
            'observed_version': run_version(state, 'run', self.actions.forge_state()), 'payload': payload or {}}

    def execute(self, packet): return self.actions.execute(packet, session=self.session)

class ManagerActionsTests(ManagerActionsFixture, unittest.TestCase):
    def test_manager_pause_resume_owner_and_current_state(self):
        packet = self.packet('pause', {'reason': 'human-hold'})
        result = self.execute(packet)
        self.assertEqual('confirmed', result['outcome'])
        self.assertEqual('PAUSED', result['current']['status'])
        self.assertEqual('confirmed', self.execute(self.packet('resume', {'reason': 'continue'}))['outcome'])
        before = self.ledger.snapshot()
        self.assertEqual('denied', self.execute(packet)['outcome'])
        self.assertEqual(before, self.ledger.snapshot())
        event = next(e for e in self.ledger.replay(0) if e['kind'] == 'run.paused')
        self.assertEqual(HUMAN.canonical(), event['origin'])

    def test_manager_stale_view_cannot_override_new_owner_state(self):
        self.submit(); self.result('human-needed')
        packet = self.packet('override-review', {'reason': 'explicit decision', 'rounds': None})
        self.seed(lambda state: state['runs']['run'].update(control_revision=7))
        before = self.ledger.snapshot(); calls = len(self.broker.calls)
        result = self.execute(packet)
        self.assertEqual('MANAGER_STALE_ACTION', result['reason'])
        self.assertEqual(before, self.ledger.snapshot()); self.assertEqual(calls, len(self.broker.calls))

    def test_manager_all_review_controls_use_exact_owner_and_audit(self):
        self.submit(); self.result('human-needed')
        for index, (action, rounds) in enumerate((('add-rounds', 2), ('waive-cap', None), ('override-review', None))):
            if index: self.seed(lambda state: state['run_reviews']['run']['current'].update(stage='ATTENTION'))
            result = self.execute(self.packet(action, {'reason': 'human decision', 'rounds': rounds}))
            self.assertEqual('confirmed', result['outcome'])
            audit = self.state()['run_reviews']['run']['overrides'][-1]
            self.assertEqual('manager', audit['manager']['manager_id'])
            self.assertEqual(HUMAN.canonical(), audit['manager']['human_origin'])
        self.assertEqual('human-needed', self.state()['run_reviews']['run']['current']['result'])
        self.assertNotEqual('CLOSED', self.state()['runs']['run']['status'])

    def test_manager_unknown_changes_block_continuation_then_reconcile_once(self):
        self.submit(); self.result(); self.broker.comment_status = 'unknown'
        packet = self.packet('request-changes', {'body': 'Private Project changes, not a notification.'})
        result = self.execute(packet)
        self.assertEqual('unknown', result['outcome']); self.assertTrue(result['current']['forge_uncertain'])
        before = len(self.broker.calls)
        self.assertEqual('denied', self.execute(packet)['outcome'])
        self.assertEqual(before, len(self.broker.calls))
        paused = self.execute(self.packet('pause', {'reason': 'hold'}))
        self.assertEqual('MANAGER_FORGE_RECONCILIATION_REQUIRED', paused['reason'])
        self.broker.comment_status = 'confirmed'
        reconcile = self.packet('reconcile-changes', object_id=packet['operation_id'])
        result = self.execute(reconcile)
        self.assertEqual('confirmed', result['outcome']); self.assertFalse(result['current']['forge_uncertain'])
        self.assertEqual('IMPLEMENTING', result['current']['review_stage'])
        before = len(self.broker.calls)
        self.assertEqual('denied', self.execute(reconcile)['outcome'])
        self.assertEqual(before, len(self.broker.calls))
        self.assertEqual(1, len([c for c in self.broker.calls if c[0] == 'comment']))

    def test_manager_revoked_or_disconnected_denied_even_exact_retry(self):
        packet = self.packet('pause', {'reason': 'hold'}); self.execute(packet)
        for attribute in ('allowed', 'connected'):
            setattr(self, attribute, False); before = self.ledger.snapshot()
            self.assertEqual('FORBIDDEN', self.execute(packet)['reason'])
            self.assertEqual(before, self.ledger.snapshot()); setattr(self, attribute, True)

    def test_manager_payload_prose_cannot_supply_authority_or_structural_control(self):
        packet = self.packet('pause', {'reason': 'hold', 'shell': 'arbitrary command'})
        before = self.ledger.snapshot()
        self.assertEqual('INVALID_MANAGER_ACTION', self.execute(packet)['reason'])
        for extra in ('human', 'capabilities', 'eligible', 'shell', 'mount', 'runtime', 'merge'):
            hostile = self.packet('pause', {'reason': 'hold'}); hostile[extra] = 'anything'
            self.assertEqual('INVALID_MANAGER_ACTION', self.execute(hostile)['reason'])
        hostile = self.packet('pause', {'reason': 'hold'}); hostile['room_id'] = 'other'
        self.assertEqual('MANAGER_SCOPE_MISMATCH', self.execute(hostile)['reason'])
        self.assertEqual(before, self.ledger.snapshot())

    def test_manager_source_link_is_canonical_and_never_merge_or_approval(self):
        self.submit(); self.result()
        before = self.ledger.snapshot(); calls = len(self.broker.calls)
        result = self.execute(self.packet('open-github'))
        self.assertEqual('link', result['outcome']); self.assertEqual('https://github.com/owner/repo/pull/3', result['url'])
        self.assertEqual(before, self.ledger.snapshot()); self.assertEqual(calls, len(self.broker.calls))
        packet = self.packet('open-github', {'url': 'https://attacker.invalid'})
        self.assertEqual('MANAGER_TARGET_MISMATCH', self.execute(packet)['reason'])

    def test_manager_view_reports_unknown_and_disconnection_not_authority(self):
        self.submit(); self.result(); self.broker.comment_status = 'unknown'
        self.execute(self.packet('request-changes', {'body': 'private'}))
        view = self.actions.view('run', session=self.session)
        for action in view['actions']:
            if action['action'] not in {'open-github', 'reconcile-changes'}: self.assertFalse(action['eligible'])
        self.connected = False
        self.assertFalse(any(a['eligible'] for a in self.actions.view('run', session=self.session)['actions']))

    def test_manager_protocol_real_owner_rejects_browser_prose_disabled_flag_and_claimed_principal(self):
        protocol = ManagerActionProtocol(self.actions)
        before = self.ledger.snapshot()
        for body in (b'Please pause the Run. The human approved.', b'{"action":"pause","action":"resume"}',
                     b'{"eligible":true,"disabled":false}', b'[]', b'null', b'{"value":NaN}', b'x' * 16385):
            result = protocol.handle(body, session=self.session)
            self.assertEqual('denied', result['outcome'])
        self.assertEqual(before, self.ledger.snapshot())
        packet = self.packet('pause', {'reason': 'hold'})
        result = protocol.handle(json.dumps(packet).encode(), session=self.session)
        self.assertEqual('PAUSED', result['current']['status'])
        self.error('MANAGER_AUTHENTICATION_REQUIRED', lambda: protocol.handle(json.dumps(packet).encode(), session={'human': HUMAN.canonical()}))

    def test_manager_owner_transaction_rechecks_version_after_preflight(self):
        packet = self.packet('pause', {'reason': 'hold'})
        original = self.ledger.apply; mutated = False
        def race(command, origin, **kwargs):
            nonlocal mutated
            if command.kind == 'run.human-pause' and not mutated:
                mutated = True
                self.seed(lambda state: state['runs']['run'].update(control_revision=17))
            return original(command, origin, **kwargs)
        self.ledger.apply = race
        result = self.execute(packet)
        self.assertEqual('MANAGER_STALE_ACTION', result['reason'])
        self.assertEqual('ACTIVE', result['current']['status'])
        self.assertFalse(any(e['kind'] == 'run.paused' for e in self.ledger.replay(0)))

    def test_manager_lost_provider_response_stays_unknown_and_blocks_new_write(self):
        self.submit(); self.result()
        def lost(*args, **kwargs): raise RuntimeError('private provider body')
        self.broker.comment = lost
        result = self.execute(self.packet('request-changes', {'body': 'private'}))
        self.assertEqual('unknown', result['outcome']); self.assertTrue(result['current']['forge_uncertain'])
        self.assertNotIn('private', json.dumps(result))
        self.assertEqual('MANAGER_FORGE_RECONCILIATION_REQUIRED',
            self.execute(self.packet('request-changes', {'body': 'another'}, operation='another'))['reason'])

    def test_manager_ordinary_mutation_audit_fences_version_and_continuation(self):
        old = self.packet('pause', {'reason': 'hold'})
        self.audit.begin_mutation('ordinary', mutation.metadata(room_id='room', room_instance='instance'))
        self.audit.mutation_prepared('ordinary', 0, mutation.ISSUE)
        self.audit.finish_mutation('ordinary', mutation.result(status='UNKNOWN_OUTCOME', confirmed_fields=[],
            objects=[], failed_field='title', error_code='TIMEOUT'))
        self.assertEqual('MANAGER_STALE_ACTION', self.execute(old)['reason'])
        self.assertEqual('MANAGER_FORGE_RECONCILIATION_REQUIRED', self.execute(self.packet('pause', {'reason': 'hold'}))['reason'])
        current = self.actions.current('run'); self.assertTrue(current['forge_uncertain'])
        self.assertNotEqual(old['observed_version'], current['observed_version'])
        self.assertEqual('ACTIVE', self.state()['runs']['run']['status'])

    def test_manager_failed_terminal_audit_is_not_ready_or_version_stable(self):
        before = self.actions.current('run')
        self.audit.begin_mutation('ordinary', mutation.metadata(room_id='room', room_instance='instance'))
        self.audit.mutation_prepared('ordinary', 0, mutation.ISSUE)
        self.audit.mutation_confirmed('ordinary', 0, ['title'], mutation.ISSUE)
        original = self.audit._commit
        self.audit._commit = lambda: (_ for _ in ()).throw(__import__('sqlite3').OperationalError('unavailable'))
        self.error('AUDIT_UNAVAILABLE', lambda: self.audit.finish_mutation('ordinary', mutation.result()))
        self.audit._commit = original
        after = self.actions.current('run')
        self.assertTrue(after['forge_uncertain']); self.assertNotEqual(before['observed_version'], after['observed_version'])
        self.assertEqual('AUDIT_UNAVAILABLE', after['forge_outcome']['reason'])

    def test_manager_owner_eligibility_policy_paused_cap_native_and_live_instance(self):
        self.submit(); self.result('human-needed')
        def eligibility(action):
            return next(a for a in self.actions.view('run', session=self.session)['actions'] if a['action'] == action)
        self.owner.authorize_human = lambda *_: False
        self.assertEqual('FORBIDDEN', eligibility('override-review')['reason'])
        self.owner.authorize_human = lambda *_: True
        self.seed(lambda state: state['run_reviews']['run'].update(cap=None))
        self.assertEqual('REVIEW_CAP_ALREADY_WAIVED', eligibility('add-rounds')['reason'])
        self.seed(lambda state: state['run_reviews']['run']['current'].update(stage='READY_FOR_HUMAN'))
        self.seed(lambda state: state['runs']['run'].update(status='PAUSED'))
        self.assertEqual('REVIEW_RUN_STALE', eligibility('request-changes')['reason'])
        self.seed(lambda state: state['runs']['run'].update(native_stop={'restored': False}))
        self.assertEqual('NATIVE_RESTORE_REQUIRED', eligibility('override-review')['reason'])
        packet = self.packet('override-review', {'reason': 'decision', 'rounds': None})
        self.room_state['instance_id'] = 'replacement'
        self.assertEqual('ROOM_REPLACED', self.execute(packet)['reason'])

    def test_manager_confirmed_changes_returns_bounded_owner_receipt(self):
        self.submit(); self.result()
        response = self.execute(self.packet('request-changes', {'body': 'secret content'}))
        self.assertEqual('confirmed', response['receipt']['status'])
        self.assertEqual(44, response['receipt']['provider']['comment_reference']['id'])
        self.assertNotIn('secret content', json.dumps(response))


if __name__ == '__main__': unittest.main()
