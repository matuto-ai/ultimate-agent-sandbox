"""Actual Supervisor state/receipts with file resources, not Docker/VM proof."""
from copy import deepcopy
from types import SimpleNamespace
import unittest

import test_room_control_plane as fixture
from uas.ledger import Command, Event, LedgerError, Origin, RoomLedger, Transition
from uas.lifecycle import LifecycleError
from uas.manager_actions import HumanSession
from uas.manager_lifecycle import current


class ManagerLifecycleTests(unittest.TestCase):
    reopen = fixture.RoomFixture.reopen
    def setUp(self):
        fixture.RoomFixture.setUp(self)
        self.ledger = RoomLedger(self.root / 'hub.db', 'alpha'); self.addCleanup(self.ledger.close)
        self.human_allowed = True; self.connected = True
        self.session = HumanSession('deployment', 'alpha', self.started['instance_id'], 'manager',
            Origin('human', 'human', 'session', 'epoch', ('human-control-room',)),
            lambda *_: self.human_allowed, lambda: self.connected)
        # Controlled service-owner readiness/revocation, never a process claim.
        self.supervisor._control_plane = SimpleNamespace(instance=self.started['instance_id'],
            require_ready_locked=lambda: True, revoke_locked=lambda *_: True)

    def packet(self, action, operation=None):
        return {'version': 1, 'operation_id': operation or action, 'action': action,
            'deployment_id': 'deployment', 'room_id': 'alpha', 'instance_id': self.started['instance_id'],
            'run_id': None, 'generation': None, 'object_id': self.started['instance_id'],
            'observed_version': current(self.supervisor._read())['observed_version'], 'payload': {}}

    def execute(self, packet):
        return self.supervisor.manager_action(packet, session=self.session, deployment_id='deployment', ledger=self.ledger)

    def test_stop_start_exact_instance_preserves_project_control_and_old_retry_no_effect(self):
        (self.project / 'human-data').write_text('retain')
        stop = self.packet('stop'); result = self.execute(stop)
        self.assertEqual('confirmed', result['outcome']); self.assertEqual('stopped', result['current']['phase'])
        start = self.packet('start'); self.assertEqual('confirmed', self.execute(start)['outcome'])
        self.assertEqual('confirmed', self.execute(self.packet('stop', 'later-stop'))['outcome'])
        calls = list(self.backend.calls)
        self.assertEqual('MANAGER_DUPLICATE_ACTION', self.execute(start)['reason'])
        self.assertEqual(calls, self.backend.calls)
        self.assertEqual('stopped', self.supervisor._read()['phase'])
        self.assertEqual('retain', (self.project / 'human-data').read_text())

    def test_stale_lifecycle_revision_and_ineligible_start_have_no_resource_effect(self):
        packet = self.packet('stop'); state = self.supervisor._read(); self.supervisor._save(state)
        calls = list(self.backend.calls); before = self.supervisor._manifest.read_bytes()
        result = self.execute(packet); self.assertEqual('MANAGER_STALE_ACTION', result['reason'])
        self.assertEqual(calls, self.backend.calls); self.assertEqual(before, self.supervisor._manifest.read_bytes())
        self.assertFalse((self.supervisor._owned_directory(state) / 'manager-actions.db').exists())
        self.assertEqual('MANAGER_ACTION_INELIGIBLE', self.execute(self.packet('start'))['reason'])

    def test_human_revocation_disconnection_and_supervisor_refusal_rechecked(self):
        packet = self.packet('stop'); self.execute(packet); calls = list(self.backend.calls)
        self.human_allowed = False; self.assertEqual('FORBIDDEN', self.execute(packet)['reason'])
        self.human_allowed = True; self.connected = False
        self.assertEqual('FORBIDDEN', self.execute(packet)['reason'])
        self.connected = True; self.allowed = False
        self.assertEqual('FORBIDDEN', self.execute(packet)['reason'])
        self.assertEqual(calls, self.backend.calls)

    def test_changed_id_payload_wrong_instance_and_structural_operations_denied(self):
        packet = self.packet('stop'); self.execute(packet)
        changed = deepcopy(packet); changed['observed_version'] = '0' * 64
        self.assertEqual('ID_CONFLICT', self.execute(changed)['reason'])
        for action in ('destroy', 'shell', 'mount', 'runtime', 'merge'):
            changed = self.packet(action)
            with self.assertRaises(LedgerError): self.execute(changed)
        changed = self.packet('start'); changed['payload'] = {'spec': 'not authority'}
        with self.assertRaises(LedgerError): self.execute(changed)
        changed = self.packet('start'); changed['object_id'] = 'other-instance'
        self.assertEqual('MANAGER_SCOPE_MISMATCH', self.execute(changed)['reason'])

    def test_unknown_stop_never_claims_completion_and_new_owner_can_reconcile(self):
        self.backend.revoke_verified = False
        packet = self.packet('stop'); result = self.execute(packet)
        self.assertEqual('unknown', result['outcome']); self.assertEqual('stop_failed', result['current']['phase'])
        self.assertEqual('running', self.backend.inspect(self.supervisor._read(), 'container')['running'] and 'running')
        calls = list(self.backend.calls); self.assertEqual('denied', self.execute(packet)['outcome'])
        self.assertEqual(calls, self.backend.calls)
        self.backend.revoke_verified = True
        self.assertEqual('confirmed', self.execute(self.packet('stop', 'explicit-new-stop'))['outcome'])

    def test_destroyed_state_cannot_be_recreated_from_manager(self):
        self.supervisor._control_plane = None
        self.supervisor.destroy(); calls = list(self.backend.calls)
        self.assertEqual('MANAGER_SCOPE_MISMATCH', self.execute(self.packet('start'))['reason'])
        self.assertEqual(calls, self.backend.calls)

    def test_lifecycle_view_uses_supervisor_policy_and_shared_hub_id_namespace(self):
        view = self.supervisor.manager_view(session=self.session, deployment_id='deployment')
        self.assertEqual([False, True], [row['eligible'] for row in view['actions']])
        self.allowed = False
        view = self.supervisor.manager_view(session=self.session, deployment_id='deployment')
        self.assertFalse(any(row['eligible'] for row in view['actions']))
        self.allowed = True
        command = Command('stop', 'another.human-action', 'run', 1, {})
        self.ledger.apply(command, self.session.human, authorize=lambda *_: True,
            decide=lambda state, _: Transition(state, (Event('fixture', {}),), {}))
        calls = list(self.backend.calls); before = self.supervisor._manifest.read_bytes()
        self.assertEqual('ID_CONFLICT', self.execute(self.packet('stop'))['reason'])
        self.assertEqual(calls, self.backend.calls); self.assertEqual(before, self.supervisor._manifest.read_bytes())

    def test_lifecycle_hub_intent_survives_missing_response_and_blocks_other_owner(self):
        packet = self.packet('stop'); self.execute(packet)
        command = Command('stop', 'run.human-pause', 'run', 1, {})
        with self.assertRaises(LedgerError) as error:
            self.ledger.apply(command, self.session.human, authorize=lambda *_: True,
                decide=lambda state, _: Transition(state, (), {}))
        self.assertEqual('ID_CONFLICT', error.exception.code)



    def test_original_lifecycle_receipt_is_read_without_repeating_effects(self):
        from uas.manager_lifecycle import inspect_result
        packet = self.packet('stop')
        self.assertEqual('confirmed', self.execute(packet)['outcome'])
        calls = list(self.backend.calls)
        with self.supervisor._locked():
            self.assertEqual('confirmed', inspect_result(self.supervisor, packet, self.session))
            changed = deepcopy(packet); changed['observed_version'] = '0' * 64
            with self.assertRaisesRegex(LedgerError, 'ID_CONFLICT'):
                inspect_result(self.supervisor, changed, self.session)
        self.assertEqual(calls, self.backend.calls)
