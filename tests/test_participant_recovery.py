"""Actual Participant manifest/Hub ledger; missing checkpoint, no native effects."""
from copy import deepcopy
from types import SimpleNamespace
import unittest

from run_control_support import RunControlCase
from uas.ledger import LedgerError, RoomLedger
from uas.manager_actions import HumanSession
from uas.participant import FixtureCredentials, FixtureParticipantController, FixtureSeat
from uas.pi_fixture import FixturePiRecipe
from uas.forge_audit import ForgeAudit


class ParticipantRecoveryTests(RunControlCase):
    def setUp(self):
        super().setUp(); self.seed_run(status='PAUSED')
        self.supervisor.room_id = 'alpha'
        self.supervisor._read = lambda: {'instance_id': 'instance', 'phase': 'running', 'desired': 'running'}
        self.supervisor._allowed = lambda *_: None
        self.supervisor._sync_directory = lambda *_: None
        controller = FixtureParticipantController.__new__(FixtureParticipantController)
        controller.supervisor, controller.hub = self.supervisor, self.hub
        controller.instance, controller.controller_id = 'instance', 'controller'
        controller.path = self.root / 'participants.json'; controller.store_failed = False
        controller.credentials = FixtureCredentials(); controller.handles = {}; controller.fenced = set()
        self.audit = ForgeAudit(self.root / "forge.db", "deployment"); self.addCleanup(self.audit.close)
        self.controller = controller
        self.failed = FixtureSeat('builder', 'alice', 'worker', ('implement', 'peer-traffic'), runtime='pi-fixture')
        self.other = FixtureSeat('reviewer', 'bob', 'worker', ('implement', 'peer-traffic'), runtime='pi-fixture')
        self.records = {seat.participant_id: {'seat': seat.document(), 'epoch': 2,
            'incarnation_id': 'process-' + seat.participant_id, 'status': 'exited', 'reason': 'process-exited', 'pid': None}
            for seat in (self.failed, self.other)}
        controller._save({'version': 1, 'room_id': 'alpha', 'instance_id': 'instance',
            'controller_id': 'controller', 'seats': self.records, 'retired_pids': []})
        self.seed(lambda state: state['fixture_context']['participants']['reviewer'].update(bound_run=None, reserved_run=None))
        self.session = HumanSession('deployment', 'alpha', 'instance', 'manager', self.human,
                                   lambda *_: self.authorized, lambda: True)

    def view(self, participant):
        return self.controller.replacement_view(participant, audit=self.audit, repository="owner/repo")

    def select(self, packet, *, session):
        return self.controller.manager_replacement(packet, session=session, audit=self.audit, repository="owner/repo")

    def failed_restore(self):
        recipe = FixturePiRecipe.__new__(FixturePiRecipe)
        self.error('NATIVE_CONTEXT_RESTORE_UNVERIFIED', lambda: self.controller.restore_pi(self.failed, recipe))

    def packet(self, *, selected='reviewer', operation='select'):
        view = self.view('builder')
        return {'version': 1, 'operation_id': operation, 'action': 'select-replacement',
            'deployment_id': 'deployment', 'room_id': 'alpha', 'instance_id': 'instance',
            'run_id': 'run-test', 'generation': 1, 'object_id': 'builder',
            'observed_version': view['observed_version'], 'payload': {'participant_id': selected}}

    def test_actual_failed_restore_records_bounded_owner_attention(self):
        self.failed_restore()
        row = self.state()['participant_recoveries']['builder']
        self.assertEqual('NATIVE_RESTORE_FAILED', row['reason'])
        self.assertEqual(('process-builder', 2, 'run-test'), (row['incarnation_id'], row['epoch'], row['run_id']))
        self.assertIsNone(row['selection']); self.assertEqual([], list(self.root.glob('*.session')))
        self.assertEqual(['reviewer'], [c['participant_id'] for c in self.view('builder')['candidates']])

    def test_selection_persists_intent_not_launch_rebind_or_resume(self):
        self.failed_restore(); packet = self.packet(); before = deepcopy(self.state())
        result = self.select(packet, session=self.session)
        self.assertEqual('selected-not-launched', result['status'])
        self.assertEqual(before['runs'], self.state()['runs'])
        self.assertEqual(before['fixture_context'], self.state()['fixture_context'])
        self.assertEqual(before['peer_traffic'], self.state()['peer_traffic'])
        self.assertEqual({}, self.controller.handles)
        self.assertEqual('alice', self.controller._read()['seats']['builder']['seat']['actor_id'])
        with RoomLedger(self.root / 'room.db', 'alpha') as reopened:
            self.assertEqual(result, reopened.snapshot()['state']['participant_recoveries']['builder']['selection'])
        self.error('MANAGER_DUPLICATE_ACTION', lambda: self.select(packet, session=self.session))

    def test_replacement_wrong_context_capability_credentials_and_closed_seat_excluded(self):
        self.failed_restore()
        original = self.controller._read()
        for mutation in ('capability', 'closed', 'credentials'):
            document = deepcopy(original); candidate = document['seats']['reviewer']
            if mutation == 'capability': candidate['seat']['capabilities'] = ['peer-traffic']
            elif mutation == 'closed': candidate['status'] = 'closed'
            else: candidate['seat']['required_credentials'] = ['forge']
            self.controller._save(document)
            self.assertEqual([], self.view('builder')['candidates'])
        self.controller._save(original)
        self.seed(lambda state: state['fixture_context']['participants']['reviewer'].update(bound_run={'run_id': 'other', 'generation': 1}))
        self.assertEqual([], self.view('builder')['candidates'])

    def test_stale_incarnation_epoch_and_revoked_human_fail_without_intent(self):
        self.failed_restore(); packet = self.packet(); original = self.controller._read()
        document = deepcopy(original); document['seats']['reviewer']['epoch'] += 1
        self.controller._save(document)
        self.error('MANAGER_STALE_ACTION', lambda: self.select(packet, session=self.session))
        packet = self.packet(); self.authorized = False
        self.error('FORBIDDEN', lambda: self.select(packet, session=self.session))
        self.authorized = True
        document = self.controller._read(); document['seats']['builder']['incarnation_id'] = 'new-process'
        self.controller._save(document)
        self.error('REPLACEMENT_ATTENTION_STALE', lambda: self.select(packet, session=self.session))
        self.assertIsNone(self.state()['participant_recoveries']['builder']['selection'])

    def test_no_failed_restore_no_selection_and_unknown_forge_blocks(self):
        self.error('REPLACEMENT_ATTENTION_STALE', lambda: self.view('builder'))
        self.failed_restore(); packet = self.packet()
        self.seed(lambda state: state.update(forge_projections={'run-test': {'state': 'unknown'}}))
        self.error('MANAGER_FORGE_RECONCILIATION_REQUIRED', lambda: self.select(packet, session=self.session))
        self.assertIsNone(self.state()['participant_recoveries']['builder']['selection'])


if __name__ == '__main__': unittest.main()
