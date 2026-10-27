"""Connected Room ledger → external Broker → Deployment audit → GitHub route fixtures.

No mocks, native processes, sockets, live credentials or accounts. Fault injection
severs responses only at explicit provider/transport boundaries.
"""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from test_github_reconciliation import RecoverableGitHub
from uas.forge import ForgeBinding
from uas.forge_audit import ForgeAudit
from uas.forge_mutations import ExternalMutationBroker
from uas.forge_projection_broker import ExternalProjectionBroker, hub_origin
from uas.forge_projections import ProjectionOutbox, enqueue_run_projection
from uas.github_mutations import GitHubMutationProvider
from uas.github_read import GitHubProject
from uas.ledger import Command, Event, RoomLedger, Transition


class Crash(BaseException):
    pass


class ConnectedAdapter:
    def __init__(self, broker, origin):
        self.broker, self.origin = broker, origin
        self.crash_before_repair = False

    def observe(self, intent, operation_id, *, authorize):
        return self.broker.execute({'id': operation_id, 'kind': 'forge-projection',
            'action': 'observe', 'intent': intent}, origin=self.origin, authorize=authorize)

    def repair(self, intent, operation_id, observed, *, authorize):
        if self.crash_before_repair: raise Crash()
        return self.broker.execute({'id': operation_id, 'kind': 'forge-projection',
            'action': 'repair', 'intent': intent, 'observed': observed},
            origin=self.origin, authorize=authorize)


class ConnectedProjectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binding = ForgeBinding('room', 'project', 'owner/repo')
        self.origin = hub_origin('instance')
        self.fixture = RecoverableGitHub()
        self.fixture.issues[1]['assignees'] = [{'id': 41}]
        self.fixture.issues[1]['labels'] = [{'name': 'type:bug'}, {'name': 'run:paused'}]
        self.provider = GitHubMutationProvider(GitHubProject('owner/repo'), self.fixture)
        self.ledger = RoomLedger(self.root / 'room.db', 'room')
        self.audit = ForgeAudit(self.root / 'audit.db', 'deployment')
        self.addCleanup(lambda: self.ledger.close()); self.addCleanup(lambda: self.audit.close())
        self.connect()
        def seed(state, _):
            state['runs'] = {'run': {'run_id': 'run', 'generation': 1, 'status': 'ACTIVE',
                'outcome': None, 'control_revision': 0, 'project_id': 'project',
                'repository': 'owner/repo', 'issue_id': 101, 'issue_number': 1,
                'github_user_id': 41, 'authorization_consumed': True,
                'policy': {'version': 7}}}
            event = enqueue_run_projection(state, 'room', 'run')
            return Transition(state, (Event('run.activated', {'run_id': 'run'}), event), {})
        self.ledger.apply(Command('seed', 'fixture.seed', 'run', None, {}), self.origin,
            authorize=lambda *_: True, decide=seed)
        self.original = deepcopy(self.ledger.snapshot()['state']['runs']['run'])

    def connect(self):
        self.broker = ExternalProjectionBroker(self.binding, 'instance', self.audit,
            'actor', 41, lambda _: self.provider)
        self.adapter = ConnectedAdapter(self.broker, self.origin)
        self.outbox = ProjectionOutbox(self.ledger, self.binding, self.adapter)

    def reopen(self):
        self.ledger.close(); self.audit.close()
        self.ledger = RoomLedger(self.root / 'room.db', 'room')
        self.audit = ForgeAudit(self.root / 'audit.db', 'deployment')
        self.connect()

    def advance(self, op='sync'):
        return self.outbox.advance(op, 'run', origin=self.origin, authorize=lambda: True)

    def assert_truth(self, state):
        self.assertEqual(self.original | {'projection': state},
                         self.ledger.snapshot()['state']['runs']['run'])

    def names(self):
        return {v['name'] for v in self.fixture.issues[1]['labels']}

    def test_lost_label_response_restart_reconciles_and_converges_without_duplicate_effect(self):
        def lost(method, path, body, response):
            if method != 'GET': raise TimeoutError('response severed after effect')
        self.fixture.after = lost
        unknown = self.advance()
        self.assertEqual('unknown', unknown['state']); self.assert_truth('unknown')
        reference = unknown['last_result']['receipt']['audit_reference']
        self.assertEqual(1, len(self.fixture.effects))
        self.reopen(); self.fixture.after = None
        self.assertEqual(unknown, self.advance())
        self.assertEqual(1, len(self.fixture.effects))
        result = self.advance('reconcile')
        self.assertEqual('repaired', result['state']); self.assert_truth('repaired')
        self.assertEqual({'type:bug', 'lifecycle:active', 'run:active'}, self.names())
        self.assertEqual(3, len(self.fixture.effects))
        audit = self.audit.get_mutation(reference)
        self.assertEqual('PARTIAL', audit['reconciliations'][-1]['observation']['status'])
        self.assertEqual('observed-only', audit['reconciliations'][-1]['observation']['attribution'])
        self.assertEqual(1, sum(m == 'POST' and b['labels'] == ['lifecycle:active']
            for m, p, b in self.fixture.effects))

    def test_known_partial_is_audited_then_reconciled_before_remaining_fields(self):
        self.fixture.before = lambda m, p, b: (
            self.fixture.response({}, 403) if m == 'POST' and len(self.fixture.effects) == 1 else None)
        partial = self.advance()
        self.assertEqual('partial', partial['state']); self.assert_truth('partial')
        self.assertIsNotNone(partial['unresolved_operation'])
        reference = partial['last_result']['receipt']['audit_reference']
        self.fixture.before = None
        self.assertEqual('repaired', self.advance('reconcile-partial')['state'])
        self.assert_truth('repaired')
        self.assertEqual(3, len(self.fixture.effects))
        self.assertEqual('PARTIAL', self.audit.get_mutation(reference)['reconciliations'][-1]['observation']['status'])
        self.assertEqual({'type:bug', 'lifecycle:active', 'run:active'}, self.names())

    def test_external_drift_repaired_without_changing_agent_work_labels_or_run_truth(self):
        self.advance()
        self.fixture.issues[1]['labels'] = [{'name': 'type:human'}, {'name': 'lifecycle:review'}]
        self.assertEqual('repaired', self.advance('external-drift')['state'])
        self.assertEqual({'type:human', 'lifecycle:active', 'run:active'}, self.names())
        self.assert_truth('repaired')
        drift = [e for e in self.ledger.replay(0) if e['kind'] == 'forge.projection-drifted']
        self.assertEqual(2, len(drift))
        self.assertEqual(['lifecycle:review'], drift[-1]['payload']['observation']['labels'])

    def test_failed_page_and_external_assignment_stay_explicit_without_repair(self):
        self.fixture.before = lambda m, p, b: self.fixture.response({}, 403) if '/labels?' in p else None
        self.assertEqual('unknown', self.advance('unreadable')['state']); self.assert_truth('unknown')
        self.assertEqual([], self.fixture.effects)
        self.fixture.before = None
        self.fixture.issues[1]['assignees'] = [{'id': 88}]
        result = self.advance('external-assignment')
        self.assertEqual('failed', result['state']); self.assert_truth('failed')
        self.assertEqual('ASSIGNMENT_CONFLICT', result['reason'])
        self.assertEqual([], self.fixture.effects)
        self.assertEqual([{'id': 88}], self.fixture.issues[1]['assignees'])

    def test_crash_after_hub_send_commit_before_broker_contact_does_not_invent_audit_row(self):
        self.adapter.crash_before_repair = True
        with self.assertRaises(Crash): self.advance()
        row = self.outbox.projection('run', origin=self.origin, authorize=lambda: True)
        operation = row['unresolved_operation']
        self.assertIsNone(self.audit.get_mutation(self.broker._key(operation)))
        self.reopen()
        self.outbox.recover('recover', 'run', origin=self.origin,
            authorize=lambda: True, fenced=lambda _: True)
        self.assertEqual('repaired', self.advance('new-attempt')['state'])
        self.assert_truth('repaired')
        self.assertEqual(3, len(self.fixture.effects))
        self.assertIsNone(self.audit.get_mutation(self.broker._key(operation)))

    def test_crash_after_effect_before_any_receipt_recovers_both_existing_owners(self):
        def crash(method, path, body, response):
            if method != 'GET': raise Crash()
        self.fixture.after = crash
        with self.assertRaises(Crash): self.advance()
        self.assertEqual(1, len(self.fixture.effects))
        self.reopen(); self.fixture.after = None
        # The existing external mutation owner terminalizes only proven-fenced
        # pending records. Hub recovery cannot invent that provider disposition.
        external = ExternalMutationBroker(self.binding, 'instance', self.audit,
            {'actor': 41}, lambda _: self.provider)
        external.recover(lambda _: True)
        self.outbox.recover('recover', 'run', origin=self.origin,
            authorize=lambda: True, fenced=lambda _: True)
        self.assertEqual('repaired', self.advance('new-attempt')['state'])
        self.assert_truth('repaired')
        self.assertEqual(3, len(self.fixture.effects))
        self.assertEqual({'type:bug', 'lifecycle:active', 'run:active'}, self.names())


if __name__ == '__main__': unittest.main()
