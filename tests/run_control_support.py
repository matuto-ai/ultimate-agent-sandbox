"""Pure Run-domain fixture: SQLite and synthetic ownership, never native setup.

Do not replace this with the Pi/Git harness: those fixtures start real processes.
Native effect methods below fail closed unless a test explicitly supplies a
small synthetic observation. These objects are not process-authentication proof.
"""
from contextlib import nullcontext
from copy import deepcopy
from dataclasses import asdict, dataclass
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from uas.config import load
from uas.ledger import Command, Event, LedgerError, Origin, RoomLedger, Transition
from uas.peer import FixtureParticipant, FixturePeerHub
from uas.run_admission import RunAdmission


def no_native(*_args, **_kwargs):
    raise AssertionError('pure Run fixture must not invoke a native effect')


@dataclass(frozen=True)
class PureSeat:
    participant_id: str
    actor_id: str
    profile_id: str
    capabilities: tuple
    runtime: str = 'pi-fixture'
    arguments: tuple = ()
    provider_host: str = 'forge.fixture.invalid'
    required_credentials: tuple = ()

    def document(self):
        return json.loads(json.dumps(asdict(self)))


class RunControlCase(unittest.TestCase):
    """Shared test fixture; source assertions only, with all native paths inert."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        source = json.loads((Path(__file__).parent / 'fixtures/two-rooms.json').read_text())
        source['deployment']['actors'][0]['github_user_id'] = 41
        source['deployment']['actors'][1]['github_user_id'] = 42
        source['rooms'][0]['profiles'][1]['capabilities'].append('can-open-requested-run')
        self.config = load(io.StringIO(json.dumps(source)))
        self.room = self.config['rooms'][0]
        self.ledger = RoomLedger(self.root / 'room.db', self.room['id'])
        self.addCleanup(self.ledger.close)
        self.hub = FixturePeerHub(self.ledger)
        self.hub.configure('configure', (FixtureParticipant('builder', 'alice'),
            FixtureParticipant('reviewer', 'bob')), 'bootstrap')
        self.authorized = True
        self.participant_authorized = True
        self.human = Origin('operator', 'human', 'manager-session', 'human-v1',
                            ('human-open-run', 'human-control-run'))
        self.origin = Origin('bob', 'reviewer', 'synthetic-requester', 'test-authority',
                             ('peer-traffic', 'can-open-requested-run'))
        self.seat = PureSeat('builder', 'alice', 'worker',
                            ('peer-traffic', 'forge-read', 'implement'))
        self.supervisor = SimpleNamespace(directory=self.root, _locked=nullcontext)
        self.controller_document = {'seats': {}, 'retired_pids': []}
        self.controller = SimpleNamespace(supervisor=self.supervisor, hub=self.hub,
            handles={}, _room=lambda **_kwargs: {'phase': 'running'},
            _read=lambda: deepcopy(self.controller_document),
            launch_pi=no_native, reset_pi=no_native, restore_pi=no_native,
            revoke=no_native, _alive=no_native, _authority=no_native)
        self.broker = SimpleNamespace(ledger=self.ledger, assignments=None,
            binding=SimpleNamespace(project_id='alpha', repository='example/alpha'),
            prepare=no_native, perform=no_native, complete=no_native)
        self.controller.forge_broker = self.broker
        self.allocator = SimpleNamespace(supervisor=self.supervisor, room=self.room,
            status=lambda: [], allocate=no_native, release=no_native, reconcile=no_native)
        self.admission = RunAdmission.__new__(RunAdmission)
        for name in ('controller', 'hub', 'ledger', 'supervisor', 'broker', 'allocator', 'room'):
            setattr(self.admission, name, getattr(self, name))
        self.admission.actors = {actor['id']: actor for actor in self.config['deployment']['actors']}
        self.admission.seats = {'builder': self.seat}
        self.admission.install = None
        self.admission.runtime_root = self.root / 'native-never-started'
        self.admission.authorize_human = lambda *_args: self.authorized
        self._seed_number = 0

    def authorize_participant(self):
        return self.participant_authorized

    def state(self):
        return self.ledger.snapshot()['state']

    def seed(self, change):
        self._seed_number += 1
        operation = 'pure-seed-' + str(self._seed_number)
        def decide(state, _command):
            change(state)
            return Transition(state, (Event('fixture.pure-state', {}),), {})
        return self.ledger.apply(Command(operation, 'fixture.pure-state', 'alpha', None, {}),
            self.human, authorize=lambda *_args: True, decide=decide)

    def seed_run(self, **changes):
        row = {'run_id': 'run-test', 'generation': 1, 'status': 'ACTIVE',
            'outcome': None, 'issue_number': 1, 'issue_id': 1001,
            'repository': 'example/alpha', 'project_id': 'alpha',
            'participant_id': 'builder', 'actor_id': 'alice', 'github_user_id': 41,
            'delivery_class': 'bounded', 'policy': deepcopy(self.room['policies'][0]),
            'checkout': {'run': 'run-test', 'participant': 'builder',
                         'path': str(self.root / 'checkout'), 'slot': 'primary'},
            'context_generation': 1, 'implementation_request': 'implementation-run-test',
            'human_operation': 'open-run-test', 'authorization_consumed': True,
            'control_revision': 0, 'control_reason': None, 'projection': 'pending',
            'assignment_audit': None}
        row.update(changes)
        def add(state):
            state.setdefault('runs', {})[row['run_id']] = deepcopy(row)
            state.setdefault('run_admissions', {})[row['run_id']] = {
                'status': 'ACTIVE', 'issue_number': row['issue_number'],
                'participant_id': row['participant_id'], 'authorization_consumed': True}
            state['fixture_context']['runs'][row['run_id']] = {
                'generation': row['generation'], 'status': 'OPEN', 'terminal_fact': None}
            state['fixture_context']['participants'][row['participant_id']].update(
                bound_run={'run_id': row['run_id'], 'generation': row['generation']},
                reserved_run=None)
        self.seed(add)
        return deepcopy(row)

    def error(self, code, action):
        with self.assertRaises(LedgerError) as caught:
            action()
        self.assertEqual(code, caught.exception.code)

