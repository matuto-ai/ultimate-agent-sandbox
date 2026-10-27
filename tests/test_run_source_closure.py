"""Pure peer-only closure and explicit configured-Run dependency failures."""
import builtins
from contextlib import contextmanager
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from uas.ledger import Command, Event, Origin, RoomLedger, Transition
from uas.peer import FixtureParticipant, FixturePeerHub, Message, WorkRequest


@contextmanager
def unavailable_run_modules():
    original = builtins.__import__
    def checked(name, globals=None, locals=None, fromlist=(), level=0):
        if ((level == 1 and (globals or {}).get('__package__') == 'uas'
             and name in {'run_control', 'run_coordination'})
                or name in {'uas.run_control', 'uas.run_coordination'}):
            raise ModuleNotFoundError('configured Run dependency unavailable: ' + name)
        return original(name, globals, locals, fromlist, level)
    with patch('builtins.__import__', checked):
        yield


class RunSourceClosureTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.ledger = RoomLedger(Path(directory.name) / 'room.db', 'room')
        self.addCleanup(self.ledger.close)
        self.hub = FixturePeerHub(self.ledger)
        self.hub.configure('configure', (FixtureParticipant('alice', 'actor-a'),
                                        FixtureParticipant('bob', 'actor-b')), 'peer-only')
        self.alice = self.hub.connect('alice', 'alice', 'alice-one', object())
        self.bob = self.hub.connect('bob', 'bob', 'bob-one', object())

    def test_peer_only_messages_requests_and_pending_need_no_run_owner(self):
        with unavailable_run_modules():
            self.hub.submit(self.alice, Message('message', 'peer-only', 1, 'bob', 'message'))
            self.hub.submit(self.alice, WorkRequest('request', 'peer-only', 1, 'bob', 'work'))
            self.assertEqual(['message', 'request'], [r['id'] for r in self.hub._pending(self.bob)])
            self.hub._reserve_capacity(self.ledger.snapshot()['state'])
        self.assertNotIn('runs', self.ledger.snapshot()['state'])

    def test_canonical_capacity_never_silently_omits_required_run_owner(self):
        for domain in ('runs', 'run_admissions'):
            state = self.ledger.snapshot()['state']
            state[domain] = {'canonical': {'status': 'ACTIVE'}}
            with unavailable_run_modules(), self.assertRaisesRegex(ModuleNotFoundError, 'run_control'):
                self.hub._reserve_capacity(state)

    def test_canonical_request_and_pending_require_coordination_dependency(self):
        self.hub.submit(self.alice, WorkRequest('before-run', 'peer-only', 1, 'bob', 'work'))
        def seed(state, _):
            state['runs'] = {'peer-only': {'run_id': 'peer-only', 'generation': 1, 'status': 'ACTIVE'}}
            return Transition(state, (Event('fixture.seed', {}),), {})
        origin = Origin('fixture', 'fixture', 'fixture', 'fixture', ('fixture-control',))
        self.ledger.apply(Command('seed', 'fixture.seed', 'peer-only', 1, {}), origin,
                          authorize=lambda *_: True, decide=seed)
        before = self.ledger.snapshot()
        with unavailable_run_modules():
            with self.assertRaisesRegex(ModuleNotFoundError, 'run_coordination'):
                self.hub.submit(self.alice, WorkRequest('after-run', 'peer-only', 1, 'bob', 'work'))
            with self.assertRaisesRegex(ModuleNotFoundError, 'run_coordination'):
                self.hub._pending(self.bob)
        self.assertEqual(before, self.ledger.snapshot())
