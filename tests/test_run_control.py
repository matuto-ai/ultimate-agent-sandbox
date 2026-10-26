"""Canonical control command fencing; synthetic state, no native proof claim."""
from concurrent.futures import ThreadPoolExecutor
from copy import copy, deepcopy
from dataclasses import replace
import threading
import unittest

import test_pi_run_admission as harness
from uas.context import MAX_CONTEXT_GENERATION
from uas.ledger import Command, Event, LedgerError, RoomLedger, Transition


class RunControlTests(unittest.TestCase):
    setUp = harness.RunAdmissionTests.setUp
    capture_evidence = harness.RunAdmissionTests.capture_evidence
    git = harness.RunAdmissionTests.git
    reopen_supervisor = harness.RunAdmissionTests.reopen_supervisor
    reopen = harness.RunAdmissionTests.reopen
    issue = harness.RunAdmissionTests.issue
    transport = harness.RunAdmissionTests.transport
    error = harness.RunAdmissionTests.error

    def seed(self, **changes):
        self.human = replace(self.human, capabilities=('human-control-run',))
        row = {'run_id': 'run-test', 'generation': 1, 'status': 'ACTIVE',
               'control_revision': 0, 'control_reason': None, 'policy': {'version': 1}}
        row.update(changes)
        self.ledger.apply(Command('seed', 'fixture.seed', 'alpha', None, {}), self.human,
            authorize=lambda *_: True, decide=lambda state, _: Transition(
                {**state, 'runs': {'run-test': row}}, (Event('fixture.seeded', {}),), {}))
        return deepcopy(row)

    def pause(self, op='pause', revision=0, generation=1, human=None):
        return self.admission.pause(op, 'run-test', generation, revision, 'human-hold', human=human or self.human)

    def test_exact_retry_replay_authorization_and_revision_aba_fencing(self):
        row = self.seed()
        paused = self.pause()
        resumed = self.admission.resume('resume', 'run-test', 1, 1, 'continue', human=self.human)
        self.assertEqual(2, resumed['control_revision'])
        self.assertEqual(paused, self.pause())
        self.pause('pause-again', 2)
        self.assertEqual(resumed, self.admission.resume('resume', 'run-test', 1, 1, 'continue', human=self.human))
        self.error('STALE_RUN_CONTROL', lambda: self.admission.resume('old-resume', 'run-test', 1, 1, 'continue', human=self.human))
        self.error('ID_CONFLICT', lambda: self.pause(revision=3))
        state = self.ledger.snapshot()
        self.authorized = False
        self.error('FORBIDDEN', self.pause)
        self.authorized = True
        self.error('FORBIDDEN', lambda: self.pause(human=replace(self.human, capabilities=('human-open-run',))))
        self.error('STALE_RUN_GENERATION', lambda: self.pause('stale-generation', 3, 2))
        self.assertEqual(state, self.ledger.snapshot())
        self.assertEqual(row['policy'], state['state']['runs']['run-test']['policy'])
        with RoomLedger(self.root / 'room.db', 'alpha') as ledger:
            restored = copy(self.admission)
            restored.ledger = ledger
            self.assertEqual(paused, restored.pause('pause', 'run-test', 1, 0, 'human-hold', human=self.human))
        self.assertEqual(['run.paused', 'run.resumed', 'run.paused'], [e['kind'] for e in self.ledger.replay(0) if e['kind'].startswith('run.')])

    def test_invalid_target_transition_types_and_exhaustion_have_no_effects(self):
        self.seed(control_revision=MAX_CONTEXT_GENERATION)
        before = self.ledger.snapshot()
        self.error('RUN_CONTROL_REVISION_EXHAUSTED', lambda: self.pause(revision=MAX_CONTEXT_GENERATION))
        self.error('UNKNOWN_RUN', lambda: self.admission.pause('unknown', 'missing', 1, 0, 'hold', human=self.human))
        self.error('INVALID_RUN_TRANSITION', lambda: self.admission.resume('resume', 'run-test', 1, MAX_CONTEXT_GENERATION, 'go', human=self.human))
        for value in (True, -1, 1.0, '1', MAX_CONTEXT_GENERATION + 1):
            self.error('INVALID_RUN_CONTROL', lambda: self.pause(revision=value))
            self.error('INVALID_RUN_CONTROL', lambda: self.pause(generation=value))
        self.assertEqual(before, self.ledger.snapshot())
        self.assertEqual([], self.allocator.status())
        self.assertEqual([], self.calls)

    def test_concurrent_same_revision_has_one_winner(self):
        self.seed()
        barrier = threading.Barrier(2)
        def pause(operation):
            with RoomLedger(self.root / 'room.db', 'alpha') as ledger:
                admission = copy(self.admission)
                admission.ledger = ledger
                barrier.wait(timeout=5)
                try:
                    return admission.pause(operation, 'run-test', 1, 0, 'hold', human=self.human)['status']
                except LedgerError as error:
                    return error.code
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertCountEqual(['PAUSED', 'STALE_RUN_CONTROL'], pool.map(pause, ['race-a', 'race-b']))
        self.assertEqual(1, self.ledger.snapshot()['state']['runs']['run-test']['control_revision'])

    def test_pending_admission_has_no_queued_control_or_consumed_authority(self):
        run, _ = self.admission._prepare('pending-open', 1, 'builder', self.human)
        control = replace(self.human, capabilities=('human-control-run',))
        before = self.ledger.snapshot()
        self.error('UNKNOWN_RUN', lambda: self.admission.pause('pending-pause', run, 1, 0, 'hold', human=control))
        self.assertEqual(before, self.ledger.snapshot())
        self.assertFalse(before['state']['run_admissions'][run]['authorization_consumed'])
        self.assertEqual([], self.calls)
        self.assertEqual([], self.allocator.status())

    def test_closed_run_cannot_resume_or_pause(self):
        self.seed(status='CLOSED')
        before = self.ledger.snapshot()
        self.error('INVALID_RUN_TRANSITION', self.pause)
        self.error('INVALID_RUN_TRANSITION', lambda: self.admission.resume('resume', 'run-test', 1, 0, 'go', human=self.human))
        self.assertEqual(before, self.ledger.snapshot())

    def test_callback_receives_exact_scope_and_other_origin_cannot_recover_receipt(self):
        self.seed()
        commands = []
        def authorize(origin, command):
            commands.append(command)
            return command.target == 'run-test' and command.payload['reason'] == 'human-hold'
        self.admission.authorize_human = authorize
        self.pause()
        self.assertEqual('run.human-pause', commands[-1].kind)
        self.assertEqual(1, commands[-1].generation)
        self.assertEqual({'expected_revision': 0, 'reason': 'human-hold'}, commands[-1].payload)
        self.error('FORBIDDEN', lambda: self.admission.resume('resume', 'run-test', 1, 1, 'other-reason', human=self.human))
        self.error('ID_CONFLICT', lambda: self.pause(human=replace(self.human, actor_id='another-operator')))

    def test_control_commit_failure_rolls_back_and_lost_ack_reconciles_exactly(self):
        from unittest.mock import patch
        self.seed()
        before = self.ledger.snapshot()
        with patch.object(self.ledger, '_commit', side_effect=LedgerError('STORAGE_ERROR')):
            self.error('STORAGE_ERROR', self.pause)
        self.assertEqual(before, self.ledger.snapshot())
        commit = self.ledger._commit
        def commit_then_lose():
            commit()
            raise LedgerError('STORAGE_ERROR')
        with patch.object(self.ledger, '_commit', commit_then_lose):
            self.error('STORAGE_ERROR', self.pause)
        committed = self.ledger.snapshot()
        self.assertEqual('PAUSED', committed['state']['runs']['run-test']['status'])
        self.assertEqual(1, committed['state']['runs']['run-test']['control_revision'])
        with RoomLedger(self.root / 'room.db', 'alpha') as ledger:
            restored = copy(self.admission)
            restored.ledger = ledger
            result = restored.pause('pause', 'run-test', 1, 0, 'human-hold', human=self.human)
        self.assertEqual('PAUSED', result['status'])
        self.assertEqual(committed, self.ledger.snapshot())
        self.assertEqual(1, len([e for e in self.ledger.replay(0) if e['kind'] == 'run.paused']))
