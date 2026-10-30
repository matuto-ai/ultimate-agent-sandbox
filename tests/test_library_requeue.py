"""T27 real Git/SQLite/service requeue of parked work; no live user data."""
from copy import deepcopy
import unittest
from unittest.mock import patch

import library_support as support
import test_library_controls as fixture
from uas import library
from uas import library_requeue as requeue
from uas.library_controls import canonical


class RequeueTests(unittest.TestCase):
    def setUp(self):
        self.fx = fixture.ControlsTests('test_operational_ack_no_git_or_model_and_exact_retry')
        self.fx.setUp(); self.addCleanup(self.fx.doCleanups)
        self.source = self.fx.source; self.service = self.fx.service
        self.controls = self.fx.controls; self.allowed = True
        self.principal = library.LocalHuman('human', 'actor', 'grant',
            lambda p, key, action: self.allowed and key == self.source.scope.project_identity
                and action in ('library-requeue', 'library-inspect'), lambda: True)

    def send(self, value):
        return self.controls.handle(canonical(value), self.principal)

    def entry(self):
        return self.service.scheduler._entries[self.source.scope.project_identity]

    def refused(self, value, code):
        with self.assertRaises(library.LibraryError) as error:
            self.send(value)
        self.assertEqual(error.exception.code, code)

    def restart(self):
        self.fx.fx.restart(); self.service = self.fx.fx.service
        self.controls.service = self.service

    def parked(self, drain='drain-park-1', *, bad=True):
        """One real source-failure parking commit through the assembly seam."""
        good, resolver = self.source.source(b'Resolvable source quotation.\n')
        missing, _ = self.source.source(b'Still-missing source quotation.\n')
        first = self.source.capture('good', sources=[good])
        second = self.source.capture('bad', sources=[missing]) if bad else None
        dead = missing['resource'] if bad else None
        self.source.assembler(lambda s, d: None).assemble(input_sha=self.source.head(),
            selected=tuple(q for q in (first, second) if q), drain_id=drain, attempt=1, at=support.AT)
        self.entry()['runner'].assembler.resolve_source = (
            lambda scope, declaration: None if declaration['resource'] == dead else resolver)
        return first, second, drain

    def value(self, drain, request='requeue-one'):
        observed = self.send(dict(version=1, action='observe', for_action='requeue',
                                  project_id='alpha'))
        return dict(version=1, action='requeue', project_id='alpha', request_id=request,
            drain_id=drain, settings_id=observed['settings_id'],
            observed_version=observed['observed_version'])

    def contents(self, path):
        return self.source.contents(path)

    def test_release_only_resolved_parked_work_in_one_canonical_commit(self):
        first, second, drain = self.parked()
        draft = self.contents('pending/' + first + '.md')
        state = deepcopy(self.entry()['state']); before = self.source.count()
        self.assertIn(first + '.md) - context; DRAFT PARKED: SOURCE_UNRESOLVED',
                      self.contents('pending/index.md'))
        value = self.value(drain)
        result = self.send(value)
        self.assertEqual(result['outcome'], 'COMMITTED')
        self.assertEqual(result['publication']['commit_sha'], self.source.head())
        self.assertEqual(result['publication']['path'].rsplit('/', 1)[-1], 'log.md')
        self.assertEqual(self.source.count(), before + 1)
        index = self.contents('pending/index.md')
        self.assertIn(first + '.md) - context; draft;', index)
        self.assertIn(second + '.md) - context; DRAFT PARKED: SOURCE_UNRESOLVED', index)
        # Release preserves the draft bytes and the readable pending state.
        self.assertEqual(self.contents('pending/' + first + '.md'), draft)
        log = self.contents('log.md')
        marker = log.rsplit(requeue.MARKER, 1)[1].splitlines()[0]
        self.assertIn(first, marker); self.assertIn(second, marker)
        self.assertIn('SOURCE_UNRESOLVED', marker)
        self.assertNotIn('Selected draft data.', marker)
        # A release is not a drain: state, drain identity and any block remain.
        self.assertEqual(self.entry()['state'], state)
        self.assertFalse(self.fx.fx.fixture.marker.exists())
        # Exact retry cannot repeat the release; changed payload under the same
        # request identity is a conflict.
        self.assertEqual(self.send(value), result)
        self.assertEqual(self.source.count(), before + 1)
        self.refused({**value, 'drain_id': 'other-drain'}, 'ID_CONFLICT')
        # Restart derives the release from canonical Git, not service memory.
        self.restart()
        self.assertIn(first + '.md) - context; draft;', self.contents('pending/index.md'))
        self.assertIn(first, self.service.scheduler._batch(self.entry()))
        self.assertNotIn(second, self.service.scheduler._batch(self.entry()))

    def test_retained_work_can_be_requeued_after_its_prerequisite_resolves(self):
        first, second, drain = self.parked()
        self.send(self.value(drain))
        resolver = self.source.source(b'Still-missing source quotation.\n')[1]
        self.entry()['runner'].assembler.resolve_source = lambda scope, declaration: resolver
        before = self.source.count()
        result = self.send(self.value(drain, 'requeue-two'))
        self.assertEqual(result['outcome'], 'COMMITTED')
        self.assertEqual(self.source.count(), before + 1)
        self.assertIn(second + '.md) - context; draft;', self.contents('pending/index.md'))

    def test_unresolved_contradiction_is_never_released(self):
        result = self.service.tick()
        self.assertEqual(result['state'], 'COMMITTED')
        drain = result['drain_id']
        self.assertIn('* **Synthesis**: ' + drain, self.contents('log.md'))
        self.assertIn('DRAFT PARKED: NEEDS_EVIDENCE', self.contents('pending/index.md'))
        before = self.source.count(); state = deepcopy(self.entry()['state'])
        self.refused(self.value(drain), 'NO_ELIGIBLE_PARKED_WORK')
        self.assertEqual(self.source.count(), before)
        self.assertIn('DRAFT PARKED: NEEDS_EVIDENCE', self.contents('pending/index.md'))
        self.assertEqual(self.entry()['state'], state)

    def test_stale_archived_busy_and_revoked_authority_refused(self):
        first, second, drain = self.parked()
        value = self.value(drain); before = self.source.count()
        self.source.capture('newer')
        self.refused(value, 'STALE_CONTROL_STATE')
        self.assertEqual(self.source.count(), before + 1)
        value = self.value(drain)
        self.allowed = False
        self.refused(value, 'FORBIDDEN')
        self.allowed = True
        self.entry()['state'].update(state='ACTIVE', selected=[first])
        self.refused(self.value(drain), 'CONTROL_BUSY')
        self.entry()['state'].update(state='READY', selected=[])
        value = self.value(drain)
        path = 'projects/' + self.source.scope.project_path + '/index.md'
        self.source.mutate({path: self.source.root_bytes() + b'\nLibrary state: archived\n'})
        self.refused(value, 'PROJECT_ARCHIVED')
        self.assertIn(first + '.md) - context; DRAFT PARKED: SOURCE_UNRESOLVED',
                      self.contents('pending/index.md'))

    def test_blocked_project_is_not_bypassed_or_released_by_a_requeue(self):
        first, second, drain = self.parked()
        self.entry()['state'].update(state='BLOCKED', due=None, reason='MODEL_FAILURE',
                                     drain_id=None, selected=[], attempt=3)
        blocked = deepcopy(self.entry()['state'])
        result = self.send(self.value(drain))
        self.assertEqual(result['outcome'], 'COMMITTED')
        self.assertIn(first + '.md) - context; draft;', self.contents('pending/index.md'))
        # Releasing canonical work neither clears the block nor executes it.
        self.assertEqual(self.entry()['state'], blocked)
        self.assertIsNone(self.service.tick())
        self.assertFalse(self.fx.fx.fixture.marker.exists())

    def test_lost_acknowledgement_reconciles_without_repeating_the_release(self):
        first, second, drain = self.parked()
        value = self.value(drain); before = self.source.count()
        with patch.object(requeue, 'finish', side_effect=RuntimeError('crash')):
            with self.assertRaises(RuntimeError):
                self.send(value)
        self.assertEqual(self.source.count(), before + 1)
        self.restart()
        result = self.send(value)
        self.assertEqual(result['outcome'], 'COMMITTED')
        self.assertEqual(result['publication']['commit_sha'], self.source.head())
        self.assertEqual(self.source.count(), before + 1)
        self.assertIn(first + '.md) - context; draft;', self.contents('pending/index.md'))

    def test_unknown_pre_push_outcome_never_reapplies(self):
        first, second, drain = self.parked()
        value = self.value(drain); before = self.source.count()
        def publish(operation, *a, **kw):
            with self.service.scheduler._records() as records:
                records.begin(operation)
            raise library.LibraryError('PUBLICATION_UNCERTAIN')
        with patch.object(self.source.publisher, 'publish', publish):
            self.refused(value, 'PUBLICATION_UNCERTAIN')
        self.restart()
        self.refused(value, 'CONTROL_OUTCOME_UNKNOWN')
        self.assertEqual(self.source.count(), before)
        self.assertIn(first + '.md) - context; DRAFT PARKED: SOURCE_UNRESOLVED',
                      self.contents('pending/index.md'))
