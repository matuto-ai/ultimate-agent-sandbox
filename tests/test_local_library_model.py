"""Installed model-evidence consumer: external authority file, no live inference.

The positive dispatch uses the real composition/Attempts/Git and a deterministic
adapter subprocess. Its synthetic evidence is not actual T42 qualification.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import library_support as support
from fixture_library_selection import write_selection
import test_library_attempts as attempt_tests
from uas import library, local_library
from uas.library_dispatch import Profile, Selection
from uas.local_installation import LocalInstallationError


class InstalledModelEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.profile = Profile('synth-local', 'local', 'provider-one', 'v1',
                               'http://127.0.0.1:1234/selected', 'local', 'zero', 'terms-v1')
        self.binding = support.binding()
        self.scope = library.participant_scope(support.ORIGIN, binding=self.binding)
        self.settings = support.settings()
        self.now = datetime(2026, 10, 31, tzinfo=timezone.utc)
        self.path = self.base / 'authority.json'
        self.command = ['/bin/true']
        self.model = {'profile': self.profile, 'command': tuple(self.command),
                      'selection': write_selection(self.path, profile=self.profile,
                          command=self.command, bindings=[self.binding])}

    def select(self, scope=None):
        return local_library._selected_model(self.model, scope or self.scope, self.settings,
                                              self.now, {self.binding['project_identity']})

    def mutate(self, change, *, repin=True):
        value = json.loads(self.path.read_bytes())
        change(value)
        self.path.write_text(json.dumps(value))
        if repin:
            self.model['selection']['sha256'] = hashlib.sha256(self.path.read_bytes()).hexdigest()

    def test_typed_selection_is_read_from_separate_pinned_authority(self):
        selected = self.select()
        self.assertIs(type(selected), Selection)
        self.assertEqual(selected.profile, self.profile)
        self.assertEqual(selected.qualification.reference, 'synth-qualification')
        self.assertEqual(selected.authorization.reference, 'synth-local')
        self.assertEqual(selected.authorization.project_identity, self.scope.project_identity)
        self.assertIsNone(selected.hosted_approval)

    def test_model_document_requires_reference_not_inline_self_attestation(self):
        value = {'profile': vars(self.profile), 'command': self.command}
        with self.assertRaisesRegex(LocalInstallationError, 'LIBRARY_DOCUMENT_MODEL'):
            local_library._model(value, self.settings)
        value['selection'] = {'qualified': True}
        with self.assertRaisesRegex(LocalInstallationError, 'INVALID_REFERENCE'):
            local_library._model(value, self.settings)
        value['selection'] = self.model['selection']
        self.assertEqual(local_library._model(value, self.settings), self.model)

    def test_every_reference_read_is_live_and_digest_pinned(self):
        self.select()
        self.mutate(lambda d: d.update(version=2), repin=False)
        with self.assertRaisesRegex(library.LibraryError, 'MODEL_EVIDENCE_INVALID'):
            self.select()
        self.path.unlink()
        with self.assertRaisesRegex(library.LibraryError, 'MODEL_EVIDENCE_INVALID'):
            self.select()

    def test_expiry_is_rechecked_without_restarting_the_service(self):
        self.select()
        self.now = datetime(2030, 1, 1, tzinfo=timezone.utc)
        with self.assertRaisesRegex(library.LibraryError, 'MODEL_EVIDENCE_INVALID'):
            self.select()

    def test_unsafe_or_symlinked_authority_is_refused(self):
        self.path.chmod(0o666)
        with self.assertRaisesRegex(library.LibraryError, 'MODEL_EVIDENCE_INVALID'):
            self.select()
        self.path.chmod(0o600)
        moved = self.path.with_suffix('.original')
        self.path.rename(moved)
        self.path.symlink_to(moved)
        with self.assertRaisesRegex(library.LibraryError, 'MODEL_EVIDENCE_INVALID'):
            self.select()

    def test_route_project_reference_expiry_and_revocation_bindings(self):
        original = self.path.read_bytes()
        project = self.scope.project_identity
        changes = (
            lambda d: d.update(profile_sha256='a' * 64),
            lambda d: d.update(command_sha256='a' * 64),
            lambda d: d['selections'].update({'b' * 64: d['selections'][project]}),
            lambda d: d['selections'][project]['qualification'].update(reference='wrong-ref'),
            lambda d: d['selections'][project]['authorization'].update(reference='wrong-ref'),
            lambda d: d['selections'][project]['qualification'].update(profile_sha256='a' * 64),
            lambda d: d['selections'][project]['authorization'].update(project_identity='b' * 64),
            lambda d: d['selections'][project]['qualification'].update(qualified=False),
            lambda d: d['selections'][project]['authorization'].update(valid_until='2020-01-01T00:00:00+00:00'),
            lambda d: d['selections'][project].update(hosted_approval={}),
        )
        for change in changes:
            self.path.write_bytes(original)
            self.mutate(change)
            with self.subTest(change=change), self.assertRaisesRegex(library.LibraryError, 'MODEL_EVIDENCE_INVALID'):
                self.select()

    def test_absent_evidence_refuses_composition_before_any_clone(self):
        self.path.unlink()
        admitted = self.admitted(self.settings, self.model)
        with self.assertRaisesRegex(library.LibraryError, 'MODEL_EVIDENCE_INVALID'):
            local_library.composition(admitted, deployment_id='deployment-1',
                state_root=self.base / 'state', ledger_for=lambda room: None,
                now=lambda: self.now)
        self.assertFalse((self.base / 'state').exists())

    def admitted(self, settings, model):
        return {'settings': settings, 'model': model,
                'rooms': {'alpha': {'project': {'id': 'alpha', 'repository': 'acme/alpha',
                            'roots': {'reference': '/srv/alpha/reference'}},
                         'source_identity': '1001', 'binding': self.binding}},
                'credentials': {}, 'operator': None,
                'qualification': {'qualified': True,
                    'target': settings['repository']['target'],
                    'branch': settings['repository']['branch']}}

    def real_runner(self):
        fixture = attempt_tests.AttemptTests('test_parking_commit_has_durable_inputs_before_contact_and_recovery_outcomes')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        reply = {'version': 1, 'drain_id': 'drain-1', 'attempt': 1, 'operations': [],
                 'outcomes': [{'queue_id': fixture.q, 'kind': 'parked', 'reason': 'NEEDS_EVIDENCE'}]}
        command = [sys.executable, str(Path(__file__).with_name('fixture_library_provider.py')),
                   str(fixture.marker), 'success', json.dumps(reply)]
        model = {'profile': fixture.profile, 'command': tuple(command),
                 'selection': write_selection(self.path, profile=fixture.profile,
                      command=command, bindings=[self.binding])}
        admitted = self.admitted(fixture.source.settings, model)
        deployment = local_library.composition(admitted, deployment_id='deployment-1',
            state_root=self.base / 'state', ledger_for=lambda room: None, now=lambda: self.now)
        # Reuse a real disposable, registered canonical target; this isolates
        # dispatch plumbing from the separately tested host/projection lifetime.
        deployment._publisher = fixture.source.publisher
        runner, _context = deployment.runner_for(fixture.source.scope)
        return fixture, runner

    def test_installed_runner_reaches_fixed_adapter_and_commits_valid_result(self):
        fixture, runner = self.real_runner()
        result = runner.run(drain_id='drain-1', attempt=1, selected=[fixture.q], at=support.AT)
        self.assertEqual(result.state, 'COMMITTED')
        self.assertTrue(fixture.marker.exists())
        self.assertEqual(result.outcomes[0]['kind'], 'parked')

    def test_revocation_after_adapter_contact_discards_result(self):
        fixture, runner = self.real_runner()
        original = runner.dispatcher.gateway.call
        def revoke(*args, **kwargs):
            result = original(*args, **kwargs)
            self.path.unlink()
            return result
        with patch.object(runner.dispatcher.gateway, 'call', revoke):
            with self.assertRaisesRegex(library.LibraryError, 'MODEL_EVIDENCE_INVALID'):
                runner.run(drain_id='drain-1', attempt=1, selected=[fixture.q], at=support.AT)
        self.assertTrue(fixture.marker.exists())
        self.assertIn(fixture.q, fixture.source.contents('pending/index.md'))
