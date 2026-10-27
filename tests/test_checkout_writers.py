"""Pure Engine-observation contracts; actual writer evidence is the Docker job."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from uas.checkout_writers import DockerCheckoutBackend, DockerCheckoutWriters
from uas.lifecycle import BackendUnknown, LifecycleError, OwnershipConflict, Supervisor


class CheckoutWriterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.repo, self.slots = root / 'repo', root / 'checkouts'
        self.repo.mkdir(); self.slots.mkdir()
        self.backend = DockerCheckoutBackend(self.repo, self.slots)
        self.supervisor = Supervisor(root / 'control', 'alpha', self.backend,
                                     authorize=lambda *_: True, revoke=lambda *_: True)
        self.guard = DockerCheckoutWriters(self.supervisor)
        self.lifecycle = {'instance_id': 'a' * 32, 'phase': 'running',
                          'spec': {'project_paths': [str(self.repo), str(self.slots)]}}
        self.resource = {'Id': 'b' * 64, 'State': {
            'Status': 'running', 'Running': True, 'Pid': 123,
            'Paused': False, 'Restarting': False, 'Dead': False,
            'StartedAt': '2026-10-27T14:00:00.123456789Z',
            'FinishedAt': '0001-01-01T00:00:00Z'}}
        with patch.object(self.backend, 'admit', return_value=self.resource):
            self.scope = self.guard.capture(self.lifecycle)

    def observe(self, resource):
        with patch.object(self.backend, '_inspect_object', return_value=resource):
            return self.guard.quiescent(self.lifecycle, self.scope)

    def stopped(self):
        resource = deepcopy(self.resource)
        resource['State'].update(Status='exited', Running=False, Pid=0,
            FinishedAt='2026-10-27T14:01:00.123456789Z')
        return resource

    def test_only_current_exact_stopped_container_proves_whole_writer_set(self):
        self.assertFalse(self.observe(self.resource))
        self.assertTrue(self.observe(self.stopped()))
        restarted = deepcopy(self.resource)
        restarted['State']['StartedAt'] = '2026-10-27T14:02:00Z'
        self.assertFalse(self.observe(restarted))
        other = self.stopped(); other['Id'] = 'c' * 64
        self.assertFalse(self.observe(other))
        self.assertFalse(self.observe(None))
        # A label/name match is checked by the backend; failures are not empty.
        for error in (BackendUnknown(), OwnershipConflict(), OSError('unavailable')):
            with patch.object(self.backend, '_inspect_object', side_effect=error):
                self.assertFalse(self.guard.quiescent(self.lifecycle, self.scope))

    def test_malformed_unknown_or_transitioning_state_never_means_stopped(self):
        mutations = [('Running', 0), ('Pid', False), ('Pid', 123), ('Status', 'dead'),
                     ('Paused', True), ('Restarting', True), ('Dead', True),
                     ('FinishedAt', '0001-01-01T00:00:00Z'), ('FinishedAt', 'invalid'),
                     ('StartedAt', None)]
        for key, value in mutations:
            with self.subTest(key=key, value=value):
                resource = self.stopped(); resource['State'][key] = value
                self.assertFalse(self.observe(resource))
        for key in self.stopped()['State']:
            resource = self.stopped(); del resource['State'][key]
            self.assertFalse(self.observe(resource))

    def test_durable_scope_roundtrip_and_wrong_instance_or_legacy_fail_closed(self):
        scope = json.loads(json.dumps(self.scope))
        self.assertTrue(self.guard.valid_scope(scope, self.lifecycle['instance_id']))
        for value in (None, {}, {**scope, 'instance': 'c' * 32},
                      {**scope, 'container': 'docker-name'}, {**scope, 'extra': True}):
            with patch.object(self.backend, '_inspect_object', side_effect=AssertionError('no inspect')):
                self.assertFalse(self.guard.quiescent(self.lifecycle, value))

    def test_capture_is_fresh_admitted_and_rejects_inconsistent_lifecycle(self):
        with patch.object(self.backend, 'admit', side_effect=BackendUnknown()):
            with self.assertRaises(LifecycleError) as error: self.guard.capture(self.lifecycle)
            self.assertEqual('WRITER_OBSERVATION_UNKNOWN', error.exception.code)
        with patch.object(self.backend, 'admit', return_value=self.stopped()):
            with self.assertRaises(LifecycleError): self.guard.capture(self.lifecycle)
            self.lifecycle['phase'] = 'stopped'
            self.assertEqual(self.scope, self.guard.capture(self.lifecycle))

    def test_writable_policy_is_only_two_configured_exact_paths(self):
        self.assertTrue(self.backend._project_writable(self.lifecycle, str(self.repo)))
        self.assertTrue(self.backend._project_writable(self.lifecycle, str(self.slots)))
        self.assertFalse(self.backend._project_writable(self.lifecycle, '/other'))
        self.lifecycle['spec']['project_paths'].remove(str(self.slots))
        with self.assertRaises(LifecycleError):
            self.backend._project_writable(self.lifecycle, str(self.repo))
