"""Pure configuration/selection checks; no native or credential access."""
from copy import deepcopy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from uas.native_qualification import QualificationPlan, QualificationError, write_startup
from types import SimpleNamespace
from unittest.mock import Mock
from uas.native_image_package import payload, envelope, inventory


class NativeQualificationTests(unittest.TestCase):
    def test_stalled_broker_pipe_has_finite_deadline_and_no_retry(self):
        stream = SimpleNamespace(fileno=lambda: 55, close=Mock())
        with patch('os.set_blocking') as nonblocking, patch('time.monotonic', return_value=1), \
                patch('select.select', return_value=([], [], [])), patch('os.write') as write:
            with self.assertRaisesRegex(QualificationError, 'BROKER_STARTUP_TIMEOUT'):
                write_startup(stream, b'public startup', 3)
        nonblocking.assert_called_once_with(55, False)
        write.assert_not_called(); stream.close.assert_called_once_with()

    def test_broker_pipe_setup_failure_closes_stream(self):
        stream = SimpleNamespace(fileno=lambda: 55, close=Mock())
        with patch("os.set_blocking", side_effect=OSError("closed")):
            with self.assertRaises(OSError):
                write_startup(stream, b"public startup", 3)
        stream.close.assert_called_once_with()

    def test_broker_pipe_partial_write_does_not_resend_prefix(self):
        stream = SimpleNamespace(fileno=lambda: 55, close=Mock())
        with patch('os.set_blocking'), patch('time.monotonic', return_value=1), \
                patch('select.select', return_value=([], [55], [])), patch('os.write', side_effect=[2, 3]) as write:
            write_startup(stream, b'abcde', 3)
        self.assertEqual([call.args for call in write.call_args_list], [(55, b'abcde'), (55, b'cde')])
        stream.close.assert_called_once_with()

    def setUp(self):
        self.config = json.loads((Path(__file__).parent / 'fixtures/two-rooms.json').read_text())
        for runtime, provider in zip(('pi', 'claude'), self.config['deployment']['providers']):
            provider.pop('endpoint', None)
            provider['model'] = 'selected-model'
            provider['auth'] = {'credential_ref': runtime + '-runtime',
                'method': 'pi-oauth-json' if runtime == 'pi' else 'claude-oauth-token'}
            self.config['deployment']['credentials'].append({'id': runtime + '-runtime', 'kind': 'runtime-provider'})
        self.selection = {'version': 1, 'profile': 'disposable-native-v1',
            'room_id': 'alpha', 'nonce': 'a' * 32, 'timeout_seconds': 90,
            'human_mergers': [7],
            'pi_manifest': {'path': '/installation/pi.json', 'sha256': 'b' * 64},
            'claude_manifest': {'path': '/installation/claude.json', 'sha256': 'c' * 64}}
        for name in ('boundary', 'hub', 'broker'):
            self.selection[name + '_manifest'] = {'path': '/installation/' + name + '.json', 'sha256': 'a' * 64}
        self.config['deployment']['actors'][1]['github_user_id'] = 8
        self.manifests = {runtime: envelope(payload(runtime, dict.fromkeys(inventory(runtime), 'd' * 64)),
            image_reference=self.config['deployment']['images'][0]['reference'],
            image_id='sha256:' + 'e' * 64) for runtime in ('pi', 'claude')}

    def plan(self):
        return QualificationPlan(json.dumps(self.config), self.selection, installation_digest='f' * 64)

    def test_check_only_reports_observations_not_authority(self):
        with patch('uas.native_qualification.read_manifest', side_effect=lambda name, digest:
                   deepcopy(self.manifests['pi' if name.endswith('/pi.json') else 'claude'])) as reader:
            result = self.plan().check()
        self.assertFalse(result['effects'])
        self.assertEqual(result['production_launcher'], 'disabled')
        self.assertEqual(result['missing_prerequisites'], [])
        self.assertIn('RUN_ADMISSION_NATIVE_ADAPTER_UNAVAILABLE', result['lifecycle_blockers'])
        self.assertEqual(reader.call_count, 2)
        self.assertNotIn('/providers/', json.dumps(result))

    def test_selection_rejects_extra_authority_or_secret_fields(self):
        for key, value in (('qualified', True), ('token', 'secret'), ('callback', 'arbitrary.module')):
            with self.subTest(key=key):
                original = deepcopy(self.selection)
                self.selection[key] = value
                with self.assertRaises(QualificationError): self.plan()
                self.selection = original

    def test_manifest_digest_is_required_before_parsing_selection(self):
        with patch('uas.native_qualification.read_manifest', side_effect=ValueError('untrusted')) as reader:
            with self.assertRaisesRegex(QualificationError, 'INSTALLATION_REFERENCE_UNVERIFIABLE'):
                QualificationPlan.read(json.dumps(self.config), '/installation/selected.json', 'f' * 64)
        reader.assert_called_once_with('/installation/selected.json', 'f' * 64)

    def test_no_auth_or_custom_provider_cannot_silently_fallback(self):
        provider = self.config['deployment']['providers'][0]
        saved = provider.pop('auth')
        with self.assertRaisesRegex(QualificationError, 'RUNTIME_AUTH_REFERENCE_REQUIRED'): self.plan()
        provider['auth'] = saved
        provider['endpoint'] = 'https://example.com/v1'
        with self.assertRaisesRegex(QualificationError, 'CUSTOM_PROVIDER_NOT_QUALIFIED'): self.plan()

    def test_timeout_is_finite_not_boolean(self):
        for value in (True, 0, 181, 1.5, None):
            self.selection['timeout_seconds'] = value
            with self.assertRaises(QualificationError): self.plan()

    def test_changed_manifest_inventory_or_paired_image_is_rejected(self):
        self.manifests['pi']['artifacts'] = {}
        with patch('uas.native_qualification.read_manifest', side_effect=lambda name, digest:
                   deepcopy(self.manifests['pi' if name.endswith('/pi.json') else 'claude'])):
            self.assertIn('PI_IMAGE_MANIFEST_UNAVAILABLE', self.plan().check()['missing_prerequisites'])
        self.manifests['pi'] = envelope(payload('pi', dict.fromkeys(inventory('pi'), 'd' * 64)),
            image_reference=self.config['deployment']['images'][0]['reference'], image_id='sha256:' + '9' * 64)
        with patch('uas.native_qualification.read_manifest', side_effect=lambda name, digest:
                   deepcopy(self.manifests['pi' if name.endswith('/pi.json') else 'claude'])):
            self.assertIn('PAIRED_IMAGE_ID_MISMATCH', self.plan().check()['missing_prerequisites'])
