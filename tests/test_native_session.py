"""Controlled lifecycle orchestration tests, never native/runtime evidence."""
from contextlib import ExitStack
from io import StringIO
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from uas.native_session import SessionBudget, dispatch, admit_once, admission_cleanup
from uas.native_host_forge import NativePiHostForge, NativeHostForge
from uas.workstation_control import SupervisorAdmission
from uas.native_qualification import QualificationError
from uas.__main__ import main
from uas.native_session import _hub
from uas.docker_exec_api import DockerExecAPI
from uas.workstation_service import RELEASE
import json
from pathlib import Path
from uas.workstation_exec import ExecSeat, EndpointLease, ExecLaunch
from uas.native_pi_recipe import NativePiRecipe, NativeMount
from uas.native_claude_recipe import NativeClaudeRecipe
from uas.claude_native_admission import NativeClaudeHostLaunch
import test_native_qualification as qualification_fixture


class NativeSessionTests(unittest.TestCase):
    def test_actual_recipe_and_exec_owners_share_short_exact_endpoint(self):
        fixture = qualification_fixture.NativeQualificationTests(); fixture.setUp()
        fixture.config['rooms'][0]['seats'][0]['arguments'] = ['--provider', 'openai']
        plan = fixture.plan(); room = plan.room
        endpoint = object.__new__(EndpointLease)
        endpoint.path = Path('/run/uas-native/' + 'a' * 32 + '/peer/pi.sock')
        mounts = tuple(NativeMount(value, value, key == 'reference')
                       for key, value in room['project']['roots'].items()) + (
            NativeMount(room['state_root'] + '/runtime', room['state_root'] + '/runtime', False),
            NativeMount(str(endpoint.path.parent), str(endpoint.path.parent), True))
        scope = {'room_id': room['id'], 'run_id': 'qualification-scope', 'generation': 1, 'context_generation': 1}
        with patch('uas.native_pi_recipe.read_manifest', return_value=fixture.manifests['pi']), \
                patch('uas.native_claude_recipe.read_manifest', return_value=fixture.manifests['claude']):
            p = plan.seats['pi']
            seat = ExecSeat(room['id'], 'a' * 32, p['participant'], p['actor'], 'seat-a', 'c' * 64, 165532, 165532)
            recipe = NativePiRecipe.from_configuration(StringIO(plan.config_text), room['id'], seat.participant_id,
                '/private/pi.json', 'b' * 64, seat=seat, scope={**scope, 'participant_id': seat.participant_id},
                checkout=room['project']['roots']['repo'], runtime_root=room['state_root'] + '/runtime',
                endpoint=str(endpoint.path), mounts=mounts)
            owner = ExecLaunch(object(), seat, endpoint, '/private/pi-launch.json', native_recipe=recipe)
            self.assertEqual(owner.native_recipe.endpoint, str(owner.endpoint.path))
            c = plan.seats['claude']
            seat = ExecSeat(room['id'], 'a' * 32, c['participant'], c['actor'], 'seat-b', 'c' * 64, 165532, 165532)
            recipe = NativeClaudeRecipe.from_configuration(StringIO(plan.config_text), room['id'], seat.participant_id,
                '/private/claude.json', 'c' * 64, seat=seat, scope={**scope, 'participant_id': seat.participant_id},
                checkout=room['project']['roots']['repo'], runtime_root=room['state_root'] + '/runtime',
                home=room['state_root'] + '/runtime/seat-b/contexts/1/home', endpoint=str(endpoint.path),
                session_id='11111111-1111-4111-8111-111111111111', mounts=mounts)
            owner = NativeClaudeHostLaunch(object(), recipe, endpoint, '/private/claude-launch.json')
            self.assertEqual(owner.recipe.endpoint, str(owner.endpoint.path))
            self.assertLess(len(owner.recipe.endpoint.encode()), 108)

    def services(self):
        services = (object.__new__(NativePiHostForge), object.__new__(NativeHostForge))
        for service in services:
            service.helper = SimpleNamespace(forge_channel=object())
            service._current = Mock(return_value=True)
            service.receive_once = Mock(return_value={'ok': True})
        return services

    def test_budget_never_resets_and_refuses_expiry(self):
        with patch('uas.native_session.time.monotonic', side_effect=[10, 11, 13]):
            budget = SessionBudget(2)
            self.assertEqual(budget.remaining(), 1)
            with self.assertRaisesRegex(QualificationError, 'DEADLINE'): budget.remaining()

    def test_dispatch_calls_exact_services_once_per_record(self):
        services = self.services()
        with patch('uas.native_session.time.monotonic', return_value=10), \
                patch('uas.native_session.select.select', return_value=([s.helper.forge_channel for s in services], [], [])):
            result = dispatch(services, SessionBudget(90), max_packets=2)
        self.assertEqual(result, {'packets': 2, 'stop': 'packet-budget-exhausted'})
        for service in services: service.receive_once.assert_called_once_with()

    def test_uncertain_request_is_not_resent(self):
        services = self.services(); services[0].receive_once.side_effect = TimeoutError()
        with patch('uas.native_session.time.monotonic', return_value=10), \
                patch('uas.native_session.select.select', return_value=([services[0].helper.forge_channel], [], [])):
            with self.assertRaises(TimeoutError): dispatch(services, SessionBudget(90))
        services[0].receive_once.assert_called_once_with()
        services[1].receive_once.assert_not_called()

    def test_provider_operation_not_started_without_whole_budget(self):
        services = self.services()
        with patch('uas.native_session.time.monotonic', return_value=10), \
                patch('uas.native_session.select.select') as poll:
            result = dispatch(services, SessionBudget(30))
        self.assertEqual(result['stop'], 'operation-budget-exhausted')
        poll.assert_not_called()
        for service in services: service.receive_once.assert_not_called()

    def test_admit_unknown_reconciles_same_owner_without_second_transfer(self):
        admission = object.__new__(SupervisorAdmission)
        admission.admit = Mock(side_effect=TimeoutError())
        admission.status = Mock(return_value={'installed': True, 'state': 'active'})
        self.assertTrue(admit_once(admission, 'a' * 32)['installed'])
        admission.admit.assert_called_once_with('a' * 32, 1)
        admission.status.assert_called_once_with()

    def test_admit_unknown_status_does_not_become_success(self):
        admission = object.__new__(SupervisorAdmission)
        admission.admit = Mock(side_effect=TimeoutError()); admission.status = Mock(side_effect=TimeoutError())
        with self.assertRaisesRegex(QualificationError, 'PI_ADMISSION_UNKNOWN'): admit_once(admission, 'a' * 32)
        self.assertEqual(admission.admit.call_count, 1)

    def test_revocation_precedes_store_close_even_setup_failure(self):
        events = []
        first = SimpleNamespace(revoke=lambda: events.append('first-revoke'))
        second = SimpleNamespace(revoke=lambda: events.append('second-revoke'))
        with self.assertRaises(ValueError):
            with ExitStack() as stack, admission_cleanup([first, second]):
                stack.callback(lambda: events.append('store-close'))
                raise ValueError('setup failed')
        self.assertEqual(events, ['second-revoke', 'first-revoke', 'store-close'])

    def test_failed_revoke_never_claims_success(self):
        admission = SimpleNamespace(revoke=Mock(side_effect=TimeoutError()))
        with self.assertRaisesRegex(QualificationError, 'REVOCATION_UNKNOWN'):
            with admission_cleanup([admission]): pass

    def test_existing_cli_invalid_utf8_remains_unreadable(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'invalid.json'
            source.write_bytes(b'\xff')
            for argv in (["validate-config", str(source)],
                         ["check-launch", str(source), "--room", "room-a"]):
                with self.subTest(command=argv[0]), patch('sys.stderr', new_callable=StringIO) as error:
                    self.assertEqual(main(argv), 2)
                    self.assertEqual(json.loads(error.getvalue())['error'], 'CONFIG_UNREADABLE')

    def test_cli_default_consumes_check_only_and_never_execute(self):
        plan = SimpleNamespace(preflight=Mock(return_value={'mode': 'check-only', 'effects': False}))
        with patch('uas.native_qualification.QualificationPlan.read', return_value=plan), \
                patch('uas.native_qualification.execute') as execute, \
                patch('sys.stdin', StringIO('{}')), patch('sys.stdout', StringIO()):
            result = main(['qualify-native', '-', '--installation', '/public/selected.json',
                           '--installation-sha256', 'a' * 64])
        self.assertEqual(result, 3); plan.preflight.assert_called_once_with(); execute.assert_not_called()

    def test_cli_explicit_execute_consumes_actual_execute_branch(self):
        plan = SimpleNamespace(preflight=Mock())
        with patch('uas.native_qualification.QualificationPlan.read', return_value=plan), \
                patch('uas.native_qualification.execute', return_value={'status': 'NATIVE_PAIR_ATTACHED'}) as execute, \
                patch('sys.stdin', StringIO('{}')), patch('sys.stdout', StringIO()):
            result = main(['qualify-native', '-', '--installation', '/public/selected.json',
                           '--installation-sha256', 'a' * 64, '--execute-qualification'])
        self.assertEqual(result, 0); execute.assert_called_once_with(plan); plan.preflight.assert_not_called()

    def test_actual_hub_bootstrap_calls_engine_attach_then_start_once(self):
        events = []
        engine = object.__new__(DockerExecAPI)
        stream = SimpleNamespace(close=lambda: events.append('stream-close'),
                                 write=lambda raw, timeout: events.append(('startup', json.loads(raw))))
        engine.attach_hub = Mock(side_effect=lambda identifier: (events.append('attach'), stream)[1])
        engine.start_hub = Mock(side_effect=lambda identifier: events.append('start'))
        channel = SimpleNamespace(close=lambda: events.append('control-close'), settimeout=Mock(),
                                  send=Mock(return_value=len(RELEASE)))
        listener = SimpleNamespace(settimeout=Mock(), accept=lambda: (channel, None))
        identity = SimpleNamespace(identity=(1, 2), require=Mock(), close=Mock())
        ready = {'version': 1, 'kind': 'HUB_READY', 'controller': 'c' * 32,
                 'room_id': 'room', 'room_instance': 'a' * 32, 'observation': {}}
        class Record:
            def __init__(self, data): self.data = data; self.credentials = (123, 165531, 165531)
            def __enter__(self): return self
            def __exit__(self, *args): pass
        resources = {'control_path': '/owned/control.sock', 'instance': 'a' * 32,
                     'mapping_digest': 'd' * 64, 'hub_id': 'e' * 64}
        plan = SimpleNamespace(room={'id': 'room', 'project': {'id': 'project', 'repository': 'owner/repo'},
            'profiles': [{'id': 'profile', 'capabilities': ['forge-read']}],
            'seats': [{'participant': p, 'actor': p, 'profile': 'profile'} for p in ('alice', 'bob')]})
        with patch('uas.native_session.time.monotonic', return_value=10), \
                patch('uas.native_session.EndpointLease', return_value=SimpleNamespace(require=Mock())), \
                patch('uas.native_session.os.pidfd_open', return_value=77), \
                patch('uas.native_session.os.close'), patch('uas.native_session._identity', return_value=(3, 4)), \
                patch('uas.native_session.enable'), patch('uas.native_session.HeldOrigin', return_value=identity), \
                patch('uas.native_session.secrets.token_hex', return_value='f' * 64), \
                patch('uas.native_session.receive', side_effect=[Record(b'HUB1' + bytes.fromhex('f' * 64)),
                                                               Record(json.dumps(ready).encode())]):
            with ExitStack() as stack:
                result = _hub(engine, resources, plan, None, listener, stack, SessionBudget(90))
                self.assertIs(result[1], identity)
        self.assertEqual(events[:2], ['attach', 'start'])
        engine.attach_hub.assert_called_once_with('e' * 64)
        engine.start_hub.assert_called_once_with('e' * 64)
        self.assertEqual(events[2][1]['run_id'], 'qualification-scope')
