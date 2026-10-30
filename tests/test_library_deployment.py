"""T40 Deployment composition over real disposable Git, SQLite and sockets.

The external target, credential reference, qualification evidence, model runner,
Room ledgers and reference mounts are controlled fixtures here. This does not
claim an installed daemon, live provider, actual target qualification or VM.
"""
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest

import library_support as support
from test_library_git import git
from uas import library, library_controls
from uas.ledger import RoomLedger
from uas.library_assembly import Assembler
from uas.library_attempts import Attempts
from uas.library_deployment import DeploymentLibrary
from uas.library_dispatch import Dispatcher, Gateway, Profile
from uas.library_git import LibraryGit
from uas.library_registration import Registrar


class LocalTransport(LibraryGit):
    """Map the admitted SSH name to disposable local Git; no network/auth proof."""
    canonical = None

    def _environment(self):
        env = super()._environment()
        env.update({'GIT_ALLOW_PROTOCOL': 'file', 'GIT_CONFIG_COUNT': '1',
                    'GIT_CONFIG_KEY_0': 'url.' + str(type(self).canonical) + '.insteadOf',
                    'GIT_CONFIG_VALUE_0': self.target})
        return env


class DeploymentLibraryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.canonical = self.base / 'canonical.git'
        git(self.base, 'init', '--bare', '-q', str(self.canonical))
        LocalTransport.canonical = self.canonical
        document = support.document()
        document['repository'].update(target='ssh://git@example.test/library.git', branch='main')
        self.document = document
        self.state = self.base / 'state'
        self.state.mkdir(mode=0o700)
        self.projects, self.origins = {}, {'alpha': support.ORIGIN, 'beta': support.OTHER}
        for room, repository, source in (('alpha', 'acme/alpha', '1001'),
                                         ('beta', 'acme/beta', '1002')):
            reference = self.base / room / 'reference'
            reference.mkdir(mode=0o755, parents=True)
            self.projects[room] = {
                'project': {'id': room, 'repository': repository,
                            'roots': {'reference': str(reference)}},
                'source_identity': source}
        self.hubs = {}

    # --- controlled trusted owners ----------------------------------------

    def scope_for(self, binding):
        return library.participant_scope(self.origins[binding['project_id']], binding=binding)

    def runner_for(self, scope):
        profile = Profile('synth-local', 'local', 'provider-one', 'v1',
                          'http://127.0.0.1:1234/selected', 'local', 'zero', 'terms-v1')
        marker = self.base / (scope.project_id + '-contact')
        reply = {'version': 1, 'drain_id': 'drain-1', 'attempt': 1,
                 'operations': [], 'outcomes': []}
        gateway = Gateway({profile.identity(): (
            sys.executable, str(Path(__file__).with_name('fixture_library_provider.py')),
            str(marker), 'success', json.dumps(reply))}, interactive=lambda: False)
        publisher = self.deployment.publisher
        dispatcher = Dispatcher(
            gateway, current_scope=lambda: scope, settings=lambda: self.deployment.settings,
            selection=lambda _scope: None, current=lambda _request: True,
            token_count=lambda _profile, body: len(body), audit=lambda _event: None,
            records_path=publisher.records_path, deployment_id=publisher.deployment_id)
        assembler = Assembler(
            publisher, current_scope=lambda: scope,
            settings=lambda: self.deployment.settings,
            resolve_source=lambda _scope, _declaration: None,
            token_count=lambda body: len(body))
        return Attempts(assembler, dispatcher), lambda _selected: ((), ())

    def ledger_for(self, room):
        return RoomLedger(self.base / room / 'hub.db', room)

    def make_deployment(self, **overrides):
        options = dict(
            state_root=self.state, deployment_id='deployment-1', settings=self.document,
            credentials={'target-cred': {}}, rooms=self.projects, scope_for=self.scope_for,
            runner_for=self.runner_for, ledger_for=self.ledger_for,
            authenticate=lambda: True, qualification=lambda _settings: True,
            publisher_factory=LocalTransport,
            now=lambda: datetime(2026, 10, 30, tzinfo=timezone.utc))
        options.update(overrides)
        value = DeploymentLibrary(**options)
        self.deployment = value
        self.addCleanup(lambda: value.stop() if value.running else None)
        return value

    def register(self, deployment, room):
        entry = self.projects[room]
        binding = library.project_binding(entry['project'], source_identity=entry['source_identity'])
        human = library.human_scope(support.session(('library-register',)), binding=binding,
                                    kind='register')
        settings = deployment.settings
        return Registrar(deployment.publisher, current_scope=lambda: human).register(
            library.action(human, settings, kind='register', operation_id='register-' + room,
                           request_id='register-' + room, payload={}, at=support.AT), settings)

    def enqueue(self, deployment, room, title, suffix='one'):
        key = (id(deployment), room)
        if key not in self.hubs:
            self.hubs[key] = deployment.hub(room)
        hub = self.hubs[key]
        request = {'id': 'command-' + room + '-' + suffix, 'kind': 'library.enqueue',
                   'request_id': 'request-' + room + '-' + suffix,
                   'capture': support.value(title=title, body='Body for ' + title + '.\n')}
        prepared = hub.prepare(request, self.origins[room], authorize=lambda: True)
        result = hub.perform(prepared, current=lambda: True)
        return hub.finish(prepared, result, authorize=lambda: True)

    def head(self):
        return git(self.canonical, 'rev-parse', 'refs/heads/main').strip()

    def events(self, room):
        with RoomLedger(self.base / room / 'hub.db', room) as ledger:
            return [event for event in ledger.replay(0, limit=1000)
                    if event['kind'] == 'library.drain.reported']

    def wait_for(self, predicate, seconds=10):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.05)
        return False

    # --- fail closed -------------------------------------------------------

    def test_missing_credential_qualification_and_mount_fail_closed_untouched(self):
        with self.assertRaisesRegex(library.LibraryError, 'MISSING_FIELD'):
            self.make_deployment(settings={'version': 1}).start()
        with self.assertRaisesRegex(library.LibraryError, 'CREDENTIAL_REFERENCE_UNAVAILABLE'):
            self.make_deployment(credentials={}).start()
        with self.assertRaisesRegex(library.LibraryError, 'TARGET_NOT_QUALIFIED'):
            self.make_deployment(qualification=None).start()
        with self.assertRaisesRegex(library.LibraryError, 'TARGET_NOT_QUALIFIED'):
            self.make_deployment(qualification=lambda _settings: False).start()
        rooms = deepcopy(self.projects)
        rooms['beta']['project']['roots']['reference'] = str(self.base / 'missing' / 'reference')
        with self.assertRaisesRegex(library.LibraryError, 'UNSAFE_REFERENCE_ROOT'):
            self.make_deployment(rooms=rooms).start()
        self.assertFalse((self.state / 'library').exists())

    def test_second_instance_is_refused_before_clone_work(self):
        first = self.make_deployment()
        first.start()
        self.assertTrue(first.running)
        second = self.make_deployment()
        with self.assertRaisesRegex(library.LibraryError, 'LEASE_BUSY'):
            second.start()
        self.assertFalse(second.running)
        self.assertTrue(first.running)
        self.assertEqual(self.register(first, 'alpha').commit_sha, self.head())

    # --- bounded Room projections -----------------------------------------

    def test_two_rooms_publish_only_their_own_coherent_projection(self):
        deployment = self.make_deployment()
        deployment.start()
        for room in ('alpha', 'beta'):
            self.register(deployment, room)
            self.assertTrue(deployment.wait_idle(room))
        published = {}
        for room, marker in (('alpha', 'ALPHA_ONLY_MARKER'), ('beta', 'BETA_ONLY_MARKER')):
            result = self.enqueue(deployment, room, marker)
            self.assertEqual(result['outcome'], 'DURABLY_QUEUED', result)
            published[room] = result['published_sha']
            self.assertTrue(deployment.wait_idle(room))
        for room, other in (('alpha', 'beta'), ('beta', 'alpha')):
            view = deployment.read(room)
            self.assertEqual(view.manifest['commit_sha'], published[room])
            self.assertEqual(view.manifest['project_id'], room)
            data = b''.join(view.files.values())
            self.assertIn((room.upper() + '_ONLY_MARKER').encode(), data)
            self.assertNotIn((other.upper() + '_ONLY_MARKER').encode(), data)
            self.assertNotIn(b'clone.git', data)
            self.assertNotIn(str(self.state / 'library').encode(), data)
            self.assertTrue(all('.git' not in Path(path).parts for path in view.files))
            self.assertFalse(any(path.startswith('projects/') for path in view.files))

    def test_room_stop_and_restart_keep_canonical_data_and_the_singleton(self):
        deployment = self.make_deployment()
        deployment.start()
        self.register(deployment, 'alpha')
        self.assertTrue(deployment.wait_idle('alpha'))
        self.enqueue(deployment, 'alpha', 'FIRST_MARKER')
        self.assertTrue(deployment.wait_idle('alpha'))
        head = self.head()
        self.assertEqual(deployment.publisher.clone_path, self.state / 'library' / 'clone.git')
        self.assertTrue(deployment.stop_room('alpha'))
        self.assertFalse(deployment.stop_room('alpha'))
        with self.assertRaisesRegex(library.LibraryError, 'ROOM_NOT_BOUND'):
            deployment.hub('alpha')
        with self.assertRaisesRegex(library.LibraryError, 'INVALID_PROJECT_BINDING'):
            deployment.start_room('gamma')
        self.assertEqual(self.head(), head)
        self.assertTrue((self.base / 'alpha' / 'reference' / 'library.snapshot.json').exists())
        self.assertTrue(deployment.running)
        self.assertTrue(deployment.service.scheduler is not None)
        deployment.start_room('alpha')
        self.assertEqual(deployment.read('alpha').manifest['commit_sha'], head)
        result = self.enqueue(deployment, 'alpha', 'SECOND_MARKER', suffix='two')
        self.assertEqual(result['outcome'], 'DURABLY_QUEUED', result)
        self.assertNotEqual(self.head(), head)
        deployment.stop()
        self.assertFalse(deployment.running)
        restarted = self.make_deployment()
        restarted.start()
        self.assertTrue(restarted.wait_idle('alpha'))
        self.assertEqual(restarted.read('alpha').manifest['commit_sha'], self.head())

    # --- independent host-local operator path -----------------------------

    def test_operator_path_serves_a_stopped_room_without_any_hub(self):
        identity = library.project_binding(
            self.projects['alpha']['project'],
            source_identity=self.projects['alpha']['source_identity'])['project_identity']
        principal = library.LocalHuman(
            'human-1', 'human-actor', 'authority-1',
            lambda _principal, project_identity, action: (
                project_identity == identity and action in ('library-drain', 'library-retry')),
            lambda: True)
        deployment = self.make_deployment(operator=lambda _uid: principal)
        deployment.start()
        self.register(deployment, 'alpha')
        self.assertTrue(deployment.wait_idle('alpha'))
        self.assertTrue(deployment.stop_room('alpha'))
        root = self.state / 'library' / 'operator'
        self.assertTrue(self.wait_for(lambda: (root / 'library-operator.sock').exists()))
        response = library_controls.request(
            root, {'version': 1, 'action': 'observe', 'project_id': 'alpha',
                   'for_action': 'drain'})
        self.assertEqual(response['outcome'], 'observed')
        self.assertEqual(response['result']['project_id'], 'alpha')
        self.assertTrue(response['result']['observed_version'])
        encoded = json.dumps(response)
        self.assertNotIn('clone.git', encoded)
        self.assertNotIn(str(self.state / 'library'), encoded)
        refused = library_controls.request(
            root, {'version': 1, 'action': 'observe', 'project_id': 'beta',
                   'for_action': 'drain'})
        self.assertEqual(refused['outcome'], 'unknown')
        self.assertEqual(refused['error'], 'FORBIDDEN')

    # --- service-to-Room ingress ------------------------------------------

    def test_service_reports_reach_each_room_ledger_without_a_hub(self):
        deployment = self.make_deployment()
        deployment.start()
        identities = {
            room: library.project_binding(self.projects[room]['project'],
                                          source_identity=self.projects[room]['source_identity']
                                          )['project_identity']
            for room in ('alpha', 'beta')}
        self.assertTrue(self.wait_for(
            lambda: all(self.events(room) for room in ('alpha', 'beta'))))
        for room, other in (('alpha', 'beta'), ('beta', 'alpha')):
            reports = [event['payload'] for event in self.events(room)]
            self.assertTrue(reports)
            self.assertTrue(all(report['room_id'] == room for report in reports))
            self.assertTrue(all(report['project_identity'] == identities[room]
                                for report in reports))
            self.assertNotIn(identities[other], json.dumps(reports))
