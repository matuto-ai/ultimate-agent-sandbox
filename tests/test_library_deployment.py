"""T40 Deployment composition over real disposable Git, SQLite and sockets.

The external target, credential reference, qualification evidence, model runner,
Room ledgers and reference mounts are controlled fixtures here. This does not
claim an installed daemon, live provider, actual target qualification or VM.
"""
from copy import deepcopy
from datetime import datetime, timezone
import json
import multiprocessing
import socket
from pathlib import Path
import sys
import tempfile
import threading
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

    def test_split_process_endpoint_binds_room_and_revokes_after_stop(self):
        deployment = self.make_deployment().start()
        from unittest.mock import Mock
        ledger_for = Mock(side_effect=AssertionError('endpoint must not open Hub ledger'))
        with unittest.mock.patch.object(deployment, 'ledger_for', ledger_for):
            endpoint = deployment.endpoint('alpha')
        ledger_for.assert_not_called()
        public = deployment.binding('alpha')
        self.assertEqual(public, self.projects['alpha'])
        public['project']['id'] = 'forged'
        self.assertEqual(deployment.binding('alpha')['project']['id'], 'alpha')
        endpoint.guard()
        deployment.stop_room('alpha')
        with self.assertRaisesRegex(library.LibraryError, 'ROOM_NOT_BOUND'):
            endpoint.guard()
        with self.assertRaisesRegex(library.LibraryError, 'ROOM_NOT_BOUND'):
            deployment.endpoint('alpha')
        self.assertTrue(deployment.bound('beta'))

    def test_installed_report_transport_refuses_foreign_and_uncertain_results(self):
        from unittest.mock import Mock
        deployment = self.make_deployment()
        transport = Mock(return_value=False)
        deployment.set_report_transport(transport)
        deployment.start()
        transport.reset_mock()
        report = {'room_id': 'alpha', 'project_identity': 'foreign'}
        self.assertFalse(deployment._transport(report))
        transport.assert_not_called()
        report['project_identity'] = deployment._rooms['alpha'].scope.project_identity
        self.assertFalse(deployment._transport(report))
        transport.return_value = True
        self.assertTrue(deployment._transport(report))
        transport.return_value = {'recorded': True}
        self.assertFalse(deployment._transport(report))
        transport.side_effect = OSError('lost reply')
        self.assertFalse(deployment._transport(report))
        with self.assertRaisesRegex(library.LibraryError, 'DEPLOYMENT_DEPENDENCY_REQUIRED'):
            deployment.set_report_transport(lambda _: True)

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
        writable = self.base / 'alpha' / 'reference'
        writable.chmod(0o777)
        self.addCleanup(writable.chmod, 0o755)
        with self.assertRaisesRegex(library.LibraryError, 'UNSAFE_REFERENCE_ROOT'):
            self.make_deployment().start()
        self.assertFalse((self.state / 'library').exists())

    def test_symlinked_service_state_is_refused_before_any_clone(self):
        service = self.state / 'library'
        service.symlink_to(self.base / 'alpha' / 'reference')
        with self.assertRaisesRegex(library.LibraryError, 'INVALID_DEPLOYMENT_STATE'):
            self.make_deployment().start()
        reference = self.base / 'alpha' / 'reference'
        self.assertFalse((reference / 'clone.git').exists())
        self.assertEqual(list(reference.iterdir()), [])

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

    def test_invalidated_qualification_blocks_capture_and_stops_writes(self):
        allowed = [True]
        deployment = self.make_deployment(qualification=lambda _settings: allowed[0])
        deployment.start()
        self.register(deployment, 'alpha')
        self.assertTrue(deployment.wait_idle('alpha'))
        self.enqueue(deployment, 'alpha', 'QUALIFIED_MARKER')
        self.assertTrue(deployment.wait_idle('alpha'))
        head = self.head()
        allowed[0] = False
        result = self.enqueue(deployment, 'alpha', 'BLOCKED_MARKER', suffix='blocked')
        self.assertNotEqual(result['outcome'], 'DURABLY_QUEUED')
        self.assertEqual(self.head(), head)
        self.assertTrue(self.wait_for(lambda: not deployment.running, seconds=3))
        with self.assertRaises(library.LibraryError):
            deployment.hub('alpha')
        deployment.stop()
        allowed[0] = True
        restarted = self.make_deployment(qualification=lambda _settings: allowed[0])
        restarted.start()
        self.assertTrue(restarted.wait_idle('alpha'))
        self.assertEqual(restarted.read('alpha').manifest['commit_sha'], head)

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
        # A restarted Room receives a fresh endpoint. Its retired Hub cannot
        # regain capture authority merely because the same Project rebound.
        stale = self.enqueue(deployment, 'alpha', 'STALE_MARKER', suffix='stale')
        self.assertNotEqual(stale['outcome'], 'DURABLY_QUEUED')
        self.assertEqual(self.head(), head)
        self.hubs.pop((id(deployment), 'alpha'))
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

    def test_manager_to_local_disposition_after_room_destroy(self):
        """T44 continuity over real Git/SQLite/Unix socket, not a human/VM run.

        Seed a blocked batch (synthesis is separately covered), inspect through
        the actual Manager adapter, then destroy its owned lifecycle instance.
        The container backend is a file fixture, not Docker/VM isolation proof.
        The same singleton and canonical data must remain locally operable.
        """
        from lifecycle_support import FileFixtureBackend
        from uas.lifecycle import FixtureSpec, Supervisor
        from uas.ledger import Origin
        from uas.manager_actions import HumanSession
        from uas.manager_library_transport import (
            FieldNotesLibraryHost, ManagerLibraryHub, LibraryServiceContact)

        identity = library.project_binding(
            self.projects['alpha']['project'], source_identity='1001')['project_identity']
        allowed, connected = [True], [True]
        principal = library.LocalHuman('t44-human', 't44-actor', 't44-grant',
            lambda _human, key, action: allowed[0] and key == identity and action in (
                'library-inspect', 'library-adjudicate', 'library-resume'), lambda: True)
        backend = FileFixtureBackend(self.base / 'resources')
        def revoke(instance, scope):
            connected[0] = False
            self.deployment.stop_room('alpha')
            return backend.revoke(instance, scope)
        supervisor = Supervisor(self.base / 'control', 'alpha', backend,
            authorize=lambda *_: True, revoke=revoke)
        spec = FixtureSpec('alpha', 'alpha', (str(self.base / 'alpha'),),
            'sha256:' + 'a' * 64, 'sha256:' + 'b' * 64, 'sha256:' + 'c' * 64)
        started = supervisor.start(spec)
        self.assertEqual(started['phase'], 'running')
        instance = self.base / 'control' / 'alpha' / 'instances' / started['instance_id']
        room_data = instance / 'data'
        deployment = self.make_deployment(operator=lambda _uid: principal,
            ledger_for=lambda room: RoomLedger(room_data / 'hub.db', room)
                if room == 'alpha' else self.ledger_for(room)).start()
        for room in ('alpha', 'beta'):
            self.register(deployment, room)
            self.assertTrue(deployment.wait_idle(room))
        first = self.enqueue(deployment, 'alpha', 'T44_PRIVATE_INSPECTION')
        second = self.enqueue(deployment, 'alpha', 'T44_RETAINED_DRAFT', suffix='two')
        self.assertEqual(first['outcome'], 'DURABLY_QUEUED')
        self.assertEqual(second['outcome'], 'DURABLY_QUEUED')
        queue, retained = first['queue_id'], second['queue_id']
        self.assertTrue(deployment.wait_idle('alpha'))
        beta = deployment.read('beta')
        scheduler = deployment.service.scheduler
        with scheduler._lock:
            entry = scheduler._entries[identity]
            scheduler._save(entry, {**entry['state'], 'state': 'BLOCKED',
                'drain_id': 't44-original', 'selected': [queue, retained],
                'attempt': 1, 'reason': 'MODEL_FAILURE', 'due': None}, scheduler.now())
        controls = library_controls.Controls(deployment.service)
        ledger = RoomLedger(room_data / 'manager-private.db', 'alpha')
        self.addCleanup(ledger.close)
        session = HumanSession('deployment-1', 'alpha', 't44-instance', 't44-human',
            Origin('t44-actor', 't44-human', 't44-incarnation', 't44-grant', ()),
            lambda *_: allowed[0], lambda: connected[0])
        context = object()
        hub = ManagerLibraryHub(ledger, deployment_id='deployment-1', room_id='alpha',
            instance_id='t44-instance', project_id='alpha', project_identity=identity,
            contact=LibraryServiceContact(controls, lambda _: principal))
        host = FieldNotesLibraryHost(hub, lambda value: session if value is context else None)
        def manager(request, operation):
            return host.handle(library_controls.canonical(dict(version=1,
                operation_id=operation, mode='execute', request=request)), context)
        observe = dict(version=1, action='observe', project_id='alpha',
                       for_action='inspect', queue_id=queue)
        observed = manager(observe, 't44-observe')['result']
        opening = dict(version=1, action='inspect', project_id='alpha', queue_id=queue,
            request_id='t44-open', settings_id=observed['settings_id'],
            observed_version=observed['observed_version'])
        inspected = manager(opening, 't44-open')
        self.assertEqual(inspected['outcome'], 'OBSERVED')
        self.assertIn('T44_PRIVATE_INSPECTION', inspected['result']['item']['text'])
        self.assertEqual(inspected['result']['commit_sha'], self.head())
        # Check intermediary evidence before deletion, not merely its absence
        # afterward. The canonical repository intentionally contains the draft.
        metadata = library_controls.canonical(ledger.snapshot()) + library_controls.canonical(
            ledger.replay(0, limit=1000))
        manager_paths = list(room_data.glob('*.db*'))
        self.assertIn(room_data / 'manager-private.db', manager_paths)
        self.assertIn(room_data / 'hub.db', manager_paths)
        for path in manager_paths:
            metadata += path.read_bytes()
        self.assertNotIn(b'T44_PRIVATE_INSPECTION', metadata)
        connected[0] = False
        self.assertEqual(manager(opening, 't44-after-disconnect')['outcome'], 'UNCONFIRMED')
        ledger.close()
        for key, captured_hub in list(self.hubs.items()):
            if key[1] == 'alpha':
                captured_hub.ledger.close()
                del self.hubs[key]
        destroyed = supervisor.destroy()
        self.assertEqual(destroyed['phase'], 'destroyed')
        self.assertFalse(instance.exists(), 'owned Room/Hub files must be removed')
        self.assertTrue((self.base / 'alpha').exists(), 'Project files are preserved')
        with self.assertRaisesRegex(library.LibraryError, 'ROOM_NOT_BOUND'):
            deployment.hub('alpha')
        self.assertTrue(deployment.running)
        self.assertEqual(deployment.read('beta').files, beta.files)
        root = self.state / 'library' / 'operator'
        def local(value):
            return library_controls.request(root, value)
        fresh = local(observe)
        self.assertEqual(fresh['outcome'], 'observed', fresh)
        observed = fresh['result']
        self.assertEqual(local({**opening, 'request_id': 't44-local-open',
            'observed_version': observed['observed_version']})['result']['item']['text'],
            inspected['result']['item']['text'])
        self.assertEqual(local({**observe, 'project_id': 'beta'})['error'], 'FORBIDDEN')
        allowed[0] = False
        self.assertEqual(local(observe)['error'], 'FORBIDDEN')
        allowed[0] = True
        conclusion = 'T44_PRIVATE_CONCLUSION Preserve the selected human decision.'
        rationale = 'T44_PRIVATE_RATIONALE Exact explanation, not model interpretation.'
        value = dict(version=1, action='adjudicate', project_id='alpha', queue_id=queue,
            drain_id='t44-original', request_id='t44-adjudicate',
            settings_id=observed['settings_id'], observed_version=observed['observed_version'],
            conclusion=conclusion, rationale=rationale)
        before = self.head()
        # Discard the real socket response: the caller has no outcome to claim.
        # Only its unchanged explicit request may later recover the receipt.
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as channel:
            channel.connect(str(root / 'library-operator.sock'))
            channel.sendall(library_controls.canonical(value))
        self.assertTrue(self.wait_for(lambda: self.head() != before))
        allowed[0] = False
        self.assertEqual(local(value)['error'], 'FORBIDDEN')
        allowed[0] = True
        receipt = local(value)
        self.assertEqual(receipt['outcome'], 'observed', receipt)
        self.assertEqual(receipt['result']['outcome'], 'COMMITTED')
        committed = self.head()
        self.assertEqual(receipt['result']['publication']['commit_sha'], committed)
        self.assertEqual(local(value), receipt)
        self.assertEqual(self.head(), committed)
        self.assertEqual(local({**value, 'rationale': 'Changed'})['error'], 'ID_CONFLICT')
        decision = git(self.canonical, 'show',
            committed + ':projects/github.com/acme/alpha/decisions/adjudication-' + queue + '.md')
        self.assertIn(conclusion, decision)
        self.assertIn(rationale, decision)
        self.assertIn('Human identity: t44-human\nActor identity: t44-actor', decision)
        self.assertEqual(scheduler.state(identity)['state'], 'DISPOSED')
        self.assertEqual(scheduler.state(identity)['selected'], [queue, retained])
        resume = local(dict(version=1, action='observe', project_id='alpha', for_action='resume'))['result']
        resumed = local(dict(version=1, action='resume', project_id='alpha', request_id='t44-resume',
            drain_id='t44-original', settings_id=resume['settings_id'],
            observed_version=resume['observed_version']))
        self.assertEqual(resumed['result']['outcome'], 'ACKNOWLEDGED')
        self.assertNotEqual(resumed['result']['operation_id'], receipt['result']['operation_id'])
        self.assertIsNone(scheduler.state(identity)['drain_id'])
        self.assertEqual(self.head(), committed)
        records = deployment.publisher.records_path
        self.assertTrue(records.is_file())
        record_paths = list(records.parent.glob(records.name + '*'))
        self.assertIn(records, record_paths)
        for path in record_paths:
            for marker in (conclusion, rationale, 'T44_PRIVATE_INSPECTION'):
                self.assertNotIn(marker.encode(), path.read_bytes())
        self.assertFalse(instance.exists(), 'operator must not recreate a Hub')
        self.assertFalse((self.base / 'alpha-contact').exists(), 'no provider call')

    def attempt_fixture(self, mode):
        import test_library_attempts as attempts_fixture
        fixture = attempts_fixture.AttemptTests(
            'test_parking_commit_has_durable_inputs_before_contact_and_recovery_outcomes')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.mode = mode
        original = fixture.source.scope
        reference = self.base / ('active-' + mode) / 'reference'
        reference.mkdir(mode=0o755, parents=True)
        scope = library.LibraryScope(seal=library._SCOPE_SEAL, **{
            **{name: getattr(original, name) for name in library.LibraryScope.__slots__
               if name != 'reference_root'},
            'reference_root': str(reference / 'library')})
        fixture.source.scope = fixture.source.fresh = scope
        LocalTransport.canonical = Path(fixture.source.target)
        document = deepcopy(fixture.source.settings)
        rooms = {'alpha': {'project': {'id': scope.project_id, 'repository': 'acme/alpha',
                                       'roots': {'reference': str(reference)}},
                           'source_identity': '1001'}}
        def runner_for(_scope):
            # The composed publisher owns the lease and records for this attempt.
            fixture.source.publisher = self.deployment.publisher
            runner = fixture.runner()
            def context(selected):
                # The fixture reply must correlate with this scheduler's real drain.
                state = self.deployment.service.scheduler.state(scope.project_identity)
                reply = {'version': 1, 'drain_id': state['drain_id'], 'attempt': state['attempt'],
                         'operations': [], 'outcomes': [
                             {'queue_id': queue, 'kind': 'parked', 'reason': 'NEEDS_EVIDENCE'}
                             for queue in selected]}
                route = runner.dispatcher.gateway.routes[fixture.profile.identity()]
                runner.dispatcher.gateway.routes[fixture.profile.identity()] = (
                    route[:3] + (fixture.mode, json.dumps(reply)))
                return (), ()
            return runner, context
        return fixture, scope, dict(
            settings=document, rooms=rooms, scope_for=lambda _binding: scope,
            runner_for=runner_for,
            credentials={document['repository']['credential_ref']: {}})

    def test_stop_during_a_live_model_attempt_keeps_the_lease_and_recovers(self):
        fixture, scope, options = self.attempt_fixture('release')
        deployment = self.make_deployment(**options)
        deployment.start()
        self.assertTrue(self.wait_for(lambda: fixture.marker.exists(), seconds=20))
        stopper = threading.Thread(target=deployment.stop)
        stopper.start()
        try:
            time.sleep(0.3)
            second = self.make_deployment(**options)
            with self.assertRaisesRegex(library.LibraryError, 'LEASE_BUSY'):
                second.start()
        finally:
            stopper.join(30)
        self.assertFalse(stopper.is_alive())
        self.assertFalse(deployment.running)
        fixture.mode = 'success'
        restarted = self.make_deployment(**options)
        restarted.start()
        self.assertTrue(restarted.running)
        self.assertTrue(self.wait_for(lambda: self.events('alpha'), seconds=30))
        self.assertTrue(self.wait_for(
            lambda: restarted.service.scheduler.state(scope.project_identity)['state']
            in ('COMMITTED', 'IDLE', 'READY', 'BACKOFF'), seconds=20))

    def test_revocation_during_a_live_attempt_blocks_publication(self):
        fixture, scope, options = self.attempt_fixture('success')
        allowed = [True]
        def hook(event):
            if event['state'] == 'returned':
                allowed[0] = False
        fixture.hook = hook
        options['qualification'] = lambda _settings: allowed[0]
        head = git(fixture.source.target, 'rev-parse', 'refs/heads/main').strip()
        deployment = self.make_deployment(**options)
        deployment.start()
        self.assertTrue(self.wait_for(lambda: not deployment.running, seconds=30))
        self.assertEqual(deployment.failure, 'TARGET_NOT_QUALIFIED')
        self.assertEqual(git(fixture.source.target, 'rev-parse', 'refs/heads/main').strip(), head)

    def test_current_shared_settings_apply_to_new_operations_and_fail_closed(self):
        from uas.library_settings import SettingsOwner, canonical
        root = self.base / 'config'
        root.mkdir(mode=0o700)
        owner = SettingsOwner(
            root / 'settings.db', 'deployment-1',
            lambda: support.settings(deepcopy(self.document)),
            now=lambda: datetime(2026, 10, 30, tzinfo=timezone.utc))
        owner.initialize({key: deepcopy(self.document[key]) for key in ('limits', 'filters')})
        principal = library.LocalHuman(
            'human', 'actor', 'grant-1',
            lambda _principal, key, action: (
                key is None and action == library.SETTINGS_CAPABILITY),
            lambda: True)
        identity = library.project_binding(
            self.projects['alpha']['project'],
            source_identity=self.projects['alpha']['source_identity'])['project_identity']
        operator = library.LocalHuman(
            'human-1', 'human-actor', 'authority-1',
            lambda _principal, project_identity, action: (
                project_identity == identity and action in ('library-drain', 'library-retry')),
            lambda: True)
        deployment = self.make_deployment(settings_owner=owner, operator=lambda _uid: operator)
        deployment.start()
        self.register(deployment, 'alpha')
        self.assertTrue(deployment.wait_idle('alpha'))
        self.assertEqual(self.enqueue(deployment, 'alpha', 'Long title')['outcome'], 'DURABLY_QUEUED')
        observed = owner.handle(canonical(dict(
            version=1, action='settings-observe', deployment='deployment-1')).encode(), principal)
        shared = observed['shared']
        shared['limits']['title_chars'] = 3
        changed = owner.handle(canonical(dict(
            version=1, action='settings-update', deployment='deployment-1',
            request_id='lower', configuration_version=observed['configuration_version'],
            settings_id=observed['settings_id'], shared=shared)).encode(), principal)
        self.assertEqual(changed['outcome'], 'CONFIGURED')
        self.assertEqual(self.enqueue(deployment, 'alpha', 'Longer title', suffix='two')['outcome'],
                         'REJECTED')
        self.assertEqual(self.enqueue(deployment, 'alpha', 'Yes', suffix='three')['outcome'],
                         'DURABLY_QUEUED')
        root = self.state / 'library' / 'operator'
        self.assertTrue(self.wait_for(lambda: (root / 'library-operator.sock').exists()))
        observed_current = library_controls.request(
            root, {'version': 1, 'action': 'observe', 'project_id': 'alpha',
                   'for_action': 'drain'})
        self.assertEqual(observed_current['outcome'], 'observed')
        self.assertEqual(observed_current['result']['settings_id'], owner()['settings_id'])
        owner.path.unlink()
        failed = self.enqueue(deployment, 'alpha', 'Yes', suffix='four')
        self.assertNotEqual(failed['outcome'], 'DURABLY_QUEUED')
        self.assertTrue(self.wait_for(lambda: not deployment.running, seconds=3))

    def test_forced_process_stop_recovers_projection_lease_and_operator(self):
        identity = library.project_binding(
            self.projects['alpha']['project'],
            source_identity=self.projects['alpha']['source_identity'])['project_identity']
        principal = library.LocalHuman(
            'human-1', 'human-actor', 'authority-1',
            lambda _principal, project_identity, action: (
                project_identity == identity and action in ('library-drain', 'library-retry')),
            lambda: True)
        options = dict(operator=lambda _uid: principal)
        seeding = self.make_deployment()
        seeding.start()
        self.register(seeding, 'alpha')
        self.assertTrue(seeding.wait_idle('alpha'))
        head = self.head()
        seeding.stop()
        ready = self.base / 'child-ready'
        def child():
            deployment = self.make_deployment(**options)
            deployment.start()
            ready.write_text('ready')
            time.sleep(30)
        process = multiprocessing.get_context('fork').Process(target=child)
        process.start()
        try:
            self.assertTrue(self.wait_for(lambda: ready.exists(), seconds=20))
            root = self.state / 'library' / 'operator'
            self.assertTrue((root / 'library-operator.sock').exists())
        finally:
            process.kill()
            process.join(5)
        self.assertFalse(process.is_alive())
        recovered = self.make_deployment(**options)
        recovered.start()
        self.assertTrue(recovered.running)
        self.assertTrue(recovered.wait_idle('alpha'))
        self.assertEqual(recovered.read('alpha').manifest['commit_sha'], head)
        self.assertEqual(self.head(), head)
        response = library_controls.request(
            root, {'version': 1, 'action': 'observe', 'project_id': 'alpha',
                   'for_action': 'drain'})
        self.assertEqual(response['outcome'], 'observed')
        recovered.stop()

    def test_revocation_during_capture_admission_blocks_publication(self):
        allowed = [True]
        deployment = self.make_deployment(qualification=lambda _settings: allowed[0])
        deployment.start()
        self.register(deployment, 'alpha')
        self.assertTrue(deployment.wait_idle('alpha'))
        head = self.head()
        hub = deployment.hub('alpha')
        calls = []
        def current():
            calls.append(1)
            if len(calls) == 1:
                allowed[0] = False
            return True
        request = {'id': 'command-revoked', 'kind': 'library.enqueue',
                   'request_id': 'request-revoked',
                   'capture': support.value(title='REVOKED_MARKER', body='Revoked body.\n')}
        prepared = hub.prepare(request, self.origins['alpha'], authorize=lambda: True)
        result = hub.perform(prepared, current=current)
        self.assertNotEqual(result['outcome'], 'DURABLY_QUEUED')
        self.assertEqual(self.head(), head)
        self.assertTrue(self.wait_for(lambda: not deployment.running, seconds=5))

    def test_unavailable_active_settings_during_attempt_blocks_publication(self):
        from uas.library_settings import SettingsOwner
        fixture, scope, options = self.attempt_fixture('success')
        root = self.base / 'settings'
        root.mkdir(mode=0o700)
        owner = SettingsOwner(
            root / 'settings.db', 'deployment-1',
            lambda: deepcopy(fixture.source.settings),
            now=lambda: datetime(2026, 10, 30, tzinfo=timezone.utc))
        owner.initialize({key: deepcopy(fixture.source.settings[key])
                          for key in ('limits', 'filters')})
        options['settings_owner'] = owner
        def hook(event):
            if event['state'] == 'returned':
                owner.path.unlink()
        fixture.hook = hook
        head = git(fixture.source.target, 'rev-parse', 'refs/heads/main').strip()
        deployment = self.make_deployment(**options)
        deployment.start()
        self.assertTrue(self.wait_for(lambda: not deployment.running, seconds=30))
        self.assertEqual(deployment.failure, 'SETTINGS_UNAVAILABLE')
        self.assertEqual(git(fixture.source.target, 'rev-parse', 'refs/heads/main').strip(), head)

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
