"""Installed host wiring of the composed Library (#252) over real files and Git.

The host entrypoint, installation selection, document admission, Room controller
and T40 composition are real; the native Room backend, Hub service owner and
Manager owner are controlled fixtures. This proves host wiring and projection
boundaries, not a VM, Docker, live provider or target qualification.
"""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import library_support as support
from test_library_git import git
from test_local_installation import native_selection
from uas import library, library_controls, local_cli, local_library
from uas.library_git import LibraryGit
from uas.library_registration import Registrar
from uas.local_installation import Installation, LocalInstallationError

TARGET = 'ssh://git@example.test/library.git'
ENVIRONMENT = 'GIT_SSH_COMMAND'  # an admitted Git transport variable
ROOT = Path(__file__).parent


real_open_library = local_library.open_library


class LocalTransport(LibraryGit):
    """Map the admitted SSH target to disposable local Git; no network proof."""
    canonical = None

    def _environment(self):
        environment = super()._environment()
        environment.update({'GIT_ALLOW_PROTOCOL': 'file', 'GIT_CONFIG_COUNT': '1',
                            'GIT_CONFIG_KEY_0': 'url.' + str(type(self).canonical) + '.insteadOf',
                            'GIT_CONFIG_VALUE_0': self.target})
        return environment


class LocalLibraryWiringTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.canonical = self.base / 'canonical.git'
        git(self.base, 'init', '--bare', '-q', str(self.canonical))
        LocalTransport.canonical = self.canonical
        previous = os.environ.get(ENVIRONMENT)
        self.addCleanup(lambda: os.environ.__setitem__(ENVIRONMENT, previous)
                        if previous is not None else os.environ.pop(ENVIRONMENT, None))
        os.environ[ENVIRONMENT] = 'fixture-credential-reference'
        self.config = self.configuration()
        self.config_path = self.base / 'project.json'
        self.config_path.write_bytes(json.dumps(self.config).encode())
        self.native = self.base / 'native.json'
        document = native_selection(self.config)
        # The prepared-host document keeps every Project path under its own
        # storage root and separate from its endpoints root.
        document['storage_root'] = str(self.base / 'host')
        document['endpoints_root'] = str(self.base / 'endpoints')
        self.native.write_bytes(json.dumps(document).encode())
        self.install = Installation(self.base / 'install')
        self.deployment = None

    # --- controlled external configuration --------------------------------

    def configuration(self):
        """The two-Room fixture with its paths relocated into disposable storage."""
        value = json.loads((ROOT / 'fixtures/two-rooms.json').read_text())
        host = self.base / 'host'
        for path, mode in ((host, 0o700), (host / 'projects', 0o755),
                           (host / 'state', 0o700)):
            path.mkdir(mode=mode, exist_ok=True)
            os.chmod(path, mode)  # the process umask must not widen owner storage
        value['deployment']['state_root'] = str(host / 'state')
        for room in value['rooms']:
            for name, selected in room['project']['roots'].items():
                room['project']['roots'][name] = str(host / 'projects' / room['id'] / name)
            room['state_root'] = str(host / 'state' / room['id'])
            project = Path(room['project']['roots']['reference']).parent
            (project / 'reference').mkdir(mode=0o755, parents=True, exist_ok=True)
            for path in (project, project / 'reference'):
                os.chmod(path, 0o755)
        return value

    def library_document(self, **overrides):
        settings = support.document()
        settings['repository'].update(target=TARGET, credential_ref='alice-git')
        value = {
            'version': 1,
            'settings': settings,
            'credentials': {'alice-git': {'environment': [ENVIRONMENT]}},
            'rooms': {'alpha': {'source_identity': '1001'}, 'beta': {'source_identity': '1002'}},
            'qualification': {'evidence': {
                'version': 1, 'target': TARGET,
                'branch': support.document()['repository']['branch'], 'qualified': True}},
            'model': {'profile': {'reference': 'synth-local', 'placement': 'local',
                                  'provider': 'provider-one', 'version': 'v1',
                                  'endpoint': 'http://127.0.0.1:1234/selected',
                                  'region': 'local', 'retention': 'zero',
                                  'terms': 'terms-v1'},
                      'command': ['/bin/true']},
        }
        value.update(overrides)
        return value

    def reference(self, path):
        return {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}

    def selected(self, document=None, *, native=True):
        """Persist one digest-pinned installation selection through the real schema."""
        library_path = self.base / 'library.json'
        library_path.write_bytes(json.dumps(self.library_document() if document is None
                                            else document).encode())
        value = {'version': 1, 'project': self.reference(self.config_path),
                 'native': self.reference(self.native) if native else None,
                 'manager': None, 'library': self.reference(library_path)}
        self.install.setup(json.dumps(value).encode())
        return library_path

    # --- real host drive ---------------------------------------------------

    def backend(self):
        native = Mock()
        native.start.return_value = {'infrastructure': {'phase': 'running', 'leftovers': []}}
        native.status.return_value = {'infrastructure': {'phase': 'running', 'leftovers': []}}
        native.stop.return_value = {'infrastructure': {'phase': 'stopped', 'leftovers': [],
                                                      'observed': {'container': {'running': False}}}}
        instance = Mock()
        instance.layout.return_value = {'hub': self.base / 'hub'}
        native.resources.return_value = ('supervisor', instance, {'instance_id': 'instance-one'})
        return native

    def open_library(self, installation, **options):
        # The patched module attribute is this wrapper; call the real admission.
        deployment = real_open_library(installation, publisher_factory=LocalTransport,
                                      **options)
        self.deployment = deployment
        return deployment

    def identifier(self, room):
        return {'alpha': '1001', 'beta': '1002'}[room]

    def room(self, room):
        return next(item for item in self.config['rooms'] if item['id'] == room)

    def register(self, room):
        binding = library.project_binding(self.room(room)['project'],
                                         source_identity=self.identifier(room))
        human = library.human_scope(support.session(('library-register',)), binding=binding,
                                   kind='register')
        settings = self.deployment.settings
        return Registrar(self.deployment.publisher, current_scope=lambda: human).register(
            library.action(human, settings, kind='register',
                           operation_id='register-' + room, request_id='register-' + room,
                           payload={}, at=support.AT), settings)

    def host(self, driver, *, stop_rooms=()):
        """The real ``run_host`` with a controlled native backend, Hub and Manager."""
        native = self.backend()
        services = Mock()
        services.rooms = ()
        services.close.return_value = True

        def serve(_installation, controller, **_):
            driver(controller)
            # Rooms the fixture reports as still running when host shutdown starts.
            services.rooms = stop_rooms

        with patch('uas.local_library.open_library', side_effect=self.open_library), \
             patch('uas.local_native.LocalNativeHost', return_value=native), \
             patch('uas.local_services.LocalServices', return_value=services), \
             patch('uas.local_manager_owner.ManagerOwner'), \
             patch('uas.local_cli.serve', side_effect=serve), \
             patch('uas.local_cli.signal.signal'):
            local_cli.run_host(self.install)
        return native

    @staticmethod
    def packet(action, room):
        return json.dumps({'action': action, 'room_id': room}).encode()

    def projection(self, room):
        reference = Path(self.room(room)['project']['roots']['reference'])
        return reference, reference / 'library', reference / 'library.snapshot.json'

    # --- evidence ----------------------------------------------------------

    def test_two_room_host_start_stop_binds_and_unbinds_only_projections(self):
        self.selected()
        observed = {}

        def driver(controller):
            for room in ('alpha', 'beta'):
                self.register(room)
            for room in ('alpha', 'beta'):
                controller.handle(self.packet('start', room))
            _, bundle, snapshot = self.projection('alpha')
            observed['bundle'] = sorted(path.name for path in bundle.iterdir())
            observed['snapshot'] = json.loads(snapshot.read_text())
            observed['siblings'] = sorted(path.name for path in
                                          self.projection('alpha')[0].iterdir()
                                          if not path.name.startswith('.'))
            observed['canonical_before_stop'] = self.deployment.publisher.head()
            controller.handle(self.packet('stop', 'alpha'))
            observed['room_after_stop'] = controller.handle(
                self.packet('status', 'alpha'))['infrastructure']['phase']
            observed['beta_after_stop'] = self.projection('beta')[1].is_dir()
            observed['canonical_after_stop'] = self.deployment.publisher.head()
            observed['singleton'] = self.deployment.running
            observed['stopped_room'] = library_controls.request(
                Path(self.install.root) / 'library' / 'operator',
                {'version': 1, 'action': 'observe', 'project_id': 'alpha',
                 'for_action': 'drain'})

        native = self.host(driver)
        self.assertEqual(observed['bundle'], ['context', 'decisions', 'index.md', 'log.md',
                                             'pending', 'research'])
        self.assertEqual(observed['snapshot']['project_id'], 'alpha')
        self.assertEqual(observed['snapshot']['project_identity'], 'github.com/1001')
        self.assertEqual(observed['siblings'], ['library', 'library.snapshot.json'])
        self.assertEqual(observed['room_after_stop'], 'running')
        self.assertTrue(observed['beta_after_stop'])
        self.assertTrue(observed['singleton'])
        self.assertEqual(observed['stopped_room']['outcome'], 'observed')
        self.assertEqual(observed['stopped_room']['result']['project_id'], 'alpha')
        # Room Stop removed no canonical content and did not end the singleton.
        self.assertEqual(observed['canonical_after_stop'], observed['canonical_before_stop'])
        self.assertTrue(observed['snapshot']['commit_sha'])
        self.assertEqual(native.stop.call_count, 1)

    def test_projection_never_exposes_clone_siblings_or_git_metadata(self):
        self.selected()
        observed = {}

        def driver(controller):
            for room in ('alpha', 'beta'):
                self.register(room)
            controller.handle(self.packet('start', 'alpha'))
            observed['published'] = {}
            observed['text'] = []
            for room in ('alpha', 'beta'):
                reference, bundle, snapshot = self.projection(room)
                observed['published'][room] = sorted(
                    path.name for path in reference.iterdir()
                    if not path.name.startswith('.'))
                files = [path for path in bundle.rglob('*')] + [snapshot]
                observed['text'].append('\n'.join(path.read_text(errors='replace')
                                                   for path in files if path.is_file()))
            observed['private'] = str(Path(self.install.root) / 'library')

        self.host(driver)
        for room in ('alpha', 'beta'):
            self.assertEqual(observed['published'][room], ['library', 'library.snapshot.json'])
            self.assertNotIn('.git', observed['published'][room])
        self.assertNotIn(observed['private'], '\n'.join(observed['text']))
        self.assertNotIn('clone.git', '\n'.join(observed['text']))
        # Each Room's published content carries only its own Project identity.
        self.assertIn('example/alpha', observed['text'][0])
        self.assertNotIn('example/beta', observed['text'][0])
        self.assertIn('example/beta', observed['text'][1])
        self.assertNotIn('example/alpha', observed['text'][1])

    def test_room_restart_after_stop_republishes_the_same_canonical_generation(self):
        self.selected()
        observed = {}

        def driver(controller):
            self.register('alpha')
            controller.handle(self.packet('start', 'alpha'))
            _, _bundle, snapshot = self.projection('alpha')
            observed['first'] = json.loads(snapshot.read_text())['commit_sha']
            observed['bound'] = self.deployment.bound('alpha')
            controller.handle(self.packet('stop', 'alpha'))
            observed['unbound'] = self.deployment.bound('alpha')
            controller.handle(self.packet('start', 'alpha'))
            observed['second'] = json.loads(self.projection('alpha')[2].read_text())['commit_sha']
            observed['rebound'] = self.deployment.bound('alpha')
            observed['head'] = self.deployment.publisher.head()

        self.host(driver)
        self.assertTrue(observed['bound'])
        self.assertFalse(observed['unbound'])
        self.assertTrue(observed['rebound'])
        self.assertEqual(observed['second'], observed['first'])
        self.assertEqual(observed['head'], observed['first'])

    def test_unsafe_service_state_root_stops_the_host_before_any_clone(self):
        self.selected()
        state = Path(self.install.root) / 'library'
        state.mkdir(mode=0o700)
        os.chmod(state, 0o777)  # group/other-writable service state
        served = []
        with self.assertRaises(library.LibraryError) as raised:
            self.host(served.append)
        self.assertEqual(raised.exception.code, 'INVALID_DEPLOYMENT_STATE')
        self.assertEqual(served, [])
        self.assertFalse((state / 'clone.git').exists())

    def test_shutdown_stops_bound_rooms_then_the_singleton_and_keeps_the_operator_path(self):
        self.selected()
        observed = {}

        def driver(controller):
            for room in ('alpha', 'beta'):
                self.register(room)
                controller.handle(self.packet('start', room))
            controller.handle(self.packet('stop', 'alpha'))
            controller.handle(self.packet('stop', 'beta'))
            observed['bound'] = [room for room in ('alpha', 'beta')
                                 if self.deployment.bound(room)]
            observed['stopped_room'] = library_controls.request(
                Path(self.install.root) / 'library' / 'operator',
                {'version': 1, 'action': 'observe', 'project_id': 'beta',
                 'for_action': 'drain'})

        native = self.host(driver, stop_rooms=('alpha', 'beta'))
        self.assertEqual(observed['bound'], [])
        self.assertEqual(observed['stopped_room']['result']['project_id'], 'beta')
        self.assertEqual(sorted(call.args[0] for call in native.stop.call_args_list),
                         ['alpha', 'alpha', 'beta', 'beta'])
        self.assertFalse(self.deployment.running)

    def test_explicit_null_operator_disables_the_host_local_path_only(self):
        observed = {}

        def driver(controller):
            observed['socket'] = (Path(self.install.root) / 'library' / 'operator'
                                 / 'library-operator.sock').exists()
            observed['running'] = self.deployment.running
            controller.handle(self.packet('start', 'alpha'))
            observed['room'] = controller.handle(
                self.packet('status', 'alpha'))['infrastructure']['phase']

        self.selected(self.library_document(operator=None))
        self.host(driver)
        self.assertFalse(observed['socket'])
        self.assertTrue(observed['running'])
        self.assertEqual(observed['room'], 'running')

    def test_host_refuses_to_serve_without_the_selected_credential_reference(self):
        self.selected()
        os.environ.pop(ENVIRONMENT)
        served = []
        with self.assertRaises(LocalInstallationError) as raised:
            self.host(served.append)
        self.assertEqual(raised.exception.code, 'LIBRARY_CREDENTIAL_UNAVAILABLE')
        self.assertEqual(served, [])

    def test_unqualified_target_stops_the_host_before_any_clone(self):
        qualification = self.library_document()['qualification']
        qualification['evidence']['qualified'] = False
        self.selected(self.library_document(qualification=qualification))
        served = []
        with self.assertRaises(library.LibraryError) as raised:
            self.host(served.append)
        self.assertEqual(raised.exception.code, 'TARGET_NOT_QUALIFIED')
        self.assertEqual(served, [])
        self.assertFalse((Path(self.install.root) / 'library').exists())

    def test_document_must_bind_configured_rooms_and_known_credentials(self):
        broken = (
            self.library_document(rooms={'gamma': {'source_identity': '1003'}}),
            self.library_document(rooms={'alpha': {'source_identity': '1001'}}),
            self.library_document(credentials={'alice-git': {'environment': ['PATH']}}),
            self.library_document(credentials={'unknown-cred': {'environment': [ENVIRONMENT]}}),
            self.library_document(qualification={'evidence': {'version': 1}}),
        )
        for document in broken:
            with self.subTest(rooms=sorted(document['rooms']),
                              credentials=sorted(document['credentials'])):
                with self.assertRaises(LocalInstallationError) as raised:
                    self.selected(document)
                self.assertTrue(raised.exception.code.startswith('LIBRARY_DOCUMENT_'))
                self.assertFalse((self.base / 'install' / 'installation.json').exists())


if __name__ == '__main__':
    unittest.main()
