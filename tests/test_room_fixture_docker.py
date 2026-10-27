"""Hosted real-Docker smoke for exact endpoint mounts and configured bounds.

The socket is an inert test-owned mount object, NOT a Broker or authentication
proof. The static fixture image cannot speak the native seqpacket protocol.
SELinux, mapped peer identity, public egress and XFS qualification stay with the
combined disposable guest scenario. This file is never run locally.
"""
import json
import os
from pathlib import Path
import socket
import stat
import tempfile
import time
import unittest

from uas.docker_fixture import DockerFixtureBackend
from uas.lifecycle import FixtureSpec, Supervisor

IMAGE = os.environ.get('UAS_DOCKER_FIXTURE_IMAGE')
TARGET = '/uas/endpoint-smoke'
LIMITS = {'Memory': 96 * 1024**2, 'MemorySwap': 96 * 1024**2,
          'NanoCpus': 750_000_000, 'PidsLimit': 24}
LOGGING = {'Type': 'local', 'Config': {'max-size': '524288',
           'max-file': '1', 'compress': 'false'}}


class EndpointSmokeBackend(DockerFixtureBackend):
    """Fixed private test recipe; only owned disposable create argv is altered."""
    def __init__(self, endpoint, alternate):
        super().__init__(timeout=3)
        self.endpoint, self.alternate = endpoint, alternate
        self.drift = None
        self.start_calls = 0

    def _endpoint_mounts(self, state):
        return ((TARGET, str(self.endpoint)),)

    def _resource_limits(self, state):
        return dict(LIMITS)

    def _log_config(self, state):
        return {'Type': LOGGING['Type'], 'Config': dict(LOGGING['Config'])}

    def _run(self, arguments, **kwargs):
        if arguments[0] == 'create' and self.drift is not None:
            arguments = list(arguments)
            expected = f'type=bind,source={self.endpoint},target={TARGET},readonly'
            if arguments.count(expected) != 1:
                raise AssertionError('exact test-owned endpoint mount not selected')
            index = arguments.index(expected)
            if self.drift == 'writable':
                arguments[index] = expected.removesuffix(',readonly')
            elif self.drift == 'source':
                arguments[index] = f'type=bind,source={self.alternate},target={TARGET},readonly'
            else:
                raise AssertionError('unknown bounded fixture drift')
        if arguments[0] == 'start':
            self.start_calls += 1
        return super()._run(arguments, **kwargs)


@unittest.skipUnless(IMAGE, 'real Docker smoke requires its hosted dedicated image job')
class RoomEndpointDockerSmoke(unittest.TestCase):
    def test_exact_readonly_endpoint_configured_bounds_and_prestart_rejections(self):
        # Both checks precede even temporary-directory/socket creation. A local
        # image variable cannot opt this hosted-only destructive fixture in.
        self.assertEqual('true', os.environ.get('GITHUB_ACTIONS'))
        self.assertEqual('Linux', os.environ.get('RUNNER_OS'))
        self.assertRegex(IMAGE, r'^sha256:[0-9a-f]{64}$')
        started = time.monotonic()
        receipts = []
        with tempfile.TemporaryDirectory(prefix='uas-endpoint-') as temporary:
            root = Path(temporary)
            project = root / 'project'; project.mkdir(mode=0o755)
            sentinel = project / 'human-owned'; sentinel.write_text('preserve')
            endpoint = root / 'endpoint'; endpoint.mkdir(mode=0o755)
            alternate = root / 'alternate'; alternate.mkdir(mode=0o755)
            endpoint_sentinel = alternate / 'unapproved'; endpoint_sentinel.write_text('preserve')
            with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
                path = endpoint / 'mount-object.sock'
                listener.bind(str(path)); listener.listen(1); path.chmod(0o600)
                identity = path.stat()
                self.assertTrue(stat.S_ISSOCK(identity.st_mode))
                self.assertEqual(os.geteuid(), identity.st_uid)
                backend = EndpointSmokeBackend(endpoint, alternate)
                supervisor = Supervisor(root / 'control', 'alpha', backend,
                    authorize=lambda *_: True, revoke=lambda *_: True)
                # No capability or service request is issued by this test;
                # revocation here is explicitly empty fixture authority.
                spec = FixtureSpec('alpha', 'endpoint-smoke', (str(project),), IMAGE,
                    'sha256:' + 'b' * 64, 'sha256:' + 'c' * 64)
                try:
                    for drift in (None, 'writable', 'source'):
                        backend.drift = drift
                        before_starts = backend.start_calls
                        result = supervisor.start(spec)
                        self.assertIsInstance(result['observed']['container'], dict, result)
                        self.assertIn('id', result['observed']['container'], result)
                        container = result['observed']['container']['id']
                        state = supervisor._read()
                        actual = backend._inspect_object(state, 'container')
                        mounts = {mount['Destination']: mount for mount in actual['Mounts']}
                        if drift is None:
                            self.assertEqual('running', result['phase'], result)
                            self.assertEqual(before_starts + 1, backend.start_calls)
                            selected = mounts[TARGET]
                            self.assertEqual('bind', selected['Type'])
                            self.assertEqual(str(endpoint), selected['Source'])
                            self.assertIs(selected['RW'], False)
                            self.assertEqual('rprivate', selected['Propagation'])
                            self.assertEqual({'/state', str(project), TARGET}, set(mounts))
                            for key, value in LIMITS.items():
                                self.assertEqual(value, actual['HostConfig'][key])
                            self.assertEqual(LOGGING, actual['HostConfig']['LogConfig'])
                            probe = json.loads(backend._run(['exec', container, '/fixture', '--probe', TARGET]))
                            self.assertEqual([], probe['errors'])
                            self.assertEqual((65532, 65532), (probe['uid'], probe['gid']))
                            self.assertEqual('EROFS', probe['project_write'])
                            self.assertEqual('EROFS', probe['root_write'])
                            self.assertEqual(str(LIMITS['Memory']), probe['cgroup']['memory.max'])
                            self.assertEqual(str(LIMITS['PidsLimit']), probe['cgroup']['pids.max'])
                            quota, period = map(int, probe['cgroup']['cpu.max'].split())
                            self.assertEqual(3 * period, 4 * quota)
                            self.assertEqual({'CapEff': '0' * 16, 'CapBnd': '0' * 16,
                                'NoNewPrivs': '1', 'Seccomp': '2'}, probe['process'])
                            receipts.append({'case': 'readonly-configured', 'live_cgroup': probe['cgroup'],
                                             'endpoint_write': probe['project_write'], 'log_config': LOGGING})
                        else:
                            self.assertEqual('start_failed', result['phase'], result)
                            self.assertEqual(before_starts, backend.start_calls)
                            self.assertEqual('created', actual['State']['Status'])
                            self.assertIs(actual['State']['Running'], False)
                            self.assertEqual('FIXTURE_BOUNDARY_ENDPOINT_MOUNT', result['leftovers'][0]['reason'])
                            self.assertEqual('', backend._run(['logs', container]))
                            receipts.append({'case': drift, 'never_started': True,
                                             'reason': result['leftovers'][0]['reason']})
                        destroyed = supervisor.destroy()
                        self.assertEqual('destroyed', destroyed['phase'], destroyed)
                        self.assertEqual({'container': None, 'volume': None}, destroyed['observed'])
                        self.assertEqual('preserve', sentinel.read_text())
                        self.assertEqual('preserve', endpoint_sentinel.read_text())
                        current = path.stat()
                        self.assertEqual((identity.st_dev, identity.st_ino), (current.st_dev, current.st_ino))
                finally:
                    # Ownership-only cleanup also works on rejected containers;
                    # never repair drift and never prune or remove by wildcard.
                    if supervisor.status()['phase'] not in ('absent', 'destroyed'):
                        cleanup = supervisor.destroy()
                        self.assertEqual('destroyed', cleanup['phase'], cleanup)
        seconds = round(time.monotonic() - started, 3)
        print('Room endpoint Docker smoke:', json.dumps({'seconds': seconds, 'cases': receipts,
            'scope': 'real mount/resource admission only; no Broker, SELinux or network qualification'}, sort_keys=True), flush=True)
        self.assertLess(seconds, 20, 'bounded endpoint smoke exceeded its hosted 20-second budget')
