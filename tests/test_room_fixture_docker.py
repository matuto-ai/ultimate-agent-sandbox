"""Hosted real-Docker smoke for exact endpoint mounts and configured bounds.

The socket is an inert test-owned mount object, NOT a Broker or authentication
proof. The static fixture image cannot speak the native seqpacket protocol.
SELinux, mapped peer identity, public egress and XFS qualification stay with the
combined disposable guest scenario. This file is never run locally.
"""
import json
from contextlib import contextmanager
import os
from pathlib import Path
import re
import select
import signal
import socket
import stat
import struct
import subprocess
import tempfile
import time
import unittest

from uas.docker_fixture import DockerFixtureBackend
from uas.docker_exec_api import DockerExecAPI
from uas.lifecycle import FixtureSpec, Supervisor

IMAGE = os.environ.get('UAS_DOCKER_FIXTURE_IMAGE')
TARGET = '/uas/endpoint-smoke'
LIMITS = {'Memory': 96 * 1024**2, 'MemorySwap': 96 * 1024**2,
          'NanoCpus': 750_000_000, 'PidsLimit': 24}
LOGGING = {'Type': 'local', 'Config': {'max-size': '524288',
           'max-file': '1', 'compress': 'false'}}
EXEC_SECONDS = 10
OUTPUT_LIMIT = 4096
STARTUP_LIMIT = 256


def remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise TimeoutError('fixed exec diagnostic deadline')
    return value


def failure(error):
    return {'type': type(error).__name__, 'message': str(error)[:256]}


@contextmanager
def exec_watchdog(checks, deadline):
    """Hosted Linux main-thread hard cap, including a stalled Engine request."""
    receipt = checks['watchdog'] = {'seconds': EXEC_SECONDS, 'fired': False, 'cleanup_errors': []}
    prior_timer = signal.getitimer(signal.ITIMER_REAL)
    if prior_timer != (0.0, 0.0):
        raise AssertionError('fixed exec will not replace an armed timer')
    if signal.SIGALRM in signal.pthread_sigmask(signal.SIG_BLOCK, ()):
        raise AssertionError('fixed exec requires unblocked watchdog')
    prior_handler = signal.getsignal(signal.SIGALRM)
    def expired(*_):
        receipt['fired'] = True
        raise TimeoutError('fixed exec hard watchdog expired')
    primary = None
    try:
        signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, remaining(deadline))
        yield
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            signal.setitimer(signal.ITIMER_REAL, *prior_timer)
        except BaseException as error:
            receipt['cleanup_errors'].append({'operation': 'restore_timer', **failure(error)})
        try:
            signal.signal(signal.SIGALRM, prior_handler)
        except BaseException as error:
            receipt['cleanup_errors'].append({'operation': 'restore_handler', **failure(error)})
        if receipt['cleanup_errors'] and primary is None:
            raise AssertionError('fixed exec watchdog cleanup incomplete')


def observe_api_start(container, checks, deadline):
    """IDs, Pid and startup bytes are diagnostics, never Participant authority."""
    started = time.monotonic()
    deadline = min(deadline, started + 3)
    checks.update(stage='create', status='in_progress', stages={}, cleanup_errors=[],
                  multiplex_hex='', stdout='', stderr='')
    stream = None
    primary = None

    def stage(name):
        checks['stage'] = name
        checks['stages'][name] = round(time.monotonic() - started, 6)
        api.timeout = remaining(deadline)

    def exact(length):
        output = bytearray()
        while len(output) < length:
            stream.channel.settimeout(remaining(deadline))
            part = stream.channel.recv(length - len(output))
            if not part:
                raise AssertionError('incomplete Docker multiplex startup')
            output.extend(part)
            checks['multiplex_hex'] = (checks['multiplex_hex'] + part.hex())[:2048]
            remaining(deadline)
        return bytes(output)

    try:
        api = DockerExecAPI('/var/run/docker.sock', timeout=remaining(deadline))
        stage('create')
        exec_id = api.create(container, {'AttachStdin': False, 'AttachStdout': True,
            'AttachStderr': True, 'Tty': False, 'Cmd': ['/fixture']})
        if not isinstance(exec_id, str) or not re.fullmatch('[0-9a-f]{64}', exec_id):
            raise AssertionError('invalid exact exec ID')
        checks['exec_id'] = exec_id
        stage('start')
        stream = api.start(exec_id)
        stage('inspect')
        observed = api.inspect(exec_id)
        checks['inspect'] = {name: observed.get(name) for name in ('ID', 'ContainerID', 'Running', 'Pid')}
        if (observed.get('ID') != exec_id or observed.get('ContainerID') != container
                or observed.get('Running') is not True
                or type(observed.get('Pid')) is not int or observed['Pid'] <= 0):
            raise AssertionError('exact live diagnostic exec not observed')
        stage('startup_bytes')
        output = {1: bytearray(), 2: bytearray()}
        for _ in range(16):
            kind, reserved, length = struct.unpack('>B3sI', exact(8))
            if kind not in output or reserved != b'\0' * 3 or not 0 < length <= STARTUP_LIMIT:
                raise AssertionError('invalid bounded Docker multiplex frame')
            part = exact(length)
            output[kind].extend(part)
            name = 'stdout' if kind == 1 else 'stderr'
            checks[name] = bytes(output[kind][:STARTUP_LIMIT]).decode('utf-8', 'replace')
            if len(output[kind]) > STARTUP_LIMIT:
                raise AssertionError('Docker startup output exceeded bound')
            if output[1].endswith(b'\n'):
                break
        if output[2] or not re.fullmatch(rb'fixture start=[1-9][0-9]{0,8} uid=65532\n', output[1]):
            raise AssertionError('fixed Go fixture startup not observed')
        remaining(deadline)
        checks['status'] = 'observed'
    except BaseException as error:
        primary = error
        checks['status'] = 'failed'
        checks['failure'] = failure(error)
        raise
    finally:
        if stream is not None:
            try:
                stream.close()  # I/O close does NOT prove daemon-owned task exit.
            except BaseException as error:
                checks['cleanup_errors'].append(failure(error))
        checks['seconds'] = round(time.monotonic() - started, 6)
        if checks['cleanup_errors']:
            checks['status'] = 'failed'
            if primary is None:
                raise AssertionError('Docker API stream cleanup incomplete')


def observe_cli_probe(container, checks, deadline):
    """One fixed owned CLI; bounded capture is not daemon task-exit evidence."""
    started = time.monotonic()
    collect_deadline = min(deadline, started + 5)
    checks.update(stage='popen', status='in_progress', stages={'popen': 0},
                  cleanup_errors=[], kill_attempted=False, reaped=False)
    buffers = {name: bytearray() for name in ('stdout', 'stderr')}
    for name in buffers:
        checks[name] = {'bytes': 0, 'output': '', 'eof': False}
    process = None
    primary = None
    pipes = {}
    drain_ready = False

    def drain(until):
        while pipes:
            ready, _, _ = select.select(list(pipes), [], [], remaining(until))
            remaining(until)
            for fd in ready:
                part = os.read(fd, 65536)
                name = pipes[fd]
                if not part:
                    checks[name]['eof'] = True
                    del pipes[fd]
                else:
                    checks[name]['bytes'] += len(part)
                    buffers[name].extend(part[:max(0, OUTPUT_LIMIT - len(buffers[name]))])
                    checks[name]['output'] = bytes(buffers[name]).decode('utf-8', 'replace')

    try:
        remaining(collect_deadline)
        process = subprocess.Popen(['docker', 'exec', container, '/fixture', '--probe', TARGET],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        checks['cli_pid'] = process.pid  # Diagnostic only; never signal this number.
        checks['stage'] = 'read'
        checks['stages']['read'] = round(time.monotonic() - started, 6)
        pipes = {process.stdout.fileno(): 'stdout', process.stderr.fileno(): 'stderr'}
        for fd in pipes:
            os.set_blocking(fd, False)
        drain_ready = True
        drain(collect_deadline)
        checks['stage'] = 'exit'
        checks['stages']['exit'] = round(time.monotonic() - started, 6)
        process.wait(timeout=remaining(collect_deadline))
        if (process.returncode != 0 or buffers['stderr']
                or any(checks[name]['bytes'] > OUTPUT_LIMIT for name in buffers)):
            raise AssertionError('fixed CLI probe failed or output truncated')
        remaining(collect_deadline)
        checks['status'] = 'collected'
        return bytes(buffers['stdout'])
    except BaseException as error:
        primary = error
        checks['status'] = 'failed'
        checks['failure'] = failure(error)
        raise
    finally:
        if process is not None:
            try:
                code = process.poll()
                checks['pre_cleanup_poll'] = {'status': 'observed', 'returncode': code}
            except BaseException as error:
                checks['pre_cleanup_poll'] = {'status': 'failed', **failure(error)}
                checks['cleanup_errors'].append({'operation': 'poll', **failure(error)})
            if process.returncode is None:
                try:
                    checks['kill_attempted'] = True
                    process.kill()  # Only this owned Popen child, never inspect Pid.
                except BaseException as error:
                    checks['cleanup_errors'].append({'operation': 'kill', **failure(error)})
            if drain_ready and pipes:
                try:
                    drain(min(deadline, time.monotonic() + 1))
                except BaseException as error:
                    checks['cleanup_errors'].append({'operation': 'drain', **failure(error)})
            try:
                checks['returncode'] = process.wait(timeout=max(0, min(1, deadline - time.monotonic())))
                checks['reaped'] = True
            except BaseException as error:
                checks['cleanup_errors'].append({'operation': 'wait', **failure(error)})
            for name in buffers:
                try:
                    getattr(process, name).close()
                except BaseException as error:
                    checks['cleanup_errors'].append({'operation': name + '_close', **failure(error)})
        checks['seconds'] = round(time.monotonic() - started, 6)
        if checks['cleanup_errors']:
            checks['status'] = 'failed'
            if primary is None:
                raise AssertionError('Docker CLI cleanup incomplete')


def observe_fixed_exec(container, checks):
    started = time.monotonic()
    deadline = started + EXEC_SECONDS
    checks.update(status='in_progress', scope='diagnostics only; IDs/Pid/markers are not authority',
                  not_tested=['Python import/readiness barrier', 'TCG latency', 'SELinux'],
                  api={}, cli={})
    if not isinstance(container, str) or not re.fullmatch('[0-9a-f]{64}', container):
        raise AssertionError('exact owned container ID required')
    checks['container_id'] = container
    try:
        with exec_watchdog(checks, deadline):
            observe_api_start(container, checks['api'], deadline)
            output = observe_cli_probe(container, checks['cli'], deadline)
            probe = json.loads(output)
            remaining(deadline)
        checks['status'] = 'captured'
        return probe
    except BaseException as error:
        checks['status'] = 'failed'
        checks['failure'] = failure(error)
        raise
    finally:
        checks['seconds'] = round(time.monotonic() - started, 6)


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
                container = None
                primary = None
                cleanup_receipt = {'case': 'owned_cleanup', 'errors': [], 'absent_container_ids': []}
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
                            diagnostic = {'case': 'fixed_exec_startup'}
                            receipts.append(diagnostic)  # Retain partial evidence on every failure.
                            probe = observe_fixed_exec(container, diagnostic)
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
                        self.assertIsNone(backend._run(['inspect', '--type', 'container', container], missing_ok=True))
                        cleanup_receipt['absent_container_ids'].append(container)
                        container = None
                        self.assertEqual('preserve', sentinel.read_text())
                        self.assertEqual('preserve', endpoint_sentinel.read_text())
                        current = path.stat()
                        self.assertEqual((identity.st_dev, identity.st_ino), (current.st_dev, current.st_ino))
                except BaseException as error:
                    primary = error
                    cleanup_receipt['primary_failure'] = failure(error)
                    raise
                finally:
                    # Ownership-only cleanup also works on rejected containers;
                    # CLI kill/stream close is insufficient for daemon exec exit.
                    # Never repair drift or prune/remove by wildcard/numeric PID.
                    try:
                        cleanup = supervisor.destroy()
                        self.assertEqual('destroyed', cleanup['phase'], cleanup)
                        self.assertEqual({'container': None, 'volume': None}, cleanup['observed'])
                        cleanup_receipt['supervisor_destroyed'] = True
                    except BaseException as error:
                        cleanup_receipt['errors'].append({'operation': 'destroy', **failure(error)})
                    if container is not None:
                        try:
                            self.assertIsNone(backend._run(['inspect', '--type', 'container', container], missing_ok=True))
                            cleanup_receipt['absent_container_ids'].append(container)
                        except BaseException as error:
                            cleanup_receipt['errors'].append({'operation': 'exact_absence', **failure(error)})
                    receipts.append(cleanup_receipt)
                    print('Room endpoint Docker diagnostics:', json.dumps(receipts, sort_keys=True), flush=True)
                    if cleanup_receipt['errors'] and primary is None:
                        raise AssertionError('exact owned Docker cleanup incomplete')
        seconds = round(time.monotonic() - started, 3)
        print('Room endpoint Docker smoke:', json.dumps({'seconds': seconds, 'cases': receipts,
            'scope': 'real mount/resource admission only; no Broker, SELinux or network qualification'}, sort_keys=True), flush=True)
        self.assertLess(seconds, 20, 'bounded endpoint smoke exceeded its hosted 20-second budget')
