"""Finite #80 collection over existing owners, never a target-host qualifier.

No admission/backend, benchmark framework, arbitrary commands, destructive probes,
Project traversal, or inferred production defaults are introduced here.
"""
from copy import deepcopy
from datetime import datetime, timezone
from dataclasses import asdict
import uuid
from decimal import Decimal
import json
import math
import os
from pathlib import Path
import re
import stat
import time

from .docker_fixture import DockerFixtureBackend
from .guest_fixture import GuestBoundaryBackend
from .ledger import RoomLedger
from .manager_actions import HumanSession
from .manager_lifecycle import current as lifecycle_current
from .lifecycle import Supervisor, FixtureSpec, LifecycleError, BackendUnknown, OwnershipConflict

CYCLES = 100
MAX_RECORD = 16384
MAX_RECORDS = 512
MAX_REPORT = 4 << 20
MISSING = ('qualified-puglab-production-backend', 'complete-owned-resource-inventory', 'actual-pi-and-claude-workload',
    'safe-point-latency-and-useful-concurrency', 'disk-and-log-enforcement',
    'limit-exhaustion-human-attention', 'interrupted-reconciliation-and-seat-failure',
    'dirty-checkout-preservation', 'manager-disconnect-replay',
    'image-profile-drift-and-provider-outage', 'explained-storage-growth-and-default-margin')
STATS_FORMAT = '{"cpu":{{json .CPUPerc}},"memory":{{json .MemUsage}},"pids":{{json .PIDs}},"block_io":{{json .BlockIO}}}'


def require(condition, code):
    if not condition:
        raise LifecycleError(code)


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def remaining(deadline):
    require(type(deadline) in (int, float) and math.isfinite(deadline), 'CAPACITY_INVALID_DEADLINE')
    value = deadline - time.monotonic()
    require(value > 0, 'CAPACITY_DEADLINE')
    return value


def identity(path, *, directory=False):
    path = Path(path)
    require(path.is_absolute() and path.resolve() == path, 'CAPACITY_PATH_CHANGED')
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode), 'CAPACITY_PATH_CHANGED')
    if not directory: require(info.st_nlink == 1, 'CAPACITY_PATH_CHANGED')
    return [info.st_dev, info.st_ino]


def size(value):
    require(type(value) is str and len(value) <= 40, 'CAPACITY_METRIC_INVALID')
    match = re.fullmatch(r'([0-9]+(?:\.[0-9]+)?)\s*(B|kB|MB|GB|TB|KiB|MiB|GiB|TiB)', value)
    require(match is not None, 'CAPACITY_METRIC_INVALID')
    units = {'B': 1, **{u: 1000**i for i, u in enumerate(('kB', 'MB', 'GB', 'TB'), 1)},
        **{u: 1024**i for i, u in enumerate(('KiB', 'MiB', 'GiB', 'TiB'), 1)}}
    result = Decimal(match[1]) * units[match[2]]
    require(0 <= result < 2**63, 'CAPACITY_METRIC_INVALID')
    return int(result)


def pair(value):
    require(type(value) is str and len(value) <= 90 and value.count('/') == 1, 'CAPACITY_METRIC_INVALID')
    return [size(item.strip()) for item in value.split('/')]


class CapacityReport:
    """Fresh append-only bounded report; never reopen or replay pending effects."""
    def __init__(self, path, project_paths):
        self.path = Path(path)
        require(self.path.is_absolute() and self.path.parent.resolve() == self.path.parent,
                'CAPACITY_REPORT_PATH')
        require(not any(self.path == Path(p) or Path(p) in self.path.parents for p in project_paths),
                'CAPACITY_REPORT_IN_PROJECT')
        self.fd = -1
        parent_identity = identity(self.path.parent, directory=True)
        parent = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            observed = os.fstat(parent)
            require([observed.st_dev, observed.st_ino] == parent_identity, 'CAPACITY_REPORT_CHANGED')
            self.fd = os.open(self.path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                              0o600, dir_fd=parent)
            info = os.fstat(self.fd)
            self.identity = [info.st_dev, info.st_ino]
            # Persist the new name as well as later file contents. On failure
            # keep any created file, close custody and perform no owner effect.
            os.fsync(parent)
            require(identity(self.path.parent, directory=True) == parent_identity,
                    'CAPACITY_REPORT_CHANGED')
        except BaseException:
            self.close()
            raise
        finally:
            os.close(parent)
        self.records = self.bytes = 0
        self.failed = False

    def append(self, value):
        require(not self.failed and self.fd >= 0, 'CAPACITY_REPORT_UNAVAILABLE')
        raw = encode(value) + b'\n'
        require(len(raw) <= MAX_RECORD and self.records < MAX_RECORDS
                and self.bytes + len(raw) <= MAX_REPORT, 'CAPACITY_REPORT_LIMIT')
        try:
            require(identity(self.path) == self.identity and os.fstat(self.fd).st_size == self.bytes,
                    'CAPACITY_REPORT_CHANGED')
            view = memoryview(raw)
            while view:
                count = os.write(self.fd, view)
                require(count > 0, 'CAPACITY_REPORT_WRITE_FAILED')
                view = view[count:]
            os.fsync(self.fd)
            self.records += 1; self.bytes += len(raw)
        except BaseException:
            self.failed = True
            raise

    def close(self):
        if self.fd >= 0:
            fd, self.fd = self.fd, -1
            os.close(fd)


class DockerCapacityObserver:
    """Fixed one-shot reads of the same canonical owned container only."""
    def __init__(self, supervisor, *, deadline):
        require(type(supervisor) is Supervisor and type(supervisor.backend) in
                (DockerFixtureBackend, GuestBoundaryBackend), 'CAPACITY_OWNER_REQUIRED')
        self.supervisor, self.backend, self.deadline = supervisor, supervisor.backend, deadline

    def admission(self):
        # Preserve the owner's executable/daemon selection and timeout. Do not
        # alter a shared backend or start a read with less than its full budget.
        timeout = self.backend.timeout
        require(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 20,
                'CAPACITY_OBSERVATION_BOUND')
        require(remaining(self.deadline) >= timeout, 'CAPACITY_DEADLINE')

    def call(self, arguments):
        self.admission()
        output = self.backend._run(arguments)
        remaining(self.deadline)
        require(type(output) is str and len(output.encode()) <= 4096, 'CAPACITY_METRIC_LIMIT')
        return output

    def sample(self, state, expected):
        remaining(self.deadline)
        self.admission()
        before = self.backend.inspect(state, 'container')
        require(before is not None and before['id'] == expected['container'] and before['running'] is True,
                'CAPACITY_CONTAINER_CHANGED')
        container = before['id']
        require(type(container) is str and re.fullmatch(r'[0-9a-f]{64}', container), 'CAPACITY_CONTAINER_CHANGED')
        raw = json.loads(self.call(['stats', '--no-stream', '--format', STATS_FORMAT, container]))
        require(type(raw) is dict and set(raw) == {'cpu', 'memory', 'pids', 'block_io'}, 'CAPACITY_METRIC_INVALID')
        require(type(raw['cpu']) is str and re.fullmatch(r'[0-9]{1,8}(?:\.[0-9]{1,6})?%', raw['cpu']), 'CAPACITY_METRIC_INVALID')
        require(type(raw['pids']) is str and re.fullmatch(r'[0-9]{1,10}', raw['pids']), 'CAPACITY_METRIC_INVALID')
        memory = pair(raw['memory']); io = pair(raw['block_io'])
        writable = json.loads(self.call(['inspect', '--size', '--type', 'container', '--format', '{{json .SizeRw}}', container]))
        require(type(writable) is int and 0 <= writable < 2**63, 'CAPACITY_METRIC_INVALID')
        self.admission()
        after = self.backend.inspect(state, 'container')
        require(after == before, 'CAPACITY_CONTAINER_CHANGED')
        remaining(self.deadline)
        return {'source': 'docker-owned-container-one-shot', 'observed_at': datetime.now(timezone.utc).isoformat(),
            'container': container, 'cpu_percent': raw['cpu'][:-1], 'memory_used_bytes': memory[0],
            'memory_limit_bytes': memory[1], 'process_count': int(raw['pids']),
            'block_read_bytes': io[0], 'block_written_bytes': io[1], 'container_writable_bytes': writable,
            'project_quota': {'state': 'unavailable', 'reason': 'NO_TARGET_HOST_QUOTA_OBSERVER'},
            'log_bytes': {'state': 'unavailable', 'reason': 'NO_OWNED_LOG_USAGE_OBSERVER'},
            'participants': {'state': 'unavailable', 'reason': 'NO_NATIVE_WORKLOAD_OBSERVER'}}


class HostCapacityScenario:
    """Exactly100 cycles over a running owner; collection is not qualification.

    The caller constructs/authenticates existing owners and authorizes actual
    host execution separately. No CLI/JSON can create those owners here.
    """
    def __init__(self, supervisor, spec, ledger, report_path, *, session, deadline, candidate_sha, workload_id):
        require(type(supervisor) is Supervisor and type(spec) is FixtureSpec
                and type(ledger) is RoomLedger and type(session) is HumanSession
                and session.room_id == ledger.room_id == supervisor.room_id == spec.room_id,
                'CAPACITY_OWNER_REQUIRED')
        require(type(candidate_sha) is str and re.fullmatch(r'[0-9a-f]{40}', candidate_sha)
                and type(workload_id) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', workload_id),
                'CAPACITY_METADATA_INVALID')
        remaining(deadline)
        self.supervisor, self.spec, self.ledger, self.deadline = supervisor, spec, ledger, deadline
        self.observer = DockerCapacityObserver(supervisor, deadline=deadline)
        self.spec_document = spec.document()
        self.report_path, self.candidate, self.workload = report_path, candidate_sha, workload_id
        self.started = False
        self.session = session
        self.operation = uuid.uuid4().hex

    def snapshot(self, phase):
        remaining(self.deadline)
        # Canonical lifecycle lock is unchanged. It is not wall-clock bounded on
        # this baseline; the deadline bounds scheduling/our one-shot reads only.
        with self.supervisor._locked():
            state = deepcopy(self.supervisor._read())
            require(state is not None and state['phase'] == phase and state['spec'] == self.spec_document
                    and state.get('pending_spec') is None
                    and state['instance_id'] == self.session.instance_id, 'CAPACITY_LIFECYCLE_CHANGED')
            resources = {}
            for kind in ('container', 'volume'):
                self.observer.admission()
                resources[kind] = self.supervisor.backend.inspect(state, kind)
            require(all(resources.values()) and resources['container']['running'] is (phase == 'running'),
                    'CAPACITY_RESOURCE_CHANGED')
            # Existing start/stop authorization is rechecked by their owner; read
            # access here is possession of the typed trusted host owner, not a
            # new participant capability or supplied authority field.
        databases = self.ledger._connection().execute('PRAGMA database_list').fetchall()
        paths = [row[2] for row in databases if row[1] == 'main']
        require(len(paths) == 1 and bool(paths[0]), 'CAPACITY_PERSISTENT_LEDGER_REQUIRED')
        ledger_path = Path(paths[0])
        snapshot = self.ledger.snapshot()
        result = {'instance': state['instance_id'], 'container': resources['container']['id'],
            'volume': resources['volume']['id'], 'image': resources['container']['image_id'],
            'projects': [identity(p, directory=True) for p in self.spec_document['project_paths']],
            'ledger': identity(ledger_path), 'room_seq': snapshot['room_seq']}
        require(snapshot['room_id'] == self.spec.room_id, 'CAPACITY_LEDGER_CHANGED')
        remaining(self.deadline)
        return state, result

    @staticmethod
    def retained(first, current):
        require(all(first[k] == current[k] for k in first if k != 'room_seq')
                and type(current['room_seq']) is int and current['room_seq'] >= first['room_seq'],
                'CAPACITY_RETENTION_FAILED')

    def run(self):
        require(not self.started, 'CAPACITY_ALREADY_STARTED')
        self.started = True
        report = CapacityReport(self.report_path, self.spec_document['project_paths'])
        completed = 0; pending = None; last = None; result = None
        try:
            report.append({'kind': 'start', 'version': 1, 'cycles_required': CYCLES,
                'candidate_sha_annotation': self.candidate, 'workload_id_annotation': self.workload,
                'host': os.uname().nodename, 'kernel': os.uname().release,
                'qualification': 'unqualified', 'missing': list(MISSING)})
            state, first = self.snapshot('running'); last = first
            report.append({'kind': 'baseline', 'identity': first, 'sample': self.observer.sample(state, first)})
            for cycle in range(1, CYCLES + 1):
                elapsed = {}
                for action, phase in (('stop', 'stopped'), ('start', 'running')):
                    remaining(self.deadline)
                    view = self.supervisor.manager_view(session=self.session, deployment_id=self.session.deployment_id)
                    require(view['current'] is not None and view['current']['instance_id'] == first['instance']
                            and view['current'] == lifecycle_current(state),
                            'CAPACITY_LIFECYCLE_CHANGED')
                    operation = 'capacity-' + self.operation + '-' + str(cycle) + '-' + action
                    request = {'version': 1, 'operation_id': operation, 'action': action,
                        'deployment_id': self.session.deployment_id, 'room_id': self.spec.room_id,
                        'instance_id': first['instance'], 'run_id': None, 'generation': None,
                        'object_id': first['instance'], 'observed_version': view['current']['observed_version'],
                        'payload': {}}
                    # Durable report intent precedes canonical fenced owner intent.
                    pending = {'cycle': cycle, 'action': action, 'operation_id': operation}
                    report.append({'kind': 'intent', **pending,
                        'instance': first['instance'], 'request': request, 'qualification': 'unqualified'})
                    remaining(self.deadline)
                    started = time.monotonic()
                    response = self.supervisor.manager_action(request, session=self.session,
                        deployment_id=self.session.deployment_id, ledger=self.ledger)
                    elapsed[action + '_seconds'] = time.monotonic() - started
                    if response.get('outcome') == 'denied':
                        report.append({'kind': 'effect-denied', **pending})
                        pending = None
                        raise LifecycleError('CAPACITY_OWNER_DENIED')
                    require(response.get('outcome') == 'confirmed', 'CAPACITY_OWNER_OUTCOME_UNCONFIRMED')
                    state, current = self.snapshot(phase)
                    self.retained(last, current); last = current
                    report.append({'kind': 'effect-observed', **pending, 'identity': current,
                        'elapsed_seconds': elapsed[action + '_seconds']})
                    pending = None
                metrics = self.observer.sample(state, last)
                completed = cycle
                report.append({'kind': 'cycle', 'cycle': cycle, 'identity': last, 'sample': metrics,
                    'timing': elapsed, 'manager': [asdict(value) for value in self.supervisor.manager_observations()]})
            result = {'collection': 'complete', 'cycles_completed': completed, 'qualification': 'unqualified',
                'missing': list(MISSING), 'defaults': None, 'cleanup': 'none-room-and-project-retained'}
            report.append({'kind': 'terminal', **result})
            return result
        except BaseException as error:
            # No stop/start/reconcile/cleanup here: uncertain effects require the
            # existing owner and fresh human decision, not report-based replay.
            code = getattr(error, 'code', 'CAPACITY_OBSERVATION_UNAVAILABLE')
            if type(code) is not str or not re.fullmatch(r'[A-Z0-9_]{1,96}', code): code = 'CAPACITY_OBSERVATION_UNAVAILABLE'
            result = {'collection': 'unknown' if pending else 'failed', 'reason': code,
                'cycles_completed': completed, 'pending': pending, 'qualification': 'unqualified',
                'missing': list(MISSING), 'defaults': None, 'cleanup': 'none-room-and-project-retained'}
            try: report.append({'kind': 'terminal', **result})
            except BaseException: pass  # Previous fsynced intent remains the evidence.
            if isinstance(error, (KeyboardInterrupt, SystemExit)): raise
            return result
        finally:
            report.close()
