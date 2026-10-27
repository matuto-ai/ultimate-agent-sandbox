#!/usr/bin/env python3
"""Explicit disposable-VM artifacts Hub, outside the Trusted Workstation.

The Run seed is trusted qualification setup, NOT Forge/Runtime Run-admission
proof. Actual evaluations use the real RoomLedger, ArtifactGateHub and private
GateControlClient. There is no Participant ADMIT, claimed verdict or mock native
admission. This entrypoint is never a production launch path.
"""
from contextlib import ExitStack, closing
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import sys
import threading
import time
import uuid

from uas.artifact_helper import GateControlClient, GateOffer
from uas.artifact_protocol import canonical
from uas.gate_evaluation import ArtifactGateHub, GateRoomBinding
from uas.gate_policy import compile_policy
from uas.kernel_origin import HeldOrigin, OriginDenied, ReceiverIdentity, enable, probe, receive
from uas.ledger import Command, Event, LedgerError, Origin, RoomLedger, Transition
from uas.workstation_exec import EndpointLease
from uas.workstation_probe import process_status

CONTROL = '/uas/control/hub.sock'
STORE = Path('/uas/hub')
RELEASE = b'AGB-RELEASE-1'
DONE_ACK = b'AGB-DONE-ACK-1'
MAX_STARTUP_BYTES = 8192
MAX_REPORT_BYTES = 1 << 20
ROOM_DISK_BYTES = 256 << 20
SCENARIOS = ('present', 'missing', 'alternates', 'mutation', 'loss', 'malformed', 'resource', 'cleanup')
_TOKEN = re.compile(r'[a-z][a-z0-9-]{0,63}\Z')
_HEX64 = re.compile(r'[0-9a-f]{64}\Z')
_HEX32 = re.compile(r'[0-9a-f]{32}\Z')
_BRANCH = re.compile(r'refs/heads/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*\Z')
STARTUP_KEYS = {'version', 'challenge', 'supervisor_identity', 'mapping_digest',
    'profile_digest', 'room_id', 'room_instance', 'project_id', 'repository',
    'run_id', 'participant_id', 'checkout', 'scenarios'}


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise OriginDenied('duplicate qualification startup field')
        value[key] = item
    return value


def configuration(raw):
    """Only the trusted exact container-start stdin supplies these bindings."""
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_STARTUP_BYTES:
        raise OriginDenied('bounded fixed Hub startup required')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise OriginDenied('invalid qualification startup') from error
    if (type(value) is not dict or set(value) != STARTUP_KEYS
            or type(value['version']) is not int or value['version'] != 1
            or any(type(value[k]) is not str or not _HEX64.fullmatch(value[k])
                   for k in ('challenge', 'mapping_digest', 'profile_digest'))
            or any(type(value[k]) is not str or not _TOKEN.fullmatch(value[k])
                   for k in ('room_id', 'project_id', 'run_id', 'participant_id'))
            or type(value['room_instance']) is not str or not _HEX32.fullmatch(value['room_instance'])
            or type(value['repository']) is not str or not re.fullmatch(
                r'[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}', value['repository'])
            or any(part in ('.', '..') for part in value['repository'].split('/'))
            or type(value['supervisor_identity']) is not list or len(value['supervisor_identity']) != 2
            or any(type(v) is not int or not 0 <= v < 2**64 for v in value['supervisor_identity'])
            or type(value['scenarios']) is not list or not 1 <= len(value['scenarios']) <= len(SCENARIOS)
            or any(type(s) is not str or s not in SCENARIOS for s in value['scenarios'])
            or len(set(value['scenarios'])) != len(value['scenarios'])):
        raise OriginDenied('invalid fixed Hub startup binding')
    checkout = value['checkout']
    if (type(checkout) is not dict or set(checkout) != {'slot', 'branch'}
            or type(checkout['slot']) is not str
            or not (checkout['slot'] == 'primary' or _HEX32.fullmatch(checkout['slot']))
            or type(checkout['branch']) is not str or not _BRANCH.fullmatch(checkout['branch'])
            or len(checkout['branch']) > 512
            or (checkout['slot'] != 'primary' and checkout['branch'] != 'refs/heads/uas-slot/' + checkout['slot'])):
        raise OriginDenied('invalid recorded checkout binding')
    return value


def fixture_policy():
    """All paths/types are fixed source; startup cannot choose evaluator input."""
    gates = []
    for scenario in SCENARIOS:
        items = [{'path': 'artifact-missing.txt' if scenario == 'missing' else 'README.md',
                  'type': 'file', 'nonempty': True}]
        if scenario == 'present':
            items.append({'path': 'docs', 'type': 'directory', 'nonempty': True})
        gates.append({'id': 'artifact-' + scenario, 'kind': 'mechanical',
                      'evaluator': 'artifacts', 'config': {'items': items}})
    names = [gate['id'] for gate in gates]
    return compile_policy({'id': 'artifact-qualification-v1', 'version': 1,
        'gates': gates, 'protected_operations': {'submit-for-review': names, 'complete': names},
        'review_return_cap': 2, 'queue_timeout_seconds': 30, 'response_timeout_seconds': 30},
        'qualification.policy')


def fixture_origin(controller):
    if type(controller) is not str or not _HEX32.fullmatch(controller):
        raise OriginDenied('invalid fixed Hub controller')
    return Origin('qualification-operator', 'qualification-human', controller,
                  'qualification-authority-v1', ('qualification-evaluate',))


def seed_fixture_run(ledger, metadata, origin):
    """Explicit fresh ledger seed; never adopts/reconstructs an existing Run."""
    if ledger.room_id != metadata['room_id']:
        raise LedgerError('QUALIFICATION_ROOM_MISMATCH')
    run = {'run_id': metadata['run_id'], 'generation': 1, 'status': 'ACTIVE',
        'project_id': metadata['project_id'], 'repository': metadata['repository'],
        'participant_id': metadata['participant_id'], 'policy': fixture_policy(),
        'checkout': deepcopy(metadata['checkout']), 'qualification_fixture_seed': True}
    command = Command('qualification-seed', 'qualification.fixture-run-seed', run['run_id'], None,
                      {'source': 'trusted-disposable-fixture', 'native_run_admission_qualified': False})
    if ledger.snapshot()['room_seq'] != 0:
        raise LedgerError('QUALIFICATION_LEDGER_NOT_FRESH')
    def decide(state, _):
        if state:
            raise LedgerError('QUALIFICATION_LEDGER_NOT_FRESH')
        state['runs'] = {run['run_id']: deepcopy(run)}
        return Transition(state, (Event('qualification.fixture-run-seeded', {
            'run_id': run['run_id'], 'generation': 1, 'checkout': deepcopy(run['checkout']),
            'native_run_admission_qualified': False}),), {'run_id': run['run_id']})
    ledger.apply(command, origin, authorize=lambda candidate, _: candidate == origin, decide=decide)


def run_evaluations(hub, metadata, origin):
    """Invoke exact public Gate arguments; preserve actual outcomes, never guess."""
    results = []
    for scenario in metadata['scenarios']:
        operation = 'artifact-' + scenario
        try:
            result = hub.evaluate(operation, metadata['run_id'], 1, operation, origin=origin)
            # A deliberate same-operation lookup proves transport retry does not
            # cause a second target/helper. It is not a hidden evaluation retry.
            duplicate = hub.evaluate(operation, metadata['run_id'], 1, operation, origin=origin)
            if canonical(result) != canonical(duplicate):
                raise LedgerError('QUALIFICATION_RETRY_CHANGED')
            results.append({'scenario': scenario, 'operation_id': operation,
                'outcome': 'evaluation', 'evaluation': result, 'exact_retry_equal': True})
        except LedgerError as error:
            results.append({'scenario': scenario, 'operation_id': operation,
                'outcome': 'request-error', 'error': error.code})
    return results


def install_fixture_faults(client, injected, *, monotonic=time.monotonic, sleep=time.sleep):
    """Fixed hostile-channel probes after REAL launch and GATE_BIND only.

    This deliberately damages the actual helper channel; it never substitutes a
    fake offer, admission, raw observation or terminal verdict. The resource
    case observes only self wall-lifetime, not CPU/memory exhaustion.
    """
    actual_start = client.start
    def start(scope, target, paths):
        offer = actual_start(scope, target, paths)
        if type(offer) is not GateOffer:
            raise OriginDenied('actual kernel-bound GateOffer required')
        gate = scope['gate_id']
        if gate == 'artifact-loss':
            offer.channel.shutdown(socket.SHUT_RDWR)
            offer.channel.close()
            injected.append({'scenario': 'loss', 'fault': 'close-actual-held-helper-channel'})
        elif gate == 'artifact-malformed':
            if offer.channel.send(b'BAD1') != 4:
                raise OriginDenied('malformed request injection not fully queued')
            injected.append({'scenario': 'malformed', 'fault': 'malformed-request-to-real-helper',
                             'malformed_helper_output_claimed': False})
        elif gate == 'artifact-resource':
            started = monotonic()
            sleep(16)  # actual bootstrap has a non-rearmable 15-second alarm
            injected.append({'scenario': 'resource', 'fault': 'withhold-request-past-self-lifetime',
                'elapsed_seconds': round(monotonic() - started, 3),
                'scope': 'wall-lifetime-only-not-cpu-or-memory-exhaustion'})
        return offer
    client.start = start


def report_document(ledger, metadata, results, injected=()):
    snapshot = ledger.snapshot()
    run = snapshot['state'].get('runs', {}).get(metadata['run_id'])
    if run is None or run['status'] != 'ACTIVE' or run['generation'] != 1:
        raise LedgerError('QUALIFICATION_RUN_ADVANCED')
    result = {'version': 1, 'room_id': metadata['room_id'], 'room_instance': metadata['room_instance'],
        'profile': 'artifacts-v1-source', 'run_seed': 'trusted-fixture-not-native-admission',
        'production_enabled': False, 'native_run_admission_qualified': False,
        'results': results, 'injected_faults': list(injected), 'ledger': snapshot}
    data = canonical(result)
    if len(data) > MAX_REPORT_BYTES:
        raise OriginDenied('qualification report byte bound exceeded')
    return data


def write_report(data):
    """Create one bounded owned report; never replace or follow prior output."""
    if type(data) is not bytes or not 0 < len(data) <= MAX_REPORT_BYTES:
        raise OriginDenied('invalid bounded qualification report')
    parent = os.open(STORE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(parent)
        if info.st_uid != 65531 or info.st_mode & 0o7777 != 0o700:
            raise OriginDenied('private Hub report directory required')
        fd = os.open('report.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.fsync(parent)
    finally:
        os.close(parent)


def _send(control, document):
    data = canonical(document)
    if len(data) > 16384 or control.send(data) != len(data):
        raise OriginDenied('incomplete qualification control record')


def main():
    if len(sys.argv) != 1 or (os.getuid(), os.getgid()) != (65531, 65531):
        raise OriginDenied('fixed unprivileged qualification Hub required')
    probe()
    status = process_status()
    if status != {'CapEff': '0000000000000000', 'CapBnd': '0000000000000000', 'NoNewPrivs': '1', 'Seccomp': '2'}:
        raise OriginDenied('actual Hub confinement differs')
    metadata = configuration(sys.stdin.buffer.readline(MAX_STARTUP_BYTES + 1))
    mapping = {'uid_map': Path('/proc/self/uid_map').read_text(),
               'gid_map': Path('/proc/self/gid_map').read_text(),
               'overflow_uid': int(Path('/proc/sys/kernel/overflowuid').read_text()),
               'overflow_gid': int(Path('/proc/sys/kernel/overflowgid').read_text())}
    if (mapping['overflow_uid'] != 65534 or mapping['overflow_gid'] != 65534
            or hashlib.sha256(json.dumps(mapping, sort_keys=True).encode()).hexdigest() != metadata['mapping_digest']):
        raise OriginDenied('actual Hub receiver mapping differs')
    endpoint = EndpointLease(CONTROL, owner=65533, group=65531)
    with ExitStack() as stack:
        control = stack.enter_context(closing(socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)))
        enable(control); control.settimeout(45); control.connect(CONTROL); endpoint.require()
        hello = b'AGB1' + bytes.fromhex(metadata['challenge'])
        if control.send(hello) != len(hello):
            raise OriginDenied('incomplete qualification bootstrap')
        with receive(control) as record:
            if record.credentials[1:] != (65533, 65533) or record.data != RELEASE:
                raise OriginDenied('unexpected qualification Supervisor')
            supervisor = HeldOrigin(record, receiver=ReceiverIdentity(65533, 65533,
                'supervisor-' + metadata['room_instance'], metadata['mapping_digest']))
            stack.callback(supervisor.close)
            if list(supervisor.identity) != metadata['supervisor_identity']:
                raise OriginDenied('Supervisor held kernel identity mismatch')
        controller = uuid.uuid4().hex
        origin = fixture_origin(controller)
        ledger = RoomLedger(STORE / 'room.db', metadata['room_id']); stack.callback(ledger.close)
        seed_fixture_run(ledger, metadata, origin)
        client = GateControlClient(control, supervisor=supervisor,
            receiver=ReceiverIdentity(65530, 65530, 'artifact-hub-' + metadata['room_instance'], metadata['mapping_digest']),
            profile_digest=metadata['profile_digest'], controller=controller, control_lock=threading.RLock())
        def authorize(candidate, command):
            return (candidate == origin and command.kind == 'gate.evaluate'
                    and command.target == metadata['run_id'] and command.generation == 1
                    and command.payload.get('gate_id') in {'artifact-' + case for case in metadata['scenarios']}
                    and not supervisor.revoked)
        injected = []
        install_fixture_faults(client, injected)
        hub = ArtifactGateHub(ledger, GateRoomBinding(metadata['room_id'], metadata['room_instance'],
            metadata['project_id'], metadata['repository'], ROOM_DISK_BYTES), client, authorize=authorize)
        _send(control, {'version': 1, 'kind': 'GATE_READY', 'controller': controller,
            'room_id': metadata['room_id'], 'room_instance': metadata['room_instance'],
            'observation': {'uid': os.getuid(), 'gid': os.getgid(), 'parent': os.getppid(),
                'kernel_status': status, **mapping,
                'label': Path('/proc/self/attr/current').read_text().rstrip('\0\n'),
                'pid_namespace': os.readlink('/proc/self/ns/pid'),
                'mount_namespace': os.readlink('/proc/self/ns/mnt')}})
        results = run_evaluations(hub, metadata, origin)
        data = report_document(ledger, metadata, results, injected); write_report(data)
        _send(control, {'version': 1, 'kind': 'GATE_DONE', 'controller': controller,
            'report_digest': hashlib.sha256(data).hexdigest(), 'report_bytes': len(data),
            'scenarios': metadata['scenarios']})
        # Supervisor authenticates the terminal sender while still held alive.
        # EOF alone never supplies terminal evidence or task-exit confirmation.
        with receive(control) as record:
            supervisor.require(record)
            if record.data != DONE_ACK:
                raise OriginDenied('missing exact qualification terminal acknowledgment')


if __name__ == '__main__':
    main()
