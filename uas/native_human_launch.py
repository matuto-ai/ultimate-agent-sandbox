"""Explicit existing operator input for one original native qualification.

This module does not create a grant file, listener, certificate or permission.
The protected operator document is authority configuration; its digest/nonce
are only correlation. Startup JSON must never contain its parsed human Origin.
"""
from contextlib import contextmanager
from copy import deepcopy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import time

from .human_mtls import ACTIONS, HumanActionBindings, HumanActionGrant
from .ledger import LedgerError, Origin, _token
from .native_pi_recipe import path, unique


GRANTS_DIRECTORY = Path('/etc/uas/native-human-grants')
MAX_GRANT_BYTES = 16384
HOST_UID = 165533
_SHA = re.compile(r'[0-9a-f]{64}\Z')
_NONCE = re.compile(r'[0-9a-f]{32}\Z')


def _require(condition, code):
    if not condition: raise LedgerError(code)


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode, info.st_uid, info.st_gid, info.st_nlink)


def reference(plan):
    """Public selection only; no file or TLS credential is opened here."""
    from .native_qualification import QualificationPlan
    _require(type(plan) is QualificationPlan, 'NATIVE_HUMAN_QUALIFICATION_PLAN_REQUIRED')
    plan.require_unchanged()
    ref = plan.installation.get('human_host_manifest')
    if ref is None: return None
    _require(type(ref) is dict and set(ref) == {'path', 'sha256'}
        and ref['path'] == str(GRANTS_DIRECTORY / (plan.installation['nonce'] + '.json'))
        and type(ref['sha256']) is str and _SHA.fullmatch(ref['sha256']),
        'NATIVE_HUMAN_GRANT_REFERENCE_INVALID')
    return deepcopy(ref)


def _parse(raw, plan):
    try: value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError):
        raise LedgerError('NATIVE_HUMAN_GRANT_INVALID') from None
    fields = {'version', 'purpose', 'deployment_id', 'room_id', 'configuration_sha256',
        'installation_nonce', 'manager_id', 'client_certificate_sha256', 'human_origin', 'actions', 'tls'}
    _require(type(value) is dict and set(value) == fields and type(value['version']) is int
        and value['version'] == 1 and value['purpose'] == 'one-original-native-qualification'
        and value['deployment_id'] == plan.config['deployment']['id']
        and value['room_id'] == plan.room['id'] and value['configuration_sha256'] == plan.config_digest
        and value['installation_nonce'] == plan.installation['nonce'], 'NATIVE_HUMAN_GRANT_SCOPE_INVALID')
    _token(value['manager_id'])
    _require(type(value['client_certificate_sha256']) is str
        and _SHA.fullmatch(value['client_certificate_sha256']), 'NATIVE_HUMAN_GRANT_INVALID')
    origin = value['human_origin']
    _require(type(origin) is dict and set(origin) == {'actor_id', 'participant_id',
        'incarnation_id', 'authority_version', 'capabilities'}
        and type(origin['capabilities']) is list, 'NATIVE_HUMAN_GRANT_INVALID')
    human = Origin(**{**origin, 'capabilities': tuple(origin['capabilities'])})
    _require(human.canonical() == origin, 'NATIVE_HUMAN_GRANT_INVALID')
    actions = value['actions']
    _require(type(actions) is list and all(type(action) is str and action in ACTIONS for action in actions)
        and len(set(actions)) == len(actions)
        and {'open-run', 'authorize-run-request'}.issubset(actions)
        and 'human-open-run' in human.capabilities, 'NATIVE_HUMAN_ACTION_GRANT_REQUIRED')
    if {'request-changes', 'reconcile-changes'}.intersection(actions):
        _require('observe' in actions and 'human-control-run' in human.capabilities,
                 'NATIVE_HUMAN_ACTION_GRANT_REQUIRED')
    tls = value['tls']
    _require(type(tls) is dict and set(tls) == {'trust_file', 'certificate_file', 'private_key_file'},
             'NATIVE_HUMAN_TLS_REFERENCES_REQUIRED')
    try:
        for filename in tls.values(): path(filename)
    except (ValueError, TypeError):
        raise LedgerError('NATIVE_HUMAN_TLS_REFERENCES_REQUIRED') from None
    return value


def read_held_grant(fd, plan, *, identity=None):
    """Read one original read-only protected FD; never reopen a selected path."""
    ref = reference(plan)
    _require(ref is not None and type(fd) is int and fd >= 3, 'NATIVE_HUMAN_GRANT_REQUIRED')
    before = os.fstat(fd)
    _require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and not before.st_mode & 0o077
        and before.st_nlink == 1 and 0 < before.st_size <= MAX_GRANT_BYTES
        and fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY,
        'NATIVE_HUMAN_PROTECTED_GRANT_REQUIRED')
    exact = _identity(before)
    _require(identity is None or tuple(identity) == exact, 'NATIVE_HUMAN_GRANT_CHANGED')
    raw = os.pread(fd, MAX_GRANT_BYTES + 1, 0)
    _require(len(raw) == before.st_size and hashlib.sha256(raw).hexdigest() == ref['sha256']
        and _identity(os.fstat(fd)) == exact, 'NATIVE_HUMAN_GRANT_CHANGED')
    value = _parse(raw, plan)
    _require(_identity(os.fstat(fd)) == exact, 'NATIVE_HUMAN_GRANT_CHANGED')
    return value, exact


def open_grant(plan):
    """Root reads an existing fixed protected directory; no setup fallback."""
    ref = reference(plan)
    _require(os.getuid() == 0 and ref is not None, 'NATIVE_HUMAN_ROOT_OWNER_REQUIRED')
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    fd = None
    try:
        for part in GRANTS_DIRECTORY.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=directory)
            os.close(directory); directory = child
            info = os.fstat(directory)
            _require(info.st_uid == 0 and not info.st_mode & 0o022,
                     'NATIVE_HUMAN_PROTECTED_DIRECTORY_REQUIRED')
        fd = os.open(Path(ref['path']).name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        value, identity = read_held_grant(fd, plan)
        return fd, value, identity
    except BaseException:
        if fd is not None: os.close(fd)
        raise
    finally:
        os.close(directory)


def raw_stream_identity(channel):
    """Validate the supplied connected raw stream, never inherited TLS state.

    Accepted-server custody is the trusted launcher contract; socket metadata
    alone cannot distinguish an accepted stream from an outbound connection.
    Actual server-side TLS and the explicit certificate grant authenticate it.
    """
    _require(type(channel) is socket.socket and channel.family in (socket.AF_INET, socket.AF_INET6)
        and channel.fileno() >= 3 and channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_STREAM
        and channel.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 0,
        'NATIVE_HUMAN_RAW_STREAM_REQUIRED')
    try:
        peer, local = channel.getpeername(), channel.getsockname()
        node = os.fstat(channel.fileno())
    except OSError:
        raise LedgerError('NATIVE_HUMAN_RAW_STREAM_REQUIRED') from None
    _require(stat.S_ISSOCK(node.st_mode) and bool(peer) and bool(local), 'NATIVE_HUMAN_RAW_STREAM_REQUIRED')
    return (channel.fileno(), node.st_dev, node.st_ino, peer, local)


class NativeHumanLaunch:
    """One-shot root custody; failed/uncertain transfer cannot mint a retry."""
    def __init__(self, plan, channel):
        self.channel = channel
        self.stream_identity = raw_stream_identity(channel)
        self.fd, _, self.grant_identity = open_grant(plan)
        self.plan = plan
        self.transferred = self.closed = False
        self.instance = None

    def transfer(self, resources, *, deadline):
        _require(not self.transferred and not self.closed and type(resources) is dict
            and resources.get('room_id') == self.plan.room['id']
            and type(resources.get('instance')) is str and _NONCE.fullmatch(resources['instance'])
            and type(deadline) in (int, float) and 0 < deadline - time.monotonic() <= 180,
            'NATIVE_HUMAN_LAUNCH_CUSTODY_REQUIRED')
        _require(raw_stream_identity(self.channel) == self.stream_identity,
                 'NATIVE_HUMAN_RAW_STREAM_CHANGED')
        read_held_grant(self.fd, self.plan, identity=self.grant_identity)
        # Fence before Popen/transfer, including when its outcome is uncertain.
        self.transferred, self.instance = True, resources['instance']
        return {'grant_fd': self.fd, 'grant_identity': list(self.grant_identity),
                'raw_fd': self.channel.fileno(), 'raw_identity': json.loads(json.dumps(self.stream_identity)),
                'instance': self.instance, 'deadline': deadline}

    def close(self):
        if self.closed: return
        self.closed = True
        try: self.channel.close()
        finally:
            fd, self.fd = self.fd, -1
            if fd >= 0: os.close(fd)


def host_bindings(plan, resources, selection):
    """Final host only, after actual original Room observation, before handshake."""
    _require(type(selection) is dict and set(selection) == {'grant_fd', 'grant_identity', 'raw_fd', 'raw_identity', 'instance', 'deadline'}
        and selection['instance'] == resources['instance'] and resources['room_id'] == plan.room['id']
        and type(selection['deadline']) in (int, float) and 0 < selection['deadline'] - time.monotonic() <= 180
        and type(selection['raw_fd']) is int and selection['raw_fd'] >= 3
        and type(selection['raw_identity']) is list and len(selection['raw_identity']) == 5
        and selection['raw_identity'][0] == selection['raw_fd']
        and type(selection['grant_identity']) is list and len(selection['grant_identity']) == 9
        and all(type(item) is int for item in selection['grant_identity']), 'NATIVE_HUMAN_LAUNCH_CUSTODY_REQUIRED')
    value, _ = read_held_grant(selection['grant_fd'], plan, identity=selection['grant_identity'])
    origin = value['human_origin']
    human = Origin(**{**origin, 'capabilities': tuple(origin['capabilities'])})
    grant = HumanActionGrant(value['deployment_id'], value['room_id'], resources['instance'],
        value['manager_id'], human, tuple(value['actions']))
    return HumanActionBindings({value['client_certificate_sha256']: grant}), value['tls']


@contextmanager
def launch_input(plan, channel):
    selected = 'human_host_manifest' in plan.installation
    _require(selected == (channel is not None), 'NATIVE_HUMAN_EXPLICIT_STREAM_REQUIRED')
    if not selected:
        yield None
        return
    reference(plan)  # Exact typed/unchanged declaration required only for opt-in.
    owner = NativeHumanLaunch(plan, channel)
    try: yield owner
    finally: owner.close()


def validate_result(plan, resources, result):
    """Root validates evidence from its exact child, never grants from its JSON."""
    from .run_admission import RunAdmission
    fields = {'version','status','room_id','instance','run_id','product_run_created','reviewer_attached',
        'session','human_review_actions_attached','human_host_attached','configuration_sha256',
        'installation_sha256','lifecycle_blockers','production_launcher','human_host_manifest_sha256','human_request'}
    _require(type(result) is dict and set(result) == fields and type(result['version']) is int
        and result['version'] == 1 and result['status'] == 'NATIVE_RUN_SESSION_FINISHED'
        and result['room_id'] == plan.room['id'] and result['instance'] == resources['instance']
        and result['configuration_sha256'] == plan.config_digest
        and result['installation_sha256'] == plan.installation_digest
        and result['human_host_manifest_sha256'] == reference(plan)['sha256']
        and result['production_launcher'] == 'disabled'
        and all(result[key] is True for key in ('product_run_created','reviewer_attached',
            'human_review_actions_attached','human_host_attached')), 'NATIVE_HUMAN_RESULT_INVALID')
    request, session = result['human_request'], result['session']
    _require(type(request) is dict and set(request) == {'operation_id','issue_number','participant_id'}
        and type(request['operation_id']) is str and type(request['issue_number']) is int
        and 1 <= request['issue_number'] <= 9_999_999_999
        and request['participant_id'] == plan.seats['pi']['participant']
        and result['run_id'] == RunAdmission.run_id(request['operation_id'])
        and type(session) is dict and session.get('current_run') == result['run_id']
        and session.get('authority_restored_from_journal') is False
        and session.get('successor_started') is False and session.get('runs') == []
        and session.get('outcome') in {'completed','inconclusive','attention','unknown'}, 'NATIVE_HUMAN_RESULT_INVALID')
    blockers = result['lifecycle_blockers']
    _require(type(blockers) is list and 1 <= len(blockers) <= 16
        and all(type(value) is str and re.fullmatch('[A-Z_]{1,96}',value) for value in blockers)
        and 'FULL_NATIVE_RUN_COMPLETION_UNQUALIFIED' in blockers, 'NATIVE_HUMAN_RESULT_INVALID')
