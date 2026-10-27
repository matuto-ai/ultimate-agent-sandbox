"""Narrow authenticated human Start for an existing persistent Room.

This is not the Manager workflow command vocabulary. A trusted operator binds a
TLS client certificate to one human and one Room instance; neither identity nor
specification is accepted from the request. Fresh Supervisor authorization and
an exact observed lifecycle revision are mandatory before recording intent.
"""
import hashlib
import json
import re
import socket
import sqlite3
import ssl
from pathlib import Path

from .lifecycle import LifecycleError, Supervisor, _canonical
from .manager_transport import receive_frame, send_frame

PATH = '/uas/room-start/v1'
TOKEN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')


class StartCertificateBindings:
    def __init__(self, bindings):
        if type(bindings) is not dict or not bindings:
            raise LifecycleError('START_CERTIFICATES_REQUIRED')
        self.bindings = {}
        for fingerprint, principal in bindings.items():
            if (type(fingerprint) is not str or not re.fullmatch('[0-9a-f]{64}', fingerprint)
                    or type(principal) is not tuple or len(principal) != 3
                    or any(type(v) is not str or not TOKEN.fullmatch(v) for v in principal)):
                raise LifecycleError('START_CERTIFICATE_BINDING_INVALID')
            self.bindings[fingerprint] = principal

    def authenticate(self, channel):
        if (type(channel) is not ssl.SSLSocket or channel.context.verify_mode != ssl.CERT_REQUIRED
                or channel.version() != 'TLSv1.3'):
            raise LifecycleError('START_MUTUAL_TLS_REQUIRED')
        certificate = channel.getpeercert(binary_form=True)
        principal = self.bindings.get(hashlib.sha256(certificate).hexdigest()) if certificate else None
        if principal is None:
            raise LifecycleError('START_HUMAN_CERTIFICATE_UNREGISTERED')
        return principal


class RemoteStart:
    """Host-owned idempotent receipt store; no callback or client-selected spec."""
    def __init__(self, supervisor, bindings):
        if type(supervisor) is not Supervisor or type(bindings) is not StartCertificateBindings:
            raise LifecycleError('START_OWNER_INVALID')
        self.supervisor, self.bindings = supervisor, bindings

    def serve_once(self, channel):
        principal = self.bindings.authenticate(channel)
        request = receive_frame(channel, path=PATH)
        result = self._start(principal, request)
        send_frame(channel, result, response=True, path=PATH)
        return result

    def _start(self, principal, request):
        # This method is a trusted transport seam, never a JSON identity parser.
        if (type(principal) is not tuple or principal not in self.bindings.bindings.values()
                or type(request) is not dict or set(request) != {'version','kind','operation_id','observed_revision'}
                or type(request['version']) is not int or request['version'] != 1 or request['kind'] != 'start'
                or type(request['operation_id']) is not str or not TOKEN.fullmatch(request['operation_id'])
                or type(request['observed_revision']) is not int or not 1 <= request['observed_revision'] < 2**63):
            raise LifecycleError('START_REQUEST_INVALID')
        human, room, instance = principal
        supervisor = self.supervisor
        with supervisor._locked():
            state = supervisor._read()
            if (state is None or room != supervisor.room_id or instance != state['instance_id']
                    or state['desired'] == 'destroyed'):
                raise LifecycleError('START_INSTANCE_MISMATCH')
            supervisor._allowed('start', state)
            control = supervisor._control_plane
            if control is None or control.require_ready_locked() is not True:
                raise LifecycleError('CONTROL_PLANE_NOT_READY')
            path = supervisor._owned_directory(state) / 'remote-start.db'
            if path.is_symlink():
                raise LifecycleError('START_STORE_INVALID')
            database = sqlite3.connect(path, isolation_level=None)
            try:
                database.execute('PRAGMA synchronous=FULL')
                database.execute('CREATE TABLE IF NOT EXISTS starts (operation TEXT PRIMARY KEY, request TEXT NOT NULL, result TEXT)')
                canonical = _canonical({'human': human, 'room': room, 'instance': instance, 'request': request})
                previous = database.execute('SELECT request,result FROM starts WHERE operation=?', (request['operation_id'],)).fetchone()
                if previous is not None and previous[0] != canonical:
                    raise LifecycleError('START_IDEMPOTENCY_CONFLICT')
                if previous is not None and previous[1] is not None:
                    return json.loads(previous[1])
                marker = {'operation_id': request['operation_id'], 'human_id': human,
                          'request_digest': hashlib.sha256(canonical.encode()).hexdigest()}
                if state.get('remote_start') != marker:
                    if state.get('observation_revision') != request['observed_revision']:
                        raise LifecycleError('START_STALE_OBSERVATION')
                    if previous is None:
                        database.execute('INSERT INTO starts VALUES (?,?,NULL)', (request['operation_id'], canonical))
                    state.update(remote_start=marker, phase='starting', desired='running')
                    supervisor._save(state)  # Persist authorized exact intent before Engine effect.
                if state['desired'] != 'running':
                    result = {'kind': 'start-superseded', 'operation_id': request['operation_id']}
                else:
                    value = supervisor._converge_running(state)
                    result = {'kind': 'start-result', 'operation_id': request['operation_id'],
                              'room_id': room, 'instance_id': instance, 'phase': value['phase']}
                database.execute('UPDATE starts SET result=? WHERE operation=?', (_canonical(result), request['operation_id']))
                return result
            except sqlite3.Error:
                raise LifecycleError('START_RECEIPT_UNCONFIRMED') from None
            finally:
                database.close()
