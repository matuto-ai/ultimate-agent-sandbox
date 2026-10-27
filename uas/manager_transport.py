"""Mutually authenticated Room-outbound transport, with a read-only vocabulary.

Listener ownership and scheduling belong to the host service. This module never
starts a server/thread, modifies certificates, discovers hosts, or reaches a
network at import/construction time. Run the exporter separately from the Hub
event loop: a Manager connection is not a Hub liveness dependency.
"""
from dataclasses import dataclass
import hashlib
import json
import ipaddress
import re
import socket
import ssl
import time
from urllib.parse import urlsplit

from .manager_projection import ProjectionError
from .manager_stream import ManagerReadModel, RoomIdentity, RoomStream, SnapshotTransfer, StreamError, sequence


MAX_FRAME = 1_048_576
TIMEOUT = 5
MAX_HEADERS = 8192
DEFAULT_PATH = '/v1/room-stream'


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise StreamError('DUPLICATE_WIRE_FIELD')
        result[key] = value
    return result


def _read_exact(channel, count, deadline):
    result = bytearray()
    while len(result) < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise StreamError('MANAGER_FRAME_TIMEOUT')
        channel.settimeout(remaining)
        part = channel.recv(count - len(result))
        if not part:
            raise StreamError('MANAGER_DISCONNECTED')
        result.extend(part)
    return bytes(result)


def _path(value):
    if (type(value) is not str or not re.fullmatch(r'/[A-Za-z0-9._~/-]{0,1023}', value)
            or any(part in {'.', '..'} for part in value.split('/'))):
        raise StreamError('INVALID_MANAGER_PATH')
    return value


def receive_frame(channel, *, response=False, path=DEFAULT_PATH):
    """One bounded ordinary HTTP/1.1 JSON POST/200 response, no chunking.

    Header and body share one absolute receive deadline. No redirect, proxy,
    decompression, URL-selected path, or ambiguous HTTP framing is accepted.
    """
    deadline = time.monotonic() + TIMEOUT
    head = bytearray()
    while not head.endswith(b'\r\n\r\n'):
        if len(head) >= MAX_HEADERS:
            raise StreamError('HTTP_HEADER_LIMIT')
        head.extend(_read_exact(channel, 1, deadline))
    try:
        lines = head[:-4].decode('ascii').split('\r\n')
    except UnicodeError:
        raise StreamError('INVALID_HTTP_HEADERS') from None
    expected = 'HTTP/1.1 200 OK' if response else 'POST ' + _path(path) + ' HTTP/1.1'
    if lines[0] != expected:
        raise StreamError('UNSUPPORTED_HTTP_MESSAGE')
    headers = {}
    for line in lines[1:]:
        name, separator, value = line.partition(':')
        name = name.lower()
        if (not separator or not re.fullmatch('[a-z0-9-]+', name) or name in headers
                or any(ord(c) < 32 or ord(c) == 127 for c in value)):
            raise StreamError('INVALID_HTTP_HEADERS')
        headers[name] = value.strip()
    if ('transfer-encoding' in headers or 'content-encoding' in headers or 'expect' in headers
            or headers.get('content-type') != 'application/json'
            or not re.fullmatch('[0-9]{1,8}', headers.get('content-length', ''))
            or not response and not headers.get('host')):
        raise StreamError('UNSUPPORTED_HTTP_FRAMING')
    length = int(headers['content-length'])
    if not 0 < length <= MAX_FRAME:
        raise StreamError('WIRE_FRAME_LIMIT')
    try:
        frame = json.loads(_read_exact(channel, length, deadline).decode('utf-8'),
                           object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise StreamError('INVALID_WIRE_JSON') from None
    if type(frame) is not dict:
        raise StreamError('INVALID_WIRE_JSON')
    return frame


def send_frame(channel, frame, *, response=False, path=DEFAULT_PATH, host='manager.fixture.invalid'):
    try:
        data = json.dumps(frame, sort_keys=True, separators=(',', ':'),
                          ensure_ascii=False, allow_nan=False).encode()
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise StreamError('INVALID_WIRE_JSON') from None
    if not 0 < len(data) <= MAX_FRAME:
        raise StreamError('WIRE_FRAME_LIMIT')
    if (type(host) is not str or not 1 <= len(host) <= 270
            or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.:-[]' for c in host)):
        raise StreamError('INVALID_MANAGER_ADDRESS')
    start = 'HTTP/1.1 200 OK' if response else 'POST ' + _path(path) + ' HTTP/1.1'
    headers = [start, 'Content-Type: application/json', 'Content-Length: ' + str(len(data)),
               'Connection: keep-alive']
    if not response:
        headers.append('Host: ' + host)
    channel.settimeout(TIMEOUT)
    channel.sendall(('\r\n'.join(headers) + '\r\n\r\n').encode('ascii') + data)


def client_tls_context(*, trust_file, certificate_file, private_key_file):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cafile=trust_file)
    context.load_cert_chain(certfile=certificate_file, keyfile=private_key_file)
    return context


def server_tls_context(*, trust_file, certificate_file, private_key_file):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=trust_file)
    context.load_cert_chain(certfile=certificate_file, keyfile=private_key_file)
    return context


class RoomCertificateBindings:
    """Operator-fixed client certificate fingerprint -> exactly one Room.

    A valid CA chain alone never grants Room selection or Deployment authority.
    Rotation/revocation is an operator task, not a Manager message operation.
    """
    def __init__(self, bindings):
        if type(bindings) is not dict or not bindings:
            raise StreamError('ROOM_CERTIFICATE_BINDINGS_REQUIRED')
        self._bindings = {}
        for fingerprint, identity in bindings.items():
            if (type(fingerprint) is not str or len(fingerprint) != 64
                    or any(c not in '0123456789abcdef' for c in fingerprint)
                    or type(identity) is not RoomIdentity):
                raise StreamError('INVALID_CERTIFICATE_BINDING')
            identity.document()
            self._bindings[fingerprint] = identity

    def authenticate(self, channel):
        if (type(channel) is not ssl.SSLSocket or channel.context.verify_mode != ssl.CERT_REQUIRED
                or channel.version() != 'TLSv1.3'):
            raise StreamError('MUTUAL_TLS_REQUIRED')
        certificate = channel.getpeercert(binary_form=True)
        if not certificate:
            raise StreamError('CLIENT_CERTIFICATE_REQUIRED')
        identity = self._bindings.get(hashlib.sha256(certificate).hexdigest())
        if identity is None:
            raise StreamError('UNREGISTERED_ROOM_CERTIFICATE')
        return identity


class ManagerSession:
    """One authenticated connection; caller cannot choose another Room later."""
    def __init__(self, model, identity):
        if type(model) is not ManagerReadModel:
            raise StreamError('MANAGER_READ_MODEL_REQUIRED')
        self._model, self.identity = model, identity
        self._session = model.connect(identity)
        self._closed = False
        self._channel = None
        self._path = DEFAULT_PATH

    def handle(self, frame):
        if self._closed or type(frame) is not dict or 'kind' not in frame:
            raise StreamError('INVALID_MANAGER_FRAME')
        kind = frame['kind']
        if kind == 'hello' and set(frame) == {'kind', 'identity'}:
            if frame['identity'] != self.identity.document():
                raise StreamError('CERTIFICATE_ROOM_MISMATCH')
            self._model._session(self.identity, self._session)
            return {'kind': 'cursor', 'identity': self.identity.document(),
                    'room_seq': self._model.cursor(self.identity)}
        if kind == 'begin' and set(frame) == {'kind', 'transfer'}:
            transfer_id = self._model.begin(self.identity, self._session, frame['transfer'])
            return {'kind': 'begun', 'transfer_id': transfer_id}
        if kind == 'events' and set(frame) == {'kind', 'page'}:
            received = self._model.append(self.identity, self._session, frame['page'])
            return {'kind': 'received', 'transfer_id': frame['page']['transfer_id'], 'room_seq': received}
        if kind == 'finish' and set(frame) == {'kind', 'transfer_id'}:
            seq = self._model.finish(self.identity, self._session, frame['transfer_id'])
            return {'kind': 'committed', 'transfer_id': frame['transfer_id'], 'room_seq': seq}
        # No command, action, refresh, scope switch, file, shell, or proxy route.
        raise StreamError('UNSUPPORTED_MANAGER_OPERATION')

    def close(self):
        if not self._closed:
            self._closed = True
            try:
                self._model.disconnect(self.identity, self._session)
            except StreamError as error:
                if error.code != 'STALE_MANAGER_CONNECTION':
                    raise


def accept_session(channel, model, bindings, *, path=DEFAULT_PATH):
    _path(path)
    if type(bindings) is not RoomCertificateBindings:
        raise StreamError('ROOM_CERTIFICATE_BINDINGS_REQUIRED')
    identity = bindings.authenticate(channel)
    channel.settimeout(TIMEOUT)
    session = ManagerSession(model, identity)
    session._channel = channel
    session._path = _path(path)
    return session


def serve_once(channel, session):
    """Host schedules one bounded frame; it owns closing failed TLS sessions."""
    if (type(channel) is not ssl.SSLSocket or type(session) is not ManagerSession
            or session._channel is not channel):
        raise StreamError('AUTHENTICATED_SESSION_REQUIRED')
    try:
        response = session.handle(receive_frame(channel, path=session._path))
        send_frame(channel, response, response=True)
    except BaseException:
        session.close()
        channel.close()
        raise


@dataclass(frozen=True)
class ManagerAddress:
    hostname: str
    port: int
    path: str = DEFAULT_PATH

    def validate(self):
        # This address is operator configuration, never a Room/Manager frame.
        if (type(self.hostname) is not str or not self.hostname or len(self.hostname) > 253
                or type(self.port) is not int or not 1 <= self.port <= 65535):
            raise StreamError('INVALID_MANAGER_ADDRESS')
        try:
            ipaddress.ip_address(self.hostname)
        except ValueError:
            if not re.fullmatch(r'[A-Za-z0-9.-]+', self.hostname):
                raise StreamError('INVALID_MANAGER_ADDRESS') from None
        _path(self.path)

    @classmethod
    def from_url(cls, url):
        """Use the real configuration's credential-free public HTTPS contract.

        A configured non-root path is the exact POST endpoint. No path is read
        from a source payload or changed by a redirect. Host listener setup must
        configure the same endpoint path explicitly.
        """
        from .config import ConfigError, _url
        try:
            _url(url, '$.deployment.manager.url')
            parsed = urlsplit(url)
            result = cls(parsed.hostname, parsed.port or 443,
                         DEFAULT_PATH if parsed.path in {'', '/'} else parsed.path)
            result.validate()
            return result
        except (ConfigError, ValueError):
            raise StreamError('INVALID_MANAGER_URL') from None


class RoomTLSClient:
    def __init__(self, identity, address, context):
        if type(identity) is not RoomIdentity or type(address) is not ManagerAddress:
            raise StreamError('FIXED_MANAGER_CONFIGURATION_REQUIRED')
        identity.document(); address.validate()
        if (type(context) is not ssl.SSLContext or context.protocol != ssl.PROTOCOL_TLS_CLIENT
                or context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname
                or context.minimum_version < ssl.TLSVersion.TLSv1_3):
            raise StreamError('MUTUAL_TLS_REQUIRED')
        self.identity, self.address, self.context = identity, address, context
        self._channel = None

    def close(self):
        if self._channel is not None:
            self._channel.close()
            self._channel = None

    def connect(self):
        self.close()
        if (self.context.verify_mode != ssl.CERT_REQUIRED or not self.context.check_hostname
                or self.context.minimum_version < ssl.TLSVersion.TLSv1_3):
            raise StreamError('MUTUAL_TLS_REQUIRED')
        channel = socket.create_connection((self.address.hostname, self.address.port), timeout=TIMEOUT)
        try:
            self._channel = self.context.wrap_socket(channel, server_hostname=self.address.hostname)
            self._channel.settimeout(TIMEOUT)
            return self.cursor()
        except BaseException:
            channel.close(); self.close()
            raise

    def cursor(self):
        reply = self._exchange({'kind': 'hello', 'identity': self.identity.document()})
        if (set(reply) != {'kind', 'identity', 'room_seq'} or reply['kind'] != 'cursor'
                or reply['identity'] != self.identity.document()):
            raise StreamError('INVALID_MANAGER_ACK')
        if reply['room_seq'] is not None:
            sequence(reply['room_seq'])
        return reply['room_seq']

    def _exchange(self, frame):
        if self._channel is None:
            raise StreamError('MANAGER_DISCONNECTED')
        host = '[' + self.address.hostname + ']' if ':' in self.address.hostname else self.address.hostname
        send_frame(self._channel, frame, path=self.address.path, host=host + ':' + str(self.address.port))
        return receive_frame(self._channel, response=True)

    def synchronize(self, transfer):
        """Send only a detached source cut and its bounded original event range.

        Lost final ACK is reconciled with hello/cursor on reconnect. No success
        is reported from a queued frame, an intermediate ACK, or TLS delivery.
        """
        if type(transfer) is not SnapshotTransfer or transfer.identity != self.identity:
            raise StreamError('TRANSFER_ROOM_MISMATCH')
        try:
            reply = self._exchange({'kind': 'begin', 'transfer': transfer.begin()})
            if reply != {'kind': 'begun', 'transfer_id': transfer.transfer_id}:
                raise StreamError('INVALID_MANAGER_ACK')
            cursor = transfer.after_seq
            while cursor is not None and cursor < transfer.cut:
                page = transfer.page(cursor)
                expected = page['events'][-1]['observed_version']
                reply = self._exchange({'kind': 'events', 'page': page})
                if (set(reply) != {'kind', 'transfer_id', 'room_seq'} or reply['kind'] != 'received'
                        or reply['transfer_id'] != transfer.transfer_id
                        or type(reply['room_seq']) is not int
                        or not expected <= reply['room_seq'] <= transfer.cut):
                    raise StreamError('INVALID_MANAGER_ACK')
                cursor = reply['room_seq']
            reply = self._exchange({'kind': 'finish', 'transfer_id': transfer.transfer_id})
            if reply != {'kind': 'committed', 'transfer_id': transfer.transfer_id, 'room_seq': transfer.cut}:
                raise StreamError('INVALID_MANAGER_ACK')
            return {'status': 'synchronized', 'room_seq': transfer.cut}
        except (OSError, StreamError, ProjectionError):
            self.close()
            # Bounded diagnostics only, not exception text or remote responses.
            return {'status': 'disconnected', 'room_seq': None, 'reason': 'MANAGER_TRANSFER_UNCONFIRMED'}


def export_once(source, client, *, captured_at):
    """One composed host-worker iteration; no background process or hidden retry.

    The host creates this worker's separate RoomLedger connection and fixed TLS
    client. Every source lock is released by capture() before synchronize()
    performs network I/O. Ordinary outage is an exporter result, not Hub stop.
    """
    from .ledger import LedgerError
    if (type(source) is not RoomStream or type(client) is not RoomTLSClient
            or source.identity != client.identity):
        raise StreamError('EXPORTER_ROOM_MISMATCH')
    try:
        cursor = client.connect() if client._channel is None else client.cursor()
        transfer = source.capture(cursor, captured_at=captured_at)
        return client.synchronize(transfer)
    except (LedgerError, ProjectionError):
        client.close()
        return {'status': 'source-unavailable', 'room_seq': None, 'reason': 'MANAGER_SOURCE_UNAVAILABLE'}
    except (OSError, StreamError):
        client.close()
        return {'status': 'disconnected', 'room_seq': None, 'reason': 'MANAGER_TRANSFER_UNCONFIRMED'}
