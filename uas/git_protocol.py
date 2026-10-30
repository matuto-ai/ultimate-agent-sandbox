"""Shared Git control codec and bounded blob receiver; no Broker or worker.

Callers still authenticate every record before decoding or receiving its blob.
"""
import base64
import hashlib
import json
import re

from .git_stream import MAX_DATA
from .kernel_origin import OriginDenied
from .typed_json import _json

MAX_BLOB = 1_048_576
_NAMES = {'source', 'source-proof', 'stdout', 'stderr', 'commit'}


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate manifest field")
        result[key] = value
    return result


def decode(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= 65536:
        raise OriginDenied('invalid Git control record')
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
        if type(value) is not dict: raise ValueError()
        return value
    except (ValueError, UnicodeError, RecursionError):
        raise OriginDenied('invalid Git control JSON') from None


def send(channel, value):
    raw = _json(value).encode()
    if len(raw) > 65536 or channel.send(raw) != len(raw):
        raise OriginDenied('incomplete Git control record')


class GitWorkerError(OriginDenied):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _fail(code='INVALID_GIT_WORKER_PROTOCOL'):
    raise GitWorkerError(code)


def receive_blob(name, recv_callback):
    """Shared with Supervisor controller; callback authenticates every record."""
    if type(name) is not str or name not in _NAMES or not callable(recv_callback):
        _fail('INVALID_GIT_WORKER_BLOB')
    header = recv_callback()
    if (type(header) is not dict or set(header) != {'kind', 'name', 'bytes', 'count', 'sha256'}
            or header['kind'] != 'blob' or header['name'] != name
            or type(header['bytes']) is not int or not 0 <= header['bytes'] <= MAX_BLOB
            or type(header['count']) is not int
            or header['count'] != max(1, (header['bytes'] + MAX_DATA - 1) // MAX_DATA)
            or type(header['sha256']) is not str or not re.fullmatch(r'[0-9a-f]{64}', header['sha256'])):
        _fail('INVALID_GIT_WORKER_BLOB')
    raw = bytearray()
    for index in range(header['count']):
        part = recv_callback()
        if (type(part) is not dict or set(part) != {'kind', 'name', 'index', 'data'}
                or part['kind'] != 'blob-part' or part['name'] != name
                or type(part['index']) is not int or part['index'] != index
                or type(part['data']) is not str or len(part['data']) > 43692):
            _fail('INVALID_GIT_WORKER_BLOB')
        try:
            block = base64.b64decode(part['data'], validate=True)
        except (ValueError, UnicodeError):
            _fail('INVALID_GIT_WORKER_BLOB')
        expected = min(MAX_DATA, header['bytes'] - index * MAX_DATA)
        if len(block) != expected or base64.b64encode(block).decode('ascii') != part['data']:
            _fail('INVALID_GIT_WORKER_BLOB')
        raw.extend(block)
    if len(raw) != header['bytes'] or hashlib.sha256(raw).hexdigest() != header['sha256']:
        _fail('INVALID_GIT_WORKER_BLOB')
    return bytes(raw)
