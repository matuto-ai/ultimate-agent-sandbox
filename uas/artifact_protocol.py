"""Artifacts-only v1 source profile and bounded raw-observation wire format.

Not a qualification or a verdict API. The scope digest authenticates correlation,
not filesystem content: the Supervisor independently reconstructs the full tree.
"""
import hashlib
import json
import re
import struct

PROFILE_ID = 'artifacts-v1-source'
HELPER_UID = HELPER_GID = 65530
MAX_ITEMS = 128
MAX_PATH_BYTES = 4095
MAX_PACKET = 16384
MAX_REQUEST_BYTES = 1 << 20
MAX_OUTPUT_BYTES = 128 << 10
MAX_OBJECT_BYTES = 16 << 20
MAX_TARGET_BYTES = 8 << 20
MAX_METADATA_BYTES = 8 << 20
RESERVATION_BYTES = MAX_OBJECT_BYTES + MAX_TARGET_BYTES + MAX_METADATA_BYTES
MAX_BLOB_BYTES = 4 << 20
MAX_ENTRIES = 512
MAX_DEPTH = 32
SCOPE_KEYS = {'version', 'evaluation_id', 'room_id', 'room_instance', 'project_id',
              'repository', 'run_id', 'generation', 'participant_id', 'policy_id',
              'policy_version', 'policy_digest', 'gate_id', 'config_digest'}
TARGET_KEYS = {'target_id', 'head_sha', 'tree_sha', 'manifest_sha256', 'source_digest',
               'device', 'inode', 'entries', 'expanded_bytes'}
SOURCE_KEYS = {'room_instance', 'project_id', 'repository', 'run_id', 'participant_id',
               'slot_id', 'branch', 'head_sha', 'source_digest'}
_HEADER = struct.Struct('!4s32s16s32sQQI')
_ITEM = struct.Struct('!4sI32sIQII')
_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')
_HEX = re.compile(r'[0-9a-f]+\Z')


class ArtifactError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def _hex(value, length):
    return type(value) is str and len(value) == length and _HEX.fullmatch(value)


def validate_scope(scope):
    if type(scope) is not dict or set(scope) != SCOPE_KEYS:
        raise ArtifactError('INVALID_ARTIFACT_SCOPE')
    for key in SCOPE_KEYS - {'version', 'generation', 'policy_version', 'repository', 'policy_digest', 'config_digest'}:
        if type(scope[key]) is not str or not _ID.fullmatch(scope[key]):
            raise ArtifactError('INVALID_ARTIFACT_SCOPE')
    if (type(scope['version']) is not int or scope['version'] != 1
            or any(type(scope[k]) is not int or not 1 <= scope[k] < 2**53
                   for k in ('generation', 'policy_version'))
            or any(not _hex(scope[k], 64) for k in ('policy_digest', 'config_digest'))
            or type(scope['repository']) is not str or not re.fullmatch(
                r'[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}', scope['repository'])):
        raise ArtifactError('INVALID_ARTIFACT_SCOPE')
    return dict(scope)


def validate_target(target):
    if (type(target) is not dict or set(target) != TARGET_KEYS
            or not _hex(target.get('target_id'), 32)
            or any(not _hex(target[k], 40) for k in ('head_sha', 'tree_sha'))
            or any(not _hex(target[k], 64) for k in ('manifest_sha256', 'source_digest'))
            or any(type(target[k]) is not int or not 0 <= target[k] < 2**64
                   for k in ('device', 'inode', 'entries', 'expanded_bytes'))
            or target['entries'] > MAX_ENTRIES or target['expanded_bytes'] > MAX_TARGET_BYTES):
        raise ArtifactError('INVALID_ARTIFACT_TARGET')
    return dict(target)


def validate_path(path):
    if type(path) is not str or not 1 <= len(path) <= 1024:
        raise ArtifactError('INVALID_ARTIFACT_PATH')
    try:
        raw = path.encode('utf-8', errors='strict')
    except UnicodeError as error:
        raise ArtifactError('INVALID_ARTIFACT_PATH') from error
    parts = path.split('/')
    if (len(raw) > MAX_PATH_BYTES or len(parts) > MAX_DEPTH
            or any(p in ('', '.', '..') or p.lower() == '.git' or len(p.encode()) > 255 for p in parts)
            or any(c in path for c in '\\*?[]')
            or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in path)):
        raise ArtifactError('INVALID_ARTIFACT_PATH')
    return raw


def validate_paths(paths):
    if type(paths) not in (tuple, list) or not 1 <= len(paths) <= MAX_ITEMS:
        raise ArtifactError('INVALID_ARTIFACT_PATHS')
    encoded = tuple(validate_path(p) for p in paths)
    if len(set(encoded)) != len(encoded):
        raise ArtifactError('DUPLICATE_ARTIFACT_PATH')
    return encoded


def scope_digest(scope, target):
    return profile_scope_digest(PROFILE_ID, scope, target)


def profile_scope_digest(profile, scope, target):
    if profile not in ('artifacts-v1-source', 'command-v1-source', 'diff-claims-v1-source'):
        raise ArtifactError('UNSUPPORTED_GATE_PROFILE')
    validate_scope(scope)
    if profile == 'command-v1-source':
        from .gate_repository import validate_command_target
        validate_command_target(target)
    elif profile == 'diff-claims-v1-source':
        from .diff_protocol import validate_diff_target
        validate_diff_target(target)
    else:
        validate_target(target)
    return hashlib.sha256(canonical({'profile': profile, 'scope': scope, 'target': target})).hexdigest()


def expected_header(scope, target, paths, *, kind='header'):
    validate_paths(paths)
    return {'kind': kind, 'scope_digest': scope_digest(scope, target),
            'target_id': target['target_id'], 'manifest_sha256': target['manifest_sha256'],
            'device': target['device'], 'inode': target['inode'], 'count': len(paths)}


def encode_request(scope, target, paths):
    encoded = validate_paths(paths)
    digest = bytes.fromhex(scope_digest(scope, target))
    packets = (_HEADER.pack(b'AGQ1', digest, bytes.fromhex(target['target_id']),
        bytes.fromhex(target['manifest_sha256']), target['device'], target['inode'], len(paths)),) + tuple(
        struct.pack('!4sII', b'AGP1', i, len(raw)) + raw for i, raw in enumerate(encoded))
    if sum(map(len, packets)) > MAX_REQUEST_BYTES:
        raise ArtifactError('ARTIFACT_REQUEST_LIMIT')
    return packets


def decode_record(packet):
    if type(packet) is not bytes or len(packet) > MAX_PACKET:
        raise ArtifactError('INVALID_ARTIFACT_RECORD')
    if len(packet) == _HEADER.size and packet[:4] in (b'AGS1', b'AGF1'):
        tag, digest, target, manifest, device, inode, count = _HEADER.unpack(packet)
        if not 1 <= count <= MAX_ITEMS:
            raise ArtifactError('INVALID_ARTIFACT_RECORD')
        return {'kind': 'header' if tag == b'AGS1' else 'final',
                'scope_digest': digest.hex(), 'target_id': target.hex(),
                'manifest_sha256': manifest.hex(), 'device': device, 'inode': inode, 'count': count}
    if len(packet) == _ITEM.size and packet[:4] == b'AGI1':
        _, index, digest, kind, length, nonempty, error = _ITEM.unpack(packet)
        if index >= MAX_ITEMS or kind not in (1, 2, 3, 4) or nonempty not in (0, 1):
            raise ArtifactError('INVALID_ARTIFACT_RECORD')
        name = {1: 'file', 2: 'directory', 3: 'missing', 4: 'error'}[kind]
        if ((name != 'file' and length != 0) or (name != 'directory' and nonempty != 0)
                or (name != 'error' and error != 0) or (name == 'error' and not 1 <= error <= 4095)
                or length > MAX_BLOB_BYTES):
            raise ArtifactError('INVALID_ARTIFACT_RECORD')
        return {'kind': 'item', 'index': index, 'path_digest': digest.hex(),
                'observed_type': name, 'length': length, 'nonempty': bool(nonempty), 'error': error}
    raise ArtifactError('INVALID_ARTIFACT_RECORD')


def decode_observation(packet, scope, target, paths):
    value = decode_record(packet)
    if value['kind'] in ('header', 'final'):
        if value != expected_header(scope, target, paths, kind=value['kind']):
            raise ArtifactError('ARTIFACT_CORRELATION_MISMATCH')
    elif (value['index'] >= len(paths) or value['path_digest'] !=
          hashlib.sha256(validate_path(paths[value['index']])).hexdigest()):
        raise ArtifactError('ARTIFACT_CORRELATION_MISMATCH')
    return value


def encode_final_ack(scope, target):
    return b'AGA1' + bytes.fromhex(scope_digest(scope, target))


def validate_source(source):
    if (type(source) is not dict or set(source) != SOURCE_KEYS
            or any(type(source[k]) is not str or not _ID.fullmatch(source[k]) for k in
                   ('room_instance', 'project_id', 'run_id', 'participant_id', 'slot_id'))
            or type(source['repository']) is not str or not re.fullmatch(
                r'[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}', source['repository'])
            or type(source['branch']) is not str or not re.fullmatch(
                r'refs/heads/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*', source['branch'])
            or len(source['branch']) > 512
            or not _hex(source['head_sha'], 40) or not _hex(source['source_digest'], 64)):
        raise ArtifactError('INVALID_ARTIFACT_SOURCE')
    return dict(source)


def path_digest(path):
    return hashlib.sha256(validate_path(path)).hexdigest()
