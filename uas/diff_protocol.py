"""Fixed base/head diff source profile; bounded raw facts, never Gate verdicts."""
from copy import deepcopy
import hashlib
import re
import struct

from .ledger import LedgerError
from .artifact_protocol import (ArtifactError, SOURCE_KEYS, MAX_ITEMS, MAX_OUTPUT_BYTES,
    canonical, validate_path, validate_scope, validate_source, validate_target)

PROFILE_ID = 'diff-claims-v1-source'
SOURCE_FIELDS = SOURCE_KEYS | {'profile', 'subject', 'binding_digest'}
TARGET_FIELDS = {'version', 'profile', 'source_digest', 'subject', 'base', 'head'}
_HEX64 = re.compile(r'[0-9a-f]{64}\Z')


def artifact_source(source):
    return {key: source[key] for key in SOURCE_KEYS}


def source_binding(source, subject):
    return hashlib.sha256(canonical({'profile': PROFILE_ID,
        'source': source, 'subject': subject})).hexdigest()


def validate_diff_source(value, *, require_head=False):
    from .gate_forge import validate_forge_target
    try:
        if type(value) is not dict or set(value) != SOURCE_FIELDS or value['profile'] != PROFILE_ID:
            raise ValueError()
        source = validate_source(artifact_source(value))
        subject = validate_forge_target(value['subject'])
        if (subject['repository'] != source['repository']
                or value['binding_digest'] != source_binding(source, subject)
                or require_head and source['head_sha'] != subject['head_sha']):
            raise ValueError()
        return deepcopy(value)
    except (ValueError, TypeError, KeyError, LedgerError) as error:
        raise ArtifactError('INVALID_DIFF_SOURCE') from error


def validate_diff_target(value):
    from .gate_forge import validate_forge_target
    try:
        if (type(value) is not dict or set(value) != TARGET_FIELDS
                or type(value['version']) is not int or value['version'] != 1
                or value['profile'] != PROFILE_ID
                or type(value['source_digest']) is not str or not _HEX64.fullmatch(value['source_digest'])):
            raise ValueError()
        subject = validate_forge_target(value['subject'])
        base, head = validate_target(value['base']), validate_target(value['head'])
        if (base['head_sha'] != subject['base_sha'] or head['head_sha'] != subject['head_sha']
                or base['source_digest'] != head['source_digest']
                or base['target_id'] == head['target_id']
                or (base['device'], base['inode']) == (head['device'], head['inode'])):
            raise ValueError()
        return deepcopy(value)
    except (ValueError, TypeError, KeyError, LedgerError) as error:
        raise ArtifactError('INVALID_DIFF_TARGET') from error


def diff_correlation(scope, target, config):
    from .gate_repository import compile_repository_config
    validate_scope(scope); validate_diff_target(target)
    config = compile_repository_config('diff-claims', config, 'diff-claims')
    return hashlib.sha256(canonical({'profile': PROFILE_ID, 'scope': scope,
                                    'target': target, 'config': config})).hexdigest()


def diff_request(scope, target, config):
    correlation = bytes.fromhex(diff_correlation(scope, target, config))
    return struct.pack('!4s32sQQQQ', b'DGQ1', correlation,
        target['base']['device'], target['base']['inode'],
        target['head']['device'], target['head']['inode'])


def diff_observation(packet, correlation):
    if (type(packet) is not bytes or not 0 < len(packet) <= 16384
            or type(correlation) is not str or not _HEX64.fullmatch(correlation)):
        raise ArtifactError('INVALID_DIFF_OBSERVATION')
    if len(packet) == 36 and packet[:4] == b'DGS1':
        if packet[4:].hex() != correlation:
            raise ArtifactError('DIFF_CORRELATION_MISMATCH')
        return {'kind': 'header', 'correlation': correlation}
    if len(packet) == 40 and packet[:4] == b'DGF1':
        if packet[4:36].hex() != correlation:
            raise ArtifactError('DIFF_CORRELATION_MISMATCH')
        count = struct.unpack('!I', packet[36:])[0]
        if count > MAX_ITEMS:
            raise ArtifactError('DIFF_OUTPUT_LIMIT')
        return {'kind': 'final', 'correlation': correlation, 'count': count}
    if len(packet) >= 13 and packet[:4] == b'DGP1':
        index, length = struct.unpack('!II', packet[4:12])
        if index >= MAX_ITEMS or length != len(packet) - 12:
            raise ArtifactError('INVALID_DIFF_OBSERVATION')
        try:
            path = packet[12:].decode('utf-8', errors='strict')
            validate_path(path)
        except (UnicodeError, ArtifactError) as error:
            raise ArtifactError('INVALID_DIFF_OBSERVATION') from error
        return {'kind': 'path', 'index': index, 'path': path}
    raise ArtifactError('INVALID_DIFF_OBSERVATION')


def diff_final_ack(correlation):
    if type(correlation) is not str or not _HEX64.fullmatch(correlation):
        raise ArtifactError('INVALID_DIFF_CORRELATION')
    return b'DGA1' + bytes.fromhex(correlation)
