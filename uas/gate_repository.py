"""Bounded repository Gate definitions and raw one-shot wire contracts.

This module performs no I/O and grants no execution authority. The command
profile owns a bounded nonescaping child tree, never a shell interface.
Only the separately admitted static command helper may consume its request.
"""
from copy import deepcopy
import hashlib
import re
import struct

from .artifact_protocol import ArtifactError, TARGET_KEYS, canonical, validate_path, validate_scope, validate_target

COMMAND_PROFILE_ID = 'command-v1-source'
DIFF_PROFILE_ID = 'diff-claims-v1-source'
MAX_ARGV = 32
MAX_ARGUMENT_BYTES = 1024
MAX_CONFIG_BYTES = 8192
MAX_COMMAND_SECONDS = 10
MAX_STREAM_BYTES = 1 << 20
TAIL_BYTES = 16 << 10
WORK_BYTES = 8 << 20
_ENVIRONMENT = {'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC', 'PYTHONDONTWRITEBYTECODE': '1'}
_HEX64 = re.compile(r'[0-9a-f]{64}\Z')
_SHELLS = frozenset(('sh', 'bash', 'dash', 'zsh', 'ksh', 'csh', 'tcsh', 'fish', 'busybox', 'env'))


def validate_command_target(value):
    if type(value) is not dict or set(value) != TARGET_KEYS | {'work'}:
        raise ArtifactError('INVALID_COMMAND_TARGET')
    validate_target({key: value[key] for key in TARGET_KEYS})
    work = value['work']
    if (type(work) is not dict or set(work) != {'device', 'inode', 'limit_bytes'}
            or any(type(work[key]) is not int or not 0 < work[key] < 2**64 for key in ('device', 'inode'))
            or type(work['limit_bytes']) is not int or work['limit_bytes'] != WORK_BYTES
            or (work['device'], work['inode']) == (value['device'], value['inode'])):
        raise ArtifactError('INVALID_COMMAND_TARGET')
    return deepcopy(value)


def compile_repository_config(evaluator, value, field):
    from .config import ConfigError
    def reject(detail):
        raise ConfigError(field, detail)
    config = deepcopy(value)
    if type(config) is not dict:
        reject('expected object')
    if evaluator == 'command':
        config.setdefault('executables', [])
        if set(config) != {'argv', 'cwd', 'timeout_seconds', 'environment', 'process_limit', 'memory_bytes', 'output_bytes', 'executable_sha256', 'executables'}:
            reject('command requires exact argv, cwd, timeout, environment, processes and executable digest')
        argv = config['argv']
        if type(argv) is not list or not 1 <= len(argv) <= MAX_ARGV:
            reject('command argv must contain 1..32 exact arguments')
        for argument in argv:
            if type(argument) is not str or '\x00' in argument:
                reject('command arguments must be NUL-free text')
            try:
                if len(argument.encode('utf-8')) > MAX_ARGUMENT_BYTES:
                    reject('command argument exceeds 1024 UTF-8 bytes')
            except UnicodeError:
                reject('command argument must be valid UTF-8')
        executable = argv[0]
        if (not executable.startswith('/usr/bin/') or '/' in executable[len('/usr/bin/'):]
                or executable.rsplit('/', 1)[-1] in _SHELLS
                or not re.fullmatch(r'/usr/bin/[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}', executable)):
            reject('command executable must be a fixed non-shell /usr/bin program')
        if type(config['executable_sha256']) is not str or not _HEX64.fullmatch(config['executable_sha256']):
            reject('command requires the provisioned executable SHA-256')
        try:
            if config['cwd'] != '.':
                validate_path(config['cwd'])
        except ArtifactError:
            reject('command cwd must be a literal target-relative directory')
        if type(config['timeout_seconds']) is not int or not 1 <= config['timeout_seconds'] <= MAX_COMMAND_SECONDS:
            reject('command timeout must be 1..10 seconds')
        if type(config['process_limit']) is not int or not 1 <= config['process_limit'] <= 32:
            reject('command process limit must be 1..32')
        if type(config['memory_bytes']) is not int or not 64 << 20 <= config['memory_bytes'] <= 128 << 20:
            reject('command per-process address-space limit must be 64..128 MiB')
        if type(config['output_bytes']) is not int or not 1024 <= config['output_bytes'] <= MAX_STREAM_BYTES:
            reject('command per-stream output limit must be 1024..1048576 bytes')
        if (type(config['environment']) is not dict
                or any(key not in _ENVIRONMENT or value != _ENVIRONMENT[key]
                       for key, value in config['environment'].items())):
            reject('command environment supports only the fixed bounded locale/time/Python-bytecode values')
        config['environment'] = dict(sorted(config['environment'].items()))
        dependencies = config['executables']
        if type(dependencies) is not list or len(dependencies) > 8:
            reject('command supports at most eight pinned child executables')
        seen = {executable}
        for dependency in dependencies:
            if (type(dependency) is not dict or set(dependency) != {'path', 'sha256'}
                    or type(dependency['path']) is not str
                    or not re.fullmatch(r'/usr/bin/[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}', dependency['path'])
                    or dependency['path'].rsplit('/', 1)[-1] in _SHELLS
                    or dependency['path'] in seen
                    or type(dependency['sha256']) is not str or not _HEX64.fullmatch(dependency['sha256'])):
                reject('child executables require distinct immutable non-shell paths and SHA-256 digests')
            seen.add(dependency['path'])
        config['executables'] = sorted(dependencies, key=lambda item: item['path'])
    elif evaluator == 'diff-claims':
        if set(config) != {'allowed_paths', 'forbidden_paths', 'require_nonempty'}:
            reject('diff-claims requires allowed paths, forbidden paths and nonempty rule')
        for key in ('allowed_paths', 'forbidden_paths'):
            paths = config[key]
            if type(paths) is not list or len(paths) > 128:
                reject('diff path constraints must be bounded lists')
            try:
                for path in paths:
                    validate_path(path)
            except ArtifactError:
                reject('diff constraints must be literal target-relative paths')
            if len(set(paths)) != len(paths):
                reject('duplicate diff path constraint')
            config[key] = sorted(paths)
        if type(config['require_nonempty']) is not bool:
            reject('diff nonempty rule must be boolean')
    else:
        reject('unsupported repository evaluator')
    if len(canonical(config)) > MAX_CONFIG_BYTES:
        reject('repository evaluator configuration exceeds 8192 bytes')
    return config


def command_request(scope, target, config):
    """One bounded binary request. Its digest covers the complete typed config."""
    validate_scope(scope); validate_command_target(target)
    config = compile_repository_config('command', config, 'command')
    digest = hashlib.sha256(canonical({'profile': COMMAND_PROFILE_ID, 'scope': scope,
                                     'target': target, 'config': config})).digest()
    argv = [value.encode() for value in config['argv']]
    environment = [(key + '=' + value).encode() for key, value in config['environment'].items()]
    cwd = config['cwd'].encode()
    payload = struct.pack('!4s32s32sIIIIIIII', b'CGQ1', digest,
        bytes.fromhex(config['executable_sha256']), config['timeout_seconds'], len(argv), len(environment), len(cwd),
        config['process_limit'], config['memory_bytes'], config['output_bytes'], len(config['executables']))
    payload += struct.pack('!QQQQQ', target['work']['device'], target['work']['inode'], target['work']['limit_bytes'],
                           target['device'], target['inode'])
    payload += cwd
    for item in argv + environment:
        payload += struct.pack('!I', len(item)) + item
    for item in config['executables']:
        path = item['path'].encode()
        payload += struct.pack('!I', len(path)) + path + bytes.fromhex(item['sha256'])
    if len(payload) > MAX_CONFIG_BYTES + 1024:
        raise ArtifactError('COMMAND_REQUEST_LIMIT')
    return payload


def command_correlation(scope, target, config):
    return command_request(scope, target, config)[4:36].hex()


def command_observation(packet, correlation):
    """Strict facts only; neither this decoder nor the helper returns a verdict."""
    if type(packet) is not bytes or len(packet) > 16384 or not _HEX64.fullmatch(correlation):
        raise ArtifactError('INVALID_COMMAND_OBSERVATION')
    if len(packet) == 36 and packet[:4] in (b'CGS1', b'CGF1'):
        if packet[4:].hex() != correlation:
            raise ArtifactError('COMMAND_CORRELATION_MISMATCH')
        return {'kind': 'header' if packet[:4] == b'CGS1' else 'final', 'correlation': correlation}
    if len(packet) == 56 and packet[:4] == b'CGR1':
        _, index, count, digest, length, truncated = struct.unpack('!4sIQ32sII', packet)
        if index not in (0, 1) or count > MAX_STREAM_BYTES + 131072 or length != min(count, TAIL_BYTES) or truncated != int(count > TAIL_BYTES):
            raise ArtifactError('INVALID_COMMAND_OBSERVATION')
        return {'kind': 'stream', 'stream': 'stdout' if index == 0 else 'stderr',
                'bytes': count, 'sha256': digest.hex(), 'tail_bytes': length, 'truncated': bool(truncated)}
    if len(packet) >= 12 and packet[:4] == b'CGT1':
        _, index, offset = struct.unpack('!4sII', packet[:12])
        if index not in (0, 1) or offset not in (0, 8192) or len(packet) > 8204 or offset + len(packet) - 12 > TAIL_BYTES:
            raise ArtifactError('INVALID_COMMAND_OBSERVATION')
        return {'kind': 'tail', 'stream': 'stdout' if index == 0 else 'stderr',
                'offset': offset, 'bytes_hex': packet[12:].hex()}
    if len(packet) == 72 and packet[:4] == b'CGE1':
        _, code, signal, timeout, limited, duration, executable, empty, descendants, work_cleaned = struct.unpack('!4siIIIQ32sIII', packet)
        if (code < -1 or code > 255 or signal > 64 or timeout not in (0, 1) or limited not in (0, 1)
                or empty != 1 or work_cleaned != 1 or descendants not in (0, 1) or duration > 15000 or (code == -1) != (signal != 0)):
            raise ArtifactError('INVALID_COMMAND_OBSERVATION')
        return {'kind': 'exit', 'exit_code': None if code == -1 else code, 'signal': signal,
                'timed_out': bool(timeout), 'output_limited': bool(limited),
                'duration_ms': duration, 'executable_sha256': executable.hex(),
                'whole_tree_exited': True, 'descendants_terminated': bool(descendants), 'work_cleaned': True}
    raise ArtifactError('INVALID_COMMAND_OBSERVATION')


def command_observations(records, scope, target, config):
    """Reduce a complete raw stream, without constructing Checks or verdicts."""
    config = compile_repository_config('command', config, 'command')
    correlation = command_correlation(scope, target, config)
    if type(records) is not list or not 5 <= len(records) <= 9:
        raise ArtifactError('COMMAND_INCOMPLETE_OBSERVATIONS')
    if records[0] != {'kind': 'header', 'correlation': correlation} or records[-1] != {'kind': 'final', 'correlation': correlation}:
        raise ArtifactError('COMMAND_CORRELATION_MISMATCH')
    position, result = 1, {}
    for name in ('stdout', 'stderr'):
        record = records[position]; position += 1
        if (type(record) is not dict or set(record) != {'kind', 'stream', 'bytes', 'sha256', 'tail_bytes', 'truncated'}
                or record['kind'] != 'stream' or record['stream'] != name
                or type(record['bytes']) is not int or not 0 <= record['bytes'] <= MAX_STREAM_BYTES + 131072
                or type(record['sha256']) is not str or not _HEX64.fullmatch(record['sha256'])
                or type(record['tail_bytes']) is not int or record['tail_bytes'] != min(record['bytes'], TAIL_BYTES)
                or type(record['truncated']) is not bool or record['truncated'] != (record['bytes'] > TAIL_BYTES)):
            raise ArtifactError('INVALID_COMMAND_OBSERVATION')
        tail = bytearray()
        while len(tail) < record['tail_bytes']:
            if position >= len(records) - 2:
                raise ArtifactError('COMMAND_INCOMPLETE_OBSERVATIONS')
            chunk = records[position]; position += 1
            if (type(chunk) is not dict or set(chunk) != {'kind', 'stream', 'offset', 'bytes_hex'}
                    or chunk['kind'] != 'tail' or chunk['stream'] != name
                    or type(chunk['offset']) is not int or chunk['offset'] != len(tail)
                    or type(chunk['bytes_hex']) is not str
                    or not re.fullmatch(r'(?:[0-9a-f]{2}){1,8192}', chunk['bytes_hex'])):
                raise ArtifactError('INVALID_COMMAND_OBSERVATION')
            value = bytes.fromhex(chunk['bytes_hex'])
            if len(value) != min(8192, record['tail_bytes'] - len(tail)):
                raise ArtifactError('INVALID_COMMAND_OBSERVATION')
            tail.extend(value)
        if record['bytes'] <= TAIL_BYTES and hashlib.sha256(tail).hexdigest() != record['sha256']:
            raise ArtifactError('COMMAND_STREAM_HASH_MISMATCH')
        result[name] = {key: record[key] for key in ('bytes', 'sha256', 'truncated')}
        result[name]['tail_hex'] = bytes(tail).hex()
    if position != len(records) - 2:
        raise ArtifactError('COMMAND_RECORD_ORDER')
    terminal = records[position]
    expected = {'kind', 'exit_code', 'signal', 'timed_out', 'output_limited', 'duration_ms',
                'executable_sha256', 'whole_tree_exited', 'descendants_terminated', 'work_cleaned'}
    if (type(terminal) is not dict or set(terminal) != expected or terminal['kind'] != 'exit'
            or not (terminal['exit_code'] is None or type(terminal['exit_code']) is int and 0 <= terminal['exit_code'] <= 255)
            or type(terminal['signal']) is not int or not 0 <= terminal['signal'] <= 64
            or (terminal['exit_code'] is None) != (terminal['signal'] != 0)
            or any(type(terminal[key]) is not bool for key in ('timed_out', 'output_limited', 'whole_tree_exited', 'descendants_terminated', 'work_cleaned'))
            or terminal['work_cleaned'] is not True or terminal['whole_tree_exited'] is not True or terminal['executable_sha256'] != config['executable_sha256']
            or type(terminal['duration_ms']) is not int or not 0 <= terminal['duration_ms'] <= 15000
            or terminal['timed_out'] and terminal['duration_ms'] < config['timeout_seconds'] * 1000
            or terminal['output_limited'] != any(result[name]['bytes'] > config['output_bytes'] for name in ('stdout', 'stderr'))):
        raise ArtifactError('INVALID_COMMAND_OBSERVATION')
    result['exit'] = {key: value for key, value in terminal.items() if key != 'kind'}
    return result, deepcopy(records[-1])
