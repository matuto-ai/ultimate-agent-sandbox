"""Read-only evidence for the fixed Room SELinux negative; never admission.

Run only inside the disposable guest through the caller's bounded child runner.
No arguments, context selection, policy loading, relabeling or allow-rule repair.
libselinux's av_decision includes flags: it is not the kernel's five-field ABI.
"""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time

POLICY_PATH = Path('/sys/fs/selinux/policy')
POLICY_LIMIT = 64 * 1024 * 1024
ALPHA = 'system_u:system_r:container_t:s0:c101,c102'
BETA = 'system_u:system_r:container_t:s0:c103,c104'
PAIRS = (
    ('same_room_listener', ALPHA, ALPHA, 'unix_stream_socket', 'connectto'),
    ('foreign_room_listener', ALPHA, BETA, 'unix_stream_socket', 'connectto'),
    ('same_room_pathname', ALPHA, 'system_u:object_r:container_file_t:s0:c101,c102', 'sock_file', 'write'),
    ('foreign_room_pathname', ALPHA, 'system_u:object_r:container_file_t:s0:c103,c104', 'sock_file', 'write'),
)
RPM_ARGUMENTS = ('/usr/bin/rpm', '-q', '--queryformat',
                 '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n',
                 'selinux-policy', 'selinux-policy-targeted', 'container-selinux', 'libselinux')


class AVDecision(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in
                ('allowed', 'decided', 'auditallow', 'auditdeny', 'seqno', 'flags')]


def unavailable(error):
    return {'status': 'unavailable', 'error_type': type(error).__name__,
            'errno': error.errno if isinstance(error, OSError) else None}


def _output(data, count, limit):
    # Bound JSON-escaped text too: control/Unicode bytes must not inflate the
    # enclosing 64 KiB guest report and erase the original negative evidence.
    text = bytes(data).decode('utf-8', errors='replace')
    low, high = 0, len(text)
    while low < high:
        middle = (low + high + 1) // 2
        if len(json.dumps(text[:middle], ensure_ascii=True)) <= limit: low = middle
        else: high = middle - 1
    return {'output': text[:low], 'bytes': count,
            'truncated': count > len(data) or low < len(text)}


def _capture(arguments, *, timeout, limit):
    """Owned fixed child, bounded retained bytes and wall time; no shell."""
    result = {'returncode': None, 'timeout': False, 'timeout_seconds': timeout}
    buffers = {key: bytearray() for key in ('stdout', 'stderr')}
    counts = {key: 0 for key in buffers}
    process = selector = None
    reaped = False
    try:
        deadline = time.monotonic() + timeout
        process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        selector = selectors.DefaultSelector()
        for name in buffers:
            stream = getattr(process, name)
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise subprocess.TimeoutExpired(arguments, timeout)
            for key, _ in selector.select(min(1, remaining)):
                try: data = os.read(key.fileobj.fileno(), 65536)
                except BlockingIOError: continue
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                counts[key.data] += len(data)
                buffers[key.data].extend(data[:max(0, limit-len(buffers[key.data]))])
        remaining = deadline - time.monotonic()
        if remaining <= 0: raise subprocess.TimeoutExpired(arguments, timeout)
        result['returncode'] = process.wait(timeout=remaining)
        reaped = True
    except subprocess.TimeoutExpired:
        result['timeout'] = True
    except Exception as error:
        result.update(unavailable(error))
    finally:
        errors = []
        if process is not None and not reaped:
            # No poll/wait has released the owned leader identity on this path.
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            except Exception as error: errors.append(type(error).__name__)
            try: result['returncode'] = process.wait(timeout=5)
            except Exception as error: errors.append(type(error).__name__)
        resources = (selector,) if process is None else (selector, process.stdout, process.stderr)
        for resource in resources:
            if resource is not None:
                try: resource.close()
                except Exception as error: errors.append(type(error).__name__)
        result['cleanup_errors'] = errors
        for name in buffers:
            result[name] = _output(buffers[name], counts[name], limit)
    return result


def _decode(result):
    result['decoded'] = None
    if not result['stdout']['truncated']:
        try: result['decoded'] = json.loads(result['stdout']['output'])
        except (ValueError, TypeError): result['decode_error'] = 'invalid_json'
    else:
        result['decode_error'] = 'truncated_json'
    return result


def capture_endpoint_probe(container):
    if type(container) is not str or re.fullmatch('[0-9a-f]{64}', container) is None:
        raise ValueError('exact immutable container ID required')
    return _decode(_capture(('/usr/bin/docker', 'exec', container, '/usr/bin/python3', '-I',
                            '/opt/uas/uas/room_probe.py', 'endpoint'), timeout=8, limit=4096))


def capture_policy_diagnostic():
    return _decode(_capture(('/usr/bin/python3', '-I', str(Path(__file__).resolve())),
                            timeout=10, limit=8192))


def load_library():
    lib = ctypes.CDLL('libselinux.so.1', use_errno=True)
    for name in ('is_selinux_enabled', 'security_getenforce', 'security_policyvers'):
        function = getattr(lib, name)
        function.argtypes = (); function.restype = ctypes.c_int
    lib.string_to_security_class.argtypes = (ctypes.c_char_p,)
    lib.string_to_security_class.restype = ctypes.c_ushort
    lib.string_to_av_perm.argtypes = (ctypes.c_ushort, ctypes.c_char_p)
    lib.string_to_av_perm.restype = ctypes.c_uint32
    lib.security_compute_av_flags_raw.argtypes = (
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ushort, ctypes.c_uint32,
        ctypes.POINTER(AVDecision))
    lib.security_compute_av_flags_raw.restype = ctypes.c_int
    return lib


def policy_digest():
    """Bound actual loaded policy bytes, not an RPM payload's proposed policy."""
    digest, count = hashlib.sha256(), 0
    with POLICY_PATH.open('rb') as stream:
        while True:
            block = stream.read(min(65536, POLICY_LIMIT + 1 - count))
            if not block: break
            count += len(block)
            if count > POLICY_LIMIT: raise ValueError('loaded policy exceeds diagnostic bound')
            digest.update(block)
    if count == 0: raise ValueError('empty loaded policy')
    return {'status': 'observed', 'path': str(POLICY_PATH),
            'bytes': count, 'sha256': digest.hexdigest()}


def policy_state(lib):
    result = {}
    for key, name in (('enabled', 'is_selinux_enabled'),
                      ('enforcing', 'security_getenforce'),
                      ('kernel_max_policy_version', 'security_policyvers')):
        try:
            ctypes.set_errno(0)
            value = getattr(lib, name)()
            if value < 0: raise OSError(ctypes.get_errno(), 'SELinux observation failed')
            result[key] = value
        except Exception as error:
            result[key] = unavailable(error)
    try: result['loaded_policy'] = policy_digest()
    except Exception as error: result['loaded_policy'] = unavailable(error)
    return result


def fixed_decisions(lib):
    result = []
    for name, source, target, class_name, permission in PAIRS:
        item = {'name': name, 'source_context': source, 'target_context': target,
                'class': class_name, 'permission': permission}
        result.append(item)  # Preserve the exact attempted pair even on failure.
        try:
            class_id = lib.string_to_security_class(class_name.encode('ascii'))
            if class_id == 0: raise ValueError('unavailable SELinux class')
            requested = lib.string_to_av_perm(class_id, permission.encode('ascii'))
            if requested == 0: raise ValueError('unavailable SELinux permission')
            item.update(class_id=class_id, requested=requested)
            decision = AVDecision()
            ctypes.set_errno(0)
            code = lib.security_compute_av_flags_raw(
                source.encode('ascii'), target.encode('ascii'), class_id,
                requested, ctypes.byref(decision))
            item['returncode'] = code
            if code != 0: raise OSError(ctypes.get_errno(), 'SELinux decision unavailable')
            masks = {key: getattr(decision, key) for key, _ in AVDecision._fields_}
            covered = masks['decided'] & requested == requested
            item.update(status='observed', **masks, requested_fully_decided=covered,
                        requested_allowed=(masks['allowed'] & requested == requested) if covered else None,
                        permissive=bool(masks['flags'] & 1))
        except Exception as error:
            item.update(unavailable(error))
    return result


def installed_packages(capture):
    try:
        result = capture(RPM_ARGUMENTS, timeout=3, limit=2048)
        result['status'] = ('observed' if result.get('status') != 'unavailable'
                            and result['returncode'] == 0 and not result['timeout']
                            and not result['stdout']['truncated'] and not result['stderr']['truncated']
                            and not result['cleanup_errors'] else 'unavailable')
        return result
    except Exception as error:
        return unavailable(error)


def collect(*, lib=None, capture=None):
    """Diagnostic-only. Missing evidence never replaces the original probe."""
    result = {'version': 1, 'diagnostic_only': True, 'admission_decision': False}
    # Bound and retain the query's actual installed NEVRAs, not candidate RPMs.
    result['installed_packages'] = installed_packages(_capture if capture is None else capture)
    try:
        lib = load_library() if lib is None else lib
        result['before'] = policy_state(lib)
        result['decisions'] = fixed_decisions(lib)
        result['after'] = policy_state(lib)
        before, after = result['before'], result['after']
        decisions = result['decisions']
        comparable = (before['loaded_policy']['status'] == after['loaded_policy']['status'] == 'observed'
                      and all(item.get('status') == 'observed' for item in decisions)
                      and all(type(before[key]) is int and type(after[key]) is int
                              for key in ('enabled', 'enforcing', 'kernel_max_policy_version')))
        result['snapshot_consistent'] = (
            before == after and len({item['seqno'] for item in decisions}) == 1
            if comparable else None)
    except Exception as error:
        result['library'] = unavailable(error)
        result['snapshot_consistent'] = None
    return result


def main():
    if len(sys.argv) != 1: raise ValueError('fixed diagnostic accepts no arguments')
    result = collect()
    print(json.dumps(result, sort_keys=True, separators=(',', ':')), flush=True)


if __name__ == '__main__':
    main()
