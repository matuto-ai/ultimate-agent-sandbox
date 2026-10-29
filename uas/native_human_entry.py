"""Fixed final-process human TLS entry for the opt-in native qualification.

Only raw stream and protected operator-manifest FDs cross exec. TLS state and
HumanSession are created here after original Room observation; startup JSON is
correlation data, never a serialized principal or authentication success.
"""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import socket
import stat
import sys
import time

from .manager_transport import server_tls_context
from .native_human_control import NativeHumanControl
from .native_human_launch import HOST_UID, _identity, host_bindings, raw_stream_identity
from .native_pi_recipe import path, unique
from .native_qualification import QualificationPlan, QualificationError


def _require(condition, code):
    if not condition: raise QualificationError(code)


def _remaining(deadline, ceiling=5):
    left = deadline - time.monotonic()
    _require(0 < left <= 180, 'NATIVE_HUMAN_ORIGINAL_DEADLINE_REQUIRED')
    return min(ceiling, left)


def _tls_reference(filename, *, private, stack):
    """Hold existing nofollow trusted references, never copy/read key contents."""
    filename = Path(path(filename))
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in filename.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=directory)
            os.close(directory); directory = child
            node = os.fstat(directory)
            _require(node.st_uid in (0, HOST_UID) and not node.st_mode & 0o022,
                     'NATIVE_HUMAN_TLS_REFERENCE_UNAVAILABLE')
        fd = os.open(filename.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=directory)
    finally:
        os.close(directory)
    stack.callback(os.close, fd)
    node = os.fstat(fd)
    _require(stat.S_ISREG(node.st_mode) and node.st_uid in (0, HOST_UID) and node.st_nlink == 1
        and 0 < node.st_size <= 1048576 and not node.st_mode & (0o077 if private else 0o022),
        'NATIVE_HUMAN_TLS_REFERENCE_UNAVAILABLE')
    return fd, _identity(node)


def _context(references):
    # SSL reads the original held descriptors. No credential bytes enter Python
    # data/results, no filename is selected by an incoming human frame.
    with ExitStack() as stack:
        held = {key: _tls_reference(filename, private=key == 'private_key_file', stack=stack)
                for key, filename in references.items()}
        context = server_tls_context(**{key: '/proc/self/fd/' + str(item[0]) for key, item in held.items()})
        for fd, identity in held.values():
            _require(_identity(os.fstat(fd)) == identity, 'NATIVE_HUMAN_TLS_REFERENCE_CHANGED')
        return context


def host(plan, resources, broker_fd, checkout_fd, git_fd=None, *, selection):
    """Actual retained TLS → HumanSession → existing native Run/Manager owners."""
    from .native_qualification_backend import readonly_supervisor
    from .native_run_admission import NativeHumanRunRequest
    from .native_session import run
    _require((os.getuid(), os.getgid()) == (HOST_UID, HOST_UID), 'TRUSTED_NATIVE_SUPERVISOR_REQUIRED')
    _require(type(plan) is QualificationPlan and type(resources) is dict and type(selection) is dict,
             'NATIVE_HUMAN_LAUNCH_CUSTODY_REQUIRED')
    # Uses the real retained lifecycle state and exact original config/instance,
    # before constructing any human grant. A JSON instance alone is insufficient.
    readonly_supervisor(plan, resources)
    bindings, references = host_bindings(plan, resources, selection)
    descriptors = [broker_fd, checkout_fd, selection['grant_fd'], selection['raw_fd']]
    if git_fd is not None: descriptors.append(git_fd)
    _require(all(type(fd) is int and fd >= 3 for fd in descriptors)
        and len(set(descriptors)) == len(descriptors), 'NATIVE_HUMAN_DISTINCT_CHANNELS_REQUIRED')
    deadline = selection['deadline']
    with ExitStack() as stack:
        stack.callback(os.close, selection['grant_fd'])
        raw = socket.socket(fileno=selection['raw_fd'])
        stack.callback(raw.close)
        observed = json.loads(json.dumps(raw_stream_identity(raw)))
        _require(observed == selection['raw_identity'], 'NATIVE_HUMAN_RAW_STREAM_CHANGED')
        context = _context(references)
        raw.settimeout(_remaining(deadline))
        secure = context.wrap_socket(raw, server_side=True)
        # No SSL state existed in the parent or survives a reconnect. Until the
        # control takes sole transport custody, this thread owns secure cleanup.
        try:
            control = NativeHumanControl(bindings, secure, instance_id=resources['instance'], deadline=deadline)
        except BaseException:
            secure.close()
            raise
        stack.callback(control.close)
        control.start()
        first = None
        while first is None:
            _remaining(deadline)
            first = control.first_request()
            if first is None: time.sleep(.01)
        request = NativeHumanRunRequest(first.operation_id, first.issue_number,
            plan.seats['pi']['participant'], control.session)
        result = run(plan, resources, broker_fd, checkout_fd, git_fd,
                     human_request=request, human_control=control)
        _require(type(result) is dict and result.get('status') == 'NATIVE_RUN_SESSION_FINISHED',
                 'NATIVE_HUMAN_RESULT_INVALID')
        return {**result, 'human_host_manifest_sha256': plan.installation['human_host_manifest']['sha256'],
                'human_request': {'operation_id': request.operation_id, 'issue_number': request.issue_number,
                                  'participant_id': request.participant_id}}


def main():
    _require(len(sys.argv) in (3, 4) and all(value.isdigit() and int(value) >= 3 for value in sys.argv[1:]),
             'INHERITED_BROKER_CHANNEL_REQUIRED')
    raw = sys.stdin.buffer.read(2 * 1048576 + 1)
    _require(len(raw) <= 2 * 1048576, 'BOUNDED_TRUSTED_STARTUP_REQUIRED')
    value = json.loads(raw, object_pairs_hook=unique)
    _require(type(value) is dict and set(value) == {'configuration', 'installation', 'installation_digest',
                                                 'resources', 'human_host'}, 'INVALID_TRUSTED_STARTUP')
    plan = QualificationPlan(value['configuration'], value['installation'], installation_digest=value['installation_digest'])
    result = host(plan, value['resources'], int(sys.argv[1]), int(sys.argv[2]),
                  None if len(sys.argv) == 3 else int(sys.argv[3]), selection=value['human_host'])
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        code = getattr(error, 'code', type(error).__name__)
        if type(code) is not str or not code.replace('_', '').isalnum() or len(code) > 96:
            code = 'NATIVE_HUMAN_SESSION_FAILED'
        print(json.dumps({'version': 1, 'status': 'FAILED', 'error': code}))
        raise SystemExit(3) from None
