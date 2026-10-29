"""Fixed non-root probe/held bootstrap for the composed disposable Room fixture.

No shell, credentials, arbitrary paths, destinations or commands. This is test
image functionality, not a Participant API or an installed production launcher.
"""
import os
import sys

DENIED_HELP_ENTRY = b'UAS_ROOM_PYTHON_ENTRY\n'
# This fixed diagnostic precedes optional/module imports, never grants authority.
if __name__ == '__main__' and sys.argv[1:] == ['denied-help-ready']:
    if os.write(2, DENIED_HELP_ENTRY) != len(DENIED_HELP_ENTRY):
        raise RuntimeError('incomplete Python entry diagnostic')

import errno
import json
from pathlib import Path
import re
import socket
import select
import time

ENDPOINT = '/uas/git/request.sock'
PUBLIC_ADDRESS = '1.1.1.1'
PUBLIC_HOST = 'one.one.one.one'
PUBLIC_CA_FILE = '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem'
PUBLIC_REQUEST = b'HEAD / HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n'


def require(value, message):
    if not value: raise RuntimeError(message)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def error_name(error):
    if isinstance(error, (TimeoutError, socket.timeout)): return 'TIMEOUT'
    return errno.errorcode.get(getattr(error, 'errno', None), 'OTHER')


def observe():
    from uas.workstation_probe import process_status
    files = {}
    for path in ('/proc/self/uid_map', '/proc/self/gid_map', '/proc/self/attr/current',
                 '/sys/fs/cgroup/memory.max', '/sys/fs/cgroup/pids.max', '/sys/fs/cgroup/cpu.max'):
        raw = Path(path).read_text()
        require(len(raw) <= 8192, 'bounded kernel observation required')
        files[path] = raw.strip('\0\n')
    return {'uid': os.getuid(), 'gid': os.getgid(), 'process': process_status(), 'files': files}


def public_head():
    """Exactly one address, certificate-checked TLS, fixed request.

    A bounded HTTP header is enough to demonstrate real public egress. No body,
    redirect following, DNS discovery, account, key, fallback or retry occurs.
    """
    import hashlib
    import ssl
    started = time.monotonic()
    def remaining():
        value = 5 - (time.monotonic() - started)
        require(value > 0, 'public HTTPS deadline exceeded')
        return value
    # The signed offline image materializes this server-auth bundle, not
    # Fedora 44's scriptlet-generated default hashed certificate directory.
    context = ssl.create_default_context(cafile=PUBLIC_CA_FILE)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw:
        raw.settimeout(remaining())
        raw.connect((PUBLIC_ADDRESS, 443))
        raw.settimeout(remaining())
        with context.wrap_socket(raw, server_hostname=PUBLIC_HOST) as channel:
            channel.settimeout(remaining())
            channel.sendall(PUBLIC_REQUEST)
            header = bytearray()
            while b'\r\n\r\n' not in header:
                require(len(header) < 4096 and time.monotonic() - started < 5, 'public header/time budget')
                channel.settimeout(remaining())
                chunk = channel.recv(min(512, 4096 - len(header)))
                remaining()  # A complete final header cannot escape the same deadline.
                require(bool(chunk), 'incomplete public HTTP header')
                header.extend(chunk)
            # HEAD has no response body. Retain only header bytes even if a
            # broken peer appends bytes to its final packet.
            header = header[:header.index(b'\r\n\r\n') + 4]
            line = bytes(header).split(b'\r\n', 1)[0]
            require(re.fullmatch(rb'HTTP/1\.[01] [1-5][0-9]{2}(?: [\x20-\x7e]*)?', line) is not None,
                    'invalid public HTTP response')
            status = int(line.split(b' ')[1])
            require(200 <= status < 400, 'public HTTPS endpoint did not respond successfully')
            return {'address': PUBLIC_ADDRESS, 'host': PUBLIC_HOST, 'port': 443,
                    'certificate_hostname_verified': True, 'http_status': status,
                    'request_bytes': len(PUBLIC_REQUEST), 'response_header_bytes': len(header),
                    'response_header_sha256': hashlib.sha256(header).hexdigest()}


def socket_probe(path):
    require(path == ENDPOINT, 'fixed endpoint required')
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as channel:
        channel.settimeout(2)
        try:
            channel.connect(path)
            return {'connected': True}
        except OSError as error:
            return {'connected': False, 'error': error_name(error)}


def private_paths():
    result = {}
    for path in ('/var/lib/uas-room-brokers', '/run/docker.sock', '/var/run/docker.sock',
                 '/var/lib/uas-boundary'):
        try: os.stat(path); result[path] = 'VISIBLE'
        except OSError as error: result[path] = error_name(error)
    try: os.unlink(ENDPOINT); result['endpoint_unlink'] = 'SUCCEEDED'
    except OSError as error: result['endpoint_unlink'] = error_name(error)
    return result


# Intentional fixture guard change: one absolute post-help orchestration ceiling,
# not an aggregate guarantee that every independent operation can use its maximum.
BOOTSTRAP_CONTROL_SECONDS = 30


def bootstrap_control_remaining(deadline):
    remaining = deadline - time.monotonic()
    require(remaining > 0, 'held bootstrap control deadline')
    return remaining


def bootstrap():
    import ctypes
    from uas.git_endpoint import EndpointPeer
    from uas.kernel_origin import enable, receive
    from uas.git_service import decode, send
    require(ctypes.CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0) == 0, 'bootstrap dumpability fence')
    challenge = bytearray()
    while len(challenge) < 32:
        data = os.read(0, 32 - len(challenge)); require(bool(data), 'bootstrap challenge absent')
        challenge.extend(data)
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as channel:
        channel.settimeout(12); enable(channel); channel.connect(ENDPOINT)
        peer = EndpointPeer(channel)
        try:
            require(channel.send(b'UAS1' + challenge) == 36, 'incomplete bootstrap correlation')
            with receive(channel) as record:
                peer.require(record)
                require(record.data == b'UAS-RELEASE-1\n', 'wrong bootstrap release')
            send(channel, {'kind': 'HELD_BOOTSTRAP', 'uid': os.getuid(), 'gid': os.getgid(),
                           'peer_credentials': list(peer.credentials), 'peer_identity': list(peer.identity),
                           'peer_label': channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERSEC, 1024).decode().rstrip('\0')})
            with receive(channel) as record:
                peer.require(record)
                require(decode(record.data) == {'kind': 'PROVE_HELP_ONLY'}, 'preflight not authorized')
            # No actor input: the actual public service derives our held task.
            # We deliberately call only its safe help route in this fixture.
            stage = 'launcher_import'
            try:
                from uas.git_launcher import main as git
                stage = 'help'
                require(git(['--help'], invoked_as='git') == 0, 'real mounted Git help failed')
                stage = 'nonhelp'
                require(git(['status'], invoked_as='git') == 128, 'non-help must be disabled')
            except Exception as error:
                # Authenticated fixed control channel; never sends traceback,
                # arbitrary exception text, secrets or authority claims.
                try:
                    send(channel, {'kind': 'BOOTSTRAP_FAILED', 'stage': stage,
                                   'error_type': type(error).__name__[:64]})
                    # The receiver authenticates a live held task. Keep this
                    # task alive until its exact peer acknowledges recording.
                    channel.settimeout(5)
                    with receive(channel) as record:
                        peer.require(record)
                        require(decode(record.data) == {'kind': 'BOOTSTRAP_FAILURE_RECORDED'},
                                'unexpected bootstrap diagnostic acknowledgement')
                except Exception:
                    pass  # Preserve the first error if the diagnostic send fails.
                raise
            # Start before send: queued delivery can never extend this child's
            # authoritative boundary. There is no keepalive or refreshed wait.
            control_deadline = time.monotonic() + BOOTSTRAP_CONTROL_SECONDS
            channel.settimeout(bootstrap_control_remaining(control_deadline))
            send(channel, {'kind': 'HELP_ONLY_PROVED'})
            channel.settimeout(bootstrap_control_remaining(control_deadline))
            with receive(channel) as record:
                peer.require(record)
                require(decode(record.data) == {'kind': 'RELEASE_WORKLOAD'}, 'workload release not authorized')
            # Authentication/decoding and late scheduling spend the same phase.
            channel.settimeout(bootstrap_control_remaining(control_deadline))
            send(channel, {'kind': 'WORKLOAD_STARTED'})
            channel.settimeout(12)  # Existing EXIT wait, outside orchestration.
            with receive(channel) as record:
                peer.require(record)
                require(decode(record.data) == {'kind': 'EXIT'}, 'unexpected fixture control')
        finally:
            peer.close()



DENIED_HELP_READY = b'UAS_ROOM_DENIED_HELP_READY\n'
DENIED_HELP_PROBE_IMPORTED = b'UAS_ROOM_PROBE_IMPORTED\n'
DENIED_HELP_LAUNCHER_IMPORTED = b'UAS_ROOM_LAUNCHER_IMPORTED\n'
DENIED_HELP_STARTUP_STEPS = (
    ('python_entry', DENIED_HELP_ENTRY),
    ('probe_imported', DENIED_HELP_PROBE_IMPORTED),
    ('launcher_imported', DENIED_HELP_LAUNCHER_IMPORTED),
    ('ready', DENIED_HELP_READY),
)
DENIED_HELP_STARTUP = b''.join(marker for _, marker in DENIED_HELP_STARTUP_STEPS)
DENIED_HELP_RELEASE = b'G'
DENIED_HELP_SETUP_SECONDS = 5


def denied_help_ready():
    """Fixture preparation barrier only; the real launcher still proves origin."""
    require(os.write(2, DENIED_HELP_PROBE_IMPORTED) == len(DENIED_HELP_PROBE_IMPORTED),
            'incomplete probe import diagnostic')
    from uas.git_launcher import main as git
    require(os.write(2, DENIED_HELP_LAUNCHER_IMPORTED) == len(DENIED_HELP_LAUNCHER_IMPORTED),
            'incomplete launcher import diagnostic')
    # Imports happen in this fresh task before the diagnostic marker. No
    # supplied module, PID, callback, endpoint or readiness flag grants access.
    require(os.write(2, DENIED_HELP_READY) == len(DENIED_HELP_READY), 'incomplete readiness marker')
    deadline = time.monotonic() + DENIED_HELP_SETUP_SECONDS
    remaining = deadline - time.monotonic()
    require(remaining > 0, 'unrelated readiness release deadline')
    ready, _, _ = select.select([0], [], [], remaining)
    require(ready == [0] and time.monotonic() < deadline, 'unrelated readiness release deadline')
    require(os.read(0, 2) == DENIED_HELP_RELEASE, 'exact fixed unrelated readiness release required')
    require(time.monotonic() < deadline, 'unrelated readiness release deadline')
    return {'code': git(['--help'], invoked_as='git')}

def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    require(os.getuid() == os.getgid() == 65532 and len(args) == 1, 'fixed nonroot Room probe required')
    mode = args[0]
    if mode == 'idle':
        while True: time.sleep(60)
    elif mode == 'bootstrap':
        bootstrap(); return
    elif mode == 'observe': result = observe()
    elif mode == 'public-head': result = public_head()
    elif mode == 'endpoint': result = socket_probe(ENDPOINT)
    elif mode == 'private': result = private_paths()
    elif mode == 'denied-help-ready': result = denied_help_ready()
    elif mode == 'denied-help':
        from uas.git_launcher import main as git
        result = {'code': git(['--help'], invoked_as='git')}
    else: raise RuntimeError('unknown fixed Room probe')
    print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == '__main__':
    # Exact immutable image source, not a caller-supplied import path.
    sys.path.insert(0, '/opt/uas')
    main()
