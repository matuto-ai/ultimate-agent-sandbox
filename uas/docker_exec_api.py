"""Bounded local Engine API I/O; no Participant identity and no automatic retry.

Only the trusted Supervisor owns this client. Never mount its socket or give this
object to a Hub. Exec create/start ambiguity is returned to the owning launch
journal. API/payload/runtime qualification remains a separate disposable test.
"""
import http.client
import json
import os
import select
import socket
import struct
import threading
import time

from .workstation_exec import ExecUnavailable, ID

API = '/v1.48'
# Source protocol reference, NOT an observed or admitted daemon version.
# moby/moby v28.0.0 api/server/router/container/exec.go:105-118
MULTIPLEX_TYPE = b'application/vnd.docker.multiplexed-stream'
MAX_JSON = 65536
MAX_FRAME = 1024 * 1024


class _UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path, timeout):
        super().__init__('localhost', timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class DockerExecAPI:
    def __init__(self, socket_path, *, timeout=5):
        if not os.path.isabs(socket_path) or not 0 < timeout <= 10:
            raise ExecUnavailable('invalid trusted Engine endpoint')
        self.socket_path, self.timeout = socket_path, timeout

    def _request(self, method, path, document=None):
        connection = _UnixHTTP(self.socket_path, self.timeout)
        try:
            body = None if document is None else json.dumps(document).encode()
            connection.request(method, API + path, body, {'Content-Type': 'application/json'})
            response = connection.getresponse()
            raw = response.read(MAX_JSON + 1)
            if response.status not in (200, 201) or len(raw) > MAX_JSON:
                raise ExecUnavailable('Engine response unavailable; do not retry mutation')
            return json.loads(raw)
        except (OSError, ValueError, http.client.HTTPException) as error:
            raise ExecUnavailable('Engine outcome unknown; reconcile owned operation') from error
        finally:
            connection.close()

    @staticmethod
    def _id(value):
        if type(value) is not str or not ID.fullmatch(value):
            raise ExecUnavailable('exact Engine ID required')
        return value

    def create(self, container_id, document):
        result = self._request('POST', '/containers/' + self._id(container_id) + '/exec', document)
        if type(result) is not dict or set(result) != {'Id'}:
            raise ExecUnavailable('unknown exec-create response')
        return self._id(result['Id'])

    def inspect(self, exec_id):
        return self._request('GET', '/exec/' + self._id(exec_id) + '/json')

    def inspect_container(self, container_id):
        """Bounded read for opt-in installation-selected native recipe binding."""
        return self._request('GET', '/containers/' + self._id(container_id) + '/json')

    def start(self, exec_id):
        path = API + '/exec/' + self._id(exec_id) + '/start'
        return self._upgrade(path, b'{"Detach":false,"Tty":false}')

    def attach_hub(self, container_id):
        """Fixed non-TTY Hub startup stdin; never infer task from init PID."""
        path = API + '/containers/' + self._id(container_id) + '/attach?stream=1&stdin=1&stdout=1&stderr=1'
        return self._upgrade(path, b'')

    def start_hub(self, container_id):
        """Start one already-owned immutable Hub container; no retry on ambiguity."""
        connection = _UnixHTTP(self.socket_path, self.timeout)
        try:
            connection.request('POST', API + '/containers/' + self._id(container_id) + '/start',
                               b'', {'Content-Length': '0'})
            response = connection.getresponse()
            if response.status != 204 or response.read(1):
                raise ExecUnavailable('Hub start unknown; reconcile exact owned container')
        finally:
            connection.close()

    def _upgrade(self, path, body):
        request = (f'POST {path} HTTP/1.1\r\nHost: localhost\r\n'
                   'Connection: Upgrade\r\nUpgrade: tcp\r\nContent-Type: application/json\r\n'
                   f'Content-Length: {len(body)}\r\n\r\n').encode() + body
        channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            channel.settimeout(self.timeout)
            channel.connect(self.socket_path)
            channel.sendall(request)
            header = bytearray()
            # Do not let a buffered HTTP reader swallow initial multiplex bytes.
            deadline = time.monotonic() + self.timeout
            while not header.endswith(b'\r\n\r\n'):
                if len(header) >= 8192 or time.monotonic() >= deadline:
                    raise ExecUnavailable('invalid Engine upgrade; start uncertain')
                byte = channel.recv(1)
                if not byte:
                    raise ExecUnavailable('Engine start EOF; start uncertain')
                header.extend(byte)
            lines = bytes(header).split(b'\r\n')
            if lines[0] != b'HTTP/1.1 101 UPGRADED':
                # Engine source uses this exact 101 response for non-TTY hijack.
                raise ExecUnavailable('Engine start did not upgrade; start uncertain')
            fields = {}
            for line in lines[1:-2]:
                key, separator, value = line.partition(b':')
                if not separator or key.lower() in fields:
                    raise ExecUnavailable('ambiguous Engine upgrade headers')
                fields[key.lower()] = value.strip().lower()
            if (fields.get(b'upgrade') != b'tcp' or fields.get(b'connection') != b'upgrade'
                    or fields.get(b'content-type') != MULTIPLEX_TYPE
                    or b'content-length' in fields or b'transfer-encoding' in fields):
                raise ExecUnavailable('Engine upgrade not verified')
            return EngineStream(channel)
        except BaseException:
            channel.close()
            raise


class EngineStream:
    """Actual exec I/O stream, deliberately with no PID or process poll method."""
    def __init__(self, channel):
        self.channel = channel
        self.closed = False
        self.io = None

    def write(self, data, *, timeout):
        if self.closed or self.io is not None:
            raise ExecUnavailable('bootstrap I/O already consumed')
        self.channel.settimeout(timeout)
        self.channel.sendall(data)

    def rpc_io(self):
        if self.closed or self.io is not None:
            raise ExecUnavailable('RPC I/O already attached')
        try:
            self.io = NativeRpcIO(self.channel)
        except BaseException:
            self.close()
            raise
        return self.io

    def close(self):
        self.closed = True
        if self.io is not None:
            self.io.close()
        try:
            self.channel.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.channel.close()


class NativeRpcIO:
    """Bounded Docker multiplex adaptation only, never Runtime authority.

    A receiver must separately receive a held-task liveness callback. Closing
    these streams only fences I/O; it neither kills nor proves exit of Pi.
    """
    def __init__(self, channel):
        self.channel = channel
        self._stop = threading.Event()
        self._threads = []
        self.error = None
        self._input = self._output = self._error = -1
        self.stdin = self.stdout = self.stderr = None
        unowned = set()
        try:
            self._input, public_input = os.pipe()
            unowned.add(public_input)
            public_output, self._output = os.pipe()
            unowned.add(public_output)
            public_error, self._error = os.pipe()
            unowned.add(public_error)
            for name, fd, mode in (('stdin', public_input, 'wb'),
                                   ('stdout', public_output, 'rb'),
                                   ('stderr', public_error, 'rb')):
                setattr(self, name, os.fdopen(fd, mode, buffering=0))
                unowned.remove(fd)
            for fd in (self._input, self._output, self._error):
                os.set_blocking(fd, False)
            self.channel.settimeout(0.2)
            for target in (self._send, self._receive):
                thread = threading.Thread(target=self._guard, args=(target,), daemon=True)
                self._threads.append(thread)
                thread.start()
        except BaseException:
            # Includes setup failure and a second worker failing to start after
            # the first is live. Closing I/O never asserts native task exit.
            self.close()
            for fd in unowned:
                os.close(fd)
            raise

    def _guard(self, target):
        try:
            target()
        except (OSError, ExecUnavailable) as error:
            self.error = str(error)[:256]
        finally:
            self._stop.set()
            try:
                self.channel.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def _read_exact(self, length):
        data = bytearray()
        while len(data) < length and not self._stop.is_set():
            try:
                part = self.channel.recv(length - len(data))
            except socket.timeout:
                continue
            if not part:
                raise ExecUnavailable('exec transport EOF (task state separate)')
            data.extend(part)
        if len(data) != length:
            raise ExecUnavailable('exec transport fenced')
        return bytes(data)

    def _receive(self):
        try:
            while not self._stop.is_set():
                stream, zero, length = struct.unpack('>B3sI', self._read_exact(8))
                if stream not in (1, 2) or zero != b'\0\0\0' or length > MAX_FRAME:
                    raise ExecUnavailable('invalid/oversized Engine multiplex frame')
                data = self._read_exact(length)
                descriptor = self._output if stream == 1 else self._error
                deadline = time.monotonic() + 2
                while data and not self._stop.is_set():
                    if time.monotonic() >= deadline:
                        raise ExecUnavailable('native output budget exceeded')
                    try:
                        count = os.write(descriptor, data)
                        data = data[count:]
                    except BlockingIOError:
                        select.select([], [descriptor], [], 0.05)
        finally:
            for name in ('_output', '_error'):
                fd = getattr(self, name)
                if fd >= 0:
                    os.close(fd); setattr(self, name, -1)

    def _send(self):
        try:
            while not self._stop.is_set():
                if not select.select([self._input], [], [], 0.1)[0]:
                    continue
                data = os.read(self._input, 65536)
                if not data:
                    return
                # A partial/timed-out send is terminal; never send another frame.
                self.channel.sendall(data)
        finally:
            if self._input >= 0:
                os.close(self._input); self._input = -1

    def close(self):
        self._stop.set()
        try:
            self.channel.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        for thread in self._threads:
            if thread.ident is not None:
                thread.join(timeout=1)
        # A started worker owns its internal descriptors until its finally
        # block runs. Unstarted workers/setup failure have no such finalizer.
        if not any(thread.is_alive() for thread in self._threads):
            for name in ('_input', '_output', '_error'):
                fd = getattr(self, name)
                if fd >= 0:
                    os.close(fd)
                    setattr(self, name, -1)
        for stream in (self.stdin, self.stdout, self.stderr):
            if stream is not None and not stream.closed:
                stream.close()
