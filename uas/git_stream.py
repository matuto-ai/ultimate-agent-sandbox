"""Bounded authenticated seqpacket-to-SSH pump; protocol bytes are not audit.

Only the external Broker calls this loop after its durable start and process
admission. ``require_record`` authenticates each kernel-origin Record; ``current``
rechecks immutable process/Room/epoch authority on every tick and each event.
The loop never reads credentials, interprets Git packs, or declares a push safe
to retry. Any failed opened session has possible external contact.
"""
import base64
from dataclasses import asdict, dataclass
import hashlib
import json
import os
import selectors
import time

from .kernel_origin import receive


MAX_DATA = 32768
MAX_BYTES = 64 * 1024 * 1024
MAX_FRAME = 45000
MAX_QUEUE = 2 * MAX_DATA
MAX_SECONDS = 30
TICK_SECONDS = .1


@dataclass(frozen=True)
class GitStreamReceipt:
    input_bytes: int
    output_bytes: int
    stderr_bytes: int
    input_sha256: str
    output_sha256: str
    exit_code: int | None
    status: str

    def document(self):
        return asdict(self)


class GitStreamError(RuntimeError):
    def __init__(self, code, receipt=None):
        self.code = code
        self.receipt = receipt
        self.contact = 'possible'
        super().__init__(code)


def _fail(code):
    raise GitStreamError(code)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail('INVALID_GIT_STREAM_FRAME')
        result[key] = value
    return result


def parse_frame(raw):
    """Only data/eof/cancel inputs, with one canonical base64 representation."""
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_FRAME:
        _fail('INVALID_GIT_STREAM_FRAME')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique,
                           parse_constant=lambda _: _fail('INVALID_GIT_STREAM_FRAME'))
        if type(value) is not dict:
            _fail('INVALID_GIT_STREAM_FRAME')
        if value == {'kind': 'eof'}:
            return 'eof', None
        if value == {'kind': 'cancel'}:
            return 'cancel', None
        if (set(value) != {'kind', 'data'} or value['kind'] != 'data'
                or type(value['data']) is not str or not value['data'].isascii()
                or not 0 < len(value['data']) <= ((MAX_DATA + 2) // 3) * 4):
            _fail('INVALID_GIT_STREAM_FRAME')
        data = base64.b64decode(value['data'], validate=True)
        if not 0 < len(data) <= MAX_DATA or base64.b64encode(data).decode('ascii') != value['data']:
            _fail('INVALID_GIT_STREAM_FRAME')
        return 'data', data
    except (ValueError, UnicodeError, TypeError, RecursionError):
        _fail('INVALID_GIT_STREAM_FRAME')


def _encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')


def data_frame(data):
    if type(data) is not bytes or not 0 < len(data) <= MAX_DATA:
        _fail('INVALID_GIT_STREAM_FRAME')
    return _encode({'kind': 'data', 'data': base64.b64encode(data).decode('ascii')})


def exit_frame(code, status):
    if type(code) is not int or not 0 <= code <= 255 or status not in ('SUCCEEDED', 'REMOTE_FAILED'):
        _fail('INVALID_GIT_STREAM_FRAME')
    return _encode({'kind': 'exit', 'code': code, 'status': status})


class GitStreamState:
    """Pure byte accounting; hashes cover bytes actually forwarded/disclosed.

    Received input and read stdout are also limited before queueing, but are not
    falsely reported as forwarded when revocation interrupts a pending queue.
    """
    def __init__(self, *, limit=MAX_BYTES):
        if type(limit) is not int or not 1 <= limit <= MAX_BYTES:
            _fail('INVALID_GIT_STREAM_LIMIT')
        self.limit = limit
        self.received = self.read_output = 0
        self.input_bytes = self.output_bytes = self.stderr_bytes = 0
        self._input = hashlib.sha256()
        self._output = hashlib.sha256()
        self.eof = False

    def accept(self, raw):
        kind, data = parse_frame(raw)
        if kind == 'cancel':
            _fail('GIT_STREAM_CANCELLED')
        if self.eof:
            _fail('GIT_STREAM_AFTER_EOF')
        if kind == 'eof':
            self.eof = True
        else:
            if self.received + len(data) > self.limit:
                _fail('GIT_STREAM_INPUT_LIMIT')
            self.received += len(data)
        return kind, data

    def written(self, data):
        if (type(data) is not bytes or not data or self.input_bytes + len(data) > self.received
                or self.input_bytes + len(data) > self.limit):
            _fail('INVALID_GIT_STREAM_ACCOUNTING')
        self.input_bytes += len(data)
        self._input.update(data)

    def read(self, data):
        if type(data) is not bytes or not data:
            _fail('INVALID_GIT_STREAM_ACCOUNTING')
        if self.read_output + len(data) > self.limit:
            _fail('GIT_STREAM_OUTPUT_LIMIT')
        self.read_output += len(data)

    def sent(self, data):
        if (type(data) is not bytes or not data or self.output_bytes + len(data) > self.read_output
                or self.output_bytes + len(data) > self.limit):
            _fail('INVALID_GIT_STREAM_ACCOUNTING')
        self.output_bytes += len(data)
        self._output.update(data)

    def discard_stderr(self, data):
        if type(data) is not bytes:
            _fail('INVALID_GIT_STREAM_ACCOUNTING')
        self.stderr_bytes += len(data)  # Actual drained count even on limit error.
        if self.stderr_bytes > self.limit:
            _fail('GIT_STREAM_STDERR_LIMIT')

    def receipt(self, *, exit_code=None, status='INTERRUPTED'):
        return GitStreamReceipt(self.input_bytes, self.output_bytes, self.stderr_bytes,
                                self._input.hexdigest(), self._output.hexdigest(), exit_code, status)


def proxy_ssh(channel, owned_session, require_record, current, *, timeout=MAX_SECONDS,
              limit=MAX_BYTES, observe_output=None):
    """Proxy one already-open SSH session and return exact transfer metadata.

    No raw stderr is forwarded or retained. Every exceptional path aborts via
    the sole-owner session API. The optional trusted output observer receives
    bounded raw stdout BEFORE forwarding. The pump NEVER sends a terminal exit:
    the caller must commit its terminal audit before using ``exit_frame``.
    A successful SSH exit is not contribution evidence or a replay grant.
    """
    state = GitStreamState()
    try:
        state = GitStreamState(limit=limit)
        if (not callable(require_record) or not callable(current)
                or (observe_output is not None and not callable(observe_output))
                or type(timeout) not in (int, float) or not 0 < timeout <= MAX_SECONDS):
            _fail('INVALID_GIT_STREAM_CONFIGURATION')
        deadline = time.monotonic() + timeout
        incoming = bytearray()
        outgoing = []  # (encoded seqpacket, raw stdout bytes)
        queued_output = 0
        stdin_open = stdout_open = stderr_open = True
        channel.setblocking(False)
        channel_fd = channel.fileno()
        stdin_fd, stdout_fd, stderr_fd = (stream.fileno() for stream in
                                        (owned_session.stdin, owned_session.stdout, owned_session.stderr))

        def guard():
            try:
                if current() is not True:
                    _fail('GIT_STREAM_AUTHORITY_REVOKED')
            except GitStreamError:
                raise
            except BaseException:
                _fail('GIT_STREAM_AUTHORITY_REVOKED')

        with selectors.DefaultSelector() as selector:
            watched = {}

            def watch(fd, events, label):
                previous = watched.get(fd)
                if not events:
                    if previous is not None:
                        selector.unregister(fd)
                        del watched[fd]
                elif previous is None:
                    selector.register(fd, events, label)
                    watched[fd] = events
                elif previous != events:
                    selector.modify(fd, events, label)
                    watched[fd] = events

            while True:
                guard()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    _fail('GIT_STREAM_TIMEOUT')
                if state.eof and not incoming and stdin_open:
                    watch(stdin_fd, 0, 'stdin')
                    owned_session.stdin.close()
                    stdin_open = False
                channel_events = selectors.EVENT_READ if len(incoming) <= MAX_QUEUE - MAX_DATA else 0
                if outgoing:
                    channel_events |= selectors.EVENT_WRITE
                watch(channel_fd, channel_events, 'channel')
                watch(stdin_fd, selectors.EVENT_WRITE if stdin_open and incoming else 0, 'stdin')
                watch(stdout_fd, selectors.EVENT_READ if stdout_open and queued_output <= MAX_QUEUE - MAX_DATA else 0, 'stdout')
                watch(stderr_fd, selectors.EVENT_READ if stderr_open else 0, 'stderr')
                events = selector.select(min(TICK_SECONDS, remaining))
                guard()
                for key, mask in events:
                    guard()
                    if key.data == 'channel':
                        if mask & selectors.EVENT_READ:
                            try:
                                record = receive(channel)
                            except BlockingIOError:
                                record = None
                            if record is not None:
                                with record:
                                    try:
                                        authorized = require_record(record)
                                    except BaseException:
                                        _fail('GIT_STREAM_AUTHORITY_REVOKED')
                                    if authorized is not None and authorized is not True:
                                        _fail('GIT_STREAM_AUTHORITY_REVOKED')
                                    guard()
                                    kind, data = state.accept(record.data)
                                if kind == 'data':
                                    incoming.extend(data)
                        if mask & selectors.EVENT_WRITE and outgoing:
                            guard()
                            packet, raw = outgoing[0]
                            try:
                                sent = channel.send(packet)
                            except BlockingIOError:
                                continue
                            if sent != len(packet):
                                _fail('GIT_STREAM_DISCONNECTED')
                            outgoing.pop(0)
                            state.sent(raw)
                            queued_output -= len(raw)
                    elif key.data == 'stdin':
                        try:
                            count = os.write(stdin_fd, incoming)
                        except BlockingIOError:
                            continue
                        if type(count) is not int or not 0 < count <= len(incoming):
                            _fail('GIT_STREAM_IO_ERROR')
                        state.written(bytes(incoming[:count]))
                        del incoming[:count]
                    elif key.data == 'stdout':
                        try:
                            data = os.read(stdout_fd, min(MAX_DATA, state.limit - state.read_output + 1))
                        except BlockingIOError:
                            continue
                        if not data:
                            watch(stdout_fd, 0, 'stdout')
                            stdout_open = False
                        else:
                            state.read(data)
                            if observe_output is not None:
                                observe_output(data)
                            outgoing.append((data_frame(data), data))
                            queued_output += len(data)
                    elif key.data == 'stderr':
                        try:
                            data = os.read(stderr_fd, min(MAX_DATA, state.limit - state.stderr_bytes + 1))
                        except BlockingIOError:
                            continue
                        if not data:
                            watch(stderr_fd, 0, 'stderr')
                            stderr_open = False
                        else:
                            state.discard_stderr(data)
                exited = owned_session.observe()
                if exited is not None and not stdout_open and not stderr_open and not outgoing:
                    guard()
                    # The sole-owner implementation rechecks ownership and
                    # kills still-owned descendants before one reap.
                    result = owned_session.finish(timeout=0)
                    guard()
                    watch(stdin_fd, 0, 'stdin')
                    if type(result) is not int:
                        _fail('GIT_STREAM_IO_ERROR')
                    if incoming and result == 0:
                        _fail('GIT_STREAM_INPUT_TRUNCATED')
                    code = min(255, 128 - result) if result < 0 else min(255, result)
                    status = 'SUCCEEDED' if code == 0 else 'REMOTE_FAILED'
                    return state.receipt(exit_code=code, status=status)
    except BaseException as error:
        code = error.code if type(error) is GitStreamError else 'GIT_STREAM_IO_ERROR'
        try:
            owned_session.abort()
        except BaseException:
            code = 'GIT_STREAM_CLEANUP_UNKNOWN'
        raise GitStreamError(code, state.receipt(status=code)) from None
