"""Small trusted-host exporter step; no daemon, authority store or worker launch.

The persistent host owns thread/process lifetime and its Room source epoch.
Construct the RoomStream on a separate RoomLedger.open_reader() connection on
the exporter thread. Never call step from the Hub request-handling thread.
"""
import math
from contextlib import contextmanager
from datetime import datetime, timezone
from io import StringIO
import threading
import time
import uuid

from .config import load
from .ledger import RoomLedger
from .manager_projection import timestamp
from .manager_stream import RoomIdentity, RoomStream, StreamError
from .manager_transport import ManagerAddress, RoomTLSClient, export_once


class RoomManagerExport:
    def __init__(self, source, client, *, interval_seconds=15, retry_limit_seconds=60):
        if (type(source) is not RoomStream or type(client) is not RoomTLSClient
                or source.identity != client.identity):
            raise StreamError('EXPORTER_ROOM_MISMATCH')
        for value in (interval_seconds, retry_limit_seconds):
            if type(value) is not int or not 1 <= value <= 300:
                raise StreamError('INVALID_EXPORT_INTERVAL')
        self.source, self.client = source, client
        self.interval, self.retry_limit = interval_seconds, retry_limit_seconds
        self._retry = 1
        self._next = None
        self._last = None
        self._closed = False

    @classmethod
    def from_configuration(cls, source, configuration, resolve_tls, **options):
        """Resolve existing operator refs once, outside Project/Manager inputs.

        resolve_tls is the trusted host's credential resolver, called with only
        client_credential_ref, server_trust_ref and fixed identity. It returns a
        configured SSLContext, not credentials in the Manager protocol. This
        module neither supplies nor invents a credential store.
        """
        if type(source) is not RoomStream or not callable(resolve_tls):
            raise StreamError('FIXED_MANAGER_CONFIGURATION_REQUIRED')
        config = load(configuration)
        identity = source.identity
        if (config['deployment']['id'] != identity.deployment_id
                or identity.room_id not in {room['id'] for room in config['rooms']}):
            raise StreamError('SOURCE_ROOM_MISMATCH')
        manager = config['deployment']['manager']
        address = ManagerAddress.from_url(manager['url'])
        try:
            context = resolve_tls(client_credential_ref=manager['client_credential_ref'],
                                  server_trust_ref=manager['server_trust_ref'], identity=identity)
        except Exception:
            raise StreamError('MANAGER_CREDENTIALS_UNAVAILABLE') from None
        return cls(source, RoomTLSClient(identity, address, context), **options)

    def step(self, *, now, captured_at):
        """One eligible transfer; the host schedules the returned next deadline.

        Workstation Stop is irrelevant: the persistent Room keeps exporting.
        Destroy/replacement closes this object; it cannot reopen or change epoch.
        A failed transfer backs off without performing Hub workflow operations.
        """
        if self._closed:
            return {'status': 'closed', 'next_attempt': None}
        if type(now) not in (int, float) or not math.isfinite(now) or now < 0:
            raise StreamError('INVALID_EXPORT_CLOCK')
        timestamp(captured_at)
        if self._last is not None and now < self._last:
            raise StreamError('EXPORT_CLOCK_REGRESSION')
        self._last = now
        if self._next is not None and now < self._next:
            return {'status': 'waiting', 'next_attempt': self._next}
        result = export_once(self.source, self.client, captured_at=captured_at)
        if result['status'] == 'synchronized':
            delay, self._retry = self.interval, 1
        else:
            delay = self._retry
            self._retry = min(self.retry_limit, self._retry * 2)
        self._next = now + delay
        return {**result, 'next_attempt': self._next}

    def close(self):
        self._closed = True
        self.client.close()


@contextmanager
def _ledger_source(reader, identity):
    yield RoomStream(reader, identity)


class RoomManagerWorker:
    """One host-owned exporter thread, not a Hub/Workstation process or daemon.

    ``open_source(reader, identity)`` is trusted construction on this thread: a
    context manager yielding the fixed RoomStream and closing any extra owner
    readers it opens. It is never selected by a Manager/Participant message.
    Stop retains this worker. Destroy requests stop under the lifecycle lock,
    then reconciles termination; join must only run outside that lock.
    """
    def __init__(self, ledger_path, identity, configuration_text, resolve_tls, *,
                 open_source=_ledger_source, interval_seconds=15, retry_limit_seconds=60):
        if (type(identity) is not RoomIdentity or type(configuration_text) is not str
                or len(configuration_text.encode()) > 1_048_576
                or not callable(resolve_tls) or not callable(open_source)):
            raise StreamError('FIXED_MANAGER_CONFIGURATION_REQUIRED')
        identity.document()
        self._path, self._identity = ledger_path, identity
        self._worker_id = uuid.uuid4().hex
        self._configuration, self._resolve_tls, self._open_source = configuration_text, resolve_tls, open_source
        self._options = {'interval_seconds': interval_seconds, 'retry_limit_seconds': retry_limit_seconds}
        self._lock = threading.Lock()
        self._stop, self._done = threading.Event(), threading.Event()
        self._thread = None
        self._phase, self._error, self._last_result = 'new', None, None

    @property
    def worker_id(self):
        return self._worker_id

    @property
    def identity(self):
        return self._identity

    def start(self):
        with self._lock:
            if self._phase != 'new':
                raise StreamError('MANAGER_WORKER_ALREADY_STARTED')
            self._phase = 'starting'
            try:
                self._thread = threading.Thread(target=self._run, name='uas-manager-' + self.identity.room_id,
                                                daemon=False)
            except BaseException:
                self._phase, self._error = 'failed', 'MANAGER_WORKER_START_FAILED'
                self._done.set()
                raise StreamError('MANAGER_WORKER_START_FAILED') from None
            thread = self._thread
        try:
            thread.start()
        except BaseException:
            self._stop.set()
            # Do not discard a thread that might have started before failure.
            # A never-started standard Thread has no identity or live execution.
            with self._lock:
                self._phase, self._error = 'failed', 'MANAGER_WORKER_START_FAILED'
            if thread.ident is None and not thread.is_alive():
                self._done.set()
            raise StreamError('MANAGER_WORKER_START_FAILED') from None

    def request_stop(self):
        """Nonblocking; safe while holding the Supervisor lifecycle lock."""
        self._stop.set()
        with self._lock:
            if self._phase == 'new':
                self._phase = 'stopped'
                self._done.set()

    def join(self, timeout=1):
        """Bounded wait OUTSIDE owner locks; false means retain this exact worker."""
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 <= timeout <= 5:
            raise StreamError('INVALID_WORKER_JOIN_TIMEOUT')
        thread = self._thread
        if thread is not None:
            if thread is threading.current_thread():
                raise StreamError('MANAGER_WORKER_SELF_JOIN')
            if thread.ident is not None:
                thread.join(timeout)
            if thread.is_alive():
                return False
        return self._done.is_set()

    def status(self):
        with self._lock:
            terminated = self._done.is_set() and (self._thread is None or not self._thread.is_alive())
            return {'worker_id': self.worker_id, 'identity': self.identity.document(), 'phase': self._phase,
                    'stop_requested': self._stop.is_set(), 'terminated': terminated,
                    'error': self._error, 'last_export': None if self._last_result is None else dict(self._last_result)}

    def _run(self):
        try:
            if self._stop.is_set():
                return
            with RoomLedger.open_reader(self._path, self.identity.room_id) as reader:
                with self._open_source(reader, self.identity) as source:
                    if (type(source) is not RoomStream or source.ledger is not reader
                            or source.identity != self.identity):
                        raise StreamError('EXPORTER_ROOM_MISMATCH')
                    if self._stop.is_set():
                        return
                    exporter = RoomManagerExport.from_configuration(source, StringIO(self._configuration),
                        self._resolve_tls, **self._options)
                    try:
                        with self._lock:
                            self._phase = 'running'
                        while not self._stop.is_set():
                            result = exporter.step(now=time.monotonic(),
                                captured_at=datetime.now(timezone.utc).isoformat())
                            with self._lock:
                                self._last_result = dict(result)
                            if result['next_attempt'] is None:
                                break
                            self._stop.wait(max(0, result['next_attempt'] - time.monotonic()))
                    finally:
                        exporter.close()
        except BaseException:
            with self._lock:
                self._phase, self._error = 'failed', 'MANAGER_WORKER_FAILED'
        finally:
            with self._lock:
                if self._phase != 'failed':
                    self._phase = 'stopped'
            self._done.set()
