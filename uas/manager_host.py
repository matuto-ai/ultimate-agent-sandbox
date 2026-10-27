"""Small trusted-host exporter step; no daemon, authority store or worker launch.

The persistent host owns thread/process lifetime and its Room source epoch.
Construct the RoomStream on a separate RoomLedger.open_reader() connection on
the exporter thread. Never call step from the Hub request-handling thread.
"""
import math

from .config import load
from .manager_projection import timestamp
from .manager_stream import RoomStream, StreamError
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
