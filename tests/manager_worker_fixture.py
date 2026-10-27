"""Reviewed hosted-only loopback worker proof helper; never a product service."""
from contextlib import contextmanager


@contextmanager
def hosted_manager_worker(supervisor, ledger_path, identity, configuration, certroot):
    """Yield exact worker + bounded receiver inspection; caller owns attachment.

    Uses already generated temporary alpha/manager certificates from the Manager
    fixture (manager.fixture.invalid SAN). No certificates/accounts are installed.
    A narrow fixture route sends that exact configured endpoint to loopback;
    actual TLS hostname/client-certificate validation remains enabled.
    """
    import os
    if not (os.environ.get('UAS_MANAGER_TLS_TEST') == '1'
            and os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_OS') == 'Linux'):
        raise RuntimeError('HOSTED_MANAGER_WORKER_FIXTURE_REQUIRED')
    from copy import deepcopy
    from datetime import datetime, timezone
    import json
    from pathlib import Path
    import socket
    import time
    from types import SimpleNamespace
    from unittest.mock import patch
    from test_manager_tls import HostedManagerTLSTests
    from uas.manager_host import RoomManagerWorker
    from uas.manager_stream import ManagerReadModel, RoomStream
    from uas.manager_transport import client_tls_context
    if identity.room_id != 'alpha':
        raise RuntimeError('FIXED_FIXTURE_ROOM_REQUIRED')
    case = HostedManagerTLSTests()
    case.certroot, case.fixture_alpha = Path(certroot), identity
    try:
        case.setUp()
    except BaseException:
        case.doCleanups()
        raise
    config = deepcopy(configuration)
    config['deployment']['manager']['url'] = 'https://manager.fixture.invalid:' + str(case.port)
    endpoint = ('manager.fixture.invalid', case.port)
    connect = socket.create_connection
    workers = []

    def loopback(address, *args, **kwargs):
        if address != endpoint:
            raise AssertionError('unexpected fixture network destination')
        return connect(('127.0.0.1', case.port), *args, **kwargs)

    @contextmanager
    def open_source(reader, fixed_identity):
        yield RoomStream(reader, fixed_identity, supervisor=supervisor)

    def resolve_tls(**refs):
        manager = config['deployment']['manager']
        if refs != {'client_credential_ref': manager['client_credential_ref'],
                    'server_trust_ref': manager['server_trust_ref'], 'identity': identity}:
            raise AssertionError('unexpected fixture credential resolution')
        return client_tls_context(trust_file=str(case.certroot / 'ca.crt'),
            certificate_file=str(case.certroot / 'alpha.crt'), private_key_file=str(case.certroot / 'alpha.key'))

    def new_worker():
        worker = RoomManagerWorker(ledger_path, identity, json.dumps(config), resolve_tls,
                                  open_source=open_source, interval_seconds=1, retry_limit_seconds=2)
        workers.append(worker)
        return worker

    def read_projection():
        return observer.view(identity, now=datetime.now(timezone.utc).isoformat())['projection']

    def wait_projection(predicate, timeout=5):
        if not 0 < timeout <= 5:
            raise AssertionError('fixture deadline exceeds five seconds')
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                projection = read_projection()
            except (KeyError, ValueError):
                projection = None
            if projection is not None and predicate(projection):
                return projection
            time.sleep(.02)
        raise AssertionError('Manager did not receive expected exact Room projection')

    def connection_count():
        with case.channel_lock:
            return case.connection_count

    def disconnect_receiver():
        """Interrupt only owned accepted sockets, retaining the same listener/store."""
        with case.channel_lock:
            channels, before = list(case.active_channels), case.connection_count
        if not channels:
            raise AssertionError('no owned receiver connection to interrupt')
        for channel in channels:
            try:
                channel.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        return before

    observer = None
    with patch('uas.manager_transport.socket.create_connection', side_effect=loopback):
        try:
            # setUp has acknowledged durable receiver initialization. This owned
            # observer stays on the caller thread; polling is now reads only.
            observer = ManagerReadModel(case.root / 'manager.sqlite3')
            yield SimpleNamespace(worker=new_worker(), new_worker=new_worker,
                                  read_projection=read_projection, wait_projection=wait_projection,
                                  disconnect_receiver=disconnect_receiver, connection_count=connection_count)
        finally:
            try:
                if observer is not None:
                    observer.close()
            finally:
                for worker in workers:
                    worker.request_stop()
                for worker in workers:
                    if not worker.join(3):
                        case.shutdown()  # Close only this owned receiver before a last bounded wait.
                        if not worker.join(3):
                            raise AssertionError('fixture exporter still owned/live; resources retained')
                if not case.doCleanups():
                    raise AssertionError('Manager receiver cleanup failed')
