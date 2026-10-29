"""Local authenticated Manager composition; existing ledger, no synthetic state.

Run serve_local_manager on its own owner thread. The trusted host supplies the
already-created Supervisor and fixed canonical Hub ledger path. No SQLite owner
is shared across threads; Supervisor exports only locked persisted observations.
"""
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import socket

from .ledger import RoomLedger, LedgerError
from .lifecycle import Supervisor
from .local_installation import Installation, canonical
from .local_manager import ManagerSelection
from .manager_stream import ManagerReadModel, RoomIdentity, RoomStream
from .manager_ui import FieldNotesDocument, ProjectBinding

MAX_REPLAY_EVENTS = 10000


def require(condition, code):
    if not condition: raise LedgerError(code)


def instance(supervisor):
    require(type(supervisor) is Supervisor, 'LOCAL_MANAGER_SUPERVISOR_REQUIRED')
    with supervisor._locked():
        state = supervisor._read()
    require(type(state) is dict and state.get('phase') not in {'destroying','destroy_failed','destroyed'},
            'LOCAL_MANAGER_ROOM_UNAVAILABLE')
    return state['instance_id']


class LocalProjection:
    """One owner-thread reader and cache; refresh only real canonical snapshots."""
    def __init__(self, ledger, model, supervisor, identity, binding):
        require(type(identity) is RoomIdentity and identity.room_id == supervisor.room_id
                and instance(supervisor) == identity.stream_id, 'LOCAL_MANAGER_INSTANCE_CHANGED')
        self.model, self.supervisor, self.identity = model, supervisor, identity
        self.stream = RoomStream(ledger, identity, supervisor=supervisor)
        self.session = model.connect(identity)
        self.document = FieldNotesDocument(model, (binding,))

    def close(self):
        self.model.disconnect(self.identity, self.session)

    def refresh(self, human):
        require(human.deployment_id == self.identity.deployment_id
                and human.room_id == self.identity.room_id
                and human.instance_id == self.identity.stream_id, 'LOCAL_MANAGER_SESSION_SCOPE')
        require(human.allowed('observe'), 'LOCAL_MANAGER_AUTHENTICATION_REVOKED')
        require(instance(self.supervisor) == self.identity.stream_id, 'LOCAL_MANAGER_INSTANCE_CHANGED')
        cursor = self.model.cursor(self.identity)
        transfer = self.stream.capture(cursor, captured_at=datetime.now(timezone.utc).isoformat())
        if cursor is not None:
            require(transfer.cut-cursor <= MAX_REPLAY_EVENTS, 'LOCAL_MANAGER_REPLAY_LIMIT')
        self.model.begin(self.identity, self.session, transfer.begin())
        if cursor is not None:
            while cursor < transfer.cut:
                page = transfer.page(cursor, limit=100)
                self.model.append(self.identity, self.session, page)
                cursor += len(page['events'])
        require(instance(self.supervisor) == self.identity.stream_id, 'LOCAL_MANAGER_INSTANCE_CHANGED')
        require(human.allowed('observe'), 'LOCAL_MANAGER_AUTHENTICATION_REVOKED')
        self.model.finish(self.identity, self.session, transfer.transfer_id)
        return self.document


def serve_local_manager(installation, supervisor, *, ledger_path, stopped, action_host_for=None, on_ready=None):
    """Serve selected existing grant until owner stop, without creating credentials.

    ledger_path must come from native backend.layout(state)['hub']/'room.db'.
    Called only after canonical Hub initialization; missing ledger fails closed.
    No Room creation/recovery, provider account, port fallback or key generation.
    """
    require(type(installation) is Installation and callable(stopped)
            and (on_ready is None or callable(on_ready)), 'LOCAL_MANAGER_INSTALLATION_REQUIRED')
    value, config, selected = installation.open()
    require(value['manager'] is not None, 'LOCAL_MANAGER_NOT_CONFIGURED')
    room_id = supervisor.room_id
    room = next((r for r in config['rooms'] if r['id'] == room_id), None)
    require(room is not None, 'LOCAL_MANAGER_ROOM_SCOPE')
    identity = RoomIdentity(config['deployment']['id'], room_id, instance(supervisor))
    selection = ManagerSelection.read(value['manager'], deployment_id=identity.deployment_id,
        room_id=room_id, instance_id=identity.stream_id,
        configuration_sha256=hashlib.sha256(canonical(config)).hexdigest())
    context = selection.tls_context()
    # Bind before opening caches: collision is an error, never choose another port.
    hostname, port = selection.authority.rsplit(':', 1)
    family = socket.AF_INET6 if hostname == '[::1]' else socket.AF_INET
    address = '::1' if family == socket.AF_INET6 else '127.0.0.1'
    with ExitStack() as stack:
        listener = socket.socket(family, socket.SOCK_STREAM)
        stack.callback(listener.close)
        listener.bind((address, int(port))); listener.listen(8)
        ledger = RoomLedger.open_reader(ledger_path, room_id); stack.callback(ledger.close)
        # Instance-specific cache avoids implicitly adopting a recreated Room stream.
        model = ManagerReadModel(installation.root / ('manager-'+room_id+'-'+identity.stream_id+'.sqlite'))
        stack.callback(model.close)
        projection = LocalProjection(ledger, model, supervisor, identity,
            ProjectBinding(identity, room['project']['id'], room['project']['repository']))
        stack.callback(projection.close)
        def document_for(human):
            current, _, _ = installation.open()
            require(current == value, 'LOCAL_MANAGER_INSTALLATION_CHANGED')
            return projection.refresh(human)
        manager = selection.manager(document_for, action_host_for=action_host_for)
        if on_ready is not None:
            on_ready({'status':'ready','url':'https://'+selection.authority+'/',
                      'mode':'observe-only' if action_host_for is None else 'scoped-actions',
                      'room_id':room_id,'instance_id':identity.stream_id})
        manager.serve(listener, context, stopped)
