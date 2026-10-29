"""Retained thread owner for the existing mTLS Manager, never a new grant."""
import threading
from .local_manager_host import serve_local_manager
from .local_installation import require


class ManagerOwner:
    def __init__(self, installation):
        self.installation = installation
        self.thread = None
        self.stopped = threading.Event()
        self.lock = threading.Lock()
        self.receipt = {'status':'not-configured'}
        self.room = None

    def ensure(self, room, supervisor, backend, state):
        _, _, selected = self.installation.open()
        if selected['manager'] is None: return self.status()
        configured_room = selected['manager'].get('room_id')
        if room != configured_room: return {'status':'not-selected-for-room'}
        if self.thread is not None:
            require(self.room == room, 'LOCAL_MANAGER_ALREADY_OWNED')
            return self.status()  # Never retry a failed or uncertain bind implicitly.
        self.room = room
        self.receipt = {'status':'starting'}
        def ready(receipt):
            with self.lock: self.receipt = dict(receipt)
        def work():
            try:
                serve_local_manager(self.installation, supervisor,
                    ledger_path=backend.layout(state)['hub']/'room.db',
                    stopped=self.stopped.is_set, on_ready=ready)
                with self.lock: self.receipt = {'status':'stopped'}
            except Exception as error:
                with self.lock:
                    self.receipt = {'status':'unknown','error':getattr(error,'code','LOCAL_MANAGER_FAILED')}
        self.thread = threading.Thread(target=work, name='uas-local-manager', daemon=False)
        self.thread.start()
        return self.status()

    def status(self):
        with self.lock: return dict(self.receipt)

    def close(self):
        self.stopped.set()
        if self.thread is not None:
            self.thread.join(timeout=10)
            require(not self.thread.is_alive(), 'LOCAL_MANAGER_STOP_UNCONFIRMED')
