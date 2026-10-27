"""Endpoint-free Field Notes consumer of an already-authorized Manager cache.

No listener, login implementation, certificate reuse, remote action or provider
access. The trusted caller fixes permitted Room identities and validated Project
bindings before rendering. This object does not authorize a human or accept an
identity/path from a browser. Human-authenticated serving belongs to the host.
"""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

from . import config
from .manager_projection import timestamp, token
from .manager_stream import ManagerReadModel, RoomIdentity, StreamError


TEMPLATE = Path(__file__).resolve().parents[1] / 'spike/manager-ui/manager-ui-prototype.html'
BOOTSTRAP = '<script type="application/json" id="manager-data"></script>'
MAX_DOCUMENT_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True)
class ProjectBinding:
    """Trusted operator metadata, distinct from live source observations."""
    identity: RoomIdentity
    project_id: str
    repository: str

    def document(self):
        if type(self.identity) is not RoomIdentity:
            raise StreamError('AUTHENTICATED_ROOM_REQUIRED')
        self.identity.document()
        token(self.project_id)
        if (type(self.repository) is not str or not config.REPOSITORY.fullmatch(self.repository)
                or any(part in {'.', '..'} for part in self.repository.split('/'))):
            raise StreamError('INVALID_PROJECT_BINDING')
        binding = {'identity': self.identity.document(), 'project_id': self.project_id,
                   'repository': self.repository}
        digest = hashlib.sha256(json.dumps(binding, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        return {'source_owner': 'operator-configuration', 'schema_version': 1,
                'project_id': self.project_id, 'repository': self.repository,
                'binding_digest': digest}

    @classmethod
    def from_configuration(cls, source, identity):
        """Read an explicitly supplied trusted configuration stream, never a URL."""
        document = config.load(source)
        if type(identity) is not RoomIdentity or identity.deployment_id != document['deployment']['id']:
            raise StreamError('SOURCE_ROOM_MISMATCH')
        room = next((room for room in document['rooms'] if room['id'] == identity.room_id), None)
        if room is None:
            raise StreamError('SOURCE_ROOM_MISMATCH')
        return cls(identity, room['project']['id'], room['project']['repository'])


class FieldNotesDocument:
    """Capture only the caller's fixed authorized Rooms on the cache owner thread.

    Constructing this object is not login or proof of read permission. The host
    must authenticate/authorize outside this module, including before each use.
    It must not expose this constructor or its model to browser-selected input.
    """
    def __init__(self, model, bindings):
        if type(model) is not ManagerReadModel or type(bindings) is not tuple:
            raise StreamError('INVALID_UI_BINDING')
        if len(bindings) > 1024 or any(type(binding) is not ProjectBinding for binding in bindings):
            raise StreamError('INVALID_UI_BINDING')
        seen = set()
        for binding in bindings:
            binding.document()
            key = (binding.identity.deployment_id, binding.identity.room_id)
            if key in seen:
                raise StreamError('DUPLICATE_UI_ROOM')
            seen.add(key)
        self._model, self._bindings = model, bindings

    def capture(self, *, now=None):
        now = datetime.now(timezone.utc).isoformat() if now is None else timestamp(now)
        rooms = []
        for binding in self._bindings:
            view = self._model.view(binding.identity, now=now)
            captured_at = None if view['projection'] is None else view['projection']['captured_at']
            valid_until = None if captured_at is None else (datetime.fromisoformat(captured_at)
                + timedelta(seconds=self._model.stale_after_seconds)).isoformat()
            rooms.append({'metadata': binding.document(), 'view': view,
                          'valid_until': valid_until, 'events': self._model.events(binding.identity)})
        value = {'schema_version': 1, 'generated_at': now, 'rooms': rooms}
        if len(json.dumps(value, allow_nan=False).encode()) > MAX_DOCUMENT_BYTES:
            raise StreamError('UI_DOCUMENT_LIMIT')
        return value

    def render(self, *, now=None):
        """A fresh self-contained document. No server, file write or polling."""
        value = self.capture(now=now)
        template = TEMPLATE.read_text(encoding='utf-8')
        if template.count(BOOTSTRAP) != 1:
            raise StreamError('UI_TEMPLATE_CONTRACT')
        # Data is never interpolated into executable JavaScript or HTML markup.
        payload = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(',', ':'))
        payload = payload.replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')
        return template.replace(BOOTSTRAP,
            '<script type="application/json" id="manager-data">' + payload + '</script>')
