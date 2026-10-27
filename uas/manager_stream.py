"""Read-only per-Room snapshot transfer and durable ordered Manager replay.

Events carry sanitized original-event metadata, NOT invented historical fact
deltas. A complete snapshot is installed only after its whole contiguous range
has arrived. Partial catch-up never claims a current projection. No object in
this module has a workflow command, supervisor control, or Broker write API.
"""
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import sqlite3

from .ledger import RoomLedger
from .manager_projection import (EXTERNAL_FIELDS, ProjectionError, SCHEMA_VERSION, SourceObservation,
                                 canonical, project_hub, timestamp, token, validate_section_value)


class StreamError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def sequence(value):
    if type(value) is not int or not 0 <= value < 2**63:
        raise StreamError('INVALID_CURSOR')
    return value


@dataclass(frozen=True)
class RoomIdentity:
    deployment_id: str
    room_id: str
    stream_id: str

    def document(self):
        return {key: token(getattr(self, key)) for key in
                ('deployment_id', 'room_id', 'stream_id')}


def _identity(value):
    if type(value) is not RoomIdentity:
        raise StreamError('AUTHENTICATED_ROOM_REQUIRED')
    return value.document()


HUB_SECTIONS = frozenset({'runs', 'candidate', 'attention', 'adapter_connections',
    'readiness', 'last_observation', 'work_requests', 'context_binding',
    'gate_history', 'gate_truth', 'lifecycle_label_drift'})
SECTION_NAMES = HUB_SECTIONS | EXTERNAL_FIELDS.keys()

_STORE_SCHEMA = {
    'manager_metadata': 'CREATE TABLE manager_metadata (singleton INTEGER PRIMARY KEY CHECK(singleton=1), version INTEGER NOT NULL)',
    'manager_rooms': 'CREATE TABLE manager_rooms (deployment TEXT, room TEXT, stream TEXT NOT NULL, cursor INTEGER, projection TEXT, PRIMARY KEY(deployment, room))',
    'manager_events': 'CREATE TABLE manager_events (deployment TEXT, room TEXT, stream TEXT, seq INTEGER, event TEXT NOT NULL, PRIMARY KEY(deployment, room, stream, seq))',
    'manager_transfers': 'CREATE TABLE manager_transfers (deployment TEXT, room TEXT, id TEXT NOT NULL, base INTEGER, cut INTEGER NOT NULL, received INTEGER NOT NULL, projection TEXT NOT NULL, PRIMARY KEY(deployment, room))',
    'manager_sources': 'CREATE TABLE manager_sources (deployment TEXT, room TEXT, section TEXT, version INTEGER NOT NULL, fact TEXT NOT NULL, PRIMARY KEY(deployment, room, section))',
}


def validate_projection(value, room_id):
    if (type(value) is not dict or set(value) != {'schema_version', 'room_id', 'room_seq',
            'captured_at', 'sections'} or type(value['schema_version']) is not int
            or value['schema_version'] != SCHEMA_VERSION or value['room_id'] != room_id
            or type(value['sections']) is not dict or set(value['sections']) != SECTION_NAMES):
        raise StreamError('INVALID_PROJECTION')
    sequence(value['room_seq']); timestamp(value['captured_at'])
    for section, fact in value['sections'].items():
        expected_owner = EXTERNAL_FIELDS[section][0] if section in EXTERNAL_FIELDS else (
            'hub-gate' if section == 'gate_truth' else 'hub')
        if (type(fact) is not dict or set(fact) != {'source_owner', 'observed_version',
                'observed_at', 'source_committed_at', 'status', 'freshness', 'reason', 'value'}
                or fact['source_owner'] != expected_owner
                or type(fact['status']) is not str or fact['status'] not in {'known', 'unknown', 'unavailable', 'failed'}
                or type(fact['freshness']) is not str or fact['freshness'] not in {'current', 'unknown', 'stale'}):
            raise StreamError('INVALID_SOURCE_FACT')
        if fact['observed_version'] is not None:
            sequence(fact['observed_version'])
        if fact['observed_at'] is not None:
            timestamp(fact['observed_at'])
        if fact['source_committed_at'] is not None:
            timestamp(fact['source_committed_at'])
        if fact['reason'] is not None:
            token(fact['reason'])
        if fact['status'] == 'known':
            if fact['observed_version'] is None or type(fact['value']) is not dict:
                raise StreamError('KNOWN_FACT_WITHOUT_SOURCE')
            validate_section_value(section, fact['value'])
        elif fact['value'] is not None:
            raise StreamError('UNKNOWN_FACT_HAS_VALUE')
    # Canonical size/depth bounds are checked before persistence and transport.
    canonical(value)
    return deepcopy(value)


def public_event(event, room_id):
    """One original ledger sequence; all Project-bearing payloads are omitted."""
    if type(event) is not dict or event.get('room_id') != room_id:
        raise StreamError('SOURCE_ROOM_MISMATCH')
    return {'source_owner': 'hub', 'observed_version': sequence(event['room_seq']),
            'kind': token(event['kind']), 'observed_at': timestamp(event['timestamp'])}


class RoomStream:
    """One fixed Room source. Capture is detached before any outbound I/O."""
    def __init__(self, ledger, identity, *, supervisor=None, participants=None, checkouts=None, audit=None, forge=None):
        _identity(identity)
        if type(ledger) is not RoomLedger or ledger.room_id != identity.room_id:
            raise StreamError('SOURCE_ROOM_MISMATCH')
        self.ledger, self.identity = ledger, identity
        # Finite trusted owner integrations, never a callable registry supplied
        # by a frame. Imports avoid making the passive projection depend on OS
        # control modules during ledger-only use.
        self._owners = []
        if supervisor is not None:
            from .lifecycle import Supervisor
            if type(supervisor) is not Supervisor or supervisor.room_id != identity.room_id:
                raise StreamError('SOURCE_OWNER_MISMATCH')
            self._owners.append((supervisor, ('room_lifecycle', 'image_profile_drift')))
        if participants is not None:
            from .participant import FixtureParticipantController
            if type(participants) is not FixtureParticipantController or participants.supervisor is not supervisor:
                raise StreamError('SOURCE_OWNER_MISMATCH')
            self._owners.append((participants, ('seats', 'processes', 'capabilities')))
        if checkouts is not None:
            from .checkouts import CheckoutAllocator
            if type(checkouts) is not CheckoutAllocator or checkouts.supervisor is not supervisor:
                raise StreamError('SOURCE_OWNER_MISMATCH')
            self._owners.append((checkouts, ('checkout_slots',)))
        if audit is not None:
            from .forge_audit import ForgeAudit
            if type(audit) is not ForgeAudit or audit.deployment_id != identity.deployment_id:
                raise StreamError('SOURCE_OWNER_MISMATCH')
            self._owners.append((audit, ('forge_diagnostics',)))
        self._forge = forge
        if forge is not None:
            from .forge import ReadOnlyForgeBroker
            if (type(forge) is not ReadOnlyForgeBroker or forge.ledger is not ledger
                    or forge.binding.room_id != identity.room_id):
                raise StreamError('SOURCE_OWNER_MISMATCH')

    def capture(self, after_seq, *, captured_at, observations=()):
        if after_seq is not None:
            sequence(after_seq)
        owner_observations = list(observations)
        if self._owners:
            from .ledger import LedgerError
            from .lifecycle import LifecycleError
            for owner, sections in self._owners:
                try:
                    values = (owner.manager_observations(self.identity.room_id)
                              if sections == ('forge_diagnostics',) else owner.manager_observations())
                    if tuple(value.section for value in values) != sections:
                        raise StreamError('SOURCE_EXPORT_CONTRACT_CHANGED')
                    owner_observations.extend(values)
                except (LedgerError, LifecycleError):
                    owner_observations.extend(SourceObservation(section, EXTERNAL_FIELDS[section][0],
                        None, None, None, status='unavailable', reason='OWNER_EXPORT_UNAVAILABLE')
                        for section in sections)
        snapshot = self.ledger.snapshot()  # One SQLite statement/cut.
        if self._forge is not None:
            from .ledger import LedgerError
            try:
                owner_observations.extend(self._forge.manager_observations(snapshot))
            except LedgerError:
                owner_observations.append(SourceObservation('dependencies', 'forge-broker', None,
                    None, None, status='unavailable', reason='OWNER_EXPORT_UNAVAILABLE'))
        if after_seq is not None and after_seq > snapshot['room_seq']:
            raise StreamError('SOURCE_CURSOR_REGRESSION')
        projection = project_hub(snapshot, captured_at=captured_at, observations=owner_observations)
        return SnapshotTransfer(self.ledger, self.identity, after_seq, projection)


class SnapshotTransfer:
    def __init__(self, ledger, identity, after_seq, projection):
        self._ledger = ledger
        self.identity, self.after_seq = identity, after_seq
        self._projection = canonical(projection)
        self.cut = projection['room_seq']
        self.transfer_id = hashlib.sha256(canonical({'identity': identity.document(),
            'after_seq': after_seq, 'projection': projection}).encode()).hexdigest()

    def begin(self):
        return {'schema_version': SCHEMA_VERSION, 'transfer_id': self.transfer_id,
                'identity': self.identity.document(), 'after_seq': self.after_seq,
                'projection': json.loads(self._projection)}

    def page(self, after_seq, *, limit=100):
        sequence(after_seq)
        if self.after_seq is None or not self.after_seq <= after_seq <= self.cut:
            raise StreamError('INVALID_TRANSFER_CURSOR')
        events = self._ledger.replay(after_seq, through_seq=self.cut, limit=limit)
        public = [public_event(event, self.identity.room_id) for event in events]
        expected = after_seq + 1
        for event in public:
            if event['observed_version'] != expected:
                raise StreamError('SOURCE_REPLAY_GAP')
            expected += 1
        if not public and after_seq < self.cut:
            raise StreamError('SOURCE_REPLAY_GAP')
        return {'transfer_id': self.transfer_id, 'after_seq': after_seq, 'events': public}


class ManagerReadModel:
    """Durable observation cache, partitioned by authenticated Room identity.

    File path is operator-owned Manager storage, never a Room-supplied path.
    Connections are intentionally not persisted: reopen starts disconnected.
    Source epoch replacement requires a separate explicit operator decision;
    a reconnect or a lower cursor cannot silently replace an existing stream.
    """
    def __init__(self, path, *, stale_after_seconds=30):
        if type(stale_after_seconds) is not int or not 1 <= stale_after_seconds <= 3600:
            raise StreamError('INVALID_STALENESS_POLICY')
        self.stale_after_seconds = stale_after_seconds
        self._sessions = {}
        self._serial = 0
        self._db = None
        try:
            if str(path) == ':memory:':
                raise StreamError('DURABLE_MANAGER_STORE_REQUIRED')
            self._db = sqlite3.connect(path, isolation_level=None)
            self._db.row_factory = sqlite3.Row
            self._db.execute('PRAGMA synchronous=FULL')
            if self._db.execute('PRAGMA journal_mode=WAL').fetchone()[0] != 'wal':
                raise StreamError('DURABLE_MANAGER_STORE_REQUIRED')
            self._db.execute('BEGIN IMMEDIATE')
            objects = self._db.execute("SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall()
            if not objects:
                for statement in _STORE_SCHEMA.values():
                    self._db.execute(statement)
                self._db.execute('INSERT INTO manager_metadata VALUES (1,1)')
            elif ({row['name']: row['sql'] for row in objects if row['type'] == 'table'} != _STORE_SCHEMA
                  or any(row['type'] != 'table' for row in objects)):
                raise StreamError('INVALID_MANAGER_STORE')
            if self._db.execute('SELECT version FROM manager_metadata WHERE singleton=1').fetchone()[0] != 1:
                raise StreamError('UNSUPPORTED_MANAGER_STORE')
            self._db.commit()
        except sqlite3.Error as error:
            self.close()
            raise StreamError('MANAGER_STORAGE_UNAVAILABLE') from error
        except BaseException:
            self.close()
            raise

    def close(self):
        self._sessions.clear()
        if self._db is not None:
            self._db.close()
            self._db = None

    def _room(self, identity):
        _identity(identity)
        row = self._db.execute('SELECT * FROM manager_rooms WHERE deployment=? AND room=?',
                               (identity.deployment_id, identity.room_id)).fetchone()
        if row is not None and row['stream'] != identity.stream_id:
            raise StreamError('ROOM_STREAM_CONFLICT')
        return row

    def connect(self, identity):
        self._room(identity)
        self._serial += 1
        self._sessions[(identity.deployment_id, identity.room_id)] = (identity, self._serial)
        return self._serial

    def _session(self, identity, session):
        _identity(identity)
        if type(session) is not int or self._sessions.get((identity.deployment_id, identity.room_id)) != (identity, session):
            raise StreamError('STALE_MANAGER_CONNECTION')

    def disconnect(self, identity, session):
        self._session(identity, session)
        del self._sessions[(identity.deployment_id, identity.room_id)]

    def cursor(self, identity):
        row = self._room(identity)
        return None if row is None else row['cursor']

    def begin(self, identity, session, frame):
        self._session(identity, session)
        if (type(frame) is not dict or set(frame) != {'schema_version', 'transfer_id', 'identity',
                'after_seq', 'projection'} or type(frame['schema_version']) is not int
                or frame['schema_version'] != SCHEMA_VERSION or frame['identity'] != identity.document()):
            raise StreamError('INVALID_BEGIN')
        projection = validate_projection(frame['projection'], identity.room_id)
        encoded = canonical(projection)
        expected_id = hashlib.sha256(canonical({'identity': identity.document(),
            'after_seq': frame['after_seq'], 'projection': projection}).encode()).hexdigest()
        if frame['transfer_id'] != expected_id:
            raise StreamError('TRANSFER_CONTENT_MISMATCH')
        base, cut = frame['after_seq'], projection['room_seq']
        if base is not None:
            sequence(base)
            if base > cut:
                raise StreamError('SOURCE_CURSOR_REGRESSION')
        row = self._room(identity)
        if base != (None if row is None else row['cursor']):
            raise StreamError('CURSOR_CONFLICT')
        if row is not None and row['projection'] is not None:
            previous = json.loads(row['projection'])
            if cut == row['cursor'] and any(previous['sections'][name] != projection['sections'][name]
                    for name in HUB_SECTIONS - EXTERNAL_FIELDS.keys()):
                raise StreamError('HUB_SNAPSHOT_CONFLICT')
        key = (identity.deployment_id, identity.room_id)
        for section in EXTERNAL_FIELDS:
            new = projection['sections'][section]
            version = new['observed_version']
            old = self._db.execute('SELECT version,fact FROM manager_sources WHERE deployment=? '
                'AND room=? AND section=?', (*key, section)).fetchone()
            if old is not None and version is not None:
                if version < old['version'] or version == old['version'] and canonical(new) != old['fact']:
                    raise StreamError('SOURCE_OBSERVATION_CONFLICT')
        self._db.execute('BEGIN IMMEDIATE')
        try:
            self._db.execute('INSERT OR IGNORE INTO manager_rooms VALUES (?, ?, ?, NULL, NULL)',
                             (*key, identity.stream_id))
            pending = self._db.execute('SELECT * FROM manager_transfers WHERE deployment=? AND room=?', key).fetchone()
            if pending is None or pending['id'] != expected_id:
                self._db.execute('INSERT OR REPLACE INTO manager_transfers VALUES (?, ?, ?, ?, ?, ?, ?)',
                    (*key, expected_id, base, cut, cut if base is None else base, encoded))
            self._db.commit()
        except BaseException:
            self._db.rollback()
            raise
        return expected_id

    def append(self, identity, session, frame):
        self._session(identity, session)
        if (type(frame) is not dict or set(frame) != {'transfer_id', 'after_seq', 'events'}
                or type(frame['events']) is not list or not 1 <= len(frame['events']) <= 1000):
            raise StreamError('INVALID_REPLAY_PAGE')
        after = sequence(frame['after_seq'])
        key = (identity.deployment_id, identity.room_id)
        self._db.execute('BEGIN IMMEDIATE')
        try:
            pending = self._db.execute('SELECT * FROM manager_transfers WHERE deployment=? AND room=?', key).fetchone()
            if pending is None or pending['id'] != frame['transfer_id'] or pending['base'] is None:
                raise StreamError('UNKNOWN_TRANSFER')
            if after < pending['base'] or after > pending['received']:
                raise StreamError('REPLAY_GAP')
            for seq, event in enumerate(frame['events'], after + 1):
                if (type(event) is not dict or set(event) != {'source_owner', 'observed_version',
                        'kind', 'observed_at'} or event['source_owner'] != 'hub'
                        or type(event['observed_version']) is not int or event['observed_version'] != seq
                        or seq > pending['cut']):
                    raise StreamError('INVALID_REPLAY_EVENT')
                token(event['kind']); timestamp(event['observed_at'])
                encoded = canonical(event)
                stored = self._db.execute('SELECT event FROM manager_events WHERE deployment=? '
                    'AND room=? AND stream=? AND seq=?', (*key, identity.stream_id, seq)).fetchone()
                if stored is not None and stored['event'] != encoded:
                    raise StreamError('SOURCE_EVENT_CONFLICT')
                self._db.execute('INSERT OR IGNORE INTO manager_events VALUES (?, ?, ?, ?, ?)',
                                 (*key, identity.stream_id, seq, encoded))
            received = max(pending['received'], after + len(frame['events']))
            self._db.execute('UPDATE manager_transfers SET received=? WHERE deployment=? AND room=?',
                             (received, *key))
            self._db.commit()
            return received
        except BaseException:
            self._db.rollback()
            raise

    def finish(self, identity, session, transfer_id):
        self._session(identity, session)
        key = (identity.deployment_id, identity.room_id)
        self._db.execute('BEGIN IMMEDIATE')
        try:
            pending = self._db.execute('SELECT * FROM manager_transfers WHERE deployment=? AND room=?', key).fetchone()
            if pending is None or pending['id'] != transfer_id:
                raise StreamError('UNKNOWN_TRANSFER')
            if pending['received'] != pending['cut']:
                raise StreamError('REPLAY_INCOMPLETE')
            current = self._room(identity)
            if current['cursor'] != pending['base']:
                raise StreamError('CURSOR_CONFLICT')
            projection = json.loads(pending['projection'])
            if current['projection'] is not None and current['cursor'] == pending['cut']:
                previous = json.loads(current['projection'])
                if any(previous['sections'][name] != projection['sections'][name]
                       for name in HUB_SECTIONS - EXTERNAL_FIELDS.keys()):
                    raise StreamError('HUB_SNAPSHOT_CONFLICT')
            for section in EXTERNAL_FIELDS:
                fact = projection['sections'][section]
                version = fact['observed_version']
                old = self._db.execute('SELECT version,fact FROM manager_sources WHERE deployment=? '
                    'AND room=? AND section=?', (*key, section)).fetchone()
                if old is not None and version is not None and (version < old['version']
                        or version == old['version'] and canonical(fact) != old['fact']):
                    raise StreamError('SOURCE_OBSERVATION_CONFLICT')
            self._db.execute('UPDATE manager_rooms SET cursor=?, projection=? WHERE deployment=? AND room=?',
                             (pending['cut'], pending['projection'], *key))
            for section, fact in projection['sections'].items():
                if section in EXTERNAL_FIELDS and fact['observed_version'] is not None:
                    self._db.execute('INSERT OR REPLACE INTO manager_sources VALUES (?, ?, ?, ?, ?)',
                                     (*key, section, fact['observed_version'], canonical(fact)))
            # The installed cursor is the durable receipt for uncertain ACKs,
            # never a reason to repeat a source workflow operation.
            self._db.execute('DELETE FROM manager_transfers WHERE deployment=? AND room=?', key)
            self._db.commit()
            return pending['cut']
        except BaseException:
            self._db.rollback()
            raise

    def view(self, identity, *, now=None):
        row = self._room(identity)
        if row is None or row['projection'] is None:
            return {'identity': identity.document(), 'status': 'unknown', 'projection': None}
        key = (identity.deployment_id, identity.room_id)
        connected = key in self._sessions
        pending = self._db.execute('SELECT 1 FROM manager_transfers WHERE deployment=? AND room=?', key).fetchone()
        projection = json.loads(row['projection'])
        current_time = datetime.now(timezone.utc) if now is None else datetime.fromisoformat(timestamp(now))
        age = (current_time - datetime.fromisoformat(projection['captured_at'])).total_seconds()
        return {'identity': identity.document(), 'status': 'connected' if connected else 'disconnected',
                'catching_up': pending is not None,
                'projection_stale': not connected or pending is not None or age > self.stale_after_seconds or age < 0,
                'projection': projection}

    def deployments(self):
        result = {}
        for row in self._db.execute('SELECT deployment, room, stream FROM manager_rooms ORDER BY deployment, room'):
            identity = RoomIdentity(row['deployment'], row['room'], row['stream'])
            result.setdefault(identity.deployment_id, []).append(self.view(identity))
        return result
