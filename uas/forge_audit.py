"""Deployment-owned read and assignment audit; no provider effects.

The trusted Broker supplies sanitized metadata and owns authority checks. The
file belongs outside Rooms/Workstations. This store does not establish that OS
boundary. A committed start is permission to attempt once, never to replay.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3

from .ledger import LedgerError, _json, _token


# The v1 assignment tables remain unchanged. v2 adds only read start/terminal
# records to this same Deployment store; it is not a second audit service.
_V1_SCHEMA = {
    'deployment': 'CREATE TABLE deployment (singleton INTEGER PRIMARY KEY CHECK(singleton=1), version INTEGER NOT NULL, id TEXT NOT NULL)',
    'starts': 'CREATE TABLE starts (id TEXT PRIMARY KEY, scope TEXT NOT NULL, metadata TEXT NOT NULL, timestamp TEXT NOT NULL)',
    'prepared': 'CREATE TABLE prepared (id TEXT PRIMARY KEY REFERENCES starts(id), issue_id INTEGER NOT NULL, timestamp TEXT NOT NULL)',
    'terminals': 'CREATE TABLE terminals (id TEXT PRIMARY KEY REFERENCES starts(id), result TEXT NOT NULL, timestamp TEXT NOT NULL)',
    'reconciliation_starts': 'CREATE TABLE reconciliation_starts (seq INTEGER PRIMARY KEY, id TEXT NOT NULL REFERENCES starts(id), reconciliation_id TEXT UNIQUE NOT NULL, timestamp TEXT NOT NULL)',
    'observations': 'CREATE TABLE observations (seq INTEGER PRIMARY KEY, id TEXT NOT NULL REFERENCES starts(id), reconciliation_id TEXT UNIQUE NOT NULL REFERENCES reconciliation_starts(reconciliation_id), observation TEXT NOT NULL, timestamp TEXT NOT NULL)',
}
_READ_SCHEMA = {
    'read_starts': 'CREATE TABLE read_starts (id TEXT PRIMARY KEY, room_id TEXT NOT NULL, metadata TEXT NOT NULL, timestamp TEXT NOT NULL)',
    'read_terminals': 'CREATE TABLE read_terminals (id TEXT PRIMARY KEY REFERENCES read_starts(id), result TEXT NOT NULL, timestamp TEXT NOT NULL)',
}
_READ_METADATA = {'room_id', 'room_instance', 'project_id', 'actor_id',
    'participant_id', 'incarnation_id', 'authority_version', 'provider_host',
    'requested_repository', 'effective_repository', 'route', 'request_digest',
    'origin_digest'}
_READ_STATUSES = frozenset({'OK', 'HELP', 'NOT_FOUND', 'DENIED',
    'PROVIDER_ERROR', 'PROVIDER_FAILURE', 'TIMEOUT', 'OUTPUT_LIMIT',
    'INVALID_RESPONSE', 'INVALID_PROVIDER_OBSERVATION', 'CREDENTIAL_UNAVAILABLE',
    'PAGINATION_LIMIT', 'STALE_PULL', 'INCOMPLETE', 'UNKNOWN',
    'INTERRUPTED_OBSERVATION', 'AUTHORITY_REVOKED', 'PATCH_UNAVAILABLE',
    'CONTENT_UNAVAILABLE', 'UNSUPPORTED_ROUTE', 'INVALID_PROJECT', 'INVALID_SELECTOR',
    'INVALID_READ_PATH', 'WHOLE_RUN_LOG_DENIED', 'PROJECT_MISMATCH', 'READ_CAPACITY',
    'INVALID_LOG_METADATA', 'LOG_NOT_COMPLETED', 'LOG_ATTEMPT_UNVERIFIED',
    'LOG_CANDIDATE_MISMATCH', 'LOG_REDIRECT_DENIED', 'LOG_TRANSFER_INCOMPLETE',
    'INVALID_LOG_REQUEST', 'INVALID_LOG_SCOPE', 'STALE_SOURCE', 'WRONG_PROCESS',
    'PROCESS_EXITED', 'AUTHORITY_STORE_UNAVAILABLE', 'INVALID_AUTHORITY_STORE',
    'CONTROLLER_REPLACED', 'ROOM_NOT_RUNNING', 'ROOM_REPLACED', 'FORBIDDEN',
    'INVALID_PROCESS_RECORD', 'INVALID_FORGE_ENVELOPE', 'INVALID_NATIVE_FRAME',
    'MISSING_ACTOR_CREDENTIAL'})
READ_AUDIT_STATUSES = _READ_STATUSES
_SHA256 = re.compile(r'[0-9a-f]{64}\Z')
_REPOSITORY = re.compile(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\Z')


def _schema(db, expected):
    # Refuse an arbitrary database with merely familiar table names. These are
    # the exact schemas emitted by the previous version and this version.
    objects = db.execute("SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall()
    actual = {r['name']: r['sql'] for r in objects if r['type'] == 'table'}
    if actual != expected or any(r['type'] not in {'table', 'index'} for r in objects):
        raise LedgerError('INVALID_STORE')
    indexes = {r['name']: r['sql'] for r in objects if r['type'] == 'index'}
    if indexes != {'scope_idx': 'CREATE INDEX scope_idx ON starts(scope)'}:
        raise LedgerError('INVALID_STORE')
    if db.execute('PRAGMA foreign_key_check').fetchone() is not None:
        raise LedgerError('INVALID_STORE')


def _read_metadata(value):
    if type(value) is not dict or set(value) != _READ_METADATA:
        raise LedgerError('INVALID_FORGE_AUDIT')
    for key in ('room_id', 'room_instance', 'project_id', 'actor_id',
                'participant_id', 'incarnation_id', 'authority_version'):
        _token(value[key])
    if (value['provider_host'] != 'github.com'
            or type(value['route']) is not str
            or not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', value['route'])
            or any(type(value[key]) is not str or not _REPOSITORY.fullmatch(value[key])
                   or value[key].split('/')[1] in {'.', '..'}
                   for key in ('requested_repository', 'effective_repository'))
            or any(type(value[key]) is not str or not _SHA256.fullmatch(value[key])
                   for key in ('request_digest', 'origin_digest'))):
        raise LedgerError('INVALID_FORGE_AUDIT')
    return json.loads(_json(value))


def _read_result(value):
    if (type(value) is not dict or set(value) != {'status', 'completeness', 'contact',
            'output_bytes', 'dropped_bytes', 'observation_digest'}
            or type(value['status']) is not str or value['status'] not in _READ_STATUSES
            or type(value['completeness']) is not str
            or value['completeness'] not in {'complete', 'incomplete', 'unknown'}
            or type(value['contact']) is not str or value['contact'] not in {'none', 'read', 'unknown'}
            or type(value['output_bytes']) is not int or not 0 <= value['output_bytes'] <= 1048576
            or (value['dropped_bytes'] is not None and (type(value['dropped_bytes']) is not int
                or not 0 <= value['dropped_bytes'] <= 2**63 - 1))
            or (value['observation_digest'] is not None and (type(value['observation_digest']) is not str
                or not _SHA256.fullmatch(value['observation_digest'])))):
        raise LedgerError('INVALID_FORGE_AUDIT')
    if ((value['status'] in {'OK', 'HELP'}) != (value['completeness'] == 'complete')
            or (value['completeness'] == 'complete' and
                (value['observation_digest'] is None or value['dropped_bytes'] is None))
            or (value['completeness'] != 'complete' and value['dropped_bytes'] is not None)
            or (value['status'] == 'OK' and value['contact'] != 'read')
            or (value['status'] == 'NOT_FOUND' and value['completeness'] != 'unknown')
            or (value['status'] == 'DENIED' and (value['contact'] != 'none'
                or value['completeness'] != 'unknown' or value['output_bytes'] != 0))
            or (value['status'] == 'INTERRUPTED_OBSERVATION' and value['contact'] != 'unknown')
            or (value['status'] == 'HELP' and value['contact'] != 'none')
            or (value['status'] in {'INTERRUPTED_OBSERVATION', 'UNKNOWN'} and
                (value['completeness'] != 'unknown' or value['output_bytes'] != 0
                 or value['observation_digest'] is not None))):
        raise LedgerError('INVALID_FORGE_AUDIT')
    return json.loads(_json(value))


_METADATA = {'room_id', 'project_id', 'repository', 'actor_id', 'participant_id',
             'incarnation_id', 'authority_version', 'issue_number',
             'github_user_id', 'request_digest'}


def _positive(value):
    return type(value) is int and 1 <= value <= 2**63 - 1


def _metadata(value):
    if type(value) is not dict or set(value) != _METADATA:
        raise LedgerError('INVALID_FORGE_AUDIT')
    for key in _METADATA - {'repository', 'issue_number', 'github_user_id', 'request_digest'}:
        _token(value[key])
    if (type(value['repository']) is not str or not re.fullmatch(
            r'[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', value['repository'])
            or not _positive(value['issue_number']) or value['issue_number'] > 9_999_999_999
            or not _positive(value['github_user_id'])
            or type(value['request_digest']) is not str
            or not re.fullmatch('[0-9a-f]{64}', value['request_digest'])):
        raise LedgerError('INVALID_FORGE_AUDIT')
    return json.loads(_json(value))


def _result(value, *, reconciliation=False, issue_id=None):
    statuses = ({'MATCHED', 'ABSENT', 'CONFLICT', 'UNKNOWN'} if reconciliation else
                {'ASSIGNED', 'ALREADY_ASSIGNED', 'ASSIGNMENT_CONFLICT', 'ISSUE_NOT_ELIGIBLE',
                 'ACTOR_MISMATCH', 'UNKNOWN_OUTCOME', 'PROVIDER_FAILURE', 'NOT_EXECUTED'})
    if (type(value) is not dict or set(value) != {'status', 'issue_id', 'observed_assignee_ids',
                                               'confirmed_fields', 'contact', 'attribution'}
            or type(value['status']) is not str or value['status'] not in statuses
            or type(value['contact']) is not str or value['contact'] not in {'none', 'read', 'write-possible'}
            or type(value['attribution']) is not str or value['attribution'] not in {'confirmed-response', 'observed-only', 'unknown'}
            or type(value['confirmed_fields']) is not list or value['confirmed_fields'] not in ([], ['add-assignee'])
            or (value['issue_id'] is not None and not _positive(value['issue_id']))
            or type(value['observed_assignee_ids']) is not list
            or len(value['observed_assignee_ids']) > 100
            or any(not _positive(v) for v in value['observed_assignee_ids'])
            or value['observed_assignee_ids'] != sorted(set(value['observed_assignee_ids']))):
        raise LedgerError('INVALID_FORGE_AUDIT')
    if value['issue_id'] is not None and issue_id is not None and value['issue_id'] != issue_id:
        raise LedgerError('INVALID_FORGE_AUDIT')
    if reconciliation:
        if value['confirmed_fields'] or value['attribution'] != 'observed-only' or value['contact'] != 'read':
            raise LedgerError('INVALID_FORGE_AUDIT')
    elif value['confirmed_fields']:
        if value['status'] != 'ASSIGNED' or value['contact'] != 'write-possible' or value['attribution'] != 'confirmed-response':
            raise LedgerError('INVALID_FORGE_AUDIT')
    elif value['status'] == 'ASSIGNED':
        raise LedgerError('INVALID_FORGE_AUDIT')
    if value['status'] == 'NOT_EXECUTED' and (value['contact'] == 'write-possible' or issue_id is not None
            or value['confirmed_fields'] or value['issue_id'] is not None or value['observed_assignee_ids']):
        raise LedgerError('INVALID_FORGE_AUDIT')
    if value['contact'] == 'write-possible' and issue_id is None:
        raise LedgerError('INVALID_FORGE_AUDIT')
    return json.loads(_json(value))


def _observation(value, metadata, issue_id):
    value = _result(value, reconciliation=True, issue_id=issue_id)
    if value['status'] == 'UNKNOWN':
        if value['observed_assignee_ids']:
            raise LedgerError('INVALID_FORGE_AUDIT')
    else:
        if not _positive(value['issue_id']) or (issue_id is not None and value['issue_id'] != issue_id):
            raise LedgerError('INVALID_FORGE_AUDIT')
        expected = ('ABSENT' if not value['observed_assignee_ids'] else
                    'MATCHED' if value['observed_assignee_ids'] == [metadata['github_user_id']] else 'CONFLICT')
        if value['status'] != expected:
            raise LedgerError('INVALID_FORGE_AUDIT')
    return value


class ForgeAudit:
    """Append-only start, terminal and reconciliation facts for one Deployment.

    get() is a trusted Broker inspection seam, not a public receipt endpoint.
    The caller must authenticate and compare stored binding before disclosure.
    """
    def __init__(self, path, deployment_id):
        self.deployment_id = _token(deployment_id)
        self._db = None
        self._read_failed = False
        try:
            if str(Path(path)) == ':memory:':
                raise LedgerError('INVALID_STORE')
            self._db = sqlite3.connect(Path(path), timeout=5, isolation_level=None)
            self._db.row_factory = sqlite3.Row
            self._db.execute('PRAGMA foreign_keys=ON')
            self._db.execute('PRAGMA synchronous=FULL')
            if self._db.execute('PRAGMA journal_mode=WAL').fetchone()[0] != 'wal':
                raise LedgerError('INVALID_STORE')
            self._db.execute('BEGIN IMMEDIATE')
            tables = {r[0] for r in self._db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            if not tables:
                for statement in _V1_SCHEMA.values():
                    self._db.execute(statement)
                self._db.execute('CREATE INDEX scope_idx ON starts(scope)')
                self._db.execute('INSERT INTO deployment VALUES(1, 1, ?)', (deployment_id,))
            row = self._db.execute('SELECT version,id FROM deployment WHERE singleton=1').fetchone()
            if row is None or row['id'] != deployment_id or row['version'] not in {1, 2}:
                raise LedgerError('DEPLOYMENT_MISMATCH')
            if row['version'] == 1:
                _schema(self._db, _V1_SCHEMA)
                for statement in _READ_SCHEMA.values():
                    self._db.execute(statement)
                self._db.execute('UPDATE deployment SET version=2 WHERE singleton=1')
            _schema(self._db, {**_V1_SCHEMA, **_READ_SCHEMA})
            self._db.commit()
        except (sqlite3.Error, OSError) as error:
            self.close()
            raise LedgerError('AUDIT_UNAVAILABLE') from error
        except BaseException:
            self.close()
            raise

    def close(self):
        if self._db is not None:
            self._db.close()
            self._db = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _connection(self):
        if self._db is None:
            raise LedgerError('AUDIT_UNAVAILABLE')
        return self._db

    def _commit(self):
        self._connection().commit()

    @staticmethod
    def _now():
        return datetime.now(timezone.utc).isoformat()

    def _get(self, db, operation_id):
        row = db.execute('SELECT metadata,timestamp FROM starts WHERE id=?', (operation_id,)).fetchone()
        if row is None:
            return None
        prepared = db.execute('SELECT issue_id FROM prepared WHERE id=?', (operation_id,)).fetchone()
        result = db.execute('SELECT result,timestamp FROM terminals WHERE id=?', (operation_id,)).fetchone()
        observations = db.execute('SELECT s.reconciliation_id,o.observation,o.timestamp,s.timestamp AS started_at FROM reconciliation_starts s LEFT JOIN observations o ON o.reconciliation_id=s.reconciliation_id WHERE s.id=? ORDER BY s.seq', (operation_id,)).fetchall()
        return {'operation_id': operation_id, 'deployment_id': self.deployment_id,
                'metadata': json.loads(row['metadata']), 'started_at': row['timestamp'],
                'issue_id': (prepared['issue_id'] if prepared is not None else
                             None if result is None else json.loads(result['result'])['issue_id']),
                'result': None if result is None else json.loads(result['result']),
                'finished_at': None if result is None else result['timestamp'],
                'reconciliations': [{'id': r['reconciliation_id'], 'observation': None if r['observation'] is None else json.loads(r['observation']),
                                     'started_at': r['started_at'], 'timestamp': r['timestamp']} for r in observations]}

    def get(self, operation_id):
        _token(operation_id)
        db = self._connection()
        try:
            db.execute('BEGIN')
            record = self._get(db, operation_id)
            db.rollback()
            return record
        except sqlite3.Error as error:
            db.rollback()
            raise LedgerError('AUDIT_UNAVAILABLE') from error

    def pending(self, room_id):
        """Trusted supervisor inspection, never a public receipt-disclosure API.

        Refuse oversized recovery rather than silently omit an unfinished write.
        The controller must establish fencing before terminalizing any record.
        """
        _token(room_id)
        db = self._connection()
        try:
            db.execute('BEGIN')
            rows = db.execute("SELECT s.id FROM starts s LEFT JOIN terminals t ON t.id=s.id "
                "WHERE t.id IS NULL AND json_extract(s.metadata, '$.room_id')=? ORDER BY s.rowid LIMIT 257",
                (room_id,)).fetchall()
            if len(rows) > 256:
                raise LedgerError('FORGE_RECOVERY_CAPACITY')
            records = [self._get(db, row['id']) for row in rows]
            db.rollback()
            return records
        except sqlite3.Error as error:
            db.rollback()
            raise LedgerError('AUDIT_UNAVAILABLE') from error
        except BaseException:
            db.rollback()
            raise

    def _read_get(self, db, operation_id):
        row = db.execute('SELECT room_id,metadata,timestamp FROM read_starts WHERE id=?',
                         (operation_id,)).fetchone()
        if row is None:
            return None
        terminal = db.execute('SELECT result,timestamp FROM read_terminals WHERE id=?',
                              (operation_id,)).fetchone()
        try:
            metadata = _read_metadata(json.loads(row['metadata']))
            if metadata['room_id'] != row['room_id'] or row['metadata'] != _json(metadata):
                raise ValueError()
            result = None if terminal is None else _read_result(json.loads(terminal['result']))
            if terminal is not None and terminal['result'] != _json(result):
                raise ValueError()
            for stamp in (row['timestamp'], None if terminal is None else terminal['timestamp']):
                if stamp is not None and (type(stamp) is not str or len(stamp) > 64
                        or datetime.fromisoformat(stamp).tzinfo is None):
                    raise ValueError()
            return {'operation_id': operation_id, 'deployment_id': self.deployment_id,
                    'metadata': metadata, 'started_at': row['timestamp'],
                    'result': result, 'finished_at': None if terminal is None else terminal['timestamp']}
        except (ValueError, TypeError, KeyError, RecursionError, LedgerError) as error:
            self._read_failed = True
            raise LedgerError('AUDIT_UNAVAILABLE') from error

    def read_record(self, operation_id):
        """Trusted exact read inspection; caller authenticates before disclosure.

        Read payloads never live in this journal. A terminal contains only its
        outcome, counts and digest; the response owner retains any retry receipt.
        """
        _token(operation_id)
        db = self._connection()
        try:
            db.execute('BEGIN')
            record = self._read_get(db, operation_id)
            db.rollback()
            return record
        except sqlite3.Error as error:
            db.rollback()
            raise LedgerError('AUDIT_UNAVAILABLE') from error
        except BaseException:
            db.rollback()
            raise

    def pending_reads(self, room_id):
        """Bounded recovery inventory, not permission to repeat provider calls.

        The trusted controller must establish loss/fencing of the old owner
        before recording an interrupted outcome. Pending can also mean in flight.
        """
        _token(room_id)
        db = self._connection()
        try:
            db.execute('BEGIN')
            rows = db.execute('SELECT s.id FROM read_starts s LEFT JOIN read_terminals t ON t.id=s.id '
                'WHERE t.id IS NULL AND s.room_id=? ORDER BY s.rowid LIMIT 257', (room_id,)).fetchall()
            if len(rows) > 256:
                raise LedgerError('FORGE_RECOVERY_CAPACITY')
            records = [self._read_get(db, row['id']) for row in rows]
            db.rollback()
            return records
        except sqlite3.Error as error:
            db.rollback()
            raise LedgerError('AUDIT_UNAVAILABLE') from error
        except BaseException:
            db.rollback()
            raise

    def begin_read(self, operation_id, metadata):
        """Commit sanitized read intent; only started=True permits one contact.

        The caller supplies current kernel/process authority and a full Origin
        digest. All attribution and route fields are compared on exact retries.
        No callback, provider, network endpoint or response content is stored.
        """
        _token(operation_id)
        metadata = _read_metadata(metadata)
        if self._read_failed:
            raise LedgerError('AUDIT_UNAVAILABLE')
        db = self._connection()
        try:
            db.execute('BEGIN IMMEDIATE')
            if (db.execute('SELECT 1 FROM starts WHERE id=?', (operation_id,)).fetchone()
                    or db.execute('SELECT 1 FROM reconciliation_starts WHERE reconciliation_id=?',
                                  (operation_id,)).fetchone()):
                raise LedgerError('ID_CONFLICT')
            prior = self._read_get(db, operation_id)
            if prior is not None:
                if prior['metadata'] != metadata:
                    raise LedgerError('ID_CONFLICT')
                db.rollback()
                return {'started': False, 'record': prior}
            count = db.execute('SELECT count(*) FROM read_starts s LEFT JOIN read_terminals t ON t.id=s.id '
                'WHERE t.id IS NULL AND s.room_id=?', (metadata['room_id'],)).fetchone()[0]
            if count >= 256:
                raise LedgerError('FORGE_RECOVERY_CAPACITY')
            db.execute('INSERT INTO read_starts VALUES(?,?,?,?)',
                       (operation_id, metadata['room_id'], _json(metadata), self._now()))
            record = self._read_get(db, operation_id)
            self._commit()
            return {'started': True, 'record': record}
        except sqlite3.Error as error:
            self._read_failed = True
            db.rollback()
            raise LedgerError('AUDIT_UNAVAILABLE') from error
        except BaseException:
            db.rollback()
            raise

    def finish_read(self, operation_id, result):
        """Commit a metadata-only terminal before a response is acknowledged.

        A failed/lost commit acknowledgement fences further read effects in this
        owner. A new trusted owner may inspect the exact durable state, but no
        missing acknowledgement permits repeating a provider invocation.
        """
        _token(operation_id)
        result = _read_result(result)
        if self._read_failed:
            raise LedgerError('AUDIT_UNAVAILABLE')
        db = self._connection()
        try:
            db.execute('BEGIN IMMEDIATE')
            record = self._read_get(db, operation_id)
            if record is None:
                raise LedgerError('FORGE_AUDIT_NOT_FOUND')
            if result['status'] == 'HELP' and record['metadata']['route'] != 'help':
                raise LedgerError('INVALID_FORGE_AUDIT')
            if record['result'] is not None:
                if record['result'] != result:
                    raise LedgerError('ID_CONFLICT')
                db.rollback()
                return record
            db.execute('INSERT INTO read_terminals VALUES(?,?,?)',
                       (operation_id, _json(result), self._now()))
            record = self._read_get(db, operation_id)
            self._commit()
            return record
        except sqlite3.Error as error:
            self._read_failed = True
            db.rollback()
            raise LedgerError('AUDIT_UNAVAILABLE') from error
        except BaseException:
            db.rollback()
            raise

    def begin(self, operation_id, metadata):
        _token(operation_id)
        metadata = _metadata(metadata)
        canonical = _json(metadata)
        # Case-insensitive GitHub repository identity. Cross-Room and changed
        # participant incarnations cannot bypass an unresolved Actor issue write.
        scope = hashlib.sha256(_json([metadata['repository'].lower(), metadata['issue_number'],
                                      metadata['actor_id']]).encode()).hexdigest()
        db = self._connection()
        try:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT 1 FROM read_starts WHERE id=?', (operation_id,)).fetchone():
                raise LedgerError('ID_CONFLICT')
            prior = self._get(db, operation_id)
            if prior is not None:
                if prior['metadata'] != metadata:
                    raise LedgerError('ID_CONFLICT')
                db.rollback()
                return {'started': False, 'record': prior}
            for row in db.execute('SELECT id FROM starts WHERE scope=?', (scope,)).fetchall():
                existing = self._get(db, row['id'])
                result = existing['result']
                if result is None or result['status'] == 'UNKNOWN_OUTCOME':
                    observations = existing['reconciliations']
                    if (result is None or not observations or observations[-1]['observation'] is None
                            or observations[-1]['observation']['status'] == 'UNKNOWN'):
                        raise LedgerError('FORGE_RECONCILIATION_REQUIRED')
            db.execute('INSERT INTO starts VALUES(?,?,?,?)', (operation_id, scope, canonical, self._now()))
            record = self._get(db, operation_id)
            self._commit()
            return {'started': True, 'record': record}
        except sqlite3.Error as error:
            db.rollback()
            raise LedgerError('AUDIT_UNAVAILABLE') from error
        except BaseException:
            db.rollback()
            raise

    def prepared(self, operation_id, issue_id):
        """Bind the validated immutable issue identity before any POST attempt."""
        _token(operation_id)
        if not _positive(issue_id):
            raise LedgerError('INVALID_FORGE_AUDIT')
        db = self._connection()
        try:
            db.execute('BEGIN IMMEDIATE')
            record = self._get(db, operation_id)
            if record is None:
                raise LedgerError('FORGE_AUDIT_NOT_FOUND')
            if record['issue_id'] is not None:
                if record['issue_id'] != issue_id:
                    raise LedgerError('ID_CONFLICT')
                db.rollback()
                return record
            if record['result'] is not None:
                raise LedgerError('FORGE_AUDIT_TERMINAL')
            db.execute('INSERT INTO prepared VALUES(?,?,?)', (operation_id, issue_id, self._now()))
            record = self._get(db, operation_id)
            self._commit()
            return record
        except sqlite3.Error as error:
            db.rollback()
            raise LedgerError('AUDIT_UNAVAILABLE') from error
        except BaseException:
            db.rollback()
            raise

    def finish(self, operation_id, result):
        _token(operation_id)
        db = self._connection()
        try:
            db.execute('BEGIN IMMEDIATE')
            record = self._get(db, operation_id)
            if record is None:
                raise LedgerError('FORGE_AUDIT_NOT_FOUND')
            result = _result(result, issue_id=record['issue_id'])
            if result['status'] in {'ASSIGNED', 'ALREADY_ASSIGNED'}:
                if (not _positive(result['issue_id'])
                        or result['observed_assignee_ids'] != [record['metadata']['github_user_id']]):
                    raise LedgerError('INVALID_FORGE_AUDIT')
                if result['status'] == 'ALREADY_ASSIGNED' and (
                        result['contact'] != 'read' or result['attribution'] != 'observed-only'
                        or result['confirmed_fields']):
                    raise LedgerError('INVALID_FORGE_AUDIT')
            if record['result'] is not None:
                if record['result'] != result:
                    raise LedgerError('ID_CONFLICT')
                db.rollback()
                return record
            db.execute('INSERT INTO terminals VALUES(?,?,?)', (operation_id, _json(result), self._now()))
            record = self._get(db, operation_id)
            self._commit()
            return record
        except sqlite3.Error as error:
            db.rollback()
            raise LedgerError('AUDIT_UNAVAILABLE') from error
        except BaseException:
            db.rollback()
            raise

    def begin_reconciliation(self, operation_id, reconciliation_id):
        """Commit one bounded read intent before provider contact; no replay grant."""
        _token(operation_id)
        _token(reconciliation_id)
        db = self._connection()
        try:
            db.execute('BEGIN IMMEDIATE')
            record = self._get(db, operation_id)
            if record is None:
                raise LedgerError('FORGE_AUDIT_NOT_FOUND')
            if db.execute('SELECT 1 FROM read_starts WHERE id=?', (reconciliation_id,)).fetchone():
                raise LedgerError('ID_CONFLICT')
            prior = db.execute('SELECT id FROM reconciliation_starts WHERE reconciliation_id=?',
                               (reconciliation_id,)).fetchone()
            if prior is not None:
                if prior['id'] != operation_id:
                    raise LedgerError('ID_CONFLICT')
                db.rollback()
                return {'started': False, 'record': record}
            if len(record['reconciliations']) >= 32:
                raise LedgerError('FORGE_RECONCILIATION_CAPACITY')
            db.execute('INSERT INTO reconciliation_starts(id,reconciliation_id,timestamp) VALUES(?,?,?)',
                       (operation_id, reconciliation_id, self._now()))
            record = self._get(db, operation_id)
            self._commit()
            return {'started': True, 'record': record}
        except sqlite3.Error as error:
            db.rollback()
            raise LedgerError('AUDIT_UNAVAILABLE') from error
        except BaseException:
            db.rollback()
            raise

    def reconcile(self, operation_id, reconciliation_id, observation):
        _token(operation_id)
        _token(reconciliation_id)
        db = self._connection()
        try:
            db.execute('BEGIN IMMEDIATE')
            record = self._get(db, operation_id)
            if record is None:
                raise LedgerError('FORGE_AUDIT_NOT_FOUND')
            start = db.execute('SELECT id FROM reconciliation_starts WHERE reconciliation_id=?', (reconciliation_id,)).fetchone()
            if start is None:
                raise LedgerError('FORGE_RECONCILIATION_NOT_STARTED')
            if start['id'] != operation_id:
                raise LedgerError('ID_CONFLICT')
            observation = _observation(observation, record['metadata'], record['issue_id'])
            prior = db.execute('SELECT id,observation FROM observations WHERE reconciliation_id=?', (reconciliation_id,)).fetchone()
            if prior is not None:
                if prior['id'] != operation_id or json.loads(prior['observation']) != observation:
                    raise LedgerError('ID_CONFLICT')
                db.rollback()
                return record
            db.execute('INSERT INTO observations(id,reconciliation_id,observation,timestamp) VALUES(?,?,?,?)',
                       (operation_id, reconciliation_id, _json(observation), self._now()))
            record = self._get(db, operation_id)
            self._commit()
            return record
        except sqlite3.Error as error:
            db.rollback()
            raise LedgerError('AUDIT_UNAVAILABLE') from error
        except BaseException:
            db.rollback()
            raise
