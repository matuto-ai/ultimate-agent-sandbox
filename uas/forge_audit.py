"""Deployment-owned read and mutation audit; no provider effects.

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
# records to this same Deployment store; v3 adds bounded multi-step mutations.
# No migration rewrites historical assignment or read records.
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
_MUTATION_SCHEMA = {
    'mutation_starts': 'CREATE TABLE mutation_starts (id TEXT PRIMARY KEY, room_id TEXT NOT NULL, repository TEXT NOT NULL, metadata TEXT NOT NULL, timestamp TEXT NOT NULL)',
    'mutation_prepared': 'CREATE TABLE mutation_prepared (id TEXT NOT NULL REFERENCES mutation_starts(id), step INTEGER NOT NULL, target TEXT NOT NULL, timestamp TEXT NOT NULL, PRIMARY KEY(id,step))',
    'mutation_confirmed': 'CREATE TABLE mutation_confirmed (id TEXT NOT NULL, step INTEGER NOT NULL, fields TEXT NOT NULL, object TEXT NOT NULL, timestamp TEXT NOT NULL, PRIMARY KEY(id,step), FOREIGN KEY(id,step) REFERENCES mutation_prepared(id,step))',
    'mutation_rejected': 'CREATE TABLE mutation_rejected (id TEXT NOT NULL, step INTEGER NOT NULL, error_code TEXT NOT NULL, timestamp TEXT NOT NULL, PRIMARY KEY(id,step), FOREIGN KEY(id,step) REFERENCES mutation_prepared(id,step))',
    'mutation_terminals': 'CREATE TABLE mutation_terminals (id TEXT PRIMARY KEY REFERENCES mutation_starts(id), result TEXT NOT NULL, timestamp TEXT NOT NULL)',
}
_RECONCILIATION_SCHEMA = {
    'projection_plans': 'CREATE TABLE projection_plans (id TEXT PRIMARY KEY REFERENCES mutation_starts(id), plan TEXT NOT NULL)',
    'mutation_intents': 'CREATE TABLE mutation_intents (id TEXT NOT NULL, step INTEGER NOT NULL, intent TEXT NOT NULL, PRIMARY KEY(id,step), FOREIGN KEY(id,step) REFERENCES mutation_prepared(id,step))',
    'mutation_reconciliation_starts': 'CREATE TABLE mutation_reconciliation_starts (seq INTEGER PRIMARY KEY, id TEXT NOT NULL REFERENCES mutation_starts(id), reconciliation_id TEXT UNIQUE NOT NULL, metadata TEXT NOT NULL, timestamp TEXT NOT NULL)',
    'mutation_observations': 'CREATE TABLE mutation_observations (reconciliation_id TEXT PRIMARY KEY REFERENCES mutation_reconciliation_starts(reconciliation_id), observation TEXT NOT NULL, timestamp TEXT NOT NULL)',
}
_MUTATION_METADATA = {'room_id', 'room_instance', 'project_id', 'repository',
    'actor_id', 'participant_id', 'incarnation_id', 'authority_version',
    'github_user_id', 'provider_host', 'route', 'request_digest', 'origin_digest'}
MUTATION_FIELDS = frozenset({'create', 'title', 'body', 'state', 'add-assignee',
    'remove-assignee', 'add-label', 'remove-label', 'dependency', 'remove-dependency',
    'comment', 'reply', 'review', 'base', 'head', 'draft'})
_MUTATION_ROUTES = frozenset({'issue-create', 'issue-edit', 'issue-close', 'issue-reopen',
    'issue-comment', 'pr-create', 'pr-edit', 'pr-close', 'pr-reopen', 'pr-comment',
    'pr-reply', 'pr-review', 'dependency-add', 'dependency-remove', 'hub-projection', 'denied'})
_MUTATION_STATUSES = frozenset({'OK', 'PARTIAL_MUTATION', 'UNKNOWN_OUTCOME',
    'NOT_EXECUTED', 'PROVIDER_FAILURE', 'DENIED'})
_MUTATION_ERRORS = frozenset({'TIMEOUT_BEFORE_CONTACT', 'AUTHORITY_REVOKED_BEFORE_CONTACT', 'INVALID_RESPONSE', 'OUTPUT_LIMIT', 'TIMEOUT',
    'ACTOR_MISMATCH', 'PROVIDER_ERROR', 'FORBIDDEN', 'STALE_PULL', 'INVALID_TARGET',
    'NOT_FOUND', 'DEPENDENCY_CONFLICT', 'UNSUPPORTED_ROUTE', 'PROJECT_MISMATCH',
    'BODY_LIMIT', 'INVALID_SELECTOR', 'INVALID_ARGUMENT', 'OWNERSHIP_DENIED',
    'LIFECYCLE_LABEL_DENIED', 'ASSIGNMENT_CONFLICT', 'AUDIT_UNAVAILABLE',
    'AUTHORITY_REVOKED', 'PROCESS_EXITED', 'MISSING_ACTOR_CREDENTIAL',
    'ROOM_NOT_RUNNING', 'ROOM_REPLACED', 'CONTROLLER_REPLACED',
    'INTERRUPTED_MUTATION', 'CREDENTIAL_UNAVAILABLE'})
_MUTATION_REJECTIONS = frozenset({'TIMEOUT_BEFORE_CONTACT', 'AUTHORITY_REVOKED_BEFORE_CONTACT', 'PROVIDER_ERROR', 'FORBIDDEN', 'NOT_FOUND',
    'INVALID_ARGUMENT', 'ASSIGNMENT_CONFLICT', 'DEPENDENCY_CONFLICT', 'OWNERSHIP_DENIED'})
_MUTATION_KINDS = frozenset({'repository', 'issue', 'pull', 'comment', 'review'})

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


def _mutation_metadata(value):
    if type(value) is not dict or set(value) != _MUTATION_METADATA:
        raise LedgerError('INVALID_FORGE_AUDIT')
    for key in ('room_id', 'room_instance', 'project_id', 'actor_id',
                'participant_id', 'incarnation_id', 'authority_version'):
        if type(value[key]) is not str:
            raise LedgerError('INVALID_FORGE_AUDIT')
        _token(value[key])
    if (value['provider_host'] != 'github.com'
            or type(value['route']) is not str or value['route'] not in _MUTATION_ROUTES
            or type(value['repository']) is not str or not _REPOSITORY.fullmatch(value['repository'])
            or value['repository'].split('/')[1] in {'.', '..'}
            or not _positive(value['github_user_id'])
            or any(type(value[key]) is not str or not _SHA256.fullmatch(value[key])
                   for key in ('request_digest', 'origin_digest'))):
        raise LedgerError('INVALID_FORGE_AUDIT')
    return json.loads(_json(value))


def _mutation_object(value, *, related=False):
    shapes = ({'kind', 'id'}, {'kind', 'id', 'number'})
    if related:
        shapes += ({'kind', 'id', 'number', 'related_id', 'related_number'},)
    if (type(value) is not dict or set(value) not in shapes
            or type(value['kind']) is not str or value['kind'] not in _MUTATION_KINDS
            or not _positive(value['id'])
            or ('number' in value and (value['kind'] not in {'issue', 'pull'}
                or not _positive(value['number'])))):
        raise LedgerError('INVALID_FORGE_AUDIT')
    if 'related_id' in value and (value['kind'] != 'issue'
            or not _positive(value['related_id']) or not _positive(value['related_number'])
            or value['related_id'] == value['id'] or value['related_number'] == value['number']):
        raise LedgerError('INVALID_FORGE_AUDIT')
    return json.loads(_json(value))


def _mutation_fields(value, *, empty=False):
    if (type(value) is not list or not (0 if empty else 1) <= len(value) <= len(MUTATION_FIELDS)
            or any(type(item) is not str or item not in MUTATION_FIELDS for item in value)
            or len(set(value)) != len(value)):
        raise LedgerError('INVALID_FORGE_AUDIT')
    return list(value)


def _mutation_result(value):
    if (type(value) is not dict or set(value) != {'status', 'confirmed_fields', 'objects',
            'contact', 'failed_field', 'error_code'}
            or type(value['status']) is not str or value['status'] not in _MUTATION_STATUSES
            or type(value['contact']) is not str or value['contact'] not in {'none', 'read', 'write-possible'}
            or (value['failed_field'] is not None and (type(value['failed_field']) is not str
                or value['failed_field'] not in MUTATION_FIELDS))
            or (value['error_code'] is not None and (type(value['error_code']) is not str
                or value['error_code'] not in _MUTATION_ERRORS))
            or type(value['objects']) is not list or len(value['objects']) > 32):
        raise LedgerError('INVALID_FORGE_AUDIT')
    _mutation_fields(value['confirmed_fields'], empty=True)
    objects = [_mutation_object(item) for item in value['objects']]
    if len({_json(item) for item in objects}) != len(objects):
        raise LedgerError('INVALID_FORGE_AUDIT')
    status, fields = value['status'], value['confirmed_fields']
    if ((status in {'OK', 'PARTIAL_MUTATION'} and not fields)
            or (status in {'NOT_EXECUTED', 'PROVIDER_FAILURE', 'DENIED'} and (fields or objects))
            or (fields and value['contact'] != 'write-possible')
            or (status == 'OK' and (value['failed_field'] is not None or value['error_code'] is not None))
            or (status == 'UNKNOWN_OUTCOME' and value['contact'] != 'write-possible')
            or (status in {'NOT_EXECUTED', 'DENIED'} and value['contact'] == 'write-possible')):
        raise LedgerError('INVALID_FORGE_AUDIT')
    return json.loads(_json(value))


def _mutation_aggregate(steps):
    fields, objects = [], []
    for row in steps:
        if row['fields'] is None:
            continue
        for name in row['fields']:
            if name not in fields:
                fields.append(name)
        if row['object'] not in objects:
            objects.append(row['object'])
    return fields, objects


def _mutation_terminal_valid(result, steps):
    fields, objects = _mutation_aggregate(steps)
    if (result['confirmed_fields'] != fields or result['objects'] != objects
            or (any(row['error_code'] not in {'AUTHORITY_REVOKED_BEFORE_CONTACT','TIMEOUT_BEFORE_CONTACT'} for row in steps)
                != (result['contact'] == 'write-possible'))
            or (result['status'] == 'OK' and any(row['fields'] is None for row in steps))
            or (steps and steps[-1]['error_code'] is not None
                and (result['error_code'] != steps[-1]['error_code']
                    or result['status'] not in {'PARTIAL_MUTATION', 'PROVIDER_FAILURE'}))):
        raise LedgerError('INVALID_FORGE_AUDIT')


def _mutation_stamp(value):
    if (type(value) is not str or len(value) > 64
            or datetime.fromisoformat(value).tzinfo is None):
        raise ValueError()


def _mutation_intent(value):
    if (type(value) is not dict or set(value) != {'fields','item_index','preimage_digest'}
            or (value['item_index'] is not None and (type(value['item_index']) is not int
                or not 0 <= value['item_index'] < 32))
            or (value['preimage_digest'] is not None and (type(value['preimage_digest']) is not str
                or not _SHA256.fullmatch(value['preimage_digest'])))):
        raise LedgerError('INVALID_FORGE_AUDIT')
    _mutation_fields(value['fields'])
    if (value['item_index'] is not None) != (len(value['fields']) == 1 and
            value['fields'][0] in {'add-label','remove-label'}):
        raise LedgerError('INVALID_FORGE_AUDIT')
    return json.loads(_json(value))


def _reconciliation_metadata(value):
    if (type(value) is not dict or set(value) != {'room_instance','origin_digest','request_digest'}
            or any(type(value[key]) is not str or not _SHA256.fullmatch(value[key])
                for key in ('origin_digest','request_digest'))):
        raise LedgerError('INVALID_FORGE_AUDIT')
    _token(value['room_instance'])
    return json.loads(_json(value))


def _mutation_observation(value):
    statuses = {'MATCHED','ABSENT','CONFLICT','UNKNOWN'}
    if (type(value) is not dict or set(value) != {'status','fields','objects','contact','attribution','error_code'}
            or type(value['status']) is not str or value['status'] not in statuses | {'PARTIAL'}
            or value['contact'] != 'read' or value['attribution'] != 'observed-only'
            or type(value['fields']) is not list or len(value['fields']) > 64
            or type(value['objects']) is not list or len(value['objects']) > 32
            or (value['error_code'] is not None and (type(value['error_code']) is not str
                or not re.fullmatch('[A-Z][A-Z0-9_]{0,63}',value['error_code'])))):
        raise LedgerError('INVALID_FORGE_AUDIT')
    seen = set()
    for item in value['fields']:
        if (type(item) is not dict or set(item) != {'field','item_index','status'}
                or type(item['field']) is not str or item['field'] not in MUTATION_FIELDS
                or type(item['status']) is not str or item['status'] not in statuses
                or (item['item_index'] is not None and (type(item['item_index']) is not int
                    or not 0 <= item['item_index'] < 32))):
            raise LedgerError('INVALID_FORGE_AUDIT')
        key=(item['field'],item['item_index'])
        if key in seen: raise LedgerError('INVALID_FORGE_AUDIT')
        seen.add(key)
    objects = [_mutation_object(item) for item in value['objects']]
    if len({_json(item) for item in objects}) != len(objects): raise LedgerError('INVALID_FORGE_AUDIT')
    states = {item['status'] for item in value['fields']}
    expected = ('UNKNOWN' if not states or 'UNKNOWN' in states else
                next(iter(states)) if len(states)==1 else 'PARTIAL')
    if value['status'] != expected: raise LedgerError('INVALID_FORGE_AUDIT')
    return json.loads(_json(value))


class ForgeAudit:
    """Append-only start, terminal and reconciliation facts for one Deployment.

    get() is a trusted Broker inspection seam, not a public receipt endpoint.
    The caller must authenticate and compare stored binding before disclosure.
    """
    def __init__(self, path, deployment_id):
        self.deployment_id = _token(deployment_id)
        self._db = None
        self._read_failed = False
        self._mutation_failed = False
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
            if row is None or row['id'] != deployment_id or row['version'] not in {1, 2, 3, 4}:
                raise LedgerError('DEPLOYMENT_MISMATCH')
            if row['version'] == 1:
                _schema(self._db, _V1_SCHEMA)
                for statement in _READ_SCHEMA.values():
                    self._db.execute(statement)
                self._db.execute('UPDATE deployment SET version=2 WHERE singleton=1')
            if row['version'] in {1, 2}:
                _schema(self._db, {**_V1_SCHEMA, **_READ_SCHEMA})
                for statement in _MUTATION_SCHEMA.values():
                    self._db.execute(statement)
                self._db.execute('UPDATE deployment SET version=3 WHERE singleton=1')
            if row['version'] in {1, 2, 3}:
                _schema(self._db, {**_V1_SCHEMA, **_READ_SCHEMA, **_MUTATION_SCHEMA})
                for statement in _RECONCILIATION_SCHEMA.values():
                    self._db.execute(statement)
                self._db.execute('UPDATE deployment SET version=4 WHERE singleton=1')
            _schema(self._db, {**_V1_SCHEMA, **_READ_SCHEMA, **_MUTATION_SCHEMA, **_RECONCILIATION_SCHEMA})
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
        if self._read_failed or self._mutation_failed:
            raise LedgerError('AUDIT_UNAVAILABLE')
        db = self._connection()
        try:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT 1 FROM mutation_reconciliation_starts WHERE reconciliation_id=?', (operation_id,)).fetchone():
                raise LedgerError('ID_CONFLICT')
            if (db.execute('SELECT 1 FROM mutation_starts WHERE id=?', (operation_id,)).fetchone()
                    or db.execute('SELECT 1 FROM starts WHERE id=?', (operation_id,)).fetchone()
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
        if self._read_failed or self._mutation_failed:
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
        if self._mutation_failed:
            raise LedgerError('AUDIT_UNAVAILABLE')
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
            if db.execute('SELECT 1 FROM mutation_reconciliation_starts WHERE reconciliation_id=?', (operation_id,)).fetchone():
                raise LedgerError('ID_CONFLICT')
            if (db.execute('SELECT 1 FROM read_starts WHERE id=?', (operation_id,)).fetchone()
                    or db.execute('SELECT 1 FROM mutation_starts WHERE id=?', (operation_id,)).fetchone()):
                raise LedgerError('ID_CONFLICT')
            prior = self._get(db, operation_id)
            if prior is not None:
                if prior['metadata'] != metadata:
                    raise LedgerError('ID_CONFLICT')
                db.rollback()
                return {'started': False, 'record': prior}
            self._mutation_fence(db, metadata['room_id'], metadata['repository'])
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
            if db.execute('SELECT 1 FROM mutation_reconciliation_starts WHERE reconciliation_id=?', (reconciliation_id,)).fetchone():
                raise LedgerError('ID_CONFLICT')
            record = self._get(db, operation_id)
            if record is None:
                raise LedgerError('FORGE_AUDIT_NOT_FOUND')
            if (db.execute('SELECT 1 FROM read_starts WHERE id=?', (reconciliation_id,)).fetchone()
                    or db.execute('SELECT 1 FROM mutation_starts WHERE id=?', (reconciliation_id,)).fetchone()):
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

    def _mutation_get(self, db, operation_id):
        row = db.execute('SELECT room_id,repository,metadata,timestamp FROM mutation_starts WHERE id=?',
                         (operation_id,)).fetchone()
        if row is None:
            return None
        terminal = db.execute('SELECT result,timestamp FROM mutation_terminals WHERE id=?',
                              (operation_id,)).fetchone()
        checkpoints = db.execute('SELECT p.step,p.target,p.timestamp AS prepared_at,c.fields,c.object,'
            'c.timestamp AS confirmed_at,r.error_code,r.timestamp AS rejected_at '
            'FROM mutation_prepared p LEFT JOIN mutation_confirmed c ON p.id=c.id AND p.step=c.step '
            'LEFT JOIN mutation_rejected r ON p.id=r.id AND p.step=r.step WHERE p.id=? ORDER BY p.step LIMIT 33', (operation_id,)).fetchall()
        try:
            metadata = _mutation_metadata(json.loads(row['metadata']))
            if (metadata['room_id'] != row['room_id']
                    or metadata['repository'].lower() != row['repository']
                    or row['metadata'] != _json(metadata) or len(checkpoints) > 32):
                raise ValueError()
            _mutation_stamp(row['timestamp'])
            steps = []
            for index, item in enumerate(checkpoints):
                if item['step'] != index or (steps and steps[-1]['fields'] is None):
                    raise ValueError()
                target = _mutation_object(json.loads(item['target']), related=True)
                self._mutation_target(metadata, target)
                if item['target'] != _json(target):
                    raise ValueError()
                _mutation_stamp(item['prepared_at'])
                fields = obj = None
                if item['fields'] is not None:
                    fields = _mutation_fields(json.loads(item['fields']))
                    obj = _mutation_object(json.loads(item['object']))
                    if item['fields'] != _json(fields) or item['object'] != _json(obj):
                        raise ValueError()
                    _mutation_stamp(item['confirmed_at'])
                    self._mutation_pair(target, obj)
                elif item['object'] is not None or item['confirmed_at'] is not None:
                    raise ValueError()
                if item['error_code'] is not None:
                    if (fields is not None or type(item['error_code']) is not str
                            or item['error_code'] not in _MUTATION_REJECTIONS):
                        raise ValueError()
                    _mutation_stamp(item['rejected_at'])
                elif item['rejected_at'] is not None:
                    raise ValueError()
                steps.append({'step': index, 'target': target, 'prepared_at': item['prepared_at'],
                    'fields': fields, 'object': obj, 'confirmed_at': item['confirmed_at'],
                    'error_code': item['error_code'], 'rejected_at': item['rejected_at']})
            result = None if terminal is None else _mutation_result(json.loads(terminal['result']))
            if terminal is not None:
                if terminal['result'] != _json(result):
                    raise ValueError()
                _mutation_stamp(terminal['timestamp'])
                _mutation_terminal_valid(result, steps)
            for step in steps:
                intent = db.execute('SELECT intent FROM mutation_intents WHERE id=? AND step=?',
                    (operation_id,step['step'])).fetchone()
                step['intent'] = None if intent is None else _mutation_intent(json.loads(intent['intent']))
                if intent is not None and (intent['intent'] != _json(step['intent'])
                        or (step['fields'] is not None and step['fields'] != step['intent']['fields'])): raise ValueError()
            reconciliations = self._mutation_observations(db,operation_id)
            return {'operation_id': operation_id, 'deployment_id': self.deployment_id,
                'reconciliations': reconciliations,
                'metadata': metadata, 'started_at': row['timestamp'], 'steps': steps,
                'result': result, 'finished_at': None if terminal is None else terminal['timestamp']}
        except (ValueError, TypeError, KeyError, RecursionError, LedgerError) as error:
            self._mutation_failed = True
            raise LedgerError('AUDIT_UNAVAILABLE') from error

    @staticmethod
    def _mutation_pair(target, obj):
        # A receipt cannot silently replace an already-bound issue/PR identity.
        # Creates use the repository as pre-contact target; comments/reviews
        # return their new child object, not a fabricated target mutation.
        allowed = {'repository': {'issue', 'pull'}, 'issue': {'issue', 'comment'},
                   'pull': {'pull', 'comment', 'review'}, 'comment': {'comment'}, 'review': {'review'}}
        if obj['kind'] not in allowed[target['kind']]:
            raise LedgerError('INVALID_FORGE_AUDIT')
        if target['kind'] == obj['kind'] and target['kind'] != 'comment':
            if {key: value for key, value in target.items() if not key.startswith('related_')} != obj:
                raise LedgerError('INVALID_FORGE_AUDIT')

    @staticmethod
    def _mutation_target(metadata, target):
        if metadata['route'] == 'denied':
            raise LedgerError('INVALID_FORGE_AUDIT')
        dependency = metadata['route'] in {'dependency-add', 'dependency-remove'}
        if dependency != ('related_id' in target):
            raise LedgerError('INVALID_FORGE_AUDIT')

    def _mutation_fence(self, db, room_id, repository):
        # Historical UNKNOWN receipts stay immutable after reconciliation. Page
        # them rather than consuming the 256 active-recovery inventory, but
        # validate each record before trusting a known-observation exemption.
        # A raw SQL status is not canonical audit evidence. Bound the total
        # examination; exceeding it fails closed rather than dropping history.
        cursor=examined=0
        while True:
            rows = db.execute('SELECT s.id,s.rowid AS ordinal FROM mutation_starts s LEFT JOIN mutation_terminals t ON t.id=s.id '
                "WHERE s.room_id=? AND s.repository=? AND s.rowid>? AND (t.id IS NULL OR json_extract(t.result,'$.status')='UNKNOWN_OUTCOME' "
                'OR EXISTS (SELECT 1 FROM mutation_prepared p LEFT JOIN mutation_confirmed c ON c.id=p.id AND c.step=p.step '
                'LEFT JOIN mutation_rejected r ON r.id=p.id AND r.step=p.step WHERE p.id=s.id AND c.id IS NULL AND r.id IS NULL)) '
                'ORDER BY s.rowid LIMIT 256', (room_id,repository.lower(),cursor)).fetchall()
            if not rows:return
            examined+=len(rows)
            if examined>4096:raise LedgerError('FORGE_RECOVERY_CAPACITY')
            for row in rows:
                record = self._mutation_get(db, row['id'])
                if (record['result'] is None or record['result']['status'] == 'UNKNOWN_OUTCOME'
                        or (record['steps'] and record['steps'][-1]['fields'] is None
                            and record['steps'][-1]['error_code'] is None)):
                    observations = record['reconciliations']
                    # A read is not a replay grant. It only lifts this uncertainty
                    # barrier; a new write still undergoes its ordinary policy.
                    if (record['result'] is None or not observations
                            or observations[-1]['observation'] is None
                            or observations[-1]['observation']['status'] == 'UNKNOWN'
                            or any(field['status'] == 'UNKNOWN' for field in observations[-1]['observation']['fields'])):
                        raise LedgerError('FORGE_RECONCILIATION_REQUIRED')
            cursor=rows[-1]['ordinal']

    def _legacy_mutation_fence(self, db, room_id, repository):
        rows = db.execute('SELECT s.id FROM starts s LEFT JOIN terminals t ON t.id=s.id '
            "WHERE json_extract(s.metadata,'$.room_id')=? AND lower(json_extract(s.metadata,'$.repository'))=? "
            "AND (t.id IS NULL OR json_extract(t.result,'$.status')='UNKNOWN_OUTCOME') "
            'ORDER BY s.rowid LIMIT 257', (room_id, repository.lower())).fetchall()
        if len(rows) > 256:
            raise LedgerError('FORGE_RECOVERY_CAPACITY')
        for row in rows:
            record = self._get(db, row['id'])
            observations = record['reconciliations']
            if (record['result'] is None or not observations or observations[-1]['observation'] is None
                    or observations[-1]['observation']['status'] == 'UNKNOWN'):
                raise LedgerError('FORGE_RECONCILIATION_REQUIRED')

    def _mutation_write_connection(self):
        if self._mutation_failed or self._read_failed:
            raise LedgerError('AUDIT_UNAVAILABLE')
        return self._connection()

    def get_mutation(self, operation_id):
        """Trusted metadata-only inspection, including after a failed commit.

        Reading a pending or terminal record never grants provider replay. The
        Broker authenticates stored ownership before disclosing any receipt.
        """
        _token(operation_id)
        db = self._connection()
        try:
            db.execute('BEGIN')
            record = self._mutation_get(db, operation_id)
            db.rollback()
            return record
        except sqlite3.Error as error:
            self._mutation_failed = True
            db.rollback()
            raise LedgerError('AUDIT_UNAVAILABLE') from error
        except BaseException:
            db.rollback()
            raise

    def pending_mutations(self, room_id):
        """Bounded restart inventory; the owner must fence old execution first."""
        _token(room_id)
        db = self._connection()
        try:
            db.execute('BEGIN')
            rows = db.execute('SELECT s.id FROM mutation_starts s LEFT JOIN mutation_terminals t ON t.id=s.id '
                'WHERE t.id IS NULL AND s.room_id=? ORDER BY s.rowid LIMIT 257', (room_id,)).fetchall()
            if len(rows) > 256:
                raise LedgerError('FORGE_RECOVERY_CAPACITY')
            records = [self._mutation_get(db, row['id']) for row in rows]
            db.rollback()
            return records
        except sqlite3.Error as error:
            self._mutation_failed = True
            db.rollback()
            raise LedgerError('AUDIT_UNAVAILABLE') from error
        except BaseException:
            db.rollback()
            raise

    def begin_mutation(self, operation_id, metadata):
        """Only a committed started=True grants one bounded mutation attempt.

        This release conservatively serializes uncertain writes per Room and
        repository, across Actors, Participants and incarnations. Reconciliation
        is a later owner: no new operation ID can bypass an unresolved outcome.
        """
        _token(operation_id)
        metadata = _mutation_metadata(metadata)
        db = self._mutation_write_connection()
        try:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT 1 FROM mutation_reconciliation_starts WHERE reconciliation_id=?', (operation_id,)).fetchone():
                raise LedgerError('ID_CONFLICT')
            if (db.execute('SELECT 1 FROM starts WHERE id=?', (operation_id,)).fetchone()
                    or db.execute('SELECT 1 FROM read_starts WHERE id=?', (operation_id,)).fetchone()
                    or db.execute('SELECT 1 FROM reconciliation_starts WHERE reconciliation_id=?',
                                  (operation_id,)).fetchone()):
                raise LedgerError('OPERATION_CONFLICT')
            prior = self._mutation_get(db, operation_id)
            if prior is not None:
                if prior['metadata'] != metadata:
                    raise LedgerError('OPERATION_CONFLICT')
                db.rollback()
                return {'started': False, 'record': prior}
            self._mutation_fence(db, metadata['room_id'], metadata['repository'])
            self._legacy_mutation_fence(db, metadata['room_id'], metadata['repository'])
            count = db.execute('SELECT count(*) FROM mutation_starts s LEFT JOIN mutation_terminals t ON t.id=s.id '
                'WHERE t.id IS NULL AND s.room_id=?', (metadata['room_id'],)).fetchone()[0]
            if count >= 256:
                raise LedgerError('FORGE_RECOVERY_CAPACITY')
            db.execute('INSERT INTO mutation_starts VALUES(?,?,?,?,?)',
                (operation_id, metadata['room_id'], metadata['repository'].lower(), _json(metadata), self._now()))
            record = self._mutation_get(db, operation_id)
            self._commit()
            return {'started': True, 'record': record}
        except sqlite3.Error as error:
            self._mutation_failed = True
            db.rollback()
            raise LedgerError('AUDIT_UNAVAILABLE') from error
        except BaseException:
            db.rollback()
            raise

    def mutation_prepared(self, operation_id, step, target, *, intent=None):
        """Commit exact target identity before possible contact for this step."""
        _token(operation_id)
        if type(step) is not int or not 0 <= step < 32:
            raise LedgerError('INVALID_FORGE_AUDIT')
        target = _mutation_object(target, related=True)
        if intent is not None: intent = _mutation_intent(intent)
        db = self._mutation_write_connection()
        try:
            db.execute('BEGIN IMMEDIATE')
            record = self._mutation_get(db, operation_id)
            if record is None:
                raise LedgerError('FORGE_AUDIT_NOT_FOUND')
            self._mutation_target(record['metadata'], target)
            if step < len(record['steps']):
                if record['steps'][step]['target'] != target or record['steps'][step]['intent'] != intent:
                    raise LedgerError('OPERATION_CONFLICT')
                db.rollback()
                return record
            if record['result'] is not None:
                raise LedgerError('FORGE_AUDIT_TERMINAL')
            if step != len(record['steps']) or (record['steps'] and record['steps'][-1]['fields'] is None):
                raise LedgerError('INVALID_FORGE_AUDIT')
            db.execute('INSERT INTO mutation_prepared VALUES(?,?,?,?)',
                       (operation_id, step, _json(target), self._now()))
            if intent is not None:
                db.execute('INSERT INTO mutation_intents VALUES(?,?,?)',(operation_id,step,_json(intent)))
            record = self._mutation_get(db, operation_id)
            self._commit()
            return record
        except sqlite3.Error as error:
            self._mutation_failed = True
            db.rollback()
            raise LedgerError('AUDIT_UNAVAILABLE') from error
        except BaseException:
            db.rollback()
            raise

    def mutation_confirmed(self, operation_id, step, fields, object):
        """Persist only fields verified in the provider response, never their text."""
        _token(operation_id)
        if type(step) is not int or not 0 <= step < 32:
            raise LedgerError('INVALID_FORGE_AUDIT')
        fields, obj = _mutation_fields(fields), _mutation_object(object)
        db = self._mutation_write_connection()
        try:
            db.execute('BEGIN IMMEDIATE')
            record = self._mutation_get(db, operation_id)
            if record is None:
                raise LedgerError('FORGE_AUDIT_NOT_FOUND')
            if step >= len(record['steps']):
                raise LedgerError('INVALID_FORGE_AUDIT')
            prior = record['steps'][step]
            self._mutation_pair(prior['target'], obj)
            if prior['intent'] is not None and prior['intent']['fields'] != fields:
                raise LedgerError('INVALID_FORGE_AUDIT')
            if prior['fields'] is not None:
                if prior['fields'] != fields or prior['object'] != obj:
                    raise LedgerError('OPERATION_CONFLICT')
                db.rollback()
                return record
            if record['result'] is not None:
                raise LedgerError('FORGE_AUDIT_TERMINAL')
            if prior['error_code'] is not None:
                raise LedgerError('OPERATION_CONFLICT')
            db.execute('INSERT INTO mutation_confirmed VALUES(?,?,?,?,?)',
                       (operation_id, step, _json(fields), _json(obj), self._now()))
            record = self._mutation_get(db, operation_id)
            self._commit()
            return record
        except sqlite3.Error as error:
            self._mutation_failed = True
            db.rollback()
            raise LedgerError('AUDIT_UNAVAILABLE') from error
        except BaseException:
            db.rollback()
            raise

    def mutation_rejected(self, operation_id, step, error_code):
        """Record a verified definite provider rejection, not transport failure.

        Only the provider adapter classifies a response as a definite rejection;
        AUTHORITY_REVOKED_BEFORE_CONTACT additionally proves transport was never entered.
        Timeout, lost/malformed response or possible side effect cannot use this
        API. A rejection terminates the step sequence without inventing fields.
        """
        _token(operation_id)
        if (type(step) is not int or not 0 <= step < 32 or type(error_code) is not str
                or error_code not in _MUTATION_REJECTIONS):
            raise LedgerError('INVALID_FORGE_AUDIT')
        db = self._mutation_write_connection()
        try:
            db.execute('BEGIN IMMEDIATE')
            record = self._mutation_get(db, operation_id)
            if record is None:
                raise LedgerError('FORGE_AUDIT_NOT_FOUND')
            if step >= len(record['steps']):
                raise LedgerError('INVALID_FORGE_AUDIT')
            prior = record['steps'][step]
            if prior['error_code'] is not None:
                if prior['error_code'] != error_code:
                    raise LedgerError('OPERATION_CONFLICT')
                db.rollback()
                return record
            if record['result'] is not None:
                raise LedgerError('FORGE_AUDIT_TERMINAL')
            if prior['fields'] is not None:
                raise LedgerError('OPERATION_CONFLICT')
            db.execute('INSERT INTO mutation_rejected VALUES(?,?,?,?)',
                       (operation_id, step, error_code, self._now()))
            record = self._mutation_get(db, operation_id)
            self._commit()
            return record
        except sqlite3.Error as error:
            self._mutation_failed = True
            db.rollback()
            raise LedgerError('AUDIT_UNAVAILABLE') from error
        except BaseException:
            db.rollback()
            raise

    def finish_mutation(self, operation_id, result):
        """Commit a truthful immutable terminal before acknowledging any success.

        Confirmed fields and objects must equal earlier durable checkpoints.
        A lost terminal acknowledgement stops this owner; a new owner may read
        the durable record but still cannot blindly repeat the mutation.
        """
        _token(operation_id)
        result = _mutation_result(result)
        db = self._mutation_write_connection()
        try:
            db.execute('BEGIN IMMEDIATE')
            record = self._mutation_get(db, operation_id)
            if record is None:
                raise LedgerError('FORGE_AUDIT_NOT_FOUND')
            _mutation_terminal_valid(result, record['steps'])
            if record['metadata']['route'] == 'denied' and (result['status'] != 'DENIED' or result['contact'] != 'none'):
                raise LedgerError('INVALID_FORGE_AUDIT')
            if record['result'] is not None:
                if record['result'] != result:
                    raise LedgerError('OPERATION_CONFLICT')
                db.rollback()
                return record
            db.execute('INSERT INTO mutation_terminals VALUES(?,?,?)',
                       (operation_id, _json(result), self._now()))
            record = self._mutation_get(db, operation_id)
            self._commit()
            return record
        except sqlite3.Error as error:
            self._mutation_failed = True
            db.rollback()
            raise LedgerError('AUDIT_UNAVAILABLE') from error
        except BaseException:
            db.rollback()
            raise

    def _mutation_observations(self, db, operation_id):
        rows=db.execute('SELECT s.reconciliation_id,s.metadata,s.timestamp AS started_at,'
            'o.observation,o.timestamp FROM mutation_reconciliation_starts s '
            'LEFT JOIN mutation_observations o ON o.reconciliation_id=s.reconciliation_id '
            'WHERE s.id=? ORDER BY s.seq LIMIT 257',(operation_id,)).fetchall()
        if len(rows)>256: raise LedgerError('FORGE_RECOVERY_CAPACITY')
        result=[]
        for row in rows:
            meta=_reconciliation_metadata(json.loads(row['metadata']))
            observation=None if row['observation'] is None else _mutation_observation(json.loads(row['observation']))
            if row['metadata'] != _json(meta) or (observation is not None and row['observation'] != _json(observation)):
                raise LedgerError('INVALID_FORGE_AUDIT')
            _mutation_stamp(row['started_at'])
            if observation is not None: _mutation_stamp(row['timestamp'])
            result.append({'id':row['reconciliation_id'],'metadata':meta,'observation':observation,
                'started_at':row['started_at'],'timestamp':row['timestamp']})
        return result

    def begin_mutation_reconciliation(self, operation_id, reconciliation_id, metadata):
        """Commit a read-only attempt; an exact retry cannot repeat even a GET.

        Pending writes must first be terminalized by a fenced replacement owner.
        An observation is separate from the immutable mutation receipt and never
        claims that an observed matching value was caused by this invocation.
        """
        _token(operation_id);_token(reconciliation_id)
        metadata=_reconciliation_metadata(metadata)
        db=self._mutation_write_connection()
        try:
            db.execute('BEGIN IMMEDIATE')
            record=self._mutation_get(db,operation_id)
            if record is None: raise LedgerError('FORGE_AUDIT_NOT_FOUND')
            if record['result'] is None: raise LedgerError('FORGE_OPERATION_PENDING')
            prior=db.execute('SELECT id,metadata FROM mutation_reconciliation_starts WHERE reconciliation_id=?',
                (reconciliation_id,)).fetchone()
            if prior is not None:
                if prior['id']!=operation_id or prior['metadata']!=_json(metadata): raise LedgerError('ID_CONFLICT')
                db.rollback();return {'started':False,'record':record}
            for table,column in (('starts','id'),('read_starts','id'),('mutation_starts','id'),
                    ('reconciliation_starts','reconciliation_id')):
                if db.execute(f'SELECT 1 FROM {table} WHERE {column}=?',(reconciliation_id,)).fetchone():
                    raise LedgerError('ID_CONFLICT')
            if len(record['reconciliations'])>=256: raise LedgerError('FORGE_RECOVERY_CAPACITY')
            db.execute('INSERT INTO mutation_reconciliation_starts(id,reconciliation_id,metadata,timestamp) VALUES(?,?,?,?)',
                (operation_id,reconciliation_id,_json(metadata),self._now()))
            record=self._mutation_get(db,operation_id)
            self._commit();return {'started':True,'record':record}
        except sqlite3.Error as error:
            self._mutation_failed=True;db.rollback()
            raise LedgerError('AUDIT_UNAVAILABLE') from error
        except BaseException:
            db.rollback();raise

    def observe_mutation(self, operation_id, reconciliation_id, observation):
        _token(operation_id);_token(reconciliation_id)
        observation=_mutation_observation(observation)
        db=self._mutation_write_connection()
        try:
            db.execute('BEGIN IMMEDIATE')
            record=self._mutation_get(db,operation_id)
            if record is None: raise LedgerError('FORGE_AUDIT_NOT_FOUND')
            start=db.execute('SELECT id FROM mutation_reconciliation_starts WHERE reconciliation_id=?',
                (reconciliation_id,)).fetchone()
            if start is None: raise LedgerError('FORGE_RECONCILIATION_NOT_STARTED')
            if start['id']!=operation_id: raise LedgerError('ID_CONFLICT')
            prior=db.execute('SELECT observation FROM mutation_observations WHERE reconciliation_id=?',
                (reconciliation_id,)).fetchone()
            if prior is not None:
                if prior['observation']!=_json(observation): raise LedgerError('ID_CONFLICT')
                db.rollback();return record
            db.execute('INSERT INTO mutation_observations VALUES(?,?,?)',
                (reconciliation_id,_json(observation),self._now()))
            record=self._mutation_get(db,operation_id)
            self._commit();return record
        except sqlite3.Error as error:
            self._mutation_failed=True;db.rollback()
            raise LedgerError('AUDIT_UNAVAILABLE') from error
        except BaseException:
            db.rollback();raise
