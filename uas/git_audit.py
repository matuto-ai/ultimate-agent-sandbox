"""Git stream facts in the one existing Deployment ForgeAudit database.

There is no stream/body/key storage, replay grant, or second mutation owner.
Only the trusted Supervisor/Broker calls this adapter after process binding.
"""
from contextlib import contextmanager
from datetime import datetime
import hashlib
import json
import re
import sqlite3

from .git_policy import GitTarget
from .ledger import LedgerError, _json, _token

GIT_SCHEMA = {
    'git_starts': 'CREATE TABLE git_starts (id TEXT PRIMARY KEY, room_id TEXT NOT NULL, metadata TEXT NOT NULL, timestamp TEXT NOT NULL)',
    'git_terminals': 'CREATE TABLE git_terminals (id TEXT PRIMARY KEY REFERENCES git_starts(id), result TEXT NOT NULL, timestamp TEXT NOT NULL)',
}
_META = {'room_id', 'room_instance', 'project_id', 'actor_id', 'participant_id',
         'incarnation_id', 'authority_version', 'origin_digest', 'host', 'repository',
         'service', 'request_digest'}
_HASH = re.compile(r'[0-9a-f]{64}\Z')
_STATUSES = {'OK', 'DENIED', 'FAILED', 'TIMEOUT', 'REVOKED', 'UNKNOWN_OUTCOME', 'INTERRUPTED'}
MAX_BYTES = 64 * 1024 * 1024


def metadata(value):
    if type(value) is not dict or set(value) != _META:
        raise LedgerError('INVALID_GIT_AUDIT')
    for key in ('room_id', 'room_instance', 'project_id', 'actor_id', 'participant_id',
                'incarnation_id', 'authority_version'):
        _token(value[key])
    try:
        GitTarget(value['host'], value['repository'], value['service'])
    except ValueError:
        raise LedgerError('INVALID_GIT_AUDIT') from None
    if any(type(value[key]) is not str or not _HASH.fullmatch(value[key])
           for key in ('origin_digest', 'request_digest')):
        raise LedgerError('INVALID_GIT_AUDIT')
    return json.loads(_json(value))


def terminal(value):
    if (type(value) is not dict or set(value) != {'status', 'contact', 'input_bytes',
            'output_bytes', 'output_sha256'}
            or type(value['status']) is not str or value['status'] not in _STATUSES
            or type(value['contact']) is not str or value['contact'] not in {'none', 'read', 'write-possible'}
            or any(type(value[key]) is not int or not 0 <= value[key] <= MAX_BYTES
                   for key in ('input_bytes', 'output_bytes'))
            or (value['output_sha256'] is not None and (type(value['output_sha256']) is not str
                or not _HASH.fullmatch(value['output_sha256'])))):
        raise LedgerError('INVALID_GIT_AUDIT')
    if ((value['status'] == 'OK' and (value['contact'] == 'none' or value['output_sha256'] is None))
            or (value['status'] == 'DENIED' and value['contact'] != 'none')
            or (value['contact'] == 'none' and (value['input_bytes'] or value['output_bytes']))
            or (value['status'] == 'UNKNOWN_OUTCOME' and value['contact'] != 'write-possible')
            or (value['status'] == 'INTERRUPTED' and value['contact'] != 'read')):
        raise LedgerError('INVALID_GIT_AUDIT')
    return json.loads(_json(value))


def stream_key(room_id, room_instance, operation_id):
    return hashlib.sha256(_json([_token(room_id), _token(room_instance), _token(operation_id)]).encode()).hexdigest()


class GitAudit:
    def __init__(self, owner):
        from .forge_audit import ForgeAudit
        if type(owner) is not ForgeAudit:
            raise LedgerError('INVALID_GIT_AUDIT')
        self.owner = owner
        self.failed = False

    @contextmanager
    def _transaction(self, *, writing=False):
        if self.failed:
            raise LedgerError('AUDIT_UNAVAILABLE')
        db = self.owner._connection()
        try:
            db.execute('BEGIN IMMEDIATE' if writing else 'BEGIN')
            yield db
            if writing: self.owner._commit()
            else: db.rollback()
        except sqlite3.Error:
            self.failed = True
            db.rollback()
            raise LedgerError('AUDIT_UNAVAILABLE') from None
        except BaseException:
            db.rollback()
            raise

    def _get(self, db, key):
        start = db.execute('SELECT * FROM git_starts WHERE id=?', (key,)).fetchone()
        if start is None: return None
        end = db.execute('SELECT * FROM git_terminals WHERE id=?', (key,)).fetchone()
        try:
            meta = metadata(json.loads(start['metadata']))
            result = None if end is None else terminal(json.loads(end['result']))
            if (start['room_id'] != meta['room_id'] or _json(meta) != start['metadata']
                    or (end is not None and _json(result) != end['result'])):
                raise ValueError()
            for stamp in (start['timestamp'], None if end is None else end['timestamp']):
                if stamp is not None and (type(stamp) is not str or len(stamp) > 64
                        or datetime.fromisoformat(stamp).tzinfo is None):
                    raise ValueError()
            if result is not None:
                expected = 'read' if meta['service'] == 'git-upload-pack' else 'write-possible'
                if result['contact'] not in ('none', expected): raise ValueError()
            return {'id': key, 'metadata': meta, 'result': result,
                    'started_at': start['timestamp'], 'finished_at': None if end is None else end['timestamp']}
        except (ValueError, TypeError, KeyError, LedgerError):
            self.failed = True
            raise LedgerError('AUDIT_UNAVAILABLE') from None

    def begin(self, operation_id, value):
        value = metadata(value)
        key = stream_key(value['room_id'], value['room_instance'], operation_id)
        with self._transaction(writing=True) as db:
            prior = self._get(db, key)
            if prior is not None:
                if prior['metadata'] != value: raise LedgerError('ID_CONFLICT')
                return {'execute': False, 'record': prior}
            if db.execute('SELECT count(*) FROM git_starts WHERE room_id=?', (value['room_id'],)).fetchone()[0] >= 100000:
                raise LedgerError('GIT_AUDIT_CAPACITY')
            if db.execute('SELECT count(*) FROM git_starts s LEFT JOIN git_terminals t ON s.id=t.id '
                          'WHERE t.id IS NULL AND s.room_id=?', (value['room_id'],)).fetchone()[0] >= 16:
                raise LedgerError('GIT_AUDIT_CAPACITY')
            db.execute('INSERT INTO git_starts VALUES (?,?,?,?)',
                       (key, value['room_id'], _json(value), self.owner._now()))
            return {'execute': True, 'record': self._get(db, key)}

    def finish(self, key, result):
        _token(key); result = terminal(result)
        with self._transaction(writing=True) as db:
            record = self._get(db, key)
            if record is None: raise LedgerError('GIT_OPERATION_UNKNOWN')
            if record['result'] is not None:
                if record['result'] != result: raise LedgerError('ID_CONFLICT')
                return record
            contact = 'read' if record['metadata']['service'] == 'git-upload-pack' else 'write-possible'
            if result['contact'] not in ('none', contact): raise LedgerError('INVALID_GIT_AUDIT')
            db.execute('INSERT INTO git_terminals VALUES (?,?,?)', (key, _json(result), self.owner._now()))
            return self._get(db, key)

    def get(self, key):
        _token(key)
        with self._transaction() as db: return self._get(db, key)

    def recover(self, room_id, room_instance, *, fenced):
        """Trusted replacement must establish old-owner fencing, not timeout."""
        _token(room_id); _token(room_instance)
        if fenced is not True: raise LedgerError('GIT_OWNER_NOT_FENCED')
        with self._transaction(writing=True) as db:
            rows = db.execute('SELECT s.id FROM git_starts s LEFT JOIN git_terminals t ON t.id=s.id '
                              'WHERE t.id IS NULL AND s.room_id=? ORDER BY s.rowid LIMIT 257', (room_id,)).fetchall()
            if len(rows) > 256: raise LedgerError('GIT_AUDIT_CAPACITY')
            recovered = []
            for row in rows:
                record = self._get(db, row['id'])
                if record['metadata']['room_instance'] != room_instance: continue
                write = record['metadata']['service'] == 'git-receive-pack'
                result = terminal({'status': 'UNKNOWN_OUTCOME' if write else 'INTERRUPTED',
                    'contact': 'write-possible' if write else 'read', 'input_bytes': 0, 'output_bytes': 0,
                    'output_sha256': None})
                db.execute('INSERT INTO git_terminals VALUES (?,?,?)', (row['id'], _json(result), self.owner._now()))
                recovered.append(self._get(db, row['id']))
            return recovered
