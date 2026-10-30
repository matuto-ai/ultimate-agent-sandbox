"""T28 durable installation-scoped shared settings, never Project authority.

The private configuration store owns limits/filter values, request identities and
safe audit receipts in one FULL-synchronous transaction. Canonical Git and the
operational journal do not own this state. Repository/model/egress authority is
read independently on every use and cannot be changed through this owner.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import stat

from . import library

MAX_REQUEST = library.MAX_SETTINGS_BYTES
MAX_STORE_BYTES = 16 * 1024 * 1024
MAX_REQUESTS = 10000
SCHEMA = {
 'active': 'CREATE TABLE active (singleton INTEGER PRIMARY KEY CHECK(singleton=1), deployment TEXT NOT NULL, revision INTEGER NOT NULL, shared TEXT NOT NULL, digest TEXT NOT NULL)',
 'requests': 'CREATE TABLE requests (request_id TEXT PRIMARY KEY, identity TEXT NOT NULL, receipt TEXT NOT NULL, receipt_digest TEXT NOT NULL)',
}


def fail(code): raise library.LibraryError(code, 'shared-settings')


def canonical(value): return library._canonical(value)


def shared(value):
    # The core validator enforces every finite fixed maximum and cross-bound.
    candidate = deepcopy(value)
    if type(candidate) is not dict or set(candidate) != {'limits','filters'}:
        fail('INVALID_SHARED_SETTINGS')
    if type(candidate['filters']) is dict and candidate['filters'].get('heuristic') == 'block':
        # The parser qualification dependency is needed only to enable blocking.
        from . import library_gate
        if not library_gate.heuristic_qualified(): fail('HEURISTIC_NOT_QUALIFIED')
    return candidate


def decode(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_REQUEST: fail('SETTINGS_REQUEST_LIMIT')
    try:
        value = json.loads(raw, object_pairs_hook=library._unique_pairs,
            parse_constant=lambda _:fail('INVALID_SETTINGS_REQUEST'))
    except (ValueError, UnicodeError, RecursionError): fail('INVALID_SETTINGS_REQUEST')
    if type(value) is not dict or type(value.get('version')) is not int or value['version'] != 1:
        fail('INVALID_SETTINGS_REQUEST')
    action = value.get('action')
    fields = {'version','action','deployment'}
    if action == 'settings-update': fields |= {'request_id','configuration_version','settings_id','shared'}
    elif action != 'settings-observe': fail('INVALID_SETTINGS_REQUEST')
    if set(value) != fields: fail('INVALID_SETTINGS_REQUEST')
    library._token(value['deployment'], 'deployment')
    if action == 'settings-update':
        library._token(value['request_id'], 'request_id')
        library._integer(value['configuration_version'], 'configuration_version')
        library._digest_value(value['settings_id'], 'settings_id')
    return value


class SettingsOwner:
    """Trusted host composition. No caller-selected paths or authority providers.

    ``authority_settings`` is the existing independent configuration reader. Its
    repository/model references and current egress remain fresh. ``operation``
    pins only shared limits/filters; consumers reuse this callable throughout
    their operation. A returned dictionary is detached, never the owner's state.
    Missing/invalid active state refuses reads, even while an operation is pinned.
    Bootstrap is explicit and exclusive, never an automatic fallback on restart.
    """
    def __init__(self, path, deployment, authority_settings, *, now=lambda:datetime.now(timezone.utc)):
        self.path = Path(path)
        library._token(deployment, 'deployment')
        if not callable(authority_settings) or not callable(now): fail('SETTINGS_DEPENDENCY')
        self.deployment, self.authority_settings, self.now = deployment, authority_settings, now
        self._pin = ContextVar('library-shared-settings', default=None)

    def _path(self, existing=True):
        root = self.path.parent
        try:
            node = root.lstat()
            if (not self.path.is_absolute() or root.resolve() != root or not stat.S_ISDIR(node.st_mode)
                    or node.st_uid != os.geteuid() or node.st_mode & 0o077): fail('SETTINGS_STORE_UNSAFE')
            if existing:
                node = self.path.lstat()
                if (not stat.S_ISREG(node.st_mode) or node.st_nlink != 1 or node.st_uid != os.geteuid()
                        or node.st_mode & 0o077 or node.st_size > MAX_STORE_BYTES): fail('SETTINGS_STORE_UNSAFE')
        except OSError: fail('SETTINGS_UNAVAILABLE')

    def _compose(self, data):
        base = library.admit_settings_value(self.authority_settings())
        document = {k:deepcopy(base[k]) for k in library.CORE_SETTINGS}
        document.update(shared(data))
        core = library._settings_core(document)
        core['egress'] = deepcopy(base['egress'])
        core['settings_id'] = library._settings_id(core)
        return library.admit_settings_value(core)

    def initialize(self, document):
        """Explicit installer bootstrap; refuses any existing file, including damaged state."""
        self._path(False)
        candidate = self._compose(document)
        data = {k:candidate[k] for k in ('filters','limits')}
        try:
            fd = os.open(self.path, os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW, 0o600)
            os.close(fd)
            with self._db(validate=False) as db:
                for statement in SCHEMA.values(): db.execute(statement)
                db.execute('INSERT INTO active VALUES(1,?,?,?,?)',
                    (self.deployment,1,canonical(data),library._digest(data)))
                self._commit(db)
            fd = os.open(self.path.parent, os.O_RDONLY|os.O_DIRECTORY)
            try: os.fsync(fd)
            finally: os.close(fd)
        except FileExistsError: fail('SETTINGS_ALREADY_EXISTS')
        except (OSError, sqlite3.Error): fail('SETTINGS_OUTCOME_UNKNOWN')

    @contextmanager
    def _db(self, *, validate=True):
        self._path()
        db = None
        try:
            db = sqlite3.connect(self.path.as_uri()+'?mode=rw', uri=True, timeout=2, isolation_level=None)
            db.row_factory = sqlite3.Row
            db.execute('PRAGMA synchronous=FULL')
            db.execute('PRAGMA journal_mode=DELETE')
            page_size = db.execute('PRAGMA page_size').fetchone()[0]
            db.execute('PRAGMA max_page_count='+str(MAX_STORE_BYTES // page_size))
            db.execute('BEGIN IMMEDIATE')
            if validate:
                schema = {r['name']:r['sql'] for r in db.execute("SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
                if db.execute("SELECT count(*) FROM sqlite_master WHERE type IN ('trigger','view')").fetchone()[0]: fail('SETTINGS_STORE_INVALID')
                if schema != SCHEMA: fail('SETTINGS_STORE_INVALID')
            yield db
        except (sqlite3.Error, OSError): fail('SETTINGS_OUTCOME_UNKNOWN')
        finally:
            if db is not None:
                db.rollback(); db.close()

    def _commit(self, db): db.commit()

    def _active(self, db):
        row = db.execute('SELECT * FROM active').fetchall()
        if len(row) != 1 or row[0]['singleton'] != 1 or row[0]['deployment'] != self.deployment:
            fail('SETTINGS_STORE_INVALID')
        row = row[0]
        library._integer(row['revision'], 'configuration_version')
        try: data = json.loads(row['shared'], object_pairs_hook=library._unique_pairs)
        except (ValueError, TypeError, RecursionError): fail('SETTINGS_STORE_INVALID')
        if library._digest(data) != row['digest']: fail('SETTINGS_STORE_INVALID')
        return row['revision'], data, self._compose(data)

    def __call__(self):
        with self._db() as db:
            _, data, settings = self._active(db)
        pinned = self._pin.get()
        return self._compose(pinned) if pinned is not None else settings

    @contextmanager
    def operation(self):
        if self._pin.get() is not None:
            yield self
            return
        with self._db() as db:
            _, data, _ = self._active(db)
        token = self._pin.set(deepcopy(data))
        try: yield self
        finally: self._pin.reset(token)

    def handle(self, raw, principal):
        return self._handle(raw, principal, reconcile=False)

    def reconcile(self, raw, principal):
        """Receipt-only lookup; never applies an unexecuted settings update."""
        return self._handle(raw, principal, reconcile=True)

    def _handle(self, raw, principal, *, reconcile):
        value = decode(raw)
        if reconcile and value['action'] != 'settings-update': fail('INVALID_SETTINGS_REQUEST')
        scope = library.local_settings_scope(principal)
        if value['deployment'] != self.deployment: fail('WRONG_SETTINGS_SCOPE')
        with self._db() as db:
            revision, data, current = self._active(db)
            if value['action'] == 'settings-observe':
                if library.local_settings_scope(principal).canonical() != scope.canonical():
                    fail('STALE_SETTINGS_AUTHORITY')
                return {'version':1,'deployment':self.deployment,'impact':'all-projects',
                    'configuration_version':revision,'settings_id':current['settings_id'],
                    'shared':deepcopy(data)}
            identity = library._digest({'request':value,'actor_id':scope.actor_id,
                'human_id':scope.human_id,'deployment':self.deployment})
            prior = db.execute('SELECT * FROM requests WHERE request_id=?',(value['request_id'],)).fetchone()
            if prior is not None:
                if prior['identity'] != identity: fail('ID_CONFLICT')
                try: result=json.loads(prior['receipt'])
                except (ValueError, TypeError): fail('SETTINGS_STORE_INVALID')
                if (type(result) is not dict or library._digest(result) != prior['receipt_digest']
                        or result.get('request_id') != value['request_id']
                        or result.get('deployment') != self.deployment): fail('SETTINGS_STORE_INVALID')
                library.audit_metadata({k:v for k,v in result.items() if k != 'publication'})
                library.local_settings_scope(principal)
                return result
            if reconcile: fail('SETTINGS_OUTCOME_UNKNOWN')
            if db.execute('SELECT count(*) FROM requests').fetchone()[0] >= MAX_REQUESTS:
                fail('SETTINGS_CAPACITY_EXHAUSTED')
            at = self.now().isoformat(); library._timestamp(at,'at')
            changed = []
            candidate = current
            outcome, reason = 'CONFIGURED', None
            try:
                if value['configuration_version'] != revision or value['settings_id'] != current['settings_id']:
                    fail('STALE_SETTINGS')
                library._integer(revision+1, 'configuration_version')
                candidate = self._compose(value['shared'])
                changed = [namespace+'.'+key for namespace in ('limits','filters')
                    for key in current[namespace] if candidate[namespace][key] != current[namespace][key]]
                if not changed: fail('UNCHANGED_SETTINGS')
            except library.LibraryError as error:
                outcome, reason = 'REJECTED', error.code
                candidate = current; changed = []
            # Authority configuration may change independently during validation.
            if self._compose(data)['settings_id'] != current['settings_id']: fail('STALE_SETTINGS')
            fresh = library.local_settings_scope(principal)
            if fresh.canonical() != scope.canonical(): fail('STALE_SETTINGS_AUTHORITY')
            result = {'version':1,'outcome':outcome,'request_id':value['request_id'],
                'deployment':self.deployment,'configuration_version':revision+(outcome=='CONFIGURED'),
                'prior_sha256':current['settings_id'],'resulting_sha256':candidate['settings_id'],
                'changed_keys':sorted(changed),'actor_id':scope.actor_id,'human_id':scope.human_id,
                'authority_version':scope.authority_version,'at':at,'reason':reason,
                'validation_outcome':outcome,'publication':None}
            library.audit_metadata({k:v for k,v in result.items() if k != 'publication'})
            if outcome == 'CONFIGURED':
                replacement = {k:candidate[k] for k in ('limits','filters')}
                db.execute('UPDATE active SET revision=?,shared=?,digest=? WHERE singleton=1',
                    (revision+1,canonical(replacement),library._digest(replacement)))
            db.execute('INSERT INTO requests VALUES(?,?,?,?)',(value['request_id'],identity,canonical(result),library._digest(result)))
            self._commit(db)
            return result
