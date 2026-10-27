"""Private controlled-command attribution, not proof of arbitrary Git objects.

Only the trusted Supervisor/Broker calls this module after authenticating the
actual process. Source anchors must come from its authenticated Git read, and
finish must consume its controlled native command's exact raw commit result.
A Participant-supplied SHA, author, trailer or writable .git object is NOT such
evidence. This store is not a push-object validator or a canonical Git store.

The private ledger retains metadata, exact source author headers and digests,
never commit messages or patch contents. GitHub's initial SHA-1 commit format
is deliberate; SHA-256 repositories are not silently interpreted as SHA-1.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import unicodedata

from .git_policy import GitIdentity, GitPolicyError
from .ledger import LedgerError, Origin, _json, _token

MAX_COMMIT = 1_048_576
_OID = re.compile(r'[0-9a-f]{40}\Z')
_DIGEST = re.compile(r'[0-9a-f]{64}\Z')
_REPOSITORY = re.compile(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\Z')
_IDENT = re.compile(r'([^<>\x00-\x1f\x7f-\x9f]+) <([^<>\s\x00-\x1f\x7f-\x9f]+)> (-?(?:0|[1-9][0-9]{0,17})) ([+-])([0-9]{2})([0-9]{2})\Z')
_SCHEMA = {
    'scope': 'CREATE TABLE scope (singleton INTEGER PRIMARY KEY CHECK(singleton=1), version INTEGER NOT NULL, room_id TEXT NOT NULL, project_id TEXT NOT NULL)',
    'anchors': 'CREATE TABLE anchors (repository TEXT NOT NULL, oid TEXT NOT NULL, raw_digest TEXT NOT NULL, author TEXT NOT NULL, PRIMARY KEY(repository,oid))',
    'advertisements': 'CREATE TABLE advertisements (repository TEXT NOT NULL, oid TEXT NOT NULL, PRIMARY KEY(repository,oid))',
    'operations': 'CREATE TABLE operations (id TEXT PRIMARY KEY, request TEXT NOT NULL, active_origin TEXT NOT NULL, identity TEXT NOT NULL, status TEXT NOT NULL, contributors TEXT NOT NULL, commit_oid TEXT, raw_digest TEXT)',
    'mutations': 'CREATE TABLE mutations (id TEXT PRIMARY KEY, run_scope TEXT NOT NULL, origin TEXT NOT NULL, command TEXT NOT NULL, request_digest TEXT NOT NULL)',
    'worker_starts': 'CREATE TABLE worker_starts (id TEXT PRIMARY KEY, checkout_id TEXT NOT NULL, request TEXT NOT NULL)',
    'worker_finishes': 'CREATE TABLE worker_finishes (id TEXT PRIMARY KEY REFERENCES worker_starts(id), evidence TEXT NOT NULL)',
    'active_workers': 'CREATE TABLE active_workers (checkout_id TEXT PRIMARY KEY, operation_id TEXT UNIQUE NOT NULL REFERENCES worker_starts(id))',
    'checkouts': 'CREATE TABLE checkouts (checkout_id TEXT PRIMARY KEY, operation_id TEXT UNIQUE NOT NULL REFERENCES operations(id))',
    'taints': 'CREATE TABLE taints (oid TEXT NOT NULL, actor_id TEXT NOT NULL, PRIMARY KEY(oid,actor_id))',
    'lineage': 'CREATE TABLE lineage (oid TEXT NOT NULL, source_oid TEXT NOT NULL, PRIMARY KEY(oid,source_oid))',
    'events': 'CREATE TABLE events (seq INTEGER PRIMARY KEY, operation_id TEXT, kind TEXT NOT NULL, metadata TEXT NOT NULL)',
}


def _oid(value):
    if type(value) is not str or not _OID.fullmatch(value):
        raise LedgerError('INVALID_GIT_OBJECT')
    return value


def _repository(value):
    if type(value) is not str or not _REPOSITORY.fullmatch(value) or value.split('/')[1] in {'.', '..'}:
        raise LedgerError('INVALID_PROJECT')
    return value


def _actors(values):
    if type(values) not in {tuple, list} or len(values) > 256:
        raise LedgerError('INVALID_GIT_CONTRIBUTORS')
    result = sorted({_token(value) for value in values})
    return result


def _run_scope(value):
    if (type(value) is not dict or set(value) != {'run_id', 'generation'}
            or type(value['generation']) is not int or not 1 <= value['generation'] <= 2**53 - 1):
        raise LedgerError('GIT_RUN_SCOPE_UNAVAILABLE')
    return {'run_id': _token(value['run_id']), 'generation': value['generation']}


def _identity(identity, origin=None):
    if type(identity) is not GitIdentity:
        raise LedgerError('INVALID_GIT_IDENTITY')
    try:
        GitIdentity(identity.actor_id, identity.name, identity.email)
    except GitPolicyError:
        raise LedgerError('INVALID_GIT_IDENTITY') from None
    result = {'actor_id': identity.actor_id, 'name': identity.name, 'email': identity.email}
    if origin is not None:
        if type(origin) is not Origin:
            raise LedgerError('FORBIDDEN')
        if result['actor_id'] != origin.actor_id:
            raise LedgerError('GIT_ACTOR_MISMATCH')
    return result


def actor_git_identity(actor):
    """Use one trusted normalized Actor record; absence is not a fallback."""
    if type(actor) is not dict or type(actor.get('git_identity')) is not dict:
        raise LedgerError('GIT_IDENTITY_UNAVAILABLE')
    value = actor['git_identity']
    if set(value) != {'name', 'email'}:
        raise LedgerError('INVALID_GIT_IDENTITY')
    try:
        identity = GitIdentity(actor.get('id'), value['name'], value['email'])
    except GitPolicyError:
        raise LedgerError('INVALID_GIT_IDENTITY') from None
    _identity(identity)
    return identity


def _ident(value):
    if (type(value) is not str or len(value) > 600
            or any(unicodedata.category(c).startswith('C') or c in '\u2028\u2029' for c in value)):
        raise LedgerError('INVALID_GIT_COMMIT')
    match = _IDENT.fullmatch(value)
    if (match is None or match[1] != match[1].strip() or len(match[1]) > 256
            or len(match[2]) > 254 or int(match[5]) > 23 or int(match[6]) > 59):
        raise LedgerError('INVALID_GIT_COMMIT')
    return match[1], match[2]


@dataclass(frozen=True)
class CommitObject:
    oid: str
    tree: str
    parents: tuple
    author: str
    committer: str
    message: bytes
    raw_digest: str


def parse_commit(raw):
    """Parse bounded actual `git cat-file commit` bytes, not display output."""
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_COMMIT or b'\0' in raw:
        raise LedgerError('INVALID_GIT_COMMIT')
    header, separator, message = raw.partition(b'\n\n')
    if not separator or len(header) > 65536 or b'\r' in header:
        raise LedgerError('INVALID_GIT_COMMIT')
    fields = []
    for line in header.split(b'\n'):
        if line.startswith(b' '):
            # Git signatures may continue a non-core header. Core identities
            # cannot be continued or shadowed by an extension header.
            if not fields or fields[-1][0] in {b'tree', b'parent', b'author', b'committer'}:
                raise LedgerError('INVALID_GIT_COMMIT')
            continue
        key, space, value = line.partition(b' ')
        if not space or not re.fullmatch(rb'[A-Za-z][A-Za-z0-9-]{0,63}', key) or not value:
            raise LedgerError('INVALID_GIT_COMMIT')
        fields.append((key, value))
    if not fields or fields[0][0] != b'tree':
        raise LedgerError('INVALID_GIT_COMMIT')
    single = {}
    parents = []
    for key, value in fields:
        if key == b'parent':
            try:
                parents.append(_oid(value.decode('ascii')))
            except (UnicodeError, LedgerError):
                raise LedgerError('INVALID_GIT_COMMIT') from None
        elif key in {b'tree', b'author', b'committer'}:
            if key in single:
                raise LedgerError('INVALID_GIT_COMMIT')
            single[key] = value
    if set(single) != {b'tree', b'author', b'committer'} or len(parents) > 32 or len(set(parents)) != len(parents):
        raise LedgerError('INVALID_GIT_COMMIT')
    try:
        tree = _oid(single[b'tree'].decode('ascii'))
        author, committer = (single[key].decode('utf-8') for key in (b'author', b'committer'))
        _ident(author); _ident(committer)
    except (UnicodeError, LedgerError):
        raise LedgerError('INVALID_GIT_COMMIT') from None
    oid = hashlib.sha1(b'commit ' + str(len(raw)).encode('ascii') + b'\0' + raw).hexdigest()
    return CommitObject(oid, tree, tuple(parents), author, committer, message, hashlib.sha256(raw).hexdigest())


class GitProvenance:
    """One private Room/Project owner; no subprocess, network or credential I/O.

    authorize() must freshly bind the current process/epoch and operation scope.
    `execute` is a one-shot committed permission, not a durable replay grant.
    Every prepare conservatively records mutation contribution before execution;
    abort, uncertainty and replacement cannot make the Actor independent again.
    """
    def __init__(self, path, room_id, project_id):
        self.room_id, self.project_id = _token(room_id), _token(project_id)
        self._db = None
        self.failed = False
        try:
            path = Path(path)
            if not path.is_absolute() or path.resolve() != path or not path.parent.is_dir():
                raise LedgerError('INVALID_STORE')
            parent = path.parent.stat()
            if parent.st_uid != os.getuid() or parent.st_mode & 0o077:
                raise LedgerError('INVALID_STORE')
            descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                node = os.fstat(descriptor)
                if not stat.S_ISREG(node.st_mode) or node.st_uid != os.getuid() or node.st_mode & 0o077 or node.st_nlink != 1:
                    raise LedgerError('INVALID_STORE')
            finally:
                os.close(descriptor)
            self._db = sqlite3.connect(path, timeout=5, isolation_level=None)
            self._db.row_factory = sqlite3.Row
            self._db.execute('PRAGMA foreign_keys=ON')
            self._db.execute('PRAGMA synchronous=FULL')
            if self._db.execute('PRAGMA journal_mode=WAL').fetchone()[0] != 'wal':
                raise LedgerError('INVALID_STORE')
            with self._transaction() as db:
                objects = db.execute("SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall()
                if not objects:
                    for sql in _SCHEMA.values():
                        db.execute(sql)
                    db.execute('INSERT INTO scope VALUES (1,1,?,?)', (room_id, project_id))
                else:
                    actual = {r['name']: r['sql'] for r in objects if r['type'] == 'table'}
                    if actual != _SCHEMA or any(r['type'] != 'table' for r in objects):
                        raise LedgerError('INVALID_STORE')
                row = db.execute('SELECT * FROM scope WHERE singleton=1').fetchone()
                if row is None or row['version'] != 1 or row['room_id'] != room_id or row['project_id'] != project_id:
                    raise LedgerError('PROJECT_MISMATCH')
        except (sqlite3.Error, OSError):
            self.close()
            raise LedgerError('GIT_PROVENANCE_UNAVAILABLE') from None
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
        if self._db is None or self.failed:
            raise LedgerError('GIT_PROVENANCE_UNAVAILABLE')
        return self._db

    def _commit(self):
        self._connection().commit()

    @contextmanager
    def _transaction(self):
        db = self._connection()
        try:
            db.execute('BEGIN IMMEDIATE')
            yield db
            self._commit()
        except sqlite3.Error:
            self.failed = True
            db.rollback()
            raise LedgerError('GIT_PROVENANCE_UNAVAILABLE') from None
        except BaseException:
            db.rollback()
            raise

    @staticmethod
    def _origin(origin, authorize):
        if type(origin) is not Origin or not callable(authorize) or authorize() is not True:
            raise LedgerError('FORBIDDEN')
        return _json(origin.canonical())

    @staticmethod
    def _event(db, operation, kind, metadata):
        if db.execute('SELECT count(*) FROM events').fetchone()[0] >= 50000:
            raise LedgerError('GIT_PROVENANCE_CAPACITY')
        db.execute('INSERT INTO events(operation_id,kind,metadata) VALUES (?,?,?)',
                   (operation, kind, _json(metadata)))

    def _taints(self, db, oid):
        result = [row[0] for row in db.execute(
            'WITH RECURSIVE sources(oid) AS (SELECT ? UNION SELECT lineage.source_oid FROM lineage JOIN sources ON lineage.oid=sources.oid) '
            'SELECT DISTINCT actor_id FROM taints JOIN sources USING(oid) ORDER BY actor_id LIMIT 257', (oid,))]
        if len(result) > 256:
            raise LedgerError('GIT_PROVENANCE_CAPACITY')
        return result

    def anchor_source(self, repository, oid, raw, *, contributors=(), advertised_tip=None, proof_digest=None):
        """Trusted authenticated-read seam, never directly a Participant route."""
        repository, oid = _repository(repository), _oid(oid)
        commit = parse_commit(raw)
        contributors = _actors(contributors)
        if advertised_tip is not None:
            _oid(advertised_tip)
            if type(proof_digest) is not str or not _DIGEST.fullmatch(proof_digest):
                raise LedgerError('INVALID_GIT_SOURCE_PROOF')
        elif proof_digest is not None:
            raise LedgerError('INVALID_GIT_SOURCE_PROOF')
        if oid != commit.oid:
            raise LedgerError('GIT_SOURCE_MISMATCH')
        with self._transaction() as db:
            if advertised_tip is not None and db.execute('SELECT 1 FROM advertisements WHERE repository=? AND oid=?', (repository, advertised_tip)).fetchone() is None:
                raise LedgerError('GIT_SOURCE_UNANCHORED')
            existing = db.execute('SELECT * FROM anchors WHERE repository=? AND oid=?', (repository, oid)).fetchone()
            if existing is not None and (existing['raw_digest'] != commit.raw_digest or existing['author'] != commit.author):
                raise LedgerError('GIT_SOURCE_MISMATCH')
            if existing is None:
                if db.execute('SELECT count(*) FROM anchors').fetchone()[0] >= 10000:
                    raise LedgerError('GIT_PROVENANCE_CAPACITY')
                db.execute('INSERT INTO anchors VALUES (?,?,?,?)', (repository, oid, commit.raw_digest, commit.author))
            for actor in contributors:
                db.execute('INSERT OR IGNORE INTO taints VALUES (?,?)', (oid, actor))
            self._event(db, None, 'source-anchored', {'repository': repository, 'oid': oid,
                'raw_digest': commit.raw_digest, 'contributors': self._taints(db, oid),
                'advertised_tip': advertised_tip, 'proof_digest': proof_digest})
            return {'repository': repository, 'oid': oid, 'author': commit.author,
                    'contributors': self._taints(db, oid)}

    def record_advertisements(self, repository, oids):
        """Trusted completed authenticated upload-pack advertisement seam.

        An advertised object identifies an immutable source. It is NOT current
        repository authorization, credential qualification or revocation proof.
        """
        repository = _repository(repository)
        if type(oids) not in {list, tuple} or len(oids) > 4096:
            raise LedgerError('INVALID_GIT_ADVERTISEMENT')
        values = sorted({_oid(oid) for oid in oids})
        if '0' * 40 in values:
            raise LedgerError('INVALID_GIT_ADVERTISEMENT')
        with self._transaction() as db:
            count = db.execute('SELECT count(*) FROM advertisements').fetchone()[0]
            new = [oid for oid in values if db.execute('SELECT 1 FROM advertisements WHERE repository=? AND oid=?',
                   (repository, oid)).fetchone() is None]
            if count + len(new) > 20000:
                raise LedgerError('GIT_PROVENANCE_CAPACITY')
            db.executemany('INSERT INTO advertisements VALUES (?,?)', ((repository, oid) for oid in new))
            metadata = {'repository': repository, 'count': len(values), 'new_count': len(new),
                'advertisement_digest': hashlib.sha256(_json(values).encode()).hexdigest()}
            self._event(db, None, 'source-advertised', metadata)
            return metadata

    def was_advertised(self, repository, oid):
        repository, oid = _repository(repository), _oid(oid)
        with self._transaction() as db:
            return db.execute('SELECT 1 FROM advertisements WHERE repository=? AND oid=?', (repository, oid)).fetchone() is not None

    def advertised_repositories(self, oid):
        """Trusted exact source lookup; this is not read-authorization evidence."""
        oid = _oid(oid)
        with self._transaction() as db:
            rows = db.execute('SELECT repository FROM advertisements WHERE oid=? ORDER BY repository LIMIT 257', (oid,)).fetchall()
            if len(rows) > 256:
                raise LedgerError('GIT_PROVENANCE_CAPACITY')
            return [row[0] for row in rows]

    def source_tips(self):
        """Bounded trusted candidate tips, never caller-selected authority."""
        from .git_source_proof import MAX_TIPS
        with self._transaction() as db:
            rows = db.execute('SELECT repository,oid FROM advertisements ORDER BY rowid DESC LIMIT ?', (MAX_TIPS,)).fetchall()
            return [{'repository': row['repository'], 'oid': row['oid']} for row in rows]

    def record_resolution(self, operation_id, origin, *, authorize):
        """A controlled staging/edit command during conflict taints its Actor.

        This does not transfer the active operation or authorize continuation.
        Raw shared worktree edits are not automatically attributed by Git.
        """
        with self._transaction() as db:
            canonical = self._origin(origin, authorize)
            row = self._row(db, operation_id)
            request = json.loads(row['request'])
            if row['status'] != 'CONFLICT' or request['kind'] != 'cherry-pick':
                raise LedgerError('GIT_OPERATION_STATE')
            contributors = sorted(set(json.loads(row['contributors'])) | {origin.actor_id})
            if len(contributors) > 256:
                raise LedgerError('GIT_PROVENANCE_CAPACITY')
            db.execute('UPDATE operations SET contributors=? WHERE id=?', (_json(contributors), operation_id))
            self._event(db, operation_id, 'resolution-contributor', {
                'origin_digest': hashlib.sha256(canonical.encode()).hexdigest(), 'contributors': contributors})
            return self._receipt(db, self._row(db, operation_id))

    def reserve_worker(self, operation_id, checkout_id, origin, request_digest, *, authorize):
        """Durably fence every possible worker before launch, including reads.

        Transport close is never an exit proof. A lost controller/launch leaves
        this slot fenced across restart; original IDs never gain replay rights.
        """
        operation_id, checkout_id = _token(operation_id), _token(checkout_id)
        if type(request_digest) is not str or not _DIGEST.fullmatch(request_digest):
            raise LedgerError('INVALID_GIT_REQUEST_DIGEST')
        with self._transaction() as db:
            canonical = self._origin(origin, authorize)
            request = _json({'origin': json.loads(canonical), 'request_digest': request_digest})
            old = db.execute('SELECT * FROM worker_starts WHERE id=?', (operation_id,)).fetchone()
            if old is not None:
                if (old['checkout_id'], old['request']) != (checkout_id, request):
                    raise LedgerError('ID_CONFLICT')
                raise LedgerError('GIT_COMMAND_ALREADY_CONSUMED')
            if db.execute('SELECT 1 FROM active_workers WHERE checkout_id=?', (checkout_id,)).fetchone():
                raise LedgerError('GIT_WORKER_QUIESCENCE_UNKNOWN')
            if db.execute('SELECT count(*) FROM worker_starts').fetchone()[0] >= 10000:
                raise LedgerError('GIT_PROVENANCE_CAPACITY')
            db.execute('INSERT INTO worker_starts VALUES (?,?,?)', (operation_id, checkout_id, request))
            db.execute('INSERT INTO active_workers VALUES (?,?)', (checkout_id, operation_id))
            self._event(db, operation_id, 'worker-reserved', {'checkout_id': checkout_id, 'request_digest': request_digest})

    def finish_worker(self, operation_id, evidence):
        """Trusted exact-worker quiescent handshake AND held pidfd exit proof.

        Not a public route. This reduction of an owned fence needs no current
        Actor authority; revocation must not prevent recording safe cleanup.
        """
        operation_id = _token(operation_id)
        if (type(evidence) is not dict or set(evidence) != {'worker_identity', 'quiescent', 'exited'}
                or evidence['quiescent'] is not True or evidence['exited'] is not True
                or type(evidence['worker_identity']) is not list or len(evidence['worker_identity']) != 2
                or any(type(n) is not int or n <= 0 for n in evidence['worker_identity'])):
            raise LedgerError('GIT_WORKER_QUIESCENCE_UNKNOWN')
        with self._transaction() as db:
            row = db.execute('SELECT * FROM worker_starts WHERE id=?', (operation_id,)).fetchone()
            if row is None: raise LedgerError('GIT_OPERATION_UNKNOWN')
            old = db.execute('SELECT evidence FROM worker_finishes WHERE id=?', (operation_id,)).fetchone()
            if old is not None:
                if old[0] != _json(evidence): raise LedgerError('ID_CONFLICT')
                return
            result = db.execute('DELETE FROM active_workers WHERE checkout_id=? AND operation_id=?', (row['checkout_id'], operation_id))
            if result.rowcount != 1: raise LedgerError('INVALID_STORE')
            db.execute('INSERT INTO worker_finishes VALUES (?,?)', (operation_id, _json(evidence)))
            self._event(db, operation_id, 'worker-quiescent-exited', evidence)

    def pending_worker(self, checkout_id):
        with self._transaction() as db:
            row = db.execute('SELECT operation_id FROM active_workers WHERE checkout_id=?', (_token(checkout_id),)).fetchone()
            return None if row is None else row[0]

    def record_mutation(self, operation_id, run_scope, origin, command, request_digest, *, authorize):
        """Monotonic controlled mutation history within one canonical Run scope.

        Only the Supervisor resolves scope; checkout reuse is not scope identity.
        An abort, reset, sibling seat or replacement cannot delete this history.
        No raw file editing is claimed as observed by this Git-specific record.
        """
        operation_id, command = _token(operation_id), _token(command)
        scope = _json(_run_scope(run_scope))
        if type(request_digest) is not str or not _DIGEST.fullmatch(request_digest):
            raise LedgerError('INVALID_GIT_REQUEST_DIGEST')
        with self._transaction() as db:
            canonical = self._origin(origin, authorize)
            old = db.execute('SELECT * FROM mutations WHERE id=?', (operation_id,)).fetchone()
            if old is not None:
                if (old['run_scope'], old['origin'], old['command'], old['request_digest']) != (scope, canonical, command, request_digest):
                    raise LedgerError('ID_CONFLICT')
                return False
            if db.execute('SELECT count(*) FROM mutations').fetchone()[0] >= 10000:
                raise LedgerError('GIT_PROVENANCE_CAPACITY')
            actors = set(self._scope_actors(db, scope)) | {origin.actor_id}
            if len(actors) > 256: raise LedgerError('GIT_PROVENANCE_CAPACITY')
            db.execute('INSERT INTO mutations VALUES (?,?,?,?,?)', (operation_id, scope, canonical, command, request_digest))
            self._event(db, operation_id, 'controlled-mutation', {
                'run_scope': run_scope, 'actor_id': origin.actor_id, 'command': command, 'request_digest': request_digest})
            return True

    @staticmethod
    def _scope_actors(db, scope):
        actors = sorted({json.loads(row[0])['actor_id'] for row in db.execute('SELECT origin FROM mutations WHERE run_scope=?', (scope,))})
        if len(actors) > 256: raise LedgerError('GIT_PROVENANCE_CAPACITY')
        return actors

    def scope_contributors(self, run_scope):
        with self._transaction() as db:
            return self._scope_actors(db, _json(_run_scope(run_scope)))

    def prepare(self, operation_id, origin, identity, *, kind='commit', source_repository=None,
                source_oid=None, parent_oid=None, checkout_id, request_digest, authorize, run_scope=None, replaced_oid=None):
        """Reserve once; native callers bind their exact invocation by digest.

        request_digest deliberately excludes raw message/argv from this store;
        the trusted controller computes it before requesting permission.
        """
        operation_id = _token(operation_id)
        checkout_id = _token(checkout_id)
        if run_scope is not None: run_scope = _run_scope(run_scope)
        if type(origin) is not Origin:
            raise LedgerError('FORBIDDEN')
        identity = _identity(identity, origin)
        if type(kind) is not str or kind not in {'commit', 'cherry-pick'}:
            raise LedgerError('UNSUPPORTED_GIT_OPERATION')
        if parent_oid is not None:
            _oid(parent_oid)
        if replaced_oid is not None:
            _oid(replaced_oid)
            if kind != 'commit': raise LedgerError('INVALID_GIT_SOURCE')
        if type(request_digest) is not str or not _DIGEST.fullmatch(request_digest):
            raise LedgerError('INVALID_GIT_REQUEST_DIGEST')
        if kind == 'cherry-pick':
            _repository(source_repository); _oid(source_oid)
        elif source_repository is not None or source_oid is not None:
            raise LedgerError('INVALID_GIT_SOURCE')
        with self._transaction() as db:
            canonical_origin = self._origin(origin, authorize)
            request = _json({'kind': kind, 'origin': origin.canonical(), 'identity': identity,
                'source_repository': source_repository, 'source_oid': source_oid, 'parent_oid': parent_oid,
                'checkout_id': checkout_id, 'request_digest': request_digest, 'run_scope': run_scope,
                'replaced_oid': replaced_oid})
            old = db.execute('SELECT * FROM operations WHERE id=?', (operation_id,)).fetchone()
            if old is not None:
                if old['request'] != request:
                    raise LedgerError('ID_CONFLICT')
                if old['active_origin'] != canonical_origin:
                    raise LedgerError('GIT_ORIGIN_MISMATCH')
                return self._receipt(db, old, execute=False)
            current = db.execute('SELECT operations.status FROM checkouts JOIN operations ON operations.id=checkouts.operation_id WHERE checkout_id=?',
                (checkout_id,)).fetchone()
            if current is not None:
                raise LedgerError('GIT_CHECKOUT_FENCED' if current['status'] == 'UNKNOWN' else 'GIT_CHECKOUT_BUSY')
            contributors = {origin.actor_id}
            if replaced_oid is not None:
                contributors.update(self._taints(db, replaced_oid))
            if run_scope is not None:
                contributors.update(self._scope_actors(db, _json(run_scope)))
            if kind == 'cherry-pick':
                if db.execute('SELECT 1 FROM anchors WHERE repository=? AND oid=?', (source_repository, source_oid)).fetchone() is None:
                    raise LedgerError('GIT_SOURCE_UNANCHORED')
                contributors.update(self._taints(db, source_oid))
            if len(contributors) > 256 or db.execute('SELECT count(*) FROM operations').fetchone()[0] >= 10000:
                raise LedgerError('GIT_PROVENANCE_CAPACITY')
            db.execute('INSERT INTO operations VALUES (?,?,?,?,?,?,NULL,NULL)',
                (operation_id, request, canonical_origin, _json(identity), 'PREPARED', _json(sorted(contributors))))
            db.execute('INSERT INTO checkouts VALUES (?,?)', (checkout_id, operation_id))
            self._event(db, operation_id, 'prepared', {'request_digest': hashlib.sha256(request.encode()).hexdigest(),
                'origin_digest': hashlib.sha256(canonical_origin.encode()).hexdigest(), 'contributors': sorted(contributors)})
            return self._receipt(db, self._row(db, operation_id), execute=True)

    @staticmethod
    def _row(db, operation_id):
        row = db.execute('SELECT * FROM operations WHERE id=?', (_token(operation_id),)).fetchone()
        if row is None:
            raise LedgerError('GIT_OPERATION_UNKNOWN')
        return row

    def _active(self, db, operation_id, origin, authorize):
        canonical = self._origin(origin, authorize)
        row = self._row(db, operation_id)
        if row['active_origin'] != canonical:
            raise LedgerError('GIT_ORIGIN_MISMATCH')
        return row

    def _receipt(self, db, row, *, execute=False):
        request = json.loads(row['request'])
        contributors = set(json.loads(row['contributors']))
        if request.get('run_scope') is not None:
            contributors.update(self._scope_actors(db, _json(request['run_scope'])))
        if request.get('replaced_oid') is not None:
            contributors.update(self._taints(db, request['replaced_oid']))
        if request['source_oid'] is not None:
            contributors.update(self._taints(db, request['source_oid']))
        if len(contributors) > 256:
            raise LedgerError('GIT_PROVENANCE_CAPACITY')
        return {'operation_id': row['id'], 'kind': request['kind'], 'status': row['status'],
            'execute': execute, 'commit_oid': row['commit_oid'], 'source_oid': request['source_oid'],
            'source_repository': request['source_repository'], 'parent_oid': request['parent_oid'],
            'checkout_id': request['checkout_id'], 'run_scope': request.get('run_scope'),
            'replaced_oid': request.get('replaced_oid'),
            'contributors': sorted(contributors), 'provenance': 'controlled-command'}

    @staticmethod
    def _release_checkout(db, row):
        checkout_id = json.loads(row['request'])['checkout_id']
        result = db.execute('DELETE FROM checkouts WHERE checkout_id=? AND operation_id=?', (checkout_id, row['id']))
        if result.rowcount != 1:
            raise LedgerError('INVALID_STORE')

    def pending_checkout(self, checkout_id):
        """Trusted controller lookup; writable .git hints do not choose a Run."""
        checkout_id = _token(checkout_id)
        with self._transaction() as db:
            row = db.execute('SELECT operations.* FROM operations JOIN checkouts ON operations.id=checkouts.operation_id WHERE checkout_id=?',
                (checkout_id,)).fetchone()
            if row is None:
                return None
            if row['status'] not in {'PREPARED', 'CONFLICT', 'UNKNOWN'}:
                raise LedgerError('INVALID_STORE')
            return self._receipt(db, row)

    def mark_conflict(self, operation_id, origin, *, authorize):
        with self._transaction() as db:
            row = self._active(db, operation_id, origin, authorize)
            if json.loads(row['request'])['kind'] != 'cherry-pick' or row['status'] not in {'PREPARED', 'CONFLICT'}:
                raise LedgerError('GIT_OPERATION_STATE')
            if row['status'] != 'CONFLICT':
                db.execute("UPDATE operations SET status='CONFLICT' WHERE id=?", (operation_id,))
                self._event(db, operation_id, 'conflict', {'source_oid': json.loads(row['request'])['source_oid']})
            return self._receipt(db, self._row(db, operation_id))

    def continue_conflict(self, operation_id, origin, identity, *, authorize):
        """Trusted explicit resolver/replacement admission, not a bearer ID."""
        if type(origin) is not Origin:
            raise LedgerError('FORBIDDEN')
        identity = _identity(identity, origin)
        with self._transaction() as db:
            canonical = self._origin(origin, authorize)
            row = self._row(db, operation_id)
            request = json.loads(row['request'])
            if request['kind'] != 'cherry-pick' or row['status'] != 'CONFLICT':
                raise LedgerError('GIT_OPERATION_STATE')
            contributors = sorted(set(json.loads(row['contributors'])) | {origin.actor_id}
                | set(self._taints(db, request['source_oid']))
                | (set(self._scope_actors(db, _json(request['run_scope']))) if request.get('run_scope') is not None else set()))
            if len(contributors) > 256:
                raise LedgerError('GIT_PROVENANCE_CAPACITY')
            db.execute("UPDATE operations SET active_origin=?,identity=?,status='PREPARED',contributors=? WHERE id=?",
                       (canonical, _json(identity), _json(contributors), operation_id))
            self._event(db, operation_id, 'continued', {'origin_digest': hashlib.sha256(canonical.encode()).hexdigest(),
                'contributors': contributors, 'source_oid': request['source_oid']})
            return self._receipt(db, self._row(db, operation_id), execute=True)

    def finish(self, operation_id, origin, raw, *, authorize):
        """Consume trusted exact controlled-command result; never raw client proof."""
        commit = parse_commit(raw)
        with self._transaction() as db:
            row = self._active(db, operation_id, origin, authorize)
            return self._finish(db, row, commit)

    def _finish(self, db, row, commit, *, reconciliation=False):
        operation_id = row['id']
        if row['status'] == 'COMMITTED':
            if row['commit_oid'] != commit.oid or row['raw_digest'] != commit.raw_digest:
                raise LedgerError('ID_CONFLICT')
            return self._receipt(db, row)
        if row['status'] != ('UNKNOWN' if reconciliation else 'PREPARED'):
            raise LedgerError('GIT_OPERATION_STATE')
        request, identity = json.loads(row['request']), json.loads(row['identity'])
        expected = (identity['name'], identity['email'])
        if _ident(commit.committer) != expected:
            raise LedgerError('GIT_COMMITTER_MISMATCH')
        if commit.parents != (() if request['parent_oid'] is None else (request['parent_oid'],)):
            raise LedgerError('GIT_PARENT_MISMATCH')
        contributors = set(json.loads(row['contributors']))
        if request.get('run_scope') is not None:
            contributors.update(self._scope_actors(db, _json(request['run_scope'])))
        if request.get('replaced_oid') is not None:
            contributors.update(self._taints(db, request['replaced_oid']))
            db.execute('INSERT OR IGNORE INTO lineage VALUES (?,?)', (commit.oid, request['replaced_oid']))
        if request['kind'] == 'commit':
            if _ident(commit.author) != expected:
                raise LedgerError('GIT_AUTHOR_MISMATCH')
        else:
            anchor = db.execute('SELECT * FROM anchors WHERE repository=? AND oid=?',
                (request['source_repository'], request['source_oid'])).fetchone()
            if anchor is None or commit.author != anchor['author']:
                raise LedgerError('GIT_SOURCE_AUTHOR_MISMATCH')
            trailer = b'(cherry picked from commit ' + request['source_oid'].encode('ascii') + b')'
            # Match a complete final line, never text embedded in prose or
            # an attacker-selected SHA. The private source anchor is truth.
            if commit.message.rstrip(b'\n').split(b'\n')[-1] != trailer:
                raise LedgerError('GIT_SOURCE_TRAILER_MISMATCH')
            contributors.update(self._taints(db, request['source_oid']))
            db.execute('INSERT OR IGNORE INTO lineage VALUES (?,?)', (commit.oid, request['source_oid']))
        if len(contributors) > 256:
            raise LedgerError('GIT_PROVENANCE_CAPACITY')
        for actor in contributors:
            db.execute('INSERT OR IGNORE INTO taints VALUES (?,?)', (commit.oid, actor))
        db.execute("UPDATE operations SET status='COMMITTED',contributors=?,commit_oid=?,raw_digest=? WHERE id=?",
            (_json(sorted(contributors)), commit.oid, commit.raw_digest, operation_id))
        self._release_checkout(db, row)
        self._event(db, operation_id, 'reconciled-committed' if reconciliation else 'committed',
            {'commit_oid': commit.oid, 'raw_digest': commit.raw_digest,
             'source_oid': request['source_oid'], 'contributors': sorted(contributors)})
        return self._receipt(db, self._row(db, operation_id))

    def _terminal(self, operation_id, origin, status, authorize):
        with self._transaction() as db:
            row = self._active(db, operation_id, origin, authorize)
            if row['status'] == status:
                return self._receipt(db, row)
            if row['status'] not in {'PREPARED', 'CONFLICT'}:
                raise LedgerError('GIT_OPERATION_STATE')
            db.execute('UPDATE operations SET status=? WHERE id=?', (status, operation_id))
            if status == 'ABORTED':
                self._release_checkout(db, row)
            self._event(db, operation_id, status.lower(), {'contributors': json.loads(row['contributors'])})
            return self._receipt(db, self._row(db, operation_id))

    def abort(self, operation_id, origin, *, authorize):
        return self._terminal(operation_id, origin, 'ABORTED', authorize)

    def mark_unknown(self, operation_id, origin, *, authorize):
        return self._terminal(operation_id, origin, 'UNKNOWN', authorize)

    def reconcile_unknown(self, operation_id, *, raw=None, confirmed_unchanged=False):
        """Trusted owner-fenced checkout reconciliation; never a client route.

        The controller must inspect authoritative controlled-command evidence
        after fencing the prior owner. Neither user text nor an arbitrary local
        Git object proves this fact. An absent observation retains UNKNOWN.
        Clearing a slot never gives permission to reexecute the original ID.
        """
        if type(confirmed_unchanged) is not bool or (raw is not None and confirmed_unchanged):
            raise LedgerError('INVALID_GIT_RECONCILIATION')
        commit = parse_commit(raw) if raw is not None else None
        with self._transaction() as db:
            row = self._row(db, operation_id)
            if row['status'] == 'COMMITTED' and commit is not None:
                return self._finish(db, row, commit, reconciliation=True)
            if row['status'] == 'ABORTED' and confirmed_unchanged:
                return self._receipt(db, row)
            if row['status'] != 'UNKNOWN':
                raise LedgerError('GIT_OPERATION_STATE')
            if commit is not None:
                return self._finish(db, row, commit, reconciliation=True)
            if confirmed_unchanged:
                db.execute("UPDATE operations SET status='ABORTED' WHERE id=?", (operation_id,))
                self._release_checkout(db, row)
                self._event(db, operation_id, 'reconciled-unchanged', {'contributors': json.loads(row['contributors'])})
                return self._receipt(db, self._row(db, operation_id))
            return self._receipt(db, row)

    def recover_pending(self, *, is_fenced):
        """Trusted replacement only after old native owner is positively fenced."""
        if not callable(is_fenced):
            raise LedgerError('FORBIDDEN')
        recovered = []
        with self._transaction() as db:
            rows = db.execute("SELECT * FROM operations WHERE status IN ('PREPARED','CONFLICT') ORDER BY id").fetchall()
            for row in rows:
                value = json.loads(row['active_origin'])
                value['capabilities'] = tuple(value['capabilities'])
                if is_fenced(Origin(**value)) is not True:
                    continue
                db.execute("UPDATE operations SET status='UNKNOWN' WHERE id=?", (row['id'],))
                self._event(db, row['id'], 'recovered-unknown', {'contributors': json.loads(row['contributors'])})
                recovered.append(row['id'])
        return recovered

    def status(self, operation_id, origin, *, authorize):
        with self._transaction() as db:
            return self._receipt(db, self._active(db, operation_id, origin, authorize))

    def contributors(self, oid):
        """Trusted control-plane read; author names/emails never select Actors."""
        with self._transaction() as db:
            return self._taints(db, _oid(oid))

    def source_anchor(self, repository, oid):
        """Trusted restart/continuation lookup; not a source admission route."""
        repository, oid = _repository(repository), _oid(oid)
        with self._transaction() as db:
            row = db.execute('SELECT * FROM anchors WHERE repository=? AND oid=?', (repository, oid)).fetchone()
            if row is None:
                raise LedgerError('GIT_SOURCE_UNANCHORED')
            return {'repository': repository, 'oid': oid, 'author': row['author'],
                    'raw_digest': row['raw_digest'], 'contributors': self._taints(db, oid)}

    def actor_contributions(self, actor_id):
        """Conservative mutation history survives abort, context and replacement."""
        actor_id = _token(actor_id)
        with self._transaction() as db:
            result = []
            for row in db.execute('SELECT * FROM operations ORDER BY id').fetchall():
                receipt = self._receipt(db, row)
                if actor_id in receipt['contributors']:
                    result.append(receipt)
            return result

    def audit_events(self):
        """Trusted metadata-only audit inspection, not a Participant endpoint."""
        with self._transaction() as db:
            return [{'sequence': row['seq'], 'operation_id': row['operation_id'], 'kind': row['kind'],
                'metadata': json.loads(row['metadata'])} for row in db.execute('SELECT * FROM events ORDER BY seq')]
