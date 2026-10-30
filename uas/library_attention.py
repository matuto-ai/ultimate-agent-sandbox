"""T38 metadata-only Library attention, deduplicated notices and receipted snooze.

Every fact here derives from one already-exported T29 observation row and the
Project's own durable attention/snooze records. No draft, title, body, prompt,
model output, log, secret or caller-provided reason ever reaches a notice.
No notification is sent at import or construction: the trusted host explicitly
samples and hands over one existing Gotify delivery, or nothing is sent.
"""
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import re
import threading

from . import library
from .library_records import LibraryRecords
from .manager_attention import MAX_NOTICE_BYTES


SNOOZE_SECONDS = 86400
PARKED = 'PARKED_CONFLICT'
BLOCKED = 'PROJECT_BLOCKED'
WARNING = 'OLDEST_DRAFT_WARNING'
FAILURE_KINDS = {'audit_failures': 'AUDIT_FAILURE', 'recovery_failures': 'RECOVERY_FAILURE'}
KEYS = {PARKED: 'parked-conflict', BLOCKED: 'project-blocked', 'AUDIT_FAILURE': 'audit-failure',
        'RECOVERY_FAILURE': 'recovery-failure', WARNING: 'oldest-draft-warning'}
# Parked conflicts and the oldest-draft warning stay Manager-only by default.
EXTERNAL_KINDS = frozenset({BLOCKED, 'AUDIT_FAILURE', 'RECOVERY_FAILURE'})
REASONS = {
    BLOCKED: 'A Library Project is blocked and needs human attention.',
    'AUDIT_FAILURE': 'A Library audit or storage failure needs attention.',
    'RECOVERY_FAILURE': 'A Library recovery failure needs attention.',
}
_SOURCE = re.compile(r'https://github\.com/[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\Z')


def fail(code):
    raise library.LibraryError(code, 'attention')


def moment(value):
    if type(value) is not str or len(value) > 40: fail('INVALID_ATTENTION_TIME')
    try: result = datetime.fromisoformat(value)
    except ValueError: fail('INVALID_ATTENTION_TIME')
    if result.tzinfo is None: fail('INVALID_ATTENTION_TIME')
    return result


def project_url(scope):
    """Canonical Project link from trusted binding coordinates, never a caller URL."""
    path = scope.project_path
    if type(path) is not str or not path.startswith('github.com/') or '..' in path:
        fail('INVALID_ATTENTION_TARGET')
    return 'https://github.com/' + path[len('github.com/'):]


@dataclass(frozen=True)
class LibraryNotice:
    """Bounded sanitized metadata and one canonical Project link."""
    project_url: str
    kind: str
    count: int
    age_seconds: int | None
    observed_at: str

    def payload(self):
        if (type(self.project_url) is not str or not _SOURCE.match(self.project_url)
                or self.kind not in REASONS or type(self.count) is not int
                or not 0 < self.count < 2**53
                or self.age_seconds is not None and (type(self.age_seconds) is not int
                    or not 0 <= self.age_seconds < 2**53)
                or type(self.observed_at) is not str):
            fail('INVALID_ATTENTION_METADATA')
        moment(self.observed_at)
        message = (REASONS[self.kind] + '\nProject: ' + self.project_url
                   + '\nObserved: ' + self.observed_at + '\nItems: ' + str(self.count))
        if self.age_seconds is not None:
            message += '\nOldest (seconds): ' + str(self.age_seconds)
        value = {'title': 'Library attention', 'priority': 5, 'message': message,
                 'extras': {'client::display': {'contentType': 'text/plain'}}}
        if len(library._canonical(value).encode()) > MAX_NOTICE_BYTES: fail('ATTENTION_LIMIT')
        return value

    def identity(self):
        return hashlib.sha256(library._canonical(self.payload()).encode()).hexdigest()


def rows(observation, *, warning_seconds, snoozes=()):
    """Derived attention rows, or None when the source cannot support them.

    Partial coverage or an unknown queue is unknown attention, never an empty
    healthy state. Counts and ages are copied literally from the observation.
    """
    if observation is None: return None
    row = observation['row']
    if row['queue_status'] != 'known' or row['coverage'] != 'complete': return None
    snoozes = dict(snoozes)
    found = {}

    def add(key, kind, count, age):
        found[key] = {'kind': kind, 'count': count, 'age_seconds': age,
                      'snoozed_until': snoozes.get(kind)}

    if row['parked_depth']:
        add(KEYS[PARKED], PARKED, row['parked_depth'], row['adjudication_wait_seconds'])
    if row['drain_state'] == 'BLOCKED':
        add(KEYS[BLOCKED], BLOCKED, 1, None)
    for field, kind in FAILURE_KINDS.items():
        if row[field]: add(KEYS[kind], kind, row[field], None)
    if (row['active_depth'] and row['oldest_age_seconds'] is not None
            and row['oldest_age_seconds'] >= warning_seconds):
        add(KEYS[WARNING], WARNING, row['active_depth'], row['oldest_age_seconds'])
    return found


def snoozes(cut, *, now):
    """Active snoozed kinds, carried on the cut so an unknown sample cannot drop it."""
    snooze = None if cut is None else cut.get('snooze')
    if not snooze or moment(snooze['until']) <= now: return {}
    return {kind: snooze['until'] for kind in snooze['kinds']}


def sample_operation(scope, settings, sample, at):
    value = library._operation('library-attention', scope, settings,
        'library-attention-' + library._digest([scope.project_identity, sample['sequence']]),
        'library-attention-' + library._digest([scope.project_identity, sample['sequence']]),
        {'manifest_sha256': library._digest(sample)}, at)
    return replace(value, manifest=sample)


def sample_receipt(operation, *, at, reason):
    return library.receipt(operation, 'ACKNOWLEDGED', at=at,
        acknowledgement=library._digest(operation.manifest), reason=reason)


class Owner:
    """Trusted service composition; current authority is rechecked around writes.

    ``publisher`` is the existing Library publisher, ``current_scope`` the current
    authenticated Project authority and ``settings`` the shared settings owner.
    Delivery is an explicit existing Gotify composition, never implicit polling.
    """
    def __init__(self, publisher, *, current_scope, settings,
                 now=lambda: datetime.now(timezone.utc)):
        if not callable(current_scope) or not callable(settings) or not callable(now):
            fail('ATTENTION_DEPENDENCY_REQUIRED')
        scope = current_scope()
        if type(scope) is not library.LibraryScope: fail('LIBRARY_AUTHENTICATION_REQUIRED')
        self.publisher, self.current_scope, self.settings, self.now = (
            publisher, current_scope, settings, now)
        self.scope = scope
        self._lock = threading.Lock()

    def _current(self):
        scope = self.current_scope()
        if type(scope) is not library.LibraryScope or scope.canonical() != self.scope.canonical():
            fail('LIBRARY_AUTHENTICATION_REQUIRED')
        library._require_scope(scope, 'participant', library.ENQUEUE_CAPABILITY)
        return scope

    def latest(self):
        self._current()
        with LibraryRecords(self.publisher.records_path, self.publisher.deployment_id) as records:
            saved = records.latest_attention(self.scope.project_identity)
        self._current()
        return None if saved is None else deepcopy(saved['manifest'])

    def sample(self, *, notify=None):
        """Persist one derived attention cut; optionally send deduplicated notices."""
        with self._lock:
            scope = self._current()
            settings = self.settings()
            accepted = None
            with LibraryRecords(self.publisher.records_path, self.publisher.deployment_id) as records:
                observation = records.latest_observation(scope.project_identity)
                previous = records.latest_attention(scope.project_identity)
                accepted = None if previous is None else deepcopy(previous['manifest'])
            observed = None if observation is None else deepcopy(observation['manifest'])
            now = self.now()
            carried = snoozes(accepted, now=now)
            until = next(iter(carried.values())) if carried else None
            found = rows(observed, warning_seconds=settings['limits']['warning_seconds'],
                         snoozes=carried)
            episodes = self._episodes(accepted, found)
            sample = {'sequence': 1 if accepted is None else accepted['sequence'] + 1,
                      'observed_at': None if observed is None else observed['observed_at'],
                      'state': 'unknown' if found is None else 'known',
                      'rows': {} if found is None else found,
                      'snooze': None if until is None else {'until': until,
                                                           'kinds': sorted(carried)},
                      'episodes': episodes,
                      'project_identity': scope.project_identity}
            self._store(scope, settings, sample, now)
            if notify is not None and sample['state'] == 'known':
                self._notify(scope, settings, observed, sample, notify, now)
            self._current()
            return sample

    @staticmethod
    def _episodes(accepted, found):
        """Monotonic per-kind episode numbers, so a later new failure can notify again.

        A kind that was absent from the previous known cut is a new episode; an
        unknown previous cut keeps the last number rather than guessing.
        """
        episodes = {} if accepted is None else dict(accepted['episodes'])
        if found is None: return episodes
        previous = None if accepted is None or accepted['state'] != 'known' else \
            {row['kind'] for row in accepted['rows'].values()}
        for kind in {row['kind'] for row in found.values()}:
            if previous is not None and kind not in previous:
                episodes[kind] = episodes.get(kind, 0) + 1
            else:
                episodes[kind] = episodes.get(kind, 1)
        return episodes

    def _store(self, scope, settings, sample, now):
        at = now.isoformat()
        operation = sample_operation(scope, settings, sample, at)
        with LibraryRecords(self.publisher.records_path, self.publisher.deployment_id) as records:
            records.begin(operation)
            records.finish(operation, sample_receipt(operation, at=at,
                reason='ATTENTION_RECORDED'))

    def _notify(self, scope, settings, observed, sample, delivery, now):
        """At most one durable notice per newly blocked Project or failure category.

        A new drain identity is a new blocked episode; retries of the same blocked
        batch and later samples of the same state reuse the stored identity. An
        active snooze suppresses the notice without consuming that identity.
        """
        notices = []
        drain = observed['row']['drain_id'] if observed is not None else None
        with LibraryRecords(self.publisher.records_path, self.publisher.deployment_id) as records:
            for key, row in sorted(sample['rows'].items()):
                if row['kind'] not in EXTERNAL_KINDS or row['snoozed_until'] is not None: continue
                evidence = [drain if row['kind'] == BLOCKED else row['kind'],
                            sample['episodes'].get(row['kind'], 1)]
                base = 'attention-notice-' + library._digest([scope.project_identity, key, evidence])
                prior = records.notice_attempts(base)
                # An attempted or uncertain delivery is never repeated automatically;
                # an undeliverable one (no configured credential) may be retried later.
                if any(item['receipt'] is None or item['receipt']['outcome'] in
                       ('ACKNOWLEDGED', 'UNKNOWN') for item in prior['items']):
                    continue
                operation_id = base + '-' + str(prior['count'] + 1)
                notice = LibraryNotice(project_url(scope), row['kind'], row['count'],
                                       row['age_seconds'], sample['observed_at'])
                at = now.isoformat()
                operation = library._operation('attention-notice', scope, settings,
                    operation_id, operation_id, {'notice_sha256': notice.identity(),
                    'attention_sha256': library._digest(sample)}, at)
                records.begin(operation)
                try: delivered = delivery.deliver_payload(notice.payload())
                except Exception: delivered = {'outcome': 'unknown', 'reason': 'GOTIFY_UNCONFIRMED'}
                outcome = {'confirmed': 'ACKNOWLEDGED', 'unknown': 'UNKNOWN'}.get(
                    delivered['outcome'], 'NOT_DURABLE')
                receipt = library.receipt(operation, outcome, at=at,
                    acknowledgement=notice.identity() if outcome == 'ACKNOWLEDGED' else None,
                    reason=None if outcome == 'ACKNOWLEDGED' else (
                        delivered.get('reason') or 'GOTIFY_UNCONFIRMED'))
                records.finish(operation, receipt)
                notices.append({'kind': row['kind'], 'outcome': delivered['outcome']})
        return notices
