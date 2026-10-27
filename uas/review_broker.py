"""Typed internal review observations and comments on the existing Broker boundary.

No Participant route, credential selection, verdict inference or merge mutation.
Merge qualification currently supports an exact two-parent merge only; ambiguous
squash/rebase/queue facts remain unknown rather than becoming a human completion.
"""
from copy import deepcopy
import hashlib
import json
import re

from .gate_forge import validate_forge_target, _matches_pull, _canonical, _digest
from .github_pr import _pull, _review, _sha
from .github_read import GitHubProject, _positive
from .github_surface import _Read
from .ledger import LedgerError, Origin, _token

REVIEW_KINDS = frozenset({'review-observe', 'review-comment', 'review-reconcile'})


def review_origin(instance):
    return Origin('review-hub', 'review-hub', _token(instance), 'hub-review-v1', ('forge-review',))


def unavailable(target, code):
    return {'status': code, 'completeness': 'unknown', 'target': validate_forge_target(target),
            'pull': None, 'reviews': [], 'merge': None}


def _matches_review_pull(pull, target):
    # GitHub may advance base.sha to the integration revision after merge.
    # The captured pre-merge base is independently anchored by commit parents.
    if not pull['merged']: return _matches_pull(pull, target)
    if pull['base']['sha'] not in {target['base_sha'], pull['merge_commit_sha']}: return False
    captured = deepcopy(pull)
    captured['base']['sha'] = target['base_sha']
    return _matches_pull(captured, target)


def validate_review_observation(value, target):
    """Validate the authenticated wire object; this does not authenticate its source."""
    target = validate_forge_target(target)
    try:
        if (type(value) is not dict or set(value) != {'status', 'completeness', 'target', 'pull', 'reviews', 'merge'}
                or value['target'] != target or len(_canonical(value)) > 48000):
            raise ValueError()
        if value['status'] != 'OK':
            if (type(value['status']) is not str or not re.fullmatch('[A-Z][A-Z0-9_]{0,63}', value['status'])
                    or value != unavailable(target, value['status'])): raise ValueError()
            return deepcopy(value)
        project = GitHubProject(target['repository'])
        pull = _pull(value['pull'], project, target['pull_number'])
        if value['completeness'] != 'complete' or pull != value['pull'] or not _matches_review_pull(pull, target):
            raise ValueError()
        reviews = value['reviews']
        if type(reviews) is not list or len(reviews) > 1000: raise ValueError()
        seen = set()
        for row in reviews:
            if _review(row, project, target['pull_number']) != row or row['id'] in seen: raise ValueError()
            seen.add(row['id'])
        merge = value['merge']
        if not pull['merged']:
            if merge is not None: raise ValueError()
        elif (type(merge) is not dict or set(merge) != {'merger_id', 'merger_type', 'integration_sha', 'method'}
                or not _positive(merge['merger_id']) or merge['merger_type'] not in {'User', 'Bot', 'Organization'}
                or merge['integration_sha'] != pull['merge_commit_sha'] or merge['method'] != 'merge'):
            raise ValueError()
        return deepcopy(value)
    except (ValueError, TypeError, KeyError, OverflowError):
        raise LedgerError('INVALID_REVIEW_OBSERVATION') from None


def validate_comment_receipt(value, target):
    target = validate_forge_target(target)
    if (type(value) is not dict or set(value) != {'status', 'audit_reference', 'comment_reference'}
            or value['status'] not in {'confirmed', 'unknown', 'error'}):
        raise LedgerError('INVALID_REVIEW_RECEIPT')
    _token(value['audit_reference'])
    ref = value['comment_reference']
    if value['status'] == 'confirmed':
        if (type(ref) is not dict or set(ref) != {'kind', 'id', 'url'} or ref['kind'] != 'comment'
                or not _positive(ref['id']) or ref['url'] != 'https://github.com/' + target['repository']
                    + '/pull/' + str(target['pull_number']) + '#issuecomment-' + str(ref['id'])):
            raise LedgerError('INVALID_REVIEW_RECEIPT')
    elif ref is not None: raise LedgerError('INVALID_REVIEW_RECEIPT')
    return deepcopy(value)


class BrokerReviewState:
    """Bounded fixed-host reads; only the external owner supplies transport."""
    max_bytes = 1_048_576
    max_pages = 10

    def __init__(self, project, transport):
        if type(project) is not GitHubProject or not callable(transport): raise ValueError()
        self.project, self.transport = project, transport

    def observe(self, target):
        target = validate_forge_target(target)
        if target['repository'] != self.project.repository: raise LedgerError('PROJECT_MISMATCH')
        reader = _Read(self)
        path = 'repos/' + self.project.repository + '/pulls/' + str(target['pull_number'])
        def identity(raw):
            pull = _pull(raw, self.project, target['pull_number'])
            if not _matches_review_pull(pull, target): raise LedgerError('STALE_PULL')
            merger = None
            if pull['merged']:
                who = raw.get('merged_by')
                if (type(who) is not dict or not _positive(who.get('id'))
                        or who.get('type') not in {'User', 'Bot', 'Organization'}):
                    raise LedgerError('UNKNOWN_MERGER')
                merger = {'merger_id': who['id'], 'merger_type': who['type'],
                          'integration_sha': pull['merge_commit_sha'], 'method': 'merge'}
            return pull, merger
        try:
            opening = reader.one(path, identity)
            reviews = reader.many(path + '/reviews', lambda raw: _review(raw, self.project, target['pull_number']))
            pull, merge = opening
            if merge is not None:
                sha = _sha(merge['integration_sha'])
                commit = reader.one('repos/' + self.project.repository + '/commits/' + sha, lambda raw: raw)
                if (type(commit) is not dict or commit.get('sha') != sha
                        or commit.get('url') != 'https://api.github.com/repos/' + self.project.repository + '/commits/' + sha
                        or type(commit.get('parents')) is not list
                        or [row.get('sha') if type(row) is dict else None for row in commit['parents']]
                            != [target['base_sha'], target['head_sha']]):
                    raise LedgerError('UNSUPPORTED_MERGE_METHOD')
            if reader.one(path, identity) != opening: raise LedgerError('STALE_PULL')
            return validate_review_observation({'status': 'OK', 'completeness': 'complete', 'target': target,
                                               'pull': pull, 'reviews': reviews, 'merge': merge}, target)
        except Exception as error:
            code = getattr(error, 'code', None)
            if type(code) is not str or not re.fullmatch('[A-Z][A-Z0-9_]{0,63}', code): code = 'INVALID_RESPONSE'
            return unavailable(target, code)


class ExternalReviewBroker:
    """Fixed authenticated Hub role, audited reads, existing mutation reconciliation."""
    def __init__(self, binding, room_instance, audit, actor_id, providers, mutations):
        from .forge import ForgeBinding
        from .forge_audit import ForgeAudit
        from .forge_mutations import ExternalMutationBroker
        if (type(binding) is not ForgeBinding or type(audit) is not ForgeAudit or not callable(providers)
                or type(mutations) is not ExternalMutationBroker or actor_id not in mutations.actors
                or mutations.binding != binding or mutations.room_instance != room_instance or mutations.audit is not audit):
            raise LedgerError('INVALID_REVIEW_OWNER')
        self.binding, self.room_instance, self.audit = binding, _token(room_instance), audit
        self.actor_id, self.providers, self.mutations = _token(actor_id), providers, mutations
        self.project = GitHubProject(binding.repository, binding.host)
        self.failed = False

    def _guard(self, origin, authorize):
        if self.failed or self.mutations.failed: raise LedgerError('AUDIT_UNAVAILABLE')
        if origin != review_origin(self.room_instance) or authorize() is not True: raise LedgerError('FORBIDDEN')
        return True

    def execute(self, envelope, *, origin, authorize):
        guard = lambda: self._guard(origin, authorize)
        guard()
        if type(envelope) is not dict or envelope.get('kind') not in REVIEW_KINDS: raise LedgerError('INVALID_FORGE_ENVELOPE')
        kind = envelope['kind']
        expected = {'id', 'kind', 'target'} | ({'body'} if kind != 'review-observe' else set())
        attempt = ('preflight_id' if kind == 'review-comment' else 'reconciliation_id') if kind != 'review-observe' else None
        if set(envelope) not in (expected, expected | ({attempt} if attempt else set())):
            raise LedgerError('INVALID_FORGE_ENVELOPE')
        if attempt and attempt in envelope: _token(envelope[attempt])
        _token(envelope['id'])
        target = validate_forge_target(envelope['target'])
        if target['repository'] != self.binding.repository: raise LedgerError('PROJECT_MISMATCH')
        try:
            if kind == 'review-observe': return self._observe(envelope, origin, guard)
            return self._comment(envelope, origin, guard)
        except LedgerError as error:
            if error.code == 'AUDIT_UNAVAILABLE': self.failed = True
            raise

    def _observe(self, envelope, origin, guard):
        from .forge_read_provider import BrokerReadProvider
        from .forge_audit import READ_AUDIT_STATUSES
        target = envelope['target']
        operation = 'review-read-' + _digest([self.binding.room_id, self.room_instance, envelope['id']])
        metadata = {'room_id': self.binding.room_id, 'room_instance': self.room_instance,
            'project_id': self.binding.project_id, 'actor_id': self.actor_id,
            'participant_id': origin.participant_id, 'incarnation_id': origin.incarnation_id,
            'authority_version': origin.authority_version, 'provider_host': 'github.com',
            'requested_repository': self.binding.repository, 'effective_repository': self.binding.repository,
            'route': 'review-observe', 'request_digest': _digest(envelope), 'origin_digest': _digest(origin.canonical())}
        begin = self.audit.begin_read(operation, metadata)
        if not begin['started']:
            guard()
            return {'audit_reference': operation, 'observation': unavailable(target, 'INTERRUPTED_OBSERVATION')}
        contacted = False
        try:
            guard()
            provider = self.providers(self.actor_id)
            if type(provider) is not BrokerReadProvider or provider.project != self.project: raise LedgerError('INVALID_REVIEW_OWNER')
            def transport(path):
                nonlocal contacted
                guard(); contacted = True
                return provider.transport(path)
            observation = BrokerReviewState(self.project, transport).observe(target)
        except Exception as error:
            code = getattr(error, 'code', 'PROVIDER_ERROR')
            if type(code) is not str or not re.fullmatch('[A-Z][A-Z0-9_]{0,63}', code): code = 'PROVIDER_ERROR'
            observation = unavailable(target, code)
        raw = _canonical(observation)
        self.audit.finish_read(operation, {'status': observation['status'] if observation['status'] in READ_AUDIT_STATUSES else 'INVALID_PROVIDER_OBSERVATION',
            'completeness': observation['completeness'], 'contact': 'read' if contacted else 'none',
            'output_bytes': len(raw), 'dropped_bytes': 0 if observation['status'] == 'OK' else None,
            'observation_digest': hashlib.sha256(raw).hexdigest()})
        guard()
        return {'audit_reference': operation, 'observation': observation}

    def _absence_receipt(self, envelope, original, mutation_key, origin, guard):
        """Authoritative journal absence, not guessed absence from GitHub errors.

        The private Broker serializes dispatch and journals every mutation before
        provider contact. A missing journal therefore proves this write never
        started. Persist the observation before allowing Hub preflight recovery.
        """
        attempt = envelope.get('reconciliation_id', 'review-reconcile-' + _digest(original))
        operation = 'review-absence-' + _digest([self.binding.room_id, self.room_instance, original, attempt])
        receipt = {'status': 'error', 'audit_reference': operation, 'comment_reference': None}
        metadata = {'room_id': self.binding.room_id, 'room_instance': self.room_instance,
            'project_id': self.binding.project_id, 'actor_id': self.actor_id,
            'participant_id': origin.participant_id, 'incarnation_id': origin.incarnation_id,
            'authority_version': origin.authority_version, 'provider_host': 'github.com',
            'requested_repository': self.binding.repository, 'effective_repository': self.binding.repository,
            'route': 'review-mutation-absence', 'request_digest': _digest(envelope), 'origin_digest': _digest(origin.canonical())}
        guard()
        begun = self.audit.begin_read(operation, metadata)
        if self.audit.get_mutation(mutation_key) is not None:
            # Another serialized request has already journaled the original key;
            # only mutation reconciliation may adjudicate that action now.
            return None
        # This route reads only the authoritative audit, never GitHub.
        raw = _canonical(receipt)
        digest = hashlib.sha256(raw).hexdigest()
        if begun['started']:
            self.audit.finish_read(operation, {'status': 'OK', 'completeness': 'complete',
                'contact': 'read', 'output_bytes': len(raw), 'dropped_bytes': 0,
                'observation_digest': digest})
        else:
            record = self.audit.read_record(operation)
            terminal = record['result']
            if terminal is None or terminal.get('observation_digest') != digest:
                receipt['status'] = 'unknown'
        guard()
        return receipt

    def _comment(self, envelope, origin, guard):
        from .forge_mutations import digest
        body, target = envelope['body'], envelope['target']
        if type(body) is not str or not body.strip() or len(body.encode()) > 32000 or '\0' in body:
            raise LedgerError('INVALID_REVIEW_COMMENT')
        # Bind every intent, including retries/reconciliation, to exact candidate.
        body += '\n\n<!-- uas:review-target:' + _digest(target) + ' -->'
        original = {'id': envelope['id'], 'kind': 'forge-write',
            'argv': ['pr', 'comment', str(target['pull_number']), '--body-file', '-'], 'body': body}
        key = 'mutation-' + digest([self.binding.room_id, self.room_instance, envelope['id']])
        fixed = Origin(self.actor_id, 'review-hub', self.room_instance, 'hub-review-v1', ('forge-read', 'forge-write'))
        if envelope['kind'] == 'review-reconcile':
            if self.audit.get_mutation(key) is None:
                absent = self._absence_receipt(envelope, original, key, origin, guard)
                if absent is not None: return absent
            receipt = self.mutations.reconcile({'id': envelope.get('reconciliation_id', 'review-reconcile-' + _digest(original)), 'kind': 'forge-reconcile',
                'audit_reference': key, 'mutation': original}, origin=fixed, authorize=guard)
            value = receipt['reconciliation']
            confirmed = value['status'] == 'MATCHED'
        else:
            if self.audit.get_mutation(key) is None:
                preflight = self._observe({'id': 'comment-preflight-' + _digest([original, envelope.get('preflight_id')]), 'kind': 'review-observe', 'target': target}, origin, guard)
                observation = preflight['observation']
                if (observation['status'] != 'OK' or observation['pull']['state'] != 'open' or observation['pull']['merged']):
                    return {'status': 'error', 'audit_reference': preflight['audit_reference'], 'comment_reference': None}
            # Validate the mutation provider's own authenticated PR reread too,
            # not only the earlier review snapshot. GitHub comments have no CAS;
            # the exact revision marker and later reducer reread fence that race.
            from .forge_mutations import ExternalMutationBroker
            from .github_mutations import GitHubMutationProvider
            from .github_read import ProviderResponse, _unique
            def select(actor):
                provider = self.mutations.providers(actor)
                if type(provider) is not GitHubMutationProvider or provider.project != self.project:
                    raise LedgerError('INVALID_REVIEW_OWNER')
                def transport(method, path, payload):
                    guard()
                    response = provider.transport(method, path, payload)
                    if method == 'GET' and path == 'repos/' + self.binding.repository + '/pulls/' + str(target['pull_number']):
                        if type(response) is not ProviderResponse or response.status != 200:
                            raise LedgerError('STALE_REVIEW_TARGET')
                        raw = json.loads(response.body, object_pairs_hook=_unique)
                        pull = _pull(raw, self.project, target['pull_number'])
                        if not _matches_pull(pull, target) or pull['state'] != 'open' or pull['merged']:
                            raise LedgerError('STALE_REVIEW_TARGET')
                    return response
                return GitHubMutationProvider(self.project, transport)
            scoped = ExternalMutationBroker(self.binding, self.room_instance, self.audit,
                self.mutations.actors, select, work_labels=self.mutations.work_labels)
            receipt = scoped.execute(original, origin=fixed, authorize=guard)
            self.failed = self.failed or scoped.failed
            value = receipt['mutation']
            confirmed = value['status'] == 'OK' and 'comment' in value['confirmed_fields']
        objects = [obj for obj in value.get('objects', []) if obj.get('kind') == 'comment']
        guard()
        if confirmed and len(objects) == 1:
            objects[0] = {**objects[0], 'url': 'https://github.com/' + target['repository'] + '/pull/' + str(target['pull_number']) + '#issuecomment-' + str(objects[0]['id'])}
        status = 'confirmed' if confirmed and len(objects) == 1 else 'unknown'
        return validate_comment_receipt({'status': status,
                'audit_reference': receipt['audit_reference'],
                'comment_reference': deepcopy(objects[0]) if confirmed and len(objects) == 1 else None}, target)
